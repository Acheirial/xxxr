//! 路由：按 `inboundTag` / `domain` / `ip` / `port` / `network` / `source` /
//! `protocol` 条件选择出站。
//!
//! 语义对齐上游 Xray `app/router/condition.go` 与
//! `features/routing/session/context.go`：
//! - 规则按配置顺序匹配，命中即返回；未命中由 [`crate::Dispatcher`] 回退到第一个出站；
//! - `domain` 使用路由目标（嗅探结果优先），需要 geodata 的条件会跳过整条规则并告警；
//! - `ip` / `port` 使用出站实际拨号的目标，`source` 使用客户端来源地址；
//! - 规则内部条件之间为「与」，同一条件的多个取值之间为「或」。

use xxxr_common::{Error, Result};
use xxxr_config::{
    DomainMatcher, DomainType, IpMatcher, MatchMode, PortList, RoutingConfig, RoutingRule,
    StringList,
};
use xxxr_proxy::SessionContext;

/// 一条编译后的路由规则。
#[derive(Debug)]
struct CompiledRule {
    inbound_tags: Option<Vec<String>>,
    domains: Option<DomainMatcher>,
    ips: Option<IpMatcher>,
    ports: Option<PortList>,
    networks: Option<Vec<String>>,
    sources: Option<IpMatcher>,
    protocols: Option<Vec<String>>,
    outbound_tag: String,
    rule_tag: Option<String>,
}

impl CompiledRule {
    /// 会话是否命中该规则。
    fn matches(&self, ctx: &SessionContext) -> bool {
        if let Some(tags) = &self.inbound_tags {
            let inbound = ctx.inbound_tag.as_deref().unwrap_or_default();
            if !tags.iter().any(|tag| tag == inbound) {
                return false;
            }
        }
        if let Some(matcher) = &self.domains {
            let matched = ctx
                .route_target()
                .and_then(|target| target.domain.as_deref())
                .is_some_and(|domain| matcher.matches(domain));
            if !matched {
                return false;
            }
        }
        if let Some(matcher) = &self.ips {
            let matched = ctx
                .outbound_target()
                .and_then(|target| target.ip)
                .is_some_and(|ip| matcher.matches(ip));
            if !matched {
                return false;
            }
        }
        if let Some(ports) = &self.ports {
            let matched = ctx
                .outbound_target()
                .is_some_and(|target| ports.matches(target.port));
            if !matched {
                return false;
            }
        }
        if let Some(networks) = &self.networks {
            let network = ctx.network.as_str();
            if !networks
                .iter()
                .any(|item| item.eq_ignore_ascii_case(network))
            {
                return false;
            }
        }
        if let Some(matcher) = &self.sources {
            let matched = ctx
                .source
                .as_ref()
                .and_then(|source| source.ip)
                .is_some_and(|ip| matcher.matches(ip));
            if !matched {
                return false;
            }
        }
        if let Some(protocols) = &self.protocols {
            let protocol = ctx.protocol.as_deref().unwrap_or_default();
            if protocol.is_empty()
                || !protocols
                    .iter()
                    .any(|item| protocol.starts_with(item.as_str()))
            {
                return false;
            }
        }
        true
    }
}

/// 路由器。
#[derive(Debug, Default)]
pub struct Router {
    rules: Vec<CompiledRule>,
}

impl Router {
    /// 从配置编译路由器。
    ///
    /// - 语法错误（坏正则、非法 IP/CIDR/端口）返回 [`Error::Config`]；
    /// - 需要 geodata 的条件（`geosite:` / `geoip:`）返回 [`Error::Unsupported`]，
    ///   此时跳过整条规则并告警，避免退化成「匹配全部」；
    /// - `enabled: false` 的规则被忽略。
    pub fn new(routing: Option<&RoutingConfig>) -> Result<Self> {
        let Some(routing) = routing else {
            return Ok(Self::default());
        };
        let mode = routing.domain_matcher.unwrap_or_default();
        let mut rules = Vec::new();
        for rule in &routing.rules {
            match compile_rule(rule, mode) {
                Ok(Some(compiled)) => rules.push(compiled),
                Ok(None) => {}
                Err(Error::Unsupported(reason)) => {
                    tracing::warn!(
                        outbound = %rule.outbound_tag,
                        rule_tag = rule.rule_tag.as_deref().unwrap_or("-"),
                        "router: skipping rule: {reason}"
                    );
                }
                Err(e) => return Err(e),
            }
        }
        Ok(Self { rules })
    }

    /// 返回已编译的规则数量。
    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }

    /// 为会话选择出站 tag；无规则命中时返回 `None`。
    pub fn pick(&self, ctx: &SessionContext) -> Option<&str> {
        for rule in &self.rules {
            if rule.matches(ctx) {
                if rule.rule_tag.is_some() {
                    tracing::debug!(
                        rule_tag = rule.rule_tag.as_deref().unwrap_or("-"),
                        outbound = %rule.outbound_tag,
                        "routing rule matched"
                    );
                }
                return Some(rule.outbound_tag.as_str());
            }
        }
        None
    }
}

/// 编译单条规则；`Ok(None)` 表示规则被显式禁用。
fn compile_rule(rule: &RoutingRule, mode: MatchMode) -> Result<Option<CompiledRule>> {
    if rule.enabled == Some(false) {
        return Ok(None);
    }
    let inbound_tags = rule
        .inbound_tag
        .as_ref()
        .filter(|list| !list.is_empty())
        .map(|list| list.as_slice().to_vec());
    let domains = match &rule.domain {
        Some(entries) if !entries.is_empty() => Some(DomainMatcher::build(
            entries.as_slice(),
            DomainType::Keyword,
            mode,
        )?),
        _ => None,
    };
    let ips = match &rule.ip {
        Some(entries) if !entries.is_empty() => Some(IpMatcher::build(entries.as_slice())?),
        _ => None,
    };
    let ports = rule.port.clone().filter(|ports| !ports.is_empty());
    let networks = network_list(rule.network.as_ref());
    // 上游语义：`sourceIP` 优先于 `source`。
    let sources = match rule.source_ip.as_ref().or(rule.source.as_ref()) {
        Some(entries) if !entries.is_empty() => Some(IpMatcher::build(entries.as_slice())?),
        _ => None,
    };
    let protocols = match &rule.protocol {
        Some(entries) if !entries.is_empty() => Some(
            entries
                .as_slice()
                .iter()
                .map(|item| item.trim().to_ascii_lowercase())
                .filter(|item| !item.is_empty())
                .collect(),
        ),
        _ => None,
    };
    Ok(Some(CompiledRule {
        inbound_tags,
        domains,
        ips,
        ports,
        networks,
        sources,
        protocols,
        outbound_tag: rule.outbound_tag.clone(),
        rule_tag: rule.rule_tag.clone(),
    }))
}

/// 传输层类型列表：统一小写。
fn network_list(list: Option<&StringList>) -> Option<Vec<String>> {
    let list = list.filter(|list| !list.is_empty())?;
    let networks: Vec<String> = list
        .as_slice()
        .iter()
        .map(|item| item.trim().to_ascii_lowercase())
        .filter(|item| !item.is_empty())
        .collect();
    (!networks.is_empty()).then_some(networks)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    use xxxr_config::{Config, RoutingConfig};
    use xxxr_net::Address;

    /// 用 JSON 片段构造路由配置（同时覆盖反序列化逻辑）。
    fn routing_from(json: &str) -> RoutingConfig {
        let config =
            Config::from_json_str(&format!("{{\"routing\":{json}}}")).expect("parse config");
        config.routing.expect("routing")
    }

    /// 构造一个会话上下文。
    fn context(
        inbound: &str,
        target: Address,
        source: Option<&str>,
        network_name: &str,
    ) -> SessionContext {
        let mut ctx = SessionContext::new(inbound.to_string(), source.map(parse_source));
        ctx.target = Some(target);
        ctx.network = if network_name == "udp" {
            xxxr_proxy::Network::Udp
        } else {
            xxxr_proxy::Network::Tcp
        };
        ctx
    }

    fn parse_address(value: &str) -> Address {
        value.parse::<Address>().expect("address")
    }

    /// 来源地址：允许省略端口（路由条件只关心 IP）。
    fn parse_source(value: &str) -> Address {
        match value.parse::<Address>() {
            Ok(address) => address,
            Err(_) => format!("{value}:0")
                .parse::<Address>()
                .expect("source address"),
        }
    }

    fn rule_for(json: &str, ctx: &SessionContext) -> Option<String> {
        let router = Router::new(Some(&routing_from(json))).expect("router");
        router.pick(ctx).map(str::to_string)
    }

    #[test]
    fn matches_by_inbound_tag_and_falls_back() {
        let json = r#"{
            "rules": [
                { "type": "field", "inboundTag": ["socks-in"], "outboundTag": "a" },
                { "type": "field", "inboundTag": "other", "outboundTag": "b" }
            ]
        }"#;
        let ctx = context("socks-in", parse_address("1.2.3.4:80"), None, "tcp");
        assert_eq!(rule_for(json, &ctx).as_deref(), Some("a"));
        // 逗号分隔的单个字符串同样生效。
        let ctx = context("other", parse_address("1.2.3.4:80"), None, "tcp");
        assert_eq!(rule_for(json, &ctx).as_deref(), Some("b"));
        // 未命中任何规则。
        let ctx = context("nope", parse_address("1.2.3.4:80"), None, "tcp");
        assert_eq!(rule_for(json, &ctx), None);
    }

    #[test]
    fn port_range_matching_uses_outbound_target_port() {
        let json = r#"{
            "rules": [
                { "type": "field", "port": "100-200", "outboundTag": "range" },
                { "type": "field", "port": 443, "outboundTag": "https" },
                { "type": "field", "port": "80,8080-8081", "outboundTag": "web" }
            ]
        }"#;
        for (port, expected) in [
            (150u16, Some("range")),
            (100, Some("range")),
            (200, Some("range")),
            (99, None),
            (443, Some("https")),
            (80, Some("web")),
            (8080, Some("web")),
            (8081, Some("web")),
            (8082, None),
        ] {
            let ctx = context("in", parse_address(&format!("1.2.3.4:{port}")), None, "tcp");
            assert_eq!(rule_for(json, &ctx).as_deref(), expected, "port {port}");
        }
    }

    #[test]
    fn network_matches_tcp_and_udp() {
        let json = r#"{
            "rules": [
                { "type": "field", "network": "udp", "outboundTag": "udp-out" },
                { "type": "field", "network": "tcp,udp", "outboundTag": "any-out" }
            ]
        }"#;
        let tcp = context("in", parse_address("1.2.3.4:53"), None, "tcp");
        assert_eq!(rule_for(json, &tcp).as_deref(), Some("any-out"));
        let udp = context("in", parse_address("1.2.3.4:53"), None, "udp");
        assert_eq!(rule_for(json, &udp).as_deref(), Some("udp-out"));
    }

    #[test]
    fn domain_conditions_full_domain_and_keyword() {
        let json = r#"{
            "rules": [
                { "type": "field", "domain": ["full:exact.example"], "outboundTag": "full" },
                { "type": "field", "domain": ["domain:suffix.example"], "outboundTag": "suffix" },
                { "type": "field", "domain": ["keyword:cdn"], "outboundTag": "keyword" },
                { "type": "field", "domain": ["regexp:^re[0-9]+\\.example$"], "outboundTag": "regexp" },
                { "type": "field", "domain": ["bare"], "outboundTag": "bare" }
            ]
        }"#;
        for (domain, expected) in [
            ("exact.example", Some("full")),
            ("sub.exact.example", None),
            ("suffix.example", Some("suffix")),
            ("deep.sub.suffix.example", Some("suffix")),
            ("notsuffix.example", None),
            ("my-cdn.example.net", Some("keyword")),
            ("re12.example", Some("regexp")),
            ("rexx.example", None),
            ("a-bare-domain.example", Some("bare")),
        ] {
            let ctx = context("in", Address::domain(domain, 443), None, "tcp");
            assert_eq!(rule_for(json, &ctx).as_deref(), expected, "domain {domain}");
        }
    }

    #[test]
    fn rule_order_is_the_priority() {
        // 同一域名同时命中多条规则时，靠前的规则优先。
        let json = r#"{
            "rules": [
                { "type": "field", "domain": ["domain:example.com"], "outboundTag": "first" },
                { "type": "field", "domain": ["keyword:example"], "outboundTag": "second" }
            ]
        }"#;
        let ctx = context("in", Address::domain("a.example.com", 80), None, "tcp");
        assert_eq!(rule_for(json, &ctx).as_deref(), Some("first"));
    }

    #[test]
    fn domain_matcher_mode_switch_keeps_results() {
        let body = r#"
            "rules": [
                { "type": "field", "domain": ["full:exact.example", "domain:suffix.example", "keyword:cdn"], "outboundTag": "out" }
            ]"#;
        for mode in ["hybrid", "regexp"] {
            let json = format!("{{ \"domainMatcher\": \"{mode}\", {body} }}");
            for (domain, expected) in [
                ("exact.example", Some("out")),
                ("x.exact.example", None),
                ("x.suffix.example", Some("out")),
                ("notsuffix.example", None),
                ("a-cdn-b.example", Some("out")),
            ] {
                let ctx = context("in", Address::domain(domain, 80), None, "tcp");
                assert_eq!(
                    rule_for(&json, &ctx).as_deref(),
                    expected,
                    "mode {mode} domain {domain}"
                );
            }
        }
        // 非法 domainMatcher 值应在解析阶段报错。
        assert!(Config::from_json_str("{\"routing\":{\"domainMatcher\":\"nope\"}}").is_err());
    }

    #[test]
    fn ip_source_and_protocol_conditions() {
        let json = r#"{
            "rules": [
                { "type": "field", "ip": ["10.0.0.0/8"], "outboundTag": "lan" },
                { "type": "field", "source": ["192.168.0.0/16"], "outboundTag": "from-lan" },
                { "type": "field", "sourceIP": "172.16.0.1", "outboundTag": "from-exact" },
                { "type": "field", "protocol": ["http"], "outboundTag": "http-out" },
                { "type": "field", "protocol": ["tls"], "outboundTag": "tls-out" }
            ]
        }"#;
        let lan = context("in", parse_address("10.1.2.3:80"), None, "tcp");
        assert_eq!(rule_for(json, &lan).as_deref(), Some("lan"));

        // ip 条件不命中时继续往后匹配。
        let wan = context(
            "in",
            parse_address("8.8.8.8:80"),
            Some("192.168.1.9"),
            "tcp",
        );
        assert_eq!(rule_for(json, &wan).as_deref(), Some("from-lan"));

        let exact = context("in", parse_address("8.8.8.8:80"), Some("172.16.0.1"), "tcp");
        assert_eq!(rule_for(json, &exact).as_deref(), Some("from-exact"));

        // protocol 取嗅探结果，并按前缀匹配（http 命中 http1）。
        let mut sniffed = context("in", parse_address("8.8.8.8:80"), None, "tcp");
        sniffed.protocol = Some("http1".to_string());
        assert_eq!(rule_for(json, &sniffed).as_deref(), Some("http-out"));

        let mut tls_ctx = context("in", parse_address("8.8.8.8:443"), None, "tcp");
        tls_ctx.protocol = Some("tls".to_string());
        assert_eq!(rule_for(json, &tls_ctx).as_deref(), Some("tls-out"));

        // 没有嗅探结果时，protocol 条件不成立。
        let plain = context("in", parse_address("8.8.8.8:80"), None, "tcp");
        assert_eq!(rule_for(json, &plain), None);
    }

    #[test]
    fn geodata_rules_are_skipped_with_a_warning() {
        let json = r#"{
            "rules": [
                { "type": "field", "domain": ["geosite:cn"], "outboundTag": "geo" },
                { "type": "field", "ip": ["geoip:cn"], "outboundTag": "geo-ip" },
                { "type": "field", "domain": ["domain:keep.example"], "outboundTag": "keep" }
            ]
        }"#;
        let router = Router::new(Some(&routing_from(json))).expect("router");
        // 两条 geodata 规则被跳过，仅保留第三条。
        assert_eq!(router.rule_count(), 1);
        let ctx = context("in", Address::domain("keep.example", 80), None, "tcp");
        assert_eq!(router.pick(&ctx), Some("keep"));
    }

    #[test]
    fn invalid_conditions_are_reported() {
        let json =
            r#"{ "rules": [ { "type": "field", "domain": ["regexp:["], "outboundTag": "x" } ] }"#;
        assert!(Router::new(Some(&routing_from(json))).is_err());
        let json =
            r#"{ "rules": [ { "type": "field", "ip": ["10.0.0.0/33"], "outboundTag": "x" } ] }"#;
        assert!(Router::new(Some(&routing_from(json))).is_err());
    }

    #[test]
    fn disabled_rules_and_ip_negation() {
        let json = r#"{
            "rules": [
                { "type": "field", "ip": ["10.0.0.0/8"], "outboundTag": "off", "enabled": false },
                { "type": "field", "ip": ["!10.0.0.0/8"], "outboundTag": "not-lan" }
            ]
        }"#;
        assert_eq!(
            rule_for(
                json,
                &context("in", parse_address("10.9.9.9:80"), None, "tcp")
            ),
            None
        );
        assert_eq!(
            rule_for(
                json,
                &context("in", parse_address("11.9.9.9:80"), None, "tcp")
            )
            .as_deref(),
            Some("not-lan")
        );
    }

    #[test]
    fn domain_rule_uses_sniffed_target_while_ip_uses_dial_target() {
        // 模拟 routeOnly：路由用嗅探域名，ip/port 仍看原始 IP。
        let json = r#"{
            "rules": [
                { "type": "field", "domain": ["full:sniffed.example"], "outboundTag": "by-domain" },
                { "type": "field", "ip": ["1.2.3.4"], "outboundTag": "by-ip" }
            ]
        }"#;
        let mut ctx = context("in", parse_address("1.2.3.4:443"), None, "tcp");
        ctx.set_sniffed(
            Address::domain("sniffed.example", 443),
            "tls".to_string(),
            true,
        );
        // 域名条件先行命中。
        assert_eq!(rule_for(json, &ctx).as_deref(), Some("by-domain"));

        // 只有 ip 规则时，routeOnly 下仍然命中原始 IP。
        let json_ip_only = r#"{
            "rules": [ { "type": "field", "ip": ["1.2.3.4"], "outboundTag": "by-ip" } ]
        }"#;
        assert_eq!(rule_for(json_ip_only, &ctx).as_deref(), Some("by-ip"));

        let mut overridden = context("in", parse_address("1.2.3.4:443"), None, "tcp");
        overridden.set_sniffed(
            Address::domain("sniffed.example", 443),
            "tls".to_string(),
            false,
        );
        // 非 routeOnly：出站目标已改成域名，ip 条件不再命中。
        assert_eq!(rule_for(json_ip_only, &overridden), None);
    }

    #[test]
    fn helper_address_parsing() {
        assert_eq!(
            parse_address("1.2.3.4:80").ip,
            Some("1.2.3.4".parse::<IpAddr>().unwrap())
        );
    }
}
