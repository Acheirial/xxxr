//! 路由：按 `inboundTag` / `domain` / `ip` 规则选择出站。
//!
//! 规则按配置顺序匹配，命中即返回；未命中时由 [`crate::Dispatcher`] 回退到
//! 第一个出站。

use std::net::IpAddr;

use xxxr_config::{RoutingConfig, RoutingRule};
use xxxr_proxy::SessionContext;

/// 域名匹配条件。
enum DomainRule {
    /// 精确匹配（`full:`）。
    Full(String),
    /// 后缀匹配（`domain:`），同时匹配子域名。
    Suffix(String),
    /// 关键词匹配（裸字符串），Xray 语义为「包含」。
    Keyword(String),
}

impl DomainRule {
    /// 判断（已小写的）域名是否命中。
    fn matches_domain(&self, domain: &str) -> bool {
        match self {
            Self::Full(expected) => domain == expected,
            Self::Suffix(suffix) => {
                if domain == suffix {
                    return true;
                }
                domain.len() > suffix.len()
                    && domain.ends_with(suffix.as_str())
                    && domain.as_bytes()[domain.len() - suffix.len() - 1] == b'.'
            }
            Self::Keyword(keyword) => domain.contains(keyword.as_str()),
        }
    }
}

/// IP 匹配条件。
enum IpRule {
    /// 单个地址。
    Plain(IpAddr),
    /// CIDR 网段。
    Cidr(IpAddr, u8),
}

impl IpRule {
    /// 判断 IP 是否命中。
    fn matches_ip(&self, ip: IpAddr) -> bool {
        match self {
            Self::Plain(expected) => *expected == ip,
            Self::Cidr(base, prefix) => match (base, ip) {
                (IpAddr::V4(base), IpAddr::V4(ip)) => prefix_match(
                    u128::from(u32::from(*base)),
                    u128::from(u32::from(ip)),
                    *prefix,
                    32,
                ),
                (IpAddr::V6(base), IpAddr::V6(ip)) => {
                    prefix_match(u128::from(*base), u128::from(ip), *prefix, 128)
                }
                _ => false,
            },
        }
    }
}

/// 前缀匹配：`prefix == 0` 时匹配任意地址。
fn prefix_match(base: u128, ip: u128, prefix: u8, width: u8) -> bool {
    if prefix == 0 {
        return true;
    }
    if prefix > width {
        return false;
    }
    let shift = 128 - u32::from(prefix);
    (base << shift) == (ip << shift)
}

/// 一条编译后的路由规则。
struct CompiledRule {
    inbound_tags: Option<Vec<String>>,
    domains: Vec<DomainRule>,
    ips: Vec<IpRule>,
    outbound_tag: String,
}

impl CompiledRule {
    /// 会话是否命中该规则：所有声明过的条件之间为「与」，列表内部为「或」。
    fn matches(&self, ctx: &SessionContext) -> bool {
        if let Some(tags) = &self.inbound_tags {
            let inbound = ctx.inbound_tag.as_deref().unwrap_or_default();
            if !tags.iter().any(|tag| tag == inbound) {
                return false;
            }
        }
        if !self.domains.is_empty() {
            let matched = ctx
                .target
                .as_ref()
                .and_then(|target| target.domain.as_deref())
                .is_some_and(|domain| self.domains.iter().any(|rule| rule.matches_domain(domain)));
            if !matched {
                return false;
            }
        }
        if !self.ips.is_empty() {
            let matched = ctx
                .target
                .as_ref()
                .and_then(|target| target.ip)
                .is_some_and(|ip| self.ips.iter().any(|rule| rule.matches_ip(ip)));
            if !matched {
                return false;
            }
        }
        true
    }
}

/// 路由器。
pub struct Router {
    rules: Vec<CompiledRule>,
}

impl Router {
    /// 从配置编译路由器。
    ///
    /// 含无法解析条件的规则会被整体跳过（并记录告警），避免退化成「匹配全部」。
    pub fn new(routing: Option<&RoutingConfig>) -> Self {
        let rules = routing
            .map(|routing| routing.rules.iter().filter_map(compile_rule).collect())
            .unwrap_or_default();
        Self { rules }
    }

    /// 返回已编译的规则数量。
    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }

    /// 为会话选择出站 tag；无规则命中时返回 `None`。
    pub fn pick(&self, ctx: &SessionContext) -> Option<&str> {
        self.rules
            .iter()
            .find(|rule| rule.matches(ctx))
            .map(|rule| rule.outbound_tag.as_str())
    }
}

fn compile_rule(rule: &RoutingRule) -> Option<CompiledRule> {
    if rule.enabled == Some(false) {
        return None;
    }
    let mut domains = Vec::new();
    if let Some(entries) = &rule.domain {
        for entry in entries {
            match compile_domain(entry) {
                Some(domain) => domains.push(domain),
                None => {
                    tracing::warn!(
                        outbound = %rule.outbound_tag,
                        "router: unsupported domain condition `{entry}`, skipping rule"
                    );
                    return None;
                }
            }
        }
    }
    let mut ips = Vec::new();
    if let Some(entries) = &rule.ip {
        for entry in entries {
            match compile_ip(entry) {
                Some(ip) => ips.push(ip),
                None => {
                    tracing::warn!(
                        outbound = %rule.outbound_tag,
                        "router: invalid ip condition `{entry}`, skipping rule"
                    );
                    return None;
                }
            }
        }
    }
    Some(CompiledRule {
        inbound_tags: rule.inbound_tag.clone(),
        domains,
        ips,
        outbound_tag: rule.outbound_tag.clone(),
    })
}

fn compile_domain(entry: &str) -> Option<DomainRule> {
    let lower = entry.trim().to_ascii_lowercase();
    if let Some(value) = lower.strip_prefix("domain:") {
        Some(DomainRule::Suffix(value.to_string()))
    } else if let Some(value) = lower.strip_prefix("full:") {
        Some(DomainRule::Full(value.to_string()))
    } else if lower.contains(':') {
        // `regexp:` / `geosite:` 等暂不支持。
        None
    } else if lower.is_empty() {
        None
    } else {
        Some(DomainRule::Keyword(lower))
    }
}

fn compile_ip(entry: &str) -> Option<IpRule> {
    let trimmed = entry.trim();
    match trimmed.split_once('/') {
        Some((address, prefix)) => {
            let base = address.parse::<IpAddr>().ok()?;
            let prefix = prefix.parse::<u8>().ok()?;
            let width = if base.is_ipv4() { 32 } else { 128 };
            if prefix > width {
                return None;
            }
            Some(IpRule::Cidr(base, prefix))
        }
        None => trimmed.parse::<IpAddr>().ok().map(IpRule::Plain),
    }
}
