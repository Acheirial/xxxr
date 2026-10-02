//! 域名嗅探（sniffing）。
//!
//! 对齐上游 Xray：
//! - 配置来自入站 `sniffing` 字段（[`SniffingSettings`]）；
//! - 单协议解析器 [`tls`] / [`http`] 对应 `common/protocol/{tls,http}`；
//! - 编排 [`sniff_and_apply`] 对应 `app/dispatcher` 的 `sniffer()` + `shouldOverride()`：
//!   最多两轮读取、总时限 [`SNIFF_TIMEOUT`]、缓冲上限 [`SNIFF_BUFFER_SIZE`]。
//!
//! 嗅探「只读不吞」：已读取的字节会通过 [`xxxr_net::Prefixed`] 重新接到连接前端，
//! 因此不会丢失客户端数据。嗅探失败一律回退为原始目标。

use std::time::Duration;

use tokio::io::AsyncReadExt;
use tokio::time::{timeout, Instant};
use xxxr_common::Result;
use xxxr_config::{DomainMatcher, DomainType, MatchMode};
use xxxr_net::{Address, Conn, Prefixed};

pub use xxxr_config::SniffingSettings;

use crate::context::{Network, SessionContext};

/// 嗅探缓冲上限（对齐上游 `sniffer()` 的 32767 字节）。
pub const SNIFF_BUFFER_SIZE: usize = 32767;
/// 嗅探总时限（对齐上游 `cacheDeadline`）。
pub const SNIFF_TIMEOUT: Duration = Duration::from_millis(200);
/// 单轮读取的栈上缓冲大小。
const READ_CHUNK: usize = 8 * 1024;

/// 嗅探结果，对应上游 `SniffResult` 的 `Protocol()` / `Domain()`。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SniffResult {
    /// 协议名：`tls` / `http1`。
    pub protocol: &'static str,
    /// 嗅探出的域名（已小写）。
    pub domain: String,
}

/// 编译后的嗅探配置。
#[derive(Debug, Clone)]
pub struct Sniffer {
    settings: SniffingSettings,
    excluded: DomainMatcher,
}

impl Sniffer {
    /// 依据入站配置构建嗅探器；未启用时返回 `None`。
    ///
    /// 非法条件（坏正则等）会告警并降级为「不排除任何域名」，
    /// 以保证配置错误不会让入站无法启动。
    pub fn build(settings: Option<&SniffingSettings>) -> Result<Option<Self>> {
        let Some(settings) = settings else {
            return Ok(None);
        };
        if !settings.enabled {
            return Ok(None);
        }
        let excluded = match DomainMatcher::build(
            &settings.domains_excluded,
            DomainType::Keyword,
            MatchMode::Hybrid,
        ) {
            Ok(matcher) => matcher,
            Err(e) => {
                tracing::warn!("sniffing: ignoring `domainsExcluded`: {e}");
                DomainMatcher::default()
            }
        };
        Ok(Some(Self {
            settings: settings.clone(),
            excluded,
        }))
    }

    /// 返回原始配置。
    pub fn settings(&self) -> &SniffingSettings {
        &self.settings
    }

    /// 对应上游 `shouldOverride`：域名非空、未被排除、且协议命中 `destOverride`。
    ///
    /// 协议按上游语义做前缀匹配，因此 `destOverride: ["http"]` 可以命中 `http1`。
    /// 上游的 `ipsExcluded` 与 `metadataOnly` 当前未实现。
    pub fn should_override(&self, result: &SniffResult) -> bool {
        if result.domain.is_empty() {
            return false;
        }
        if self.excluded.matches(&result.domain) {
            return false;
        }
        self.settings
            .dest_override
            .iter()
            .any(|pattern| protocol_matches(result.protocol, pattern))
    }
}

/// 协议前缀匹配（上游 `shouldOverride` 的双向前缀比较）。
fn protocol_matches(protocol: &str, pattern: &str) -> bool {
    !pattern.is_empty() && (protocol.starts_with(pattern) || pattern.starts_with(protocol))
}

/// 嗅探一段 payload；返回第一个成功的结果。
///
/// 顺序与上游一致：先 HTTP 后 TLS；仅对 TCP 生效。
pub fn sniff(payload: &[u8], network: Network) -> Option<SniffResult> {
    if network != Network::Tcp || payload.is_empty() {
        return None;
    }
    http::sniff(payload).or_else(|| tls::sniff(payload))
}

/// 在入站握手完成后执行嗅探，并返回「可继续使用」的连接。
///
/// 返回的连接在必要时会把已读取的字节重新接到前端，因此调用方可以照常
/// 把数据转发给出站。`sniffer` 为 `None`（未启用嗅探）时原样返回连接。
pub async fn sniff_and_apply(
    mut conn: Box<dyn Conn>,
    sniffer: Option<&Sniffer>,
    ctx: &mut SessionContext,
) -> Result<Box<dyn Conn>> {
    let Some(sniffer) = sniffer else {
        return Ok(conn);
    };
    let Some(target) = ctx.target.clone() else {
        return Ok(conn);
    };

    let payload = read_initial_payload(&mut conn, ctx.network).await;
    if let Some(result) = sniff(&payload, ctx.network) {
        ctx.protocol = Some(result.protocol.to_string());
        if sniffer.should_override(&result) {
            let domain = Address::domain(result.domain.clone(), target.port);
            let route_only = sniffer.settings().route_only;
            tracing::debug!(
                protocol = result.protocol,
                domain = %result.domain,
                route_only,
                "sniffed destination"
            );
            ctx.set_sniffed(domain, result.protocol.to_string(), route_only);
        }
    }

    if payload.is_empty() {
        Ok(conn)
    } else {
        Ok(Box::new(Prefixed::new(conn, payload)))
    }
}

/// 读取初始 payload：最多两轮、总时限 [`SNIFF_TIMEOUT`]。
///
/// 与上游 `sniffer()` 的两次 `Cache` 尝试一致：第一轮拿到数据即可解析时立即返回，
/// 数据不足时再读一轮。
async fn read_initial_payload(conn: &mut dyn Conn, network: Network) -> Vec<u8> {
    let mut buffer = Vec::new();
    if network != Network::Tcp {
        return buffer;
    }
    let deadline = Instant::now() + SNIFF_TIMEOUT;
    for _ in 0..2 {
        if !read_once(conn, &mut buffer, deadline).await {
            break;
        }
        if sniff(&buffer, network).is_some() {
            break;
        }
    }
    buffer
}

/// 单轮读取：等到有数据、EOF 或超时为止（对齐上游 `ReadMultiBufferTimeout`）。
///
/// 返回 `false` 表示无法再读（EOF / 出错 / 超时 / 缓冲已满）。
async fn read_once(conn: &mut dyn Conn, buffer: &mut Vec<u8>, deadline: Instant) -> bool {
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return false;
    }
    let capacity = SNIFF_BUFFER_SIZE.saturating_sub(buffer.len());
    if capacity == 0 {
        return false;
    }
    let mut chunk = [0u8; READ_CHUNK];
    let limit = capacity.min(READ_CHUNK);
    match timeout(remaining, conn.read(&mut chunk[..limit])).await {
        Ok(Ok(0)) => false,
        Ok(Ok(read)) => {
            buffer.extend_from_slice(&chunk[..read]);
            true
        }
        Ok(Err(_)) => false,
        Err(_) => false,
    }
}

/// 域名合法性：可路由的 ASCII，且不以 `.` 结尾。
fn valid_domain(domain: &str) -> bool {
    !domain.is_empty()
        && domain.len() <= 255
        && !domain.ends_with('.')
        && domain.bytes().all(|byte| byte > b' ' && byte < 0x7f)
}

/// 小写化（仅在有需要时分配）。
fn lower(domain: &str) -> String {
    if domain.bytes().any(|byte| byte.is_ascii_uppercase()) {
        domain.to_ascii_lowercase()
    } else {
        domain.to_string()
    }
}

/// TLS 嗅探（对齐上游 `common/protocol/tls/sniff.go`）。
pub mod tls {
    use super::{lower, valid_domain, SniffResult};

    /// 是否为合法 TLS 版本（主版本号必须为 3）。
    pub fn is_valid_tls_version(major: u8, _minor: u8) -> bool {
        major == 3
    }

    /// 从 TLS record 中提取 SNI。
    ///
    /// 返回 `None` 表示「不是 TLS」或「数据不足」，两种情况都不修改会话目标。
    pub fn sniff(buffer: &[u8]) -> Option<SniffResult> {
        if buffer.len() < 5 {
            return None;
        }
        if buffer[0] != 0x16 || !is_valid_tls_version(buffer[1], buffer[2]) {
            return None;
        }
        let record_len = usize::from(u16::from_be_bytes([buffer[3], buffer[4]]));
        if 5 + record_len > buffer.len() {
            return None;
        }
        read_client_hello(&buffer[5..5 + record_len])
    }

    /// 解析 ClientHello 消息体并提取 `server_name` 扩展。
    pub fn read_client_hello(data: &[u8]) -> Option<SniffResult> {
        if data.len() < 42 {
            return None;
        }
        let session_id_len = usize::from(data[38]);
        if session_id_len > 32 || data.len() < 39 + session_id_len {
            return None;
        }
        let mut data = &data[39 + session_id_len..];
        if data.len() < 2 {
            return None;
        }
        let cipher_suite_len = usize::from(u16::from_be_bytes([data[0], data[1]]));
        if cipher_suite_len % 2 == 1 || data.len() < 2 + cipher_suite_len {
            return None;
        }
        data = &data[2 + cipher_suite_len..];
        if data.is_empty() {
            return None;
        }
        let compression_len = usize::from(data[0]);
        if data.len() < 1 + compression_len {
            return None;
        }
        data = &data[1 + compression_len..];
        if data.len() < 2 {
            return None;
        }
        let extensions_len = usize::from(u16::from_be_bytes([data[0], data[1]]));
        let mut data = &data[2..];
        if extensions_len != data.len() {
            return None;
        }

        while !data.is_empty() {
            if data.len() < 4 {
                return None;
            }
            let extension = u16::from_be_bytes([data[0], data[1]]);
            let length = usize::from(u16::from_be_bytes([data[2], data[3]]));
            data = &data[4..];
            if data.len() < length {
                return None;
            }
            if extension == 0x00 {
                if let Some(domain) = read_server_name(&data[..length]) {
                    return Some(SniffResult {
                        protocol: "tls",
                        domain: lower(&domain),
                    });
                }
            }
            data = &data[length..];
        }
        None
    }

    /// 解析 `server_name` 扩展，返回第一个 `host_name` 条目。
    fn read_server_name(data: &[u8]) -> Option<String> {
        if data.len() < 2 {
            return None;
        }
        let names_len = usize::from(u16::from_be_bytes([data[0], data[1]]));
        let mut data = &data[2..];
        if data.len() != names_len {
            return None;
        }
        while !data.is_empty() {
            if data.len() < 3 {
                return None;
            }
            let name_type = data[0];
            let name_len = usize::from(u16::from_be_bytes([data[1], data[2]]));
            data = &data[3..];
            if data.len() < name_len {
                return None;
            }
            if name_type == 0 {
                let name = std::str::from_utf8(&data[..name_len]).ok()?;
                return valid_domain(name).then(|| name.to_string());
            }
            data = &data[name_len..];
        }
        None
    }
}

/// HTTP 嗅探（对齐上游 `common/protocol/http/sniff.go`）。
pub mod http {
    use super::{lower, valid_domain, SniffResult};

    /// 上游认可的 HTTP 方法（大小写不敏感）。
    const METHODS: [&str; 7] = ["get", "post", "head", "put", "delete", "options", "connect"];

    /// 是否以 HTTP 方法开头；`None` 表示数据不足。
    fn begin_with_http_method(buffer: &[u8]) -> Option<bool> {
        for method in METHODS {
            let bytes = method.as_bytes();
            if buffer.len() < bytes.len() && bytes.starts_with(&buffer.to_ascii_lowercase()) {
                return None;
            }
            if buffer.len() >= bytes.len() && buffer[..bytes.len()].eq_ignore_ascii_case(bytes) {
                return Some(true);
            }
        }
        Some(false)
    }

    /// 从 HTTP/1.x 请求头中提取 `Host`。
    ///
    /// 只解析已经以 `\n` 结尾的完整头行，避免把分片中的半个域名当成 `Host`；
    /// 因此数据不足时返回 `None`，由调用方再读一轮。
    pub fn sniff(buffer: &[u8]) -> Option<SniffResult> {
        if begin_with_http_method(buffer) != Some(true) {
            return None;
        }
        let end = buffer.iter().rposition(|byte| *byte == b'\n')? + 1;
        let head = &buffer[..end];

        let mut host = None;
        for line in head.split(|byte| *byte == b'\n').skip(1) {
            let line = line.strip_suffix(b"\r").unwrap_or(line);
            if line.is_empty() {
                break;
            }
            let Some(colon) = line.iter().position(|byte| *byte == b':') else {
                continue;
            };
            if !line[..colon].eq_ignore_ascii_case(b"host") {
                continue;
            }
            let value = trim_ascii(&line[colon + 1..]);
            let value = std::str::from_utf8(value).ok()?;
            host = parse_host(value);
        }

        let host = host?;
        if !valid_domain(&host) {
            return None;
        }
        Some(SniffResult {
            protocol: "http1",
            domain: lower(&host),
        })
    }

    /// 去除首尾空白。
    fn trim_ascii(mut value: &[u8]) -> &[u8] {
        while let Some((first, rest)) = value.split_first() {
            if first.is_ascii_whitespace() {
                value = rest;
            } else {
                break;
            }
        }
        while let Some((last, rest)) = value.split_last() {
            if last.is_ascii_whitespace() {
                value = rest;
            } else {
                break;
            }
        }
        value
    }

    /// 从 `Host` 值中剥离端口；IPv6 字面量不视为域名。
    fn parse_host(value: &str) -> Option<String> {
        let value = value.trim();
        if value.is_empty() || value.starts_with('[') {
            return None;
        }
        match value.rsplit_once(':') {
            Some((host, port)) if port.chars().all(|c| c.is_ascii_digit()) => {
                Some(host.to_string())
            }
            _ => Some(value.to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 构造最小的 TLS 1.2 ClientHello（含 `server_name` 扩展）。
    fn client_hello_with(server_name: &str, extension_type: u16) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]); // client_version
        body.extend_from_slice(&[0u8; 32]); // random
        body.push(0); // session_id length
        body.extend_from_slice(&[0x00, 0x02, 0x13, 0x01]); // cipher suites
        body.extend_from_slice(&[0x01, 0x00]); // compression methods

        let mut sni = Vec::new();
        sni.extend_from_slice(&((server_name.len() + 3) as u16).to_be_bytes());
        sni.push(0x00); // host_name
        sni.extend_from_slice(&(server_name.len() as u16).to_be_bytes());
        sni.extend_from_slice(server_name.as_bytes());

        let mut extensions = Vec::new();
        extensions.extend_from_slice(&extension_type.to_be_bytes());
        extensions.extend_from_slice(&(sni.len() as u16).to_be_bytes());
        extensions.extend_from_slice(&sni);

        let mut hello_body = body;
        hello_body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        hello_body.extend_from_slice(&extensions);

        let mut hello = Vec::new();
        hello.push(0x01); // handshake type: client_hello
        hello.extend_from_slice(&(hello_body.len() as u32).to_be_bytes()[1..]);
        hello.extend_from_slice(&hello_body);

        let mut record = Vec::new();
        record.push(0x16);
        record.extend_from_slice(&[0x03, 0x01]);
        record.extend_from_slice(&(hello.len() as u16).to_be_bytes());
        record.extend_from_slice(&hello);
        record
    }

    fn client_hello(server_name: &str) -> Vec<u8> {
        client_hello_with(server_name, 0x0000)
    }

    fn settings(dest_override: &[&str], excluded: &[&str], route_only: bool) -> SniffingSettings {
        SniffingSettings {
            enabled: true,
            dest_override: dest_override
                .iter()
                .map(|item| (*item).to_string())
                .collect(),
            domains_excluded: excluded.iter().map(|item| (*item).to_string()).collect(),
            route_only,
        }
    }

    #[test]
    fn tls_sniff_extracts_sni() {
        let result = tls::sniff(&client_hello("Example.COM")).expect("sni");
        assert_eq!(result.protocol, "tls");
        assert_eq!(result.domain, "example.com");
    }

    #[test]
    fn tls_sniff_is_bounds_safe_and_returns_none_for_partial() {
        assert!(tls::sniff(b"definitely not tls").is_none());
        let full = client_hello("a.example.com");
        for cut in 0..full.len() {
            // 任意截断都必须安全返回 None（绝不 panic、绝不误报）。
            assert!(tls::sniff(&full[..cut]).is_none(), "cut at {cut}");
        }
        assert!(tls::sniff(&full).is_some());
    }

    #[test]
    fn tls_sniff_without_server_name_extension() {
        assert!(tls::sniff(&client_hello_with("x.example.com", 0x00ff)).is_none());
    }

    #[test]
    fn http_sniff_extracts_host() {
        let request =
            b"GET /index.html HTTP/1.1\r\nUser-Agent: x\r\nHost: WWW.Example.Net:8080\r\n\r\n";
        let result = http::sniff(request).expect("host");
        assert_eq!(result.protocol, "http1");
        assert_eq!(result.domain, "www.example.net");

        assert_eq!(
            http::sniff(b"POST / HTTP/1.1\nHost: bare.example\n\n")
                .unwrap()
                .domain,
            "bare.example"
        );
        assert!(http::sniff(b"NOTAMETHOD / HTTP/1.1\r\nHost: a.b\r\n\r\n").is_none());
        assert!(http::sniff(b"GET / HTTP/1.1\r\nX-Other: 1\r\n\r\n").is_none());
        assert!(http::sniff(b"GET / HTTP/1.1\r\nHost: [::1]:80\r\n\r\n").is_none());
        // 数据不足：方法不完整 / 头行未结束。
        assert!(http::sniff(b"GE").is_none());
        assert!(http::sniff(b"GET / HTTP/1.1\r\nHost: incomplete.exa").is_none());
        assert!(http::sniff(b"GET / HTTP/1.1\r\n").is_none());
    }

    #[test]
    fn sniff_dispatches_by_network() {
        let request = b"GET / HTTP/1.1\r\nHost: a.b\r\n\r\n";
        assert_eq!(sniff(request, Network::Tcp).unwrap().domain, "a.b");
        assert!(sniff(request, Network::Udp).is_none());
        assert!(sniff(b"", Network::Tcp).is_none());
        assert_eq!(
            sniff(&client_hello("tls.example"), Network::Tcp)
                .unwrap()
                .domain,
            "tls.example"
        );
    }

    #[test]
    fn should_override_follows_dest_override_and_exclusions() {
        let sniffer = Sniffer::build(Some(&settings(
            &["tls"],
            &[
                "domain:blocked.example",
                "full:exact.example",
                "regexp:^ad.*$",
            ],
            false,
        )))
        .unwrap()
        .expect("enabled");

        let tls_result = |domain: &str| SniffResult {
            protocol: "tls",
            domain: domain.to_string(),
        };
        let http_result = |domain: &str| SniffResult {
            protocol: "http1",
            domain: domain.to_string(),
        };

        assert!(sniffer.should_override(&tls_result("ok.example")));
        // destOverride 未包含 http。
        assert!(!sniffer.should_override(&http_result("ok.example")));
        // domainsExcluded：子域、精确、正则。
        assert!(!sniffer.should_override(&tls_result("blocked.example")));
        assert!(!sniffer.should_override(&tls_result("sub.blocked.example")));
        assert!(!sniffer.should_override(&tls_result("exact.example")));
        assert!(!sniffer.should_override(&tls_result("adserver.example")));
        // 空域名永不改写。
        assert!(!sniffer.should_override(&tls_result("")));

        // 前缀匹配：destOverride ["http"] 命中协议 http1。
        let http_sniffer = Sniffer::build(Some(&settings(&["http"], &[], false)))
            .unwrap()
            .unwrap();
        assert!(http_sniffer.should_override(&http_result("ok.example")));
        assert!(!http_sniffer.should_override(&tls_result("ok.example")));
    }

    #[test]
    fn sniffing_disabled_builds_nothing() {
        let disabled = SniffingSettings {
            enabled: false,
            ..settings(&["tls"], &[], false)
        };
        assert!(Sniffer::build(Some(&disabled)).unwrap().is_none());
        assert!(Sniffer::build(None).unwrap().is_none());
    }

    #[test]
    fn route_only_keeps_dial_target_while_routing_uses_domain() {
        let original = Address::domain("1.2.3.4", 443);
        let sniffed = Address::domain("sni.example", 443);

        let mut route_only = SessionContext {
            target: Some(original.clone()),
            ..SessionContext::default()
        };
        route_only.set_sniffed(sniffed.clone(), "tls".to_string(), true);
        assert_eq!(route_only.target.as_ref(), Some(&sniffed));
        assert_eq!(route_only.route_target(), Some(&sniffed));
        assert_eq!(route_only.outbound_target(), Some(&original));
        assert_eq!(route_only.original_target.as_ref(), Some(&original));
        assert_eq!(route_only.protocol.as_deref(), Some("tls"));

        let mut override_mode = SessionContext {
            target: Some(original.clone()),
            ..SessionContext::default()
        };
        override_mode.set_sniffed(sniffed.clone(), "tls".to_string(), false);
        assert_eq!(override_mode.route_target(), Some(&sniffed));
        assert_eq!(override_mode.outbound_target(), Some(&sniffed));
        assert_eq!(override_mode.original_target.as_ref(), Some(&original));
    }
}
