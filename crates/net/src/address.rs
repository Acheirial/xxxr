//! 目标地址模型。

use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;

use xxxr_common::Error;

/// 目标地址：`ip` 与 `domain` 二选一，另外携带端口。
///
/// 支持 `FromStr` 解析 `host:port` 形式（IPv6 需写成 `[::1]:443`），
/// `Display` 输出同样的形式。
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Address {
    /// IPv4 / IPv6 地址；与 [`Address::domain`] 互斥。
    pub ip: Option<IpAddr>,
    /// 域名（统一小写）；与 [`Address::ip`] 互斥。
    pub domain: Option<String>,
    /// 端口。
    pub port: u16,
}

impl Address {
    /// 使用域名构造地址（自动转为小写）。
    pub fn domain(domain: impl Into<String>, port: u16) -> Self {
        Self {
            ip: None,
            domain: Some(domain.into().to_ascii_lowercase()),
            port,
        }
    }

    /// 使用 IP 构造地址。
    pub fn ip(ip: IpAddr, port: u16) -> Self {
        Self {
            ip: Some(ip),
            domain: None,
            port,
        }
    }

    /// 是否以域名表示。
    pub fn is_domain(&self) -> bool {
        self.domain.is_some()
    }

    /// 返回主机部分（域名或 IP 字符串），用于 TLS SNI / HTTP `Host`。
    pub fn host(&self) -> String {
        match (&self.domain, self.ip) {
            (Some(domain), _) => domain.clone(),
            (None, Some(ip)) => ip.to_string(),
            (None, None) => String::new(),
        }
    }
}

impl From<SocketAddr> for Address {
    fn from(value: SocketAddr) -> Self {
        Self::ip(value.ip(), value.port())
    }
}

impl FromStr for Address {
    type Err = Error;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let value = value.trim();
        if value.is_empty() {
            return Err(Error::Address("empty address".to_string()));
        }
        if let Ok(socket) = value.parse::<SocketAddr>() {
            return Ok(Self::ip(socket.ip(), socket.port()));
        }
        let (host, port) = value
            .rsplit_once(':')
            .ok_or_else(|| Error::Address(format!("missing port in `{value}`")))?;
        let port = port
            .parse::<u16>()
            .map_err(|_| Error::Address(format!("invalid port `{port}` in `{value}`")))?;
        let host = host.trim_start_matches('[').trim_end_matches(']');
        if host.is_empty() {
            return Err(Error::Address(format!("missing host in `{value}`")));
        }
        match host.parse::<IpAddr>() {
            Ok(ip) => Ok(Self::ip(ip, port)),
            Err(_) => Ok(Self::domain(host, port)),
        }
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match (&self.domain, self.ip) {
            (Some(domain), _) => write!(f, "{domain}:{}", self.port),
            (None, Some(IpAddr::V6(v6))) => write!(f, "[{v6}]:{}", self.port),
            (None, Some(ip)) => write!(f, "{ip}:{}", self.port),
            (None, None) => write!(f, ":{}", self.port),
        }
    }
}
