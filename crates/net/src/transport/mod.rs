//! 传输层配置模型与组合逻辑。
//!
//! 对应 Xray 的 `streamSettings`：`network` 决定传输类型，`security` 决定是否
//! 套用 TLS；组合顺序为 TCP → TLS → WebSocket（即 `ws` over `tls`）。

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use tokio::net::TcpStream;
use xxxr_common::{Error, Result};

use crate::address::Address;
use crate::conn::Conn;

pub mod tls;
pub mod ws;

pub use tls::{Certificate, TlsSettings};

/// 传输层网络类型，对应 Xray `streamSettings.network`。
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum Transport {
    /// 纯 TCP（Xray 中亦写作 `raw`/`tcp`）。
    #[default]
    Tcp,
    /// WebSocket。
    Ws,
    /// 未识别的其他传输，保留配置原值。
    Other(String),
}

impl Transport {
    /// 返回配置中的字符串表示。
    pub fn as_str(&self) -> &str {
        match self {
            Self::Tcp => "tcp",
            Self::Ws => "ws",
            Self::Other(name) => name,
        }
    }
}

impl Serialize for Transport {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for Transport {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        let raw = String::deserialize(deserializer)?;
        Ok(match raw.to_ascii_lowercase().as_str() {
            "tcp" | "raw" => Self::Tcp,
            "ws" | "websocket" => Self::Ws,
            _ => Self::Other(raw),
        })
    }
}

/// 传输层安全类型，对应 Xray `streamSettings.security`。
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum Security {
    /// 不加密。
    #[default]
    None,
    /// TLS。
    Tls,
    /// 未识别的其他安全类型，保留配置原值。
    Other(String),
}

impl Security {
    /// 返回配置中的字符串表示。
    pub fn as_str(&self) -> &str {
        match self {
            Self::None => "none",
            Self::Tls => "tls",
            Self::Other(name) => name,
        }
    }
}

impl Serialize for Security {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for Security {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        let raw = String::deserialize(deserializer)?;
        Ok(match raw.to_ascii_lowercase().as_str() {
            "none" | "" => Self::None,
            "tls" => Self::Tls,
            _ => Self::Other(raw),
        })
    }
}

/// Xray 风格的传输层配置（`streamSettings`）。
///
/// 未知字段会被忽略；缺省时等价于「TCP + 不加密」。
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct StreamSettings {
    /// 传输层类型，对应 `network`。
    pub network: Transport,
    /// 安全类型，对应 `security`。
    pub security: Security,
    /// TLS 参数，对应 `tlsSettings`。
    pub tls_settings: Option<TlsSettings>,
    /// WebSocket 参数，对应 `wsSettings`。
    pub ws_settings: Option<WsSettings>,
}

impl StreamSettings {
    /// 客户端：在已建立的 TCP 连接之上依次套用 TLS、WebSocket。
    pub async fn wrap_client(&self, stream: TcpStream, dest: &Address) -> Result<Box<dyn Conn>> {
        let mut conn: Box<dyn Conn> = Box::new(stream);
        if self.security == Security::Tls {
            let tls_settings = self.tls_settings.clone().unwrap_or_default();
            let server_name = tls_settings
                .server_name
                .clone()
                .unwrap_or_else(|| dest.host());
            if server_name.is_empty() {
                return Err(Error::Tls("missing server name for TLS".to_string()));
            }
            conn = tls::wrap_client(conn, &tls_settings, &server_name).await?;
        }
        match &self.network {
            Transport::Tcp => {}
            Transport::Ws => {
                let ws_settings = self.ws_settings.clone().unwrap_or_default();
                let host = ws_settings.host.clone().unwrap_or_else(|| dest.host());
                conn = ws::wrap_client(conn, &ws_settings, &host).await?;
            }
            Transport::Other(name) => {
                return Err(Error::unsupported(format!("transport `{name}`")));
            }
        }
        Ok(conn)
    }

    /// 服务端：对已接受的 TCP 流依次完成 TLS、WebSocket 握手。
    pub async fn wrap_server(&self, stream: TcpStream) -> Result<Box<dyn Conn>> {
        let mut conn: Box<dyn Conn> = Box::new(stream);
        if self.security == Security::Tls {
            let tls_settings = self.tls_settings.clone().ok_or_else(|| {
                Error::Tls("`tlsSettings` is required when security is `tls`".to_string())
            })?;
            conn = tls::wrap_server(conn, &tls_settings).await?;
        }
        match &self.network {
            Transport::Tcp => {}
            Transport::Ws => {
                let ws_settings = self.ws_settings.clone().unwrap_or_default();
                conn = ws::wrap_server(conn, &ws_settings).await?;
            }
            Transport::Other(name) => {
                return Err(Error::unsupported(format!("transport `{name}`")));
            }
        }
        Ok(conn)
    }
}

/// Xray `streamSettings.wsSettings` 的模型。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct WsSettings {
    /// 握手路径，默认 `/`。
    pub path: String,
    /// `Host` 请求头覆盖值。
    pub host: Option<String>,
    /// 额外请求头（`Host` 键会被 [`WsSettings::host`] 取代）。
    pub headers: Option<std::collections::HashMap<String, String>>,
}

impl Default for WsSettings {
    fn default() -> Self {
        Self {
            path: "/".to_string(),
            host: None,
            headers: None,
        }
    }
}
