//! 出站拨号器。

use std::net::SocketAddr;
use std::time::Duration;

use tokio::net::TcpStream;
use xxxr_common::{Error, Result};

use crate::address::Address;
use crate::conn::Conn;
use crate::transport::StreamSettings;

/// 默认拨号超时。
pub const DEFAULT_DIAL_TIMEOUT: Duration = Duration::from_secs(10);

/// 出站拨号器：按 [`StreamSettings`] 建立到目标地址的连接。
#[derive(Debug, Clone)]
pub struct Dialer {
    settings: StreamSettings,
    timeout: Duration,
}

impl Dialer {
    /// 使用给定传输配置创建拨号器。
    pub fn new(settings: StreamSettings) -> Self {
        Self {
            settings,
            timeout: DEFAULT_DIAL_TIMEOUT,
        }
    }

    /// 覆盖拨号超时。
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// 返回该拨号器使用的传输配置。
    pub fn settings(&self) -> &StreamSettings {
        &self.settings
    }

    /// 解析目标地址为套接字地址列表。
    pub async fn resolve(dest: &Address) -> Result<Vec<SocketAddr>> {
        if let Some(ip) = dest.ip {
            return Ok(vec![SocketAddr::new(ip, dest.port)]);
        }
        let domain = dest
            .domain
            .as_deref()
            .ok_or_else(|| Error::Address("address has neither ip nor domain".to_string()))?;
        let addrs: Vec<SocketAddr> = tokio::net::lookup_host((domain, dest.port))
            .await
            .map_err(|e| Error::Address(format!("resolve `{domain}` failed: {e}")))?
            .collect();
        if addrs.is_empty() {
            return Err(Error::Address(format!(
                "resolve `{domain}` returned no address"
            )));
        }
        Ok(addrs)
    }

    /// 拨号到 `dest` 并完成传输层（TLS / WebSocket）握手。
    pub async fn dial(&self, dest: &Address) -> Result<Box<dyn Conn>> {
        let addrs = Self::resolve(dest).await?;
        let mut last_error = None;
        for addr in addrs {
            match tokio::time::timeout(self.timeout, TcpStream::connect(addr)).await {
                Ok(Ok(stream)) => {
                    let _ = stream.set_nodelay(true);
                    return self.settings.wrap_client(stream, dest).await;
                }
                Ok(Err(e)) => last_error = Some(Error::Io(e)),
                Err(_) => {
                    last_error = Some(Error::Other(format!("dial {addr} timed out")));
                }
            }
        }
        Err(last_error.unwrap_or_else(|| Error::Other(format!("dial {dest} failed"))))
    }
}
