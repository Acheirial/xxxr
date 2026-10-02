//! Trojan 出站。

use std::sync::atomic::{AtomicUsize, Ordering};

use async_trait::async_trait;
use tokio::io::AsyncWriteExt;
use xxxr_common::{Error, Result};
use xxxr_net::{Address, Conn, Dialer, StreamSettings};

use crate::context::SessionContext;
use crate::relay;
use crate::traits::OutboundHandler;
use crate::trojan::{self, COMMAND_TCP};

/// 一台上游服务器及其派生的认证键。
struct ServerEntry {
    address: Address,
    key: String,
}

/// Trojan 出站。
///
/// Trojan 在传输层上依赖 TLS，但具体由 `streamSettings` 决定：安全类型不是 `tls`
/// 时仍然按配置工作，只是会在构造时告警（明文传输不安全）。
pub struct TrojanOutbound {
    tag: String,
    dialer: Dialer,
    servers: Vec<ServerEntry>,
    next: AtomicUsize,
}

impl TrojanOutbound {
    /// 创建 Trojan 出站；`servers` 为归一化后的 `(地址, 明文密码)` 列表。
    pub fn new(
        tag: impl Into<String>,
        servers: Vec<(Address, String)>,
        settings: StreamSettings,
    ) -> Self {
        let tag = tag.into();
        if servers.len() > 1 {
            tracing::debug!(outbound = %tag, count = servers.len(), "trojan servers will be round-robined");
        }
        if settings.security != xxxr_net::Security::Tls {
            tracing::warn!(
                outbound = %tag,
                security = settings.security.as_str(),
                "trojan is configured without TLS; the wire format will be sent in clear text"
            );
        }
        let servers = servers
            .into_iter()
            .map(|(address, password)| ServerEntry {
                address,
                key: trojan::password_key(&password),
            })
            .collect();
        Self {
            tag,
            dialer: Dialer::new(settings),
            servers,
            next: AtomicUsize::new(0),
        }
    }

    /// 轮询选择一台服务器。
    fn pick(&self) -> Result<&ServerEntry> {
        if self.servers.is_empty() {
            return Err(Error::config("trojan outbound has no server".to_string()));
        }
        let index = self.next.fetch_add(1, Ordering::Relaxed) % self.servers.len();
        Ok(&self.servers[index])
    }
}

#[async_trait]
impl OutboundHandler for TrojanOutbound {
    fn tag(&self) -> &str {
        &self.tag
    }

    async fn dial(
        &self,
        _ctx: &mut SessionContext,
        dest: Address,
        out: &mut dyn Conn,
    ) -> Result<()> {
        let server = self.pick()?;
        let mut remote = self.dialer.dial(&server.address).await?;
        let header = trojan::encode_request(&server.key, &dest, COMMAND_TCP)?;
        remote.write_all(&header).await?;
        remote.flush().await?;
        relay::pump(out, &mut *remote).await
    }
}
