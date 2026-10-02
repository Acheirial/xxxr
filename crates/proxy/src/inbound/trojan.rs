//! Trojan 入站。

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use async_trait::async_trait;
use tokio::net::TcpStream;
use xxxr_common::{Error, Result};
use xxxr_config::TrojanInboundSettings;
use xxxr_net::{Address, Listener};

use crate::context::{Network, SessionContext};
use crate::sniff::{sniff_and_apply, Sniffer};
use crate::traits::{Dispatcher, InboundHandler, ShutdownSignal};
use crate::trojan::{self, COMMAND_TCP};

/// Trojan 入站。
///
/// 认证失败（键未知或首帧不合法）且未配置 `fallbacks` 时，按上游语义直接关闭连接
/// 并记录日志；本版本尚未实现回落转发。
pub struct TrojanInbound {
    tag: String,
    listener: Arc<Listener>,
    /// 认证键（56 字符 hex）→ 用户标识（email 或密码占位）。
    users: HashMap<String, String>,
}

impl TrojanInbound {
    /// 创建 Trojan 入站；`listener` 必须已完成端口绑定。
    pub fn new(
        tag: impl Into<String>,
        listener: Arc<Listener>,
        settings: TrojanInboundSettings,
    ) -> Self {
        let tag = tag.into();
        if settings.fallbacks.is_some() {
            tracing::warn!(
                inbound = %tag,
                "trojan `fallbacks` is not implemented yet; invalid authentication closes the connection"
            );
        }
        let users = settings
            .all_clients()
            .into_iter()
            .map(|client| {
                let key = trojan::password_key(&client.password);
                let label = client.email.clone().unwrap_or_else(|| format!("{key:.8}"));
                (key, label)
            })
            .collect();
        Self {
            tag,
            listener,
            users,
        }
    }

    /// 返回实际监听地址。
    pub fn local_addr(&self) -> SocketAddr {
        self.listener.local_addr()
    }

    /// 返回已登记的用户数量。
    pub fn user_count(&self) -> usize {
        self.users.len()
    }
}

#[async_trait]
impl InboundHandler for TrojanInbound {
    fn tag(&self) -> &str {
        &self.tag
    }

    async fn listen(
        &self,
        dispatcher: Arc<dyn Dispatcher>,
        mut shutdown: ShutdownSignal,
        sniffer: Option<Arc<Sniffer>>,
    ) -> Result<()> {
        let listener = self.listener.to_tokio()?;
        let local = self.listener.local_addr();
        tracing::info!(
            tag = %self.tag,
            %local,
            users = self.users.len(),
            sniffing = sniffer.is_some(),
            "trojan inbound listening"
        );
        loop {
            let accepted = tokio::select! {
                _ = shutdown.changed() => {
                    tracing::info!(tag = %self.tag, "trojan inbound stopped accepting connections");
                    return Ok(());
                }
                accepted = listener.accept() => accepted,
            };
            let (stream, peer) = match accepted {
                Ok(pair) => pair,
                Err(e) => {
                    tracing::warn!(tag = %self.tag, "accept failed: {e}");
                    continue;
                }
            };
            let inbound_tag = self.tag.clone();
            let users = self.users.clone();
            let listener = Arc::clone(&self.listener);
            let dispatcher = Arc::clone(&dispatcher);
            let sniffer = sniffer.clone();
            tokio::spawn(async move {
                match handle_connection(
                    stream,
                    peer,
                    &listener,
                    &users,
                    &inbound_tag,
                    &dispatcher,
                    sniffer.as_deref(),
                )
                .await
                {
                    Ok(()) => tracing::debug!(%peer, "trojan session finished"),
                    Err(e) => tracing::debug!(%peer, "trojan session closed: {e}"),
                }
            });
        }
    }
}

async fn handle_connection(
    stream: TcpStream,
    peer: SocketAddr,
    listener: &Listener,
    users: &HashMap<String, String>,
    inbound_tag: &str,
    dispatcher: &Arc<dyn Dispatcher>,
    sniffer: Option<&Sniffer>,
) -> Result<()> {
    let mut conn = listener.accept_stream(stream, peer).await?;
    let request = trojan::read_request(&mut conn).await?;

    let user = match users.get(&request.key) {
        Some(user) => user.clone(),
        None => {
            // 上游语义：无 fallback 配置时直接关闭并记日志。
            tracing::warn!(%peer, "trojan: unknown user, closing connection");
            return Err(Error::protocol("trojan: invalid user".to_string()));
        }
    };
    if request.command != COMMAND_TCP {
        return Err(Error::unsupported(format!(
            "trojan command {} (UDP is not implemented)",
            request.command
        )));
    }
    tracing::debug!(%peer, user = %user, dest = %request.dest, "trojan request");

    let mut ctx = SessionContext::new(inbound_tag.to_string(), Some(Address::from(peer)));
    ctx.target = Some(request.dest);
    ctx.network = Network::Tcp;

    // 上游语义：入站协议握手完成后、路由之前执行嗅探。
    let mut conn = sniff_and_apply(conn, sniffer, &mut ctx).await?;
    dispatcher.dispatch(&mut ctx, &mut *conn).await
}
