//! VLESS 入站（TCP，protocol version 0）。

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use async_trait::async_trait;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use uuid::Uuid;
use xxxr_common::{Error, Result};
use xxxr_config::VlessInboundSettings;
use xxxr_net::{Address, Listener};

use crate::context::{Network, SessionContext};
use crate::traits::{Dispatcher, InboundHandler};
use crate::vless::{self, Command};

/// VLESS 入站。
pub struct VlessInbound {
    tag: String,
    listener: Arc<Listener>,
    /// 合法用户：UUID -> email。
    users: HashMap<Uuid, String>,
}

impl VlessInbound {
    /// 创建 VLESS 入站；`listener` 必须已完成端口绑定。
    pub fn new(
        tag: impl Into<String>,
        listener: Arc<Listener>,
        settings: VlessInboundSettings,
    ) -> Self {
        let users = settings
            .clients
            .into_iter()
            .map(|client| {
                (
                    client.id,
                    client.email.unwrap_or_else(|| client.id.to_string()),
                )
            })
            .collect();
        Self {
            tag: tag.into(),
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
impl InboundHandler for VlessInbound {
    fn tag(&self) -> &str {
        &self.tag
    }

    async fn listen(&self, dispatcher: Arc<dyn Dispatcher>) -> Result<()> {
        let listener = self.listener.to_tokio()?;
        let local = self.listener.local_addr();
        tracing::info!(tag = %self.tag, %local, "vless inbound listening");
        loop {
            let (stream, peer) = match listener.accept().await {
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
            tokio::spawn(async move {
                match handle_connection(stream, peer, &listener, &users, &inbound_tag, &dispatcher)
                    .await
                {
                    Ok(()) => tracing::debug!(%peer, "vless session finished"),
                    Err(e) => tracing::debug!(%peer, "vless session closed: {e}"),
                }
            });
        }
    }
}

async fn handle_connection(
    stream: TcpStream,
    peer: SocketAddr,
    listener: &Listener,
    users: &HashMap<Uuid, String>,
    inbound_tag: &str,
    dispatcher: &Arc<dyn Dispatcher>,
) -> Result<()> {
    let mut conn = listener.accept_stream(stream, peer).await?;
    let request = vless::read_request(&mut conn).await?;
    let user = users
        .get(&request.user_id)
        .ok_or_else(|| Error::protocol(format!("vless: unknown user id {}", request.user_id)))?;
    if request.command != Command::Tcp {
        return Err(Error::unsupported(format!(
            "vless command {:?}",
            request.command
        )));
    }
    tracing::debug!(%peer, user = %user, dest = %request.dest, "vless request");

    // 回写响应头：原样回显客户端 addons（当前版本不承载流控语义）。
    let response = vless::encode_response(&request.addons);
    conn.write_all(&response).await?;
    conn.flush().await?;

    let mut ctx = SessionContext::new(inbound_tag.to_string(), Some(Address::from(peer)));
    ctx.target = Some(request.dest);
    ctx.network = Network::Tcp;
    dispatcher.dispatch(&mut ctx, &mut *conn).await
}
