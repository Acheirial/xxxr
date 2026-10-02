//! VLESS 出站（TCP，protocol version 0）。

use async_trait::async_trait;
use tokio::io::AsyncWriteExt;
use uuid::Uuid;
use xxxr_common::Result;
use xxxr_net::{Address, Conn, Dialer, StreamSettings};

use crate::context::SessionContext;
use crate::relay;
use crate::traits::OutboundHandler;
use crate::vless::{self, Command, RequestHeader};

/// VLESS 出站。
pub struct VlessOutbound {
    tag: String,
    dialer: Dialer,
    server: Address,
    user_id: Uuid,
}

impl VlessOutbound {
    /// 创建 VLESS 出站。
    ///
    /// `server` 为上游 VLESS 服务器地址，`settings` 为该出站自身的
    /// `streamSettings`（可套用 TCP / WebSocket / TLS）。
    pub fn new(
        tag: impl Into<String>,
        server: Address,
        user_id: Uuid,
        settings: StreamSettings,
    ) -> Self {
        Self {
            tag: tag.into(),
            dialer: Dialer::new(settings),
            server,
            user_id,
        }
    }
}

#[async_trait]
impl OutboundHandler for VlessOutbound {
    fn tag(&self) -> &str {
        &self.tag
    }

    async fn dial(
        &self,
        _ctx: &mut SessionContext,
        dest: Address,
        out: &mut dyn Conn,
    ) -> Result<()> {
        let mut remote = self.dialer.dial(&self.server).await?;
        let header = vless::encode_request(&RequestHeader {
            user_id: self.user_id,
            addons: Vec::new(),
            command: Command::Tcp,
            dest,
        })?;
        remote.write_all(&header).await?;
        remote.flush().await?;
        // 读取响应头（addons 当前版本不承载语义）。
        let _addons = vless::read_response(&mut remote).await?;
        relay::pump(out, &mut *remote).await
    }
}
