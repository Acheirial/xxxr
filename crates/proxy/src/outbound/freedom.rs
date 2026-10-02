//! Freedom 出站：直连目标地址。

use async_trait::async_trait;
use xxxr_common::Result;
use xxxr_net::{Address, Conn, Dialer, StreamSettings};

use crate::context::SessionContext;
use crate::relay;
use crate::traits::OutboundHandler;

/// Freedom 出站，对应 Xray 的 `freedom`。
pub struct Freedom {
    tag: String,
    dialer: Dialer,
}

impl Freedom {
    /// 创建 Freedom 出站；`settings` 为该出站自身的 `streamSettings`（通常为空）。
    pub fn new(tag: impl Into<String>, settings: StreamSettings) -> Self {
        Self {
            tag: tag.into(),
            dialer: Dialer::new(settings),
        }
    }
}

#[async_trait]
impl OutboundHandler for Freedom {
    fn tag(&self) -> &str {
        &self.tag
    }

    async fn dial(
        &self,
        _ctx: &mut SessionContext,
        dest: Address,
        out: &mut dyn Conn,
    ) -> Result<()> {
        let mut remote = self.dialer.dial(&dest).await?;
        relay::pump(out, &mut *remote).await
    }
}
