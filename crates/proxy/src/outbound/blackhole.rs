//! Blackhole 出站：直接关闭连接。

use async_trait::async_trait;
use xxxr_common::Result;
use xxxr_net::{Address, Conn};

use crate::context::SessionContext;
use crate::traits::OutboundHandler;

/// Blackhole 出站，对应 Xray 的 `blackhole`。
///
/// 当前实现直接关闭入站连接（配置中的 `response` 字段被接受但忽略）。
pub struct Blackhole {
    tag: String,
}

impl Blackhole {
    /// 创建 Blackhole 出站。
    pub fn new(tag: impl Into<String>) -> Self {
        Self { tag: tag.into() }
    }
}

#[async_trait]
impl OutboundHandler for Blackhole {
    fn tag(&self) -> &str {
        &self.tag
    }

    async fn dial(
        &self,
        _ctx: &mut SessionContext,
        _dest: Address,
        _out: &mut dyn Conn,
    ) -> Result<()> {
        Ok(())
    }
}
