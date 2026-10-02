//! 入站 / 出站 / 分发器抽象。

use std::sync::Arc;

use async_trait::async_trait;
use xxxr_common::Result;
use xxxr_net::{Address, Conn};

use crate::context::SessionContext;

/// 出站处理器：把入站连接接到目标地址。
#[async_trait]
pub trait OutboundHandler: Send + Sync {
    /// 返回该出站在配置中的唯一 tag。
    fn tag(&self) -> &str;

    /// 拨号到 `dest`，并在 `out`（入站侧连接）与远端之间双向转发数据，
    /// 直到任一端关闭或发生错误。
    async fn dial(&self, ctx: &mut SessionContext, dest: Address, out: &mut dyn Conn)
        -> Result<()>;
}

/// 入站处理器：监听端口并把接受到的连接交给分发器。
#[async_trait]
pub trait InboundHandler: Send + Sync {
    /// 返回该入站在配置中的唯一 tag。
    fn tag(&self) -> &str;

    /// 启动监听；该 future 只有在监听被关闭或出错时才会返回。
    async fn listen(&self, dispatcher: Arc<dyn Dispatcher>) -> Result<()>;
}

/// 分发器：根据会话上下文选择出站并完成数据转发。
#[async_trait]
pub trait Dispatcher: Send + Sync {
    /// 处理一条已完成入站协议握手的连接。
    async fn dispatch(&self, ctx: &mut SessionContext, out: &mut dyn Conn) -> Result<()>;
}
