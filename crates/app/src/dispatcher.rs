//! 分发器：维护 `tag -> outbound` 表并按路由选择出站。

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use xxxr_common::{Error, Result};
use xxxr_net::Conn;
use xxxr_proxy::{Dispatcher as DispatcherApi, OutboundHandler, SessionContext};

use crate::router::Router;

/// 出站分发器。
pub struct Dispatcher {
    outbounds: HashMap<String, Arc<dyn OutboundHandler>>,
    router: Router,
    default_tag: Option<String>,
}

impl Dispatcher {
    /// 创建分发器。
    ///
    /// `default_tag` 为路由未命中时使用的出站 tag（通常是第一个出站）。
    pub fn new(
        outbounds: HashMap<String, Arc<dyn OutboundHandler>>,
        router: Router,
        default_tag: Option<String>,
    ) -> Self {
        Self {
            outbounds,
            router,
            default_tag,
        }
    }

    /// 按 tag 取出出站处理器。
    pub fn outbound(&self, tag: &str) -> Option<&Arc<dyn OutboundHandler>> {
        self.outbounds.get(tag)
    }

    /// 返回已注册的出站数量。
    pub fn outbound_count(&self) -> usize {
        self.outbounds.len()
    }

    /// 为会话选择出站 tag：先匹配路由规则，再回退到默认出站。
    pub fn select_tag(&self, ctx: &SessionContext) -> Option<String> {
        self.router
            .pick(ctx)
            .map(str::to_string)
            .or_else(|| self.default_tag.clone())
    }
}

#[async_trait]
impl DispatcherApi for Dispatcher {
    async fn dispatch(&self, ctx: &mut SessionContext, out: &mut dyn Conn) -> Result<()> {
        let target = ctx
            .target
            .clone()
            .ok_or_else(|| Error::protocol("session has no target address".to_string()))?;
        let tag = self
            .select_tag(ctx)
            .ok_or_else(|| Error::config("no outbound configured".to_string()))?;
        let handler = self
            .outbounds
            .get(&tag)
            .ok_or_else(|| Error::config(format!("unknown outbound `{tag}`")))?;
        ctx.outbound_tag = Some(tag.clone());
        tracing::debug!(
            inbound = ?ctx.inbound_tag,
            outbound = %tag,
            %target,
            "dispatching session"
        );
        handler.dial(ctx, target, out).await
    }
}
