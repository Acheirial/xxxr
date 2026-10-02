//! 实例：从配置装配出站、路由与入站，并可启动/关闭。

use std::collections::HashMap;
use std::sync::Arc;

use tokio::task::JoinHandle;
use xxxr_common::Result;
use xxxr_config::Config;
use xxxr_proxy::{build_inbound, build_outbound, InboundHandler, OutboundHandler};

use crate::dispatcher::Dispatcher;
use crate::router::Router;

/// 一个由配置装配而成的实例。
///
/// [`Instance::new`] 会完成全部端口绑定，因此端口冲突会立即返回错误；
/// [`Instance::start`] 只是把入站的 accept 循环放进后台任务。
pub struct Instance {
    config: Config,
    dispatcher: Arc<Dispatcher>,
    inbounds: Vec<Arc<dyn InboundHandler>>,
    tasks: Vec<JoinHandle<()>>,
}

impl Instance {
    /// 依据配置装配实例。
    pub fn new(config: Config) -> Result<Self> {
        config.validate()?;
        let mut outbounds: HashMap<String, Arc<dyn OutboundHandler>> = HashMap::new();
        for outbound in &config.outbounds {
            let handler = build_outbound(outbound)?;
            outbounds.insert(handler.tag().to_string(), handler);
        }
        let router = Router::new(config.routing.as_ref());
        let default_tag = config.default_outbound_tag().map(str::to_string);
        let dispatcher = Arc::new(Dispatcher::new(outbounds, router, default_tag));

        let mut inbounds = Vec::new();
        for inbound in &config.inbounds {
            inbounds.push(build_inbound(inbound)?);
        }

        Ok(Self {
            config,
            dispatcher,
            inbounds,
            tasks: Vec::new(),
        })
    }

    /// 返回实例使用的配置。
    pub fn config(&self) -> &Config {
        &self.config
    }

    /// 返回分发器。
    pub fn dispatcher(&self) -> &Arc<Dispatcher> {
        &self.dispatcher
    }

    /// 返回入站 tag 列表。
    pub fn inbound_tags(&self) -> Vec<&str> {
        self.inbounds.iter().map(|inbound| inbound.tag()).collect()
    }

    /// 启动全部入站监听，返回启动的任务数量。
    pub fn start(&mut self) -> usize {
        for inbound in &self.inbounds {
            let dispatcher = Arc::clone(&self.dispatcher);
            let inbound = Arc::clone(inbound);
            self.tasks.push(tokio::spawn(async move {
                if let Err(e) = inbound.listen(dispatcher).await {
                    tracing::error!(tag = %inbound.tag(), "inbound stopped: {e}");
                }
            }));
        }
        self.tasks.len()
    }

    /// 关闭实例：中止全部入站任务。
    pub fn shutdown(&mut self) {
        for task in self.tasks.drain(..) {
            task.abort();
        }
    }

    /// 等待全部入站任务结束（通常只在出错时返回）。
    pub async fn wait(&mut self) {
        for task in self.tasks.drain(..) {
            let _ = task.await;
        }
    }
}
