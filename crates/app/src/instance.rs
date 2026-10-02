//! 实例：从配置装配出站、路由与入站，并可启动与优雅关闭。

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::watch;
use tokio::task::JoinHandle;
use xxxr_common::Result;
use xxxr_config::Config;
use xxxr_proxy::{build_inbound, build_outbound, InboundHandler, OutboundHandler, Sniffer};

use crate::dispatcher::Dispatcher;
use crate::router::Router;

/// 关闭时等待入站任务退出的最长时间。
pub const SHUTDOWN_GRACE: Duration = Duration::from_secs(5);

/// 单个入站的运行时状态。
struct InboundRuntime {
    handler: Arc<dyn InboundHandler>,
    sniffer: Option<Arc<Sniffer>>,
}

/// 一个由配置装配而成的实例。
///
/// [`Instance::new`] 会完成全部端口绑定与路由编译，因此端口冲突、配置错误
/// 会立即返回；[`Instance::start`] 只是把入站的 accept 循环放进后台任务。
pub struct Instance {
    config: Config,
    dispatcher: Arc<Dispatcher>,
    inbounds: Vec<InboundRuntime>,
    shutdown_tx: watch::Sender<bool>,
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
        let router = Router::new(config.routing.as_ref())?;
        let default_tag = config.default_outbound_tag().map(str::to_string);
        let dispatcher = Arc::new(Dispatcher::new(outbounds, router, default_tag));

        let mut inbounds = Vec::new();
        for inbound in &config.inbounds {
            let handler = build_inbound(inbound)?;
            let sniffer = Sniffer::build(inbound.sniffing.as_ref())?.map(Arc::new);
            inbounds.push(InboundRuntime { handler, sniffer });
        }

        let (shutdown_tx, _) = watch::channel(false);
        Ok(Self {
            config,
            dispatcher,
            inbounds,
            shutdown_tx,
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
        self.inbounds
            .iter()
            .map(|runtime| runtime.handler.tag())
            .collect()
    }

    /// 返回启用了嗅探的入站数量。
    pub fn sniffing_inbound_count(&self) -> usize {
        self.inbounds
            .iter()
            .filter(|runtime| runtime.sniffer.is_some())
            .count()
    }

    /// 启动全部入站监听，返回启动的任务数量。
    pub fn start(&mut self) -> usize {
        for runtime in &self.inbounds {
            let dispatcher = Arc::clone(&self.dispatcher);
            let shutdown = self.shutdown_tx.subscribe();
            let handler = Arc::clone(&runtime.handler);
            let sniffer = runtime.sniffer.clone();
            self.tasks.push(tokio::spawn(async move {
                if let Err(e) = handler.listen(dispatcher, shutdown, sniffer).await {
                    tracing::error!(tag = %handler.tag(), "inbound stopped: {e}");
                }
            }));
        }
        self.tasks.len()
    }

    /// 优雅关闭：先通知入站停止接受新连接，再等待其任务退出。
    ///
    /// 等待上限为 [`SHUTDOWN_GRACE`]；超时仍未退出的任务会被中止。
    pub async fn shutdown(&mut self) {
        let _ = self.shutdown_tx.send(true);
        for mut task in self.tasks.drain(..) {
            tokio::select! {
                _ = &mut task => {}
                _ = tokio::time::sleep(SHUTDOWN_GRACE) => {
                    tracing::warn!("inbound did not stop in time; aborting its task");
                    task.abort();
                }
            }
        }
    }

    /// 等待全部入站任务结束（通常只在出错时返回）。
    pub async fn wait(&mut self) {
        for task in self.tasks.drain(..) {
            let _ = task.await;
        }
    }
}
