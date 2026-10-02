//! 命令行接口。

use std::path::{Path, PathBuf};

use clap::{Parser, Subcommand};
use xxxr_common::{logging::init_logging, Result};
use xxxr_config::Config;

use crate::instance::Instance;

/// xxxr：Xray-core 的 Rust 重写实现。
#[derive(Debug, Parser)]
#[command(
    name = "xxxr",
    version,
    about = "xxxr: a Rust rewrite of Xray-core",
    long_about = None
)]
pub struct Cli {
    /// 配置文件路径（JSON）。
    #[arg(short, long, value_name = "FILE", global = true)]
    pub config: Option<PathBuf>,

    /// 子命令。
    #[command(subcommand)]
    pub command: Command,
}

/// 子命令。
#[derive(Debug, Subcommand)]
pub enum Command {
    /// 按配置文件启动实例。
    Run,
    /// 打印版本信息。
    Version,
}

/// 版本字符串。
pub fn version_string() -> String {
    format!(
        "xxxr {} ({})",
        env!("CARGO_PKG_VERSION"),
        env!("CARGO_PKG_REPOSITORY")
    )
}

/// 加载配置并运行实例，直到收到 `SIGINT`（Ctrl-C）或 `SIGTERM`。
pub async fn run(config_path: &Path) -> Result<()> {
    let config = Config::load(config_path)?;
    init_logging(config.log.loglevel);
    let mut instance = Instance::new(config)?;
    let started = instance.start();
    tracing::info!(
        "xxxr started, {started} inbound(s) listening; press Ctrl-C or send SIGTERM to stop"
    );
    wait_for_shutdown_signal().await;
    tracing::info!("shutting down");
    instance.shutdown().await;
    Ok(())
}

/// 等待关闭信号：`SIGINT` 与 `SIGTERM` 走同一条优雅关闭路径。
async fn wait_for_shutdown_signal() {
    #[cfg(unix)]
    {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut terminate) => {
                tokio::select! {
                    result = tokio::signal::ctrl_c() => {
                        if let Err(e) = result {
                            tracing::warn!("SIGINT listener failed: {e}");
                        }
                    }
                    _ = terminate.recv() => {}
                }
            }
            Err(e) => {
                tracing::warn!("SIGTERM listener failed: {e}");
                if let Err(e) = tokio::signal::ctrl_c().await {
                    tracing::warn!("SIGINT listener failed: {e}");
                }
            }
        }
    }
    #[cfg(not(unix))]
    {
        if let Err(e) = tokio::signal::ctrl_c().await {
            tracing::warn!("SIGINT listener failed: {e}");
        }
    }
}
