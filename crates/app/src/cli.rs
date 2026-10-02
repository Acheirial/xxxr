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

/// 加载配置并运行实例，直到收到 `Ctrl-C`。
pub async fn run(config_path: &Path) -> Result<()> {
    let config = Config::load(config_path)?;
    init_logging(config.log.loglevel);
    let mut instance = Instance::new(config)?;
    let started = instance.start();
    tracing::info!("xxxr started, {started} inbound(s) listening; press Ctrl-C to stop");
    tokio::signal::ctrl_c()
        .await
        .map_err(|e| xxxr_common::Error::other(format!("listen for Ctrl-C failed: {e}")))?;
    tracing::info!("shutting down");
    instance.shutdown();
    Ok(())
}
