//! 日志初始化。
//!
//! 对应 Xray 配置中的 `log.loglevel`。日志使用 `tracing` 生态，
//! 通过 [`init_logging`] 安装全局 subscriber。

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use tracing_subscriber::fmt as tracing_fmt;
use tracing_subscriber::EnvFilter;

use crate::{Error, Result};

/// 日志级别，对应 Xray `log.loglevel` 的可选值。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Level {
    /// 调试级别。
    Debug,
    /// 普通信息。
    #[default]
    Info,
    /// 警告。
    Warning,
    /// 错误。
    Error,
    /// 关闭日志输出。
    None,
}

impl Level {
    /// 返回该级别对应的 `tracing` 过滤指令字符串。
    pub fn as_filter(&self) -> &'static str {
        match self {
            Self::Debug => "debug",
            Self::Info => "info",
            Self::Warning => "warn",
            Self::Error => "error",
            Self::None => "off",
        }
    }
}

impl FromStr for Level {
    type Err = Error;

    fn from_str(value: &str) -> Result<Self> {
        match value.to_ascii_lowercase().as_str() {
            "debug" => Ok(Self::Debug),
            "info" => Ok(Self::Info),
            "warning" | "warn" => Ok(Self::Warning),
            "error" => Ok(Self::Error),
            "none" | "off" => Ok(Self::None),
            other => Err(Error::config(format!("invalid log level: {other}"))),
        }
    }
}

impl fmt::Display for Level {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Debug => "debug",
            Self::Info => "info",
            Self::Warning => "warning",
            Self::Error => "error",
            Self::None => "none",
        })
    }
}

impl Serialize for Level {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for Level {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        let raw = String::deserialize(deserializer)?;
        Self::from_str(&raw).map_err(serde::de::Error::custom)
    }
}

/// 安装全局 `tracing` subscriber。
///
/// 若环境变量 `RUST_LOG` 存在则优先使用它，否则使用 `level`。
/// 重复调用会被静默忽略（全局 subscriber 只能安装一次）。
pub fn init_logging(level: Level) {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(format!("xxxr={level}")));
    let subscriber = tracing_fmt::Subscriber::builder()
        .with_env_filter(filter)
        .with_target(true)
        .finish();
    let _ = tracing::subscriber::set_global_default(subscriber);
}
