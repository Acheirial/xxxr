//! `xxxr-common`：跨 crate 共享的基础设施。
//!
//! 本 crate 只提供最基础的能力：统一的错误类型 [`Error`] 与日志初始化
//! [`logging::init_logging`]。它不依赖任何其他 `xxxr-*` crate，因此可以被
//! 整个 workspace 安全复用。
#![deny(missing_docs)]

pub mod error;
pub mod logging;

pub use error::{Error, Result};
