//! `xxxr`：Xray-core 的 Rust 重写实现。
//!
//! 本 crate 提供可执行文件 `xxxr` 以及装配层：分发器 [`Dispatcher`]、
//! 路由器 [`Router`] 与实例 [`Instance`]。
#![deny(missing_docs)]

pub mod cli;
pub mod dispatcher;
pub mod instance;
pub mod router;

pub use dispatcher::Dispatcher;
pub use instance::Instance;
pub use router::Router;
