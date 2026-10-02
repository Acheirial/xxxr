//! `xxxr-net`：网络层。
//!
//! 提供统一的地址模型 [`Address`]、连接抽象 [`Conn`]，以及按 Xray 风格
//! `streamSettings` 组合的拨号器 [`Dialer`] 与监听器 [`Listener`]。
//! 支持的传输：TCP、WebSocket（`ws`）、TLS（`tls`）。
#![deny(missing_docs)]

pub mod address;
pub mod conn;
pub mod dialer;
pub mod listener;
pub mod prefixed;
pub mod transport;

pub use address::Address;
pub use conn::Conn;
pub use dialer::Dialer;
pub use listener::Listener;
pub use prefixed::Prefixed;
pub use transport::{Security, StreamSettings, TlsSettings, Transport, WsSettings};
