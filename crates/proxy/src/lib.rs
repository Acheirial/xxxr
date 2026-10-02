//! `xxxr-proxy`：协议层。
//!
//! 定义入站/出站处理器抽象（[`InboundHandler`] / [`OutboundHandler`]）以及
//! 分发器接口 [`Dispatcher`]，并提供本里程碑所需的协议实现：
//!
//! - 入站：SOCKS5（CONNECT）、VLESS（TCP，version 0）
//! - 出站：Freedom、Blackhole、VLESS（TCP）
#![deny(missing_docs)]

pub mod context;
pub mod inbound;
pub mod outbound;
pub mod relay;
pub mod traits;
pub mod vless;

pub use context::{Network, SessionContext};
pub use inbound::{build_inbound, SocksInbound, VlessInbound};
pub use outbound::{build_outbound, Blackhole, Freedom, VlessOutbound};
pub use traits::{Dispatcher, InboundHandler, OutboundHandler};
