//! `xxxr-config`：Xray JSON 配置的 serde 模型、加载与校验。
//!
//! 设计原则：
//! - 顶层结构对应 Xray 的 `log` / `inbounds` / `outbounds` / `routing`；
//! - 协议名、传输名使用小写字符串 tag，未知取值保留原值（[`Protocol::Other`]）；
//! - 所有字段均可缺省，未知字段一律忽略，保证与前向配置兼容；
//! - `settings` 保持为 [`serde_json::Value`]，由各协议实现按需解析为强类型。
#![deny(missing_docs)]

pub mod model;
pub mod settings;

pub use model::{
    Config, InboundConfig, LogConfig, OutboundConfig, Protocol, RoutingConfig, RoutingRule,
};
pub use settings::{
    BlackholeSettings, FreedomSettings, SocksAccount, SocksInboundSettings, VlessClient,
    VlessInboundSettings, VlessOutboundSettings, VlessServer, VlessUser,
};
pub use xxxr_common::logging::Level;
