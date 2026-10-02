//! 入站处理器与工厂函数。

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;

use xxxr_common::{Error, Result};
use xxxr_config::{InboundConfig, Protocol, SocksInboundSettings, VlessInboundSettings};
use xxxr_net::Listener;

use crate::traits::InboundHandler;

mod socks;
mod vless;

pub use socks::SocksInbound;
pub use vless::VlessInbound;

/// 依据配置构建入站处理器。
///
/// 构造期即完成端口绑定，因此端口冲突、非法监听地址会立即报错。
pub fn build_inbound(config: &InboundConfig) -> Result<Arc<dyn InboundHandler>> {
    let port = config
        .port
        .ok_or_else(|| Error::config(format!("inbound `{}` requires `port`", config.tag)))?;
    let ip = resolve_listen(config)?;
    let stream_settings = config.stream_settings.clone().unwrap_or_default();
    let listener = Arc::new(Listener::bind(SocketAddr::new(ip, port), stream_settings)?);
    match &config.protocol {
        Protocol::Socks => {
            let settings: SocksInboundSettings = config.parse_settings()?;
            settings.validate(&config.tag)?;
            Ok(Arc::new(SocksInbound::new(
                config.tag.clone(),
                listener,
                settings,
            )))
        }
        Protocol::Vless => {
            let settings: VlessInboundSettings = config.parse_settings()?;
            settings.validate(&config.tag)?;
            Ok(Arc::new(VlessInbound::new(
                config.tag.clone(),
                listener,
                settings,
            )))
        }
        other => Err(Error::unsupported(format!(
            "inbound protocol `{}`",
            other.as_str()
        ))),
    }
}

/// 解析 `listen` 字段，缺省为 `0.0.0.0`。
fn resolve_listen(config: &InboundConfig) -> Result<IpAddr> {
    match config.listen.as_deref() {
        None | Some("") => Ok(IpAddr::V4(Ipv4Addr::UNSPECIFIED)),
        Some(value) => value.parse::<IpAddr>().map_err(|e| {
            Error::config(format!(
                "inbound `{}` listen `{value}` is invalid: {e}",
                config.tag
            ))
        }),
    }
}
