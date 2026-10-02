//! 出站处理器与工厂函数。

use std::sync::Arc;

use xxxr_common::{Error, Result};
use xxxr_config::{OutboundConfig, Protocol, VlessOutboundSettings};
use xxxr_net::Address;

use crate::traits::OutboundHandler;

mod blackhole;
mod freedom;
mod vless;

pub use blackhole::Blackhole;
pub use freedom::Freedom;
pub use vless::VlessOutbound;

/// 依据配置构建出站处理器。
pub fn build_outbound(config: &OutboundConfig) -> Result<Arc<dyn OutboundHandler>> {
    let stream_settings = config.stream_settings.clone().unwrap_or_default();
    match &config.protocol {
        Protocol::Freedom => Ok(Arc::new(Freedom::new(config.tag.clone(), stream_settings))),
        Protocol::Blackhole => Ok(Arc::new(Blackhole::new(config.tag.clone()))),
        Protocol::Vless => {
            let settings: VlessOutboundSettings = config.parse_settings()?;
            settings.validate(&config.tag)?;
            let server = settings.vnext.first().ok_or_else(|| {
                Error::config(format!("outbound `{}` requires `vnext`", config.tag))
            })?;
            let user = server.users.first().ok_or_else(|| {
                Error::config(format!(
                    "outbound `{}` requires at least one vnext user",
                    config.tag
                ))
            })?;
            let address = parse_server_address(&server.address, server.port)?;
            Ok(Arc::new(VlessOutbound::new(
                config.tag.clone(),
                address,
                user.id,
                stream_settings,
            )))
        }
        other => Err(Error::unsupported(format!(
            "outbound protocol `{}`",
            other.as_str()
        ))),
    }
}

/// 把配置中的 `address` + `port` 组合为 [`Address`]。
fn parse_server_address(host: &str, port: u16) -> Result<Address> {
    format!("{host}:{port}")
        .parse::<Address>()
        .map_err(|e| Error::config(format!("invalid vnext address `{host}`: {e}")))
}
