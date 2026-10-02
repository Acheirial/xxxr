//! 出站处理器与工厂函数。

use std::sync::Arc;

use xxxr_common::{Error, Result};
use xxxr_config::{
    OutboundConfig, Protocol, TrojanOutboundSettings, VlessOutboundSettings, VmessOutboundSettings,
};
use xxxr_net::Address;

use crate::traits::OutboundHandler;

mod blackhole;
mod freedom;
mod trojan;
mod vless;
mod vmess;

pub use blackhole::Blackhole;
pub use freedom::Freedom;
pub use trojan::TrojanOutbound;
pub use vless::VlessOutbound;
pub use vmess::VmessOutbound;

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
        Protocol::Trojan => {
            let settings: TrojanOutboundSettings = config.parse_settings()?;
            settings.validate(&config.tag)?;
            let servers = settings
                .all_servers()
                .into_iter()
                .map(|server| {
                    parse_server_address(&server.address, server.port)
                        .map(|address| (address, server.password))
                })
                .collect::<Result<Vec<_>>>()?;
            Ok(Arc::new(TrojanOutbound::new(
                config.tag.clone(),
                servers,
                stream_settings,
            )))
        }
        Protocol::Vmess => {
            let settings: VmessOutboundSettings = config.parse_settings()?;
            settings.validate(&config.tag)?;
            let server = settings.all_servers().into_iter().next().ok_or_else(|| {
                Error::config(format!("outbound `{}` requires `vnext`", config.tag))
            })?;
            let user = server.users.first().cloned().ok_or_else(|| {
                Error::config(format!(
                    "outbound `{}` requires at least one vnext user",
                    config.tag
                ))
            })?;
            if user.alter_id.unwrap_or(0) != 0 {
                tracing::warn!(
                    outbound = %config.tag,
                    "vmess `alterId` is ignored: only AEAD is supported"
                );
            }
            let address = parse_server_address(&server.address, server.port)?;
            let experiments = user.experiments.clone().unwrap_or_default();
            Ok(Arc::new(VmessOutbound::new(
                config.tag.clone(),
                address,
                user.id,
                user.security.unwrap_or_default(),
                &experiments,
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
