//! 会话上下文。

use xxxr_common::{Error, Result};
use xxxr_net::Address;

/// 会话使用的网络类型。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Network {
    /// TCP 会话。
    #[default]
    Tcp,
    /// UDP 会话（当前版本入站仅支持 TCP）。
    Udp,
}

/// 一次代理会话的上下文，在入站与出站之间传递。
#[derive(Debug, Clone, Default)]
pub struct SessionContext {
    /// 处理该会话的入站 tag；路由器据此匹配 `inboundTag` 规则。
    pub inbound_tag: Option<String>,
    /// 最终选中的出站 tag，由分发器写入。
    pub outbound_tag: Option<String>,
    /// 客户端来源地址。
    pub source: Option<Address>,
    /// 会话目标地址；入站协议握手完成后必须填写。
    pub target: Option<Address>,
    /// 会话网络类型。
    pub network: Network,
}

impl SessionContext {
    /// 创建上下文并填写入站 tag 与来源地址。
    pub fn new(inbound_tag: impl Into<String>, source: Option<Address>) -> Self {
        Self {
            inbound_tag: Some(inbound_tag.into()),
            source,
            ..Self::default()
        }
    }

    /// 取出目标地址；未设置时返回协议错误。
    pub fn require_target(&self) -> Result<&Address> {
        self.target
            .as_ref()
            .ok_or_else(|| Error::protocol("session has no target address"))
    }
}
