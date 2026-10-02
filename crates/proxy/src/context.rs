//! 会话上下文。
//!
//! 字段与上游 Xray 的 `session.Outbound` 对应关系：
//!
//! | 本结构 | 上游 | 含义 |
//! |---|---|---|
//! | [`SessionContext::target`] | 改写后的 `Destination` | 供路由使用的目标（可能已被嗅探为域名） |
//! | [`SessionContext::original_target`] | `Outbound.OriginalTarget` | 嗅探前的原始目标 |
//! | [`SessionContext::sniffed_target`] | `Outbound.RouteTarget` | 嗅探得到的域名目标（`destOverride` 命中时） |
//! | [`SessionContext::dial_target`] | `Outbound.Target` | 出站实际拨号的目标 |
//!
//! 路由条件对目标的取用也照抄上游 `features/routing/session`：
//! `domain` 用 RouteTarget（[`SessionContext::route_target`]），
//! `ip` / `port` 用 Outbound.Target（[`SessionContext::outbound_target`]）。

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

impl Network {
    /// 返回小写名称（`tcp` / `udp`），用于路由 `network` 条件。
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
        }
    }
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
    /// 会话目标地址；入站协议握手完成后必须填写，命中 `destOverride` 时会被改写为嗅探域名。
    pub target: Option<Address>,
    /// 会话网络类型。
    pub network: Network,
    /// 嗅探前的原始目标地址。
    pub original_target: Option<Address>,
    /// 嗅探得到的目标地址（`destOverride` 命中时设置）。
    pub sniffed_target: Option<Address>,
    /// 嗅探出的协议名（例如 `tls` / `http1`），供路由 `protocol` 条件匹配。
    pub protocol: Option<String>,
    /// 出站实际拨号的目标；`routeOnly` 模式下与 [`SessionContext::target`] 不同。
    pub dial_target: Option<Address>,
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

    /// 路由 `domain` 条件使用的目标：优先嗅探结果，其次会话目标。
    pub fn route_target(&self) -> Option<&Address> {
        self.sniffed_target.as_ref().or(self.target.as_ref())
    }

    /// 路由 `ip` / `port` 条件与出站拨号使用的目标。
    pub fn outbound_target(&self) -> Option<&Address> {
        self.dial_target.as_ref().or_else(|| self.route_target())
    }

    /// 记录嗅探结果。
    ///
    /// `target` 为「域名 + 原端口」；`route_only` 为 `true` 时只影响路由，
    /// 出站仍然拨号原始目标（等价上游 `Outbound.RouteTarget` 语义）。
    pub fn set_sniffed(&mut self, target: Address, protocol: String, route_only: bool) {
        if self.original_target.is_none() {
            self.original_target = self.target.clone();
        }
        let dial_target = if route_only {
            self.original_target.clone()
        } else {
            Some(target.clone())
        };
        self.target = Some(target.clone());
        self.sniffed_target = Some(target);
        self.dial_target = dial_target;
        self.protocol = Some(protocol);
    }
}
