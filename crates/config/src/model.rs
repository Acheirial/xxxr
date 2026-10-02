//! 顶层配置模型。

use std::collections::HashSet;
use std::path::Path;

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use xxxr_common::logging::Level;
use xxxr_common::{Error, Result};

use crate::settings::{SocksInboundSettings, VlessInboundSettings, VlessOutboundSettings};

/// 协议名称，由 JSON 中的小写字符串反序列化。
///
/// 未识别的协议保留原值，便于在校验阶段给出明确的错误信息。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Protocol {
    /// VLESS。
    Vless,
    /// SOCKS（SOCKS5）。
    Socks,
    /// Freedom（直连）。
    Freedom,
    /// Blackhole（丢弃）。
    Blackhole,
    /// 其他未实现的协议。
    Other(String),
}

impl Protocol {
    /// 返回配置中的字符串表示。
    pub fn as_str(&self) -> &str {
        match self {
            Self::Vless => "vless",
            Self::Socks => "socks",
            Self::Freedom => "freedom",
            Self::Blackhole => "blackhole",
            Self::Other(name) => name,
        }
    }

    /// 是否为当前版本已实现的协议。
    pub fn is_supported(&self) -> bool {
        !matches!(self, Self::Other(_))
    }
}

impl Serialize for Protocol {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl Default for Protocol {
    /// 缺省值为「未知协议」，会在 [`Config::validate`] 阶段被拒绝。
    fn default() -> Self {
        Self::Other(String::new())
    }
}

impl<'de> Deserialize<'de> for Protocol {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        let raw = String::deserialize(deserializer)?;
        Ok(match raw.to_ascii_lowercase().as_str() {
            "vless" => Self::Vless,
            "socks" => Self::Socks,
            "freedom" => Self::Freedom,
            "blackhole" => Self::Blackhole,
            _ => Self::Other(raw),
        })
    }
}

/// 日志配置（`log`）。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct LogConfig {
    /// 日志级别。
    pub loglevel: Level,
    /// 访问日志输出路径，未实现具体落盘，仅保留字段。
    pub access: String,
    /// 错误日志输出路径，未实现具体落盘，仅保留字段。
    pub error: String,
}

impl Default for LogConfig {
    fn default() -> Self {
        Self {
            loglevel: Level::Warning,
            access: String::new(),
            error: String::new(),
        }
    }
}

/// 入站配置（`inbounds[]`）。
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct InboundConfig {
    /// 唯一标签，用于路由匹配。
    pub tag: String,
    /// 监听地址，缺省为 `0.0.0.0`。
    pub listen: Option<String>,
    /// 监听端口，接受数字或字符串形式。
    #[serde(deserialize_with = "deserialize_opt_port")]
    pub port: Option<u16>,
    /// 协议名。
    pub protocol: Protocol,
    /// 协议参数，由具体协议解析。
    pub settings: serde_json::Value,
    /// 传输层配置。
    pub stream_settings: Option<xxxr_net::StreamSettings>,
    /// 嗅探配置，当前仅保留字段。
    pub sniffing: Option<serde_json::Value>,
}

impl InboundConfig {
    /// 把 `settings` 解析为强类型；缺省（`null`）时视为空对象。
    pub fn parse_settings<T: serde::de::DeserializeOwned>(&self) -> Result<T> {
        parse_settings_value(&self.settings)
            .map_err(|e| Error::config(format!("inbound `{}` settings is invalid: {e}", self.tag)))
    }
}

/// 出站配置（`outbounds[]`）。
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct OutboundConfig {
    /// 唯一标签，用于路由目标。
    pub tag: String,
    /// 协议名。
    pub protocol: Protocol,
    /// 协议参数，由具体协议解析。
    pub settings: serde_json::Value,
    /// 传输层配置。
    pub stream_settings: Option<xxxr_net::StreamSettings>,
    /// 绑定的本地地址（`sendThrough`），当前仅保留字段。
    pub send_through: Option<String>,
}

impl OutboundConfig {
    /// 把 `settings` 解析为强类型；缺省（`null`）时视为空对象。
    pub fn parse_settings<T: serde::de::DeserializeOwned>(&self) -> Result<T> {
        parse_settings_value(&self.settings)
            .map_err(|e| Error::config(format!("outbound `{}` settings is invalid: {e}", self.tag)))
    }
}

/// 把 `settings` 字段解析为强类型，`null` 视为空对象。
fn parse_settings_value<T: serde::de::DeserializeOwned>(
    value: &serde_json::Value,
) -> std::result::Result<T, serde_json::Error> {
    if value.is_null() {
        serde_json::from_value(serde_json::Value::Object(serde_json::Map::new()))
    } else {
        serde_json::from_value(value.clone())
    }
}

/// 路由配置（`routing`）。
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct RoutingConfig {
    /// 域名解析策略，当前仅保留字段。
    pub domain_strategy: Option<String>,
    /// 规则列表，按顺序匹配，命中即停止。
    pub rules: Vec<RoutingRule>,
}

/// 单条路由规则。
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct RoutingRule {
    /// 规则类型（Xray 为 `field`），当前仅保留字段。
    pub r#type: Option<String>,
    /// 匹配的入站 tag 列表。
    pub inbound_tag: Option<Vec<String>>,
    /// 匹配的域名列表，支持 `domain:` / `full:` / 裸关键词前缀。
    pub domain: Option<Vec<String>>,
    /// 匹配的 IP 列表，支持单个 IP 或 CIDR。
    pub ip: Option<Vec<String>>,
    /// 匹配的目标端口（暂不解析）。
    pub port: Option<String>,
    /// 匹配的协议类型 `tcp` / `udp`（暂不解析）。
    pub network: Option<String>,
    /// 命中的出站 tag。
    pub outbound_tag: String,
    /// 规则标签，当前仅保留字段。
    pub rule_tag: Option<String>,
    /// 是否启用，缺省为启用。
    pub enabled: Option<bool>,
}

/// Xray 顶层配置。
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct Config {
    /// 日志配置。
    pub log: LogConfig,
    /// 入站列表。
    pub inbounds: Vec<InboundConfig>,
    /// 出站列表。
    pub outbounds: Vec<OutboundConfig>,
    /// 路由配置，缺省表示全部走第一个出站。
    pub routing: Option<RoutingConfig>,
}

impl Config {
    /// 从 JSON 字符串解析配置。
    pub fn from_json_str(text: &str) -> Result<Self> {
        serde_json::from_str(text).map_err(|e| Error::config(format!("invalid json: {e}")))
    }

    /// 从文件加载配置。
    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let text = std::fs::read_to_string(path)
            .map_err(|e| Error::config(format!("read config `{}` failed: {e}", path.display())))?;
        Self::from_json_str(&text)
    }

    /// 默认出站 tag：列表中的第一个出站。
    pub fn default_outbound_tag(&self) -> Option<&str> {
        self.outbounds.first().map(|outbound| outbound.tag.as_str())
    }

    /// 校验配置的完整性，错误信息面向使用者可读。
    pub fn validate(&self) -> Result<()> {
        let mut inbound_tags = HashSet::new();
        for inbound in &self.inbounds {
            if inbound.tag.is_empty() {
                return Err(Error::config("inbound tag must not be empty".to_string()));
            }
            if !inbound_tags.insert(inbound.tag.as_str()) {
                return Err(Error::config(format!(
                    "duplicated inbound tag `{}`",
                    inbound.tag
                )));
            }
            if inbound.port.is_none() {
                return Err(Error::config(format!(
                    "inbound `{}` requires `port`",
                    inbound.tag
                )));
            }
            if !inbound.protocol.is_supported() {
                return Err(Error::unsupported(format!(
                    "inbound protocol `{}`",
                    inbound.protocol.as_str()
                )));
            }
            match inbound.protocol {
                Protocol::Socks => {
                    let settings: SocksInboundSettings = inbound.parse_settings()?;
                    settings.validate(&inbound.tag)?;
                }
                Protocol::Vless => {
                    let settings: VlessInboundSettings = inbound.parse_settings()?;
                    settings.validate(&inbound.tag)?;
                }
                _ => {
                    return Err(Error::unsupported(format!(
                        "inbound protocol `{}`",
                        inbound.protocol.as_str()
                    )));
                }
            }
        }

        let mut outbound_tags = HashSet::new();
        for outbound in &self.outbounds {
            if outbound.tag.is_empty() {
                return Err(Error::config("outbound tag must not be empty".to_string()));
            }
            if !outbound_tags.insert(outbound.tag.as_str()) {
                return Err(Error::config(format!(
                    "duplicated outbound tag `{}`",
                    outbound.tag
                )));
            }
            if !outbound.protocol.is_supported() {
                return Err(Error::unsupported(format!(
                    "outbound protocol `{}`",
                    outbound.protocol.as_str()
                )));
            }
            match outbound.protocol {
                Protocol::Vless => {
                    let settings: VlessOutboundSettings = outbound.parse_settings()?;
                    settings.validate(&outbound.tag)?;
                }
                Protocol::Freedom | Protocol::Blackhole | Protocol::Socks => {}
                _ => {
                    return Err(Error::unsupported(format!(
                        "outbound protocol `{}`",
                        outbound.protocol.as_str()
                    )));
                }
            }
        }

        if let Some(routing) = &self.routing {
            for rule in &routing.rules {
                if rule.outbound_tag.is_empty() {
                    return Err(Error::config(
                        "routing rule requires `outboundTag`".to_string(),
                    ));
                }
                if !outbound_tags.contains(rule.outbound_tag.as_str()) {
                    return Err(Error::config(format!(
                        "routing rule refers to unknown outbound `{}`",
                        rule.outbound_tag
                    )));
                }
            }
        }
        Ok(())
    }
}

/// 端口字段反序列化：同时接受数字与字符串。
fn deserialize_opt_port<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<Option<u16>, D::Error> {
    let value = serde_json::Value::deserialize(deserializer)?;
    match value {
        serde_json::Value::Null => Ok(None),
        serde_json::Value::Number(number) => number
            .as_u64()
            .and_then(|port| u16::try_from(port).ok())
            .map(Some)
            .ok_or_else(|| serde::de::Error::custom("invalid `port`")),
        serde_json::Value::String(text) => text
            .trim()
            .parse::<u16>()
            .map(Some)
            .map_err(|_| serde::de::Error::custom("invalid `port`")),
        _ => Err(serde::de::Error::custom("invalid `port`")),
    }
}
