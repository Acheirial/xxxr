//! 各协议 `settings` 字段的强类型模型。
//!
//! 这些结构只在需要时由对应的协议实现解析；未知字段会被忽略。

use serde::{Deserialize, Serialize};
use uuid::Uuid;
use xxxr_common::{Error, Result};

/// SOCKS 入站设置（`inbounds[].settings`）。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct SocksInboundSettings {
    /// 认证方式：`noauth` 或 `password`。
    pub auth: String,
    /// `auth = password` 时的账号列表。
    pub accounts: Vec<SocksAccount>,
    /// 是否支持 UDP ASSOCIATE（当前版本尚未实现，保留字段）。
    pub udp: bool,
    /// 覆盖转发目标地址（Xray 的 `address`），当前未启用。
    pub address: Option<String>,
}

impl Default for SocksInboundSettings {
    fn default() -> Self {
        Self {
            auth: "noauth".to_string(),
            accounts: Vec::new(),
            udp: false,
            address: None,
        }
    }
}

impl SocksInboundSettings {
    /// 校验设置合法性。
    pub fn validate(&self, tag: &str) -> Result<()> {
        match self.auth.as_str() {
            "noauth" | "" => Ok(()),
            "password" => {
                if self.accounts.is_empty() {
                    return Err(Error::config(format!(
                        "inbound `{tag}`: `auth = password` requires `accounts`"
                    )));
                }
                Ok(())
            }
            other => Err(Error::config(format!(
                "inbound `{tag}`: unsupported socks auth `{other}`"
            ))),
        }
    }
}

/// SOCKS 账号。
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct SocksAccount {
    /// 用户名。
    pub user: String,
    /// 密码。
    pub pass: String,
}

/// VLESS 入站设置。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct VlessInboundSettings {
    /// 允许接入的用户列表。
    pub clients: Vec<VlessClient>,
    /// 解密方式，当前仅支持 `none`。
    pub decryption: String,
    /// 回落配置（当前版本尚未实现，保留字段）。
    pub fallbacks: Option<serde_json::Value>,
}

impl Default for VlessInboundSettings {
    fn default() -> Self {
        Self {
            clients: Vec::new(),
            decryption: "none".to_string(),
            fallbacks: None,
        }
    }
}

impl VlessInboundSettings {
    /// 校验设置合法性。
    pub fn validate(&self, tag: &str) -> Result<()> {
        if self.clients.is_empty() {
            return Err(Error::config(format!(
                "inbound `{tag}`: vless requires at least one client"
            )));
        }
        if !self.decryption.is_empty() && self.decryption != "none" {
            return Err(Error::unsupported(format!(
                "inbound `{tag}`: vless decryption `{}`",
                self.decryption
            )));
        }
        Ok(())
    }
}

/// VLESS 入站用户。
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct VlessClient {
    /// 用户 UUID。
    pub id: Uuid,
    /// 备注邮箱。
    pub email: Option<String>,
    /// 流控方式（当前版本未实现，接受但忽略）。
    pub flow: Option<String>,
    /// 用户等级（当前版本未实现，接受但忽略）。
    pub level: Option<u32>,
}

/// VLESS 出站设置。
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct VlessOutboundSettings {
    /// 上游服务器列表（当前仅使用第一个）。
    pub vnext: Vec<VlessServer>,
}

impl VlessOutboundSettings {
    /// 校验设置合法性。
    pub fn validate(&self, tag: &str) -> Result<()> {
        let server = self
            .vnext
            .first()
            .ok_or_else(|| Error::config(format!("outbound `{tag}`: vless requires `vnext`")))?;
        if server.address.is_empty() {
            return Err(Error::config(format!(
                "outbound `{tag}`: vless `vnext[].address` must not be empty"
            )));
        }
        if server.port == 0 {
            return Err(Error::config(format!(
                "outbound `{tag}`: vless `vnext[].port` must not be 0"
            )));
        }
        if server.users.is_empty() {
            return Err(Error::config(format!(
                "outbound `{tag}`: vless `vnext[].users` must not be empty"
            )));
        }
        Ok(())
    }
}

/// VLESS 上游服务器。
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct VlessServer {
    /// 服务器地址（域名或 IP）。
    pub address: String,
    /// 服务器端口。
    pub port: u16,
    /// 用户列表（当前仅使用第一个）。
    pub users: Vec<VlessUser>,
}

/// VLESS 出站用户。
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct VlessUser {
    /// 用户 UUID。
    pub id: Uuid,
    /// 加密方式，VLESS 固定为 `none`。
    pub encryption: Option<String>,
    /// 流控方式（当前版本未实现，接受但忽略）。
    pub flow: Option<String>,
    /// 用户等级（当前版本未实现，接受但忽略）。
    pub level: Option<u32>,
}

/// Freedom 出站设置。
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct FreedomSettings {
    /// 域名解析策略，当前仅保留字段。
    pub domain_strategy: Option<String>,
    /// 重定向目标，当前未启用。
    pub redirect: Option<String>,
}

/// Blackhole 出站设置。
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct BlackholeSettings {
    /// 响应类型，当前版本一律直接关闭连接。
    pub response: Option<serde_json::Value>,
}
