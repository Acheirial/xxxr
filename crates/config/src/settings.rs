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

/// 入站的域名嗅探配置（`inbounds[].sniffing`）。
/// 字段名与上游 `SniffingConfig` 一致。上游的 `metadataOnly` 与 `ipsExcluded`
/// 当前未实现（前者依赖 fake DNS，后者依赖 geoip 数据）。
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct SniffingSettings {
    /// 是否启用嗅探。
    pub enabled: bool,
    /// 命中其中任一协议时，用嗅探出的域名改写目标地址。
    ///
    /// 协议按前缀匹配，因此 `"http"` 可以命中 `http1`。
    pub dest_override: Vec<String>,
    /// 不参与改写的域名条件。
    ///
    /// 支持 `regexp:` / `full:` / `domain:` / `keyword:` 前缀；未带前缀时按
    /// 上游语义等同于 `keyword:`（子串匹配）。
    pub domains_excluded: Vec<String>,
    /// 仅把嗅探结果用于路由匹配，不改写出站实际拨号的目标。
    pub route_only: bool,
}

/// Trojan 入站设置（`inbounds[].settings`）。
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct TrojanInboundSettings {
    /// 允许接入的用户列表（`users` 与 `clients` 等价）。
    pub clients: Vec<TrojanClient>,
    /// 用户列表的别名（Xray 文档中使用 `clients`）。
    pub users: Option<Vec<TrojanClient>>,
    /// 回落配置；当前版本未实现（保留字段）。
    pub fallbacks: Option<serde_json::Value>,
}

impl TrojanInboundSettings {
    /// 返回全部已配置用户。
    pub fn all_clients(&self) -> Vec<TrojanClient> {
        let mut clients = self.clients.clone();
        if let Some(users) = &self.users {
            clients.extend(users.iter().cloned());
        }
        clients
    }

    /// 校验设置合法性。
    pub fn validate(&self, tag: &str) -> Result<()> {
        let clients = self.all_clients();
        if clients.is_empty() {
            return Err(Error::config(format!(
                "inbound `{tag}`: trojan requires at least one client"
            )));
        }
        for client in &clients {
            if client.password.is_empty() {
                return Err(Error::config(format!(
                    "inbound `{tag}`: trojan client password must not be empty"
                )));
            }
            if client.flow.is_some() {
                return Err(Error::config(format!(
                    "inbound `{tag}`: flow is not supported for trojan"
                )));
            }
        }
        Ok(())
    }
}

/// Trojan 入站用户。
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct TrojanClient {
    /// 明文密码（线上发送的是其 SHA-224 的十六进制）。
    pub password: String,
    /// 备注邮箱。
    pub email: Option<String>,
    /// 用户等级（当前版本未实现，接受但忽略）。
    pub level: Option<u32>,
    /// 流控方式；Trojan 不支持，配置即报错（对齐上游）。
    pub flow: Option<String>,
}

/// Trojan 出站设置。
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct TrojanOutboundSettings {
    /// 上游服务器列表（多台按顺序轮询）。
    pub servers: Vec<TrojanServer>,
    /// 单服务器写法：地址。
    pub address: Option<String>,
    /// 单服务器写法：端口。
    pub port: Option<u16>,
    /// 单服务器写法：密码。
    pub password: Option<String>,
}

impl TrojanOutboundSettings {
    /// 归一化为服务器列表（兼容 `servers[]` 与单 `address/port/password` 两种写法）。
    pub fn all_servers(&self) -> Vec<TrojanServer> {
        let mut servers = self.servers.clone();
        if let (Some(address), Some(port), Some(password)) =
            (&self.address, self.port, &self.password)
        {
            servers.push(TrojanServer {
                address: address.clone(),
                port,
                password: password.clone(),
                email: None,
                level: None,
            });
        }
        servers
    }

    /// 校验设置合法性。
    pub fn validate(&self, tag: &str) -> Result<()> {
        let servers = self.all_servers();
        if servers.is_empty() {
            return Err(Error::config(format!(
                "outbound `{tag}`: trojan requires `servers` or `address`/`port`/`password`"
            )));
        }
        for server in &servers {
            if server.address.is_empty() || server.port == 0 || server.password.is_empty() {
                return Err(Error::config(format!(
                    "outbound `{tag}`: trojan server needs address, port and password"
                )));
            }
        }
        Ok(())
    }
}

/// Trojan 上游服务器。
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct TrojanServer {
    /// 服务器地址（域名或 IP）。
    pub address: String,
    /// 服务器端口。
    pub port: u16,
    /// 明文密码。
    pub password: String,
    /// 备注邮箱（当前版本未使用）。
    pub email: Option<String>,
    /// 用户等级（当前版本未使用）。
    pub level: Option<u32>,
}

/// VMess 传输安全类型，对应 `security` 字段。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum VmessSecurity {
    /// `auto`：按硬件能力选用 AEAD 算法（本实现落到 AES-128-GCM）。
    #[default]
    Auto,
    /// `aes-128-gcm`。
    Aes128Gcm,
    /// `chacha20-poly1305`。
    Chacha20Poly1305,
}

impl VmessSecurity {
    /// 返回配置中的字符串表示。
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::Aes128Gcm => "aes-128-gcm",
            Self::Chacha20Poly1305 => "chacha20-poly1305",
        }
    }

    /// 解析配置值；未知取值按上游语义回落到 `auto`。
    pub fn parse(value: &str) -> Self {
        match value.to_ascii_lowercase().as_str() {
            "aes-128-gcm" => Self::Aes128Gcm,
            "chacha20-poly1305" => Self::Chacha20Poly1305,
            _ => Self::Auto,
        }
    }
}

impl std::str::FromStr for VmessSecurity {
    type Err = Error;

    fn from_str(value: &str) -> Result<Self> {
        Ok(Self::parse(value))
    }
}

impl Serialize for VmessSecurity {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for VmessSecurity {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Self, D::Error> {
        let raw = String::deserialize(deserializer)?;
        Ok(Self::parse(&raw))
    }
}

/// VMess 入站设置（`inbounds[].settings`）。
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct VmessInboundSettings {
    /// 允许接入的用户列表（`clients` 与 `users` 等价）。
    pub clients: Vec<VmessClient>,
    /// 用户列表的别名。
    pub users: Option<Vec<VmessClient>>,
    /// 默认配置（`default.level`），当前仅保留字段。
    pub default: Option<serde_json::Value>,
}

impl VmessInboundSettings {
    /// 返回全部已配置用户。
    pub fn all_clients(&self) -> Vec<VmessClient> {
        let mut clients = self.clients.clone();
        if let Some(users) = &self.users {
            clients.extend(users.iter().cloned());
        }
        clients
    }

    /// 校验设置合法性。
    pub fn validate(&self, tag: &str) -> Result<()> {
        if self.all_clients().is_empty() {
            return Err(Error::config(format!(
                "inbound `{tag}`: vmess requires at least one client"
            )));
        }
        Ok(())
    }
}

/// VMess 入站用户。
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct VmessClient {
    /// 用户 UUID。
    pub id: Uuid,
    /// 仅 AEAD 模式：`alterId` 不再参与运算，非 0 会记录告警。
    pub alter_id: Option<u32>,
    /// 备注邮箱。
    pub email: Option<String>,
    /// 用户等级（当前版本未实现，接受但忽略）。
    pub level: Option<u32>,
    /// 该用户的 `security`（缺省 `auto`）。
    pub security: Option<VmessSecurity>,
    /// 实验特性列表（`AuthenticatedLength` / `NoTerminationSignal`）。
    pub experiments: Option<Vec<String>>,
}

/// VMess 出站设置。
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct VmessOutboundSettings {
    /// 上游服务器列表（当前仅使用第一个）。
    pub vnext: Vec<VmessServer>,
    /// 单服务器写法：地址。
    pub address: Option<String>,
    /// 单服务器写法：端口。
    pub port: Option<u16>,
    /// 单服务器写法：用户 UUID。
    pub id: Option<Uuid>,
    /// 单服务器写法：security。
    pub security: Option<VmessSecurity>,
}

impl VmessOutboundSettings {
    /// 归一化为服务器列表。
    pub fn all_servers(&self) -> Vec<VmessServer> {
        let mut servers = self.vnext.clone();
        if let (Some(address), Some(port), Some(id)) = (&self.address, self.port, self.id) {
            servers.push(VmessServer {
                address: address.clone(),
                port,
                users: vec![VmessUser {
                    id,
                    alter_id: None,
                    email: None,
                    level: None,
                    security: self.security,
                    experiments: None,
                }],
            });
        }
        servers
    }

    /// 校验设置合法性。
    pub fn validate(&self, tag: &str) -> Result<()> {
        let servers = self.all_servers();
        let server = servers
            .first()
            .ok_or_else(|| Error::config(format!("outbound `{tag}`: vmess requires `vnext`")))?;
        if server.address.is_empty() || server.port == 0 {
            return Err(Error::config(format!(
                "outbound `{tag}`: vmess server needs address and non-zero port"
            )));
        }
        if server.users.is_empty() {
            return Err(Error::config(format!(
                "outbound `{tag}`: vmess requires at least one user"
            )));
        }
        Ok(())
    }
}

/// VMess 上游服务器。
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct VmessServer {
    /// 服务器地址（域名或 IP）。
    pub address: String,
    /// 服务器端口。
    pub port: u16,
    /// 用户列表（当前仅使用第一个）。
    pub users: Vec<VmessUser>,
}

/// VMess 出站用户。
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct VmessUser {
    /// 用户 UUID。
    pub id: Uuid,
    /// 仅 AEAD 模式：非 0 会记录告警。
    pub alter_id: Option<u32>,
    /// 备注邮箱（当前版本未使用）。
    pub email: Option<String>,
    /// 用户等级（当前版本未使用）。
    pub level: Option<u32>,
    /// `security`（缺省 `auto`）。
    pub security: Option<VmessSecurity>,
    /// 实验特性列表。
    pub experiments: Option<Vec<String>>,
}
