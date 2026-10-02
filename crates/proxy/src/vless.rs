//! VLESS 协议编解码（protocol version 0）。
//!
//! 请求头布局：`version(1) | user_id(16) | addons_len(1) | addons(M) |
//! command(1) | port(2, BE) | address_type(1) | address`；
//! 响应头布局：`version(1) | addons_len(1) | addons(M)`。

use tokio::io::{AsyncRead, AsyncReadExt};
use uuid::Uuid;
use xxxr_common::{Error, Result};
use xxxr_net::Address;

/// VLESS 协议版本。
pub const VERSION: u8 = 0;

/// 地址类型：IPv4。
pub const ADDRESS_TYPE_IPV4: u8 = 0x01;
/// 地址类型：域名。
pub const ADDRESS_TYPE_DOMAIN: u8 = 0x02;
/// 地址类型：IPv6。
pub const ADDRESS_TYPE_IPV6: u8 = 0x03;

/// VLESS 命令。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Command {
    /// TCP 代理。
    Tcp,
    /// UDP 代理。
    Udp,
    /// 复用（mux）。
    Mux,
}

impl Command {
    /// 从字节解析命令。
    pub fn from_u8(value: u8) -> Result<Self> {
        match value {
            0x01 => Ok(Self::Tcp),
            0x02 => Ok(Self::Udp),
            0x03 => Ok(Self::Mux),
            other => Err(Error::protocol(format!("unknown vless command {other}"))),
        }
    }

    /// 转换为协议字节。
    pub fn as_u8(self) -> u8 {
        match self {
            Self::Tcp => 0x01,
            Self::Udp => 0x02,
            Self::Mux => 0x03,
        }
    }
}

/// VLESS 请求头。
#[derive(Debug, Clone)]
pub struct RequestHeader {
    /// 客户端 UUID。
    pub user_id: Uuid,
    /// 附加数据（原样保留，便于回写）。
    pub addons: Vec<u8>,
    /// 请求命令。
    pub command: Command,
    /// 目标地址。
    pub dest: Address,
}

/// 读取并解析请求头。
pub async fn read_request<R: AsyncRead + Unpin>(reader: &mut R) -> Result<RequestHeader> {
    let version = reader.read_u8().await?;
    if version != VERSION {
        return Err(Error::protocol(format!(
            "unsupported vless version {version}"
        )));
    }
    let mut raw_id = [0u8; 16];
    reader.read_exact(&mut raw_id).await?;
    let user_id = Uuid::from_bytes(raw_id);
    let addons_len = reader.read_u8().await? as usize;
    let mut addons = vec![0u8; addons_len];
    if addons_len > 0 {
        reader.read_exact(&mut addons).await?;
    }
    let command = Command::from_u8(reader.read_u8().await?)?;
    let dest = read_address(reader).await?;
    Ok(RequestHeader {
        user_id,
        addons,
        command,
        dest,
    })
}

/// 编码请求头。
pub fn encode_request(header: &RequestHeader) -> Result<Vec<u8>> {
    if header.addons.len() > u8::MAX as usize {
        return Err(Error::protocol("vless addons too long".to_string()));
    }
    let mut out = Vec::with_capacity(32);
    out.push(VERSION);
    out.extend_from_slice(header.user_id.as_bytes());
    out.push(header.addons.len() as u8);
    out.extend_from_slice(&header.addons);
    out.push(header.command.as_u8());
    encode_address(&header.dest, &mut out)?;
    Ok(out)
}

/// 读取响应头，返回其中的 addons。
pub async fn read_response<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Vec<u8>> {
    let version = reader.read_u8().await?;
    if version != VERSION {
        return Err(Error::protocol(format!(
            "unsupported vless response version {version}"
        )));
    }
    let addons_len = reader.read_u8().await? as usize;
    let mut addons = vec![0u8; addons_len];
    if addons_len > 0 {
        reader.read_exact(&mut addons).await?;
    }
    Ok(addons)
}

/// 编码响应头。
pub fn encode_response(addons: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(2 + addons.len());
    out.push(VERSION);
    out.push(addons.len() as u8);
    out.extend_from_slice(addons);
    out
}

/// 读取 VLESS 地址。
///
/// VLESS 采用「端口在前」的编码：`port(2) + address_type(1) + address`；
/// 这与 SOCKS5 的「端口在后」不同，切勿混用。
pub async fn read_address<R: AsyncRead + Unpin + ?Sized>(reader: &mut R) -> Result<Address> {
    crate::codec::read_address(reader, crate::codec::AddressStyle::Vmess).await
}

/// 编码 VLESS 地址（`port(2) + address_type(1) + address`）。
pub fn encode_address(dest: &Address, out: &mut Vec<u8>) -> Result<()> {
    crate::codec::write_address(dest, crate::codec::AddressStyle::Vmess, out)
}
