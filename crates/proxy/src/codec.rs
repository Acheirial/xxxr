//! 地址编解码：不同协议对 ATYP 取值与端口位置的定义不同。
//!
//! 上游把这两件事建模为 `AddressFamilyByte` 与 `PortThenAddress()` 两个选项
//! （`common/protocol/address.go`）。本模块把它们合并成一个枚举，避免各协议
//! 各自手写一份而把顺序写错（VLESS/VMess 与 SOCKS5/Trojan 恰好相反）。
//!
//! | 风格 | ATYP (IPv4/Domain/IPv6) | 顺序 |
//! |---|---|---|
//! | [`AddressStyle::Socks`]（SOCKS5、Trojan） | `1/3/4` | 地址在前、端口在后 |
//! | [`AddressStyle::Vmess`]（VLESS、VMess、Mux） | `1/2/3` | 端口在前、地址在后 |

use std::net::IpAddr;

use tokio::io::{AsyncRead, AsyncReadExt};
use xxxr_common::{Error, Result};
use xxxr_net::Address;

/// 地址编码风格。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressStyle {
    /// SOCKS5 / Trojan：`1/3/4`，地址在前、2 字节大端端口在后。
    Socks,
    /// VLESS / VMess：`1/2/3`，2 字节大端端口在前、地址在后。
    Vmess,
}

impl AddressStyle {
    /// IPv4 的 ATYP。
    pub fn ipv4_type(self) -> u8 {
        0x01
    }

    /// 域名的 ATYP。
    pub fn domain_type(self) -> u8 {
        match self {
            Self::Socks => 0x03,
            Self::Vmess => 0x02,
        }
    }

    /// IPv6 的 ATYP。
    pub fn ipv6_type(self) -> u8 {
        match self {
            Self::Socks => 0x04,
            Self::Vmess => 0x03,
        }
    }

    /// 端口是否在地址之前。
    pub fn port_first(self) -> bool {
        matches!(self, Self::Vmess)
    }
}

/// 读取一个地址（含端口）。
pub async fn read_address<R: AsyncRead + Unpin + ?Sized>(
    reader: &mut R,
    style: AddressStyle,
) -> Result<Address> {
    if style.port_first() {
        let port = reader.read_u16().await?;
        let kind = reader.read_u8().await?;
        read_host(reader, style, kind, port).await
    } else {
        let kind = reader.read_u8().await?;
        let host = read_host(reader, style, kind, 0).await?;
        let port = reader.read_u16().await?;
        Ok(Address { port, ..host })
    }
}

/// 读取地址主体（不含端口），`port` 为已知端口（端口在前的风格）。
async fn read_host<R: AsyncRead + Unpin + ?Sized>(
    reader: &mut R,
    style: AddressStyle,
    kind: u8,
    port: u16,
) -> Result<Address> {
    if kind == style.ipv4_type() {
        let mut raw = [0u8; 4];
        reader.read_exact(&mut raw).await?;
        return Ok(Address::ip(IpAddr::from(raw), port));
    }
    if kind == style.ipv6_type() {
        let mut raw = [0u8; 16];
        reader.read_exact(&mut raw).await?;
        return Ok(Address::ip(IpAddr::from(raw), port));
    }
    if kind == style.domain_type() {
        let length = reader.read_u8().await? as usize;
        if length == 0 {
            return Err(Error::protocol("empty domain in address".to_string()));
        }
        let mut raw = vec![0u8; length];
        reader.read_exact(&mut raw).await?;
        let domain = String::from_utf8(raw)
            .map_err(|e| Error::protocol(format!("invalid domain in address: {e}")))?;
        return Ok(Address::domain(domain, port));
    }
    Err(Error::protocol(format!("unsupported address type {kind}")))
}

/// 写出一个地址（含端口）。
pub fn write_address(dest: &Address, style: AddressStyle, out: &mut Vec<u8>) -> Result<()> {
    if style.port_first() {
        out.extend_from_slice(&dest.port.to_be_bytes());
    }
    write_host(dest, style, out)?;
    if !style.port_first() {
        out.extend_from_slice(&dest.port.to_be_bytes());
    }
    Ok(())
}

/// 写出地址主体（不含端口）。
fn write_host(dest: &Address, style: AddressStyle, out: &mut Vec<u8>) -> Result<()> {
    match (&dest.domain, dest.ip) {
        (Some(domain), _) => {
            let bytes = domain.as_bytes();
            if bytes.len() > u8::MAX as usize {
                return Err(Error::protocol("domain too long".to_string()));
            }
            out.push(style.domain_type());
            out.push(bytes.len() as u8);
            out.extend_from_slice(bytes);
        }
        (None, Some(IpAddr::V4(v4))) => {
            out.push(style.ipv4_type());
            out.extend_from_slice(&v4.octets());
        }
        (None, Some(IpAddr::V6(v6))) => {
            out.push(style.ipv6_type());
            out.extend_from_slice(&v6.octets());
        }
        (None, None) => {
            return Err(Error::protocol(
                "address has neither domain nor ip".to_string(),
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn round_trip(style: AddressStyle, address: Address) {
        let mut out = Vec::new();
        write_address(&address, style, &mut out).expect("write");
        let parsed = read_address(&mut out.as_slice(), style)
            .await
            .expect("read");
        assert_eq!(parsed, address, "{style:?}");
    }

    #[tokio::test]
    async fn round_trips_both_styles() {
        for style in [AddressStyle::Socks, AddressStyle::Vmess] {
            round_trip(style, Address::domain("example.com", 443)).await;
            round_trip(style, Address::ip("127.0.0.1".parse().unwrap(), 80)).await;
            round_trip(style, Address::ip("2001:db8::1".parse().unwrap(), 65535)).await;
        }
    }

    #[tokio::test]
    async fn styles_use_different_atyp_and_order() {
        let address = Address::ip("127.0.0.1".parse().unwrap(), 0x0102);
        let mut socks = Vec::new();
        write_address(&address, AddressStyle::Socks, &mut socks).unwrap();
        assert_eq!(socks, vec![0x01, 127, 0, 0, 1, 0x01, 0x02]);

        let mut vmess = Vec::new();
        write_address(&address, AddressStyle::Vmess, &mut vmess).unwrap();
        assert_eq!(vmess, vec![0x01, 0x02, 0x01, 127, 0, 0, 1]);

        // IPv6 的 ATYP 在两种风格下不同。
        let v6 = Address::ip("::1".parse().unwrap(), 1);
        let mut socks = Vec::new();
        write_address(&v6, AddressStyle::Socks, &mut socks).unwrap();
        assert_eq!(socks[0], 0x04);
        let mut vmess = Vec::new();
        write_address(&v6, AddressStyle::Vmess, &mut vmess).unwrap();
        assert_eq!(vmess[2], 0x03);
    }

    #[tokio::test]
    async fn rejects_unknown_type_and_empty_domain() {
        let mut input: &[u8] = &[0x09, 0, 0];
        assert!(read_address(&mut input, AddressStyle::Vmess).await.is_err());
        let mut input: &[u8] = &[0x00, 0x01, 0x02, 0x00];
        assert!(read_address(&mut input, AddressStyle::Vmess).await.is_err());
    }
}
