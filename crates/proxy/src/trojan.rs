//! Trojan 协议编解码（依据 `docs/trojan-protocol.md`，上游 v26.9.30）。
//!
//! 请求头字节序列：
//!
//! ```text
//! hex(SHA-224(password))(56) | CRLF | command(1) | 地址 | port(2) | CRLF
//! ```
//!
//! 地址风格为 SOCKS5 同族（ATYP `1/4/3`，地址在前、端口在后），与 VLESS/VMess 相反。
//! Trojan 协议层没有独立响应头：认证通过后直接双向转发目标数据。

use sha2::{Digest, Sha224};
use tokio::io::{AsyncRead, AsyncReadExt};
use xxxr_common::{Error, Result};
use xxxr_net::Address;

use crate::codec::{read_address, write_address, AddressStyle};

/// 认证键（`hex(SHA-224(password))`）的长度。
pub const KEY_LEN: usize = 56;
/// 请求行分隔符。
pub const CRLF: [u8; 2] = [0x0d, 0x0a];
/// 命令：TCP CONNECT。
pub const COMMAND_TCP: u8 = 0x01;
/// 命令：UDP ASSOCIATE。
pub const COMMAND_UDP: u8 = 0x03;

/// 计算线上认证键：`hex(SHA-224(password))`，56 个小写十六进制字符。
///
/// 注意：上游发送的就是这 56 字节 ASCII 本身；服务端把收到的 56 字节再 hex
/// 一次作为查表键，因此**大写十六进制不会被接受**，本函数始终输出小写。
pub fn password_key(password: &str) -> String {
    let digest = Sha224::digest(password.as_bytes());
    hex::encode(digest)
}

/// 校验一个认证键是否为 56 位十六进制。
pub fn is_valid_key(key: &str) -> bool {
    key.len() == KEY_LEN && key.bytes().all(|byte| byte.is_ascii_hexdigit())
}

/// 已解析的请求头。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestHeader {
    /// 认证键（56 字节 ASCII）。
    pub key: String,
    /// 命令（`1` = TCP，`3` = UDP）。
    pub command: u8,
    /// 目标地址。
    pub dest: Address,
}

impl RequestHeader {
    /// 是否为 TCP 命令。
    pub fn is_tcp(&self) -> bool {
        self.command == COMMAND_TCP
    }
}

/// 读取并解析请求头。
pub async fn read_request<R: AsyncRead + Unpin>(reader: &mut R) -> Result<RequestHeader> {
    let mut raw = [0u8; KEY_LEN];
    reader.read_exact(&mut raw).await?;
    let key = String::from_utf8_lossy(&raw).into_owned();
    expect_crlf(reader).await?;

    let command = reader.read_u8().await?;
    let dest = read_address(reader, AddressStyle::Socks).await?;
    expect_crlf(reader).await?;

    Ok(RequestHeader { key, command, dest })
}

/// 编码请求头（客户端侧）。
pub fn encode_request(key: &str, dest: &Address, command: u8) -> Result<Vec<u8>> {
    if !is_valid_key(key) {
        return Err(Error::protocol(format!(
            "invalid trojan key: expected {KEY_LEN} hex characters"
        )));
    }
    let mut out = Vec::with_capacity(KEY_LEN + 8);
    out.extend_from_slice(key.as_bytes());
    out.extend_from_slice(&CRLF);
    out.push(command);
    write_address(dest, AddressStyle::Socks, &mut out)?;
    out.extend_from_slice(&CRLF);
    Ok(out)
}

/// 读取并校验 CRLF。
async fn expect_crlf<R: AsyncRead + Unpin>(reader: &mut R) -> Result<()> {
    let mut crlf = [0u8; 2];
    reader.read_exact(&mut crlf).await?;
    if crlf != CRLF {
        return Err(Error::protocol("trojan: expected CRLF".to_string()));
    }
    Ok(())
}

/// 上游的首帧判定：前 56 字节为键、第 57 字节为 `\r`。
pub fn looks_like_request(first: &[u8]) -> bool {
    first.len() >= 58 && first[KEY_LEN] == b'\r'
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 来自上游实现（Go `sha256.Sum224`）的固定向量。
    #[test]
    fn password_key_matches_upstream_vectors() {
        assert_eq!(
            password_key("password"),
            "d63dc919e201d7bc4c825630d2cf25fdc93d4b2f0d46706d29038d01"
        );
        assert_eq!(
            password_key("12345678"),
            "7e6a4309ddf6e8866679f61ace4f621b0e3455ebac2e831a60f13cd1"
        );
        assert_eq!(
            password_key(""),
            "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f"
        );
        assert_eq!(password_key("password").len(), KEY_LEN);
        assert!(is_valid_key(&password_key("x")));
        assert!(!is_valid_key("short"));
        // 大写仍是合法十六进制，但与用户表（小写）不相等 → 线上不会被接受。
        let lower = password_key("x");
        let upper = lower.to_uppercase();
        assert!(is_valid_key(&upper));
        assert_ne!(lower, upper);
    }

    #[tokio::test]
    async fn request_round_trip_for_all_address_types() {
        let key = password_key("secret");
        for dest in [
            Address::ip("127.0.0.1".parse().unwrap(), 443),
            Address::ip("2001:db8::1".parse().unwrap(), 8443),
            Address::domain("example.com", 80),
        ] {
            let encoded = encode_request(&key, &dest, COMMAND_TCP).unwrap();
            // 固定布局：56 字节键 + CRLF + command + 地址 + CRLF
            assert_eq!(&encoded[..KEY_LEN], key.as_bytes());
            assert_eq!(&encoded[KEY_LEN..KEY_LEN + 2], &CRLF);
            assert_eq!(encoded[KEY_LEN + 2], COMMAND_TCP);
            assert_eq!(&encoded[encoded.len() - 2..], &CRLF);

            let parsed = read_request(&mut encoded.as_slice()).await.unwrap();
            assert_eq!(parsed.key, key);
            assert_eq!(parsed.command, COMMAND_TCP);
            assert_eq!(parsed.dest, dest);
            assert!(parsed.is_tcp());
            assert!(looks_like_request(&encoded));
        }
    }

    #[tokio::test]
    async fn udp_command_is_parsed_but_not_tcp() {
        let key = password_key("secret");
        let dest = Address::domain("udp.example", 53);
        let encoded = encode_request(&key, &dest, COMMAND_UDP).unwrap();
        let parsed = read_request(&mut encoded.as_slice()).await.unwrap();
        assert_eq!(parsed.command, COMMAND_UDP);
        assert!(!parsed.is_tcp());
    }

    #[tokio::test]
    async fn rejects_bad_crlf_and_short_input() {
        let key = password_key("secret");
        let mut encoded = encode_request(&key, &Address::domain("a.b", 1), COMMAND_TCP).unwrap();
        encoded[KEY_LEN] = b'X';
        assert!(read_request(&mut encoded.as_slice()).await.is_err());
        assert!(read_request(&mut b"too short".as_slice()).await.is_err());
        assert!(!looks_like_request(b"short"));
    }

    #[test]
    fn rejects_invalid_key_on_encode() {
        assert!(encode_request("not-a-key", &Address::domain("a.b", 1), COMMAND_TCP).is_err());
    }
}
