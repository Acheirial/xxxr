//! VMess 头部：内层请求头与外层 AEAD 封装（依据 `docs/vmess-protocol.md`）。
//!
//! 外层线上顺序：`AuthID(16) | LengthAEAD(18) | ConnectionNonce(8) | PayloadAEAD(L+16)`。
//! 内层明文为 38 字节定长字段 + 地址端口 + 填充 + 4 字节 FNV-1a 校验。

use rand::RngCore;
use tokio::io::{AsyncRead, AsyncReadExt};
use xxxr_common::{Error, Result};
use xxxr_config::VmessSecurity;
use xxxr_net::Address;

use super::crypto::{self, aes_gcm_open, aes_gcm_seal, create_auth_id, fnv1a32, header_nonce};
use super::kdf::kdf16;
use crate::codec::{write_address, AddressStyle};

/// 协议版本。
pub const VERSION: u8 = 1;
/// 命令：TCP。
pub const COMMAND_TCP: u8 = 0x01;
/// 命令：UDP。
pub const COMMAND_UDP: u8 = 0x02;
/// 命令：Mux。
pub const COMMAND_MUX: u8 = 0x03;
/// 选项位：ChunkStream（已废弃，保留位）。
pub const OPTION_CHUNK_STREAM: u8 = 0x01;
/// 选项位：ChunkMasking。
pub const OPTION_CHUNK_MASKING: u8 = 0x04;
/// 选项位：GlobalPadding。
pub const OPTION_GLOBAL_PADDING: u8 = 0x08;
/// 选项位：AuthenticatedLength。
pub const OPTION_AUTHENTICATED_LENGTH: u8 = 0x10;

/// 内层请求头。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestHeader {
    /// 协议版本（当前恒为 `1`）。
    pub version: u8,
    /// 请求体 IV。
    pub body_iv: [u8; 16],
    /// 请求体密钥。
    pub body_key: [u8; 16],
    /// 响应认证字节 V。
    pub response_header: u8,
    /// 选项位图。
    pub option: u8,
    /// 会话 `security`。
    pub security: VmessSecurity,
    /// 命令。
    pub command: u8,
    /// 目标地址。
    pub dest: Address,
}

impl RequestHeader {
    /// 选项位是否置位。
    pub fn has_option(&self, option: u8) -> bool {
        self.option & option != 0
    }
}

/// `security` 的线上取值（上游 `SecurityType` 枚举）。
fn security_to_wire(security: VmessSecurity) -> u8 {
    match security {
        VmessSecurity::Auto => 2,
        VmessSecurity::Aes128Gcm => 3,
        VmessSecurity::Chacha20Poly1305 => 4,
    }
}

/// 由线上取值还原 `security`；`auto` 之外的未知值一律按 `auto` 处理。
fn security_from_wire(value: u8) -> VmessSecurity {
    match value {
        3 => VmessSecurity::Aes128Gcm,
        4 => VmessSecurity::Chacha20Poly1305,
        _ => VmessSecurity::Auto,
    }
}

/// 编码内层请求头（明文）。
pub fn encode_inner(header: &RequestHeader, rng: &mut impl RngCore) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(64);
    out.push(header.version);
    out.extend_from_slice(&header.body_iv);
    out.extend_from_slice(&header.body_key);
    out.push(header.response_header);
    out.push(header.option);

    let padding_len = (rng.next_u32() % 16) as u8;
    let security_byte = (padding_len << 4) | security_to_wire(header.security);
    out.extend_from_slice(&[security_byte, 0x00, header.command]);

    if header.command != COMMAND_MUX {
        write_address(&header.dest, AddressStyle::Vmess, &mut out)?;
    }

    if padding_len > 0 {
        let mut padding = vec![0u8; padding_len as usize];
        rng.fill_bytes(&mut padding);
        out.extend_from_slice(&padding);
    }

    let checksum = fnv1a32(&out);
    out.extend_from_slice(&checksum.to_be_bytes());
    Ok(out)
}

/// 解码内层请求头（明文），并校验 FNV。
pub fn decode_inner(data: &[u8]) -> Result<RequestHeader> {
    if data.len() < 38 {
        return Err(Error::protocol("vmess: inner header too short".to_string()));
    }
    let version = data[0];
    let mut body_iv = [0u8; 16];
    body_iv.copy_from_slice(&data[1..17]);
    let mut body_key = [0u8; 16];
    body_key.copy_from_slice(&data[17..33]);
    let response_header = data[33];
    let option = data[34];
    let padding_len = (data[35] >> 4) as usize;
    let security = security_from_wire(data[35] & 0x0f);
    let command = data[37];

    let mut offset = 38;
    let dest = if command == COMMAND_MUX {
        Address::domain("v1.mux.cool", 0)
    } else if command == COMMAND_TCP || command == COMMAND_UDP {
        let (address, consumed) = read_address_at(&data[offset..])?;
        offset += consumed;
        address
    } else {
        return Err(Error::protocol(format!(
            "vmess: unsupported command {command}"
        )));
    };

    offset += padding_len;
    if data.len() < offset + 4 {
        return Err(Error::protocol("vmess: inner header truncated".to_string()));
    }
    let expected = u32::from_be_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
    ]);
    let actual = fnv1a32(&data[..offset]);
    if expected != actual {
        return Err(Error::protocol(
            "vmess: inner header checksum mismatch".to_string(),
        ));
    }

    Ok(RequestHeader {
        version,
        body_iv,
        body_key,
        response_header,
        option,
        security,
        command,
        dest,
    })
}

/// 从字节切片读取地址，返回（地址, 消耗字节数）。
fn read_address_at(data: &[u8]) -> Result<(Address, usize)> {
    let (begin, style) = (data, AddressStyle::Vmess);
    // 端口在前的风格：port(2) + atyp(1) + 变长地址
    if begin.len() < 3 {
        return Err(Error::protocol("vmess: address truncated".to_string()));
    }
    let port = u16::from_be_bytes([begin[0], begin[1]]);
    let kind = begin[2];
    let (address, host_len) = match kind {
        k if k == style.ipv4_type() => {
            if begin.len() < 7 {
                return Err(Error::protocol("vmess: ipv4 truncated".to_string()));
            }
            let mut raw = [0u8; 4];
            raw.copy_from_slice(&begin[3..7]);
            (Address::ip(std::net::IpAddr::from(raw), port), 4)
        }
        k if k == style.ipv6_type() => {
            if begin.len() < 19 {
                return Err(Error::protocol("vmess: ipv6 truncated".to_string()));
            }
            let mut raw = [0u8; 16];
            raw.copy_from_slice(&begin[3..19]);
            (Address::ip(std::net::IpAddr::from(raw), port), 16)
        }
        k if k == style.domain_type() => {
            let length = usize::from(begin[3]);
            if length == 0 || begin.len() < 4 + length {
                return Err(Error::protocol("vmess: domain truncated".to_string()));
            }
            let domain = std::str::from_utf8(&begin[4..4 + length])
                .map_err(|e| Error::protocol(format!("vmess: invalid domain: {e}")))?;
            (Address::domain(domain, port), 1 + length)
        }
        other => {
            return Err(Error::protocol(format!(
                "vmess: unsupported address type {other}"
            )));
        }
    };
    Ok((address, 3 + host_len))
}

/// 密封外层头：`AuthID | LengthAEAD | ConnectionNonce | PayloadAEAD`。
pub fn seal_header(cmd_key: &[u8; 16], inner: &[u8], rng: &mut impl RngCore) -> Result<Vec<u8>> {
    let mut connection_nonce = [0u8; 8];
    rng.fill_bytes(&mut connection_nonce);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs() as i64)
        .map_err(|e| Error::other(format!("system clock error: {e}")))?;
    let auth_id = create_auth_id(cmd_key, now, rng);

    let mut length = [0u8; 2];
    length.copy_from_slice(&(inner.len() as u16).to_be_bytes());

    let auth_id_slice = auth_id.as_slice();
    let nonce_slice = connection_nonce.as_slice();

    let length_key = kdf16(
        cmd_key,
        &[b"VMess Header AEAD Key_Length", auth_id_slice, nonce_slice],
    );
    let length_nonce = header_nonce(
        cmd_key,
        &[
            b"VMess Header AEAD Nonce_Length",
            auth_id_slice,
            nonce_slice,
        ],
    );
    let sealed_length = aes_gcm_seal(&length_key, &length_nonce, &length, &auth_id)?;

    let payload_key = kdf16(
        cmd_key,
        &[b"VMess Header AEAD Key", auth_id_slice, nonce_slice],
    );
    let payload_nonce = header_nonce(
        cmd_key,
        &[b"VMess Header AEAD Nonce", auth_id_slice, nonce_slice],
    );
    let sealed_payload = aes_gcm_seal(&payload_key, &payload_nonce, inner, &auth_id)?;

    let mut out = Vec::with_capacity(16 + 18 + 8 + sealed_payload.len());
    out.extend_from_slice(&auth_id);
    out.extend_from_slice(&sealed_length);
    out.extend_from_slice(&connection_nonce);
    out.extend_from_slice(&sealed_payload);
    Ok(out)
}

/// 打开外层头，返回内层明文。
pub async fn open_header<R: AsyncRead + Unpin + ?Sized>(
    cmd_key: &[u8; 16],
    auth_id: &[u8; 16],
    reader: &mut R,
) -> Result<Vec<u8>> {
    let mut sealed_length = [0u8; 18];
    reader.read_exact(&mut sealed_length).await?;
    let mut connection_nonce = [0u8; 8];
    reader.read_exact(&mut connection_nonce).await?;

    let auth_id_slice = auth_id.as_slice();
    let nonce_slice = connection_nonce.as_slice();

    let length_key = kdf16(
        cmd_key,
        &[b"VMess Header AEAD Key_Length", auth_id_slice, nonce_slice],
    );
    let length_nonce = header_nonce(
        cmd_key,
        &[
            b"VMess Header AEAD Nonce_Length",
            auth_id_slice,
            nonce_slice,
        ],
    );
    let length = aes_gcm_open(&length_key, &length_nonce, &sealed_length, auth_id)?;
    if length.len() != 2 {
        return Err(Error::protocol("vmess: invalid length field".to_string()));
    }
    let length = usize::from(u16::from_be_bytes([length[0], length[1]]));

    let mut sealed_payload = vec![0u8; length + 16];
    reader.read_exact(&mut sealed_payload).await?;

    let payload_key = kdf16(
        cmd_key,
        &[b"VMess Header AEAD Key", auth_id_slice, nonce_slice],
    );
    let payload_nonce = header_nonce(
        cmd_key,
        &[b"VMess Header AEAD Nonce", auth_id_slice, nonce_slice],
    );
    aes_gcm_open(&payload_key, &payload_nonce, &sealed_payload, auth_id)
}

/// 响应头：`LengthAEAD(18) | PayloadAEAD((2 + 2 + command) + 16)`。
///
/// 明文体为 `V(1) | Option(1)`，无命令时补 `0x00 0x00`。
pub fn encode_response_header(
    response_body_key: &[u8; 16],
    response_body_iv: &[u8; 16],
    response_header: u8,
    option: u8,
) -> Result<Vec<u8>> {
    let plain = [response_header, option, 0x00, 0x00];
    let length_key = kdf16(response_body_key, &[b"AEAD Resp Header Len Key"]);
    let length_nonce = header_nonce(response_body_iv, &[b"AEAD Resp Header Len IV"]);
    let mut length_plain = [0u8; 2];
    length_plain.copy_from_slice(&(plain.len() as u16).to_be_bytes());
    let sealed_length = aes_gcm_seal(&length_key, &length_nonce, &length_plain, &[])?;

    let payload_key = kdf16(response_body_key, &[b"AEAD Resp Header Key"]);
    let payload_nonce = header_nonce(response_body_iv, &[b"AEAD Resp Header IV"]);
    let sealed_payload = aes_gcm_seal(&payload_key, &payload_nonce, &plain, &[])?;

    let mut out = Vec::with_capacity(sealed_length.len() + sealed_payload.len());
    out.extend_from_slice(&sealed_length);
    out.extend_from_slice(&sealed_payload);
    Ok(out)
}

/// 解析响应头，校验 V 是否等于请求中的 `response_header`。
pub async fn decode_response_header<R: AsyncRead + Unpin + ?Sized>(
    response_body_key: &[u8; 16],
    response_body_iv: &[u8; 16],
    expected_v: u8,
    reader: &mut R,
) -> Result<()> {
    let mut sealed_length = [0u8; 18];
    reader.read_exact(&mut sealed_length).await?;
    let length_key = kdf16(response_body_key, &[b"AEAD Resp Header Len Key"]);
    let length_nonce = header_nonce(response_body_iv, &[b"AEAD Resp Header Len IV"]);
    let length = aes_gcm_open(&length_key, &length_nonce, &sealed_length, &[])?;
    if length.len() != 2 {
        return Err(Error::protocol(
            "vmess: invalid response length".to_string(),
        ));
    }
    let length = usize::from(u16::from_be_bytes([length[0], length[1]]));

    let mut sealed_payload = vec![0u8; length + 16];
    reader.read_exact(&mut sealed_payload).await?;
    let payload_key = kdf16(response_body_key, &[b"AEAD Resp Header Key"]);
    let payload_nonce = header_nonce(response_body_iv, &[b"AEAD Resp Header IV"]);
    let plain = aes_gcm_open(&payload_key, &payload_nonce, &sealed_payload, &[])?;

    let v = plain
        .first()
        .ok_or_else(|| Error::protocol("vmess: empty response header".to_string()))?;
    if *v != expected_v {
        return Err(Error::protocol(format!(
            "vmess: unexpected response header (expected {expected_v}, got {v})"
        )));
    }
    Ok(())
}

/// 由请求体密钥派生响应体密钥：`SHA256(key)[:16]`。
pub fn derive_response_key(key: &[u8; 16]) -> [u8; 16] {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(key);
    let mut out = [0u8; 16];
    out.copy_from_slice(&digest[..16]);
    out
}

/// 供其它模块使用的密码学助手再导出。
pub use crypto::BodyCipherKind;

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;

    fn rng() -> rand::rngs::StdRng {
        rand::rngs::StdRng::seed_from_u64(42)
    }

    fn sample_header(security: VmessSecurity, dest: Address) -> RequestHeader {
        RequestHeader {
            version: VERSION,
            body_iv: [1u8; 16],
            body_key: [2u8; 16],
            response_header: 0x7f,
            option: OPTION_CHUNK_MASKING | OPTION_GLOBAL_PADDING,
            security,
            command: COMMAND_TCP,
            dest,
        }
    }

    #[test]
    fn inner_header_round_trip_for_all_address_types() {
        for dest in [
            Address::ip("127.0.0.1".parse().unwrap(), 443),
            Address::ip("2001:db8::1".parse().unwrap(), 8443),
            Address::domain("example.com", 80),
        ] {
            for security in [
                VmessSecurity::Auto,
                VmessSecurity::Aes128Gcm,
                VmessSecurity::Chacha20Poly1305,
            ] {
                let header = sample_header(security, dest.clone());
                let mut rng = rng();
                let encoded = encode_inner(&header, &mut rng).expect("encode");
                let decoded = decode_inner(&encoded).expect("decode");
                assert_eq!(decoded, header);
                assert!(decoded.has_option(OPTION_CHUNK_MASKING));
                assert!(!decoded.has_option(OPTION_AUTHENTICATED_LENGTH));
            }
        }
    }

    #[test]
    fn inner_header_is_randomised_by_padding_length() {
        let header = sample_header(VmessSecurity::Aes128Gcm, Address::domain("a.b", 1));
        let mut rng = rng();
        let mut lengths = std::collections::HashSet::new();
        for _ in 0..64 {
            let encoded = encode_inner(&header, &mut rng).unwrap();
            lengths.insert(encoded.len());
        }
        // paddingLen 为 0..15，因此长度应当出现多种取值
        assert!(lengths.len() > 1, "padding must vary: {lengths:?}");
        assert!(decode_inner(&encode_inner(&header, &mut rng).unwrap()).is_ok());
    }

    #[test]
    fn inner_header_detects_tampering() {
        let header = sample_header(VmessSecurity::Aes128Gcm, Address::domain("a.b", 1));
        let mut rng = rng();
        let encoded = encode_inner(&header, &mut rng).unwrap();
        for index in 0..encoded.len() {
            let mut broken = encoded.clone();
            broken[index] ^= 0x01;
            // 篡改命令/地址类型等字段时可能变成其它合法结构，但校验和必须失败
            let result = decode_inner(&broken);
            assert!(
                result.is_err(),
                "tampered byte {index} must be rejected: {result:?}"
            );
        }
    }

    #[tokio::test]
    async fn outer_header_round_trip_and_tamper_detection() {
        let cmd_key = crypto::cmd_key(
            &uuid::Uuid::parse_str("b831381d-6324-4d53-ad4f-8cda48b30811").unwrap(),
        );
        let mut rng = rng();
        let inner = encode_inner(
            &sample_header(VmessSecurity::Chacha20Poly1305, Address::domain("x.y", 443)),
            &mut rng,
        )
        .unwrap();

        let sealed = seal_header(&cmd_key, &inner, &mut rng).unwrap();

        let mut auth_id = [0u8; 16];
        auth_id.copy_from_slice(&sealed[..16]);
        // AuthID 必须是能通过 CRC 与时间窗校验的合法值
        assert!(crypto::open_auth_id(&cmd_key, &auth_id).is_ok());
        let opened = open_header(&cmd_key, &auth_id, &mut &sealed[16..])
            .await
            .expect("open");
        assert_eq!(opened, inner);

        // 篡改 AuthID / LengthAEAD / nonce / payload 任意一处都应失败
        for index in 0..sealed.len() {
            let mut broken = sealed.clone();
            broken[index] ^= 0xff;
            let mut auth = [0u8; 16];
            auth.copy_from_slice(&broken[..16]);
            let result = open_header(&cmd_key, &auth, &mut &broken[16..]).await;
            assert!(result.is_err(), "tampered byte {index} must be rejected");
        }

        // 不同的 cmdKey 无法打开
        let other = crypto::cmd_key(
            &uuid::Uuid::parse_str("11111111-2222-3333-4444-555555555555").unwrap(),
        );
        assert!(open_header(&other, &auth_id, &mut &sealed[16..])
            .await
            .is_err());
    }

    #[tokio::test]
    async fn response_header_round_trip_and_v_check() {
        let key = [3u8; 16];
        let iv = [4u8; 16];
        let encoded = encode_response_header(&key, &iv, 0x42, OPTION_GLOBAL_PADDING).unwrap();
        decode_response_header(&key, &iv, 0x42, &mut encoded.as_slice())
            .await
            .expect("v matches");

        // V 不匹配必须报错
        assert!(
            decode_response_header(&key, &iv, 0x43, &mut encoded.as_slice())
                .await
                .is_err()
        );
        // 篡改密文必须报错
        let mut broken = encoded.clone();
        let last = broken.len() - 1;
        broken[last] ^= 0x01;
        assert!(
            decode_response_header(&key, &iv, 0x42, &mut broken.as_slice())
                .await
                .is_err()
        );
    }

    #[test]
    fn response_key_derivation_uses_sha256_prefix() {
        use sha2::{Digest, Sha256};
        let key = [9u8; 16];
        assert_eq!(&derive_response_key(&key)[..], &Sha256::digest(key)[..16]);
    }

    #[test]
    fn command_mux_has_synthetic_address() {
        let header = RequestHeader {
            command: COMMAND_MUX,
            ..sample_header(VmessSecurity::Auto, Address::domain("ignored", 1))
        };
        let mut rng = rng();
        let encoded = encode_inner(&header, &mut rng).unwrap();
        let decoded = decode_inner(&encoded).unwrap();
        assert_eq!(decoded.dest, Address::domain("v1.mux.cool", 0));
    }

    #[test]
    fn unknown_command_is_rejected() {
        let header = RequestHeader {
            command: 0x09,
            ..sample_header(VmessSecurity::Auto, Address::domain("a.b", 1))
        };
        let mut rng = rng();
        let encoded = encode_inner(&header, &mut rng).unwrap();
        assert!(decode_inner(&encoded).is_err());
    }
}
