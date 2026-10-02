//! VMess AEAD 的密码学原语：cmdKey、FNV-1a、AuthID、AEAD 封装。

use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit};
use aes::Aes128;
use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes128Gcm, Nonce};
use chacha20poly1305::ChaCha20Poly1305;
use md5::{Digest as _, Md5};
use rand::RngCore;
use uuid::Uuid;
use xxxr_common::{Error, Result};

use super::kdf::{kdf, kdf16};

/// `cmdKey` 的固定后缀（上游 `common/protocol/id.go:47`）。
const CMD_KEY_SUFFIX: &[u8] = b"c48619fe-8f02-49e0-b9e9-edf763e17e21";

/// AuthID 时间窗（秒），对齐上游 `authid.go:110`。
pub const AUTH_ID_WINDOW_SECONDS: i64 = 120;

/// 计算 `cmdKey = MD5(uuid || "c48619fe-8f02-49e0-b9e9-edf763e17e21")`。
pub fn cmd_key(id: &Uuid) -> [u8; 16] {
    let mut hasher = Md5::new();
    hasher.update(id.as_bytes());
    hasher.update(CMD_KEY_SUFFIX);
    let digest = hasher.finalize();
    let mut out = [0u8; 16];
    out.copy_from_slice(&digest);
    out
}

/// FNV-1a-32（上游 `fnv.New32a()`）。
pub fn fnv1a32(data: &[u8]) -> u32 {
    let mut hash: u32 = 0x811c_9dc5;
    for byte in data {
        hash ^= u32::from(*byte);
        hash = hash.wrapping_mul(0x0100_0193);
    }
    hash
}

/// AuthID 的 AES-128-ECB 密钥：`KDF16(cmdKey, "AES Auth ID Encryption")`。
pub fn auth_id_key(cmd_key: &[u8; 16]) -> [u8; 16] {
    kdf16(cmd_key, &[b"AES Auth ID Encryption"])
}

/// 用 AES-128-ECB 加密单个 16 字节分组。
fn ecb_encrypt(key: &[u8; 16], block: &[u8; 16]) -> [u8; 16] {
    let cipher = Aes128::new(key.into());
    let mut buffer = *block;
    let mut generic = aes::cipher::Block::<Aes128>::clone_from_slice(&buffer);
    cipher.encrypt_block(&mut generic);
    buffer.copy_from_slice(&generic);
    buffer
}

/// 用 AES-128-ECB 解密单个 16 字节分组。
fn ecb_decrypt(key: &[u8; 16], block: &[u8; 16]) -> [u8; 16] {
    let cipher = Aes128::new(key.into());
    let mut buffer = *block;
    let mut generic = aes::cipher::Block::<Aes128>::clone_from_slice(&buffer);
    cipher.decrypt_block(&mut generic);
    buffer.copy_from_slice(&generic);
    buffer
}

/// 生成 AuthID：`BE(unix_time, 8) || random(4) || BE(crc32(前 12 字节), 4)` 经 ECB 加密。
pub fn create_auth_id(cmd_key: &[u8; 16], unix_time: i64, rng: &mut impl RngCore) -> [u8; 16] {
    let mut plain = [0u8; 16];
    plain[..8].copy_from_slice(&unix_time.to_be_bytes());
    rng.fill_bytes(&mut plain[8..12]);
    let checksum = crc32fast::hash(&plain[..12]);
    plain[12..].copy_from_slice(&checksum.to_be_bytes());
    ecb_encrypt(&auth_id_key(cmd_key), &plain)
}

/// 解密并校验 AuthID，返回其中的时间戳（秒）。
///
/// 只做 CRC 与「非负」校验；时间窗由调用方按 [`AUTH_ID_WINDOW_SECONDS`] 判断。
pub fn open_auth_id(cmd_key: &[u8; 16], auth_id: &[u8; 16]) -> Result<i64> {
    let plain = ecb_decrypt(&auth_id_key(cmd_key), auth_id);
    let expected = crc32fast::hash(&plain[..12]);
    let actual = u32::from_be_bytes([plain[12], plain[13], plain[14], plain[15]]);
    if expected != actual {
        return Err(Error::protocol(
            "vmess: auth id checksum mismatch".to_string(),
        ));
    }
    let timestamp = i64::from_be_bytes([
        plain[0], plain[1], plain[2], plain[3], plain[4], plain[5], plain[6], plain[7],
    ]);
    if timestamp < 0 {
        return Err(Error::protocol(
            "vmess: negative auth id timestamp".to_string(),
        ));
    }
    Ok(timestamp)
}

/// 会话加密算法。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BodyCipherKind {
    /// AES-128-GCM。
    Aes128Gcm,
    /// ChaCha20-Poly1305。
    ChaCha20Poly1305,
}

impl BodyCipherKind {
    /// 由配置中的 `security` 解析；`auto` 落到 AES-128-GCM。
    pub fn from_security(security: xxxr_config::VmessSecurity) -> Self {
        match security {
            xxxr_config::VmessSecurity::Chacha20Poly1305 => Self::ChaCha20Poly1305,
            _ => Self::Aes128Gcm,
        }
    }

    /// 返回配置中的字符串表示。
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Aes128Gcm => "aes-128-gcm",
            Self::ChaCha20Poly1305 => "chacha20-poly1305",
        }
    }
}

/// 由 16 字节 IV 派生 ChaCha20-Poly1305 的 32 字节密钥（上游 `encoding/auth.go:21-28`）。
pub fn chacha_key_from_iv(iv: &[u8; 16]) -> [u8; 32] {
    let first = Md5::digest(iv);
    let second = Md5::digest(&first[..16]);
    let mut key = [0u8; 32];
    key[..16].copy_from_slice(&first);
    key[16..].copy_from_slice(&second);
    key
}

/// 分块 AEAD 的 nonce：`BE(counter) || iv[2..12]`（上游 `GenerateChunkNonce`）。
pub fn chunk_nonce(iv: &[u8; 16], counter: u16) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&iv[..12]);
    nonce[..2].copy_from_slice(&counter.to_be_bytes());
    nonce
}

/// 会话体加密器：AEAD 的封装（AES-128-GCM 或 ChaCha20-Poly1305）。
pub enum BodyCipher {
    /// AES-128-GCM，密钥为 `requestBodyKey` 本身。
    Aes128Gcm(Box<Aes128Gcm>),
    /// ChaCha20-Poly1305，密钥由 IV 派生。
    ChaCha20Poly1305(Box<ChaCha20Poly1305>),
}

impl BodyCipher {
    /// 依据算法与 16 字节会话密钥构建。
    pub fn new(kind: BodyCipherKind, key: &[u8; 16], iv: &[u8; 16]) -> Result<Self> {
        match kind {
            BodyCipherKind::Aes128Gcm => {
                let cipher = Aes128Gcm::new_from_slice(key)
                    .map_err(|e| Error::other(format!("invalid aes-128-gcm key: {e}")))?;
                Ok(Self::Aes128Gcm(Box::new(cipher)))
            }
            BodyCipherKind::ChaCha20Poly1305 => {
                let cipher = ChaCha20Poly1305::new_from_slice(&chacha_key_from_iv(iv))
                    .map_err(|e| Error::other(format!("invalid chacha20-poly1305 key: {e}")))?;
                Ok(Self::ChaCha20Poly1305(Box::new(cipher)))
            }
        }
    }

    /// 加密并附加 16 字节 tag。
    pub fn seal(&self, nonce: &[u8; 12], plaintext: &[u8]) -> Result<Vec<u8>> {
        let payload = Payload {
            msg: plaintext,
            aad: &[],
        };
        let nonce = Nonce::from_slice(nonce);
        match self {
            Self::Aes128Gcm(cipher) => cipher
                .encrypt(nonce, payload)
                .map_err(|_| Error::protocol("vmess: aes-gcm seal failed".to_string())),
            Self::ChaCha20Poly1305(cipher) => cipher
                .encrypt(nonce, payload)
                .map_err(|_| Error::protocol("vmess: chacha20-poly1305 seal failed".to_string())),
        }
    }

    /// 校验 tag 并解密。
    pub fn open(&self, nonce: &[u8; 12], ciphertext: &[u8]) -> Result<Vec<u8>> {
        let payload = Payload {
            msg: ciphertext,
            aad: &[],
        };
        let nonce = Nonce::from_slice(nonce);
        match self {
            Self::Aes128Gcm(cipher) => cipher
                .decrypt(nonce, payload)
                .map_err(|_| Error::protocol("vmess: aes-gcm open failed".to_string())),
            Self::ChaCha20Poly1305(cipher) => cipher
                .decrypt(nonce, payload)
                .map_err(|_| Error::protocol("vmess: chacha20-poly1305 open failed".to_string())),
        }
    }
}

/// AES-128-GCM 加密（带 AAD），用于 VMess 头部。
pub fn aes_gcm_seal(key: &[u8], nonce: &[u8; 12], plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    let cipher = Aes128Gcm::new_from_slice(key)
        .map_err(|e| Error::other(format!("invalid aes-128-gcm key: {e}")))?;
    cipher
        .encrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| Error::protocol("vmess: aes-gcm seal failed".to_string()))
}

/// AES-128-GCM 解密（带 AAD），用于 VMess 头部。
pub fn aes_gcm_open(
    key: &[u8],
    nonce: &[u8; 12],
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>> {
    let cipher = Aes128Gcm::new_from_slice(key)
        .map_err(|e| Error::other(format!("invalid aes-128-gcm key: {e}")))?;
    cipher
        .decrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| Error::protocol("vmess: aes-gcm open failed".to_string()))
}

/// 头部 AEAD 的 12 字节 nonce：取 [`kdf`] 结果的前 12 字节。
pub fn header_nonce(key: &[u8], path: &[&[u8]]) -> [u8; 12] {
    let full = kdf(key, path);
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&full[..12]);
    nonce
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cmd_key_matches_upstream() {
        let id = Uuid::parse_str("b831381d-6324-4d53-ad4f-8cda48b30811").unwrap();
        assert_eq!(
            hex::encode(cmd_key(&id)),
            "b50d916ac0cec067981af8e5f38a758f"
        );
    }

    #[test]
    fn fnv1a_matches_upstream() {
        assert_eq!(fnv1a32(b""), 0x811c_9dc5);
        assert_eq!(fnv1a32(b"hello"), 0x4f9f_2cab);
        assert_eq!(fnv1a32(b"abcdefghijklmnopqrstuvwxyz"), 0xb0bc_0c82);
    }

    #[test]
    fn auth_id_ecb_matches_upstream_vector() {
        // 与 docs/test-vectors/vmess-aead.json 的 `vmess.authid.key` 交叉校验
        let key = auth_id_key(b"0123456789abcdef");
        assert_eq!(hex::encode(key), "ebde3a0b17bf94c86fa140917ec6a0c9");
        let cmd_key: [u8; 16] = hex::decode("30313233343536373839616263646566")
            .unwrap()
            .try_into()
            .unwrap();
        assert_eq!(hex::encode(auth_id_key(&cmd_key)), hex::encode(key));
        let mut plain = [0u8; 16];
        plain.copy_from_slice(&hex::decode("000000006553f1001122334455667788").expect("hex"));
        let checksum = crc32fast::hash(&plain[..12]);
        plain[12..].copy_from_slice(&checksum.to_be_bytes());
        assert_eq!(hex::encode(plain), "000000006553f10011223344799b13eb");
        assert_eq!(
            hex::encode(ecb_encrypt(&key, &plain)),
            "e38c6b954b5a474a6740ead6389f72d6"
        );
        // 解密回去应当得到同一明文
        assert_eq!(ecb_decrypt(&key, &ecb_encrypt(&key, &plain)), plain);
    }

    #[test]
    fn auth_id_round_trip_and_tamper_detection() {
        let key = cmd_key(&Uuid::parse_str("b831381d-6324-4d53-ad4f-8cda48b30811").unwrap());
        let mut rng = rand::rngs::mock::StepRng::new(0x1234_5678, 0x9abc_def0);
        let auth_id = create_auth_id(&key, 1_700_000_000, &mut rng);
        assert_eq!(open_auth_id(&key, &auth_id).unwrap(), 1_700_000_000);

        // 篡改任意一个字节都应失败（CRC 校验）
        for index in 0..16 {
            let mut broken = auth_id;
            broken[index] ^= 0x01;
            assert!(
                open_auth_id(&key, &broken).is_err(),
                "tampered byte {index} must be rejected"
            );
        }
        // 错误的 cmdKey 同样失败
        let other = cmd_key(&Uuid::parse_str("11111111-2222-3333-4444-555555555555").unwrap());
        assert!(open_auth_id(&other, &auth_id).is_err());
    }

    #[test]
    fn body_ciphers_round_trip_and_reject_tampering() {
        for kind in [BodyCipherKind::Aes128Gcm, BodyCipherKind::ChaCha20Poly1305] {
            let key = [7u8; 16];
            let iv = [9u8; 16];
            let cipher = BodyCipher::new(kind, &key, &iv).unwrap();
            let nonce = chunk_nonce(&iv, 0);
            let sealed = cipher.seal(&nonce, b"payload").unwrap();
            assert_eq!(sealed.len(), 7 + 16);
            assert_eq!(cipher.open(&nonce, &sealed).unwrap(), b"payload");

            let mut broken = sealed.clone();
            broken[0] ^= 0xff;
            assert!(cipher.open(&nonce, &broken).is_err(), "{kind:?}");

            // 不同的 nonce 计数器不应解密成功
            assert!(
                cipher.open(&chunk_nonce(&iv, 1), &sealed).is_err(),
                "{kind:?}"
            );
        }
    }

    #[test]
    fn chunk_nonce_layout() {
        let iv = [0xaa, 0xbb, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14];
        assert_eq!(
            chunk_nonce(&iv, 0x0102),
            [0x01, 0x02, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10]
        );
    }

    #[test]
    fn chacha_key_derivation_is_md5_of_md5() {
        let iv = [0u8; 16];
        let key = chacha_key_from_iv(&iv);
        let first = Md5::digest(iv);
        assert_eq!(&key[..16], &first[..]);
        assert_eq!(&key[16..], &Md5::digest(&first[..16])[..]);
    }
}
