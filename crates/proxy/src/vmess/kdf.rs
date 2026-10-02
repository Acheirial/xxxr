//! VMess AEAD 的 KDF。
//!
//! 上游 `proxy/vmess/aead/kdf.go` 用了一个自引用的 HMAC 技巧：新一层的
//! `hmac.New` 的 hash 工厂在两次调用中都返回**同一个**上一层 HMAC 对象，
//! 于是新旧 HMAC 共享底层状态，`Sum()` 里的 `outer.Reset()` 会连带清空
//! `inner`。这不是常规的「嵌套 HMAC」，必须逐语义复刻，否则派生的密钥全错。
//!
//! 本模块用 [`GoHash`] 抽象精确建模 Go `hash.Hash` 的语义（`Write` 累积、
//! `Sum` 不重置状态、`Reset` 回到 ipad 状态），再逐行照搬 `kdf.go` 的结构。
//! 单元测试用上游 Go 实现生成的固定向量校验。

use std::cell::RefCell;
use std::rc::Rc;

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

/// KDF 的盐常量。
pub const KDF_SALT: &str = "VMess AEAD KDF";

/// 复刻 Go `hash.Hash` 的语义。
trait GoHash {
    /// 追加数据。
    fn write(&mut self, data: &[u8]);
    /// 计算摘要（**不**重置状态）。
    fn sum(&self) -> Vec<u8>;
    /// 重置到 ipad 状态。
    fn reset(&mut self);
    /// 摘要长度。
    fn size(&self) -> usize;
    /// 块长度。
    fn block_size(&self) -> usize;
}

/// 叶子哈希：SHA-256。
struct Sha256Leaf(Sha256);

impl Sha256Leaf {
    fn new() -> Self {
        Self(Sha256::new())
    }
}

impl GoHash for Sha256Leaf {
    fn write(&mut self, data: &[u8]) {
        Digest::update(&mut self.0, data);
    }

    fn sum(&self) -> Vec<u8> {
        // 克隆后 finalize，保持自身状态不变（对应 Go 的 Sum）。
        self.0.clone().finalize().to_vec()
    }

    fn reset(&mut self) {
        self.0 = Sha256::new();
    }

    fn size(&self) -> usize {
        32
    }

    fn block_size(&self) -> usize {
        64
    }
}

/// 共享句柄：多个「哈希实例」指向同一个底层对象（对应上游 `hash2{hmacf}` 与 `hmacf`）。
#[derive(Clone)]
struct Shared(Rc<RefCell<Box<dyn GoHash>>>);

impl Shared {
    fn new(hash: Box<dyn GoHash>) -> Self {
        Self(Rc::new(RefCell::new(hash)))
    }
}

impl GoHash for Shared {
    fn write(&mut self, data: &[u8]) {
        self.0.borrow_mut().write(data);
    }

    fn sum(&self) -> Vec<u8> {
        self.0.borrow().sum()
    }

    fn reset(&mut self) {
        self.0.borrow_mut().reset();
    }

    fn size(&self) -> usize {
        self.0.borrow().size()
    }

    fn block_size(&self) -> usize {
        self.0.borrow().block_size()
    }
}

/// 复刻 Go `crypto/internal/fips140/hmac` 的 HMAC 对象。
struct GoHmac {
    inner: Shared,
    outer: Shared,
    size: usize,
    block: usize,
    ipad: Vec<u8>,
    opad: Vec<u8>,
}

impl GoHmac {
    fn new(factory: impl Fn() -> Shared, key: &[u8]) -> Self {
        // 与 Go 一致：先 outer 再 inner，且两次调用返回同一个对象。
        let outer = factory();
        let inner = factory();
        let block = inner.block_size();
        let mut ipad = vec![0u8; block];
        let mut opad = vec![0u8; block];
        let key = if key.len() > block {
            let mut outer = outer.clone();
            outer.write(key);
            outer.sum()
        } else {
            key.to_vec()
        };
        ipad[..key.len()].copy_from_slice(&key);
        opad[..key.len()].copy_from_slice(&key);
        for byte in ipad.iter_mut() {
            *byte ^= 0x36;
        }
        for byte in opad.iter_mut() {
            *byte ^= 0x5c;
        }
        let size = inner.size();
        let mut seeded = inner.clone();
        seeded.write(&ipad);
        Self {
            inner,
            outer,
            size,
            block,
            ipad,
            opad,
        }
    }
}

impl GoHash for GoHmac {
    fn write(&mut self, data: &[u8]) {
        self.inner.write(data);
    }

    fn sum(&self) -> Vec<u8> {
        let digest = self.inner.sum();
        let mut outer = self.outer.clone();
        outer.reset();
        outer.write(&self.opad);
        outer.write(&digest);
        outer.sum()
    }

    fn reset(&mut self) {
        self.inner.reset();
        self.inner.write(&self.ipad);
    }

    fn size(&self) -> usize {
        self.size
    }

    fn block_size(&self) -> usize {
        self.block
    }
}

/// `KDF(key, path...)`：返回 32 字节。
///
/// `path` 的每个元素是**字节串**：上游把 AuthID / ConnectionNonce 等原始字节
/// 直接当作 path 元素传入，因此这里不能用 `&str`。
pub fn kdf(key: &[u8], path: &[&[u8]]) -> [u8; 32] {
    let mut hmacf = Shared::new(Box::new(GoHmac::new(
        || Shared::new(Box::new(Sha256Leaf::new())),
        KDF_SALT.as_bytes(),
    )));
    for element in path {
        let previous = hmacf.clone();
        hmacf = Shared::new(Box::new(GoHmac::new(|| previous.clone(), element)));
    }
    hmacf.write(key);
    let digest = hmacf.sum();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest[..32]);
    out
}

/// `KDF16(key, path...)`：取 [`kdf`] 结果的前 16 字节。
pub fn kdf16(key: &[u8], path: &[&[u8]]) -> [u8; 16] {
    let full = kdf(key, path);
    let mut out = [0u8; 16];
    out.copy_from_slice(&full[..16]);
    out
}

/// 供其它模块复用的 HMAC-SHA256（标准 HMAC，非 KDF 技巧）。
pub fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("hmac accepts any key length");
    mac.update(data);
    let out = mac.finalize().into_bytes();
    let mut result = [0u8; 32];
    result.copy_from_slice(&out);
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 由上游 Go 实现（`proxy/vmess/aead/kdf.go`）生成的固定向量。
    #[test]
    fn kdf_matches_upstream_vectors() {
        assert_eq!(
            hex::encode(kdf(
                b"Demo Key for Auth ID Test",
                &[b"Demo Path for Auth ID Test"]
            )),
            "66e41ad47fa745fbfd1e97325e93dbf4a04daac03e50fdf3052da7136662dfe1"
        );
        assert_eq!(
            hex::encode(kdf(b"0123456789abcdef", &[b"AES Auth ID Encryption"])),
            "ebde3a0b17bf94c86fa140917ec6a0c9773a777693a18a40bb09b38fb9b0b816"
        );
        assert_eq!(
            hex::encode(kdf(
                b"0123456789abcdef",
                &[b"VMess Header AEAD Key", b"AAP", b"NONCE123"]
            )),
            "bcbc3fe0d6356eca20d8637211622eced569ffbb5578879d2771d232b3d6a580"
        );
        assert_eq!(
            hex::encode(kdf(b"k", &[b"a", b"b", b"c"])),
            "87c2868e71bdf5392ff0787cb70aafdd321d22b119302c7b075cf0098f6cde8d"
        );
    }

    /// 与 `docs/test-vectors/vmess-aead.json`（另一 worker 由上游 Go 源码独立推导）
    /// 交叉校验：空 path、单 path、多 path 三组取值完全一致。
    #[test]
    fn kdf_matches_documented_test_vectors() {
        assert_eq!(
            hex::encode(kdf(b"Demo Key for Auth ID Test", &[])),
            "7b9d2c2e1fab0b407a2ec00bab371b9667ca35f6674086ef384251821f6005f8"
        );
        assert_eq!(
            hex::encode(kdf(
                b"Demo Key for Auth ID Test",
                &[b"Demo Path for Auth ID Test"]
            )),
            "66e41ad47fa745fbfd1e97325e93dbf4a04daac03e50fdf3052da7136662dfe1"
        );
        assert_eq!(
            hex::encode(kdf(b"key material", &[b"A", b"B"])),
            "1b8cf8b2e33405f9926de2562cc93772761b5a6cca936e048bb1bea207aa5d96"
        );
        assert_eq!(
            hex::encode(kdf16(b"key material", &[b"A", b"B"])),
            "1b8cf8b2e33405f9926de2562cc93772"
        );
    }

    #[test]
    fn kdf16_is_a_prefix_of_kdf() {
        let full = kdf(b"key", &[b"path"]);
        assert_eq!(kdf16(b"key", &[b"path"]), full[..16]);
    }

    #[test]
    fn kdf_depends_on_path_order_and_length() {
        assert_ne!(kdf(b"k", &[b"a", b"b"]), kdf(b"k", &[b"b", b"a"]));
        assert_ne!(kdf(b"k", &[b"a"]), kdf(b"k", &[b"a", b"a"]));
        assert_ne!(kdf(b"k1", &[b"a"]), kdf(b"k2", &[b"a"]));
    }

    #[test]
    fn hmac_sha256_is_standard() {
        // RFC 4231 test case 1
        assert_eq!(
            hex::encode(hmac_sha256(&[0x0b; 20], b"Hi There")),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        );
    }
}
