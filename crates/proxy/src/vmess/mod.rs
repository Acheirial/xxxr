//! VMess（AEAD）协议实现。
//!
//! 模块划分对齐上游 `proxy/vmess/{aead,encoding}` 与 `common/crypto`：
//! - [`kdf`]：`KDF`/`KDF16`（含上游自引用 HMAC 语义的精确复刻）；
//! - [`crypto`]：cmdKey、FNV-1a、AuthID、AEAD 封装；
//! - [`header`]：内层请求头与外层 AEAD 封装、响应头；
//! - [`chunk`]：会话体的 chunk 分帧（掩码 / 填充 / AuthenticatedLength）。
//!
//! 当前只实现 AEAD 线格式（上游 v26.9.30 也只有这一种）；AES-128-CFB 在上游
//! 已是死代码，未实现。

pub mod chunk;
pub mod crypto;
pub mod header;
pub mod kdf;

pub use chunk::{ChunkParams, ChunkedStream, AEAD_OVERHEAD, BUFFER_SIZE};
pub use crypto::{cmd_key, BodyCipherKind};
pub use header::{
    RequestHeader, COMMAND_MUX, COMMAND_TCP, COMMAND_UDP, OPTION_AUTHENTICATED_LENGTH,
    OPTION_CHUNK_MASKING, OPTION_CHUNK_STREAM, OPTION_GLOBAL_PADDING, VERSION,
};
