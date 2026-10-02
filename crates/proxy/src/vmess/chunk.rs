//! VMess 会话体分帧（chunk stream）。
//!
//! 每个 chunk 为 `[size 字段][AEAD 密文][明文填充]`：
//! - `size` = 密文长度（明文 + 16 字节 tag）+ 填充长度，按大端 2 字节；
//! - 若启用 ChunkMasking，size 字段与填充长度都用 `SHAKE128(iv)` 生成的掩码异或；
//! - 若启用 AuthenticatedLength，size 字段本身再包一层 AEAD（18 字节）；
//! - 写空明文即为结束标记（下游读到 `size == 16 + padding` 时视为 EOF）。
//!
//! 读取方向与写入方向各有独立的密钥 / IV / 掩码流与 nonce 计数器，因此
//! [`ChunkedStream`] 分别保存两套参数。

use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::{Buf, BytesMut};
use rand::RngCore;
use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::{Shake128, Shake128Reader};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use xxxr_common::{Error, Result};
use xxxr_net::Conn;

use super::crypto::{chunk_nonce, BodyCipher, BodyCipherKind};
use super::header::{OPTION_AUTHENTICATED_LENGTH, OPTION_CHUNK_MASKING, OPTION_GLOBAL_PADDING};
use super::kdf::kdf16;

/// AEAD tag 开销。
pub const AEAD_OVERHEAD: usize = 16;
/// 上游的缓冲上限（`buf.Size`）。
pub const BUFFER_SIZE: usize = 8192;
/// 全局填充上限。
pub const MAX_PADDING: usize = 64;
/// AuthenticatedLength 下 size 字段的字节数。
pub const AUTH_LENGTH_FIELD: usize = 2 + AEAD_OVERHEAD;

/// 一个方向的分帧参数。
#[derive(Debug, Clone)]
pub struct ChunkParams {
    /// 会话密钥（16 字节）。
    pub key: [u8; 16],
    /// 会话 IV（16 字节）。
    pub iv: [u8; 16],
    /// AEAD 算法。
    pub kind: BodyCipherKind,
    /// 是否启用 ChunkMasking。
    pub masking: bool,
    /// 是否启用 GlobalPadding。
    pub padding: bool,
    /// 是否启用 AuthenticatedLength。
    pub authenticated_length: bool,
}

impl ChunkParams {
    /// 由会话参数与请求选项构造。
    pub fn new(key: [u8; 16], iv: [u8; 16], kind: BodyCipherKind, option: u8) -> Self {
        Self {
            key,
            iv,
            kind,
            masking: option & OPTION_CHUNK_MASKING != 0,
            padding: option & OPTION_GLOBAL_PADDING != 0,
            authenticated_length: option & OPTION_AUTHENTICATED_LENGTH != 0,
        }
    }

    /// size 字段的字节数。
    fn size_field_bytes(&self) -> usize {
        if self.authenticated_length {
            AUTH_LENGTH_FIELD
        } else {
            2
        }
    }

    /// 单个 chunk 允许的最大明文长度。
    fn max_plaintext(&self) -> usize {
        let padding = if self.padding { MAX_PADDING } else { 0 };
        BUFFER_SIZE
            .saturating_sub(AEAD_OVERHEAD + self.size_field_bytes() + padding)
            .max(1)
    }
}

/// `SHAKE128(iv)` 生成的掩码流（对齐上游 `ShakeSizeParser`）。
struct ShakeMask {
    reader: Shake128Reader,
}

impl ShakeMask {
    fn new(iv: &[u8; 16]) -> Self {
        let mut shake = Shake128::default();
        shake.update(iv);
        Self {
            reader: shake.finalize_xof(),
        }
    }

    fn next(&mut self) -> u16 {
        let mut buffer = [0u8; 2];
        self.reader.read(&mut buffer);
        u16::from_be_bytes(buffer)
    }

    fn next_padding(&mut self) -> usize {
        usize::from(self.next() % MAX_PADDING as u16)
    }
}

/// 读取方向的分帧状态。
struct Reader {
    cipher: BodyCipher,
    params: ChunkParams,
    mask: ShakeMask,
    length_cipher: Option<BodyCipher>,
    counter: u16,
    inbuf: BytesMut,
    plain: BytesMut,
    eof: bool,
}

impl Reader {
    fn new(params: ChunkParams) -> Result<Self> {
        let cipher = BodyCipher::new(params.kind, &params.key, &params.iv)?;
        let length_cipher = if params.authenticated_length {
            let key = kdf16(&params.key, &[b"auth_len"]);
            Some(BodyCipher::new(params.kind, &key, &params.iv)?)
        } else {
            None
        };
        Ok(Self {
            cipher,
            mask: ShakeMask::new(&params.iv),
            params,
            length_cipher,
            counter: 0,
            inbuf: BytesMut::new(),
            plain: BytesMut::new(),
            eof: false,
        })
    }

    /// 尝试解出一个 chunk；数据不足返回 `Ok(None)`。
    fn try_decode(&mut self) -> Result<Option<()>> {
        let field = self.params.size_field_bytes();
        if self.inbuf.len() < field {
            return Ok(None);
        }
        // 填充长度与 size 的掩码顺序与上游一致：先取填充长度，再取 size 掩码。
        let padding = if self.params.padding {
            self.mask.next_padding()
        } else {
            0
        };
        let ciphertext_and_padding = if let Some(length_cipher) = &self.length_cipher {
            let nonce = chunk_nonce(&self.params.iv, self.counter);
            let plain = length_cipher.open(&nonce, &self.inbuf[..field])?;
            if plain.len() != 2 {
                return Err(Error::protocol("vmess: invalid length field".to_string()));
            }
            // `Decode` 会把 overhead 加回来，因此这里是「密文 + 填充」的长度。
            usize::from(u16::from_be_bytes([plain[0], plain[1]])) + AEAD_OVERHEAD
        } else {
            let encoded = u16::from_be_bytes([self.inbuf[0], self.inbuf[1]]);
            let size = if self.params.masking {
                self.mask.next() ^ encoded
            } else {
                encoded
            };
            usize::from(size)
        };

        if ciphertext_and_padding < AEAD_OVERHEAD + padding {
            return Err(Error::protocol(format!(
                "vmess: invalid chunk size {ciphertext_and_padding}"
            )));
        }
        if self.inbuf.len() < field + ciphertext_and_padding {
            return Ok(None);
        }
        self.inbuf.advance(field);
        let ciphertext_len = ciphertext_and_padding - padding;
        let ciphertext = self.inbuf.split_to(ciphertext_len);
        self.inbuf.advance(padding);

        if ciphertext_len == AEAD_OVERHEAD {
            // 空明文：结束标记（对齐上游，不校验 tag）。
            self.eof = true;
            return Ok(Some(()));
        }
        let nonce = chunk_nonce(&self.params.iv, self.counter);
        self.counter = self.counter.wrapping_add(1);
        let plain = self.cipher.open(&nonce, &ciphertext)?;
        self.plain.extend_from_slice(&plain);
        Ok(Some(()))
    }

    /// 从底层连接读取更多原始字节；返回是否仍有数据。
    fn poll_fill(
        &mut self,
        cx: &mut Context<'_>,
        inner: &mut Box<dyn Conn>,
    ) -> Poll<std::io::Result<bool>> {
        let mut chunk = [0u8; BUFFER_SIZE];
        let mut buffer = ReadBuf::new(&mut chunk);
        match Pin::new(&mut *inner).poll_read(cx, &mut buffer) {
            Poll::Ready(Ok(())) => {
                let filled = buffer.filled();
                if filled.is_empty() {
                    return Poll::Ready(Ok(false));
                }
                self.inbuf.extend_from_slice(filled);
                Poll::Ready(Ok(true))
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }
}

/// 写入方向的分帧状态。
struct Writer {
    cipher: BodyCipher,
    params: ChunkParams,
    mask: ShakeMask,
    length_cipher: Option<BodyCipher>,
    counter: u16,
    outbuf: Vec<u8>,
    /// 是否已写入结束标记。
    finished: bool,
}

impl Writer {
    fn new(params: ChunkParams) -> Result<Self> {
        let cipher = BodyCipher::new(params.kind, &params.key, &params.iv)?;
        let length_cipher = if params.authenticated_length {
            let key = kdf16(&params.key, &[b"auth_len"]);
            Some(BodyCipher::new(params.kind, &key, &params.iv)?)
        } else {
            None
        };
        Ok(Self {
            cipher,
            mask: ShakeMask::new(&params.iv),
            params,
            length_cipher,
            counter: 0,
            outbuf: Vec::new(),
            finished: false,
        })
    }

    /// 编码一个 chunk 追加到 `outbuf`。
    fn encode(&mut self, plaintext: &[u8], rng: &mut impl RngCore) -> Result<()> {
        let padding = if self.params.padding {
            self.mask.next_padding()
        } else {
            0
        };
        let nonce = chunk_nonce(&self.params.iv, self.counter);
        let ciphertext = self.cipher.seal(&nonce, plaintext)?;
        let size = ciphertext.len() + padding;

        if let Some(length_cipher) = &self.length_cipher {
            // 上游 `AEADChunkSizeParser.Encode` 写入的是 `size - overhead`
            // （即明文长度 + 填充），读取端再把它加回 overhead。
            let encoded = size - AEAD_OVERHEAD;
            let plain = (encoded as u16).to_be_bytes();
            let sealed = length_cipher.seal(&nonce, &plain)?;
            self.outbuf.extend_from_slice(&sealed);
        } else if self.params.masking {
            let encoded = self.mask.next() ^ (size as u16);
            self.outbuf.extend_from_slice(&encoded.to_be_bytes());
        } else {
            self.outbuf.extend_from_slice(&(size as u16).to_be_bytes());
        }

        self.outbuf.extend_from_slice(&ciphertext);
        if padding > 0 {
            let start = self.outbuf.len();
            self.outbuf.resize(start + padding, 0);
            rng.fill_bytes(&mut self.outbuf[start..]);
        }
        self.counter = self.counter.wrapping_add(1);
        Ok(())
    }

    /// 尽可能把 `outbuf` 写出去。
    fn try_flush(
        &mut self,
        cx: &mut Context<'_>,
        inner: &mut Box<dyn Conn>,
    ) -> Poll<std::io::Result<()>> {
        while !self.outbuf.is_empty() {
            match Pin::new(&mut *inner).poll_write(cx, &self.outbuf) {
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(std::io::ErrorKind::WriteZero.into()));
                }
                Poll::Ready(Ok(written)) => {
                    self.outbuf.drain(..written);
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
        Poll::Ready(Ok(()))
    }
}

/// 在底层连接上透明地做 VMess chunk 分帧的连接包装。
///
/// 读方向使用 `read` 参数（对服务端是请求体、对客户端是响应体），
/// 写方向使用 `write` 参数，两者互不影响。
pub struct ChunkedStream {
    inner: Box<dyn Conn>,
    reader: Reader,
    writer: Writer,
}

impl ChunkedStream {
    /// 构造分帧连接。
    pub fn new(inner: Box<dyn Conn>, read: ChunkParams, write: ChunkParams) -> Result<Self> {
        Ok(Self {
            inner,
            reader: Reader::new(read)?,
            writer: Writer::new(write)?,
        })
    }
}

impl AsyncRead for ChunkedStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        let this = self.get_mut();
        loop {
            if !this.reader.plain.is_empty() {
                let take = std::cmp::min(buf.remaining(), this.reader.plain.len());
                buf.put_slice(&this.reader.plain[..take]);
                this.reader.plain.advance(take);
                return Poll::Ready(Ok(()));
            }
            if this.reader.eof {
                return Poll::Ready(Ok(()));
            }
            let decoded = match this.reader.try_decode() {
                Ok(decoded) => decoded,
                Err(e) => {
                    return Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        e.to_string(),
                    )));
                }
            };
            if decoded.is_some() {
                continue;
            }
            match this.reader.poll_fill(cx, &mut this.inner) {
                Poll::Ready(Ok(true)) => continue,
                Poll::Ready(Ok(false)) => {
                    // 底层关闭：若还有未解出的数据则视为截断。
                    if this.reader.inbuf.is_empty() {
                        this.reader.eof = true;
                        return Poll::Ready(Ok(()));
                    }
                    return Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::UnexpectedEof,
                        "vmess: connection closed mid-chunk",
                    )));
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl AsyncWrite for ChunkedStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        match this.writer.try_flush(cx, &mut this.inner) {
            Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Pending => return Poll::Pending,
        }

        let mut rng = rand::thread_rng();
        let take = std::cmp::min(buf.len(), this.writer.params.max_plaintext());
        let previous = this.writer.outbuf.len();
        if let Err(e) = this.writer.encode(&buf[..take], &mut rng) {
            this.writer.outbuf.truncate(previous);
            return Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                e.to_string(),
            )));
        }
        match Pin::new(&mut this.inner).poll_write(cx, &this.writer.outbuf[previous..]) {
            Poll::Ready(Ok(0)) => {
                this.writer.outbuf.truncate(previous);
                Poll::Ready(Err(std::io::ErrorKind::WriteZero.into()))
            }
            Poll::Ready(Ok(written)) => {
                this.writer.outbuf.drain(..previous + written);
                Poll::Ready(Ok(take))
            }
            Poll::Ready(Err(e)) => {
                this.writer.outbuf.truncate(previous);
                Poll::Ready(Err(e))
            }
            Poll::Pending => {
                this.writer.outbuf.truncate(previous);
                Poll::Pending
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        match this.writer.try_flush(cx, &mut this.inner) {
            Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Pending => return Poll::Pending,
        }
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        if !this.writer.finished {
            // 结束标记：空明文 chunk（对齐上游 WriteMultiBuffer(空)）。
            let mut rng = rand::thread_rng();
            let previous = this.writer.outbuf.len();
            if let Err(e) = this.writer.encode(&[], &mut rng) {
                this.writer.outbuf.truncate(previous);
                return Poll::Ready(Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    e.to_string(),
                )));
            }
            this.writer.finished = true;
        }
        match this.writer.try_flush(cx, &mut this.inner) {
            Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Pending => return Poll::Pending,
        }
        Pin::new(&mut this.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use tokio::io::AsyncReadExt;
    use tokio::io::AsyncWriteExt;

    fn params(kind: BodyCipherKind, option: u8, iv: u8) -> ChunkParams {
        ChunkParams::new([7u8; 16], [iv; 16], kind, option)
    }

    /// 把一个明文流编码成原始 VMess chunk 字节。
    async fn encode_stream(params: &ChunkParams, plaintext: &[u8]) -> Vec<u8> {
        let (writer_side, mut peer) = tokio::io::duplex(BUFFER_SIZE * 8);
        let mut writer =
            ChunkedStream::new(Box::new(writer_side), params.clone(), params.clone()).unwrap();
        let payload = plaintext.to_vec();
        let task = tokio::spawn(async move {
            writer.write_all(&payload).await.unwrap();
            writer.shutdown().await.unwrap();
        });
        let mut raw = Vec::new();
        peer.read_to_end(&mut raw).await.unwrap();
        task.await.unwrap();
        raw
    }

    /// 把原始字节喂给一个分帧读取端，返回读到的明文。
    async fn decode_stream(params: &ChunkParams, raw: &[u8]) -> std::io::Result<Vec<u8>> {
        let (mut sink, peer) = tokio::io::duplex(BUFFER_SIZE * 8);
        let mut reader =
            ChunkedStream::new(Box::new(peer), params.clone(), params.clone()).unwrap();
        let mut input = raw.to_vec();
        tokio::spawn(async move {
            let _ = sink.write_all(&input).await;
            let _ = sink.shutdown().await;
            input.clear();
        });
        let mut received = Vec::new();
        reader.read_to_end(&mut received).await?;
        Ok(received)
    }

    #[tokio::test]
    async fn chunks_round_trip_without_options() {
        for kind in [BodyCipherKind::Aes128Gcm, BodyCipherKind::ChaCha20Poly1305] {
            let params = params(kind, 0, 3);
            let raw = encode_stream(&params, b"hello vmess").await;
            assert_eq!(decode_stream(&params, &raw).await.unwrap(), b"hello vmess");
        }
    }

    #[tokio::test]
    async fn chunks_round_trip_with_masking_and_padding() {
        for kind in [BodyCipherKind::Aes128Gcm, BodyCipherKind::ChaCha20Poly1305] {
            let option = OPTION_CHUNK_MASKING | OPTION_GLOBAL_PADDING;
            let params = params(kind, option, 5);
            let payload = vec![0xabu8; 5000];
            let raw = encode_stream(&params, &payload).await;
            assert_eq!(decode_stream(&params, &raw).await.unwrap(), payload);
        }
    }

    #[tokio::test]
    async fn chunks_round_trip_with_authenticated_length() {
        let option = OPTION_AUTHENTICATED_LENGTH | OPTION_CHUNK_MASKING;
        let params = params(BodyCipherKind::Aes128Gcm, option, 7);
        let raw = encode_stream(&params, b"authenticated length").await;
        assert_eq!(
            decode_stream(&params, &raw).await.unwrap(),
            b"authenticated length"
        );
    }

    #[tokio::test]
    async fn large_payload_is_split_into_multiple_chunks() {
        let params = params(BodyCipherKind::Aes128Gcm, OPTION_CHUNK_MASKING, 11);
        let payload: Vec<u8> = (0..40_000u32).map(|index| index as u8).collect();
        let raw = encode_stream(&params, &payload).await;
        // 40000 字节必须被切成多个 chunk
        assert!(raw.len() > payload.len() + 32);
        assert_eq!(decode_stream(&params, &raw).await.unwrap(), payload);
    }

    #[tokio::test]
    async fn empty_write_terminates_the_stream() {
        let params = params(BodyCipherKind::Aes128Gcm, 0, 19);
        let raw = encode_stream(&params, b"").await;
        // 仅一个结束标记：size 字段 + 16 字节 tag
        assert_eq!(raw.len(), 2 + AEAD_OVERHEAD);
        assert!(decode_stream(&params, &raw).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn tampering_with_ciphertext_is_detected() {
        for kind in [BodyCipherKind::Aes128Gcm, BodyCipherKind::ChaCha20Poly1305] {
            let params = params(kind, 0, 13);
            let raw = encode_stream(&params, b"secret payload").await;
            // 控制组：未篡改时必须能解出
            assert_eq!(
                decode_stream(&params, &raw).await.unwrap(),
                b"secret payload"
            );
            // 篡改密文中的任意一个字节（跳过 2 字节 size 字段）
            for index in 2..raw.len() - AEAD_OVERHEAD - 1 {
                let mut broken = raw.clone();
                broken[index] ^= 0x01;
                assert!(
                    decode_stream(&params, &broken).await.is_err(),
                    "{kind:?}: tampered byte {index} must be rejected"
                );
            }
        }
    }

    #[tokio::test]
    async fn wrong_key_cannot_decrypt() {
        let params = params(BodyCipherKind::Aes128Gcm, 0, 23);
        let raw = encode_stream(&params, b"secret").await;
        let mut other = params.clone();
        other.key = [9u8; 16];
        assert!(decode_stream(&other, &raw).await.is_err());
    }

    #[tokio::test]
    async fn truncated_stream_is_reported() {
        let params = params(BodyCipherKind::Aes128Gcm, 0, 17);
        let raw = encode_stream(&params, b"abcdefghij").await;
        let truncated = &raw[..raw.len() - 4];
        assert!(decode_stream(&params, truncated).await.is_err());
    }

    #[test]
    fn max_plaintext_matches_upstream_payload_size() {
        let plain = ChunkParams::new(
            [0u8; 16],
            [0u8; 16],
            BodyCipherKind::Aes128Gcm,
            OPTION_CHUNK_MASKING | OPTION_GLOBAL_PADDING,
        );
        assert_eq!(plain.max_plaintext(), BUFFER_SIZE - 16 - 2 - 64);
        let authenticated = ChunkParams::new(
            [0u8; 16],
            [0u8; 16],
            BodyCipherKind::Aes128Gcm,
            OPTION_AUTHENTICATED_LENGTH,
        );
        assert_eq!(
            authenticated.max_plaintext(),
            BUFFER_SIZE - 16 - AUTH_LENGTH_FIELD
        );
    }
}
