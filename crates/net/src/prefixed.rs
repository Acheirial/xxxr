//! 回填流：把已经读取的字节重新接到连接前端。
//!
//! 嗅探需要「先读一段再决定」，但读完的字节仍然属于客户端数据，必须原样转发给
//! 出站。该类型把已读取的字节排在最前面，之后再透传底层连接。

use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::conn::Conn;

/// 在底层连接之前插入一段已读取字节的连接包装。
pub struct Prefixed {
    inner: Box<dyn Conn>,
    prefix: Vec<u8>,
    offset: usize,
}

impl Prefixed {
    /// 用底层连接与已读取的 `prefix` 构造。
    pub fn new(inner: Box<dyn Conn>, prefix: impl Into<Vec<u8>>) -> Self {
        Self {
            inner,
            prefix: prefix.into(),
            offset: 0,
        }
    }

    /// 尚未交出的回填字节数。
    pub fn remaining(&self) -> usize {
        self.prefix.len().saturating_sub(self.offset)
    }
}

impl AsyncRead for Prefixed {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        let this = self.get_mut();
        if this.offset < this.prefix.len() {
            let pending = &this.prefix[this.offset..];
            let take = pending.len().min(buf.remaining());
            buf.put_slice(&pending[..take]);
            this.offset += take;
            if this.offset >= this.prefix.len() {
                // 回填完毕，释放缓冲。
                this.prefix = Vec::new();
                this.offset = 0;
            }
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut this.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for Prefixed {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}
