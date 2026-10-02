//! WebSocket 传输（RFC 6455 的最小可用子集）。
//!
//! 仅实现代理所需的部分：HTTP Upgrade 握手、binary/text/continuation 数据帧、
//! ping/pong 与 close 控制帧。不做扩展协商（如 permessage-deflate）。

use std::collections::HashMap;
use std::pin::Pin;
use std::task::{Context, Poll};

use base64::Engine;
use bytes::{Buf, BytesMut};
use sha1::{Digest, Sha1};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use xxxr_common::{Error, Result};

use crate::conn::Conn;
use crate::transport::WsSettings;

/// RFC 6455 规定的握手 GUID。
const WS_GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
/// 握手头部最大长度。
const MAX_HEAD_SIZE: usize = 8 * 1024;
/// 单个 WebSocket 帧载荷上限（防御性限制）。
const MAX_FRAME_SIZE: usize = 16 * 1024 * 1024;
/// 底层读缓冲每次读取的字节数。
const READ_CHUNK: usize = 8 * 1024;

const OP_CONT: u8 = 0x0;
const OP_TEXT: u8 = 0x1;
const OP_BINARY: u8 = 0x2;
const OP_CLOSE: u8 = 0x8;
const OP_PING: u8 = 0x9;
const OP_PONG: u8 = 0xa;

/// 服务端 WebSocket 握手。
pub async fn wrap_server(stream: Box<dyn Conn>, settings: &WsSettings) -> Result<Box<dyn Conn>> {
    let mut stream = stream;
    let (head, rest) = read_http_head(&mut stream).await?;
    let request = HttpRequest::parse(&head)?;
    if request.method != "GET" {
        return Err(Error::WebSocket(format!(
            "unexpected websocket method `{}`",
            request.method
        )));
    }
    if !request.is_upgrade() {
        return Err(Error::WebSocket(
            "not a websocket upgrade request".to_string(),
        ));
    }
    if normalize_path(&request.path) != normalize_path(&settings.path) {
        return Err(Error::WebSocket(format!(
            "unexpected websocket path `{}`",
            request.path
        )));
    }
    let key = request
        .header("sec-websocket-key")
        .ok_or_else(|| Error::WebSocket("missing `Sec-WebSocket-Key`".to_string()))?;
    let response = format!(
        "HTTP/1.1 101 Switching Protocols\r\n\
         Upgrade: websocket\r\n\
         Connection: Upgrade\r\n\
         Sec-WebSocket-Accept: {}\r\n\r\n",
        accept_key(key)
    );
    stream.write_all(response.as_bytes()).await?;
    stream.flush().await?;
    Ok(Box::new(WsStream::new(stream, rest, false)))
}

/// 客户端 WebSocket 握手。
pub async fn wrap_client(
    stream: Box<dyn Conn>,
    settings: &WsSettings,
    host: &str,
) -> Result<Box<dyn Conn>> {
    let mut stream = stream;
    let key = base64::engine::general_purpose::STANDARD.encode(random_bytes());
    let path = if settings.path.is_empty() {
        "/"
    } else {
        settings.path.as_str()
    };
    let host_header = settings
        .host
        .clone()
        .or_else(|| {
            settings
                .headers
                .as_ref()
                .and_then(|headers| headers.get("Host").cloned())
        })
        .unwrap_or_else(|| host.to_string());

    let mut request = String::new();
    request.push_str(&format!("GET {path} HTTP/1.1\r\n"));
    request.push_str(&format!("Host: {host_header}\r\n"));
    request.push_str("Upgrade: websocket\r\n");
    request.push_str("Connection: Upgrade\r\n");
    request.push_str(&format!("Sec-WebSocket-Key: {key}\r\n"));
    request.push_str("Sec-WebSocket-Version: 13\r\n");
    if let Some(headers) = &settings.headers {
        for (name, value) in headers {
            if !name.eq_ignore_ascii_case("host") {
                request.push_str(&format!("{name}: {value}\r\n"));
            }
        }
    }
    request.push_str("\r\n");

    stream.write_all(request.as_bytes()).await?;
    stream.flush().await?;

    let (head, rest) = read_http_head(&mut stream).await?;
    let status_line = head.lines().next().unwrap_or_default();
    let mut parts = status_line.split_whitespace();
    parts.next();
    if parts.next() != Some("101") {
        return Err(Error::WebSocket(format!(
            "websocket handshake failed: {status_line}"
        )));
    }
    let response = HttpRequest::parse(&head)?;
    match response.header("sec-websocket-accept") {
        Some(value) if value == accept_key(&key) => {}
        _ => {
            return Err(Error::WebSocket(
                "invalid `Sec-WebSocket-Accept`".to_string(),
            ));
        }
    }
    Ok(Box::new(WsStream::new(stream, rest, true)))
}

/// 计算 `Sec-WebSocket-Accept`。
fn accept_key(key: &str) -> String {
    let mut hasher = Sha1::new();
    hasher.update(key.as_bytes());
    hasher.update(WS_GUID.as_bytes());
    base64::engine::general_purpose::STANDARD.encode(hasher.finalize())
}

/// 生成 16 字节随机客户端 key。
fn random_bytes() -> [u8; 16] {
    uuid::Uuid::new_v4().into_bytes()
}

fn normalize_path(path: &str) -> &str {
    path.split('?').next().unwrap_or("")
}

fn find_sequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// 读取 HTTP 头部，返回（头部文本，随后的剩余字节）。
async fn read_http_head(stream: &mut Box<dyn Conn>) -> Result<(String, BytesMut)> {
    let mut buffer = Vec::new();
    let mut chunk = [0u8; 1024];
    loop {
        let read = stream.read(&mut chunk).await?;
        if read == 0 {
            return Err(Error::WebSocket(
                "connection closed during websocket handshake".to_string(),
            ));
        }
        buffer.extend_from_slice(&chunk[..read]);
        if let Some(position) = find_sequence(&buffer, b"\r\n\r\n") {
            let head = String::from_utf8_lossy(&buffer[..position]).into_owned();
            let rest = BytesMut::from(&buffer[position + 4..]);
            return Ok((head, rest));
        }
        if buffer.len() > MAX_HEAD_SIZE {
            return Err(Error::WebSocket(
                "websocket handshake header too large".to_string(),
            ));
        }
    }
}

/// 解析后的 HTTP 请求/响应头部。
#[derive(Debug)]
struct HttpRequest {
    method: String,
    path: String,
    headers: HashMap<String, String>,
}

impl HttpRequest {
    fn parse(head: &str) -> Result<Self> {
        let mut lines = head.split("\r\n");
        let start_line = lines.next().unwrap_or_default();
        let mut parts = start_line.split_whitespace();
        let method = parts.next().unwrap_or_default().to_string();
        let path = parts.next().unwrap_or_default().to_string();
        if path.is_empty() {
            return Err(Error::WebSocket(format!(
                "malformed http start line: `{start_line}`"
            )));
        }
        let mut headers = HashMap::new();
        for line in lines {
            if line.is_empty() {
                continue;
            }
            if let Some((name, value)) = line.split_once(':') {
                headers.insert(name.trim().to_ascii_lowercase(), value.trim().to_string());
            }
        }
        Ok(Self {
            method,
            path,
            headers,
        })
    }

    fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(name).map(String::as_str)
    }

    fn is_upgrade(&self) -> bool {
        let upgrade = self
            .header("upgrade")
            .is_some_and(|value| value.eq_ignore_ascii_case("websocket"));
        let connection = self
            .header("connection")
            .is_some_and(|value| value.to_ascii_lowercase().contains("upgrade"));
        upgrade && connection
    }
}

/// 解析出的帧头。
#[derive(Debug, Clone, Copy)]
struct FrameHeader {
    opcode: u8,
    mask: Option<[u8; 4]>,
    payload_len: usize,
    header_len: usize,
}

/// 尝试解析一个完整帧；数据不足时返回 `Ok(None)`。
fn parse_frame(buffer: &[u8]) -> Result<Option<FrameHeader>> {
    if buffer.len() < 2 {
        return Ok(None);
    }
    if buffer[0] & 0x70 != 0 {
        return Err(Error::WebSocket("reserved bits must be zero".to_string()));
    }
    let opcode = buffer[0] & 0x0f;
    let masked = buffer[1] & 0x80 != 0;
    let length_code = (buffer[1] & 0x7f) as usize;
    let mut offset = 2;
    let payload_len = match length_code {
        126 => {
            if buffer.len() < 4 {
                return Ok(None);
            }
            offset = 4;
            u16::from_be_bytes([buffer[2], buffer[3]]) as usize
        }
        127 => {
            if buffer.len() < 10 {
                return Ok(None);
            }
            let mut raw = [0u8; 8];
            raw.copy_from_slice(&buffer[2..10]);
            offset = 10;
            usize::try_from(u64::from_be_bytes(raw))
                .map_err(|_| Error::WebSocket("websocket frame too large".to_string()))?
        }
        value => value,
    };
    if payload_len > MAX_FRAME_SIZE {
        return Err(Error::WebSocket(format!(
            "websocket frame of {payload_len} bytes exceeds limit"
        )));
    }
    let mask = if masked {
        if buffer.len() < offset + 4 {
            return Ok(None);
        }
        let mut key = [0u8; 4];
        key.copy_from_slice(&buffer[offset..offset + 4]);
        offset += 4;
        Some(key)
    } else {
        None
    };
    if buffer.len() < offset + payload_len {
        return Ok(None);
    }
    Ok(Some(FrameHeader {
        opcode,
        mask,
        payload_len,
        header_len: offset,
    }))
}

/// 编码一个帧（客户端发送时 `mask` 为 `true`）。
fn encode_frame(opcode: u8, payload: &[u8], mask: bool, out: &mut Vec<u8>) {
    out.push(0x80 | opcode);
    let length = payload.len();
    let mask_bit = if mask { 0x80u8 } else { 0 };
    if length < 126 {
        out.push(mask_bit | length as u8);
    } else if length <= usize::from(u16::MAX) {
        out.push(mask_bit | 126);
        out.extend_from_slice(&(length as u16).to_be_bytes());
    } else {
        out.push(mask_bit | 127);
        out.extend_from_slice(&(length as u64).to_be_bytes());
    }
    if mask {
        let key = random_bytes();
        let key = [key[0], key[1], key[2], key[3]];
        out.extend_from_slice(&key);
        for (index, byte) in payload.iter().enumerate() {
            out.push(byte ^ key[index & 3]);
        }
    } else {
        out.extend_from_slice(payload);
    }
}

/// WebSocket 帧层：把底层连接上的帧流还原为字节流。
///
/// 该类型实现了 [`tokio::io::AsyncRead`] 与 [`tokio::io::AsyncWrite`]，
/// 因此可以直接作为 [`Conn`] 使用。
pub struct WsStream {
    inner: Box<dyn Conn>,
    /// 尚未解析的原始字节。
    inbuf: BytesMut,
    /// 已解码、待交给读取方的载荷。
    read_buf: BytesMut,
    /// 待写出的编码后字节。
    write_buf: Vec<u8>,
    /// 去往对端的帧是否需要掩码（客户端为 `true`）。
    mask_out: bool,
    eof: bool,
    close_sent: bool,
}

impl WsStream {
    fn new(inner: Box<dyn Conn>, rest: BytesMut, mask_out: bool) -> Self {
        Self {
            inner,
            inbuf: rest,
            read_buf: BytesMut::new(),
            write_buf: Vec::new(),
            mask_out,
            eof: false,
            close_sent: false,
        }
    }

    /// 尽可能把 `write_buf` 刷入底层连接。
    fn try_flush(&mut self, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        while !self.write_buf.is_empty() {
            let result = Pin::new(&mut self.inner).poll_write(cx, &self.write_buf);
            match result {
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(std::io::ErrorKind::WriteZero.into()));
                }
                Poll::Ready(Ok(written)) => {
                    self.write_buf.drain(..written);
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
        Poll::Ready(Ok(()))
    }

    fn queue_frame(&mut self, opcode: u8, payload: &[u8]) {
        let mask = self.mask_out;
        encode_frame(opcode, payload, mask, &mut self.write_buf);
    }
}

impl AsyncRead for WsStream {
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
            if !this.read_buf.is_empty() {
                let take = std::cmp::min(buf.remaining(), this.read_buf.len());
                buf.put_slice(&this.read_buf[..take]);
                this.read_buf.advance(take);
                return Poll::Ready(Ok(()));
            }
            if this.eof {
                return Poll::Ready(Ok(()));
            }

            let parsed = match parse_frame(&this.inbuf) {
                Ok(parsed) => parsed,
                Err(e) => {
                    return Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        e.to_string(),
                    )));
                }
            };
            if let Some(frame) = parsed {
                let total = frame.header_len + frame.payload_len;
                let mut raw = this.inbuf.split_to(total);
                let mut payload = raw.split_off(frame.header_len);
                if let Some(key) = frame.mask {
                    for (index, byte) in payload.iter_mut().enumerate() {
                        *byte ^= key[index & 3];
                    }
                }
                match frame.opcode {
                    OP_TEXT | OP_BINARY | OP_CONT => this.read_buf.extend_from_slice(&payload),
                    OP_PING => {
                        this.queue_frame(OP_PONG, &payload);
                        let _ = this.try_flush(cx);
                    }
                    OP_PONG => {}
                    OP_CLOSE => {
                        if !this.close_sent {
                            this.close_sent = true;
                            this.queue_frame(OP_CLOSE, &[]);
                            let _ = this.try_flush(cx);
                        }
                        let _ = Pin::new(&mut this.inner).poll_shutdown(cx);
                        this.eof = true;
                        if this.read_buf.is_empty() {
                            return Poll::Ready(Ok(()));
                        }
                    }
                    _ => {}
                }
                continue;
            }

            let mut chunk = [0u8; READ_CHUNK];
            let mut chunk_buf = ReadBuf::new(&mut chunk);
            let result = Pin::new(&mut this.inner).poll_read(cx, &mut chunk_buf);
            match result {
                Poll::Ready(Ok(())) => {
                    let filled = chunk_buf.filled();
                    if filled.is_empty() {
                        this.eof = true;
                        return Poll::Ready(Ok(()));
                    }
                    this.inbuf.extend_from_slice(filled);
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl AsyncWrite for WsStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        match this.try_flush(cx) {
            Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Pending => return Poll::Pending,
        }
        let previous = this.write_buf.len();
        this.queue_frame(OP_BINARY, buf);
        let result = Pin::new(&mut this.inner).poll_write(cx, &this.write_buf[previous..]);
        match result {
            Poll::Ready(Ok(0)) => {
                this.write_buf.truncate(previous);
                Poll::Ready(Err(std::io::ErrorKind::WriteZero.into()))
            }
            Poll::Ready(Ok(written)) => {
                this.write_buf.drain(..previous + written);
                Poll::Ready(Ok(buf.len()))
            }
            Poll::Ready(Err(e)) => {
                this.write_buf.truncate(previous);
                Poll::Ready(Err(e))
            }
            Poll::Pending => {
                this.write_buf.truncate(previous);
                Poll::Pending
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        match this.try_flush(cx) {
            Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Pending => return Poll::Pending,
        }
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        if !this.close_sent {
            this.close_sent = true;
            this.queue_frame(OP_CLOSE, &[]);
        }
        match this.try_flush(cx) {
            Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Pending => return Poll::Pending,
        }
        Pin::new(&mut this.inner).poll_shutdown(cx)
    }
}
