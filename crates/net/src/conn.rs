//! 连接抽象。

use tokio::io::{AsyncRead, AsyncWrite};

/// 一条已建立的双向字节流连接。
///
/// 任何满足 `AsyncRead + AsyncWrite + Send + Unpin + 'static` 的类型都自动实现
/// 该 trait，因此 `TcpStream`、TLS 流、WebSocket 包装流以及
/// `Box<dyn Conn>` 都可以直接作为 [`Conn`] 使用（trait object 同样是 `Send`）。
pub trait Conn: AsyncRead + AsyncWrite + Send + Unpin + 'static {}

impl<T> Conn for T where T: AsyncRead + AsyncWrite + Send + Unpin + 'static {}
