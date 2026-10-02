//! 入站 TCP 监听器。

use std::net::{SocketAddr, TcpListener as StdTcpListener};

use tokio::net::{TcpListener, TcpStream};
use xxxr_common::{Error, Result};

use crate::conn::Conn;
use crate::transport::StreamSettings;

/// 入站监听器：持有已绑定的套接字与传输层配置。
///
/// 绑定使用标准库同步完成，因此可以在 tokio 运行时之外构造并快速暴露
/// 端口占用错误；接受连接时再转换为 tokio 监听器。
#[derive(Debug)]
pub struct Listener {
    inner: StdTcpListener,
    settings: StreamSettings,
    local_addr: SocketAddr,
}

impl Listener {
    /// 同步绑定 `addr`；端口为 `0` 时由系统分配。
    pub fn bind(addr: SocketAddr, settings: StreamSettings) -> Result<Self> {
        let inner = StdTcpListener::bind(addr)?;
        inner.set_nonblocking(true)?;
        let local_addr = inner.local_addr()?;
        Ok(Self {
            inner,
            settings,
            local_addr,
        })
    }

    /// 返回实际绑定的地址。
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// 返回传输层配置。
    pub fn settings(&self) -> &StreamSettings {
        &self.settings
    }

    /// 转换为 tokio 监听器；必须在 tokio 运行时上下文中调用。
    pub fn to_tokio(&self) -> Result<TcpListener> {
        let cloned = self.inner.try_clone()?;
        TcpListener::from_std(cloned).map_err(Error::Io)
    }

    /// 对已接受的 TCP 流完成 TLS / WebSocket 握手。
    pub async fn accept_stream(
        &self,
        stream: TcpStream,
        peer: SocketAddr,
    ) -> Result<Box<dyn Conn>> {
        let _ = stream.set_nodelay(true);
        tracing::debug!(%peer, "accepted connection");
        self.settings.wrap_server(stream).await
    }
}
