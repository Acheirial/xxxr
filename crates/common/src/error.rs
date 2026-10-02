//! 统一错误类型。

/// workspace 内所有库 crate 共用的错误类型。
///
/// 各层不再自定义错误类型，避免大量 `From` 转换噪声；在 CLI 边界
/// （`xxxr` 二进制）会转换为 `anyhow::Error` 以获得更好的上下文。
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// 底层 I/O 错误。
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    /// 地址解析错误。
    #[error("address error: {0}")]
    Address(String),

    /// 配置错误（JSON 非法、字段缺失、取值不合法等）。
    #[error("config error: {0}")]
    Config(String),

    /// 协议错误（握手数据不符合规范、鉴权失败等）。
    #[error("protocol error: {0}")]
    Protocol(String),

    /// TLS 相关错误。
    #[error("tls error: {0}")]
    Tls(String),

    /// WebSocket 相关错误。
    #[error("websocket error: {0}")]
    WebSocket(String),

    /// 明确不支持的能力。
    #[error("unsupported: {0}")]
    Unsupported(String),

    /// 其他错误。
    #[error("{0}")]
    Other(String),
}

impl Error {
    /// 构造一个 [`Error::Other`]。
    pub fn other(message: impl Into<String>) -> Self {
        Self::Other(message.into())
    }

    /// 构造一个 [`Error::Protocol`]。
    pub fn protocol(message: impl Into<String>) -> Self {
        Self::Protocol(message.into())
    }

    /// 构造一个 [`Error::Config`]。
    pub fn config(message: impl Into<String>) -> Self {
        Self::Config(message.into())
    }

    /// 构造一个 [`Error::Unsupported`]。
    pub fn unsupported(message: impl Into<String>) -> Self {
        Self::Unsupported(message.into())
    }
}

/// workspace 统一 `Result` 别名。
pub type Result<T, E = Error> = std::result::Result<T, E>;
