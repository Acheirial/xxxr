//! SOCKS5 入站（RFC 1928，当前实现 CONNECT）。

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;

use async_trait::async_trait;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use xxxr_common::{Error, Result};
use xxxr_config::{SocksAccount, SocksInboundSettings};
use xxxr_net::{Address, Conn, Listener};

use crate::context::{Network, SessionContext};
use crate::sniff::{sniff_and_apply, Sniffer};
use crate::traits::{Dispatcher, InboundHandler, ShutdownSignal};

const SOCKS_VERSION: u8 = 0x05;
const METHOD_NO_AUTH: u8 = 0x00;
const METHOD_USER_PASS: u8 = 0x02;
const METHOD_NONE_ACCEPTABLE: u8 = 0xff;
const COMMAND_CONNECT: u8 = 0x01;
const REPLY_SUCCEEDED: u8 = 0x00;
const REPLY_COMMAND_NOT_SUPPORTED: u8 = 0x07;
const ADDRESS_TYPE_IPV4: u8 = 0x01;
const ADDRESS_TYPE_IPV6: u8 = 0x04;

/// SOCKS5 入站。
pub struct SocksInbound {
    tag: String,
    listener: Arc<Listener>,
    settings: SocksInboundSettings,
}

impl SocksInbound {
    /// 创建 SOCKS5 入站；`listener` 必须已完成端口绑定。
    pub fn new(
        tag: impl Into<String>,
        listener: Arc<Listener>,
        settings: SocksInboundSettings,
    ) -> Self {
        Self {
            tag: tag.into(),
            listener,
            settings,
        }
    }

    /// 返回实际监听地址。
    pub fn local_addr(&self) -> SocketAddr {
        self.listener.local_addr()
    }
}

/// 每条连接共享的上下文。
struct Shared {
    inbound_tag: String,
    listener: Arc<Listener>,
    accounts: Option<Vec<SocksAccount>>,
    dispatcher: Arc<dyn Dispatcher>,
}

#[async_trait]
impl InboundHandler for SocksInbound {
    fn tag(&self) -> &str {
        &self.tag
    }

    async fn listen(
        &self,
        dispatcher: Arc<dyn Dispatcher>,
        mut shutdown: ShutdownSignal,
        sniffer: Option<Arc<Sniffer>>,
    ) -> Result<()> {
        let listener = self.listener.to_tokio()?;
        let local = self.listener.local_addr();
        tracing::info!(
            tag = %self.tag,
            %local,
            sniffing = sniffer.is_some(),
            "socks inbound listening"
        );
        let shared = Arc::new(Shared {
            inbound_tag: self.tag.clone(),
            listener: Arc::clone(&self.listener),
            accounts: if self.settings.auth == "password" {
                Some(self.settings.accounts.clone())
            } else {
                None
            },
            dispatcher,
        });
        loop {
            let accepted = tokio::select! {
                _ = shutdown.changed() => {
                    tracing::info!(
                        tag = %self.tag,
                        "socks inbound stopped accepting connections"
                    );
                    return Ok(());
                }
                accepted = listener.accept() => accepted,
            };
            let (stream, peer) = match accepted {
                Ok(pair) => pair,
                Err(e) => {
                    tracing::warn!(tag = %self.tag, "accept failed: {e}");
                    continue;
                }
            };
            let shared = Arc::clone(&shared);
            let sniffer = sniffer.clone();
            tokio::spawn(async move {
                match handle_connection(stream, peer, &shared, sniffer.as_deref()).await {
                    Ok(()) => tracing::debug!(%peer, "socks session finished"),
                    Err(e) => tracing::debug!(%peer, "socks session closed: {e}"),
                }
            });
        }
    }
}

async fn handle_connection(
    stream: TcpStream,
    peer: SocketAddr,
    shared: &Shared,
    sniffer: Option<&Sniffer>,
) -> Result<()> {
    let local = stream
        .local_addr()
        .unwrap_or_else(|_| SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)));
    let mut conn = shared.listener.accept_stream(stream, peer).await?;

    // 方法协商
    let version = conn.read_u8().await?;
    if version != SOCKS_VERSION {
        return Err(Error::protocol(format!(
            "unsupported socks version {version}"
        )));
    }
    let method_count = conn.read_u8().await? as usize;
    let mut methods = vec![0u8; method_count];
    conn.read_exact(&mut methods).await?;

    let expected_method = if shared.accounts.is_some() {
        METHOD_USER_PASS
    } else {
        METHOD_NO_AUTH
    };
    if !methods.contains(&expected_method) {
        conn.write_all(&[SOCKS_VERSION, METHOD_NONE_ACCEPTABLE])
            .await?;
        conn.flush().await?;
        return Err(Error::protocol(
            "no acceptable socks authentication method".to_string(),
        ));
    }
    conn.write_all(&[SOCKS_VERSION, expected_method]).await?;
    conn.flush().await?;

    if let Some(accounts) = &shared.accounts {
        verify_user_password(&mut conn, accounts).await?;
    }

    // 请求
    let version = conn.read_u8().await?;
    if version != SOCKS_VERSION {
        return Err(Error::protocol(format!(
            "unsupported socks request version {version}"
        )));
    }
    let command = conn.read_u8().await?;
    let _reserved = conn.read_u8().await?;
    let dest = read_address(&mut conn).await?;

    if command != COMMAND_CONNECT {
        write_reply(&mut conn, REPLY_COMMAND_NOT_SUPPORTED, local).await?;
        return Err(Error::unsupported(format!(
            "socks command {command} (only CONNECT is implemented)"
        )));
    }
    write_reply(&mut conn, REPLY_SUCCEEDED, local).await?;

    let mut ctx = SessionContext::new(shared.inbound_tag.clone(), Some(Address::from(peer)));
    ctx.target = Some(dest);
    ctx.network = Network::Tcp;

    // 上游语义：入站协议握手完成后、路由之前执行嗅探。
    let mut conn = sniff_and_apply(conn, sniffer, &mut ctx).await?;
    shared.dispatcher.dispatch(&mut ctx, &mut *conn).await
}

async fn verify_user_password(conn: &mut dyn Conn, accounts: &[SocksAccount]) -> Result<()> {
    let version = conn.read_u8().await?;
    if version != 0x01 {
        return Err(Error::protocol(format!(
            "unsupported socks auth version {version}"
        )));
    }
    let user_len = conn.read_u8().await? as usize;
    let mut user = vec![0u8; user_len];
    conn.read_exact(&mut user).await?;
    let pass_len = conn.read_u8().await? as usize;
    let mut pass = vec![0u8; pass_len];
    conn.read_exact(&mut pass).await?;

    let user = String::from_utf8_lossy(&user);
    let pass = String::from_utf8_lossy(&pass);
    let accepted = accounts
        .iter()
        .any(|account| account.user == user && account.pass == pass);
    conn.write_all(&[0x01, if accepted { 0x00 } else { 0x01 }])
        .await?;
    conn.flush().await?;
    if accepted {
        Ok(())
    } else {
        Err(Error::protocol("socks authentication failed".to_string()))
    }
}

async fn read_address(conn: &mut dyn Conn) -> Result<Address> {
    crate::codec::read_address(conn, crate::codec::AddressStyle::Socks).await
}

async fn write_reply(conn: &mut dyn Conn, reply: u8, bound: SocketAddr) -> Result<()> {
    let mut response = vec![SOCKS_VERSION, reply, 0x00];
    match bound.ip() {
        IpAddr::V4(v4) => {
            response.push(ADDRESS_TYPE_IPV4);
            response.extend_from_slice(&v4.octets());
        }
        IpAddr::V6(v6) => {
            response.push(ADDRESS_TYPE_IPV6);
            response.extend_from_slice(&v6.octets());
        }
    }
    response.extend_from_slice(&bound.port().to_be_bytes());
    conn.write_all(&response).await?;
    conn.flush().await?;
    Ok(())
}
