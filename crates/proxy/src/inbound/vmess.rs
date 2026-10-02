//! VMess（AEAD）入站。

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use xxxr_common::{Error, Result};
use xxxr_config::{VmessInboundSettings, VmessSecurity};
use xxxr_net::{Address, Listener};

use crate::context::{Network, SessionContext};
use crate::sniff::{sniff_and_apply, Sniffer};
use crate::traits::{Dispatcher, InboundHandler, ShutdownSignal};
use crate::vmess::chunk::{ChunkParams, ChunkedStream};
use crate::vmess::crypto::{self, BodyCipherKind, AUTH_ID_WINDOW_SECONDS};
use crate::vmess::header::{self, COMMAND_TCP};

/// AuthID 重放过滤器（对齐上游 `antireplay.MapFilter`：120 秒窗口）。
struct ReplayGuard {
    entries: std::sync::Mutex<std::collections::HashMap<[u8; 16], std::time::Instant>>,
    /// 触发清理的条目数上限。
    max_entries: usize,
}

impl ReplayGuard {
    fn new() -> Self {
        Self {
            entries: std::sync::Mutex::new(std::collections::HashMap::new()),
            max_entries: 4096,
        }
    }

    /// 记录一个 AuthID；若在时间窗内重复出现则返回 `false`。
    fn check_and_insert(&self, auth_id: &[u8; 16], window: Duration) -> bool {
        let now = std::time::Instant::now();
        let mut entries = match self.entries.lock() {
            Ok(entries) => entries,
            Err(poisoned) => poisoned.into_inner(),
        };
        // 定期清理过期条目，避免表无限增长。
        if entries.len() > self.max_entries {
            entries.retain(|_, seen| now.duration_since(*seen) <= window);
        }
        match entries.get(auth_id) {
            Some(seen) if now.duration_since(*seen) <= window => false,
            _ => {
                entries.insert(*auth_id, now);
                true
            }
        }
    }
}

/// 处理单条连接所需的共享上下文（全部为 `Arc`，可低成本克隆进任务）。
#[derive(Clone)]
struct Session {
    listener: Arc<Listener>,
    users: Arc<Vec<UserEntry>>,
    inbound_tag: String,
    dispatcher: Arc<dyn Dispatcher>,
    sniffer: Option<Arc<Sniffer>>,
    replay: Arc<ReplayGuard>,
}

/// 一个登记用户。
struct UserEntry {
    /// 备注邮箱（日志用）。
    email: String,
    /// 由 UUID 派生的 cmdKey。
    cmd_key: [u8; 16],
    /// 该用户允许的 `security`（缺省 `auto`）。
    security: VmessSecurity,
}

/// VMess 入站。
pub struct VmessInbound {
    tag: String,
    listener: Arc<Listener>,
    users: Vec<UserEntry>,
    replay: Arc<ReplayGuard>,
}

impl VmessInbound {
    /// 创建 VMess 入站；`listener` 必须已完成端口绑定。
    pub fn new(
        tag: impl Into<String>,
        listener: Arc<Listener>,
        settings: VmessInboundSettings,
    ) -> Self {
        let tag = tag.into();
        let users = settings
            .all_clients()
            .into_iter()
            .map(|client| {
                if client.alter_id.unwrap_or(0) != 0 {
                    tracing::warn!(
                        inbound = %tag,
                        user = %client.id,
                        "vmess `alterId` is ignored: only AEAD is supported"
                    );
                }
                UserEntry {
                    email: client.email.unwrap_or_else(|| client.id.to_string()),
                    cmd_key: crypto::cmd_key(&client.id),
                    security: client.security.unwrap_or_default(),
                }
            })
            .collect();
        Self {
            tag,
            listener,
            users,
            replay: Arc::new(ReplayGuard::new()),
        }
    }

    /// 返回实际监听地址。
    pub fn local_addr(&self) -> SocketAddr {
        self.listener.local_addr()
    }

    /// 返回已登记的用户数量。
    pub fn user_count(&self) -> usize {
        self.users.len()
    }
}

#[async_trait]
impl InboundHandler for VmessInbound {
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
            users = self.users.len(),
            sniffing = sniffer.is_some(),
            "vmess inbound listening"
        );
        let users = Arc::new(
            self.users
                .iter()
                .map(|user| UserEntry {
                    email: user.email.clone(),
                    cmd_key: user.cmd_key,
                    security: user.security,
                })
                .collect::<Vec<_>>(),
        );
        let session = Session {
            listener: Arc::clone(&self.listener),
            users,
            inbound_tag: self.tag.clone(),
            dispatcher,
            sniffer,
            replay: Arc::clone(&self.replay),
        };
        loop {
            let accepted = tokio::select! {
                _ = shutdown.changed() => {
                    tracing::info!(tag = %self.tag, "vmess inbound stopped accepting connections");
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
            let session = session.clone();
            tokio::spawn(async move {
                match handle_connection(stream, peer, session).await {
                    Ok(()) => tracing::debug!(%peer, "vmess session finished"),
                    Err(e) => tracing::debug!(%peer, "vmess session closed: {e}"),
                }
            });
        }
    }
}

/// 在用户表中匹配 AuthID（对应上游 `AuthIDDecoderHolder::Match`）。
fn match_user<'a>(users: &'a [UserEntry], auth_id: &[u8; 16]) -> Option<(&'a UserEntry, i64)> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs() as i64)
        .ok()?;
    for user in users {
        let Ok(timestamp) = crypto::open_auth_id(&user.cmd_key, auth_id) else {
            continue;
        };
        if (timestamp - now).abs() > AUTH_ID_WINDOW_SECONDS {
            tracing::debug!(user = %user.email, "vmess: timestamp outside the accepted window");
            continue;
        }
        return Some((user, timestamp));
    }
    None
}

async fn handle_connection(stream: TcpStream, peer: SocketAddr, session: Session) -> Result<()> {
    let mut conn = session.listener.accept_stream(stream, peer).await?;

    let mut auth_id = [0u8; 16];
    conn.read_exact(&mut auth_id).await?;
    let (user, _timestamp) = match match_user(&session.users, &auth_id) {
        Some(found) => found,
        None => {
            return Err(Error::protocol(
                "vmess: invalid user or unsynchronized clock".to_string(),
            ));
        }
    };
    if !session
        .replay
        .check_and_insert(&auth_id, Duration::from_secs(AUTH_ID_WINDOW_SECONDS as u64))
    {
        return Err(Error::protocol(
            "vmess: replayed auth id, possibly under replay attack".to_string(),
        ));
    }

    let inner = header::open_header(&user.cmd_key, &auth_id, &mut conn).await?;
    let request = header::decode_inner(&inner)?;
    if request.version != header::VERSION {
        return Err(Error::protocol(format!(
            "vmess: unsupported version {}",
            request.version
        )));
    }
    if request.security == VmessSecurity::Auto {
        return Err(Error::protocol(
            "vmess: `security` must be aes-128-gcm or chacha20-poly1305".to_string(),
        ));
    }
    if request.command != COMMAND_TCP {
        return Err(Error::unsupported(format!(
            "vmess command {} (only TCP is implemented)",
            request.command
        )));
    }
    tracing::debug!(%peer, user = %user.email, dest = %request.dest, "vmess request");

    // 响应密钥/IV 由请求派生（SHA256 前 16 字节）。
    let response_key = header::derive_response_key(&request.body_key);
    let response_iv = header::derive_response_key(&request.body_iv);
    let response_header =
        header::encode_response_header(&response_key, &response_iv, request.response_header, 0)?;
    conn.write_all(&response_header).await?;
    conn.flush().await?;

    let kind = BodyCipherKind::from_security(request.security);
    let read_params = ChunkParams::new(request.body_key, request.body_iv, kind, request.option);
    let write_params = ChunkParams::new(response_key, response_iv, kind, request.option);
    let conn: Box<dyn xxxr_net::Conn> =
        Box::new(ChunkedStream::new(conn, read_params, write_params)?);

    let mut ctx = SessionContext::new(session.inbound_tag.clone(), Some(Address::from(peer)));
    ctx.target = Some(request.dest);
    ctx.network = Network::Tcp;

    // 上游语义：入站协议握手完成后、路由之前执行嗅探。
    let mut conn = sniff_and_apply(conn, session.sniffer.as_deref(), &mut ctx).await?;
    session.dispatcher.dispatch(&mut ctx, &mut *conn).await
}
