//! VMess（AEAD）出站。

use async_trait::async_trait;
use rand::RngCore;
use tokio::io::AsyncWriteExt;
use uuid::Uuid;
use xxxr_common::Result;
use xxxr_config::VmessSecurity;
use xxxr_net::{Address, Conn, Dialer, StreamSettings};

use crate::context::SessionContext;
use crate::relay;
use crate::traits::OutboundHandler;
use crate::vmess::chunk::{ChunkParams, ChunkedStream};
use crate::vmess::crypto::{self, BodyCipherKind};
use crate::vmess::header::{
    self, COMMAND_TCP, OPTION_AUTHENTICATED_LENGTH, OPTION_CHUNK_MASKING, OPTION_CHUNK_STREAM,
    OPTION_GLOBAL_PADDING,
};

/// VMess 出站（AEAD，TCP）。
pub struct VmessOutbound {
    tag: String,
    dialer: Dialer,
    server: Address,
    cmd_key: [u8; 16],
    security: VmessSecurity,
    authenticated_length: bool,
}

impl VmessOutbound {
    /// 创建 VMess 出站。
    ///
    /// `security` 中的 `auto` 会按硬件能力解析为 AES-128-GCM（上游 `auto` 语义）。
    pub fn new(
        tag: impl Into<String>,
        server: Address,
        user_id: Uuid,
        security: VmessSecurity,
        experiments: &[String],
        settings: StreamSettings,
    ) -> Self {
        let authenticated_length = experiments
            .iter()
            .any(|name| name.eq_ignore_ascii_case("AuthenticatedLength"));
        Self {
            tag: tag.into(),
            dialer: Dialer::new(settings),
            server,
            cmd_key: crypto::cmd_key(&user_id),
            security,
            authenticated_length,
        }
    }

    /// 实际使用的 `security`（`auto` 已解析）。
    fn resolved_security(&self) -> VmessSecurity {
        match self.security {
            VmessSecurity::Auto => VmessSecurity::Aes128Gcm,
            other => other,
        }
    }

    /// 生成请求选项位图（对齐上游 outbound：AEAD 下启用掩码与填充）。
    fn request_option(&self) -> u8 {
        let mut option = OPTION_CHUNK_STREAM | OPTION_CHUNK_MASKING | OPTION_GLOBAL_PADDING;
        if self.authenticated_length {
            option |= OPTION_AUTHENTICATED_LENGTH;
        }
        option
    }
}

#[async_trait]
impl OutboundHandler for VmessOutbound {
    fn tag(&self) -> &str {
        &self.tag
    }

    async fn dial(
        &self,
        _ctx: &mut SessionContext,
        dest: Address,
        out: &mut dyn Conn,
    ) -> Result<()> {
        let mut remote = self.dialer.dial(&self.server).await?;
        let mut rng = rand::rngs::OsRng;

        let mut body_key = [0u8; 16];
        let mut body_iv = [0u8; 16];
        rng.fill_bytes(&mut body_key);
        rng.fill_bytes(&mut body_iv);
        let response_header = (rng.next_u32() & 0xff) as u8;

        let request = header::RequestHeader {
            version: header::VERSION,
            body_iv,
            body_key,
            response_header,
            option: self.request_option(),
            security: self.resolved_security(),
            command: COMMAND_TCP,
            dest,
        };
        let inner = header::encode_inner(&request, &mut rng)?;
        let sealed = header::seal_header(&self.cmd_key, &inner, &mut rng)?;
        remote.write_all(&sealed).await?;
        remote.flush().await?;

        // 响应头使用派生密钥加密，并校验其中的 V。
        let response_key = header::derive_response_key(&body_key);
        let response_iv = header::derive_response_key(&body_iv);
        header::decode_response_header(&response_key, &response_iv, response_header, &mut remote)
            .await?;

        let kind = BodyCipherKind::from_security(self.resolved_security());
        let write_params = ChunkParams::new(body_key, body_iv, kind, request.option);
        let read_params = ChunkParams::new(response_key, response_iv, kind, request.option);
        let mut remote: Box<dyn Conn> =
            Box::new(ChunkedStream::new(remote, read_params, write_params)?);
        relay::pump(out, &mut *remote).await
    }
}
