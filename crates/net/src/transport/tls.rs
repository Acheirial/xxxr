//! TLS 传输（基于 rustls，统一使用 ring provider）。

use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::{ClientConfig, DigitallySignedStruct, RootCertStore, ServerConfig, SignatureScheme};
use rustls_pki_types::{CertificateDer, IpAddr as PkiIpAddr, PrivateKeyDer, ServerName, UnixTime};
use serde::{Deserialize, Serialize};
use tokio_rustls::{TlsAcceptor, TlsConnector};
use xxxr_common::{Error, Result};

use crate::conn::Conn;

/// Xray `streamSettings.tlsSettings` 的模型。
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct TlsSettings {
    /// 客户端 SNI / 证书校验使用的服务器名。
    pub server_name: Option<String>,
    /// 客户端是否跳过证书校验（不安全，仅用于调试）。
    pub allow_insecure: bool,
    /// ALPN 协议列表；未配置时不下发。
    pub alpn: Option<Vec<String>>,
    /// 客户端是否禁用系统根证书。
    pub disable_system_root: bool,
    /// 证书列表；服务端必须提供，客户端可作为额外信任根。
    pub certificates: Option<Vec<Certificate>>,
}

/// 证书与私钥配置：文件路径或内联 PEM 内容二选一。
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct Certificate {
    /// 证书链 PEM 文件路径。
    pub certificate_file: Option<String>,
    /// 私钥 PEM 文件路径。
    pub key_file: Option<String>,
    /// 内联证书链 PEM 内容。
    pub certificate: Option<Vec<String>>,
    /// 内联私钥 PEM 内容。
    pub key: Option<Vec<String>>,
    /// 用途：`encipherment` / `verify` / `issue` / `authorityVerify`。
    pub usage: Option<String>,
}

/// 客户端 TLS 握手。
pub async fn wrap_client(
    stream: Box<dyn Conn>,
    settings: &TlsSettings,
    server_name: &str,
) -> Result<Box<dyn Conn>> {
    let config = client_config(settings)?;
    let name = server_name_from(server_name)?;
    let connector = TlsConnector::from(config);
    let stream = connector
        .connect(name, stream)
        .await
        .map_err(|e| Error::Tls(format!("tls handshake with `{server_name}` failed: {e}")))?;
    Ok(Box::new(stream))
}

/// 服务端 TLS 握手。
pub async fn wrap_server(stream: Box<dyn Conn>, settings: &TlsSettings) -> Result<Box<dyn Conn>> {
    let config = server_config(settings)?;
    let acceptor = TlsAcceptor::from(config);
    let stream = acceptor
        .accept(stream)
        .await
        .map_err(|e| Error::Tls(format!("tls accept failed: {e}")))?;
    Ok(Box::new(stream))
}

fn server_name_from(value: &str) -> Result<ServerName<'static>> {
    if let Ok(ip) = value.parse::<std::net::IpAddr>() {
        return Ok(ServerName::IpAddress(PkiIpAddr::from(ip)));
    }
    ServerName::try_from(value.to_string())
        .map_err(|e| Error::Tls(format!("invalid server name `{value}`: {e}")))
}

fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

fn client_config(settings: &TlsSettings) -> Result<Arc<ClientConfig>> {
    let provider = provider();
    let builder = ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .map_err(|e| Error::Tls(format!("tls config: {e}")))?;

    let mut config = if settings.allow_insecure {
        builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerify { provider }))
            .with_no_client_auth()
    } else {
        let mut roots = RootCertStore::empty();
        if !settings.disable_system_root {
            roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        }
        builder.with_root_certificates(roots).with_no_client_auth()
    };
    if let Some(alpn) = &settings.alpn {
        config.alpn_protocols = alpn.iter().map(|p| p.as_bytes().to_vec()).collect();
    }
    Ok(Arc::new(config))
}

fn server_config(settings: &TlsSettings) -> Result<Arc<ServerConfig>> {
    let certificates = settings.certificates.as_ref().ok_or_else(|| {
        Error::Tls("`tlsSettings.certificates` is required for inbound TLS".to_string())
    })?;
    let entry = certificates
        .first()
        .ok_or_else(|| Error::Tls("`tlsSettings.certificates` is empty".to_string()))?;
    let chain = load_cert_chain(entry)?;
    let key = load_private_key(entry)?;
    let mut config = ServerConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .map_err(|e| Error::Tls(format!("tls config: {e}")))?
        .with_no_client_auth()
        .with_single_cert(chain, key)
        .map_err(|e| Error::Tls(format!("invalid certificate or key: {e}")))?;
    if let Some(alpn) = &settings.alpn {
        config.alpn_protocols = alpn.iter().map(|p| p.as_bytes().to_vec()).collect();
    }
    Ok(Arc::new(config))
}

fn load_cert_chain(entry: &Certificate) -> Result<Vec<CertificateDer<'static>>> {
    let mut chain = Vec::new();
    if let Some(path) = &entry.certificate_file {
        let data = std::fs::read(path)
            .map_err(|e| Error::Tls(format!("read certificate file `{path}`: {e}")))?;
        let mut reader = std::io::BufReader::new(data.as_slice());
        for item in rustls_pemfile::certs(&mut reader) {
            chain.push(item.map_err(|e| Error::Tls(format!("parse certificate `{path}`: {e}")))?);
        }
    }
    if let Some(inline) = &entry.certificate {
        for pem in inline {
            let mut reader = std::io::BufReader::new(pem.as_bytes());
            for item in rustls_pemfile::certs(&mut reader) {
                chain.push(item.map_err(|e| Error::Tls(format!("parse inline certificate: {e}")))?);
            }
        }
    }
    if chain.is_empty() {
        return Err(Error::Tls(
            "no certificate found in tls settings".to_string(),
        ));
    }
    Ok(chain)
}

fn load_private_key(entry: &Certificate) -> Result<PrivateKeyDer<'static>> {
    if let Some(path) = &entry.key_file {
        let data = std::fs::read(path)
            .map_err(|e| Error::Tls(format!("read private key file `{path}`: {e}")))?;
        let mut reader = std::io::BufReader::new(data.as_slice());
        if let Some(key) = rustls_pemfile::private_key(&mut reader)
            .map_err(|e| Error::Tls(format!("parse private key `{path}`: {e}")))?
        {
            return Ok(key);
        }
        return Err(Error::Tls(format!("no private key found in `{path}`")));
    }
    if let Some(inline) = &entry.key {
        for pem in inline {
            let mut reader = std::io::BufReader::new(pem.as_bytes());
            if let Some(key) = rustls_pemfile::private_key(&mut reader)
                .map_err(|e| Error::Tls(format!("parse inline private key: {e}")))?
            {
                return Ok(key);
            }
        }
    }
    Err(Error::Tls(
        "no private key found in tls settings".to_string(),
    ))
}

/// `allowInsecure` 使用的证书校验器：不做任何校验，仅校验签名本身。
#[derive(Debug)]
struct NoVerify {
    provider: Arc<rustls::crypto::CryptoProvider>,
}

impl ServerCertVerifier for NoVerify {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}
