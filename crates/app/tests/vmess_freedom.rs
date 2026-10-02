//! 集成测试：VMess（AEAD）入站 → Freedom 出站 → 本地回声服务器。
//!
//! 客户端侧直接用 `xxxr_proxy::vmess` 的编解码实现，因此这个测试同时覆盖了
//! 客户端与服务端两端的头部、KDF、AEAD 与 chunk 分帧。

use std::net::SocketAddr;
use std::time::Duration;

use rand::RngCore;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use uuid::Uuid;
use xxxr::Instance;
use xxxr_common::logging::{init_logging, Level};
use xxxr_config::{Config, VmessSecurity};
use xxxr_net::{Address, Conn};
use xxxr_proxy::vmess::chunk::{ChunkParams, ChunkedStream};
use xxxr_proxy::vmess::crypto::{self, BodyCipherKind};
use xxxr_proxy::vmess::header::{
    self, COMMAND_TCP, OPTION_CHUNK_MASKING, OPTION_CHUNK_STREAM, OPTION_GLOBAL_PADDING,
};

/// 测试用用户 UUID。
const USER_ID: &str = "b831381d-6324-4d53-ad4f-8cda48b30811";

/// 安装日志（仅本 workspace 的 crate），便于 CI 失败时定位原因。
fn setup_logging() {
    std::env::set_var("RUST_LOG", "xxxr=debug");
    init_logging(Level::Debug);
}

/// 启动一个回声服务器，返回其监听地址。
async fn spawn_echo_server() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind echo");
    let address = listener.local_addr().expect("echo local addr");
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let mut buffer = [0u8; 4096];
                loop {
                    match stream.read(&mut buffer).await {
                        Ok(0) | Err(_) => break,
                        Ok(read) => {
                            if stream.write_all(&buffer[..read]).await.is_err() {
                                break;
                            }
                        }
                    }
                }
            });
        }
    });
    address
}

/// 预留一个空闲端口。
async fn reserve_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind temp");
    let port = listener.local_addr().expect("temp local addr").port();
    drop(listener);
    port
}

/// 带重试地连接实例，等待 accept 循环就绪。
async fn connect_with_retry(port: u16) -> TcpStream {
    for _ in 0..100 {
        if let Ok(stream) = TcpStream::connect(("127.0.0.1", port)).await {
            return stream;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("instance on port {port} did not accept connections");
}

/// 构造 VMess 入站 + freedom 出站的配置。
fn build_config(port: u16, security: &str) -> Config {
    let json = format!(
        r#"{{
            "log": {{ "loglevel": "warning" }},
            "inbounds": [
                {{
                    "tag": "vmess-in",
                    "listen": "127.0.0.1",
                    "port": {port},
                    "protocol": "vmess",
                    "settings": {{
                        "clients": [
                            {{ "id": "{USER_ID}", "email": "test", "security": "{security}" }}
                        ]
                    }}
                }}
            ],
            "outbounds": [
                {{ "tag": "direct", "protocol": "freedom", "settings": {{}} }}
            ]
        }}"#
    );
    Config::from_json_str(&json).expect("parse config")
}

/// 建立一条 VMess 会话：发送请求头、校验响应头，返回分帧后的连接。
async fn vmess_connect(
    port: u16,
    dest: Address,
    user_id: Uuid,
    security: VmessSecurity,
) -> ChunkedStream {
    let mut stream = connect_with_retry(port).await;
    let mut rng = rand::rngs::OsRng;
    let mut body_key = [0u8; 16];
    let mut body_iv = [0u8; 16];
    rng.fill_bytes(&mut body_key);
    rng.fill_bytes(&mut body_iv);
    let response_header = (rng.next_u32() & 0xff) as u8;

    let option = OPTION_CHUNK_STREAM | OPTION_CHUNK_MASKING | OPTION_GLOBAL_PADDING;
    let request = header::RequestHeader {
        version: header::VERSION,
        body_iv,
        body_key,
        response_header,
        option,
        security,
        command: COMMAND_TCP,
        dest,
    };
    let inner = header::encode_inner(&request, &mut rng).expect("encode inner");
    let sealed =
        header::seal_header(&crypto::cmd_key(&user_id), &inner, &mut rng).expect("seal header");
    stream.write_all(&sealed).await.unwrap();
    stream.flush().await.unwrap();

    let response_key = header::derive_response_key(&body_key);
    let response_iv = header::derive_response_key(&body_iv);
    header::decode_response_header(&response_key, &response_iv, response_header, &mut stream)
        .await
        .expect("response header must validate");

    let kind = BodyCipherKind::from_security(security);
    let write_params = ChunkParams::new(body_key, body_iv, kind, option);
    let read_params = ChunkParams::new(response_key, response_iv, kind, option);
    ChunkedStream::new(Box::new(stream) as Box<dyn Conn>, read_params, write_params)
        .expect("chunked stream")
}

fn to_address(socket: SocketAddr) -> Address {
    Address::ip(socket.ip(), socket.port())
}

#[tokio::test]
async fn vmess_round_trip_aes_128_gcm() {
    setup_logging();
    let echo = spawn_echo_server().await;
    let port = reserve_port().await;
    let mut instance = Instance::new(build_config(port, "aes-128-gcm")).expect("build instance");
    instance.start();

    let mut client = vmess_connect(
        port,
        to_address(echo),
        Uuid::parse_str(USER_ID).unwrap(),
        VmessSecurity::Aes128Gcm,
    )
    .await;

    let payload = b"hello from vmess client";
    client.write_all(payload).await.unwrap();
    client.flush().await.unwrap();
    let mut echoed = vec![0u8; payload.len()];
    client.read_exact(&mut echoed).await.unwrap();
    assert_eq!(&echoed, payload);

    instance.shutdown().await;
}

#[tokio::test]
async fn vmess_round_trip_chacha20_poly1305_with_large_payload() {
    setup_logging();
    let echo = spawn_echo_server().await;
    let port = reserve_port().await;
    let mut instance =
        Instance::new(build_config(port, "chacha20-poly1305")).expect("build instance");
    instance.start();

    let mut client = vmess_connect(
        port,
        to_address(echo),
        Uuid::parse_str(USER_ID).unwrap(),
        VmessSecurity::Chacha20Poly1305,
    )
    .await;

    // 分两轮各 12KiB：每轮都超过单个 chunk 上限（8110），强制多 chunk 分帧；
    // 写完立刻读回，避免依赖内核缓冲大小而出现死锁。
    for round in 0..2u8 {
        let payload: Vec<u8> = (0..12_000u32).map(|index| (index as u8) ^ round).collect();
        client.write_all(&payload).await.unwrap();
        client.flush().await.unwrap();
        let mut received = vec![0u8; payload.len()];
        client.read_exact(&mut received).await.unwrap();
        assert_eq!(received, payload, "round {round}");
    }

    instance.shutdown().await;
}

#[tokio::test]
async fn vmess_rejects_unknown_user() {
    setup_logging();
    let echo = spawn_echo_server().await;
    let port = reserve_port().await;
    let mut instance = Instance::new(build_config(port, "aes-128-gcm")).expect("build instance");
    instance.start();

    // 未登记的用户：服务端在 AuthID 匹配阶段失败，直接关闭连接。
    let mut stream = connect_with_retry(port).await;
    let mut rng = rand::rngs::OsRng;
    let mut body_key = [0u8; 16];
    let mut body_iv = [0u8; 16];
    rng.fill_bytes(&mut body_key);
    rng.fill_bytes(&mut body_iv);
    let request = header::RequestHeader {
        version: header::VERSION,
        body_iv,
        body_key,
        response_header: 1,
        option: OPTION_CHUNK_MASKING,
        security: VmessSecurity::Aes128Gcm,
        command: COMMAND_TCP,
        dest: to_address(echo),
    };
    let inner = header::encode_inner(&request, &mut rng).unwrap();
    let unknown = Uuid::parse_str("11111111-2222-3333-4444-555555555555").unwrap();
    let sealed = header::seal_header(&crypto::cmd_key(&unknown), &inner, &mut rng).unwrap();
    stream.write_all(&sealed).await.unwrap();

    let mut buffer = [0u8; 32];
    match stream.read(&mut buffer).await {
        Ok(read) => assert_eq!(read, 0, "unknown user must be rejected"),
        Err(e) if e.kind() == std::io::ErrorKind::ConnectionReset => {}
        Err(e) => panic!("unexpected error: {e}"),
    }

    instance.shutdown().await;
}

#[tokio::test]
async fn vmess_rejects_replayed_auth_id() {
    setup_logging();
    let echo = spawn_echo_server().await;
    let port = reserve_port().await;
    let mut instance = Instance::new(build_config(port, "aes-128-gcm")).expect("build instance");
    instance.start();

    // 手工构造一份完整的请求头字节，然后原样重放两次。
    let mut rng = rand::rngs::OsRng;
    let mut body_key = [0u8; 16];
    let mut body_iv = [0u8; 16];
    rng.fill_bytes(&mut body_key);
    rng.fill_bytes(&mut body_iv);
    let request = header::RequestHeader {
        version: header::VERSION,
        body_iv,
        body_key,
        response_header: 2,
        option: OPTION_CHUNK_MASKING,
        security: VmessSecurity::Aes128Gcm,
        command: COMMAND_TCP,
        dest: to_address(echo),
    };
    let user_id = Uuid::parse_str(USER_ID).unwrap();
    let inner = header::encode_inner(&request, &mut rng).unwrap();
    let sealed = header::seal_header(&crypto::cmd_key(&user_id), &inner, &mut rng).unwrap();

    // 第一次：正常完成握手。
    let mut first = connect_with_retry(port).await;
    first.write_all(&sealed).await.unwrap();
    let mut buffer = [0u8; 32];
    assert!(
        first.read(&mut buffer).await.unwrap() > 0,
        "first request must be accepted"
    );

    // 第二次：同一份 AuthID 重放，服务端应拒绝（时间窗内视为重放）。
    let mut second = connect_with_retry(port).await;
    second.write_all(&sealed).await.unwrap();
    match second.read(&mut buffer).await {
        Ok(read) => assert_eq!(read, 0, "replayed auth id must be rejected"),
        Err(e) if e.kind() == std::io::ErrorKind::ConnectionReset => {}
        Err(e) => panic!("unexpected error: {e}"),
    }

    instance.shutdown().await;
}
