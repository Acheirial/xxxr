//! 集成测试：VLESS 入站 → Freedom 出站 → 本地回声服务器。

use std::net::SocketAddr;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use uuid::Uuid;
use xxxr::Instance;
use xxxr_common::logging::{init_logging, Level};
use xxxr_config::Config;

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

/// 构造 VLESS 入站 + freedom 出站的最小配置。
fn build_config(vless_port: u16) -> Config {
    let json = format!(
        r#"{{
            "log": {{ "loglevel": "warning" }},
            "inbounds": [
                {{
                    "tag": "vless-in",
                    "listen": "127.0.0.1",
                    "port": {vless_port},
                    "protocol": "vless",
                    "settings": {{
                        "decryption": "none",
                        "clients": [{{ "id": "{USER_ID}", "email": "test" }}]
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

/// 编码一个 VLESS TCP 请求头（域名形式的目标地址）。
fn vless_request(host: &str, port: u16) -> Vec<u8> {
    let mut header = Vec::new();
    header.push(0u8); // version
    header.extend_from_slice(Uuid::parse_str(USER_ID).unwrap().as_bytes());
    header.push(0u8); // addons length
    header.push(0x01); // command: TCP
    header.extend_from_slice(&port.to_be_bytes());
    header.push(0x02); // address type: domain
    header.push(host.len() as u8);
    header.extend_from_slice(host.as_bytes());
    header
}

#[tokio::test]
async fn vless_tcp_round_trip() {
    setup_logging();
    let echo = spawn_echo_server().await;
    let port = reserve_port().await;
    let mut instance = Instance::new(build_config(port)).expect("build instance");
    instance.start();

    let mut client = connect_with_retry(port).await;
    client
        .write_all(&vless_request("127.0.0.1", echo.port()))
        .await
        .unwrap();

    // 响应头：version + addons length。
    let mut response = [0u8; 2];
    client.read_exact(&mut response).await.unwrap();
    assert_eq!(response[0], 0x00);

    // 数据往返。
    let payload = b"hello from vless client";
    client.write_all(payload).await.unwrap();
    let mut echoed = vec![0u8; payload.len()];
    client.read_exact(&mut echoed).await.unwrap();
    assert_eq!(&echoed, payload);

    instance.shutdown();
}

#[tokio::test]
async fn vless_rejects_unknown_user() {
    setup_logging();
    let echo = spawn_echo_server().await;
    let port = reserve_port().await;
    let mut instance = Instance::new(build_config(port)).expect("build instance");
    instance.start();

    let mut client = connect_with_retry(port).await;
    let mut header = vless_request("127.0.0.1", echo.port());
    // 替换为未登记的 UUID。
    let unknown = Uuid::parse_str("11111111-2222-3333-4444-555555555555").unwrap();
    header[1..17].copy_from_slice(unknown.as_bytes());
    client.write_all(&header).await.unwrap();

    // 服务端应关闭连接且不回写响应头。由于服务端未回写任何数据即断开，
    // Linux 上可能表现为 FIN（读到 0）或 RST（ConnectionReset），两者都算拒绝。
    let mut buffer = [0u8; 2];
    match client.read(&mut buffer).await {
        Ok(read) => assert_eq!(read, 0, "connection must be closed for unknown user"),
        Err(e) if e.kind() == std::io::ErrorKind::ConnectionReset => {}
        Err(e) => panic!("unexpected error for unknown user: {e}"),
    }

    instance.shutdown();
}
