//! 集成测试：Trojan 入站 → Freedom 出站 → 本地回声服务器。
//!
//! Trojan 通常跑在 TLS 之上，但协议本身与传输层无关；这里按 `streamSettings`
//! 用明文传输，以便在本地回环验证线格式本身。

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use xxxr::Instance;
use xxxr_common::logging::{init_logging, Level};
use xxxr_config::Config;
use xxxr_net::Address;
use xxxr_proxy::trojan::{encode_request, password_key, COMMAND_TCP, COMMAND_UDP};

/// 测试用密码。
const PASSWORD: &str = "secret";

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

/// 构造 Trojan 入站 + freedom 出站的最小配置。
fn build_config(port: u16) -> Config {
    let json = format!(
        r#"{{
            "log": {{ "loglevel": "warning" }},
            "inbounds": [
                {{
                    "tag": "trojan-in",
                    "listen": "127.0.0.1",
                    "port": {port},
                    "protocol": "trojan",
                    "settings": {{
                        "clients": [{{ "password": "{PASSWORD}", "email": "test" }}]
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

/// 把套接字地址转成协议地址。
fn to_address(socket: SocketAddr) -> Address {
    match socket.ip() {
        IpAddr::V4(v4) => Address::ip(IpAddr::V4(v4), socket.port()),
        IpAddr::V6(v6) => Address::ip(IpAddr::V6(v6), socket.port()),
    }
}

#[tokio::test]
async fn trojan_round_trip_to_echo() {
    setup_logging();
    let echo = spawn_echo_server().await;
    let port = reserve_port().await;
    let mut instance = Instance::new(build_config(port)).expect("build instance");
    instance.start();

    let mut client = connect_with_retry(port).await;
    let header = encode_request(&password_key(PASSWORD), &to_address(echo), COMMAND_TCP)
        .expect("encode request");
    client.write_all(&header).await.unwrap();

    // Trojan 没有响应头：认证通过后可以直接发数据。
    let payload = b"hello from trojan client";
    client.write_all(payload).await.unwrap();
    let mut echoed = vec![0u8; payload.len()];
    client.read_exact(&mut echoed).await.unwrap();
    assert_eq!(&echoed, payload);

    instance.shutdown().await;
}

#[tokio::test]
async fn trojan_round_trip_with_domain_destination() {
    setup_logging();
    let echo = spawn_echo_server().await;
    let port = reserve_port().await;
    let mut instance = Instance::new(build_config(port)).expect("build instance");
    instance.start();

    // 域名形式的目标地址（IPv4 字面量域名，freedom 会直接解析）。
    let mut client = connect_with_retry(port).await;
    let header = encode_request(
        &password_key(PASSWORD),
        &Address::domain("127.0.0.1", echo.port()),
        COMMAND_TCP,
    )
    .expect("encode request");
    client.write_all(&header).await.unwrap();

    let payload = b"domain destination";
    client.write_all(payload).await.unwrap();
    let mut echoed = vec![0u8; payload.len()];
    client.read_exact(&mut echoed).await.unwrap();
    assert_eq!(&echoed, payload);

    instance.shutdown().await;
}

#[tokio::test]
async fn trojan_rejects_unknown_password() {
    setup_logging();
    let echo = spawn_echo_server().await;
    let port = reserve_port().await;
    let mut instance = Instance::new(build_config(port)).expect("build instance");
    instance.start();

    let mut client = connect_with_retry(port).await;
    let header = encode_request(&password_key("wrong"), &to_address(echo), COMMAND_TCP)
        .expect("encode request");
    client.write_all(&header).await.unwrap();

    // 无 fallback 配置时应直接关闭连接（FIN 或 RST）。
    let mut buffer = [0u8; 16];
    match client.read(&mut buffer).await {
        Ok(read) => assert_eq!(read, 0, "unknown user must be rejected"),
        Err(e) if e.kind() == std::io::ErrorKind::ConnectionReset => {}
        Err(e) => panic!("unexpected error: {e}"),
    }

    instance.shutdown().await;
}

#[tokio::test]
async fn trojan_rejects_udp_command() {
    setup_logging();
    let echo = spawn_echo_server().await;
    let port = reserve_port().await;
    let mut instance = Instance::new(build_config(port)).expect("build instance");
    instance.start();

    let mut client = connect_with_retry(port).await;
    // 认证正确但命令是 UDP：本版本明确不支持，连接应被关闭。
    let header = encode_request(&password_key(PASSWORD), &to_address(echo), COMMAND_UDP)
        .expect("encode request");
    client.write_all(&header).await.unwrap();

    let mut buffer = [0u8; 16];
    match client.read(&mut buffer).await {
        Ok(read) => assert_eq!(read, 0, "UDP command must be rejected"),
        Err(e) if e.kind() == std::io::ErrorKind::ConnectionReset => {}
        Err(e) => panic!("unexpected error: {e}"),
    }

    instance.shutdown().await;
}
