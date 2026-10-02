//! 集成测试：SOCKS5 入站 → Freedom 出站 → 本地回声服务器。

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use xxxr::Instance;
use xxxr_common::logging::{init_logging, Level};
use xxxr_config::Config;

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

/// 构造 SOCKS 入站 + freedom 出站的最小配置。
fn build_config(socks_port: u16) -> Config {
    let json = format!(
        r#"{{
            "log": {{ "loglevel": "warning" }},
            "inbounds": [
                {{
                    "tag": "socks-in",
                    "listen": "127.0.0.1",
                    "port": {socks_port},
                    "protocol": "socks",
                    "settings": {{ "auth": "noauth", "udp": true }}
                }}
            ],
            "outbounds": [
                {{ "tag": "direct", "protocol": "freedom", "settings": {{}} }}
            ]
        }}"#
    );
    Config::from_json_str(&json).expect("parse config")
}

#[tokio::test]
async fn socks5_connect_round_trip() {
    setup_logging();
    let echo = spawn_echo_server().await;
    let port = reserve_port().await;
    let mut instance = Instance::new(build_config(port)).expect("build instance");
    instance.start();

    let mut client = connect_with_retry(port).await;

    // 方法协商：仅提供「无认证」。
    client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
    let mut method = [0u8; 2];
    client.read_exact(&mut method).await.unwrap();
    assert_eq!(method, [0x05, 0x00], "server must select no-auth");

    // CONNECT 请求。
    let mut request = vec![0x05, 0x01, 0x00];
    match echo.ip() {
        IpAddr::V4(v4) => {
            request.push(0x01);
            request.extend_from_slice(&v4.octets());
        }
        IpAddr::V6(v6) => {
            request.push(0x04);
            request.extend_from_slice(&v6.octets());
        }
    }
    request.extend_from_slice(&echo.port().to_be_bytes());
    client.write_all(&request).await.unwrap();

    // 应答（IPv4 形式共 10 字节）。
    let mut reply = [0u8; 10];
    client.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply[0], 0x05);
    assert_eq!(reply[1], 0x00, "CONNECT must succeed");

    // 数据往返。
    let payload = b"hello from socks client";
    client.write_all(payload).await.unwrap();
    let mut echoed = vec![0u8; payload.len()];
    client.read_exact(&mut echoed).await.unwrap();
    assert_eq!(&echoed, payload);

    instance.shutdown().await;
}

#[tokio::test]
async fn socks5_password_auth_rejects_bad_credentials() {
    setup_logging();
    let port = reserve_port().await;
    let json = format!(
        r#"{{
            "inbounds": [
                {{
                    "tag": "socks-in",
                    "listen": "127.0.0.1",
                    "port": {port},
                    "protocol": "socks",
                    "settings": {{
                        "auth": "password",
                        "accounts": [{{ "user": "u", "pass": "p" }}]
                    }}
                }}
            ],
            "outbounds": [
                {{ "tag": "direct", "protocol": "freedom", "settings": {{}} }}
            ]
        }}"#
    );
    let config = Config::from_json_str(&json).expect("parse config");
    let mut instance = Instance::new(config).expect("build instance");
    instance.start();

    let mut client = connect_with_retry(port).await;
    client.write_all(&[0x05, 0x01, 0x02]).await.unwrap();
    let mut method = [0u8; 2];
    client.read_exact(&mut method).await.unwrap();
    assert_eq!(method, [0x05, 0x02], "server must select user/pass auth");

    // 错误的凭据：应先收到失败状态，随后连接被关闭。
    client
        .write_all(&[0x01, 0x01, b'x', 0x01, b'y'])
        .await
        .unwrap();
    let mut status = [0u8; 2];
    client.read_exact(&mut status).await.unwrap();
    assert_eq!(status, [0x01, 0x01], "bad credentials must be rejected");

    instance.shutdown().await;
}
