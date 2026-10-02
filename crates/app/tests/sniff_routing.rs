//! 集成测试：TLS 嗅探 + 按嗅探域名路由。
//!
//! 拓扑：客户端 → SOCKS5 入站（开启 `sniffing`，`routeOnly`）→ 路由按嗅探出的
//! SNI 选择出站 → freedom 连到本地「假 TLS 服务」；未命中规则的 SNI 走 blackhole。
//!
//! 假 TLS 服务只做回显：客户端发 ClientHello，服务端原样回发，因此可以直接断言
//! 「数据是否穿过了预期的出站」。

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

/// 启动回显服务器（充当「目标站点」），返回其监听地址。
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

/// 构造最小 TLS 1.2 ClientHello（含 `server_name` 扩展）。
fn client_hello(server_name: &str) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&[0x03, 0x03]);
    body.extend_from_slice(&[0u8; 32]);
    body.push(0);
    body.extend_from_slice(&[0x00, 0x02, 0x13, 0x01]);
    body.extend_from_slice(&[0x01, 0x00]);

    let mut sni = Vec::new();
    sni.extend_from_slice(&((server_name.len() + 3) as u16).to_be_bytes());
    sni.push(0x00);
    sni.extend_from_slice(&(server_name.len() as u16).to_be_bytes());
    sni.extend_from_slice(server_name.as_bytes());

    let mut extensions = Vec::new();
    extensions.extend_from_slice(&[0x00, 0x00]);
    extensions.extend_from_slice(&(sni.len() as u16).to_be_bytes());
    extensions.extend_from_slice(&sni);

    let mut hello_body = body;
    hello_body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
    hello_body.extend_from_slice(&extensions);

    let mut hello = Vec::new();
    hello.push(0x01);
    hello.extend_from_slice(&(hello_body.len() as u32).to_be_bytes()[1..]);
    hello.extend_from_slice(&hello_body);

    let mut record = Vec::new();
    record.push(0x16);
    record.extend_from_slice(&[0x03, 0x01]);
    record.extend_from_slice(&(hello.len() as u16).to_be_bytes());
    record.extend_from_slice(&hello);
    record
}

/// 配置：SOCKS 入站（启用嗅探、routeOnly）+ 按嗅探域名分流 + freedom/blackhole 出站。
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
                    "settings": {{ "auth": "noauth" }},
                    "sniffing": {{
                        "enabled": true,
                        "destOverride": ["tls", "http"],
                        "routeOnly": true,
                        "domainsExcluded": ["domain:excluded.example"]
                    }}
                }}
            ],
            "outbounds": [
                {{ "tag": "blackhole", "protocol": "blackhole", "settings": {{}} }},
                {{ "tag": "direct", "protocol": "freedom", "settings": {{}} }}
            ],
            "routing": {{
                "rules": [
                    {{
                        "type": "field",
                        "inboundTag": ["socks-in"],
                        "domain": ["full:sniffed.example"],
                        "outboundTag": "direct"
                    }}
                ]
            }}
        }}"#
    );
    Config::from_json_str(&json).expect("parse config")
}

/// 通过 SOCKS5 CONNECT 建立到 `target` 的隧道。
async fn socks_connect(port: u16, target: SocketAddr) -> TcpStream {
    let mut client = connect_with_retry(port).await;
    client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
    let mut method = [0u8; 2];
    client.read_exact(&mut method).await.unwrap();
    assert_eq!(method, [0x05, 0x00]);

    let mut request = vec![0x05, 0x01, 0x00];
    match target.ip() {
        IpAddr::V4(v4) => {
            request.push(0x01);
            request.extend_from_slice(&v4.octets());
        }
        IpAddr::V6(v6) => {
            request.push(0x04);
            request.extend_from_slice(&v6.octets());
        }
    }
    request.extend_from_slice(&target.port().to_be_bytes());
    client.write_all(&request).await.unwrap();

    let mut reply = [0u8; 10];
    client.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply[1], 0x00, "CONNECT must succeed");
    client
}

#[tokio::test]
async fn routes_by_sniffed_sni_to_configured_outbound() {
    setup_logging();
    let echo = spawn_echo_server().await;
    let port = reserve_port().await;
    let mut instance = Instance::new(build_config(port)).expect("build instance");
    assert_eq!(instance.sniffing_inbound_count(), 1);
    instance.start();

    // SNI 命中路由规则 → 走 freedom，数据能往返。
    let mut client = socks_connect(port, echo).await;
    let hello = client_hello("sniffed.example");
    client.write_all(&hello).await.unwrap();
    let mut echoed = vec![0u8; hello.len()];
    client.read_exact(&mut echoed).await.unwrap();
    assert_eq!(
        echoed, hello,
        "sniffed SNI must be routed to the freedom outbound"
    );

    instance.shutdown().await;
}

#[tokio::test]
async fn unmatched_sniffed_domain_falls_back_to_first_outbound() {
    setup_logging();
    let echo = spawn_echo_server().await;
    let port = reserve_port().await;
    let mut instance = Instance::new(build_config(port)).expect("build instance");
    instance.start();

    // SNI 不命中规则 → 默认出站是 blackhole：连接被关闭，没有任何回显。
    let mut client = socks_connect(port, echo).await;
    client
        .write_all(&client_hello("unmatched.example"))
        .await
        .unwrap();
    let mut buffer = [0u8; 16];
    match client.read(&mut buffer).await {
        Ok(read) => assert_eq!(read, 0, "blackhole must close the session"),
        Err(e) if e.kind() == std::io::ErrorKind::ConnectionReset => {}
        Err(e) => panic!("unexpected error: {e}"),
    }

    instance.shutdown().await;
}

#[tokio::test]
async fn excluded_domain_is_not_used_for_routing() {
    setup_logging();
    let echo = spawn_echo_server().await;
    let port = reserve_port().await;
    let mut instance = Instance::new(build_config(port)).expect("build instance");
    instance.start();

    // 被 domainsExcluded 排除的域名不参与改写，因此也不参与按域名路由 → blackhole。
    let mut client = socks_connect(port, echo).await;
    client
        .write_all(&client_hello("excluded.example"))
        .await
        .unwrap();
    let mut buffer = [0u8; 16];
    let first = client.read(&mut buffer).await;
    assert!(
        matches!(first, Ok(0)) || first.is_err(),
        "excluded SNI must not be used for routing"
    );

    instance.shutdown().await;
}
