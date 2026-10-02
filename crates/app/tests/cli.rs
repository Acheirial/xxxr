//! `xxxr` CLI 的端到端冒烟测试。
//!
//! 这些用例直接执行编译出的二进制，验证 `version` 与 `run` 子命令的真实行为
//! （配置加载、端口绑定、进程退出码）。

use std::io::Write;
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// 编译出的 `xxxr` 二进制路径。
fn binary() -> &'static str {
    env!("CARGO_BIN_EXE_xxxr")
}

/// 预留一个空闲的本地端口。
fn reserve_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind temp port");
    listener.local_addr().expect("temp addr").port()
}

/// 把配置写入 cargo 提供的测试临时目录（`target/tmp`）。
fn write_config(contents: &str) -> PathBuf {
    let path = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("xxxr-cli-smoke.json");
    let mut file = std::fs::File::create(&path).expect("create config file");
    file.write_all(contents.as_bytes())
        .expect("write config file");
    path
}

#[test]
fn version_subcommand_prints_version() {
    let output = Command::new(binary())
        .arg("version")
        .output()
        .expect("spawn `xxxr version`");
    assert!(output.status.success(), "`xxxr version` must exit 0");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains(env!("CARGO_PKG_VERSION")),
        "unexpected stdout: {stdout}"
    );
}

#[test]
fn run_without_config_fails() {
    let output = Command::new(binary())
        .arg("run")
        .output()
        .expect("spawn `xxxr run`");
    assert!(
        !output.status.success(),
        "`xxxr run` without `-c` must fail"
    );
}

#[test]
fn run_binds_configured_port() {
    let port = reserve_port();
    let config = write_config(&format!(
        r#"{{
            "log": {{ "loglevel": "warning" }},
            "inbounds": [
                {{
                    "tag": "socks-in",
                    "listen": "127.0.0.1",
                    "port": {port},
                    "protocol": "socks",
                    "settings": {{ "auth": "noauth" }}
                }}
            ],
            "outbounds": [
                {{ "tag": "direct", "protocol": "freedom", "settings": {{}} }}
            ]
        }}"#
    ));

    let mut child = Command::new(binary())
        .arg("-c")
        .arg(&config)
        .arg("run")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn `xxxr -c <config> run`");

    let target = SocketAddr::from(([127, 0, 0, 1], port));
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut listening = false;
    while Instant::now() < deadline {
        if child.try_wait().expect("try_wait").is_some() {
            break;
        }
        if TcpStream::connect_timeout(&target, Duration::from_millis(200)).is_ok() {
            listening = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }

    let _ = child.kill();
    let _ = child.wait();
    assert!(
        listening,
        "`xxxr -c <config> run` must listen on port {port}"
    );
}
