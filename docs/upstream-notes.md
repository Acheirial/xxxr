# 上游 XTLS/Xray-core 版本与结构备注

> 本文所有结论均来自本地克隆 `/home/dev/tmp/xray-core-ref`，引用格式为 `路径:行号`。
> 无法确认的内容标注「未确认」。

## 1. 版本信息（已核实）

| 项 | 值 | 证据 |
|---|---|---|
| 克隆源 | `https://github.com/XTLS/Xray-core.git`（`--depth 1`，分支 `main`） | `git ls-remote` |
| HEAD commit | `b26a91de4f3294e26a0ad0a970b81a386a41f789` | `git rev-parse HEAD` |
| 最新 tag / release | **`v26.9.30`**（2026-09-30 07:40:04 +0000） | `git ls-remote --tags`；`git log -1` |
| 内核版本常量 | `Version_x=26, Version_y=9, Version_z=30` | `core/core.go:20-23` |
| Go module | `github.com/xtls/xray-core`，`go 1.27` | `go.mod:1-3` |

**重要更正**：任务书假设「最新 release 是 v26.3.27 / d2758a0」与事实不符。
- `v26.3.27` **确实存在**，其 commit 为 `d2758a023cd7f4174a5a5fa4ff66e487d4342ba0`（见 `git ls-remote --tags`），但已被多个 tag 超越。
- 当前最新为 `v26.9.30`（commit 与 HEAD 相同）。
- 中间存在的 tag：`v26.3.27, v26.4.13, v26.4.15, v26.4.17, v26.4.25, v26.5.3, v26.5.9, v26.6.1, v26.6.22, v26.6.27, v26.7.11, v26.7.28, v26.9.8, v26.9.9, v26.9.30`。

## 2. 目录结构概览

顶层（`ls` 输出）：

```
app/          应用层（dispatcher/dns/log/proxyman/router/policy/stats/reverse/observatory/...）
common/       通用库（net/buf/protocol/serial/session/crypto/uuid/geodata/...）
core/         核心 Config、版本、Instance 管理
features/     接口定义（inbound/outbound/routing/dns/policy/stats/extension）
infra/conf/   JSON 配置解析（本文档主要依据）+ infra/vformat、vprotogen
main/         入口与 distro/json/toml/yaml/confloader/commands
proxy/        各代理协议实现
transport/    传输层（internet/ + pipe/）
testing/      集成测试脚本
```

`proxy/` 下协议实现（`ls proxy/`）：
`blackhole, dns, dokodemo, freedom, http, hysteria, loopback, masque, shadowsocks, shadowsocks_2022, socks, trojan, tun, vless, vmess, wireguard`

`transport/internet/` 下传输实现（`ls transport/internet/*/`）：
`browser_dialer, finalmask, grpc, headers, httpupgrade, hysteria, kcp, masque, reality, splithttp, stat, tagged, tcp, tls, udp, websocket, xdrive`

实际注册清单见 `main/distro/all/all.go:1-83`：代理注册 `blackhole/dns/dokodemo/freedom/http/loopback/masque/shadowsocks/socks/trojan/vless(inbound|outbound)/vmess(inbound|outbound)/wireguard`；传输注册 `grpc/httpupgrade/kcp/masque/reality/splithttp/tcp/tls/udp/websocket/xdrive`；头部伪装 `headers/http`、`headers/noop`。

## 3. crust 化模块映射建议

Rust 侧建议按"语义边界"而非 Go 包边界切分。下表给出映射（`→` 左侧为上游 Go 包）。

| 上游 Go 包 | Rust crate / module 建议 | 职责 |
|---|---|---|
| `common/net` | `xray-net` | 地址/端口/目标/网络类型，`Address`、`Destination`、`Port`、`Network` |
| `common/buf` | `xray-buf` | 零拷贝 `Buffer`/`MultiBuffer`、`Reader`/`Writer` trait |
| `common/protocol` | `xray-proto` | `RequestHeader`/`RequestCommand`/`AddressType`、地址解析器 |
| `common/serial` | `xray-serial` | TypedMessage（protobuf Any）封装 |
| `common/uuid` | `xray-uuid` | UUID 解析与规范串 |
| `common/session`, `common/signal`, `common/task` | `xray-common` | 上下文、取消信号、任务编排 |
| `common/crypto`, `common/protocol/tls`, `common/protocol/quic` | `xray-crypto` | AEAD、TLS/QUIC 辅助 |
| `transport/internet` | `xray-transport` | `StreamConfig`、dialer/listener、sockopt |
| `transport/internet/{tcp,websocket,splithttp,grpc,kcp,httpupgrade,hysteria,masque,xdrive}` | `xray-transport-*`（可合并为子模块） | 各 `network` 实现 |
| `transport/internet/{tls,reality}` | `xray-transport-security` | `security=tls/reality` |
| `proxy/vless` | `xray-proxy-vless` | VLESS 线协议 + 账号 + validator |
| `proxy/vmess` | `xray-proxy-vmess` | VMess 线协议（aead/encoding） |
| `proxy/{trojan,shadowsocks,shadowsocks_2022,socks,http}` | `xray-proxy-*` | 各协议 |
| `proxy/{freedom,blackhole,dokodemo,loopback,dns,wireguard,tun,hysteria,masque}` | `xray-proxy-*` | 出/入站特殊协议 |
| `app/{dispatcher,proxyman,router,dns,policy,stats,log,reverse,observatory,...}` | `xray-app` / `xray-app-*` | 应用层 |
| `infra/conf` | `xray-config` | JSON schema 解析（建议用 serde + 自定义反序列化复刻宽容语法） |
| `core` | `xray-core` | 顶层 `Config` 组装、feature 注册 |
| `features/*` | `xray-features` | trait 定义 |

### 建议要点（依据上游实现）

1. **配置解析宽容度必须复刻**：上游大量字段接受 `int | string | "lo-hi"` 多形态（如 `PortList`、`Int32Range`，见 `common.go:215-363`），serde 需自定义 `Deserialize`，不能只用 `u16`。
2. **地址类型映射是协议相关而非全局**：VLESS 用 IPv4=1/Domain=2/IPv6=3 且 **port 在前**（`proxy/vless/encoding/encoding.go:22-27`），而 SOCKS5 用 IPv4=1/IPv6=4/Domain=3 且 **address 在前**（`proxy/socks/protocol.go:39-43`，address.go 默认 portLast）。Rust 侧不要共享单一映射常量。
3. **`method` 是 `network` 的历史别名**（`transport_internet.go:80-82`），解析时需兼容。
4. **大量旧特性已被显式移除并报错**：`security=xtls`、`http`/`quic` 传输、全局 `transport`、`proxySettings`、`allowInsecure`、`freedom.noise`(单数) 等。Rust 重写应直接丢弃，并在解析时报对应错误（见 `transport_internet.go:13-46`、`xray.go:268,674`、`transport_security.go:362`）。

## 4. 参考命名与注册机制

- 配置加载器以 `protocol` 字段做映射：`inboundConfigLoader` 与 `outboundConfigLoader`（`infra/conf/xray.go:24-57`）。
- 各协议通过 Go `init()` 注册到 feature（`main/distro/all/all.go` 的空白 import 集合即完整清单）。
- Rust 侧建议等价做法：显式 `Registry` + `enum ProtocolKind`，或 feature-gated 注册表，避免隐式 init。