# Trojan 线协议规格（依据 upstream v26.9.30）

> 证据引用 `/home/dev/tmp/xray-core-ref` 内 Go 源码 `路径:行号`。
> 主实现：`proxy/trojan/{protocol,config,validator,client,server}.go`；配置：`infra/conf/trojan.go`。
> 注意：当前版本对 Trojan 打出弃用告警，推荐迁移到 "VLESS with Flow & Seed"（`infra/conf/trojan.go:42,121`、`114`）。

## 1. 账号与密码哈希

- `MemoryAccount{Password string, Key []byte}`（`proxy/trojan/config.go:15-18`）。
- `Key = hex.Encode(SHA-224(password))`，即 **56 个 ASCII 十六进制字符**（小写）（`config.go:44-50`）。
- 线上发送的是这 56 字节 ASCII（不是 28 字节原始摘要）（`protocol.go:70`，`buffer.Write(c.Account.Key)`）。
- 服务端认证键 = `hexString(收到的 56 字节)`（即对 ASCII 再 hex 一次得到 112 字符）（`server.go:188`、`validator.go:19-27, 46-52`）。因此**客户端必须发送小写 hex**，大写会导致用户名不匹配。

## 2. 地址编码（SOCKS5 风格，与 VLESS/VMess 不同）

`addrParser = NewAddressParser(AddressFamilyByte(0x01,IPv4), AddressFamilyByte(0x04,IPv6), AddressFamilyByte(0x03,Domain))`（`proxy/trojan/protocol.go:16-21`）。

| ATYP | 含义 | 长度 |
|---|---|---|
| `0x01` | IPv4 | 4 字节 |
| `0x04` | IPv6 | 16 字节 |
| `0x03` | 域名 | 1 字节长度 + N 字节 |

**未传 `PortThenAddress` ⇒ 地址在前、2 字节大端端口在后**（`common/protocol/address.go:55-75, 117-146`）。与 `docs/socks-protocol.md` 一致，与 `docs/vless-protocol.md` / `docs/vmess-protocol.md` 不同。

## 3. TCP 请求头

由 `ConnWriter.writeHeader` 生成（`proxy/trojan/protocol.go:64-92`），字节序列：

| 偏移 | 长度 | 字段 |
|---|---|---|
| 0 | 56 | `hex(SHA-224(password))` |
| 56 | 2 | `CRLF` = `0x0D 0x0A`（`protocol.go:14`） |
| 58 | 1 | Command：`1`=TCP，`3`=UDP（`protocol.go:24-27`） |
| 59 | 变长 | 地址 + 端口（§2 编码） |
| — | 2 | 再次 `CRLF` |

- Command 由目标网络决定：`Target.Network == UDP` → 3，否则 1（`protocol.go:67-70`）。
- 头在首次写 payload 前发送（`protocol.go:38-45`），之后直接透传数据（`protocol.go:47`）。
- 客户端 `Proxy` 用 `ConnWriter{Account, Target}` 写请求（`proxy/trojan/client.go` Process）。

服务端解析（`ConnReader.ParseHeader`，`protocol.go:161-199`）：读 56 字节 hash → CRLF → command → address/port → CRLF；`command==3` 则目标网络为 UDP（`protocol.go:177-180`）。

服务端首个字节流判定（`server.go:176`）：`firstLen < 58 || first.Byte(56) != '\r'` 即认为非 Trojan（56 字节 hash + CRLF 的 `\r` 位于下标 56）。

**响应**：Trojan 协议层**没有独立的响应头**——服务端校验通过后直接双向转发目标数据。

## 4. UDP 分帧

UDP 模式（Command=3）下，每个数据报独立成帧，且目标地址逐帧携带（支持多目标混合）：

### 4.1 发送（`PacketWriter.writePacket`，`protocol.go:125-145`）

| 长度 | 字段 |
|---|---|
| 变长 | 目的地址 + 2 字节大端端口（§2） |
| 2 | payload 长度（大端 uint16） |
| 2 | `CRLF` |
| N | payload |

### 4.2 接收（`PacketReader.ReadMultiBuffer`，`protocol.go:220-262`）

逆序读取：地址+端口 → 长度（大端）→ CRLF → payload。约束：
- `maxLength = 8192`，`remain > maxLength` 直接报 `oversize payload`（`protocol.go:24, 232-234`）。
- payload 按 `buf.Size`（8192）分片读入 multi-buffer（`protocol.go:236-252`）。
- 每个 buffer 标记 `b.UDP = &dest`（`protocol.go:240`）。

服务端 UDP 走 `handleUDPPayload`（`server.go:247-...`），把 `PacketReader` 接到 UDP dispatcher，回程用 `PacketWriter`。

## 5. 回退（fallback）

### 5.1 触发条件（`server.go:172-210`）

- 配置了 `fallbacks` 时 `napfb != nil`（`server.go:172-173`）。
- 首帧不满足 Trojan 判定，或 56 字节 hash 查不到用户 → `shouldFallback = true`（`server.go:176-201`）。
- 有 fallback 配置则进入 `s.fallback(...)`，否则报 `invalid protocol or invalid user`（`server.go:203-207`）。

### 5.2 选择逻辑（`server.go:364-470`）

匹配维度为 **name（SNI）→ alpn → path** 三级 map（`fallbacks map[string]map[string]map[string]*Fallback`，`server.go:40, 65-113`）：
1. 从底层连接取 SNI 与 ALPN：TLS 连接用 `ConnectionState().ServerName/NegotiatedProtocol`；REALITY 连接同理（`server.go:371-386`）。
2. name 匹配：若 `napfb` 多于一项或没有 `""` 项，则用「name 包含某键且键最长」做子串匹配，否则回退到 `""`（`server.go:388-403`）。
3. alpn 不存在则回退到 `""`（`server.go:408-415`）。
4. path：从首帧文本里解析 HTTP 请求行路径（`server.go:417-447`）：要求 `firstLen >= 18` 且 `first.Byte(4) != '*'`（非 h2c），在 `[4,8]` 找 `/` 且前一字节为空格，取到 `?`/空格前的部分（最多约 60 字节），再在 path map 中查找。
5. 用 `retry.ExponentialBackoff(5,100)` 拨号 `fb.Type`/`fb.Dest`，随后双向转发（`server.go:450-500`）。
6. `fb.Xver`（1 或 2）时先向目标发送 PROXY protocol v1/v2 头（`server.go:471-500`）。

### 5.3 配置字段（`infra/conf/trojan.go:96-104, 155-205`）

| 字段 | 类型 | 说明 |
|---|---|---|
| `name` | string | 按 SNI 匹配（可为空 = 默认） |
| `alpn` | string | 按 ALPN 匹配（可为空 = 默认） |
| `path` | string | 必须以 `/` 开头或为空（`trojan.go:174-176`） |
| `type` | string | `tcp` / `unix` / `serve`；留空且 `dest` 非空时自动推断 |
| `dest` | number\|string | 目标；必填 |
| `xver` | uint64 | PROXY protocol 版本，仅 0/1/2（`trojan.go:198-200`） |

**默认回退端口**：**不存在隐式默认端口**。`dest` 是必填项；当 `dest` 为纯数字时会被规范化为 `localhost:<port>`（`trojan.go:188-190`）。`type` 推断规则：`dest=="serve-ws-none"`→`serve`；绝对路径或以 `@` 开头→`unix`；否则能被 `host:port` 解析→`tcp`（`trojan.go:177-194`）。注意 `type=="serve"` 在 `proxy/trojan/server.go` 中**无对应拨号处理**（`server.go:457` 直接 `DialContext(fb.Type,...)`），仓库内也无 `"serve"` 网络注册点 —— 该分支疑似遗留，**未确认**能否实际工作。

## 6. 配置字段总览（`infra/conf/trojan.go`）

- 入站 `settings`：`users`/`clients[]{password,level,email,flow}`、`fallbacks[]`（`trojan.go:106-118`）。用户 `flow` 非空直接报 `Flow for Trojan` 已移除（`trojan.go:71-75, 133-136`）。
- 客户端 `settings`：`address,port,level,email,password,flow,servers[]{...}`（`trojan.go:31-39`）。
- 客户端与服务端均打印弃用告警（`trojan.go:42,121`）。

## 7. 与既有文档的地址映射对照

| 协议 | ATYP IPv4/IPv6/Domain | 端口位置 | 证据 |
|---|---|---|---|
| Trojan | `1 / 4 / 3` | 地址后 | `proxy/trojan/protocol.go:16-21` |
| SOCKS5 | `1 / 4 / 3` | 地址后 | `proxy/socks/protocol.go:39-43` |
| VLESS | `1 / 2 / 3` | 端口前 | `proxy/vless/encoding/encoding.go:22-27` |
| VMess | `1 / 2 / 3` | 端口前 | `proxy/vmess/encoding/encoding.go:12-17` |
| Mux.Cool | `1 / 2 / 3` | 端口前 | `common/mux/frame.go:38-43` |

Trojan 与 SOCKS5 同族；VLESS/VMess/Mux 同族。