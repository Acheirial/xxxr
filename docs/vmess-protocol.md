# VMess 线协议逐字节规格（依据 upstream v26.9.30）

> 证据引用 `/home/dev/tmp/xray-core-ref` 内 Go 源码 `路径:行号`。
> 主实现：`proxy/vmess/encoding/{client,server,encoding,auth,commands}.go`、`proxy/vmess/aead/{encrypt,authid,kdf,consts}.go`、`common/crypto/{auth,chunk}.go`、`common/protocol/*`。

## 0. 重要前提：当前版本只有 AEAD，没有 AES-128-CFB 线格式

- 协议版本 `Version = byte(1)`（`proxy/vmess/encoding/encoding.go:8-10`）。
- 当前 `security` **仅支持 `aes-128-gcm` 与 `chacha20-poly1305`**（外加 `auto`，运行时按硬件解析为前两者之一）。枚举：`SecurityType_UNKNOWN=0, AUTO=2, AES128_GCM=3, CHACHA20_POLY1305=4`（`common/protocol/headers.pb.go:27-31`）。`auto` 的解析见 `common/protocol/headers.go:83-90`。
- `EncodeRequestBody` / `DecodeRequestBody` 的 switch **只有** AES128_GCM 与 CHACHA20_POLY1305 两个分支，default 直接报 `invalid option: Security`（`proxy/vmess/encoding/client.go:159-160`、`proxy/vmess/encoding/server.go:398-399`）。
- **AES-128-CFB 已不在线格式中**：`common/crypto/aes.go:11-21` 仍保留 `NewAesDecryptionStream`/`NewAesEncryptionStream`（CFB），且 `client.go:236-237`（`c.responseReader = NewCryptionReader(CFB...)`）与 `server.go:320-322`（`s.responseWriter = NewCryptionWriter(CFB...)`）仍对这两个字段赋值，但 `responseReader`/`responseWriter` **在全仓库无其他读取点**（grep 仅命中定义与赋值），实际响应体走 `DecodeResponseBody(request, reader)` / `EncodeResponseBody(request, output)`（`proxy/vmess/outbound/outbound.go:199`、`proxy/vmess/inbound/inbound.go:191`），传入的是**原始** reader/writer。结论：CFB 路径为死代码，Rust 重写无需实现。
- 本文件描述的是 **AEAD（VMess AEAD / 又称 "VMess MD5/timestamp + AEAD header"）** 格式，即当前唯一的线上格式。

## 1. 常量

| 常量 | 值 | 证据 |
|---|---|---|
| Version | `1` | `proxy/vmess/encoding/encoding.go:8-10` |
| Command TCP / UDP / Mux | `0x01` / `0x02` / `0x03` | `common/protocol/headers.go:15-17` |
| 地址类型 IPv4 / Domain / IPv6 | `0x01` / `0x02` / `0x03` | `common/protocol/payload.go:13-15` |
| Option ChunkStream | `0x01`（已废弃注释） | `common/protocol/headers.go:33-34` |
| Option ChunkMasking | `0x04` | `common/protocol/headers.go:38` |
| Option GlobalPadding | `0x08` | `common/protocol/headers.go:40` |
| Option AuthenticatedLength | `0x10` | `common/protocol/headers.go:42` |
| ID 长度 | `IDBytesLen = 16` | `common/protocol/id.go:10-12` |

### 1.1 CmdKey 派生（关键）

`protocol.NewID(uuid)` 计算 `cmdKey = MD5(uuid.Bytes() || "c48619fe-8f02-49e0-b9e9-edf763e17e21")`（`common/protocol/id.go:42-49`）。VMess 的 AuthID 加密与 AEAD KDF 全部以该 `cmdKey` 为根密钥。

## 2. 地址编码（与 VLESS 相同，与 SOCKS5 不同）

`addrParser = NewAddressParser(AddressFamilyByte(1,IPv4), AddressFamilyByte(2,Domain), AddressFamilyByte(3,IPv6), PortThenAddress())`（`proxy/vmess/encoding/encoding.go:12-17`）。

| ATYP | 含义 | 长度 |
|---|---|---|
| `0x01` | IPv4 | 4 字节 |
| `0x02` | Domain | 1 字节长度 + N 字节 |
| `0x03` | IPv6 | 16 字节 |

**PortThenAddress ⇒ 先 2 字节大端端口，再地址**（`common/protocol/address.go:15-19`、`105-111`）。

⚠️ 与 SOCKS5 的区别：SOCKS5 是 `1/4/3` 且**地址在前**（见 `docs/socks-protocol.md`）。VMess / VLESS / Mux.Cool 三者一致（`1/2/3`，端口在前）。

## 3. 外层：VMess AEAD Header

### 3.1 发送（`SealVMessAEADHeader`，`proxy/vmess/aead/encrypt.go:14-60`）

输出字节序列（`encrypt.go:55-58`）：

| 偏移 | 长度 | 字段 | 说明 |
|---|---|---|---|
| 0 | 16 | **AuthID** | `CreateAuthID(cmdKey, unixTime)` 的 AES-ECB 加密结果 |
| 16 | 18 | LengthAEAD | `AES-GCM.Seal(nonce, uint16BE(len(内层头)), aad=AuthID)` → 2 明文 + 16 tag |
| 34 | 8 | ConnectionNonce | 随机字节（`encrypt.go:17-20`） |
| 42 | `L+16` | PayloadAEAD | `AES-GCM.Seal(nonce, 内层头数据, aad=AuthID)` |

其中 `L = len(内层头数据)`（`encrypt.go:25-27`）。

**LengthAEAD 的 key/nonce**（`encrypt.go:31-39`）：
- key = `KDF16(cmdKey, "VMess Header AEAD Key_Length", AuthID, ConnectionNonce)`
- nonce = `KDF(cmdKey, "VMess Header AEAD Nonce_Length", AuthID, ConnectionNonce)[:12]`
- AAD = AuthID（16 字节）

**PayloadAEAD 的 key/nonce**（`encrypt.go:43-51`）：
- key = `KDF16(cmdKey, "VMess Header AEAD Key", AuthID, ConnectionNonce)`
- nonce = `KDF(cmdKey, "VMess Header AEAD Nonce", AuthID, ConnectionNonce)[:12]`
- AAD = AuthID

接收端 `OpenVMessAEADHeader`（`encrypt.go:63-135`）反向：先读 18 字节 LengthAEAD + 8 字节 nonce，解密得 `length`(uint16BE)，再读 `length+16` 字节 PayloadAEAD 解密（`encrypt.go:69-131`）。

### 3.2 AuthID 生成与校验（`CreateAuthID`，`proxy/vmess/aead/authid.go:26-40`）

明文 16 字节 = `BE(time int64, 8)` || `random(4)` || `BE(crc32.IEEE(前12字节), 4)`（`authid.go:27-33`），再用 AES-128-ECB（key = `KDF16(cmdKey, "AES Auth ID Encryption")`，`authid.go:42-49`）加密。

接收端 `AuthIDDecoder.Decode` 解密后解析出 `t, zero, rand`（`authid.go:58-66`），`Match` 依次校验（`authid.go:99-121`）：
1. `zero == crc32.IEEE(data[:12])`（`authid.go:102-104`）
2. `t >= 0`（`authid.go:106-108`）
3. `|t - now| <= 120` 秒（`authid.go:110-112`）
4. 重放过滤 `antireplay.MapFilter[16]`（`authid.go:70`、`114-116`）

### 3.3 KDF（`proxy/vmess/aead/kdf.go`）

```
KDF(key, path...) = HMAC-SHA256 嵌套链：初始 HMAC 以 "VMess AEAD KDF" 为 key，逐层以 path[i] 为 key 包裹，最后 Write(key)
KDF16 = KDF(...)[:16]
```
（`kdf.go:11-30`）。盐常量集中在 `proxy/vmess/aead/consts.go:3-14`。

## 4. 内层请求头（AEAD 解包后的明文，38 字节 + 变长）

服务端 `DecodeRequestHeader`（`proxy/vmess/encoding/server.go:127-249`）：
1. 先读 16 字节 AuthID（`server.go:158-160`，`ReadFullFrom(reader, protocol.IDBytesLen)`），交给 AEAD 校验与解包（`server.go:162-176`）。
2. 从解包流读 **38 字节** 定长块（`server.go:181`）：

| 偏移 | 长度 | 字段 | 证据 |
|---|---|---|---|
| 0 | 1 | Version | `server.go:187` |
| 1 | 16 | requestBodyIV | `server.go:190` |
| 17 | 16 | requestBodyKey | `server.go:191` |
| 33 | 1 | ResponseHeader（下称 V） | `server.go:200` |
| 34 | 1 | Option（bitmask） | `server.go:201` |
| 35 | 1 | 高 4 位=paddingLen；低 4 位=Security | `server.go:202-203` |
| 36 | 1 | reserved（保留，未使用） | `server.go:204` |
| 37 | 1 | Command | `server.go:205` |

3. Command 为 TCP/UDP 时，紧接着读「端口(2)+地址」（`server.go:207-216`）；Command=Mux 时地址固定为 `v1.mux.cool`、端口 0（`server.go:208-210`）。
4. 再读 `paddingLen` 字节填充（`server.go:218-223`）。
5. 最后读 4 字节校验：`FNV-1a-32(前面所有已写字节) == BE(最后 4 字节)`（`server.go:225-236`）。

客户端 `EncodeRequestHeader`（`client.go:63-102`）构造顺序完全对应：
`Version` → `requestBodyIV` → `requestBodyKey` → `responseHeader` → `Option` → `[paddingLen<<4 | Security, 0, Command]` → 地址端口（非 Mux）→ padding → FNV 校验（`client.go:69-96`），最后整体交给 `SealVMessAEADHeader`（`client.go:98`）。

要点：
- `paddingLen = dice.Roll(16)`，即随机 0–15（`client.go:75`）。
- `requestBodyKey`/`requestBodyIV` 各 16 字节随机，在 `NewClientSession` 中生成（`client.go:41-45`）。
- 响应密钥由请求密钥派生：`responseBodyKey = SHA256(requestBodyKey)[:16]`，`responseBodyIV = SHA256(requestBodyIV)[:16]`（`client.go:47-51`，服务端同样在 `server.go:315-318` 重算）。

## 5. 响应头（AEAD）

服务端 `EncodeResponseHeader`（`proxy/vmess/encoding/server.go:313-355`）：
1. 明文头 = `[V(1), Option(1)]` + `MarshalCommand(command)`；无命令时写 `{0x00, 0x00}`（`server.go:322-328`）。
2. 长度（2 字节 BE）用 **LengthAEAD** 加密：key = `KDF16(responseBodyKey, "AEAD Resp Header Len Key")`，iv = `KDF(responseBodyIV, "AEAD Resp Header Len IV")[:12]`，输出 18 字节（`server.go:330-345`）。
3. 明文头用 **PayloadAEAD** 加密：key = `KDF16(responseBodyKey, "AEAD Resp Header Key")`，iv = `KDF(responseBodyIV, "AEAD Resp Header IV")[:12]`（`server.go:347-355`）。
4. 线上顺序：`LengthAEAD(18) || PayloadAEAD(len+16)`。

客户端 `DecodeResponseHeader`（`client.go:165-239`）：
- 读 18 字节 → 解密得 length → 读 `length+16` → 解密得明文头。
- 校验 `明文头[0] == V`（即客户端自己发去的 `responseHeader`），否则报 `unexpected response header`（`client.go:227-229`）。
- 解析 `Option = 头[1]`；若 `头[2] != 0`，则 `cmdID = 头[2]`、`dataLen = 头[3]`，随后读 `dataLen` 字节命令体并 `UnmarshalCommand`（`client.go:231-243`）。

命令编解码 `MarshalCommand`/`UnmarshalCommand`（`proxy/vmess/encoding/commands.go:21-70`）：`[cmdID(1)][len(1)][auth(4, FNV-1a 大端)][body]`，`auth = Authenticate(body)`（`commands.go:21-50`、`14-18`）；当前 `CommandFactory` 的 switch 无任何具体实现（`commands.go:35-38`、`65-68`），即响应命令未实际启用。

## 6. 请求/响应体分帧（`common/crypto/auth.go`）

体加密统一由 `AuthenticationWriter`/`AuthenticationReader` + `ChunkSizeParser` + `Authenticator` 完成。

### 6.1 分帧格式

每个 chunk = `[sizeField(2 或 18 字节)][AEAD 密文]`：
- `sizeField` 明文值 = `密文长度`（即 `明文长度 + 16`，AES-GCM/ChaCha 的 tag 开销）**+ padding 长度**（`common/crypto/auth.go:249-263`）。
- 无 AuthenticatedLength 时 `sizeField` 就是 2 字节 BE（`PlainChunkSizeParser`，`common/crypto/chunk.go:28-41`）。
- 有 AuthenticatedLength 时 `sizeField` 被再包一层 AEAD：`AEADChunkSizeParser`，`Encode` 写 `size-overhead` 再 Seal，输出 `2+overhead` 字节（`chunk.go:43-60`），key = `KDF16(bodyKey, "auth_len")`（`client.go:127-136`、`server.go:266-274`）。

### 6.2 流类型 vs 包类型

- TransferTypeStream（TCP/Mux）：按 `payloadSize = buf.Size(8192) - overhead - sizeBytes - maxPadding` 切片，每片一个 chunk（`common/crypto/auth.go:278-310`；`common/buf/buffer.go:13` `Size = 8192`）。
- TransferTypePacket（UDP）：每个 buffer 一个 chunk（`common/crypto/auth.go:312-336`）。TransferType 由 Command 决定（`common/protocol/headers.go:20-28`）。

### 6.3 结束标记（EOF）

写空 buffer 时 seal 空明文，得到 `size == overhead + padding` 的 chunk；读端遇到 `size == overhead+padding` 即视为 `io.EOF`（`common/crypto/auth.go:149-151`、`common/crypto/auth.go:338-343`）。outbound/inbound 用 `WriteMultiBuffer(buf.MultiBuffer{})` 发送该结束帧（`proxy/vmess/outbound/outbound.go:180-181`、`proxy/vmess/inbound/inbound.go:217-218`），可被 `NoTerminationSignal` 实验项关闭（`account.go:44-66`）。

### 6.4 掩码与填充

- ChunkMasking（Option `0x04`）：`ShakeSizeParser` 以 `SHAKE128(nonce=requestBodyIV/responseBodyIV)` 生成 2 字节 XOR 掩码，`Encode/Decode` 用其异或长度（`encoding/auth.go:30-62`）。
- GlobalPadding（Option `0x08`）：`NextPaddingLen() = next()%64`，`MaxPaddingLen() = 64`（`common/crypto/auth.go:64-70`）；padding 以**明文**附加在密文之后（`common/crypto/auth.go:270-276`）。
- 是否启用：outbound 在 security∈{aes-128-gcm, chacha20-poly1305, auto} 等情况启用 ChunkMasking/GlobalPadding（`proxy/vmess/outbound/outbound.go:107-116`、`224-226`）。

### 6.5 Chunk nonce（AEAD nonce 生成）

`GenerateChunkNonce(iv, size)`：取 IV 的副本，把前 2 字节设为递增 uint16 计数器（`client.go:302-310`），其余字节为 IV，返回 `size`（12）字节。

### 6.6 ChaCha20-Poly1305 密钥派生

`GenerateChacha20Poly1305Key(b)`：`md5(b)` → 前 16 字节；`md5(前16字节)` → 后 16 字节，共 32 字节（`encoding/auth.go:21-28`）。

## 7. 重放保护

- 服务端 `SessionHistory`：以 `sessionID{user[16], key[16], nonce[16]}` 为键，3 分钟过期，每 30 秒清理（`server.go:26-52`、`56-90`）；重复即报 `duplicated session id`（`server.go:192-199`）。
- AuthID 层：120 秒时间窗 + `antireplay.MapFilter[16]`（`authid.go:70`、`113-118`）。
- 无效头触发 `BehaviorSeedLimitedDrainer` 混淆读取模式（`server.go:129-136`、`client.go:52-58`；`common/drain/drainer.go:14`）。

## 8. 配置字段（`infra/conf/vmess.go`）

- 用户/账号：`id`(UUID)、`security`、`experiments`（`infra/conf/vmess.go:19-21`）。
- `security` 映射：`aes-128-gcm`→AES128_GCM、`chacha20-poly1305`→CHACHA20_POLY1305、`auto`→AUTO、**其他值默认 AUTO**（`infra/conf/vmess.go:26-37`）。
- `experiments` 含 `AuthenticatedLength` / `NoTerminationSignal` 时启用对应实验（`proxy/vmess/account.go:44-66`）。
- 入站 `users`/`clients`/`default{level}`；出站 `address,port,level,email,id,security,experiments,vnext[]`（`infra/conf/vmess.go:47-185`）。

## 9. 与既有文档的关系

- 地址类型映射与 `docs/vless-protocol.md` **一致**（`1/2/3`，端口在前），与 `docs/socks-protocol.md` **不一致**（后者 `1/4/3`，地址在前）。
- `v1.mux.cool`、Mux 帧格式见 `docs/mux.md`。