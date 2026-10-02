# Shadowsocks 协议规格（依据 upstream v26.9.30）

> 证据引用 `/home/dev/tmp/xray-core-ref` 内 Go 源码 `路径:行号`。
> 主实现：`proxy/shadowsocks/{protocol,config,validator}.go`、`proxy/shadowsocks_2022/{shadowsocks_2022,stream,packet,kdf,cipher,replay,inbound,inbound_multi,inbound_relay,outbound,config}.go`；配置：`infra/conf/shadowsocks.go`。

## 0. 对任务假设的三处更正（重要）

1. **不存在 `none` / `plain` method**：全仓库 `proxy/shadowsocks/`、`infra/conf/shadowsocks.go` 中无 `none`/`plain`/`NONE`/`Plain` 任何匹配（grep 无命中）；`getCipher()` 与 `cipherFromString` 均只认 AEAD 四类（`proxy/shadowsocks/config.go:62-85`、`infra/conf/shadowsocks.go:15-27`）。
2. **不存在 legacy 流密码**（`aes-256-cfb`/`chacha20`/`rc4-md5` 等）：`cipherFromString` 的 switch 无这些分支，落到 default 返回 `CipherType_UNKNOWN`；用户侧校验要求 `CipherType_AES_128_GCM(5) <= t <= CipherType_XCHACHA20_POLY1305(8)`（`infra/conf/shadowsocks.go:75-78`），单用户侧要求 `!= UNKNOWN`（`infra/conf/shadowsocks.go:98-100`）。枚举定义 `proxy/shadowsocks/config.pb.go:29-33`。
3. **不存在独立的 `shadowsocks_2022` 入站/出站协议名，也不存在 `infra/conf/shadowsocks_2022.go`**：
   - 协议名仍是 `shadowsocks`；是否走 2022 由 `method` 是否命中 `shadowsocks_2022.GetCipherMethod` 决定（`infra/conf/shadowsocks.go:56`、`229`）。
   - 2022 的配置结构（`ServerConfig`/`MultiUserServerConfig`/`RelayServerConfig`/`ClientConfig`）在 `infra/conf/shadowsocks.go:111-187`、`229-241` 内构建。
   - 仅 Go 包名为 `proxy/shadowsocks_2022`，其 `inbound.go:20-24` / `outbound.go:20-24` 通过 `RegisterConfig((*ServerConfig)/(*ClientConfig))` 注册，但**入口协议名是 `shadowsocks`**。

---

# 一、Shadowsocks（AEAD，非 2022）

## 1. method 取值全集

`cipherFromString`（`infra/conf/shadowsocks.go:15-27`，大小写不敏感）：

| 配置 method | CipherType | KeyBytes | IVBytes | AEAD |
|---|---|---|---|---|
| `aes-128-gcm`、`aead_aes_128_gcm` | `AES_128_GCM`(5) | 16 | 16 | AES-GCM |
| `aes-256-gcm`、`aead_aes_256_gcm` | `AES_256_GCM`(6) | 32 | 32 | AES-GCM |
| `chacha20-poly1305`、`aead_chacha20_poly1305`、`chacha20-ietf-poly1305` | `CHACHA20_POLY1305`(7) | 32 | 32 | ChaCha20-Poly1305 |
| `xchacha20-poly1305`、`aead_xchacha20_poly1305`、`xchacha20-ietf-poly1305` | `XCHACHA20_POLY1305`(8) | 32 | 32 | XChaCha20-Poly1305 |
| 其他 | `UNKNOWN`(0) | — | — | 报错 |

KeyBytes/IVBytes 见 `proxy/shadowsocks/config.go:62-85`；枚举值见 `proxy/shadowsocks/config.pb.go:29-33`。**注意**：legacy AEAD 的 IV 长度等于密钥长度（16/32），不是 12。

## 2. 密钥派生（OpenSSL EVP_BytesToKey/MD5 链）

`passwordToCipherKey(password, keySize)`（`proxy/shadowsocks/config.go:187-202`）：
```
key = MD5(password)
while len(key) < keySize:
    key += MD5(prevMD5 || password)
```
用 `Account.AsAccount()` 时以 `Cipher.KeySize()` 调用（`config.go:97-104`）。

## 3. 会话子密钥派生（HKDF-SHA1）

`hkdfSHA1(secret=masterKey, salt=IV, outKey)`（`proxy/shadowsocks/config.go:204-207`）：
```
HKDF-SHA1(secret=masterKey, salt=IV, info="ss-subkey") → subkey(len=KeyBytes)
```
调用点：`createAuthenticator`（`config.go:136-145`）、`EncodePacket`/`DecodePacket`（`config.go:161-185`）、validator 嗅探（`validator.go:126-129`）。

## 4. nonce 生成

`crypto.GenerateAEADNonceWithSize(nonceSize)`（`common/crypto/auth.go:43-53`）：init 为全 `0xFF`，每次取用时**从最后一字节向前递增**（`GenerateIncreasingNonce`，`common/crypto/auth.go:30-40`）。即 nonce 不是从 0 计数，而是从 `FF..FF` 开始递增（回绕后为 `00..00`）。

## 5. TCP

### 5.1 请求（`WriteTCPRequest`，`protocol.go:134-163`）
```
[IV : IVSize 字节][AEAD 加密流: 地址+端口 + 载荷...]
```
- IV 随机生成并明文前置（`protocol.go:140-147`）。
- 地址+端口作为流的第一个 chunk 加密写入（`protocol.go:149-160`）。
- 加密流 = `NewAuthenticationWriter(auth, AEADChunkSizeParser{auth}, writer, TransferTypeStream, nil)`（`config.go:147-152`）。

### 5.2 请求读取（`ReadTCPSession`，`protocol.go:57-132`）
- 先读 50 字节（`protocol.go:69`）交给 `validator.Get(bs, RequestCommandTCP)` 试解。
- validator 用前 `IVSize` 字节作 IV 派生 subkey，并尝试 `aead.Open(..., bs[ivLen:ivLen+18], nil)` 解出 4+nonceSize 长度的试探块；成功即匹配用户（`validator.go:112-152`）。
- 命中后 `reader = &FullReader{reader, bs[ivLen:]}`（`protocol.go:86`），随后构建 `AuthenticationReader`（`protocol.go:88-94`）。
- **注意**：TCP 长度字段是整个 chunk 的**密文长度**（含 tag），由 `AEADChunkSizeParser` 加密后传输（见 §7）。
- 地址解析用 `addrParser.ReadAddressPort`（`protocol.go:113`）。

### 5.3 响应（`ReadTCPResponse`/`WriteTCPResponse`，`protocol.go:165-205`）
与请求对称：响应首部同样是 `[IV][加密流]`；阅读方向先读 IV 再建解密流。响应运行时用 `hmac-SHA256("SSBSKDF", masterKey)` 派生 drain 行为种子（`protocol.go:168-171`）。

## 6. UDP

### 6.1 编码（`EncodeUDPPacket`，`protocol.go:207-228`）
```
[IV : IVSize][密文: 地址+端口 + 载荷]
```
整段（地址+端口+载荷）作为一个 AEAD 块加密（`config.go:161-168`，`EncodePacket`）。

### 6.2 解码（`DecodeUDPPacket`，`protocol.go:230-280`）
- validator 以 `RequestCommandUDP` 试解：nonce 为 `data[8192-nonceSize:8192]`（`validator.go:141-144`），即假定接收缓冲长度为 8192。
- 解密后 `payload.SetByte(0, payload.Byte(0)&0x0F)` 掩掉地址类型高 4 位（`protocol.go:264`）——对应 `WithAddressTypeParser(func(b byte) byte { return b & 0x0F })`（`protocol.go:24-31`）。

## 7. chunk 分帧（`common/crypto`）

- `AEADChunkSizeParser`：`sizeField` 明文写 `size - overhead`（2 字节 BE），再整体 AEAD Seal（`common/crypto/chunk.go:43-60`）→ 线上 2+16 字节；读端先 Open 再 `+overhead`（`chunk.go:52-60`）。
- `AuthenticationWriter` 流模式按 `buf.Size(8192) - overhead - sizeBytes - maxPadding` 切片（`common/crypto/auth.go:278-310`）。
- EOF = `size == overhead + padding`（`common/crypto/auth.go:149-151`）。

## 8. 地址编码

`addrParser` 为 `1/4/3` 且 `WithAddressTypeParser(b & 0x0F)`（`protocol.go:24-31`），默认 portLast（**地址在前、端口在后**）。⇒ 与 SOCKS5/Trojan 同族，与 VLESS/VMess/Mux 不同（详见 `docs/socks-protocol.md` §2）。

## 9. 多用户与 IV 唯一性

- `Validator.Add`：非 AEAD 密码不允许单端口多用户（`validator.go:32-35`，当前无此类密码，故实际总是允许）。
- IV 唯一性由 `Validator.Get` 侧无显式检查；`ErrIVNotUnique`（`config.go:29`）在 `protocol.go:80-83` 被处理但在 `validator.Get` 当前实现中**未返回**——属保留错误（未确认是否会实际触发）。

## 10. 配置字段（`infra/conf/shadowsocks.go`）

- 服务端 `ShadowsocksServerConfig`（`infra/conf/shadowsocks.go:39-46`）：`method`、`password`、`level`、`email`、`users`/`clients[]{method,password,level,email,address,port}`、`network`。
- 客户端 `ShadowsocksClientConfig`（`infra/conf/shadowsocks.go:189-197`）：`address,port,level,email,method,password,servers[]{...}`；`servers` 必须恰好 1 个（`infra/conf/shadowsocks.go:216-218`）。
- 双侧均打印弃用告警，推荐迁移到 "VLESS Encryption"（`infra/conf/shadowsocks.go:49`、`201`）。

---

# 二、Shadowsocks-2022（SIP022）

## 1. 方法（`proxy/shadowsocks_2022/cipher.go:18-22`；方法名常量 `shadowsocks_2022.go:178-180`）

| method | KeySaltLength | IsChaCha |
|---|---|---|
| `2022-blake3-aes-128-gcm` | 16 | false |
| `2022-blake3-aes-256-gcm` | 32 | false |
| `2022-blake3-chacha20-poly1305` | 32 | true |

## 2. PSK 解析

- `ParseKey`：先 base64.StdEncoding 解码，失败则按原始字节；长度必须等于 `keyLength`，否则 `ErrBadKey`（`kdf.go:16-25`）。
- `ParsePSKList`：以 `:` 分隔为多 PSK（中继/多用户场景），逐个校验（`kdf.go:27-37`）。
- 客户端 `ParsePSKList(config.Key, method.KeySaltLength)`（`outbound.go:43`）；**chacha20 不支持多 key**（`outbound.go:47-49`、`packet.go:52-54`）。

## 3. 子密钥派生（BLAKE3）

`deriveSubKey(ctx, psk, salt, keyLength)`：`keyMaterial = psk || salt`，`blake3.DeriveKey(out, ctx, keyMaterial)`（`kdf.go:40-48`）。
- 会话子密钥 context = `"shadowsocks 2022 session subkey"`（`kdf.go:12`，`DeriveSessionSubKey` `kdf.go:50-52`）。
- 身份子密钥 context = `"shadowsocks 2022 identity subkey"`（`kdf.go:13`，`DeriveIdentitySubKey` `kdf.go:54-56`）。
- `DeriveUserPSKHash` = `BLAKE3-512(nextPSK)` 取前 16 字节（`kdf.go:58-63`）。

## 4. TCP 请求头（客户端 → 服务端）

`WriteTCPRequest`（`stream.go:321-395`），线上顺序：

```
[clientSalt : KeySaltLength]                     ← 明文
[EIH_i : 16 字节] × (len(pskList)-1)             ← 多用户身份头，AES-ECB 加密(identity subkey)
[FixedHeaderChunk : 11+16 字节]                  ← AEAD(session subkey, nonce=0)
[VarHeaderChunk : varHeaderLen+16 字节]          ← AEAD(session subkey, nonce=1)
```

- FixedHeader 明文（`RequestHeaderFixedChunkLength = 1+8+2 = 11`，`shadowsocks_2022.go:168`）：
  `[type=0 (HeaderTypeClient)][timestamp u64 BE][varHeaderLen u16 BE]`（`stream.go:358-361`）。
- VarHeader 明文 = `[地址+端口][paddingLen u16 BE][padding][payload]`（`stream.go:365-385`）。
- padding：若 `payloadLen < MaxPaddingLength(900)` 则 `paddingLen = rand[1,900]`，否则 0（`stream.go:333-335`；`MaxPaddingLength=900` `shadowsocks_2022.go:165`）。
- **paddingLen 为 0 且无 payload 时服务端必须拒绝**（SIP022 §3.1.4，`stream.go:311-313`）。
- EIH 逐跳：`block = AES(identitySubkey(psk_i))`，密文 = `AES-ECB-Encrypt(pskHash(psk_{i+1}))`（`stream.go:349-357`）。

### 4.1 服务端读取（`ReadClientRequestHeaderWithFixed`，`stream.go:244-315`）
- 用 session subkey 解 FixedHeader（nonce 0，`stream.go:245-250`），校验 `type == 0`（`stream.go:252-254`）。
- 时间戳校验：`|now - epoch| <= 30` 秒，否则 `ErrBadTimestamp`（`stream.go:256-260`）。
- `varHeaderLen != 0` 校验（`stream.go:262-265`）。
- 读 `varHeaderLen+16` 解 VarHeader（nonce 1，`stream.go:267-283`），解析地址+端口、paddingLen、padding，剩余为 EarlyData（`stream.go:285-309`）。

### 4.2 服务端入口（`InitServerStream`，`stream.go:608-624`）
先 `DeriveSessionSubKey(psk, clientSalt)` → `NewStreamReader` → 解析请求头 → **salt 重放过滤** `saltFilter.Check(salt)` 失败返回 `ErrSaltNotUnique`（`stream.go:620-623`）。
- salt 过滤器：`antireplay.NewMapFilter[[32]byte](60)`，即在 `Inbound` 构造时以 60 秒窗口建表（`inbound.go:66`）。
- 服务端一次读 `KeySaltLength + 11 + 16` 字节完成 salt+fixed header（`inbound.go:100-107`）。
- 失败时 `ResetTCPConn` 设 `SO_LINGER=0` 发 RST（`shadowsocks_2022.go:113-118`；调用 `inbound.go:105,116`）。

## 5. TCP 响应头（服务端 → 客户端）

`sendHeaderWithFirstPayload`（`stream.go:482-536`），线上顺序：
```
[serverSalt : KeySaltLength]
[FixedRespChunk : (1+8+KeySaltLength+2)+16]      ← AEAD(respSubkey, nonce=0)
[InitialPayloadChunk : payloadLen+16]            ← 仅当 payloadLen>0
```
- FixedResp 明文 = `[type=1 (HeaderTypeServer)][timestamp u64][echoedClientSalt][initialPayloadLen u16]`（`stream.go:502-508`）。
- 响应头懒发送：与首个 payload chunk 合并；无 payload 时在 `Close()` 时发 `initialPayloadLen=0` 的头（`stream.go:543-601`）。
- 客户端 `ReadTCPResponse`（`stream.go:398-461`）：一次读 salt+fixed chunk，校验 type==1、`|now-ts|<=30`、回显的 clientSalt 完全一致（`stream.go:428-442`）。

## 6. 流分帧（`StreamWriter`/`StreamReader`）

每个 chunk（`stream.go:82-99`）：
```
[seal(len u16 BE) : 2+16] [seal(payload) : len+16]
```
- 每 chunk **递增两次 nonce**（长度一次、载荷一次，`stream.go:94-97`、`stream.go:171-178`）。
- `MaxPacketSize = 65535`；`payloadLen==0 || > MaxPacketSize` 报 `ErrInvalidRequest`（`stream.go:167-169`）。
- nonce 递增方向：**从第 0 字节起递增**（`IncreaseNonce`，`stream.go:34-42`），与 legacy AEAD（从末字节）相反。
- `StreamNonceSize = 12`，`AEADTagSize = 16`（`shadowsocks_2022.go:170-172`）。

## 7. UDP（UDPPacketCodec）

### 7.1 ChaCha 模式（`2022-blake3-chacha20-poly1305`）
```
[nonce : 24] [XChaCha20-Poly1305(sessionID u64 || packetID u64 || body)]
```
- 解密：`nonce=data[:24]`，`plain[:8]=sessionID`，`plain[8:16]=packetID`（`packet.go:200-214`）。
- 编码服务端包：`plainBuf = sessionID||packetID||body`（`packet.go:329-350`）。

### 7.2 AES 模式
```
[AES-ECB(sessionID u64 || packetID u64) : 16]  [bodyAEAD : body+16]
```
- header 用 `method.NewBlock(psk)` 的 AES-ECB 加密（`packet.go:218-222`）。
- body 密钥 = `DeriveSessionSubKey(psk, rawHeader[:8], KeySaltLength)`；body nonce = `rawHeader[4:16]`（`packet.go:250-274`）。
- 服务端回复用独立的 `ServerSessionID`（随机 8 字节）与其派生 body 密钥（`packet.go:305-322`、`packet.go:365-395`）。

### 7.3 UDP body 明文（`parsePlainUDPPacket`，`packet.go:146-194`）
```
[type(1)] [timestamp u64 BE] [clientSessionID u64 （仅 server 包）] [paddingLen u16 BE] [padding] [地址+端口] [payload]
```
- 时间戳容差同为 30 秒（`packet.go:157-161`）。
- `PacketMinimalHeaderSize = 30`（`shadowsocks_2022.go:169`）。

### 7.4 重放与 session 管理
- 每个 (sessionID) 维护 `SlidingWindow` 检查 packetID（`replay.go:25-76`；调用 `packet.go:213-216, 226-228`）。
- `UDPSessionManager` 带超时清理（`replay.go:124-...`）；服务端 UDP 超时 500 秒（`inbound.go:52`）。
- 客户端会话：`current`/`old` 双 server session；**旧 session 最后收到包 <60s 时拒绝新 session**，旧 session >60s 视为过期（`packet.go:466-497`）。
- 客户端仅当目标端口为 53（DNS）且 payload < 900 时填充（`packet.go:506-509`）。

## 8. 入站/出站进程与套接字

| 角色 | 单用户 | 多用户 | 中继 |
|---|---|---|---|
| 服务端类型 | `ServerConfig` → `Inbound` | `MultiUserServerConfig` → `MultiUserInbound` | `RelayServerConfig` → `RelayInbound` |
| 证据 | `inbound.go:37` | `inbound_multi.go:49` | `inbound_relay.go:47` |

- 客户端：`ClientConfig` → `Outbound`（`outbound.go:37`）。
- 入站 `inbound.Name = "shadowsocks-2022"`、`CanSpliceCopy=3`（`inbound.go:84-86`）；出站同理（`outbound.go:78-79`）。
- 网络默认 TCP+UDP（`inbound.go:39-44`）。
- API 支持动态增删用户：`MultiUserInbound.AddUser/RemoveUser`（`inbound_multi.go:107,139`）。

## 9. 配置差异（`infra/conf/shadowsocks.go:111-187`）

| 场景 | 判定 | 生成类型 |
|---|---|---|
| 无 `users` | 直接 | `shadowsocks_2022.ServerConfig` |
| 有 `users` 且首个 user 无 `address` | 多用户 | `MultiUserServerConfig`（要求 method 含 `aes`，user.method 必须为空） |
| 有 `users` 且首个 user 有 `address` | 中继 | `RelayServerConfig`（user.method 必须为空，address 必填） |

- 多用户/中继**仅支持 `2022-blake3-aes-*-gcm`**（`infra/conf/shadowsocks.go:126-127`）。
- 客户端：method 命中 2022 则生成 `shadowsocks_2022.ClientConfig`，否则 legacy `shadowsocks.ClientConfig`（`infra/conf/shadowsocks.go:229-241`）。

## 10. 地址编码（2022）

`addrParser` 与 legacy 相同：`1/4/3` + `b & 0x0F`，portLast（`stream.go:23-31`）。UDP 侧 `ParseAddressPort` 是**独立实现**（`1/4/3`，地址在前端口在后，`packet.go:111-143`），不使用 addrParser。

## 11. 未确认项

- `ErrIVNotUnique` 是否可能由 `validator.Get` 实际产生（`proxy/shadowsocks/config.go:29`）——当前实现未见返回路径。
- EIH 多跳链在 3 个以上 PSK 时的完整语义未逐字节验证（仅确认逐层加密构造，`stream.go:349-357`）。