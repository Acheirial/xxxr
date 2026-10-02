# TLS 与 REALITY 规格（依据 upstream v26.9.30）

> 证据引用 `/home/dev/tmp/xray-core-ref`（XTLS/Xray-core v26.9.30，HEAD `b26a91de4f3294e26a0ad0a970b81a386a41f789`）内 Go 源码 `路径:行号`。
> 配置：`infra/conf/transport_security.go`；实现：`transport/internet/tls/*.go`、`transport/internet/reality/*.go`。

## 0. 前提与更正

1. **`allowInsecure` 已被移除**：设置即报错，指向 `pinnedPeerCertSha256`(pcs) 与 `verifyPeerCertByName`(vcn)（`infra/conf/transport_security.go:362-364`）。
2. **`security=xtls` 已被移除**（`infra/conf/transport_internet.go:120`）。
3. **`maxUselessRecords` 不在本仓库**：全仓库 grep 无命中。REALITY 的服务端握手与「无用记录」上限逻辑位于外部库 `github.com/xtls/reality`（`transport/internet/reality/reality.go:24`、`config.go:9`），本仓库只做配置映射与客户端侧握手。任务书提到的「四档」**未确认**。
4. 配置字段名以 `infra/conf/transport_security.go` 为准；proto 字段名（camelCase 差异）见 `transport/internet/tls/config.proto`、`transport/internet/reality/config.proto`。

---

# 一、`security=tls`

## 1.1 配置字段（`TLSConfig`，`infra/conf/transport_security.go:300-320`）

| JSON 字段 | 类型 | 默认 | 语义 |
|---|---|---|---|
| `allowInsecure` | bool | — | **已移除**，报错（`transport_security.go:362-364`） |
| `certificates` | `TLSCertConfig[]` | — | 见 §1.2 |
| `serverName` | string | 空 | SNI；特殊值 `fromMitm` 表示「不设置 SNI」（`transport/internet/tls/config.go:276-281`） |
| `alpn` | string[] | 空 → `["h2","http/1.1"]` | 见 §1.3 |
| `enableSessionResumption` | bool | false | 反向映射 `SessionTicketsDisabled = !EnableSessionResumption`（`tls/config.go:390-391`） |
| `disableSystemRoot` | bool | false | 不使用系统根证书 |
| `minVersion` / `maxVersion` | string | 空 | `1.0`/`1.1`/`1.2`/`1.3`（`tls/config.go:429-449`） |
| `cipherSuites` | string | 空 | `:` 分隔的套件名，按 `crypto/tls` 的 `CipherSuites()`+`InsecureCipherSuites()` 名表匹配（`tls/config.go:451-465`） |
| `fingerprint` | string | 空 → `chrome` | uTLS 指纹名，见 §2 |
| `rejectUnknownSni` | bool | false | 服务端拒绝未知 SNI（`tls/config.go:414`） |
| `curvePreferences` | string[] | 空 | 见 §1.4 |
| `masterKeyLog` | string | 空 | 写 SSLKEYLOGFILE；值 `none` 视为关闭（`tls/config.go:467-475`） |
| `pinnedPeerCertSha256` | string | 空 | 逗号分隔 hex（**允许含冒号**，会剔除），每项必须 32 字节（`transport_security.go:375-380`） |
| `verifyPeerCertByName` | string | 空 | 逗号分隔域名列表，用于按名验证（`transport_security.go:382-390`） |
| `echServerKeys` | string | 空 | base64.StdEncoding → `EncryptedClientHelloKeys`（`transport_security.go:392-398`） |
| `echConfigList` | string | 空 | base64 直填，或 DNS 形式 `域名+https://dns/dns-query`（`transport/internet/tls/ech.go:58-79`） |
| `echSockopt` | SocketConfig | — | ECH 查询专用 sockopt（`transport_security.go:401-407`） |

`GetTLSConfig`（`tls/config.go:367-482`）要点：
- `Rand` 被替换为 `RandCarrier`：既提供随机源，也挂载 `VerifyPeerCertificate` 回调以支持 pin/按名验证（`config.go:283-352, 383-401`）。
- 若 `verifyPeerCertByName` 或 `pinnedPeerCertSha256` 非空 → `InsecureSkipVerify = true`，改由自定义回调验证（`config.go:394-405`）。
- `ClientSessionCache` 为全局 LRU 128（`config.go:22`）。
- `GetCertificate` 由 `BuildCertificates()` 或自定义 CA 生成（`config.go:410-415`）。

## 1.2 `certificates[]`（`TLSCertConfig`，`infra/conf/transport_security.go:248-298`）

| 字段 | 说明 |
|---|---|
| `certificateFile` / `certificate` | 证书文件路径 或 PEM 字符串数组 |
| `keyFile` / `key` | 私钥 |
| `usage` | `encipherment`(默认) / `verify` / `issue`（`transport_security.go:275-283`） |
| `ocspStapling` | OCSP 装订间隔（秒） |
| `oneTimeLoading` | 仅当同时提供 file 路径时才尊重该值，否则强制 true（`transport_security.go:284-288`） |
| `buildChain` | 构建证书链 |

只有 `usage == ENCIPHERMENT` 的证书会进入 `BuildCertificates()`（`tls/config.go:49-55`）。

## 1.3 ALPN

- 未配置时默认 `["h2","http/1.1"]`（`tls/config.go:425-427`）。
- `alpn` 含 `fromMitm` 时**只允许一个元素**（`transport_security.go:336-345`，判定 `tls.IsFromMitm`，`tls/config.go:553-555`）。
- 传输会按需覆盖：httpupgrade 强制 `http/1.1`（`transport/internet/httpupgrade/dialer.go:66-68`）；grpc 服务端用 `h2`（`transport/internet/grpc/hub.go:110-113`）；XHTTP 用 `h3` 判定 H3（`transport/internet/splithttp/dialer.go:82-99`）。

## 1.4 `curvePreferences` 名称表（`tls/config.go:527-551`）

`curvep256`、`curvep384`、`curvep521`、`x25519`、`x25519mlkem768`、`secp256r1mlkem768`、`secp384r1mlkem1024`（大小写不敏感；未知名仅告警）。

## 1.5 证书 pin 与验证

- `pinnedPeerCertSha256`：对链上每个证书算 `SHA256(DER)` 比对；叶证书命中 → `foundLeaf`，CA 命中 → `foundCA`（`tls/config.go:561-...`；`transport/internet/tls/pin.go:10-28`）。
- `verifyPeerCertByName`：用该名字列表作为 `x509.VerifyOptions.DNSName` 逐个尝试（`tls/config.go:313-322`）。
- CLI `xray tls hash` 即输出 `SHA256(DER)` 的 hex（`transport/internet/tls/pin.go:21-28`）。

## 1.6 ECH 默认值

- 服务端：`echServerKeys` → `ConvertToGoECHKeys` → `EncryptedClientHelloKeys`（`tls/ech.go:41-49, 317-...`）。
- 客户端：`echConfigList` 直填 base64 或走 DNS HTTPS 记录查询；**查询失败时用固定的无效配置 `{1,1,4,5,1,4}` 使连接失败**（`tls/ech.go:51-57`）。
- DNS 查询默认端口 53（`tls/ech.go:261`）。
- ECH 配置有全局缓存（`tls/ech.go:100-113`）。

---

# 二、uTLS 指纹名全集

`GetFingerprint`（`transport/internet/tls/tls.go:204-218`）查找顺序：空 → `chrome`(HelloChrome_Auto)；再查 `PresetFingerprints` → `ModernFingerprints` → `OtherFingerprints`；都未命中返回 nil（调用方回退到标准 `crypto/tls`）。

### PresetFingerprints（`tls.go:220-234`）
`chrome`、`firefox`、`safari`、`ios`、`android`、`edge`、`360`、`qq`、`random`、`randomized`、`randomizednoalpn`、`unsafe`。
- `random` 在 init 时从 `ModernFingerprints` 随机选一个（`tls.go:182-190`）。
- `randomized`/`randomizednoalpn` 使用 `utls.HelloRandomizedALPN/NoALPN` + 随机 PRNG seed + 自定义权重（TLS1.3 强制、首 key share 不用 P-256）（`tls.go:192-202`）。
- `unsafe` 在映射中为 nil → 运行时回退到标准 TLS（`tls.go:231`；配置侧对 `unsafe` 跳过指纹校验 `transport_security.go:355-356`）。

### ModernFingerprints（`tls.go:236-249`）
`hellofirefox_120`、`hellofirefox_148`、`hellochrome_120`、`hellochrome_131`、`hellochrome_133`、`helloios_13`、`helloios_14`、`helloedge_106`、`hellosafari_26_3`、`hello360_11_0`、`helloqq_11_1`。

### OtherFingerprints（`tls.go:251-...`）
`hellogolang`、`hellorandomized`、`hellorandomizedalpn`、`hellorandomizednoalpn`、`hellofirefox_auto`、`hellofirefox_55/56/63/65/99/102/105`、`hellochrome_auto`、`hellochrome_58/62/70/72/83/87/96/100/102`、`hellochrome_106_shuffle`、`helloios_auto`、`helloios_11_1/12_1`、`helloandroid_11_okhttp`、`helloedge_85`、`helloedge_auto`、`hellosafari_16_0`、`hellosafari_auto`、`hello360_auto`、`hello360_7_5`、`helloqq_auto`，以及 Chrome beta：`hellochrome_100_psk`、`hellochrome_112_psk_shuf`、`hellochrome_114_padding_psk_shuf`、`hellochrome_115_pq`、`hellochrome_115_pq_psk`、`hellochrome_120_pq`。

---

# 三、`security=reality`

## 3.1 配置字段（`REALITYConfig`，`infra/conf/transport_security.go:27-52`）

| 字段 | 角色 | 语义 / 校验 |
|---|---|---|
| `show` | 通用 | 打印握手诊断（`transport/internet/reality/reality.go:206-209`） |
| `dest` / `target` | 服务端 | 回退目标；`target` 会覆盖 `dest`（`transport_security.go:59-61`）。数字/字符串；`@`或`/`开头 → type=unix；`host:port` → tcp；纯数字 → `localhost:<n>`（`transport_security.go:62-87`） |
| `type` | 服务端 | `tcp` / `unix`（未填由 dest 推断，推断失败报错 `please fill in a valid value for "target"`，`transport_security.go:88-90`） |
| `xver` | 服务端 | PROXY protocol 版本，仅 0/1/2（`transport_security.go:91-93`） |
| `serverNames` | 服务端 | 必填非空（`transport_security.go:94-96`）；对 `.ru/.ir/.cn`/`apple`/`icloud`/`microsoft` 会告警（`transport_security.go:163-169`） |
| `privateKey` | 服务端 | 必填，base64.RawURLEncoding，解码后必须 32 字节（`transport_security.go:97-101`） |
| `minClientVer` / `maxClientVer` | 服务端 | `a.b.c`，各段 < 256（`transport_security.go:101-136`） |
| `maxTimeDiff` | 服务端 | 毫秒；映射为 `time.Duration(MaxTimeDiff)*time.Millisecond`（`transport/internet/reality/config.go:29`） |
| `shortIds` | 服务端 | 必填非空；每项 hex ≤16 字符，解码到 8 字节缓冲（`transport_security.go:135-147`） |
| `mldsa65Seed` | 服务端 | base64.RawURLEncoding，32 字节；不得等于 `privateKey`（`transport_security.go:154-161`） |
| `limitFallbackUpload` / `limitFallbackDownload` | 服务端 | `{afterBytes, bytesPerSec, burstBytesPerSec}`（`transport_security.go:171-181`） |
| `fingerprint` | 客户端 | 同 §2；**`unsafe`/`hellogolang` 被拒绝**（`transport_security.go:180-186`） |
| `serverName` | 客户端 | SNI；服务端配置不得用 `serverNames`（客户端侧报错，`transport_security.go:187-189`） |
| `password` | 客户端 | 与 `publicKey` 等价（password 优先覆盖 publicKey）（`transport_security.go:190-192`）；base64.RawURLEncoding，32 字节（`transport_security.go:193-198`） |
| `publicKey` | 客户端 | 同上 |
| `shortId` | 客户端 | hex ≤16 字符 → 8 字节（`transport_security.go:199-208`）；客户端不得用 `shortIds`（`transport_security.go:199-201`） |
| `mldsa65Verify` | 客户端 | base64.RawURLEncoding，**必须 1952 字节**（`transport_security.go:209-213`） |
| `spiderX` | 客户端 | 必须以 `/` 开头，默认 `/`（`transport_security.go:214-218`）；查询参数 `p`/`c`/`t`/`i`/`r` 解析为 `SpiderY[0..9]`（见 §3.4） |
| `masterKeyLog` | 通用 | keylog 文件（`transport/internet/reality/config.go:61-72`） |

映射到 `reality.Config`（`transport/internet/reality/config.go:16-59`）：`NextProtos` 强制 nil、`SessionTicketsDisabled = true`、`ServerNames`/`ShortIds` 转成 map。

## 3.2 客户端握手流程（`UClient`，`transport/internet/reality/reality.go:142-302`）

1. uTLS 配置：`InsecureSkipVerify: true`、`SessionTicketsDisabled: true`、`VerifyPeerCertificate = uConn.VerifyPeerCertificate`；`ServerName` 为空时用 `dest.Address`（`reality.go:144-158`）。
2. 指纹：`tls.GetFingerprint(config.Fingerprint)`，为 nil 直接报错（**REALITY 必须用 uTLS**，`reality.go:159-162`）。
3. **SessionId（32 字节）承载**（`reality.go:164-175`）：
   - `[0..3)` = `core.Version_x/y/z` + 保留 0
   - `[4..8)` = 大端 unix 时间戳
   - `[8..16)` = `shortId`（8 字节）
   - 先整体 `copy(hello.Raw[39:], hello.SessionId)` 固定位置写入
4. **X25519 共享密钥**：`ecdhe.ECDH(serverPublicKey)`；ECDHE 取 `HandshakeState.State13.KeyShareKeys.Ecdhe`，为空则取 `MlkemEcdhe`（支持 X25519MLKEM768）（`reality.go:177-191`）。
5. **AuthKey 派生**：`HKDF-SHA256(authKey, salt = hello.Random[:20], info = "REALITY")` → 32 字节（`reality.go:192-194`）。
6. **SessionId 前 16 字节加密**：`AES-GCM(AuthKey).Seal(hello.SessionId[:0], nonce = hello.Random[20:], plaintext = hello.SessionId[:16], aad = hello.Raw)`，再写回 `hello.Raw[39:]`（`reality.go:195-200`）。
7. 握手；若 `!uConn.Verified` → 触发 spiderX 爬虫（模仿浏览器访问）并返回 `REALITY: processed invalid connection`（`reality.go:206-300`）。
8. **证书验证**（`VerifyPeerCertificate`，`reality.go:101-139`）：
   - 取叶证书的 `ed25519.PublicKey`，用 `HMAC-SHA512(AuthKey)` 计算并与证书 `Signature` 比对；相等则视为 REALITY 认证成功；
   - 若配置了 `mldsa65Verify`，再对 `HMAC(AuthKey)` 覆盖 `pub || hello.Raw || serverHello.Raw` 的结果做 ML-DSA-65 验证（签名在 `certs[0].Extensions[0].Value`）；
   - 否则回退到标准 `x509.Verify`（说明收到真实证书 → 记日志告警）。

## 3.3 服务端握手

服务端 `Server()` 只是薄封装：`reality.Server(ctx, conn, config)`（`transport/internet/reality/reality.go:65-68`），**握手主体在外部库 `github.com/xtls/reality`**（`reality.go:24`、`config.go:9`）。因此「target 探测」「无用记录上限」等细节**不在本仓库**，标注**未确认**。

## 3.4 spiderX / SpiderY

`spiderX` 的查询串被解析为 10 个 int64 槽（`infra/conf/transport_security.go:220-244`）：
- `p` → `SpiderY[0],SpiderY[1]`：padding cookie 长度区间
- `c` → `SpiderY[2],SpiderY[3]`：并发数
- `t` → `SpiderY[4],SpiderY[5]`：每路径请求次数
- `i` → `SpiderY[6],SpiderY[7]`：间隔毫秒
- `r` → `SpiderY[8],SpiderY[9]`：返回前等待毫秒

运行期用途见 `reality.go:255-298`（Referer 链、`padding` cookie、href 正则 `href="([/h].*?)"` 收集路径、路径去重 map）。

## 3.5 与其它传输的联动

- REALITY 下 `decideHTTPVersion` 返回 `2`（XHTTP 走 H2）（`transport/internet/splithttp/dialer.go:82-85`）。
- REALITY 下 XHTTP `auto` 模式选 `stream-one`（或配了 downloadSettings 时 `stream-up`）（`splithttp/dialer.go:334-340`）。
- grpc 客户端在 reality 存在时用 `reality.UClient` 作为底层连接（`transport/internet/grpc/dial.go:129-137`）。

---

# 四、未确认项

1. **REALITY 服务端握手全部细节**（含 `maxUselessRecords` 及其档位、target 探测、证书回退时序）：位于外部依赖 `github.com/xtls/reality`，**不在本仓库**，未确认。
2. `config.ShortId` 不足 8 字节时的填充语义：`hex.Decode` 到 8 字节缓冲，高位/低位填充顺序未逐字节验证（`infra/conf/transport_security.go:211-213`、`transport/internet/reality/reality.go:173`）。
3. `echConfigList` 走 DNS 时的 HTTPS 记录解析与缓存过期细节未逐行核对（`transport/internet/tls/ech.go:141-316`）。
4. 上游无 TLS/REALITY 的字节级固定测试向量，本文件为语义规格。