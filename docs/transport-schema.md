# streamSettings / 传输层 schema（依据 upstream v26.9.30）

> 证据引用 `/home/dev/tmp/xray-core-ref` 内 Go 源码 `路径:行号`。

## 1. `StreamConfig` 全字段

定义：`infra/conf/transport_internet.go:48-68`；构建：`transport_internet.go:70-203`。
适用于入站 `streamSettings` 与出站 `streamSettings`。

| JSON 字段 | 类型 | 说明 |
|---|---|---|
| `address` | Address | 覆写连接地址（outbound） |
| `port` | uint16 | 覆写端口 |
| `network` | string | 传输协议，见 §2。默认 `"tcp"`（`transport_internet.go:73-76`） |
| `method` | string | **`network` 的历史别名**；两者都设时 `method` 覆盖 `network`（`transport_internet.go:80-82`） |
| `security` | string | 见 §3，默认 `""`(=none) |
| `finalmask` | FinalMask | TCP/UDP 混淆，见 §4 |
| `tlsSettings` | TLSConfig | `security=tls` 时使用 |
| `realitySettings` | REALITYConfig | `security=reality` 时使用 |
| `rawSettings` | TCPConfig | RAW(即 tcp) 传输设置；会覆盖 `tcpSettings`（`transport_internet.go:125-127`） |
| `tcpSettings` | TCPConfig | tcp 传输设置 |
| `xhttpSettings` | SplitHTTPConfig | XHTTP 传输；会覆盖 `splithttpSettings`（`transport_internet.go:138-140`） |
| `splithttpSettings` | SplitHTTPConfig | splithttp 别名 |
| `kcpSettings` | KCPConfig | mKCP |
| `grpcSettings` | GRPCConfig | gRPC（已弃用告警，`transport_internet.go:24-25`） |
| `wsSettings` | WebSocketConfig | WebSocket（已弃用告警，`transport_internet.go:27-28`） |
| `httpupgradeSettings` | HttpUpgradeConfig | HTTPUpgrade（已弃用告警，`transport_internet.go:30-31`） |
| `hysteriaSettings` | HysteriaConfig | hysteria 传输 |
| `masqueSettings` | MasqueConfig | masque 传输 |
| `xdriveSettings` | XDriveConfig | xdrive 传输 |
| `sockopt` | SocketConfig | 底层套接字设置，见 §6 |

## 2. `network` 取值（`TransportProtocol.Build`，`transport_internet.go:13-46`）

| 配置值（大小写不敏感） | 归一化后 | 备注 |
|---|---|---|
| `raw`, `tcp` | `tcp` | RAW |
| `xhttp`, `splithttp` | `splithttp` | XHTTP |
| `kcp`, `mkcp` | `mkcp` | mKCP |
| `grpc` | `grpc` | 已弃用，推荐 XHTTP stream-up H2 |
| `ws`, `websocket` | `websocket` | 已弃用，推荐 XHTTP |
| `httpupgrade` | `httpupgrade` | 已弃用，推荐 XHTTP |
| `hysteria` | `hysteria` | |
| `masque` | `masque` | 仅 masque 入/出站可用 |
| `xdrive` | `xdrive` | |
| `h2`, `h3`, `http` | — | **已移除**，报错指向 XHTTP（`transport_internet.go:33-34`） |
| `quic` | — | **已移除**，报错指向 XHTTP（`transport_internet.go:35-36`） |
| 其他 | — | 报 `unknown transport protocol` |

任务书列出的 `tcp/ws/http/grpc/xhttp/kcp/quic/httpupgrade/hysteria` 中，**`http` 与 `quic` 在当前版本已被移除**；另有 `masque`、`xdrive` 两个新传输。

## 3. `security` 取值（`transport_internet.go:91-122`）

| 值 | 行为 |
|---|---|
| `""`, `none` | 不加密 |
| `tls` | 使用 `tlsSettings`（缺省 `&TLSConfig{}`），设置 `SecurityType`=TLS 类型 |
| `reality` | 使用 `realitySettings`（必填，否则报错）；**仅支持 network 为 `tcp`/`splithttp`/`grpc`**（`transport_internet.go:106-108`） |
| `xtls` | **已移除**，报错指向 `xtls-rprx-vision with TLS or REALITY`（`transport_internet.go:120`） |
| 其他 | 报 `Unknown security` |

REALITY 监听非 443 端口会告警（`xray.go:183`）。

## 4. `finalmask`（混淆）

定义：`transport_finalmask.go:1162-1166`。

| 字段 | 类型 | 说明 |
|---|---|---|
| `tcp` | `[]Mask` | 每项 `{type, settings}`（`transport_finalmask.go:1116-1119`） |
| `udp` | `[]Mask` | 同上 |
| `quicParams` | QuicParamsConfig | 见下 |

`QuicParamsConfig`（`transport_finalmask.go:1142-1160`）：`congestion`(`reno|bbr|brutal|force-brutal`，默认空)、`debug`、`bbrProfile`(`conservative|standard|aggressive`，默认 standard)、`brutalUp`/`brutalDown`(Bandwidth，最小 65536 B/s)、`brutalDisableLossCompensation`、`initStreamReceiveWindow`/`maxStreamReceiveWindow`/`initConnectionReceiveWindow`/`maxConnectionReceiveWindow`(≥16384)、`maxIdleTimeout`(4-120)、`keepAlivePeriod`(2-60)、`disablePathMtuDiscovery`、`disableChromeParrot`、`disableGSO`、`maxIncomingStreams`(≥8)、`disableStatelessReset`（校验见 `transport_internet.go:240-345`）。

`Bandwidth` 字符串支持单位 `b/bps/k/kb/m/mb/g/gb/t/tb`（`transport_method.go:699-738`）。

## 5. 各传输设置字段

### 5.1 tcp / raw — `TCPConfig`（`transport_method.go:236-239`）
`header`(json.RawMessage，TCP 伪装头)、`acceptProxyProtocol`(bool)。头 loader 见 `transport_method.go:242-260`。

### 5.2 websocket — `WebSocketConfig`（`transport_method.go:613-619`）
`host`(string)、`path`(string)、`headers`(map；含 `host` 会告警并迁移到独立 `host`)、`acceptProxyProtocol`(bool)、`heartbeatPeriod`(uint32)。`path` 的查询串 `ed` 被提取为掩码强度并移除（`transport_method.go:622-653`）。

### 5.3 httpupgrade — `HttpUpgradeConfig`（`transport_method.go:655-660`）
`host`、`path`、`headers`(map；**不允许含 `host`**)、`acceptProxyProtocol`。`ed` 处理同上。

### 5.4 splithttp / xhttp — `SplitHTTPConfig`（`transport_method.go:261-290`）
`host`、`path`、`mode`(默认 `auto`；可选 `auto|packet-up|stream-up|stream-one`，`transport_method.go:322-327`)、`headers`(**不允许含 `host`**)、`xPaddingBytes`(Int32Range，不可为 0)、`xPaddingObfsMode`、`xPaddingKey`(默认 `x_padding`)、`xPaddingHeader`(默认 `X-Padding`)、`xPaddingPlacement`(默认 `queryInHeader`；可选 `cookie|header|query|queryInHeader`)、`xPaddingMethod`(默认 `repeat-x`；可选 `repeat-x|tokenish`)、`uplinkHTTPMethod`、`sessionIDPlacement`、`sessionIDKey`、`sessionIDTable`、`sessionIDLength`、`seqPlacement`、`seqKey`、`uplinkDataPlacement`、`uplinkDataKey`、`uplinkChunkSize`、`noGRPCHeader`、`noSSEHeader`、`scMaxEachPostBytes`、`scMinPostsIntervalMs`、`scMaxBufferedPosts`、`scStreamUpServerSecs`、`serverMaxHeaderBytes`、`xmux`(见下)、`downloadSettings`(StreamConfig)、`extra`(RawMessage，会与顶层合并)。
`XmuxConfig`（`transport_method.go:294-301`）：`maxConcurrency`、`maxConnections`、`cMaxReuseTimes`、`hMaxRequestTimes`、`hMaxReusableSecs`（均 Int32Range）、`hKeepAlivePeriod`(int64)。

### 5.5 kcp — `KCPConfig`（`transport_method.go:527-536`）
`mtu`(*uint32，≥21)、`tti`(*uint32，10-1000)、`uplinkCapacity`、`downlinkCapacity`、`cwndMultiplier`(≥1)、`maxSendingWindow`(≥mtu)、`header`、`seed`(*string)。校验见 `transport_method.go:540-577`。

### 5.6 grpc — `GRPCConfig`（`transport_method.go:578-587`）
`authority`、`serviceName`、`multiMode`(bool)、`idle_timeout`、`health_check_timeout`、`permit_without_stream`、`initial_windows_size`、`user_agent`。≤0 归零（`transport_method.go:589-609`）。

### 5.7 hysteria 传输 — `HysteriaConfig`（`transport_method.go:757-762`）
`version`(**必须 = 2**)、`auth`、`udpIdleTimeout`(默认 60，范围 2-600)、`masquerade`(`Masquerade`，`transport_method.go:742-755`：`type`、`dir`、`url`、`rewriteHost`、`xForwarded`、`insecure`、`content`、`headers`、`statusCode`)。对应 proto `transport/internet/hysteria/config.proto:8-25`。

### 5.8 masque — `MasqueConfig`（`transport_method.go:793-799`）
`host`、`path`(默认 `/.well-known/masque/ip/*/*/`，见 `transport/internet/masque/config.go:10`)、`user`、`pass`、`headers`(不得含 `host`/`capsule-protocol`)。`path` 支持变量 `{target}`/`{ipproto}`（`transport_method.go:801-858`）。

### 5.9 xdrive — `XDriveConfig`（`transport_method.go:860-874`）
`remoteFolder`、`service`(`local|"Google Drive"|template`)、`secrets`(Google Drive 需 3 项)、`segmentBytes`、`flushIntervalMs`、`pollIntervalMs`、`maxPollIntervalMs`、`sessionTtlSeconds`、`concurrency`、`eagerWindowMs`、`holeTimeoutMs`、`template`(RawMessage)。

## 6. `sockopt` — `SocketConfig`

定义：`transport_sockopt.go:45-67`。

| 字段 | 类型 | 说明 |
|---|---|---|
| `mark` | int32 | Linux SO_MARK |
| `tcpFastOpen` | interface{} | true / false / 数字 |
| `tproxy` | string | `off`/`redirect`/`tproxy` |
| `acceptProxyProtocol` | bool | |
| `domainStrategy` | string | |
| `dialerProxy` | string | 出站链式代理 tag |
| `tcpKeepAliveInterval` / `tcpKeepAliveIdle` | int32 | |
| `tcpCongestion` | string | |
| `tcpWindowClamp` / `tcpMaxSeg` | int32 | |
| `penetrate` | bool | |
| `tcpUserTimeout` | int32 | |
| `v6only` | bool | |
| `interface` | string | |
| `tcpMptcp` | bool | |
| `customSockopt` | `[]{system,network,level,opt,value,type}` | `transport_sockopt.go:12-19` |
| `addressPortStrategy` | string | |
| `happyEyeballs` | `{prioritizeIPv6,tryDelayMs,interleave,maxConcurrentTry}` | 默认 `interleave=1, maxConcurrentTry=4`（`transport_sockopt.go:21-43`） |
| `trustedXForwardedFor` | string[] | |

## 7. TLS — `TLSConfig`（`transport_security.go:300-320`）

| 字段 | 类型 | 默认 / 说明 |
|---|---|---|
| `allowInsecure` | bool | **已移除**，报错（`transport_security.go:362`） |
| `certificates` | TLSCertConfig[] | 见下 |
| `serverName` | string | SNI |
| `alpn` | string[] | 传 `fromMitm` 时只允许 1 个元素（`transport_security.go:342`） |
| `enableSessionResumption` | bool | |
| `disableSystemRoot` | bool | |
| `minVersion` / `maxVersion` | string | `1.0/1.1/1.2/1.3`（映射见 `transport/internet/tls/config.go:429-448`） |
| `cipherSuites` | string | |
| `fingerprint` | string | 默认在 `transport/internet/tls`；`unsafe` 表示不伪造，否则必须能被 `tls.GetFingerprint` 识别（`transport_security.go:355-356`） |
| `rejectUnknownSni` | bool | |
| `curvePreferences` | string[] | |
| `masterKeyLog` | string | |
| `pinnedPeerCertSha256` | string | 逗号分隔 hex（支持冒号），每项 32 字节（`transport_security.go:375-380`） |
| `verifyPeerCertByName` | string | 逗号分隔（`transport_security.go:382-390`） |
| `echServerKeys` | string | base64 |
| `echConfigList` | string | |
| `echSockopt` | SocketConfig | ECH 专用 sockopt |

`TLSCertConfig`（`transport_security.go:248-256`）：`certificateFile`、`certificate`(string[])、`keyFile`、`key`(string[])、`usage`(`encipherment`(默认)/`verify`/`issue`)、`ocspStapling`、`oneTimeLoading`、`buildChain`。

## 8. REALITY — `REALITYConfig`（`transport_security.go:27-52`）

服务端：`masterKeyLog`、`show`、`target`/`dest`(RawMessage；数字/字符串；`@`/`/` 开头=unix，`host:port`=tcp)、`type`、`xver`(0/1/2)、`serverNames[]`(必填非空)、`privateKey`(必填，base64 raw-url，32 字节)、`minClientVer`/`maxClientVer`(a.b.c，各段 <256)、`maxTimeDiff`、`shortIds[]`、`mldsa65Seed`、`limitFallbackUpload`/`limitFallbackDownload`(`{afterBytes,bytesPerSec,burstBytesPerSec}`，`transport_security.go:21-25`)。

客户端：`fingerprint`、`serverName`、`password`、`publicKey`、`shortId`、`mldsa65Verify`、`spiderX`。校验见 `transport_security.go:54-247`。