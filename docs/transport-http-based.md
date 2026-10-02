# HTTP 系传输规格：httpupgrade / splithttp (XHTTP) / grpc

> 证据引用 `/home/dev/tmp/xray-core-ref`（XTLS/Xray-core v26.9.30，HEAD `b26a91de4f3294e26a0ad0a970b81a386a41f789`）内 Go 源码 `路径:行号`。

## 0. 前提与更正

1. **三种传输在本版本均被标记为「非移除型弃用」**，建议迁移到 XHTTP：
   - `grpc` → `XHTTP stream-up H2`（`infra/conf/transport_internet.go:24-25`）
   - `ws`/`websocket` → `XHTTP H2 & H3`（`transport_internet.go:27-28`）
   - `httpupgrade` → `XHTTP H2 & H3`（`transport_internet.go:30-31`）
2. `network` 归一化名：`httpupgrade`（`transport/internet/httpupgrade/httpupgrade.go:3`）、`splithttp`（`transport/internet/splithttp/splithttp.go:3`）、`grpc`（`transport/internet/grpc/grpc.go:3`）。配置侧 `xhttp`/`splithttp` 都归一为 `splithttp`，`raw`/`tcp` 归一为 `tcp`（`infra/conf/transport_internet.go:20-22`）。
3. **`h2`/`h3`/`http`/`quic` 传输已移除**（`transport_internet.go:33-36`）。XHTTP 的 H2/H3 由 `security=tls` 的 ALPN 决定（见 §2.7）。
4. **gRPC 的 5 字节前缀不是 Xray 实现的**：它是 gRPC 协议自身的「1 字节压缩标志 + 4 字节大端长度」消息分帧，由 `google.golang.org/grpc` 处理。Xray 只定义 protobuf 消息 `Hunk`/`MultiHunk`（`transport/internet/grpc/encoding/stream.proto:7-13`）。

---

# 一、httpupgrade（HTTPUpgrade）

## 1.1 配置字段

`HttpUpgradeConfig`（`infra/conf/transport_method.go:655-660`）→ proto `Config`（`transport/internet/httpupgrade/config.proto:9-15`）：

| JSON 字段 | proto | 说明 |
|---|---|---|
| `host` | `host = 1` | HTTP Host 头与 SNI 回退 |
| `path` | `path = 2` | 请求路径；缺省 `/`，非 `/` 开头会自动补（`transport/internet/httpupgrade/config.go:8-17`） |
| `headers` | `header = 3`（map） | 额外请求头；**不得含 `host`**（构建时报错，`infra/conf/transport_method.go:683-690`） |
| `acceptProxyProtocol` | `accept_proxy_protocol = 4` | 服务端接受 PROXY protocol |
| `ed`（不直接暴露） | `ed = 5` | 从 `path` 的查询串 `ed` 提取并移除（`transport_method.go:667-678`）；仅客户端用于决定是否立即读响应（见 §1.4） |

## 1.2 客户端握手（`dialhttpUpgrade`，`transport/internet/httpupgrade/dialer.go:48-131`）

1. 先建立底层连接：`FinalMask.DialTCP` 或 `internet.DialSystem`（`dialer.go:51-58`）。
2. 若配了 TLS：`GetTLSConfig(WithDestination(dest), WithNextProto("http/1.1"))` —— **强制 ALPN `http/1.1`**（`dialer.go:66-68`）。有 uTLS 指纹则 `tls.UClient(...).WebsocketHandshakeContext(ctx)`，否则 `tls.Client`（`dialer.go:69-76`）。
3. URL 组装：`Scheme` = `https`(有 TLS) / `http`；`Host` 优先级 **config.host → tlsConfig.ServerName → dest.Address**（`dialer.go:82-88`）；`Path` = `GetNormalizedPath()`（`dialer.go:89`）。
4. 请求为 **`GET`**，头：先写入 `headers`（`AddHeader` 直接追加，避免 MIME 规范化，`dialer.go:135-138`），再 `TryDefaultHeadersWith(header, "ws")` 补浏览器头（`dialer.go:98`），然后：
   - `Connection: Upgrade`（`dialer.go:99`）
   - `Upgrade: websocket`（`dialer.go:100`）
   - 若未自带 `Sec-WebSocket-Key`：随机 16 字节 base64.StdEncoding（`dialer.go:102-107`）
   - 若未自带 `Sec-WebSocket-Version`：`13`（`dialer.go:108-110`）
5. `req.Write(conn)` 后返回 `ConnRF{Conn, Req, First:true}`（`dialer.go:112-118`）。
6. **`ed == 0` 时立即阻塞读响应**（`connRF.Read([]byte{})`），否则延迟到首次读（`dialer.go:123-128`）。

## 1.3 响应校验（`ConnRF.Read`，`dialer.go:27-46`）

首次读时用 `http.ReadResponse`（buffer 大小 = 调用方 `len(b)`），要求：
- `resp.Status == "101 Switching Protocols"`
- `Upgrade`（小写）`== "websocket"`
- `Connection`（小写）`== "upgrade"`

否则报 `unrecognized reply`。通过后**只把 bufio 里已缓冲的字节**排空返回（`dialer.go:43`），后续为原始流。

## 1.4 服务端（`server.upgrade`，`transport/internet/httpupgrade/hub.go:49-104`）

- 读超时 **4 秒**（与 websocket 相同），头部读取上限 **12288 字节**（`hub.go:51-53`）。
- 若配置了 `host`：用 `internet.IsValidHTTPHost(req.Host, config.Host)` 校验（忽略大小写；req 含端口时比较 host 部分，`transport/internet/internet.go:8-15`）；`path` 必须**完全等于**归一化 path（`hub.go:60-68`）。
- 要求 `Connection`（小写）`== "upgrade"` 且 `Upgrade`（小写）`== "websocket"`，否则 `unrecognized request`（`hub.go:70-74`）。
- 回 `101 Switching Protocols` + `Connection: Upgrade` + `Upgrade: websocket`；**若请求带了 `Sec-WebSocket-Key`，回 `Sec-WebSocket-Accept = base64(SHA1(key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))`**（RFC 6455 magic，`hub.go:76-90`）。
- 之后交裸流给上层；远端地址经 `trustedXForwardedFor` 修正（`hub.go:95-103`）。
- 监听：可套 TLS 监听器（`hub.go:152-157`）；`acceptProxyProtocol` 与 sockopt 合并（`hub.go:126-131`）。

**要点**：`Sec-WebSocket-Key` 复用是「兼容性伪装」——服务端只回算 Accept，不产生 WebSocket 帧；101 之后是**纯裸字节流**，无帧、无掩码、无 ping/pong。

---

# 二、splithttp（XHTTP）

## 2.1 配置字段

`SplitHTTPConfig`（`infra/conf/transport_method.go:261-290`）。归一化默认值（`transport/internet/splithttp/config.go`）：

| 字段 | 默认 | 证据 |
|---|---|---|
| `mode` | `auto`（运行时解析见 §2.3） | `transport_method.go:322-327` |
| `path` | `"/"`；若 `sessionIDPlacement`/`seqPlacement` 为 `path` 则保证以 `/` 结尾 | `config.go:20-36` |
| `host` | 空 → 回退 `tlsConfig.ServerName` → `realityConfig.ServerName` → `dest.Address` | `dialer.go:300-312` |
| `headers` | 不得含 `host` | `transport_method.go:330-334` |
| `uplinkHTTPMethod` | `POST` | `config.go:132-138` |
| `sessionIDPlacement` | `path` | `config.go:215-220` |
| `seqPlacement` | `path` | `config.go:222-227` |
| `uplinkDataPlacement` | `body` | `config.go:229-234` |
| `sessionIDKey` | 按 placement：`header`→`X-Session`；`cookie`/`query`→`x_session` | `config.go:236-248` |
| `seqKey` | 按 placement：`header`→`X-Seq`；`cookie`/`query`→`x_seq` | `config.go:250-262` |
| `scMaxEachPostBytes` | `[1000000, 1000000]` | `config.go:140-149` |
| `scMinPostsIntervalMs` | `[30, 30]` | `config.go:151-160` |
| `scMaxBufferedPosts` | `30` | `config.go:162-168` |
| `scStreamUpServerSecs` | `[20, 80]` | `config.go:170-178` |
| `uplinkChunkSize` | 按 placement：`cookie`→`[2048,3072]`；`header`→`[3000,4000]`；否则 = `scMaxEachPostBytes`；显式值 <64 时抬到 64 | `config.go:180-207` |
| `serverMaxHeaderBytes` | `8192` | `config.go:209-213` |
| `xPaddingBytes` | `[100, 1000]` | `xpadding.go:179-187` |
| `xPaddingKey`/`xPaddingHeader`/`xPaddingPlacement`/`xPaddingMethod` | `x_padding` / `X-Padding` / `queryInHeader` / `repeat-x` | `transport_method.go:339-357` |
| `noSSEHeader` | false（即默认发 SSE 头） | `hub.go:364-367` |
| `noGRPCHeader` | false（即 stream-up/one 默认带 `Content-Type: application/grpc`） | `config.go:326-328` |
| `xmux` 各字段 | 未设 → `[0,0]` | `config.go:430-488` |

## 2.2 请求元数据放置

`ApplyMetaToRequest`（`config.go:264-299`）把 `sessionId` 与 `seqStr` 按各自 placement 放入：`path`（追加路径段，`appendToPath` `config.go:529-534`）、`query`、`header`、`cookie`。服务端 `ExtractMetaFromRequest` 逆过程（`config.go:383-428`）。

**path 模式**下 session 与 seq 依次占路径段（`config.go:391-418`）。

## 2.3 模式（`mode`）与运行时选择

配置校验：`auto`/`packet-up`/`stream-up`/`stream-one`（`transport_method.go:322-327`）。

客户端 `auto` 解析（`transport/internet/splithttp/dialer.go:330-340`）：
```
auto → packet-up
若 security=reality → stream-one
若 reality 且配置了 downloadSettings → stream-up
```

服务端对模式的强制（`hub.go:153-157, 199-202, 240-243`）：
- 无 sessionId 且 mode ∉ {空, auto, stream-one, stream-up} → 400（`stream-one mode is not allowed`）
- 有 sessionId 且无 seq 且 mode ∉ {空, auto, stream-up} → 400（`stream-up mode is not allowed`）
- 有 sessionId 且有 seq 且 mode ∉ {空, auto, packet-up} → 400（`packet-up mode is not allowed`）

### 上行/下行判定（`hub.go:186-193`）
`GET` 且 `seqStr != ""` → 上行；`GET` 且无 seq → 下行；非 `GET` → 上行。

## 2.4 packet 模式（packet-up / stream-down）

- **上行**：客户端把每次上传切成 ≤ `maxUploadSize`（`scMaxEachPostBytes.rand()`）的分片，每片发一个 HTTP 请求，带自增 `seq`（`dialer.go:460-540`）。分片间隔至少 `scMinPostsIntervalMs.rand()` 毫秒（`dialer.go:519-521`）。管道读取缓冲 = `scMaxEachPostBytes.rand()`，实际 pipe 限额 `max(0, maxUploadSize-buf.Size)`（`dialer.go:460-468`），并用 `uploadWriter` 精确切分（`dialer.go:550-576`）。
- **服务端**：把上行数据按 3 种 placement 解析（`hub.go:245-315`）：
  - `header`：`<uplinkDataKey>-<i>` 逐块拼接后 **base64.RawURLEncoding** 解码（`hub.go:247-264`）
  - `cookie`：`<uplinkDataKey>_<i>` 逐块拼接后同样解码（`hub.go:266-284`）
  - `body`：直接读 body（`hub.go:286-305`）
  - `auto`：三者都解析并 `slices.Concat`（`hub.go:309-310`）
  - 超 `scMaxEachPostBytes` → 413（`hub.go:287-293, 318-323`）
- 按 `seq` 推入会话的 `uploadQueue`（`hub.go:326-337`），由优先队列按序重排（`transport/internet/splithttp/upload_queue.go:74-120`）；队列容量 = `scMaxBufferedPosts`（`hub.go:57`，`upload_queue.go:30-37`）。

## 2.5 stream 模式（stream-up / stream-down / stream-one）

- **stream-down**：`GET` 长连接；响应写 `X-Accel-Buffering: no`、`Cache-Control: no-store`，并（默认）`Content-Type: text/event-stream` 以禁用中间盒缓冲（`hub.go:356-367`）；用 `http.Flusher` 实时冲刷（`hub.go:369-371`）。连接生命周期跟随请求上下文或服务端写端（`hub.go:396-401`）。
- **stream-up**：客户端 `GET`/`POST`（`GetNormalizedUplinkHTTPMethod`）带 body 长连接，`uploadOnly=true`（`client.go:47-96`）；服务端把它作为 `Reader` 推入 uploadQueue（`hub.go:203-238`），并在 legacy Referer/obfs padding 存在时按 `scStreamUpServerSecs.rand()` 秒周期性写入 `X` 填充（`hub.go:225-235`）。
- **stream-one**：单个请求同时上下行；不生成 sessionId（`dialer.go:342-344`），服务端 sessionId 为空即走 stream-down 分支（`hub.go:352-403`）。
- 客户端 `OpenStream`：`GET`(下行) 或上行方法(up/one)，`FillStreamRequest`（`client.go:60-72`），`Content-Type: application/grpc`（除非 `noGRPCHeader`）（`config.go:326-328`）。

## 2.6 会话与队列（服务端）

- `upsertSession`：无则新建 `httpSession{uploadQueue, isFullyConnected}`；若 30 秒内未完成 GET（`isFullyConnected`），会话被回收（`hub.go:56-93`）。
- GET 到达后 `isFullyConnected.Close()` 并 `defer` 删除会话（`hub.go:354-357`）。
- 下行写入用 `httpServerConn`（加锁 + `Flush`，`hub.go:406-428`）。
- 客户端 `downloadSettings` 会另建一套 `MemoryStreamConfig` 与其 xmux（`dialer.go:352-395`），实现上下行分离的 host/tls/mode。

## 2.7 H2 / H3 差异（`decideHTTPVersion`，`dialer.go:82-99`）

| 条件 | HTTP 版本 |
|---|---|
| `security=reality` | `2` |
| 无 TLS | `1.1` |
| ALPN 恰好 1 项且为 `http/1.1` | `1.1` |
| ALPN 恰好 1 项且为 `h3` | `3`（并把 dest 改为 UDP，`dialer.go:104-106`） |
| 其他 | `2` |

- **H1.1**：`http.Transport` 且 `DisableKeepAlives: true`；上行 packet 走**自建连接池**并手工序列化请求以支持重试（`dialer.go:280-290`，`client.go:126-175`）。
- **H2**：`http2.Transport`，`IdleConnTimeout=net.ConnIdleTimeout`，`ReadIdleTimeout` 取 `xmux.hKeepAlivePeriod`，未设则为 `net.ChromeH2KeepAlivePeriod`（`dialer.go:243-254`）。
- **H3**：`quic-go/http3.Transport` + `quic.Transport`；受 `finalmask.quicParams` 控制窗口/空闲/MTU/GSO/拥塞（`reno`/`bbr`/`force-brutal`），并默认开启 `ChromeParrot`（`dialer.go:150-242`）。服务端 `isH3` 判定 = ALPN 恰为 `h3`（`hub.go:497`），否则 TCP 上同时支持明文 HTTP/1.1 与 h2c（`hub.go:556-566`）。
- 服务端 `MaxHeaderBytes` = `serverMaxHeaderBytes`（默认 8192），`ReadHeaderTimeout` 4s（`hub.go:560-565`）。

## 2.8 xmux（多路复用连接池）

`XmuxManager` 按 `hMaxRequestTimes`/`hMaxReusableSecs`/`maxConnections` 等生成 `XmuxClient`，用 `LeftRequests` 与 `UnreusableAt` 决定何时换新连接（`transport/internet/splithttp/mux.go:62-79, 81-99`；`dialer.go:519-524`）。未设时 `LeftRequests = math.MaxInt32`（即不轮换）（`mux.go:70`）。

## 2.9 xpadding（填充伪装）

- 请求侧：`FillStreamRequest`/`FillPacketRequest` 中按 `xPaddingBytes.rand()` 生成长度并放置（`config.go:301-329, 331-381`）；obfs 模式用配置的 placement/key/header，否则固定 `queryInHeader` + key `x_padding` + header `Referer`（`config.go:306-318`）。
- 服务端：响应侧固定用 header `X-Padding`（`hub.go:117-125`），校验 length 是否落在 `[from,to]`（`xpadding.go:307-...`），非法回 400（`hub.go:143-148`）。
- 填充内容：`repeat-x` 或 `tokenish`（base62，按 Huffman 估算长度，`xpadding.go:22-60`）。

---

# 三、grpc

## 3.1 配置字段

`GRPCConfig`（`infra/conf/transport_method.go:578-587`）→ proto（`transport/internet/grpc/config.proto:8-16`）：

| JSON 字段 | 说明 |
|---|---|
| `authority` | gRPC `:authority`；空则回退 `tlsServerName` → 目标域名（`dial.go:151-159`） |
| `serviceName` | 服务名；见 §3.2 |
| `multiMode` | 使用 `MultiHunk`（`TunMulti` 流）而非 `Hunk`（`Tun` 流）（`dial.go:59-66`） |
| `idle_timeout` / `health_check_timeout` / `permit_without_stream` | keepalive（`dial.go:161-167`；服务端 `hub.go:117-122`） |
| `initial_windows_size` | HTTP/2 初始窗口（`dial.go:169-171`） |
| `user_agent` | 见 §3.4 |

≤0 归零（`transport_method.go:589-609`）。

## 3.2 服务名与流名派生（`transport/internet/grpc/config.go`）

- `getServiceName`（`config.go:17-34`）：不以 `/` 开头时 `url.PathEscape(serviceName)`；否则取「第一个到最后一个 `/` 之间」的路径，逐段 `PathEscape` 后以 `/` 连接。
- `getTunStreamName`（`config.go:36-44`）：非自定义路径时固定 `"Tun"`；否则取最后一段中 `|` 之前的部分。
- `getTunMultiStreamName`（`config.go:46-59`）：非自定义路径时固定 `"TunMulti"`；否则按 `|` 分割：客户端用第 0 段，**服务端用第 1 段**。

方法路径 = `"/" + serviceName + "/" + streamName`（`encoding/customSeviceName.go:32-45`）。

## 3.3 消息分帧

- proto 服务定义：`rpc Tun(stream Hunk) returns (stream Hunk)` 与 `rpc TunMulti(stream MultiHunk) returns (stream MultiHunk)`（`encoding/stream.proto:11-13`）；`Hunk{ bytes data = 1 }`、`MultiHunk{ repeated bytes data = 1 }`（`encoding/stream.proto:7-9`）。
- **线上分帧由 gRPC 自身完成**：每条消息前缀 `[1 字节 compressed-flag][4 字节大端 length]`（gRPC over HTTP/2 DATA 帧约定）。Xray 侧不做该分帧，只做消息内容映射：
  - `Hunk` 单包：`Read` 直接回填 `hunk.Data`（`encoding/hunkconn.go:52-79`），`Write` 每次 `Send(&Hunk{Data: buf})`（`hunkconn.go:108-118`）。
  - `MultiHunk`：一次 `Send` 携带多段（`encoding/multiconn.go:91-109`），读时逐段成 `MultiBuffer`（`multiconn.go:62-89`）。
- `SendMsg/RecvMsg` 由生成的 `GenericClientStream`/服务端 stream 提供（`encoding/customSeviceName.go:32-52`）。
- 远端地址从 gRPC peer/metadata 取得，并支持 `X-Forwarded-For`（仅在 sockopt 信任列表中时）（`encoding/remoteaddr.go:13-52`）。

## 3.4 User-Agent 处理（`dial.go:184-204`）

| `user_agent` | 实际 UA |
|---|---|
| `chrome` 或 空 | `utils.ChromeUA` |
| `firefox` | `utils.FirefoxUA` |
| `edge` | `utils.MSEdgeUA` |
| `golang` | `""`（清空） |
| 其他 | 原样透传 |

注释明确不建议把 gRPC 的 UA 伪装成真实浏览器（浏览器无法发起真 gRPC）。UA 通过反射直接改写 grpc 内部 `dopts.copts.UserAgent`，以去掉 `grpc-go/<ver>` 后缀（`dial.go:206-210`）。

## 3.5 服务端

- `grpc.NewServer`，配了 TLS 时用 `credentials.NewTLS(GetTLSConfig(WithNextProto("h2")))`（**注意注释：gRPC 服务端可能静默忽略 TLS 错误**，`hub.go:110-115`）。
- 注册服务用 `RegisterGRPCServiceServerX(s, listener, serviceName, tunName, tunMultiName)`（`hub.go:144`）。
- `Tun`/`TunMulti` 回调各构造一个 `Hunk`/`MultiHunk` 连接并交给 `handler`；连接存活到 `tunCtx.Done()`（`hub.go:40-47`）。