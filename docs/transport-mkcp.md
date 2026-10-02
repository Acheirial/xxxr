# mKCP 传输规格（依据 upstream v26.9.30）

> 证据引用 `/home/dev/tmp/xray-core-ref`（XTLS/Xray-core v26.9.30，HEAD `b26a91de4f3294e26a0ad0a970b81a386a41f789`）内 Go 源码 `路径:行号`。
> 主实现：`transport/internet/kcp/*.go`。

## 0. 前提与更正

1. **本版本的 mKCP 配置只有 6 个字段**：`mtu`、`tti`、`uplinkCapacity`、`downlinkCapacity`、`cwndMultiplier`、`maxSendingWindow`（proto `transport/internet/kcp/config.proto:10-15`）。
2. **`congestion` / `readBufferSize` / `writeBufferSize` 字段不存在**（全仓库无对应 JSON 标签）。
3. **`header` 与 `seed` 字段在配置结构体中存在但 `Build()` 完全未使用**（`infra/conf/transport_method.go:535-536` 定义，`540-577` 的 Build 未引用）——即 mKCP 自带的 header 混淆在本版本**已不再生效**。
4. 原来的混淆头类型（dns/dtls/srtp/utp/wechat/wireguard）**迁移到了 `finalmask`**，通过 `streamSettings.finalmask.tcp[].settings.header` 使用，作用于 UDP 数据包级别（`infra/conf/transport_finalmask.go:708-725`；实现 `transport/internet/finalmask/mkcp/header/*.go`）。见 §6。
5. 协议名归一化为 **`mkcp`**（`transport/internet/kcp/kcp.go:9`；配置别名 `kcp`/`mkcp` 见 `infra/conf/transport_internet.go:23`）。

## 1. 配置与默认值

默认值（`transport/internet/kcp/config.go:29-37`，注册工厂）：

| 字段 | 默认 |
|---|---|
| `mtu` | 1350 |
| `tti` | 50（毫秒） |
| `uplinkCapacity` | 5（MB/s） |
| `downlinkCapacity` | 20（MB/s） |
| `cwndMultiplier` | 1 |
| `maxSendingWindow` | 2 MiB |

校验（`infra/conf/transport_method.go:559-575`）：`mtu >= 21`、`10 <= tti <= 1000`、`cwndMultiplier >= 1`、`maxSendingWindow / mtu > 0`。

由配置派生的运行时参数（`transport/internet/kcp/config.go`）：

| 名称 | 公式 | 用途 |
|---|---|---|
| `GetSendingInFlightSize` | `uplinkCapacity*1024*1024/mtu/(1000/tti)`，下限 8 | 发送窗口上限（`config.go:8-14`） |
| `GetSendingBufferSize` | `maxSendingWindow/mtu` | 发送缓冲窗口（`config.go:16-18`） |
| `GetReceivingInFlightSize` | `downlinkCapacity*1024*1024/mtu/(1000/tti)`，下限 8 | 接收窗口（`config.go:20-26`） |
| MSS | `mtu - 18`（`DataSegmentOverhead`） | 单段最大载荷（`connection.go:218`、`segment.go:39`） |

## 2. 段（Segment）线格式

**通用头 4 字节**（`segment.go:107-118` 等）：`conv`(u16 BE) + `command`(u8) + `option`(u8)。

命令（`segment.go:12-21`）：`ACK=0`、`Data=1`、`Terminate=2`、`Ping=3`。
选项（`segment.go:24-27`）：`SegmentOptionClose = 1`。

### 2.1 Data 段（`segment.go:58-119`）

| 偏移 | 长度 | 字段 |
|---|---|---|
| 0 | 2 | conv（大端 u16） |
| 2 | 1 | command = 1 |
| 3 | 1 | option |
| 4 | 4 | timestamp（大端 u32） |
| 8 | 4 | number（大端 u32） |
| 12 | 4 | sendingNext（大端 u32，= 发送方 firstUnacknowledged） |
| 16 | 2 | dataLen（大端 u16） |
| 18 | dataLen | payload |

`ByteSize = 18 + payload`，`DataSegmentOverhead = 18`（`segment.go:39, 117-119`）。

### 2.2 ACK 段（`segment.go:122-227`）

| 偏移 | 长度 | 字段 |
|---|---|---|
| 0 | 4 | 通用头（command = 0） |
| 4 | 4 | receivingWindow（大端 u32） |
| 8 | 4 | receivingNext（大端 u32） |
| 12 | 4 | timestamp（大端 u32） |
| 16 | 1 | count |
| 17 | 4×count | number 列表（大端 u32 各） |

`ByteSize = 17 + 4*len(NumberList)`（`segment.go:205-207`）。单段 number 上限 `ackNumberLimit = 128`，且实际容量为 `(mss - 17) / 4`（`segment.go:138-146`、`receiving.go:96`）。

### 2.3 CmdOnly 段（Terminate/Ping，`segment.go:229-283`）

| 偏移 | 长度 | 字段 |
|---|---|---|
| 0 | 4 | 通用头 |
| 4 | 4 | sendingNext（大端 u32） |
| 8 | 4 | receivingNext（大端 u32） |
| 12 | 4 | peerRTO（大端 u32） |

`ByteSize = 16`。

### 2.4 多段复用

一个 UDP 载荷可含多个连续段，`ReadSegment` 返回 `(segment, rest)` 逐个切分（`segment.go:286-312`）；`KCPPacketReader.Read` 循环解析直到失败（`transport/internet/kcp/io.go:9-20`）。

## 3. 会话建立（无握手）

- 客户端启动时 `globalConv` 取随机 u16，每次拨号 `conv = uint16(atomic.AddUint32(&globalConv, 1))`（`dialer.go:18, 67`）。
- 服务端按 `ConnectionID{Remote, Port, Conv}` 索引会话（`listener.go:18-22`）；收到未知 `(src, conv)` 的首个段时**直接创建会话**，除非该段是 `CommandTerminate`（此时丢弃）（`listener.go:82-121`）。
- 服务端 UDP hub 容量 1024（`listener.go:49`）；可叠加 TLS（`listener.go:115-118`）。

## 4. 可靠性机制

### 4.1 定时器

- `dataUpdater`：间隔 = `tti` 毫秒，条件为发送/接收窗口需要更新（`connection.go:234-240`）。
- `pingUpdater`：固定 5000 毫秒（`connection.go:242-247`）。
- `flush`（`connection.go:609-647`）：
  - `StateActive` 且 30 秒无入站数据 → `Close()`（`connection.go:615-617`）
  - 状态机超时：`StateTerminating` 8 秒、`StatePeerTerminating` 4 秒、`StateReadyToClose` 15 秒（`connection.go:631-641`）
  - 每轮都 `receivingWorker.Flush` + `sendingWorker.Flush`（`connection.go:644-645`）
  - 距上次 ping ≥ 3000 ms 则发 `CommandPing`（`connection.go:642-644`）

### 4.2 RTT / RTO（类 RFC 6298，`connection.go:52-121`）

- 初始 `rto = 100`，`minRtt = tti`（`connection.go:219-222`）。
- `Update(rtt, current)`：`srtt`/`variation` 指数平滑；`rto = srtt + 4*variation`（若 `minRtt < 4*variation`）否则 `srtt + variation`，上限 10000，最后 `rto = rto*5/4`（`connection.go:73-107`）。
- `UpdatePeerRTO`：每 3000 ms 才接受对端 RTO（`connection.go:61-71`）。

### 4.3 发送与重传（`transport/internet/kcp/sending.go`）

- `SendingWindow.Flush(current, rto, maxInFlightSize)`（`sending.go:98-129`）：遍历发送窗口，对**已到期**的段（`current - segment.timeout < 0x7FFFFFFF` 视为未到期，跳过）重发：设置 `timeout = current + rto`、`Timestamp = current`、`transmit++`；首次发送（`transmit == 0`）计入 `totalInFlightSize`，否则计入 `lost`；最后按 `lost*100/totalInFlightSize` 调用 `onPacketLoss`。发送量受 `maxInFlightSize` 限制。
- `SendingWorker.Flush`（`sending.go:310-341`）：`cwnd = min(GetSendingInFlightSize, remoteNextNumber-firstUnacknowledged, controlWindow) * cwndMultiplier`，然后 `window.Flush(current, rto, cwnd)`。
- **拥塞控制**（`OnPacketLoss`，`sending.go:290-308`）：丢包率 ≥15% → `controlWindow = 3/4`；≤5% → `+= 1/4`；下限 16；上限 `GetSendingInFlightSize`。
- **ACK 处理**（`ProcessSegment`，`sending.go:223-258`）：更新 `remoteNextNumber`（取 max）、`window.Clear(seg.ReceivingNext)`；对 ACK 列表逐个 `processAck`；若最大被确认号被移除则 `HandleFastAck` 并把 `current - seg.Timestamp` 作为 RTT 样本（限 <10 s）。
- `HandleFastAck`（`sending.go:68-83`）：对被 ACK 号之前的已发段，把 `timeout` 提前 `rto/3`，实现快速重传。
- **`fastResend` 字段被初始化为 2 但从未被读取**（`sending.go:161, 170`，grep 无其他引用）——属遗留字段。

### 4.4 接收与 ACK 生成（`transport/internet/kcp/receiving.go`）

- `ProcessSegment`（`receiving.go:168-183`）：`idx = number - nextNumber`，若 `idx >= windowSize` 直接丢弃；否则 `acklist.Clear(seg.SendingNext)`、`acklist.Add(number, seg.Timestamp)`、`window.Set(...)`（重复则释放）。
- `ReadMultiBuffer`（`receiving.go:185-207`）：从 `nextNumber` 起按序取出，保证顺序交付。
- `AckList.Flush`（`receiving.go:93-141`）：为每个待确认号设置 `nextFlush = current + max(rto/2, 20)`；满则发送并新建段；若 `dirty` 或有剩余则补发（重复 ACK 以对抗丢包）。
- `ReceivingWorker.Write`（`receiving.go:241-...`）：填 `conv`、`ReceivingNext = nextNumber`、`ReceivingWindow = nextNumber + windowSize`。

### 4.5 状态机（`connection.go:38-45`）

`StateActive=0`、`StateReadyToClose=1`、`StatePeerClosed=2`、`StateTerminating=3`、`StatePeerTerminating=4`、`StateTerminated=5`。`Input` 按段类型分派（`connection.go:562-607`）：Data → 接收窗口；ACK → 发送窗口；CmdOnly → Terminate 状态迁移 + 更新对端 next/RTO；`SegmentOptionClose` 触发 `OnPeerClosed`（`connection.go:546-560`）。

## 5. 数据通路

- 写：`WriteMultiBuffer` → `writeMultiBufferInternal`，按 `mss` 切片，`sendingWorker.Push` 失败（窗口满）时 `waitForDataOutput` 等待（`connection.go:379-428`）。
- 读：`ReadMultiBuffer` 从接收窗口按序取（`connection.go:258-281`）。
- 收发均通过 `signal.Notifier` + `dataUpdater` 唤醒，避免忙等。

## 6. 混淆头（finalmask，非 mKCP 配置）

`finalmask` 的 `header` 类型与线上头部（`transport/internet/finalmask/mkcp/header/`）：

| 配置 `header` | ID | 头长度 | 线上前缀 |
|---|---|---|---|
| `dns` | 0 | 变长（DNS 报文） | DNS 查询报文（`header_dns.go`） |
| `dtls` | 1 | 13 | `17 FE FD` + epoch(2) + `00 00` + seq(4) + length(2)（`header_dtls.go:9-23`） |
| `srtp` | 2 | 4 | header(2) + number(2)（`header_srtp.go:10-17`） |
| `utp` | 3 | 4 | 见 `header_utp.go:11-` |
| `wechat` | 4 | 13 | `A1 08` + sn(4) + `00 10 11 18 30 22 30`（`header_wechat.go:9-23`） |
| `wireguard` | 5 | 4 | `04 00 00 00`（`header_wireguard.go:5-13`） |

`headerConn.WriteTo` 把头部写入载荷开头，`ReadFrom` 直接返回 `len(p) - Size()`（`transport/internet/finalmask/mkcp/header/conn.go:51-56`）。另有两种非 header 型 mask：`mkcp/original`（xor）与 `mkcp/aes128gcm`（`infra/conf/transport_finalmask.go:698-707`）。

**注意**：这些 mask 由 `streamSettings.finalmask` 驱动（`infra/conf/transport_internet.go:246-260`），与 `kcpSettings.header` 无关。

## 7. 未确认项

- 上游无 mKCP 的字节级固定测试向量；本文件仅描述实现语义，未生成向量。
- `fastResend` 字段是否在其它分支/版本被使用未确认（本版本内确认未被读取）。
- `stateBeginTime` 与 `dataUpdater` 交互的精确时序（如 8 s/4 s/15 s 超时的触发边界）未逐帧验证。