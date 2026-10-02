# Mux.Cool 帧格式规格（依据 upstream v26.9.30）

> 证据引用 `/home/dev/tmp/xray-core-ref` 内 Go 源码 `路径:行号`。
> 主实现：`common/mux/{frame,writer,reader,session,client,server}.go`。

## 0. 地址与端口

- 目标地址常量：`muxCoolAddress = net.DomainAddress("v1.mux.cool")`，`muxCoolPort = net.Port(9527)`（`common/mux/client.go:185-186`）。
- **不存在 `xray.mux.cool`**：全仓库 grep `xray.mux.cool` 无任何命中（仅 `v1.mux.cool`）。任务书提到的 "xray.mux.cool 变体" **未确认/不存在**。
- 服务端只接受目标地址等于 `v1.mux.cool` 的请求（`common/mux/server.go:41-45`、`62-66`）。
- VLESS 与 VMess 在收到 Command=Mux 时都把地址置为 `v1.mux.cool`（`proxy/vless/encoding/encoding.go:115-116`、`proxy/vmess/encoding/server.go:208-210`）。

## 1. 常量

| 常量 | 值 | 证据 |
|---|---|---|
| SessionStatus New | `0x01` | `frame.go:20` |
| SessionStatus Keep | `0x02` | `frame.go:21` |
| SessionStatus End | `0x03` | `frame.go:22` |
| SessionStatus KeepAlive | `0x04` | `frame.go:23` |
| Option Data | `0x01` | `frame.go:27` |
| Option Error | `0x02` | `frame.go:28` |
| TargetNetwork TCP | `0x01` | `frame.go:34` |
| TargetNetwork UDP | `0x02` | `frame.go:35` |
| metadata 最大长度 | `512` | `frame.go:119` |
| 数据分片（stream） | `8*1024` | `writer.go:104` |

## 2. 帧格式

源码注释（`common/mux/frame.go:46-56`）：

```
2 bytes - length          ← metadata 长度 metaLen
2 bytes - session id
1 byte  - status
1 byte  - option

1 byte  - network
2 bytes - port
n bytes - address
```

完整线上帧（`writeMetaWithFrame`，`writer.go:71-87`）：

```
[metaLen : 2 字节 BE]
[metadata : metaLen 字节]
[dataLen : 2 字节 BE]     ← 仅"带数据"的帧
[data : dataLen 字节]
```

- `metaLen` 只覆盖 metadata（sessionID+status+option+地址等），不含 data 长度字段（`frame.go:67-111` 中 `lenBytes` 最终填 `len1-len0`）。
- `dataLen` 由 `serial.WriteUint16(frame, uint16(data.Len()))` 写入（`writer.go:79-81`）；读端 `PacketReader` 先读 2 字节长度再读数据（`reader.go:30-50`）。

### 2.1 metadata 明细（`FrameMetadata.WriteTo`，`frame.go:67-111`）

固定前缀：

| 偏移 | 长度 | 字段 |
|---|---|---|
| 0 | 2 | sessionID（大端 uint16） |
| 2 | 1 | SessionStatus |
| 3 | 1 | Option（bitmask） |

当 `status == New`（`frame.go:77-96`）追加：

| 字段 | 说明 |
|---|---|
| network(1) | `TargetNetworkTCP=1` / `TargetNetworkUDP=2` |
| 地址+端口 | addrParser 编码（§3） |
| （可选）source network + source 地址端口 | 仅当 `Inbound != nil` 且 source/local 有效时（`frame.go:83-96`） |
| （可选）GlobalID(8) | 否则若该 buffer 是 UDP 且无 inbound 信息，写 8 字节 XUDP GlobalID（`frame.go:100-101`） |

当 `status == Keep` 且 buffer 带 UDP 目标时（`frame.go:97-100`）追加 `network(1)=2` + UDP 地址端口。

解析端 `UnmarshalFromBuffer`（`frame.go:134-222`）：
- 读 sessionID/status/option（`frame.go:136-141`）。
- 读目标地址条件：`status==New`，**或** `status==Keep 且第 4 字节==TargetNetworkUDP`（`frame.go:144-145`，注释 "MUST check the flag first"）。
- `status==New && readSourceAndLocal` 时解析 source 与 local（reverse mux 场景，`frame.go:167-210`）。
- `status==New && OptionData && 目标为 UDP && 剩余≥8` 时读取 GlobalID（`frame.go:216-219`）。

## 3. 地址编码

`addrParser = NewAddressParser(AddressFamilyByte(1,IPv4), AddressFamilyByte(2,Domain), AddressFamilyByte(3,IPv6), PortThenAddress())`（`frame.go:38-43`）。

⇒ ATYP `1/2/3`，**端口在前、地址在后**，与 VLESS/VMess 一致，与 SOCKS5/Trojan（`1/4/3`，地址在前）不同。

## 4. 状态语义

| 状态 | 语义 | 发送方 | 处理 |
|---|---|---|---|
| New(0x01) | 建立新子会话，携带目标地址 | 发起侧 | 服务端 `handleStatusNew` 分发到 dispatcher（`server.go:165-298`）；客户端 `handleStatusNew` 仅丢弃数据（`client.go:341-346`，用于 reverse mux） |
| Keep(0x02) | 既有子会话的后续数据 | 双方 | 按 sessionID 找到会话并投递数据（`server.go:300-324`、`client.go:348-372`） |
| End(0x03) | 关闭子会话 | 双方 | 关闭对应 session（`server.go:326-334`、`client.go:374-380`） |
| KeepAlive(0x04) | 保活 | **无发送方** | 仅接收处理（丢弃数据；`server.go:158-163`、`client.go:333-339`）。当前代码**没有任何地方发送 KeepAlive 帧**，属保留状态 |

写入侧自动切换 New→Keep：`Writer.getNextFrameMeta` 首次写为 `New`，之后为 `Keep`（`writer.go:44-58`）；`Writer.Close` 写 `End`，若 `hasError` 则附加 `OptionError`（`writer.go:122-134`）。

## 5. 数据分片与读写

- 发送：`Writer.WriteMultiBuffer` 对流类型按 8 KiB 切片（`writer.go:107`），对包类型每 buffer 一帧（`writer.go:108-112`）。
- 空 buffer 写 → 仅发一帧 metadata（无 data）（`writer.go:60-67, 99-101`）。
- 读取：
  - stream：`NewStreamReader` = `ChunkStreamReader{PlainChunkSizeParser}`，每帧 `[len:2][data]`，限制 1 个 chunk（`reader.go:57-59`、`common/crypto/chunk.go:19-24, 62-...`）。
  - packet：`PacketReader` 读 `[len:2][data]`，`len > buf.Size(8192)` 报错（`reader.go:30-50`）。
  - 选择由 `Session.NewReader` 依 transferType 决定（`session.go:207-214`）。

## 6. GlobalID 与 XUDP（XUDP 复用）

- `GlobalID` 8 字节，由 `xudp.GetGlobalID(ctx)` 从入站源地址派生（仅 dokodemo-door/socks/shadowsocks/tun 的 UDP 入站，`common/xudp/xudp.go:65-79`）。
- 客户端在 New 帧上带 GlobalID（`frame.go:93-95`）；服务端见 `GlobalID != 0` 时走 XUDP 路径：以 GlobalID 复用同一子会话（`server.go:195-260`），并使用 `TransferTypePacket`（`server.go:257`）。
- XUDP 状态机 `Initializing/Active/Expiring`，过期 1 分钟后回收（`session.go:218-252`）。

## 7. 会话管理

- `SessionManager{sessions map[uint16]*Session, count}`（`session.go:18-22`）。
- `Allocate` 受 `ClientStrategy{MaxConcurrency, MaxConnection}` 限制，超限返回 nil（`session.go:54-72`）。
- `CloseIfNoSessionAndIdle` 在无活跃子会话且计数未变时关闭整条 mux 连接（`session.go:120-137`）——客户端 monitor 每 16 秒检查一次（`client.go:190-198, 225-241`）；服务端 monitor 每 60 秒检查（`server.go:95-109, 127-140`）。

## 8. 配置映射

`streamSettings`/出站 `mux` 配置 `MuxConfig`（`infra/conf/xray.go:106-128`）：`enabled`、`concurrency`(int16，<0 完全禁用)、`xudpConcurrency`(int16)、`xudpProxyUDP443`(默认 `reject`)。→ `proxyman.MultiplexingConfig`。详见 `docs/config-schema.md`。

## 9. 与既有文档的关系

- 地址映射同 `docs/vless-protocol.md`、`docs/vmess-protocol.md`（`1/2/3`，端口在前）。
- Command=Mux 的触发与 `v1.mux.cool` 地址见 `docs/vless-protocol.md:§2`、`docs/vmess-protocol.md:§4`。