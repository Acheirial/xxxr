# VLESS 线协议逐字节规格（依据 upstream v26.9.30）

> 证据引用 `/home/dev/tmp/xray-core-ref` 内 Go 源码 `路径:行号`。
> 主实现：`proxy/vless/encoding/encoding.go`、`proxy/vless/encoding/addons.go`、`common/protocol/{headers,payload,address}.go`。

## 1. 常量

| 常量 | 值 | 证据 |
|---|---|---|
| 协议版本 | `0x00` | `proxy/vless/encoding/encoding.go:19`（`Version = byte(0)`） |
| Command TCP | `0x01` | `common/protocol/headers.go:15` |
| Command UDP | `0x02` | `common/protocol/headers.go:16` |
| Command Mux | `0x03` | `common/protocol/headers.go:17` |
| Command Rvs（反向） | `0x04` | `common/protocol/headers.go:18` |
| 地址类型 IPv4 | `0x01` | `common/protocol/payload.go:13` |
| 地址类型 Domain | `0x02` | `common/protocol/payload.go:14` |
| 地址类型 IPv6 | `0x03` | `common/protocol/payload.go:15` |
| Flow：无 | `""` | `proxy/vless/vless.go:9`（`None`） |
| Flow：Vision | `"xtls-rprx-vision"` | `proxy/vless/vless.go:10`（`XRV`） |

**关键：VLESS 地址解析器为「Port 在前、地址在后」**：`addrParser = NewAddressParser(AddressFamilyByte(1,IPv4), AddressFamilyByte(2,Domain), AddressFamilyByte(3,IPv6), PortThenAddress())`（`encoding.go:22-27`）。`PortThenAddress` 使 `WriteAddressPort` 先写 2 字节端口再写地址（`common/protocol/address.go:15-19, 116-121`）。

## 2. 请求头（EncodeRequestHeader，`encoding.go:30-61`）

按写入顺序（字节偏移从 0 起）：

| 偏移 | 长度 | 字段 | 说明 |
|---|---|---|---|
| 0 | 1 | Version | 固定 `0x00`（`encoding.go:34`） |
| 1 | 16 | User ID (UUID) | `MemoryAccount.ID.Bytes()`（`encoding.go:38`） |
| 17 | 1 | Addons 长度 `L` | `EncodeHeaderAddons`（`addons.go:17-37`） |
| 18 | `L` | Addons 载荷 | 仅当 `L>0`；protobuf 编码的 `Addons` 消息 |
| 18+`L` | 1 | Command | `0x01/0x02/0x03/0x04`（`encoding.go:46`） |
| 19+`L` | 2 | 端口 | **仅当 Command 为 TCP/UDP**，大端 uint16（`encoding.go:50-54`） |
| 21+`L` | 1 | 地址类型 | 仅当 TCP/UDP：`1`=IPv4 / `2`=Domain / `3`=IPv6 |
| 22+`L` | 4/16/变长 | 地址 | IPv4=4 字节；IPv6=16 字节；Domain=1 字节长度 + N 字节域名 |

要点：
- **Command 为 Mux(`0x03`) 或 Rvs(`0x04`) 时不写端口与地址**（`encoding.go:50`）。Mux 在解码侧被映射为地址 `v1.mux.cool`，Rvs 映射为 `v1.rvs.cool`（`encoding.go:115-118`）。
- 域名的读取：先读 1 字节长度，再读该长度字节；若首字符是数字或 `[` 会先尝试按 IP 解析，否则校验合法域名（`address.go:190-215`）。域名长度上限 256（`headers.go:81-83`）。
- 解码顺序见 `DecodeRequestHeader`（`encoding.go:64-132`）：先 version→UUID→addons→command→地址。

### 2.1 Addons 编码（`addons.go:17-37`）

```proto
message Addons {
  string Flow = 1;   // proxy/vless/encoding/addons.proto
  bytes  Seed = 2;
}
```
（见 `addons.pb.go:25-29` 与 rawDesc。）

- `EncodeHeaderAddons`：若 `Flow == "xtls-rprx-vision"`，则 `proto.Marshal(addons)` 得到 `N` 字节，写入 `1 字节长度 N` + `N 字节`；**否则只写 1 字节 `0x00`**（`addons.go:19-36`）。
- `DecodeHeaderAddons`：读 1 字节长度；非 0 时读该长度字节并 `proto.Unmarshal`（`addons.go:39-63`）。注意解码端对未知 `Flow` **不报错**（switch 的 default 为空）。

### 2.2 UUID 处理关键点

用户查找时对 UUID 做归一化：`ProcessUUID(id)` 将 `id[6]` 和 `id[7]` 清零后再作为 key（`proxy/vless/validator.go:21-25`），即 UUID 的 version/variant 位被忽略。服务端以该归一化 UUID 建表（`validator.go:30-38, 53-58`）。Rust 重写必须复刻此行为，否则部分客户端 UUID 无法匹配。

## 3. 响应头（`encoding.go:135-175`）

| 偏移 | 长度 | 字段 | 说明 |
|---|---|---|---|
| 0 | 1 | Version | 必须等于请求 Version，否则报错（`encoding.go:163-164`） |
| 1 | 1 | Addons 长度 | |
| 2 | `L` | Addons 载荷 | 仅当 `L>0` |

`EncodeResponseHeader`（`encoding.go:135-153`）写 version + addons；**响应头不含 UUID/command/地址**。
入站实际构造的 `responseAddons` 为空结构（`proxy/vless/inbound/inbound.go:546-548`）。

## 4. 请求体（body）

`EncodeBodyAddons` / `DecodeBodyAddons`（`addons.go:66-85`）根据 Command/Flow 决定分帧：

| 条件 | 读端 | 写端 | 帧格式 | 证据 |
|---|---|---|---|---|
| Command=UDP 且 Flow≠Vision | `LengthPacketReader` | `MultiLengthPacketWriter` | 每包 `2 字节大端长度 + 载荷` | `addons.go:66-69, 77-84` |
| Flow=Vision | Vision reader/writer | — | XTLS Vision 填充协议 | `addons.go:70-72`；`inbound.go:614-616` |
| 其他 | 原始流 | 原始流 | 无额外帧 | `addons.go:84` |

UDP 长度帧细节（`addons.go:126-191`）：
- 写：`LengthPacketWriter` 把整批数据前加 2 字节大端长度（`addons.go:139-157`）。
- 读：`LengthPacketReader` 读 2 字节大端长度 `L`，再读取 `L` 字节（`addons.go:174-191`）。
- XUDP（mux 内 UDP）用 `MultiLengthPacketWriter`，对每个 buffer 单独加 2 字节长度（`addons.go:99-124`）。

## 5. Flow 取值与语义

| Flow 值 | 合法场景 | 证据 |
|---|---|---|
| `""` | 默认，明文/普通流 | `proxy/vless/vless.go:9` |
| `"xtls-rprx-vision"` | TCP；要求外层为 TLS 1.3 或 REALITY，且 READ/RAW 直连 | `inbound.go:552-596` |
| `"xtls-rprx-vision-udp443"` | **仅出站配置**可接受（历史兼容） | `infra/conf/vless.go:331` |

服务端校验：客户端声明的 flow 必须与账号 flow 一致，否则拒绝（`inbound.go:552-596`）。Vision 不支持 UDP（`inbound.go:557-558`）。若客户端 flow 为空而账号要求 Vision，且命令为 TCP 或 mux-non-XUDP，会被拒绝（`inbound.go:593-595`）。

## 6. 账号 / 服务端配置字段（`infra/conf/vless.go`）

- 入站 `settings`（`vless.go:33-39`）：`users`/`clients`、`decryption`、`fallbacks[]`、`flow`、`testseed[]`。
  - 账号字段：`id`(UUID)、`flow`、`level`、`email`、`encryption`(入站禁止)、`reverse`、`testseed`。
  - `flow` 只允许 `""` 或 `xtls-rprx-vision`（`vless.go:51-53`）。
  - `decryption` 必须显式设 `"none"`（除非为 PQ 加密串），否则报错（`vless.go:108-166`）。
- 出站简化式 `settings`（`vless.go:245-259`）：`address,port,level,email,id,flow,seed,encryption,reverse,testpre,testseed,vnext[]`；`vnext` 必须恰好 1 个成员且 users 恰好 1 个（`vless.go:272-290`）。

### `fallbacks`（`vless.go:24-32, 161-215`）
每项：`name`、`alpn`、`path`（空或以 `/` 开头）、`type`(`tcp`/`unix`/`serve`，由 dest 推断)、`dest`、`xver`(0/1/2)。`decryption != none` 时不允许 fallbacks（`vless.go:164-166`）。

## 7. VLESS 加密扩展（`encryption != none`，即 "mlkem768x25519plus"）

这是一个独立的后量子握手层，与经典 VLESS 头**并列/包裹**，不是同一层解析。

- 配置语法：`mlkem768x25519plus.<native|xorpub|random>.<1rtt|0rtt>.<padding>...<serverKey>`，解析见 `infra/conf/vless.go:108-166`（入站）与 `vless.go:337-378`（出站）。
- 原语（`proxy/vless/encryption/common.go`）：16 字节 IV；AEAD（AES-GCM 或 ChaCha20-Poly1305，按硬件能力，`client.go:69`）；长度编码 `[hi,lo]`（`common.go:EncodeLength`）；`XorConn`（`encryption/xor.go`）；握手流程 `ClientInstance.Handshake`（`encryption/client.go:65`）与 `ServerInstance.Handshake`（`encryption/server.go:117`）。
- 详细的逐字节握手顺序（ClientHello 布局、PFS 公钥交换、ticket、padding 生成）**未确认**，需专项；本文只确认配置语法与所用原语。