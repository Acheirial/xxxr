# SOCKS 协议帧格式（依据 upstream v26.9.30）

> 证据引用 `/home/dev/tmp/xray-core-ref` 内 Go 源码 `路径:行号`。
> 主实现：`proxy/socks/protocol.go`；服务端握手：`proxy/socks/server.go`；临时 UDP 连接：`proxy/socks/temp_udp_listen.go`。

## 1. 常量（`proxy/socks/protocol.go:17-36`）

| 名称 | 值 | 行号 |
|---|---|---|
| SOCKS5 版本 | `0x05` | `protocol.go:18` |
| SOCKS4 版本 | `0x04` | `protocol.go:19` |
| CMD CONNECT | `0x01` | `protocol.go:21` |
| CMD BIND | `0x02` | `protocol.go:22` |
| CMD UDP ASSOCIATE | `0x03` | `protocol.go:23` |
| CMD TorResolve | `0xF0` | `protocol.go:24` |
| CMD TorResolvePTR | `0xF1` | `protocol.go:25` |
| SOCKS4 GRANTED / REJECTED | `90` / `91` | `protocol.go:27-28` |
| AUTH 无需认证 | `0x00` | `protocol.go:30` |
| AUTH 用户名密码 | `0x02` | `protocol.go:32` |
| AUTH 无匹配方法 | `0xFF` | `protocol.go:33` |
| 状态 SUCCESS | `0x00` | `protocol.go:35` |
| 状态 命令不支持 | `0x07` | `protocol.go:36` |

## 2. 地址类型映射（**与 VLESS 不同**）

`addrParser = NewAddressParser(AddressFamilyByte(0x01,IPv4), AddressFamilyByte(0x04,IPv6), AddressFamilyByte(0x03,Domain))`（`protocol.go:39-43`）。

| ATYP | 含义 | 地址长度 |
|---|---|---|
| `0x01` | IPv4 | 4 字节 |
| `0x04` | IPv6 | 16 字节 |
| `0x03` | 域名 | 1 字节长度 + N 字节 |

未传 `PortThenAddress`，故解析器为 **portLast：先地址、后 2 字节大端端口**（`common/protocol/address.go:55-75, 117-146`）。

## 3. 顶层握手分流（`Handshake`，`protocol.go:230-256`）

先读 2 字节 `[version, cmd]`；`version==0x04` 走 SOCKS4，`version==0x05` 走 SOCKS5；其他报 `unknown Socks version`。

## 4. SOCKS5

### 4.1 方法协商（`auth5`，`protocol.go:101-141`）

```
客户端 -> 服务端:  VER(1)=0x05  NMETHODS(1)  METHODS(NMETHODS)
服务端 -> 客户端:  VER(1)=0x05  METHOD(1)
```

- 服务端读取 `NMETHODS` 字节方法列表（`protocol.go:105-107`）。
- 期望方法：配置 `auth=noauth` → `0x00`；`auth=password` → `0x02`（`protocol.go:109-113`）。
- 若列表不含期望方法，回 `{0x05, 0xFF}` 并报 `no matching auth method`（`protocol.go:114-118`）。
- 否则回 `{0x05, expectedAuth}`（`protocol.go:120-122`）。

### 4.2 用户名/密码认证（RFC 1929 子协商，`protocol.go:124-138, 258-286`）

```
客户端 -> 服务端:  VER(1)=0x01  ULEN(1)  UNAME(ULEN)  PLEN(1)  PASSWD(PLEN)
服务端 -> 客户端:  VER(1)=0x01  STATUS(1)     ; 0x00 成功 / 0xFF 失败
```

`ReadUsernamePassword` 读取布局（`protocol.go:258-286`）。失败时服务端回 `{0x01, 0xFF}`（`protocol.go:135-136`），成功回 `{0x01, 0x00}`（`protocol.go:138`）。

### 4.3 请求（`handshake5`，`protocol.go:143-227`）

```
VER(1)=0x05  CMD(1)  RSV(1)=0x00  <ADDR: ATYP+地址+端口>
```

- 服务端读 3 字节，仅取 `cmd=buffer.Byte(1)`（`protocol.go:155-163`；未校验 VER 与 RSV）。
- 命令映射（`protocol.go:165-183`）：

| CMD | 行为 |
|---|---|
| `0x01` CONNECT / `0xF0` TorResolve / `0xF1` TorResolvePTR | 映射为 `RequestCommandTCP`（Tor 命令当作 CONNECT 处理，`protocol.go:167-170`） |
| `0x03` UDP ASSOCIATE | 若 `udp` 未启用，回 `{0x05,0x07,0x00,...}` 并报 `UDP is not enabled.`；否则映射 `RequestCommandUDP`（`protocol.go:171-177`） |
| `0x02` BIND | 回 `statusCmdNotSupport` 并报 `TCP bind is not supported.`（`protocol.go:178-180`） |
| 其他 | 回 `statusCmdNotSupport` 并报 `unknown command`（`protocol.go:181-183`） |

- 随后读地址与端口（`protocol.go:187-192`）。

### 4.4 响应（`writeSocks5Response`，`protocol.go:320-330`）

```
VER(1)=0x05  REP(1)  RSV(1)=0x00  <ADDR: ATYP+地址+端口>
```

- 成功用 `statusSuccess=0x00`（`protocol.go:221`）。
- UDP ASSOCIATE 成功时的绑定地址：若配置了服务端 `ip` 则用它，否则用 TCP 连接本地地址；端口为新建 UDP socket 的本地端口（`protocol.go:194-221`）。

### 4.5 UDP ASSOCIATE 数据帧（`DecodeUDPPacket`/`EncodeUDPPacket`，`protocol.go:344-390`）

```
RSV(2)=0x00 0x00  FRAG(1)=0x00  ATYP(1)  地址  端口(2,大端)  DATA...
```

- 解码：包长 <5 报错；`packet[2]`(FRAG) 非 0 则丢弃（不支持分片）（`protocol.go:344-366`）。
- 编码：先写 `{0,0,0}`，再写地址+端口，再写数据；若数据超 `buf.Size` 则返回空 buffer（丢弃过大包）（`protocol.go:369-390`）。
- UDP 关联的期望远端：请求地址为域名或未指定 IP 时，取 TCP 连接远端 IP；否则用请求 IP 与端口（端口 0 合法）（`protocol.go:203-213`）。
- `TempUDPConn` 将 UDP hub 与 TCP 连接绑定，TCP 关闭时一并关闭（`temp_udp_listen.go:12-72`）。

### 4.6 客户端握手（`ClientHandshake`，`protocol.go:441-535`）

1. 发 `{0x05, 0x01, authByte}`；`authByte`=`0x00`（无用户）或 `0x02`（有用户）（`protocol.go:442-452`）。
2. 读 2 字节，校验 VER=0x05 与 METHOD 一致（`protocol.go:455-464`）。
3. 若 `authByte==0x02`，按 RFC 1929 发送子协商（`protocol.go:466-484`）。
4. 发请求：`{0x05, command, 0x00}`；UDP 时地址固定写 `{1,0,0,0,0,0,0}`（即 `0.0.0.0:0`，`protocol.go:487-499`）。
5. 读 3 字节响应头，`REP!=0` 报错；再读绑定地址+端口（`protocol.go:501-516`）。
6. UDP 时返回服务端 UDP 端点；TCP 返回 `nil, nil`（`protocol.go:518-528`）。

## 5. SOCKS4 / SOCKS4a（`handshake4`，`protocol.go:52-99`）

```
VER(1)=0x04  CMD(1)  DSTPORT(2,大端)  DSTIP(4)  USERID(NUL 结尾)  [SOCKS4a 域名(NUL 结尾)]
```

- 若配置要求密码认证，直接拒绝（`socks 4 is not allowed when auth is required.`，`protocol.go:53-56`）。
- 读 6 字节：`port = bytes[0:2]`，`address = bytes[2:6]`（`protocol.go:61-69`）。
- 读 NUL 结尾的 userid（`ReadUntilNull`，`protocol.go:288-314`）。
- SOCKS4a：若 IP 首字节为 `0x00`，再读 NUL 结尾域名并按域名解析（`protocol.go:75-81`）。
- 仅支持 CMD CONNECT(`0x01`)（`protocol.go:83-97`）。
- 响应（`writeSocks4Response`，`protocol.go:332-342`）：`VN(1)=0x00  CD(1)=90/91  DSTPORT(2)  DSTIP(4)`。注意首字节写 `0x00` 而非 `0x04`。

## 6. 服务端配置字段（`infra/conf/socks.go:30-36`）

| 字段 | 类型 | 说明 / 默认 |
|---|---|---|
| `auth` | string | `noauth` / `password`；**其他值默认 noauth**（`socks.go:42-49`） |
| `users` / `accounts` | `[]{user,pass}` | `accounts` 覆盖 `users`（`socks.go:51-53`） |
| `udp` | bool | 是否允许 UDP ASSOCIATE |
| `ip` | Address | UDP ASSOCIATE 响应中返回的 IP |
| `userLevel` | uint32 | 策略级别 |

入站协议名别名：`socks` 与 `mixed` 共用 `SocksServerConfig`（`infra/conf/xray.go:29-30`）。