# Xray-core JSON 配置 schema（依据 upstream v26.9.30）

> 证据均引用 `/home/dev/tmp/xray-core-ref` 内 Go 源码 `路径:行号`。
> 字段名 = JSON tag；类型 = Go 类型；「默认」来自 `Build()` 中的赋值。未在源码出现者标注「未确认」。

## 0. 顶层 `Config`

定义：`infra/conf/xray.go:402-421`。

| JSON 字段 | Go 类型 | 必填 | 说明 / 默认 |
|---|---|---|---|
| `transport` | `map[string]json.RawMessage` | 否 | **已废弃**。非空时报 `PrintRemovedFeatureError`（`xray.go:674`） |
| `env` | `map[string]string` | 否 | 启动时 `os.Setenv` 注入（`xray.go:507-511`） |
| `log` | `LogConfig` | 否 | 缺省用 `DefaultLogConfig()`（`xray.go:586-590`） |
| `routing` | `RouterConfig` | 否 | 路由规则/负载均衡 |
| `dns` | `DNSConfig` | 否 | DNS app（`infra/conf/dns.go`） |
| `inbounds` | `[]InboundDetourConfig` | 否 | 入站列表 |
| `outbounds` | `[]OutboundDetourConfig` | 否 | 出站列表 |
| `policy` | `PolicyConfig` | 否 | `policy.go`；`levels{ handshake, connIdle, uplinkOnly, downlinkOnly, statsUserUplink, statsUserDownlink, statsUserOnline, bufferSize }`、`system{ statsInboundUplink, statsInboundDownlink, statsOutboundUplink, statsOutboundDownlink }`（`policy.go`） |
| `api` | `APIConfig` | 否 | `{ tag, listen, services[] }`（`api.go`） |
| `metrics` | `MetricsConfig` | 否 | `metrics.go` |
| `stats` | `StatsConfig` | 否 | 空对象 `{}`（`xray.go:387-392`） |
| `reverse` | `ReverseConfig` | 否 | **已废弃**：非空即报错指向 "VLESS Reverse Proxy"（`xray.go:619`） |
| `fakeDns` | `FakeDNSConfig` | 否 | `fakedns.go` |
| `observatory` | `ObservatoryConfig` | 否 | `observatory.go` |
| `burstObservatory` | `BurstObservatoryConfig` | 否 | `observatory.go` |
| `version` | `VersionConfig` | 否 | `{ min, max }`（`version.go:10-25`） |
| `geodata` | `GeodataConfig` | 否 | `geodata.go` |

App 装配顺序见 `xray.go:543-700`：`log` 始终插到最前（`xray.go:592`），然后 `dispatcher/proxyman(inbound/outbound)`；`fakeDns` 插到最前。

## 1. `log`

定义：`infra/conf/log.go:18-24`；默认：`log.go:10-16`。

| 字段 | 类型 | 默认 | 说明 |
|---|---|---|---|
| `access` | string | `""` → 控制台 | 特殊值 `"none"` 关闭；其他值为文件路径 |
| `error` | string | `""` → 控制台 | 同上 |
| `loglevel` | string | `"warning"` | 可选 `debug` / `info` / `warning`(默认) / `error` / `none`。`none` 同时关闭 error+access（`log.go:49-58`） |
| `dnsLog` | bool | `false` | 映射到 `EnableDnsLog` |
| `maskAddress` | string | `""` | 日志地址掩码 |

默认（无 `log` 段）：AccessLog=关闭(`LogType_None`)、ErrorLog=控制台、级别=`Warning`（`log.go:10-16`）。

## 2. 入站 `inbounds[]`

定义：`infra/conf/xray.go:130-138`；构建：`xray.go:141-215`。

| 字段 | 类型 | 必填 | 说明 / 默认 |
|---|---|---|---|
| `protocol` | string | 是 | 见 §4 协议名 |
| `port` | `PortList` | 条件* | 可为 `443`、`"443"`、`"1-65535"`、`"1,2,3"`、`"env:PORT"`（`common.go:215-273`） |
| `listen` | `Address` | 否 | 默认 AnyIP；可为 IP、`localhost`、绝对路径 / `@` 前缀的 Unix socket |
| `settings` | object | 否 | 协议专属，缺省 `{}` |
| `tag` | string | 否 | 唯一标识 |
| `streamSettings` | `StreamConfig` | 否 | 见 `transport-schema.md` |
| `sniffing` | `SniffingConfig` | 否 | 见下 |

*`tun` 协议不需要 `port`（`xray.go:145-147`）；监听 AnyIP 时必须提供 `port`，监听具体 IP 时也必须有 `port`（`xray.go:148-177`）。

`SniffingConfig`（`xray.go:59-66`）：`enabled`(bool)、`destOverride`(string[]，取值 `http` / `tls|https|ssl` / `quic` / `fakedns|fakedns+others`)、`domainsExcluded`(string[])、`ipsExcluded`(string[])、`metadataOnly`(bool)、`routeOnly`(bool)。

## 3. 出站 `outbounds[]`

定义：`infra/conf/xray.go:220-228`；构建：`xray.go:255-383`。

| 字段 | 类型 | 必填 | 说明 / 默认 |
|---|---|---|---|
| `protocol` | string | 是 | 见 §4 |
| `sendThrough` | string | 否 | 源 IP；支持 `ip/cidr`；域名只允许 `origin` / `srcip`（`xray.go:288-302`） |
| `tag` | string | 否 | 唯一标识 |
| `settings` | object | 否 | 协议专属，缺省 `{}` |
| `streamSettings` | `StreamConfig` | 否 | 见 `transport-schema.md` |
| `proxySettings` | object | 否 | **已移除**，报错指向 `streamSettings.sockopt.dialerProxy`（`xray.go:268`） |
| `mux` | `MuxConfig` | 否 | 多路复用，见下 |
| `targetStrategy` | string | 否 | 默认 `"AsIs"`。可选（大小写不敏感）：`AsIs`/空、`UseIP`、`UseIPv4`、`UseIPv6`、`UseIPv4v6`、`UseIPv6v4`、`ForceIP`、`ForceIPv4`、`ForceIPv6`、`ForceIPv4v6`、`ForceIPv6v4`（`xray.go:272-286`） |

`MuxConfig`（`xray.go:106-111`，构建 `xray.go:114-128`）：`enabled`(bool)、`concurrency`(int16，`<0` 完全禁用)、`xudpConcurrency`(int16)、`xudpProxyUDP443`(string，默认 `"reject"`，可选 `reject|allow|skip`)。

出站约束（`xray.go:242-252` 定义校验、`xray.go:343-380` 调用与 masque/freedom 检查）：
- VLESS/Trojan 未启用 TLS/加密且目标非私网地址时禁止（`validateOutboundTransportSecurity`）。
- `masque` 出站不支持 `mux`；`masque` 传输只能由 masque 出站使用。
- `freedom` 出站不支持 `sockopt.addressPortStrategy`；`freedom.domainStrategy` 已废弃，自动迁移到 `sockopt.domainStrategy`。

## 4. 协议名清单（来自加载器映射）

### 入站 `inboundConfigLoader`（`xray.go:24-39`）
| `protocol` | 实现配置类型 | 源码 |
|---|---|---|
| `dokodemo-door`、别名 `tunnel` | `DokodemoConfig` | `dokodemo.go` |
| `http` | `HTTPServerConfig` | `http.go` |
| `shadowsocks` | `ShadowsocksServerConfig` | `shadowsocks.go` |
| `socks`、别名 `mixed` | `SocksServerConfig` | `socks.go` |
| `vless` | `VLessInboundConfig` | `vless.go` |
| `vmess` | `VMessInboundConfig` | `vmess.go` |
| `trojan` | `TrojanServerConfig` | `trojan.go` |
| `wireguard` | `WireGuardConfig{IsClient:false}` | `wireguard.go` |
| `hysteria` | `HysteriaServerConfig` | `hysteria.go` |
| `masque` | `MasqueServerConfig` | `masque.go` |
| `tun` | `TunConfig` | `tun.go` |

### 出站 `outboundConfigLoader`（`xray.go:40-57`）
| `protocol` | 实现配置类型 | 源码 |
|---|---|---|
| `blackhole`、别名 `block` | `BlackholeConfig` | `blackhole.go` |
| `loopback` | `LoopbackConfig` | `loopback.go` |
| `freedom`、别名 `direct` | `FreedomConfig` | `freedom.go` |
| `http` | `HTTPClientConfig` | `http.go` |
| `shadowsocks` | `ShadowsocksClientConfig` | `shadowsocks.go` |
| `socks` | `SocksClientConfig` | `socks.go` |
| `vless` | `VLessOutboundConfig` | `vless.go` |
| `vmess` | `VMessOutboundConfig` | `vmess.go` |
| `trojan` | `TrojanClientConfig` | `trojan.go` |
| `hysteria` | `HysteriaClientConfig` | `hysteria.go` |
| `masque` | `MasqueClientConfig` | `masque.go` |
| `dns` | `DNSOutboundConfig` | `dns_proxy.go:60` |
| `wireguard` | `WireGuardConfig{IsClient:true}` | `wireguard.go` |

注：入站无 `dns`；出站无 `dokodemo-door`/`dns` 入站形态。`shadowsocks_2022` 无独立配置名，通过 `method` 选择。

### 4.1 各协议 `settings` 关键字段

**dokodemo-door**（`dokodemo.go`）：`address`、`port`、`network`(NetworkList，默认 tcp,udp)、`allowedNetwork`、`rewriteAddress`、`rewritePort`、`portMap`(map)、`followRedirect`(bool)、`userLevel`(uint32)。

**http**（`http.go`）：服务端 `users[]/accounts[]{user,pass}`、`allowTransparent`(bool)、`userLevel`；客户端 `address,port,level,email,user,pass,servers[]{address,port,users}`、`headers`(map)。

**shadowsocks**（`shadowsocks.go`）：服务端 `method,password,level,email,users/clients[]{method,password,level,email,address,port},network`；客户端 `address,port,level,email,method,password,servers[]{address,port,level,email,method,password}`。

**socks**（`socks.go:13-83`）：服务端 `auth`(string)、`users/accounts[]{user,pass}`、`udp`(bool)、`ip`(Address)、`userLevel`；客户端 `address,port,level,email,user,pass,servers[]{address,port,users}`。

**vmess**（`vmess.go`）：用户 `{id,security,experiments}`；入站 `users/clients,default{level}`；出站 `address,port,level,email,id,security,experiments,vnext[]`。

**vless**（`vless.go:33-39, 245-259`）：入站 `users/clients[]{id,flow,encryption(禁止),level,email,reverse,testseed}`, `decryption`, `fallbacks[]{name,alpn,path,type,dest,xver}`, `flow`, `testseed[]`；出站简化式 `address,port,level,email,id,flow,seed,encryption,reverse,testpre,testseed,vnext[]`。详见 `vless-protocol.md`。

**trojan**（`trojan.go`）：服务端 `users/clients[]{password,level,email,flow}`、`fallbacks[]{name,alpn,path,type,dest,xver}`；客户端 `address,port,level,email,password,flow,servers[]{...}`。

**freedom**（`freedom.go:19-53, 55-231`）：`targetStrategy`、`domainStrategy`(废弃)、`redirect`(host:port)、`userLevel`、`fragment{packets,length{lo-hi},interval,maxSplit}`、`noises[]{type(rand|str|hex|base64),packet,delay,applyTo(ip|ipv4|ipv6)}`、`proxyProtocol`(0-2)、`ipsBlocked`、`finalRules[]{action(allow|block),network,port,ip,blockDelay}`。`noise`(单数) 已移除。

**blackhole**（`blackhole.go`）：`response{type,customResponseData}`。

**loopback**（`loopback.go`）：`inboundTag`、`sniffing`。

**dns 出站**（`dns_proxy.go:60-70`）：`network`、`address`、`port`、`rewriteNetwork`、`rewriteAddress`、`rewritePort`、`userLevel`、`rules[]`、`nonIPQuery`(废弃)、`blockTypes`(废弃)。旧字段与新 `rules` 互斥（`dns_proxy.go:96-110`）。

**wireguard**（`wireguard.go`）：`noKernelTun`(bool)、`secretKey`、`address[]`、`peers[]{publicKey,preSharedKey,endpoint,keepAlive,allowedIPs,level,email}`、`mtu`、`reserved[]byte`、`remoteDNS`(DNS[])。

**hysteria**（`hysteria.go`）：客户端 `version,address,port`；服务端 `version,users/clients[]{auth,level,email}`。

**masque**（`masque.go`）：客户端 `address,port,remoteDNS`；服务端 `users/clients[]{pass,level,email},address[],mtu`。

**tun**（`tun.go`）：`name,desc,mtu,gateway[],dns[],userLevel,autoSystemRoutingTable[],autoOutboundsInterface,autoSystemDnsToGateway,autoSystemWfpBlockLeak[]`。

## 5. 路由 `routing`

定义：`infra/conf/router.go:71-75`。

| 字段 | 类型 | 默认 | 说明 |
|---|---|---|---|
| `domainStrategy` | string | `"AsIs"` | 可选 `AsIs`(默认)、`IPIfNonMatch`、`IPOnDemand`，大小写不敏感（`router.go:77-91`） |
| `rules` | array | — | 规则列表，见下 |
| `balancers` | array | — | 负载均衡器 |

### 5.1 规则 `rules[]`

外层公共字段（`RouterRule`，`router.go:120-124`）：`ruleTag`、`outboundTag`（与 `balancerTag` 二选一，必填其一，否则报错 `router.go:168-177`）、`balancerTag`。

字段规则（`RawFieldRule`，`router.go:133-153`）：

| 字段 | 类型 | 说明 |
|---|---|---|
| `domain` / `domains` | string[] | 两者等价，后者覆盖前者；支持 `geosite:`/`ext:`/`regexp:`/`domain:`/`full:` 等前缀 |
| `ip` | string[] | IP 规则，支持 `geoip:`/CIDR/`ext:` |
| `port` | `PortList` | 目标端口 |
| `network` | `NetworkList` | 取值 `tcp`/`udp`/`tcp,udp` |
| `sourceIP` / `source` | string[] | 两者等价，`source` 作回退 |
| `sourcePort` | `PortList` | 源端口 |
| `localIP` | string[] | 本机 IP |
| `localPort` | `PortList` | 本机端口 |
| `user` | string[] | 用户 email 列表 |
| `vlessRoute` | `PortList` | VLESS 路由 |
| `inboundTag` | string[] | 入站 tag |
| `protocol` | string[] | 嗅探协议 |
| `attrs` | map[string]string | 属性匹配（`len>0` 才生效） |
| `process` | string[] | 进程名（`len>0`） |
| `localOS` | string[] | 本机操作系统（`len>0`） |
| `webhook` | object | `{url, deduplication, headers}`，`url` 非空才生效（`router.go:126-131`） |

解析映射细节见 `router.go:155-274`。

### 5.2 负载均衡 `balancers[]`

`BalancingRule`（`router.go:21-26`）：`tag`(必填非空)、`selector`(string[]，必填非空)、`strategy{type,settings}`、`fallbackTag`。
- `strategy.type` 可选：`random`(默认)、`leastLoad`、`leastPing`、`roundRobin`，大小写不敏感（`router.go:39-48`）。

## 6. 已删除 / 禁止的配置（Rust 重写应直接拒绝）

| 配置 | 错误指向 | 证据 |
|---|---|---|
| 顶层 `transport` | `streamSettings in inbounds and outbounds` | `xray.go:674` |
| 顶层 `reverse`（旧 `reverse`） | `VLESS Reverse Proxy` | `xray.go:619` |
| 出站 `proxySettings` | `streamSettings.sockopt.dialerProxy` | `xray.go:268` |
| TLS `allowInsecure` | `pinnedPeerCertSha256`/`verifyPeerCertByName` | `transport_security.go:362` |
| freedom `noise`（单数） | `noises = [ ... ]` | `freedom.go:146` |
| `security: "xtls"` | `xtls-rprx-vision with TLS or REALITY` | `transport_internet.go:120` |
| `network: "http"` / `"quic"` | XHTTP | `transport_internet.go:33-36` |