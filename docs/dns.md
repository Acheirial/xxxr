# DNS 规格（依据 upstream v26.9.30）

> 证据引用 `/home/dev/tmp/xray-core-ref` 内 Go 源码 `路径:行号`。
> 主要实现：`app/dns/{dns,nameserver,hosts,nameserver_*}.go`；配置：`infra/conf/dns.go`；出站：`proxy/dns/dns.go` + `infra/conf/dns_proxy.go`。

## 0. 对任务假设的更正

1. **不存在 `staticHosts` JSON 字段**：JSON 侧只有 `hosts`（对象，`infra/conf/dns.go:162`）与 `useSystemHosts`（bool，`dns.go:171`）。`StaticHosts` 是 protobuf 内部字段名（`config.StaticHosts`，`infra/conf/dns.go:361-372`），非用户 JSON 键。
2. **不存在 `dns` 入站**：出站加载器含 `"dns"`（`infra/conf/xray.go:54`），入站加载器**不含**（`infra/conf/xray.go:24-39`）。`dns` 仅可作为 `outbounds[].protocol`。
3. **不存在 `dnsOutboundTag` 配置字段**：全仓库 grep `dnsOutboundTag` / `dnsOutbound` / `DNSOutboundTag` 无命中。DNS 走哪个出站由**路由规则**决定（见 §7）。
4. **DNS 服务器地址不支持的 scheme**：`udp://`、`dhcp://`、远程 `quic://`、`geosite:` 形式均**未实现**（`app/dns/nameserver.go:52-80` 的完整 switch）。支持列表见 §4。

---

## 1. 顶层 `dns` 配置块（`infra/conf/dns.go:160-172`）

| JSON 字段 | Go 类型 | 默认 | 说明 |
|---|---|---|---|
| `servers` | `[]*NameServerConfig` | — | DNS 服务器列表 |
| `hosts` | `HostsWrapper`（对象） | — | 静态 hosts 映射 |
| `clientIp` | Address | — | 全局 EDNS Client Subnet IP |
| `tag` | string | — | DNS 出站标签（缺省时随机生成 `xray.system.<uuid>`，`app/dns/config.go:35-38`、`app/dns/dns.go:88-91`） |
| `queryStrategy` | string | `UseIP` | 见 §3 |
| `disableCache` | bool | false | 全局禁用缓存 |
| `serveStale` | bool | false | 过期后仍回旧值 |
| `serveExpiredTTL` | uint32 | 0 | 过期数据最长可用秒数 |
| `disableFallback` | bool | false | 禁用未匹配域名的兜底查询 |
| `disableFallbackIfMatch` | bool | false | 有域名匹配时禁用兜底 |
| `enableParallelQuery` | bool | false | 并行查询 |
| `useSystemHosts` | bool | false | 追加读取系统 hosts 文件 |

构建：`DNSConfig.Build`（`infra/conf/dns.go:269-379`）→ `dns.Config`。

## 2. `servers[]` 字段（`NameServerConfig`，`infra/conf/dns.go:19-35`）

| 字段 | 类型 | 默认 | 说明 |
|---|---|---|---|
| `address` | Address | 必填 | 服务器地址/URL，见 §4 |
| `clientIp` | Address | — | 该服务器的 ECS IP（`dns.go:126-133`） |
| `port` | uint16 | — | 覆盖端口（`dns.go:134-137`）；`Address` 为纯 URL 时本字段由 `UnmarshalJSON` 独立承载 |
| `skipFallback` | bool | false | 跳过默认兜底（`dns.go:139`） |
| `domains` | string[] | — | 该服务器服务的域名（`Domain_Substr` 默认，`dns.go:89`） |
| `expectedIPs` | string[] | — | 期望 IP 规则；含 `"*"` 时置 `ActPrior=true`（`dns.go:95-108`） |
| `expectIPs` | string[] | — | `expectedIPs` 的**别名**：仅当 `expectedIPs` 为空时回填（`dns.go:94-96`） |
| `unexpectedIPs` | string[] | — | 排除 IP 规则；含 `"*"` 时置 `ActUnprior=true`（`dns.go:110-123`） |
| `queryStrategy` | string | 继承全局 | 见 §3 |
| `tag` | string | 继承全局 | 该服务器的出站 tag |
| `timeoutMs` | uint64 | — | 查询超时（毫秒） |
| `disableCache` | *bool | 继承全局 | 指针，可覆盖（`app/dns/dns.go:127-130`） |
| `serveStale` | *bool | 继承全局 | 同上（`dns.go:132-135`） |
| `serveExpiredTTL` | *uint32 | 继承全局 | 同上（`dns.go:137-140`） |
| `finalQuery` | bool | false | 命中此服务器后终止继续选择（`app/dns/dns.go:310-313, 320-323`） |

**简写**：`servers` 元素也可直接是字符串/对象形式的地址（`UnmarshalJSON`，`infra/conf/dns.go:37-82`）。

## 3. `queryStrategy`（`infra/conf/dns.go:381-394`）

| 配置值（多个别名） | QueryStrategy | 效果 |
|---|---|---|
| `useip` / `use_ip` / `use-ip` | `USE_IP`（默认） | v4+v6 |
| `useip4` / `useipv4` / `use_ip_v4` 等 | `USE_IP4` | 仅 v4 |
| `useip6` / `useipv6` / `use-ipv6` 等 | `USE_IP6` | 仅 v6 |
| `usesys` / `usesystem` / `use-system` 等 | `USE_SYS` | 依系统路由能力动态决定 v4/v6（`app/dns/dns.go:55-63, 245-248`） |
| 其他 | `USE_IP` | 默认 |

全局的 ipOption 建立见 `app/dns/dns.go:51-75`；服务器级覆盖 `ResolveIpOptionOverride`（`app/dns/nameserver.go:230-...`）。

## 4. 服务器地址 scheme（`app/dns/nameserver.go:47-80`）

| 地址形式 | 模式 | 说明 |
|---|---|---|
| `localhost` | Local（系统解析器） | `NewLocalNameServer`（`nameserver.go:54-55`） |
| `https://...` | DoH 远程 | 走 dispatcher 出站（`nameserver.go:56-57`） |
| `h2c://...` | DoH(h2c) 远程 | `nameserver.go:58-59` |
| `https+local://...` | DoH 本地 | 直连系统（`nameserver.go:60-61`） |
| `h2c+local://...` | DoH(h2c) 本地 | `nameserver.go:62-63` |
| `quic+local://...` | DoQ 本地 | 仅本地（**无远程 quic 模式**，`nameserver.go:64-65`） |
| `tcp://host:port` | DoT 远程 | 走 dispatcher（`nameserver.go:66-67`） |
| `tcp+local://...` | DoT 本地 | `nameserver.go:68-69` |
| `fakedns` | FakeDNS | 需 FakeDNS 引擎（`nameserver.go:70-77`） |
| 纯 IP（无 scheme） | UDP 经典 DNS | 默认 `Network_UDP`（`nameserver.go:79-84`） |

**不支持**：`udp://` 显式 scheme（UDP 是「无 scheme 的默认」）、`dhcp://`、远程 `quic://`、`geosite:`。

### 4.1 `localhost` 的特殊路由优先级
本地 DNS 服务器会额外获得一组「本地 TLD / 无点域名」规则（`app/dns/config.go:13-23`：无点域名、`local`、`localdomain`、`localhost`、`lan`、`home.arpa`、`example`、`invalid`、`test`），由 `updateRules(isLocalNameServer)` 注入（`app/dns/dns.go:100-113`）。

## 5. `hosts`（静态映射）

- JSON：`hosts` 为对象 `{ "<域名规则>": <IP|域名|数组> }`（`HostsWrapper`，`infra/conf/dns.go:207-253`）。
- 值可为单个地址、地址数组；**若为域名则作为「域名替换」(ProxiedDomain)**（`newHostMapping`，`infra/conf/dns.go:211-234`）。
- 键按 `ParseDomainRule(rule, Domain_Full)` 解析——**默认精确匹配（Full）**，也可写 `domain:` / `keyword:` / `regexp:`（`infra/conf/dns.go:254-266`；`common/geodata/rule_parser.go:226-260`）。
- 合成 proto `Config_HostMapping`（`Domain` + `Ip` 或 `ProxiedDomain`）。

### 5.1 与 routing 的交互
静态 hosts 命中时：域名替换会改写查询域名并记录日志；命中 IP 直接返回、TTL 固定为 **10**（`app/dns/dns.go:276-286`，`return ips, 10, nil`）。即 hosts 命中的域名**不经过 DNS 服务器与出站**，因此不会被路由到远程解析。

### 5.2 `useSystemHosts`
读取系统 hosts：Windows 为 `%SystemRoot%\System32\drivers\etc\hosts`，其他为 `/etc/hosts`（`infra/conf/dns.go:396-412`）；解析规则见 `readSystemHostsFrom`（`dns.go:414-455`），每条按 `Domain_Full` 建映射。

## 6. 服务器选择与查询流程（`app/dns/dns.go`）

`LookupIP`（`app/dns/dns.go:238-287`）顺序：
1. 规范化域名（去尾点），空则报错（`dns.go:240-244`）。
2. 依 queryStrategy/系统能力裁剪 v4/v6（`dns.go:245-253`）；两者皆禁用报 `ErrEmptyResponse`。
3. **静态 hosts 查找**：命中则返回（TTL=10 或域名替换）（`dns.go:256-286`）。
4. 名称服务器查询：`enableParallelQuery ? parallelQuery : serialQuery`（`dns.go:282-286`）。

### 6.1 `sortClients`（`app/dns/dns.go:289-341`）
- 先按域名匹配（`domainMatcher.Match`，索引升序）挑选，命中服务器按索引顺序加入，`finalQuery` 命中即返回（`dns.go:294-317`）。
- 未匹配或未禁用兜底时，按配置顺序追加**未被选中且 `skipFallback=false`** 的服务器（`dns.go:319-331`）。
- 结果为空时回退到第一个服务器并告警（`dns.go:333-340`）。

### 6.2 `serialQuery` / `parallelQuery`
- 串行：逐个查询，任一有 IP 即返回；`FakeEnable=false` 时跳过 FakeDNS 服务器（`app/dns/dns.go:385-406`）。
- 并行：`asyncQueryAll` 并发查询；`makeGroups` 将**相邻且 policyID 相同**的服务器分为一组，组内竞速取最快成功，组全失败才进入下一组（`app/dns/dns.go:408-496`）。
- 错误归并 `mergeQueryErrors`：忽略 `errRecordNotFound`（服务器无响应），全 `ErrEmptyResponse` 则返回 `ErrEmptyResponse`（`app/dns/dns.go:365-383`）。
- 缓存：`serveStale` 时若缓存过期但 `serveExpiredTTL==0` 或小于 ttl 仍可回旧值（`app/dns/nameserver_cached.go:35-36`）。

### 6.3 `expectIPs` / `unexpectedIPs` 过滤（`app/dns/nameserver.go:195-226`）

服务器返回结果后按 matcher 过滤：
- `expectedIPs` 且 `actPrior=false`：仅保留命中项，若为空报 `ErrEmptyResponse`（`nameserver.go:195-201`）。
- `unexpectedIPs` 且 `actUnprior=false`：剔除命中项，若为空报 `ErrEmptyResponse`（`nameserver.go:203-210`）。
- `expectedIPs` 且 `actPrior=true`（列表含 `"*"`）：若有命中项则**仅保留命中项**（优先），否则保持原结果（`nameserver.go:211-218`）。
- `unexpectedIPs` 且 `actUnprior=true`（列表含 `"*"`）：若有非命中项则保留非命中项（降级），否则保持原结果（`nameserver.go:219-226`）。

超时默认 4000ms，可由 `timeoutMs` 覆盖（`app/dns/nameserver.go:138-140`）；查询 ctx 会带上该服务器的 tag 作为 inbound tag（`nameserver.go:183`），供路由/出站识别。

## 7. DNS 查询走哪个出站

**没有 `dnsOutboundTag` 之类的直接配置。** 实际机制：
- 名称服务器（DoH/DoT/经典 UDP）把查询交给 **dispatcher**（`routing.Dispatcher`），即进入全局路由决策：
  - UDP 经典：`udp.NewDispatcher(dispatcher, ...)` + `Dispatch`（`app/dns/nameserver_udp.go:56, 134, 192`）。
  - TCP：`dispatcher.Dispatch(toDnsContext(...), destination)`（`app/dns/nameserver_tcp.go:44`）。
  - DoH：`dispatcher.Dispatch(dnsCtx, dest)`（`app/dns/nameserver_doh.go:62-68`）。
  - `+local` 变体与 `tcp` 的本地回退使用 `internet.DialSystem`（`app/dns/nameserver_tcp.go:67`、`nameserver_doh.go:96`）。
- 因此「DNS 走哪个出站」由 `routing.rules` 对**DNS 服务器目标地址**（或该 DNS 的 tag）的匹配决定；也可用 `streamSettings.sockopt.dialerProxy` 链式代理。
- 影响 DNS 解析时机的路由策略是 `domainStrategy`（`IpIfNonMatch` / `IpOnDemand`），见 `docs/sniffing-and-routing.md` §二.1.3。

## 8. `dns` 出站（`protocol: "dns"`）

用于处理**客户端发给 Xray 的 DNS 查询**（如 dokodemo/tun 转发的 53 端口流量），而非上游递归。

配置：`DNSOutboundConfig`（`infra/conf/dns_proxy.go:60-70`）：`network`、`address`、`port`、`rewriteNetwork`、`rewriteAddress`、`rewritePort`、`userLevel`、`rules[]`、`nonIPQuery`(废弃)、`blockTypes`(废弃)。旧字段与 `rules` 互斥（`infra/conf/dns_proxy.go:96-110`）。

规则 `rules[]`（`DNSOutboundRuleConfig`，`infra/conf/dns_proxy.go:13-18`）：`action`、`qType`(PortList)、`domain`(StringList)、`rCode`。`action` 映射（`infra/conf/dns_proxy.go:24-34`）：

| action | 行为 |
|---|---|
| `direct` | 转发到 `rewriteServer`（`proxy/dns/dns.go:283-285`） |
| `drop` | 直接丢弃（`proxy/dns/dns.go:265-267`） |
| `return` | 返回 rCode，不解析（`proxy/dns/dns.go:268-274`） |
| `hijack` | 用本地 DNS 客户端解析 A/AAAA 并构造应答（`proxy/dns/dns.go:275-282`，仅 A/AAAA） |

处理逻辑：`Handler.Process`（`proxy/dns/dns.go:155-311`）；`applyRules`（`proxy/dns/dns.go:141-153`）；`handleIPQuery`（`proxy/dns/dns.go:313-...`）用 `h.client.LookupIP(..., FakeEnable:true)` 解析并写回 DNS 报文。`IsOwnLink` 防止自环（`proxy/dns/dns.go:74-81, 130-132`；`app/dns/dns.go:207-216`）。

## 9. FakeDNS 服务器

`fakedns` 地址形式（`app/dns/nameserver.go:70-77`）→ `FakeDNSServer`（`app/dns/nameserver_fakedns.go:12-51`）：`Name()=="FakeDNS"`，查询返回 fake IP，TTL=1（`nameserver_fakedns.go:44-50`）。`FakeEnable=false` 时查询流程会跳过它（`app/dns/dns.go:390-392, 470-473`）。

## 10. 未确认项

- `PolicyID` 对并分组的具体语义已从 `makeGroups` 确认（相邻且 policyID 相同才合并），但 JSON 层未暴露该字段，仅为内部去重键（`infra/conf/dns.go:288-338`、`app/dns/dns.go:535-...`）。