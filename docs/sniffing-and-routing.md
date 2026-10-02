# Sniffing 与 Routing 规格（依据 upstream v26.9.30）

> 证据引用 `/home/dev/tmp/xray-core-ref` 内 Go 源码 `路径:行号`。

# 一、Sniffing

## 1. 配置 → 运行时映射

`SniffingConfig`（`infra/conf/xray.go:59-66`）字段：`enabled`、`destOverride`、`domainsExcluded`、`ipsExcluded`、`metadataOnly`、`routeOnly`。
构建：`SniffingConfig.Build`（`infra/conf/xray.go:69-104`）。

`destOverride` 取值映射（`xray.go:72-82`，大小写不敏感）：

| 配置值 | 归一化协议名 |
|---|---|
| `http` | `http` |
| `tls` / `https` / `ssl` | `tls` |
| `quic` | `quic` |
| `fakedns` / `fakedns+others` | `fakedns` |
| 其他 | 报错 `unknown protocol` |

- `domainsExcluded` → `geodata.ParseDomainRules(..., Domain_Substr)`（**子串匹配**，见 §三）（`xray.go:86-89`）。
- `ipsExcluded` → `geodata.ParseIPRules`（`xray.go:91-94`）。
- 结果 `proxyman.SniffingConfig` → `proxyman.BuildSniffingRequest` → `session.SniffingRequest`（`app/proxyman/config.go:8-34`）；字段定义见 `common/session/session.go:78-86`。
- 入站装配：`app/proxyman/inbound/always.go:56`。

## 2. 嗅探器集合与调度

`NewSniffer` 注册顺序（`app/dispatcher/sniffer.go:36-57`）：
1. HTTP（TCP）
2. TLS（TCP）
3. BitTorrent（TCP）
4. QUIC（UDP）
5. uTP/BitTorrent（UDP）
6. FakeDNS（元数据嗅探器，若启用）
7. `fakedns+others`（若启用，插到最前）

每个嗅探器返回 `common.ErrNoClue`（不匹配但可能后续匹配）、`protocol.ErrProtoNeedMoreData`（已匹配但需更多数据）或 `nil`+结果（`sniffer.go:59-110`）。`SniffMetadata` 只跑元数据嗅探器（`sniffer.go:88-113`）。

`sniffer()` 驱动逻辑（`app/dispatcher/default.go:378-437`）：
- 先跑 `SniffMetadata`；`metadataOnly=true` 时直接返回元数据结果。
- 否则循环缓存 payload（初始 200ms 预算），最多 2 次「无进展」尝试；遇 `ErrProtoNeedMoreData` 不计数继续读；超时/无果返回 `errSniffingTimeout`。
- 内容与元数据都成功时返回 `CompositeResult(metadata, content)`（`default.go:431-433`、`sniffer.go:115-136`）。

## 3. 各协议嗅探的字节偏移与边界

### 3.1 TLS — `common/protocol/tls/sniff.go`

`SniffTLS`（`sniff.go:132-153`）：
- 需要 `len(b) >= 5`；否则 `ErrNoClue`。
- `b[0] == 0x16`（TLS Handshake），否则 `errNotTLS`。
- `IsValidTLSVersion(b[1], b[2])`：要求 major `== 3`（`sniff.go:28-30`）。
- `headerLen = BE(b[3:5])`；`5+headerLen > len(b)` → `ErrNoClue`（等待更多数据）。
- 对 `b[5:5+headerLen]` 调 `ReadClientHello`。

`ReadClientHello`（`sniff.go:34-129`）：
- 需 `len >= 42`；`sessionIDLen = data[38]`，要求 `<=32` 且数据足够（`sniff.go:35-42`）。
- 跳过 sessionID、2 字节 cipherSuiteLen（偶数校验）、压缩方法长度，得 extensions 区（`sniff.go:48-61`）。
- 遍历扩展：找 `extension == 0x00`（server_name），解析 `serverNameList`，取 `nameType == 0` 的项为 SNI（`sniff.go:72-113`）。
- SNI 中若出现 `<= ' '`（0x20）的字节 → 返回 `ErrProtoNeedMoreData`（QUIC 跨包场景）；末尾 `.` → `errNotClientHello`（`sniff.go:100-109`）。

### 3.2 HTTP — `common/protocol/http/sniff.go`

`SniffHTTP`（`sniff.go:61-117`）：
- 首部必须以 HTTP 方法开头（大小写不敏感）：`get/post/head/put/delete/options/connect`（`sniff.go:42, 47-59`）。数据不足以判定方法 → `ErrNoClue`；不匹配 → `errNotHTTPMethod`。
- 按 `\n` 分割 header；从第 2 行起按 `:` 分 key/value（`sniff.go:77-91`）。
- 若 key（小写）= `host`：解析 host（默认端口 80），取 `dest.Address.String()` 作为域名（`sniff.go:92-96`）。
- 请求行（第 1 行）按空格分为 3 段时，记录 `:method`/`:path` 属性（仅当无既有属性时，`sniff.go:105-111`）。
- 有 host 才返回结果，否则 `ErrNoClue`。

### 3.3 QUIC — `common/protocol/quic/sniff.go`

`SniffQUIC`（`sniff.go:69-...`）：
- 长首部校验：`typeByte & 0x80 != 0` 且 `typeByte & 0x40 != 0`，否则非 QUIC/非 Initial（`sniff.go:89-91`）。
- 版本 = `BE(b[1:5])`，必须属于 `{draft29, v1, v2}`（`sniff.go:99-104`、`sniff.go:62-66`）。
- 跳过 DCID（1 字节长度 + N）与 SCID（1 字节长度 + N）（`sniff.go:106-115`）。
- `packetType = (typeByte & 0x30) >> 4`；仅 Initial 包继续（`sniff.go:120-121`）。
- Initial 包跳过 token（varint 长度 + N）（`sniff.go:124-130`），读 packetLen（varint）（`sniff.go:134-136`）。
- 用版本对应的 initial salt + HKDF 解出 header protection key，去保护后从 CRYPTO 帧重组 ClientHello，复用 `tls.ReadClientHello` 提取 SNI（`sniff.go:150-...`）。
- 数据不足 → `ErrNoClue`。

### 3.4 BitTorrent — `common/protocol/bittorrent/bittorrent.go`

- `SniffBittorrent`（`bittorrent.go:22-32`）：`len>=20` 且 `b[0]==19 && string(b[1:20])=="BitTorrent protocol"` → 命中（协议名 `bittorrent`，无域名）。
- `SniffUTP`（`bittorrent.go:34-...`）：`b[0]==0x41`（ST_SYN+version1）且 `BE(b[8:12])==0`，再遍历扩展链校验。

### 3.5 FakeDNS — `app/dispatcher/fakednssniffer.go`

- 元数据嗅探器 `newFakeDNSSniffer`（`fakednssniffer.go:16-...`）：从上下文取 FakeDNS 引擎，按目标 IP 反查域名，协议名 `fakedns`（`fakednssniffer.go:52-58`）。
- `DNSThenOthersSniffResult`（`fakednssniffer.go:72-87`）：协议名 `fakedns+others`，`IsProtoSubsetOf` 对以原始协议名开头的匹配返回 true（`fakednssniffer.go:77-79`），使 `fakedns+others` 在配置里同时覆盖 `fakedns` 与其他嗅探。

## 4. 覆盖决策与 `routeOnly` / `metadataOnly`

`shouldOverride`（`app/dispatcher/default.go:232-262`）：
1. 嗅探域名为空 → false。
2. `ExcludeForDomain.MatchAny(lower(domain))` → false。
3. 目标是 IP 且 `ExcludeForIP.Match(ip)` → false。
4. 遍历 `OverrideDestinationForProtocol`：`HasPrefix(protocolString,p) || HasPrefix(p,protocolString)` → true（前缀双向匹配）。
5. FakeDNS 特例：`protocolString != "bittorrent"` 且 `p=="fakedns"` 且目标 IP 在 fake 池 → true（伪造 IP 未命中时仍用嗅探）。
6. `SnifferIsProtoSubsetOf.IsProtoSubsetOf(p)` → true。

`Dispatch`/`DispatchLink`（`default.go:267-376`）：
- `enabled=false` 直接路由；否则先嗅探，成功则 `content.Protocol = result.Protocol()`。
- 覆盖时把 `destination.Address` 替换为嗅探域名。
- **routeOnly**：当 `routeOnly==true` 且协议不是 `fakedns`/`fakedns+others` 且非 fakeIP 时，只设置 `ob.RouteTarget = destination`（仅用于路由决策），`ob.Target` 保持原目标；否则设置 `ob.Target`（`default.go:311-317`、`366-372`）。
- **metadataOnly**：只跑元数据嗅探器（`sniffer()`，`default.go:384-392`）。

# 二、Routing

## 1. 配置结构（`infra/conf/router.go`）

`RouterConfig`（`router.go:71-75`）：`rules`、`domainStrategy`、`balancers`。
`getDomainStrategy`（`router.go:77-91`）：`IpIfNonMatch` / `IpOnDemand` / 其他（默认）→ `AsIs`（大小写不敏感）。

### 1.1 规则字段（`RawFieldRule`，`router.go:133-153`；解析 `parseFieldRule` `router.go:132-278`）

| JSON 字段 | 映射条件 | 证据 |
|---|---|---|
| `ruleTag` | 规则标签 | `router.go:120-124, 161` |
| `outboundTag` / `balancerTag` | 二选一，均空则报错 | `router.go:168-177` |
| `domain` / `domains` | 域名规则（`domains` 覆盖 `domain`） | `router.go:175-192` |
| `ip` | 目标 IP 规则 | `router.go:194-201` |
| `port` | 目标端口 | `router.go:203-205` |
| `network` | `tcp`/`udp` | `router.go:207-209` |
| `sourceIP` / `source` | 源 IP（`source` 作回退） | `router.go:211-222` |
| `sourcePort` | 源端口 | `router.go:224-226` |
| `localIP` | 本机 IP | `router.go:228-235` |
| `localPort` | 本机端口 | `router.go:237-239` |
| `user` | 用户 email | `router.go:241-245` |
| `vlessRoute` | VLESS 路由（按端口匹配） | `router.go:247-249` |
| `inboundTag` | 入站标签 | `router.go:251-255` |
| `protocol` | 嗅探协议（前缀匹配） | `router.go:257-261` |
| `attrs` | 属性（regex，`len>0` 才生效） | `router.go:263-265` |
| `process` | 进程名（`len>0`） | `router.go:267-269` |
| `localOS` | 本机 OS（`len>0`） | `router.go:271-273` |
| `webhook` | `url` 非空才生效 | `router.go:126-131, 275-281` |

### 1.2 条件构建（`app/router/config.go:33-118`）

`BuildCondition` 把上述字段转成 `ConditionChan`（所有条件 AND，`condition.go:23-34`）。未设置任何有效字段 → 报 `this rule has no effective fields`（`config.go:114-116`）。

关键 matcher（`app/router/condition.go`）：
- `DomainMatcher`：输入 `strings.ToLower`，`MatchAny`（`condition.go:49-79`）。
- `IPMatcher`：asType ∈ {Local, Source, Target}（`condition.go:81-110`）。
- `PortMatcher`：asType ∈ {Local, Source, Target, VlessRoute}（`condition.go:112-139`）。
- `NetworkMatcher`：按 `net.Network` 索引布尔表（`condition.go:141-156`）。
- `UserMatcher`：精确匹配 + `regexp:` 前缀正则（`condition.go:158-201`）。
- `InboundTagMatcher`：精确匹配（`condition.go:203-231`）。
- `ProtocolMatcher`：`strings.HasPrefix(protocol, p)`（`condition.go:233-263`）。
- `AttributeMatcher`：key 小写化，value 用预编译 regex 全匹配（`condition.go:265-291`）。
- `ProcessNameMatcher`：按进程名/绝对路径/目录/`self/`/`xray/` 匹配（`condition.go:293-398`）。
- `LocalOSMatcher`：构建期一次性比较 `runtime.GOOS`（大小写不敏感）（`condition.go:400-415`）。

### 1.3 `domainStrategy` 行为（`app/router/router.go:188-224`）

- `IpOnDemand`：进入 `pickRouteInternal` 时先给 ctx 注入 DNS client，域名 matcher 可即时解析（`router.go:194-196`）。
- 按顺序跑所有规则，命中即返回（`router.go:198-203`）。
- `IpIfNonMatch`：若首轮无命中且目标含域名且未 `skipDNSResolve`，注入 DNS client 后**再跑一遍**规则（`router.go:205-220`）。
- `AsIs`（默认）：不做解析。

### 1.4 负载均衡（`infra/conf/router.go:21-69`、`app/router/config.go:125-169`）

- 配置：`tag`（非空）、`selector`（非空）、`strategy{type,settings}`、`fallbackTag`（`router.go:21-26, 31-38`）。
- `strategy.type`：`random`(默认)/`leastLoad`/`leastPing`/`roundRobin`（`infra/conf/router.go:39-48`；`app/router/config.go:125-169`）。
- `leastLoad` 的 `settings`：`costs`、`baselines`、`expected`、`maxRTT`、`tolerance`（`infra/conf/router_strategy.go:33-43`）。
- 选中后 `Rule.GetTag()` 返回 balancer 选出的 outbound（`app/router/config.go:21-26`）。

### 1.5 Webhook

规则可挂 `webhook{url,deduplication,headers}`（`infra/conf/router.go:126-131`）。命中规则时 `PickRoute` 触发 `rule.Webhook.Fire(...)`（`app/router/router.go:56-62`）；事件结构含 email/level/protocol/network/source/destination/originalTarget/routeTarget/inboundTag/inboundName/inboundLocal/outboundTag/ts（`app/router/webhook.go:22-36`）。支持 `http`/`http+unix` URL（`webhook.go:52-60`）。

# 三、域名匹配语义（domainMatcher）

## 1. 规则前缀解析（`common/geodata/rule_parser.go:226-260`）

`parseCustomDomainRule(rule, defaultType)`：

| 前缀 | Domain_Type | 匹配器 | 语义 |
|---|---|---|---|
| `regexp:` | Regex | `RegexMatcher` | Go RE2 正则 |
| `domain:` | Domain | `DomainMatcher` | 后缀（标签边界） |
| `full:` | Full | `FullMatcher` | 精确相等 |
| `keyword:` | Substr | `SubstrMatcher` | 子串包含 |
| `dotless:` | Regex | 展开为 `^[^.]*<substr>[^.]*$`（或 `^[^.]*$`） | 无点匹配 |
| 无前缀 | `defaultType` | 取决于调用方 | — |

`geosite:`/`ext:`/`ext-domain:`/`ext-site:` 走 geosite 数据文件（`rule_parser.go:161-205`）。

## 2. 各匹配器实现（`common/geodata/strmatcher/matchers.go`）

- `FullMatcher.Match`：`string(m) == s`（`matchers.go:31-33`）。
- `DomainMatcher.Match`：`strings.HasSuffix(s, pattern)` 且（长度相等或 `s[len-len(pattern)-1] == '.'`）——**标签边界后缀**（`matchers.go:50-57`）。
- `SubstrMatcher.Match`：`strings.Contains(s, pattern)`（`matchers.go:73-75`）。
- `RegexMatcher`：RE2（`matchers.go:77+`）。
- 输入统一 `strings.ToLower`（`app/router/condition.go:60,69`；`common/geodata/domain_matcher.go:198-209`）。

## 3. ⚠️ 关键：routing/`sniffing.domainsExcluded` 中裸域名的默认类型是 **Substr（子串）**

`infra/conf/router.go:176,184` 与 `infra/conf/xray.go:86`、`infra/conf/dns.go:89` 调用 `ParseDomainRules(rules, geodata.Domain_Substr)`。
`Domain_Substr`（枚举值 0，`common/geodata/geodat.pb.go:27-36`）→ `strmatcher.Substr`（`common/geodata/domain_matcher.go:200-202`）→ `strings.Contains`。

因此裸条目 `"example.com"` 是**子串匹配**（会命中 `example.com.evil.net`）。要后缀匹配须写 `"domain:example.com"`，精确匹配写 `"full:example.com"`。测试佐证：`Domain_Substr` 值 `"exam"` 命中 `example.com`、`exam.net`（`common/geodata/domain_matcher_test.go:85-104`）。

## 4. 匹配器实现（"hybrid" 组合）

`MphValueMatcher` 将不同 Domain_Type 分派到不同结构（`common/geodata/strmatcher/valuematcher_mph.go:5-8`）：
- `Full` + `Domain` → `MphMatcherGroup`：Rabin-Karp 后缀哈希 + 最小完美哈希表（`matchergroup_mph.go:1-60`）。
- `Substr` → `ACAutomatonMatcherGroup`（Aho-Corasick 自动机，`matchergroup_ac_automation.go`）。
- `Regex` → `SimpleMatcherGroup`（线性扫描，`matchergroup_simple.go`）。

域名匹配器工厂按平台选择实现：iOS/Android 用 `CompactMphDomainMatcherFactory`，其他用 `MphDomainMatcherFactory`（`common/geodata/domain_matcher.go:214-221`）。路由侧 `DomainMatcher` 包装 `geodata.DomainReg.BuildDomainMatcher`（`app/router/condition.go:49-79`）。

## 5. 与既有文档的关系

- 无地址编码冲突；本文件补充 `sniffing`/`routing` 语义，与 `docs/config-schema.md` 的 §5 字段表互补。