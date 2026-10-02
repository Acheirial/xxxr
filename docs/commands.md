# CLI 命令规格（依据 upstream v26.9.30）

> 证据引用 `/home/dev/tmp/xray-core-ref` 内 Go 源码 `路径:行号`。
> 入口：`main/main.go`、`main/run.go`、`main/version.go`；命令框架：`main/commands/base/*.go`；子命令：`main/commands/all/**`；API 配置：`infra/conf/api.go`。

## 0. 命令框架

- 命令树根为 `base.RootCommand`（`main/commands/base/root.go:6-13`）。
- 命令名由 `UsageLine` 推导：`Name()` = usage 中第一个 flag/参数之前的最后一个词（`main/commands/base/command.go:52-76`）。例如 `api adu [...]` 的名字是 `adu`，`tls cert [...]` 的名字是 `cert`。
- 分发：`base.Execute()` 遍历子命令；`xray help ...` 走帮助；`CustomFlags=true` 的命令自行解析 flag（`main/commands/base/execute.go:16-69`）。
- 注册入口：`main/distro/all/all.go` 空导入 `main/commands/all`；`main/commands/all/commands.go:10-22` 把 `api/convert/tls/uuid/x25519/wg/mldsa65/mlkem768/vlessenc` 挂到根。

## 1. 入口参数兼容（`main/main.go:12-52`）

`getArgsV4Compatible()`（`main/main.go:25-52`）：
- 无参数 → 追加 `run`。
- `-h`/`--help` → `help`。
- `-version` → `version`。
- 其他以 `-` 开头的参数 → 作为 `run` 的参数。

## 2. 顶层命令

| 命令 | 说明 | 定义 |
|---|---|---|
| `run` | 运行 Xray（默认命令） | `main/run.go:25-26` |
| `version` | 打印版本 | `main/version.go:10-16` |
| `help` | 帮助 | `main/commands/base/execute.go:21-25`、`help.go` |
| `api` | 调用运行中进程的 API | `main/commands/all/api/api.go:8-32` |
| `convert` | 配置转换 | `main/commands/all/convert/convert.go:8-16` |
| `tls` | TLS 工具 | `main/commands/all/tls/tls.go:8-17` |
| `uuid` | 生成 UUIDv4/v5 | `main/commands/all/uuid.go:9-16` |
| `x25519` | 生成 X25519 密钥对 | `main/commands/all/x25519.go:6-12` |
| `wg` | 生成 WireGuard 密钥对 | `main/commands/all/wg.go:7-13` |
| `mldsa65` | 生成 ML-DSA-65 密钥对 | `main/commands/all/mldsa65.go:10-17` |
| `mlkem768` | 生成 ML-KEM-768 密钥对 | `main/commands/all/mlkem768.go:11-18` |
| `vlessenc` | 生成 VLESS 加密配置对 | `main/commands/all/vlessenc.go:10-15` |

## 3. `run`

`UsageLine`：`xray run [-c config.json] [-confdir dir]`（`main/run.go:26`）。

| Flag | 类型 | 默认 | 说明 | 行号 |
|---|---|---|---|---|
| `-c` / `-config` | `cmdarg.Arg`（可重复） | — | 配置文件路径 | `run.go:63-64` |
| `-confdir` | string | — | 目录，按格式匹配加载 | `run.go:65, 145-156` |
| `-format` | string | `auto` | 输入格式：`json`/`toml`/`yaml`/`yml`/`auto` | `run.go:60, 135-144` |
| `-test` | bool | false | 仅测试配置，不启动 | `run.go:59` |
| `-dump` | bool | false | 仅打印合并后的配置 | `run.go:58` |

配置发现顺序（`getConfigFilePath`，`run.go:165-206`）：`-confdir` → 环境变量 confdir → `-c/-config` → 当前目录 `config.{json,jsonc,toml,yaml,yml}` → 环境变量配置路径 → `stdin:`。
`executeRun`（`run.go:74-110`）：`-dump` 打印后退出；否则启动服务；`-test` 成功打印 `Configuration OK.` 后退出；启动失败退出码 23（防止 systemd 重启）。
格式解析 `getConfigFormat`（`run.go:208-214`）；加载/创建 `startXray`（`run.go:216-230`）。

## 4. `api`（gRPC 客户端）

### 4.1 共享 flag（`setSharedFlags`，`main/commands/all/api/shared.go:33-39`）

| Flag | 默认 | 说明 |
|---|---|---|
| `-s` / `-server` | `127.0.0.1:8080` | API 服务器地址 |
| `-t` / `-timeout` | `3` | 超时（秒） |
| `-json` | false | 以 JSON 输出响应（`showJSONResponse`，`shared.go:117-124`） |

连接：`dialAPIServer` 用 gRPC insecure + `WithBlock`（`shared.go:41-53`）。
参数加载 `loadArg` 支持本地文件 / `http(s)://` / `stdin:`（`shared.go:55-75`）。

### 4.2 子命令

| 命令名 | UsageLine | 说明 | 定义 |
|---|---|---|---|
| `restartlogger` | `api restartlogger [--server=...]` | 重启日志器 | `api/logger_restart.go:10-11` |
| `stats` | `api stats [--server=...] [-name '']` | 取统计；flags `-name`、`-reset` | `api/stats_get.go:10-11, 38-39` |
| `statsquery` | `api statsquery [--server=...] [-pattern '']` | 查询统计；flags `-pattern`、`-reset` | `api/stats_query.go:10-11, 38-39` |
| `statssys` | `api statssys [--server=...]` | 系统统计 | `api/stats_sys.go:10-11` |
| `statsonline` | `api statsonline [--server=...] [-email '']` | 单用户在线会话数；flag `-email` | `api/stats_online.go:10-11, 35` |
| `statsonlineiplist` | `api statsonlineiplist [...] [-email '' \| -all [-include-traffic] [-reset]]` | 用户在线 IP 与访问时间；flags `-email`/`-all`/`-include-traffic`/`-reset` | `api/stats_online_ip_list.go:10-11, 47-50` |
| `statsgetallonlineusers` | `api statsgetallonlineusers [--server=...]` | 全部在线用户数组 | `api/stats_get_all_online_users.go:10-11` |
| `bi` | `api bi [--server=...] [balancer]...` | 取 balancer 信息 | `api/balancer_info.go:15-16` |
| `bo` | `api bo [--server=...] <-b balancer> outboundTag <-r>` | 覆写 balancer | `api/balancer_override.go:10-11` |
| `adi` | `api adi [--server=...] <c1.json> [c2.json]...` | 添加入站 | `api/inbounds_add.go:14-15` |
| `rmi` | `api rmi [--server=...] <json_file\|tag> [...]` | 删除入站 | `api/inbounds_remove.go:13-14` |
| `lsi` | `api lsi [--server=...] [--isOnlyTags=true]` | 列出站 | `api/inbounds_list.go:10-11` |
| `ado` | `api ado [--server=...] <c1.json> [c2.json]...` | 添加出站 | `api/outbounds_add.go:14-15` |
| `rmo` | `api rmo [--server=...] <json_file\|tag> [...]` | 删除出站 | `api/outbounds_remove.go:13-14` |
| `lso` | `api lso [--server=...]` | 列出站 | `api/outbounds_list.go:10-11` |
| `adu` | `api adu [--server=...] <c1.json> [c2.json]...` | 向入站添加用户 | `api/inbound_user_add.go:28-29` |
| `rmu` | `api rmu [--server=...] -tag=tag <email1> [email2]...` | 从入站删除用户 | `api/inbound_user_remove.go:14-15` |
| `inbounduser` | `api inbounduser [--server=...] -tag=tag [-email=email]` | 取入站用户 | `api/inbound_user.go:10-11` |
| `inboundusercount` | `api inboundusercount [--server=...] -tag=tag` | 入站用户数 | `api/inbound_user_count.go:10-11` |
| `adrules` | `api adrules [--server=...] <c1.json> [c2.json]...` | 添加路由规则 | `api/rules_add.go:15-16` |
| `rmrules` | `api rmrules [--server=...] [ruleTag]...` | 按 ruleTag 删除规则 | `api/rules_remove.go:12-13` |
| `lsrules` | `api lsrules [--server=...]` | 列出路由规则 | `api/rules_list.go:10-11` |
| `sib` | `api sib [--server=...] -outbound=blocked -inbound=socks 1.2.3.4` | 按源 IP 阻断 | `api/source_ip_block.go:16-17` |

`adu` 输入为完整 inbound 配置 JSON，解析后按 tag 逐个用户调用 `HandlerService.AlterInbound` + `AddUserOperation`（`api/inbound_user_add.go:44-151`）；仅支持带 `Users` 的入站类型（vmess/vless/trojan/shadowsocks/shadowsocks_2022 多用户/masque/hysteria）（`api/inbound_user_add.go:79-100`）。

### 4.3 配置依赖（`infra/conf/api.go`）

`api` 配置块 `{ tag(必填), listen, services[] }`（`infra/conf/api.go:18-22`），`Build` 要求 `tag` 非空（`api.go:25-27`）。`services` 取值（大小写不敏感，`api.go:31-44`）：
`reflectionservice`、`handlerservice`、`loggerservice`、`statsservice`、`observatoryservice`、`routingservice`。
- `api.listen` 是 gRPC 监听地址；API 客户端默认连 `127.0.0.1:8080`，需与之匹配。
- 统计类命令依赖 `stats` 配置块与 `policy` 的 `statsUserUplink/Downlink/Online` 等开关；用户类命令依赖对应入站的动态用户能力（`adu`/`rmu` 走 HandlerService）。
- 对应的 gRPC 服务实现：`app/proxyman/command/command.go:221`、`app/stats/command/command.go:216`、`app/log/command/command.go:42`、`app/router/command/command.go:146`。

## 5. `tls` 子命令（`main/commands/all/tls/tls.go:12-16`）

| 命令 | UsageLine | 说明 | 关键 flag | 定义 |
|---|---|---|---|---|
| `cert` | `tls cert [--ca] [--domain=example.com] [--expire=240h]` | 生成证书 | `-domain`(可重复)、`-name`(默认 `Xray Inc`)、`-org`、`-ca`、`-json`(默认 true)、`-file`、`-expire`(默认 3 月) | `tls/cert.go:19-64` |
| `ping` | `tls ping [-ip <ip>] <domain>` | TLS 握手探测 | `-ip` | `tls/ping.go:22-38` |
| `hash` | `tls hash` | 计算证书 SHA256 | `-cert`(默认 `fullchain.pem`) | `tls/hash.go:17-29` |
| `ech` | `tls ech [--serverName (string)] [--pem] [-i "ECHServerKeys"]` | 生成 TLS-ECH 证书 | `-i`、`-serverName`(默认 `cloudflare-ech.com`)、`-pem` | `tls/ech.go:19-39` |

`tls hash` 输出：`Leaf SHA256:` 与各 `CA <CN> SHA256:`（`main/commands/all/tls/hash.go:72-77`）。

## 6. `convert` 子命令（`main/commands/all/convert/convert.go:12-15`）

| 命令 | UsageLine | 说明 | 关键 flag | 定义 |
|---|---|---|---|---|
| `json` | `convert json [-type] [stdin:] [typedMessage file]` | 单个 typedMessage → JSON | `-t`/`-type` | `convert/json.go:16-17, 36-52` |
| `pb` | `convert pb [-outpbfile file] [-debug] [-type] [json file] ...` | 多个 JSON → protobuf | `-o`/`-outpbfile`、`-d`/`-debug`、`-t`/`-type` | `convert/protobuf.go:17-18, 57-70` |

`convert json` 输入格式（`convert/json.go:23-31`）：
```json
{ "type": "xray.proxy.shadowsocks.Account", "value": "CgMxMTEQBg==" }
```
`convert pb -debug` 仅用于调试，**不可回灌 Xray**（`convert/protobuf.go:24-29`）。

## 7. 密钥/工具命令

| 命令 | UsageLine | 输出 | 定义 |
|---|---|---|---|
| `uuid` | `uuid [-i "example"]` | 无 `-i` 生成 UUIDv4；有则 UUIDv5（输入 ≤30 字节） | `main/commands/all/uuid.go:9-38` |
| `x25519` | `x25519 [-i "private key"] [--std-encoding]` | `PrivateKey/Password(PublicKey)/Hash32`，默认 base64.RawURLEncoding | `main/commands/all/x25519.go:6-30`、`main/commands/all/curve25519.go:11-55` |
| `wg` | `wg [-i "private key (base64.StdEncoding)"]` | 同 x25519，但用 base64.StdEncoding | `main/commands/all/wg.go:7-22` |
| `mldsa65` | `mldsa65 [-i "seed (base64.RawURLEncoding)"]` | `Seed/Verify` | `main/commands/all/mldsa65.go:10-38` |
| `mlkem768` | `mlkem768 [-i "seed (base64.RawURLEncoding)"]` | `Seed/Client/Hash32` | `main/commands/all/mlkem768.go:11-44` |
| `vlessenc` | `vlessenc` | 输出 X25519 与 ML-KEM-768 两套 `decryption`/`encryption` JSON 片段 | `main/commands/all/vlessenc.go:11-41` |

## 8. 未确认项

- `api sib` / `bo` / `adu` 等命令的**完整参数解析与错误码**未逐行核对（已确认 UsageLine 与 flag 名，行号见上表）。
- 任务书提到的 `mtu`、`certChainHash`、`load` 命令**不存在**：全仓库命令清单中无 `mtu`（仅 `tls hash` 做证书哈希）；`load`/`test` 不是子命令，而是 `run` 的行为（`-test`）/ 配置加载函数（`core.LoadConfig`）。已核实 `main/commands` 下全部文件列表（见 `main/commands/all/commands.go`、`main/commands/all/api/api.go`、`main/commands/all/tls/tls.go`、`main/commands/all/convert/convert.go` 的注册集合）。