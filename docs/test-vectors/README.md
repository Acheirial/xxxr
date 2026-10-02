# Xray-core 测试向量（test vectors）

供 Rust 重写实现 worker 直接用作单测数据。所有向量均派生自上游 **XTLS/Xray-core v26.9.30**：

| 项 | 值 |
|---|---|
| 仓库 | `https://github.com/XTLS/Xray-core` |
| HEAD | `b26a91de4f3294e26a0ad0a970b81a386a41f789` |
| tag | `v26.9.30` |

---

## 0. 重要前提：上游没有固定字节向量

上游的协议测试（`proxy/vmess/aead/*_test.go`、`proxy/vmess/encoding/encoding_test.go`、`proxy/vless/encoding/encoding_test.go`、`proxy/trojan/protocol_test.go`、`proxy/shadowsocks/*_test.go`、`proxy/shadowsocks_2022/*_test.go`）**全部是 round-trip 或随机输入断言**，不含任何「期望字节」常量。因此本目录中：

- **`derived: false`（固定向量）**：值是**直接读自源码的常量**（KDF 盐字符串、枚举值、方法名、帧长度上限、CRLF 常量等），无任何计算。
- **`derived: true`（推导向量）**：值是**用上游算法本身、以显式给定的确定性输入计算得到的输出**。上游没有该期望值，但推导可复现：脚本逐行照抄上游实现（见 §5），并且能用第二实现交叉验证（见 §4）。

**没有**任何一条向量是「上游文档/测试里写死的期望输出」。请勿把 `derived: true` 的向量当作上游权威断言；它们是我方按源码语义生成的、可独立复算的基准。

---

## 1. 文件格式

每个 JSON 文件结构：

```jsonc
{
  "meta": {
    "repo": "XTLS/Xray-core",
    "head": "b26a91de…",
    "tag": "v26.9.30",
    "file": "vmess-aead.json",
    "generator": "…如何生成的…",
    "notes": "…适用范围与警告…",
    "vector_count": 13,
    "derived_count": 11,
    "fixed_count": 2
  },
  "vectors": [ /* 见下 */ ]
}
```

单个向量对象字段：

| 字段 | 类型 | 含义 |
|---|---|---|
| `id` | string | 唯一标识，形如 `vmess.kdf.one_path`；建议 Rust 测试名沿用 |
| `kind` | string | 向量类别，见 §2 |
| `source` | string | **上游出处**，`文件:行号`（可含多段，以 `; ` 分隔） |
| `derived` | bool | `true`=由上游算法计算得到（非上游断言）；`false`=源码常量 |
| `input` | object | 输入（字符串/整数/hex，键名自解释） |
| `expected` | object | 期望输出（hex 一律**小写、无前缀**） |
| `note` | string? | 可选补充（算法细节、构造方式、验证方式） |

约定：

- 所有 hex 字符串 **小写、无 `0x` 前缀、无分隔符**。
- ASCII 输入用 `*_ascii` 后缀，二进制输入/输出用 `*_hex` 后缀。
- 时间戳为 Unix 秒（i64）。

## 2. `kind` 取值

| kind | 含义 |
|---|---|
| `kdf` | 密钥派生（输入密钥/盐 → 输出子密钥） |
| `hash` | 摘要（如 Trojan SHA-224 hex） |
| `aes-ecb` | AES-ECB 单块（VMess AuthID） |
| `aead-seal` / `aead-open` | AEAD 封装/解封装 |
| `aead-frame` / `stream-frame` / `udp-frame` | 分帧/数据帧字节 |
| `header-layout` | 协议头字节布局（含字段分解） |
| `address-encoding` | 地址类型编码 |
| `method-list` | 协议方法名与参数清单 |
| `constants` | 常量/枚举/尺寸上限 |
| `invariant` | 算法不变式（附示例值） |

## 3. 文件清单与统计

| 文件 | 向量数 | derived | fixed | 覆盖 |
|---|---|---|---|---|
| `vmess-aead.json` | 13 | 11 | 2 | KDF 盐链、AuthID（crc32+AES-ECB）、内层头布局、FNV-1a 校验、AEAD 外层头与派生密钥、chunk 分帧、常量 |
| `trojan.json` | 4 | 3 | 1 | SHA-224 hex、TCP 请求头、UDP 帧、常量 |
| `vless.json` | 6 | 4 | 2 | 请求/响应头、addons(Flow) 编码、地址 1/2/3（端口在前）、UUID 归一化、常量 |
| `shadowsocks.json` | 11 | 9 | 2 | EVP_BytesToKey(MD5) 密钥、HKDF-SHA1 子密钥、AEAD/UDP 帧、nonce 阶梯、SS2022 BLAKE3 子密钥、2022 TCP 请求/响应头、2022 流帧、方法清单 |
| **合计** | **34** | **27** | **7** | |

### 3.1 向量 ID 速查

**vmess-aead.json**：`vmess.kdf.empty_path` / `.one_path` / `.two_paths`、`vmess.kdf.salt_constants`(fixed)、`vmess.authid.key`、`vmess.authid.ecb`、`vmess.authid.decode`、`vmess.inner_header.38`、`vmess.inner_header.with_addr_padding_checksum`、`vmess.aead.sealed_header`、`vmess.aead.open_roundtrip`、`vmess.chunk.framing`、`vmess.constants`(fixed)

**trojan.json**：`trojan.sha224`、`trojan.tcp_request_header`、`trojan.udp_packet`、`trojan.constants`(fixed)

**vless.json**：`vless.request_header.no_addons`、`vless.request_header.with_flow`、`vless.response_header`、`vless.address.types`、`vless.constants`(fixed)、`vless.uuid.normalization`(fixed)

**shadowsocks.json**：`ss.legacy.evp_bytes_to_key`、`ss.legacy.hkdf_sha1_subkey`、`ss.legacy.aead_frame`、`ss.legacy.udp_packet`、`ss.legacy.nonce_ladder`、`ss2022.blake3.subkeys`、`ss2022.tcp_request_header`、`ss2022.tcp_response_header`、`ss2022.stream_chunk`、`ss.methods.legacy`(fixed)、`ss.methods.2022`(fixed)

## 4. 向量可信度与交叉验证

生成方式为「照抄上游实现 + 第二实现交叉验证」：

| 条目 | 验证方式 | 结果 |
|---|---|---|
| VMess KDF 链 | 逐行照抄 `kdf.go` 在 Go 1.26.8 下运行（含 `hash2` 共享状态语义） | 唯一来源（Go 专有构造） |
| VMess AuthID 的 AES-ECB 步 | Go 产出密文 → Python `cryptography` AES-ECB 用同一 key 复算 | **一致** |
| VMess AEAD 外层头 | Go 内 `OpenVMessAEADHeader` 逆运算 | **`sealed_open_payload_matches: true`** |
| SS EVP_BytesToKey | Go 产出 → Python `hashlib.md5` 复算 16 字节链 | **一致**（`098f6bcd…`） |
| SS HKDF-SHA1 子密钥 | Go `crypto/hkdf` → Python `cryptography.HKDF(SHA1)` | **一致**（`6e1fe8a4…`） |
| SS AEAD / UDP 帧 | Python 生成 → Python 解密回原文 | **一致** |
| Trojan SHA-224 | Go → Python `hashlib.sha224` | **一致** |
| SS2022 BLAKE3 子密钥/头/帧 | Python `blake3.derive_key` + AES-GCM 生成 → 解密回原文 | **一致** |

## 5. 如何复现（可再生成）

生成脚本位于 `/home/dev/tmp/`（不在仓库内，属于分析临时产物）：

- `/home/dev/tmp/vec-gen2/gen.go`：逐行照抄上游算法的 Go 程序（仅用标准库：`crypto/aes|cipher|hkdf|hmac|md5|sha1|sha256`、`hash/fnv`、`hash/crc32`）。
  运行：`cd /home/dev/tmp/vec-gen2 && go run gen.go > go_out.json`
- `/home/dev/tmp/vec-gen2/gen.py`：BLAKE3 与 Python 侧交叉验证、SS/SS2022 帧构造。
  运行：`PYTHONPATH=/home/dev/tmp/pylibs python3 gen.py`
- `/home/dev/tmp/vec-gen2/assemble.py`：合并上述输出并写出本目录的 4 个 JSON。
  运行：`PYTHONPATH=/home/dev/tmp/pylibs python3 assemble.py`

> 上游源码克隆位于 `/home/dev/tmp/xray-core-ref`（`git rev-parse HEAD` 应与上文一致）。

## 6. 在 Rust 单测中的用法

建议把 JSON 通过 `include_str!` 嵌入，或用 `serde` 反序列化到结构体：

```rust
#[derive(serde::Deserialize)]
struct File { meta: serde_json::Value, vectors: Vec<Vector> }

#[derive(serde::Deserialize)]
struct Vector {
    id: String,
    kind: String,
    source: String,
    derived: bool,
    input: serde_json::Value,
    expected: serde_json::Value,
    #[serde(default)] note: Option<String>,
}

fn hex(s: &str) -> Vec<u8> { /* hex::decode */ }

#[test]
fn vmess_kdf_one_path_matches_upstream() {
    let f: File = serde_json::from_str(include_str!("../docs/test-vectors/vmess-aead.json")).unwrap();
    let v = f.vectors.iter().find(|v| v.id == "vmess.kdf.one_path").unwrap();
    let key = v.input["key_ascii"].as_str().unwrap().as_bytes();
    let path = v.input["path"][0].as_str().unwrap();
    let got = xray_crypto::vmess_kdf(key, &[path]);
    assert_eq!(hex(v.expected["kdf_hex"].as_str().unwrap()), got);
}
```

使用建议：

1. **优先用 `derived: true` 的向量做回归**：它们锁定了字节级行为（KDF、头布局、帧）。
2. **`fixed: true` 的向量适合做常量单测**：枚举值、盐字符串、尺寸上限，防止常量写错。
3. **先跑 round-trip，再跑向量**：`aead-seal` 与 `aead-open` 成对，能定位「加密对但解密错」这类问题。
4. **`header-layout` 的 `expected.fields`** 可用于逐字段断言，定位偏移错误。
5. `input` 中的 `*_ascii` 字段是 UTF-8/ASCII 字节；`*_hex` 是原始字节。

## 7. 已知限制与未确认项

- **无上游固定字节向量**：全部 `derived: true` 的期望值由我方推导，非上游断言（上游测试仅 round-trip）。
- **VMess KDF 只能由 Go 语义复现**：`kdf.go` 依赖 Go `hmac.New` 与 `hash2` 的共享状态细节；Rust 实现需按「每层 path 元素作为 HMAC key、上一层的 HMAC 实例作为本层的底层 hash」实现，并**用本目录的向量校验**。若 Rust 实现与本向量不一致，以本向量为准（它们由上游代码直接产出）。
- **VMess 加密扩展（`mlkem768x25519plus`）无向量**：该层未在上游测试中固定，本轮未覆盖（见 `docs/vless-protocol.md` §7 标注「未确认」）。
- **SS2022 多跳 EIH（3 个以上 PSK）未出向量**：仅单 PSK 与双跳字段语义已在 `docs/shadowsocks-protocol.md` 记录，字节级向量未生成。
- **旧 cipher（AES-128-CFB 等）不存在于本版本**，故无向量；`docs/vmess-protocol.md` §0 已说明其为本仓库中的死代码。
- 向量中的 PSK/密码均为**公开测试用值**（如 `"password"`、`"test"`、全 `00`/`ff` 模式），不含任何真实凭据。