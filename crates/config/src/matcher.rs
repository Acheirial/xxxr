//! 路由与嗅探共用的匹配原语。
//!
//! 提供四类条件，语义对齐上游 Xray：
//! - [`StringList`]：字符串列表，接受 JSON 数组或逗号分隔的单个字符串；
//! - [`DomainMatcher`]：域名条件（`full:` / `domain:` / `keyword:` / `regexp:` / `dotless:`）；
//! - [`IpMatcher`]：IP 条件（单个 IP 或 CIDR，`!` 前缀取反）；
//! - [`PortList`]：端口或端口段（`"80"` / `"100-200"` / `"80,443"` 或数字）。
//!
//! 所有匹配器内部都是「条件之间取或」；不同条件组之间由调用方（路由规则）取与。

use std::borrow::Cow;
use std::net::IpAddr;
use std::str::FromStr;

use regex::Regex;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use xxxr_common::{Error, Result};

/// 字符串列表：JSON 数组，或逗号分隔的单个字符串。
///
/// 对应上游 `infra/conf.StringList` / `NetworkList` 的解析方式。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct StringList(
    /// 列表内容。
    pub Vec<String>,
);

impl StringList {
    /// 按给定字符串列表构造。
    pub fn new(items: Vec<String>) -> Self {
        Self(items)
    }

    /// 以切片形式访问。
    pub fn as_slice(&self) -> &[String] {
        &self.0
    }

    /// 是否为空。
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// 元素个数。
    pub fn len(&self) -> usize {
        self.0.len()
    }
}

impl Serialize for StringList {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        self.0.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for StringList {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Raw {
            Array(Vec<String>),
            One(String),
        }

        match Raw::deserialize(deserializer)? {
            Raw::Array(items) => Ok(Self(items)),
            Raw::One(text) => Ok(Self(split_list(&text))),
        }
    }
}

/// 按逗号切分并去除空白与空项。
fn split_list(text: &str) -> Vec<String> {
    text.split(',')
        .map(str::trim)
        .filter(|item| !item.is_empty())
        .map(str::to_string)
        .collect()
}

/// 域名条件的匹配类型。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DomainType {
    /// 精确匹配（`full:`）。
    Full,
    /// 子域匹配（`domain:`）：命中自身与任意子域。
    Domain,
    /// 子串匹配（`keyword:`，也是无前缀条件的默认类型）。
    Keyword,
    /// 正则匹配（`regexp:`）。
    Regex,
}

/// 域名匹配器的工作模式。
///
/// 对应旧版 Xray 的 `routing.domainMatcher`（上游 v26.9.30 已移除该字段，
/// 本实现保留它用于兼容老配置）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum MatchMode {
    /// 精确/子域/子串走线性匹配，只有 `regexp:` 使用正则。
    #[default]
    Hybrid,
    /// 所有条件都编译为正则。
    Regexp,
}

impl FromStr for MatchMode {
    type Err = Error;

    fn from_str(value: &str) -> Result<Self> {
        match value.to_ascii_lowercase().as_str() {
            "hybrid" | "linear" | "" => Ok(Self::Hybrid),
            "regexp" | "regex" => Ok(Self::Regexp),
            other => Err(Error::config(format!(
                "unknown domainMatcher `{other}` (expected hybrid or regexp)"
            ))),
        }
    }
}

impl MatchMode {
    /// 返回配置中的字符串表示。
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Hybrid => "hybrid",
            Self::Regexp => "regexp",
        }
    }
}

impl Serialize for MatchMode {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for MatchMode {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        let raw = String::deserialize(deserializer)?;
        Self::from_str(&raw).map_err(serde::de::Error::custom)
    }
}

/// 域名条件匹配器。
#[derive(Debug, Clone, Default)]
pub struct DomainMatcher {
    /// 线性匹配的（类型, 已小写值）。
    fast: Vec<(DomainType, String)>,
    /// 正则匹配。
    regex: Vec<Regex>,
}

impl DomainMatcher {
    /// 编译一组域名条件。
    ///
    /// - 需要 geodata（`geosite:` / `ext:`）的条目返回 [`Error::Unsupported`]，
    ///   由调用方决定是跳过整条规则还是忽略该条目；
    /// - 语法错误（如非法正则）返回 [`Error::Config`]。
    pub fn build(entries: &[String], default_type: DomainType, mode: MatchMode) -> Result<Self> {
        let mut fast = Vec::new();
        let mut regex = Vec::new();
        for raw in entries {
            let entry = raw.trim();
            if entry.is_empty() {
                continue;
            }
            let (kind, value) = parse_domain_entry(entry, default_type)?;
            let pattern = if kind == DomainType::Regex {
                Some(value.to_string())
            } else if mode == MatchMode::Regexp {
                regex_source(kind, value.as_ref())
            } else {
                None
            };
            match pattern {
                Some(pattern) => regex.push(compile_regex(&pattern, entry)?),
                None => fast.push((kind, value.to_ascii_lowercase())),
            }
        }
        Ok(Self { fast, regex })
    }

    /// 是否包含任何有效条件。
    pub fn is_empty(&self) -> bool {
        self.fast.is_empty() && self.regex.is_empty()
    }

    /// 判断域名是否命中（大小写不敏感）。
    pub fn matches(&self, domain: &str) -> bool {
        if domain.is_empty() {
            return false;
        }
        let lower = if domain.bytes().any(|byte| byte.is_ascii_uppercase()) {
            Cow::Owned(domain.to_ascii_lowercase())
        } else {
            Cow::Borrowed(domain)
        };
        self.fast
            .iter()
            .any(|(kind, value)| match_domain_fast(*kind, value, &lower))
            || self.regex.iter().any(|re| re.is_match(&lower))
    }
}

/// 解析带前缀的域名条件；`dotless:` 会生成正则源码，因此返回值可能是自有字符串。
fn parse_domain_entry(entry: &str, default_type: DomainType) -> Result<(DomainType, Cow<'_, str>)> {
    if let Some(value) = entry.strip_prefix("regexp:") {
        return Ok((DomainType::Regex, Cow::Borrowed(value)));
    }
    if let Some(value) = entry.strip_prefix("full:") {
        return Ok((DomainType::Full, Cow::Borrowed(value)));
    }
    if let Some(value) = entry.strip_prefix("domain:") {
        return Ok((DomainType::Domain, Cow::Borrowed(value)));
    }
    if let Some(value) = entry.strip_prefix("keyword:") {
        return Ok((DomainType::Keyword, Cow::Borrowed(value)));
    }
    if let Some(substr) = entry.strip_prefix("dotless:") {
        let pattern = if substr.is_empty() {
            "^[^.]*$".to_string()
        } else if substr.contains('.') {
            return Err(Error::config(format!(
                "dotless condition `{entry}` must not contain a dot"
            )));
        } else {
            format!("^[^.]*{}[^.]*$", regex::escape(substr))
        };
        return Ok((DomainType::Regex, Cow::Owned(pattern)));
    }
    for prefix in ["geosite:", "ext:", "ext-site:", "ext-domain:"] {
        if entry.starts_with(prefix) {
            return Err(Error::unsupported(format!(
                "domain condition `{entry}` needs geodata, which is not bundled"
            )));
        }
    }
    Ok((default_type, Cow::Borrowed(entry)))
}

/// 线性匹配。
fn match_domain_fast(kind: DomainType, value: &str, domain: &str) -> bool {
    match kind {
        DomainType::Full => domain == value,
        DomainType::Domain => {
            domain == value
                || (domain.len() > value.len()
                    && domain.ends_with(value)
                    && domain.as_bytes()[domain.len() - value.len() - 1] == b'.')
        }
        DomainType::Keyword => domain.contains(value),
        DomainType::Regex => false,
    }
}

/// 把线性条件转成正则源码（`regexp` 模式下使用）。
fn regex_source(kind: DomainType, value: &str) -> Option<String> {
    match kind {
        DomainType::Full => Some(format!("^{}$", regex::escape(value))),
        DomainType::Domain => Some(format!("(^|\\.){}$", regex::escape(value))),
        DomainType::Keyword => Some(regex::escape(value)),
        DomainType::Regex => None,
    }
}

/// 编译正则并给出面向用户的错误信息。
fn compile_regex(pattern: &str, origin: &str) -> Result<Regex> {
    Regex::new(pattern).map_err(|e| Error::config(format!("invalid domain regexp `{origin}`: {e}")))
}

/// 单个 IP 条件。
#[derive(Debug, Clone, Copy)]
struct IpEntry {
    base: IpAddr,
    prefix: u8,
    negate: bool,
}

impl IpEntry {
    fn contains(&self, ip: IpAddr) -> bool {
        match (self.base, ip) {
            (IpAddr::V4(base), IpAddr::V4(ip)) => {
                prefix_match_v4(u32::from(base), u32::from(ip), self.prefix)
            }
            (IpAddr::V6(base), IpAddr::V6(ip)) => {
                prefix_match_v6(u128::from(base), u128::from(ip), self.prefix)
            }
            _ => false,
        }
    }
}

/// IPv4 前缀匹配：比较地址的高 `prefix` 位；`prefix == 0` 命中任意地址。
fn prefix_match_v4(base: u32, ip: u32, prefix: u8) -> bool {
    if prefix == 0 {
        return true;
    }
    if prefix > 32 {
        return false;
    }
    let mask = u32::MAX << (32 - u32::from(prefix));
    (base & mask) == (ip & mask)
}

/// IPv6 前缀匹配：比较地址的高 `prefix` 位；`prefix == 0` 命中任意地址。
fn prefix_match_v6(base: u128, ip: u128, prefix: u8) -> bool {
    if prefix == 0 {
        return true;
    }
    if prefix > 128 {
        return false;
    }
    let mask = u128::MAX << (128 - u32::from(prefix));
    (base & mask) == (ip & mask)
}

/// IP 条件匹配器。
#[derive(Debug, Clone, Default)]
pub struct IpMatcher {
    entries: Vec<IpEntry>,
}

impl IpMatcher {
    /// 编译一组 IP 条件。
    ///
    /// - `geoip:` / `ext-ip:` 返回 [`Error::Unsupported`]；
    /// - 非法 IP 或 CIDR 返回 [`Error::Config`]。
    pub fn build(entries: &[String]) -> Result<Self> {
        let mut compiled = Vec::new();
        for raw in entries {
            let entry = raw.trim();
            if entry.is_empty() {
                continue;
            }
            if entry.starts_with("geoip:")
                || entry.starts_with("ext-ip:")
                || entry.starts_with("ext:")
            {
                return Err(Error::unsupported(format!(
                    "ip condition `{entry}` needs geodata, which is not bundled"
                )));
            }
            let (negate, value) = match entry.strip_prefix('!') {
                Some(rest) => (true, rest.trim()),
                None => (false, entry),
            };
            let (base, prefix) = match value.split_once('/') {
                Some((address, prefix)) => {
                    let base = address
                        .parse::<IpAddr>()
                        .map_err(|e| Error::config(format!("invalid ip `{entry}`: {e}")))?;
                    let prefix = prefix
                        .parse::<u8>()
                        .map_err(|e| Error::config(format!("invalid ip prefix `{entry}`: {e}")))?;
                    let width = if base.is_ipv4() { 32 } else { 128 };
                    if prefix > width {
                        return Err(Error::config(format!(
                            "invalid ip prefix `{entry}`: must be <= {width}"
                        )));
                    }
                    (base, prefix)
                }
                None => {
                    let base = value
                        .parse::<IpAddr>()
                        .map_err(|e| Error::config(format!("invalid ip `{entry}`: {e}")))?;
                    let width = if base.is_ipv4() { 32 } else { 128 };
                    (base, width)
                }
            };
            compiled.push(IpEntry {
                base,
                prefix,
                negate,
            });
        }
        Ok(Self { entries: compiled })
    }

    /// 是否包含任何有效条件。
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// 判断 IP 是否命中。
    pub fn matches(&self, ip: IpAddr) -> bool {
        self.entries
            .iter()
            .any(|entry| entry.contains(ip) != entry.negate)
    }
}

/// 端口条件。
///
/// 接受数字、`"80"`、`"100-200"`、`"80,443"`，以及由它们组成的数组。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PortList {
    /// 端口段（闭区间）。
    ranges: Vec<(u16, u16)>,
}

impl PortList {
    /// 解析字符串形式的端口条件（逗号分隔）。
    pub fn parse(text: &str) -> Result<Self> {
        let mut ranges = Vec::new();
        for item in split_list(text) {
            ranges.push(parse_port_range(&item)?);
        }
        Ok(Self { ranges })
    }

    /// 是否包含任何有效条件。
    pub fn is_empty(&self) -> bool {
        self.ranges.is_empty()
    }

    /// 端口段列表。
    pub fn ranges(&self) -> &[(u16, u16)] {
        &self.ranges
    }

    /// 判断端口是否命中。
    pub fn matches(&self, port: u16) -> bool {
        self.ranges
            .iter()
            .any(|(from, to)| (*from..=*to).contains(&port))
    }
}

/// 解析单个端口或端口段。
fn parse_port_range(item: &str) -> Result<(u16, u16)> {
    let bad = || Error::config(format!("invalid port range `{item}`"));
    match item.split_once('-') {
        Some((from, to)) => {
            let from = from.trim().parse::<u16>().map_err(|_| bad())?;
            let to = to.trim().parse::<u16>().map_err(|_| bad())?;
            if from > to {
                return Err(bad());
            }
            Ok((from, to))
        }
        None => {
            let port = item.trim().parse::<u16>().map_err(|_| bad())?;
            Ok((port, port))
        }
    }
}

impl Serialize for PortList {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        self.ranges.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for PortList {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Entry {
            Number(u16),
            Text(String),
        }

        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Raw {
            One(Entry),
            Many(Vec<Entry>),
        }

        fn convert<E: serde::de::Error>(entry: Entry) -> std::result::Result<Vec<(u16, u16)>, E> {
            match entry {
                Entry::Number(port) => Ok(vec![(port, port)]),
                Entry::Text(text) => match PortList::parse(&text) {
                    Ok(list) => Ok(list.ranges),
                    Err(e) => Err(E::custom(e.to_string())),
                },
            }
        }

        let ranges = match Raw::deserialize(deserializer)? {
            Raw::One(entry) => convert(entry)?,
            Raw::Many(entries) => {
                let mut ranges = Vec::new();
                for entry in entries {
                    ranges.extend(convert(entry)?);
                }
                ranges
            }
        };
        Ok(Self { ranges })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn list(items: &[&str]) -> Vec<String> {
        items.iter().map(|item| (*item).to_string()).collect()
    }

    #[test]
    fn string_list_accepts_array_and_comma_string() {
        let array: StringList = serde_json::from_str(r#"["a","b"]"#).unwrap();
        assert_eq!(array.as_slice(), ["a", "b"]);
        let comma: StringList = serde_json::from_str(r#""a, b ,,c""#).unwrap();
        assert_eq!(comma.as_slice(), ["a", "b", "c"]);
    }

    #[test]
    fn hybrid_domain_matching() {
        let matcher = DomainMatcher::build(
            &list(&[
                "full:example.com",
                "domain:test.org",
                "keyword:cdn",
                "regexp:^a.*z$",
            ]),
            DomainType::Keyword,
            MatchMode::Hybrid,
        )
        .unwrap();

        assert!(matcher.matches("example.com"));
        assert!(!matcher.matches("sub.example.com"));
        assert!(matcher.matches("Test.Org"));
        assert!(matcher.matches("a.test.org"));
        // `domain:` 是「后缀 + 点边界」，因此这里不应命中。
        assert!(!matcher.matches("notatest.org.net"));
        assert!(matcher.matches("my-cdn-host.net"));
        assert!(matcher.matches("abz"));
        assert!(!matcher.matches("example.org"));
        assert!(!matcher.matches(""));
    }

    #[test]
    fn bare_domain_uses_default_type() {
        let keyword =
            DomainMatcher::build(&list(&["example"]), DomainType::Keyword, MatchMode::Hybrid)
                .unwrap();
        assert!(keyword.matches("www.example.net"));

        let subdomain = DomainMatcher::build(
            &list(&["example.com"]),
            DomainType::Domain,
            MatchMode::Hybrid,
        )
        .unwrap();
        assert!(subdomain.matches("www.example.com"));
        assert!(!subdomain.matches("notexample.com"));
    }

    #[test]
    fn regexp_mode_matches_like_hybrid() {
        for mode in [MatchMode::Hybrid, MatchMode::Regexp] {
            let matcher = DomainMatcher::build(
                &list(&["full:example.com", "domain:test.org", "keyword:cdn"]),
                DomainType::Keyword,
                mode,
            )
            .unwrap();
            assert!(matcher.matches("example.com"), "{mode:?}");
            assert!(!matcher.matches("sub.example.com"), "{mode:?}");
            assert!(matcher.matches("a.test.org"), "{mode:?}");
            assert!(!matcher.matches("ateat.org"), "{mode:?}");
            assert!(matcher.matches("my-cdn-host.net"), "{mode:?}");
        }
    }

    #[test]
    fn dotless_and_invalid_conditions() {
        let matcher = DomainMatcher::build(
            &list(&["dotless:abc"]),
            DomainType::Keyword,
            MatchMode::Hybrid,
        )
        .unwrap();
        assert!(matcher.matches("xabcy"));
        assert!(!matcher.matches("xabc.y"));

        assert!(DomainMatcher::build(
            &list(&["dotless:a.b"]),
            DomainType::Keyword,
            MatchMode::Hybrid
        )
        .is_err());
        assert!(
            DomainMatcher::build(&list(&["regexp:["]), DomainType::Keyword, MatchMode::Hybrid)
                .is_err()
        );
        assert!(matches!(
            DomainMatcher::build(
                &list(&["geosite:cn"]),
                DomainType::Keyword,
                MatchMode::Hybrid
            ),
            Err(Error::Unsupported(_))
        ));
    }

    #[test]
    fn ip_matching_with_cidr_and_negation() {
        let matcher =
            IpMatcher::build(&list(&["127.0.0.1", "10.0.0.0/8", "2001:db8::/32"])).unwrap();
        assert!(matcher.matches("127.0.0.1".parse().unwrap()));
        assert!(!matcher.matches("127.0.0.2".parse().unwrap()));
        assert!(matcher.matches("10.255.255.255".parse().unwrap()));
        assert!(!matcher.matches("11.0.0.1".parse().unwrap()));
        assert!(matcher.matches("2001:db8::1".parse().unwrap()));
        assert!(!matcher.matches("2001:db9::1".parse().unwrap()));
        // 跨族不匹配
        assert!(!matcher.matches("::1".parse().unwrap()));

        let negated = IpMatcher::build(&list(&["!10.0.0.0/8"])).unwrap();
        assert!(negated.matches("192.168.1.1".parse().unwrap()));
        assert!(!negated.matches("10.1.2.3".parse().unwrap()));

        // /24 边界：只比较高 24 位。
        let slash24 = IpMatcher::build(&list(&["192.168.1.0/24"])).unwrap();
        assert!(slash24.matches("192.168.1.0".parse().unwrap()));
        assert!(slash24.matches("192.168.1.255".parse().unwrap()));
        assert!(!slash24.matches("192.168.2.0".parse().unwrap()));
        assert!(!slash24.matches("192.168.0.255".parse().unwrap()));

        // /8 边界：两侧各取一个。
        let slash8 = IpMatcher::build(&list(&["10.0.0.0/8"])).unwrap();
        assert!(slash8.matches("10.0.0.0".parse().unwrap()));
        assert!(slash8.matches("10.255.255.255".parse().unwrap()));
        assert!(!slash8.matches("9.255.255.255".parse().unwrap()));
        assert!(!slash8.matches("11.0.0.0".parse().unwrap()));

        // /32 等价于精确匹配。
        let slash32 = IpMatcher::build(&list(&["127.0.0.1/32"])).unwrap();
        assert!(slash32.matches("127.0.0.1".parse().unwrap()));
        assert!(!slash32.matches("127.0.0.2".parse().unwrap()));

        // IPv6 /32 边界。
        let v6 = IpMatcher::build(&list(&["2001:db8::/32"])).unwrap();
        assert!(v6.matches("2001:db8::".parse().unwrap()));
        assert!(v6.matches("2001:db8:ffff::1".parse().unwrap()));
        assert!(!v6.matches("2001:db9::".parse().unwrap()));

        let all = IpMatcher::build(&list(&["0.0.0.0/0"])).unwrap();
        assert!(all.matches("1.2.3.4".parse().unwrap()));
        assert!(!all.matches("::1".parse().unwrap()));

        assert!(matches!(
            IpMatcher::build(&list(&["geoip:cn"])),
            Err(Error::Unsupported(_))
        ));
        assert!(IpMatcher::build(&list(&["10.0.0.0/33"])).is_err());
        assert!(IpMatcher::build(&list(&["not-an-ip"])).is_err());
    }

    #[test]
    fn port_lists_parse_and_match() {
        let simple: PortList = serde_json::from_str("443").unwrap();
        assert!(simple.matches(443));
        assert!(!simple.matches(444));

        let text: PortList = serde_json::from_str(r#""80,100-200""#).unwrap();
        assert!(text.matches(80));
        assert!(text.matches(100));
        assert!(text.matches(200));
        assert!(!text.matches(99));
        assert!(!text.matches(201));

        let array: PortList = serde_json::from_str(r#"["80","100-200",443]"#).unwrap();
        assert!(array.matches(443));
        assert!(array.matches(150));
        assert_eq!(array.ranges().len(), 3);
        assert!(!array.is_empty());

        assert!(serde_json::from_str::<PortList>(r#""200-100""#).is_err());
        assert!(serde_json::from_str::<PortList>(r#""abc""#).is_err());
        assert!(serde_json::from_str::<PortList>(r#""0-70000""#).is_err());
    }

    #[test]
    fn match_mode_parsing() {
        assert_eq!("hybrid".parse::<MatchMode>().unwrap(), MatchMode::Hybrid);
        assert_eq!("linear".parse::<MatchMode>().unwrap(), MatchMode::Hybrid);
        assert_eq!("regexp".parse::<MatchMode>().unwrap(), MatchMode::Regexp);
        assert!("nope".parse::<MatchMode>().is_err());
    }
}
