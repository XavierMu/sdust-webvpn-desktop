//! 黑白名单路由规则。
//!
//! - **全局模式**：忽略两个名单，除内置直连外一律走 WebVPN
//! - PAC 模式：白名单（proxy）命中走 WebVPN；黑名单（direct）命中直连，**优先级高于白名单**；
//!   两个都不命中直连
//!
//! 条目写法：
//! - `*`                 全部主机
//! - `lib.sdust.edu.cn`  本机 + 所有子域
//! - `*.example.com`     同上（`*.` / 前导点只是写法糖，含义一样）
//! - `10.0.0.0/8`        IPv4 网段
//! - `172.18.129.250`    单个 IPv4（等价 /32）
//!
//! 内置规则：`webvpn.sdust.edu.cn`（WebVPN 自身）、`localhost`、`127.0.0.0/8`、
//! `::1` 永远直连，避免代理打回自己形成环路。

use std::net::Ipv4Addr;

pub const WEBVPN_HOST: &str = "webvpn.sdust.edu.cn";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Decision {
    Proxy,
    Direct,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Rule {
    /// 匹配全部主机
    All,
    /// 域名后缀：host == domain 或者 host 以 ".domain" 结尾
    Domain(String),
    /// IPv4 网段：network / prefix
    Cidr(u32, u8),
}

impl Rule {
    fn parse(raw: &str) -> Option<Rule> {
        let s = raw.trim().to_ascii_lowercase();
        if s.is_empty() || s.starts_with('#') || s.starts_with("//") {
            return None;
        }
        if s == "*" {
            return Some(Rule::All);
        }
        if let Some((net, len)) = s.split_once('/') {
            let ip: Ipv4Addr = net.trim().parse().ok()?;
            let prefix: u8 = len.trim().parse().ok()?;
            if prefix > 32 {
                return None;
            }
            return Some(Rule::Cidr(mask_of(u32::from(ip), prefix), prefix));
        }
        if let Ok(ip) = s.parse::<Ipv4Addr>() {
            return Some(Rule::Cidr(u32::from(ip), 32));
        }
        let domain = s
            .strip_prefix("*.")
            .or_else(|| s.strip_prefix('.'))
            .unwrap_or(&s)
            .trim_end_matches('.')
            .to_string();
        if domain.is_empty() || domain.contains('/') || domain.contains(':') {
            return None;
        }
        Some(Rule::Domain(domain))
    }

    fn matches(&self, host: &str) -> bool {
        match self {
            Rule::All => true,
            Rule::Domain(d) => host == d || host.ends_with(&format!(".{d}")),
            Rule::Cidr(net, prefix) => match host.parse::<Ipv4Addr>() {
                Ok(ip) => mask_of(u32::from(ip), *prefix) == *net,
                Err(_) => false,
            },
        }
    }
}

fn mask_of(ip: u32, prefix: u8) -> u32 {
    if prefix == 0 {
        0
    } else {
        ip & (u32::MAX << (32 - prefix))
    }
}

#[derive(Clone, Debug, Default)]
pub struct RuleSet {
    proxy: Vec<Rule>,
    direct: Vec<Rule>,
    proxy_raw: Vec<String>,
    direct_raw: Vec<String>,
    /// 全局模式：忽略名单，除内置直连外全部走 WebVPN
    global_mode: bool,
}

impl RuleSet {
    pub fn new(proxy: &[String], direct: &[String]) -> Self {
        Self {
            proxy: parse_list(proxy),
            direct: parse_list(direct),
            proxy_raw: clean_list(proxy),
            direct_raw: clean_list(direct),
            global_mode: false,
        }
    }

    /// 全局模式：忽略黑白名单，除内置直连（WebVPN 自身 / 本机）外全部走 WebVPN
    pub fn global(proxy: &[String], direct: &[String]) -> Self {
        Self {
            global_mode: true,
            ..Self::new(proxy, direct)
        }
    }

    pub fn decide(&self, host: &str) -> Decision {
        let host = normalize_host(host);
        if host.is_empty() || is_builtin_direct(&host) {
            return Decision::Direct;
        }
        if self.global_mode {
            return Decision::Proxy;
        }
        if self.direct.iter().any(|r| r.matches(&host)) {
            return Decision::Direct;
        }
        if self.proxy.iter().any(|r| r.matches(&host)) {
            return Decision::Proxy;
        }
        Decision::Direct
    }

    pub fn proxy_entries(&self) -> &[String] {
        &self.proxy_raw
    }

    pub fn direct_entries(&self) -> &[String] {
        &self.direct_raw
    }

    pub fn is_empty(&self) -> bool {
        self.proxy.is_empty() && self.direct.is_empty()
    }
}

fn parse_list(list: &[String]) -> Vec<Rule> {
    list.iter().filter_map(|s| Rule::parse(s)).collect()
}

fn clean_list(list: &[String]) -> Vec<String> {
    list.iter()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty() && !s.starts_with('#'))
        .collect()
}

pub fn normalize_host(host: &str) -> String {
    host.trim()
        .trim_matches(|c| c == '[' || c == ']')
        .trim_end_matches('.')
        .to_ascii_lowercase()
}

fn is_builtin_direct(host: &str) -> bool {
    if host == WEBVPN_HOST || host == "localhost" || host == "::1" {
        return true;
    }
    if let Ok(ip) = host.parse::<Ipv4Addr>() {
        return ip.is_loopback();
    }
    false
}

/// PAC 里能表达的规则形态
pub enum PacEntry {
    All,
    Domain(String),
    Net(String, String), // 网络地址, 子网掩码
}

/// 把一条配置转换成 PAC 可用的形态（非法条目返回 None）
pub fn pac_entry(raw: &str) -> Option<PacEntry> {
    match Rule::parse(raw)? {
        Rule::All => Some(PacEntry::All),
        Rule::Domain(d) => Some(PacEntry::Domain(d)),
        Rule::Cidr(net, prefix) => {
            let mask = if prefix == 0 { 0 } else { u32::MAX << (32 - prefix) };
            Some(PacEntry::Net(
                Ipv4Addr::from(net).to_string(),
                Ipv4Addr::from(mask).to_string(),
            ))
        }
    }
}

/// 把配置里的条目拆成列表（支持换行、逗号、分号、空白分隔）
pub fn split_entries(text: &str) -> Vec<String> {
    text.split(|c: char| c == '\n' || c == ',' || c == ';' || c == '\t')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| x.to_string()).collect()
    }

    #[test]
    fn whitelist_matches_subdomains() {
        let r = RuleSet::new(&s(&["lib.sdust.edu.cn"]), &[]);
        assert_eq!(r.decide("lib.sdust.edu.cn"), Decision::Proxy);
        assert_eq!(r.decide("a.b.lib.sdust.edu.cn"), Decision::Proxy);
        assert_eq!(r.decide("other.sdust.edu.cn"), Decision::Direct);
    }

    #[test]
    fn wildcard_and_bare_domain() {
        let r = RuleSet::new(&s(&["*.example.com", ".test.org", "plain.net"]), &[]);
        assert_eq!(r.decide("a.example.com"), Decision::Proxy);
        assert_eq!(r.decide("example.com"), Decision::Proxy); // *. 等同于裸域名
        assert_eq!(r.decide("x.test.org"), Decision::Proxy);
        assert_eq!(r.decide("plain.net"), Decision::Proxy);
    }

    #[test]
    fn cidr_and_ip() {
        let r = RuleSet::new(&s(&["10.0.0.0/8", "172.18.129.250", "192.168.0.0/16"]), &[]);
        assert_eq!(r.decide("10.1.2.3"), Decision::Proxy);
        assert_eq!(r.decide("172.18.129.250"), Decision::Proxy);
        assert_eq!(r.decide("172.18.129.251"), Decision::Direct);
        assert_eq!(r.decide("192.168.5.5"), Decision::Proxy);
        assert_eq!(r.decide("8.8.8.8"), Decision::Direct);
    }

    #[test]
    fn direct_wins_over_proxy() {
        let r = RuleSet::new(&s(&["*"]), &s(&["baidu.com", "10.0.0.0/8"]));
        assert_eq!(r.decide("www.baidu.com"), Decision::Direct);
        assert_eq!(r.decide("10.9.9.9"), Decision::Direct);
        assert_eq!(r.decide("github.com"), Decision::Proxy);
    }

    #[test]
    fn default_is_direct() {
        let r = RuleSet::new(&s(&["sdust.edu.cn"]), &[]);
        assert_eq!(r.decide("www.baidu.com"), Decision::Direct);
        assert_eq!(r.decide(""), Decision::Direct);
    }

    #[test]
    fn global_ignores_lists_but_keeps_builtin() {
        let r = RuleSet::global(&s(&["sdust.edu.cn"]), &s(&["www.baidu.com"]));
        assert_eq!(r.decide("www.baidu.com"), Decision::Proxy);
        assert_eq!(r.decide("example.com"), Decision::Proxy);
        assert_eq!(r.decide("zs.sdust.edu.cn"), Decision::Proxy);
        assert_eq!(r.decide("webvpn.sdust.edu.cn"), Decision::Direct);
        assert_eq!(r.decide("127.0.0.1"), Decision::Direct);
    }

    #[test]
    fn builtin_never_proxied() {
        let r = RuleSet::new(&s(&["*"]), &[]);
        assert_eq!(r.decide("webvpn.sdust.edu.cn"), Decision::Direct);
        assert_eq!(r.decide("localhost"), Decision::Direct);
        assert_eq!(r.decide("127.0.0.1"), Decision::Direct);
    }

    #[test]
    fn split_entries_mixed_separators() {
        let got = split_entries("a.com\n b.com, c.com;d.com\n\n");
        assert_eq!(got, vec!["a.com", "b.com", "c.com", "d.com"]);
    }
}
