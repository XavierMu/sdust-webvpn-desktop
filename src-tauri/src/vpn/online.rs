//! 在线分流规则：从用户给的网址拉一份「公共同步规则」，与本地名单合并。
//!
//! 支持的响应格式（都按「白名单 / 黑名单」两段来理解）：
//!
//! 1. JSON（推荐，本项目自己的格式）
//!    ```json
//!    {
//!      "name": "SDUST 校内站点公共规则",
//!      "updated": "2026-10-31",
//!      "proxy": ["sdust.edu.cn", "10.0.0.0/8", "*.cnki.net"],
//!      "direct": ["zhfw.sdust.edu.cn"]
//!    }
//!    ```
//! 2. JSON 其它字段名也认：`whitelist` / `blacklist`、`proxyHosts` / `directHosts`、
//!    或者 Clash 风格的 `{ "payload": [...] }`（按白名单处理）。
//! 3. 纯文本：一行一条，# 开头是注释；`[proxy]` / `[direct]` 段标记切换归属，
//!    没标段时整份都当白名单。
//!
//! 规则条目本身与本地名单同一套写法（域名后缀 / CIDR / 单个 IP / `*`），
//! 解析与去重都在 `rules.rs` 里，这里只负责「把远端文本变成两个列表」。

use serde::{Deserialize, Serialize};

use super::rules::split_entries;

/// 远端规则原文大小上限：防止有人把整个网站当规则文件塞过来
pub const MAX_BYTES: usize = 1024 * 1024;

#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct RemoteRules {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub updated: String,
    #[serde(default)]
    pub proxy: Vec<String>,
    #[serde(default)]
    pub direct: Vec<String>,
}

impl RemoteRules {
    pub fn total(&self) -> usize {
        self.proxy.len() + self.direct.len()
    }
}

/// 在 JSON 里找一个「字符串列表」字段：先按给定键名，都找不到就返回 None。
/// 数组里允许混杂非字符串（会被忽略），字符串里也允许用换行/逗号分隔多条。
fn find_list(v: &serde_json::Value, keys: &[&str]) -> Option<Vec<String>> {
    for k in keys {
        match v.get(k) {
            Some(serde_json::Value::Array(items)) => {
                let mut out = Vec::new();
                for it in items {
                    if let Some(s) = it.as_str() {
                        out.extend(split_entries(s));
                    }
                }
                return Some(out);
            }
            Some(serde_json::Value::String(s)) => return Some(split_entries(s)),
            _ => {}
        }
    }
    None
}

fn dedup(list: Vec<String>) -> Vec<String> {
    let mut seen = std::collections::HashSet::new();
    list.into_iter()
        .filter(|h| !h.is_empty() && seen.insert(h.to_ascii_lowercase()))
        .collect()
}

/// 纯文本规则：一行一条，`#` / `//` 开头是注释；`[proxy]`、`[direct]`（也认
/// `[whitelist]`、`[blacklist]`）切换后续行的归属，没标段的算白名单。
fn parse_text(text: &str) -> RemoteRules {
    let mut out = RemoteRules::default();
    let mut section = true; // true = 白名单
    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() {
            continue;
        }
        let low = line.to_ascii_lowercase();
        if low.starts_with('[') && low.ends_with(']') {
            let name = &low[1..low.len() - 1];
            if name.contains("direct") || name.contains("black") || name.contains("直连") {
                section = false;
            } else if name.contains("proxy") || name.contains(" white") || name.contains("白名单") {
                section = true;
            }
            continue;
        }
        if line.starts_with('#') || line.starts_with("//") || low.starts_with("http") {
            continue;
        }
        for item in split_entries(line) {
            if section {
                out.proxy.push(item);
            } else {
                out.direct.push(item);
            }
        }
    }
    out.proxy = dedup(out.proxy);
    out.direct = dedup(out.direct);
    out
}

/// 把一段 JSON 规则文本解析成 `RemoteRules`（顶层数组按 Clash `payload` 风格整份当白名单）。
fn parse_json(body: &str) -> Result<RemoteRules, String> {
    let v: serde_json::Value =
        serde_json::from_str(body).map_err(|e| format!("规则不是合法 JSON：{e}"))?;
    Ok(if let serde_json::Value::Array(items) = &v {
        let mut list = Vec::new();
        for it in items {
            if let Some(s) = it.as_str() {
                list.extend(split_entries(s));
            }
        }
        RemoteRules {
            proxy: dedup(list),
            ..Default::default()
        }
    } else {
        RemoteRules {
            name: v
                .get("name")
                .or_else(|| v.get("title"))
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .to_string(),
            updated: v
                .get("updated")
                .or_else(|| v.get("update"))
                .or_else(|| v.get("date"))
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .to_string(),
            proxy: dedup(
                find_list(
                    &v,
                    &["proxy", "whitelist", "white_list", "proxyHosts", "payload"],
                )
                .unwrap_or_default(),
            ),
            direct: dedup(
                find_list(&v, &["direct", "blacklist", "black_list", "directHosts"])
                    .unwrap_or_default(),
            ),
        }
    })
}

/// 把远端返回的正文解析成规则；解析不出任何条目时返回错误（让界面能提示用户）。
pub fn parse(body: &str) -> Result<RemoteRules, String> {
    let body = body.trim().trim_start_matches('\u{feff}'); // 顺手吃掉可能的 BOM
    if body.is_empty() {
        return Err("规则内容为空".into());
    }
    // `{` 开头只能是 JSON；`[` 开头两种都可能（顶层数组 / `[proxy]` 分段），先试 JSON、不行再当文本。
    let mut rules = if body.starts_with('{') {
        parse_json(body)?
    } else if body.starts_with('[') {
        match parse_json(body) {
            Ok(r) => r,
            Err(_) => parse_text(body),
        }
    } else {
        parse_text(body)
    };
    if rules.total() == 0 {
        return Err("规则里没有可用的条目（支持域名后缀、IPv4、10.0.0.0/8 这类网段）".into());
    }
    // 单条太长、含空格的条目直接丢掉：多半是解析串了
    rules.proxy.retain(|h| h.len() <= 64 && !h.contains(char::is_whitespace));
    rules.direct.retain(|h| h.len() <= 64 && !h.contains(char::is_whitespace));
    if rules.total() == 0 {
        return Err("规则里没有可用的条目（支持域名后缀、IPv4、10.0.0.0/8 这类网段）".into());
    }
    Ok(rules)
}

/// 把远端规则合并到本地名单：远端条目排在前面（先匹配），本地条目补在后面。
pub fn merge(
    remote: &RemoteRules,
    local_proxy: &[String],
    local_direct: &[String],
) -> (Vec<String>, Vec<String>) {
    let mut proxy = remote.proxy.clone();
    proxy.extend(local_proxy.iter().cloned());
    let mut direct = remote.direct.clone();
    direct.extend(local_direct.iter().cloned());
    (dedup(proxy), dedup(direct))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_json_rules() {
        let body = r#"{"name":"公共规则","updated":"2026-10-31","proxy":["sdust.edu.cn","10.0.0.0/8"],"direct":["zhfw.sdust.edu.cn"]}"#;
        let r = parse(body).unwrap();
        assert_eq!(r.name, "公共规则");
        assert_eq!(r.updated, "2026-10-31");
        assert_eq!(r.proxy, vec!["sdust.edu.cn", "10.0.0.0/8"]);
        assert_eq!(r.direct, vec!["zhfw.sdust.edu.cn"]);
    }

    #[test]
    fn parses_clash_payload() {
        let body = r#"{"payload":["*.cnki.net","www.sslibrary.com"]}"#;
        let r = parse(body).unwrap();
        assert_eq!(r.proxy.len(), 2);
        assert_eq!(r.direct.len(), 0);
    }

    #[test]
    fn parses_text_sections() {
        let body = "# 公共规则\n[proxy]\nsdust.edu.cn\n10.0.0.0/8\n[direct]\nzhfw.sdust.edu.cn\n";
        let r = parse(body).unwrap();
        assert_eq!(r.proxy, vec!["sdust.edu.cn", "10.0.0.0/8"]);
        assert_eq!(r.direct, vec!["zhfw.sdust.edu.cn"]);
    }

    #[test]
    fn parses_text_starting_with_section() {
        // 正文直接以 [proxy] 开头时不能被当成 JSON 数组（这条曾经踩过）
        let body = "[proxy]\nsdust.edu.cn\n[direct]\nzhfw.sdust.edu.cn\n";
        let r = parse(body).unwrap();
        assert_eq!(r.proxy, vec!["sdust.edu.cn"]);
        assert_eq!(r.direct, vec!["zhfw.sdust.edu.cn"]);
    }

    #[test]
    fn rejects_empty() {
        assert!(parse("   ").is_err());
        assert!(parse(r#"{"proxy":[]}"#).is_err());
    }

    #[test]
    fn merge_puts_remote_first() {
        let remote = RemoteRules {
            proxy: vec!["cnki.net".into()],
            direct: vec!["zhfw.sdust.edu.cn".into()],
            ..Default::default()
        };
        let (p, d) = merge(&remote, &["sdust.edu.cn".into()], &[]);
        assert_eq!(p, vec!["cnki.net", "sdust.edu.cn"]);
        assert_eq!(d, vec!["zhfw.sdust.edu.cn"]);
    }
}
