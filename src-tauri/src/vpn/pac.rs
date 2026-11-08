//! PAC 脚本：规则和进程内路由完全一致（黑名单优先，默认直连）。

use super::rules::{pac_entry, PacEntry, RuleSet};

pub fn build_pac(proxy_port: u16, rules: &RuleSet) -> String {
    let direct = js_list(rules.direct_entries());
    let proxy = js_list(rules.proxy_entries());
    format!(
        r#"// 山科大 WebVPN 本地代理 PAC（自动生成）
var PROXY = "PROXY 127.0.0.1:{proxy_port}";
var DIRECT_RULES = {direct};
var PROXY_RULES = {proxy};

function vpnCidrMatch(host, spec) {{
  var parts = spec.split("/");
  if (parts.length !== 2) return false;
  if (!/^\d+\.\d+\.\d+\.\d+$/.test(host)) return false;
  return isInNet(host, parts[0], maskOf(parseInt(parts[1], 10)));
}}

function maskOf(len) {{
  if (len <= 0) return "0.0.0.0";
  if (len >= 32) return "255.255.255.255";
  var m = (0xffffffff << (32 - len)) >>> 0;
  return [(m >>> 24) & 255, (m >>> 16) & 255, (m >>> 8) & 255, m & 255].join(".");
}}

function vpnMatch(host, list) {{
  for (var i = 0; i < list.length; i++) {{
    var e = list[i];
    if (e === "*") return true;
    if (e.indexOf("/") >= 0) {{
      if (vpnCidrMatch(host, e)) return true;
      continue;
    }}
    var d = e.replace(/^\*\./, "").replace(/^\./, "");
    if (host === d || dnsDomainIs(host, "." + d)) return true;
  }}
  return false;
}}

function FindProxyForURL(url, host) {{
  host = host.toLowerCase();
  if (host === "webvpn.sdust.edu.cn" || host === "localhost" || host === "::1") return "DIRECT";
  if (/^127\./.test(host)) return "DIRECT";
  if (vpnMatch(host, DIRECT_RULES)) return "DIRECT";
  if (vpnMatch(host, PROXY_RULES)) return PROXY;
  return "DIRECT";
}}
"#
    )
}

fn js_list(entries: &[String]) -> String {
    let items: Vec<String> = entries
        .iter()
        .filter_map(|e| match pac_entry(e) {
            Some(PacEntry::All) => Some("\"*\"".to_string()),
            Some(PacEntry::Domain(d)) => Some(js_str(&d)),
            // 转成 "网络/前缀" 形式，运行时再算掩码
            Some(PacEntry::Net(net, mask)) => {
                let prefix = mask_to_prefix(&mask);
                Some(js_str(&format!("{net}/{prefix}")))
            }
            None => None,
        })
        .collect();
    format!("[{}]", items.join(","))
}

fn mask_to_prefix(mask: &str) -> u8 {
    match mask.parse::<std::net::Ipv4Addr>() {
        Ok(m) => u32::from(m).count_ones() as u8,
        Err(_) => 32,
    }
}

fn js_str(s: &str) -> String {
    serde_json::to_string(s).unwrap_or_else(|_| "\"\"".to_string())
}

#[cfg(test)]
mod tests {
    use super::super::rules::RuleSet;
    use super::build_pac;

    #[test]
    fn pac_contains_both_lists() {
        let rules = RuleSet::new(
            &["sdust.edu.cn".into(), "10.0.0.0/8".into()],
            &["baidu.com".into()],
        );
        let pac = build_pac(8899, &rules);
        assert!(pac.contains("PROXY 127.0.0.1:8899"));
        assert!(pac.contains("sdust.edu.cn"));
        assert!(pac.contains("10.0.0.0/8"));
        assert!(pac.contains("baidu.com"));
        assert!(pac.contains("DIRECT_RULES"));
    }

    #[test]
    fn pac_keeps_star() {
        let rules = RuleSet::new(&["*".into()], &[]);
        let pac = build_pac(8899, &rules);
        assert!(pac.contains("\"*\""));
    }
}
