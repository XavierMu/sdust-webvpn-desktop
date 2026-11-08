//! 响应改写：把 WebVPN 生成的 `/http(s)/<hex>/...` 还原成目标原始地址。

use once_cell::sync::Lazy;
use regex::Regex;

use super::wrd::decode_host;

static RE_ORIGIN: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?i)(?:https?:)?//webvpn\.sdust\.edu\.cn").unwrap());
static RE_PATH: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"/(https?)(?:-(\d+))?/([0-9a-fA-F]{32,})").unwrap());
static RE_SCRIPT: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?i)<script\b[^>]*\bsrc\s*=\s*["'][^"']*/wengine-vpn/[^"']*["'][^>]*>\s*</script>"#)
        .unwrap()
});
static RE_LINK: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?i)<link\b[^>]*\bhref\s*=\s*["'][^"']*/wengine-vpn/[^"']*["'][^>]*>"#).unwrap()
});
static RE_SETCOOKIE_DOMAIN: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?i);\s*domain=[^;]*").unwrap());
static RE_SETCOOKIE_PATH: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i);\s*path=/(?:https?)(?:-\d+)?/[0-9a-fA-F]{32,}[^;]*").unwrap()
});

/// 把文本里所有 `/http[s][-port]/<hex>` 还原成 `scheme://host`
pub fn rewrite_links(text: &str) -> String {
    let stripped = RE_ORIGIN.replace_all(text, "");
    RE_PATH
        .replace_all(&stripped, |caps: &regex::Captures| {
            let scheme = &caps[1];
            let hex = caps[3].to_lowercase();
            match decode_host(&hex) {
                Ok(host) => format!("{scheme}://{host}"),
                Err(_) => caps[0].to_string(),
            }
        })
        .into_owned()
}

/// 去掉门户注入的客户端改写脚本，否则它会把链接又改回 /http/…
pub fn strip_vpn_scripts(html: &str) -> String {
    let out = RE_SCRIPT.replace_all(html, "");
    RE_LINK.replace_all(&out, "").into_owned()
}

/// WebVPN 会把校内站点的 JS 包成 `vpn_eval(<函数体字符串>, "<url>")`、把 SPA 构建产物里的
/// 属性访问改写成 `vpn_get_obj(...)` 等，实现都在门户的 `/wengine-vpn/js/main.js` 里
/// （我们为了不被二次改写会删掉它）。透明代理下这些函数只需要“原样执行 / 原样访问”，
/// 所以注入一个等价的最小实现。
const VPN_SHIM: &str = concat!(
    r#"<script>(function(){var g=window;"#,
    // vpn_eval：WebVPN 用它将 "函数体字符串" 当脚本执行
    r#"if(!g.vpn_eval)g.vpn_eval=function(c,u){try{var s=document.createElement('script');"#,
    r#"s.text=String(c)+"\n//# sourceURL="+(u||'vpn-eval.js');"#,
    r#"(document.head||document.documentElement).appendChild(s);"#,
    r#"if(s.parentNode)s.parentNode.removeChild(s)}"#,
    r#"catch(e){try{(0,eval)(String(c))}catch(e2){if(g.console)console.error('[vpn_eval]',e2)}}};"#,
    r#"if(!g.vpn_get_obj)g.vpn_get_obj=function(o,k){return o==null?k:o[k]};"#,
    r#"if(!g.vpn_set_obj)g.vpn_set_obj=function(o,k,v){o[k]=v;return v};"#,
    r#"if(!g.vpn_call_fn)g.vpn_call_fn=function(o,k){var a=[].slice.call(arguments,2);"#,
    r#"var f=o==null?undefined:o[k];return typeof f==='function'?f.apply(o,a):undefined};"#,
    r#"if(!g.vpn_instance_of)g.vpn_instance_of=function(a,b){return a instanceof b};"#,
    // vpn_rewrite_js(code, mode)：WebVPN 用它把内联事件里的函数体"改写成可 eval 的脚本"。
    // 我们在 HTML 层已把地址还原，所以这里只负责让 `return` 合法、`this` 保持原样。
    r#"if(!g.vpn_rewrite_js)g.vpn_rewrite_js=function(c,m){var s=String(c==null?'':c);"#,
    r#"if(s.indexOf('return')<0)return s;var nl=String.fromCharCode(10);"#,
    r#"return '(function(){'+nl+s+nl+'}).call(this)'};"#,
    r#"if(!g.vpn_rewrite_url)g.vpn_rewrite_url=function(u){return u};"#,
    r#"if(!g.vpn_get_origin)g.vpn_get_origin=function(){return location.origin};"#,
    r#"var SHIM_KEYS=['vpn_eval','vpn_get_obj','vpn_set_obj','vpn_call_fn','vpn_instance_of',"#,
    r#"'vpn_rewrite_js','vpn_rewrite_url','vpn_get_origin','vpn_inject_script',"#,
    r#"'vpn_inject_scripts_window','vpn_update_config','vpn_update_cookie','vpn_reload_hook'];"#,
    r#"if(!g.vpn_inject_script)g.vpn_inject_script=function(el){return el};"#,
    r#"if(!g.vpn_inject_scripts_window)g.vpn_inject_scripts_window=function(el){"#,
    r#"try{var t=window.top;if(t&&t!==g){for(var i=0;i<SHIM_KEYS.length;i++){var k=SHIM_KEYS[i];"#,
    r#"if(!t[k]){try{t[k]=g[k]}catch(e){}}}}}catch(e){}return el};"#,
    r#"if(!g.vpn_update_config)g.vpn_update_config=function(){return null};"#,
    r#"if(!g.vpn_update_cookie)g.vpn_update_cookie=function(){return null};"#,
    r#"if(!g.vpn_reload_hook)g.vpn_reload_hook=null;"#,
    r#"})();</script>"#
);

/// 给 HTML 注入 `vpn_*` 兼容层（校内站点的 JS/SPA 依赖它；已注入则跳过）
pub fn inject_vpn_shim(html: &str) -> String {
    if html.contains("g.vpn_get_obj=") || html.contains("window.vpn_get_obj") {
        return html.to_string();
    }
    static RE_HEAD: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?i)<head\b[^>]*>").unwrap());
    if let Some(m) = RE_HEAD.find(html) {
        let at = m.end();
        return format!("{}{}{}", &html[..at], VPN_SHIM, &html[at..]);
    }
    static RE_HTML: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?i)<html\b[^>]*>").unwrap());
    if let Some(m) = RE_HTML.find(html) {
        let at = m.end();
        return format!("{}{}{}", &html[..at], VPN_SHIM, &html[at..]);
    }
    format!("{VPN_SHIM}{html}")
}

/// 改写 Location 等跳转地址
pub fn rewrite_url(u: &str) -> String {
    if u.is_empty() {
        return u.to_string();
    }
    let stripped = RE_ORIGIN.replace(u, "");
    if !RE_PATH.is_match(&stripped) {
        return u.to_string();
    }
    rewrite_links(&stripped)
}

/// 改写 Set-Cookie：去掉 Domain，路径前缀改成 `/`
pub fn rewrite_set_cookie(line: &str) -> String {
    let out = RE_SETCOOKIE_DOMAIN.replace_all(line, "");
    RE_SETCOOKIE_PATH
        .replace_all(&out, "; Path=/")
        .into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rewrites_links_back_to_origins() {
        let html = r#"<a href="/http/77726476706e69737468656265737421fdee0f8f23257b44300d8db9d6562d/cas/login">x</a>
<img src="//webvpn.sdust.edu.cn/https/77726476706e69737468656265737421fdee0f8f23257b44300d8db9d6562d/a.png">"#;
        let out = rewrite_links(html);
        assert!(out.contains("http://my.sdust.edu.cn/cas/login"));
        assert!(out.contains("https://my.sdust.edu.cn/a.png"));
        assert!(!out.contains("webvpn.sdust.edu.cn"));
    }

    #[test]
    fn strips_portal_scripts_and_fixes_cookies() {
        let html = r#"<script src="/wengine-vpn/js/main.js"></script><p>ok</p>"#;
        assert_eq!(strip_vpn_scripts(html), "<p>ok</p>");
        assert_eq!(
            rewrite_set_cookie("a=1; Domain=.sdust.edu.cn; Path=/http/77726476706e69737468656265737421fdee0f8f23257b44300d8db9d6562d/x; HttpOnly"),
            "a=1; Path=/; HttpOnly"
        );
    }

    #[test]
    fn injects_vpn_shim_once() {
        let html = "<!doctype html><html><head><title>t</title></head><body></body></html>";
        let out = inject_vpn_shim(html);
        assert!(out.contains("g.vpn_get_obj="));
        assert!(out.contains("g.vpn_eval="));
        assert!(out.find("g.vpn_get_obj=").unwrap() < out.find("<title>").unwrap());
        // 再注入一次不会重复
        assert_eq!(inject_vpn_shim(&out), out);
    }

    #[test]
    fn rewrites_locations() {        assert_eq!(
            rewrite_url("https://webvpn.sdust.edu.cn/https/77726476706e69737468656265737421fdee0f8f23257b44300d8db9d6562d/cas/"),
            "https://my.sdust.edu.cn/cas/"
        );
        assert_eq!(rewrite_url("https://www.baidu.com/x"), "https://www.baidu.com/x");
    }
}
