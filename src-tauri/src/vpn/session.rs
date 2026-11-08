//! 会话：CAS 登录（RSA 加密密码）、Cookie 持久化、保活、掉线自动重登。

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use once_cell::sync::Lazy;
use regex::Regex;
use rsa::BigUint;

use super::cookies::CookieJar;
use super::creds::Creds;
use super::paths::Paths;
use super::wrd::{WEBVPN_HOST, WEBVPN_ORIGIN};

static RE_FORM: Lazy<Regex> =
    Lazy::new(|| Regex::new(r#"<form id="fm1" action="([^"]+)""#).unwrap());
static RE_EXEC: Lazy<Regex> =
    Lazy::new(|| Regex::new(r#"name="execution" value="([^"]+)""#).unwrap());
static RE_TITLE: Lazy<Regex> = Lazy::new(|| Regex::new(r"<title>([^<]*)</title>").unwrap());
static RE_MSG: Lazy<Regex> = Lazy::new(|| Regex::new(r#"id="msg"[^>]*>([^<]+)<"#).unwrap());
static RE_ERR: Lazy<Regex> =
    Lazy::new(|| Regex::new(r#"class="errors"[^>]*>([\s\S]{0,200}?)<"#).unwrap());

pub fn ticket_name() -> String {
    format!("wengine_vpn_ticket{}", WEBVPN_HOST.replace('.', "_"))
}

#[derive(Debug, Clone)]
pub struct Resp {
    pub status: u16,
    pub url: String,
    pub location: Option<String>,
    pub content_type: String,
    pub set_cookie: Vec<String>,
    pub body: Bytes,
}

impl Resp {
    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).to_string()
    }
    pub fn is_redirect(&self) -> bool {
        (300..400).contains(&self.status)
    }
}

pub struct Session {
    pub client: reqwest::Client,
    pub jar: Mutex<CookieJar>,
    pub creds: Mutex<Option<Creds>>,
    cookies_path: PathBuf,
    login_lock: tokio::sync::Mutex<()>,
    last_login: Mutex<Option<u64>>,
    /// 最近一次登录失败的原因（成功则清空），供界面直观提示
    last_error: Mutex<Option<(String, u64)>>,
    /// 会话是不是**真的**还能用：最近一次真实请求走通了才是 true。
    /// 只看 `logged_in()`（罐里有票据）不够 —— 票据可能过期、可能是匿名票据。
    ok: AtomicBool,
    /// 后台保活连续失败了几次。核心现在随程序常驻，保活每 5 分钟一次；
    /// 本机存的是错密码时等于每 5 分钟撞一次统一认证，容易被刷出验证码甚至锁号，
    /// 所以连续失败 [`KEEPALIVE_MAX_FAILS`] 次就暂停自动重登，等用户手动登录或下次启动。
    keepalive_fails: AtomicU32,
    relogin_paused: AtomicBool,
}

/// 连续失败多少次就暂停后台自动重登
pub const KEEPALIVE_MAX_FAILS: u32 = 3;

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

impl Session {
    pub fn new(paths: &Paths) -> Self {
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(std::time::Duration::from_secs(30))
            .no_proxy()
            .build()
            .expect("构建 HTTP 客户端失败");
        let jar = CookieJar::load(&paths.cookies());
        Self {
            client,
            jar: Mutex::new(jar),
            creds: Mutex::new(None),
            cookies_path: paths.cookies(),
            login_lock: tokio::sync::Mutex::new(()),
            last_login: Mutex::new(None),
            last_error: Mutex::new(None),
            ok: AtomicBool::new(false),
            keepalive_fails: AtomicU32::new(0),
            relogin_paused: AtomicBool::new(false),
        }
    }

    pub fn set_creds(&self, creds: Option<Creds>) {
        *self.creds.lock().unwrap() = creds;
    }

    pub fn has_creds(&self) -> bool {
        self.creds.lock().unwrap().is_some()
    }

    pub fn ticket(&self) -> Option<String> {
        self.jar.lock().unwrap().get(&ticket_name()).cloned()
    }

    pub fn logged_in(&self) -> bool {
        self.ticket().is_some()
    }

    /// 会话当前对应的账号（本机保存/正在使用的那一份），没有则为 None
    pub fn username(&self) -> Option<String> {
        self.creds.lock().unwrap().as_ref().map(|c| c.username.clone())
    }

    /// 最近一次真实请求走通了（会话确认可用）
    pub fn session_ok(&self) -> bool {
        self.ok.load(Ordering::Relaxed)
    }

    fn mark_ok(&self) {
        self.ok.store(true, Ordering::Relaxed);
        // 有请求真的走通了 → 之前攒的失败计数作废
        self.keepalive_fails.store(0, Ordering::Relaxed);
        self.relogin_paused.store(false, Ordering::Relaxed);
    }

    fn mark_bad(&self) {
        self.ok.store(false, Ordering::Relaxed);
    }

    /// 后台保活暂停自动重登了吗（界面上据此提示"自动重登已暂停"）
    pub fn relogin_paused(&self) -> bool {
        self.relogin_paused.load(Ordering::Relaxed)
    }

    pub fn keepalive_fails(&self) -> u32 {
        self.keepalive_fails.load(Ordering::Relaxed)
    }

    /// 记一次保活结果：成功就把计数清零（`mark_ok` 也会清），
    /// 失败累加，到上限就暂停自动重登。
    pub fn note_keepalive(&self, ok: bool) {
        if ok {
            self.keepalive_fails.store(0, Ordering::Relaxed);
            self.relogin_paused.store(false, Ordering::Relaxed);
            return;
        }
        let n = self.keepalive_fails.fetch_add(1, Ordering::Relaxed) + 1;
        if n >= KEEPALIVE_MAX_FAILS {
            self.relogin_paused.store(true, Ordering::Relaxed);
        }
    }

    pub fn cookie_header(&self) -> String {
        self.jar.lock().unwrap().header()
    }

    pub fn save(&self) {
        self.jar.lock().unwrap().save(&self.cookies_path);
    }

    fn absorb(&self, set_cookie: &[String]) {
        self.jar.lock().unwrap().set_from_response(set_cookie);
    }

    pub fn status_json(&self) -> serde_json::Value {
        let t = self.ticket();
        let err = self.last_error.lock().unwrap().clone();
        serde_json::json!({
            "loggedIn": t.is_some(),
            "sessionOk": self.session_ok(),
            // 裸票据（界面自己截断显示），不再拼中文后缀让人去正则裁
            "ticket": t,
            "username": self.username(),
            "cookies": self.jar.lock().unwrap().names(),
            "lastLoginAt": *self.last_login.lock().unwrap(),
            "hasCreds": self.has_creds(),
            "lastError": err.as_ref().map(|(e, _)| e.clone()),
            "lastErrorAt": err.map(|(_, at)| at),
            // 后台自动重登已经暂停（连续失败到上限），界面提示一次
            "reloginPaused": self.relogin_paused(),
            "keepaliveFails": self.keepalive_fails(),
        })
    }

    /// 原始请求（不跟随跳转，自动带/收 Cookie）
    pub async fn raw(
        &self,
        method: reqwest::Method,
        url: &str,
        extra: &[(String, String)],
        body: Option<Bytes>,
    ) -> Result<Resp, String> {
        let mut req = self.client.request(method, url);
        for (k, v) in DEFAULT_HEADERS.iter() {
            req = req.header(*k, *v);
        }
        let ck = self.cookie_header();
        if !ck.is_empty() {
            req = req.header("cookie", ck);
        }
        for (k, v) in extra {
            req = req.header(k, v);
        }
        if let Some(b) = body {
            req = req.body(b);
        }
        let res = req.send().await.map_err(|e| format!("请求失败：{e}"))?;
        let status = res.status().as_u16();
        let location = res
            .headers()
            .get("location")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());
        let content_type = res
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();
        let set_cookie: Vec<String> = res
            .headers()
            .get_all("set-cookie")
            .iter()
            .filter_map(|v| v.to_str().ok().map(|s| s.to_string()))
            .collect();
        let body = res.bytes().await.map_err(|e| format!("读取响应失败：{e}"))?;
        self.absorb(&set_cookie);
        Ok(Resp {
            status,
            url: url.to_string(),
            location,
            content_type,
            set_cookie,
            body,
        })
    }

    pub async fn follow(&self, url: &str, max: usize) -> Result<Resp, String> {
        let mut cur = url.to_string();
        for _ in 0..max {
            let res = self.raw(reqwest::Method::GET, &cur, &[], None).await?;
            if res.is_redirect() {
                if let Some(loc) = &res.location {
                    cur = join_url(&cur, loc)?;
                    continue;
                }
            }
            return Ok(res);
        }
        Err("重定向过多".into())
    }

    /// 登录（并发去重）。失败原因会记进 last_error，界面据此弹「登录失败」提示。
    ///
    /// 失败时必须把 Cookie 罐还原：登录流程会先清空罐子，再访问
    /// `/login?cas_login=true` —— **这一步在没登录的情况下也会下发一张匿名
    /// `wengine_vpn_ticket…`**，留着它会让 `logged_in()` 误报 true（界面显示"已登录"、
    /// 可实际什么都打不开），同时会把用户原本还能用的会话顶掉。
    pub async fn login(&self) -> Result<String, String> {
        let snapshot = self.jar.lock().unwrap().clone();
        let r = self.login_inner().await;
        match &r {
            Ok(_) => {
                *self.last_error.lock().unwrap() = None;
                self.mark_ok();
            }
            Err(e) => {
                *self.jar.lock().unwrap() = snapshot;
                *self.last_error.lock().unwrap() = Some((e.clone(), now_secs()));
            }
        }
        r
    }

    /// 清掉登录失败记录（例如用户点了「稍后」又想手动重试时）
    pub fn clear_last_error(&self) {
        *self.last_error.lock().unwrap() = None;
    }

    async fn login_inner(&self) -> Result<String, String> {
        let _guard = self.login_lock.lock().await;
        let creds = {
            let c = self.creds.lock().unwrap();
            c.clone().ok_or_else(|| "没有可用的账号密码".to_string())?
        };

        // 用全新的罐登录，避免旧 Cookie 干扰
        *self.jar.lock().unwrap() = CookieJar::default();

        let page = self.follow(&format!("{WEBVPN_ORIGIN}/login?cas_login=true"), 10).await?;
        let html = page.text();
        let action_raw = RE_FORM
            .captures(&html)
            .map(|c| c[1].to_string())
            .ok_or_else(|| "CAS 页面结构变化：找不到 fm1 表单".to_string())?;
        let action = join_url(&page.url, &action_raw)?;
        let execution = RE_EXEC
            .captures(&html)
            .map(|c| c[1].to_string())
            .ok_or_else(|| "CAS 页面结构变化：找不到 execution token".to_string())?;

        let cas_base = join_url(&page.url, "./")?;
        let key_url = join_url(&cas_base, "v2/getPubKey")?;
        let key_res = self.raw(reqwest::Method::GET, &key_url, &[], None).await?;
        let pubkey: serde_json::Value = serde_json::from_str(&key_res.text())
            .map_err(|e| format!("公钥不是 JSON：{e}"))?;
        let exponent = pubkey
            .get("exponent")
            .and_then(|v| v.as_str())
            .ok_or_else(|| "公钥缺少 exponent".to_string())?;
        let modulus = pubkey
            .get("modulus")
            .and_then(|v| v.as_str())
            .ok_or_else(|| "公钥缺少 modulus".to_string())?;

        let reversed: String = creds.password.chars().rev().collect();
        let encrypted = rsa_encrypt(exponent, modulus, &reversed)?;

        let form = format!(
            "username={}&password={}&authcode=&rememberMe=true&execution={}&_eventId=submit",
            urlencode(&creds.username),
            urlencode(&encrypted),
            urlencode(&execution)
        );
        let post = self
            .raw(
                reqwest::Method::POST,
                &action,
                &[
                    (
                        "Content-Type".into(),
                        "application/x-www-form-urlencoded".into(),
                    ),
                    ("Origin".into(), WEBVPN_ORIGIN.into()),
                    ("Referer".into(), page.url.clone()),
                ],
                Some(Bytes::from(form)),
            )
            .await?;

        if post.is_redirect() {
            let loc = post.location.clone().unwrap_or_default();
            let next = join_url(&post.url, &loc)?;
            let done = self.follow(&next, 10).await?;
            let title = RE_TITLE
                .captures(&done.text())
                .map(|c| c[1].to_string())
                .unwrap_or_default();
            let ticket = self
                .ticket()
                .ok_or_else(|| format!("CAS 登录未拿到 WebVPN 票据（最终页 title={title}）"))?;
            *self.last_login.lock().unwrap() = Some(now_secs());
            self.save();
            return Ok(ticket);
        }

        let text = post.text();
        let msg = RE_MSG
            .captures(&text)
            .map(|c| c[1].trim().to_string())
            .or_else(|| RE_ERR.captures(&text).map(|c| c[1].trim().to_string()))
            .unwrap_or_else(|| {
                let stripped = Regex::new(r"<[^>]+>").unwrap().replace_all(&text, " ");
                let joined = stripped.split_whitespace().collect::<Vec<_>>().join(" ");
                joined.chars().take(200).collect::<String>()
            });
        let captcha = text.contains("id=\"authcode\"") && (text.contains("captcha") || text.contains("验证码"));
        Err(format!(
            "CAS 登录失败（HTTP {}）：{}{}",
            post.status,
            msg,
            if captcha { "（可能需要验证码）" } else { "" }
        ))
    }

    /// 带自动重登的 WebVPN 请求
    pub async fn fetch(&self, url: &str) -> Result<Resp, String> {
        if !self.logged_in() {
            self.login().await?;
        }
        let mut res = self.raw(reqwest::Method::GET, url, &[], None).await?;
        if looks_logged_out(&res) {
            // 服务器把我们当未登录：先记下"会话不算可用"，重登成功再翻回来
            self.mark_bad();
            self.login().await?;
            res = self.raw(reqwest::Method::GET, url, &[], None).await?;
        }
        if !looks_logged_out(&res) {
            self.mark_ok();
        }
        Ok(res)
    }

    pub async fn keep_alive(&self) -> bool {
        // 本机既没存账号、也没有会话：没什么可保活的。硬发请求只会让 fetch 去"自动重登"，
        // 然后把「没有可用的账号密码」记成一次登录失败 —— 界面上会莫名其妙出现红色报错。
        if !self.has_creds() && !self.logged_in() {
            return true;
        }
        let url = format!("{WEBVPN_ORIGIN}/user/info");
        matches!(self.fetch(&url).await, Ok(r) if r.status == 200)
    }

    /// 核对当前会话是不是真的还能用：真发一个请求，被踢回登录页时 `fetch` 会自动用本机
    /// 凭据重登，重登失败的原因原样返回。启动核心前用它把关 —— 只看"罐里有票据"不够：
    /// 票据可能是过期的、从别处带过来的，也可能是上一次登录失败留下的匿名票据。
    pub async fn verify(&self) -> Result<String, String> {
        let url = format!("{WEBVPN_ORIGIN}/user/info");
        let res = self.fetch(&url).await?;
        if res.status != 200 {
            self.mark_bad();
            return Err(format!("会话不可用（HTTP {}）", res.status));
        }
        Ok(self.ticket().unwrap_or_default())
    }

    /// 退出登录：清掉会话（内存 + 磁盘 `state/cookies.json`），
    /// **本机保存的账号密码（.secrets）保留**，随时可以再点「登录」进来。
    pub fn logout(&self) {
        *self.jar.lock().unwrap() = CookieJar::default();
        self.save();
        self.mark_bad();
        self.clear_last_error();
    }

    /// 「清除本机账号」用：内存里那份凭据也一起丢掉。
    /// 磁盘上的 `.secrets/creds.dpapi` 由 `creds::forget()` 删。
    pub fn forget_creds(&self) {
        *self.creds.lock().unwrap() = None;
    }
}

/// 与浏览器一致的基础请求头（部分网关会因此返回不同页面）
pub const DEFAULT_HEADERS: &[(&str, &str)] = &[
    (
        "user-agent",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    ),
    (
        "accept",
        "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    ),
    ("accept-language", "zh-CN,zh;q=0.9,en;q=0.8"),
    ("accept-encoding", "identity"),
    ("connection", "keep-alive"),
];

pub fn looks_logged_out(res: &Resp) -> bool {
    if !res.is_redirect() {
        return false;
    }
    let loc = res.location.clone().unwrap_or_default();
    loc.contains("/login") && (loc.ends_with("/login") || loc.contains("/login?"))
}

fn hex_uint(s: &str) -> Result<BigUint, String> {
    let t = s.trim().trim_start_matches("0x").trim_start_matches("0X");
    if t.is_empty() || !t.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(format!("公钥数值不是十六进制：{}", &t[..t.len().min(24)]));
    }
    // jsbn 接受奇数位的十六进制串，hex crate 不接受，这里左补 0
    let padded = if t.len() % 2 == 1 {
        format!("0{t}")
    } else {
        t.to_string()
    };
    let bytes = hex::decode(padded).map_err(|e| e.to_string())?;
    Ok(BigUint::from_bytes_be(&bytes))
}

fn rsa_encrypt(exponent_hex: &str, modulus_hex: &str, plain: &str) -> Result<String, String> {
    // 服务端用的是经典 jsbn `RSAUtils`：不是 PKCS#1，而是
    //   1) 把字符按 charCodeAt & 0xff 取字节，右侧补 0 到 chunkSize 的整数倍；
    //   2) 每 chunkSize 字节按【小端】解释成整数；3) 直接做 v^e mod n；4) 输出十六进制。
    // chunkSize = 2 * ((bits(n) - 1) / 16)，512 位模数时为 62。
    let n = hex_uint(modulus_hex)?;
    let e = hex_uint(exponent_hex)?;
    let bits = n.bits() as usize;
    let chunk = 2 * (bits.saturating_sub(1) / 16);
    if chunk == 0 {
        return Err("CAS 公钥过短".into());
    }
    let mut bytes: Vec<u8> = plain.chars().map(|c| (c as u32 & 0xff) as u8).collect();
    if bytes.is_empty() {
        return Err("密码为空".into());
    }
    while bytes.len() % chunk != 0 {
        bytes.push(0);
    }
    let mut out: Vec<String> = Vec::new();
    for block in bytes.chunks(chunk) {
        let v = BigUint::from_bytes_le(block);
        if v >= n {
            return Err("CAS 公钥太小，密码块溢出".into());
        }
        out.push(v.modpow(&e, &n).to_str_radix(16));
    }
    Ok(out.join(" "))
}

#[cfg(test)]
mod rsa_tests {
    use super::rsa_encrypt;

    #[test]
    fn matches_jsbn_raw_rsa() {
        // 抓到的实际公钥与 jsbn 输出（同输入、同公钥，jsbn 结果确定性）。
        // 用反转后的示例串替代真实口令，验证的仍是「反转 + 原始 RSA」这条链路。
        let modulus = "a27e03092669b916d8e918789def2513fc40fb9faa60eac4eeb322d0fa705ba176df62af09c0bd766071ff8dedb3b7c75509549dba828f402cc19373a6c37133";
        let expected = "7e9141161086d72a20a7086a7680fb324a76e3b8e6853a62569f506489a722a0665dad97feafc1831996c751447f07c9f6f13b7fb0510341690da1dac304c4f5";
        let reversed: String = "ssap-elpmaxe".chars().rev().collect();
        let got = rsa_encrypt("10001", modulus, &reversed).unwrap();
        assert_eq!(got, expected);
    }
}

pub fn urlencode(s: &str) -> String {
    let mut out = String::new();
    for b in s.as_bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(*b as char)
            }
            b' ' => out.push('+'),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// 用 base 解析相对地址
pub fn join_url(base: &str, rel: &str) -> Result<String, String> {
    let b = url::Url::parse(base).map_err(|e| format!("地址不合法（{base}）：{e}"))?;
    b.join(rel)
        .map(|u| u.to_string())
        .map_err(|e| format!("地址拼接失败：{e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn joins_urls() {
        assert_eq!(
            join_url("https://a.b/c/d", "../x") .unwrap(),
            "https://a.b/x"
        );
        assert_eq!(
            join_url("https://a.b/c/d", "https://c.d/e").unwrap(),
            "https://c.d/e"
        );
    }

    #[test]
    fn encodes_form_values() {
        assert_eq!(urlencode("a b+c"), "a+b%2Bc");
    }
}
