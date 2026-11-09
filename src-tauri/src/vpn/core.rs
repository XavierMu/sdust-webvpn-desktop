//! 应用编排：会话 + 代理 + 系统代理 + 证书 + 本地控制接口（给界面调用，兼容原 JS 版）。

use std::collections::VecDeque;
use std::io::Write;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU16, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

use axum::body::Bytes;
use axum::extract::{Query, State};
use axum::http::{header, Method, Request, StatusCode};
use axum::middleware::{from_fn, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use parking_lot::Mutex;
use serde::Serialize;
use serde_json::json;

use super::certstore;
use super::certs::Ca;
use super::creds;
use super::online;
use super::pac::build_pac;
use super::rules::{split_entries, RuleSet};
use super::paths::{Config, Paths};

/// 进程级退出钩子：由 main.rs 注入（Tauri AppHandle 退出），供控制接口 /quit 调用。
static QUIT_HOOK: std::sync::OnceLock<Box<dyn Fn() + Send + Sync>> = std::sync::OnceLock::new();

/// 注册退出钩子（只在启动时调用一次）。
pub fn set_quit_hook<F: Fn() + Send + Sync + 'static>(f: F) {
    let _ = QUIT_HOOK.set(Box::new(f));
}
use super::proxy::{self, Proxy, Stats};
use super::session::Session;
use super::sysproxy;

pub const CONTROL_PORT: u16 = 8897;

/// 启动后多久跑第一次在线规则同步。只要等主窗口挂上、界面能显示「同步中…」就够了，
/// 不必多拖（新装用户靠这一步拿到第一份公共规则）。
const FIRST_SYNC_DELAY_SECS: u64 = 3;

/// 同步进行中标志：`/status` 里报给界面，用来显示「正在同步…」
struct SyncingFlag<'a>(&'a AtomicBool);

impl Drop for SyncingFlag<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Relaxed);
    }
}

#[derive(Serialize, Clone)]
pub struct LogLine {
    pub i: u64,
    pub t: String,
    pub msg: String,
}

pub struct Core {
    pub paths: Paths,
    pub cfg: Mutex<Config>,
    pub session: Arc<Session>,
    pub ca: Arc<Ca>,
    proxy: Mutex<Option<Proxy>>,
    stats: Mutex<Option<Arc<Stats>>>,
    keepalive: Mutex<Option<tokio::task::JoinHandle<()>>>,
    /// 在线规则的定期同步任务
    online_timer: Mutex<Option<tauri::async_runtime::JoinHandle<()>>>,
    /// 正在同步在线规则（界面据此显示「同步中…」）
    online_syncing: AtomicBool,
    logs: Mutex<VecDeque<LogLine>>,
    seq: AtomicU64,
    pub control_port: AtomicU16,
    rules: proxy::RulesHandle,
    /// PAC 版本号：规则变化时自增，用作 AutoConfigURL 的查询参数，强制客户端重新拉取
    pac_gen: AtomicU64,
    ca_cache: Mutex<Option<(bool, Instant)>>,
    sys_cache: Mutex<Option<(sysproxy::ProxyState, Instant)>>,
    /// 串行化「启动核心」：界面轮询、按钮、保存账号可能同时触发，
    /// 不能让两次 `start_proxy` 并发去抢 8899（会有一个绑不上，界面上就是一条吓人的失败日志）
    start_gate: tokio::sync::Mutex<()>,
}

impl Core {
    pub fn new(root: PathBuf) -> Result<Arc<Self>, String> {
        let paths = Paths::new(root);
        let cfg = Config::load(&paths);
        let session = Arc::new(Session::new(&paths));
        session.set_creds(creds::load(&paths).ok());
        let ca = Arc::new(Ca::load_or_create(paths.ca_dir())?);
        // 启动时先把上次同步下来的在线规则读进来，规则立刻生效（不用等第一次同步）
        let remote = std::fs::read_to_string(paths.online_rules())
            .ok()
            .and_then(|t| online::parse(&t).ok());
        let rules = Arc::new(parking_lot::RwLock::new(Arc::new(build_rules(
            &cfg,
            remote.as_ref(),
        ))));
        let core = Arc::new(Self {
            paths,
            cfg: Mutex::new(cfg),
            session,
            ca,
            proxy: Mutex::new(None),
            stats: Mutex::new(None),
            keepalive: Mutex::new(None),
            online_timer: Mutex::new(None),
            online_syncing: AtomicBool::new(false),
            logs: Mutex::new(VecDeque::new()),
            seq: AtomicU64::new(0),
            control_port: AtomicU16::new(CONTROL_PORT),
            rules,
            pac_gen: AtomicU64::new(0),
            ca_cache: Mutex::new(None),
            sys_cache: Mutex::new(None),
            start_gate: tokio::sync::Mutex::new(()),
        });
        core.log("核心已就绪");
        if let Some(msg) = sysproxy::heal(&core.paths, core.proxy_port()) {
            core.log(msg);
        }
        core.start_online_timer();
        Ok(core)
    }

    pub fn log(&self, msg: impl AsRef<str>) {
        let msg = msg.as_ref().to_string();
        let i = self.seq.fetch_add(1, Ordering::Relaxed);
        let t = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        println!("[{t}] {msg}");
        self.append_log_file(&t, &msg);
        let mut logs = self.logs.lock();
        logs.push_back(LogLine { i, t, msg });
        while logs.len() > 800 {
            logs.pop_front();
        }
    }

    /// 界面上那份日志只留在内存（最多 800 行），同时往 `state\core.log` 追加一份，
    /// 这样用户出问题可以直接把文件发过来（「关于」弹窗里写的就是这个路径）。
    /// 文件超过 512 KB 时只保留最后 500 行，免得长期挂机把盘撑大。
    /// 写文件失败（只读目录、被占用等）不影响程序，也不写回上次的错误。
    fn append_log_file(&self, t: &str, msg: &str) {
        let path = self.paths.log_file();
        const MAX_BYTES: u64 = 512 * 1024;
        const KEEP_LINES: usize = 500;
        if std::fs::metadata(&path).map(|m| m.len() > MAX_BYTES).unwrap_or(false) {
            if let Ok(text) = std::fs::read_to_string(&path) {
                let mut tail: Vec<&str> = text.lines().rev().take(KEEP_LINES).collect();
                tail.reverse();
                let _ = std::fs::write(&path, format!("{}\n", tail.join("\n")));
            }
        }
        if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(&path) {
            let _ = writeln!(f, "[{t}] {msg}");
        }
    }

    pub fn proxy_port(&self) -> u16 {
        self.cfg.lock().proxy_port
    }

    /// PAC 地址（带版本号，规则变了 URL 就变，浏览器/WinHTTP 会重新拉取）
    pub fn pac_url(&self) -> String {
        format!(
            "http://127.0.0.1:{}/pac?g={}",
            self.control_port.load(Ordering::Relaxed),
            self.pac_gen.load(Ordering::Relaxed)
        )
    }

    /// 用当前配置重建规则（配置改了立刻生效，不用重启代理）
    pub fn rebuild_rules(&self) {
        let remote = self.cached_remote_rules();
        let rules = build_rules(&self.cfg.lock(), remote.as_ref());
        *self.rules.write() = Arc::new(rules);
        // PAC 模式：Windows 会缓存 PAC 脚本，靠改 URL 触发重新下载，否则新规则不生效
        self.pac_gen.fetch_add(1, Ordering::Relaxed);
        let sys = sysproxy::get();
        if sys.auto_config_url.contains("/pac") {
            match sysproxy::enable_pac_saved(&self.paths, &self.pac_url()) {
                Ok(_) => {
                    self.invalidate_sys_cache();
                    self.log("PAC 已刷新（新规则立即生效）");
                }
                Err(e) => self.log(format!("刷新 PAC 失败：{e}")),
            }
        }
    }

    pub fn proxy_hosts(&self) -> Vec<String> {
        self.cfg.lock().proxy_hosts.clone()
    }

    pub fn direct_hosts(&self) -> Vec<String> {
        self.cfg.lock().direct_hosts.clone()
    }

    /// 在线规则占的优先程度：`local` 表示只用本地名单，其余（默认 `online`）叠加在线规则。
    fn online_active(&self) -> bool {
        let cfg = self.cfg.lock();
        !cfg.online_urls_clean().is_empty() && cfg.rule_source != "local"
    }

    /// 当前生效的在线规则（读每次同步时落盘的那份；没有/坏了就当空）
    fn cached_remote_rules(&self) -> Option<online::RemoteRules> {
        if !self.online_active() {
            return None;
        }
        let text = std::fs::read_to_string(self.paths.online_rules()).ok()?;
        online::parse(&text).ok()
    }

    /// 拉一次在线规则：成功后落盘、更新状态字段，并重建规则（立刻生效）。
    ///
    /// 配了多个地址时按顺序试，只要有一份能解析出条目就停；全都失败才报错
    /// （错误里带上每个地址各自的原因）。`force` 关掉「远端比本地旧就拒绝」的检查。
    ///
    /// 版本号跟本地缓存**一样**时也先往后试：CDN 缓存分支文件（jsDelivr 对 `@main`
    /// 约 12 小时）时，先命中的镜像往往是旧内容，版本号恰好相同，直接接受就永远看不到
    /// 后面的新规则。所以把它当保底留着，继续找更新的；都没有更新的才用保底。
    pub async fn sync_online_rules(
        self: &Arc<Self>,
        force: bool,
    ) -> Result<online::RemoteRules, String> {
        let urls = self.cfg.lock().online_urls_clean();
        if urls.is_empty() {
            return Err("还没有填在线规则的网址".into());
        }
        let prev_rev = self.cfg.lock().online_revision;
        // 同步期间 /status 里 syncing = true，界面显示「同步中…」；不管从哪条路返回都会清掉
        self.online_syncing.store(true, Ordering::Relaxed);
        let _syncing = SyncingFlag(&self.online_syncing);

        // 一个地址失败就记一条，继续试下一个；最后一起报出来才知道是哪条路的问题
        let mut errors: Vec<String> = Vec::new();
        // 版本号跟本地一样的那份：先当保底，继续往后找版本更高的
        let mut same_rev: Option<(String, String, &'static str, online::RemoteRules)> = None;
        let mut fetched: Option<(String, String, &'static str, online::RemoteRules)> = None;
        for (i, url) in urls.iter().enumerate() {
            let more_mirrors = i + 1 < urls.len();
            if !url.starts_with("http://") && !url.starts_with("https://") {
                errors.push(format!("{url} → 网址要以 http:// 或 https:// 开头"));
                continue;
            }
            let (body, via) = match self.fetch_rule_body(url).await {
                Ok(x) => x,
                Err(e) => {
                    errors.push(format!("{url} → {e}"));
                    continue;
                }
            };
            let rules = match online::parse(&body) {
                Ok(r) => r,
                Err(e) => {
                    errors.push(format!("{url} → {e}"));
                    continue;
                }
            };
            if !force {
                if let Some(rev) = online::revision(&rules) {
                    // 远端版本比本地缓存旧：可能是 CDN 还在发旧文件（jsDelivr 有缓存），
                    // 也可能对面误回滚。跳过这个地址，让后面的镜像有机会给出新版本。
                    if prev_rev > 0 && rev < prev_rev {
                        errors.push(format!(
                            "{url} → 远端版本 {rev} 比本地缓存的 {prev_rev} 旧，已跳过（要强行覆盖请用「强制同步」）"
                        ));
                        continue;
                    }
                    // 版本跟本地一样：很可能就是 CDN 还在发旧文件。留着当保底，先试下一个镜像。
                    if prev_rev > 0 && rev == prev_rev && more_mirrors {
                        if same_rev.is_none() {
                            same_rev = Some((url.clone(), body, via, rules));
                        }
                        continue;
                    }
                }
            }
            fetched = Some((url.clone(), body, via, rules));
            break;
        }

        // 试完一轮：没有更新的就用「版本相同」的那份保底（缓存本身没错，只是没新版）
        let (url, body, via, rules) = match fetched.or(same_rev) {
            Some(x) => x,
            None => {
                let msg = errors.join("；");
                let mut cfg = self.cfg.lock();
                cfg.online_error = msg.clone();
                cfg.save(&self.paths);
                return Err(msg);
            }
        };

        std::fs::write(self.paths.online_rules(), &body).ok();
        {
            let mut cfg = self.cfg.lock();
            cfg.online_synced_at = now_secs();
            cfg.online_count = rules.total() as u64;
            cfg.online_last_url = url.clone();
            // 远端没给版本号时不要清零：保留上一次的判据，否则防回滚会失效
            if let Some(rev) = online::revision(&rules) {
                cfg.online_revision = rev;
            }
            cfg.online_error.clear();
            cfg.save(&self.paths);
        }
        self.rebuild_rules();
        self.log(format!(
            "在线规则已同步（{} 条，经{via}，来自 {url}）：白名单 +{} / 黑名单 +{}",
            rules.total(),
            rules.proxy.len(),
            rules.direct.len()
        ));
        Ok(rules)
    }

    /// 取远端规则正文。
    ///
    /// 两条路的差别只对「命中白名单的地址」存在：那种请求进本机代理后会被改写成
    /// WebVPN 路径，才算真的另一条出口，所以先走代理、不行再直连。
    /// 站外地址则相反 —— 本机代理对它也是直连出去，同一个出口试两遍只是白等 20 秒，
    /// 所以只试一次。
    async fn fetch_rule_body(&self, url: &str) -> Result<(String, &'static str), String> {
        let host = reqwest::Url::parse(url)
            .ok()
            .and_then(|u| u.host_str().map(|h| h.to_string()))
            .unwrap_or_default();
        let proxied = !host.is_empty()
            && self.rules.read().decide(&host) == super::rules::Decision::Proxy;
        let modes: &[&str] = if proxied {
            &["proxy", "direct"]
        } else {
            &["direct"]
        };

        let mut errors: Vec<String> = Vec::new();
        for mode in modes {
            let via = if *mode == "proxy" { "本机代理" } else { "直连" };
            let builder = reqwest::Client::builder().timeout(std::time::Duration::from_secs(20));
            let builder = if *mode == "proxy" {
                match reqwest::Proxy::all(format!("http://127.0.0.1:{}", self.proxy_port())) {
                    Ok(p) => builder.proxy(p),
                    Err(e) => {
                        errors.push(format!("经本机代理失败：{e}"));
                        continue;
                    }
                }
            } else {
                builder
            };
            let client = match builder.build() {
                Ok(c) => c,
                Err(e) => {
                    errors.push(format!("经{via}失败：{e}"));
                    continue;
                }
            };
            match client.get(url).send().await {
                Ok(res) if res.status().is_success() => {
                    let text = res.text().await.map_err(|e| format!("读取失败：{e}"))?;
                    if text.len() > online::MAX_BYTES {
                        return Err(format!("规则文件太大（{} 字节）", text.len()));
                    }
                    return Ok((text, via));
                }
                Ok(res) => errors.push(format!("经{via}返回 HTTP {}", res.status())),
                Err(e) => {
                    let mut t = e.to_string();
                    t.truncate(t.find(" for url").unwrap_or(t.len().min(90)));
                    errors.push(format!("经{via}失败：{t}"));
                }
            }
        }
        Err(format!("拉取失败：{}", errors.join("；")))
    }

    /// 定期同步：按 `online_interval_hours` 排一次，0 表示不自动同步。
    fn start_online_timer(self: &Arc<Self>) {
        let mut guard = self.online_timer.lock();
        if guard.is_some() {
            return;
        }
        let core = self.clone();
        // Core::new 是同步构造、跑在主线程上，此时还没有 Tokio reactor，	okio::spawn 会 panic；
        // tauri::async_runtime 有全局运行时，从任何线程调都安全。
        *guard = Some(tauri::async_runtime::spawn(async move {
            // 等界面和核心起来就行，不用拖太久：新装用户靠这一步拿到第一份公共规则
            // （内置了默认规则地址，所以这就是「开箱即有规则」）
            tokio::time::sleep(std::time::Duration::from_secs(FIRST_SYNC_DELAY_SECS)).await;
            {
                let (hours, n) = {
                    let cfg = core.cfg.lock();
                    (cfg.online_interval_hours, cfg.online_urls_clean().len())
                };
                if hours > 0 && n > 0 {
                    let every = if hours == 24 {
                        "每 24 小时".to_string()
                    } else if hours % 24 == 0 {
                        format!("每 {} 天", hours / 24)
                    } else {
                        format!("每 {hours} 小时")
                    };
                    core.log(format!(
                        "在线规则：启动 {FIRST_SYNC_DELAY_SECS} 秒后自动同步一次，之后{every}一次（订阅了 {n} 个地址，可在「在线规则…」里改）"
                    ));
                }
            }
            loop {
                let (hours, urls) = {
                    let cfg = core.cfg.lock();
                    (cfg.online_interval_hours, cfg.online_urls_clean())
                };
                if hours == 0 || urls.is_empty() || !core.online_active() {
                    tokio::time::sleep(std::time::Duration::from_secs(10 * 60)).await;
                    continue;
                }
                let due = {
                    let cfg = core.cfg.lock();
                    cfg.online_synced_at + hours * 3600
                };
                if now_secs() >= due {
                    // 自动同步按时间到点就跑，不强制覆盖：远端版本比本地旧时宁可留着旧的
                    if let Err(e) = core.sync_online_rules(false).await {
                        core.log(format!("自动同步在线规则失败：{e}"));
                    }
                }
                tokio::time::sleep(std::time::Duration::from_secs(10 * 60)).await;
            }
        }));
    }

    pub fn proxy_running(&self) -> bool {
        self.proxy.lock().is_some()
    }

    pub fn stats_json(&self) -> serde_json::Value {
        match self.stats.lock().as_ref() {
            Some(s) => s.json(),
            None => json!({ "school": 0, "direct": 0, "rewrites": 0, "errors": 0 }),
        }
    }

    pub fn ca_installed(&self, force: bool) -> bool {
        let mut cache = self.ca_cache.lock();
        if !force {
            if let Some((v, at)) = *cache {
                if at.elapsed().as_secs() < 60 {
                    return v;
                }
            }
        }
        let installed = self
            .ca
            .thumbprint()
            .map(|t| sysproxy::cert_installed(&t))
            .unwrap_or(false);
        *cache = Some((installed, Instant::now()));
        installed
    }

    pub fn system_proxy_cached(&self, force: bool) -> sysproxy::ProxyState {
        let mut cache = self.sys_cache.lock();
        if !force {
            if let Some((v, at)) = cache.as_ref() {
                if at.elapsed().as_secs() < 10 {
                    return v.clone();
                }
            }
        }
        let v = sysproxy::get();
        *cache = Some((v.clone(), Instant::now()));
        v
    }

    pub fn invalidate_sys_cache(&self) {
        *self.sys_cache.lock() = None;
    }

    pub fn invalidate_ca_cache(&self) {
        *self.ca_cache.lock() = None;
    }

    pub async fn start_proxy(self: &Arc<Self>, port: Option<u16>) -> Result<(bool, u16), String> {
        // 先拿闸门：并发进来的第二个调用在这里排队，拿到之后会看到 proxy_running() 已经为真而直接返回
        let _gate = self.start_gate.lock().await;
        if self.proxy_running() {
            return Ok((true, self.proxy_port()));
        }
        if !self.session.has_creds() {
            if let Ok(c) = creds::load(&self.paths) {
                self.session.set_creds(Some(c));
            }
        }
        if !self.session.logged_in() {
            self.log("没有会话，正在登录…");
            let ticket = self.session.login().await?;
            self.log(format!("登录成功（票据 {}…）", &ticket.chars().take(6).collect::<String>()));
        } else {
            // 启动核心前先核对会话真的可用：只看"罐里有票据"不够 —— 过期的、从别处带过来的、
            // 或者上一次登录失败留下的票据都会让它误判。verify 失效时会用本机凭据重登，
            // 重登不成功就把核心拦下来（错误会带回界面，弹出失败原因）。
            match self.session.verify().await {
                Ok(t) => self.log(format!(
                    "会话可用（票据 {}…），启动核心",
                    &t.chars().take(6).collect::<String>()
                )),
                Err(e) => {
                    self.log(format!("启动核心失败：{e}"));
                    return Err(e);
                }
            }
        }
        let port = port.unwrap_or_else(|| self.proxy_port());
        let log_core = self.clone();
        let logfn: proxy::LogFn = Arc::new(move |m: String| log_core.log(m));
        let p = proxy::start(
            self.ca.clone(),
            self.session.clone(),
            port,
            self.rules.clone(),
            logfn,
        )
        .await?;
        let actual = p.port;
        *self.stats.lock() = Some(p.stats.clone());
        *self.proxy.lock() = Some(p);
        {
            let mut cfg = self.cfg.lock();
            cfg.proxy_port = actual;
            cfg.save(&self.paths);
        }
        self.log(format!("本地代理已启动 127.0.0.1:{actual}"));
        self.start_keepalive();
        Ok((true, actual))
    }

    pub fn stop_proxy(&self) -> bool {
        // 先还原系统代理：否则停掉核心后系统代理仍指向 127.0.0.1:8899，全机断网
        let sys = self.system_proxy_cached(true);
        let ours = format!("127.0.0.1:{}", self.proxy_port());
        if sys.auto_config_url.contains("127.0.0.1") {
            match sysproxy::disable(&self.paths) {
                Ok(_) => self.log("系统代理（PAC）已还原：核心已停止"),
                Err(e) => self.log(format!("还原系统代理失败：{e}")),
            }
            self.invalidate_sys_cache();
        } else if sys.enabled && sys.server == ours {
            match sysproxy::disable(&self.paths) {
                Ok(_) => self.log("系统代理已还原：核心已停止"),
                Err(e) => self.log(format!("还原系统代理失败：{e}")),
            }
            self.invalidate_sys_cache();
        }
        if let Some(p) = self.proxy.lock().take() {
            self.log(format!(
                "代理统计 school={} direct={} rewrites={} errors={}",
                p.stats.school.load(Ordering::Relaxed),
                p.stats.direct.load(Ordering::Relaxed),
                p.stats.rewrites.load(Ordering::Relaxed),
                p.stats.errors.load(Ordering::Relaxed)
            ));
            p.stop();
        }
        if let Some(h) = self.keepalive.lock().take() {
            h.abort();
        }
        if sysproxy::user_env_proxy_points_to_localhost() {
            if let Err(e) = sysproxy::unset_user_env_proxy() {
                self.log(format!("清除命令行代理环境变量失败：{e}"));
            } else {
                self.log("命令行代理环境变量已清除");
            }
            self.cfg.lock().env_proxy = false;
            self.cfg.lock().save(&self.paths);
        }
        false
    }

    /// 按当前模式接管系统代理（不启动核心）。托盘菜单用；
    /// 界面上的「开启系统代理」走 `/sysproxy`，那边还要处理命令行环境变量开关。
    pub fn enable_sysproxy_saved(&self) -> Result<(), String> {
        let pac = self.cfg.lock().sysproxy_mode == "pac";
        let port = self.proxy_port();
        let r = if pac {
            sysproxy::enable_pac_saved(&self.paths, &self.pac_url())
        } else {
            sysproxy::enable_saved(
                &self.paths,
                &format!("127.0.0.1:{port}"),
                "<local>;127.0.0.1;localhost",
            )
        };
        if r.is_ok() && !pac && self.cfg.lock().env_proxy {
            if let Err(e) =
                sysproxy::set_user_env_proxy(&format!("127.0.0.1:{port}"), "localhost,127.0.0.1,::1")
            {
                self.log(format!("命令行代理环境变量设置失败：{e}"));
            }
        }
        self.invalidate_sys_cache();
        r
    }

    /// 只还原系统代理，**不停止核心**（托盘「关闭系统代理」用）。
    /// 核心现在随程序常驻，所以"关掉代理"和"停掉核心"是两件事了。
    pub fn release_sysproxy(&self) -> Result<(), String> {
        if sysproxy::user_env_proxy_points_to_localhost() {
            match sysproxy::unset_user_env_proxy() {
                Ok(_) => {
                    self.cfg.lock().env_proxy = false;
                    self.cfg.lock().save(&self.paths);
                }
                Err(e) => self.log(format!("清除命令行代理环境变量失败：{e}")),
            }
        }
        let r = sysproxy::disable(&self.paths);
        self.invalidate_sys_cache();
        r
    }

    fn start_keepalive(self: &Arc<Self>) {
        let mut guard = self.keepalive.lock();
        if guard.is_some() {
            return;
        }
        let core = self.clone();
        // 正常 5 分钟一次；VPN_KEEPALIVE_SECS 只是给自动化测试用的短间隔钩子，不写进界面
        let secs = std::env::var("VPN_KEEPALIVE_SECS")
            .ok()
            .and_then(|s| s.trim().parse::<u64>().ok())
            .filter(|n| *n >= 1)
            .unwrap_or(5 * 60);
        *guard = Some(tokio::spawn(async move {
            let mut ticker = tokio::time::interval(std::time::Duration::from_secs(secs));
            ticker.tick().await;
            loop {
                ticker.tick().await;
                // 连续失败到上限就停手：本机存的密码是错的时，不能每 5 分钟去撞一次统一认证
                if core.session.relogin_paused() {
                    continue;
                }
                let ok = core.session.keep_alive().await;
                core.session.note_keepalive(ok);
                if !ok {
                    if core.session.relogin_paused() {
                        core.log(format!(
                            "自动重登已暂停：连续 {} 次保活失败。改好密码后点「保存并登录」，或重启程序再试",
                            super::session::KEEPALIVE_MAX_FAILS
                        ));
                    } else {
                        core.log(format!(
                            "保活失败（第 {} 次）：会话可能已过期",
                            core.session.keepalive_fails()
                        ));
                    }
                }
            }
        }));
    }

    pub fn install_ca(&self) -> Result<serde_json::Value, String> {
        let der = self.ca_der()?;
        certstore::install_root(&der)?;
        let ok = self
            .ca
            .thumbprint()
            .map(|t| certstore::has_root(&t))
            .unwrap_or(false);
        if !ok {
            return Err("根证书写入后校验失败（可能被安全软件还原）".into());
        }
        self.log("根证书已装入当前用户（CN=SDUST WebVPN Local CA）");
        self.invalidate_ca_cache();
        Ok(json!({ "installed": true, "path": self.ca.cert_file().to_string_lossy() }))
    }

    pub fn uninstall_ca(&self) -> Result<serde_json::Value, String> {
        let thumb = self
            .ca
            .thumbprint()
            .ok_or_else(|| "读不到本地 CA 指纹".to_string())?;
        let removed = certstore::delete_root(&thumb)?;
        if removed == 0 && certstore::has_root(&thumb) {
            return Err("删除根证书失败：证书仍在证书库中".into());
        }
        self.log(format!("根证书已卸载（删除 {removed} 个）"));
        self.invalidate_ca_cache();
        Ok(json!({ "installed": false }))
    }

    fn ca_der(&self) -> Result<Vec<u8>, String> {
        let pem = std::fs::read_to_string(self.ca.cert_file())
            .map_err(|e| format!("读取 CA 证书失败：{e}"))?;
        let mut rd = std::io::Cursor::new(pem.into_bytes());
        let certs = rustls_pemfile::certs(&mut rd)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| format!("解析 CA 证书失败：{e}"))?;
        certs
            .into_iter()
            .next()
            .map(|c| c.to_vec())
            .ok_or_else(|| "CA 证书文件为空".to_string())
    }

    /// 程序文件（exe）的时间戳：同一个版本号的不同构建/覆盖安装时间，用来区分手上的 exe
    fn built_at(&self) -> u64 {
        std::env::current_exe()
            .and_then(|p| std::fs::metadata(p))
            .and_then(|m| m.modified())
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }

    pub fn status_json(&self) -> serde_json::Value {
        let sys = self.system_proxy_cached(false);
        let remote = self.cached_remote_rules();
        // 系统代理现在到底是不是我们接管的（别人也会写同一个注册表键）
        let (owner, owner_detail) = sysproxy::owner(&sys, self.proxy_port(), &self.pac_url());
        json!({
            "session": self.session.status_json(),
            "proxy": {
                "running": self.proxy_running(),
                "port": self.proxy_port(),
                "stats": self.stats_json(),
            },
            "systemProxy": {
                "enabled": sys.enabled,
                "server": sys.server,
                "override": sys.override_list,
                "autoConfigUrl": sys.auto_config_url,
                "owner": owner,
                "ownerDetail": owner_detail,
            },
            "ca": {
                "installed": self.ca_installed(false),
                "path": self.ca.cert_file().to_string_lossy(),
            },
            "config": {
                "controlPort": self.control_port.load(Ordering::Relaxed),
                "proxyPort": self.proxy_port(),
                "proxyHosts": self.proxy_hosts(),
                "directHosts": self.direct_hosts(),
                "sysproxyMode": self.cfg.lock().sysproxy_mode.clone(),
                "autoSysproxy": self.cfg.lock().auto_sysproxy,
                "guideSeen": self.cfg.lock().guide_seen,
                "caPromptSeen": self.cfg.lock().ca_prompt_seen,
                "caPromptSnoozeUntil": self.cfg.lock().ca_prompt_snooze_until,
                "envProxy": sysproxy::user_env_proxy_points_to_localhost(),
                "dataRoot": self.paths.root.to_string_lossy(),
                "version": env!("CARGO_PKG_VERSION"),
                "builtAt": self.built_at(),
            },
            "online": {
                "urls": self.cfg.lock().online_urls_clean(),
                "lastUrl": self.cfg.lock().online_last_url,
                "source": self.cfg.lock().rule_source,
                "intervalHours": self.cfg.lock().online_interval_hours,
                "syncedAt": self.cfg.lock().online_synced_at,
                "count": self.cfg.lock().online_count,
                "revision": self.cfg.lock().online_revision,
                "error": self.cfg.lock().online_error,
                "active": self.online_active(),
                "syncing": self.online_syncing.load(Ordering::Relaxed),
                "remoteProxy": remote.as_ref().map(|r| r.proxy.len()).unwrap_or(0),
                "remoteDirect": remote.as_ref().map(|r| r.direct.len()).unwrap_or(0),
                // 具体条目也带上：界面「在线规则…」弹窗里要能直接看到当前生效的内容
                "remoteProxyList": remote.as_ref().map(|r| r.proxy.clone()).unwrap_or_default(),
                "remoteDirectList": remote.as_ref().map(|r| r.direct.clone()).unwrap_or_default(),
                "remoteVersion": remote.as_ref().and_then(|r| r.version),
                "remoteName": remote.as_ref().map(|r| r.name.clone()).unwrap_or_default(),
                "remoteUpdated": remote.as_ref().map(|r| r.updated.clone()).unwrap_or_default(),
            },
        })
    }

    /// 控制接口（阻塞到服务器结束）
    pub async fn serve_control(self: Arc<Self>) -> Result<(), String> {
        let app = router(self.clone()).layer(from_fn(cors));
        let addr = std::net::SocketAddr::from(([127, 0, 0, 1], CONTROL_PORT));
        let listener = tokio::net::TcpListener::bind(addr)
            .await
            .map_err(|e| format!("控制端口 {CONTROL_PORT} 绑定失败：{e}"))?;
        self.log(format!("控制接口 http://127.0.0.1:{CONTROL_PORT}"));
        axum::serve(listener, app)
            .await
            .map_err(|e| format!("控制接口退出：{e}"))
    }

    /// 退出前恢复系统代理（有备份才动）
    pub fn shutdown(&self) {
        // stop_proxy 里已经会在必要时还原系统代理（并消耗备份文件）；
        // 只有备份仍然存在（例如只开了代理没停核心）时才需要再还原一次。
        self.stop_proxy();
        if self.paths.sysproxy_backup().exists() {
            if let Err(e) = sysproxy::disable(&self.paths) {
                self.log(format!("还原系统代理失败：{e}"));
            } else {
                self.log("系统代理已还原");
            }
        }
        self.session.save();
    }
}

async fn cors(req: Request<axum::body::Body>, next: Next) -> Response {
    if req.method() == Method::OPTIONS {
        return Response::builder()
            .status(StatusCode::NO_CONTENT)
            .header(header::ACCESS_CONTROL_ALLOW_ORIGIN, "*")
            .header(header::ACCESS_CONTROL_ALLOW_METHODS, "GET,POST,OPTIONS")
            .header(header::ACCESS_CONTROL_ALLOW_HEADERS, "content-type")
            .body(axum::body::Body::empty())
            .unwrap();
    }
    let mut res = next.run(req).await;
    let h = res.headers_mut();
    h.insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, "*".parse().unwrap());
    h.insert(
        header::ACCESS_CONTROL_ALLOW_METHODS,
        "GET,POST,OPTIONS".parse().unwrap(),
    );
    h.insert(
        header::ACCESS_CONTROL_ALLOW_HEADERS,
        "content-type".parse().unwrap(),
    );
    res
}

fn parse_body(body: &Bytes) -> serde_json::Value {
    if body.is_empty() {
        return serde_json::Value::Null;
    }
    serde_json::from_slice(body).unwrap_or(serde_json::Value::Null)
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// 接受数组或「换行/逗号分隔」的字符串；两种键名都认
fn rule_list(v: &serde_json::Value, key: &str, alt: &str) -> Option<Vec<String>> {
    for k in [key, alt] {
        match v.get(k) {
            Some(serde_json::Value::Array(items)) => {
                let list: Vec<String> = items
                    .iter()
                    .filter_map(|h| h.as_str())
                    .flat_map(split_entries)
                    .collect();
                return Some(list);
            }
            Some(serde_json::Value::String(text)) => return Some(split_entries(text)),
            _ => {}
        }
    }
    None
}

fn build_rules(cfg: &Config, remote: Option<&online::RemoteRules>) -> RuleSet {
    // 全局模式：忽略名单，全部走 WebVPN；PAC 模式：按黑白名单
    let (proxy, direct) = effective_lists(cfg, remote);
    if cfg.sysproxy_mode == "global" {
        RuleSet::global(&proxy, &direct)
    } else {
        RuleSet::new(&proxy, &direct)
    }
}

/// 合并后的「生效名单」：在线规则（有的话）排前面，本地名单补在后面。
/// `rule_source = local` 或没填网址时只认本地名单。
fn effective_lists(
    cfg: &Config,
    remote: Option<&online::RemoteRules>,
) -> (Vec<String>, Vec<String>) {
    match remote {
        Some(r) if !cfg.online_urls_clean().is_empty() && cfg.rule_source != "local" => {
            online::merge(r, &cfg.proxy_hosts, &cfg.direct_hosts)
        }
        _ => (cfg.proxy_hosts.clone(), cfg.direct_hosts.clone()),
    }
}

fn body_str(v: &serde_json::Value, key: &str) -> String {
    v.get(key).and_then(|x| x.as_str()).unwrap_or("").to_string()
}

fn body_bool(v: &serde_json::Value, key: &str) -> bool {
    v.get(key).and_then(|x| x.as_bool()).unwrap_or(false)
}

type CoreState = State<Arc<Core>>;

async fn s_status(State(core): CoreState) -> Json<serde_json::Value> {
    Json(core.status_json())
}

async fn s_logs(State(core): CoreState, Query(q): Query<std::collections::HashMap<String, String>>) -> Json<serde_json::Value> {
    let after: i64 = q
        .get("after")
        .and_then(|v| v.parse().ok())
        .unwrap_or(-1);
    let lines: Vec<LogLine> = core
        .logs
        .lock()
        .iter()
        .filter(|l| l.i as i64 > after)
        .cloned()
        .collect();
    let next = core.seq.load(Ordering::Relaxed) as i64 - 1;
    Json(json!({ "lines": lines, "next": next }))
}

async fn s_pac(State(core): CoreState) -> Response {
    let rules = core.rules.read().clone();
    let pac = build_pac(core.proxy_port(), &rules);
    (
        [
            (header::CONTENT_TYPE, "application/x-ns-proxy-autoconfig; charset=utf-8"),
            (header::CACHE_CONTROL, "no-store, no-cache, must-revalidate"),
            (header::PRAGMA, "no-cache"),
        ],
        pac,
    )
        .into_response()
}

async fn s_root() -> Response {
    (
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
        "<h1>SDUST WebVPN</h1><p>控制接口运行中</p>",
    )
        .into_response()
}

async fn s_login(State(core): CoreState) -> Json<serde_json::Value> {
    match core.session.login().await {
        Ok(t) => {
            core.log("登录成功");
            Json(json!({ "ok": true, "ticket": format!("{}…", t.chars().take(6).collect::<String>()) }))
        }
        Err(e) => {
            core.log(format!("登录失败：{e}"));
            Json(json!({ "error": e }))
        }
    }
}

/// 退出登录 / 清除本机账号：清会话 + 停代理（不停的话系统代理会指向一个什么都做不了的
/// 代理，整机上网都会异常）。`forget=true` 时连 `.secrets` 里保存的账号密码一起删掉，
/// 下次必须重新填、重新登录。
async fn s_logout(State(core): CoreState, body: Bytes) -> Json<serde_json::Value> {
    let v = parse_body(&body);
    let forget = body_bool(&v, "forget");
    let was_running = core.proxy_running();
    if was_running {
        core.stop_proxy();
    }
    core.session.logout();
    if forget {
        if let Err(e) = creds::forget(&core.paths) {
            core.log(format!("清除本机账号失败：{e}"));
            return Json(json!({ "error": e }));
        }
        core.session.forget_creds();
        core.log(if was_running {
            "已清除本机账号（凭据和会话已删除、代理已停止）"
        } else {
            "已清除本机账号（凭据和会话已删除）"
        });
    } else {
        core.log(if was_running {
            "已退出登录（会话已清除、代理已停止；保存的账号密码保留）"
        } else {
            "已退出登录（会话已清除；保存的账号密码保留）"
        });
    }
    Json(json!({
        "ok": true,
        "running": core.proxy_running(),
        "wasRunning": was_running,
        "forgot": forget,
    }))
}

async fn s_credentials(State(core): CoreState, body: Bytes) -> Json<serde_json::Value> {
    let v = parse_body(&body);
    let username = body_str(&v, "username");
    let password = body_str(&v, "password");
    if username.is_empty() || password.is_empty() {
        return Json(json!({ "error": "缺少账号或密码" }));
    }
    // 先用刚填的凭据试登录，**成功了才落盘**：
    // 密码打错时不要把错的写进 .secrets（会覆盖掉本机原来那份能用的，还会被反复重试）
    let prev = core.session.creds.lock().unwrap().clone();
    // 新一轮尝试：先把上一次的失败记录清掉，界面上的红色提示会随这一轮结果重新出现
    core.session.clear_last_error();
    core.session.set_creds(Some(creds::Creds {
        username: username.clone(),
        password: password.clone(),
        source: "dpapi",
    }));
    match core.session.login().await {
        Ok(t) => {
            if let Err(e) = creds::save_dpapi(&core.paths, &username, &password) {
                core.log(format!("保存凭据失败：{e}"));
                return Json(json!({ "error": format!("已登录，但凭据没能保存到本机：{e}") }));
            }
            core.log("凭据已保存（DPAPI）并登录成功");
            Json(json!({ "ok": true, "ticket": format!("{}…", t.chars().take(6).collect::<String>()) }))
        }
        Err(e) => {
            // 登录没成功 → 内存里也退回原样，别让错的凭据顶掉原来能用的
            core.session.set_creds(prev);
            core.log(format!("登录失败：{e}"));
            Json(json!({ "error": e }))
        }
    }
}

async fn s_proxy_start(State(core): CoreState, body: Bytes) -> Json<serde_json::Value> {
    let v = parse_body(&body);
    let port = v.get("port").and_then(|x| x.as_u64()).map(|x| x as u16);
    match core.start_proxy(port).await {
        Ok((running, port)) => Json(json!({ "running": running, "port": port })),
        Err(e) => {
            core.log(format!("启动代理失败：{e}"));
            Json(json!({ "error": e }))
        }
    }
}

async fn s_proxy_stop(State(core): CoreState) -> Json<serde_json::Value> {
    Json(json!({ "running": core.stop_proxy() }))
}

async fn s_quit() -> Json<serde_json::Value> {
    match QUIT_HOOK.get() {
        Some(f) => {
            f();
            Json(json!({ "ok": true }))
        }
        None => Json(json!({ "error": "退出钩子未注册" })),
    }
}

async fn s_config(State(core): CoreState, body: Bytes) -> Json<serde_json::Value> {
    let v = parse_body(&body);
    let port = v.get("proxyPort").and_then(|x| x.as_u64()).map(|x| x as u16);
    let new_mode = v.get("sysproxyMode").and_then(|x| x.as_str()).map(|m| m.to_string());
    if let Some(m) = &new_mode {
        if m == "pac" || m == "global" {
            core.cfg.lock().sysproxy_mode = m.clone();
        }
    }
    if let Some(env) = v.get("envProxy").and_then(|x| x.as_bool()) {
        core.cfg.lock().env_proxy = env;
    }
    if let Some(auto) = v.get("autoSysproxy").and_then(|x| x.as_bool()) {
        core.cfg.lock().auto_sysproxy = auto;
    }
    if let Some(seen) = v.get("guideSeen").and_then(|x| x.as_bool()) {
        core.cfg.lock().guide_seen = seen;
    }
    if let Some(seen) = v.get("caPromptSeen").and_then(|x| x.as_bool()) {
        core.cfg.lock().ca_prompt_seen = seen;
    }
    if let Some(until) = v.get("caPromptSnoozeUntil").and_then(|x| x.as_u64()) {
        core.cfg.lock().ca_prompt_snooze_until = until;
    }
    // ---- 在线规则 / 校内导航 ----
    let mut rules_changed = false;
    // 界面发的是数组（一行一个地址）；`onlineUrl` 是旧版单地址字段，留着兼容外部脚本
    let new_urls: Option<Vec<String>> = match v.get("onlineUrls").and_then(|x| x.as_array()) {
        Some(arr) => Some(
            arr.iter()
                .filter_map(|x| x.as_str())
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect(),
        ),
        None => v.get("onlineUrl").and_then(|x| x.as_str()).map(|s| {
            let s = s.trim();
            if s.is_empty() {
                Vec::new()
            } else {
                vec![s.to_string()]
            }
        }),
    };
    if let Some(urls) = new_urls {
        if urls != core.cfg.lock().online_urls_clean() {
            core.cfg.lock().online_urls = urls;
            rules_changed = true;
        }
    }
    if let Some(src) = v.get("ruleSource").and_then(|x| x.as_str()) {
        if src == "online" || src == "local" {
            if src != core.cfg.lock().rule_source {
                core.cfg.lock().rule_source = src.to_string();
                rules_changed = true;
            }
        }
    }
    if let Some(h) = v.get("onlineIntervalHours").and_then(|x| x.as_u64()) {
        core.cfg.lock().online_interval_hours = h.min(24 * 30);
    }
    if let Some(list) = rule_list(&v, "proxyHosts", "extraHosts") {
        core.cfg.lock().proxy_hosts = list;
        rules_changed = true;
    }
    if let Some(list) = rule_list(&v, "directHosts", "directHostsText") {
        core.cfg.lock().direct_hosts = list;
        rules_changed = true;
    }
    if rules_changed {
        core.cfg.lock().rules_version = super::paths::RULES_VERSION;
        core.rebuild_rules();
    }
    if let Some(p) = port {
        if p != core.proxy_port() {
            let was_running = core.proxy_running();
            // 端口要变了：先看现在是不是本程序在接管（要用旧端口去比），
            // 重启核心之后好按新端口重新接管，不然系统代理会指向一个已经不监听的端口。
            let was_ours = {
                let sys = core.system_proxy_cached(true);
                sysproxy::owner(&sys, core.proxy_port(), &core.pac_url()).0 == "ours"
            };
            core.stop_proxy();
            core.cfg.lock().proxy_port = p;
            if was_running {
                match core.start_proxy(Some(p)).await {
                    Ok(_) => {
                        if was_ours {
                            match core.enable_sysproxy_saved() {
                                Ok(_) => core
                                    .log(format!("端口已改为 {p}，核心已重启并重新接管系统代理")),
                                Err(e) => core
                                    .log(format!("端口改为 {p} 后重新接管系统代理失败：{e}")),
                            }
                        } else {
                            core.log(format!("端口已改为 {p}，核心已重启"));
                        }
                    }
                    Err(e) => core.log(format!("按新端口重启代理失败：{e}")),
                }
            }
        }
    }
    // 系统代理开着的时候改了模式 → 立刻按新模式重新接管
    let (mode_now, sys_on) = (core.cfg.lock().sysproxy_mode.clone(), core.system_proxy_cached(true));
    if let Some(m) = new_mode {
        if sys_on.enabled || !sys_on.auto_config_url.is_empty() {
            let r = match m.as_str() {
                "pac" => sysproxy::enable_pac_saved(&core.paths, &core.pac_url()),
                _ => sysproxy::enable_saved(
                    &core.paths,
                    &format!("127.0.0.1:{}", core.proxy_port()),
                    "<local>;127.0.0.1;localhost",
                ),
            };
            match r {
                Ok(_) => core.log(format!("系统代理已切换为 {}", if m == "pac" { "PAC 模式" } else { "全局模式" })),
                Err(e) => core.log(format!("切换系统代理模式失败：{e}")),
            }
            core.invalidate_sys_cache();
        }
    }
    let _ = mode_now;
    {
        let cfg = core.cfg.lock();
        cfg.save(&core.paths);
        core.log(format!(
            "设置已保存：端口 {}，白名单 {} 条，黑名单 {} 条，系统代理 {}",
            cfg.proxy_port,
            cfg.proxy_hosts.len(),
            cfg.direct_hosts.len(),
            if cfg.sysproxy_mode == "pac" { "PAC" } else { "全局" }
        ));
    }
    Json(json!({
        "proxyPort": core.proxy_port(),
        "proxyHosts": core.proxy_hosts(),
        "directHosts": core.direct_hosts(),
        "sysproxyMode": core.cfg.lock().sysproxy_mode.clone(),
        "envProxy": core.cfg.lock().env_proxy,
        "guideSeen": core.cfg.lock().guide_seen,
        "onlineUrls": core.cfg.lock().online_urls_clean(),
        "ruleSource": core.cfg.lock().rule_source,
    }))
}

/// 在线规则：`{"action":"sync"}` 立刻拉一次（`{"force":true}` 忽略版本检查）；
/// `{"action":"clear"}` 清掉已缓存的在线规则。
async fn s_online(State(core): CoreState, body: Bytes) -> Json<serde_json::Value> {
    let v = parse_body(&body);
    let action = body_str(&v, "action");
    let force = body_bool(&v, "force");
    match action.as_str() {
        "sync" | "" => match core.sync_online_rules(force).await {
            Ok(r) => Json(json!({
                "ok": true,
                "name": r.name,
                "updated": r.updated,
                "version": r.version,
                "proxy": r.proxy.len(),
                "direct": r.direct.len(),
                "total": r.total(),
                "url": core.cfg.lock().online_last_url,
            })),
            Err(e) => Json(json!({ "error": e })),
        },
        "clear" => {
            let _ = std::fs::remove_file(core.paths.online_rules());
            {
                let mut cfg = core.cfg.lock();
                cfg.online_count = 0;
                cfg.online_synced_at = 0;
                // 连版本判据一起清掉，否则「清除缓存」之后反而再也同步不回同一个版本
                cfg.online_revision = 0;
                cfg.online_last_url.clear();
                cfg.online_error.clear();
                cfg.save(&core.paths);
            }
            core.rebuild_rules();
            core.log("已清除缓存的在线规则（恢复只用本地名单）");
            Json(json!({ "ok": true }))
        }
        other => Json(json!({ "error": format!("不认识的操作：{other}") })),
    }
}

async fn s_sysproxy(State(core): CoreState, body: Bytes) -> Json<serde_json::Value> {
    let v = parse_body(&body);
    let mode = body_str(&v, "mode");
    core.invalidate_sys_cache();
    let result = match mode.as_str() {
        "off" => {
            if sysproxy::user_env_proxy_points_to_localhost() {
                let _ = sysproxy::unset_user_env_proxy();
                core.cfg.lock().env_proxy = false;
                core.cfg.lock().save(&core.paths);
                core.log("命令行代理环境变量已清除");
            }
            sysproxy::disable(&core.paths).map(|_| core.log("系统代理已还原"))
        }
        "pac" => {
            core.cfg.lock().sysproxy_mode = "pac".into();
            sysproxy::enable_pac_saved(&core.paths, &core.pac_url())
            .map(|_| core.log("系统代理已切到 PAC 模式"))
        }
        _ => {
            core.cfg.lock().sysproxy_mode = "global".into();
            let server = format!("127.0.0.1:{}", core.proxy_port());
            let want_env = v
                .get("envProxy")
                .and_then(|x| x.as_bool())
                .unwrap_or_else(|| core.cfg.lock().env_proxy);
            let r = sysproxy::enable_saved(&core.paths, &server, "<local>;127.0.0.1;localhost");
            if r.is_ok() {
                let env_res = if want_env {
                    sysproxy::set_user_env_proxy(&server, "localhost,127.0.0.1,::1")
                } else {
                    sysproxy::unset_user_env_proxy()
                };
                match env_res {
                    Ok(_) => core.log(if want_env {
                        "已为命令行程序设置代理环境变量"
                    } else {
                        "命令行代理环境变量已清除"
                    }),
                    Err(e) => core.log(format!("命令行代理环境变量设置失败：{e}")),
                }
                core.cfg.lock().env_proxy = want_env;
            }
            r.map(|_| core.log("系统代理已指向本地代理"))
        }
    };
    // 模式切换会改变"谁能走 WebVPN"的判定（全局=忽略名单），立刻生效
    core.rebuild_rules();
    core.invalidate_sys_cache();
    match result {
        Ok(_) => Json(json!({
            "ok": true,
            "systemProxy": {
                "enabled": core.system_proxy_cached(true).enabled,
                "server": core.system_proxy_cached(true).server,
            }
        })),
        Err(e) => {
            core.log(format!("系统代理设置失败：{e}"));
            Json(json!({ "error": e }))
        }
    }
}

async fn s_envproxy(State(core): CoreState, body: Bytes) -> Json<serde_json::Value> {
    let v = parse_body(&body);
    core.invalidate_sys_cache();
    let r = if body_bool(&v, "enabled") {
        sysproxy::set_user_env_proxy(
            &format!("127.0.0.1:{}", core.proxy_port()),
            "localhost,127.0.0.1,::1",
        )
        .map(|_| core.log("用户环境变量代理已设置"))
    } else {
        sysproxy::unset_user_env_proxy().map(|_| core.log("用户环境变量代理已清除"))
    };
    match r {
        Ok(_) => Json(json!({ "ok": true })),
        Err(e) => Json(json!({ "error": e })),
    }
}

async fn s_ca_install(State(core): CoreState) -> Json<serde_json::Value> {
    match core.install_ca() {
        Ok(v) => Json(v),
        Err(e) => {
            core.log(format!("安装根证书失败：{e}"));
            Json(json!({ "error": e }))
        }
    }
}

async fn s_ca_uninstall(State(core): CoreState) -> Json<serde_json::Value> {
    match core.uninstall_ca() {
        Ok(v) => Json(v),
        Err(e) => {
            core.log(format!("卸载根证书失败：{e}"));
            Json(json!({ "error": e }))
        }
    }
}

/// 体检用的一次请求：`Some(代理)` 走本机代理，`None` 直连；只关心状态码。
async fn probe_status(proxy: Option<&str>, url: &str) -> Result<u16, String> {
    let mut b = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(std::time::Duration::from_secs(6))
        // 这里只验"隧道通不通"：reqwest 用的是内置根证书库，本来就不认 Windows 根证书库，
        // 正常校验必然失败。浏览器信不信我们的根证书，另外查注册表（cert_installed）。
        .danger_accept_invalid_certs(true);
    b = match proxy {
        Some(p) => b.proxy(reqwest::Proxy::all(p).map_err(|e| e.to_string())?),
        None => b.no_proxy(),
    };
    let client = b.build().map_err(|e| e.to_string())?;
    let res = client.get(url).send().await.map_err(|e| brief_err(&e.to_string()))?;
    Ok(res.status().as_u16())
}

/// 把 reqwest 的长错误压成界面上一行能看懂的
fn brief_err(e: &str) -> String {
    let mut t = e.lines().next().unwrap_or(e).trim().to_string();
    if let Some(i) = t.find(" for url (") {
        t.truncate(i);
    }
    if t.is_empty() {
        t = "请求失败".into();
    }
    if t.chars().count() > 80 {
        t = t.chars().take(80).collect::<String>() + "…";
    }
    t
}

fn check_item(
    id: &str,
    label: &str,
    level: &str,
    ok: bool,
    detail: String,
    fix: String,
) -> serde_json::Value {
    json!({ "id": id, "label": label, "level": level, "ok": ok, "detail": detail, "fix": fix })
}

/// 状态检查：真的发请求，把界面上每盏灯都验一遍（账号 / 核心 / 系统代理 / 根证书 / 学校）。
///
/// 慢（3-8 秒，最坏是等会话请求超时），所以只在用户点「检查」时才跑，不放进 2 秒轮询。
async fn s_doctor(State(core): CoreState) -> Json<serde_json::Value> {
    let port = core.proxy_port();
    let cport = core.control_port.load(Ordering::Relaxed);
    let running = core.proxy_running();
    let mut items: Vec<serde_json::Value> = Vec::new();

    // 1) 控制接口：能回这个请求就说明活着
    items.push(check_item(
        "control",
        "控制接口",
        "ok",
        true,
        format!("127.0.0.1:{cport} 正常响应"),
        String::new(),
    ));

    // 2) 统一认证会话：真发一次 /user/info（失败会被 fetch 自动重登一次）
    let (level, ok, detail, fix) = match core.session.verify().await {
        Ok(t) => {
            let short: String = t.chars().take(6).collect();
            let detail = if short.is_empty() {
                "会话可用".to_string()
            } else {
                format!("会话可用（票据 {short}…）")
            };
            ("ok", true, detail, String::new())
        }
        Err(e) if e.contains("没有可用的账号密码") => (
            "warn",
            false,
            "还没有登录（本机没保存账号密码）".to_string(),
            "在「账号与证书」里填账号密码，点「保存并登录」".to_string(),
        ),
        Err(e) => (
            "bad",
            false,
            e,
            "重新填一次密码点「保存并登录」；老失败就先在校内直连确认账号本身没问题".to_string(),
        ),
    };
    items.push(check_item("session", "统一认证会话", level, ok, detail, fix));

    // 3) 核心 + 穿透：真的借本机代理访问一次学校（只读 GET）
    if !running {
        items.push(check_item(
            "proxy",
            "本地代理",
            "warn",
            false,
            format!("127.0.0.1:{port} 没在跑"),
            "核心随程序自动启动，没起来就在顶部横幅点「重试」（原因看右侧日志）".to_string(),
        ));
    } else {
        let proxy = format!("http://127.0.0.1:{port}");
        let mut parts: Vec<String> = Vec::new();
        let mut ok = true;
        let mut level = "ok";
        let mut fix = String::new();
        for (name, url) in [
            ("HTTP", "http://www.sdust.edu.cn/"),
            ("HTTPS", "https://www.sdust.edu.cn/"),
        ] {
            match probe_status(Some(&proxy), url).await {
                Ok(s) if s < 400 => parts.push(format!("{name} {s}")),
                Ok(s) => {
                    parts.push(format!("{name} {s}（被拒）"));
                    ok = false;
                    level = "warn";
                    fix = "能连上但学校侧拒绝了：看看账号登录没有、分流名单对不对".into();
                }
                Err(e) => {
                    parts.push(format!("{name} 断了：{e}"));
                    ok = false;
                    level = "bad";
                    fix = "等一会儿再看，或者重启一次程序；还不行看右侧日志".into();
                }
            }
        }
        items.push(check_item("proxy", "本地代理", level, ok, parts.join(" · "), fix));
    }

    // 4) 系统代理：期望值 vs 注册表真值（顺便揪出"被翻墙软件占了"）
    let sys = core.system_proxy_cached(true);
    let (owner, who) = sysproxy::owner(&sys, port, &core.pac_url());
    let env_on = sysproxy::user_env_proxy_points_to_localhost();
    let (level, ok, detail, fix) = match owner {
        // 指向本程序，但核心没跑（上次被强杀、没走正常收尾）——系统代理会指向一个死端口
        "ours" if !running => (
            "warn",
            false,
            format!(
                "系统代理还指着本程序（{}），但核心没在跑",
                if who == "PAC" { "PAC" } else { "全局" }
            ),
            "点「关闭系统代理」还原（会把接管前的设置放回去），或者点「开启系统代理」重新用起来"
                .to_string(),
        ),
        "ours" => (
            "ok",
            true,
            format!(
                "已接管（{}）{}",
                if who == "PAC" { "PAC" } else { "全局" },
                if env_on { " · 命令行环境变量也已设置" } else { "" }
            ),
            String::new(),
        ),
        "other" => (
            "bad",
            false,
            format!("被其它程序占用：{who}"),
            "点「开启系统代理」重新接管；如果那是翻墙软件的系统代理模式，建议改用它的 TUN 模式（两个都开会互相顶）".to_string(),
        ),
        _ if running => (
            "warn",
            false,
            "核心在跑，但系统代理没指向本机".to_string(),
            "点「开启系统代理」".to_string(),
        ),
        _ => ("ok", true, "没接管（核心没跑，正常）".to_string(), String::new()),
    };
    items.push(check_item("sysproxy", "系统代理", level, ok, detail, fix));

    // 5) 根证书
    let ca = core.ca_installed(true);
    items.push(check_item(
        "ca",
        "根证书",
        if ca { "ok" } else { "warn" },
        ca,
        if ca {
            "已装进当前用户的根证书库".to_string()
        } else {
            "没装".to_string()
        },
        if ca {
            String::new()
        } else {
            "点「账号与证书」卡片里的「安装」；不装的话 HTTPS 网站会提示证书不受信任".to_string()
        },
    ));

    // 6) 学校服务器（直连，不经过本机代理）
    match probe_status(None, "https://webvpn.sdust.edu.cn/").await {
        Ok(s) => items.push(check_item(
            "school",
            "学校服务器",
            "ok",
            true,
            format!("直连可达（HTTP {s}）"),
            String::new(),
        )),
        Err(e) => items.push(check_item(
            "school",
            "学校服务器",
            "bad",
            false,
            format!("直连不通：{e}"),
            "检查本机网络 / DNS；校外用 WebVPN 也得先能连上这个域名".to_string(),
        )),
    }

    let bad = items
        .iter()
        .filter(|i| i.get("ok").and_then(|x| x.as_bool()) != Some(true))
        .count();
    core.log(format!(
        "状态检查完成：共 {} 项，{} 项要注意",
        items.len(),
        bad
    ));
    Json(json!({ "ok": bad == 0, "bad": bad, "items": items }))
}

fn router(core: Arc<Core>) -> Router {
    Router::new()
        .route("/status", get(s_status))
        .route("/logs", get(s_logs))
        .route("/pac", get(s_pac))
        .route("/", get(s_root))
        .route("/login", post(s_login))
        .route("/logout", post(s_logout))
        .route("/doctor", post(s_doctor))
        .route("/credentials", post(s_credentials))
        .route("/proxy/start", post(s_proxy_start))
        .route("/proxy/stop", post(s_proxy_stop))
        .route("/config", post(s_config))
        .route("/online", post(s_online))
        .route("/sysproxy", post(s_sysproxy))
        .route("/envproxy", post(s_envproxy))
        .route("/ca/install", post(s_ca_install))
        .route("/ca/uninstall", post(s_ca_uninstall))
        .route("/quit", post(s_quit))
        .with_state(core)
}
