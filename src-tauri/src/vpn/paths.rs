//! 目录与配置。

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug)]
pub struct Paths {
    pub root: PathBuf,
}

impl Paths {
    pub fn new(root: PathBuf) -> Self {
        let p = Self { root };
        let _ = std::fs::create_dir_all(p.state());
        p
    }

    pub fn state(&self) -> PathBuf {
        self.root.join("state")
    }
    pub fn cookies(&self) -> PathBuf {
        self.state().join("cookies.json")
    }
    pub fn config(&self) -> PathBuf {
        self.state().join("config.json")
    }
    pub fn ca_dir(&self) -> PathBuf {
        self.state().join("ca")
    }
    pub fn ca_cert(&self) -> PathBuf {
        self.ca_dir().join("ca.crt")
    }
    pub fn ca_key(&self) -> PathBuf {
        self.ca_dir().join("ca.key")
    }
    pub fn certs_dir(&self) -> PathBuf {
        self.state().join("certs")
    }
    pub fn secrets(&self) -> PathBuf {
        self.root.join(".secrets")
    }
    pub fn dpapi(&self) -> PathBuf {
        self.secrets().join("creds.dpapi")
    }
    pub fn creds_json(&self) -> PathBuf {
        self.secrets().join("creds.json")
    }
    pub fn sysproxy_backup(&self) -> PathBuf {
        self.state().join("sysproxy-backup.json")
    }
    pub fn log_file(&self) -> PathBuf {
        self.state().join("core.log")
    }
    /// 在线规则最近一次成功同步下来的原文（离线也能用）
    pub fn online_rules(&self) -> PathBuf {
        self.state().join("online-rules.json")
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Config {
    #[serde(default = "default_proxy_port")]
    pub proxy_port: u16,
    /// 白名单：命中就走 WebVPN
    #[serde(default)]
    pub proxy_hosts: Vec<String>,
    /// 黑名单：命中就直连（优先级高于白名单）
    #[serde(default)]
    pub direct_hosts: Vec<String>,
    /// 规则结构版本（0/1 = 旧「额外域名」配置，需要迁移一次）
    #[serde(default)]
    pub rules_version: u32,
    /// 旧版字段：只读，用于迁移；不再写回
    #[serde(default, rename = "extraHosts", skip_serializing)]
    pub legacy_extra_hosts: Vec<String>,
    /// 系统代理模式：pac（按名单分流，默认）或 global（全局，全部走学校出口）
    #[serde(default = "default_sysproxy_mode")]
    pub sysproxy_mode: String,
    /// 是否同时给命令行程序设置 HTTP_PROXY 等用户环境变量
    #[serde(default)]
    pub env_proxy: bool,
    /// 启动核心时自动接管系统代理
    #[serde(default = "default_true")]
    pub auto_sysproxy: bool,
    /// 是否已经看过「首次使用」引导弹窗（看过就不再自动弹）
    #[serde(default)]
    pub guide_seen: bool,
    /// 是否已经看过「安装根证书」的单独提示（勾了不再提示就不再自动弹）
    #[serde(default)]
    pub ca_prompt_seen: bool,
    /// 点了「稍后」之后，这个时间点（unix 秒）之前不再自动弹证书提示；0 = 没推迟过
    #[serde(default)]
    pub ca_prompt_snooze_until: u64,
    /// 在线规则地址：一行一个，按顺序尝试，前面的打不开就试后面的；空 = 只用本地名单
    #[serde(default = "default_rule_urls")]
    pub online_urls: Vec<String>,
    /// 旧版单地址字段：只读，用于迁移到 `online_urls`；不再写回
    #[serde(default, rename = "online_url", skip_serializing)]
    pub legacy_online_url: String,
    /// 在线规则与本地名单怎么合：`online`（在线优先，本地补充）或 `local`（只认本地名单）
    #[serde(default = "default_rule_source")]
    pub rule_source: String,
    /// 是否每 N 小时自动同步一次在线规则（0 = 只在点「同步」时拉）
    #[serde(default = "default_online_interval")]
    pub online_interval_hours: u64,
    /// 最近一次同步成功的时间（unix 秒）与当时的条目数，界面用来显示状态
    #[serde(default)]
    pub online_synced_at: u64,
    #[serde(default)]
    pub online_count: u64,
    /// 最近一次成功同步用的那个地址（配了多个镜像时，用来显示实际走的哪条）
    #[serde(default)]
    pub online_last_url: String,
    /// 最近一次成功同步的远端版本（数字 version，或 updated 里的 YYYYMMDD；0 = 未知）。
    /// 下次同步拿到更小的值就拒绝覆盖，避免 CDN 缓存/误操作把规则回滚。
    #[serde(default)]
    pub online_revision: u64,
    /// 最近一次同步的失败原因（成功后清空）
    #[serde(default)]
    pub online_error: String,
}

fn default_online_interval() -> u64 {
    24
}

fn default_rule_source() -> String {
    "online".to_string()
}

/// 内置的公共规则地址，按顺序尝试（前面的打不开/内容比本地旧就试下一个）。
///
/// 规则文件托管在 GitHub 的 `sdust-webvpn-rules` 仓库，用 jsDelivr 的 CDN 取
/// （比 `raw.githubusercontent.com` 在国内的可达性好一些），最后一条原始地址兜底。
/// 全部失败时不动已缓存的规则 —— 也就是「拉不到就继续用上次的」。
pub fn default_rule_urls() -> Vec<String> {
    vec![
        "https://fastly.jsdelivr.net/gh/XavierMu/sdust-webvpn-rules@main/rules.json".to_string(),
        "https://cdn.jsdelivr.net/gh/XavierMu/sdust-webvpn-rules@main/rules.json".to_string(),
        "https://raw.githubusercontent.com/XavierMu/sdust-webvpn-rules/main/rules.json".to_string(),
    ]
}


fn default_true() -> bool {
    true
}

fn default_sysproxy_mode() -> String {
    "pac".to_string()
}

fn default_proxy_port() -> u16 {
    8899
}

impl Default for Config {
    fn default() -> Self {
        Self {
            proxy_port: default_proxy_port(),
            proxy_hosts: default_proxy_hosts(),
            direct_hosts: Vec::new(),
            rules_version: RULES_VERSION,
            legacy_extra_hosts: Vec::new(),
            sysproxy_mode: default_sysproxy_mode(),
            env_proxy: false,
            auto_sysproxy: true,
            guide_seen: false,
            ca_prompt_seen: false,
            ca_prompt_snooze_until: 0,
            online_urls: default_rule_urls(),
            legacy_online_url: String::new(),
            rule_source: default_rule_source(),
            online_interval_hours: default_online_interval(),
            online_synced_at: 0,
            online_count: 0,
            online_last_url: String::new(),
            online_revision: 0,
            online_error: String::new(),
        }
    }
}

/// 白名单默认值。改这个列表时记得把下面的 `RULES_VERSION` 加 1，
/// 老配置会在启动时把「新增的默认项」并进去（不会覆盖用户自己加的）。
pub const RULES_VERSION: u32 = 3;

/// 新装/迁移时白名单的初始内容，保持「装完就能用」的旧行为。
/// 校内导航里点开就要能用的站点，域名都写在这里：
/// `sdust.edu.cn` 一个后缀就带上全部 *.sdust.edu.cn；内网地址段覆盖那些 10/172.16/192.168 的机器；
/// 剩下的几个是校外的付费资源（知网、超星电子书、国研网、IEEE Xplore），
/// 学校买了、从校内网出去才能用。
pub fn default_proxy_hosts() -> Vec<String> {
    vec![
        "sdust.edu.cn".to_string(),
        "cnki.net".to_string(),
        "sslibrary.com".to_string(),
        "drcnet.com.cn".to_string(),
        "ieeexplore.ieee.org".to_string(),
        "10.0.0.0/8".to_string(),
        "172.16.0.0/12".to_string(),
        "192.168.0.0/16".to_string(),
        "100.64.0.0/10".to_string(),
        "169.254.0.0/16".to_string(),
    ]
}

impl Config {
    pub fn load(paths: &Paths) -> Self {
        let mut cfg: Config = std::fs::read_to_string(paths.config())
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default();
        // 老配置里手填的单地址：原样尊重，不再往里补默认镜像
        cfg.migrate_online_urls();
        if cfg.rules_version < RULES_VERSION {
            cfg.migrate_rules();
        }
        cfg
    }

    /// 旧版 `online_url`（单个字符串）→ `online_urls`（列表）。
    /// 用户当初是自己填的地址，迁移时原样保留，不掺默认镜像。
    fn migrate_online_urls(&mut self) {
        if !self.legacy_online_url.trim().is_empty() {
            self.online_urls = vec![self.legacy_online_url.trim().to_string()];
        }
        self.legacy_online_url.clear();
    }

    /// 生效的在线规则地址：去空行、去重、保持顺序。空 = 用户关掉了在线规则。
    pub fn online_urls_clean(&self) -> Vec<String> {
        let mut seen = std::collections::HashSet::new();
        self.online_urls
            .iter()
            .map(|u| u.trim().to_string())
            .filter(|u| !u.is_empty() && seen.insert(u.clone()))
            .collect()
    }

    /// 迁移名单：v0（只有 `extraHosts`）→ 默认白名单 + 原来的额外域名；
    /// v1 起（已经有 `proxy_hosts`）→ **只把新增的默认项并进去**，用户自己加的一条都不动。
    fn migrate_rules(&mut self) {
        let mut defaults = default_proxy_hosts();
        defaults.extend(self.legacy_extra_hosts.iter().cloned());
        self.legacy_extra_hosts.clear();

        if self.rules_version >= 1 || !self.proxy_hosts.is_empty() {
            let mut merged = self.proxy_hosts.clone();
            merged.extend(defaults);
            let mut seen = std::collections::HashSet::new();
            merged.retain(|h| seen.insert(h.to_ascii_lowercase()));
            self.proxy_hosts = merged;
        } else {
            let mut seen = std::collections::HashSet::new();
            defaults.retain(|h| seen.insert(h.to_ascii_lowercase()));
            self.proxy_hosts = defaults;
        }
        self.rules_version = RULES_VERSION;
    }

    pub fn save(&self, paths: &Paths) {
        if let Ok(s) = serde_json::to_string_pretty(self) {
            let _ = std::fs::write(paths.config(), s);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_config_gets_builtin_rule_urls() {
        assert_eq!(Config::default().online_urls, default_rule_urls());
        assert!(!default_rule_urls().is_empty());
    }

    #[test]
    fn old_single_url_wins_over_defaults() {
        let mut cfg: Config = serde_json::from_str(r#"{"online_url":" https://my.example/r.json "}"#)
            .expect("老配置要能读进来");
        cfg.migrate_online_urls();
        assert_eq!(cfg.online_urls, vec!["https://my.example/r.json"]);
        assert!(cfg.legacy_online_url.is_empty());
    }

    #[test]
    fn empty_old_url_keeps_defaults() {
        let mut cfg: Config = serde_json::from_str(r#"{"online_url":""}"#).expect("要能读进来");
        cfg.migrate_online_urls();
        assert_eq!(cfg.online_urls, default_rule_urls());
    }

    #[test]
    fn saved_config_does_not_write_the_legacy_field() {
        let s = serde_json::to_string(&Config::default()).unwrap();
        assert!(s.contains("online_urls"));
        assert!(!s.contains("\"online_url\""));
    }

    #[test]
    fn clean_urls_drops_blanks_and_dupes() {
        let mut cfg = Config::default();
        cfg.online_urls = vec![
            "  https://a.example/r.json  ".into(),
            String::new(),
            "https://b.example/r.json".into(),
            "https://a.example/r.json".into(),
            "   ".into(),
        ];
        assert_eq!(
            cfg.online_urls_clean(),
            vec!["https://a.example/r.json", "https://b.example/r.json"]
        );
    }

    #[test]
    fn clearing_the_list_disables_online_rules() {
        // 用户把多行框清空 = 明确关掉在线规则，不能再回退到默认镜像
        let mut cfg = Config::default();
        cfg.online_urls = Vec::new();
        assert!(cfg.online_urls_clean().is_empty());
        let back: Config = serde_json::from_str(&serde_json::to_string(&cfg).unwrap()).unwrap();
        assert!(back.online_urls_clean().is_empty());
    }

    #[test]
    fn builtin_whitelist_covers_ieee() {
        assert!(default_proxy_hosts()
            .iter()
            .any(|h| h == "ieeexplore.ieee.org"));
    }

    #[test]
    fn old_config_picks_up_new_builtin_hosts() {
        // 老配置（rules_version 2，还没有这一条）升级后要能拿到新加的内置白名单，
        // 自己加的条目一条都不能丢，内置项也不能重复
        let mut cfg: Config =
            serde_json::from_str(r#"{"rules_version":2,"proxy_hosts":["sdust.edu.cn","my.example"]}"#)
                .expect("老配置要能读进来");
        cfg.migrate_rules();
        assert_eq!(cfg.rules_version, RULES_VERSION);
        assert!(cfg.proxy_hosts.iter().any(|h| h == "ieeexplore.ieee.org"));
        assert!(cfg.proxy_hosts.iter().any(|h| h == "my.example"));
        assert_eq!(
            cfg.proxy_hosts.iter().filter(|h| *h == "sdust.edu.cn").count(),
            1
        );
    }
}
