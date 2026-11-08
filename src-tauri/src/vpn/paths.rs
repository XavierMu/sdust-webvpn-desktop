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
    /// 在线规则来源：空 = 只用本地名单；非空 = 拉这个网址的规则（用户在「分流规则」里填）
    #[serde(default)]
    pub online_url: String,
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
            online_url: String::new(),
            rule_source: default_rule_source(),
            online_interval_hours: default_online_interval(),
            online_synced_at: 0,
            online_count: 0,
            online_error: String::new(),
        }
    }
}

/// 白名单默认值。改这个列表时记得把下面的 `RULES_VERSION` 加 1，
/// 老配置会在启动时把「新增的默认项」并进去（不会覆盖用户自己加的）。
pub const RULES_VERSION: u32 = 2;

/// 新装/迁移时白名单的初始内容，保持「装完就能用」的旧行为。
/// 校内导航里点开就要能用的站点，域名都写在这里：
/// `sdust.edu.cn` 一个后缀就带上全部 *.sdust.edu.cn；内网地址段覆盖那些 10/172.16/192.168 的机器；
/// 剩下三个是校外的付费资源（知网、超星电子书、国研网），学校买了、从校内网出去才能用。
pub fn default_proxy_hosts() -> Vec<String> {
    vec![
        "sdust.edu.cn".to_string(),
        "cnki.net".to_string(),
        "sslibrary.com".to_string(),
        "drcnet.com.cn".to_string(),
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
        if cfg.rules_version < RULES_VERSION {
            cfg.migrate_rules();
        }
        cfg
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
