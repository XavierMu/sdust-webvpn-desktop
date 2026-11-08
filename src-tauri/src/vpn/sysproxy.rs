//! Windows 系统代理（HKCU Internet Settings）与环境变量代理，无需管理员权限。

use std::ffi::c_void;

use serde::{Deserialize, Serialize};
use windows_sys::Win32::Foundation::{ERROR_FILE_NOT_FOUND, ERROR_SUCCESS};
use windows_sys::Win32::Networking::WinInet::{
    InternetSetOptionW, INTERNET_OPTION_REFRESH, INTERNET_OPTION_SETTINGS_CHANGED,
};
use windows_sys::Win32::System::Registry::{
    RegCloseKey, RegDeleteValueW, RegOpenKeyExW, RegQueryValueExW, RegSetValueExW, HKEY,
    HKEY_CURRENT_USER, KEY_READ, KEY_SET_VALUE, REG_DWORD, REG_SZ,
};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    SendMessageTimeoutW, HWND_BROADCAST, SMTO_ABORTIFHUNG, WM_SETTINGCHANGE,
};

use super::paths::Paths;

const INTERNET_SETTINGS: &str = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings";
const ENV_KEY: &str = "Environment";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyState {
    pub enabled: bool,
    pub server: String,
    #[serde(rename = "override")]
    pub override_list: String,
    #[serde(rename = "autoConfigUrl")]
    pub auto_config_url: String,
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

fn open_key(path: &str, access: u32) -> Option<HKEY> {
    let p = wide(path);
    let mut key: HKEY = std::ptr::null_mut();
    let rc = unsafe { RegOpenKeyExW(HKEY_CURRENT_USER, p.as_ptr(), 0, access, &mut key) };
    if rc == ERROR_SUCCESS {
        Some(key)
    } else {
        None
    }
}

fn read_string(hive: HKEY, name: &str) -> String {
    let n = wide(name);
    let mut kind: u32 = 0;
    let mut size: u32 = 0;
    let rc = unsafe {
        RegQueryValueExW(
            hive,
            n.as_ptr(),
            std::ptr::null_mut(),
            &mut kind,
            std::ptr::null_mut(),
            &mut size,
        )
    };
    if rc != ERROR_SUCCESS || size == 0 {
        return String::new();
    }
    let mut buf = vec![0u8; size as usize];
    let rc = unsafe {
        RegQueryValueExW(
            hive,
            n.as_ptr(),
            std::ptr::null_mut(),
            &mut kind,
            buf.as_mut_ptr(),
            &mut size,
        )
    };
    if rc != ERROR_SUCCESS {
        return String::new();
    }
    if kind == REG_SZ {
        let u16s: Vec<u16> = buf
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .take_while(|c| *c != 0)
            .collect();
        String::from_utf16_lossy(&u16s)
    } else if kind == REG_DWORD && buf.len() >= 4 {
        String::new()
    } else {
        String::new()
    }
}

fn read_dword(hive: HKEY, name: &str) -> u32 {
    let n = wide(name);
    let mut kind: u32 = 0;
    let mut data: u32 = 0;
    let mut size: u32 = 4;
    let rc = unsafe {
        RegQueryValueExW(
            hive,
            n.as_ptr(),
            std::ptr::null_mut(),
            &mut kind,
            &mut data as *mut u32 as *mut u8,
            &mut size,
        )
    };
    if rc == ERROR_SUCCESS && kind == REG_DWORD {
        data
    } else {
        0
    }
}

fn set_string(hive: HKEY, name: &str, value: &str) -> bool {
    let n = wide(name);
    let v = wide(value);
    let bytes = v.len() * 2;
    unsafe {
        RegSetValueExW(
            hive,
            n.as_ptr(),
            0,
            REG_SZ,
            v.as_ptr() as *const u8,
            bytes as u32,
        ) == ERROR_SUCCESS
    }
}

fn set_dword(hive: HKEY, name: &str, value: u32) -> bool {
    let n = wide(name);
    unsafe {
        RegSetValueExW(
            hive,
            n.as_ptr(),
            0,
            REG_DWORD,
            &value as *const u32 as *const u8,
            4,
        ) == ERROR_SUCCESS
    }
}

fn delete_value(hive: HKEY, name: &str) {
    let n = wide(name);
    let rc = unsafe { RegDeleteValueW(hive, n.as_ptr()) };
    let _ = rc != ERROR_FILE_NOT_FOUND;
}

/// 通知系统代理设置已变化（否则浏览器要等一会儿才生效）
pub fn refresh() {
    unsafe {
        InternetSetOptionW(
            std::ptr::null_mut(),
            INTERNET_OPTION_SETTINGS_CHANGED as u32,
            std::ptr::null_mut() as *mut c_void,
            0,
        );
        InternetSetOptionW(
            std::ptr::null_mut(),
            INTERNET_OPTION_REFRESH as u32,
            std::ptr::null_mut() as *mut c_void,
            0,
        );
    }
}

/// 当前用户的根证书库里是否已有该指纹（SHA-1 大写 hex）
pub fn cert_installed(thumb: &str) -> bool {
    if thumb.is_empty() {
        return false;
    }
    let path = format!(
        r"Software\Microsoft\SystemCertificates\Root\Certificates\{}",
        thumb.to_uppercase()
    );
    match open_key(&path, KEY_READ) {
        Some(k) => {
            unsafe { RegCloseKey(k) };
            true
        }
        None => false,
    }
}

pub fn get() -> ProxyState {
    let Some(key) = open_key(INTERNET_SETTINGS, KEY_READ) else {
        return ProxyState {
            enabled: false,
            server: String::new(),
            override_list: String::new(),
            auto_config_url: String::new(),
        };
    };
    let state = ProxyState {
        enabled: read_dword(key, "ProxyEnable") == 1,
        server: read_string(key, "ProxyServer"),
        override_list: read_string(key, "ProxyOverride"),
        auto_config_url: read_string(key, "AutoConfigURL"),
    };
    unsafe { RegCloseKey(key) };
    state
}

/// 当前设置是否指向本机代理（固定端口或 PAC 都算）
fn points_at_localhost(s: &ProxyState) -> bool {
    let server_local = s.server.starts_with("127.0.0.1:") || s.server.starts_with("localhost:");
    let pac_local = s.auto_config_url.starts_with("http://127.0.0.1")
        || s.auto_config_url.starts_with("http://localhost");
    server_local || pac_local || s.server.contains("127.0.0.1:")
}

/// 现在的系统代理到底归谁：`ours` / `none` / `other`（`other` 附带对方地址，界面要说清楚）。
///
/// 只看 `ProxyEnable` 是不够的 —— 别的代理软件（Clash / v2rayN 之类）写的是同一个注册表键，
/// 光看"开着"就会把别人的代理当成我们自己的，用户看到"系统代理：全局"却上不了校内网站。
pub fn owner(state: &ProxyState, our_proxy_port: u16, our_pac_url: &str) -> (&'static str, String) {
    let server = state.server.trim().to_string();
    let pac = state.auto_config_url.trim().to_string();
    let ours_server = server == format!("127.0.0.1:{our_proxy_port}")
        || server == format!("localhost:{our_proxy_port}");
    // PAC 的 URL 带 ?g=版本号，重启后版本会变，所以只比路径部分
    let base = |u: &str| {
        u.split('?')
            .next()
            .unwrap_or("")
            .trim_end_matches('/')
            .to_ascii_lowercase()
    };
    let ours_pac = !pac.is_empty() && base(&pac) == base(our_pac_url);
    if ours_pac {
        return ("ours", "PAC".to_string());
    }
    if ours_server && state.enabled {
        return ("ours", server);
    }
    let pac_other = !pac.is_empty();
    let server_other = state.enabled && !server.is_empty();
    match (pac_other, server_other) {
        (true, true) => ("other", format!("{server}（PAC：{pac}）")),
        (true, false) => ("other", pac),
        (false, true) => ("other", server),
        (false, false) => ("none", String::new()),
    }
}

/// 记录接管前的原始设置。
///
/// 只在「当前设置不是本机代理」时才写/覆盖：模式切换（全局↔PAC）时两种形态都算“我们”，
/// 否则第二次接管会把我们自己的地址写进备份，还原时就把用户原来的代理弄丢了。
fn backup_if_needed(paths: &Paths) {
    let file = paths.sysproxy_backup();
    let mut cur = get();
    let pointing_at_us = points_at_localhost(&cur);
    if file.exists() && pointing_at_us {
        // 已经指向我们：现存备份才是真正的"原始设置"，保留
        return;
    }
    // 备份里不要留“指向我们自己”的残留；非本机的用户代理原样保留
    if pointing_at_us {
        if cur.server.starts_with("127.0.0.1:") || cur.server.starts_with("localhost:") {
            cur.server.clear();
            cur.enabled = false;
        }
        if cur.auto_config_url.starts_with("http://127.0.0.1")
            || cur.auto_config_url.starts_with("http://localhost")
        {
            cur.auto_config_url.clear();
        }
    }
    let cur_empty = cur.server.is_empty() && !cur.enabled && cur.auto_config_url.is_empty();
    if cur_empty && file.exists() {
        if let Ok(t) = std::fs::read_to_string(&file) {
            if let Ok(prev) = serde_json::from_str::<ProxyState>(&t) {
                if !prev.server.is_empty() || prev.enabled {
                    // 已有更可信的“原始设置”，别用一份空的覆盖它
                    return;
                }
            }
        }
    }
    let _ = std::fs::create_dir_all(paths.state());
    if let Ok(s) = serde_json::to_string_pretty(&cur) {
        let _ = std::fs::write(file, s);
    }
}

/// 上次异常退出（比如崩溃）后系统代理可能还指向本机已停止的代理，
/// 启动时先还原一次，避免“一开机就断网”。
pub fn heal(paths: &Paths, our_port: u16) -> Option<String> {
    let cur = get();
    let ours = format!("127.0.0.1:{our_port}");
    let points_at_us = cur.server == ours
        || (!cur.auto_config_url.is_empty() && cur.auto_config_url.contains(&ours))
        || cur.auto_config_url.contains("127.0.0.1");
    if points_at_us && paths.sysproxy_backup().exists() {
        if disable(paths).is_ok() {
            return Some("检测到上次未还原的系统代理，已自动还原".to_string());
        }
    }
    None
}

/// 固定服务器模式
pub fn enable(server: &str, override_list: &str) -> Result<(), String> {
    let key = open_key(INTERNET_SETTINGS, KEY_READ | KEY_SET_VALUE)
        .ok_or_else(|| "打不开 Internet Settings 注册表键".to_string())?;
    let ok = set_string(key, "ProxyServer", server)
        && set_string(key, "ProxyOverride", override_list)
        && set_dword(key, "ProxyEnable", 1);
    delete_value(key, "AutoConfigURL");
    unsafe { RegCloseKey(key) };
    refresh();
    if ok {
        Ok(())
    } else {
        Err("写入代理设置失败（可能被安全软件拦截）".into())
    }
}

/// PAC 模式
pub fn enable_pac(pac_url: &str) -> Result<(), String> {
    let key = open_key(INTERNET_SETTINGS, KEY_READ | KEY_SET_VALUE)
        .ok_or_else(|| "打不开 Internet Settings 注册表键".to_string())?;
    // 保留 ProxyServer 原值：PAC 生效时它本来就被忽略，删掉反而会丢用户原来的代理地址
    let ok = set_string(key, "AutoConfigURL", pac_url) && set_dword(key, "ProxyEnable", 0);
    unsafe { RegCloseKey(key) };
    refresh();
    if ok {
        Ok(())
    } else {
        Err("写入 PAC 设置失败".into())
    }
}

/// 打开系统代理（有则备份原值，供还原）
pub fn enable_saved(paths: &Paths, server: &str, override_list: &str) -> Result<(), String> {
    backup_if_needed(paths);
    enable(server, override_list)
}

pub fn enable_pac_saved(paths: &Paths, pac_url: &str) -> Result<(), String> {
    backup_if_needed(paths);
    enable_pac(pac_url)
}

/// 还原（有备份用备份，没备份就关掉）
pub fn disable(paths: &Paths) -> Result<(), String> {
    let key = open_key(INTERNET_SETTINGS, KEY_READ | KEY_SET_VALUE)
        .ok_or_else(|| "打不开 Internet Settings 注册表键".to_string())?;

    let backup = std::fs::read_to_string(paths.sysproxy_backup())
        .ok()
        .and_then(|s| serde_json::from_str::<ProxyState>(&s).ok());

    match backup {
        Some(mut b) => {
            if b.auto_config_url.starts_with("http://127.0.0.1") || b.auto_config_url.starts_with("http://localhost") {
                b.auto_config_url.clear();
            }
            if b.server.starts_with("127.0.0.1:") || b.server.starts_with("localhost:") {
                b.server.clear();
                b.enabled = false;
            }
            if b.server.is_empty() {
                delete_value(key, "ProxyServer");
            } else {
                set_string(key, "ProxyServer", &b.server);
            }
            if !b.override_list.is_empty() {
                set_string(key, "ProxyOverride", &b.override_list);
            }
            if b.auto_config_url.is_empty() {
                delete_value(key, "AutoConfigURL");
            } else {
                set_string(key, "AutoConfigURL", &b.auto_config_url);
            }
            set_dword(key, "ProxyEnable", if b.enabled { 1 } else { 0 });
            // 备份**不删**：以后每次接管/还原都还能回到同一份原始设置，
            // 避免中途某次把备份覆盖成空值后，用户的代理地址就找不回来了。
        }
        None => {
            // 没有备份时只清理“指向本机”的设置，别动用户自己的代理
            let cur = get();
            set_dword(key, "ProxyEnable", 0);
            if cur.server.starts_with("127.0.0.1:") || cur.server.starts_with("localhost:") {
                delete_value(key, "ProxyServer");
            }
            if cur.auto_config_url.contains("127.0.0.1") {
                delete_value(key, "AutoConfigURL");
            }
        }
    }
    unsafe { RegCloseKey(key) };
    refresh();
    Ok(())
}

fn env_key_write() -> Option<HKEY> {
    open_key(ENV_KEY, KEY_READ | KEY_SET_VALUE)
}

fn broadcast_env_change() {
    let param = wide("Environment");
    unsafe {
        let mut result: usize = 0;
        SendMessageTimeoutW(
            HWND_BROADCAST,
            WM_SETTINGCHANGE,
            0,
            param.as_ptr() as isize,
            SMTO_ABORTIFHUNG,
            2000,
            &mut result,
        );
    }
}

/// 给命令行程序（git/pip/npm）设置用户环境变量
pub fn set_user_env_proxy(server: &str, no_proxy: &str) -> Result<(), String> {
    let key = env_key_write().ok_or_else(|| "打不开 HKCU\\Environment".to_string())?;
    let url = format!("http://{server}");
    let ok = set_string(key, "HTTP_PROXY", &url)
        && set_string(key, "HTTPS_PROXY", &url)
        && set_string(key, "NO_PROXY", no_proxy);
    unsafe { RegCloseKey(key) };
    broadcast_env_change();
    if ok {
        Ok(())
    } else {
        Err("写入环境变量失败".into())
    }
}

/// 当前用户环境变量里的代理是否指向本机代理（127.0.0.1 / localhost）
pub fn user_env_proxy_points_to_localhost() -> bool {
    let Some(key) = env_key_write() else {
        return false;
    };
    let http = read_string(key, "HTTP_PROXY");
    let https = read_string(key, "HTTPS_PROXY");
    unsafe { RegCloseKey(key) };
    ours_host(&http) || ours_host(&https)
}

fn ours_host(v: &str) -> bool {
    let t = v.trim().to_ascii_lowercase();
    if t.is_empty() {
        return false;
    }
    let t = t.trim_start_matches("http://").trim_start_matches("https://");
    t.starts_with("127.0.0.1:") || t.starts_with("localhost:") || t.starts_with("[::1]:")
}

/// 只清除“指向本机代理”的那几个值，用户自己设的 HTTP_PROXY 不动。
pub fn unset_user_env_proxy() -> Result<(), String> {
    let key = env_key_write().ok_or_else(|| "打不开 HKCU\\Environment".to_string())?;
    if ours_host(&read_string(key, "HTTP_PROXY")) {
        delete_value(key, "HTTP_PROXY");
    }
    if ours_host(&read_string(key, "HTTPS_PROXY")) {
        delete_value(key, "HTTPS_PROXY");
    }
    let no_proxy = read_string(key, "NO_PROXY");
    if no_proxy.contains("127.0.0.1") && no_proxy.contains("localhost") {
        delete_value(key, "NO_PROXY");
    }
    unsafe { RegCloseKey(key) };
    broadcast_env_change();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_current_proxy_state() {
        let s = get();
        // 只验证能读出结构，不断言具体值
        let _ = (s.enabled, s.server, s.override_list, s.auto_config_url);
    }
}
