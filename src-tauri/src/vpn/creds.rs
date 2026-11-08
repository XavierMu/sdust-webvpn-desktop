//! 凭据存取：环境变量 → 明文 json（调试）→ DPAPI 密文。

use std::path::PathBuf;

use base64::Engine;
use serde::{Deserialize, Serialize};

use super::dpapi;
use super::paths::Paths;

#[derive(Clone, Debug)]
pub struct Creds {
    pub username: String,
    pub password: String,
    pub source: &'static str,
}

#[derive(Serialize, Deserialize)]
struct DpapiBlob {
    username: String,
    secret: String,
}

pub fn load(paths: &Paths) -> Result<Creds, String> {
    if let (Ok(u), Ok(p)) = (std::env::var("VPN_USER"), std::env::var("VPN_PASS")) {
        if !u.is_empty() && !p.is_empty() {
            return Ok(Creds {
                username: u,
                password: p,
                source: "env",
            });
        }
    }

    if let Ok(s) = std::fs::read_to_string(paths.creds_json()) {
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(&s) {
            let u = v.get("username").and_then(|x| x.as_str()).unwrap_or("");
            let p = v.get("password").and_then(|x| x.as_str()).unwrap_or("");
            if !u.is_empty() && !p.is_empty() {
                return Ok(Creds {
                    username: u.to_string(),
                    password: p.to_string(),
                    source: "json",
                });
            }
        }
    }

    if let Ok(s) = std::fs::read_to_string(paths.dpapi()) {
        let blob: DpapiBlob = serde_json::from_str(&s).map_err(|e| format!("凭据文件损坏：{e}"))?;
        let raw = base64::engine::general_purpose::STANDARD
            .decode(blob.secret.trim())
            .map_err(|e| format!("凭据 base64 解析失败：{e}"))?;
        let plain = dpapi::unprotect(&raw)?;
        let text = String::from_utf8(plain).map_err(|_| "DPAPI 明文不是 UTF-8".to_string())?;
        let mut it = text.splitn(2, '\n');
        let user = it.next().unwrap_or("").to_string();
        let pass = it.next().unwrap_or("").to_string();
        if !user.is_empty() && !pass.is_empty() {
            return Ok(Creds {
                username: user,
                password: pass,
                source: "dpapi",
            });
        }
    }

    Err("找不到凭据：请先在界面里填账号/密码保存，或设置 VPN_USER/VPN_PASS".into())
}

/// 「清除本机账号」：删掉本机保存的凭据（DPAPI 密文）。文件本来就不存在也算成功。
pub fn forget(paths: &Paths) -> Result<(), String> {
    match std::fs::remove_file(paths.dpapi()) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(format!("删除凭据失败：{e}")),
    }
}

pub fn save_dpapi(paths: &Paths, username: &str, password: &str) -> Result<PathBuf, String> {
    std::fs::create_dir_all(paths.secrets()).map_err(|e| format!("创建目录失败：{e}"))?;
    let plain = format!("{username}\n{password}");
    let enc = dpapi::protect(plain.as_bytes())?;
    let blob = DpapiBlob {
        username: username.to_string(),
        secret: base64::engine::general_purpose::STANDARD.encode(enc),
    };
    let file = paths.dpapi();
    let text = serde_json::to_string_pretty(&blob).map_err(|e| e.to_string())?;
    std::fs::write(&file, text).map_err(|e| format!("写入凭据失败：{e}"))?;
    Ok(file)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dpapi_roundtrip() {
        let enc = dpapi::protect(b"example-user\nsecret").unwrap();
        let dec = dpapi::unprotect(&enc).unwrap();
        assert_eq!(dec, b"example-user\nsecret");
    }
}
