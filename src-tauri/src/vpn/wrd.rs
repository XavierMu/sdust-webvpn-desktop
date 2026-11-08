//! 网瑞达 WebVPN 底层编解码。
//!
//! 关键事实（已用学校页面验证）：
//! - 资源地址改写：`/http/<hex>`、`/https/<hex>`，其中
//!   `hex = hex("wrdvpnisthebest!") + hex(AES-128-CFB(目标主机, key=iv="wrdvpnisthebest!"))`
//! - 门户 `/do-login` 密码：AES-128-CFB，key = iv = `wrdvpnisawesome!`，
//!   输出 `hex(iv) + hex(ct)`，截断到 `16 + 明文长度` 字节。

use aes::cipher::{AsyncStreamCipher, KeyIvInit};
use cfb_mode::{Decryptor, Encryptor};

pub const WEBVPN_HOST: &str = "webvpn.sdust.edu.cn";
pub const WEBVPN_ORIGIN: &str = "https://webvpn.sdust.edu.cn";

const LOGIN_KEY: &[u8; 16] = b"wrdvpnisawesome!";
const URL_KEY: &[u8; 16] = b"wrdvpnisthebest!";

fn encrypt_cfb(key: &[u8; 16], data: &[u8]) -> Vec<u8> {
    let mut buf = data.to_vec();
    Encryptor::<aes::Aes128>::new(key.into(), key.into()).encrypt(&mut buf);
    buf
}

fn decrypt_cfb(key: &[u8; 16], data: &[u8]) -> Vec<u8> {
    let mut buf = data.to_vec();
    Decryptor::<aes::Aes128>::new(key.into(), key.into()).decrypt(&mut buf);
    buf
}

/// 目标主机 -> `/http/<hex>` 里的 hex
pub fn encode_host(host: &str) -> String {
    let ct = encrypt_cfb(URL_KEY, host.as_bytes());
    let mut out = URL_KEY.to_vec();
    out.extend_from_slice(&ct);
    hex::encode(out)
}

/// hex -> 目标主机
pub fn decode_host(encoded: &str) -> Result<String, String> {
    let buf = hex::decode(encoded).map_err(|e| format!("hex 解析失败：{e}"))?;
    if buf.len() < 17 {
        return Err("hex 长度不足".into());
    }
    let pt = decrypt_cfb(URL_KEY, &buf[16..]);
    String::from_utf8(pt).map_err(|e| format!("主机名不是 UTF-8：{e}"))
}

/// 登录表单 password 加密（与页面 encrypt() 逐字节一致）
pub fn encrypt_password(text: &str) -> String {
    let n = text.chars().count();
    let mut padded = text.to_string();
    if n % 16 != 0 {
        padded.push_str(&"0".repeat(16 - n % 16));
    }
    let ct = encrypt_cfb(LOGIN_KEY, padded.as_bytes());
    let mut out = LOGIN_KEY.to_vec();
    out.extend_from_slice(&ct);
    out.truncate(16 + n);
    hex::encode(out)
}

/// `/http/<hex>/path?query`
pub fn http_path(host: &str, path: &str, scheme: &str) -> String {
    let suffix = if path.starts_with('/') {
        path.to_string()
    } else {
        format!("/{path}")
    };
    format!("/{scheme}/{}{}", encode_host(host), suffix)
}

/// 默认请求头（与浏览器一致，WebVPN 对此敏感）
pub fn default_headers() -> Vec<(&'static str, &'static str)> {
    vec![
        (
            "User-Agent",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
        ),
        (
            "Accept",
            "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        ),
        ("Accept-Language", "zh-CN,zh;q=0.9,en;q=0.8"),
        ("Accept-Encoding", "identity"),
        ("Connection", "keep-alive"),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_host_like_the_portal() {
        assert_eq!(
            encode_host("my.sdust.edu.cn"),
            "77726476706e69737468656265737421fdee0f8f23257b44300d8db9d6562d"
        );
        assert_eq!(
            encode_host("172.18.129.250:8080"),
            "77726476706e69737468656265737421a1a013d2766826012c51c7fecd05796da9f508"
        );
    }

    #[test]
    fn decodes_host() {
        assert_eq!(
            decode_host("77726476706e69737468656265737421fdee0f8f23257b44300d8db9d6562d").unwrap(),
            "my.sdust.edu.cn"
        );
        assert!(decode_host("abcd").is_err());
    }

    #[test]
    fn encrypts_password_like_the_page() {
        // 固定向量：明文 "example-pass" 与页面 encrypt() 逐字节一致
        assert_eq!(
            encrypt_password("example-pass"),
            "77726476706e6973617765736f6d6521e370da6d8b578b67c0d56b30"
        );
    }

    #[test]
    fn builds_webvpn_path() {
        assert_eq!(
            http_path("my.sdust.edu.cn", "/cas/login?service=x", "https"),
            "/https/77726476706e69737468656265737421fdee0f8f23257b44300d8db9d6562d/cas/login?service=x"
        );
    }
}
