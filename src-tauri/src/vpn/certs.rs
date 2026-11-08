//! 本地 CA：自签根证书 + 按域名即时签发叶子证书（rustls 用）。

use std::collections::HashMap;
use std::io::Cursor;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use rcgen::{
    BasicConstraints, Certificate, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa,
    KeyPair, KeyUsagePurpose,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::ServerConfig;
use time::{Duration, OffsetDateTime};

pub const CA_CN: &str = "SDUST WebVPN Local CA";

pub struct Ca {
    pub dir: PathBuf,
    key: KeyPair,
    issuer: Certificate,
    ca_pem: String,
    cache: Mutex<HashMap<String, Arc<ServerConfig>>>,
}

fn key_usages_ca() -> Vec<KeyUsagePurpose> {
    vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
        KeyUsagePurpose::DigitalSignature,
    ]
}

fn ca_params() -> CertificateParams {
    let mut p = CertificateParams::default();
    p.distinguished_name = rcgen::DistinguishedName::new();
    p.distinguished_name.push(DnType::CommonName, CA_CN);
    p.distinguished_name.push(DnType::OrganizationName, "SDUST WebVPN");
    p.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    p.key_usages = key_usages_ca();
    p.not_before = OffsetDateTime::now_utc() - Duration::days(1);
    p.not_after = OffsetDateTime::now_utc() + Duration::days(3650);
    p
}

impl Ca {
    pub fn load_or_create(dir: PathBuf) -> Result<Self, String> {
        std::fs::create_dir_all(&dir).map_err(|e| format!("创建证书目录失败：{e}"))?;
        let cert_file = dir.join("ca.crt");
        let key_file = dir.join("ca.key");

        if let (Ok(ca_pem), Ok(key_pem)) = (
            std::fs::read_to_string(&cert_file),
            std::fs::read_to_string(&key_file),
        ) {
            if let Ok(key) = KeyPair::from_pem(&key_pem) {
                // 用同一把私钥重建 issuer（只需 DN / 密钥标识，签名用 ca.key）
                if let Ok(issuer) = ca_params().self_signed(&key) {
                    return Ok(Self {
                        dir,
                        key,
                        issuer,
                        ca_pem,
                        cache: Mutex::new(HashMap::new()),
                    });
                }
            }
        }

        let key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)
            .map_err(|e| format!("生成 CA 私钥失败：{e}"))?;
        let issuer = ca_params()
            .self_signed(&key)
            .map_err(|e| format!("生成 CA 证书失败：{e}"))?;
        let ca_pem = issuer.pem();
        std::fs::write(&cert_file, &ca_pem).map_err(|e| format!("写入 CA 证书失败：{e}"))?;
        std::fs::write(&key_file, key.serialize_pem()).map_err(|e| format!("写入 CA 私钥失败：{e}"))?;
        Ok(Self {
            dir,
            key,
            issuer,
            ca_pem,
            cache: Mutex::new(HashMap::new()),
        })
    }

    pub fn cert_file(&self) -> PathBuf {
        self.dir.join("ca.crt")
    }

    pub fn ca_pem(&self) -> &str {
        &self.ca_pem
    }

    fn leaf_pem(&self, host: &str) -> Result<(String, String), String> {
        let key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)
            .map_err(|e| format!("生成叶子私钥失败：{e}"))?;
        let mut p = CertificateParams::new(vec![host.to_string()])
            .map_err(|e| format!("域名不合法（{host}）：{e}"))?;
        p.distinguished_name = rcgen::DistinguishedName::new();
        p.distinguished_name.push(DnType::CommonName, host);
        p.is_ca = IsCa::NoCa;
        p.key_usages = vec![KeyUsagePurpose::DigitalSignature, KeyUsagePurpose::KeyEncipherment];
        p.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        p.use_authority_key_identifier_extension = true;
        p.not_before = OffsetDateTime::now_utc() - Duration::days(1);
        p.not_after = OffsetDateTime::now_utc() + Duration::days(825);
        let cert = p
            .signed_by(&key, &self.issuer, &self.key)
            .map_err(|e| format!("签发 {host} 证书失败：{e}"))?;
        Ok((cert.pem(), key.serialize_pem()))
    }

    /// 给某个域名准备 rustls 服务端配置（带内存缓存）
    pub fn server_config(&self, host: &str) -> Result<Arc<ServerConfig>, String> {
        if let Some(cfg) = self.cache.lock().unwrap().get(host) {
            return Ok(cfg.clone());
        }
        let (cert_pem, key_pem) = self.leaf_pem(host)?;
        let certs: Vec<CertificateDer<'static>> =
            rustls_pemfile::certs(&mut Cursor::new(cert_pem.as_bytes()))
                .collect::<Result<_, _>>()
                .map_err(|e| format!("解析证书失败：{e}"))?;
        let key: PrivateKeyDer<'static> = rustls_pemfile::private_key(&mut Cursor::new(
            key_pem.as_bytes(),
        ))
        .map_err(|e| format!("解析私钥失败：{e}"))?
        .ok_or_else(|| "证书缺少私钥".to_string())?;

        let mut cfg = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .map_err(|e| format!("构建 TLS 配置失败：{e}"))?;
        cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
        let cfg = Arc::new(cfg);
        self.cache
            .lock()
            .unwrap()
            .insert(host.to_string(), cfg.clone());
        Ok(cfg)
    }

    /// 当前 CA 的 SHA-1 指纹（大写 hex），用于查注册表判断是否已安装
    pub fn thumbprint(&self) -> Option<String> {
        use sha1::{Digest, Sha1};
        let der = pem_to_der(&self.ca_pem)?;
        let mut h = Sha1::new();
        h.update(&der);
        Some(hex::encode(h.finalize()).to_uppercase())
    }
}

fn pem_to_der(pem: &str) -> Option<Vec<u8>> {
    let start = pem.find("-----BEGIN CERTIFICATE-----")?;
    let rest = &pem[start..];
    let body_start = rest.find('\n')? + 1;
    let body_end = rest.find("-----END CERTIFICATE-----")?;
    let b64: String = rest[body_start..body_end]
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.decode(b64).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn issues_leaf_for_host() {
        let dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("target")
            .join(format!("ca-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let ca = Ca::load_or_create(dir.clone()).unwrap();
        assert!(ca.ca_pem().contains("BEGIN CERTIFICATE"));
        assert!(ca.thumbprint().is_some());
        let cfg = ca.server_config("my.sdust.edu.cn").unwrap();
        assert_eq!(cfg.alpn_protocols[0], b"http/1.1".to_vec());
        // 再加载一次走磁盘分支
        let ca2 = Ca::load_or_create(dir.clone()).unwrap();
        assert!(ca2.server_config("172.18.129.250").is_ok());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
