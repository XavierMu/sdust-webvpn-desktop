//! 直接操作 Windows「当前用户 → 受信任的根证书颁发机构」证书库。
//!
//! 不再调用 certutil：`certutil -delstore` 是交互式命令，确认对话框依赖控制台窗口，
//! 被 `CREATE_NO_WINDOW` 抑制后删除会静默失败，而退出码又看不出问题
//! （表现为界面显示"已卸载"、实际证书还在）。这里用 crypt32 的原生 API，
//! 结果以返回值/错误码为准。

use std::ffi::c_void;
use windows_sys::Win32::Security::Cryptography::{
    CertAddEncodedCertificateToStore, CertCloseStore, CertDeleteCertificateFromStore,
    CertFindCertificateInStore, CertFreeCertificateContext, CertOpenStore, CERT_FIND_HASH, CERT_STORE_ADD_REPLACE_EXISTING, CERT_STORE_PROV_SYSTEM_W,
    CERT_SYSTEM_STORE_CURRENT_USER, PKCS_7_ASN_ENCODING, X509_ASN_ENCODING,
};

const ENCODING: u32 = X509_ASN_ENCODING | PKCS_7_ASN_ENCODING;

/// 对应 Windows 的 CRYPT_HASH_BLOB（windows-sys 没有导出这个结构体）
#[repr(C)]
struct HashBlob {
    cb_data: u32,
    pb_data: *mut u8,
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

fn open_root() -> Result<*mut c_void, String> {
    let name = wide("Root");
    let store = unsafe {
        CertOpenStore(
            CERT_STORE_PROV_SYSTEM_W,
            0,
            0,
            CERT_SYSTEM_STORE_CURRENT_USER,
            name.as_ptr() as *const c_void,
        )
    };
    if store.is_null() {
        Err(format!(
            "打开根证书库失败：{}",
            std::io::Error::last_os_error()
        ))
    } else {
        Ok(store)
    }
}

fn thumb_bytes(thumb_hex: &str) -> Result<Vec<u8>, String> {
    let clean: String = thumb_hex.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    if clean.is_empty() || clean.len() % 2 != 0 {
        return Err(format!("证书指纹无效：{thumb_hex}"));
    }
    (0..clean.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&clean[i..i + 2], 16).map_err(|e| e.to_string()))
        .collect()
}

fn find_by_thumb(store: *mut c_void, thumb_hex: &str) -> Result<Option<*mut c_void>, String> {
    let mut bytes = thumb_bytes(thumb_hex)?;
    let blob = HashBlob {
        cb_data: bytes.len() as u32,
        pb_data: bytes.as_mut_ptr(),
    };
    let ctx = unsafe {
        CertFindCertificateInStore(
            store,
            ENCODING,
            0,
            CERT_FIND_HASH,
            &blob as *const _ as *const c_void,
            std::ptr::null(),
        )
    };
    let _ = bytes;
    if ctx.is_null() {
        Ok(None)
    } else {
        Ok(Some(ctx as *mut c_void))
    }
}

/// 根证书库里是否已有该指纹（大小写不敏感）
pub fn has_root(thumb_hex: &str) -> bool {
    let Ok(store) = open_root() else {
        return false;
    };
    let found = match find_by_thumb(store, thumb_hex) {
        Ok(Some(ctx)) => {
            unsafe { CertFreeCertificateContext(ctx as *const _) };
            true
        }
        _ => false,
    };
    unsafe { CertCloseStore(store, 0) };
    found
}

/// 安装 DER 证书到根证书库（已存在则覆盖），返回是否新装
pub fn install_root(der: &[u8]) -> Result<(), String> {
    let store = open_root()?;
    let mut ctx: *mut _ = std::ptr::null_mut();
    let ok = unsafe {
        CertAddEncodedCertificateToStore(
            store,
            ENCODING,
            der.as_ptr(),
            der.len() as u32,
            CERT_STORE_ADD_REPLACE_EXISTING,
            &mut ctx,
        )
    };
    let err = std::io::Error::last_os_error();
    if !ctx.is_null() {
        unsafe { CertFreeCertificateContext(ctx as *const _) };
    }
    unsafe { CertCloseStore(store, 0) };
    if ok == 0 {
        return Err(format!("写入根证书库失败：{err}"));
    }
    Ok(())
}

/// 从根证书库删除该指纹的证书，返回删除数量
pub fn delete_root(thumb_hex: &str) -> Result<u32, String> {
    let store = open_root()?;
    let mut removed = 0u32;
    loop {
        let found = find_by_thumb(store, thumb_hex)?;
        match found {
            None => break,
            Some(ctx) => {
                let ok = unsafe { CertDeleteCertificateFromStore(ctx as *const _) };
                if ok == 0 {
                    let err = std::io::Error::last_os_error();
                    unsafe { CertCloseStore(store, 0) };
                    return Err(format!("删除根证书失败：{err}"));
                }
                // CertDeleteCertificateFromStore 成功后自身释放 context
                removed += 1;
                if removed > 8 {
                    break;
                }
            }
        }
    }
    unsafe { CertCloseStore(store, 0) };
    Ok(removed)
}
