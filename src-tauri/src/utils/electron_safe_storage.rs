//! Electron `safeStorage` 同源加密 / 解密工具（Windows 实现）。
//!
//! Windsurf / VSCode 等 Electron 应用把敏感的会话凭据存放在 `state.vscdb` 的
//! `secret://...` key 下，value 是用 Electron `safeStorage` API 加密后的
//! `Buffer { type, data: number[] }` JSON。要在外部进程写回这种加密 blob，
//! 必须复刻 Chromium 的 `os_crypt` 实现：
//!
//! - **Windows**：从 `<userData>/Local State` JSON 中读取 `os_crypt.encrypted_key`，
//!   base64 解码后跳过前 5 字节固定串 `"DPAPI"`，剩下的字节调 Win32
//!   `CryptUnprotectData` 解出 32 字节 master key，再用 AES-256-GCM 加密，
//!   输出格式 = `b"v10"` + 12 字节随机 nonce + ciphertext+tag。
//!
//! 参考实现：jlcodes99/cockpit-tools 的
//! `crates/cockpit-core/src/modules/windsurf_instance.rs`。
//!
//! macOS / Linux 路径暂未实现：本项目目前只发布 Windows x64 安装包。

use crate::utils::{AppError, AppResult};
use base64::{engine::general_purpose, Engine as _};
use serde_json::Value;
use std::path::Path;

/// Electron safeStorage 在 Windows 上使用的密文前缀。
pub const V10_PREFIX: &[u8] = b"v10";

/// 调用 Win32 `CryptUnprotectData` 解密一段 DPAPI 加密的字节序列。
///
/// 仅当当前用户上下文与加密时一致时能解密成功（DPAPI 把用户登录凭据当成 KEK）。
#[cfg(target_os = "windows")]
fn dpapi_decrypt(encrypted: &[u8]) -> AppResult<Vec<u8>> {
    use std::ptr;
    use winapi::shared::minwindef::DWORD;
    use winapi::um::dpapi::CryptUnprotectData;
    use winapi::um::winbase::LocalFree;
    use winapi::um::wincrypt::DATA_BLOB;

    let mut input = DATA_BLOB {
        cbData: encrypted.len() as DWORD,
        pbData: encrypted.as_ptr() as *mut u8,
    };
    let mut output = DATA_BLOB {
        cbData: 0,
        pbData: ptr::null_mut(),
    };

    let ok = unsafe {
        CryptUnprotectData(
            &mut input,
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            0,
            &mut output,
        )
    };
    if ok == 0 {
        return Err(AppError::FileOperation(
            "DPAPI CryptUnprotectData 调用失败：当前用户无法解密 Local State 主密钥".to_string(),
        ));
    }

    let result = unsafe {
        std::slice::from_raw_parts(output.pbData, output.cbData as usize).to_vec()
    };
    unsafe {
        LocalFree(output.pbData as *mut _);
    }
    Ok(result)
}

/// 读取 `<userData>/Local State` 并恢复 Electron os_crypt 的 32 字节主密钥。
///
/// `data_root` 是 Windsurf 的 userData 目录，例如
/// `%APPDATA%\Windsurf` 或 `%APPDATA%\Windsurf - Next`。
#[cfg(target_os = "windows")]
pub fn get_windows_master_key(data_root: &Path) -> AppResult<Vec<u8>> {
    let path = data_root.join("Local State");
    if !path.exists() {
        return Err(AppError::FileOperation(format!(
            "Windsurf Local State 不存在: {}",
            path.display()
        )));
    }

    let content = std::fs::read_to_string(&path)
        .map_err(|e| AppError::FileOperation(format!("读取 Local State 失败: {}", e)))?;
    let json: Value = serde_json::from_str(&content)
        .map_err(|e| AppError::FileOperation(format!("解析 Local State JSON 失败: {}", e)))?;

    let encrypted_key_b64 = json["os_crypt"]["encrypted_key"]
        .as_str()
        .ok_or_else(|| AppError::FileOperation("Local State 缺少 os_crypt.encrypted_key".to_string()))?;
    let encrypted_key_bytes = general_purpose::STANDARD
        .decode(encrypted_key_b64)
        .map_err(|e| AppError::FileOperation(format!("base64 解码 encrypted_key 失败: {}", e)))?;

    if encrypted_key_bytes.len() < 6 {
        return Err(AppError::FileOperation(
            "encrypted_key 长度异常（少于 6 字节）".to_string(),
        ));
    }
    if &encrypted_key_bytes[..5] != b"DPAPI" {
        return Err(AppError::FileOperation(
            "encrypted_key 前缀不是 \"DPAPI\"，可能 Windsurf 已切换到不同的加密方案".to_string(),
        ));
    }

    let key = dpapi_decrypt(&encrypted_key_bytes[5..])?;
    if key.len() != 32 {
        return Err(AppError::FileOperation(format!(
            "DPAPI 解密后的 AES key 长度异常: {} bytes（期望 32）",
            key.len()
        )));
    }
    Ok(key)
}

/// 用恢复出的 master key 做 AES-256-GCM 加密，返回 Electron safeStorage v10 格式：
/// `b"v10"` + 12 字节 nonce + ciphertext+auth_tag。
#[cfg(target_os = "windows")]
pub fn encrypt_v10(master_key: &[u8], plaintext: &[u8]) -> AppResult<Vec<u8>> {
    use aes_gcm::aead::generic_array::GenericArray;
    use aes_gcm::aead::{Aead, AeadCore, OsRng};
    use aes_gcm::{Aes256Gcm, KeyInit};

    if master_key.len() != 32 {
        return Err(AppError::FileOperation(format!(
            "AES-256 master key 长度必须为 32: 实际 {}",
            master_key.len()
        )));
    }

    let cipher = Aes256Gcm::new(GenericArray::from_slice(master_key));
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let ciphertext = cipher
        .encrypt(&nonce, plaintext)
        .map_err(|e| AppError::FileOperation(format!("AES-GCM 加密失败: {}", e)))?;

    let mut result = Vec::with_capacity(V10_PREFIX.len() + 12 + ciphertext.len());
    result.extend_from_slice(V10_PREFIX);
    result.extend_from_slice(nonce.as_slice());
    result.extend_from_slice(&ciphertext);
    Ok(result)
}

/// 把加密后的字节序列编码为 Electron safeStorage 在 SQLite 里实际存储的 JSON：
/// `{"type": "Buffer", "data": [<bytes>]}`。
pub fn encode_buffer_json(encrypted: &[u8]) -> String {
    let arr: Vec<u8> = encrypted.to_vec();
    serde_json::json!({
        "type": "Buffer",
        "data": arr,
    })
    .to_string()
}

/// 一站式：读 Local State → 取主密钥 → AES-256-GCM 加密 → 编成 Buffer JSON。
#[cfg(target_os = "windows")]
pub fn encrypt_to_buffer_json(data_root: &Path, plaintext: &[u8]) -> AppResult<String> {
    let key = get_windows_master_key(data_root)?;
    let encrypted = encrypt_v10(&key, plaintext)?;
    Ok(encode_buffer_json(&encrypted))
}

// ---- 非 Windows 平台占位实现：本项目目前只支持 Windows。----
#[cfg(not(target_os = "windows"))]
pub fn get_windows_master_key(_data_root: &Path) -> AppResult<Vec<u8>> {
    Err(AppError::FileOperation(
        "Electron safeStorage 注入当前仅在 Windows 上实现".to_string(),
    ))
}

#[cfg(not(target_os = "windows"))]
pub fn encrypt_v10(_master_key: &[u8], _plaintext: &[u8]) -> AppResult<Vec<u8>> {
    Err(AppError::FileOperation(
        "Electron safeStorage 注入当前仅在 Windows 上实现".to_string(),
    ))
}

#[cfg(not(target_os = "windows"))]
pub fn encrypt_to_buffer_json(_data_root: &Path, _plaintext: &[u8]) -> AppResult<String> {
    Err(AppError::FileOperation(
        "Electron safeStorage 注入当前仅在 Windows 上实现".to_string(),
    ))
}
