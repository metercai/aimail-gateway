//! 库内凭据材料的"密封"(at-rest sealing) —— 2026-09-22 加固
//!
//! 背景(实测): 请求签名的 HMAC 密钥 = DB 里的 `api_keys.key_hash` 本身
//! (`sig = HMAC-SHA256(key = key_hash, msg = signature_base)`)。于是任何拿到 DB 读权限的人
//! (备份/只读副本/逻辑导出/SQL 注入)无需爆破即可冒充任意 key 签名。
//!
//! 本模块把"库里存的"变成"必须有平台 admin-key 才能用":
//!   seal_key      = HMAC-SHA256(key = admin_key, msg = "aimail-gateway:key-seal:v1")
//!   stored(key)   = "v1:" + base64( nonce(12) || AES-256-GCM(seal_key, sha256(raw_key)) )
//!   legacy        = 不以 "v1:" 开头 ⇒ 视作历史明文哈希, 原样使用
//!
//! 关键设计:
//!  * **线协议不变** ⇒ 客户端零改动: 客户端离线算的仍是 sha256(raw_key), 只是服务端在验签前
//!    先把库里的密文解封回 sha256(raw_key)。
//!  * **双形态共存** ⇒ 迁移可随时暂停/回滚, 不存在"半迁移即全站 401"的窗口。
//!  * **派生沿用既有模式** (同 `core/server.rs` 的 DB 加密键派生): 一个根秘密 + 域分离常量,
//!    不引入任何需要独立生成/备份/轮换的新秘密。标签与既有常量不同, 严禁跨用途复用。
//!  * **fail closed**: 启动时若库内已有密封材料而 admin-key 不可得 ⇒ 拒绝提供服务(见 `ensure_loaded`)。

use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::sync::OnceLock;

/// 域分离标签。必须与既有常量不同(现有: `aimail-gateway:code:encryption:v1`、`aimail-gateway:db:encryption:v1`)。
pub const SEAL_CONTEXT: &[u8] = b"aimail-gateway:key-seal:v1";

/// 密封值的版本前缀。
pub const SEAL_PREFIX: &str = "v1:";

const NONCE_LEN: usize = 12;

/// 从平台 admin-key 派生 32 字节密封子密钥(与 DB 加密键同构的 HMAC-SHA256 域分离派生)。
pub fn derive_seal_key(admin_key: &str) -> [u8; 32] {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(admin_key.as_bytes())
        .expect("HMAC accepts any key len");
    mac.update(SEAL_CONTEXT);
    let out = mac.finalize().into_bytes();
    let mut key = [0u8; 32];
    key.copy_from_slice(&out);
    key
}

/// 是否已密封(判断存储形态, 不涉及密钥)。
pub fn is_sealed(stored: &str) -> bool {
    stored.starts_with(SEAL_PREFIX)
}

/// 确定性 nonce = HMAC-SHA256(seal_key, plaintext)[..12]。
///
/// 为什么确定性而非随机: 库内存在 `WHERE key_hash = ?` 的**等值查找**(`verify_api_key`), 随机 nonce
/// 会让同一明文每次得到不同密文 ⇒ 查找失效。确定性密封保留等值语义(同一明文恒得同一密文),
/// 而无密钥者无法预测 nonce(GCM 的 (key, nonce) 组合不会重复使用 ⇒ 安全)。
/// 明文均为 256 位随机哈希(sha256) ⇒ 不存在"低熵明文被离线暴破"的面。
fn derive_nonce(seal_key: &[u8; 32], plaintext: &str) -> [u8; NONCE_LEN] {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(seal_key).expect("HMAC accepts any key len");
    mac.update(plaintext.as_bytes());
    let out = mac.finalize().into_bytes();
    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(&out[..NONCE_LEN]);
    nonce
}

/// 密封: 明文(sha256(raw_key) 的 hex) → `v1:<base64(nonce||ciphertext+tag)>`(确定性)。
pub fn seal(seal_key: &[u8; 32], plaintext: &str) -> Result<String, String> {
    let cipher = Aes256Gcm::new_from_slice(seal_key).map_err(|e| format!("seal key: {e}"))?;
    let nonce = derive_nonce(seal_key, plaintext);
    let ct = cipher
        .encrypt(Nonce::from_slice(&nonce), plaintext.as_bytes())
        .map_err(|e| format!("seal encrypt: {e}"))?;
    let mut blob = Vec::with_capacity(NONCE_LEN + ct.len());
    blob.extend_from_slice(&nonce);
    blob.extend_from_slice(&ct);
    Ok(format!("{SEAL_PREFIX}{}", B64.encode(blob)))
}

/// 解封: `v1:<base64>` → 明文。
pub fn open(seal_key: &[u8; 32], stored: &str) -> Result<String, String> {
    let body = stored
        .strip_prefix(SEAL_PREFIX)
        .ok_or_else(|| "not a sealed value".to_string())?;
    let blob = B64.decode(body).map_err(|e| format!("seal base64: {e}"))?;
    if blob.len() <= NONCE_LEN {
        return Err("sealed value too short".to_string());
    }
    let (nonce, ct) = blob.split_at(NONCE_LEN);
    let cipher = Aes256Gcm::new_from_slice(seal_key).map_err(|e| format!("seal key: {e}"))?;
    let pt = cipher
        .decrypt(Nonce::from_slice(nonce), ct)
        .map_err(|_| "seal open failed (wrong admin key or tampered ciphertext)".to_string())?;
    String::from_utf8(pt).map_err(|e| format!("seal plaintext utf8: {e}"))
}

/// 取"可用于验签的材料": 密封值 ⇒ 解封; 历史明文 ⇒ 原样返回。
///
/// `seal_key = None`(admin-key 不可得)时, 遇到密封值一律失败 —— 绝不静默当作明文使用。
pub fn signing_material(seal_key: Option<&[u8; 32]>, stored: &str) -> Result<String, String> {
    if !is_sealed(stored) {
        return Ok(stored.to_string());
    }
    let key = seal_key.ok_or_else(|| {
        "credential is sealed but no platform admin key is available to open it".to_string()
    })?;
    open(key, stored)
}

// ── 进程级装载(单实例服务: 启动时定一次) ──────────────────────────────
static SEAL: OnceLock<[u8; 32]> = OnceLock::new();

/// 启动时装载密封子密钥(重复调用无害, 以第一次为准)。
pub fn init(admin_key: &str) {
    if admin_key.trim().is_empty() {
        return;
    }
    let _ = SEAL.set(derive_seal_key(admin_key.trim()));
}

/// 密封是否已装载。
pub fn loaded() -> bool {
    SEAL.get().is_some()
}

/// 进程级密封子密钥引用。
pub fn key_ref() -> Option<&'static [u8; 32]> {
    SEAL.get()
}

/// 用进程级密钥密封(未装载时返回 None, 调用方决定降级策略)。
pub fn seal_if_loaded(plaintext: &str) -> Option<String> {
    SEAL.get().and_then(|k| seal(k, plaintext).ok())
}

/// 落库用: 有 admin-key 时密封, 否则保持历史明文形态并**告警**(降级模式, 生产必须有 admin-key)。
pub fn store_hash(raw_hash: &str) -> String {
    match seal_if_loaded(raw_hash) {
        Some(v) => v,
        None => {
            tracing::warn!(
                operation = "credential_unsealed",
                "platform admin key unavailable — storing credential hash unsealed (degraded mode)"
            );
            raw_hash.to_string()
        }
    }
}

/// 用进程级密钥解封(未装载/解封失败 ⇒ Err)。
pub fn signing_material_env(stored: &str) -> Result<String, String> {
    signing_material(SEAL.get(), stored)
}

/// fail-closed 判定: 库里已有密封材料却没有 admin-key 时, 服务不得启动。
pub fn ensure_loaded(sealed_rows_exist: bool) -> Result<(), String> {
    if sealed_rows_exist && SEAL.get().is_none() {
        return Err(
            "database contains sealed credential material but the platform admin key is unavailable \
             (check the admin key file) — refusing to start rather than failing every signature"
                .to_string(),
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn k() -> [u8; 32] {
        derive_seal_key("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
    }

    #[test]
    fn seal_roundtrip() {
        let key = k();
        let plain = "8f14e45fceea167a5a36dedd4bea2543"; // 形如 sha256 hex
        let sealed = seal(&key, plain).unwrap();
        assert!(is_sealed(&sealed));
        assert_ne!(sealed.contains(plain), true, "密文不得含明文");
        assert_eq!(open(&key, &sealed).unwrap(), plain);
    }

    #[test]
    fn seal_is_deterministic_for_lookup_semantics() {
        // 必须确定性: 库内有 WHERE key_hash = ? 的等值查找(verify_api_key)
        let key = k();
        assert_eq!(seal(&key, "same").unwrap(), seal(&key, "same").unwrap());
        // 不同明文必须得到不同密文/不同 nonce(无重复 (key,nonce) 组合)
        assert_ne!(seal(&key, "a").unwrap(), seal(&key, "b").unwrap());
    }

    #[test]
    fn wrong_key_fails_closed() {
        let sealed = seal(&k(), "secret-hash").unwrap();
        let other =
            derive_seal_key("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        assert!(open(&other, &sealed).is_err(), "换 admin-key 必须解不开");
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let key = k();
        let sealed = seal(&key, "secret-hash").unwrap();
        let mut blob = B64
            .decode(sealed.strip_prefix(SEAL_PREFIX).unwrap())
            .unwrap();
        let last = blob.len() - 1;
        blob[last] ^= 0x01;
        let tampered = format!("{SEAL_PREFIX}{}", B64.encode(blob));
        assert!(open(&key, &tampered).is_err(), "GCM 认证标签必须拒绝篡改");
    }

    #[test]
    fn legacy_plaintext_is_accepted() {
        // 历史形态: sha256(raw) 明文落库 ⇒ 原样可用(迁移可暂停/回滚)
        let legacy = "aabbccddeeff00112233445566778899";
        assert_eq!(signing_material(None, legacy).unwrap(), legacy);
        assert_eq!(signing_material(Some(&k()), legacy).unwrap(), legacy);
    }

    #[test]
    fn sealed_without_admin_key_is_refused() {
        let sealed = seal(&k(), "legacy").unwrap();
        let err = signing_material(None, &sealed).unwrap_err();
        assert!(
            err.contains("no platform admin key"),
            "必须显式报错而不是当作明文: {err}"
        );
    }

    #[test]
    fn derived_labels_are_domain_separated() {
        let admin = "some-admin-key";
        let seal_key = derive_seal_key(admin);
        // 与既有用途(DB 加密/code 加密)必须不同: 同一 IKM 不同标签 ⇒ 不同子密钥
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(admin.as_bytes()).unwrap();
        mac.update(b"aimail-gateway:db:encryption:v1");
        let db_key = mac.finalize().into_bytes();
        assert_ne!(&seal_key[..], &db_key[..], "seal 子密钥不得等于 DB 加密键");
    }

    #[test]
    fn ensure_loaded_fails_closed() {
        assert!(ensure_loaded(false).is_ok(), "无密封材料 ⇒ 无所谓");
        // 注意: 本进程若已被其它测试 init 过, loaded() 为真 —— 只断言"缺 key 且有密封材料"这一分支
        if !loaded() {
            assert!(ensure_loaded(true).is_err());
        }
    }
}
