//! "Sealing" (at-rest sealing) of stored credential material - 2026-09-22 hardening
//!
//! Background (observed in production): the HMAC key for request signatures = the DB's `api_keys.key_hash` itself
//! (`sig = HMAC-SHA256(key = key_hash, msg = signature_base)`). So anyone with DB read access
//! (backup/read-only replica/logical export/SQL injection) can impersonate any key's signatures without brute force.
//!
//! This module turns "what is stored in the DB" into "usable only with the platform admin-key":
//!   seal_key      = HMAC-SHA256(key = admin_key, msg = "aimail-gateway:key-seal:v1")
//!   stored(key)   = "v1:" + base64( nonce(12) || AES-256-GCM(seal_key, sha256(raw_key)) )
//!   legacy        = not prefixed with "v1:" => treated as a historical plaintext hash, used as-is
//!
//! Key design points:
//!  * **Wire protocol unchanged** => zero client changes: the client still computes sha256(raw_key) offline; the server, before verifying a signature,
//!    first unseals the stored ciphertext back to sha256(raw_key).
//!  * **Dual form coexistence** => the migration can be paused/rolled back anytime; there is no "half-migrated and the whole site returns 401" window.
//!  * **Derivation follows the existing pattern** (same as the DB encryption key in `core/server.rs`): one root secret + a domain-separation constant,
//!    introducing no new secret that needs independent generation/backup/rotation. The label differs from existing constants; cross-purpose reuse is forbidden.
//!  * **fail closed**: at startup, if the DB already holds sealed material but the admin-key is unavailable => refuse to serve (see `ensure_loaded`).

use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::sync::OnceLock;

/// Domain-separation label. Must differ from existing constants (current: `aimail-gateway:code:encryption:v1`, `aimail-gateway:db:encryption:v1`).
pub const SEAL_CONTEXT: &[u8] = b"aimail-gateway:key-seal:v1";

/// Version prefix of a sealed value.
pub const SEAL_PREFIX: &str = "v1:";

const NONCE_LEN: usize = 12;

/// Derive a 32-byte sealing subkey from the platform admin-key (HMAC-SHA256 domain-separated derivation, same construction as the DB encryption key).
pub fn derive_seal_key(admin_key: &str) -> [u8; 32] {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(admin_key.as_bytes())
        .expect("HMAC accepts any key len");
    mac.update(SEAL_CONTEXT);
    let out = mac.finalize().into_bytes();
    let mut key = [0u8; 32];
    key.copy_from_slice(&out);
    key
}

/// Whether a value is already sealed (storage-form check; does not involve keys).
pub fn is_sealed(stored: &str) -> bool {
    stored.starts_with(SEAL_PREFIX)
}

/// Deterministic nonce = HMAC-SHA256(seal_key, plaintext)[..12].
///
/// Why deterministic instead of random: the DB performs an **equality lookup** `WHERE key_hash = ?` (`verify_api_key`); a random nonce
/// would give the same plaintext a different ciphertext each time => the lookup breaks. Deterministic sealing preserves equality semantics (same plaintext always yields the same ciphertext),
/// while someone without the key cannot predict the nonce (GCM (key, nonce) pairs are never reused => safe).
/// All plaintexts are 256-bit random hashes (sha256) => there is no "low-entropy plaintext brute-forced offline" surface.
fn derive_nonce(seal_key: &[u8; 32], plaintext: &str) -> [u8; NONCE_LEN] {
    let mut mac =
        <Hmac<Sha256> as Mac>::new_from_slice(seal_key).expect("HMAC accepts any key len");
    mac.update(plaintext.as_bytes());
    let out = mac.finalize().into_bytes();
    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(&out[..NONCE_LEN]);
    nonce
}

/// Seal: plaintext (hex of sha256(raw_key)) -> `v1:<base64(nonce||ciphertext+tag)>` (deterministic).
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

/// Unseal: `v1:<base64>` -> plaintext.
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

/// Get "material usable for signature verification": sealed value => unseal; historical plaintext => return as-is.
///
/// When `seal_key = None` (admin-key unavailable), any sealed value fails outright - never silently used as plaintext.
pub fn signing_material(seal_key: Option<&[u8; 32]>, stored: &str) -> Result<String, String> {
    if !is_sealed(stored) {
        return Ok(stored.to_string());
    }
    let key = seal_key.ok_or_else(|| {
        "credential is sealed but no platform admin key is available to open it".to_string()
    })?;
    open(key, stored)
}

// ── process-level loading (single-instance service: decided once at startup) ──────────────────────
static SEAL: OnceLock<[u8; 32]> = OnceLock::new();

/// Load the sealing subkey at startup (repeat calls are harmless; the first one wins).
pub fn init(admin_key: &str) {
    if admin_key.trim().is_empty() {
        return;
    }
    let _ = SEAL.set(derive_seal_key(admin_key.trim()));
}

/// Whether the sealing subkey is loaded.
pub fn loaded() -> bool {
    SEAL.get().is_some()
}

/// Process-level reference to the sealing subkey.
pub fn key_ref() -> Option<&'static [u8; 32]> {
    SEAL.get()
}

/// Seal with the process-level key (returns None when not loaded; the caller decides the fallback strategy).
pub fn seal_if_loaded(plaintext: &str) -> Option<String> {
    SEAL.get().and_then(|k| seal(k, plaintext).ok())
}

/// For DB writes: seal when the admin-key exists, otherwise keep the historical plaintext form and **warn** (degraded mode; production must have an admin-key).
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

/// Unseal with the process-level key (not loaded / unseal failure => Err).
pub fn signing_material_env(stored: &str) -> Result<String, String> {
    signing_material(SEAL.get(), stored)
}

/// Fail-closed check: when the DB holds sealed material but there is no admin-key, the service must not start.
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
        let plain = "8f14e45fceea167a5a36dedd4bea2543"; // looks like sha256 hex
        let sealed = seal(&key, plain).unwrap();
        assert!(is_sealed(&sealed));
        assert!(!sealed.contains(plain), "the ciphertext must not contain the plaintext");
        assert_eq!(open(&key, &sealed).unwrap(), plain);
    }

    #[test]
    fn seal_is_deterministic_for_lookup_semantics() {
        // must be deterministic: the DB has a WHERE key_hash = ? equality lookup (verify_api_key)
        let key = k();
        assert_eq!(seal(&key, "same").unwrap(), seal(&key, "same").unwrap());
        // different plaintexts must yield different ciphertexts/nonces (no repeated (key,nonce) pairs)
        assert_ne!(seal(&key, "a").unwrap(), seal(&key, "b").unwrap());
    }

    #[test]
    fn wrong_key_fails_closed() {
        let sealed = seal(&k(), "secret-hash").unwrap();
        let other =
            derive_seal_key("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        assert!(open(&other, &sealed).is_err(), "a different admin-key must not be able to unseal");
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
        assert!(open(&key, &tampered).is_err(), "the GCM auth tag must reject tampering");
    }

    #[test]
    fn legacy_plaintext_is_accepted() {
        // historical form: sha256(raw) stored in plaintext => usable as-is (the migration can be paused/rolled back)
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
            "must fail explicitly instead of being treated as plaintext: {err}"
        );
    }

    #[test]
    fn derived_labels_are_domain_separated() {
        let admin = "some-admin-key";
        let seal_key = derive_seal_key(admin);
        // must differ from existing purposes (DB encryption / code encryption): same IKM, different label => different subkey
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(admin.as_bytes()).unwrap();
        mac.update(b"aimail-gateway:db:encryption:v1");
        let db_key = mac.finalize().into_bytes();
        assert_ne!(&seal_key[..], &db_key[..], "the seal subkey must not equal the DB encryption key");
    }

    #[test]
    fn ensure_loaded_fails_closed() {
        assert!(ensure_loaded(false).is_ok(), "no sealed material => nothing to check");
        // Note: if this process was already initialized by another test, loaded() is true - only assert the "missing key plus sealed material" branch
        if !loaded() {
            assert!(ensure_loaded(true).is_err());
        }
    }
}
