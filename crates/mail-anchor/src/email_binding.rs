//! `EmailBinding` 锚定载荷（协议 §7.1）。
//!
//! ```text
//! payload_hash = "blake2b:" + BLAKE2b-256( "EmailBinding-v1\n{did}\n{email}\n{issuer_did}\n" )
//! ```
//!
//! 为什么是"事实锚"而不是把 `EmailBindingVC` 锚成 `IssuedVc`：接收方手里只有邮件
//! （`did` 来自头、`email` 来自 `From`、`issuer_did` 来自锚定记录），**没有那张 VC**，
//! 所以它必须能用这三样东西独立重建哈希。`IssuedVc` 的 preimage 是 VC 全文，
//! 没有 VC 就无法重算——这是"能不能"的问题，不是取向问题。

use crate::{blake2b256_hex, check_field, AnchorError, ANCHOR_HASH_PREFIX, EMAIL_BINDING_TAG};

/// 构造 `EmailBinding` 的行式 preimage（四行，每行尾随 `\n`，含末行）。
///
/// 字段做最小规范化：`email` 转小写（地址大小写不敏感），`did` 与 `issuer_did` 原样。
pub fn preimage(did: &str, email: &str, issuer_did: &str) -> Result<Vec<u8>, AnchorError> {
    let email = email.trim().to_lowercase();
    check_field("did", did)?;
    check_field("email", &email)?;
    check_field("issuer_did", issuer_did)?;

    Ok(format!("{EMAIL_BINDING_TAG}\n{did}\n{email}\n{issuer_did}\n").into_bytes())
}

/// 计算链上应存的 `payload_hash`（带 `blake2b:` 前缀）。
pub fn payload_hash(did: &str, email: &str, issuer_did: &str) -> Result<String, AnchorError> {
    let bytes = preimage(did, email, issuer_did)?;
    Ok(format!("{ANCHOR_HASH_PREFIX}{}", blake2b256_hex(&bytes)))
}

/// 校验链上值：重建后与 `anchor_payload_hash` 比对。
///
/// 调用方必须**先**从锚定记录里读出 `issuer_did` 再调这里（协议 §7.1 的鸡生蛋解法）。
pub fn verify(
    anchor_payload_hash: &str,
    did: &str,
    email: &str,
    issuer_did: &str,
) -> Result<(), AnchorError> {
    let recomputed = payload_hash(did, email, issuer_did)?;
    if recomputed != anchor_payload_hash {
        return Err(AnchorError::PayloadMismatch {
            expected: anchor_payload_hash.to_string(),
            recomputed,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const DID: &str = "did:key:z6MkehRgf7yJbgaGfYsdoAsKdBPE3dj2CYhowQdcjqSJgvVd";
    const ISSUER: &str = "did:web:issuer.example.com";

    #[test]
    fn preimage_is_four_terminated_lines() {
        let bytes = preimage(DID, "alice@example.com", ISSUER).unwrap();
        let text = std::str::from_utf8(&bytes).unwrap();
        assert!(text.ends_with('\n'), "末行必须尾随换行");
        assert_eq!(text.matches('\n').count(), 4);
        assert!(text.starts_with("EmailBinding-v1\n"));
    }

    #[test]
    fn email_is_lowercased_but_did_is_not() {
        let lower = payload_hash(DID, "alice@example.com", ISSUER).unwrap();
        let mixed = payload_hash(DID, "Alice@Example.COM", ISSUER).unwrap();
        assert_eq!(lower, mixed);

        let upper_did = payload_hash("DID:KEY:Z6MK", "alice@example.com", ISSUER).unwrap();
        let lower_did = payload_hash("did:key:z6mk", "alice@example.com", ISSUER).unwrap();
        assert_ne!(upper_did, lower_did, "did 不做大小写折叠");
    }

    #[test]
    fn issuer_change_changes_hash() {
        let a = payload_hash(DID, "alice@example.com", ISSUER).unwrap();
        let b = payload_hash(DID, "alice@example.com", "did:web:other.example.com").unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn verify_reports_mismatch_with_both_values() {
        let hash = payload_hash(DID, "alice@example.com", ISSUER).unwrap();
        assert!(verify(&hash, DID, "alice@example.com", ISSUER).is_ok());

        match verify(&hash, DID, "bob@example.com", ISSUER) {
            Err(AnchorError::PayloadMismatch {
                expected,
                recomputed,
            }) => {
                assert_eq!(expected, hash);
                assert_ne!(recomputed, hash);
            }
            other => panic!("expected PayloadMismatch, got {other:?}"),
        }
    }

    #[test]
    fn rejects_newline_injection() {
        // 攻击面：`did` 里塞换行可以伪造出与别的组合相同的 preimage。
        assert!(matches!(
            payload_hash("did:key:x\nEMAIL", "a@b.c", ISSUER),
            Err(AnchorError::NewlineInField { .. })
        ));
        // 行内换行必须拒绝（首尾空白会被 trim，那是无害规范化）
        assert!(matches!(
            payload_hash(DID, "a@b.c\nDID-Signature-v1", ISSUER),
            Err(AnchorError::NewlineInField { .. })
        ));
        // 首尾空白是规范化，不构成拒绝理由
        assert_eq!(
            payload_hash(DID, "  a@b.c  ", ISSUER).unwrap(),
            payload_hash(DID, "a@b.c", ISSUER).unwrap()
        );
    }

    #[test]
    fn rejects_empty_fields() {
        assert!(matches!(
            payload_hash("", "a@b.c", ISSUER),
            Err(AnchorError::EmptyField { field: "did" })
        ));
        assert!(matches!(
            payload_hash(DID, "", ISSUER),
            Err(AnchorError::EmptyField { field: "email" })
        ));
    }
}
