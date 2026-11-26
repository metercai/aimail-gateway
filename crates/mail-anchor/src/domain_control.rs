//! `DomainControl` 锚定载荷与控制权校验（协议 §7.2）。
//!
//! ```text
//! payload_hash = "blake2b:" + BLAKE2b-256( "DomainControl-v1\n{domain}\n{issuer_did}\n" )
//! ```
//!
//! 这条锚定是 `EmailBinding` 的**前置证据**：规范要求在每次 `EmailBinding` 写入/续期**之前**
//! 完成控制权校验，执行者只能是创建 `EmailBinding` 的一方（发行方 = gateway 的 Issuer 角色）。
//!
//! 引导顺序不能反：
//!
//! ```text
//! 1. 发行方创建 DomainControl 锚定            -> anchor_id
//! 2. 域名所有者发布 TXT: _email-verification.<domain> "ev-anchor=chain:<anchor_id>"
//! 3. 每次写/续 EmailBinding 前，重做 2 的解析与锚定核对
//! ```
//!
//! 目前 gateway **没有任何**域名归属的 DNS 验证（`system_domains` 只是内部表），
//! 所以第 2 步是一条新的运营前置，不是代码能替代的。

use crate::{blake2b256_hex, check_field, AnchorError, ANCHOR_HASH_PREFIX, DOMAIN_CONTROL_TAG};

/// TXT 记录所在的前缀（协议 §7.2）。
pub const TXT_NAME_PREFIX: &str = "_email-verification.";
/// TXT 记录里指向锚定的键名。
pub const TXT_ANCHOR_KEY: &str = "ev-anchor=";

/// 构造 `DomainControl` 的行式 preimage（三行，每行尾随 `\n`，含末行）。
///
/// `domain` 规范化为 ASCII 小写。
pub fn preimage(domain: &str, issuer_did: &str) -> Result<Vec<u8>, AnchorError> {
    let domain = domain.trim().to_lowercase();
    check_field("domain", &domain)?;
    check_field("issuer_did", issuer_did)?;

    Ok(format!("{DOMAIN_CONTROL_TAG}\n{domain}\n{issuer_did}\n").into_bytes())
}

/// 计算链上应存的 `payload_hash`（带 `blake2b:` 前缀）。
pub fn payload_hash(domain: &str, issuer_did: &str) -> Result<String, AnchorError> {
    let bytes = preimage(domain, issuer_did)?;
    Ok(format!("{ANCHOR_HASH_PREFIX}{}", blake2b256_hex(&bytes)))
}

/// 校验链上值：重建后与 `anchor_payload_hash` 比对。
pub fn verify(
    anchor_payload_hash: &str,
    domain: &str,
    issuer_did: &str,
) -> Result<(), AnchorError> {
    let recomputed = payload_hash(domain, issuer_did)?;
    if recomputed != anchor_payload_hash {
        return Err(AnchorError::PayloadMismatch {
            expected: anchor_payload_hash.to_string(),
            recomputed,
        });
    }
    Ok(())
}

/// 给定域名，返回应当查询的 TXT 记录全名（带结尾点，便于直接喂给解析器）。
pub fn txt_record_name(domain: &str) -> String {
    format!("{}{}.", TXT_NAME_PREFIX, domain.trim().to_lowercase())
}

/// 从一组 TXT 记录里取出 `chain:<anchor_id>`。
///
/// 返回 `Ok(None)` 表示"没有符合格式的记录"——调用方要把它与"DNS 不可用"区分开：
/// 前者是控制权不成立，后者是暂时性故障（不应据此判定伪造）。
pub fn parse_anchor_ref(records: &[String]) -> Option<String> {
    for record in records {
        for part in record.split_whitespace() {
            if let Some(value) = part.strip_prefix(TXT_ANCHOR_KEY) {
                if let Some(anchor) = value.strip_prefix("chain:") {
                    if !anchor.is_empty() {
                        return Some(anchor.to_string());
                    }
                }
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    const ISSUER: &str = "did:web:issuer.example.com";

    #[test]
    fn preimage_is_three_terminated_lines() {
        let text = String::from_utf8(preimage("example.com", ISSUER).unwrap()).unwrap();
        assert!(text.starts_with("DomainControl-v1\n"));
        assert!(text.ends_with('\n'));
        assert_eq!(text.matches('\n').count(), 3);
    }

    #[test]
    fn domain_is_lowercased() {
        let a = payload_hash("example.com", ISSUER).unwrap();
        let b = payload_hash("Example.COM", ISSUER).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn different_domain_changes_hash() {
        let a = payload_hash("example.com", ISSUER).unwrap();
        let b = payload_hash("other.example.com", ISSUER).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn txt_name_is_prefixed_and_absolute() {
        assert_eq!(
            txt_record_name("Example.com"),
            "_email-verification.example.com."
        );
    }

    #[test]
    fn parses_anchor_ref_from_txt() {
        let records = vec![
            "v=spf1 -all".to_string(),
            "ev-anchor=chain:anchor-xyz789".to_string(),
        ];
        assert_eq!(
            parse_anchor_ref(&records),
            Some("anchor-xyz789".to_string())
        );

        assert_eq!(parse_anchor_ref(&[]), None);
        assert_eq!(parse_anchor_ref(&["ev-anchor=".to_string()]), None);
        assert_eq!(parse_anchor_ref(&["ev-anchor=chain:".to_string()]), None);
        // 只认 chain: 前缀
        assert_eq!(parse_anchor_ref(&["ev-anchor=ipfs:abc".to_string()]), None);
    }

    #[test]
    fn rejects_newline_injection() {
        assert!(matches!(
            payload_hash("example.com\nDomainControl-v1", ISSUER),
            Err(AnchorError::NewlineInField { field: "domain" })
        ));
    }
}
