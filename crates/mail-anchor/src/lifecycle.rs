//! 锚定生命周期判定（协议 §7、设计计划 §43）。
//!
//! 判定顺序是**规范性**的：类型 → 发行方 → 撤销 → 过期 → 有效期窗口。
//! 先因为类型不对而失败，就不该再因为过期而失败——上层报告 `reason` 时需要确定性的归因。

use crate::ports::AnchorSnapshot;
use crate::AnchorError;

/// 校验策略。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Policy {
    /// 允许的最长有效期窗口。超出即拒绝，用于压缩"域名易主后旧锚定仍有效"的有界窗口。
    pub max_anchor_validity_days: u64,
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            max_anchor_validity_days: 180,
        }
    }
}

const SECONDS_PER_DAY: u64 = 86_400;

/// 校验一条锚定是否可用于当前时刻的验证。
///
/// * `expected_type` —— 必须与该记录的类型一致（防止类型与 preimage 错配，协议 §7.3）；
/// * `expected_issuer` —— 期望的发行方 `did:web`；`None` 表示不校验（验证路径上用于给出
///   `anchor_hash_mismatch` 之前的先验检查可省略）；
/// * `now` —— Unix 秒。
pub fn check(
    anchor: &AnchorSnapshot,
    expected_type: &str,
    expected_issuer: Option<&str>,
    now: u64,
    policy: Policy,
) -> Result<(), AnchorError> {
    if anchor.anchor_type != expected_type {
        return Err(AnchorError::AnchorTypeMismatch {
            expected: expected_type.to_string(),
            actual: anchor.anchor_type.clone(),
        });
    }

    if let Some(expected) = expected_issuer {
        if !anchor.issuer_did.eq_ignore_ascii_case(expected) {
            return Err(AnchorError::IssuerMismatch {
                expected: expected.to_string(),
                actual: anchor.issuer_did.clone(),
            });
        }
    }

    if anchor.revoked {
        return Err(AnchorError::AnchorRevoked);
    }

    if anchor.valid_until != 0 && now > anchor.valid_until {
        return Err(AnchorError::AnchorExpired {
            valid_until: anchor.valid_until,
            now,
        });
    }

    // 只在有明确截止时才谈窗口长度；`valid_until == 0`（永久）不受窗口上限约束，
    // 但永久锚定本身不该用于 EmailBinding（协议 §7.1 的默认策略是非 0）。
    if anchor.valid_until != 0 {
        let max_seconds = policy
            .max_anchor_validity_days
            .saturating_mul(SECONDS_PER_DAY);
        let window = anchor.valid_until.saturating_sub(anchor.created_at);
        if max_seconds != 0 && window > max_seconds {
            return Err(AnchorError::AnchorValidityTooLong {
                seconds: window,
                max_seconds,
            });
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn snapshot() -> AnchorSnapshot {
        AnchorSnapshot {
            anchor_type: crate::ANCHOR_TYPE_EMAIL_BINDING.to_string(),
            issuer_did: "did:web:issuer.example.com".to_string(),
            revoked: false,
            created_at: 1_700_000_000,
            valid_until: 1_700_000_000 + 90 * SECONDS_PER_DAY,
            payload_hash: "blake2b:00".to_string(),
        }
    }

    const NOW: u64 = 1_700_000_100;

    #[test]
    fn healthy_anchor_passes() {
        assert!(check(
            &snapshot(),
            crate::ANCHOR_TYPE_EMAIL_BINDING,
            None,
            NOW,
            Policy::default()
        )
        .is_ok());
    }

    #[test]
    fn type_mismatch_is_reported_first() {
        let mut a = snapshot();
        a.anchor_type = crate::ANCHOR_TYPE_DOMAIN_CONTROL.to_string();
        a.revoked = true; // 同时撤销，也必须先报类型
        assert!(matches!(
            check(
                &a,
                crate::ANCHOR_TYPE_EMAIL_BINDING,
                None,
                NOW,
                Policy::default()
            ),
            Err(AnchorError::AnchorTypeMismatch { .. })
        ));
    }

    #[test]
    fn issuer_mismatch_is_reported() {
        let anchor = snapshot();
        assert!(matches!(
            check(
                &anchor,
                crate::ANCHOR_TYPE_EMAIL_BINDING,
                Some("did:web:other.example.com"),
                NOW,
                Policy::default()
            ),
            Err(AnchorError::IssuerMismatch { .. })
        ));
        // 大小写不敏感
        assert!(check(
            &anchor,
            crate::ANCHOR_TYPE_EMAIL_BINDING,
            Some("DID:WEB:ISSUER.EXAMPLE.COM"),
            NOW,
            Policy::default()
        )
        .is_ok());
    }

    #[test]
    fn revoked_beats_expiry() {
        let mut a = snapshot();
        a.revoked = true;
        a.valid_until = 1; // 也过期了
        assert_eq!(
            check(
                &a,
                crate::ANCHOR_TYPE_EMAIL_BINDING,
                None,
                NOW,
                Policy::default()
            )
            .unwrap_err(),
            AnchorError::AnchorRevoked
        );
    }

    #[test]
    fn revocation_is_immediate_and_not_bounded_by_valid_until() {
        // 未到 valid_until 也照样撤销
        let mut a = snapshot();
        a.revoked = true;
        assert_eq!(
            check(
                &a,
                crate::ANCHOR_TYPE_EMAIL_BINDING,
                None,
                NOW,
                Policy::default()
            )
            .unwrap_err(),
            AnchorError::AnchorRevoked
        );
    }

    #[test]
    fn expiry_boundary_is_inclusive() {
        let mut a = snapshot();
        a.valid_until = NOW;
        assert!(check(
            &a,
            crate::ANCHOR_TYPE_EMAIL_BINDING,
            None,
            NOW,
            Policy::default()
        )
        .is_ok());
        assert!(matches!(
            check(
                &a,
                crate::ANCHOR_TYPE_EMAIL_BINDING,
                None,
                NOW + 1,
                Policy::default()
            ),
            Err(AnchorError::AnchorExpired { .. })
        ));
    }

    #[test]
    fn permanent_anchor_never_expires() {
        let mut a = snapshot();
        a.valid_until = 0;
        a.created_at = 1;
        assert!(check(
            &a,
            crate::ANCHOR_TYPE_EMAIL_BINDING,
            None,
            u64::MAX / 2,
            Policy::default()
        )
        .is_ok());
    }

    #[test]
    fn overlong_validity_window_is_rejected() {
        let mut a = snapshot();
        a.valid_until = a.created_at + 365 * SECONDS_PER_DAY;
        assert!(matches!(
            check(
                &a,
                crate::ANCHOR_TYPE_EMAIL_BINDING,
                None,
                NOW,
                Policy {
                    max_anchor_validity_days: 180
                }
            ),
            Err(AnchorError::AnchorValidityTooLong { .. })
        ));
    }
}
