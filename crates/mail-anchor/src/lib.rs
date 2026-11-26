//! `mail-anchor` — AIMail 锚点层（`EmailBinding` / `DomainControl`）。
//!
//! 规范：`protocol/DID-SIGNATURE-PROTOCOL.md`（本 crate 实现其中 §7 的锚点部分）。
//! 设计依据：`aimail` 仓 `docs/did-vc-email-authenticity-plan.md` §58「组件边界」。
//!
//! # 边界（硬性）
//!
//! * **邮件层不在本 crate**：`Content-v1` 投影、`DID-Signature` 头编解码、Ed25519 验签
//!   都由 `did-sdk` 提供（v0.3.0）。那部分是 Rust / Python / TypeScript 共用的字节契约，
//!   在本 crate 里再实现一次就会制造两份实现、必然漂移。
//! * **本 crate 不做 I/O**：所有外部交互（读/写锚定、DNS 查询、VC 签发）都经过
//!   [`ports`] 里的三个 trait，由 `aimail-gateway` 注入实现，测试注入 Mock。
//! * 因此本 crate 的依赖里没有 `axum` / `rusqlite` / `mailin` / `reqwest`。
//!
//! # 为什么不放在 did-sdk 或 chain-sdk
//!
//! `did-sdk` 有规范级约束 R1（不做链查询、不持链账户私钥），`chain-sdk` 声明自己
//!「不是钱包、不含 VC 存储与治理」。锚点层同时需要"链锚定语义"和"VC 语义"，
//! 放在任一侧都会破坏其边界，所以它独立存在。

#![forbid(unsafe_code)]

pub mod domain_control;
pub mod email_binding;
pub mod lifecycle;
pub mod ports;
pub mod vc;

/// `EmailBinding` 的 preimage 首行（协议 §7.1）。
pub const EMAIL_BINDING_TAG: &str = "EmailBinding-v1";
/// `DomainControl` 的 preimage 首行（协议 §7.2）。
pub const DOMAIN_CONTROL_TAG: &str = "DomainControl-v1";
/// 锚点层摘要前缀（协议 §2：链上承诺一律 BLAKE2b）。
pub const ANCHOR_HASH_PREFIX: &str = "blake2b:";

/// 链上 `AnchorRecord.anchor_type` 的字面值：邮件地址绑定。
pub const ANCHOR_TYPE_EMAIL_BINDING: &str = "EmailBinding";
/// 链上 `AnchorRecord.anchor_type` 的字面值：域名控制权。
pub const ANCHOR_TYPE_DOMAIN_CONTROL: &str = "DomainControl";

/// 锚点层的错误。刻意保持小而稳定：调用方（gateway / SDK）按变体映射成协议里的 reason 字符串。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AnchorError {
    /// 必填字段为空。
    EmptyField { field: &'static str },
    /// 字段含有 `\n` 或 `\r` —— 会破坏行式 preimage 的定界，必须拒绝（防 preimage 碰撞）。
    NewlineInField { field: &'static str },
    /// `anchor_type` 不是期望的类型（协议 §7.3：类型标签与 preimage 必须人工配对）。
    AnchorTypeMismatch { expected: String, actual: String },
    /// 发行方与该锚定记录的 `issuer_did` 不一致。
    IssuerMismatch { expected: String, actual: String },
    /// 锚定已被撤销（即时生效，不受 `valid_until` 约束）。
    AnchorRevoked,
    /// 锚定已过期（`valid_until != 0` 且 `now > valid_until`）。
    AnchorExpired { valid_until: u64, now: u64 },
    /// 锚定有效期窗口超过策略上限。
    AnchorValidityTooLong { seconds: u64, max_seconds: u64 },
    /// 重建出的 `payload_hash` 与链上值不一致。
    PayloadMismatch {
        expected: String,
        recomputed: String,
    },
}

impl std::fmt::Display for AnchorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EmptyField { field } => write!(f, "field `{field}` must not be empty"),
            Self::NewlineInField { field } => {
                write!(f, "field `{field}` must not contain a newline")
            }
            Self::AnchorTypeMismatch { expected, actual } => {
                write!(
                    f,
                    "anchor type mismatch: expected `{expected}`, got `{actual}`"
                )
            }
            Self::IssuerMismatch { expected, actual } => {
                write!(f, "issuer mismatch: expected `{expected}`, got `{actual}`")
            }
            Self::AnchorRevoked => write!(f, "anchor is revoked"),
            Self::AnchorExpired { valid_until, now } => {
                write!(f, "anchor expired: valid_until={valid_until}, now={now}")
            }
            Self::AnchorValidityTooLong {
                seconds,
                max_seconds,
            } => write!(
                f,
                "anchor validity {seconds}s exceeds policy limit {max_seconds}s"
            ),
            Self::PayloadMismatch {
                expected,
                recomputed,
            } => write!(
                f,
                "payload hash mismatch: expected `{expected}`, recomputed `{recomputed}`"
            ),
        }
    }
}

impl std::error::Error for AnchorError {}

/// BLAKE2b，**32 字节摘要参数**（`Blake2b<U32>`），返回小写 hex。
///
/// 注意：这不是 `BLAKE2b-512` 的截断，也不是 `BLAKE2s-256`（协议 §2）。
pub fn blake2b256_hex(data: &[u8]) -> String {
    use blake2::digest::consts::U32;
    use blake2::{Blake2b, Digest};

    let mut hasher = Blake2b::<U32>::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

/// 行式 preimage 的公共校验：非空、且不含换行。
///
/// 行式格式的定界完全依赖 `\n`；字段里出现换行就能让两个不同的输入产生同一段字节，
/// 所以在构造 preimage 之前必须拒绝（协议 §7.1）。
pub(crate) fn check_field(name: &'static str, value: &str) -> Result<(), AnchorError> {
    if value.is_empty() {
        return Err(AnchorError::EmptyField { field: name });
    }
    if value.contains('\n') || value.contains('\r') {
        return Err(AnchorError::NewlineInField { field: name });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blake2b256_matches_known_vector() {
        // BLAKE2b-256("") —— 用于钉住「摘要长度是参数」这件事。
        assert_eq!(
            blake2b256_hex(b""),
            "0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8"
        );
    }

    #[test]
    fn blake2b256_is_not_truncated_blake2b512() {
        use blake2::digest::consts::U64;
        use blake2::{Blake2b, Digest};

        let mut wide = Blake2b::<U64>::new();
        wide.update(b"x");
        let wide_hex = hex::encode(wide.finalize());

        // 摘要长度是 BLAKE2b 的参数，不是截断：前 32 字节并不相同。
        assert_ne!(blake2b256_hex(b"x"), wide_hex[..64]);
    }

    #[test]
    fn empty_and_newline_fields_are_rejected() {
        assert_eq!(
            check_field("did", "").unwrap_err(),
            AnchorError::EmptyField { field: "did" }
        );
        assert_eq!(
            check_field("did", "a\nb").unwrap_err(),
            AnchorError::NewlineInField { field: "did" }
        );
        assert_eq!(
            check_field("did", "a\rb").unwrap_err(),
            AnchorError::NewlineInField { field: "did" }
        );
        assert!(check_field("did", "did:key:z6Mk").is_ok());
    }
}
