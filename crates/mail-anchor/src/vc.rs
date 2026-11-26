//! `EmailBindingVC` 的声明形状与组装入口（协议 §8、设计计划 §40）。
//!
//! # 本 crate 只声明「声明里放什么」，不实现签名
//!
//! VC 的 proof 由 `did-sdk` 的 `DidSdk<Server>`（`assemble_vc_with_proof` /
//! `issue_self_asserted_vc`）产生，经 [`crate::ports::VcIssuer`] 注入。这里只固定：
//!
//! * `credentialSubject` 的字段（`id` = 持有者 DID，`email` = 绑定的地址）；
//! * `credentialStatus.anchorId` **指向 `EmailBinding` 事实锚**。
//!
//! # 两个 anchor 字段不能混
//!
//! | 字段 | 指向 | 谁消费 |
//! |---|---|---|
//! | `credentialStatus.anchorId` | `EmailBinding` 事实锚（本模块产出） | 接收方 / 审计 |
//! | VC 顶层 `anchor_id` | 该 VC 自己的 `IssuedVc` 锚（本 profile 不产生） | did-sdk 的选择性披露路径 |
//!
//! 而且 `credentialStatus` **会进入** VC 的 `IssuedVc` 哈希（`anchor_payload_hash` 只丢
//! `proof` 与 `anchor_id`）。含义：**事实锚不可替换**——想换只能撤销旧锚、新建、重签 VC。

use serde::{Deserialize, Serialize};

/// `EmailBindingVC` 的 `credentialSubject`。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EmailBindingSubject {
    /// 持有者（被绑定的 agent）的 `did:key`。
    pub id: String,
    /// 被绑定的邮件地址（小写）。
    pub email: String,
}

/// 组装 VC 所需的全部输入。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EmailBindingVcRequest {
    /// 事实锚 id（写入 `credentialStatus.anchorId`）。
    pub anchor_id: String,
    /// 持有者 DID。
    pub did: String,
    /// 被绑定的地址（本结构会转小写）。
    pub email: String,
    /// 过期时间（RFC3339 UTC）。应与锚定的 `valid_until` 对齐。
    pub expiration_date: Option<String>,
}

impl EmailBindingVcRequest {
    /// 供 [`crate::ports::VcIssuer::issue`] 使用的 `credentialSubject`。
    pub fn subject(&self) -> EmailBindingSubject {
        EmailBindingSubject {
            id: self.did.clone(),
            email: self.email.trim().to_lowercase(),
        }
    }

    /// `credentialStatus` —— 指向事实锚而不是 VC 自己的锚。
    pub fn credential_status(&self) -> serde_json::Value {
        serde_json::json!({
            "type": "AnchorStatus",
            "anchorId": self.anchor_id,
        })
    }

    /// 校验请求自洽（字段非空、地址含 `@`）。
    pub fn validate(&self) -> Result<(), crate::AnchorError> {
        crate::check_field("anchor_id", &self.anchor_id)?;
        crate::check_field("did", &self.did)?;
        crate::check_field("email", &self.email)?;
        if !self.email.contains('@') {
            return Err(crate::AnchorError::EmptyField { field: "email" });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request() -> EmailBindingVcRequest {
        EmailBindingVcRequest {
            anchor_id: "anchor-abc123".to_string(),
            did: "did:key:z6MkehRgf7yJbgaGfYsdoAsKdBPE3dj2CYhowQdcjqSJgvVd".to_string(),
            email: "Alice@Example.COM".to_string(),
            expiration_date: Some("2027-01-01T00:00:00Z".to_string()),
        }
    }

    #[test]
    fn subject_lowercases_email_only() {
        let subject = request().subject();
        assert_eq!(subject.email, "alice@example.com");
        assert!(subject.id.starts_with("did:key:"));
    }

    #[test]
    fn credential_status_points_at_the_fact_anchor() {
        let status = request().credential_status();
        assert_eq!(status["type"], "AnchorStatus");
        assert_eq!(status["anchorId"], "anchor-abc123");
        // 关键：不是 VC 顶层 anchor_id
        assert!(status.get("anchor_id").is_none());
    }

    #[test]
    fn validate_rejects_blank_and_malformed() {
        assert!(request().validate().is_ok());

        let mut r = request();
        r.anchor_id = String::new();
        assert!(r.validate().is_err());

        let mut r = request();
        r.email = "not-an-address".to_string();
        assert!(r.validate().is_err());
    }
}
