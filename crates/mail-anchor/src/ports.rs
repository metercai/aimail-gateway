//! 锚点层的外部 I/O 边界。
//!
//! 本 crate 自己不做任何 I/O：读/写锚定、DNS 查询、VC 签发全部经这三个 trait 注入。
//! 这样同一份 preimage / 生命周期逻辑既能被 gateway 使用，也能在 `chain-sdk::Mock` +
//! 假 DNS 下做全流程测试（不需要真链、SMTP、SQLite）。

use async_trait::async_trait;

use crate::AnchorError;

/// 锚定记录的最小视图。
///
/// 只放本层需要的字段；`chain-sdk` 的 `AnchorRecord` 由 gateway 侧转成这个结构，
/// 避免把 chain-sdk 的类型泄漏进 crate 的公开 API（也便于单测直接构造）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnchorSnapshot {
    /// 链上记录的 `anchor_type`（如 `EmailBinding` / `DomainControl`）。
    pub anchor_type: String,
    /// 信任链根（`AnchorRecord.issuer_did`）。协议 §7.1 规定 `issuer_id` 取这个字段。
    pub issuer_did: String,
    /// 生命周期：是否已撤销（即时生效）。
    pub revoked: bool,
    /// 插入时间（Unix 秒）。用于计算有效期窗口长度。
    pub created_at: u64,
    /// 有效期截止（Unix 秒）；`0` 表示永久有效。
    pub valid_until: u64,
    /// 链上承诺的载荷哈希，形如 `blake2b:<hex>`。
    pub payload_hash: String,
}

/// 锚定的读写端口。`Issuer` 角色用全部方法；`Verifier` 只用 [`AnchorStore::get`]。
#[async_trait]
pub trait AnchorStore: Send + Sync {
    /// 按 id 取锚定；不存在返回 `Ok(None)`（而不是错误——上层要区分"不存在"与"不可用"）。
    async fn get(&self, anchor_id: &str) -> Result<Option<AnchorSnapshot>, AnchorError>;

    /// 创建一个锚定，返回 `anchor_id`。`valid_until = 0` 表示永久。
    async fn create(
        &self,
        anchor_type: &str,
        payload_hash: &str,
        valid_until: u64,
    ) -> Result<String, AnchorError>;

    /// 续期。仅对 `valid_until != 0` 的锚定有效。
    async fn renew(&self, anchor_id: &str, valid_until: u64) -> Result<(), AnchorError>;

    /// 撤销。即时生效，不受 `valid_until` 约束。
    async fn revoke(&self, anchor_id: &str) -> Result<(), AnchorError>;
}

/// DNS TXT 查询端口（`DomainControl` 的控制权校验用）。
#[async_trait]
pub trait DnsResolver: Send + Sync {
    /// 返回 `<name>` 的所有 TXT 记录（已拼接的字符串形式）。
    ///
    /// 实现方负责处理超时与重试；本层只做"记录存在 + 格式合法 + 指向的锚定有效"的判断。
    async fn lookup_txt(&self, name: &str) -> Result<Vec<String>, AnchorError>;
}

/// VC 签发端口（`EmailBindingVC` 的组装由 `did-sdk` 完成，本 crate 只提供声明）。
#[async_trait]
pub trait VcIssuer: Send + Sync {
    /// 用给定的 `credentialSubject` 与过期时间签发一张 VC，返回紧凑 JSON。
    ///
    /// `anchor_id` 必须写入 `credentialStatus.anchorId`（指向 `EmailBinding` 事实锚），
    /// 而不是 VC 顶层的 `anchor_id`（那是 `IssuedVc` 锚，见协议 §7.3）。
    async fn issue(
        &self,
        credential_type: &str,
        subject: serde_json::Value,
        expiration_date: Option<String>,
    ) -> Result<serde_json::Value, AnchorError>;
}
