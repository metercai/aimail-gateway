//! 共享的"外发邮件入队"助手(2026-09-22 提取)。
//!
//! 动因: welcome 端点内联了一段外发入队逻辑(建记录 + endpoints + metrics + trigger);
//! 网关新增的"安全员指令确认信"需要同一套动作 ⇒ 按"共享逻辑必须提取公共实现"抽到这里,
//! 避免第二份副本(此前 pull_intercept 的验签副本已因重复漏修过一次)。
//!
//! 依赖故意做成**按需注入**(config / email_factory / metrics?/ trigger_tx?), 而不是收 `HttpState`:
//! 确认信发生在投递路径(deliver.rs)里, 那里没有 HttpState。

use serde_json::json;
use tracing::{info, warn};
use uuid::Uuid;

use crate::core::api::monitor::Metrics;
use crate::core::config::Config;
use crate::core::email::factory::EmailFactory;
use tokio::sync::mpsc::Sender;

/// 入队一封**单收件人、无附件**的外发邮件, 并在有 trigger 句柄时唤醒调度器。
///
/// 返回 `email_id`; 失败返回 `Err(原因)`。确认信失败**不应**影响指令本身的执行结果,
/// 所以调用方按 warn 处理即可。
#[allow(clippy::too_many_arguments)] // explicit parameter list is deliberate: internal constructor/handler API
pub async fn enqueue_outbound_simple(
    cfg: &Config,
    email_factory: &EmailFactory,
    metrics: Option<&Metrics>,
    trigger_tx: Option<&Sender<String>>,
    system_id: &str,
    from: &str,
    to: &str,
    subject: &str,
    body: &str,
) -> Result<String, String> {
    let email_id = Uuid::new_v4().to_string();
    let recipients_json = json!({ "to": [to] }).to_string();

    // Endpoint resolution (2026-09-23, S4 e2e 实证): the original helper
    // hardcoded `protocol: mx`, so confirmations to INTERNAL recipients
    // (registered on this gateway) were dropped by loopback prevention in the
    // SMTP sender and swept away — the ack never reached same-host managers.
    // Resolve the webhook endpoint like the welcome endpoint does; fall back
    // to the MX envelope only when the recipient has no webhook (external).
    let endpoints_str = {
        let internal = email_factory
            .env_factory
            .build_endpoints_for_recipients(&[to.to_string()])
            .await;
        if internal == "{}" || internal.is_empty() {
            let mut eps = serde_json::Map::new();
            eps.insert(
                to.to_lowercase(),
                json!({ "status": "pending", "protocol": "mx" }),
            );
            serde_json::to_string(&eps).unwrap_or_default()
        } else {
            internal
        }
    };

    // Delivery-type routing (2026-09-23): for outbound records
    // `detect_delivery_type` only consults the explicit header override
    // (body present ⇒ SMTP). An internal recipient must go through the
    // webhook processor (which consumes the endpoints above), otherwise the
    // SMTP sender's loopback prevention silently drops the mail.
    let headers_json = {
        let is_internal = endpoints_str.contains("\"url\"");
        let mut h = serde_json::Map::new();
        if is_internal {
            h.insert("delivery_type".to_string(), json!("webhook"));
        }
        let domain = from.split('@').nth(1).unwrap_or("aimail-relay");
        h.insert(
            "Message-ID".to_string(),
            json!(format!("<{}@{}>", Uuid::new_v4(), domain)),
        );
        serde_json::to_string(&h).unwrap_or_default()
    };
    let max_attempts = cfg.retry.max_attempts as i32;

    match email_factory
        .create_outbound(
            &email_id,
            system_id,
            from,
            &recipients_json,
            subject,
            body,
            Some(&endpoints_str),
            None,
            Some(&headers_json),
            max_attempts,
        )
        .await
    {
        Ok(record) => {
            if let Some(m) = metrics {
                m.inc_emails_queued_api();
            }
            info!(
                operation = "outbound_queued",
                email_id = %record.id,
                sender = %from,
                to = %to,
                "outbound mail queued"
            );
            if let Some(tx) = trigger_tx {
                if let Err(e) = tx.try_send(record.id.clone()) {
                    if let Some(m) = metrics {
                        m.inc_trigger_dropped();
                    }
                    warn!(
                        operation = "outbound_trigger_failed",
                        error = %e,
                        email_id = %record.id,
                        "failed to trigger outbound dispatch"
                    );
                }
            }
            Ok(record.id.clone())
        }
        Err(e) => Err(e.to_string()),
    }
}

/// 确认信所需的上下文 —— 投递路径(deliver.rs)里没有 `HttpState`, 故按需注入这几件。
pub struct AckCtx<'a> {
    pub cfg: &'a Config,
    pub email_factory: &'a EmailFactory,
    pub metrics: Option<&'a Metrics>,
    pub trigger_tx: Option<&'a Sender<String>>,
}

/// 指令处理的失败确认信上下文(2026-09-23): 指令必有回复 ⇒ **非 manager 发件人也必须收到**
/// "Command failed" 确认信, 否则非 manager 的指令静默无反馈, 发件方无从发现。
/// sender = 指令邮件发件人(失败确认信收件人); system_id = 目标地址归属系统(路由用);
/// to_agent(指令目标地址)逐命中不同, 由调用点作参数传入, 不入结构体。
pub struct FailedCommandAck<'a> {
    pub cfg: &'a Config,
    pub email_factory: &'a EmailFactory,
    pub metrics: Option<&'a Metrics>,
    pub trigger_tx: Option<&'a Sender<String>>,
    pub sender: &'a str,
    pub system_id: &'a str,
}
