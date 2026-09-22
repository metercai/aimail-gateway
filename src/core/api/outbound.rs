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

use crate::core::config::Config;
use crate::core::email::factory::EmailFactory;
use crate::core::api::monitor::Metrics;
use tokio::sync::mpsc::Sender;

/// 入队一封**单收件人、无附件**的外发邮件, 并在有 trigger 句柄时唤醒调度器。
///
/// 返回 `email_id`; 失败返回 `Err(原因)`。确认信失败**不应**影响指令本身的执行结果,
/// 所以调用方按 warn 处理即可。
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

    let mut eps = serde_json::Map::new();
    eps.insert(
        to.to_lowercase(),
        json!({ "status": "pending", "protocol": "mx" }),
    );
    let endpoints_str = serde_json::to_string(&eps).unwrap_or_default();

    let domain = from.split('@').nth(1).unwrap_or("aimail-relay");
    let headers_json =
        json!({ "Message-ID": format!("<{}@{}>", Uuid::new_v4(), domain) }).to_string();
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
