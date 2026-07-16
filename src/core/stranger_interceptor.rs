//! StrangerInterceptor — handles inbound emails from non-whitelisted senders
//! with recognized universal commands ([WHOAMI], [VERIFY], [HELP], ...).
//!
//! Entry points (SMTP receiver + send API) inject X-Mail-Stranger + X-Mail-Command
//! headers before creating the EmailRecord. This interceptor reads those headers
//! and handles the command without re-checking whitelists.

use crate::core::email::factory::EmailFactory;
use crate::core::strategy::{InboundInterceptor, InterceptorDecision};
use async_trait::async_trait;
use std::sync::Arc;
use tracing;

pub struct StrangerInterceptor {
    email_factory: Arc<EmailFactory>,
    system_id: String,
}

impl StrangerInterceptor {
    pub fn new(email_factory: Arc<EmailFactory>, system_id: &str) -> Self {
        Self {
            email_factory,
            system_id: system_id.to_string(),
        }
    }

    fn is_header_true(headers: &serde_json::Value, key: &str) -> bool {
        headers
            .as_object()
            .and_then(|h| h.get(key))
            .and_then(|v| v.as_str())
            .map(|s| s.eq_ignore_ascii_case("true"))
            .unwrap_or(false)
    }

    fn header_str<'a>(headers: &'a serde_json::Value, key: &str) -> Option<&'a str> {
        headers.as_object()?.get(key)?.as_str()
    }

    async fn get_public_whoami(&self, agent_addr: &str) -> Option<String> {
        self.email_factory
            .env_factory
            .db
            .agent_state_get(agent_addr, "public_whoami")
            .await
            .ok()
            .flatten()
            .map(|(_, v)| v)
    }

    async fn send_auto_reply(
        &self,
        from: &str,
        to: &str,
        subject: &str,
        body: &str,
    ) {
        let email_id = format!("sr-{}", uuid::Uuid::new_v4());
        if let Err(e) = self
            .email_factory
            .create_outbound(
                &email_id,
                &self.system_id,
                from,
                to,
                subject,
                body,
                None,
                None,
                None,
                3,
            )
            .await
        {
            tracing::warn!(
                "[stranger] failed to create auto-reply: to={} error={:?}",
                to,
                e
            );
        }
    }
}

#[async_trait]
impl InboundInterceptor for StrangerInterceptor {
    fn name(&self) -> &str {
        "StrangerInterceptor"
    }

    fn priority(&self) -> u32 {
        5
    }

    async fn intercept(
        &self,
        _record: &crate::core::email::storage::EmailRecord,
        payload: &mut serde_json::Value,
    ) -> crate::core::strategy::InterceptorDecision {
        let headers = match payload.get("headers") {
            Some(h) => h,
            None => return InterceptorDecision::PassThrough,
        };

        // Only handle stranger emails
        if !Self::is_header_true(headers, "x-mail-stranger") {
            return InterceptorDecision::PassThrough;
        }

        let command = match Self::header_str(headers, "x-mail-command") {
            Some(c) => c.to_lowercase(),
            None => return InterceptorDecision::PassThrough,
        };

        let sender = payload["from"].as_str().unwrap_or("");
        // recipient is the first `to` address (this agent)
        let recipient = payload["to"]
            .as_array()
            .and_then(|a| a.first())
            .and_then(|v| v.as_str())
            .unwrap_or("");

        match command.as_str() {
            "whoami" => {
                let body = self
                    .get_public_whoami(recipient)
                    .await
                    .unwrap_or_else(|| "Agent not configured yet.".to_string());

                let reply_subject = format!(
                    "Re: {}",
                    payload["subject"].as_str().unwrap_or("[WHOAMI]")
                );
                self.send_auto_reply(recipient, sender, &reply_subject, &body)
                    .await;

                tracing::info!(
                    "[stranger] whoami auto-reply: from={} to={}",
                    recipient,
                    sender
                );
                InterceptorDecision::Handled
            }
            // Future commands:
            // "verify" => handle_verify(),
            // "help"   => handle_help(),
            _ => InterceptorDecision::PassThrough,
        }
    }
}
