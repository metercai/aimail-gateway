//! A2aInterceptor — 拦截入站邮件，处理 A 流指令 / 注入 B 流身份。

use crate::board::commands;
use crate::board::db;
use crate::board::models::{parse_board_email, A2aCommand, Board, BoardStatus, Member};
use crate::board::notify::Notifier;
use crate::core::email::factory::AttachmentFactory;
use std::cell::RefCell;
use crate::core::email::factory::EmailFactory;
use crate::core::errors::AppResult;
use crate::core::strategy::InboundInterceptor;
use async_trait::async_trait;
use serde_json::Value;
use std::sync::Arc;

pub struct A2aInterceptor {
    pub email_factory: Arc<EmailFactory>,
    pub attachment_factory: Arc<AttachmentFactory>,
    pub system_id: String,
    pub storage_path: String,
    pub gateway_domain: String,
    pub gateway_url: String,
}

impl A2aInterceptor {
    pub fn new(
        email_factory: Arc<EmailFactory>,
        attachment_factory: Arc<AttachmentFactory>,
        system_id: &str,
        storage_path: &str,
        gateway_domain: &str,
        gateway_url: &str,
    ) -> Self {
        Self {
            email_factory,
            attachment_factory,
            system_id: system_id.to_string(),
            storage_path: storage_path.to_string(),
            gateway_domain: gateway_domain.to_string(),
            gateway_url: gateway_url.to_string(),
        }
    }

    fn resolve_board(&self, to_addr: &str) -> Option<(String, String, String)> {
        parse_board_email(to_addr)
    }
}

fn seed_default_role_permissions_conn(conn: &rusqlite::Connection) -> crate::core::errors::AppResult<()> {
    let defaults: &[(&str, &[&str])] = &[
        ("orchestrator", &["init","tasks","assign","review","block","unblock",
                           "cancel","reassign","edit","deadline","output","notify",
                           "members","roles","config","arbitrate","comment","list","show",
                           "heartbeat"]),
        ("verifier",     &["verify","approve","reject","output","comment","list","show","roles","members","status","heartbeat"]),
        ("worker",       &["complete","commit","block","heartbeat","comment","list","show","roles","members","status"]),
        ("owner",        &["tasks","unblock","reassign","comment","list","show","heartbeat"]),
    ];
    for (role, verbs) in defaults {
        for verb in *verbs {
            conn.execute(
                "INSERT OR IGNORE INTO role_permissions (role, verb) VALUES (?1, ?2)",
                rusqlite::params![role, verb],
            )?;
        }
    }
    Ok(())
}

#[async_trait]
impl InboundInterceptor for A2aInterceptor {
    fn name(&self) -> &str {
        "A2aInterceptor"
    }

    fn priority(&self) -> u32 {
        20
    }

    async fn intercept(
        &self,
        _record: &crate::core::email::storage::EmailRecord,
        payload: &mut Value,
    ) -> crate::core::strategy::InterceptorDecision {
        let subject = payload["subject"].as_str().unwrap_or("").trim().to_string();
        let sender = payload["from"].as_str().unwrap_or("").to_string();
        let raw_attachments_json: Option<String> = payload.get("attachments")
            .and_then(|v| serde_json::to_string(v).ok());
        let to_addr = payload["to"]
            .as_array()
            .and_then(|a| a.first())
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();

        // ── Board creation flow: [A2A] new → orchestrator (no .a2a address) ──
        // Human sends to orchestrator to create a board
        if subject.starts_with("[A2A] new ") {
            // Distinguish: TO has .a2a@ → task creation; TO has no .a2a@ → board creation via [A2A] new
            let is_board_addr = to_addr.contains(".a2a@");
            if is_board_addr {
                // Let normal [A2A] handling below process this as task creation
            } else {
                // Board creation flow
                let rest = subject.strip_prefix("[A2A] new ").unwrap_or("").trim();
                let (short_part, desc) = rest.split_once(':').unwrap_or((rest, ""));
                let short_id = crate::board::models::sanitize_short_id(short_part.trim());
                let description = desc.trim().to_string();

                if short_id.is_empty() {
                    return crate::core::strategy::InterceptorDecision::PassThrough;
                }

            // Compute board identifiers (same formula as regular boards)
            let gateway_domain = self.gateway_domain.clone();
let board_id = crate::board::models::derive_board_id(&short_id, &gateway_domain);
            let board_email = format!("{}.a2a@{}", short_id, gateway_domain);
            let gateway_url = self.gateway_url.clone();

            // Parse members from body
            let body = payload["body"].as_str().unwrap_or("");
            let params: Option<Value> = serde_json::from_str(body).ok();
            let members = params.as_ref()
                .and_then(|p| p.get("members"))
                .and_then(|v| v.as_array());

            // Validate: members must include orchestrator AND verifier
            let has_orch = members.map(|arr| {
                arr.iter().any(|m| m.get("role").and_then(|v| v.as_str()) == Some("orchestrator"))
            }).unwrap_or(false);
            let has_verifier = members.map(|arr| {
                arr.iter().any(|m| m.get("role").and_then(|v| v.as_str()) == Some("verifier"))
            }).unwrap_or(false);

            if !has_orch {
                tracing::warn!("[a2a_board] [A2A] new board rejected: must include an orchestrator member");
                return crate::core::strategy::InterceptorDecision::PassThrough;
            }
            if !has_verifier {
                tracing::warn!("[a2a_board] [A2A] new board rejected: must include a verifier member");
                return crate::core::strategy::InterceptorDecision::PassThrough;
            }

            // Validate: recipient is the orchestrator
            let orch_email = members.as_ref()
                .and_then(|arr| arr.iter()
                    .find(|m| m.get("role").and_then(|v| v.as_str()) == Some("orchestrator"))
                    .and_then(|m| m.get("email").and_then(|v| v.as_str()))
                ).unwrap_or("");
            if orch_email != to_addr {
                tracing::warn!(
                    "[a2a_board] [A2A] new board rejected: recipient {} != orchestrator {}",
                    to_addr, orch_email
                );
                return crate::core::strategy::InterceptorDecision::PassThrough;
            }

            // Open/create board DB and create board
            let conn = match db::open_board_db(&self.storage_path, &board_id) {
                Ok(c) => c,
                Err(_) => {
                    tracing::error!("[a2a_board] [A2A] new failed to open board DB");
                    return crate::core::strategy::InterceptorDecision::PassThrough;
                }
            };

            // Create board if not exists
            if db::get_board(&conn, &board_id).is_err() {
                let board = Board {
                    id: board_id.clone(),
                    short_id: short_id.clone(),
                    board_email: board_email.clone(),
                    description: if description.is_empty() { None } else { Some(description.clone()) },
                    status: BoardStatus::Active,
                    output_task_id: None,
                    plan_version: None,
            plan_text: None,
                    plan_confirmed_at: None,
                    criteria_version: None,
            criteria_text: None,
            criteria_confirmed_at: None,
                    gateway_url: gateway_url.clone(),
                    created_at: chrono::Utc::now().to_rfc3339(),
                    completed_at: None,
                };
                db::create_board(&conn, &board).ok();
            }

            // Register members
            if let Some(members) = members {
                for m in members {
                    let email = m.get("email").and_then(|v| v.as_str()).unwrap_or("");
                    let role = m.get("role").and_then(|v| v.as_str()).unwrap_or("worker");
                    let display = m.get("display_name").and_then(|v| v.as_str()).unwrap_or(email);
                    if !email.is_empty() {
                        let member = Member {
                            email: email.to_string(),
                            role: role.to_string(),
                            display_name: display.to_string(),
                            board_id: board_id.clone(),
                            joined_at: Some(chrono::Utc::now().to_rfc3339()),
                            domains: None,
                            capability_snapshot: None,
                        };
                        db::add_member(&conn, &member).ok();
                    }
                }
            }

            // Validate: sender must be an owner member
            let sender_is_owner = db::get_member(&conn, &board_id, &sender)
                .ok().flatten()
                .map(|m| m.role == "owner")
                .unwrap_or(false);
            if !sender_is_owner {
                tracing::warn!("[a2a_board] [A2A] new rejected: sender {} is not an owner", sender);
                return crate::core::strategy::InterceptorDecision::PassThrough;
            }

            // Seed default role_permissions
            // Parse role_permissions from body if provided (override defaults)
            if let Some(permissions) = params.as_ref()
                .and_then(|p| p.get("role_permissions"))
                .and_then(|v| v.as_array())
            {
                let perms: Vec<(String, Vec<String>)> = permissions
                    .iter()
                    .filter_map(|entry| {
                        let role = entry.get("role")?.as_str()?.to_string();
                        let verbs: Vec<String> = entry.get("verbs")?
                            .as_array()?.iter()
                            .filter_map(|v| v.as_str().map(String::from))
                            .collect();
                        Some((role, verbs))
                    })
                    .collect();
                db::insert_role_permissions(&conn, &board_id, &perms).ok();
            }
            if let Err(e) = seed_default_role_permissions_conn(&conn) {
                tracing::warn!("[a2a_board] [create] role_permissions seed failed: {:?}", e);
            }

            // Send team initialization notification to all members
            {
                let members_list: Vec<String> = members.map(|arr| arr.iter().filter_map(|m| {
                    let email = m.get("email").and_then(|v| v.as_str()).unwrap_or("");
                    let role = m.get("role").and_then(|v| v.as_str()).unwrap_or("");
                    let display = m.get("display_name").and_then(|v| v.as_str()).unwrap_or(email);
                    if email.is_empty() { None } else { Some(format!("  {} ({}) — {}", display, email, role)) }
                }).collect()).unwrap_or_default();

                let notify_body = format!(
                    "项目: {} ({})
Board Email: {}
Board ID: {}

团队成员:
{}

请将团队成员的邮件地址加入你的联系人中。",
                    short_id,
                    description,
                    board_email,
                    board_id,
                    members_list.join("
"),
                );
                let notify_subject = format!("[A2A] notice: Board {} created — {}", short_id, description.clone());

                if let Some(all_members) = members {
                    for m in all_members {
                        let email = m.get("email").and_then(|v| v.as_str()).unwrap_or("");
                        if !email.is_empty() {
                            let _ = self.email_factory.create_outbound(
                                &format!("a2a-init-notify-{}", uuid::Uuid::new_v4()),
                                &self.system_id,
                                &format!("{} <{}>", short_id, board_email),
                                email,
                                &notify_subject,
                                &notify_body,
                                None, None, None, 3,
                            ).await;
                        }
                    }
                }
            }

            // Inject board context for downstream (B flow)
            let member_role = payload["from"].as_str().and_then(|sender| {
                db::get_member(&conn, &board_id, sender).ok().flatten()
                    .map(|m| m.role)
            }).unwrap_or_else(|| "owner".to_string());

            payload["board_id"] = serde_json::json!(board_id);
            payload["board_role"] = serde_json::json!(member_role);

            tracing::info!(
                "[a2a_board] [A2A] new board created: short_id={} board_id={}",
                short_id, board_id
            );

            return crate::core::strategy::InterceptorDecision::PassThrough;
            }
        }

        // Try to resolve board from the 'to' address (existing flow)
        let (short_id, board_id, _domain) = match self.resolve_board(&to_addr) {
            Some(r) => r,
            None => return crate::core::strategy::InterceptorDecision::PassThrough,
        };

        // Open board DB
        let conn = match db::open_board_db(&self.storage_path, &board_id) {
            Ok(c) => c,
            Err(_) => return crate::core::strategy::InterceptorDecision::PassThrough,
        };

        // ── A 流: [A2A] prefix → Rust 闭环 ──
        if let Some(rest) = subject.strip_prefix("[A2A] ") {
            let verb = rest.split_whitespace().next().unwrap_or("").to_string();
            // Only A类 verbs forward attachments; B类 clear
            let carry_verbs = ["complete", "output", "comment", "create", "arbitrate"];
            let attachments_json: Option<String> = if carry_verbs.contains(&verb.as_str()) {
                raw_attachments_json.clone()
            } else {
                None
            };
            let task_id = rest.split_whitespace().nth(1).map(|s| s.to_string());

            // Parse optional params from body (JSON body or inline)
            let body = payload["body"].as_str().unwrap_or("");
            let params: Option<Value> = serde_json::from_str(body).ok().or_else(|| {
                Some(serde_json::json!({"body": body}))
            });

            // Get or create board record
            let board = match db::get_board(&conn, &board_id) {
                Ok(b) => b,
                Err(_) => {
                    // Auto-create board record if not exists (for init command)
                    let ts = chrono::Utc::now().to_rfc3339();
                    let board = Board {
                        id: board_id.clone(),
                        short_id: short_id.clone(),
                        board_email: format!("{}.a2a@{}", short_id, self.gateway_domain),
                        description: None,
                        status: BoardStatus::Active,
                        output_task_id: None,
                        plan_version: None,
            plan_text: None,
                        plan_confirmed_at: None,
                        criteria_version: None,
            criteria_text: None,
            criteria_confirmed_at: None,
                        gateway_url: self.gateway_url.clone(),
                        created_at: ts,
                        completed_at: None,
                    };
                    let _ = db::create_board(&conn, &board);
                    board
                }
            };

            let notifier = Notifier {
                email_factory: Some(self.email_factory.clone()),
                system_id: self.system_id.clone(),
                board_short_id: board.short_id.clone(),
                board_email: board.board_email.clone(),
                board_id: board.id.clone(),
                gateway_domain: self.gateway_domain.clone(),
                attachments_json: attachments_json.clone(),
                tasks: RefCell::new(Vec::new()),
            };

            // Auto-inject board_id into params so commands don't need it in body
            // ── Inject attachments from SMTP payload into command params ──
            let mut params = params;
            if let Some(ref mut p) = params {
                if p.get("board_id").is_none() {
                    p["board_id"] = Value::String(board_id.clone());
                }
                // Inject attachments_json for complete/output handlers
                if let Some(attachments) = payload.get("attachments") {
                    if p.get("_attachments").is_none() {
                        p["_attachments"] = attachments.clone();
                    }
                }
            }

            let cmd = A2aCommand {
                verb,
                task_id,
                params,
            };

            match commands::execute_command(&conn, &notifier, &cmd, &sender) {
                Ok(response) => {
                    tracing::info!(
                        "[a2a_board] command executed: verb={} sender={} status={}",
                        cmd.verb, sender, response.status
                    );
                    // Await notification tasks spawned by the command
                    let tasks = notifier.take_tasks();
                    for task in tasks {
                        let _ = task.await;
                    }
                }
                Err(e) => {
                    tracing::warn!(
                        "[a2a_board] command failed: verb={} sender={} error={:?}",
                        cmd.verb, sender, e
                    );
                    // TODO: send SMTP error reply to sender
                }
            }

            return crate::core::strategy::InterceptorDecision::Handled;
        }

        // ── Human 审批: TO 含 board 地址 + [Confirm] → 更新 board 属性 ──
        {
            let to_list = payload["to"].as_array().cloned().unwrap_or_default();
            let mut board_in_to = None;
            for addr in &to_list {
                if let Some(a) = addr.as_str() {
                    if let Some((_sid, bid, _dom)) = self.resolve_board(a) {
                        board_in_to = Some(bid);
                        break;
                    }
                }
            }

            if let Some(bid) = board_in_to {
                let subject_lower = subject.to_lowercase();
                // [Confirm] plan v{N}  or  [Confirm] criteria v{N}
                if let Some(rest) = subject_lower.strip_prefix("[confirm] ") {
                    let rest = rest.trim();
                    if let Some((_board, params)) = rest.split_once(' ') {
                        let params = params.trim();
                        if let Some((type_, ver)) = params.split_once(' ') {
                            let ver = ver.trim_start_matches('v');
                            if let Ok(bconn) = db::open_board_db(&self.storage_path, &bid) {
                                if type_ == "plan" {
                                    let now = chrono::Utc::now().to_rfc3339();
                                    let body = payload["body"].as_str().unwrap_or("");
                                    bconn.execute(
                                        "UPDATE boards SET plan_version = ?1, plan_text = ?2, plan_confirmed_at = ?3 WHERE id = ?4",
                                        rusqlite::params![ver, body, now, bid],
                                    ).ok();
                                    tracing::info!("[a2a_board] plan approved: board={} version={}", bid, ver);
                                } else if type_ == "criteria" {
                                    let now = chrono::Utc::now().to_rfc3339();
                                    let body = payload["body"].as_str().unwrap_or("");
                                    bconn.execute(
                                        "UPDATE boards SET criteria_version = ?1, criteria_text = ?2, criteria_confirmed_at = ?3 WHERE id = ?4",
                                        rusqlite::params![ver, body, now, bid],
                                    ).ok();
                                    tracing::info!("[a2a_board] criteria approved: board={} version={}", bid, ver);
                                } else if type_ == "output" {
                                    let now = chrono::Utc::now().to_rfc3339();
                                    bconn.execute(
                                        "UPDATE boards SET status = ?1, completed_at = ?2 WHERE id = ?3",
                                        rusqlite::params!["completed", now, bid],
                                    ).ok();
                                    tracing::info!("[a2a_board] output confirmed: board={} status=completed", bid);
                                }
                            }
                        }
                    }
                }

                // Also inject session context (like normal session flow)
                if let Ok(bconn) = db::open_board_db(&self.storage_path, &bid) {
                    let from_member = db::get_member(&bconn, &bid, &sender).ok().flatten();
                    if let Some(fm) = from_member {
                        payload["board_id"] = Value::String(bid.clone());
                        payload["board_role"] = Value::String(fm.role.clone());
                        payload["from_role"] = Value::String(fm.role.clone());
                    }
                }
                return crate::core::strategy::InterceptorDecision::PassThrough;
            }
        }

        // ── 会话流: CC 含 board 地址 + FROM/TO 均为 member → 注入身份 ──
        {
            let cc_list = payload["cc"].as_array().cloned().unwrap_or_default();
            let mut detected_board = None;
            for cc in &cc_list {
                if let Some(cc_addr) = cc.as_str() {
                    if let Some((_sid, bid, _dom)) = self.resolve_board(cc_addr) {
                        detected_board = Some(bid);
                        break;
                    }
                }
            }

            if let Some(bid) = detected_board {
                if let Ok(bconn) = db::open_board_db(&self.storage_path, &bid) {
                    let from_member = db::get_member(&bconn, &bid, &sender).ok().flatten();
                    let to_member = db::get_member(&bconn, &bid, &to_addr).ok().flatten();
                    let from_ok = from_member.is_some();
                    let to_ok = to_member.is_some();

                    if from_ok && to_ok {
                        let fm = from_member.unwrap();
                        let tm = to_member.unwrap();
                        let bid_dbg = bid.clone();
                        let from_dbg = fm.role.clone();
                        let to_dbg = tm.role.clone();
                        payload["board_id"] = Value::String(bid);
                        payload["board_role"] = Value::String(tm.role);
                        payload["from_role"] = Value::String(fm.role);
                        tracing::debug!(
                            "[a2a_board] session flow: board_id={} from={}({}) to={}({})",
                            bid_dbg, sender, from_dbg, to_addr, to_dbg
                        );
                    } else {
                        tracing::debug!(
                            "[a2a_board] session flow skipped: from_ok={} to_ok={}",
                            from_ok, to_ok
                        );
                    }
                }
            }
        }

        // ── 会话流 fallback: X-Board-* headers (outbound external path) ──
        crate::core::strategy::InterceptorDecision::PassThrough
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use crate::board::models::parse_board_email;

    #[test]
    fn test_resolve_board_valid_address() {
        let result = parse_board_email("pgmig001.a2a@mail.hermes.io");
        assert!(result.is_some());
        let (short_id, board_id, domain) = result.unwrap();
        assert_eq!(short_id, "pgmig001");
        assert_eq!(domain, "mail.hermes.io");
        assert_eq!(board_id.len(), 20);
    }

    #[test]
    fn test_resolve_board_invalid_suffix() {
        assert!(parse_board_email("pgmig001@mail.hermes.io").is_none());
    }

    #[test]
    fn test_resolve_board_no_at() {
        assert!(parse_board_email("invalid").is_none());
    }

    #[test]
    fn test_resolve_board_empty() {
        assert!(parse_board_email("").is_none());
    }

    #[test]
    fn test_interceptor_name() {
        let interceptor = A2aInterceptor::new(
            Arc::new(unsafe { std::mem::zeroed() }), // 测试中不使用
            "test", "", "", "",
        );
        assert_eq!(interceptor.name(), "A2aInterceptor");
    }

    #[test]
    fn test_interceptor_priority() {
        let interceptor = A2aInterceptor::new(
            Arc::new(unsafe { std::mem::zeroed() }),
            "test", "", "", "",
        );
        assert_eq!(interceptor.priority(), 20);
    }

    #[test]
    fn test_new_interceptor_creates() {
        let interceptor = A2aInterceptor::new(
            Arc::new(unsafe { std::mem::zeroed() }),
            "sys01",
            "/tmp/storage",
            "mail.hermes.io",
            "https://gw.hermes.io",
        );
        assert_eq!(interceptor.system_id, "sys01");
        assert_eq!(interceptor.storage_path, "/tmp/storage");
        assert_eq!(interceptor.gateway_domain, "mail.hermes.io");
        assert_eq!(interceptor.gateway_url, "https://gw.hermes.io");
    }
}

/// Register the A2A interceptor on the given email factory.
/// Call this once during server startup.
pub fn register(
    email_factory: &std::sync::Arc<crate::core::email::factory::EmailFactory>,
    attachment_factory: &std::sync::Arc<AttachmentFactory>,
    storage_path: &str,
    system_id: &str,
    gateway_domain: &str,
    gateway_url: &str,
) {
    use crate::core::strategy::InboundInterceptor;
    let a2a = std::sync::Arc::new(A2aInterceptor::new(
        email_factory.clone(),
        attachment_factory.clone(),
        system_id,
        storage_path,
        gateway_domain,
        gateway_url,
    ));
    email_factory.env_factory.register_interceptor(a2a as std::sync::Arc<dyn InboundInterceptor>);

}
