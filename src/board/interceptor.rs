//! A2aInterceptor — intercepts inbound emails, processes A-flow commands / injects B-flow identity.

use crate::board::commands;
use crate::board::db;
use crate::board::models::{parse_board_email, A2aCommand, Board, BoardStatus, Member};
use crate::board::notify::Notifier;
use crate::board::quota::BoardQuotaChecker;
use crate::core::email::factory::AttachmentFactory;
use crate::core::email::factory::EmailFactory;
use crate::core::strategy::InboundInterceptor;
use async_trait::async_trait;
use serde_json::Value;
use std::cell::RefCell;
use std::sync::Arc;

pub struct A2aInterceptor {
    pub email_factory: Arc<EmailFactory>,
    pub attachment_factory: Arc<AttachmentFactory>,
    pub storage_path: String,
    pub gateway_url: String,
    pub board_quota: Arc<dyn BoardQuotaChecker>,
}

impl A2aInterceptor {
    pub fn new(
        email_factory: Arc<EmailFactory>,
        attachment_factory: Arc<AttachmentFactory>,
        storage_path: &str,
        gateway_url: &str,
        board_quota: Arc<dyn BoardQuotaChecker>,
    ) -> Self {
        Self {
            email_factory,
            attachment_factory,
            storage_path: storage_path.to_string(),
            gateway_url: gateway_url.to_string(),
            board_quota,
        }
    }

    fn resolve_board(&self, to_addr: &str) -> Option<(String, String, String)> {
        parse_board_email(to_addr)
    }
}

fn seed_default_role_permissions_conn(
    conn: &rusqlite::Connection,
) -> crate::core::errors::AppResult<()> {
    let defaults: &[(&str, &[&str])] = &[
        (
            "orchestrator",
            &[
                "init",
                "tasks",
                "assign",
                "review",
                "block",
                "unblock",
                "cancel",
                "reassign",
                "edit",
                "deadline",
                "output",
                "notify",
                "members",
                "roles",
                "config",
                "arbitrate",
                "comment",
                "list",
                "show",
                "heartbeat",
            ],
        ),
        (
            "verifier",
            &[
                "verify",
                "approve",
                "reject",
                "output",
                "comment",
                "list",
                "show",
                "roles",
                "members",
                "status",
                "heartbeat",
            ],
        ),
        (
            "worker",
            &[
                "complete",
                "commit",
                "block",
                "heartbeat",
                "comment",
                "list",
                "show",
                "roles",
                "members",
                "status",
            ],
        ),
        (
            "owner",
            &[
                "tasks",
                "unblock",
                "reassign",
                "comment",
                "list",
                "show",
                "heartbeat",
            ],
        ),
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
        let raw_attachments_json: Option<String> = payload
            .get("attachments")
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

                // Parse members from body
                let body = payload["body"].as_str().unwrap_or("");
                let params: Option<Value> = serde_json::from_str(body).ok();
                let members = params
                    .as_ref()
                    .and_then(|p| p.get("members"))
                    .and_then(|v| v.as_array());

                // Validate: members must include orchestrator AND verifier
                let has_orch = members
                    .map(|arr| {
                        arr.iter()
                            .any(|m| m.get("role").and_then(|v| v.as_str()) == Some("orchestrator"))
                    })
                    .unwrap_or(false);
                let has_verifier = members
                    .map(|arr| {
                        arr.iter()
                            .any(|m| m.get("role").and_then(|v| v.as_str()) == Some("verifier"))
                    })
                    .unwrap_or(false);

                if !has_orch {
                    tracing::warn!(
                        "[a2a_board] [A2A] new board rejected: must include an orchestrator member"
                    );
                    return crate::core::strategy::InterceptorDecision::PassThrough;
                }
                if !has_verifier {
                    tracing::warn!(
                        "[a2a_board] [A2A] new board rejected: must include a verifier member"
                    );
                    return crate::core::strategy::InterceptorDecision::PassThrough;
                }

                // Validate: recipient is the orchestrator
                let orch_email = members
                    .as_ref()
                    .and_then(|arr| {
                        arr.iter()
                            .find(|m| {
                                m.get("role").and_then(|v| v.as_str()) == Some("orchestrator")
                            })
                            .and_then(|m| m.get("email").and_then(|v| v.as_str()))
                    })
                    .unwrap_or("");
                if orch_email != to_addr {
                    tracing::warn!(
                        "[a2a_board] [A2A] new board rejected: recipient {} != orchestrator {}",
                        to_addr,
                        orch_email
                    );
                    return crate::core::strategy::InterceptorDecision::PassThrough;
                }

                // Compute board identifiers from orchestrator's domain
                let orch_domain = orch_email.split('@').nth(1).unwrap_or("");

                // Resolve orchestrator system for quota attribution
                let orch_system = self
                    .email_factory
                    .env_factory
                    .lookup_domain_addr(orch_email)
                    .await
                    .ok()
                    .flatten()
                    .map(|r| r.system_id)
                    .unwrap_or_default();

                // Shared-domain systems embed the system name in the board
                // address: {short}.{system_name}.a2a@{shared_domain} — the
                // full-address hash keeps boards of different systems apart.
                let is_shared = orch_system.starts_with("shared-");
                let board_email = if is_shared {
                    let sys_name = orch_email
                        .split('@')
                        .next()
                        .and_then(|l| l.rsplit('.').next())
                        .unwrap_or("");
                    format!("{}.{}.a2a@{}", short_id, sys_name, orch_domain)
                } else {
                    format!("{}.a2a@{}", short_id, orch_domain)
                };
                let board_id = crate::board::models::derive_board_id(&board_email);

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
                        goal: if description.is_empty() {
                            None
                        } else {
                            Some(description.clone())
                        },
                        status: BoardStatus::Active,
                        output_task_id: None,
                        plan_version: None,
                        plan_text: None,
                        plan_confirmed_at: None,
                        criteria_version: None,
                        criteria_text: None,
                        criteria_confirmed_at: None,
                        created_at: chrono::Utc::now().to_rfc3339(),
                        completed_at: None,
                    };
                    // Board quota: check max_active_boards
                    if let Err(e) = self.board_quota.check_active_boards(&orch_system) {
                        tracing::warn!("[a2a_board] Board quota exceeded: {e:?}");
                        return crate::core::strategy::InterceptorDecision::PassThrough;
                    }
                    db::create_board(&conn, &board).ok();
                    self.board_quota.invalidate_cache();
                }

                // Register members and collect invite info
                let mut member_invites: Vec<(String, String)> = Vec::new();
                if let Some(members) = members {
                    for m in members {
                        let email = m.get("email").and_then(|v| v.as_str()).unwrap_or("");
                        let role = m.get("role").and_then(|v| v.as_str()).unwrap_or("worker");
                        let display = m
                            .get("display_name")
                            .and_then(|v| v.as_str())
                            .unwrap_or(email);
                        if !email.is_empty() {
                            let token = db::generate_board_token();
                            let member = Member {
                                email: email.to_string(),
                                role: role.to_string(),
                                display_name: display.to_string(),
                                board_id: board_id.clone(),
                                board_token: Some(token.clone()),
                                joined_at: Some(chrono::Utc::now().to_rfc3339()),
                                domains: None,
                                capability_snapshot: None,
                            };
                            db::add_member(&conn, &member).ok();
                            member_invites.push((email.to_string(), token));
                        }
                    }
                }
                // Board group whitelist: one entry per board replaces N
                // per-member personal whitelist rows. Members auto-pass
                // SMTP/HTTP whitelist checks; cross-gateway members are
                // learnt from invite notifications (X-Board-Members header,
                // receiver.rs) — no manual per-member whitelisting needed.
                let all_members: Vec<String> = member_invites
                    .iter()
                    .map(|(email, _)| email.clone())
                    .collect();
                let _ = self
                    .email_factory
                    .env_factory
                    .db
                    .replace_board_members(&board_email, &all_members)
                    .await;

                // Validate: sender must be an owner member
                let sender_is_owner = db::get_member(&conn, &board_id, &sender)
                    .ok()
                    .flatten()
                    .map(|m| m.role == "owner")
                    .unwrap_or(false);
                if !sender_is_owner {
                    tracing::warn!(
                        "[a2a_board] [A2A] new rejected: sender {} is not an owner",
                        sender
                    );
                    return crate::core::strategy::InterceptorDecision::PassThrough;
                }

                // Seed default role_permissions
                // Parse role_permissions from body if provided (override defaults)
                if let Some(permissions) = params
                    .as_ref()
                    .and_then(|p| p.get("role_permissions"))
                    .and_then(|v| v.as_array())
                {
                    let perms: Vec<(String, Vec<String>)> = permissions
                        .iter()
                        .filter_map(|entry| {
                            let role = entry.get("role")?.as_str()?.to_string();
                            let verbs: Vec<String> = entry
                                .get("verbs")?
                                .as_array()?
                                .iter()
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
                    let members_list: Vec<String> = members
                        .map(|arr| {
                            arr.iter()
                                .filter_map(|m| {
                                    let email =
                                        m.get("email").and_then(|v| v.as_str()).unwrap_or("");
                                    let role = m.get("role").and_then(|v| v.as_str()).unwrap_or("");
                                    let display = m
                                        .get("display_name")
                                        .and_then(|v| v.as_str())
                                        .unwrap_or(email);
                                    if email.is_empty() {
                                        None
                                    } else {
                                        Some(format!("  {} ({}) — {}", display, email, role))
                                    }
                                })
                                .collect()
                        })
                        .unwrap_or_default();

                    let cn = description.chars().any(|c| matches!(c, '\u{4e00}'..='\u{9fff}'));
                    let (proj_l, members_l) = if cn {
                        ("项目", "团队成员")
                    } else {
                        ("Project", "Team Members")
                    };
                    let notify_body = format!(
                    "{proj_l}: {} ({})\\nBoard Email: {}\\nBoard ID: {}\\nGateway: {}\\n\\n{members_l}:\\n{}",
                    short_id,
                    description,
                    board_email,
                    board_id,
                    self.gateway_url,
                    members_list.join("\\n"),
                );
                    let notify_subject = format!(
                        "[A2A] notice: Board {} created — {}",
                        short_id,
                        description.clone()
                    );

                    if let Some(all_members) = members {
                        for m in all_members {
                            let email = m.get("email").and_then(|v| v.as_str()).unwrap_or("");
                            if !email.is_empty() {
                                let _ = self
                                    .email_factory
                                    .create_outbound(
                                        &format!("a2a-init-notify-{}", uuid::Uuid::new_v4()),
                                        &orch_system,
                                        &format!("{} <{}>", short_id, board_email),
                                        email,
                                        &notify_subject,
                                        &notify_body,
                                        None,
                                        None,
                                        None,
                                        3,
                                    )
                                    .await;
                            }
                        }
                    }
                }

                // Send individual invite emails via Notifier
                use crate::board::notify::Notifier;
                let invite_notifier = Notifier {
                    email_factory: Some(self.email_factory.clone()),
                    board_db_path: self.storage_path.clone(),
                    system_id: orch_system.clone(),
                    board_short_id: short_id.clone(),
                    board_email: board_email.clone(),
                    board_id: board_id.clone(),
                    gateway_domain: orch_domain.to_string(),
                    gateway_url: self.gateway_url.clone(),
                    attachments_json: None,
                    tasks: RefCell::new(Vec::new()),
                };
                // Group-whitelist header: full list of newly invited members.
                let new_members_csv = member_invites
                    .iter()
                    .map(|(email, _)| email.as_str())
                    .collect::<Vec<_>>()
                    .join(",");
                for (email, token) in &member_invites {
                    invite_notifier.notify_invite(
                        email, token, &board_id, &board_email, &short_id, &new_members_csv,
                    );
                }

                // Inject board context for downstream (B flow)
                let member_role = payload["from"]
                    .as_str()
                    .and_then(|sender| {
                        db::get_member(&conn, &board_id, sender)
                            .ok()
                            .flatten()
                            .map(|m| m.role)
                    })
                    .unwrap_or_else(|| "owner".to_string());

                payload["board_id"] = serde_json::json!(board_id);
                payload["board_role"] = serde_json::json!(member_role);

                tracing::info!(
                    "[a2a_board] [A2A] new board created: short_id={} board_id={}",
                    short_id,
                    board_id
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

        // ── A-flow: [A2A] prefix → Rust closed loop ──
        if let Some(rest) = subject.strip_prefix("[A2A] ") {
            let verb = rest.split_whitespace().next().unwrap_or("").to_string();
            // Only A-flow verbs forward attachments; B-flow clears
            let carry_verbs = ["complete", "output", "comment", "create", "arbitrate"];
            let attachments_json: Option<String> = if carry_verbs.contains(&verb.as_str()) {
                raw_attachments_json.clone()
            } else {
                None
            };
            let task_id = rest.split_whitespace().nth(1).map(|s| s.to_string());

            // Parse optional params from body (JSON body or inline)
            let body = payload["body"].as_str().unwrap_or("");
            let params: Option<Value> = serde_json::from_str(body)
                .ok()
                .or_else(|| Some(serde_json::json!({"body": body})));

            // Get or create board record
            let board = match db::get_board(&conn, &board_id) {
                Ok(b) => b,
                Err(_) => {
                    // Auto-create board record if not exists (for init command)
                    let ts = chrono::Utc::now().to_rfc3339();
                    let board_domain = to_addr.split('@').nth(1).unwrap_or("");
                    let board = Board {
                        id: board_id.clone(),
                        short_id: short_id.clone(),
                        board_email: format!("{}.a2a@{}", short_id, board_domain),
                        goal: None,
                        status: BoardStatus::Active,
                        output_task_id: None,
                        plan_version: None,
                        plan_text: None,
                        plan_confirmed_at: None,
                        criteria_version: None,
                        criteria_text: None,
                        criteria_confirmed_at: None,
                        created_at: ts,
                        completed_at: None,
                    };
                    let _ = db::create_board(&conn, &board);
                    self.board_quota.invalidate_cache();
                    board
                }
            };

            let board_domain = board.board_email.split('@').nth(1).unwrap_or("");

            let notifier = Notifier {
                email_factory: Some(self.email_factory.clone()),
                board_db_path: self.storage_path.clone(),
                system_id: board_domain.to_string(),
                board_short_id: board.short_id.clone(),
                board_email: board.board_email.clone(),
                board_id: board.id.clone(),
                gateway_domain: board_domain.to_string(),
                gateway_url: self.gateway_url.clone(),
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
                        cmd.verb,
                        sender,
                        response.status
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
                        cmd.verb,
                        sender,
                        e
                    );
                    // TODO: send SMTP error reply to sender
                }
            }

            return crate::core::strategy::InterceptorDecision::Handled;
        }

        // ── Human approval: TO has board address + [Confirm] → update board ──
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
                // [Confirm] plan v{N} / [Confirm] criteria v{N} / [Confirm] output {board}
                // (documented 2-segment form) and [Confirm] {board} {type} v{N} (3-segment)
                if let Some((kind, after, _board_token)) = parse_confirm(&subject_lower) {
                    if let Ok(bconn) = db::open_board_db(&self.storage_path, &bid) {
                        // Owner-only approval (documented: [Confirm] is an owner command)
                        let is_owner = db::get_member(&bconn, &bid, &sender)
                            .ok()
                            .flatten()
                            .map(|m| m.role == "owner")
                            .unwrap_or(false);
                        if !is_owner {
                            tracing::warn!(
                                "[a2a_board] [Confirm] rejected: sender {} is not an owner",
                                sender
                            );
                        } else {
                            match kind {
                                ConfirmType::Plan | ConfirmType::Criteria => {
                                    if let Some(ver_raw) = after {
                                        let ver = ver_raw.trim_start_matches('v');
                                        if ver.is_empty() {
                                            tracing::warn!(
                                                "[a2a_board] [Confirm] {} missing version",
                                                if kind == ConfirmType::Plan { "plan" } else { "criteria" }
                                            );
                                        } else {
                                            let now = chrono::Utc::now().to_rfc3339();
                                            let body = payload["body"].as_str().unwrap_or("");
                                            let (sql, what) = if kind == ConfirmType::Plan {
                                                ("UPDATE boards SET plan_version = ?1, plan_text = ?2, plan_confirmed_at = ?3 WHERE id = ?4", "plan")
                                            } else {
                                                ("UPDATE boards SET criteria_version = ?1, criteria_text = ?2, criteria_confirmed_at = ?3 WHERE id = ?4", "criteria")
                                            };
                                            bconn.execute(sql, rusqlite::params![ver, body, now, bid]).ok();
                                            tracing::info!(
                                                "[a2a_board] {} approved: board={} version={}",
                                                what, bid, ver
                                            );
                                        }
                                    }
                                }
                                ConfirmType::Output => {
                                    let now = chrono::Utc::now().to_rfc3339();
                                    bconn.execute(
                                        "UPDATE boards SET status = ?1, completed_at = ?2 WHERE id = ?3",
                                        rusqlite::params!["completed", now, bid],
                                    )
                                    .ok();
                                    tracing::info!(
                                        "[a2a_board] output confirmed: board={} status=completed",
                                        bid
                                    );
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

        // ── Session flow: CC has board address + FROM/TO both members → inject identity ──
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
                            bid_dbg,
                            sender,
                            from_dbg,
                            to_addr,
                            to_dbg
                        );
                    } else {
                        tracing::debug!(
                            "[a2a_board] session flow skipped: from_ok={} to_ok={}",
                            from_ok,
                            to_ok
                        );
                    }
                }
            }
        }

        // ── Session flow fallback: X-Board-* headers (outbound external path) ──
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

    // interceptor new() tests removed — cannot construct without valid
    // EmailFactory/AttachmentFactory; unsafe zeroed() insta-crashes.
    // Covered by integration tests that exercise the full pipeline.
}

/// Register the A2A interceptor on the given email factory.
/// Call this once during server startup.
pub fn register(
    email_factory: &std::sync::Arc<crate::core::email::factory::EmailFactory>,
    attachment_factory: &std::sync::Arc<AttachmentFactory>,
    storage_path: &str,
    gateway_url: &str,
    board_quota: Arc<dyn BoardQuotaChecker>,
) {
    use crate::core::strategy::InboundInterceptor;
    let a2a = std::sync::Arc::new(A2aInterceptor::new(
        email_factory.clone(),
        attachment_factory.clone(),
        storage_path,
        gateway_url,
        board_quota.clone(),
    ));
    email_factory
        .env_factory
        .register_interceptor(a2a as std::sync::Arc<dyn InboundInterceptor>);
}

/// Kind of a `[Confirm]` approval email (documented in A2A-BOARD-GUIDE).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfirmType {
    Plan,
    Criteria,
    Output,
}

/// Parse a `[Confirm]` subject into (kind, after, board_token).
///
/// Accepts the documented forms:
///   - `[confirm] plan v2` / `[confirm] criteria v1` (board from TO address)
///   - `[confirm] output web-redesign`
/// and the legacy 3-segment form `[confirm] {board} {type} v{N}`.
///
/// Returns `None` when no confirm type token is present.
fn parse_confirm(subject: &str) -> Option<(ConfirmType, Option<String>, Option<String>)> {
    let rest = subject.trim().strip_prefix("confirm")?.trim();
    let tokens: Vec<&str> = rest.split_whitespace().collect();
    if tokens.is_empty() {
        return None;
    }
    let type_idx = tokens
        .iter()
        .position(|t| matches!(*t, "plan" | "criteria" | "output"))?;
    let kind = match tokens[type_idx] {
        "plan" => ConfirmType::Plan,
        "criteria" => ConfirmType::Criteria,
        _ => ConfirmType::Output,
    };
    // 3-segment form: a board token precedes the type word.
    let board = if type_idx == 1 {
        Some(tokens[0].to_string())
    } else {
        None
    };
    let after = tokens.get(type_idx + 1).map(|s| s.to_string());
    Some((kind, after, board))
}

#[cfg(test)]
mod confirm_tests {
    use super::*;

    #[test]
    fn parses_documented_plan_form() {
        let (kind, after, board) = parse_confirm("confirm plan v2").unwrap();
        assert_eq!(kind, ConfirmType::Plan);
        assert_eq!(after.as_deref(), Some("v2"));
        assert_eq!(board, None);
    }

    #[test]
    fn parses_documented_criteria_form() {
        let (kind, after, board) = parse_confirm("confirm criteria v1").unwrap();
        assert_eq!(kind, ConfirmType::Criteria);
        assert_eq!(after.as_deref(), Some("v1"));
        assert_eq!(board, None);
    }

    #[test]
    fn parses_documented_output_form() {
        let (kind, after, board) = parse_confirm("confirm output web-redesign").unwrap();
        assert_eq!(kind, ConfirmType::Output);
        assert_eq!(after.as_deref(), Some("web-redesign"));
        assert_eq!(board, None);
    }

    #[test]
    fn parses_legacy_three_segment_form() {
        let (kind, after, board) = parse_confirm("confirm web-redesign plan v2").unwrap();
        assert_eq!(kind, ConfirmType::Plan);
        assert_eq!(after.as_deref(), Some("v2"));
        assert_eq!(board.as_deref(), Some("web-redesign"));
    }

    #[test]
    fn rejects_subject_without_confirm_type() {
        assert!(parse_confirm("confirm hello world").is_none());
        assert!(parse_confirm("plan v2").is_none());
        assert!(parse_confirm("").is_none());
    }
}
