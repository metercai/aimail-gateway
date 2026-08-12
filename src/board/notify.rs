//! C-flow notifications — Board → member notification emails.
//!
//! Each notification creates an outbound EmailRecord; scheduler handles delivery.
//! Delivery path scheduler-determined (webhook for same-gateway, SMTP relay for external).

use crate::board::models::*;
use crate::core::email::factory::EmailFactory;
use std::cell::RefCell;
use std::sync::Arc;
use tokio::task::JoinHandle;

/// Detect if text contains CJK characters.
fn has_cjk(text: &str) -> bool {
    text.chars()
        .any(|c| matches!(c, '\u{4e00}'..='\u{9fff}' | '\u{3000}'..='\u{303f}' | '\u{ff00}'..='\u{ffef}'))
}

/// Return `cn` if the task's subject or body contains Chinese, otherwise `en`.
fn t<'a>(task: &Task, cn: &'a str, en: &'a str) -> &'a str {
    if has_cjk(&task.title) || has_cjk(&task.body) {
        cn
    } else {
        en
    }
}

pub struct Notifier {
    pub email_factory: Option<Arc<EmailFactory>>,
    pub system_id: String,
    pub board_short_id: String,
    pub board_email: String,
    pub board_id: String,
    pub gateway_domain: String,
    pub gateway_url: String,
    pub board_db_path: String,
    pub attachments_json: Option<String>,
    pub tasks: RefCell<Vec<JoinHandle<()>>>,
}

impl Notifier {
    /// Collect all spawned notification tasks for awaiting.
    pub fn take_tasks(&self) -> Vec<JoinHandle<()>> {
        self.tasks.borrow_mut().drain(..).collect()
    }
    fn format_body(&self, cn: bool, label: &str, task: &Task, context: &str, action: &str) -> String {
        let (task_l, board_l, ctx_l, act_l) = if cn {
            ("任务", "看板", "上下文", "操作")
        } else {
            ("Task", "Board", "Context", "Action")
        };
        format!(
            "── A2A Board ──\n\n{label}\n  {task_l}: {sid} — {title}\n  {board_l}: {bsid}\n\n── {ctx_l} ──\n{context}\n\n── {act_l} ──\n{action}",
            label = label,
            task_l = task_l,
            sid = task.short_id,
            title = task.title,
            board_l = board_l,
            bsid = self.board_short_id,
            ctx_l = ctx_l,
            context = context,
            act_l = act_l,
            action = action,
        )
    }

    fn create_email(&self, to: &str, subject: &str, body: &str) {
        let factory = match &self.email_factory {
            Some(f) => f.clone(),
            None => {
                tracing::info!(
                    "[a2a_board] notification (no factory): to={} subject={}",
                    to,
                    subject
                );
                return;
            }
        };
        let sender = self.board_email.clone();
        let email_id = format!("a2a_{}_{}", &self.board_id[..8], uuid::Uuid::new_v4());
        let sid = self.system_id.clone();
        let to = to.to_string();
        let subject = subject.to_string();
        let body = body.to_string();
        let is_internal = to.contains(&format!("@{}", self.gateway_domain));
        let attachments = self.attachments_json.clone();
        let handle = tokio::spawn(async move {
            let result = if is_internal {
                factory
                    .create_inbound(
                        &email_id, &sid, &sender, &to, &subject, &body, None, None, None, 3,
                    )
                    .await
            } else {
                factory
                    .create_outbound(
                        &email_id,
                        &sid,
                        &sender,
                        &to,
                        &subject,
                        &body,
                        None,
                        attachments.as_deref(),
                        None,
                        3,
                    )
                    .await
            };
            if let Err(e) = result {
                tracing::error!(
                    "[a2a_board] notify failed: to={} subject={} error={:?}",
                    to,
                    subject,
                    e
                );
            }
        });
        self.tasks.borrow_mut().push(handle);
    }

    fn create_email_to_all(&self, members: &[Member], subject: &str, body: &str) {
        for m in members {
            self.create_email(&m.email, subject, body);
        }
    }

    // ── C1: task assignment ──
    pub fn notify_assigned(&self, task: &Task) {
        let cn = has_cjk(&task.title) || has_cjk(&task.body);
        let subject = format!("[A2A] assigned {}: {}", task.short_id, task.title);
        let context = format!(
            "{}\n{}: {}\n{}: {}\n{}: {}",
            t(task, "描述", "Description"),
            t(task, "分配人", "Assignee"),
            task.assignee,
            t(task, "审阅者", "Reviewer"),
            task.reviewer.as_deref().unwrap_or(t(task, "(无)", "(none)")),
            t(task, "创建人", "Created by"),
            task.created_by,
        );
        let body = self.format_body(
            cn,
            t(task, "新任务分配", "New Task Assigned"),
            task,
            &context,
            &format!(
                "{} [A2A] heartbeat {}",
                t(task, "开始执行后发", "Send after starting:"),
                task.short_id,
            ),
        );
        self.create_email(&task.assignee, &subject, &body);
    }

    // ── C2: pending review ──
    pub fn notify_review_needed(&self, task: &Task) {
        let cn = has_cjk(&task.title) || has_cjk(&task.body);
        let subject = format!("[A2A] review-needed {}: {}", task.short_id, task.title);
        let context = format!("{}: {}\n{}: {}", t(task, "完成人", "Completed by"), task.assignee, t(task, "产出物", "Output"), task.summary);
        let body = self.format_body(
            cn,
            t(task, "待审阅", "Pending Review"),
            task,
            &context,
            &format!(
                "[A2A] approve {}  — {}\n  [A2A] reject {}   — {}",
                task.short_id, t(task, "通过", "Approve"),
                task.short_id, t(task, "退回", "Reject"),
            ),
        );
        if let Some(reviewer) = &task.reviewer {
            self.create_email(reviewer, &subject, &body);
        }
    }

    // ── C3: review approved ──
    pub fn notify_approved(&self, task: &Task) {
        let cn = has_cjk(&task.title) || has_cjk(&task.body);
        let subject = format!("[A2A] approved {}: {}", task.short_id, task.title);
        let context = format!("{}: {}", t(task, "审阅人", "Reviewer"), task.reviewer.as_deref().unwrap_or(t(task, "(无)", "(none)")));
        let body = self.format_body(cn, t(task, "审阅通过", "Approved"), task, &context, t(task, "已完成，无后续操作", "Completed, no further action"));
        self.create_email(&task.assignee, &subject, &body);
    }

    // ── C4: review rejected ──
    pub fn notify_rejected(&self, task: &Task, reason: &str) {
        let cn = has_cjk(&task.title) || has_cjk(&task.body);
        let subject = format!("[A2A] rejected {}: {}", task.short_id, task.title);
        let context = format!(
            "{}: {}\n{}: {}",
            t(task, "审阅人", "Reviewer"),
            task.reviewer.as_deref().unwrap_or("unknown"),
            t(task, "原因", "Reason"),
            reason,
        );
        let body = self.format_body(
            cn,
            t(task, "审阅退回", "Rejected"),
            task,
            &context,
            &format!("{} [A2A] complete {}", t(task, "修改后重新", "Revise and re-submit"), task.short_id),
        );
        self.create_email(&task.assignee, &subject, &body);
    }

    // ── C5: blocked ──
    pub fn notify_blocked(&self, task: &Task, blocker: &str) {
        let cn = has_cjk(&task.title) || has_cjk(&task.body);
        let subject = format!("[A2A] blocked {}: {}", task.short_id, task.title);
        let body = self.format_body(
            cn,
            t(task, "任务阻塞", "Task Blocked"),
            task,
            &format!("{}: {}", t(task, "阻挡人", "Blocker"), blocker),
            t(task, "Orchestrator 协调处理", "Orchestrator will coordinate"),
        );
        if let Ok(members) = crate::board::db::list_members(
            &crate::board::db::open_board_db(&self.board_db_path, &task.board_id).unwrap(),
            &task.board_id,
        ) {
            for m in &members {
                if m.role == "orchestrator" || m.email == blocker {
                    self.create_email(&m.email, &subject, &body);
                }
            }
        }
    }

    // ── C6: unblocked ──
    pub fn notify_unblocked(&self, task: &Task, unblocker: &str) {
        let cn = has_cjk(&task.title) || has_cjk(&task.body);
        let subject = format!("[A2A] unblocked {}: {}", task.short_id, task.title);
        let body = self.format_body(
            cn,
            t(task, "阻塞解除", "Unblocked"),
            task,
            &format!("{}: {}", t(task, "解除人", "Unblocked by"), unblocker),
            t(task, "继续执行", "Resume execution"),
        );
        self.create_email(&task.assignee, &subject, &body);
    }

    // ── C7: cancelled ──
    pub fn notify_cancelled(&self, task: &Task) {
        let cn = has_cjk(&task.title) || has_cjk(&task.body);
        let subject = format!("[A2A] cancelled {}: {}", task.short_id, task.title);
        let body = self.format_body(
            cn,
            t(task, "任务取消", "Task Cancelled"),
            task,
            t(task, "已终止", "Terminated"),
            t(task, "停止工作等待新分配", "Stop work, await re-assignment"),
        );
        self.create_email(&task.assignee, &subject, &body);
    }

    // ── C8: project output ──
    pub fn notify_output(&self, task: &Task) {
        let cn = has_cjk(&task.title) || has_cjk(&task.body);
        let subject = format!("[A2A] output: {} {}", self.board_short_id, task.title);
        let context = format!("{}: {}\nsummary: {}", t(task, "最终输出", "Final Output"), task.title, task.summary);
        let body = self.format_body(
            cn,
            t(task, "项目输出", "Project Output"),
            task,
            &context,
            &format!("[Confirm] output {} — {}", self.board_short_id, t(task, "验收通过", "Accepted")),
        );
        if let Ok(members) = crate::board::db::list_members(
            &crate::board::db::open_board_db("", &self.board_id).unwrap(),
            &self.board_id,
        ) {
            for m in &members {
                if m.role == "owner" {
                    self.create_email(&m.email, &subject, &body);
                }
            }
        }
    }

    // ── C9: comment ──
    pub fn notify_comment(&self, task: &Task, commenter: &str, text: &str) {
        let cn = has_cjk(&task.title) || has_cjk(&task.body);
        let subject = format!("[A2A] comment {}: {}", task.short_id, task.title);
        let body = self.format_body(
            cn,
            t(task, "新评论", "New Comment"),
            task,
            &format!("{}: {}\n{}", t(task, "来自", "From"), commenter, text),
            t(task, "直接回复邮件参与讨论", "Reply directly to join the discussion"),
        );
        let recipient = if commenter == task.assignee {
            task.reviewer.as_deref().unwrap_or("")
        } else {
            &task.assignee
        };
        if !recipient.is_empty() {
            self.create_email(recipient, &subject, &body);
        }
    }

    // ── C10: broadcast ──
    pub fn notify_all(&self, board_id: &str, message: &str) {
        let subject = format!("[A2A] notice: {} {}", self.board_short_id, message);
        if let Ok(members) = crate::board::db::list_members(
            &crate::board::db::open_board_db("", board_id).unwrap(),
            board_id,
        ) {
            self.create_email_to_all(&members, &subject, message);
        }
    }

    /// Send individual invite to a board member with token and gateway URL.
    pub fn notify_invite(
        &self,
        member_email: &str,
        board_token: &str,
        board_id: &str,
        board_email: &str,
        short_id: &str,
    ) {
        let body = format!(
            "── A2A Board ──\n\n{}\n  {}: {}\n  Board Email: {}\n\n── {} ──\nAPI: {}\nBoard ID: {}\nToken: {}",
            "Board Invitation",
            "Board",
            short_id,
            board_email,
            "Information",
            self.gateway_url,
            board_id,
            board_token,
        );
        let subject = format!("[A2A] invite: {}", short_id);
        self.create_email(member_email, &subject, &body);
    }

    // ── arbitration request ──
    pub fn notify_arbitrate(
        &self,
        task: Option<&Task>,
        requester: &str,
        admin_email: &str,
        dispute: &str,
    ) {
        let cn = task.map_or(false, |t| has_cjk(&t.title) || has_cjk(&t.body));
        let task_label = if cn { "任务" } else { "Task" };
        let task_info = task
            .map(|t| format!("{}: {} ({})", task_label, t.short_id, t.title))
            .unwrap_or_default();
        let subject = format!("[A2A] arbitrate: {}", self.board_short_id);
        let (arb_req, from, dispute_l, submitted) = if cn {
            ("仲裁请求", "来自", "争议", "仲裁请求已提交给 Admin。")
        } else {
            ("Arbitration Request", "From", "Dispute", "Arbitration request submitted to Admin.")
        };
        let body = format!(
            "{}\n{}: {}\n{}\n{}: {}",
            arb_req, from, requester, task_info, dispute_l, dispute
        );
        if !admin_email.is_empty() {
            self.create_email(admin_email, &subject, &body);
        }
        self.create_email(requester, &subject, submitted);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::board::models::*;

    fn make_board() -> Board {
        Board {
            id: "a3f8c21b9d4e73b2f0c1".to_string(),
            short_id: "pgmig001".to_string(),
            board_email: "pgmig001.a2a@test.io".to_string(),
            goal: None,
            status: BoardStatus::Active,
            output_task_id: None,
            plan_version: None,
            plan_text: None,
            plan_confirmed_at: None,
            criteria_version: None,
            criteria_text: None,
            criteria_confirmed_at: None,
            created_at: "2026-07-01T00:00:00Z".to_string(),
            completed_at: None,
        }
    }

    fn make_task() -> Task {
        Task {
            id: "t_T1_a3f8c21b".to_string(),
            short_id: "T1".to_string(),
            board_id: "a3f8c21b9d4e73b2f0c1".to_string(),
            title: "成本分析".to_string(),
            body: "对比 AWS/GCP 3年 TCO".to_string(),
            status: TaskStatus::Running,
            assignee: "worker@t.io".to_string(),
            reviewer: Some("veri@t.io".to_string()),
            parent_ids: vec![],
            tags: vec![],
            summary: "AWS cheaper by 15%".to_string(),
            metadata: None,
            created_by: "orch@t.io".to_string(),
            created_at: "2026-07-01T00:00:00Z".to_string(),
            updated_at: "2026-07-01T00:00:00Z".to_string(),
            completed_at: None,
            cancelled_at: None,
            deadline: None,
        }
    }

    #[test]
    fn test_notify_assigned_subject() {
        let board = make_board();
        let notifier = Notifier {
            board_db_path: "".to_string(),
            email_factory: None,
            system_id: "test".to_string(),
            board_short_id: board.short_id.clone(),
            board_email: board.board_email.clone(),
            board_id: board.id.clone(),
            gateway_domain: "test.io".to_string(),
            gateway_url: "".to_string(),
            attachments_json: None,
            tasks: RefCell::new(Vec::new()),
        };
        let task = make_task();
        // Just verify it doesn't panic (no email sent since factory is None)
        notifier.notify_assigned(&task);
    }

    #[test]
    fn test_notify_review_needed_subject() {
        let board = make_board();
        let notifier = Notifier {
            board_db_path: "".to_string(),
            email_factory: None,
            system_id: "test".to_string(),
            board_short_id: board.short_id.clone(),
            board_email: board.board_email.clone(),
            board_id: board.id.clone(),
            gateway_domain: "test.io".to_string(),
            gateway_url: "".to_string(),
            attachments_json: None,
            tasks: RefCell::new(Vec::new()),
        };
        let task = make_task();
        notifier.notify_review_needed(&task);
    }

    #[test]
    fn test_notify_approved_subject() {
        let board = make_board();
        let notifier = Notifier {
            board_db_path: "".to_string(),
            email_factory: None,
            system_id: "test".to_string(),
            board_short_id: board.short_id.clone(),
            board_email: board.board_email.clone(),
            board_id: board.id.clone(),
            gateway_domain: "test.io".to_string(),
            gateway_url: "".to_string(),
            attachments_json: None,
            tasks: RefCell::new(Vec::new()),
        };
        let task = make_task();
        notifier.notify_approved(&task);
    }

    #[test]
    fn test_notify_rejected_subject() {
        let board = make_board();
        let notifier = Notifier {
            board_db_path: "".to_string(),
            email_factory: None,
            system_id: "test".to_string(),
            board_short_id: board.short_id.clone(),
            board_email: board.board_email.clone(),
            board_id: board.id.clone(),
            gateway_domain: "test.io".to_string(),
            gateway_url: "".to_string(),
            attachments_json: None,
            tasks: RefCell::new(Vec::new()),
        };
        let task = make_task();
        notifier.notify_rejected(&task, "need more data");
    }

    #[test]
    fn test_notify_blocked_subject() {
        let board = make_board();
        let notifier = Notifier {
            board_db_path: "".to_string(),
            email_factory: None,
            system_id: "test".to_string(),
            board_short_id: board.short_id.clone(),
            board_email: board.board_email.clone(),
            board_id: board.id.clone(),
            gateway_domain: "test.io".to_string(),
            gateway_url: "".to_string(),
            attachments_json: None,
            tasks: RefCell::new(Vec::new()),
        };
        let task = make_task();
        notifier.notify_blocked(&task, "worker@t.io");
    }

    #[test]
    fn test_notify_unblocked_subject() {
        let board = make_board();
        let notifier = Notifier {
            board_db_path: "".to_string(),
            email_factory: None,
            system_id: "test".to_string(),
            board_short_id: board.short_id.clone(),
            board_email: board.board_email.clone(),
            board_id: board.id.clone(),
            gateway_domain: "test.io".to_string(),
            gateway_url: "".to_string(),
            attachments_json: None,
            tasks: RefCell::new(Vec::new()),
        };
        let task = make_task();
        notifier.notify_unblocked(&task, "orch@t.io");
    }

    #[test]
    fn test_notify_cancelled_subject() {
        let board = make_board();
        let notifier = Notifier {
            board_db_path: "".to_string(),
            email_factory: None,
            system_id: "test".to_string(),
            board_short_id: board.short_id.clone(),
            board_email: board.board_email.clone(),
            board_id: board.id.clone(),
            gateway_domain: "test.io".to_string(),
            gateway_url: "".to_string(),
            attachments_json: None,
            tasks: RefCell::new(Vec::new()),
        };
        let task = make_task();
        notifier.notify_cancelled(&task);
    }

    #[test]
    fn test_notify_comment_subject() {
        let board = make_board();
        let notifier = Notifier {
            board_db_path: "".to_string(),
            email_factory: None,
            system_id: "test".to_string(),
            board_short_id: board.short_id.clone(),
            board_email: board.board_email.clone(),
            board_id: board.id.clone(),
            gateway_domain: "test.io".to_string(),
            gateway_url: "".to_string(),
            attachments_json: None,
            tasks: RefCell::new(Vec::new()),
        };
        let task = make_task();
        notifier.notify_comment(&task, "veri@t.io", "looks good");
    }

    #[test]
    fn test_notify_comment_to_reviewer_when_assignee_comments() {
        let board = make_board();
        let notifier = Notifier {
            board_db_path: "".to_string(),
            email_factory: None,
            system_id: "test".to_string(),
            board_short_id: board.short_id.clone(),
            board_email: board.board_email.clone(),
            board_id: board.id.clone(),
            gateway_domain: "test.io".to_string(),
            gateway_url: "".to_string(),
            attachments_json: None,
            tasks: RefCell::new(Vec::new()),
        };
        let task = make_task();
        // assignee comments -> notification goes to reviewer
        notifier.notify_comment(&task, "worker@t.io", "please review");
    }

    #[test]
    fn test_notify_all_subject() {
        let board = make_board();
        let notifier = Notifier {
            board_db_path: "".to_string(),
            email_factory: None,
            system_id: "test".to_string(),
            board_short_id: board.short_id.clone(),
            board_email: board.board_email.clone(),
            board_id: board.id.clone(),
            gateway_domain: "test.io".to_string(),
            gateway_url: "".to_string(),
            attachments_json: None,
            tasks: RefCell::new(Vec::new()),
        };
        notifier.notify_all("a3f8c21b9d4e73b2f0c1", "test message");
    }

    #[test]
    fn test_notify_arbitrate_subject() {
        let board = make_board();
        let notifier = Notifier {
            board_db_path: "".to_string(),
            email_factory: None,
            system_id: "test".to_string(),
            board_short_id: board.short_id.clone(),
            board_email: board.board_email.clone(),
            board_id: board.id.clone(),
            gateway_domain: "test.io".to_string(),
            gateway_url: "".to_string(),
            attachments_json: None,
            tasks: RefCell::new(Vec::new()),
        };
        let task = make_task();
        notifier.notify_arbitrate(Some(&task), "veri@t.io", "admin@t.io", "dispute text");
    }
}
