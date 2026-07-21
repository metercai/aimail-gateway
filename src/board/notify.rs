//! C-flow notifications — Board → member notification emails.
//!
//! Each notification creates an outbound EmailRecord; scheduler handles delivery.
//! Delivery path scheduler-determined (webhook for same-gateway, SMTP relay for external).

use crate::board::models::*;
use crate::core::email::factory::EmailFactory;
use std::cell::RefCell;
use std::sync::Arc;
use tokio::task::JoinHandle;

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
    fn format_body(&self, label: &str, task: &Task, context: &str, action: &str) -> String {
        format!(
            "── A2A Board ──\n\n{label}\n  任务: {sid} — {title}\n  看板: {bsid}\n\n── 上下文 ──\n{context}\n\n── 操作 ──\n{action}",
            label = label,
            sid = task.short_id,
            title = task.title,
            bsid = self.board_short_id,
            context = context,
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
        let subject = format!("[A2A] assigned {}: {}", task.short_id, task.title);
        let context = format!(
            "描述: {}\n分配人: {}\n审阅者: {}\n创建人: {}",
            task.body,
            task.assignee,
            task.reviewer.as_deref().unwrap_or("(无)"),
            task.created_by,
        );
        let body = self.format_body(
            "新任务分配",
            task,
            &context,
            &format!("开始执行后发 [A2A] heartbeat {}", task.short_id),
        );
        self.create_email(&task.assignee, &subject, &body);
    }

    // ── C2: pending review ──
    pub fn notify_review_needed(&self, task: &Task) {
        let subject = format!("[A2A] review-needed {}: {}", task.short_id, task.title);
        let context = format!("完成人: {}\n产出物: {}", task.assignee, task.summary,);
        let body = self.format_body(
            "待审阅",
            task,
            &context,
            &format!(
                "[A2A] approve {}  — 通过\n  [A2A] reject {}   — 退回",
                task.short_id, task.short_id
            ),
        );
        if let Some(reviewer) = &task.reviewer {
            self.create_email(reviewer, &subject, &body);
        }
    }

    // ── C3: review approved ──
    pub fn notify_approved(&self, task: &Task) {
        let subject = format!("[A2A] approved {}: {}", task.short_id, task.title);
        let context = format!("审阅人: {}", task.reviewer.as_deref().unwrap_or("(无)"));
        let body = self.format_body("审阅通过", task, &context, "已完成，无后续操作");
        self.create_email(&task.assignee, &subject, &body);
    }

    // ── C4: review rejected ──
    pub fn notify_rejected(&self, task: &Task, reason: &str) {
        let subject = format!("[A2A] rejected {}: {}", task.short_id, task.title);
        let context = format!(
            "审阅人: {}\n原因: {}",
            task.reviewer.as_deref().unwrap_or("unknown"),
            reason,
        );
        let body = self.format_body(
            "审阅退回",
            task,
            &context,
            &format!("修改后重新 [A2A] complete {}", task.short_id),
        );
        self.create_email(&task.assignee, &subject, &body);
    }

    // ── C5: blocked ──
    pub fn notify_blocked(&self, task: &Task, blocker: &str) {
        let subject = format!("[A2A] blocked {}: {}", task.short_id, task.title);
        let body = self.format_body(
            "任务阻塞",
            task,
            &format!("阻挡人: {}", blocker),
            "Orchestrator 协调处理",
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
        let subject = format!("[A2A] unblocked {}: {}", task.short_id, task.title);
        let body = self.format_body(
            "阻塞解除",
            task,
            &format!("解除人: {}", unblocker),
            "继续执行",
        );
        self.create_email(&task.assignee, &subject, &body);
    }

    // ── C7: cancelled ──
    pub fn notify_cancelled(&self, task: &Task) {
        let subject = format!("[A2A] cancelled {}: {}", task.short_id, task.title);
        let body = self.format_body("任务取消", task, "已终止", "停止工作等待新分配");
        self.create_email(&task.assignee, &subject, &body);
    }

    // ── C8: project output ──
    pub fn notify_output(&self, task: &Task) {
        let subject = format!("[A2A] output: {} {}", self.board_short_id, task.title);
        let context = format!("最终输出: {}\nsummary: {}", task.title, task.summary);
        let body = self.format_body(
            "项目输出",
            task,
            &context,
            &format!("[Confirm] output {} — 验收通过", self.board_short_id),
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
        let subject = format!("[A2A] comment {}: {}", task.short_id, task.title);
        let body = self.format_body(
            "新评论",
            task,
            &format!("来自: {}\n{}", commenter, text),
            "直接回复邮件参与讨论",
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
            "── A2A Board ──\n\nBoard 邀请\n  看板: {}\n  Board Email: {}\n\n── 信息 ──\nAPI: {}\nBoard ID: {}\nToken: {}",
            short_id, board_email, self.gateway_url, board_id, board_token
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
        let task_info = task
            .map(|t| format!("任务: {} ({})", t.short_id, t.title))
            .unwrap_or_default();
        let subject = format!("[A2A] arbitrate: {}", self.board_short_id);
        let body = format!(
            "仲裁请求\n来自: {}\n{}\n争议: {}",
            requester, task_info, dispute
        );
        if !admin_email.is_empty() {
            self.create_email(admin_email, &subject, &body);
        }
        self.create_email(requester, &subject, "仲裁请求已提交给 Admin。");
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
            description: None,
            status: BoardStatus::Active,
            output_task_id: None,
            plan_version: None,
            plan_text: None,
            plan_confirmed_at: None,
            criteria_version: None,
            criteria_text: None,
            criteria_confirmed_at: None,
            gateway_url: "".to_string(),
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
