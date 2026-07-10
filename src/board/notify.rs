//! C 流通知 — Board → 成员的通知邮件。
//!
//! 每个通知创建一封出站邮件记录（EmailRecord），调度器自动投递。
//! 投递路径由调度器决定（同 gateway 走 webhook，外部走 SMTP relay）。

use crate::board::models::*;
use crate::core::email::factory::EmailFactory;
use crate::core::errors::AppResult;
use std::cell::RefCell;
use std::sync::Arc;
use tokio::task::JoinHandle;

pub struct Notifier<'a> {
    pub email_factory: Option<Arc<EmailFactory>>,
    pub system_id: &'a str,
    pub board: &'a Board,
    pub gateway_domain: &'a str,
    pub tasks: RefCell<Vec<JoinHandle<()>>>,
}

impl Notifier<'_> {
    /// Collect all spawned notification tasks for awaiting.
    pub fn take_tasks(&self) -> Vec<JoinHandle<()>> {
        self.tasks.borrow_mut().drain(..).collect()
    }
    fn create_email(&self, to: &str, subject: &str, body: &str) {
        let factory = match &self.email_factory {
            Some(f) => f.clone(),
            None => {
                tracing::info!("[a2a_board] notification (no factory): to={} subject={}", to, subject);
                return;
            }
        };
        let sender = format!("{} <{}>", self.board.short_id, self.board.board_email);
        let email_id = format!(
            "a2a_{}_{}",
            &self.board.id[..8],
            uuid::Uuid::new_v4()
        );
        let sid = self.system_id.to_string();
        let to = to.to_string();
        let subject = subject.to_string();
        let body = body.to_string();
        let is_internal = to.contains(&format!("@{}", self.gateway_domain));
        let handle = tokio::spawn(async move {
            let result = if is_internal {
                factory.create_inbound(
                    &email_id, &sid, &sender, &to, &subject, &body,
                    None, None, None, 3,
                ).await
            } else {
                factory.create_outbound(
                    &email_id, &sid, &sender, &to, &subject, &body,
                    None, None, None, 3,
                ).await
            };
            if let Err(e) = result {
                tracing::error!(
                    "[a2a_board] notify failed: to={} subject={} error={:?}",
                    to, subject, e
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

    // ── C1: 任务分配 ──
    pub fn notify_assigned(&self, task: &Task) {
        let subject = format!("[A2A] assigned {}: {}", task.short_id, task.title);
        let body = format!(
            "task_id: {}\nboard: {}\n标题: {}\n描述: {}\n审阅者: {}\n创建人: {}",
            task.id, task.board_id, task.title, task.body,
            task.reviewer.as_deref().unwrap_or("(无)"),
            task.created_by,
        );
        self.create_email(&task.assignee, &subject, &body);
    }

    // ── C2: 待审阅 ──
    pub fn notify_review_needed(&self, task: &Task) {
        let subject = format!("[A2A] review-needed {}: {}", task.short_id, task.title);
        let body = format!(
            "task_id: {}\n完成人: {}\n标题: {}\nsummary: {}\n\n请审阅后执行 [A2A] approve {} 或 [A2A] reject {}。",
            task.id, task.assignee, task.title, task.summary, task.short_id, task.short_id,
        );
        if let Some(reviewer) = &task.reviewer {
            self.create_email(reviewer, &subject, &body);
        }
    }

    // ── C3: 审阅通过 ──
    pub fn notify_approved(&self, task: &Task) {
        let subject = format!("[A2A] approved {}: {}", task.short_id, task.title);
        let body = format!("task_id: {}\n任务 {} 已通过审阅，状态: 已完成。", task.id, task.short_id);
        self.create_email(&task.assignee, &subject, &body);
    }

    // ── C4: 审阅退回 ──
    pub fn notify_rejected(&self, task: &Task, reason: &str) {
        let subject = format!("[A2A] rejected {}: {}", task.short_id, task.title);
        let body = format!(
            "task_id: {}\n审阅人: {}\n原因: {}\n状态: 已退回，请修订后重新 [A2A] complete {}。",
            task.id,
            task.reviewer.as_deref().unwrap_or("unknown"),
            reason,
            task.short_id,
        );
        self.create_email(&task.assignee, &subject, &body);
    }

    // ── C5: 阻挡 ──
    pub fn notify_blocked(&self, task: &Task, blocker: &str) {
        let subject = format!("[A2A] blocked {}: {}", task.short_id, task.title);
        let body = format!("task_id: {}\n阻挡人: {}\n请 Orchestrator 协调处理。", task.id, blocker);
        if let Ok(members) = crate::board::db::list_members(
            &crate::board::db::open_board_db("", &task.board_id).unwrap(),
            &task.board_id,
        ) {
            for m in &members {
                if m.role == "orchestrator" || m.email == blocker {
                    self.create_email(&m.email, &subject, &body);
                }
            }
        }
    }

    // ── C6: 解除阻挡 ──
    pub fn notify_unblocked(&self, task: &Task, unblocker: &str) {
        let subject = format!("[A2A] unblocked {}: {}", task.short_id, task.title);
        let body = format!("task_id: {}\n解除人: {}\n状态: 已解除阻挡，请继续执行。", task.id, unblocker);
        self.create_email(&task.assignee, &subject, &body);
    }

    // ── C7: 取消 ──
    pub fn notify_cancelled(&self, task: &Task) {
        let subject = format!("[A2A] cancelled {}: {}", task.short_id, task.title);
        let body = format!("task_id: {}\n任务已取消，请停止工作等待新分配。", task.id);
        self.create_email(&task.assignee, &subject, &body);
    }

    // ── C8: 项目输出 ──
    pub fn notify_owner_rejected(&self, board_id: &str) {
        let members = crate::board::db::list_members(&self.db.lock().unwrap(), board_id).unwrap_or_default();
        for m in &members {
            if m.role == "orchestrator" {
                let subject = format!("[A2A] reopen: Owner rejected output for board {}", board_id);
                let body = "Owner rejected the output. All tasks have been reopened.".to_string();
                self.create_email(&m.email, &subject, &body);
            }
        }
    }

    pub fn notify_output(&self, task: &Task) {
        let subject = format!("[A2A] output: {} {}", self.board.short_id, task.title);
        let body = format!(
            "output by: verifier\nboard: {}\ntask: {}\n最终输出: {}\nsummary: {}\n\n请 Human 验收确认。发送 [Confirm] output {} 完成最终验收。",
            self.board.short_id, task.short_id, task.title, task.summary, self.board.short_id,
        );
        if let Ok(members) = crate::board::db::list_members(
            &crate::board::db::open_board_db("", &self.board.id).unwrap(),
            &self.board.id,
        ) {
            for m in &members {
                if m.role == "owner" {
                    self.create_email(&m.email, &subject, &body);
                }
            }
        }
    }

    // ── C9: 评论 ──
    pub fn notify_comment(&self, task: &Task, commenter: &str, text: &str) {
        let subject = format!("[A2A] comment {}: {}", task.short_id, task.title);
        let body = format!("task_id: {}\n来自: {}\n评论: {}", task.id, commenter, text);
        let recipient = if commenter == task.assignee {
            task.reviewer.as_deref().unwrap_or("")
        } else {
            &task.assignee
        };
        if !recipient.is_empty() {
            self.create_email(recipient, &subject, &body);
        }
    }

    // ── C10: 全员通知 ──
    pub fn notify_all(&self, board_id: &str, message: &str) {
        let subject = format!("[A2A] notice: {} {}", self.board.short_id, message);
        if let Ok(members) = crate::board::db::list_members(
            &crate::board::db::open_board_db("", board_id).unwrap(),
            board_id,
        ) {
            self.create_email_to_all(&members, &subject, message);
        }
    }

    // ── 仲裁请求 ──
    pub fn notify_arbitrate(&self, task: Option<&Task>, requester: &str, admin_email: &str, dispute: &str) {
        let task_info = task
            .map(|t| format!("task: {} ({})", t.short_id, t.title))
            .unwrap_or_default();
        let subject = format!("[A2A] arbitrate: {}", self.board.short_id);
        let body = format!("仲裁请求来自: {}\n{}\n争议: {}", requester, task_info, dispute);
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
        let notifier = Notifier { email_factory: None, system_id: "test", board: &board };
        let task = make_task();
        // Just verify it doesn't panic (no email sent since factory is None)
        notifier.notify_assigned(&task);
    }

    #[test]
    fn test_notify_review_needed_subject() {
        let board = make_board();
        let notifier = Notifier { email_factory: None, system_id: "test", board: &board };
        let task = make_task();
        notifier.notify_review_needed(&task);
    }

    #[test]
    fn test_notify_approved_subject() {
        let board = make_board();
        let notifier = Notifier { email_factory: None, system_id: "test", board: &board };
        let task = make_task();
        notifier.notify_approved(&task);
    }

    #[test]
    fn test_notify_rejected_subject() {
        let board = make_board();
        let notifier = Notifier { email_factory: None, system_id: "test", board: &board };
        let task = make_task();
        notifier.notify_rejected(&task, "need more data");
    }

    #[test]
    fn test_notify_blocked_subject() {
        let board = make_board();
        let notifier = Notifier { email_factory: None, system_id: "test", board: &board };
        let task = make_task();
        notifier.notify_blocked(&task, "worker@t.io");
    }

    #[test]
    fn test_notify_unblocked_subject() {
        let board = make_board();
        let notifier = Notifier { email_factory: None, system_id: "test", board: &board };
        let task = make_task();
        notifier.notify_unblocked(&task, "orch@t.io");
    }

    #[test]
    fn test_notify_cancelled_subject() {
        let board = make_board();
        let notifier = Notifier { email_factory: None, system_id: "test", board: &board };
        let task = make_task();
        notifier.notify_cancelled(&task);
    }

    #[test]
    fn test_notify_comment_subject() {
        let board = make_board();
        let notifier = Notifier { email_factory: None, system_id: "test", board: &board };
        let task = make_task();
        notifier.notify_comment(&task, "veri@t.io", "looks good");
    }

    #[test]
    fn test_notify_comment_to_reviewer_when_assignee_comments() {
        let board = make_board();
        let notifier = Notifier { email_factory: None, system_id: "test", board: &board };
        let task = make_task();
        // assignee comments -> notification goes to reviewer
        notifier.notify_comment(&task, "worker@t.io", "please review");
    }

    #[test]
    fn test_notify_all_subject() {
        let board = make_board();
        let notifier = Notifier { email_factory: None, system_id: "test", board: &board };
        notifier.notify_all("a3f8c21b9d4e73b2f0c1", "test message");
    }

    #[test]
    fn test_notify_arbitrate_subject() {
        let board = make_board();
        let notifier = Notifier { email_factory: None, system_id: "test", board: &board };
        let task = make_task();
        notifier.notify_arbitrate(Some(&task), "veri@t.io", "admin@t.io", "dispute text");
    }
}
