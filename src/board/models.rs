use serde::{Deserialize, Serialize};

// ── Board ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Board {
    pub id: String,
    pub short_id: String,
    pub board_email: String,
    pub description: Option<String>,
    pub status: BoardStatus,
    pub output_task_id: Option<String>,
    pub plan_version: Option<String>,
    pub plan_text: Option<String>,
    pub plan_confirmed_at: Option<String>,
    pub criteria_version: Option<String>,
    pub criteria_text: Option<String>,
    pub criteria_confirmed_at: Option<String>,
    pub gateway_url: String,
    pub created_at: String,
    pub completed_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum BoardStatus {
    #[serde(rename = "active")]
    Active,
    #[serde(rename = "awaiting_owner")]
    AwaitingOwner,
    #[serde(rename = "completed")]
    Completed,
    #[serde(rename = "archived")]
    Archived,
}

impl std::fmt::Display for BoardStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BoardStatus::Active => write!(f, "active"),
            BoardStatus::AwaitingOwner => write!(f, "awaiting_owner"),
            BoardStatus::Completed => write!(f, "completed"),
            BoardStatus::Archived => write!(f, "archived"),
        }
    }
}

// ── Member ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Member {
    pub email: String,
    pub role: String,
    pub display_name: String,
    pub board_id: String,
    pub joined_at: Option<String>,
    pub domains: Option<Vec<String>>,
    pub capability_snapshot: Option<String>,
}

// ── Task ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Task {
    pub id: String,
    pub short_id: String,
    pub board_id: String,
    pub title: String,
    pub body: String,
    pub status: TaskStatus,
    pub assignee: String,
    pub reviewer: Option<String>,
    pub parent_ids: Vec<String>,
    pub tags: Vec<String>,
    pub summary: String,
    pub metadata: Option<String>,
    pub created_by: String,
    pub created_at: String,
    pub updated_at: String,
    pub completed_at: Option<String>,
    pub cancelled_at: Option<String>,
    pub deadline: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum TaskStatus {
    #[serde(rename = "todo")]
    Todo,
    #[serde(rename = "ready")]
    Ready,
    #[serde(rename = "running")]
    Running,
    #[serde(rename = "reviewing")]
    Reviewing,
    #[serde(rename = "done")]
    Done,
    #[serde(rename = "blocked")]
    Blocked,
    #[serde(rename = "cancelled")]
    Cancelled,
}

impl std::fmt::Display for TaskStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TaskStatus::Todo => write!(f, "todo"),
            TaskStatus::Ready => write!(f, "ready"),
            TaskStatus::Running => write!(f, "running"),
            TaskStatus::Reviewing => write!(f, "reviewing"),
            TaskStatus::Done => write!(f, "done"),
            TaskStatus::Blocked => write!(f, "blocked"),
            TaskStatus::Cancelled => write!(f, "cancelled"),
        }
    }
}

// ── TaskEvent ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskEvent {
    pub id: i64,
    pub task_id: String,
    pub event_type: String,
    pub actor: String,
    pub payload: Option<serde_json::Value>,
    pub created_at: String,
}

// ── Command ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct A2aCommand {
    pub verb: String,
    pub task_id: Option<String>,
    pub params: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandResponse {
    pub status: String,
    pub task: Option<Task>,
    pub data: Option<serde_json::Value>,
    pub error: Option<String>,
}

// ── Create request ────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateBoardRequest {
    pub project_id: String,
    pub short_id: String,
    pub members: Vec<CreateMember>,
    pub board_email: String,
    pub gateway_url: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateMember {
    pub email: String,
    pub role: String,
    pub display_name: String,
}

// ── Helper: derive board_id from short_id + domain ────────────────────

pub fn derive_board_id(short_id: &str, gateway_domain: &str) -> String {
    use sha2::{Digest, Sha256};
    let input = format!("{}:{}", short_id.to_lowercase(), gateway_domain);
    let hash = Sha256::digest(input.as_bytes());
    hex::encode(&hash[..10])
}

/// Parse a board address like `xk9mp2q.a2a@mail.hermes.io` into (short_id, board_id, domain).

/// Sanitize short_id: filter to [a-zA-Z0-9_-], truncate to 16, pad to 5.
pub fn sanitize_short_id(raw: &str) -> String {
    let filtered: String = raw
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_')
        .take(16)
        .collect();
    if filtered.len() >= 5 {
        filtered
    } else {
        // Pad with random chars to reach 5
        let pad_len = 5 - filtered.len();
        let pad: String = (0..pad_len)
            .map(|_| {
                let idx = rand::random::<u8>() % 36;
                if idx < 10 {
                    (b'0' + idx) as char
                } else {
                    (b'a' + (idx - 10)) as char
                }
            })
            .collect();
        format!("{}{}", filtered, pad)
    }
}

#[cfg(test)]
mod sanitize_tests {
    use super::*;

    #[test]
    fn test_sanitize_short_id_normal() {
        assert_eq!(sanitize_short_id("my-project"), "my-project");
    }

    #[test]
    fn test_sanitize_too_long() {
        let result = sanitize_short_id("this-is-a-very-long-project-name");
        assert_eq!(result.len(), 16);
        assert!(result.starts_with("this-is-a-very-l"));
    }

    #[test]
    fn test_sanitize_too_short() {
        let result = sanitize_short_id("ab");
        assert_eq!(result.len(), 5);
        assert!(result.starts_with("ab"));
    }

    #[test]
    fn test_sanitize_invalid_chars() {
        let result = sanitize_short_id("web-redesign!!!@#$");
        assert_eq!(result, "web-redesign");
    }

    #[test]
    fn test_sanitize_empty() {
        let result = sanitize_short_id("");
        assert_eq!(result.len(), 5);
    }
}

pub fn parse_board_email(to_addr: &str) -> Option<(String, String, String)> {
    let (local, domain) = to_addr.split_once('@')?;
    let short_id = local.strip_suffix(".a2a")?;
    let board_id = derive_board_id(short_id, domain);
    Some((short_id.to_string(), board_id, domain.to_string()))
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_derive_board_id_deterministic() {
        let id1 = derive_board_id("pgmig001", "mail.hermes.io");
        let id2 = derive_board_id("pgmig001", "mail.hermes.io");
        assert_eq!(id1, id2, "同输入应产生相同 board_id");
        assert_eq!(id1.len(), 20, "board_id 应为 20 hex 字符");
    }

    #[test]
    fn test_derive_board_id_different_domain() {
        let id1 = derive_board_id("pgmig001", "mail.hermes.io");
        let id2 = derive_board_id("pgmig001", "mail.other.io");
        assert_ne!(id1, id2, "不同 domain 应产生不同 board_id");
    }

    #[test]
    fn test_derive_board_id_different_short_id() {
        let id1 = derive_board_id("pgmig001", "mail.hermes.io");
        let id2 = derive_board_id("costv2", "mail.hermes.io");
        assert_ne!(id1, id2, "不同 short_id 应产生不同 board_id");
    }

    #[test]
    fn test_derive_board_id_length() {
        let id = derive_board_id("test1234", "domain.com");
        assert_eq!(id.len(), 20, "board_id 应为 10 字节 = 20 hex 字符");
    }

    #[test]
    fn test_parse_board_email_valid() {
        let result = parse_board_email("pgmig001.a2a@mail.hermes.io");
        assert!(result.is_some(), "有效地址应解析成功");
        let (short_id, board_id, domain) = result.unwrap();
        assert_eq!(short_id, "pgmig001");
        assert_eq!(domain, "mail.hermes.io");
        assert_eq!(board_id.len(), 20);
    }

    #[test]
    fn test_parse_board_email_missing_a2a() {
        let result = parse_board_email("pgmig001@mail.hermes.io");
        assert!(result.is_none(), "缺少 .a2a 后缀应返回 None");
    }

    #[test]
    fn test_parse_board_email_no_at() {
        let result = parse_board_email("invalid");
        assert!(result.is_none(), "缺少 @ 应返回 None");
    }

    #[test]
    fn test_parse_board_email_empty() {
        let result = parse_board_email("");
        assert!(result.is_none(), "空字符串应返回 None");
    }

    #[test]
    fn test_parse_board_email_short_id_extraction() {
        let (short_id, _, _) = parse_board_email("xk9mp2q.a2a@gateway.io").unwrap();
        assert_eq!(short_id, "xk9mp2q");
    }

    #[test]
    fn test_board_status_display_active() {
        assert_eq!(BoardStatus::Active.to_string(), "active");
    }

    #[test]
    fn test_board_status_display_archived() {
        assert_eq!(BoardStatus::Archived.to_string(), "archived");
    }

    #[test]
    fn test_task_status_display() {
        assert_eq!(TaskStatus::Todo.to_string(), "todo");
        assert_eq!(TaskStatus::Ready.to_string(), "ready");
        assert_eq!(TaskStatus::Running.to_string(), "running");
        assert_eq!(TaskStatus::Reviewing.to_string(), "reviewing");
        assert_eq!(TaskStatus::Done.to_string(), "done");
        assert_eq!(TaskStatus::Blocked.to_string(), "blocked");
        assert_eq!(TaskStatus::Cancelled.to_string(), "cancelled");
    }
}
