//! a2a_board — A2A project collaboration board module.
//!
//! Provides:
//! - [A2A] email command processing (27 verbs, all Rust-closed-loop)
//! - board.db management (boards, members, tasks, events)
//! - C flow notifications (12 types — board/notify.rs is the source of truth)
//! - toolset HTTP API (6 endpoints — see core/api/http.rs board_routes)
//! - A2aInterceptor for inbound email processing

pub mod addr;
pub mod awareness;
pub mod commands;
pub mod db;
pub mod handlers;
pub mod interceptor;
pub mod models;
pub mod notify;
pub mod registry;
pub mod sweeper;
