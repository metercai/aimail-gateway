//! a2a_board — A2A project collaboration board module.
//!
//! Provides:
//! - [A2A] email command processing (19 verbs, all Rust-closed-loop)
//! - board.db management (boards, members, tasks, events)
//! - C flow notifications (10 types)
//! - toolset HTTP API (4 endpoints)
//! - A2aInterceptor for inbound email processing

pub mod archiver;
pub mod commands;
pub mod db;
pub mod handlers;
pub mod interceptor;
pub mod models;
pub mod notify;
pub mod quota;
pub mod router;
pub mod sweeper;
