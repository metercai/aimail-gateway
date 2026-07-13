//! a2a_board — A2A project collaboration board module.
//!
//! Provides:
//! - [A2A] email command processing (19 verbs, all Rust-closed-loop)
//! - board.db management (boards, members, tasks, events)
//! - C flow notifications (10 types)
//! - toolset HTTP API (4 endpoints)
//! - A2aInterceptor for inbound email processing

pub mod models;
pub mod db;
pub mod commands;
pub mod notify;
pub mod sweeper;
pub mod interceptor;
pub mod router;
pub mod handlers;
pub mod archiver;
