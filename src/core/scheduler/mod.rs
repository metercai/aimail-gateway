//! Scheduler — email delivery orchestrator with retry, overlimit, and attachment-expiry flows.

pub mod backoff;
pub mod batch;
pub mod deliver;
pub mod exhaustion;
pub mod flows;

pub use entry::run_retry_worker_with_trigger;

mod entry;
