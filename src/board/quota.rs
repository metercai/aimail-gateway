//! Board quota checker trait. Core defines the interface; Advanced provides the impl.
//!
//! `check_active_boards` is `async` (not sync + `block_on`) because it is
//! invoked from the async interceptor path running on tokio worker threads —
//! a synchronous `block_on` there panics ("Cannot start a runtime from
//! within a runtime").

use crate::core::errors::AppResult;
use async_trait::async_trait;

/// Quota check interface for board operations.
#[async_trait]
pub trait BoardQuotaChecker: Send + Sync {
    async fn check_active_boards(&self, system_id: &str) -> AppResult<()>;
    /// Invalidate cached board count — called after board create or archive.
    fn invalidate_cache(&self) { /* default no-op */
    }
}

/// Default no-op: no limits.
pub struct NoopBoardQuota;

#[async_trait]
impl BoardQuotaChecker for NoopBoardQuota {
    async fn check_active_boards(&self, _system_id: &str) -> AppResult<()> {
        Ok(())
    }
}
