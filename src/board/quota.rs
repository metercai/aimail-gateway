//! Board quota checker trait. Core defines the interface; Advanced provides the impl.

use crate::core::errors::AppResult;

/// Quota check interface for board operations.
pub trait BoardQuotaChecker: Send + Sync {
    fn check_active_boards(&self, system_id: &str) -> AppResult<()>;
    /// Invalidate cached board count — called after board create or archive.
    fn invalidate_cache(&self) { /* default no-op */
    }
}

/// Default no-op: no limits.
pub struct NoopBoardQuota;

impl BoardQuotaChecker for NoopBoardQuota {
    fn check_active_boards(&self, _system_id: &str) -> AppResult<()> {
        Ok(())
    }
}
