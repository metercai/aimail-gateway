// Base edition: no-op strategy implementations.
// Every trait method is a safe passthrough.

use async_trait::async_trait;

use crate::core::errors::{AppError, AppResult};

use std::sync::Arc;

use crate::board::quota::NoopBoardQuota;
use crate::core::strategy::{
    ExtensionProviders, MessageSigner, QuotaChecker, RouterHook, SystemStore,
};

// ── MessageSigner ──

pub struct BaseMessageSigner;

#[async_trait]
impl MessageSigner for BaseMessageSigner {
    async fn sign(&self, _raw: &[u8], _email_id: &str) -> Option<Vec<u8>> {
        None
    }
}

// ── QuotaChecker ──

pub struct BaseQuotaChecker;

#[async_trait]
impl QuotaChecker for BaseQuotaChecker {
    async fn check_send_quota(&self, _system_id: &str) -> Result<(), AppError> {
        Ok(())
    }
    async fn check_domain_quota(&self, _system_id: &str) -> Result<(), AppError> {
        Ok(())
    }
    async fn check_address_quota(&self, _system_id: &str) -> Result<(), AppError> {
        Ok(())
    }
}

// ── SystemStore ──

pub struct BaseSystemStore;

#[async_trait]
impl SystemStore for BaseSystemStore {
    async fn resolve_system(
        &self,
        _id: &str,
    ) -> AppResult<Option<crate::core::storage::SystemRecord>> {
        Ok(Some(crate::core::storage::SystemRecord {
            id: _id.into(),
            admin_email: "Admin".into(),
            limits_config: None,
            is_active: true,
            created_at: String::new(),
        }))
    }
}

// ── RouterHook ──

pub struct BaseRouterHook(pub crate::core::api::types::HttpState);

impl RouterHook for BaseRouterHook {
    fn mount(&self, router: axum::Router) -> axum::Router {
        let api_env_factory = self.0.factories.email.env_factory.clone();
        let batch = axum::Router::new()
            .route(
                "/api/v1/admin/activation-codes/batch",
                axum::routing::post(crate::core::api::activation::batch_generate_codes),
            )
            .with_state(self.0.clone())
            .route_layer(axum::middleware::from_fn(move |req, next| {
                crate::core::api::auth::auth_layer(api_env_factory.clone(), req, next)
            }));
        router.merge(batch)
    }
}

// ── Base ExtensionProviders ───────────────────────────────────────

impl ExtensionProviders {
    /// Create providers with Base (no-op) implementations.
    pub fn base() -> Self {
        Self {
            quota_checker: Arc::new(BaseQuotaChecker),
            dkim_signer: Arc::new(BaseMessageSigner),
            board_quota: Arc::new(NoopBoardQuota),
        }
    }
}
