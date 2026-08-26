// Base edition: no-op strategy implementations.
// Every trait method is a safe passthrough.

use async_trait::async_trait;

use crate::core::errors::AppResult;

use std::sync::Arc;

use crate::core::strategy::{
    AdmissionGate, ExtensionProviders, OutboundTransform, RouterHook, SystemStore,
};

// ── OutboundTransform ──

pub struct NoopOutboundTransform;

#[async_trait]
impl OutboundTransform for NoopOutboundTransform {
    async fn transform(&self, _raw: &[u8], _email_id: &str) -> Option<Vec<u8>> {
        None
    }
}

// ── AdmissionGate ──

pub struct BaseAdmissionGate;

#[async_trait]
impl AdmissionGate for BaseAdmissionGate {
    async fn admit_address(&self, _system_id: &str) -> AppResult<()> {
        Ok(())
    }
    async fn admit_domain(&self, _system_id: &str) -> AppResult<()> {
        Ok(())
    }
    async fn admit_board(&self, _system_id: &str) -> AppResult<()> {
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
        let body_cap = crate::core::api::auth::signature_body_cap(
            self.0.config.storage.attachment_max_size as u64,
        );
        let batch = axum::Router::new()
            .route(
                "/api/v1/admin/activation-codes/batch",
                axum::routing::post(crate::core::api::activation::batch_generate_codes),
            )
            .with_state(self.0.clone())
            .route_layer(axum::middleware::from_fn(move |req, next| {
                let ef = api_env_factory.clone();
                let cap = body_cap;
                async move {
                    crate::core::api::auth::auth_layer(ef, req, next, cap).await
                }
            }));
        router.merge(batch)
    }
}

// ── Base ExtensionProviders ───────────────────────────────────────

impl ExtensionProviders {
    /// Create providers with Base (no-op) implementations.
    pub fn base() -> Self {
        Self {
            admission_gate: Arc::new(BaseAdmissionGate),
            outbound: Arc::new(NoopOutboundTransform),
        }
    }
}
