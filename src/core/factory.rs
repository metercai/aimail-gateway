//! Domain-driven environment factory.

use std::sync::{Arc, RwLock};

use crate::core::errors::{AppError, AppResult};
use crate::core::storage::{
    ApiKeyRecord, Database, DomainAddrMetaRecord, SystemDomainRecord, SystemRecord, WhitelistRecord,
};
use crate::core::strategy::SystemStore;

/// Database-backed environment factory.
#[derive(Clone)]
pub struct EnvFactory {
    pub db: Arc<Database>,
    system_store: Arc<dyn SystemStore>,
    interceptors: Arc<RwLock<Vec<Arc<dyn crate::core::strategy::InboundInterceptor>>>>,
    /// Board address cache for RCPT substantive checks. Built empty;
    /// production wiring calls `with_board_registry` (loaded from disk)
    /// after construction. Test factories that never see `.a2a@`
    /// recipients can leave it empty.
    board_registry: Arc<crate::board::registry::BoardRegistry>,
}

impl EnvFactory {
    pub fn new(
        db: Arc<Database>,
        system_store: Arc<dyn SystemStore>,
    ) -> Self {
        Self {
            db,
            system_store,
            interceptors: Arc::new(RwLock::new(Vec::new())),
            board_registry: Arc::new(crate::board::registry::BoardRegistry::new()),
        }
    }

    /// Attach the shared board registry (production path: load from disk
    /// once, then share across SMTP handlers and interceptors).
    pub fn with_board_registry(
        mut self,
        registry: Arc<crate::board::registry::BoardRegistry>,
    ) -> Self {
        self.board_registry = registry;
        self
    }

    /// Access the board registry (RCPT substantive check).
    pub fn board_registry(&self) -> &Arc<crate::board::registry::BoardRegistry> {
        &self.board_registry
    }

    /// Resolve a system_id from a domain name by looking up the system_domains table.
    async fn resolve_system_id_from_domain(&self, domain: &str) -> AppResult<String> {
        let record = self
            .lookup_domain_addr(domain)
            .await?
            .ok_or_else(|| AppError::NotFound(format!("domain not found: {}", domain)))?;
        Ok(record.system_id)
    }

    // ── Interceptors ──
    pub fn get_interceptors(
        &self,
    ) -> &Arc<RwLock<Vec<Arc<dyn crate::core::strategy::InboundInterceptor>>>> {
        &self.interceptors
    }

    pub fn register_interceptor(
        &self,
        interceptor: Arc<dyn crate::core::strategy::InboundInterceptor>,
    ) {
        let mut list = self.interceptors.write().unwrap();
        list.push(interceptor);
        // Sort by priority (lowest first)
        list.sort_by_key(|i| i.priority());
    }

    // ── System ──
    pub async fn resolve_system(&self, id: &str) -> AppResult<Option<SystemRecord>> {
        self.system_store.resolve_system(id).await
    }

    // ── Domains ──

    /// Register a new domain under a system.
    /// For email-address domains (containing '@'), also upsert into domain_addr_meta
    /// as the authoritative per-agent webhook store.
    pub async fn create_domain(
        &self,
        id: &str,
        system_id: &str,
        domain: &str,
        webhook_url: Option<&str>,
        webhook_secret: Option<&str>,
        manager_address: Option<&str>,
    ) -> AppResult<SystemDomainRecord> {
        // Pre-check: domain must be globally unique
        if self.lookup_domain_addr(domain).await?.is_some() {
            return Err(AppError::Conflict(format!(
                "Domain '{}' already exists",
                domain
            )));
        }
        let record = self
            .db
            .insert_system_domain(id, system_id, domain, webhook_url, webhook_secret)
            .await?;
        if domain.contains('@') {
            let _ = self
                .db
                .upsert_domain_addr_meta(domain, system_id, manager_address, None, None)
                .await;
        }
        Ok(record)
    }

    /// Resolve a system-domain record by its internal ID.
    pub async fn resolve_domain(&self, id: &str) -> AppResult<Option<SystemDomainRecord>> {
        self.db.get_system_domain(id).await
    }

    /// Look up a system-domain record by domain_addr key.
    /// Key can be a bare domain ("example.com") or a full address ("user@example.com").
    /// Performs exact match — no fallback logic. Caller decides what to pass.
    pub async fn lookup_domain_addr(&self, key: &str) -> AppResult<Option<SystemDomainRecord>> {
        self.db.get_system_domain_by_name(key).await
    }

    /// Resolve an email address to a domain record, with domain-level fallback.
    /// Step 1: exact match on full address → Step 2: extract domain and retry.
    /// Use when you have an address and need the best available domain record.
    pub async fn resolve_domain_from_address(
        &self,
        address: &str,
    ) -> AppResult<Option<SystemDomainRecord>> {
        // Step 1: exact match on full address
        if let Ok(Some(record)) = self.lookup_domain_addr(address).await {
            return Ok(Some(record));
        }
        // Step 2: extract domain and retry
        let domain = match address.rsplit('@').next() {
            Some(d) => d,
            None => return Ok(None),
        };
        self.lookup_domain_addr(domain).await
    }

    /// List all domains registered under a system (by system ID directly).
    pub async fn list_domains_by_system(
        &self,
        system_id: &str,
    ) -> AppResult<Vec<SystemDomainRecord>> {
        self.db.list_system_domains(system_id).await
    }

    /// List all domains registered under the system that owns this domain.
    pub async fn list_domains(&self, domain: &str) -> AppResult<Vec<SystemDomainRecord>> {
        let system_id = self.resolve_system_id_from_domain(domain).await?;
        self.db.list_system_domains(&system_id).await
    }

    /// Update a domain's webhook config, active flag, manager address, agent signature, or agent persona.
    /// For email-address domains, also syncs to domain_addr_meta.
    pub async fn update_domain(
        &self,
        id: &str,
        webhook_url: Option<&str>,
        webhook_secret: Option<&str>,
        is_active: Option<bool>,
    ) -> AppResult<Option<SystemDomainRecord>> {
        let existing = self.db.get_system_domain(id).await?;
        let result = self
            .db
            .update_system_domain(id, webhook_url, webhook_secret, is_active)
            .await?;
        if let Some(ref record) = existing {
            if record.domain.contains('@') {
                let _ = self
                    .db
                    .upsert_domain_addr_meta(&record.domain, &record.system_id, None, None, None)
                    .await;
            }
        }
        Ok(result)
    }

    /// Delete a domain registration.
    /// For email-address domains, also cleans up domain_addr_meta.
    pub async fn delete_domain(&self, id: &str) -> AppResult<()> {
        let existing = self.db.get_system_domain(id).await?;
        self.db.delete_system_domain(id).await?;
        if let Some(ref record) = existing {
            if record.domain.contains('@') {
                let _ = self.db.delete_domain_addr_meta(&record.domain).await;
            }
        }
        Ok(())
    }

    /// Resolve webhook URL and secret for a domain, falling back to system defaults.
    pub async fn resolve_webhook_for_domain(
        &self,
        domain_record: &SystemDomainRecord,
    ) -> AppResult<(String, String)> {
        let url = domain_record.webhook_url.clone().unwrap_or_default();
        let secret = domain_record.webhook_secret.clone().unwrap_or_default();
        Ok((url, secret))
    }

    // ── Agent meta ──

    /// Get agent metadata by email address.
    pub async fn resolve_domain_addr_meta(
        &self,
        email: &str,
    ) -> AppResult<Option<DomainAddrMetaRecord>> {
        self.db.get_domain_addr_meta(email).await
    }

    /// Upsert agent metadata (create or update).
    pub async fn upsert_domain_addr_meta(
        &self,
        email: &str,
        system_id: &str,
        manager_address: Option<&str>,
        agent_signature: Option<&str>,
        agent_persona: Option<&str>,
    ) -> AppResult<DomainAddrMetaRecord> {
        self.db
            .upsert_domain_addr_meta(
                email,
                system_id,
                manager_address,
                agent_signature,
                agent_persona,
            )
            .await
    }

    /// List all agents with metadata for a system.
    pub async fn list_domain_addr_meta_by_system(
        &self,
        system_id: &str,
    ) -> AppResult<Vec<DomainAddrMetaRecord>> {
        self.db.list_domain_addr_meta_by_system(system_id).await
    }

    /// Delete agent metadata.
    pub async fn delete_domain_addr_meta(&self, email: &str) -> AppResult<()> {
        self.db.delete_domain_addr_meta(email).await
    }

    // ── Whitelists ──

    /// Create a whitelist entry.
    pub async fn create_whitelist_entry(
        &self,
        domain_addr: &str,
        direction: &str,
        value: &str,
        description: Option<&str>,
    ) -> AppResult<WhitelistRecord> {
        let keys = crate::core::whitelist::ExactKeyResolver
            .resolve(&self.db, domain_addr)
            .await?;
        let (system_id, _) = &keys[0];
        let record = self
            .db
            .insert_whitelist(
                system_id,
                domain_addr,
                direction,
                value,
                "system",
                None,
                description,
            )
            .await?;
        // Invalidate cache so new rule takes effect immediately
        self.db.whitelist_cache.invalidate(&record.value);
        Ok(record)
    }

    /// Look up a specific whitelist entry by its compound key.
    pub async fn resolve_whitelist_entry(
        &self,
        domain_addr: &str,
        value: &str,
    ) -> AppResult<Option<WhitelistRecord>> {
        let keys = crate::core::whitelist::ExactKeyResolver
            .resolve(&self.db, domain_addr)
            .await?;
        let (system_id, _) = &keys[0];
        self.db.get_whitelist(system_id, domain_addr, value).await
    }

    /// List all whitelist entries for the system that owns this domain.
    pub async fn list_whitelist_entries(&self, domain: &str) -> AppResult<Vec<WhitelistRecord>> {
        match self.resolve_system_id_from_domain(domain).await {
            Ok(system_id) => self.db.list_whitelists(&system_id).await,
            Err(_) => Ok(Vec::new()), // non-existent domain → empty list
        }
    }

    /// Toggle a whitelist entry active/inactive.
    pub async fn update_whitelist_entry(
        &self,
        id: i64,
        is_active: Option<bool>,
        direction: Option<String>,
    ) -> AppResult<Option<WhitelistRecord>> {
        let record = self.db.update_whitelist(id, is_active, direction).await?;
        // Invalidate cache so toggle takes effect immediately
        if let Some(ref r) = record {
            self.db.whitelist_cache.invalidate(&r.value);
        }
        Ok(record)
    }

    /// Delete a whitelist entry.
    pub async fn delete_whitelist_entry(&self, id: i64) -> AppResult<()> {
        // Look up the record to get the value for cache invalidation
        if let Some(record) = self.db.get_whitelist_by_id(id).await? {
            self.db.whitelist_cache.invalidate(&record.value);
        }
        self.db.delete_whitelist(id).await
    }

    /// Delete a whitelist entry by domain_addr and value (for manager commands).
    pub async fn delete_whitelist_entry_by_value(
        &self,
        domain_addr: &str,
        value: &str,
    ) -> AppResult<()> {
        self.db.whitelist_cache.invalidate(value);
        self.db
            .delete_whitelist_by_domain_and_value(domain_addr, value)
            .await
    }

    /// Get a whitelist entry by its primary key ID.
    pub async fn get_whitelist_entry_by_id(&self, id: i64) -> AppResult<Option<WhitelistRecord>> {
        self.db.get_whitelist_by_id(id).await
    }

    /// Count active whitelist entries for a scope (domain, directions).
    ///
    /// P0 gate: used by HTTP send ("to"/"all") and SMTP receive ("from"/"all").
    /// Returns 0 → reject immediately (no whitelist protection at all).
    ///
    /// Uses exact-address matching to determine lookup keys.
    pub async fn count_whitelist_entries(
        &self,
        domain: &str,
        directions: &[&str],
    ) -> AppResult<i64> {
        let keys = crate::core::whitelist::ExactKeyResolver
            .resolve(&self.db, domain)
            .await?;
        for (system_id, lookup_key) in &keys {
            let count = self
                .db
                .count_whitelist_entries(system_id, lookup_key, directions)
                .await?;
            if count > 0 {
                return Ok(count);
            }
        }
        Ok(0)
    }

    /// Count whitelist entries for a specific api_key (agent scope).
    pub async fn count_whitelist_entries_by_api_key(
        &self,
        system_id: &str,
        api_key_id: i64,
    ) -> AppResult<i64> {
        self.db
            .count_whitelist_entries_by_api_key(system_id, api_key_id)
            .await
    }

    /// Check if a value is whitelisted for a given scope.
    /// Uses DomainResolver to determine lookup keys (base=exact, advanced=fallback).
    pub async fn check_whitelisted(
        &self,
        domain_addr: &str,
        value: &str,
        direction: &str,
    ) -> AppResult<bool> {
        // A2A board address (`.a2a@`) is NOT a registered domain record —
        // the domain resolver would fail on it (reserved local part). Board
        // members auto-pass via the board group whitelist instead.
        if crate::board::addr::is_board_address(domain_addr) {
            return Ok(self.db.is_board_member(domain_addr, value).await?);
        }
        let keys = crate::core::whitelist::ExactKeyResolver
            .resolve(&self.db, domain_addr)
            .await?;
        for (system_id, lookup_key) in &keys {
            if self
                .db
                .is_whitelisted(system_id, lookup_key, value, direction)
                .await?
            {
                return Ok(true);
            }
        }
        // Board group whitelist: when the *value* (sender) is a board
        // address, board members auto-pass (no per-member whitelist storm).
        if crate::board::addr::is_board_address(value) && self.db.is_board_member(value, domain_addr).await? {
            return Ok(true);
        }
        Ok(false)
    }

    /// Create a new API key record.
    #[allow(clippy::too_many_arguments)]
    pub async fn create_api_key(
        &self,
        system_id: &str,
        email_address: &str,
        key_hash: &str,
        key_prefix: &str,
        scopes: &[String],
        expires_at: Option<&str>,
        category: &str,
    ) -> AppResult<ApiKeyRecord> {
        self.db
            .insert_api_key(
                system_id,
                email_address,
                key_hash,
                key_prefix,
                scopes,
                expires_at,
                category,
            )
            .await
    }

    /// Look up an API key by its hash (for authentication).
    pub async fn resolve_api_key(&self, key_hash: &str) -> AppResult<Option<ApiKeyRecord>> {
        self.db.lookup_api_key(key_hash).await
    }

    /// Verify an API key hash exists and is active.
    /// Returns the full ApiKeyRecord if valid, None if invalid/expired/deactivated.
    pub async fn verify_api_key(&self, key_hash: &str) -> AppResult<Option<ApiKeyRecord>> {
        self.db.verify_api_key(key_hash).await
    }

    /// Resolve an API key by its numeric ID.
    pub async fn resolve_api_key_by_id(&self, id: i64) -> AppResult<Option<ApiKeyRecord>> {
        self.db.get_api_key(id).await
    }

    /// List all API keys.
    pub async fn list_api_keys(&self) -> AppResult<Vec<ApiKeyRecord>> {
        self.db.list_api_keys().await
    }

    /// Update API key scopes or active flag.
    pub async fn update_api_key(
        &self,
        id: i64,
        scopes: Option<Vec<String>>,
        is_active: Option<bool>,
    ) -> AppResult<Option<ApiKeyRecord>> {
        self.db.update_api_key(id, scopes, is_active).await
    }

    /// Delete an API key.
    pub async fn delete_api_key(&self, id: i64) -> AppResult<()> {
        self.db.delete_api_key(id).await
    }

    /// Rotate an API key: generate a new hash and prefix, update in DB.
    pub async fn rotate_api_key(
        &self,
        id: i64,
        new_key_hash: &str,
        new_key_prefix: &str,
    ) -> AppResult<Option<ApiKeyRecord>> {
        self.db
            .rotate_api_key(id, new_key_hash, new_key_prefix)
            .await
    }

    /// List API keys filtered by system_id and category.
    pub async fn list_api_keys_by_system(
        &self,
        system_id: &str,
        category: &str,
    ) -> AppResult<Vec<ApiKeyRecord>> {
        self.db.list_api_keys_by_system(system_id, category).await
    }

    /// Resolve an API key by email address.
    pub async fn resolve_api_key_by_email(&self, email: &str) -> AppResult<Option<ApiKeyRecord>> {
        self.db.get_api_key_by_email(email).await
    }

    /// Create a whitelist entry with explicit category and api_key_id.

    pub async fn create_whitelist_entry_full(
        &self,
        domain_addr: &str,
        direction: &str,
        value: &str,
        category: &str,
        api_key_id: Option<i64>,
        description: Option<&str>,
    ) -> AppResult<WhitelistRecord> {
        let keys = crate::core::whitelist::ExactKeyResolver
            .resolve(&self.db, domain_addr)
            .await?;
        let (system_id, _) = &keys[0];
        let record = self
            .db
            .insert_whitelist(
                system_id,
                domain_addr,
                direction,
                value,
                category,
                api_key_id,
                description,
            )
            .await?;
        self.db.whitelist_cache.invalidate(&record.value);
        Ok(record)
    }

    /// Resolve webhook URL for a given address.
    /// Two-step: exact match on full email → fallback to bare domain.
    /// Only ACTIVE domains are resolved (AUDIT-1 P2-4: deactivated domains
    /// must not receive deliveries).
    pub async fn resolve_webhook_url(&self, sender: &str) -> Option<String> {
        let lower = sender.to_lowercase();
        // Step 1: exact match on full email address (active only)
        if let Ok(Some(record)) = self.db.get_active_system_domain_by_domain(&lower).await {
            let url = record.webhook_url.as_deref().filter(|u| !u.is_empty())?;
            return Some(url.to_string());
        }
        // Step 2: fallback to bare domain (active only)
        if let Some(domain) = lower.split('@').nth(1) {
            if let Ok(Some(record)) = self.db.get_active_system_domain_by_domain(domain).await {
                return record.webhook_url.filter(|u| !u.is_empty());
            }
        }
        None
    }

    /// Build endpoints JSON for recipient webhook delivery.
    /// Calls resolve_webhook_url for each recipient.
    pub async fn build_endpoints_for_recipients(&self, recipients: &[String]) -> String {
        let mut map = serde_json::Map::new();

        for email in recipients {
            let lower = email.to_lowercase();
            if map.contains_key(&lower) {
                continue;
            }
            if let Some(url) = self.resolve_webhook_url(&lower).await {
                map.insert(
                    lower.clone(),
                    serde_json::json!({"url": url, "status": "pending"}),
                );
            }
        }

        serde_json::to_string(&map).unwrap_or_else(|_| "{}".to_string())
    }
}
