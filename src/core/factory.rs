//! Domain-driven environment factory.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::{Arc, Mutex, RwLock};

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
    /// D9: signed-request freshness window (was a hardcoded 300 s constant).
    signature_window_ms: u64,
    /// D9: optional replay (nonce) cache — `None` when
    /// `api.replay_protection` is off.
    signature_cache: Option<Arc<SignatureCache>>,
    /// D5: in-memory `last_used_at` accumulator — the auth hot path only
    /// records here; a background task batch-flushes to the database.
    last_used_tracker: Arc<LastUsedTracker>,
    /// D3: `[webhook] allow_private_targets` policy — refused by default;
    /// read at registration (delivery re-checks with the same value).
    webhook_allow_private: bool,
    allow_unidentified_keys: bool,
}

impl EnvFactory {
    /// D9: freshness window in milliseconds (read by the auth layer).
    pub fn signature_window_ms(&self) -> u64 {
        self.signature_window_ms
    }

    /// D9: set the freshness window and the optional replay cache from config.
    /// Production wiring calls this once after construction; test factories
    /// can leave the 120 s default and no cache.
    pub fn with_signature_auth(mut self, window_secs: u64, replay_protection: bool) -> Self {
        self.signature_window_ms = window_secs.saturating_mul(1000);
        self.signature_cache = replay_protection.then(|| {
            Arc::new(
                SignatureCache::new(SIGNATURE_CACHE_CAPACITY).with_ttl(self.signature_window_ms),
            )
        });
        self
    }

    /// D9: record a verified signature; `Some(first_seen_ms)` if this exact
    /// (identity, timestamp, method, path) tuple was already verified within
    /// the window. The lookup and the insert happen under one lock hold, so
    /// two concurrent identical requests cannot both win — the first
    /// inserts, the second sees the hit.
    pub fn check_and_record_signature(&self, nonce_key: &str) -> Option<u64> {
        self.signature_cache
            .as_ref()
            .and_then(|c| c.check_and_record(nonce_key))
    }

    /// D5: shared `last_used_at` accumulator (server wiring spawns the
    /// batch-flush task against this handle).
    pub fn last_used_tracker(&self) -> &Arc<LastUsedTracker> {
        &self.last_used_tracker
    }

    /// D5: hot-path record — in-memory only, never touches the database.
    pub fn note_api_key_last_used(&self, id: i64) {
        self.last_used_tracker.note(id);
    }
}

/// D5: in-memory set of API keys whose `last_used_at` is newer than the last
/// database write. The auth hot path only inserts here (no DB write per
/// request); a background task drains and batch-writes at most once per flush
/// interval, and once more on graceful shutdown.
pub struct LastUsedTracker {
    pending: Mutex<HashSet<i64>>,
}

impl Default for LastUsedTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl LastUsedTracker {
    pub fn new() -> Self {
        Self {
            pending: Mutex::new(HashSet::new()),
        }
    }

    /// Record a key use (idempotent — repeated uses within the flush window
    /// collapse to a single pending entry).
    pub fn note(&self, id: i64) {
        let mut g = self.pending.lock().unwrap_or_else(|e| e.into_inner());
        g.insert(id);
    }

    /// Take all pending ids (clearing the set) for a batch flush.
    pub fn drain(&self) -> Vec<i64> {
        let mut g = self.pending.lock().unwrap_or_else(|e| e.into_inner());
        g.drain().collect()
    }
}

/// D9: bounded cache of verified signature tuples (identity + timestamp +
/// method + path). A re-send of an already-verified request inside the
/// freshness window is a replay → the caller answers 409.
///
/// `HashMap` for lookup + insertion order for eviction. Eviction is
/// approximate-LRU (oldest-inserted first, skipping keys re-recorded since):
/// good enough for a replay cache, zero allocations on the hit path, no
/// intrusive list to keep in sync.
pub struct SignatureCache {
    cap: usize,
    ttl_ms: u64,
    inner: Mutex<SignatureCacheInner>,
}

struct SignatureCacheInner {
    key: HashMap<String, u64>, // nonce_key -> verified_at_ms
    order: VecDeque<String>,   // insertion order (eviction candidate pool)
}

const SIGNATURE_CACHE_CAPACITY: usize = 10_000;

impl SignatureCache {
    pub fn new(capacity: usize) -> Self {
        Self {
            cap: capacity,
            ttl_ms: 0, // set via with_ttl
            inner: Mutex::new(SignatureCacheInner {
                key: HashMap::new(),
                order: VecDeque::new(),
            }),
        }
    }

    /// TTL = freshness window; an entry is valid for as long as the
    /// timestamp it carries could still pass the window check.
    pub(crate) fn with_ttl(mut self, ttl_ms: u64) -> Self {
        self.ttl_ms = ttl_ms;
        self
    }

    /// `Some(first_seen_ms)` when this exact tuple was already verified
    /// within the TTL; otherwise records it and returns `None`.
    pub(crate) fn check_and_record(&self, nonce_key: &str) -> Option<u64> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());

        if let Some(ts) = g.key.get(nonce_key) {
            if now.saturating_sub(*ts) <= self.ttl_ms {
                return Some(*ts);
            }
            // Expired: treat as absent — the key is re-accepted below.
            g.key.remove(nonce_key);
        }

        g.key.insert(nonce_key.to_string(), now);
        g.order.push_back(nonce_key.to_string());

        // Evict oldest-inserted keys until within capacity. Stale pool
        // entries (already removed or expired above) are skipped.
        while g.key.len() > self.cap {
            match g.order.pop_front() {
                Some(k) => {
                    if g.key.contains_key(&k) {
                        g.key.remove(&k);
                    }
                }
                None => break, // pool exhausted but map over cap: cannot
                               // happen (pool grows with the map), but never
                               // loop forever.
            }
        }
        None
    }
}

/// D3: registration-time webhook target check — absolute http(s) URL
/// whose host resolves to deliverable addresses. Literal IPs are classified
/// directly; domains are resolved and every result classified; dead hosts are
/// refused (fail loudly — same posture as the scheme check added 2026-09-27).
/// Private ranges are refused unless `allow_private` is set.
async fn validate_webhook_url(webhook_url: Option<&str>, allow_private: bool) -> AppResult<()> {
    if let Some(u) = webhook_url.map(str::trim).filter(|u| !u.is_empty()) {
        if let Err(e) = crate::core::webhook_target::validate_webhook_target(u, allow_private).await
        {
            tracing::error!(
                operation = "webhook_url_rejected",
                webhook_url = %u,
                "rejected a webhook_url that cannot be safely delivered"
            );
            return Err(e);
        }
    }
    Ok(())
}

impl EnvFactory {
    pub fn new(db: Arc<Database>, system_store: Arc<dyn SystemStore>) -> Self {
        Self {
            db,
            system_store,
            interceptors: Arc::new(RwLock::new(Vec::new())),
            board_registry: Arc::new(crate::board::registry::BoardRegistry::new()),
            // D9: 120 s default — matches `ApiConfig::default()`; production
            // wiring overrides both window and replay cache from config.
            signature_window_ms: crate::core::api::auth::DEFAULT_SIGNATURE_WINDOW_MS,
            signature_cache: None,
            last_used_tracker: Arc::new(LastUsedTracker::new()),
            webhook_allow_private: false,
            allow_unidentified_keys: false,
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

    /// D3: attach the webhook target policy from `[webhook]`.
    pub fn with_webhook_policy(mut self, allow_private: bool) -> Self {
        self.webhook_allow_private = allow_private;
        self
    }

    /// D1: attach the identity policy from `[api] allow_unidentified_keys`.
    /// `true` re-enables the degraded empty-identity fallback (SQL-capped at
    /// 64 candidates); `false` (default) refuses empty identities with
    /// 401 `identity_required` before any body read or database access.
    pub fn with_identity_policy(mut self, allow_unidentified: bool) -> Self {
        self.allow_unidentified_keys = allow_unidentified;
        self
    }

    /// D1: whether the degraded empty-identity fallback is enabled.
    pub fn allows_unidentified_keys(&self) -> bool {
        self.allow_unidentified_keys
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

    /// Register (or re-register) a domain under a system.
    /// For email-address domains (containing '@'), also upsert into domain_addr_meta
    /// as the authoritative per-agent webhook store.
    ///
    /// Re-registration semantics (2026-10-13, owner ruling "复用注册(重发地址)"):
    /// re-registering the same domain **within the same system** is an idempotent
    /// upsert — it refreshes webhook_url / webhook_secret / manager (this is how
    /// the inbound-up feedback loop pushes the confirmed inbound URL back to the
    /// gateway). Re-registering a domain owned by a **different** system is
    /// still a conflict (anti-squat).
    pub async fn create_domain(
        &self,
        id: &str,
        system_id: &str,
        domain: &str,
        webhook_url: Option<&str>,
        webhook_secret: Option<&str>,
        manager_address: Option<&str>,
    ) -> AppResult<SystemDomainRecord> {
        validate_webhook_url(webhook_url, self.webhook_allow_private).await?;
        // Same-system re-registration: upsert (refresh webhook fields).
        if let Some(existing) = self.lookup_domain_addr(domain).await? {
            if existing.system_id != system_id {
                return Err(AppError::Conflict(format!(
                    "Domain '{}' already exists (owned by another system)",
                    domain
                )));
            }
            let updated = self
                .db
                .update_system_domain(&existing.id, webhook_url, webhook_secret, Some(true))
                .await?
                .ok_or_else(|| {
                    AppError::Internal(format!(
                        "update_system_domain returned no rows for existing domain '{}'",
                        domain
                    ))
                })?;
            if domain.contains('@') {
                let _ = self
                    .db
                    .upsert_domain_addr_meta(domain, system_id, manager_address, None, None)
                    .await;
            }
            return Ok(updated);
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

    /// Update a domain's webhook config or active flag.
    /// Does not touch agent meta (domain_addr_meta): meta lifecycle is owned
    /// by create_domain (upsert manager) and delete_domain (cleanup). An update
    /// must not wipe manager_address / agent_signature / agent_persona.
    pub async fn update_domain(
        &self,
        id: &str,
        webhook_url: Option<&str>,
        webhook_secret: Option<&str>,
        is_active: Option<bool>,
    ) -> AppResult<Option<SystemDomainRecord>> {
        validate_webhook_url(webhook_url, self.webhook_allow_private).await?;
        self.db
            .update_system_domain(id, webhook_url, webhook_secret, is_active)
            .await
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

    /// Resolve webhook URL and secret for a domain (the record's own
    /// fields — no fallback).
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
    /// Uses DomainResolver to determine lookup keys (exact match first, then the
    /// resolver's fallback rules).
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
            return self.db.is_board_member(domain_addr, value).await;
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
        if crate::board::addr::is_board_address(value)
            && self.db.is_board_member(value, domain_addr).await?
        {
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

    /// Verify an API key hash exists and is active.
    /// Returns the full ApiKeyRecord if valid, None if invalid/expired/deactivated.
    pub async fn verify_api_key(&self, key_hash: &str) -> AppResult<Option<ApiKeyRecord>> {
        self.db.verify_api_key(key_hash).await
    }

    /// Update `last_used_at` for an API key (best-effort observability).
    pub async fn touch_api_key_last_used(&self, id: i64) -> AppResult<()> {
        self.db.touch_api_key_last_used(id).await
    }

    /// Candidate keys for signature verification, by caller identity
    /// (see Database::list_api_keys_by_identity).
    pub async fn list_api_keys_by_identity(&self, identity: &str) -> AppResult<Vec<ApiKeyRecord>> {
        self.db.list_api_keys_by_identity(identity).await
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

    /// Align an existing key's category + scopes in place (standalone bootstrap migration).
    pub async fn update_api_key_category_and_scopes(
        &self,
        id: i64,
        category: &str,
        scopes: &[String],
    ) -> AppResult<()> {
        self.db
            .update_api_key_category_and_scopes(id, category, scopes)
            .await
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

    /// The system a domain (agent address or bare domain) belongs to - agent_admin's authorization object is the agent
    /// (regardless of shared-domain status), so the permission decision must land on "same system"; this returns the resolution result.
    /// Unresolvable (unregistered address/domain) returns None; the caller treats it as unauthorized.
    pub async fn owning_system_of(&self, domain_addr: &str) -> Option<String> {
        if domain_addr.contains('@') {
            if let Ok(Some(k)) = self.resolve_api_key_by_email(domain_addr).await {
                return Some(k.system_id);
            }
        }
        self.db
            .get_active_system_domain_by_domain(domain_addr)
            .await
            .ok()
            .flatten()
            .map(|d| d.system_id)
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

// ── Tests ─────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::base::strategy::BaseSystemStore;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_factory() -> (Database, EnvFactory) {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("aimailgw-factory-test-{ts}"));
        std::fs::create_dir_all(&dir).unwrap();
        let db = Database::open(dir.join("aimail.db"), 4, None).unwrap();
        let factory = EnvFactory::new(Arc::new(db.clone()), Arc::new(BaseSystemStore));
        (db, factory)
    }

    // P1-2: updating a domain's webhook config must not wipe agent meta
    // (manager_address / agent_signature / agent_persona).
    #[tokio::test]
    async fn update_domain_does_not_wipe_agent_meta() {
        let (_db, factory) = temp_factory();
        let addr = "agent@test.com";

        // Create an address-type domain with manager, then set signature + persona.
        factory
            .create_domain(
                "1",
                "sys1",
                addr,
                Some("http://hook"),
                None,
                Some("mgr@test.com"),
            )
            .await
            .unwrap();
        factory
            .upsert_domain_addr_meta(
                addr,
                "sys1",
                Some("mgr@test.com"),
                Some("sig text"),
                Some("assistant"),
            )
            .await
            .unwrap();

        // Update webhook config only.
        let updated = factory
            .update_domain("1", Some("http://newhook"), None, None)
            .await
            .unwrap()
            .expect("record must exist");
        assert_eq!(
            updated.webhook_url.as_deref(),
            Some("http://newhook"),
            "webhook_url update must apply"
        );

        // Meta must be untouched.
        let meta = factory
            .resolve_domain_addr_meta(addr)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            meta.manager_address, "mgr@test.com",
            "manager must survive update"
        );
        assert_eq!(
            meta.agent_signature, "sig text",
            "signature must survive update"
        );
        assert_eq!(
            meta.agent_persona, "assistant",
            "persona must survive update"
        );
    }

    /// 2026-09-27: only an absolute http(s) URL can be delivered to.
    ///
    /// Measured on the L2 journey (J4e) and in a direct probe: `system_domains.webhook_url`
    /// is handed straight to reqwest, so `'127.0.0.1'` and even the scheme-less
    /// `'127.0.0.1:18789'` (the shape the CLI used to register for the bridge-push case)
    /// both die with "builder error" — a silent inbound black hole, visible only as the
    /// mail being promoted to overlimit. Registration must refuse them loudly.
    #[tokio::test]
    async fn rejects_undeliverable_webhook_url() {
        let (_db, factory) = temp_factory();
        for (i, bad) in [
            "127.0.0.1",
            "127.0.0.1:18789",
            "example.com/hook",
            "ftp://x/y",
        ]
        .iter()
        .enumerate()
        {
            let res = factory
                .create_domain(
                    &format!("d{i}"),
                    "sys1",
                    &format!("agent{i}@test.com"),
                    Some(bad),
                    None,
                    None,
                )
                .await;
            assert!(res.is_err(), "webhook_url {bad:?} must be refused");
            assert!(
                matches!(res.err(), Some(AppError::Validation(_))),
                "refusal must be a Validation error for {bad:?}"
            );
        }

        // D3: loopback targets are refused by default; the acceptance check
        // below uses the policy-open variant (private deployment mode).
        let factory = factory.with_webhook_policy(true);
        let ok = factory
            .create_domain(
                "dok",
                "sys1",
                "agent-ok@test.com",
                Some("http://127.0.0.1:18789/aimail/inbound"),
                None,
                None,
            )
            .await;
        assert!(ok.is_ok(), "absolute URL must be accepted: {:?}", ok.err());

        let upd = factory
            .update_domain("dok", Some("127.0.0.1:18789"), None, None)
            .await;
        assert!(
            matches!(upd.err(), Some(AppError::Validation(_))),
            "the update path must refuse an undeliverable value too"
        );
    }

    // 2026-10-13: re-registering (复用注册 / 重发地址) the same domain within
    // the same system must be an idempotent upsert — this is the mechanism
    // the inbound-up feedback loop uses to push the confirmed inbound URL
    // back to the gateway. A cross-system re-registration stays a conflict.
    #[tokio::test]
    async fn reregister_same_system_is_upsert() {
        let (_db, factory) = temp_factory();
        // D3: the fixture registers loopback/TEST-NET webhook URLs; open the
        // private-targets policy so this test keeps exercising the upsert
        // contract, not the target policy (covered in webhook_target.rs).
        let factory = factory.with_webhook_policy(true);
        factory
            .create_domain(
                "1",
                "sys1",
                "agent@test.com",
                Some("http://127.0.0.1:9099/aimail/inbound"),
                Some("secret-old"),
                Some("mgr@test.com"),
            )
            .await
            .unwrap();

        // Re-register: same address, new confirmed inbound URL.
        let again = factory
            .create_domain(
                "2",
                "sys1",
                "agent@test.com",
                Some("http://203.0.113.7:9099/aimail/inbound"),
                Some("secret-new"),
                Some("mgr@test.com"),
            )
            .await
            .expect("same-system re-registration must be an upsert");
        assert_eq!(
            again.webhook_url.as_deref(),
            Some("http://203.0.113.7:9099/aimail/inbound"),
            "upsert must refresh webhook_url"
        );
        assert_eq!(
            again.webhook_secret.as_deref(),
            Some("secret-new"),
            "upsert must refresh webhook_secret"
        );
        assert!(again.is_active, "upsert must keep the domain active");

        // Only one row may exist for the domain.
        let rows = factory.list_domains("agent@test.com").await.unwrap();
        assert_eq!(rows.len(), 1, "re-registration must not duplicate the row");
    }

    #[tokio::test]
    async fn reregister_other_system_still_conflicts() {
        let (_db, factory) = temp_factory();
        factory
            .create_domain("1", "sys1", "agent@test.com", None, None, None)
            .await
            .unwrap();
        let res = factory
            .create_domain("2", "sys2", "agent@test.com", None, None, None)
            .await;
        assert!(
            matches!(res.err(), Some(AppError::Conflict(_))),
            "cross-system re-registration must stay a conflict"
        );
    }
}
