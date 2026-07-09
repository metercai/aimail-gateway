//! Authorization scopes for the permission model.
//!
//! # Hierarchy
//!
/// ```text
/// platform — platform-level management (systems, IP filter, global monitoring)
///   Cannot create agents or manage system-internal resources.
///
/// system — system-level management (domains, whitelists, agent keys)
///   Scoped to a single system.
///
/// domain — domain-level management (domain addresses, domain whitelists)
///   Scoped to a single domain. Created by system admin for domain isolation.
///
/// agent_admin — agent-level management within a system (agent keys, agent whitelists, agent stats)
///   Scoped to a single system. Cannot manage domains or system-level configuration.
///
/// Agent — self-service (send email, manage own whitelist, rotate own key)
///   Scoped to a single email address.
///
/// bridge — relay-bridge operations (pending deliveries poll + ack only)
///   Scoped to a single system. Minimal privilege for amail-bridge.
/// ```
use serde::{Deserialize, Serialize};
use std::fmt;

/// The single scope assigned to an API key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Scope {
    PlatformAdmin,
    SystemAdmin,
    AgentAdmin,
    Agent,
    Bridge,
}

impl Scope {
    /// Parse a scope from its string representation (from the DB).
    /// Accepts legacy strings for backward compatibility.
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "platform" | "admin" | "system_admin" => Some(Scope::PlatformAdmin),
            "system" | "tenant_admin" => Some(Scope::SystemAdmin),
            "agent_admin" => Some(Scope::AgentAdmin),
            "agent" => Some(Scope::Agent),
            "bridge" | "pending" => Some(Scope::Bridge),
            _ => None,
        }
    }

    /// Serialize scope to its canonical string form.
    pub fn as_str(&self) -> &'static str {
        match self {
            Scope::PlatformAdmin => "platform",
            Scope::SystemAdmin => "system",
            Scope::AgentAdmin => "agent_admin",
            Scope::Agent => "agent",
            Scope::Bridge => "bridge",
        }
    }
}

impl fmt::Display for Scope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Category of an API key — determines visibility boundaries.
///
/// - `platform`: only platform_admin keys (not visible to system admins)
/// - `system`: system_admin keys (visible to platform_admin as shell, manageable by system_admin)
/// - `domain`: domain-level admin keys (bare domain email, system scope, scoped to one domain)
/// - `agent`: agent keys (visible as shell to system_admin, self-managed by agent)
/// - `agent_admin`: agent_admin keys (visible to platform_admin, manageable by system/admin)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum KeyCategory {
    Platform,
    System,
    Domain,
    Agent,
    AgentAdmin,
}

impl KeyCategory {
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "platform" => Some(KeyCategory::Platform),
            "system" => Some(KeyCategory::System),
            "domain" => Some(KeyCategory::Domain),
            "agent" => Some(KeyCategory::Agent),
            "agent_admin" => Some(KeyCategory::AgentAdmin),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            KeyCategory::Platform => "platform",
            KeyCategory::System => "system",
            KeyCategory::Domain => "domain",
            KeyCategory::Agent => "agent",
            KeyCategory::AgentAdmin => "agent_admin",
        }
    }
}

/// Category of a whitelist entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum WhitelistCategory {
    System,
    Agent,
}

impl WhitelistCategory {
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "system" => Some(WhitelistCategory::System),
            "agent" => Some(WhitelistCategory::Agent),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            WhitelistCategory::System => "system",
            WhitelistCategory::Agent => "agent",
        }
    }
}
