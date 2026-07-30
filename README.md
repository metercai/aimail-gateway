[English](README.md) | [🇨🇳 中文](README_zh.md)

# amail-gateway

![Rust](https://img.shields.io/badge/Rust-1.75%2B-orange) ![Platform](https://img.shields.io/badge/platform-linux%20%7C%20macOS%20%7C%20windows-969696) ![License](https://img.shields.io/badge/License-MPL--2.0-blue)


**A bidirectional mail gateway purpose-built for AI Agents** — providing instant SMTP inbound and HTTP outbound mail channels so every Agent can seamlessly join the global email network.

---

## 1. What is amail-gateway

amail-gateway is a lightweight, high-performance Rust mail gateway that solves two core problems for Agent email:

- **Inbound:** Traditional solutions rely on IMAP/POP3 polling — high latency, wasted resources. amail-gateway pushes inbound mail to Agents in real-time via Webhook. No polling required.
- **Outbound:** A standard HTTP API lets Agents send mail with a single toolset call. Same-gateway recipients go through internal Webhook direct delivery; external addresses go through SMTP relay — fast and efficient.

Beyond these fundamentals, amail-gateway is purpose-built for how AI Agents actually use email:

- **Security:** Agents shouldn't be exposed to spam and attacks on the open mail network. The default whitelist enforces bidirectional control — unauthorized senders cannot reach Agents, and Agents cannot send to unauthorized addresses. Every Agent has a designated security officer for critical operation oversight.
- **Content:** Traditional LLMs struggle with raw HTML/MIME email — inefficient and severely token-wasteful. amail-gateway includes a content processing pipeline that extracts key information, strips styling noise, and uniformly converts to clean Markdown optimized for LLM consumption.
- **Collaboration:** Email for Agents goes beyond message delivery — it's about human-like conversation and coordination. amail-gateway has several built-in capabilities for this:
  - **Contact profiling and session memory** — multi-party conversations stay clear and natural.
  - **Stranger [WHOAMI]** — Agents can publicly declare their role for easy discovery and efficient role-based interaction.
  - **A2A Board engine** — autonomous heterogeneous multi-Agent collaboration via standard mail protocols.

**amail-gateway is the core infrastructure of AgentMail.** The [AgentMail](https://github.com/metercai/agentmail) toolchain integrates different Agent systems, enabling heterogeneous multi-Agent human-like conversation and collaboration over email.

---

## 2. Features

**Inbound:**
- **Standard SMTP** — port 25, compatible with any mail client
- **Multi-domain** — receive mail for multiple domains on one gateway
- **Webhook push** — real-time HTTP POST to Agent Webhook URL
- **Multi-address aggregation** — batch push to multiple recipients at once
- **Webhook hybrid mode** — push/pull mixed delivery for the same email
- **Derived address support** — compatible with multi-identity addresses:
  -  `{role_name}.{agent_name}@{mx_domain}`
- **Immediate rejection** — invalid recipients, oversized mail, internal-sender-as-external rejected instantly to save resources
- **Push scheduling** — async queue, auto-retry on failure, expired resource cleanup

**Outbound:**
- **Pre-upload attachments** — dedicated upload endpoint for higher delivery success
- **HTTP send API** — JSON-format mail via HTTP, Agent-friendly
- **Standard SMTP outbound** — configurable external relay
- **Internal forwarding** — same-gateway recipients delivered directly, no public network loop
- **Derived address support** — compatible with multi-identity addresses
- **Outbound scheduling** — async queue, auto-retry on failure, expired resource cleanup
- **Bounce handling** — RFC 3464 compliant automatic bounce recognition and processing

**Security:**
- **Default bidirectional whitelist** — unauthorized senders can't reach Agents; Agents can't send to unauthorized addresses
- **Security officer** — every Agent has a security officer address for critical operation oversight
- **API Key authentication** — independent keys per Agent with multi-scope management
- **Tiered API keys** — separate system/domain/agent key levels, isolated per scenario
- **Behavior scoping** — role and scope-based behavior limitation to prevent out-of-bounds actions
- **Loop prevention** — internal recipients never relayed externally, internal senders never accepted as inbound, auto-reply suppression to avoid cycles
- **Audit logging** — critical operations fully recorded and traceable

**Content:**
- **Encoding detection** — auto-detect mail encoding and convert to UTF-8
- **Attachment management** — auto-extract attachments for download, metadata flows with email
- **Format conversion** — body cleaning and conversion to Markdown, ready for LLM consumption
- **Information extraction** — sender signature extraction for identity recognition
- **Thread tracking** — automatic In-Reply-To / References chain maintenance
- **Thread summary** — persistent thread context, Agents retain memory across sessions
- **Raw snapshots** — optional raw email preservation for future mining and audit

**Collaboration:**
- **Contact profiling** — build dynamic profiles for contacts, making replies more targeted
- **Session summary** — build session summaries per contact, keeping conversations organized
- **Identity self-declaration** — tiered `[WHOAMI]` instruction response for strangers and contacts, enabling role discovery
- **A2A Board** — pipeline view + task dependencies + assignee tracing, at a glance
- **A2A Task engine** — instruction flow + session flow + notification flow, event-driven autonomous collaboration
- **Definable roles** — roles and behaviors customized through config data and prompts, an LLM-native workflow engine
- **Human-in-the-loop** — human-Agent hybrid workflows, with objectives and deliverables controlled by humans

---

## 3. Quick Start

amail-gateway needs to connect to the external mail network. Prepare a VPS with firewall ports open for SMTP and HTTP.

```bash
cp .env.example .env
# Edit .env with:
#   AMAIL_DEPLOY_HOST    — VPS IP address
#   AMAIL_DEPLOY_USER    — SSH login user
#   AMAIL_DEPLOY_KEY     — SSH private key path (optional)
```

### Option A: Binary Deployment

```bash
# Build, upload and install systemd service
bash deploy-bin.sh build
bash deploy-bin.sh setup-systemd
bash deploy-bin.sh start
bash deploy-bin.sh health
```

### Option B: Docker Deployment

```bash
# Build image with commit hash
bash deploy-docker.sh build

# Push to remote server and run
bash deploy-docker.sh push
bash deploy-docker.sh run
```

---

## 4. Configuration

### Key Settings

| Field | Section | Description |
|------|---------|-------------|
| `bind` | `[smtp]` | Inbound SMTP listen address, default `0.0.0.0:25` |
| `hostname` | `[smtp]` | EHLO hostname, should match PTR record (e.g. `amail.token.tm`) |
| `bind` | `[http]` | HTTP API listen address, default `0.0.0.0:8080` |
| `smtp_server` | `[relay]` | External relay address (e.g. `smtp://smtp.example.com:587`) |
| `username / password` | `[relay]` | Relay authentication credentials |
| `path` | `[storage]` | Data directory (database, attachments), default `./data` |
| `attachment_max_size` | `[storage]` | Max attachment size |
| `timeout_secs` | `[webhook]` | Webhook push timeout (seconds) |
| `max_attempts` | `[retry]` | Max delivery retry attempts |

### Example config.toml

```toml
[http]
bind = "0.0.0.0:8080"
# hostname = "mail.yourdomain.com"

[smtp]
bind = "0.0.0.0:25"
# hostname = "mail.yourdomain.com"
# max_message_size = 10485760
# max_connections = 100

[relay]
# smtp_server = "smtp://smtp.example.com:587"
# username = "relay@example.com"
# password = "your-password"
# dns_server = "127.0.0.1:53"
# auto_reply_from = "noreply@yourdomain.com"
# auto_reply_subject_prefix = "[Auto-Reply] "
# delivery_window_secs = 7200
# mx_dns_override = { "example.com" = "127.0.0.1:25" }

[webhook]
# timeout_secs = 10
# pending_ttl_hours = 72

[retry]
# max_attempts = 3
# initial_backoff_secs = 5
# multiplier = 2
# max_backoff_secs = 300
# poll_interval_secs = 5
# batch_size = 50

[storage]
path = "./data"
# pool_size = 25
# encryption = false
# attachment_max_size = 20971520
# attachment_lifetime_hours = 720
# attachment_max_attachments = 5
# attachment_allowed_types = []

[logging]
# level = "info"
# file = "/var/log/amail-gateway.log"

[admin]
# email = "admin@yourdomain.com"

[board]
# heartbeat_stale_seconds = 14400
# task_timeout_seconds = 259200
# sweeper_interval_seconds = 900
# max_active_boards = 5
# archive_retention_days = 90
```

---

## 5. Related Projects

- [agentmail](https://github.com/metercai/agentmail) — Agent integration toolchain (one-click deploy with patch/skill/toolset)
