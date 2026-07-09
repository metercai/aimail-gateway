[English](README.md) | [🇨🇳 中文](README_zh.md)

# amail-gateway

![Rust](https://img.shields.io/badge/Rust-1.75%2B-orange) ![Platform](https://img.shields.io/badge/platform-linux%20%7C%20macOS%20%7C%20windows-969696) ![License](https://img.shields.io/badge/License-MPL--2.0-blue)


**A bidirectional mail gateway purpose-built for AI Agents** — providing instant SMTP inbound and HTTP outbound mail channels so every Agent can seamlessly join the global email network.

---

## 1. What is amail-gateway

amail-gateway is a lightweight, high-performance Rust mail gateway that solves two core problems for Agent email:

- **Inbound:** Traditional solutions rely on IMAP/POP3 polling — high latency, wasted resources. amail-gateway pushes inbound mail to Agents in real-time via Webhook. No polling required.
- **Outbound:** A standard HTTP API lets Agents send mail with a single call. Same-domain recipients go through internal Webhook routing; external recipients go through SMTP relay.

Beyond these fundamentals, amail-gateway is purpose-built for how AI Agents actually use email:

- **Security:** Agents shouldn't be exposed to spam and attacks on the open mail network. Default whitelist prevents unauthorized senders from reaching Agents, and prevents Agents from sending to unauthorized recipients. Every Agent has a designated security officer for critical operation oversight.
- **Content:** LLMs struggle with raw HTML/MIME email — inefficient and token-wasteful. amail-gateway includes a content processing pipeline that extracts key information, strips styling noise, and converts to clean Markdown optimized for LLM consumption.
- **Collaboration:** Email for Agents goes beyond message delivery — it's about conversation and coordination. amail-gateway has built-in instruction emails and an A2A Board engine, enabling autonomous Agent-Agent collaboration over standard mail protocols.

**amail-gateway is the core infrastructure of AgentMail.** Combined with the [AgentMail](https://github.com/metercai/agentmail) integration toolchain, Agents get one-click email access.

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
# Build
cargo build --release -p amail-gateway

# Upload and install systemd service
bash deploy.sh upload
bash deploy.sh setup-systemd
bash deploy.sh start
bash deploy.sh health
```

### Option B: Docker Deployment

```bash
# Build and push image to VPS
docker build -t amail-gateway .
docker save amail-gateway | ssh root@$AMAIL_DEPLOY_HOST "docker load"

# Run on VPS
ssh root@$AMAIL_DEPLOY_HOST "docker run -d \\
  --name amail-gateway \\
  -p 8080:8080 -p 25:25 \\
  -v /etc/amail/config.toml:/etc/amail/config.toml \\
  -v /data/amail:/data \\
  amail-gateway"
```

---

## 4. Configuration

### Key Settings

| Section | Field | Description |
|---------|-------|-------------|
| `[smtp]` | `bind` | Inbound SMTP listen address, default `0.0.0.0:25` |
| `[smtp]` | `hostname` | EHLO hostname, should match PTR record (e.g. `amail.token.tm`) |
| `[http]` | `bind` | HTTP API listen address, default `0.0.0.0:38080` |
| `[relay]` | `smtp_server` | External relay address (e.g. `smtp://smtp.example.com:587`) |
| `[relay]` | `username / password` | Relay authentication credentials |
| `[storage]` | `path` | Data directory (database, attachments), default `./data` |
| `[storage]` | `attachment_max_size` | Max attachment size |
| `[webhook]` | `timeout_secs` | Webhook push timeout (seconds) |
| `[retry]` | `max_attempts` | Max delivery retry attempts |

### Example config.toml

```toml
[smtp]
bind = "0.0.0.0:25"
hostname = "amail.yourdomain.com"       # match PTR record
max_message_size = 26214400             # 25 MiB
max_connections = 100

[http]
bind = "0.0.0.0:38080"

[relay]
smtp_server = "smtp://smtp.example.com:587"
username = "relay@example.com"
password = "your-password"
auto_reply_subject_prefix = "Re: "
delivery_window_secs = 7200             # NDR bounce correlation window (2h)

[storage]
path = "./data"
pool_size = 25
attachment_max_size = 26214400
attachment_lifetime_hours = 72
attachment_allowed_types = ["pdf", "png", "jpg", "docx", "xlsx"]

[webhook]
timeout_secs = 30
pending_ttl_hours = 72

[retry]
max_attempts = 3
initial_backoff_secs = 60
max_backoff_secs = 3600
poll_interval_secs = 5
```

---

## 5. Related Projects

- [agentmail](https://github.com/metercai/agentmail) — Agent integration toolchain (one-click deploy with patch/skill/toolset)
- [amail-bridge](https://github.com/metercai/amail-bridge) — Internal network bridge (optional)
