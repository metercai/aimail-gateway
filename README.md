English | [🇨🇳 中文](README_zh.md)

# aimail-gateway

![Rust](https://img.shields.io/badge/Rust-orange) ![Platform](https://img.shields.io/badge/platform-linux%20%7C%20macOS%20%7C%20windows-969696) ![License](https://img.shields.io/badge/License-MPL--2.0-blue)


This is **the bidirectional mail gateway built for AI Agents** — it gives Agents a two-way SMTP/HTTP channel for inbound and outbound mail forwarding, so an Agent joins the global email network over plain HTTP and uses email freely for conversation and collaboration.

---

## 1. What is aimail-gateway

aimail-gateway is a lightweight, high-performance bidirectional Rust mail gateway. It shields Agents from a crowd of legacy mail protocols (SMTP/POP3/IMAP) and sends and receives mail through a native REST API instead:

- **Inbound:** Traditional solutions rely on IMAP/POP3 polling against a cloud-hosted inbox — high latency, wasted resources. aimail-gateway pushes inbound mail to the Agent in real time via Webhook and drives the mail pipeline with message events. Inbound mail is stored and searched on the Agent side; the gateway keeps nothing.
- **Outbound:** aimail-gateway exposes an HTTP `send_mail` API. An Agent sends mail with a single toolset call. Same-gateway recipients are delivered by an internal Webhook; external addresses go out over SMTP. Two routes in, two routes out — fast and efficient.

On top of native mail send/receive, aimail-gateway is purpose-built for what Agent mail actually looks like:

- **Security:** Agent mail addresses are fully exposed on the open mail network and will attract spam and other malicious traffic. aimail-gateway enables bidirectional whitelist control by default and binds a human manager to every Agent, building a security boundary for each Agent, governing critical operations, and eliminating any risk of losing control.
- **Content:** raw HTML/MIME mail is inefficient for LLMs and badly token-wasteful. aimail-gateway ships a built-in content pipeline that extracts the key information, strips styling noise, and hands clean Markdown to the Agent.

Once an Agent holds a globally unique mail address, its identity is globally identifiable and its messages can be routed and delivered. Sending and receiving mail then stops being plain message transport and becomes an ongoing multi-party conversation with the outside world — and **collaboration**. aimail-gateway therefore also provides the tooling teamwork needs: **contact profiling**, **session summaries**, **identity cards**, and the **A2A board & task engine**.

**aimail-gateway connects different Agent systems with the traditional mail network — the infrastructure of a hybrid human–Agent internet** — while [AIMail](https://github.com/metercai/aimail) provides the aimail CLI and SDK that onboard and maintain the various Agent systems. Together they form a human-led network where cross-platform Agents converse and collaborate freely.

---

## 2. Features

**Inbound:**
- **Standard SMTP** — port 25, compatible with any mail client
- **Multi-domain** — receive mail for multiple domains on one gateway
- **Webhook push** — real-time HTTP POST to Agent Webhook URL
- **Multi-address aggregation** — batch push to multiple recipients at once
- **Webhook hybrid mode** — push/pull mixed delivery for the same email
- **Instant rejection of invalid inbound** — invalid recipients, oversized mail, internal-address senders rejected instantly to save resources
- **Push scheduling** — async queue push, auto-retry on failure, expired resource cleanup

**Outbound:**
- **Pre-upload attachments** — dedicated upload endpoint for higher delivery success
- **HTTP send API** — JSON-format mail over HTTP, Agent-friendly
- **SMTP outbound** — direct delivery to the target mail domain, or through a configured external relay
- **Internal forwarding** — same-gateway recipients delivered internally, no detour across the public network
- **Outbound scheduling** — async queue delivery, auto-retry on failure, expired resource cleanup
- **Bounce handling** — RFC 3464 compliant automatic post-send bounce recognition and processing

**Security:**
- **Default bidirectional whitelist** — unauthorized senders cannot get in; outbound content cannot reach unauthorized recipients
- **Bound manager** — a manager address per Agent; mail commands govern critical operations and act as a safety net
- **API Key authentication** — independent key per Agent, multi-scope management
- **Tiered API keys** — system/domain/agent key levels, isolated per scenario and never exposed to each other
- **Behavior scoping** — role and scope-based behavior limits that avoid risky actions
- **Loop prevention** — internal recipients never relayed externally, internal senders never accepted inbound, auto-replies never retried, so no cycles can form
- **Audit logging** — critical operations fully recorded and auditable

**Content:**
- **Encoding detection** — detect mail encoding automatically and convert to UTF-8
- **Attachment management** — attachments extracted and served for download, metadata travels with the mail
- **Format conversion** — body cleaned and converted to Markdown, directly consumable by LLMs
- **Information extraction** — sender signature extraction for identity recognition
- **Thread tracking** — automatic In-Reply-To / References chain maintenance
- **Mail snapshots** — raw mail is not retained; the Agent stores, searches, and audits on its own

**Collaboration:**
- **Contact profiling** — dynamic profiles per contact, so replies land better
- **Session summary** — topic summaries per session, keeping conversations coherent and orderly
- **Identity cards** — a tiered identity-card response flow for the public (strangers) and acquaintances (contacts): secure, trustworthy, low-cost role discovery that helps task collaboration
- **A2A board** — pipeline view + task dependencies + assignee tracing, all at a glance
- **A2A task engine** — instruction flow + session flow + notification flow, event-driven autonomous collaboration
- **Definable roles and behaviors** — roles and behaviors defined by config data and prompts; an LLM-native workflow engine
- **Owner-controlled goals & deliverables** — human–Agent hybrid workflows where goals and outputs are solely controlled by the human (Owner)

---

## 3. Quick Start

aimail-gateway must interconnect with the external mail system. Prepare a VPS and open the configured smtp and http ports in the firewall.

The gateway has exactly one runtime config file, `config.toml` (read from `./config.toml` by default; use `-c/--config` to point elsewhere). The repository-root `.env` only serves the deploy scripts below (SSH connection details) — it is not the gateway's runtime config.

```bash
cp .env.example .env
# Edit .env with:
#   AIMAIL_DEPLOY_HOST    — VPS IP address
#   AIMAIL_DEPLOY_USER    — SSH login user
#   AIMAIL_DEPLOY_KEY     — SSH private key path (optional)
#   AIMAIL_DEPLOY_PORT    — SSH port (optional, default 22)
```

### Option A: Binary Deployment

```bash
# 1) Prepare the runtime config (smtp.hostname is required and must match the VPS PTR record)
cp config.toml.example config.toml   # edit config.toml before uploading

# 2) Build and upload the binary (→ /usr/local/bin/aimail-gateway), install the systemd unit
bash deploy-bin.sh build
bash deploy-bin.sh upload
bash deploy-bin.sh setup-systemd     # the unit's ExecStart reads /etc/aimail/config.toml

# 3) Upload the runtime config (the deploy script ships the binary and the systemd unit, not the config)
set -a; . ./.env; set +a
ssh -p "${AIMAIL_DEPLOY_PORT:-22}" -i "${AIMAIL_DEPLOY_KEY:-$HOME/.ssh/id_deploy}" \
  "${AIMAIL_DEPLOY_USER}@${AIMAIL_DEPLOY_HOST}" "mkdir -p /etc/aimail /var/aimail"
scp -P "${AIMAIL_DEPLOY_PORT:-22}" -i "${AIMAIL_DEPLOY_KEY:-$HOME/.ssh/id_deploy}" config.toml \
  "${AIMAIL_DEPLOY_USER}@${AIMAIL_DEPLOY_HOST}:/etc/aimail/config.toml"

# 4) Start and check health
bash deploy-bin.sh start
bash deploy-bin.sh health            # probes http://127.0.0.1:8080/health
```

### Option B: Docker Deployment

```bash
# 1) Build the image (.git is not in the build context — pass the version via GIT_COMMIT;
#    the build needs access to crates.io)
TAG=$(git rev-parse --short HEAD)
docker build --build-arg "GIT_COMMIT=${TAG}" -t "aimail-gateway:${TAG}" .

# 2) Run as root: the image ships a non-root user, but port 25 and the data directory
#    both require root. config.toml is the same file as in Option A; with the default
#    storage path (./data) the container stores into /data, so mounting it persists state.
docker run -d --name aimail-gateway --restart unless-stopped --user 0:0 \
  -p 25:25 -p 8080:8080 \
  -v /etc/aimail/config.toml:/etc/aimail/config.toml:ro \
  -v /var/aimail:/data \
  "aimail-gateway:${TAG}" --config /etc/aimail/config.toml

# 3) Health check (the image has no shell — probe from the host)
curl -sf http://127.0.0.1:8080/health
```

---

## 4. Configuration

### Key Settings

| Field | Section | Description |
|------|---------|-------------|
| `bind` | `[smtp]` | Inbound SMTP listen address, default `0.0.0.0:25` |
| `hostname` | `[smtp]` | **Required.** EHLO hostname and PTR name for outbound connections; must match the VPS PTR record (e.g. `mail.example.com`); startup fails without it |
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
hostname = "mail.example.com"           # Required: EHLO/PTR name, must match the VPS PTR record
# max_message_size = 10485760
# max_connections = 100

[relay]
# smtp_server = "smtp://smtp.example.com:587"
# username = "relay@example.com"
# password = "your-password"
# dns_server = "127.0.0.1:53"
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
# file = "/var/log/aimail-gateway.log"

[admin]
# email = "admin@yourdomain.com"

[board]
# heartbeat_stale_seconds = 14400
# task_timeout_seconds = 259200
# sweeper_interval_seconds = 900
# max_active_boards = 5
# archive_retention_days = 90
```

### Environment Variable Overrides

The following environment variables override the matching settings. Precedence: built-in defaults < `config.toml` < environment variables (handy for container/CI deployments where you'd rather not edit the config file):

| Environment variable | Overrides |
|---------|---------|
| `AIMAILGW_HTTP_ADDR` | `[http] bind` |
| `AIMAILGW_SMTP_ADDR` | `[smtp] bind` |
| `AIMAILGW_STORAGE_PATH` | `[storage] path` |
| `AIMAILGW_RELAY_SMTP_SERVER` | `[relay] smtp_server` |
| `AIMAILGW_RELAY_USERNAME` | `[relay] username` |
| `AIMAILGW_RELAY_PASSWORD` | `[relay] password` |
| `AIMAILGW_LOGGING_LEVEL` | `[logging] level` |

---

## 5. Related Projects

- [AIMail](https://github.com/metercai/aimail) — the AIMail main repository, containing the aimail CLI and the aimail SDK: it connects different Agent systems to aimail-gateway and handles day-to-day maintenance on the host.
