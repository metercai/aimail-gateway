[English](README.md) | 🇨🇳 中文

# aimail-gateway

![Rust](https://img.shields.io/badge/Rust-orange) ![Platform](https://img.shields.io/badge/platform-linux%20%7C%20macOS%20%7C%20windows-969696) ![License](https://img.shields.io/badge/License-MPL--2.0-blue)


这是**AI Agent 专属的双向邮件网关**——为 Agent 提供 SMTP/HTTP 的收发信双向邮件转发通道，让 Agent 以标准HTTP协议无缝接入全球邮件网络，可以自由的用邮件进行交流与协作。

---

## 1. 什么是 aimail-gateway

aimail-gateway 是一个轻量而高性能的 Rust 双向邮件网关。它为 Agent 屏蔽了复杂的SMTP/POP3/IMAP等众多传统邮件协议，而以原生的REST API来收发邮件：

- **收信：** 传统方案里需要依赖 IMAP/POP3 协议轮询访问托管在云端的inbox，延迟高，资源浪费。而aimail-gateway 则通过 Webhook 实时推送入站邮件消息，以消息事件驱动邮件处理流程。邮件正文与头部存于 Agent 本地并可检索，gateway 自身不留存 —— 它只保留投递与重试之间的临时暂存，无论投递成功与否，最终都会清除。
- **发信：** aimail-gateway 提供 JSON HTTP 发信接口（`POST /api/v1/send`）。 Agent 调用 toolset 即可完成发信任务。同 gateway 收件人走内部 Webhook 直投，外部地址则走 SMTP 转发。内外双路由，高效快捷。

aimail-gateway 在原生收发邮件基础上，还针对 Agent 邮件的场景特点做了专属优化，包括：

- **安全：** Agent 邮件地址完全暴露在开放的邮件网络中，将会遭受垃圾邮件等各种恶意攻击。aimail-gateway 默认开启双向白名单控制，并绑定安全员，为每个 Agent 构建安全边界，管控关键操作，杜绝失控风险。
- **内容：** LLM 处理原始 HTML/MIME 邮件效率低下，也严重浪费Token。aimail-gateway 内置了内容处理链，自动提取关键信息，剥离样式噪声，以 Markdown 的干净格式进入 Agent。

当 Agent 拥有了全网唯一的邮件地址，即身份可以被全网唯一标识，其消息可以被路由和送达。收发邮件将不仅仅是信息的传递，而是与外界持续的多方对话与 **协作** 。为此，aimail-gateway 同步提供了团队协作（teamwork）所需的工具支撑：**联系人画像**，**会话摘要**，**身份卡片**，**A2A看板与任务引擎**。

**aimail-gateway 连接了不同 Agent 系统与传统邮件网络，是人与 Agent 混合互联网络的基础设施**，而 [AIMail](https://github.com/metercai/aimail) 提供了 aimail 命令行工具与 SDK，负责不同 Agent 系统的接入和维护。它们共同构建了由人主导、跨平台 Agent 可自由会话与协作的全新网络。

---

## 2. 功能特性

**收信：**
- SMTP 标准协议入站 — 标准 25 端口，兼容任何邮件客户端
- 多域名支持 — 同网关接收多个域名的邮件
- Webhook 推送 — 实时 HTTP POST 到 Agent Webhook URL
- 多地址聚合推送 — 多目标地址聚合一次性推送
- Webhook 混合模式 — 同一封邮件支持混合(push/pull)模式推送
- 即时阻断无效入站 — 无效收件人/超大邮件/内地址发件人等即时拒绝，节省资源占用
- 推送调度 — 异步队列推送，失败自动重试，过期资源自动回收

**发信：**
- 附件提前上传 — 独立附件上传接口，提高邮件发送成功率
- HTTP发信API — JSON格式邮件，HTTP发送接口, Agent友好
- SMTP 协议出站 — 可直投目标邮件域，也可配置的外部邮件中继
- 内地址转发 — 同网关收件人内转直投，避免在外部网络兜圈子
- 发信调度 — 异步队列投递，失败自动重试，过期资源自动回收
- 退信处理 — 兼容RFC 3464标准的发信后自动退信识别和处理

**安全：**
- 默认双向白名单 — 默认拒绝非授权发件人（仅 `[WHOAMI]` 等通用身份查询会被应答），出站内容无法外发未授权收件地址
- 绑定安全员 — 为每 Agent 配置安全员地址，配套指令邮件管控关键操作，做安全兜底
- API Key 认证（HMAC 请求签名） — 每 Agent 独立 Key，多 scope 管理；明文 Key 不过网，协议见 `docs/API-SIGNATURE-PROTOCOL.md`
- 分级API key — 区分 system/domain/agent 等不同级别的key，各场景独立，互不见面
- 行为限定 — 基于角色和作用域的行为限定，规避行为风险
- 回环阻断 — 内收件人地址不外发，内发件人地址不入站，自动回复邮件不重试，避免循环调用
- 审计日志 — 关键操作全记录，可审计追溯

**内容：**
- 编码检测 — 自动识别邮件编码并转换为 UTF-8
- 附件管理 — 附件自动提取并转文件下载, 元数据随邮件流转
- 格式转换 — 正文格式清洗和转换到Markdown, LLM 可直接消费
- 信息提取 — 发件人签名提取, 有效识别和发现身份
- 线程追踪 — 自动维护 In-Reply-To / References 链路
- 不长期归档 — 原始邮件不留存，由Agent自行存储、检索和审计回溯，附件保留窗口见 `[storage] attachment_lifetime_hours`

**协作：**
- 联系人画像 — 为联系人建立动态画像，让回复更善解人意
- 会话摘要 — 记录会话的主题摘要，让会话自然连贯，井然有序 
- 身份卡片 — 面向公众（陌生人）和熟人（联系人）的分级身份卡片响应流程，确保安全、可信和低资源消耗的角色发现，有利于任务协作
- A2A 看板 — 流程视图 + 任务依赖 + 责任人追溯，一目了然
- A2A 任务引擎 — 指令流 + 会话流 + 通知流，事件驱动的自主协作任务
- 角色行为可定义 — 角色与权限模型由配置数据定义（网关自身不含 LLM；LLM 侧行为在 Agent 系统）
- 目标产出专属控制 — 人与 Agent 混合的工作流，目标和产出由人类（Owner）唯一主控

---

## 3. 快速开始

aimail-gateway 需要与外网邮件系统互联，需先准备一台 VPS，并在防火墙放行配置的 smtp 与 http 端口。

网关自身的运行时配置只有一份 `config.toml`（默认读当前目录的 `./config.toml`，可用 `-c/--config` 指定）；仓库根的 `.env` 只服务于下方的部署脚本（SSH 连接信息），不是网关的运行时配置。

```bash
cp .env.example .env
# 编辑 .env 填入：
#   AIMAIL_DEPLOY_HOST    — VPS IP 地址
#   AIMAIL_DEPLOY_USER    — SSH 登录用户
#   AIMAIL_DEPLOY_KEY     — SSH 私钥路径（可选）
#   AIMAIL_DEPLOY_PORT    — SSH 端口（可选，默认 22）
```

### 方式一：编译二进制部署

```bash
# 1) 准备运行时配置（smtp.hostname 必填，须与 VPS 的 PTR 记录一致）
cp config.toml.example config.toml   # 编辑 config.toml 后再上传

# 2) 编译并上传二进制（→ /usr/local/bin/aimail-gateway），安装 systemd 服务
bash deploy-bin.sh build
bash deploy-bin.sh upload
bash deploy-bin.sh setup-systemd     # 服务单元的 ExecStart 读 /etc/aimail/config.toml

# 3) 上传运行时配置（部署脚本只分发二进制与 systemd 单元，不分发配置）
set -a; . ./.env; set +a
# 若 ~/.ssh/id_deploy 不存在，脚本会省略 -i 并使用你的 ssh-agent
ssh -p "${AIMAIL_DEPLOY_PORT:-22}" -i "${AIMAIL_DEPLOY_KEY:-$HOME/.ssh/id_deploy}" \
  "${AIMAIL_DEPLOY_USER}@${AIMAIL_DEPLOY_HOST}" "mkdir -p /etc/aimail /var/aimail"
scp -P "${AIMAIL_DEPLOY_PORT:-22}" -i "${AIMAIL_DEPLOY_KEY:-$HOME/.ssh/id_deploy}" config.toml \
  "${AIMAIL_DEPLOY_USER}@${AIMAIL_DEPLOY_HOST}:/etc/aimail/config.toml"

# 4) 启动并体检
bash deploy-bin.sh start
bash deploy-bin.sh health            # 探测 http://127.0.0.1:8080/health
```

### 方式二：Docker 镜像部署

```bash
# 1) 构建镜像（.git 不在构建上下文中，版本号用 GIT_COMMIT 显式传入；构建需能访问 crates.io）
TAG=$(git rev-parse --short HEAD)
docker build --build-arg "GIT_COMMIT=${TAG}" -t "aimail-gateway:${TAG}" .

# 2) 启动（须用 root：镜像默认非 root 用户，而 25 端口与数据目录都需要 root 权限；
#    config.toml 同方式一，存储路径用默认 ./data 即容器内 /data，挂载即持久化）
docker run -d --name aimail-gateway --restart unless-stopped --user 0:0 \
  -p 25:25 -p 8080:8080 \
  -v /etc/aimail/config.toml:/etc/aimail/config.toml:ro \
  -v /var/aimail:/data \
  "aimail-gateway:${TAG}" --config /etc/aimail/config.toml

# 3) 体检（镜像内无 shell，健康检查从宿主机发起）
curl -sf http://127.0.0.1:8080/health
```

---

## 4. 配置说明

### 重点配置项

| 关键字段 | 配置段 | 说明 |
|---------|--------|------|
| `bind` | `[smtp]` | 入站 SMTP 监听地址，默认 `0.0.0.0:25` |
| `hostname` | `[smtp]` | **必填**。EHLO 主机名与出站连接的 PTR 名，须与 VPS 的 PTR 记录一致（如 `mail.example.com`）；缺失将启动失败 |
| `bind` | `[http]` | HTTP API 监听地址，默认 `0.0.0.0:8080` |
| `smtp_server` | `[relay]` | 外部邮件中继地址（如 `smtp://smtp.example.com:587`） |
| `username / password` | `[relay]` | 中继认证凭据 |
| `path` | `[storage]` | 数据目录（数据库、附件），默认 `./data` |
| `attachment_max_size` | `[storage]` | 附件大小上限 |
| `timeout_secs` | `[webhook]` | Webhook 推送超时（秒） |
| `max_attempts` | `[retry]` | 投递失败最大重试次数 |

### config.toml 示例

下方为常用键的节选，完整带注释的文件见 `config.toml.example`。

```toml
# 节选 —— 完整带注释的文件见 config.toml.example
[http]
bind = "0.0.0.0:8080"
# hostname = "mail.yourdomain.com"

[smtp]
bind = "0.0.0.0:25"
hostname = "mail.example.com"           # 必填：EHLO/PTR 名，须与 VPS 的 PTR 记录一致
# max_message_size = 10485760
# max_connections = 100
# channel_capacity = 1000

[relay]
# smtp_server = "smtp://smtp.example.com:587"
# username = "relay@example.com"
# password = "your-password"
# dns_server = "127.0.0.1:53"
# auto_reply_subject_prefix = "[Auto-Reply] "
# auto_reply_body = "This is an automated message from the aimail system. The delivery could not be completed after all retry attempts. For assistance, please contact your service administrator."
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
# readying_stuck_secs = 30

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

### 环境变量覆盖

以下环境变量可覆盖同名配置项，优先级为：内置默认值 < `config.toml` < 环境变量（容器/CI 部署时可不改配置文件）：

| 环境变量 | 覆盖字段 |
|---------|---------|
| `AIMAILGW_HTTP_ADDR` | `[http] bind` |
| `AIMAILGW_SMTP_ADDR` | `[smtp] bind` |
| `AIMAILGW_STORAGE_PATH` | `[storage] path` |
| `AIMAILGW_RELAY_SMTP_SERVER` | `[relay] smtp_server` |
| `AIMAILGW_RELAY_USERNAME` | `[relay] username` |
| `AIMAILGW_RELAY_PASSWORD` | `[relay] password` |
| `AIMAILGW_LOGGING_LEVEL` | `[logging] level` |

---

## 5. 相关项目

- [AIMail](https://github.com/metercai/aimail) — AIMail 系统主仓，包含aimail cli 和 aimail sdk，实现不同Agent系统与aimail-gateway的对接，以及本机的日常维护。
