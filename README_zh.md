[English](README.md) | 🇨🇳 中文

# aimail-gateway

![Rust](https://img.shields.io/badge/Rust-1.75%2B-orange) ![Platform](https://img.shields.io/badge/platform-linux%20%7C%20macOS%20%7C%20windows-969696) ![License](https://img.shields.io/badge/License-MPL--2.0-blue)


**AI Agent 专属的双向邮件网关**——为每个 Agent 提供 SMTP 收信和 HTTP 发信的即时邮件通道，让 Agent 无缝接入全球邮件网络，可以自由进行邮件交流与协作。

---

## 1. 什么是 aimail-gateway

aimail-gateway 是一个轻量级、高性能的 Rust 邮件网关。它首先解决了 Agent 原生收发邮件的核心问题：

- **收信：** 传统方案里需要依赖 IMAP/POP3 协议轮询访问托管在云端的inbox，延迟高，资源浪费。而aimail-gateway 则通过 Webhook 实时推送入站邮件消息，消息事件驱动，无需轮询，本地文件夹即inbox。
- **发信：** aimail-gateway 提供 HTTP 协议的 send_mail API。 Agent 可以调用 toolset 即可完成发信任务。同 gateway 收件人走内部 Webhook 直投，外部地址则走 SMTP 转发，高效快捷。

其次，在原生收发邮件基础上，aimail-gateway 针对 Agent 的邮件场景特点做了专属优化，包括：

- **安全：** Agent 若完全暴露在开放的邮件网络中，将遭受垃圾邮件等各种恶意攻击。aimail-gateway 默认开启白名单控制，即每个 Agent 邮件地址都有双向可控的联系人地址簿。建立授信的安全边界，非授权不能发，非授权不能收，双向管控杜绝失控隐患。同时，系统还为每个 Agent 绑定人类安全员邮箱，可对关键操作进行把关。
- **内容：** LLM 处理原始 HTML/MIME 邮件效率低下，也严重浪费Token。aimail-gateway 内置了内容处理链，自动提取邮件关键信息，剥离样式噪声，内容最终转换为 LLM 友好的 Markdown 干净文本。

当 Agent 拥有全网唯一的邮件地址，就意味着拥有了全网唯一的身份。收发邮件不仅仅是信息传递，更是与外界进行持续的多方对话与 **协作** 。为此，aimail-gateway 也提供了团队协作（teamwork）所需的工具支撑：

- **联系人画像**，持续沉淀每个联系人的特征属性和关注焦点，让对话更善解人意。
- **会话记忆**，持续记录不同主题的会话摘要，让会话自然连贯，对答如流。
- **陌生人 WHOAMI**，向公众展示自身定位，便于角色的发现和高效率的角色会话。
- **A2A 看板引擎**，基于邮件协议实现异构多 Agent 之间的自主协作。

**aimail-gateway 连接着传统邮件网络和各类 Agent 系统，是人与 Agent 混合互联网络的基础设施**，而 [AIMail](https://github.com/metercai/aimail) 则是命令行工具，负责不同 Agent 系统的接入和维护。它们共同构建了由人主导、异构 Agent 间可自由会话与协作的全新网络。

---

## 2. 功能特性

**收信：**
- SMTP 标准协议入站 — 标准 25 端口，兼容任何邮件客户端
- 多域名支持 — 同网关接收多个域名的邮件
- Webhook 推送 — 实时 HTTP POST 到 Agent Webhook URL
- 多地址聚合推送 — 多目标地址聚合一次性推送
- Webhook 混合模式 — 同一封邮件支持混合(push/pull)模式推送
- 派生地址兼容 — 兼容一个 Agent 主地址派生的多身份地址，比如 Hermes Agent 的 Persona: `{role_name}.{agent_name}@{mx_domain}`
- 即时阻断无效入站 — 无效收件人/超大邮件/内地址发件人等即时拒绝，节省资源占用
- 推送调度 — 异步队列推送，失败自动重试，过期资源自动回收

**发信：**
- 附件提前上传 — 独立附件上传接口，提高邮件发送成功率
- HTTP发信API — JSON格式邮件，HTTP发送接口, Agent友好
- SMTP 协议出站 — 可直投目标邮件域，也可配置的外部邮件中继
- 内地址转发 — 同网关收件人邮件内转直投，避免外部公网兜圈子
- 派生地址兼容 — 兼容一个 Agent 主地址派生的多身份地址
- 发信调度 — 异步队列投递，失败自动重试，过期资源自动回收
- 退信处理 — 兼容RFC 3464标准的发信后自动退信识别和处理

**安全：**
- 默认双向白名单 — 非授权发件人无法触达 Agent，同时 Agent 无法将内容外发给未授权收件地址
- 安全管理员 — 每 Agent 配置安全管理员地址，关键操作需安全员确认做安全兜底
- API Key 认证 — 每个 Agent 独立 Key，多 scope 管理
- 分级API key — 区分 system/domain/agent 不同级别的key，各场景独立，互不见面
- 行为限定 — 基于角色和作用域的行为限定，规避出格行为
- 回还阻断 — 内收件人地址不外发，内发件人地址不入站，自动回复邮件不重试等，避免循环调用
- 审计日志 — 关键操作全记录，可审计追溯

**内容：**
- 编码检测 — 自动识别邮件编码并转换为 UTF-8
- 附件管理 — 附件自动提取并转文件下载, 元数据随邮件流转
- 格式转换 — 正文格式清洗和转换到Markdown, LLM 可直接消费
- 信息提取 — 发件人签名提取, 有效识别和发现身份
- 线程追踪 — 自动维护 In-Reply-To / References 链路
- 线程摘要 — 持久化线程上下文，Agent 跨会话保持记忆
- 原始快照 — 可选保存原始邮件，便于后续挖掘和审计回溯

**协作：**
- 联系人画像 — 为联系人建立动态画像，让回复更善解人意
- 会话摘要 — 记录会话的主题摘要，让会话自然连贯，井然有序 
- 身份自述 — 对陌生人和联系人的分级 `[WHOAMI]` 指令邮件响应，利于角色发现
- A2A 看板 — 流程视图 + 任务依赖 + 责任人追溯，一目了然
- A2A 任务引擎 — 指令流 + 会话流 + 通知流，事件驱动自主协作
- 角色可定义 — 角色与行为通过配置数据和prompt自定义，LLM 原生驱动的工作流引擎
- 人类主控 — 人与 Agent 混合的工作流，目标和产出由人类（Owner）主控

---

## 3. 快速开始

aimail-gateway 需要与外网邮件系统互联，建议先准备好一台 VPS，防火墙打开配置的smtp和http端口。如果没有VPS，可以到官方DEMO节点申请测试账号试用。如果需要生产性部署，可以到官方DEMO节点申请独立节点版本试用。

```bash
cp .env.example .env
# 编辑 .env 填入：
#   AIMAIL_DEPLOY_HOST    — VPS IP 地址
#   AIMAIL_DEPLOY_USER    — SSH 登录用户
#   AIMAIL_DEPLOY_KEY     — SSH 私钥路径（可选）
```

### 方式一：编译二进制部署

```bash
# 编译、上传并安装 systemd 服务
bash deploy-bin.sh build
bash deploy-bin.sh setup-systemd
bash deploy-bin.sh start
bash deploy-bin.sh health
```

### 方式二：Docker 镜像部署

```bash
# 构建带 commit hash 的镜像
bash deploy-docker.sh build

# 推送到远端服务器并启动
bash deploy-docker.sh push
bash deploy-docker.sh run
```

---

## 4. 配置说明

### 重点配置项

| 关键字段 | 配置段 | 说明 |
|---------|--------|------|
| `bind` | `[smtp]` | 入站 SMTP 监听地址，默认 `0.0.0.0:25` |
| `hostname` | `[smtp]` | EHLO 主机名，应与 PTR 记录一致（如 `amail.token.tm`） |
| `bind` | `[http]` | HTTP API 监听地址，默认 `0.0.0.0:8080` |
| `smtp_server` | `[relay]` | 外部邮件中继地址（如 `smtp://smtp.example.com:587`） |
| `username / password` | `[relay]` | 中继认证凭据 |
| `path` | `[storage]` | 数据目录（数据库、附件），默认 `./data` |
| `attachment_max_size` | `[storage]` | 附件大小上限 |
| `timeout_secs` | `[webhook]` | Webhook 推送超时（秒） |
| `max_attempts` | `[retry]` | 投递失败最大重试次数 |

### config.toml 示例

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

---

## 5. 相关项目

- [agentmail](https://github.com/metercai/agentmail) — Agent 集成工具链（一键部署，含patch/skill/toolset）
