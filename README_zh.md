[English](README.md) | 🇨🇳 中文

# amail-gateway

![Rust](https://img.shields.io/badge/Rust-1.75%2B-orange) ![Platform](https://img.shields.io/badge/platform-linux%20%7C%20macOS%20%7C%20windows-969696) ![License](https://img.shields.io/badge/License-MPL--2.0-blue)


**AI Agent 专属的双向邮件网关**——为每个 Agent 提供 SMTP 收信和 HTTP 发信的即时邮件通道，让 Agent 无缝接入全球邮件网络。

---

## 1. 什么是 amail-gateway

amail-gateway 是一个轻量级、高性能的 Rust 邮件网关，重点解决了 Agent 收发邮件的两个核心问题：

- **收信：** 传统方案依赖 IMAP/POP3 轮询，延迟高、资源浪费。amail-gateway 通过 Webhook 实时推送入站邮件，无需轮询。
- **发信：** 提供标准 HTTP API，Agent 调用 toolset 即可发信。同域收件人走内部 Webhook 直转，外部地址走 SMTP 转发。

此外，amail-gateway 针对 AI Agent 的邮件使用实际场景，做了专门的优化：

- **安全：** Agent 不应暴露在开放的邮件网络中承受垃圾邮件和恶意攻击。amail-gateway 默认白名单机制，非授权发件人无法触达 Agent，同时 Agent 也无法给非授权收件人发送内容。每个 Agent 配置安全员，对关键操作进行把关，对完全兜底。
- **内容：** LLM 处理原始 HTML/MIME 邮件效率低、浪费Token。amail-gateway 具有内容处理链，自动提取关键信息，剥离样式噪声，转换为 LLM 适用的 Markdown 干净文本。
- **协作：** Agent 收发邮件的目的不仅仅是信息传递，更重要的是与外界的会话与协作。amail-gateway 内置了指令邮件和 A2A 看板引擎，可以用邮件协议实现 Agent 之间的自主协作。

**amail-gateway 是 AgentMail 的核心基础设施**，在 [AgentMail](https://github.com/metercai/agentmail) 提供的集成工具链配合下，可以实现 Agent 的一键邮件接入。

---

## 2. 功能特性

**收信：**
- SMTP 标准协议入站 — 标准 25 端口，兼容任何邮件客户端
- 多域名支持 — 同网关接收多个域名的邮件
- Webhook 推送 — 实时 HTTP POST 到 Agent Webhook URL
- 多地址聚合推送 — 多目标地址聚合一次性推送
- Webhook 混合模式 — 同一封邮件支持混合(push/pull)模式推送
- 派生地址兼容 — 兼容一个 Agent 主地址派生的多身份地址: `{role_name}.{agent_name}@{mx_domain}`
- 即时阻断无效入站 — 无效收件人/超大邮件/内地址发件人等即时拒绝，节省资源占用
- 推送调度 — 异步队列推送，失败自动重试，过期资源自动回收

**发信：**
- 附件提前上传 — 独立附件上传接口，提高邮件发送成功率
- HTTP发信API — JSON格式邮件，HTTP发送接口, Agent友好
- SMTP 标准协议出站 — 可配置的外部邮件中继发送服务
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
- 身份自述 — 对陌生人和联系人的分级 `[WHOAMI]` 指令邮件响应，利于角色发现
- A2A 看板 — 流程视图 + 任务依赖 + 责任人追溯，一目了然
- A2A 任务引擎 — 指令流 + 会话流 + 通知流，事件驱动自主协作
- 角色可定义 — 角色与行为通过配置数据和prompt自定义，LLM 原生驱动的工作流引擎
- 人类主控 — 人与 Agent 混合的工作流，目标和产出由人类主控

---

## 3. 快速开始

amail-gateway 需要与外网邮件系统互联，建议先准备好一台 VPS，防火墙打开配置的smtp和http端口。

```bash
cp .env.example .env
# 编辑 .env 填入：
#   AMAIL_DEPLOY_HOST    — VPS IP 地址
#   AMAIL_DEPLOY_USER    — SSH 登录用户
#   AMAIL_DEPLOY_KEY     — SSH 私钥路径（可选）
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
[smtp]
bind = "0.0.0.0:25"
hostname = "amail.yourdomain.com"       # 与 PTR 记录一致
max_message_size = 26214400             # 25 MiB
max_connections = 100

[http]
bind = "0.0.0.0:38080"

[relay]
smtp_server = "smtp://smtp.example.com:587"
username = "relay@example.com"
password = "your-password"
auto_reply_subject_prefix = "Re: "
delivery_window_secs = 7200             # 退信关联窗口（2h）

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

## 5. 相关项目

- [agentmail](https://github.com/metercai/agentmail) — Agent 集成工具链（一键部署，含patch/skill/toolset）
- [amail-bridge](https://github.com/metercai/amail-bridge) — 内网穿透桥接（可选）
