# AUDIT-3-FIX-PLAN — aimail-gateway 发版前修复方案

- 审计 HEAD: 4ca1f9e (v1.0.0, 2026-08-26)
- 日期: 2026-08-26
- 状态: **待评审**（评审通过后执行）
- 验证基线: cargo check 0 error 0 自身 warning / cargo test 196 全绿 / advanced cargo check 通过

修复顺序: P1-1 → P1-2 → P1-3 → P2 → P3（每项独立 commit, 便于回滚）
所有改动后: cargo check + cargo test + advanced cargo check 三绿。

---

## P1-1 【安全隐患】activate-address 公开端点可创建 platform 级 key

- 位置: src/core/api/activation.rs:65-108 (activate_address_code), :242-358 (activate_address_handler)
- 路由: src/core/api/http.rs:124 — `/api/v1/activate-address` 在 auth_layer 之外（无认证, 码即凭据, 设计如此）

### 根因
1. handler 把调用方 body 的 `scopes` 数组原样透传（:265-273 解析 → :328-334 传入 activate_address_code → :87-91 无过滤 → factory.create_api_key 直接入库）。DB 层 insert_api_key 不做任何 scope 校验, keys.rs 的分级/地址级校验全部被绕过。
2. `email_address` 不校验与激活码绑定地址一致 — 码泄露后可激活任意已注册域的任意地址。

### 攻击路径（实证）
```
POST /api/v1/activate-address
{ "code": "<任意有效 addr- 激活码>", "email_address": "", "scopes": ["platform"] }
→ create_api_key(system_id=<码的 system_id>, email="", scopes=["platform"], category="agent")
→ 生成 platform scope 的系统级 key（email 为空还跳过域校验）
```
拿到任意激活码（register_address 响应会返回 raw codes）即可提权到 platform。

### 修复方案（两步, 都在 activation.rs）
**A. scopes 固定, 忽略调用方输入（:87-91）**
```rust
// before
let actual_scopes: Vec<String> = if scopes.is_empty() {
    vec!["agent".to_string()]
} else {
    scopes.to_vec()
};
// after — 地址激活码永远只产生 agent scope key
let actual_scopes: Vec<String> = vec!["agent".to_string()];
```
同时删掉 handler 里的 scopes 解析（:265-273）与 activate_address_code 的 scopes 参数, 签名改为
`activate_address_code(db, code, email_address, factory)`。调用点同步（:328）。

**B. 校验 email 与码绑定地址一致（activate_address_code 内, :73-75 之后）**
```rust
// before
let (system_id, _) = db.lookup_activation_code(&hash).await?.ok_or(...)?;
// after
let (system_id, bound_email) = db.lookup_activation_code(&hash).await?.ok_or(...)?;
if !bound_email.is_empty() && !email_address.eq_ignore_ascii_case(&bound_email) {
    return Err(AppError::Internal("activation code is bound to a different address".into()));
}
```
语义: register_address 生成的码绑定具体地址（严格匹配）; batch_generate_codes（platform/system 管理端）不传 email 生成的码绑定为空 → 保持任意地址可激活（管理端通用码, 现有行为不变）。这避免破坏批量发码流程。

### 风险
- 低: 激活码语义收窄到"绑定地址", 是合理收紧; 管理端通用码行为不变。
- 需要确认: 集成脚本（setup_system.py / register_agent.py / agentmail activate_address）是否传 scopes 或依赖非绑定地址激活 — 修复前 grep 三侧确认。

### 验证
- 单测: 新增 test 覆盖 (a) scopes=["platform"] 激活 → 生成的 key 只有 agent scope; (b) 码绑定 alice@x.com 激活 bob@x.com → 拒绝。
- e2e: category 脚本/base-api-test 激活路径回归。

---

## P1-2 【数据丢失】PUT 更新域配置静默清空该地址全部 meta

- 位置: src/core/factory.rs:176-183 (update_domain)
- 触发: PUT /api/v1/admin/system-domains/{id} (http.rs:793-802) 改 webhook_url/webhook_secret/is_active

### 根因
update_domain 对含 `@` 的域记录（agent 地址）无条件调用
`upsert_domain_addr_meta(domain, system_id, None, None, None)` — upsert 是全列覆盖,
None 参数被 unwrap_or("") 变成空串 → ON CONFLICT DO UPDATE SET 把
manager_address / agent_signature / agent_persona 全部写成 ''。
改一次 webhook 配置 = 该 agent 的 manager 认证（SMTP 550）、出站签名、persona/WHOAMI 全丢。

### 修复方案
**删除 update_domain 里的 upsert 调用**（:176-183）。域 webhook 配置更新与 agent meta
无关 — meta 的生命周期由 create_domain（创建时 upsert manager）与 delete_domain
（删除时清 meta）负责。update 路径不触碰 meta 即正确。

```rust
// before (factory.rs:170-185)
pub async fn update_domain(&self, id, webhook_url, webhook_secret, is_active) -> ... {
    let existing = self.db.get_system_domain(id).await?;
    let result = self.db.update_system_domain(id, webhook_url, webhook_secret, is_active).await?;
    if let Some(ref record) = existing {
        if record.domain.contains('@') {
            let _ = self.db.upsert_domain_addr_meta(&record.domain, &record.system_id, None, None, None).await;
        }
    }
    Ok(result)
}
// after — 移除整个 if 块（existing 查询也不再需要, 一并删）
pub async fn update_domain(&self, id, webhook_url, webhook_secret, is_active) -> ... {
    self.db.update_system_domain(id, webhook_url, webhook_secret, is_active).await
}
```

### 备选（不推荐）
改 upsert_domain_addr_meta 的 Option 语义为 "None=保留旧值" — 需要先读旧行再合并,
影响所有 5 个调用方, 且引入"调用方必须知道 None 语义"的隐式契约。改动面大、易错。

### 风险
- 极低: 删除的是有害副作用。create/delete 路径不受影响。
- 需确认: advanced 是否覆盖 update_domain 或依赖其 meta 同步行为 — grep advanced。

### 验证
- 单测: 注册地址（含 manager）→ PUT 更新 webhook_url → 断言 meta 三字段不变。
- e2e: category-4 域管理用例回归。

---

## P1-3 【逻辑错误】无扩展名附件上传后下载 500

- save 侧: src/core/smtp/receiver.rs:118-121 + src/core/email/factory.rs:950-958
  均用 `Path::extension().unwrap_or("bin")` → 存成 `{id}.bin`
- load 侧: src/core/scheduler/deliver.rs:74-82 同用 Path::extension ✓
- **下载侧: src/core/api/files.rs:198 用 `rsplit('.').next().unwrap_or("bin")`** ← 唯一不一致

### 根因
`"report".rsplit('.').next()` 返回 `"report"`（无点 → 整个字符串）, unwrap_or 不触发,
于是找 `{id}.report` 而文件实际是 `{id}.bin` → open 失败 → 500。
AUDIT-1 P2-5 声称修复但只统一了保存侧与 SMTP 加载侧, files.rs 下载侧漏改。

### 修复方案
**在 AttachmentFactory 增加单一派生入口, 四处统一调用**（消除同类漂移的根因）:
```rust
// src/core/email/factory.rs, AttachmentFactory impl 内新增
/// 从文件名派生磁盘扩展名（保存/加载/下载共用同一规则, 防路径派生漂移）。
pub fn extension_for(filename: &str) -> &str {
    std::path::Path::new(filename)
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("bin")
}
```
改动点:
1. files.rs:198 → `let ext = AttachmentFactory::extension_for(&record.filename);`
2. receiver.rs:118-121 → 调用 extension_for
3. email/factory.rs save_attachment:950-958 → 调用 extension_for
4. deliver.rs:74-82 → 调用 extension_for

### 风险
- 低: 纯派生逻辑统一, 无行为变化（除修复无扩展名下载）。

### 验证
- 单测: save("report") → file_path 后缀 == "bin"; 模拟 load 路径一致。
- e2e: 上传无扩展名附件 → 下载成功（新增用例）。

---

## P2-1 【逻辑漏洞】approve persona 省略段清空已有值

- 位置: src/core/api/webhook.rs:528-560 (parse_persona_approval), :653-661 (PersonaApproval 分支)

### 根因
parse_persona_approval 返回 (String, String), 省略段 = 空串; 调用方
`upsert_domain_addr_meta(..., Some(signature), Some(persona))` 把空串也写入,
全列覆盖 upsert 清空已有签名/persona。
例: 经理只发 `approve persona\npersona: 我是助手` → signature="" → 已有签名被抹。

### 修复方案
**调用方按"省略段保留"合并**（最小改动, 不动 upsert 语义）:
```rust
// webhook.rs:653-661, PersonaApproval 分支
ManagerCommand::PersonaApproval { persona, signature } => {
    // 省略段（空串）保留已有值 — upsert 是全列覆盖, 不能传空串
    let sig = if signature.is_empty() { agent_meta.agent_signature.as_str() } else { signature.as_str() };
    let per = if persona.is_empty() { agent_meta.agent_persona.as_str() } else { persona.as_str() };
    if let Err(e) = env_factory.upsert_domain_addr_meta(
        to_addr, &agent_meta.system_id,
        Some(&agent_meta.manager_address),
        Some(sig), Some(per),
    ).await { ... }
}
```
同时补测试: 只含 persona 段 → 签名保持; 只含 signature 段 → persona 保持。

### 风险
- 低: 语义从"覆盖"改为"合并", 符合命令直觉。显式想清空签名的场景不受支持
  （可后续加 `signature: (空)` 显式清空语法, 本次不做）。

### 验证
- 单测: test_parse_persona_approval_only_persona / only_signature + upsert 合并断言。

---

## P2-2 【配置冲突】HMAC 签名 body cap 30MB 硬编码 vs 可配置附件上限

- 位置: src/core/api/auth.rs:27, :128

### 根因
auth_layer 先缓冲请求体（上限 MAX_SIGNATURE_BODY_BYTES=30MB）。advanced 产品
max_attachment_size 无上限校验（products.rs:19 裸 i64）, 配 >30MB 时上传被
auth_layer 413 — 配置允许但实际拒绝。

### 修复方案
**cap 与配置联动**: auth_layer 的 route_layer 闭包（http.rs:116-118）同时捕获
`state.config.storage.attachment_max_size`, cap 取 `max(30MB, attachment_max_size)` 再留余量:
```rust
// auth.rs — 常量改为函数
fn signature_body_cap(configured_max: usize) -> usize {
    configured_max.max(MAX_SIGNATURE_BODY_BYTES) + 1024 * 1024
}
// http.rs:116-118 route_layer 闭包
let api_env_factory = state.factories.email.env_factory.clone();
let body_cap = state.config.storage.attachment_max_size;
route_layer(from_fn(move |req, next| auth_layer_with_cap(api_env_factory.clone(), body_cap, req, next)))
```
auth_layer 增加 body_cap 参数（或从闭包传入）。base 默认 20MB → cap=31MB, 行为不变;
advanced 配 50MB → cap=51MB。

### 备选（不推荐）
只把常量提到 64MB — 仍可能与更大的配置冲突, 治标不治本。

### 风险
- 中: auth_layer 签名变化（加参数）, 是 base 公共 API — advanced 若直接调用 auth_layer
  需同步。grep advanced 确认后执行。
- 低: 内存占用随配置线性（每个请求缓冲 ≤ cap+1MB）。

### 验证
- e2e: 配 attachment_max_size=40MB 的 advanced 环境上传 35MB 附件成功（不 413）。

---

## P2-3 【逻辑错误】smtps:// 无端口时默认 25 而非 465

- 位置: src/core/smtp/transport.rs:55-58

### 根因
`None => (scheme_stripped, 25)` 对 smtps:// 也落 25, SMTPS 标准端口是 465。
配置 `smtps://mail.example.com`（省略端口）→ TLS 连 25 端口失败。

### 修复方案
```rust
// before
let (host, port) = match scheme_stripped.rsplit_once(':') {
    Some((h, p)) => (h, p.parse::<u16>().unwrap_or(25)),
    None => (scheme_stripped, 25),
};
// after — 默认端口按 scheme 区分
let (host, port) = match scheme_stripped.rsplit_once(':') {
    Some((h, p)) => (h, p.parse::<u16>().unwrap_or(if has_scheme == "smtps" { 465 } else { 25 })),
    None => (scheme_stripped, if has_scheme == "smtps" { 465 } else { 25 }),
};
```
（has_scheme 已是 &str, "smtps" 分支提前可读。）

### 风险
- 低: 仅影响"省略端口 + smtps://"的配置（此前必失败）。

### 验证
- 单测: build_transport 的端口解析（scheme×端口矩阵）。

---

## P2-4 【死代码】email/factory.rs build_with_attachments 删除

- 位置: src/core/email/factory.rs:688-730（手工 MIME 构造, filename 未转义）

### 根因
生产出站路径（sender.rs:18）import 的是 `crate::core::smtp::mime::build_with_attachments`
（lettre 版）。email/factory.rs 的版本 0 调用方（已 grep 全仓 + advanced 确认）。
保留是维护负担: 手工 base64 + 未转义 filename, 若未来误接会被投毒。

### 修复方案
删除 :688-730 函数。连带检查 base64_encode_wrapped（:733-749）是否还有调用方 —
grep 显示仅 build_with_attachments 用 → 一并删除（保留则标注）。

### 风险
- 极低: 纯删除, 无行为变化。cargo test 确认。

### 验证
- cargo check（删后无 unused warning）+ cargo test。

---

## P2-5 【断链】register_stranger_interceptor 的 legacy admin 迁移注释无实现

- 位置: src/core/server.rs:318-320

### 根因
注释声称 "Legacy support: if the bootstrap ID doesn't exist yet but there are
existing api_keys under 'admin', use admin once then migrate. One-shot migration."
下方无任何迁移代码 — 死注释（或曾有的逻辑被删）。

### 修复方案
删除该注释块（:318-320）。若需保留迁移语义, 需单独设计（bootstrap_id 已由
setup_admin_key 的 system.id 文件持久化, admin 迁移无实际入口）。

### 风险
- 极低。

### 验证
- 无（注释删除）。

---

## P2-6 【输出文本】bodyproc 装配输出硬编码中文标签

- 位置: src/core/email/bodyproc.rs:394, :403, :422-424

### 根因
assemble_layers 输出 `**发件人签名:**` / `**转发邮件:**` / `**回复:**` / `**引用:**`
/ `**原发件人签名:**` — 中文标签硬编码进 webhook payload body, 与代码库英文约定
（及用户"通知模板英文化"决策）冲突, 对非中文 agent 是噪音。

### 修复方案
改为**按内容语言自适应双语标签**(用户拍板, 与通知模板 has_cjk 双语模式一致):
- 检测: body 含 CJK 字符(Unicode 范围 \u{4e00}-\u{9fff} + \u{3000}-\u{303f} + \u{ff00}-\u{ffef})→ 中文标签, 否则英文标签。信号 = body 内容本身, 非系统 locale。
- utils.rs 新增 `pub fn has_cjk(text: &str) -> bool`(与 advanced 通知模板同逻辑, 供两处复用)。
- process_email_body 检测一次 `has_cjk(body)`, 传入 assemble_layers:
```rust
// bodyproc.rs
fn assemble_layers(layers: &[Layer], cn: bool) -> String {
    // cn=true: "**发件人签名:**" / "**转发邮件:**" / "**回复:**" / "**引用:**" / "**原发件人签名:**"
    // cn=false: "**Sender Signature:**" / "**Forwarded Message:**" / "**Reply:**" / "**Quoted:**" / "**Original Sender Signature:**"
}
pub fn process_email_body(body: &str, _is_html: bool) -> ProcessedEmail {
    let cn = crate::core::email::utils::has_cjk(body);
    let layers = decompose_layers(body);
    let assembled = assemble_layers(&layers, cn);
    ...
}
```

### 风险
- 低: 中英邮件各自得到母语标签, 符合既有双语模板约定。agent 侧不解析标签(仅人类可读), 无消费方影响(grep 确认)。

### 验证
- 单测: 中文 body → 中文标签; 英文 body → 英文标签; 混合 → 按检测结果。

---

## P3 批次（记录 + 低风险修复, 逐项）

### P3-1 死代码删除（已确认 advanced 无引用, 删除安全）
- records.rs:153-158 `sender_hash_prefix`（DefaultHasher 与 sha256 路径不一致, 恒未用）
- storage.rs:424-455 `update_email_status`（0 调用, factory 用专用状态方法）
- utils.rs:165-173 `parse_headers`（0 调用, 生产用 mailparse）
- 删除后 cargo check 确认无 unused。

### P3-2 config.rs:368-369 注释漂移
`AIMAILGW_HTTP_ADDR → http.addr` 实际字段是 `http.bind`（:373-377）。
注释改 `http.bind` / `smtp.bind`。

### P3-3 update_system_domain is_active=None 强制置 1（storage.rs:658）
```sql
-- before
SET webhook_url = ?1, webhook_secret = ?2, is_active = ?3 ...
-- is_active 参数 None → unwrap_or(1) → 部分更新变"重新激活"
-- after
SET webhook_url = ?1, webhook_secret = ?2, is_active = COALESCE(?3, is_active), ...
```
参数照传 Option<i32>（None → NULL → COALESCE 保留旧值）。

### P3-4 delete_system_domain 不清域缓存（storage.rs:670-677）
删除时 `domain_cache.remove(domain)`（需先查记录拿 domain）。

### P3-5 filter_external_recipients DB 错误静默丢收件人（sender.rs:361-362）
`Err(e) => warn + continue` → 改为 `return Err(...)`（DB 故障不应静默丢收件人）。

### P3-6 cleanup_deliveries 7 天硬编码（storage.rs:1585）
提取 `const DELIVERED_AUDIT_RETENTION_DAYS: i64 = 7;`。

### P3-7 激活限速表失败条目不清理（activation.rs:112-138）
check_activation_limit 顺带清理已过期条目（`since.elapsed() >= BLOCK_SECS` 时 remove）。

### P3-8 SystemDomainResponse.manager_address 恒空（types.rs:274-288）
**调研结论**（用户问询, 2026-08-26）:
- 用途: manager_address 是该 agent 地址的管理员邮箱, 三重作用: ① advanced SMTP
  认证发送的授权锚（strategy.rs:386-422, sender 必须命中 meta.manager_address）;
  ② register_address 自动建 Agent↔Manager 双向白名单; ③ 经理命令/接口权限判定
  （update_agent_meta、create_whitelist、approve persona 均以
  meta.manager_address == 调用方 为授权）。
- 来源: domain_addr_meta.manager_address 列（register_address 写入, PUT agent-meta 更新）。
  权威在 domain_addr_meta 表 — system_domains 表没有该列。
- 恒空根因: SystemDomainResponse 由 SystemDomainRecord（system_domains 行）转换,
  表无该列 → types.rs:283-285 硬编码 String::new(); base 的 list handler 不 JOIN meta。
  **advanced 已自行补齐**: advanced/storage.rs:1191-1205 域列表查询 JOIN
  domain_addr_meta 返回真实值。agentmail 侧不读响应字段（只传参 + 本地 config）。
- 结论: base 的"预留未接线"结构缺陷, 非设计如此。

**方案 C（推荐, base 补齐接线, 与 advanced 对齐）**:
- list_system_domains handler（http.rs:676 区域）: 对含 `@` 的地址型记录, 批量查
  domain_addr_meta（一次 IN 查询或逐条, 域数量少可接受）, 填充
  manager_address / agent_signature / agent_persona 三个字段。
- create/update 域 handler 的响应: 同步填充（create 时已有 manager_address 入参可回显;
  update 后查一次 meta）。
- 方案 B（删除字段）不可行: advanced create_domain_with_hints 读取
  base_resp.manager_address（advanced/api/http.rs:114）, 删除破坏 advanced 编译。
- 保留方案 A（标注 deprecated）作备选, 仅在 C 改动面被认为过大时选用。

### 验证
- 单测: 注册带 manager 的地址 → list_system_domains 响应 manager_address 非空;
  无 meta 的裸域记录 → 空串。

### P3-9 记录不修（说明理由）
- verify_api_key/list_api_keys_by_identity expires_at 亚秒边界 — 影响 <1s, 无害
- 空 identity 全表扫描 — 64 候选上限兜底, 文档已声明生产客户端应带 identity
- board 组白名单学习无签名锚 — 2026-08-16 已裁定攻击链不可达（anti-loop + 格式锚）
- webhook 通知无 ar- 前缀防护 — 实际链条终止于 wn- 的 [Overlimit] 防护, 无循环

---

## 影响面核对（base 改动 → advanced 编译）
执行前 grep advanced 确认: update_domain / upsert_domain_addr_meta /
auth_layer / AttachmentFactory::extension_for / parse_headers / update_email_status /
sender_hash_prefix 的引用情况（已知: 除 auth_layer 与 upsert 外均零引用）。
每项修复后跑 advanced cargo check。

## 提交计划
按 P1-1 → P1-2 → P1-3 → P2-1..6 → P3 顺序, 每项一个 commit,
提交信息前缀 fix(audit3)/chore(audit3)/refactor(audit3), 便于逐个回滚。
最后统一跑三绿 + 回归。
