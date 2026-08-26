# 主动探测与安全执行规范

## 1. 原则

AgentGo 必须具备主动探测能力。只做被动观察通常只能产生“疑似”，无法证明漏洞是否真实存在，也难以给出针对性修复建议。

主动探测的边界是：

- 有明确授权；
- 目标、路径、端口和身份均在 scope；
- 优先只读和低影响；
- 只执行获得结论所需的最小动作；
- 有速率、并发、时间和请求预算；
- 证据充分立即停止；
- 能清理临时测试数据；
- 永不执行破坏性动作。

## 2. 探测等级

漏洞名称不能直接决定探测等级。同一个 Family 中，不同 Technique 可能分别属于 L1、L2、Signal 或 fixture-only。V2 Module 只能声明所需 Capability；SecurityPolicy 根据实际 method、transport、body、环境、身份、对象和副作用取风险上界，模块和 Agent 都不能降级。

### L0：被动

不向目标新增请求，例如分析用户导入的 HAR、历史响应、公开文档和已有扫描记录。

### L1：安全主动探测

默认可在授权范围内自动执行：

- 页面和接口的低速访问；
- HEAD/GET/OPTIONS 等只读请求；
- 参数存在性、类型和基线差异测试；
- 惰性随机标记；
- 非写入式 SQL 差异验证；
- 隔离浏览器中的反射和 DOM 上下文验证；
- 两个授权测试身份之间的只读响应对照；
- 访问受控回连端点的 SSRF 验证；
- 已批准登录流程中的正常请求重放。

L1 仍必须经过 scope、预算、方法和 payload 摘要检查。

当前 V1 自动执行器只对 GET/HEAD/OPTIONS 与隔离浏览器本地渲染开放 L1 自动化。`POST`、`PUT`、`PATCH` 即使调用方声称“只读”，也默认进入 L2：必须有专用测试对象、可验证清理方案和逐次人工批准。这样既保留主动验证，也避免把真实业务写接口误当成安全探测入口。

上述“请求重放”仅指不改变状态的安全方法；带请求体或可能写入状态的重放适用 L2 规则。

### L2：敏感但可回退

必须逐次人工批准，并使用专用测试对象：

- 创建可删除的临时内容；
- 上传惰性文本或图片到明确测试目录；
- 对测试订单、测试账号或沙箱支付流程进行状态验证；
- 低速率限制验证；
- 访问明确列入 scope 的内部测试服务；
- 需要短暂改变测试对象状态、且能够确认清理的动作。

批准记录必须包含目标、动作摘要、预期副作用、清理方案、有效期和批准者。清理失败时任务立即停止并进入人工处理。

### L3：破坏性或不可接受

永久禁止，不能通过普通 UI 开关或 Agent 建议放行：

- DROP、TRUNCATE、ALTER DATABASE/TABLE；
- DELETE FROM、UPDATE、INSERT INTO 等生产数据写操作；
- 通用/未绑定 HTTP DELETE，或对生产、未知归属及真实业务对象的不可逆修改；
- 删除文件、格式化磁盘、停止关键服务；
- WebShell、恶意宏、持久化、计划任务、后门；
- 真实账号接管、密码修改、凭据喷洒；
- 横向移动、内网扩散、云元数据窃取；
- 高强度 DoS、资源耗尽和并发压测；
- 窃取 Cookie、Token、隐私数据或批量下载业务数据；
- 绕过 scope、审计、速率或人工批准。

SecurityPolicy 对 L3 返回不可覆盖的 DENY。

这里的 HTTP DELETE 指通用/未绑定删除、删除生产或未知归属对象，以及把删除本身作为漏洞证明。唯一窄例外是专用 `cleanup` capability：仅对 AgentGo 创建、所有权已证明且标记 disposable 的 TestObject，调用目标事先声明的精确 delete/revoke/reset 协议；它必须绑定原 L2 bundle、批准、scope、identity/session generation 和资源 ID，禁止枚举删除，执行后必须终态复核。该能力只能恢复测试状态，不能由漏洞模块当作探测步骤；目标没有安全清理协议时，对应 L2 Technique 不得激活。

## 3. Scope 强制执行

执行器必须在每一次实际网络动作前重新检查：

- scheme、hostname、解析后的 IP、port；
- path 前缀；
- 当前身份；
- scope 有效期；
- redirect 目标；
- DNS 重解析结果；
- 代理和回连地址；
- 剩余请求、并发和时间预算。

不能只在创建任务时检查一次。重定向、DNS rebinding、URL 编码和代理转发都不能成为越界通道。

reviewed HTTP 与离线 Browser 的实际 I/O 只能经统一
`ExecutionPort`。每个单步动作必须有不可变 Grant 和数据库原子 claim 的
Lease；HTTP 在 claim 后解析 DNS、Guard 授权地址并持久化 dispatch 后才
发送。Runner 不自动跟随 redirect，每一跳必须重新编译、重新经过 Policy、
签发 child Grant/Lease 并重新做 DNS guard。跨 origin credential 降为
`omit`，残留 Authorization/Cookie 等凭据头在发送前拒绝。

lease claim 必须在同一 SQLite 事务内原子 reserve 总请求、滑动窗口
RPM、并发、发送/接收字节和计划时长；超卖失败关闭。private/loopback/
link-local/reserved 只有 scope 网络条目精确列出 host 或 IP 或 CIDR、port
与 purpose 后才允许，旧布尔位不能整类放开。SSRF 目标侧地址与 AgentGo
执行侧地址分开校验。目标 URL 在 Policy 前做 canonicalization，解析歧义
fail closed。redirect 遇 https→http、非 HTTP(S) 或重解析变化立即停止。
HTTP 响应对 header 累计字节、原始 body、解压后大小、压缩比和慢读间隔
设硬上限；证据保存仍遵循 CapturePolicy。

## 4. 数据库相关探测

SQL 注入验证只允许使用非写入式、低影响差异策略：

- 基线请求；
- 布尔条件差异；
- 受限的错误特征；
- 严格超时上限下的时间差异；
- 负对照与重复验证。

禁止：

- 堆叠执行写语句；
- 修改 schema；
- 写入、删除或批量读取业务数据；
- 导出用户、密码、订单等真实敏感数据；
- 为扩大影响继续提权。

确认标准应优先依赖可重复差异和最小证据，而不是读取真实数据证明影响。

## 5. V1 漏洞族安全验证

### SQL 注入

确认至少需要可重复的测试/负对照差异，并排除缓存、网络抖动和普通异常。时间差异必须设置单请求超时和最大重复次数。

### XSS

使用无外传能力的随机标记和隔离浏览器观察执行上下文。反射不等于执行。存储型场景只能使用专用测试账号和临时对象，并在任务结束后清理。

已实现受保护原件的后端存储边界：完整 context/decision 封套、
OS-wrapped AES-256-GCM、内容寻址 ciphertext、普通读取/Renderer/报告
拒绝、metadata-only redacted derivative、配额、retention、crypto-erase
和审计。该能力不等于在线执行已采集证据。

实际在线路径仍固定保存 hash-only Browser 摘要，没有把真实 DOM 或
screenshot 通过 Lease provenance 接入 protected-original。真实 DOM/截图
采集、Lease 绑定和确认规则接线尚未接入。即使 marker 在隔离浏览器中
执行，只要缺少这条可复核证据链，就必须输出 `Inconclusive`，不能
Confirmed。

### SSRF

只允许访问项目控制的回连域名或显式授权的测试服务。默认阻断 localhost、链路本地、云元数据、RFC1918 私网和重定向到上述地址；只有这些地址本身明确属于实验 scope 时才可测试。

### 越权 / IDOR

至少准备两个授权测试身份和已知归属的测试资源。优先进行只读访问对照；不得修改或删除其他身份资源。发现可读取证据后立即停止扩大枚举。

## 6. WAF 与阻断

默认产品行为：

- 保存阻断响应；
- 降低速率并检查是否误触；
- 将结果记为 Not Confirmed 或 Inconclusive；
- 不自动进行编码混淆、分片或其他规避性绕过。

只有在专用靶场、规则明确允许且单独批准的研究任务中，才可启用受控的防护兼容性实验；该能力不得作为 V1 自动流程。

## 7. ProbeProposal

任何主动动作执行前必须形成结构化 Proposal：

- targetUrl、method、identityId；
- familyId、techniqueId、module/strategy version、SubjectRefs 和 hypothesis；
- capabilityIds、transport、body codec 和运行环境；
- probeLevel、sideEffect；
- payloadSummary，不保存不必要的敏感原文；
- expectedEvidence；
- maxRequests、timeout、rate；
- stopConditions；
- cleanupPlan；
- scopeSnapshotId。

Proposal/编译结果必须绑定 TemplateIntentHash、
ResolvedIntentHash 和 WireRequestHMAC；Runner 发送前使用单次
ExecutionLease 复核最终 method、URL、header/body、identity/session
generation、scope、capability、purpose、TestObject ref 和 stepId。
仅有 `policyDecisionId` 或 `userApproved=true` 不能授权执行。L2 已收敛为
可哈希的 TestObject / SideEffectEnvelope / L2ActionBundle /
CleanupReceipt 状态机，并由 Application 签发创建证明；专用 cleanup
capability 只允许目标声明的 POST/PUT/PATCH `delete|revoke|reset`，通用
HTTP DELETE 仍由 SecurityPolicy 永久禁止。SessionVault 与可信
ApprovalPort 尚未实现，因此没有解析后的 identity/session/CSRF
绑定和可信批准时，任何路径都不能进入 `pending-approval`、`approved`
或 `running-*`。产品环境 L2 继续禁用；不得把纯协议描述为已上线。
loopback fixture 上的首次 L2 执行尚未开放。

SecurityPolicy 返回 allow、deny 或 approval_required，并生成
policyDecisionId；ExecutionAuthority 以该决定签发 Grant/Lease。Runner
只消费 Guard 原子 claim 后的 opaque token，不接受调用方裸 decisionId。

protected-original 后端只接受与已允许 PolicyDecision、完整
EvidenceCaptureContext 和 protected-original CaptureDecision 一致的封套。
原文只作为瞬时加密输入，磁盘保存 ciphertext；普通 Evidence `read`、
Renderer、报告和导出均不得取得原文。该后端接口不能被 Agent、Runner 或
模型直接调用来扩大在线 capture authority。

## 8. 停止条件

出现任一情况立即停止当前候选：

- 已获得满足确认规则的最小证据；
- 目标离开 scope；
- 出现非预期状态变化；
- 发现真实用户或生产数据可能受影响；
- 清理失败；
- 连续重复且无新证据；
- 达到请求、时间、模型 Token 或速率预算；
- 会话或授权状态不明确；
- WAF/防护阻断且没有单独批准继续研究。

## 9. 证据与审计

每次主动执行至少记录：

- scope 和身份快照；
- Proposal 与 PolicyDecision；
- 请求方法、URL、头部脱敏摘要和 body 哈希；
- 响应状态、长度、时间、关键差异；
- 截图、HAR、DOM、回连记录等证据引用；
- 是否发生副作用；
- 清理结果；
- Agent、Prompt、模型、工具和规则版本。

没有这些证据时只能输出待验证假设，不能标记为 Confirmed。

必要原件获准进入 protected-original 后端时，还必须记录 capture
context/decision、source hash、保护计划、配额决定、retention、派生
Evidence 引用和创建/拒绝访问/完整性/到期审计。到期先 crypto-erase
wrapped key，再清理内容寻址 ciphertext；metadata-only derivative 可继续
用于普通 UI 和脱敏报告。在线 hash-only Evidence 不得仅因后端存在该
能力而改记为“已保存原件”。
