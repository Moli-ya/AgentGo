# Day 10：可信批准服务与首条 L2 Loopback Fixture 闭环

## 当天目标

在 Day 8 的事务状态模型和 Day 9 的 identity/session/CSRF 基础全部通过验收后，移除不可信 `userApproved` 布尔语义，建立只由后端信任边界注入的 `ActorContext` 与 `ApprovalService`。随后仅在 Day 7 的 loopback fixture 上，对 AgentGo 创建且所有权已证明的 disposable TestObject 跑通第一条 L2 事务闭环。

当天不把 L2 开放给真实业务目标，也不开发 Renderer 批准 UI。fixture 使用的批准替身必须被清楚标注为 `fixture-only`；真实授权环境只有接入可认证、可审计、不可由 Renderer/Agent 伪造的后端可信批准端口后，才具备申请 L2 的必要条件。

## 前置条件与硬门禁

- Day 8 的 TestObject、SideEffectEnvelope、L2ActionBundle、状态机、CleanupCapability 和 Receipt 测试全部通过；
- Day 9 的 IdentityContext、SessionVault、CSRF binding、AuthorizationMatrix 与 generation 失效测试全部通过；
- Day 7 的基础 loopback fixture、attestation 和 Suite/Qualification 骨架可用；Day10 先为它增加一个版本化 L2 TestObject 场景，再执行闭环，不能把该场景反写成 Day7 已完成能力；
- Day10 新增的 fixture 对象必须具备 AgentGo 创建证据、精确资源 ID、所有权证明、初始状态和目标声明的 cleanup protocol，且没有外部邮件、队列、webhook、计费或生产依赖；
- 任一前置证据缺失时，当天只能实现审批模型和拒绝路径，不得执行 primary；
- Renderer 不新增批准、Session 或 L2 控制 UI，现有页面只需保持可用、可编译。

## 具体工作

### 1. 建立可信 ActorContext

定义 `ActorContext`，至少包含：

- `actorId`、角色/权限、认证时间、认证强度、可信 session ID；
- 审计来源、调用通道和可批准的 target/scope 范围；
- 短期有效期、撤销状态和不可伪造的后端签名/handle。

ActorContext 只能由 Main/Application composition root 或等价后端信任适配器注入。Agent、模型输出、Renderer payload、页面内容、fixture 请求和普通 IPC 输入均不能设置 `actorId`、`approvedBy`、`approvedAt`、角色或认证结果。

### 2. 定义真实授权所需的后端可信批准端口

提供稳定的 Application port（例如 `ApprovalPort`，具体命名以现有接口为准），支持 proposal 查询、`approve`、`reject`、`revoke` 与状态审计。该 port 必须：

- 要求可信 ActorContext，而不是接受 `userApproved=true`；
- 在后端完成身份认证/权限判断、批准签名与审计持久化；
- 只接收 Bundle ID/hash 和明确决策，不接收调用方自报的批准者/时间；
- 返回版本化 Approval record 和原因码，不直接返回 secret；
- 对未来 CLI、本地受控管理端或 UI 保持 transport-neutral，但当天不增加 Renderer 通道。

真实授权环境若尚无可认证的人类调用适配器，L2 必须保持禁用。测试用 `FixtureApprovalAdapter` 只能在 test/fixture build 中注册，记录中强制写入 `approvalMode=fixture-only`，报告不得把它描述为真实人工批准。

### 3. 生成完整、脱敏且可核对的 Approval Proposal

Proposal 至少展示/持久化以下非敏感信息：

- target/scope 快照、method、module/technique/version；
- 每一步 intent hash、顺序和 request count/concurrency/time 上限；
- Day 9 的 identityContextVersion、sessionGeneration、csrfBindingVersion、authorizationMatrixVersion；
- TestObject 精确引用、所有权证明摘要、SideEffectEnvelope；
- primary 的预期变化、cleanup capability、预期终态和有效期；
- 未知项、失败冻结规则和需要人工理解的风险。

Cookie、Authorization、CSRF、请求体敏感字段和 secret 只显示 sanitized preview/hash。proposal hash 绑定完整 Bundle，不允许批准后补写字段。

### 4. 实现 approve/reject/revoke 与强绑定

- Approval record 逐 Bundle、短期有效且单次使用；
- 批准签名/hash 绑定 Bundle hash、Scope、target、module version、TestObject/version、SideEffectEnvelope、ActorContext、identity/session/CSRF/矩阵版本和 cleanup capability；
- 任一请求 variant、session generation、CSRF、身份、对象、Scope、副作用、模块或 cleanup 变化，旧批准立即失效；
- reject/revoke/expire 后不得继续申请 primary grant；运行中撤销时按已发送状态进入安全停止或 cleanup/recovery，不伪造“从未执行”；
- 删除旧 `userApproved` 的授权含义；为兼容保留的字段必须被忽略并记录拒绝原因，不能作为旁路。

### 5. 建立逐步骤 L2ProbeOrchestrator

在确定性 Application Service 内按 Day 8 固定顺序执行：

1. 校验 Approval、Scope、预算、TestObject、session generation 和 CSRF binding；
2. `pre-read` 并保存角色化 Evidence；
3. 为唯一 `primary` 申请专用 ExecutionGrant/Lease，发送前再次核对 approval hash 与 generation；
4. `post-read` 判断预期状态变化与未知副作用；
5. 进入 cleanup 或在严格证据成立时签发 `not-needed-no-state-change`；
6. `cleanup-verify` 与 `terminal-read`；
7. 写入不可变 Receipt、审计和最终状态。

每一步使用独立 purpose 和最小能力。primary 最多一次；超时、崩溃、响应丢失或发送结果未知时进入 `primary-unknown`，不得自动重放。

### 6. 执行唯一允许的 fixture L2 闭环

只在 loopback fixture 创建一个隔离、可丢弃、无外部副作用的测试对象，并执行一条 POST form 或 JSON 状态改变：

`create fixture TestObject -> pre-read -> fixture-only approve -> primary -> post-read -> cleanup -> cleanup-verify -> terminal-read -> receipt`

闭环必须使用 Day 9 的专用测试 identity/session/CSRF 绑定。执行结束后对象状态与基线完全一致或对象按声明协议不存在，并有可验证 Receipt。不得复用该批准测试另一个对象、另一个 session generation 或另一个请求 variant。

### 7. 严格实现 cleanup 的窄例外

- 普通/未知语义 HTTP `DELETE`、生产数据删除、真实业务对象删除和非 AgentGo 对象删除继续永久禁止；
- 只有专用 `CleanupCapability` 可调用 fixture 明确声明的 `delete`、`revoke` 或 `reset`；
- cleanup 精确绑定 AgentGo 创建且所有权证明的 disposable TestObject、资源 ID、原 Bundle、同一批准、最大请求数和预期终态；
- cleanup 不是漏洞探测，不能收集越权信号、改变资源 ID、扩大 Scope、枚举对象或作为新的 validation primary；
- cleanup 后必须复核终态。失败时标记 `cleanup-failed`，冻结同 target/TestObject 普通执行，并输出人工恢复所需的脱敏证据。

### 8. 注入故障并验证恢复边界

覆盖 primary 前崩溃、primary 发送后响应丢失、post-read 超时、cleanup 失败、cleanup-verify 不一致、批准撤销和 session 轮换。验证：

- 明确未发送的 primary 只能通过新 Bundle/新批准重试；
- 可能已发送的 primary 不自动重放，只能 state-observe 后 cleanup/recovery/人工接管；
- cleanup 失败后普通队列冻结，恢复动作使用更窄的专用 proposal；
- fixture 测试完成后无残留对象、会话或未消费批准。

### 9. 保持 UI 与数据安全边界

- 不新增 Renderer View、按钮或可伪造批准的 IPC；
- Main/Preload 若为合同兼容必须调整，只暴露只读状态，不暴露测试批准适配器；
- audit、Evidence、错误和报告统一 secret stripping；
- fixture-only 批准在结果、报告和测试证据中显著标记，不得宣称代表生产人工审批或真实目标安全性。

## 预计改动位置

- `packages/contracts/src/application.ts`、`packages/contracts/src/security.ts`：ActorContext、Approval proposal/record、可信 port 和原因码；
- `packages/application/src/approval-service.ts`、`l2-probe-orchestrator.ts`：批准与逐步编排；
- `packages/db/src/schema.ts`、`repository.ts`：批准、状态事件和 Receipt 的不可变审计；
- Day 7 loopback fixture：合成 TestObject、session/CSRF、显式 cleanup protocol 与故障注入；
- Approval/L2/DB/fixture integration tests；
- Main composition root：只注册可信后端 port；不把 `FixtureApprovalAdapter` 暴露给产品构建或 Renderer；
- `docs/security/active-probing-policy.md`、`docs/architecture/data-model.md`：同步批准信任边界和 cleanup 窄例外。

## 测试与验收证据

- 信任边界：Renderer/Agent/普通 IPC 伪造 actor、role、approvedBy、approvedAt、`userApproved`、bundle hash 全部拒绝；
- 决策：approve/reject/revoke/expire、单次消费、角色越权和审计完整性；
- 强绑定：Scope、variant、module、TestObject、SideEffect、identity、session generation、CSRF、授权矩阵或 cleanup 任一变化都使批准失效；
- 正常闭环：fixture 终态等于基线或按协议删除，存在完整 Evidence 链与 CleanupReceipt，primary 请求数恰为 1；
- cleanup 边界：普通 DELETE、真实对象、非 disposable、无所有权证明、资源 ID 漂移、跨批准和把 cleanup 当探测全部拒绝；
- 故障恢复：primary 响应丢失/崩溃不重放，cleanup failed 冻结普通动作，recovery 需要独立且更窄的批准；
- secret sentinel：Cookie/Token/Authorization/CSRF/敏感 body 不出现在 proposal、DB 普通字段、Evidence 派生视图、日志、错误、报告或 Renderer；
- 构建隔离：产品 composition root 无 `FixtureApprovalAdapter`，fixture 报告含 `approvalMode=fixture-only`；
- 运行 approval/L2/session/DB/fixture integration tests、`pnpm typecheck` 和受影响构建；现有 Renderer smoke 必须继续通过。

## 合格交付

- 只有后端可信 ActorContext 能批准完整 Bundle，布尔字段、Agent 输出和 Renderer payload 无法伪造授权；
- 批准精确绑定 Day 9 的 session generation/identity/CSRF/授权矩阵，任一漂移都会失败关闭；
- 首条 L2 只在 loopback fixture 上执行，primary 恰好一次，cleanup 终态经复核且证据链完整；
- cleanup 的 delete/revoke/reset 仅限 AgentGo 创建、所有权已证明的 disposable TestObject，并且不能被用作漏洞探测；
- fixture 批准被明确标为 `fixture-only`，没有可信生产批准适配器时真实目标 L2 保持禁用；
- Renderer 无新增 UI 且继续可用，所有 secret 与审计边界通过测试。
