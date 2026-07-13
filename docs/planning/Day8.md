# Day 8：TestObject、L2ActionBundle 与 Cleanup 纯状态模型

## 当天目标

只建立 L2（敏感但可回退动作）的确定性领域协议、持久化状态和失败关闭规则，不连接目标、不发送 HTTP/浏览器请求，也不产生任何真实副作用。当天要回答的是“一个可变状态动作必须具备哪些可验证前提、如何被精确描述、发生中断后允许走向哪些状态”，而不是提前实现审批或执行。

Day 8 结束时，L2 必须从 `userApproved=true + cleanupPlan` 这样的松散约定，收敛为可校验、可审计、可恢复但不可自动重放 primary 的事务模型。Day 9 才提供 identity/session/CSRF 的真实绑定值，Day 10 才提供可信批准并在 loopback fixture 上首次执行。

## 前置条件与边界

- 复用 Day 4 的规范化请求、intent hash 与最终请求绑定设计，复用 Day 5 的 ExecutionGrant/Lease 和预算语义；不得另建旁路执行器。
- Day 7 的 loopback fixture 本日只可作为后续协议设计参照，不得对其发送 L2 请求。
- `SessionVault`、`IdentityContext`、CSRF 生命周期和可信 `ActorContext` 尚未实现，因此本日只定义相应的强类型引用槽位与“缺失即不可批准/不可执行”约束，不伪造 generation、身份归属或批准者。
- Agent 只可提出候选 Bundle；Renderer 只可展示脱敏状态。两者都不能创建批准、推进状态、写 Receipt 或调用 cleanup。
- Renderer 不新增页面、按钮、IPC 批准入口或会话管理 UI；如合同变化影响现有 UI，只保持编译兼容。
- 网络调用计数必须为 0；任何集成测试都只能使用纯内存/Repository 测试替身。

## 具体工作

### 1. 建立专用测试对象合同

定义 `TestObject` 及其版本化 schema，至少包含：

- `testObjectId`、scan/target/identity/tenant 引用、对象类型和对象版本；
- 明确的 `createdByAgentGo` 或等价不可伪造来源证明、创建时间、有效期与 disposable 标记；
- 允许读取/修改的精确 field/state 白名单，不允许使用“整个对象”“任意字段”等宽泛表达；
- 所有权证明引用、创建证据 hash、当前基线证据 hash 与资源的规范化精确标识；
- cleanup capability 引用及目标显式声明的 cleanup 协议；
- 失效、被外部修改、归属变化和 tenant 变化时的关闭条件。

对象归属不得由模型推断。缺少 AgentGo 创建证明、disposable 标记、精确资源标识或所有权证据时，该对象只能参与 L1 只读验证，不能进入 L2 候选。

### 2. 建立副作用封装

定义 `SideEffectEnvelope`，至少记录：

- 允许发生的单一预期状态变化和最大影响范围；
- 允许写入的资源、字段、旧值约束和目标新值约束；
- 邮件、短信、队列、webhook、计费、缓存失效、审计告警等外部副作用清单；
- pre/post/terminal observation 的证据角色与判定规则；
- 未知副作用、不可观测副作用和无法恢复项。

只要存在未声明或不可回退副作用，Bundle 即保持 `ineligible`，不得通过后续批准服务把它提升为可执行。

### 3. 定义有序 L2ActionBundle

定义不可变、可哈希的 `L2ActionBundle`：

1. `pre-read`；
2. 至多一个 `primary`；
3. `post-read`；
4. `cleanup` 或有充分证据的 `cleanup-not-needed`；
5. `cleanup-verify`；
6. `terminal-read`。

每一步绑定 Day 4 intent hash、Day 5 grant/lease purpose、精确 TestObject 版本、Scope 快照、module/technique/version 和预算。Bundle 预留必须由 Day 9 提供的 `identityContextVersion`、`sessionGeneration`、`csrfBindingVersion`；这些引用未解析前只允许 `draft`，不能进入 `pending-approval`。

Bundle 变更不得原地覆盖：请求、顺序、Scope、对象、副作用、身份、会话、CSRF、模块版本或 cleanup 协议任一变化，都生成新版本与新 hash，并让旧候选失效。

### 4. 把 cleanup 定义为窄化专用能力

明确以下不可协商规则：

- 通用/未知语义的 HTTP `DELETE` 永久禁止；删除生产对象、真实业务对象或非 AgentGo 所有对象永久禁止。
- cleanup 不属于漏洞探测步骤，不能用于观察越权、猜测资源、批量枚举、扩大影响或替代 primary。
- 只有同时满足“AgentGo 创建、所有权已证明、disposable、精确资源 ID、同一 L2 Bundle/批准、目标显式声明 cleanup 协议”时，专用 `CleanupCapability` 才可描述一个 cleanup 动作。
- 该 capability 只允许调用目标声明的 `delete`、`revoke` 或 `reset` 语义；不得退化为向任意 URL 发送 DELETE。其目标、方法、资源 ID、预期终态和最大请求数必须在 Bundle hash 内。
- cleanup 完成后必须执行终态复核并签发 Receipt；无法复核时是 `cleanup-failed` 或 `inconclusive`，不能伪造成功。

本日只定义和校验上述 capability，不调用它。后续 Day 10 的可信批准必须覆盖 primary 与 cleanup；不得为 cleanup 临时放宽 Scope 或复用其他对象的批准。

### 5. 定义状态机与合法迁移

状态至少覆盖：

- `draft`、`ineligible`、`pending-approval`、`approved`；
- `running-pre-read`、`running-primary`、`primary-unknown`、`running-post-read`；
- `cleanup-pending`、`cleanup-running`、`cleanup-verifying`；
- `clean`、`cleanup-failed`、`expired`、`revoked`、`interrupted`、`inconclusive`。

定义事件、guard、version 和审计原因码，明确每个状态允许申请的 grant purpose。没有 Day 9 的 session/identity/CSRF 绑定和 Day 10 的可信批准时，迁移到 `approved` 或任何 `running-*` 状态必须失败。

primary 一旦“可能已发送”，恢复流程不得自动重放。系统先进入 `primary-unknown` 并要求 state-observe；仅在能证明 primary 未发送时才允许重新生成新 Bundle，否则只允许受限 cleanup/recovery 或人工接管。

### 6. 定义 Receipt 与失败冻结规则

- `CleanupReceipt` 绑定 Bundle hash、TestObject 版本、每步 Evidence hash、执行 actor、时间、最终资源状态和 cleanup capability。
- `not-needed-no-state-change` 仅可在 pre/post/terminal 三类完整证据一致且请求执行状态明确时签发；超时、响应丢失或证据缺失不得使用。
- cleanup 失败后冻结同 target/TestObject 的普通 L1/L2 队列，只允许专门的、范围更窄的 recovery proposal 或人工处置。
- 状态和 Receipt 只能由确定性 Application Service/Repository 写入；使用事务或 optimistic version 防止重复 primary、错序 step 和并发覆盖。

### 7. 明确本日不做事项

- 不实现 SessionVault、Cookie jar、CSRF 提取或多身份选择；
- 不实现 ActorContext、ApprovalService 或任何人工批准入口；
- 不执行 loopback fixture，不连接真实目标；
- 不新增 Renderer UI，不让 Agent/Renderer 直接调用 Repository；
- 不声称 L2 已可用于真实授权环境。

## 预计改动位置

- `packages/contracts/src/security.ts`、`packages/contracts/src/application.ts`：TestObject、Bundle、状态、Receipt 和强类型引用；
- `packages/domain/src/l2/**`：纯状态机、guard、hash 规范和失败关闭规则；
- `packages/db/src/schema.ts`、`migrations.ts`、`repository.ts`：版本化状态与不可变审计记录；
- `packages/domain`、`packages/db`、`packages/application` 对应的纯状态测试；
- `docs/security/active-probing-policy.md`、`docs/architecture/data-model.md`：同步协议和 cleanup 边界。

不得在 `http-runner`、`browser-runner`、Main IPC 或 Renderer 中加入 L2 执行代码。

## 测试与验收证据

- schema：缺 TestObject、缺 AgentGo 创建证明、非 disposable、归属/tenant/identity/version 不匹配、未知副作用、宽泛资源、无 cleanup 协议均拒绝；
- Bundle：step 缺失/错序、两个 primary、hash 漂移、未解析 session/identity/CSRF 引用、过期或撤销均不可进入批准态；
- 状态机：非法跳转、重复 primary、并发版本冲突、崩溃恢复、`primary-unknown` 与 cleanup failed freeze 全部覆盖；
- Receipt：Evidence hash、步骤、TestObject、actor 占位引用、时间和终态一一对应；证据不足时无法生成 `not-needed-no-state-change`；
- cleanup policy：普通 DELETE、真实业务删除、非 AgentGo 对象、非精确资源和跨 Bundle cleanup 全部拒绝；仅验证专用 capability 的静态资格，不发请求；
- 运行相关 contracts/domain/DB/Application 测试与 `pnpm typecheck`，并保存“HTTP runner/browser runner 调用次数均为 0”的测试证据。

## 合格交付

- L2 领域协议、状态迁移、Receipt 和 cleanup capability 均有版本化 schema、原因码、持久化设计和自动测试；
- 没有 session/identity/CSRF 与可信批准时，任何路径都不能进入执行态；
- 对普通/未知 DELETE 和真实业务删除保持永久禁止，唯一 cleanup 窄例外被绑定到 AgentGo 所有的 disposable TestObject；
- primary 的未知结果不会触发自动重放，cleanup 失败会冻结后续普通执行；
- 本日无网络、无真实副作用、无 Renderer 新功能，不能把该交付描述为“L2 已上线”。
