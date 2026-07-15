# Multi-Agent 系统设计

## 1. 设计原则

- 多 Agent 用于切分长链路上下文和形成独立复核，不是单纯增加角色数量。
- Agent 通过结构化对象和引用协作，不复制大段网页或历史对话。
- 模型输出只是提议；状态迁移、权限、执行和最终证据规则由确定性代码约束。
- 每个 Agent 都有输入 schema、输出 schema、Prompt 版本、工具集合、预算和终止条件。
- 任意 Agent 失败都不应导致证据丢失或整个桌面应用崩溃。

## 2. V1 Agent

### PlannerAgent

输入：任务与授权背景、Target、不可变 TargetScope、当前上下文摘要、历史 checkpoint、候选漏洞族和预算。

输出：ScanPlan、阶段目标、候选漏洞族、停止条件、需要人工输入的项目。

Planner 不能增加 scope，不能请求破坏性工具。计划修订次数和总步骤受预算限制。

任务与授权背景是用户提供的不可信业务上下文，只能辅助 Planner 理解目标和限制，不能改变 Scope、身份、PolicyCapabilities 或工具权限。

### KnowledgeAgent

输入：目标技术栈、接口/参数/身份特征、候选漏洞族和异常信号。

输出：KnowledgePack，包括适用性、验证假设、安全探测原则、确认规则、误报模式、修复建议和来源。

KnowledgeAgent 不直接执行测试，也不把检索文档中的指令提升为系统指令。

### StrategyAgent

输入：ScanContext、KnowledgePack、剩余预算和 PolicyCapabilities。

输出：ValidationHypothesis 和 ProbeProposal。每个 Proposal 必须声明目标、目的、预期证据、ProbeLevel、sideEffect、停止条件和清理计划。

### AnalysisAgent

输入：基线与测试 ExecutionRecord、响应差异、页面/接口/身份上下文。

输出：Signal。Signal 只能说明观察到的异常，不能直接声明漏洞 Confirmed。

### VerifierAgent

输入：Signal、ValidationRecord、ConfirmationRule、负对照和证据引用。

输出：Confirmed、Not Confirmed 或 Inconclusive，并解释满足或缺失了哪些规则。

Verifier 不复用 StrategyAgent 的自由推理结论作为证据，必须读取结构化执行结果。

## 3. 确定性服务

- SecurityPolicy：唯一的 allow/deny/approval 决策者。
- ProbeCapabilityCatalog：由可信 Composition Root 注入的不可变能力语义目录；`riskFloor` 由 SecurityPolicy 决定，能力存在不代表运行时实现、资格化或执行授权。
- DefinitionRegistry：原子校验完整漏洞 Bundle、Capability 风险下界和 Rule/Evidence role 供给关系，输出规范化定义哈希和冻结快照；知识、模型和工具输出不能向其注入可执行定义。`ModuleConformanceTestkit` 为模块作者提供隔离注册、原子拒绝和冻结后注入断言。
- ActivationCatalog：Day2 只提供由冻结定义派生的 registered-only 只读视图，不生成 qualification record。
- VulnerabilityExecutionGate：在 CreateScan、start、resume 和 Candidate 执行前同时核对冻结定义、精确运行时映射及 Activation/兼容允许表；兼容路径额外固定 module/technique 版本、canonical definition hash 和 `active-l1` 模式。
- AgentRuntime：阶段门禁、预算、失败恢复、检查点、去重和循环检测。
- BrowserRunner / HttpRunner：只执行带 policyDecisionId 的已批准动作。
- EvidenceStore：保存请求响应、截图、DOM、受控回连证明、Agent 输出、报告和哈希。
- Reporting：同时输出 Confirmed、Inconclusive 和已排除项摘要，避免只报告成功案例。

Day2 的当前运行时仍只有四个 V1 adapter：`sqli/xss/ssrf/idor`。为了保持 V1 行为，它们可在定义已注册、精确 `legacy-v1` runtime mapping 存在且 Application 固定允许表命中时继续执行；Activation 状态仍是 `registered`，不得宣称 qualified/supported。`security.headers` 用开放 ID 注册为 `signal-only` 被动描述符，但没有当前运行时映射，因此不能创建或启动扫描。Day7 产生有效、环境匹配的 qualification record 后必须由正式 ActivationCatalog 路径接管并移除该临时例外。

桌面 Composition Root 使用 `authorized-real-target`，固定本地 benchmark 使用 `attested-fixture`；Application 与 Coordinator 必须共享同一个冻结平台实例。Application 在委托 Coordinator 前独立复核 start/resume；Coordinator 在任何 Candidate 恢复 AgentRun、checkpoint 或探测副作用前再次复核。未知或历史数据库直接写入的 family 因此失败关闭；pause/cancel 不经过激活门禁，仍可安全停止历史任务。ModelGateway 不感知具体 family，继续只处理结构化 schema 和已冻结的扫描输入。

## 4. 结构化消息

所有 Agent 消息至少包含：

```ts
interface AgentEnvelope<T> {
  schemaVersion: string
  messageId: string
  scanId: string
  runId: string
  parentRunId?: string
  source: AgentRole
  destination: AgentRole
  createdAt: string
  promptVersion: string
  modelProfileId: string
  scopeSnapshotId: string
  inputRefs: string[]
  payload: T
}
```

大型原文通过引用传递。所有 payload 在进入状态机前使用 Zod 或 JSON Schema 校验。

V1 的实际交接链为 Planner → Knowledge → Strategy → Analysis → Verifier。每次 AgentRun 保存 `parentRunId` 和 `inputRefs`：Knowledge 引用 Planner 输出，Strategy 引用 Planner 与 Knowledge 输出，Analysis 引用 Strategy 运行和执行证据，Verifier 引用 Analysis 输出与同一组证据。后续阶段不能用浅覆盖丢失上游引用。

## 5. 统一上下文

```text
Workspace
  -> Target + Scope
  -> Identity / Role
  -> Page
  -> Endpoint
  -> Parameter
  -> Interaction (Request + Response + State)
  -> Signal
  -> Validation
  -> Evidence
  -> Finding
```

上下文中的每个结论都要有来源、创建者、时间、版本和证据引用。页面内容、历史报告和模型摘要必须区分原始事实与推断。

## 6. 记忆层

- Run Memory：当前 Agent 调用需要的最小上下文，结束后可释放。
- Scan Memory：一次扫描的页面、接口、身份、动作、信号和验证结果。
- Workspace Memory：目标、Scope 快照、身份、扫描历史和审计记录。
- Knowledge Memory：版本化知识条目和案例摘要。

记忆压缩不得丢失关键证据引用。摘要超过 token 预算时按“事实 > 证据 > 决策 > 对话”优先级保留。

## 7. 规划稳定性

每个扫描至少设置：

- 固定且有界的阶段序列；
- 最大计划修订次数；
- 最大请求数和每分钟速率；
- 最大并发；
- 最大模型 Token；
- 最大总时长；
- 相同动作指纹去重；
- 连续无新证据次数；
- 人工暂停和显式恢复。

达到预算、连续重复、scope 变化、会话失效或策略拒绝时，Runtime 必须暂停、重规划或输出 Inconclusive，不能无限循环。

## 8. 阶段状态机

扫描状态为 `draft -> queued/running -> completed`，执行中可进入 `awaiting-user`、`paused`、`failed` 或 `cancelled`。运行阶段依次为 intake、passive-recon、active-enum、hypothesis、validation、verification、report，每个阶段完成后生成 checkpoint。

## 9. 人工介入点

- 授权范围确认；
- 测试身份和临时数据准备；
- L2 敏感主动探测批准；
- 会话恢复；
- 高风险外部工具启用；
- Inconclusive 人工复核；
- 报告脱敏与导出。

人工批准必须绑定具体 Proposal、目标、参数摘要和有效期，不能成为永久全局放行。

## 10. Prompt 与模型

Prompt 视为代码，至少记录 id、version、hash、适用 Agent、输入输出 schema 和变更说明。当前五个 V1 Agent Prompt 版本为 `1.1.0`，均向外部模型提供明确 JSON 输出契约。

不同 Agent 可以使用不同 Provider、Base URL、模型和 Token 预算，但都必须通过 ModelGateway。创建扫描时必须解析并冻结五个角色的 Profile ID；Coordinator 按扫描配置路由，只有兼容旧记录缺少该字段时才回退到角色默认 Profile。模型调用记录保存模型标识、Prompt 版本、输入/输出 Token、耗时、输入输出摘要和脱敏结果；不记录或估算费用。OpenAI-compatible 连接测试必须真实调用 `chat/completions` 并完成结构化响应校验，其 Token 也计入对应 Profile。
