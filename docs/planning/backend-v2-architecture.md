# AgentGo Backend V2：可扩展漏洞模块架构

> 状态：DAY0 目标架构草案，尚未实现；“现有/V1”才表示当前代码事实
> 基线日期：2026-07-13
> 适用范围：`packages/contracts`、`packages/domain`、`packages/application`、`packages/security-policy`、`packages/db`、`packages/knowledge-base`、`packages/evaluation`、执行器和报告后端
> 前端边界：本轮只保持现有前端可启动、可创建和查看既有扫描，不进行整体重建

## 1. 目标、承诺和非承诺

Backend V2 的目标不是把新的漏洞名字继续追加到四值枚举，而是建立一条可以持续增加 Web 漏洞族和验证技术、同时不削弱安全策略的通用后端链路：

```text
Inventory
  -> Detector
  -> Candidate
  -> CandidateCompiler
  -> ValidationPlan
  -> Policy / Approval / ExecutionLease
  -> PlanExecutor
  -> Observation / Signal
  -> ConfirmationRule
  -> Evidence
  -> Finding / Remediation / Benchmark
```

本架构承诺：

- 新增一个完整漏洞模块时，不需要给 `DefaultScanCoordinator` 增加新的 `if/else` 或 `switch` 分支。
- 每个漏洞技术都能声明自己支持的协议、Selector、身份、业务前置条件、风险能力、证据要求和成熟度。
- 能安全主动确认的技术继续保留主动探测；需要测试对象和清理的技术进入 L2 逐次审批。
- 暂不具备安全确认条件的技术仍可进入 `inventory-only`、`signal-only` 或 `fixture-only`，但不能被夸大为已确认漏洞。
- 未知模块、未知能力、未知副作用和版本不匹配一律失败关闭。

本架构不承诺在 20 个工作包内“自动挖出所有 Web 漏洞”。Web 漏洞不存在有限且永远完整的集合，业务逻辑问题还依赖目标特有的不变量、身份矩阵和状态机。合理交付是完成可扩展框架、迁移现有四类、提供若干不同风险模式的参考模块，并形成后续逐类交付的强制 DoD。

## 2. 当前结构性问题

现有实现中的 `VulnerabilityFamily` 是 `sqli`、`xss`、`ssrf`、`idor` 四值枚举。四类同时被硬编码在 contracts、Prompt、确定性参数提示、Coordinator、ConfirmationRule、Knowledge、Reporting、Fixture 和 Benchmark 中。

尤其需要消除以下耦合：

- `packages/contracts/src/workflow.ts` 的固定 `z.enum`；
- `packages/application/src/agent-prompts.ts` 中按四类建立的 `parameterHints` 和固定 JSON 契约；
- `packages/application/src/scan-coordinator.ts` 中按四类展开的 `validateCandidate()`；
- `packages/application/src/validation-engine.ts` 中 `Record<VulnerabilityFamily, ConfirmationRuleDefinition>`；
- `packages/evaluation/src/index.ts` 对 `VulnerabilityFamilySchema.options` 的全局覆盖假设；
- `packages/evaluation/src/local-fixture.ts` 的四类固定路由。

DAY0 复现的 V1 Scope 基线竞态已由 Day1 修复：migration `0005_monotonic_scope_revisions` 建立每 Target 单调 revision、显式 current pointer、旧库确定性回填和 DB 不变量，Scan 冻结精确 scope ID/version；同毫秒、并发与路径别名回归已通过。V2 必须复用该事实，不能退回 `created_at`/UUID 排序或 sleep/retry。

SQLite 中现有 family 字段本身是 `TEXT`，没有四值 `CHECK` 约束，因此无需破坏性重写历史数据。迁移重点应放在运行时类型、注册表、版本快照和通用执行链。

## 3. 稳定 Family ID 与 Technique ID

### 3.1 ID 定义

Family 是稳定的问题域标识，Technique 是具体检测或确认技术。二者必须分开：

```ts
export const VulnerabilityFamilyIdSchema = z
  .string()
  .regex(/^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*$/)
  .max(100)

export const VulnerabilityTechniqueIdSchema = z
  .string()
  .regex(/^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*$/)
  .max(160)

export type VulnerabilityFamilyId = z.infer<
  typeof VulnerabilityFamilyIdSchema
>
export type VulnerabilityTechniqueId = z.infer<
  typeof VulnerabilityTechniqueIdSchema
>
```

示例：

```text
family=sqli
  technique=sqli.boolean-differential
  technique=sqli.error-signal
  technique=sqli.bounded-time-differential

family=xss
  technique=xss.reflected-inert-marker
  technique=xss.stored-test-object
  technique=xss.dom-fixed-replay
```

Family/Technique ID 是不随展示名称变化的主键。版本单独使用 SemVer 字段，不能把版本拼进 ID。

### 3.2 Legacy 四类兼容

已有 `sqli`、`xss`、`ssrf`、`idor` 继续作为永久稳定 Family ID，不改名、不批量更新历史 Finding：

```ts
export const LEGACY_V1_FAMILY_IDS = [
  'sqli',
  'xss',
  'ssrf',
  'idor'
] as const

/** 兼容一个迁移周期，内部新代码不得继续使用旧名称。 */
export const VulnerabilityFamilySchema = VulnerabilityFamilyIdSchema
export type VulnerabilityFamily = VulnerabilityFamilyId
```

contracts 只验证 ID 语法。Application 必须通过当前 Registry 验证 ID 是否存在、版本是否可用、成熟度是否允许主动验证。任意合法字符串不能仅因通过 Zod 就获得执行能力。

### 3.3 扫描冻结快照

创建 Scan 时必须保存：

- `familyId`；
- `techniqueId` 和 Technique Version；
- Module ID、Module Version 和定义哈希；
- ConfirmationRule、EvidenceProfile、Remediation 版本；
- 当时可用的协议执行能力和安全能力快照；
- Registry Snapshot Hash。

恢复扫描时若快照对应版本已不存在或定义哈希变化，扫描进入 `awaiting-user` 或将候选记为 `inconclusive`，不能静默套用新版本规则。

## 4. Manifest、Registry 与 Bundle 原子注册

### 4.1 Manifest

每个漏洞模块以只读 Manifest 描述能力，而不是由 Coordinator 猜测：

```ts
interface VulnerabilityModuleManifest {
  moduleId: string
  moduleVersion: string
  family: FamilyManifest
  techniques: TechniqueManifest[]
  sourceRefs: string[]
  definitionHash: string
}

interface FamilyManifest {
  familyId: VulnerabilityFamilyId
  displayName: string
  category: string
  description: string
  defaultEnabled: boolean
}

interface TechniqueManifest {
  techniqueId: VulnerabilityTechniqueId
  familyId: VulnerabilityFamilyId
  version: string
  declaredMode:
    | 'active-l1'
    | 'active-l2'
    | 'signal-only'
    | 'fixture-only'
    | 'inventory-only'
    | 'forbidden'
  supportedSubjects: SubjectRef['kind'][]
  requiredCapabilityIds: string[]
  detectorIds: string[]
  strategyIds: string[]
  confirmationRuleIds: string[]
  evidenceProfileIds: string[]
  remediationIds: string[]
}
```

`declaredMode` 只是定义作者的声明，不是执行授权。运行时另由 ActivationCatalog 提供 `activationStatus`、`qualifiedEnvironments` 和 qualification record；任何代码不得把声明为 `active-l1/active-l2` 直接解释成已激活。

### 4.2 Bundle

一个可运行模块必须以完整 Bundle 原子注册：

```ts
interface VulnerabilityModuleBundle {
  manifest: VulnerabilityModuleManifest
  detectors: DetectorDefinition[]
  signalKinds: SignalKindDefinition[]
  strategies: ProbeStrategyDefinition[]
  confirmationRules: ConfirmationRuleDefinition[]
  evidenceProfiles: EvidenceProfileDefinition[]
  remediations: RemediationDefinition[]
}
```

Fixture 和 Benchmark 属于测试侧 Bundle，不得进入生产 Composition Root：

```ts
interface VulnerabilityModuleTestBundle {
  moduleId: string
  moduleVersion: string
  fixtures: FixtureDefinition[]
  benchmarkSuites: BenchmarkSuiteDefinition[]
}
```

### 4.3 DefinitionRegistry 与 ActivationCatalog

Day2 的 `DefinitionRegistry` 是通过依赖注入传递的统一定义门面，内部包含：

- `FamilyRegistry`
- `DetectorRegistry`
- `SignalKindRegistry`
- `ProbeStrategyRegistry`
- `ConfirmationRuleRegistry`
- `EvidenceProfileRegistry`
- `RemediationRegistry`

测试进程另行组合 `FixtureRegistry`、`BenchmarkRegistry` 和 `QualificationService`。生产 Composition Root 不加载 fixture/benchmark 代码，只加载签名或内容寻址的 qualification record，并据此构造只读 `ActivationCatalog`。Day2 为保持 V1 行为，仅在同一 Composition Root 中额外注入固定 `sqli/xss/ssrf/idor` 的 `legacy-v1` definition/runtime 映射与 Application allowlist；它是封闭的临时兼容门，不是 qualification record。禁止建立可在任意位置修改的全局 Service Locator。

`registerBundle()` 必须一次性校验：

1. 所有 ID 和版本唯一；
2. Technique 引用的 Detector、Strategy、Rule、EvidenceProfile、Remediation 全部存在；
3. Strategy 所需 Capability 已在安全能力目录注册；
4. ConfirmationRule 的输入 Schema、Evidence Role 和三态输出完整；
5. `active-l2` Strategy 必须声明 TestObject、SideEffectEnvelope、CleanupProtocol 和 cleanup-verify；
6. 声明 active 的 Technique 必须引用预期 Suite ID/version，但 Day2 缺少 qualification 时只能成为 `registered-only`；仅固定四类 V1 可由 `legacy-v1` 临时兼容门继续执行，状态仍为 registered 且不得声明 qualified/supported；
7. 定义哈希、构建产物哈希、commit 和 SemVer 一致，内容变化但版本未变化时拒绝启动；
8. 任一项失败则整个 Bundle 不可见，不允许部分注册。

Day7 之后的激活流程是：

```text
DefinitionRegistry frozen snapshot
  + TestBundle / Suite / Fixture attestation
  -> QualificationService
  -> QualificationRecord(definition/build/suite/fixture hashes, environment, result)
  -> production ActivationCatalog
```

`ActivationCatalog` 的状态至少为 registered、qualified、suspended、retired。record 缺失、过期、hash 不匹配或环境不匹配时，Technique 保持 registered-only 或 suspended；不能因 Registry 中“存在”就主动执行。唯一的 Day2 过渡例外是固定四类 `legacy-v1`：同时命中冻结 Registry definition、精确 legacy runtime mapping 和 Application allowlist 时可维持既有 V1 执行，但其支持声明仍必须显示 registered/unqualified。`security.headers` 及其他 registered-only 定义不得命中该例外。

应用初始化完成后 Registry 必须冻结。Knowledge 文档、模型输出、MCP 工具输出和用户导入内容都不能注册可执行代码。

## 5. SubjectRef：不再假设所有漏洞都属于一个参数

当前 Candidate 强制依赖 `endpointId + parameterId`，无法表达安全响应头、会话、OAuth 流、代理链、跨身份矩阵、依赖组件和业务工作流。

V2 使用经 Zod 校验的判别联合：

```ts
type SubjectRef =
  | { kind: 'endpoint'; endpointId: string }
  | { kind: 'selector'; requestVariantId: string; selector: SelectorRef }
  | { kind: 'page-dom'; pageId: string; sinkRef?: string }
  | { kind: 'identity-pair'; firstIdentityId: string; secondIdentityId: string }
  | { kind: 'authorization-matrix'; matrixId: string; version: string }
  | { kind: 'workflow-transition'; workflowId: string; transitionId: string }
  | { kind: 'protocol-channel'; channelId: string; protocol: ProtocolKind }
  | { kind: 'component'; componentId: string; version?: string }
```

Selector 也应从固定 location 枚举升级为结构化引用，逐步支持：

- query/path/header/cookie；
- form/JSON Pointer；
- multipart part；
- XML Path；
- GraphQL variable/argument；
- WebSocket message field。

现有 Endpoint/Parameter 继续保留为 Inventory 的兼容视图；新模块使用 RequestVariant 和 SubjectRef，不再创建第二套平行 Endpoint 真源。

## 6. Capability、协议与环境分级

### 6.1 三个独立维度

安全判断必须同时考虑：

1. 漏洞技术需要什么执行能力；
2. 实际请求使用什么协议和数据编码；
3. 当前环境允许什么风险。

Family 名称永远不能直接决定安全等级。

建议协议维度：

```text
Transport:
  standard-http
  browser
  controlled-oob-http
  controlled-oob-dns
  websocket
  sse
  raw-http1
  http2

BodyEncoding:
  none
  form
  json
  multipart
  xml
  graphql
```

### 6.2 环境等级

```text
offline
  只处理导入文件、已有证据和本地纯计算。

attested-fixture
  固定版本、本地或隔离靶场，有 attestation、reset 和测试数据。

authorized-test-environment
  用户拥有或书面授权的测试环境，允许显式批准的 TestObject/L2。

authorized-real-target
  真实业务授权目标；只执行满足最小影响、证据和安全前置条件的能力。
```

环境从低风险到高真实性并不代表权限自动扩大。`attested-fixture` 可以承载某些协议研究，但其批准不能复用于真实目标。

### 6.3 Probe Capability Catalog

Capability ID 使用 SecurityPolicy 维护的封闭目录，例如：

```text
inventory.offline-import
http.reviewed-read
http.identity-read-compare
browser.offline-replay
browser.mediated-read
oob.controlled-observe
http.test-object-write
file.inert-test-upload
workflow.test-object-transition
concurrency.bounded-test-object
protocol.raw-http-fixture
```

风险下界由 SecurityPolicy 决定：

| 等级 | 允许范围 | 典型能力 |
|---|---|---|
| L0 | 被动、离线 | HAR/OpenAPI 导入、知识匹配、已有证据分析 |
| L1 | reviewed、只读、低影响 | GET/HEAD、只读身份对照、离线浏览器回放、受控只读回连 |
| L2 | 敏感但可回退，逐次审批 | TestObject POST/PUT/PATCH、惰性上传、存储型 XSS、业务状态转换、有界并发 |
| L3 | 永久拒绝 | 通用/未绑定 HTTP DELETE、生产或未知对象写入、命令执行证明、凭据攻击、持久化、横向移动、高强度 DoS |

约束：

- 未知 Capability、未知协议和未知副作用默认拒绝。
- Module 只能声明所需 Capability，不能声明它属于更低风险。
- Policy 必须根据 Method、Body、Transport、环境和实际副作用计算风险上界。
- `raw-http1/http2` 的 request-smuggling/desync 默认仅允许 `attested-fixture`。
- DoS/ReDoS 在真实目标只能生成静态或低影响 Signal，不能用资源耗尽证明。
- RCE、反序列化和危险文件上传在真实目标不得通过执行系统命令来确认。
- WAF 阻断默认 `Inconclusive`，没有独立授权不得自动绕过。
- 专用 cleanup capability 不是探测能力。它只能对 AgentGo 创建且有所有权证明的 disposable TestObject 调用目标声明的精确 delete/revoke/reset，绑定同一 L2 bundle/批准/对象 ID，并在执行后终态复核；无安全清理协议时对应 L2 technique 不激活。

## 7. 受限 ValidationPlan DSL

### 7.1 为什么必须受限

漏洞模块不能直接持有 HttpRunner、BrowserRunner、Repository、CredentialStore 或 PolicyBroker。否则新增模块可以绕开策略和审计。

`ProbeStrategy` 只能执行纯编译：输入 Candidate、冻结 Inventory、Scope、Session、TestObject、授权矩阵和 Capability Snapshot，输出声明式 ValidationPlan。

### 7.2 Plan 结构

```ts
interface ValidationPlan {
  planId: string
  planVersion: string
  planHash: string
  candidateId: string
  familyId: VulnerabilityFamilyId
  techniqueId: VulnerabilityTechniqueId
  strategyId: string
  strategyVersion: string
  subjectRefs: SubjectRef[]
  environment: EnvironmentClass
  requiredCapabilityIds: string[]
  steps: ValidationPlanStep[]
  confirmationRuleRef: VersionedRef
  evidenceProfileRef: VersionedRef
  remediationRef: VersionedRef
  stopConditions: StopCondition[]
  maxRequests: number
  maxDurationMs: number
}
```

允许的 Step 是封闭判别联合：

```text
http-request
browser-offline-replay
browser-mediated-read
callback-register
callback-poll
state-observe
bounded-parallel-group
cleanup
cleanup-verify
```

每个网络或状态 Step 必须带：

- stepId、Purpose 和 Capability ID；
- canonical RequestIntent 引用；
- identity/session generation；
- expected Evidence Roles；
- maxRequests、timeout、redirect 和 response capture 限制；
- probeLevel、sideEffect 和失败处理；
- L2 时的 TestObject、SideEffectEnvelope、ApprovalBundle 和 CleanupProtocol 引用。

DSL 禁止：

- 任意函数回调、动态 `eval` 或脚本；
- 无上界循环和递归；
- 模块自行直接发包；
- 在运行中由 Agent 改写已批准 Step；
- 一个审批覆盖多个未冻结 primary 写操作；
- cleanup failure 后继续执行非 recovery Step。

### 7.3 单步授权与请求绑定

每个真实 I/O Step 都必须走：

```text
PlanStep
  -> canonical RequestIntent
  -> ProbeProposal
  -> PolicyDecision / Approval
  -> single-use ExecutionLease
  -> actual request hash recheck
  -> Runner
```

实际 URL、Method、Header 名称集合、Body Hash、Identity、Session Generation、Scope Snapshot、TestObject 和 Step ID 必须与 Lease 绑定。重放、篡改、过期、并发 claim 或请求体不一致均拒绝。

## 8. 通用执行链与 Coordinator 去分支

### 8.1 服务职责

```text
DetectorService
  读取 Inventory/已有 Observation，运行纯 Detector，产生 CandidateSeed。

CandidateCompiler
  把 CandidateSeed 与 Registry、Scope、Session、TestObject、依赖和 Capability
  组合，确定 active-l1/active-l2/signal-only/inventory-only/forbidden。

ProbePlanExecutor
  只解释受限 DSL；所有 I/O 经 Policy、Lease 和对应协议 Adapter。

ObservationNormalizer
  将 Runner 结果转成版本化、已校验 Observation，不做漏洞结论。

SignalService
  按 SignalKind Schema 保存异常事实；Signal 不等于 Finding。

ConfirmationEngine
  按 Rule ID/Version 调用纯函数规则，输出 Confirmed/Not Confirmed/Inconclusive。

FindingAssembler
  组合确定性 Verdict、EvidenceProfile、Remediation 和 Registry Snapshot。
```

### 8.2 Coordinator 最终职责

`DefaultScanCoordinator` 只保留：

- phase/checkpoint；
- CandidateAttempt 队列和幂等恢复；
- 调用通用服务；
- 处理 `completed/awaiting-user/paused/failed` PhaseOutcome；
- 执行预算和全局停止条件；
- 报告阶段收口。

Coordinator 不再导入 `assessSqli/assessXss/assessSsrf/assessIdor`，不再创建各家 payload，不再知道某类需要几个请求。

### 8.3 Agent 的边界

- Agent 可以建议 `familyId/techniqueId/subjectRefs/reason`。
- Agent 输出必须通过 Schema，并验证 Technique 已在冻结 Registry Snapshot 中。
- Agent 不能决定 ProbeLevel、Approval、Capability、Cleanup Eligibility 或最终 Confirmed。
- 确定性 Detector 与 Agent Candidate 都必须进入同一个 CandidateCompiler。

## 9. Detector、Signal、ConfirmationRule 与 Remediation

### 9.1 Detector

Detector 是纯函数并且有预算：

```ts
interface DetectorDefinition {
  detectorId: string
  version: string
  familyId: VulnerabilityFamilyId
  techniqueId: VulnerabilityTechniqueId
  inputSchemaVersion: string
  detect(context: DetectionContext): CandidateSeed[]
}
```

Detector 只能基于 Inventory、技术指纹、已有结构化 Observation 和人工提供的不变量形成候选。名称匹配只能作为弱信号，不能直接 Confirmed。

### 9.2 SignalKind

通用 SignalKind 示例：

- response-status-difference；
- response-structural-difference；
- bounded-repeatable-timing-difference；
- marker-reflected；
- browser-marker-executed；
- unique-callback-observed；
- cross-identity-access-equivalence；
- unexpected-state-delta；
- protocol-parser-disagreement；
- security-control-missing。

每类 Signal 都有独立属性 Schema。禁止把未经校验的任意 `Record<string, unknown>` 直接作为 Confirmation 输入。

### 9.3 ConfirmationRule

ConfirmationRule 必须：

- 是无 I/O 的确定性纯函数；
- 绑定 Family、Technique、Rule ID/Version 和定义哈希；
- 明确 required、negative、inconclusive Evidence Role；
- 输出 completed/failed/missing checks；
- 把 WAF、超时、会话失效、证据缺失和 cleanup failure 正确归入 Inconclusive；
- 不允许 Agent 将确定性上限从 Not Confirmed/Inconclusive 提升为 Confirmed。

### 9.4 Remediation

RemediationDefinition 至少包含：

- root cause；
- short-term mitigation；
- code/configuration remediation；
- regression test；
- CWE/OWASP 映射；
- applicable techniques；
- source refs 和版本。

Finding 保存当时使用的 remediation snapshot。Knowledge 可以提供经审核的补充建议，但不能覆盖确定性最低修复要求。

## 10. 角色化 Evidence 与数据库迁移

### 10.1 当前限制

现有 ValidationRun 固定为一个 Proposal、一个 Decision、一个 ToolCall 和 baseline/test/negativeControl 三个引用，无法表达：

- 多身份授权矩阵；
- stored XSS 的 write/read/cleanup；
- OOB SSRF 的 register/dispatch/poll；
- race 的并发组；
- OAuth/SAML 多跳；
- 前后端解析差异。

### 10.2 新表

建议新增：

```text
scan_module_snapshots
validation_plan_runs
validation_step_runs
validation_observations
validation_evidence_bindings
```

核心关系：

```text
CandidateAttempt
  -> ValidationPlanRun
      -> ValidationStepRun
          -> PolicyDecision / ToolCall / Interaction
          -> Observation
          -> EvidenceBinding(role -> EvidenceItem)
      -> ConfirmationRuleResult
      -> Finding
```

EvidenceBinding 至少保存：

- planRunId/stepRunId；
- role；
- evidenceId；
- ordinal；
- capturePolicy/evidenceProfile version；
- redaction state；
- module/rule definition hash。

角色示例：

```text
baseline-owner
true-control-first
false-control
true-control-repeat
cross-identity-read
state-before
state-after
cleanup-receipt
cleanup-verify
browser-dom
browser-screenshot-redacted
callback-event
```

### 10.3 现有表扩展

- `signals`：增加 `technique_id`、`signal_kind_id`、`subject_refs_json`、`observation_refs_json`。
- `findings`：增加 `technique_id`、`module_id/version`、`remediation_id/version`、`registry_snapshot_hash`。
- `confirmation_rules`：增加 `technique_id`、`evaluator_id/version`、`definition_hash`、`evidence_profile_id/version`。
- `knowledge_intelligence` 和 `benchmark_cases`：增加 Technique 和 Module Version。

DB 只能保存定义元数据、版本和哈希，不能从数据库加载并执行任意 Rule 代码。

### 10.4 兼容迁移顺序

1. 新表和新列先以 nullable/兼容模式加入。
2. 将历史四类映射到现有技术：
   - `sqli.boolean-differential`
   - `xss.reflected-inert-marker`
   - `ssrf.controlled-inband-proof`
   - `idor.readonly-two-identity`
3. 把旧 baseline/test/negative 引用回填成 Evidence Role Binding。
4. 新代码双写旧字段和新结构，并执行一致性断言。
5. 旧 Benchmark 完整通过后，新结构成为读取真源。
6. 至少一个发布周期后再评估删除旧字段；本轮不做破坏性删除。

## 11. Knowledge 对接

KnowledgeEntry 和导入候选增加：

- `familyId`；
- `techniqueIds`；
- applicability；
- signal kinds；
- safe probe principles；
- confirmation rule refs；
- negative controls；
- forbidden capabilities；
- remediation refs；
- source refs、freshness 和 review state。

约束：

- `packages/knowledge-base` 保持纯数据和纯检索函数，不依赖 Application/DB。
- Application 中只有一个 RetrievalService，替代 `buildKnowledgePack` 与 Coordinator 私有拼装的双路径。
- RetrievalService 查询 Registry，只把当前 Scan Snapshot 中存在的 Technique 提供给 CandidateCompiler。
- 未映射、未发布、过期或含指令注入的知识只能作为人工审查资料。
- PoC/Request Template 始终为 `unsafeToExecute=true`；知识导入不能直接生成可执行 ValidationPlan。

## 12. Evaluation、Fixture 与覆盖矩阵

### 12.1 不再遍历全局枚举

开放 Family ID 后，Benchmark 不能要求“Registry 中所有 Family 自动各五正五负”。每个 BenchmarkSuite 应显式声明：

- familyId/techniqueId/moduleVersion；
- fixtureId/version/attestation；
- protocol/bodyEncoding/selector；
- required case categories；
- required evidence roles；
- reset/cleanup protocol；
- performance 和 safety gates。

GroundTruthCase 增加：

- techniqueId；
- expectedVerdict 和 expectedReasonCode；
- environment/protocol/selector；
- requiredEvidenceRoles；
- expected cleanup state；
- fixture attestation hash。

### 12.2 Technique 激活门禁

Technique 要标为 `active-l1` 或 `active-l2`，至少要有：

- 逻辑不同的正例；
- 逻辑不同的负例；
- WAF/超时/前置条件缺失等 Inconclusive；
- 越界、未批准、Lease 篡改等安全案例；
- L2 时的 cleanup success/failure/recovery 案例；
- Confirmed 的 Evidence Role 完整性测试；
- 三次确定性重复结果。

Benchmark 分 family、technique、protocol、selector、环境和风险等级统计。缺失 Prediction、未知 Prediction、Module/Fixture Version 不匹配或任一安全计数非零必须使 CLI 失败。

激活门禁产出内容寻址的 `QualificationRecord`，而不是直接修改 DefinitionRegistry。record 必须绑定 canonical definition snapshot、实际构建产物/commit、suite、fixture attestation、执行器/Policy 版本和环境；生产只读验证 record 后才允许 ActivationCatalog 把 technique 标为 qualified。

FixtureApprovalAuthority 只存在于 `packages/evaluation`，仅接受固定 loopback fixture、精确版本、临时数据库和精确 Plan Hash，禁止注入生产 Application Composition Root。

## 13. 代码落点

建议目录：

```text
packages/contracts/src/
  vulnerability.ts
  subject.ts
  validation-plan.ts
  capability.ts

packages/domain/src/vulnerabilities/
  module.ts
  registry.ts
  detector.ts
  signal.ts
  confirmation.ts
  evidence.ts
  remediation.ts

packages/vulnerability-modules/src/
  registry.ts
  sqli/
  xss/
  ssrf/
  idor/
  testkit/

packages/application/src/vulnerability-engine/
  detector-service.ts
  candidate-compiler.ts
  probe-plan-executor.ts
  observation-normalizer.ts
  signal-service.ts
  confirmation-service.ts
  finding-assembler.ts

packages/security-policy/src/
  capability-catalog.ts
  capability-policy.ts

packages/evaluation/src/
  fixture-registry.ts
  benchmark-registry.ts
  module-contract-suite.ts
```

`packages/application/src/validation-engine.ts` 在迁移期保留为 legacy adapter，四类迁移完成后拆除 family 分支。`packages/application/src/scan-coordinator.ts` 只依赖上述通用服务和 Registry 门面。

## 14. 模块 Definition of Done

一个漏洞 Technique 只有同时满足以下条件才算交付：

1. 稳定 Family/Technique/Module ID、SemVer 和定义哈希；
2. Manifest 写明支持的 Subject、协议、Selector、环境、成熟度和 Capability；
3. Detector 有输入 Schema、候选依据、误报模式和预算；
4. Strategy 只生成受限 ValidationPlan，不直接访问 Runner/DB/凭据；
5. 每个 I/O Step 都能绑定 PolicyDecision、ExecutionLease 和实际请求哈希；
6. L2 有 TestObject、SideEffectEnvelope、逐次审批、cleanup 和 cleanup-verify；
7. SignalKind 和 Observation Schema 完整；
8. ConfirmationRule 为纯函数，三态、负对照和缺失证据语义明确；
9. EvidenceProfile 有角色、最小数量、脱敏和禁止捕获字段；
10. Remediation 有根因、修复、复测、CWE/OWASP 和来源；
11. Fixture 具备固定版本、attestation、reset 和出站隔离；
12. Benchmark 包含正、负、Inconclusive、安全和必要的 cleanup 案例；
13. Knowledge 条目已审核且只能引用注册的 Technique；
14. 报告能区分 Candidate、Signal、Confirmed、Not Confirmed、Inconclusive 和未运行；
15. `pnpm typecheck`、相关单元/集成、安全测试、legacy benchmark 和模块合同测试全部通过。

缺少任一项时最多标记为 `inventory-only`、`signal-only` 或 `fixture-only`，不得标记 Active。

## 15. 前端冻结边界

本轮不重建 Renderer，不继续扩张当前大型 `App.tsx`。只允许以下兼容性工作：

- Bootstrap 后端增加只读 `familyDescriptors/capabilityMatrix`；保留旧四类数组兼容现有 UI。
- 新 Family 无前端专用标签时使用后端 displayName 或稳定 ID fallback，不能导致页面崩溃。
- 现有创建 Scan、开始/暂停/恢复、Finding、Evidence 和报告路径保持可用。
- 新的 L2 Approval/Recovery 先通过 Application integration test、fixture CLI 和稳定 contracts 验收；本轮不为它们创建 Renderer 入口。
- 新模块的完整筛选、配置、矩阵视图和前端重建进入后端稳定后的独立计划。

前端冒烟测试仍是发布门禁，但前端功能数量不是 Backend V2 的完成证据。

## 16. 安全不变量

无论增加多少漏洞模块，下列规则不可由 Module、Agent、用户知识或配置覆盖：

- 永久禁止 DROP/TRUNCATE、生产或未知归属数据增删改、通用/未绑定 HTTP DELETE、真实账户接管、凭据喷洒、持久化、横向移动、高强度 DoS、恶意文件、云元数据访问和越界访问。TestObject 的专用 cleanup 窄例外必须满足第 6 节全部绑定条件，且不能被模块当作验证手段。
- 未知 GET 不能仅因 Method 是 GET 就视为无副作用；必须 reviewed 后才能进入 L1。
- POST/PUT/PATCH 或任何可能改变状态的请求默认 L2，且必须使用专用 TestObject、逐次审批和可验证清理。
- 所有主动动作必须经过 SecurityPolicy、原子预算、单次 Lease、DNS/IP/Redirect 重校验和证据审计。
- Cookie、Authorization、Token、密码、CSRF Secret 和 OOB Plain Token 不进入 SQLite、日志、报告或模型。
- 页面、Knowledge、模型和工具输出均为不可信内容，只能形成建议，不能提升权限。
- WAF、网络抖动、会话失效、协议不支持、版本不一致或证据不足均为 Inconclusive，不得伪造 Confirmed。
- cleanup failure 后只允许新批准的 recovery/cleanup-verify，不允许继续枚举或验证。
- 主动探测必须保留，但只执行获得结论所需的最小动作，达到最小证据立即停止。

## 17. 20 个顺序工作包的可实现边界

本节与 [20 天总览](complex-web-20-day-plan.md) 及 Day1～Day20 保持同一顺序；若详细 Day 文档和本节有冲突，以详细 Day 的硬退出条件为准。它们是顺序工作包，不是可以并行压缩安全门禁的自然日承诺。

### Day 1～3：事实、Registry 与 Inventory

- 冻结代码/测试/覆盖事实和 Renderer 边界；
- 增加 Family/Technique/Subject/Manifest/Bundle contracts，建立 DefinitionRegistry 原子校验和 Snapshot Hash；
- 建立统一 scan-scoped Inventory、RequestVariant/Source/Selector/Codec/Transport、opaque identity/session/test-object refs 与 Scan 模块快照。

退出条件：旧数据可解析；未知 Family 在 Application 边界被拒绝；多来源幂等、secret 不落库、Registry 合同测试通过。

### Day 4～6：请求恒等绑定与执行硬门禁

- 建立纯 RequestCompiler、Template/Resolved/Wire 三阶段 hash 和 EvidenceCapturePolicy；
- 建立单次 ExecutionGrant/Lease、Runner wire request 重校验；
- 建立原子 request/RPM/concurrency/bytes 预算和 DNS/IP/redirect/response resource 门禁。

退出条件：未知能力、风险降级、请求篡改、重放、并发 claim、预算超卖和网络越界全部失败关闭。

### Day 7～10：评测、L2 与 Session

- Day7 建立 Evaluation core、Ground Truth/Suite Registry、基础 loopback fixture、qualification record 和 legacy 40 Case 兼容；四类 legacy technique 取得有效、环境匹配的 qualification record 后，Composition Root 必须以正式 ActivationCatalog 路径替换并移除 Day2 临时兼容例外；
- Day8 建立不联网的 TestObject、L2ActionBundle、SideEffectEnvelope 和 cleanup/recovery 状态协议；
- Day9 建立 SessionVault、CSRF、IdentityContext 和 AuthorizationMatrix；
- Day10 建立可信 ApprovalPort/Service，并仅在认证 loopback fixture 上跑通首条 L2 闭环。

退出条件：L1/L2 fixture 链路可执行、可恢复、可审计；审批不可伪造，secret 不持久化，cleanup failure 阻断后续普通动作。

### Day 11～13：真实 Web 发现

- 建立 OpenAPI/HAR/Postman/GraphQL 描述的离线导入；
- 建立 HTML/JS/source map 静态提取、AssetManifest 和 ExtractionRule；
- 再建立消费冻结 AssetManifest 的 Policy-mediated BrowserNetworkBroker、固定 SPA fetch/XHR 发现、producer merge 和最小依赖图。

退出条件：所有发现进入唯一 Inventory；导入零网络，浏览器零旁路，依赖有来源且不由 Agent 猜测。

### Day 14～15：通用运行时与 Coordinator 去分支

- 建立受限 ValidationPlan DSL、Plan/Step/Observation/EvidenceBinding、统一 RetrievalService；
- 建立 DetectorService、CandidateCompiler、CandidateAttempt、PhaseOutcome 和安全恢复；
- 将 legacy 四类按 V1 行为等价包装进通用模块/plan，切换唯一执行真源并删除 Coordinator family 分支。

退出条件：未注册知识不能执行；每个 I/O 都经过 Policy/Lease；Coordinator 不再知道具体漏洞步骤，legacy suite 不回退。

### Day 16～19：四个参考模块与无分支扩展示例

- Day16：在 parity bundle 上增强 SQLi 非写入差异和复杂 selector；
- Day17：在 parity bundle 上增强 IDOR/BOLA 多身份只读授权矩阵；
- Day18：在 parity bundle 上增强反射/离线 DOM/测试对象存储 XSS；
- Day19：在 parity bundle 上增强回显/OOB SSRF，并把 Day2 registered-only 的 `security.headers` descriptor 资格化为被动 detector。

退出条件：四个参考模块各有正、负、Inconclusive 和安全 Case；新增被动模块未修改 Coordinator，未完成技术保持 signal/fixture/inventory 状态。

### Day 20：全量门禁

- 运行 typecheck、单元/集成/安全测试、legacy/complex benchmark、模块合同、property/fuzz 和确定性重复评测；
- 在规则冻结后运行至少一个版本固定、可重置、与开发 fixture 隔离的第三方本地 Web/API holdout；
- 验证报告脱敏、迁移、暂停恢复和现有前端 build/smoke；
- 输出 Coverage Matrix，逐项标注 Active、Signal、Fixture、Inventory、Forbidden；
- 未完成或未经真实证据验证的能力明确标为 deferred/not-run。

退出条件：安全计数为零；模块与 Registry/ActivationCatalog 版本可复现；self-built、external-holdout、authorized-pilot、not-run 分栏；发布说明不把框架支持范围夸大为全部漏洞已实现。没有可信产品 ApprovalPort 时，L2 只标 fixture-qualified。

## 18. 20 天之后的持续扩展

后续按 Module DoD 分批覆盖以下类别，而不是一次性把名称加入枚举：

- SQL/NoSQL/Command/SSTI/LDAP/XPath/CRLF 等注入；
- reflected/stored/DOM XSS、Open Redirect、Clickjacking、postMessage；
- SSRF、XXE、反序列化、Path Traversal、文件上传和 RCE Signal；
- Session、JWT、OAuth、SAML、密码重置；
- IDOR/BOLA、BFLA、跨租户、Mass Assignment；
- CORS、Host Header、Cache、HTTP Parameter Pollution、Request Smuggling；
- REST、GraphQL、WebSocket、Webhook 和安全速率限制；
- 工作流、支付/订单/审批、Race/TOCTOU 等依赖人工 BusinessInvariant 的业务逻辑；
- 信息泄露、配置、依赖情报和 AI Web 风险。

每个类别都必须展示真实成熟度。框架能够容纳某类漏洞，不等于该类已经具备真实目标主动确认能力。
