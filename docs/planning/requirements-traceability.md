# AgentGo 需求追踪与支持声明口径

> 状态：Day1 规划交付物（2026-07-13 已验收）；本文件本身不是实现/资格完成声明，实际完成证据见 [Day1 事实基线](day1-baseline.md)
>
> 事实基线：`2851e915bd30acd5ee3abef22733a86e24f20e85`（DAY0 规划复核提交）
>
> 基线日期：2026-07-13（Asia/Shanghai）

## 1. 使用规则与来源

本文件把当前代码事实、Day1 当期工作、Day2～Day20 顺序工作包、Day20 后七波路线和明确非目标放在同一追踪面中。计划文字、未验收的工作区改动、fixture 名称或一次成功运行都不能作为“已支持”证据。

稳定需求 ID 采用 `AG-{域}-{三位序号}`。已发布 ID 不重排、不复用；需求拆分时保留原 ID 并新增子项，废弃时标记 deprecated 并保留迁移指向。本文分类只有以下四种，分类本身不表示完成状态：

| 分类 | 含义 |
|---|---|
| `已有` | 当前 V1 已有全部或部分实现；真实边界仍以证据与“缺口”列为准。 |
| `Day1` | 本工作包必须完成并取证；未通过 Day1 退出门槛前仍是待验收。 |
| `后续波次` | 主责为 Day2～Day20 或 W1～W7；出现设计、类型或占位代码不等于交付。 |
| `非目标` | 当前计划明确不做或永久禁止；不得为了提高覆盖率创建执行路径。 |

每项只给一个“唯一主责工作包”。其他包可以提供依赖或回归测试，但不能据此抢先改变状态。主要依据如下：

- [DAY0 复核记录](Day0.md) 与 [Day1 计划](Day1.md)；
- [20 个顺序工作包总览](complex-web-20-day-plan.md) 及 [Day2](Day2.md)～[Day20](Day20.md)；
- [Backend V2 目标架构](backend-v2-architecture.md)；
- [Web 漏洞覆盖矩阵](web-vulnerability-coverage-matrix.md) 与 [复杂接口能力矩阵](complex-web-interface-capability-matrix.md)；
- [Day20 后七波路线](post-20-day-vulnerability-roadmap.md)；
- [总体架构](../architecture/overview.md)、[数据模型](../architecture/data-model.md)、[Agent 系统](../architecture/agent-system.md)；
- [主动探测规范](../security/active-probing-policy.md)、[威胁模型](../security/threat-model.md)；
- [V1 当前能力核查](../audits/v1-current-capability-audit.md)、[项目范围](../project-scope.md) 与 [路线图](../roadmap.md)。

“当前代码/测试证据”只说明可定位的现状，不替代当期测试。DAY0 的 `19` 个测试文件、`72` 项测试和 40 Case 重跑结果是历史基线；Day1 必须重新取证，不能直接沿用为完成记录。

## 2. 最小支持声明格式

### 支持声明结构

| 需求 ID | 需求 | 来源 | 分类 | 唯一主责工作包 | 当前代码/测试证据 | 缺口 / 验收边界 |
|---|---|---|---|---|---|---|
| AG-CLAIM-001 | 定义可追溯、可按环境与协议切片的最小支持声明，禁止使用全局支持布尔值。 | Day1 必须工作 6；Backend V2 §4/12 | `Day1` | Day1 | 本节格式；V1 事实见覆盖矩阵与本文件 §4 | Day1 不实现 Registry/Activation/qualification；缺可信资格记录时不能声明 supported。 |

任何未来面向用户、报告或机器的“支持”声明，最少必须形成以下证据切片。`maturity` 是三个相互独立状态的容器，不是一个含糊布尔值：

```yaml
familyId: "<stable-family-id>"
techniqueId: "<stable-technique-id>"
moduleVersion: "<semver>"
maturity:
  implementationState: "implemented-v1 | partial-v1 | inventory-partial | not-started | policy-forbidden"
  declaredMode: "active-l1 | active-l2 | signal-only | fixture-only | inventory-only | forbidden"
  activationStatus: null # 或 registered | qualified | suspended | retired
environment:
  - "offline | attested-fixture | authorized-test-environment | authorized-real-target"
protocolSelector:
  - protocol: "<versioned transport/codec profile>"
    selector: "<query/path/header/cookie/form/json-pointer/xml-path/multipart-part/graphql-variable/websocket-field/...>"
benchmarkSuite:
  suiteId: "<stable-suite-id>"
  suiteVersion: "<version>"
  resultClass: "self-built-fixture | external-local-holdout | authorized-pilot | not-run"
  qualificationRecordRef: null # qualified 时必须为内容寻址引用
```

字段语义：

- `implementationState` 只陈述代码与测试实际成熟度，值域与覆盖矩阵当前状态一致；它不能由 Manifest 作者自行升级。
- `declaredMode` 只是模块作者声明的最高意图模式，不是执行授权。
- `activationStatus` 只能来自未来只读 ActivationCatalog；`registered` 等价于 registered-only，不能主动执行；`qualified` 仍只对记录绑定的 environment 与 protocol/selector 切片有效。`null` 表示尚无可信 Catalog 记录，不是另一种激活状态。
- `environment` 与 `protocolSelector` 必须逐项列出，不能用 `supportsComplexApi=true`、`supportsWeb=true` 或 family 级总布尔值代替。
- `benchmarkSuite` 至少绑定 suite ID/version、结果类别和 qualification record；self-built fixture 不得冒充 external holdout 或 authorized pilot。

只有 `implementationState` 与声明切片一致、`activationStatus=qualified`、qualification record 的 definition/build/suite/fixture/Policy 哈希有效、环境及 protocol/selector 精确匹配时，才能对该切片作支持声明。任一字段缺失、`not-run`、版本不匹配或只有计划文字时不得标记 supported。

Day1 **只定义并评审这个格式**。Day1 不实现 DefinitionRegistry、ActivationCatalog、QualificationService 或 Registry schema，不生成伪造的 qualification record，也不把 V1 四类硬编码闭环改写成已资格化模块；这些分别由 Day2、Day7 及后续工作包负责。

## 3. 架构与安全不变量

| 需求 ID | 需求 | 来源 | 分类 | 唯一主责工作包 | 当前代码/测试证据 | 缺口 / 验收边界 |
|---|---|---|---|---|---|---|
| AG-ARCH-001 | Renderer 只展示数据和表达用户意图，不直连文件系统、SQLite、secret、Runner 或目标网络。 | 总体架构 §2/4；AGENTS.md | `已有` | Day20 | [Main 窗口配置](../../apps/desktop/src/main/index.ts)、[Preload 白名单](../../apps/desktop/src/preload/index.ts)、[Desktop contract test](../../packages/contracts/src/desktop.test.ts) | Day20 及每次桌面边界变更需 build/smoke；新 V2 服务不能提前暴露给 Renderer。 |
| AG-ARCH-002 | 跨进程能力先在 contracts 定义并双向校验，再经 Preload 白名单暴露。 | 总体架构 §2/4/6；AGENTS.md | `已有` | Day20 | [desktop contracts](../../packages/contracts/src/desktop.ts) 与 [Main IPC 注册](../../apps/desktop/src/main/index.ts) 使用输入/输出 schema | 后续合同应优先兼容；非法 IPC、输出 schema 与白名单回归仍是发布门禁。 |
| AG-ARCH-003 | Domain/漏洞模块不依赖 Electron UI，也不能持有 Runner、Repository、CredentialStore 或任意网络回调。 | Backend V2 §7/14；总体架构 §5/6 | `后续波次` | Day15 | [domain package](../../packages/domain/src/index.ts) 当前不依赖 Electron；现有验证仍集中在 [Coordinator](../../packages/application/src/scan-coordinator.ts) | Day15 必须以 architecture test 证明模块只输出声明式 Plan，Coordinator 无 family 分支且只有一个联网真源。 |
| AG-ARCH-004 | 所有模型调用经过 model-gateway，外部输出先结构化校验和脱敏。 | 总体架构 §6/7；Agent 系统 §10 | `已有` | Day20 | [ModelGateway](../../packages/model-gateway/src/index.ts)、[gateway tests](../../packages/model-gateway/src/model-gateway.test.ts)；Application 依赖其接口 | 持续禁止业务包直连 Provider；Day20 secret scan 与依赖边界测试需再次证明。 |
| AG-ARCH-005 | Agent 只提出候选和解释；授权、执行、Evidence、ConfirmationRule 与报告结论由确定性服务决定。 | Agent 系统 §1～3；Backend V2 §8/9 | `已有` | Day15 | [agent-runtime](../../packages/agent-runtime/src/index.ts)、[validation engine](../../packages/application/src/validation-engine.ts)、[reporting](../../packages/reporting/src/index.ts) | 当前四类逻辑仍写死；Day14/15 迁入通用 CandidateCompiler/Plan/ConfirmationEngine 后才能证明开放扩展。 |
| AG-ARCH-006 | 扫描冻结 scope、module、technique、rule、evidence profile、capability 与 Registry snapshot；恢复不得偷用新版。 | Backend V2 §3.3；数据模型 §7 | `后续波次` | Day3 | V1 Scan 已保存 `scopeSnapshotId`，见 [contracts workflow](../../packages/contracts/src/workflow.ts) 与 [DB schema](../../packages/db/src/schema.ts) | module/capability/Registry snapshot 尚不存在；缺历史版本必须 awaiting-user/Inconclusive。 |
| AG-ARCH-007 | 新 Agent 同时具备输入/输出 schema、Prompt 版本、预算、日志与测试；新 Finding 类型同时具备 Signal、Validation、确认规则、Evidence、修复与评测。 | AGENTS.md；Agent 系统 §1/10；Backend V2 §14 | `已有` | Day20 | V1 五 Agent schema/Prompt 与测试位于 [application](../../packages/application/src)；Finding/Rule/Report 已有基础链 | 任何后续新增必须过 module/conformance gate；缺一项最多 signal/inventory/fixture。 |
| AG-SEC-001 | 每次实际 I/O 前重新核对 origin/path/port/IP/redirect/identity/有效期/预算，未知或歧义输入 fail closed。 | 主动探测 §3；Backend V2 §16 | `已有` | Day6 | [security-policy](../../packages/security-policy/src/index.ts)、[HTTP runner](../../packages/http-runner/src/index.ts) 及相应测试覆盖现有 Scope/DNS/redirect 边界 | 原子预算、精细地址分类、每跳 Lease 与最终 wire 绑定尚待 Day5/6。 |
| AG-SEC-002 | L1 仅 reviewed 只读最小动作；POST/PUT/PATCH 或未知副作用默认 L2；family 名称不能降级风险。 | 主动探测 §2；Backend V2 §6/16 | `已有` | Day6 | [security-policy tests](../../packages/security-policy/src/security-policy.test.ts) 覆盖基础风险判定 | 当前产品 L2 只有调用方布尔语义；可信批准/TestObject/cleanup 完成前真实目标 L2 不可用。 |
| AG-SEC-003 | DROP/TRUNCATE、生产/未知对象增删改、通用 DELETE、账号接管、凭据喷洒、持久化、横移、高强度 DoS、恶意文件、metadata 与越界永久拒绝。 | 主动探测 §2；Backend V2 §16；覆盖矩阵 `WEB-SAFE-*` | `已有` | Day20 | [security-policy](../../packages/security-policy/src/index.ts) 与 [policy tests](../../packages/security-policy/src/security-policy.test.ts) 有现有危险动作拒绝 | Day20 要求所有永久禁止 ToolCall 计数为 0；后续模块、MCP、知识与配置均不能覆盖。 |
| AG-SEC-004 | cleanup 只收尾本次 AgentGo 创建且 ownership-attested、disposable、精确 ID 的 TestObject；不是漏洞探测，失败后仅 recovery。 | 主动探测 §2；七波路线 §5 | `后续波次` | Day8 | 当前仅有自然语言 cleanupPlan/调用方批准边界，见 [security contracts](../../packages/contracts/src/security.ts) | Day8 建纯状态模型；Day10 才在 loopback fixture 执行。无安全 cleanup 协议时相应 L2 不激活。 |
| AG-SEC-005 | Cookie、Authorization、Token、密码、CSRF secret 与 OOB plain token 不进入 SQLite、普通 Evidence、日志、模型或报告。 | 威胁模型 §5/8/9；Backend V2 §16 | `已有` | Day9 | [credential store](../../packages/db/src/credential-store.ts)、[model gateway](../../packages/model-gateway/src/index.ts) 与测试已有凭据引用/脱敏基础 | SessionVault、私有 Cookie/CSRF sink 和 generation 隔离尚待 Day9；Day20 需全链 secret scan。 |
| AG-SEC-006 | 页面、知识、模型、MCP、规范文件与工具输出均是不可信内容，不能提升 prompt、权限、scope、预算或工具能力。 | 威胁模型 §3/4/8；总体架构 §3 | `已有` | Day14 | [knowledge-base](../../packages/knowledge-base/src/index.ts)、[model-gateway](../../packages/model-gateway/src/index.ts)、[MCP hub](../../packages/mcp-hub/src/index.ts) 有校验/裁剪基础 | 未发布或未映射知识必须无法进入 CandidateCompiler；协议导入和浏览器内容还需 Day11～14 的隔离测试。 |
| AG-SEC-007 | Evidence 默认不可变、内容哈希可校验；脱敏生成派生物并保留审计关系，捕获前遵循最小化策略。 | 数据模型 §3/6；威胁模型 §9 | `已有` | Day4 | [EvidenceStore](../../packages/db/src/evidence-store.ts) 与 [evidence tests](../../packages/db/src/evidence-store.test.ts) 实现内容寻址、hash、derivedFrom | V1 ExecutionService 仍可能先保存原始响应；Day4 必须增加 CapturePolicy、敏感字段禁止捕获与受保护原件边界。 |
| AG-SEC-008 | 每次主动执行记录 scope/identity、Proposal/Policy、请求/响应摘要、Evidence、side effect、cleanup、版本与结束状态。 | 主动探测 §7/9；数据模型 §7 | `已有` | Day5 | [execution service](../../packages/application/src/execution-service.ts)、[repository](../../packages/db/src/repository.ts)、[execution tests](../../packages/application/src/execution-service.test.ts) 有 V1 审计链 | 缺 Template/Resolved/Wire hash、单次 Lease、step role 和 L2 Receipt；Day5/10 补齐。 |
| AG-SEC-009 | WAF、网络抖动、会话失效、协议不支持、版本不一致、证据不足或 cleanup failure 输出 Inconclusive，不得伪造 Confirmed。 | 主动探测 §6/8；Backend V2 §9/16 | `已有` | Day20 | [validation engine](../../packages/application/src/validation-engine.ts) 已有三态 Verdict 基础 | 各 technique 必须有版本化纯确认规则、异质负对照与安全 Case；Day20 审计模型/Agent 无提升路径。 |
| AG-SEC-010 | 达到最小证据、预算、重复、scope/session 变化或安全阻断立即停止；预算必须原子且不可超卖。 | Agent 系统 §7；主动探测 §1/8 | `已有` | Day6 | [agent-runtime tests](../../packages/agent-runtime/src/agent-runtime.test.ts) 与现有 Policy/Runner 有阶段、取消和部分预算 | V1 请求完成后计数/RPM 声明不足以支撑并发复杂 Plan；Day6 建 reserve/settle 与资源门禁。 |

## 4. V1 当前真实边界

| 需求 ID | 当前事实 | 来源 | 分类 | 唯一主责工作包 | 当前代码/测试证据 | 缺口 / 禁止外推 |
|---|---|---|---|---|---|---|
| AG-V1-001 | 当前 family 只有 `sqli/xss/ssrf/idor`，四类可在本地固定靶场走通 Signal → Validation → Verdict → Evidence → Report。 | V1 审计；DAY0 §3 | `已有` | Day15 | [VulnerabilityFamilySchema](../../packages/contracts/src/workflow.ts)、[Coordinator](../../packages/application/src/scan-coordinator.ts)、[validation engine](../../packages/application/src/validation-engine.ts) | 四值枚举横跨 Application/DB/Knowledge/Reporting/Evaluation/Renderer；不能称为开放漏洞平台。 |
| AG-V1-002 | 扫描阶段为 intake、passive-recon、active-enum、hypothesis、validation、verification、report，并支持暂停/取消/恢复。 | Agent 系统 §8；DAY0 §3 | `已有` | Day15 | [agent-runtime](../../packages/agent-runtime/src/index.ts)、[Coordinator tests](../../packages/application/src/scan-coordinator.test.ts) | passive/active discovery 较浅；尚无通用 CandidateAttempt/PhaseOutcome 与复杂 step 恢复。 |
| AG-V1-003 | SQLi 仅为 GET query 的只读布尔差异、负对照与重复。 | V1 审计 | `已有` | Day16 | [SQLi rule](../../packages/application/src/validation-engine.ts)、[fixture](../../packages/evaluation/src/local-fixture.ts) | path/form/JSON、稳定错误/时间策略未资格化；禁止读取数据与写语句。 |
| AG-V1-004 | XSS 为惰性反射 marker 加断网 `setContent` 浏览器观察。 | V1 审计 | `已有` | Day18 | [Coordinator XSS branch](../../packages/application/src/scan-coordinator.ts)、[BrowserRunner](../../packages/browser-runner/src/index.ts) | 不是登录 SPA/运行期浏览器；存储型与复杂 DOM 尚未实现，反射不等于执行。 |
| AG-V1-005 | SSRF 只确认目标响应中返回的受控 proof。 | V1 审计 | `已有` | Day19 | [Coordinator SSRF branch](../../packages/application/src/scan-coordinator.ts)、[fixture](../../packages/evaluation/src/local-fixture.ts) | 无真实 CallbackCollector；blind OOB 必须 Inconclusive，不能把 mock/回显写成生产 OOB。 |
| AG-V1-006 | IDOR 使用两个授权测试身份和已知资源做 GET query 只读对照。 | V1 审计 | `已有` | Day17 | [Coordinator IDOR branch](../../packages/application/src/scan-coordinator.ts)、[validation engine](../../packages/application/src/validation-engine.ts) | 无 path/body、层级对象、完整 tenant/role matrix；不得枚举真实 ID 或写删对象。 |
| AG-V1-007 | Policy 已检查 scope、method、identity、DNS/redirect 与声明预算，但 L2 仍依赖 `userApproved` 布尔。 | V1 审计；主动探测 §7 | `已有` | Day10 | [security-policy](../../packages/security-policy/src/index.ts)、[execution policy](../../packages/application/src/execution-policy.ts) | 无可信 ActorContext/ApprovalPort、TestObject 与 cleanup；真实目标 L2 保持禁用。 |
| AG-V1-008 | HTTP Runner 可发送 body 并限制 timeout/size；Browser Runner 是断网离线渲染。 | DAY0 §3 | `已有` | Day13 | [HTTP Runner](../../packages/http-runner/src/index.ts)、[Browser Runner](../../packages/browser-runner/src/index.ts) 及测试 | Coordinator 未利用复杂 body；无 BrowserNetworkBroker、Session/CSRF 或复杂协议 adapter。 |
| AG-V1-009 | Evidence 内容寻址、hash 校验、派生脱敏与三态报告已存在。 | V1 审计；数据模型 | `已有` | Day4 | [EvidenceStore](../../packages/db/src/evidence-store.ts)、[reporting](../../packages/reporting/src/index.ts) 及测试 | 缺捕获前字段裁剪、加密/密钥生命周期、保留期和配额门禁；原始响应过量捕获是已知风险。 |
| AG-V1-010 | Knowledge 有四类内置条目、来源元数据、FTS5、导入 Extractor/Reviewer 和人工发布。 | V1 审计 | `已有` | Day14 | [knowledge-base](../../packages/knowledge-base/src/index.ts)、[knowledge tests](../../packages/knowledge-base/src/knowledge-base.test.ts) | 来源与数量有限，存在两条组装路径；无 Registry-aware 统一检索，知识不能直接生成可执行 Plan。 |
| AG-V1-011 | Model 调用经 model-gateway；MCP 已有配置、加密凭据引用、连接测试与 capability discovery。 | 总体架构 §7/9；V1 审计 | `已有` | Day20 | [model-gateway](../../packages/model-gateway/src/index.ts)、[mcp-hub](../../packages/mcp-hub/src/index.ts) 及测试 | MCP 自动工具调用、逐次授权与 Evidence 映射未进入 V1；不得退化为任意 shell/SSH。 |
| AG-V1-012 | DAY0 的同毫秒 Scope 排序竞态已由 Day1 migration `0005_monotonic_scope_revisions`、单调 revision、显式 current pointer 与精确 Scan snapshot 解除。 | DAY0 §10/10.1；Day1 基线 §3；V1 审计 | `Day1` | Day1 | [DB migrations](../../packages/db/src/migrations.ts)、[repository](../../packages/db/src/repository.ts)、[database tests](../../packages/db/src/database.test.ts)、[验收记录](day1-baseline.md#3-scope-顺序迁移与冻结语义) | 当前 pointer 仍可为 NULL 以支持 Target→Scope 同事务创建；异常原始 SQL 数据读取 fail closed。后续不得退回时间/UUID 推断。 |
| AG-V1-013 | 固定评测为四类各 5 正 5 负，共 40 个同构 GET Case。 | V1 审计；DAY0 §3 | `已有` | Day7 | [evaluation](../../packages/evaluation/src/index.ts)、[local fixture](../../packages/evaluation/src/local-fixture.ts) 及测试 | 一次重跑满分不证明稳定或真实 Web 准确率；无 technique/protocol/selector/L2/holdout 级评测。 |
| AG-V1-014 | 当前桌面已有 Dashboard、Target/Identity、Scan、Findings/Reports、Audit、Knowledge、MCP、Agent/Model 入口。 | DAY0 §3/7 | `已有` | Day20 | [Renderer App](../../apps/desktop/src/renderer/src/App.tsx)、[desktop contracts](../../packages/contracts/src/desktop.ts) | 缺组件/E2E 业务测试；smoke 只证明启动到 renderer-ready，不等于完整 Target→Report E2E。 |
| AG-V1-015 | Multi-Agent、KnowledgeAgent 和 Verifier 的研究价值尚未被外部 holdout、多模型重复与消融证明。 | V1 审计“不能据此声称”；路线图研究阶段 | `非目标` | W7 | 当前只有固定 fixture 与 V1 自动测试 | 在长期评测完成前，不得把研究问题写成已证实成果。 |

## 5. Day1 必须交付的需求

| 需求 ID | Day1 交付 | 来源 | 分类 | 唯一主责工作包 | 当前代码/测试证据 | 缺口 / 完成证据 |
|---|---|---|---|---|---|---|
| AG-D01-001 | 建立逐项需求追踪，所有项具有稳定 ID、分类、唯一主责、证据和缺口。 | Day1 必须工作 1；合格交付 | `Day1` | Day1 | 本文件 77 个唯一需求 ID；[Day1 验收](day1-baseline.md#1-day1-八项交付) | 已验收；未来行仍必须保持真实状态，不得因计划存在改成已实现。 |
| AG-D01-002 | 审核覆盖矩阵：每个 WSTG/ASVS/API/SRC 类别有稳定目录 ID、当前成熟度、环境、Capability、停止条件和波次。 | Day1 必须工作 2 | `Day1` | Day1 | [覆盖矩阵](web-vulnerability-coverage-matrix.md) 与 [98 项机器目录](web-vulnerability-coverage-catalog.json)；6 项契约测试 | 已验收；未知 ASVS/Top 10 2025 精确映射保持 pending-verification，不猜编号。 |
| AG-D01-003 | 修复 Scope 快照竞态并冻结确定 scope ID/version。 | Day1 必须工作 3；DAY0 §10.1 | `Day1` | Day1 | migration `0005`、[repository](../../packages/db/src/repository.ts)、[9 项 DB 测试](../../packages/db/src/database.test.ts) 与 [Application 精确返回测试](../../packages/application/src/application-service.test.ts) | 已验收；覆盖同毫秒、create/update、路径别名并发、旧库、DB 不变量、回滚与 createScan；禁用 sleep/UUID 排序/失败重试掩盖。 |
| AG-D01-004 | 重新记录 commit、Node/pnpm/Electron/Playwright/SQLite、测试数、fixture/migration 版本、build 与 desktop smoke。 | Day1 必须工作 4 | `Day1` | Day1 | [Day1 环境与命令记录](day1-baseline.md#2-环境与版本) | 已验收；执行起点与未提交工作区状态均明确记录，DAY0 数字只作历史参照。 |
| AG-D01-005 | 冻结 `apps/desktop/src/renderer/**`；除后端兼容修复外不增加 View、导航或交互。 | Day1 必须工作 5 | `Day1` | Day1 | [Renderer](../../apps/desktop/src/renderer) 相对基线 diff 为空；typecheck/build/smoke 通过 | 已验收；冻结规则继续适用于后端工作包。 |
| AG-D01-006 | 定义 `familyId + techniqueId + moduleVersion + maturity + environment + protocol/selector + benchmarkSuite` 支持声明。 | Day1 必须工作 6 | `Day1` | Day1 | 本文件 §2 | 格式已验收；Registry/Activation/qualification 仍为 Day2/Day7，当前未生成 supported 声明。 |
| AG-D01-007 | 生成仅含合成数据、可重建且有 schema version/hash 的 V1 数据库 baseline。 | Day1 必须工作 7 | `Day1` | Day1 | [生成/验证脚本](../../scripts/v1-database-baseline.ts)、[4 项测试](../../scripts/v1-database-baseline.test.ts) 与 [双 hash 记录](day1-baseline.md#6-合成-v1-数据库-baseline) | 已验收；仅 `.invalid` 合成数据，生成物仍不得提交。 |
| AG-D01-008 | 审核 Git 忽略边界，计划原件、DB、凭据、Evidence、benchmark results、release 和本机缓存不得入库。 | Day1 必须工作 8 | `Day1` | Day1 | [`.gitignore`](../../.gitignore) 与 [最终审计](day1-baseline.md#7-git敏感数据与顺延边界) | 已验收；后续新增生成物仍必须逐项检查，不能依赖泛化目录名猜测。 |

## 6. 二十个顺序工作包追踪

这些是顺序工作包，不是自然日承诺。`当前证据` 中出现前置实现，只表示可复用基础；退出门槛未通过时该包仍未完成。

| 需求 ID | 目标交付 | 来源 | 分类 | 唯一主责工作包 | 当前代码/测试证据 | 主要缺口 / 退出边界 |
|---|---|---|---|---|---|---|
| AG-WP-001 | Scope 竞态修复、事实/覆盖/支持声明基线与 Renderer 冻结。 | [Day1](Day1.md) | `Day1` | Day1 | [Day1 完成记录](Day1.md#完成记录) 与 [事实基线](day1-baseline.md) | 2026-07-13 已验收；不包含 Registry/Activation/qualification，也不外推固定 fixture。 |
| AG-WP-002 | 开放 Family/Technique ID、Manifest、原子 DefinitionRegistry 与 legacy bundle；注册不等于激活。 | [Day2](Day2.md) | `后续波次` | Day2 | 当前仍为 [四值 enum](../../packages/contracts/src/workflow.ts) 与硬编码规则 | Registry/Bundle/Activation view/conformance 均未实现；`security.headers` 只能先 registered-only，未知 family fail closed。 |
| AG-WP-003 | 唯一 scan-scoped Inventory、RequestVariant/Source/Selector/Codec/Transport、opaque refs 与 module snapshot。 | [Day3](Day3.md) | `后续波次` | Day3 | V1 有 Endpoint/Parameter/Scan 表，见 [schema](../../packages/db/src/schema.ts) | 多来源幂等、secret 裁剪、旧库迁移和 frozen module snapshot 尚缺。 |
| AG-WP-004 | 纯 RequestCompiler、Template/Resolved/Wire 三阶段哈希与 EvidenceCapturePolicy。 | [Day4](Day4.md) | `后续波次` | Day4 | V1 HTTP 构造/Evidence 保存位于 [execution service](../../packages/application/src/execution-service.ts) | 无统一 compiler、opaque generation 绑定或 capture-before-store 最小化；未实现 codec 必须拒绝。 |
| AG-WP-005 | ExecutionGrant、单次 Lease、实际 wire 恒等复核与唯一 ExecutionPort。 | [Day5](Day5.md) | `后续波次` | Day5 | V1 有 PolicyDecision 与 Runner，见 [execution policy](../../packages/application/src/execution-policy.ts) | 裸 decisionId、重放、并发 claim、redirect child grant 与 crash unknown 语义尚缺。 |
| AG-WP-006 | 原子 request/RPM/concurrency/bytes 预算和 DNS/IP/redirect/response resource 门禁。 | [Day6](Day6.md) | `后续波次` | Day6 | 现有 [policy](../../packages/security-policy/src/index.ts) 与 [runner](../../packages/http-runner/src/index.ts) 有部分限制 | reserve/settle、精细地址类、压缩炸弹/慢读和稳定 reason code 尚缺。 |
| AG-WP-007 | Evaluation Core、Ground Truth v2、Suite Registry、基础 loopback fixture 与 QualificationRecord。 | [Day7](Day7.md) | `后续波次` | Day7 | [evaluation](../../packages/evaluation/src/index.ts) 与 [fixture](../../packages/evaluation/src/local-fixture.ts) 仅四类固定套件 | technique/protocol/selector/environment/Evidence role/三态与 activation record 尚缺；生产不得加载 fixture 代码。 |
| AG-WP-008 | 不联网的 TestObject、L2ActionBundle、SideEffectEnvelope、cleanup/recovery 状态和 Receipt。 | [Day8](Day8.md) | `后续波次` | Day8 | 当前只有基础 Probe/Policy 合同 | 当天网络必须为 0；没有 Day9/10 绑定与批准时任何路径不得进入 approved/running。 |
| AG-WP-009 | SessionVault、IdentityContext、CSRF binding 与 AuthorizationMatrix。 | [Day9](Day9.md) | `后续波次` | Day9 | V1 有 Identity 与 [credential store](../../packages/db/src/credential-store.ts) | 无 Cookie jar generation、CSRF 私有 sink、授权真值矩阵；当天 L2 primary/cleanup 必须为 0。 |
| AG-WP-010 | 可信 ActorContext/ApprovalService 与首条 fixture-only L2 闭环。 | [Day10](Day10.md) | `后续波次` | Day10 | 当前 Policy 仍读取调用方 `userApproved` | Renderer/Agent 不可伪造；仅 loopback TestObject primary 一次并 cleanup-verify。无可信产品端口时真实 L2 禁用。 |
| AG-WP-011 | OpenAPI 3.0/3.1、Swagger 2、HAR、Postman 与 GraphQL 描述的零网络 Preview/Commit 导入。 | [Day11](Day11.md) | `后续波次` | Day11 | 当前无统一离线接口导入服务 | parser profile、资源限制、secret 裁剪、Scope、幂等 provenance 与零网络测试尚缺；导入仅 inventory。 |
| AG-WP-012 | HTML/JS/source map 离线静态发现、冻结 AssetManifest 与 ExtractionRule。 | [Day12](Day12.md) | `后续波次` | Day12 | V1 仅浅层 HTML/link/form 发现 | 不得下载/执行资源；全局 producer merge 与浏览器留给 Day13，复杂协议只产 inventory hint。 |
| AG-WP-013 | Policy-mediated BrowserNetworkBroker、固定 SPA fetch/XHR、唯一 Producer Merge 与 DependencyGraph。 | [Day13](Day13.md) | `后续波次` | Day13 | [BrowserRunner](../../packages/browser-runner/src/index.ts) 仅断网 `setContent` | 浏览器零直连、冻结 manifest、未知写动作只盘点、所有 producer 唯一合并与依赖缺值暂停尚缺。 |
| AG-WP-014 | 通用受限 ValidationPlan/step runtime、角色化 Evidence 与 Registry-aware RetrievalService。 | [Day14](Day14.md) | `后续波次` | Day14 | V1 [validation engine](../../packages/application/src/validation-engine.ts) 与 Knowledge 有专用路径 | 无开放 DSL/step persistence/统一 retrieval；每个 I/O 仍需独立 Policy/Lease，模块不得 callback/直调 Runner。 |
| AG-WP-015 | 四类 legacy parity bundle、通用 Coordinator、CandidateAttempt/PhaseOutcome 与安全恢复。 | [Day15](Day15.md) | `后续波次` | Day15 | [Coordinator](../../packages/application/src/scan-coordinator.ts) 仍含四类分支 | 必须 shadow 不双发、golden parity、逐类切单一真源并删除 family 分支；任一类未迁移则 partial。 |
| AG-WP-016 | SQLi 参考模块：复杂 selector 下的非写入差异与分 technique 成熟度。 | [Day16](Day16.md) | `后续波次` | Day16 | V1 只有 GET query boolean 差异 | 在 Day15 同一 bundle 增强；form/JSON 为批准 L2，时间法 fixture-only，破坏性语义请求数 0。 |
| AG-WP-017 | IDOR/BOLA 参考模块：已知 TestObject、多身份只读 AuthorizationMatrix。 | [Day17](Day17.md) | `后续波次` | Day17 | V1 仅双身份 GET query 对照 | path/query、owner/public/shared/admin/tenant/parent 控制与 selected-field Evidence 尚缺；不枚举/写对象。 |
| AG-WP-018 | XSS 参考模块：惰性反射、离线 DOM 与可清理 stored TestObject 分级。 | [Day18](Day18.md) | `后续波次` | Day18 | V1 有反射 marker 与离线 BrowserRunner | 需上下文/编码/CSP/负对照；stored 仅 L2 TestObject，浏览器外联为 0，cleanup failure 冻结。 |
| AG-WP-019 | SSRF 回显/OOB 参考模块，并资格化零新增请求的 `security.headers` 被动模块。 | [Day19](Day19.md) | `后续波次` | Day19 | V1 仅回显 proof；无 CallbackCollector/headers module | OOB token 关联、危险网络拒绝、collector unavailable 三态与无分支扩展证明尚缺；mock 不冒充生产。 |
| AG-WP-020 | 全量 conformance/迁移/恢复/安全/benchmark/holdout/报告与桌面兼容门禁。 | [Day20](Day20.md) | `后续波次` | Day20 | DAY0 仅有 V1 check/build/smoke 与固定 benchmark 历史证据 | `benchmark:complex`、`benchmark:holdout` 等目标命令当前未交付；安全计数必须为 0，self-built/holdout/pilot/not-run 分栏。 |

## 7. Day20 后七波追踪

W1～W7 全部是 Day20 合格退出后的后端路线，当前均不得描述为已实现。每波还必须交付独立固定 holdout、完整 Module/Adapter DoD、覆盖矩阵和复杂接口八维状态更新，并保证既有桌面与此前回归不退化。

| 需求 ID | 波次交付 | 来源 | 分类 | 唯一主责工作包 | 当前代码/测试证据 | 主要缺口 / 退出边界 |
|---|---|---|---|---|---|---|
| AG-POST-001 | 被动攻击面与安全姿态：JS/API 图、Header/TLS/Cookie/CORS、错误/方法面、泄漏与组件 Signal。 | 七波路线 W1 | `后续波次` | W1 | V1 只有浅层发现、部分 Cookie/响应元数据；Day19 目标仅含首个 headers 模块 | 建 AttackSurfaceGraph/Passive Analyzer 与 W1 独立 holdout；版本/字符串/缺 Header 不自动升级高危或 CVE。 |
| AG-POST-002 | 身份、Session、JWT/OAuth/OIDC/SAML 与对象/字段/功能/租户授权。 | 七波路线 W2 | `后续波次` | W2 | V1 仅静态测试身份与双身份 IDOR；Day9/10 是前置目标 | AuthFlow/token 生命周期/SSO/多维 Matrix 与 W2 holdout 尚缺；不喷洒、不接管、不绕 MFA。 |
| AG-POST-003 | 现代 Web/API 协议：REST 描述扩展、GraphQL、WebSocket、SSE、Webhook、SOAP/WSDL、gRPC 与 AsyncAPI。 | 七波路线 W3 | `后续波次` | W3 | 当前 HTTP Runner 能发普通 HTTP，但这不是协议语义支持 | 每协议分别声明 discovery/import/replay/active/session/auth/streaming/OOB；写消息/订阅为 L2，未知维度 fail closed。 |
| AG-POST-004 | 业务状态、多租户、workflow、不变量、幂等、低速 rate limit 与受限 race/TOCTOU。 | 七波路线 W4 | `后续波次` | W4 | 当前无用户确认 BusinessInvariant/WorkflowOracle | 必须用测试 tenant/TestObject、可回退状态和 bounded concurrency；无用户 oracle 不 Confirmed，不做真实支付/通知/压测。 |
| AG-POST-005 | 通用注入 generator/differential 框架：NoSQL/ORM/LDAP/XPath/SSTI/HPP/CRLF/原型污染等。 | 七波路线 W5 | `后续波次` | W5 | V1 只有 SQLi GET query 专用逻辑 | 新语法族必须 manifest 化且不改 Coordinator；自由文本 payload、命令/代码/高成本时间/公式副作用在真实环境拒绝。 |
| AG-POST-006 | 文件/XML 与真实浏览器客户端：XXE、Traversal、upload/archive、反序列化、DOM/stored XSS、postMessage/storage/tabnabbing/XSSI/XS-Leak。 | 七波路线 W6 | `后续波次` | W6 | 当前无 multipart/XML 文件生命周期；BrowserRunner 仅离线渲染 | W6A/W6B 顺序发布；EphemeralFileVault、Broker、派生物 cleanup 与零第二网络出口门禁尚缺。 |
| AG-POST-007 | 隔离协议实验、组件/供应链、RCE/crypto lab、LLM Web 与长期消融/泛化评测。 | 七波路线 W7 | `后续波次` | W7 | MCP/Knowledge/模型与固定 fixture 只提供前置基础 | raw protocol/危险实验必须与 production root 编译隔离；每子版本独立 holdout，长期 sealed holdout 不参与调参，永久禁止调用为 0。 |

## 8. Renderer 冻结与非目标

| 需求 ID | 边界 | 来源 | 分类 | 唯一主责工作包 | 当前证据 | 缺口 / 验收 |
|---|---|---|---|---|---|---|
| AG-UI-001 | Day1～Day20 不重建 Renderer，不新增 Approval/Cleanup/Session/Import/Waiting/XSS Evidence/Callback 页面、导航或临时交互。 | DAY0 §7；20 包总览 §7 | `Day1` | Day1 | [Renderer 目录](../../apps/desktop/src/renderer) 与现有八个入口 | 只允许后端兼容导致的最小编译/启动修复；diff 审核必须证明没有功能扩张。 |
| AG-UI-002 | 新后端先通过 contracts、Application integration、fixture CLI、Repository、报告 JSON 与 benchmark 验收。 | 20 包总览 §7；Backend V2 §15 | `后续波次` | Day14 | 当前已有 contracts/Application/evaluation 测试基础 | 后端完成不能依赖手工 UI 点击，也不能为了演示提前暴露不稳定服务。 |
| AG-UI-003 | Main/Preload 仅在现有前端运行必需时做最小兼容；任何边界变更当日 build + smoke。 | DAY0 §7；20 包总览 §7 | `后续波次` | Day20 | [Main](../../apps/desktop/src/main/index.ts)、[Preload](../../apps/desktop/src/preload/index.ts)、[smoke script](../../scripts/smoke-desktop.ps1) | Day20 证明 renderer-ready、白名单/schema 不回退和既有流程不崩；smoke 不冒充业务 E2E。 |
| AG-UI-004 | W1～W7 仍只建设后端只读 contracts；未来前端不得重写 Policy、Eligibility、Verdict 或 cleanup。 | 七波路线 §9 | `后续波次` | W7 | 当前无 V2 descriptor/coverage/pending-action contracts | 这些合同只在相应后端状态机稳定后交付，不授权当前新增 Renderer UI。 |
| AG-NG-001 | “自动发现任意真实 Web 的所有已知/未知漏洞”不是 20 包或七波承诺。 | 20 包总览 §2/8；七波路线 §10 | `非目标` | 非目标（无执行包） | V1 仅四类固定 GET fixture | 必须按 exact technique/environment/protocol/selector 报告，未知业务与不安全场景保持 Signal/Inconclusive。 |
| AG-NG-002 | 未授权公网扫描、高并发分布式扫描、自动红队全链、生产数据修改、WAF 绕过、持久化与横向移动不在项目范围。 | 项目范围 §6；主动探测 §2/6 | `非目标` | 非目标（无执行包） | SecurityPolicy 已有部分拒绝测试 | 永久禁止项不得因波次、用户配置、Agent 或 MCP 获得例外。 |
| AG-NG-003 | 当前后端计划不建设通用 Kali 控制平台、任意 SSH/shell 通道、自训练基础模型或大型图数据库。 | 项目范围 §6；总体架构 §9 | `非目标` | 非目标（无执行包） | 当前 MCP 仅配置/连接测试/能力发现 | Stretch 能力未来也必须走 Registry、Policy、Lease、Evidence，不抢占安全门禁。 |
| AG-NG-004 | Day20 不完成新前端、正式代码签名、完整 NSIS 安装/升级/卸载矩阵或结题材料。 | Day20；路线图产品化阶段 | `非目标` | 非目标（产品化阶段） | 当前有 build/pack 配置与 desktop smoke | 这些由后端稳定后的前端/产品化阶段承担，不得作为 Day20 后端完成条件伪造。 |
| AG-NG-005 | fixture 满分、少量 holdout 或 smoke 不能证明真实互联网准确率、完整 E2E 或 Multi-Agent 研究价值。 | V1 审计；Day20；七波路线 §7 | `非目标` | W7 | DAY0 有固定 40 Case 与 smoke 历史结果 | 必须分 development fixture、external holdout、authorized pilot、sealed holdout、not-run，并保留 limitations。 |

## 9. Day1 关闭规则

本文件只能与下列证据一起支撑 Day1 退出，不能单独把 Day1 标为 completed：

1. §5 的 Day1 八项交付各有实际生成物、命令和脱敏结果；
2. Scope 同毫秒、连续更新、并发更新、旧库迁移和 createScan 精确 snapshot 测试稳定通过；
3. `pnpm check`、`pnpm smoke:desktop`、`pnpm benchmark:verify` 与三次全新输出目录 benchmark 结果均被记录，任何失败都不得用重跑掩盖；
4. 合成数据库可重复生成相同 hash、迁移通过且 secret scan 为 0；
5. Renderer diff 符合冻结边界，Git 中没有运行数据库、Evidence、凭据、benchmark result、release、计划原件或本机缓存；
6. 本文件和两份覆盖矩阵的本地链接、需求 ID 唯一性、20 包/七波计数及关键状态词通过自动自检。

后续更新必须同时修改对应需求行的“当前代码/测试证据”和“缺口”，不得只改分类或宣传性状态。
