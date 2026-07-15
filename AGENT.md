# AgentGo 项目设计入口

> 文档状态：当前有效
> 基线日期：2026-07-13
> 项目周期：2026-06 至 2027-06

## 1. 项目定位

AgentGo 是“基于 Multi-Agent 协作的授权 Web 漏洞挖掘与验证系统”的 Windows 桌面研究原型。

系统围绕页面、接口、参数、身份、请求、响应和业务状态构建统一上下文，由多个职责清晰的 Agent 协作完成：

1. 任务规划；
2. 目标与接口整理；
3. 漏洞知识检索；
4. 安全测试策略生成；
5. 低影响主动验证；
6. 响应分析与独立复核；
7. 证据化报告和修复建议。

项目只面向教学靶场、自有系统和有明确授权的测试环境。它不是未授权公网扫描器，也不追求破坏性利用、持久化或横向移动。

## 2. 不变的核心思想

- Windows 桌面、本地优先、可安装交付。
- TypeScript 为主栈，Electron + React 提供桌面体验。
- Playwright 与 HTTP Runner 负责浏览器和协议级测试。
- SQLite + Files 保存任务状态、上下文、证据和报告。
- 所有模型访问统一经过 ModelGateway。
- 多 Agent 通过版本化结构化对象协作，不依赖无边界自然语言串话。
- 所有执行动作先经过确定性的 SecurityPolicy。
- 主动探测是核心能力，但必须低影响、可审计、可回退、有预算。
- 最终结论遵循 Signal -> Validation -> Verdict，并使用 Confirmed / Not Confirmed / Inconclusive 三态协议。
- 所有 Confirmed Finding 必须绑定可复现证据和修复建议。

## 3. V1 基线与 V2 覆盖目标

V1 是已经存在的历史基线，必须准确保留，不能因为 V2 计划扩大而改写为不存在的能力。

一期优先跑通以下四类漏洞的端到端闭环：

| 漏洞族 | V1 目标 | 默认边界 |
|---|---|---|
| SQL 注入 | 非写入式差异验证、证据归档 | 禁止 DROP、TRUNCATE、DELETE、UPDATE、INSERT、堆叠写操作 |
| XSS | 使用惰性标记和隔离浏览器确认执行上下文 | 禁止窃取 Cookie、影响真实用户或植入持久恶意内容 |
| SSRF | 仅访问受控回连端点或明确授权的测试服务 | 禁止访问云元数据、未授权内网、回环地址和越界目标 |
| 越权 / IDOR | 使用两个授权测试身份进行只读差异验证 | 禁止修改、删除或公开其他真实用户数据 |

文件上传、OAuth/JWT、业务逻辑、GraphQL 等没有进入 V1。它们在 V2 中不再被笼统归为可有可无的 Stretch Goal，而是进入版本化 Web 漏洞覆盖矩阵和后续实现波次。MCP Server 配置、连接测试和能力发现已经接入；Agent 自动调用、Kali 工具服务器和 Rust sidecar 仍是增强项，不能绕过 SecurityPolicy、Module Registry 或确定性执行链。

### V1 自动化能力的明确边界

当前自动验证器只对**授权范围内的 GET 查询参数**执行 L1 低影响验证；它会建立链接、表单和参数清单，但不会自动对 POST、PUT、PATCH、JSON Body、Header、Cookie 或路径参数发起验证。任何可能改变业务状态的请求都必须作为 L2 提案，绑定专用测试对象、清理方案和逐次人工批准。

因此，V1 已证明的是“固定本地靶场上的四类漏洞闭环”，不是对复杂 SPA、登录流程、业务工作流或任意 API 形态的完整覆盖。盲 SSRF、存储型/复杂 DOM XSS、路径/Body 型 IDOR 和复杂业务逻辑仍应保持 `Inconclusive`，直到相应的证据采集与确认规则实现并通过评测。

### V2 后端目标（Day2 扩展底座已实现，其余仍在规划）

V2 的长期目标是覆盖已知 Web 漏洞分类并可持续接入新类别，而不是把几十个名字继续追加到四值枚举。工程实现必须遵守：

- 使用稳定字符串 `familyId` 和 `techniqueId`，由可信、冻结的 DefinitionRegistry 原子注册完整 Module Bundle，再由独立 qualification record/ActivationCatalog 决定执行资格；注册本身不等于允许主动探测；
- 每个 Technique 明确 Subject、协议、Selector、环境、Capability、成熟度、Detector、ValidationPlan、ConfirmationRule、EvidenceProfile、Remediation、Knowledge 和 Benchmark；
- 成熟度只能是 `active-l1`、`active-l2`、`signal-only`、`fixture-only`、`inventory-only` 或 `forbidden`；
- 模块只能输出经过 schema 校验的候选和受限 ValidationPlan，不能持有 Runner、Repository、凭据或任意网络回调；
- Coordinator 只负责 phase、队列、checkpoint、awaiting-user 和恢复，不包含具体漏洞分支；
- 无法在真实业务中安全确认的 RCE、反序列化、协议差异、DoS 或业务逻辑场景必须保持 Signal、Fixture 或 Inconclusive，不能为追求“覆盖率”执行破坏性证明；
- “覆盖完整分类”表示每类都有可审计状态和交付路径，不表示保证发现所有未知漏洞或所有目标特有业务缺陷。

V2 的详细架构、逐类状态和实施顺序见 `docs/planning/Day0.md`、`docs/planning/backend-v2-architecture.md`、`docs/planning/web-vulnerability-coverage-matrix.md`、`docs/planning/complex-web-interface-capability-matrix.md` 与 Day1～Day20。Day1 已于 2026-07-13 按 `docs/planning/day1-baseline.md` 完成；Day2 于 2026-07-15 交付开放 ID、Capability Catalog、原子 DefinitionRegistry、registered-only Activation 视图、四类 legacy adapter 和执行门禁，证据见 `docs/audits/day2-completion-2026-07-15.md`。这不代表 Day7 qualification、Day14 通用运行时或新增漏洞检测已完成；计划文档或目录名称本身不能作为已实现、已激活或已资格化的证据。

### 当前前端边界

当前 Renderer 保持可用即可。后端计划期间原则上冻结 `apps/desktop/src/renderer/**`，不新增临时审批、会话、导入、清理或证据 View；只允许修复 contracts 兼容、编译和启动回归。新后端能力先通过 Application integration tests、fixture CLI、benchmark 和报告 JSON 验收，后端合同稳定后再统一重建前端。

## 4. Agent 与确定性服务边界

V1 的模型型 Agent：

- PlannerAgent：生成和修订任务计划。
- KnowledgeAgent：构造带来源、适用性和安全约束的 KnowledgePack。
- StrategyAgent：将上下文和知识转化为验证假设与候选测试方案。
- AnalysisAgent：比较基线与测试结果，生成 Signal。
- VerifierAgent：依据版本化确认规则给出 Verdict。

当前已存在的确定性服务：

- SecurityPolicy：授权范围、速率、并发、方法和破坏性动作硬门禁。
- BrowserRunner / HttpRunner：执行获批动作并采集证据。
- EvidenceStore：不可变证据、哈希、脱敏和来源管理。
- Reporting：模板化输出报告、复现步骤和修复建议。
- AgentRuntime：状态机、预算、重试、检查点和结构化消息路由。
- ProbeCapabilityCatalog：冻结的能力语义目录及 SecurityPolicy `riskFloor`，不授予执行资格。
- DefinitionRegistry：原子注册完整 Bundle、校验引用/模式/能力风险下界/证据角色并输出 canonical hash；第一版 Module Conformance testkit 已提供。
- RegisteredOnlyActivationCatalog / VulnerabilityExecutionGate：分离定义与激活，并在 create/start/resume/candidate 四处失败关闭；临时 legacy 例外固定到 canonical tuple、definition hash 与 `active-l1`。

V2 计划新增或重构、当前不能按已存在使用的确定性服务：

- QualificationService / 资格记录驱动的生产 ActivationCatalog / CandidateCompiler：验证测试证明、冻结版本、Subject 和正式执行资格；
- ValidationPlanExecutor / 通用 ConfirmationEngine：解释受限步骤、组织角色化 Observation，并用版本化纯规则给出三态结论；
- ExecutionGrant / Lease、原子预算、SessionVault、TestObject/L2 状态机、可信 ApprovalPort，以及受策略代理的 BrowserNetworkBroker。

模型可以提出动作，但不能自行扩大授权范围，也不能覆盖 SecurityPolicy 的拒绝结果。

## 5. 当前技术基线

- Electron + React + TypeScript + Vite
- pnpm workspace monorepo
- Playwright Core 隔离 BrowserRunner（已接入 DOM、表单、链接和惰性 XSS 标记验证）
- undici HttpRunner（已接入 DNS 固定、逐跳重定向复检和响应证据采集）
- SQLite + Drizzle ORM
- Zod 作为配置、IPC 和 Agent 输出校验层
- Vitest 作为单元和集成测试框架
- electron-builder + NSIS 作为后续 Windows 安装器

架构详情见 docs/architecture/overview.md。

## 6. 当前规范文档

- docs/project-scope.md：目标、非目标和交付边界
- docs/architecture/overview.md：总体架构和仓库结构
- docs/architecture/agent-system.md：Agent、消息协议、记忆和终止条件
- docs/architecture/data-model.md：核心数据实体和可追溯关系
- docs/security/active-probing-policy.md：低影响主动探测分级和硬性禁令
- docs/security/threat-model.md：Agentic、Electron、模型和工具威胁模型
- docs/workflows/src-hunting.md：授权 SRC 漏洞挖掘阶段门禁
- docs/knowledge/knowledge-agent.md：知识库、检索、KnowledgePack 和质量评估
- docs/evaluation/benchmark-plan.md：基准、对照实验和指标
- docs/audits/v1-current-capability-audit.md：当前实现与计划书的可验证满足度及缺口
- docs/planning/README.md：后端优先 20 个顺序工作包索引
- docs/planning/Day0.md：本轮现状复核、Day1/Day2 撤销与计划重排记录
- docs/planning/backend-v2-architecture.md：可扩展漏洞模块、ValidationPlan 和证据架构
- docs/planning/web-vulnerability-coverage-matrix.md：完整 Web 漏洞目录、当前成熟度与安全验证方式
- docs/planning/complex-web-interface-capability-matrix.md：复杂协议/接口的解析、盘点、重放和主动验证能力边界
- docs/planning/post-20-day-vulnerability-roadmap.md：20 天后的七波后端覆盖路线
- docs/roadmap.md：与大创计划对应的阶段安排
- docs/research/related-work.md：开源同类项目研究记录

根目录 AGENTS.md 是人类开发者和 AI 编程代理都必须遵守的精简工程规则。
其中“Codex 开发八荣八耻”属于 MUST 级行为准则，所有实现、调试、重构和验证任务均不得绕过。

## 7. 决策管理

文档中的要求使用以下含义：

- MUST：安全、数据和架构不变量，不能静默绕过。
- SHOULD：默认方案；偏离时必须写 ADR 并说明证据。
- MAY：可选增强，不得阻塞当前里程碑。

重大技术调整先记录到 docs/adr/，再修改实现。历史长版架构基线保存在 docs/archive/architecture-baseline-2026-04-29.md，仅供追溯。
