# Day 0：现状复核、撤销确认与 20 个工作包重排

> 状态：DAY0 planning-only；Day1、Day2 均为 `pending`。
> 复核日期：2026-07-13（Asia/Shanghai）
> 代码基线：`b4ac70e0626536c833d9a6da2f5d270bdbb8ffb8`
> 本日边界：只撤销提前实施内容、核查现状和完善计划；不实现 Registry、Inventory、L2、Session、Approval、Browser Broker 或漏洞模块。

## 1. 八荣八耻与执行约束

DAY0 开始前已逐条重读 `AGENTS.md` 的“Codex 开发八荣八耻”。本次复核遵循以下证据顺序：先查 contracts、类型、Composition Root、Coordinator、Runner、Policy、Repository、测试和现有文档，再写计划；未知或尚未运行的结果标为 `待验证`，不以计划中的目标接口冒充当前能力。

本日不创建产品 API、数据库迁移、依赖或运行时模块。所有文档中的 V2 名称都是目标设计，除非明确写成“V1 已实现”。

## 2. Day1 / Day2 撤销结果

用户要求撤销 Day1 和 Day2 已提前执行的工作。撤销范围及证据如下：

| 项目 | 结果 |
|---|---|
| contracts、application、runtime、db、evaluation、renderer 等源码变更 | 已撤销；`apps/**`、`packages/**` 相对上述 HEAD 无差异。 |
| 根 `package.json`、`.gitignore` 等实现性变更 | 已撤销。 |
| 临时漏洞开放 ID、迁移 baseline 脚本/fixture/test | 已删除。 |
| 忽略目录中的 `benchmark-results/day1-baseline` | 已删除；其他历史 benchmark 目录未触碰。 |
| `day1-baseline.md`、`requirements-traceability.md` 及 Day1 完成记录 | 已删除；不能再引用 20 个测试文件、75 项测试等已撤销结果。 |
| Day1、Day2 计划本身 | 保留为待执行工作包，状态均为 `pending`。 |
| DAY0 架构、覆盖和后续路线文档 | 保留并在本次复审中继续修订。 |

撤销不使用 `git reset`、`git checkout` 或覆盖式回滚，避免破坏用户已有工作。

## 3. 当前 V1 能力事实

| 区域 | 当前实际能力 | 当前边界 / 缺口 |
|---|---|---|
| 漏洞类型 | `VulnerabilityFamilySchema` 仅有 `sqli/xss/ssrf/idor`。 | Prompt、Application、DB、Knowledge、Reporting、Evaluation、Renderer 横向依赖四值枚举。未知 family 若直接开放会触发 Coordinator 末尾 IDOR 兜底风险，必须先做 fail-closed。 |
| 扫描流程 | intake、passive-recon、active-enum、hypothesis、validation、verification、report；可暂停、取消和恢复。 | passive recon 主要记录输入；active enum 仅浅层同域 GET、单身份、有限页面，不是复杂 SPA/API 发现器。 |
| 主动验证 | SQLi GET query 布尔差异；XSS 惰性 marker + 断网 HTML 重放；SSRF 回显式受控证明；IDOR 两个授权测试身份的只读对照。 | 未覆盖 form/JSON/XML/multipart、真实 OOB collector、运行期浏览器、多步骤会话、CSRF、写入型 TestObject 等复杂接口。 |
| 策略 | 检查 scope、有效期、identity、声明速率/并发，拒绝危险 method、破坏性或未知副作用。 | L2 仍依赖调用方 `userApproved: boolean`；PolicyDecision 未绑定最终 header/body/session wire bytes；预算缺少原子 reservation/claim。 |
| 执行器 | HTTP Runner 每次 redirect 重做 DNS/IP 检查，跨源移除凭据，限制 timeout/响应大小；Browser Runner 断网 `setContent`。 | Browser Runner 不能发现登录后 SPA；Policy 与最终发网字节之间仍需 Grant/Lease/哈希闭环。 |
| Evidence | 内容寻址、hash 校验、引用进入 Finding/Report。 | 当前会先保存原始 response body、DOM/screenshot，再生成脱敏派生物；缺少捕获前字段裁剪、加密/密钥生命周期、保留期与配额门禁。 |
| Knowledge Agent | 内置少量条目；导入内容先脱敏和不可信指令扫描，经 Extractor/Reviewer 后人工发布。 | 来源和知识量有限；存在两条 KnowledgePack 组装路径；导入模板被标记为不可直接执行，尚无 Registry-aware 统一检索。 |
| MCP / Model | MCP 可配置、测试连接和发现 capability；模型调用经过 model-gateway，结构化输出校验。 | MCP capability 尚不能进入受 Policy/Lease/Evidence 约束的 Agent 工具执行链。 |
| 数据库 | SQLite migration `0001`～`0004`；Repository 覆盖扫描、证据、知识、MCP、评测等。 | URL inventory 会保留 query value；缺少 V2 module snapshot、Attempt、Lease、L2、Session metadata 等迁移。 |
| 评测 | 固定本地 fixture 40 Case，四类各 5 正 5 负；有评测 manifest 和 runner。 | 同构自建 GET Case 不能证明复杂真实 Web 泛化；部分流程指标并非由真实故障注入得出。 |
| 桌面端 | Electron + React，现有 Dashboard、Target/Identity、Scan、Findings/Reports、Audit、Knowledge、MCP、Agent/Model 等入口可用。 | 缺少组件/E2E 业务测试；本轮冻结 Renderer，只验证编译、构建、启动与现有基础链不回归。 |

### 3.1 已核对的 Desktop / IPC 核心接口

以下接口来自当前 `AgentGoDesktopApi` 和 `IPC_CHANNELS`，是现有前端可以依赖的白名单边界；计划不凭空创造同名替代接口：

| 能力组 | 当前方法 |
|---|---|
| 启动与概览 | `getBootstrapState`、`runPolicySelfCheck`、`getDashboard`、`notifyRendererReady` |
| Workspace | `listWorkspaces`、`createWorkspace`、`deleteWorkspace` |
| Target / Identity | `listTargets`、`getTargetDetail`、`createTarget`、`updateTarget`、`deleteTarget`、`saveIdentity`、`deleteIdentity` |
| Scan | `listScans`、`createScan`、`controlScan`、`getScanDetail`、`onScanEvent` |
| Knowledge | `searchKnowledge`、`listKnowledgeImports`、`getKnowledgeImport`、`createKnowledgeImport`、`extractKnowledgeImport`、`updateKnowledgeCandidate`、`reviewKnowledgeImport`、`deleteKnowledgeImport` |
| Finding / Report | `listFindings`、`listReports`、`generateReport`、`exportReport` |
| Model | `listModelProfiles`、`listModelProfileUsage`、`saveModelProfile`、`deleteModelProfile`、`testModelProfile` |
| MCP | `listMcpServers`、`saveMcpServer`、`deleteMcpServer`、`testMcpServer` |
| Audit | `listAuditLogs` |

Main 对 IPC 输入先做 schema 校验，输出再由 `DesktopOutputSchemas` 校验；Preload 只暴露上述白名单，Renderer 不直接访问文件系统、SQLite、secret、Runner 或任意目标网络。表中的 `deleteWorkspace/deleteTarget/...` 是删除 AgentGo 本地管理记录的产品操作，不是允许扫描器对目标发送 HTTP DELETE。

### 3.2 已核对的内部执行接口

| 接口 / 服务 | 当前职责 | DAY0 判断 |
|---|---|---|
| `evaluateProbe` / `evaluateResolvedAddresses` | 对动作与解析地址做确定性策略判定。 | 已存在；需在 Day4～Day6 扩展为 wire hash、Lease 和原子预算闭环。 |
| `ExecutionService` | 组合 Policy decision、HTTP/Browser Runner、ToolCall 和 Evidence 保存。 | 已存在；当前原始响应捕获和 `userApproved` 信任边界需收紧。 |
| `UndiciHttpRunner.execute/cancel` | HTTP 请求、DNS 固定、redirect 逐跳复核、超时和大小限制。 | 已存在；后续只能由统一 ExecutionPort 调用。 |
| `PlaywrightBrowserRunner.execute/cancel` | 断网 HTML `setContent`、DOM/form/link 观察和惰性 XSS marker。 | 已存在；不是 Day13 规划的运行期 BrowserNetworkBroker。 |
| `DefaultScanCoordinator` | 扫描 phase、Agent 调用、枚举、四类候选验证、Finding/Report 协调。 | 已存在且过重；Day15 在 parity 证据下去 family 分支。 |
| `DefaultModelGateway` / `ModelGateway` | Profile/Prompt 查找、字段脱敏、结构化模型调用与输出 schema 校验。 | 已存在；所有未来 Agent 模型调用继续复用。 |
| `AgentGoRepository` / `EvidenceStore` | SQLite 领域持久化、Evidence 内容寻址和读取校验。 | 已存在；V2 需迁移、CapturePolicy、加密/保留期/配额。 |
| `agent-runtime` 状态函数 | 计划、phase transition、action result、修订与停滞终止。 | 已存在；不是完整 ValidationPlan step runtime。 |

这些事实同时解释了为何计划优先复用现有 Runner、Repository、ModelGateway 和状态机，而不是另造第二套执行链。

## 4. 本轮复审发现的计划问题与决定

### 4.1 注册不等于激活

Day2 只建立 `DefinitionRegistry`，允许结构正确的 descriptor/bundle 被登记为 `registered-only`。Day7 由独立 Suite/Conformance 流水线生成不可伪造的 qualification record；生产 `ActivationCatalog` 只消费资格证明，不加载 fixture 代码。必须分开记录：

- `declaredMode`：模块声明想支持的模式；
- `activationStatus`：registered / qualified / suspended / retired；
- `qualifiedEnvironments`：fixture、external-fixture、authorized-pilot 等；
- definition/build hash、suite version 和 qualification timestamp。

任何模块都不能因“注册成功”自动获得主动执行资格。

### 4.2 消除 Day4～Day10 的前向依赖

- Day3 先定义不含 secret 的 opaque `IdentityRef`、`SessionGenerationRef`、`TestObjectRef` 和 module snapshot。
- Day4、Day5 只把这些引用及其 generation/hash 绑定进 intent/grant，不假设 Vault、CSRF 或 TestObject 服务已经存在。
- Day7 只完成评测核心、legacy suite 和基础 loopback fixture；两身份、CSRF、临时对象、OOB 等复杂能力按后续工作包渐进增加。
- Day8 建立纯 L2/TestObject 状态模型，不发网。
- Day9 建立 SessionVault、Identity、CSRF 和 AuthorizationMatrix。
- Day10 建立可信审批与首条经认证的 L2 loopback fixture 闭环。

### 4.3 调整发现链顺序

- Day11：OpenAPI/HAR/Postman/GraphQL 等离线导入；
- Day12：HTML/JavaScript/source map 静态发现和冻结 AssetManifest；
- Day13：受策略代理的运行期浏览器发现、producer merge 与依赖图。

浏览器先消费已冻结资产清单，避免静态与动态生产器重复定义权威数据。

### 4.4 明确迁移只有一个执行真源

Day15 完成四类 V1 行为等价 adapter，统一切到通用运行时并删除 Coordinator family 分支。Day16～Day19 在同一批模块上增加复杂 selector、身份、浏览器、OOB 和 L2 能力；不得保留 legacy 与 V2 并行联网路径。

`security.headers` 在 Day2 仅为 descriptor-only 的结构 canary；Day19 才实现并通过资格门禁成为不新增请求的 passive detector。

### 4.5 复杂接口不能用一个“支持 API”概括

单独维护 [复杂 Web/API 接口能力矩阵](complex-web-interface-capability-matrix.md)，对每种协议分别记录 parse、inventory、replay、active validation、身份/会话、流式/OOB、fixture 和资格状态。类型“可表达”不等于 adapter“已实现”。

### 4.6 20 天是顺序工作包，不是自然日承诺

每个 Day 是一个可顺延、带硬退出条件的工作包。默认容量为 1 名主实现者 + Codex 持续辅助；单工作包预估 1～3 个有效开发日，复杂迁移和安全门禁可拆为 A/B 子包，但不能并行跨越未通过的依赖门。总日历时间应按实际测试反馈滚动估算，不能通过减少负例或放松策略追日期。

## 5. 调整后的硬依赖图

```text
DAY0 review/rollback
  -> Day1 facts + machine-readable coverage
  -> Day2 DefinitionRegistry (registered-only)
  -> Day3 Inventory + opaque refs + frozen module snapshot
  -> Day4 pure compiler + capture/key abstractions
  -> Day5 grant/lease + single execution port
  -> Day6 atomic budget + network/resource gates
  -> Day7 evaluation core + qualification records + basic fixture
  -> Day8 L2/TestObject pure state model
  -> Day9 Session/Identity/CSRF/Auth matrix
  -> Day10 trusted Approval + first authenticated L2 fixture
  -> Day11 offline interface import
  -> Day12 static HTML/JS discovery
  -> Day13 brokered browser + producer/dependency merge
  -> Day14 generic plan runtime + unified retrieval
  -> Day15 V1 parity adapters + Coordinator debranch
  -> Day16..19 reference-module V2 enrichment
  -> Day20 conformance + external holdout + desktop compatibility
```

任何上游工作包未满足“合格交付”，下游只能继续补上游证据，不能把计划状态改成 completed。

## 6. 主动探测与清理边界

保留真实漏洞发现所需的主动验证，但强制按最小影响执行：

- L1：书面授权范围内、只读、有界、惰性 marker、差异对照或受控回连；每次 I/O 重新检查 scope、解析地址、redirect、身份、预算和停止条件。
- L2：仅 AgentGo 创建且有所有权证明的 disposable TestObject；逐 bundle 可信人工批准；primary 只执行一次；必须 post-read、cleanup、cleanup-verify 并保存回执。
- 永久禁止：DROP/TRUNCATE、对生产或未知归属数据的增删改、真实账号接管、凭据喷洒、持久化、WebShell、横向移动、云元数据、批量敏感数据读取、高强度 DoS、越界访问和自动 WAF 绕过。
- 通用/未绑定 HTTP DELETE、删除真实业务对象或把 cleanup 当漏洞证明永久禁止。仅专用 `cleanup` capability 可对 AgentGo 创建的 disposable TestObject 调用目标明确声明的 delete/revoke/reset；必须精确绑定资源 ID、同一批准和 scope，不能枚举删除，执行后必须终态复核。若目标没有安全清理协议，则该 L2 technique 不激活。
- cleanup 失败立即冻结同目标/对象的普通执行，只允许受限 recovery；结论为 `Inconclusive`，不得伪造 Confirmed。

详细规则以 [主动探测与安全执行规范](../security/active-probing-policy.md) 为准。

## 7. 前端冻结与“仍可用”定义

DAY0～Day20 不重建 Renderer，不新增临时 Approval、Cleanup、Session、Import、Waiting、XSS Evidence 或 Callback 页面。只有后端兼容变更导致现有界面无法编译/启动时，才允许最小兼容修复。

“前端仍可用”至少需要以下证据：

1. Renderer/Main/Preload typecheck 通过；Renderer 不获得 Node、文件系统、数据库、secret 或执行器直连能力。
2. production build 成功，无缺失 preload、chunk 或静态资源。
3. 桌面冒烟启动到 `renderer-ready`，基础设施和安全策略自检通过，进程正常退出。
4. 现有 IPC contract 输入输出继续 schema 校验；若任何工作包修改 Main/Preload/contracts，必须当日运行 build + smoke，而非等到 Day20。
5. DAY0 不把 smoke 等同于完整业务 E2E；Target -> Scan -> Finding -> Report 的自动化 E2E 缺口继续明确记录。

## 8. Day20 的真实适用性口径

自建 fixture 只证明实现与自身 Ground Truth 一致。Day20 至少需要一个版本固定、可重置、仅本地运行的第三方 Web/API holdout；规则冻结后才能执行，并区分：

- `self-built-fixture`；
- `external-local-holdout`；
- `authorized-pilot`；
- `not-run`。

没有真实授权审批入口时，Day20 的 L2 只能标为 `fixture-qualified`。若要启用真实授权测试环境 L2，必须交付本地可信 ApprovalPort/CLI：绑定 OS 用户与短期会话，secret 交互式读取而非命令行参数，批准详情可审计；fixture 测试替身不得冒充人工批准。

## 9. DAY0 交付清单

- [x] 撤销 Day1/Day2 提前实施的源码、测试、生成物和完成声明。
- [x] 完整核查 V1 contracts、Coordinator、Policy/Runner、Evidence、DB、Knowledge、Evaluation、Desktop 与核心接口。
- [x] 复审 20 个工作包的依赖、迁移定义、安全边界、前端边界和验收口径。
- [x] 保留主动探测，同时细化 TestObject 专用 cleanup 与永久禁止动作的边界。
- [x] 补充漏洞覆盖矩阵和复杂接口能力矩阵；未实现项保持显式缺口。
- [x] 把 Day1、Day2 状态重置为 pending，并以本文件作为唯一 DAY0 执行记录。
- [x] 运行本日文档一致性、拆分后的 `pnpm check` 等价命令、`pnpm benchmark:verify`、40 Case loopback benchmark 和 `pnpm smoke:desktop`，回填实测结果。

## 10. DAY0 完成记录

- 状态：`completed`（只表示 DAY0 复核与规划完成；Day1～Day20 仍为 pending）。
- 源码状态：Day1/Day2 实现撤销后，`apps/**`、`packages/**` 与根实现文件相对 HEAD 无差异。
- 环境：Node `v24.14.0`，pnpm `10.33.2`，19 个 `*.test.ts` 文件，40 个 legacy fixture Case，数据库 migration `0001`～`0004`。
- `pnpm typecheck`：通过，14/15 workspace projects 的现有 typecheck 脚本全部完成。
- `pnpm test`：通过，19 个测试文件、72 项测试全部通过。
- `pnpm build`：通过，Main、Preload、Renderer production build 全部完成。
- `pnpm benchmark:verify`：通过，evaluation manifest/metric 的 2 项测试通过。
- `pnpm smoke:desktop`：通过，输出 `AGENTGO_SMOKE_TEST_OK`。
- `pnpm check`：提高外部命令上限后完整通过，用时约 38 秒；其中 19 个测试文件、72 项测试通过，production build 成功。此前一次 60 秒工具上限终止未形成测试失败结论。
- 40 Case 实跑：第一次在第 5 个 Case 初始化 Scan 时失败；新输出目录重跑后 40/40 通过，20 Confirmed、20 Not Confirmed，Precision/Recall/F1=1，`safetyPassed=true`。这不是可忽略的偶发输出，而是下面已确认的基线竞态。
- 未完成：Day1～Day20 均未实施；真实复杂接口、L2 产品审批和外部 holdout 均属于后续工作包。

### 10.1 DAY0 新确认的阻塞缺陷

`AgentGoRepository.getLatestScope()` 只按毫秒级 `created_at DESC` 选 Scope。benchmark 先创建空 identity scope，再立即创建含测试身份的新 scope；两条记录可能具有相同 `created_at`。失败数据库中同一 Target 的两个 Scope 时间戳均为 `1783920144304`，查询先返回了 `allowed_identity_ids=[]`，因此 `createScan()` 报“扫描身份未包含在当前授权范围快照中”；第二次运行因时序不同而全部通过。

这说明当前 40 Case 结果存在初始化 flakiness，不能只记录成功重跑。Day1 必须在建立事实基线前修复并测试 Scope 的权威顺序：采用每 Target 单调 revision 或显式 current-scope snapshot 绑定；不得用 `sleep`、随机 UUID 排序或重试掩盖竞态。迁移/回填、同毫秒双快照、并发更新和 createScan 精确 snapshot 测试通过后，才可把 benchmark baseline 标为稳定。
