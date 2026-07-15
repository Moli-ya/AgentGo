# AgentGo 全 Web 漏洞扩展后端：20 个顺序工作包总览

> 复审日期：2026-07-13
> 代码基线：TypeScript + Electron + React；五 Agent、SecurityPolicy、HTTP/离线浏览器 Runner、SQLite、Evidence、Reporting、40 Case 固定靶场已经存在。
> 计划定位：DAY0 只复核与重排；Day1～Day20 先建立可扩展且非破坏的后端平台，再持续补齐漏洞模块；前端本轮只维持可用。

## 1. 为什么必须重排

现有代码能在本地固定靶场对 SQLi、XSS、SSRF、IDOR 的 GET query 场景完成 `Signal -> Validation -> Verdict -> Evidence -> Report`。但扩展到真实复杂 Web 时存在五个结构性问题：

1. `VulnerabilityFamilySchema` 是四值枚举；Prompt、Coordinator、Knowledge、Reporting、Evaluation 和 Renderer 都横向写死四类。
2. `DefaultScanCoordinator.validateCandidate()` 直接包含四类执行流程，新增 XXE、上传、JWT 或业务逻辑会继续扩大单文件和条件分支。
3. Candidate 强制绑定 endpoint/parameter，无法表达页面、DOM sink、身份关系、工作流、组件、协议通道和缓存链。
4. 当前 PolicyDecision 没有完整绑定最终 header/body bytes；复杂请求执行前必须先完成哈希、租约、预算和证据捕获硬门禁。
5. 原计划在 Day8～Day19 安排多套临时 Renderer 页面，与“后端完成后统一重建前端”的开发策略冲突。

因此本计划把 Registry、通用 Subject、ValidationPlan、Capability、角色化 Evidence 和模块一致性测试前置；四类现有能力改为兼容样板，而不是最终架构的边界。

## 2. 20 个工作包能承诺什么

Day20 工作包合格退出时的结果是：

- 后端可注册开放式 `familyId/techniqueId`，新增模块不修改 Coordinator 主流程；
- Scanner 可以表达普通 HTTP、表单、JSON、XML、multipart、GraphQL、浏览器、WebSocket、受控 OOB 和专用靶场 raw HTTP 的能力边界，即使部分 adapter 尚未实现；
- 每个主动步骤都由结构化 Capability、Scope、三阶段请求哈希、ExecutionLease、预算、EvidenceCapturePolicy 和停止条件约束；
- L2 具备 TestObject、SideEffectEnvelope、可信审批、逐步骤授权、清理与恢复状态机；
- SQLi、IDOR/BOLA、XSS、SSRF 迁为四个参考模块并覆盖复杂 selector/身份/OOB/浏览器样例；
- 至少增加一个不改 Coordinator 即可接入的低风险被动模块，用于证明扩展协议成立；
- 所有已知 Web 漏洞类别都有唯一 ID、成熟度、允许环境、所需能力、实现波次和验收定义；
- 现有桌面前端仍能 typecheck、build、启动和使用，但不承诺展示所有新后端能力。

20 个工作包不能诚实承诺“真实环境的所有 Web 漏洞都能自动挖到”。[OWASP WSTG v4.2](https://owasp.org/www-project-web-security-testing-guide/v42/) 覆盖身份、认证、授权、会话、输入验证、业务逻辑、客户端和 API 等大量领域；业务语义和新型漏洞仍会持续变化。平台对不能安全确认的类别必须输出 Signal、`Inconclusive` 或 `fixture-only`，而不是伪造 `Confirmed`。WSTG 5.0 仍是演进分支，引用必须保留版本，不能使用会漂移的 `latest` 链接作为验收基线。

## 3. 漏洞覆盖口径

分类基线采用版本化、可追踪的交叉映射：

- OWASP WSTG v4.2 stable，并记录逐步演进的 5.0 标识；
- [OWASP ASVS 5.0.0](https://owasp.org/www-project-application-security-verification-standard/)；
- [OWASP API Security Top 10 2023](https://owasp.org/API-Security/editions/2023/en/0x00-header/)；
- [OWASP Top 10 2025](https://owasp.org/Top10/2025/0x00_2025-Introduction/)；
- 项目 `src-hunter` 工作流中的授权 SRC 实战类别。

覆盖状态只能取以下值：

| 状态 | 含义 |
|---|---|
| `active-l1` | 真实授权环境可执行低影响、只读、有界主动验证。 |
| `active-l2` | 仅使用专用测试对象，逐次人工批准，完成清理和终态复核。 |
| `signal-only` | 可盘点或产生结构化疑似，但真实环境不进行高风险利用证明。 |
| `fixture-only` | 只在带证明的专用靶场/隔离协议环境主动确认。 |
| `inventory-only` | 只记录资产、组件、配置或业务前置条件。 |
| `forbidden` | 即使有普通批准也永久不能执行的动作。 |

一个 family 可同时包含不同成熟度的 technique。例如反射 XSS 的只读 marker 可以是 L1，存储 XSS 是 L2，而真实用户触发和 Cookie 外传永久禁止。漏洞名称不能直接决定探测等级，Policy 必须按实际 method、transport、payload capability、副作用、环境和对象取风险上界。

## 4. 不变的主动探测边界

- 只测试教学靶场、自有系统或书面授权范围；每次 I/O 前复核 origin、path、port、解析 IP、redirect、身份、有效期和剩余预算。
- L1 只做获得结论所需的最小只读差异、惰性 marker、受控回连和授权测试身份对照。
- POST/PUT/PATCH、上传、存储内容、状态转换和有界并发默认 L2；必须绑定专用 TestObject、SideEffectEnvelope、逐次批准、清理协议与清理回执。
- 永久拒绝 DROP/TRUNCATE、生产或未知归属数据增删改、通用/未绑定 HTTP DELETE、真实账号接管、凭据喷洒、持久化、WebShell、横向移动、云元数据访问、批量敏感数据读取、高强度 DoS 和越界访问。仅专用 cleanup capability 可对 AgentGo 创建且有所有权证明的 disposable TestObject 调用目标声明的 delete/revoke/reset；它必须精确绑定对象、同一批准并完成终态复核，且不得作为漏洞探测步骤。
- RCE/反序列化/高危上传在真实业务只能使用无命令执行的安全信号；命令执行证明仅限专用 fixture，且不得包含 shell、持久化或数据外传。
- DoS、request smuggling/desync、HTTP/2 downgrade 只允许有界、可复位、明确 attested 的专用环境；共享生产链路不主动证明。
- WAF、会话不明、异常状态变化、Evidence 不足或 cleanup 失败立即停止，输出 `Inconclusive`；不自动绕过 WAF。
- Agent 只提出候选和解释，Registry、Compiler、Policy、Executor、ConfirmationRule、EvidenceStore 和 Reporter 决定能否执行及最终 verdict。

完整行为规则继续以 [主动探测与安全执行规范](../security/active-probing-policy.md) 为准。

## 5. 目标后端主链

```text
Inventory Producers
  -> Inventory Merge / Subject Graph
  -> DetectorService
  -> CandidateCompiler
  -> ValidationPlan (受限 DSL)
  -> Proposal / Approval / ExecutionLease
  -> Protocol Adapter + EvidenceCapture
  -> ObservationSet
  -> ConfirmationEngine
  -> FindingAssembler / Report / Evaluation
```

模块不得持有 Runner、Repository 或任意网络回调；它只能输出经过 schema 校验的 Detector result、Candidate 和声明式 ValidationPlan。所有真实 I/O 都由通用 Executor 在当下重新经过 Policy。Registry 在 Composition Root 原子加载后冻结，知识导入和模型输出不能注入可执行代码。

## 6. 20 个工作包的顺序与硬依赖

| 日程 | 后端交付 | 退出门槛 |
|---|---|---|
| Day1 | Scope 快照竞态修复、事实基线、完整覆盖目录、需求追踪、Renderer 冻结 | 同毫秒/并发 Scope 顺序稳定，benchmark 连续通过；代码/测试/文档数字一致，所有类别有状态而非空承诺。 |
| Day2 | 稳定 Family/Technique ID、DefinitionRegistry、legacy descriptor adapter | `security.headers` 仅 registered-only；注册不等于主动激活；未知 family 在所有执行入口 fail closed；仅固定四类 V1 通过封闭 `legacy-v1` definition/runtime/allowlist 临时兼容门保持既有执行，状态仍为 registered/unqualified。 |
| Day3 | scan-scoped Inventory、SubjectRef、Variant/Source/Selector/Codec/Transport、opaque identity/session/test-object refs | 多来源幂等，旧库迁移，secret 不落库，扫描冻结 module snapshot。 |
| Day4 | 纯 RequestCompiler、三阶段哈希、EvidenceCapturePolicy/KeyRef | 无联网单测覆盖 header/body 与 opaque generation/ref 绑定；不前置假设 Session/TestObject 服务已实现。 |
| Day5 | ExecutionGrant/Lease、wire request 恒等复核、Runner 统一入口 | 篡改、重放、并发 claim 全部失败关闭。 |
| Day6 | 原子请求/RPM/并发/字节预算、DNS/redirect/IP 加固 | 每跳复核、预算不可超卖、危险地址 fail closed。 |
| Day7 | Evaluation core、Ground Truth v2、Suite Registry、基础 loopback fixture、Qualification record | legacy 正/负/Inconclusive/安全 Case 可版本化运行；生产只消费资格证明，不加载 fixture 代码；有效资格记录接管四类 legacy 激活后移除 Day2 临时兼容门。 |
| Day8 | TestObject、L2ActionBundle、SideEffectEnvelope、Cleanup 状态机 | 不联网也能验证顺序、过期、撤销、失败恢复。 |
| Day9 | SessionVault、私有 Cookie sink、CSRF、IdentityContext/AuthorizationMatrix | secret 不持久化，多身份/过期/恢复正确；为审批提供稳定 generation。 |
| Day10 | 可信 ActorContext、ApprovalService、首条认证 L2 fixture 闭环 | Renderer/Agent 不能伪造批准，approval 绑定 session generation，primary 不重复且完成清理。 |
| Day11 | OpenAPI JSON/YAML、HAR、Postman/GraphQL 描述的离线导入管线 | preview/commit 零网络，统一写 Inventory。 |
| Day12 | HTML/JS/source map 静态发现、AssetManifest 与 ExtractionRule | 零网络解析，来源可追溯，不猜因果，未知动态值只盘点。 |
| Day13 | Policy-mediated BrowserNetworkBroker、固定 SPA fetch/XHR 发现、producer merge/依赖图 | 浏览器无旁路出口，消费冻结 AssetManifest，未知写动作仅盘点，循环/缺值安全暂停。 |
| Day14 | 通用 ValidationPlan step runtime、模块调度、统一 RetrievalService | 多身份/OOB/L2 等计划可执行且所有步骤经 Policy。 |
| Day15 | 四类 V1 行为等价 adapter、通用 Coordinator、PhaseOutcome、CandidateAttempt、恢复 | 唯一执行真源切到通用运行时；Coordinator 不再含 family 分支，旧 40 Case 等价且恢复不重复 I/O。 |
| Day16 | SQLi 参考模块 V2 增强 | 在 Day15 同一模块上增加复杂 selector；正/负/Inconclusive 与非写入门禁通过。 |
| Day17 | IDOR/BOLA 参考模块 | 两身份只读矩阵、跨租户误报排除和停止条件通过。 |
| Day18 | XSS 参考模块 | 反射/离线 DOM/测试对象存储场景分级正确并可清理。 |
| Day19 | SSRF 参考模块 V2 增强 + `security.headers` passive qualification | 回显/OOB 关联正确；Day2 descriptor 升级为零新增请求的 qualified detector，接入不改 Coordinator。 |
| Day20 | 全量回归、Coverage/Conformance gate、外部本地 holdout、报告与桌面兼容 | 所有安全门禁为 0；build/smoke 通过；自建/外部/授权/未运行结果分栏，不夸大覆盖。 |

## 7. 前端与 IPC 边界

- 不新增 Renderer 页面，不对当前大型 `App.tsx` 继续堆临时流程；后端完成后再整体设计新前端。
- contracts 的新字段优先向后兼容；现有 `families` 保留一个兼容周期，并允许旧四类标签 fallback。
- 本轮后端验收通过 Application integration tests、fixture/benchmark CLI、Repository 测试和报告 JSON 完成，不依赖 UI 手工点击。
- Main/Preload 只在现有前端运行所必需时增加最小兼容；不提前暴露不稳定的全套新服务。
- 每次跨层变更都运行 `pnpm typecheck`；涉及 contracts/Main/Preload/Renderer 的工作包当日运行 `pnpm build` 和 `pnpm smoke:desktop`，Day20 再运行全量门禁。前端可用的定义是现有页面可启动到 renderer-ready、Preload 白名单和 IPC schema 不回退、基础流程不崩溃，不是已支持操作所有 V2 后端功能。

## 8. Day20 合格定义

以下条件必须同时满足：

1. Registry 原子校验 Family/Technique/Strategy/Rule/Evidence/Remediation 引用、版本和 Capability；未知模块或未知能力 fail closed。
2. 新增一个 passive/inventory 模块无需编辑 Coordinator、ValidationEngine 的分支、Reporting 标签表或枚举 options。
3. 每个 frozen Scan 保存 module/technique/capability 版本快照；缺少旧版本时安全暂停，不偷用新版继续。
4. 每个真实网络步骤都有 Scope 快照、Template/Resolved/Wire hash、单次 Lease、预算扣减、PolicyDecision、Evidence role 和结束状态。
5. L2 的 approval、test object、primary、post-read、cleanup、cleanup-verify 顺序可审计；cleanup 失败后普通执行为 0。
6. 四个参考模块至少各有 4 个逻辑不同正例、4 个负例、2 个 Inconclusive 和安全拒绝样例；旧 40 Case 不回退；transport × selector × identity × workflow 至少通过预先声明的 pairwise 覆盖门禁。
7. `Confirmed` 必须来自版本化纯确认规则并满足角色化 Evidence；模型、知识或 Agent 自然语言不能提升 verdict。
8. Coverage Matrix 中每个已知类别都有成熟度、环境和后续波次；未实现项没有被写成支持。
9. out-of-scope、L3、未批准 L2、明文 secret、无证据 Confirmed、Lease 重放、cleanup failed 后非恢复执行七项计数均为 0。
10. parser/compiler property/fuzz、迁移/崩溃/恢复、claimed lease、session expiry、cleanup recovery、benchmark/conformance、规则冻结后的第三方本地 holdout、`pnpm check`、`pnpm build`、`pnpm smoke:desktop` 通过；Git 中无运行数据库、Evidence、凭据、结果目录或计划书原件。

还必须有依赖边界测试禁止漏洞模块直接调用 `fetch`、`node:http`、`fs` 或 Electron；secret scan 覆盖 DB、日志、错误、报告和普通 Evidence；Registry canonical snapshot/lockfile 绑定 definition、构建产物与 commit，不能只绑定 metadata。同一结论满足确认规则后，额外探测请求数必须为 0。

任一门禁失败时该工作包不能标为完成。计划整体顺延，不通过减少测试或扩大 Scope 来换取日期。

## 9. 20 天之后

[20 天后覆盖路线](post-20-day-vulnerability-roadmap.md) 按共享能力依次实现被动姿态，身份/会话/授权，复杂 API 协议，业务状态/多租户，通用注入，文件/XML/浏览器，以及协议实验/供应链/LLM。接口级真实能力另见 [复杂 Web/API 接口能力矩阵](complex-web-interface-capability-matrix.md)。每个新 technique 必须同时交付 Manifest、Detector、ValidationPlan、ConfirmationRule、EvidenceProfile、Remediation、Knowledge、Fixture、Benchmark 和安全门禁；缺任一项只能保持 signal/inventory 状态。
