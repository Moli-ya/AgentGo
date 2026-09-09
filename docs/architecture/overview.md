# 总体架构

## 1. 架构目标

AgentGo 采用“桌面外壳 + 本地编排引擎 + 确定性安全执行层 + Agent 推理层 + 证据与知识层”的结构。设计优先级依次为：

1. 授权边界和真实业务安全；
2. 可复现证据；
3. 完整研究闭环；
4. 桌面响应性和可恢复性；
5. 后续工具扩展能力。

## 2. 逻辑结构

```text
Electron Renderer
  | typed preload API
Electron Main
  | lifecycle / typed IPC / application services
Scan Coordinator + Agent Runtime
  | plan / state machine / budgets / checkpoints
  | DefinitionRegistry / Activation / runtime execution gate
  +--> ModelGateway --------> external model providers
  +--> KnowledgeBase -------> local index / curated sources
  +--> SecurityPolicy ------> deterministic allow/deny/approval
  +--> ExecutionPort
         | compile / policy / grant / single-use lease / evidence audit
         +--> Runner Guard --> HttpRunner / offline BrowserRunner
  +--> EvidenceStore -------> SQLite metadata + immutable redacted files
                              + protected-original ciphertext envelopes
```

Renderer 只展示数据和发起用户意图；Main 负责生命周期、双向 Schema 校验的可信 IPC 和应用服务。V1 的异步扫描编排运行在 Main 中，网络、模型和浏览器操作均可取消且受预算约束。若后续 profiling 证明 Main 中的同步存储操作影响响应性，再把协调器迁移到 Utility Process 或受控 Worker；这不是当前实现状态。

## 3. 信任边界

- 不可信：目标网页、HTTP 响应、导入知识、模型输出、MCP 输出、用户导入模板。
- 半可信：经过解析和来源标注的 KnowledgeChunk、Agent 中间产物。
- 可信控制面：SecurityPolicy、Zod schema、目标授权快照、预算和状态机。
- 可信存储面：密钥引用、审计日志、不可变证据索引。

任何不可信内容都不能直接改变 system prompt、授权范围、工具权限或安全策略。

## 4. Electron 安全基线

桌面窗口必须启用：

- contextIsolation = true；
- sandbox = true；
- nodeIntegration = false；
- 受限的 Preload 白名单；
- 严格 CSP；
- 禁止任意新窗口和非预期导航；
- IPC channel 和 payload schema 校验；
- Renderer 不直接访问数据库、文件系统、密钥和执行器。

开发模式可以加载本地 Vite 地址，生产模式只能加载打包后的本地资源。

## 5. 包职责

- apps/desktop：Electron Main、Preload、React Renderer。
- packages/contracts：跨进程和跨包共享的版本化类型。
- packages/domain：Target、Scan、Signal、Validation、Finding 等领域模型，原子 DefinitionRegistry/canonical snapshot，以及 L2 纯状态机/hash/cleanup 资格。
- packages/security-policy：授权范围和主动探测硬门禁，以及不可变 ProbeCapabilityCatalog。
- packages/agent-runtime：阶段状态机、预算、检查点和 Agent 调度。
- packages/knowledge-base：知识摄取、检索和 KnowledgePack。
- packages/model-gateway：Provider-neutral 模型接口、模型配置和脱敏。
- packages/db：Drizzle schema、迁移和仓储边界。
- packages/application：Application-owned `ExecutionPort`、RequestCompiler、
  ExecutionAuthority、Runner Guard 编排、Evidence capture/audit、crash
  recovery 与 `L2ProtocolService`；Coordinator 不能直接持有 Runner，
  L2 协议模块不得 import Runner。
- packages/browser-runner：Playwright 封装。离线 XSS replay 只执行已 claim
  的 offline lease；Day 13 另提供 `PlaywrightBrokeredBrowserRecon`，默认
  `offline: true`，只把 Broker 批准且已写入 Evidence 的响应 `route.fulfill`
  给页面。Application 的 BrowserRecon 不得直接 import 本包；Chromium
  不能直连目标，也不能保留第二套 Cookie jar。
- packages/http-runner：单跳 HTTP transport；claim 后解析 DNS，经 Guard
  授权并持久化 dispatch 后才发包，不自动跟随 redirect。
- packages/reporting：Findings、证据和修复建议的模板化输出。
- packages/evaluation：versioned technique suite、loopback fixture、`complex-v1` / 密封 local holdout runner、指标与 QualificationService；只在评测进程使用。生产 Application 不 import 本包，只加载内容寻址 QualificationRecord。项目自建 holdout 结果类是 `self-built-fixture`；只有 `benchmarks/external-rest-openapi/` 的真实第三方 target 预留可使用 `external-local-holdout`，不得把任一自建结果写成第三方产品准确率。
- packages/mcp-hub：官方 MCP SDK 封装，负责 STDIO / Streamable HTTP 连接测试和能力发现。

## 6. 依赖方向

```text
renderer -> contracts
main -> contracts + security-policy + application services
agent-runtime -> contracts + domain + model-gateway + knowledge-base
application -> contracts + domain + db + security-policy + model-gateway + mcp-hub + runners + deterministic services
runners -> contracts
infrastructure -> domain ports
domain -> no Electron / no provider SDK / no Playwright
```

禁止业务模块绕过 ModelGateway 直接调用模型。Coordinator、模块和 Renderer
只能调用 `ExecutionPort`；Runner 不能自行取得授权或绕过
ExecutionGrant/Lease/Guard。

## 7. 模型配置

桌面设置页为每个 Agent 提供图形化 Profile 配置：

- Provider；
- Base URL；
- 模型名称；
- API Key 凭据引用；
- 超时、RPM/TPM；
- Token 预算与按 Profile 持久用量；
- 连接测试；
- 推理、抽取、验证等模型 Profile。

明文 API Key 只进入操作系统凭据存储或 Electron safeStorage 封装，SQLite 只保存 credentialId。

## 8. 数据存储

- SQLite：结构化业务状态、索引、审计摘要。
- Files：脱敏请求响应、Agent 结构化输出、报告内容，以及仅由
  protected-original 后端路径创建的内容寻址 ciphertext；普通文件路径不等于
  受保护原件。
- Credential Store：API Key 和其他长期凭据。
- Browser Context：每次隔离渲染临时创建，阻断全部页面网络请求，结束后关闭，不保存持久 Profile。

普通证据使用内容哈希寻址并保存 SHA-256、来源和脱敏状态。
protected-original 后端能力要求完整的 capture context/decision 封套，
使用随机数据密钥进行 AES-256-GCM 加密，再由操作系统安全存储封装数据密钥；
磁盘只落内容寻址 ciphertext。普通 `read`、Renderer 和报告路径拒绝原件，
只允许 metadata-only redacted derivative。配额、保留期、到期 crypto-erase
和访问/到期审计由 EvidenceStore 与 migration `0010` 共同约束。

## 9. MCP 与 Kali 的定位

MCP Hub 是可替换的工具协议扩展层。桌面端现已支持本地 STDIO 和远程 Streamable HTTP Server 的配置、加密凭据引用、手动连接测试，以及 tools / resources / prompts 能力发现。新 Server 默认禁用，MCP 输出视为不可信内容。

Agent 自动调用 MCP 工具、逐次权限审批、Evidence 映射、Kali 工具服务器、SSH 维护和高自由度工具编排仍属于后续阶段。即使接入，也必须经过同一 SecurityPolicy、目标范围、人工审批和证据映射，不得获得绕过策略的特殊通道。

## 10. 技术验证状态

reviewed HTTP 与离线 Browser I/O 已接入统一 Compiler/Grant/Lease/Guard/Evidence 链。
原子预算与精确网络门禁已落地；四类 legacy 执行资格由 QualificationRecord
接管，默认临时兼容允许表已移除。protected-original 后端已补齐存储、
访问拒绝、派生、配额、保留期和审计能力。这些后端能力不改变在线执行的
capture authority：当前实际在线路径仍固定保存 hash-only 请求/结果摘要。
当前技术边界还包括：

- Electron Main/Preload/Renderer 可构建并启动；
- workspace 包能被桌面端导入；
- IPC 输入/输出 Schema 和安全窗口设置生效；
- SecurityPolicy 能允许安全主动动作并拒绝破坏性动作；
- Vitest、TypeScript 和生产构建可在 Windows 环境通过；
- Playwright Core 随 ASAR 解包后可被打包主进程加载；
- SQLite 数据层、迁移和内容寻址证据存储通过测试；
- Electron safeStorage 边界已接入，凭据文件只保存加密字节。
- HTTP redirect 每跳重新经过 policy、child grant/lease 与 DNS guard；
  跨 origin credential 降级，Runner 不自动跟随。
- claimed-but-unknown 启动恢复为 interrupted/unknown 并把 Scan 置为
  `awaiting-user`，不自动重放；没有 claimed lease 的普通中断任务恢复为
  `paused`。
- migration `0010_protected_evidence_envelopes` 建立受保护原件封套；
  完整 context/decision、原文 hash、保护计划、wrapped key、nonce、tag、
  retention 和 availability 状态均受版本化 schema 与数据库约束。
- protected-original 使用 OS-wrapped AES-256-GCM 和内容寻址 ciphertext；
  普通 Evidence `read`、Renderer、报告与导出只见元数据或
  metadata-only redacted derivative。到期先事务性擦除 wrapped key，再
  清理 ciphertext，并记录创建、拒绝访问、完整性验证和到期审计。
- 在线路径仍只持久化 capture-decision-bound hash-only 摘要。真实
  DOM/截图采集、与 Lease 的完整 provenance 绑定及其确认规则接线尚未接入；
  在此之前需要这类证据的 XSS 必须保持 Inconclusive。
- Day 13 固定 SPA fixture 上的 BrowserRecon 把 navigation/subresource/fetch
  候选交给 `executeMediatedHttp`：Grant 仍使用扫描模块已有的
  `http.reviewed-read`，不新增 catalog 成员，也不把 `browser.mediated-read`
  挂到 Grant。未知 GET 与写动作只盘点；WebSocket/SSE 为 unsupported。
- Day 14 通用 ValidationPlan 运行时与 RetrievalService 已落地。Coordinator
  的 Knowledge 组装走 RetrievalService。Day 15 起验证阶段只经
  Detector → CandidateCompiler → legacy-parity adapter →
  ValidationPlanExecutor，Coordinator 不再按漏洞族分支发请求。SQLi
  参考 bundle `sqli.legacy-v1@1.2.0` 现含三个独立 technique：
  `sqli.boolean-differential`、`sqli.error-signal` 与
  `sqli.bounded-time-differential`；联网执行仍只有同一 adapter 路径，
  每个参数只选一个 technique。时间差异仅 `attested-fixture`。
- Day 17 起 IDOR 参考 bundle `idor.legacy-v1@1.2.0` 在同一模块上增加
  `idor.v2-bola-read-differential`（计划名 `authz.bola.read-differential`），
  并预留 BFLA / BOPLA / cross-tenant / parent-child 为 signal-only。
  合格 40-case 入口仍是 `idor.two-test-identities-readonly`。无
  AuthorizationMatrix 的 BOLA 候选在 CandidateCompiler 保持 awaiting-user，
  不阻断已资格化的双身份对照。两个相似 200 长度不能 Confirmed。
- Day 18 起 XSS 参考 bundle `xss.legacy-v1@1.2.0` 在同一模块上增加
  `xss.replay-dom-offline`（计划名 `xss.dom-offline-replay`）与 L2
  `xss.stored-test-object`。合格入口仍是 `xss.reflected-inert-marker`
  （计划名 `xss.reflected-marker`）。产品 L2 禁用时存储型 Compiler
  awaiting-user。40-case 反射正例在 attested-fixture 上经离线 Browser
  replay 确认；产品路径若缺少可审阅 DOM/截图 Evidence 仍须 Inconclusive。

仍需在正式发布前完成代码签名、自定义图标、不同 Windows 版本的真实安装/升级/卸载矩阵和长期运行压测。
