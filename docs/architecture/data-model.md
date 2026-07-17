# 数据模型与证据链

## 1. 核心实体

- Workspace：本地项目隔离边界。
- Target：授权目标和基础配置。
- TargetScope：允许的 origin、路径、端口、身份和时间范围；每个 Target 内以不可变 `revision` 记录快照创建顺序。
- Identity：授权测试账号、角色和凭据引用。
- Scan：一次扫描任务及预算快照。
- VulnerabilityModuleManifest / DefinitionRegistrySnapshot：进程内冻结的漏洞定义、六类交叉引用和内容哈希。
- VulnerabilityTechniqueActivationView：与 Manifest 分离的只读激活视图；Day2 全部为 registered-only，资格记录由 Day7 负责。
- Page / Endpoint：按 Scan 隔离的目标表面目录；Endpoint 的身份为 `(scanId, method, canonicalRoute)`，canonical route 不含 query value 或 fragment。
- RequestVariant / RequestVariantSelector / InventorySource：同一 Endpoint 的结构化请求变体、无值 selector 与幂等来源/provenance；人工 review 与确定性 execution class 分离。
- ScanModuleSnapshot：每个 Scan 使用的 module、technique、rule、evidence profile、capability descriptor、Registry 与环境快照；集合创建后封存且不可增删改。
- IdentityRef / SessionGenerationRef / TestObjectRef：不含凭据或对象内容的 opaque 引用合同；Day3 只保存稳定 ID、generation/version、owner/scope binding 与状态摘要。
- Interaction：一次请求、响应和业务状态变化。
- AgentRun / ModelInvocation / ModelProfileUsageEvent：Agent 调用、结构化模型记录和按 Profile 的 Token 用量。
- McpServer：MCP Transport、非敏感配置、Agent 绑定、风险标签与能力发现结果；敏感值只保存凭据引用。
- ProbeProposal / PolicyDecision / ToolCall：动作提议、策略决定和实际执行。
- Signal：值得验证的异常，不等于漏洞。
- ValidationRun：验证步骤、负对照和结构化结果。
- ConfirmationRule：版本化确认条件。
- EvidenceItem：不可变证据元数据。
- Finding：最终三态结论和修复建议。
- KnowledgeDoc / KnowledgeChunk：知识来源和检索单元。
- KnowledgeImport / KnowledgeIntelligence / KnowledgeAgentRun：公开情报或 PoC 的脱敏原文、固定结构候选和双 Agent 摄取审计。
- AuditLog：关键操作与安全事件。

## 2. 关键关系

```text
Target 1--n TargetScope
Target 1--1 current TargetScope pointer
Target 1--n Identity
Target 1--n Scan
Scan 1--n Endpoint
Endpoint 1--n RequestVariant
RequestVariant 1--n RequestVariantSelector
RequestVariant 1--n InventorySource
Scan 1--n ScanModuleSnapshot
Scan 1--n AgentRun
Scan 1--n Interaction
Interaction 1--n Signal
Signal 1--n ValidationRun
ValidationRun n--n EvidenceItem
Finding n--n EvidenceItem
Finding n--1 ConfirmationRule
ProbeProposal 1--1 PolicyDecision
PolicyDecision 1--0..1 ToolCall
```

`targets.current_scope_id` 是权威当前 Scope 指针，`target_scopes.revision` 只表示该 Target 下不可变快照的单调创建顺序。数据库拒绝非正整数/重复 revision、跨 Target pointer 和 Scope 原地更新。切回内容相同的历史快照时复用原 Scope ID/revision，并只原子更新 current pointer；不得重新按 `created_at` 或 UUID 推断当前快照。`current_scope_id` 只为 Target→Scope 同事务创建保留可空中间态，读取异常空指针时必须 fail closed。`Scan.scopeSnapshotId` 在创建时冻结该指针指向的精确 Scope，后续 Target 更新不改变既有 Scan。

Day2 将 `Scan.families`、Signal 和 Finding 的 family 合同从四值枚举改为格式受限的稳定字符串 ID；SQLite 原本以 JSON/TEXT 保存这些值，因此不需要迁移，也不改写历史四类数据。contracts 不再提供默认 family，Application 在创建扫描时显式注入固定四类默认值，并在持久化前完成 Definition/runtime/Activation 门禁。DefinitionRegistry、Capability Catalog 和 registered-only Activation 视图只在可信 Composition Root 中构建。

Day3 的 migration `0006_unified_inventory_and_module_snapshots` 把既有 Endpoint/Parameter/Scan 回填到统一 Inventory 与 legacy module snapshot。新 Scan 在同一事务中写入完整 module snapshot 集合并封存；数据库触发器拒绝封存后的插入、更新、删除或解封，也拒绝未封存 Scan 进入 `queued`/`running`。Application 与 Coordinator 在开始/恢复前重新核对 snapshot hash、选中 Definition、完整 capability descriptor、Registry、环境与授权语义；历史版本缺失或 legacy 环境未知时转为 `awaiting-user`/Inconclusive，不偷用当前版本。该快照证明的是扫描语义可复核，不等于 Day7 的 qualification/support 声明。

Inventory 写入统一经过 Application `InventoryService`，repository 以 canonical identity、structure hash 和 provenance hash 原子幂等合并；跨 Scan/Endpoint/Variant/Page 引用由合同、事务和数据库触发器共同拒绝。人工 `reviewStatus` 不能修改按 method、codec、transport 与 capability 得出的 `executionClass`，非标准或尚未实现的 adapter 继续 fail closed。旧 `parameters` 表只作为兼容输入保留，不再是新发现链路的事实真源。

## 3. EvidenceItem

每条证据至少包含：

- id、workspaceId、scanId；
- type 和 MIME；
- source、createdAt、createdBy；
- filePath 或受控对象引用；
- sha256、size；
- redactionState；
- request/response/interaction 引用；
- policyDecisionId；
- captureTool 和版本；
- retentionUntil；
- integrityStatus。

证据文件默认不可覆盖。脱敏版本创建新 EvidenceItem，并通过 derivedFrom 指向原始证据。

## 4. Signal、Validation 与 Finding

Signal 保存：

- family、endpointId、parameterId、identityId；
- observedDifference；
- hypothesis；
- confidenceHint；
- evidenceRefs；
- status。

ValidationRun 保存：

- confirmationRuleId 和版本；
- probeProposalId、policyDecisionId、toolCallId；
- baseline、test、negativeControl；
- completedChecks、failedChecks、missingChecks；
- cleanupStatus；
- result。

Finding 保存：

- title、family、CWE/OWASP 映射；
- affected endpoint、parameter、identity 和资源；
- verdict；
- severity 与置信度；
- evidenceRefs；
- reproducibility；
- remediation；
- confirmationRuleId/version；
- prompt/model/tool versions；
- firstSeenAt、lastVerifiedAt。

status 用于生命周期，例如 draft/reviewed/exported；verdict 只使用 Confirmed、NotConfirmed、Inconclusive，避免语义重复。

## 5. 必需表

V1 Drizzle schema 至少覆盖：

- workspaces、targets、target_scopes、identities；
- scans、pages、endpoints、parameters、request_variants、request_variant_selectors、inventory_sources、scan_module_snapshots、interactions；
- agent_runs、model_invocations；
- model_profile_usage_events、mcp_servers；
- probe_proposals、policy_decisions、tool_calls；
- signals、validation_runs、confirmation_rules；
- evidence_items、findings、finding_evidence；
- knowledge_docs、knowledge_chunks、knowledge_imports、knowledge_intelligence、knowledge_agent_runs；
- reports、audit_logs。

## 6. 数据保护

- API Key、MCP Token、MCP 环境变量和自定义请求头只保存 credentialId；SQLite 只记录非敏感字段名。
- Target seed 只接受无 userinfo/fragment/credential-shaped 结构的 HTTP(S) URL，合同允许的 benign query 保留其请求语义；旧库危险或非法 seed 迁移到专用的 `legacy-target-review.invalid/reconfigure/` 待重配地址，不能静默代表原目标，后续按常规 Scope 校验失败关闭。Page/Endpoint canonical identity 不含 query value，preview 与旧库迁移对 URL、页面标题、敏感 query/header/cookie/body 字段、高熵 token 与 sentinel 做确定性脱敏。原始 wire URL 只在执行调用期间瞬时使用；PolicyDecision、ToolCall、请求/响应摘要、错误摘要和脱敏 Evidence 派生中的 URL 与敏感元数据保存脱敏表示。V1 仍可能先保存完整响应 body 为不可变 `original` Evidence，再生成文本脱敏派生；捕获前最小化与 CapturePolicy 由 Day4 收口。
- RequestVariant 只保存 body shape、允许 header 名、selector 结构与值类型；opaque refs 不保存 Cookie、Authorization、CSRF、Token、密码或真实 TestObject 内容。
- 知识导入原文在入库前脱敏；HTTP 请求只保存为 `unsafeToExecute=true` 的惰性模板，凭据值替换为占位符。
- Cookie、Token 和原始响应按最小必要原则保存，文本证据生成独立脱敏派生；`retentionUntil` 已保留在模型中，自动生命周期清理仍需后续实现。
- V1 桌面只允许生成和导出脱敏报告，并在报告列表明确标注脱敏状态；未来若开放原始报告导出，必须先增加敏感字段清单和逐项确认。
- 发送外部模型时只传完成当前任务所需的最小摘要。
- Target/Workspace 删除会级联清理数据库、未被其他记录引用的证据文件和测试身份凭据；运行中扫描必须先暂停或取消。

## 7. 可复现性

每个 Verdict 必须能够反查：

- 使用了哪个 scope 快照；
- 使用了哪组已封存的 module/technique/Definition/Capability/Registry/环境快照；
- 哪个 Agent 和 Prompt 版本提出假设；
- 哪个模型 Profile 参与；
- 哪个知识条目和来源被引用；
- SecurityPolicy 做了什么决定；
- 实际执行了什么请求；
- 保存了哪些证据；
- 哪条确认规则得出结论。
