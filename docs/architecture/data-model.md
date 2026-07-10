# 数据模型与证据链

## 1. 核心实体

- Workspace：本地项目隔离边界。
- Target：授权目标和基础配置。
- TargetScope：允许的 origin、路径、端口、身份和时间范围。
- Identity：授权测试账号、角色和凭据引用。
- Scan：一次扫描任务及预算快照。
- Page / Endpoint / Parameter：目标表面目录。
- Interaction：一次请求、响应和业务状态变化。
- AgentRun / ModelInvocation：Agent 与模型调用记录。
- ProbeProposal / PolicyDecision / ToolCall：动作提议、策略决定和实际执行。
- Signal：值得验证的异常，不等于漏洞。
- ValidationRun：验证步骤、负对照和结构化结果。
- ConfirmationRule：版本化确认条件。
- EvidenceItem：不可变证据元数据。
- Finding：最终三态结论和修复建议。
- KnowledgeDoc / KnowledgeChunk：知识来源和检索单元。
- AuditLog：关键操作与安全事件。

## 2. 关键关系

```text
Target 1--n TargetScope
Target 1--n Identity
Target 1--n Scan
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
- scans、pages、endpoints、parameters、interactions；
- agent_runs、model_invocations；
- probe_proposals、policy_decisions、tool_calls；
- signals、validation_runs、confirmation_rules；
- evidence_items、findings、finding_evidence；
- knowledge_docs、knowledge_chunks；
- reports、audit_logs。

## 6. 数据保护

- API Key 和密码只保存 credentialId。
- Cookie、Token 和原始响应按最小必要原则保存，并设置过期和清理策略。
- 导出前必须显示将包含哪些敏感字段。
- 发送外部模型时只传完成当前任务所需的最小摘要。
- 工作区删除时提供数据库、证据、浏览器 Profile 和缓存的完整清理选项。

## 7. 可复现性

每个 Verdict 必须能够反查：

- 使用了哪个 scope 快照；
- 哪个 Agent 和 Prompt 版本提出假设；
- 哪个模型 Profile 参与；
- 哪个知识条目和来源被引用；
- SecurityPolicy 做了什么决定；
- 实际执行了什么请求；
- 保存了哪些证据；
- 哪条确认规则得出结论。
