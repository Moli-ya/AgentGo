# KnowledgeAgent 与漏洞知识库

## 1. 定位

KnowledgeAgent 负责把目标上下文转换为小而可信、可引用、带安全约束的 KnowledgePack。它不是随意生成 payload 的聊天 Agent，也不是未经治理的攻击脚本仓库。

KnowledgeAgent 的价值应通过检索质量、策略适用性、误报减少和修复建议质量进行评估。

## 2. 内容类型

- 漏洞族定义和适用条件；
- 页面、接口、参数和身份信号；
- 安全 ProbeTemplate；
- ConfirmationRule；
- FalsePositivePattern；
- 修复建议和复测方法；
- CWE、OWASP、WSTG 映射；
- 官方公告和版本影响范围；
- 经脱敏的已确认案例摘要；
- 禁止动作和策略约束。

V1 首先建设 SQL 注入、XSS、SSRF、越权/IDOR 四个知识包。

## 3. 来源治理

知识来源按信任级别管理：

1. 内置规则：项目评审通过、版本化；
2. 标准与官方资料：OWASP、CWE、WSTG、厂商公告；
3. 公开研究：保留作者、URL、日期和许可证；
4. 用户导入：默认低信任，需要人工确认；
5. 在线检索：只形成候选知识，不直接修改内置确认规则。

每个 KnowledgeDoc 保存 sourceType、sourceUrl、publishedAt、ingestedAt、license、sha256、trustLevel 和 reviewStatus。

## 4. 摄取流程

```text
Acquire
  -> Parse
  -> Remove secrets and personal data
  -> Detect instruction/prompt-injection text
  -> Normalize terminology
  -> Split by vulnerability concept
  -> Tag family/tech/applicability
  -> Deduplicate and compare conflicts
  -> Human review for trusted rules
  -> Index
```

网页或文档中的命令式文本只能作为引用内容，不得进入 system prompt 或工具权限。

当前桌面实现使用两段式 Agent 摄取：IntelligenceExtractorAgent 通过 Knowledge Profile 生成 `vulnerability-intel.v1` 候选，IntelligenceReviewerAgent 通过 Verifier Profile 独立输出字段问题。两次调用均记录 Prompt 版本、模型 Profile、Token、哈希、耗时和父运行关系。候选必须人工发布后才进入 FTS5；待审核内容不会进入扫描 KnowledgePack。

固定候选至少包含 vendor、product、vulnerabilityType、CVE/CWE、affectedVersions、preconditions、affectedEndpoints、signals、confirmationRules、remediation、forbiddenActions 和字段级原文引文。HTTP 请求模板强制标记 `unsafeToExecute=true`，不代表可执行 ProbeProposal。

## 5. 检索流程

V1：

1. 根据 family、技术栈、method、content-type、参数位置、身份和信号做结构化过滤；
2. 使用 SQLite FTS5 和别名词典召回；
3. 规则加权排序；
4. 过滤过期、低信任和不适用条目；
5. 组装受 token 预算限制的 KnowledgePack。

研究实验中加入 embedding/hybrid retrieval，与纯 FTS5 做对照；向量检索不是 V1 桌面运行的前置条件。

## 6. KnowledgePack

至少包含：

```ts
interface KnowledgePack {
  query: KnowledgeQuery
  matchedTopics: string[]
  vulnerabilityFamilies: string[]
  applicability: Applicability[]
  hypotheses: HypothesisHint[]
  safeProbeTemplates: ProbeTemplateRef[]
  confirmationRules: ConfirmationRuleRef[]
  falsePositivePatterns: FalsePositivePattern[]
  remediationHints: RemediationHint[]
  policyConstraints: string[]
  sourceRefs: SourceRef[]
  freshness: string
  confidence: number
  tokenEstimate: number
}
```

每个重要结论必须能够定位到 sourceRef。推荐工具只是 capability 建议，最终执行仍由 StrategyAgent、SecurityPolicy 和 Runner 决定。

## 7. ProbeTemplate 管理

ProbeTemplate 必须结构化并包含：

- family、scenario、parameterLocation；
- probeLevel 和 sideEffect；
- requiredContext；
- templateVariables；
- expectedSignal；
- negativeControl；
- maxRequests、timeout；
- forbiddenWhen；
- cleanupPlan；
- sourceRefs 和版本。

模板不得包含生产数据写入、真实凭据获取、持久化和越界访问。任何导入模板先经过静态安全扫描和人工审核。

## 8. 四类 V1 知识包

### SQL 注入

重点描述参数类型、查询语义假设、布尔/时间/错误差异、缓存和网络抖动误报、参数化查询修复。

### XSS

区分反射、存储和 DOM 上下文，描述编码位置、浏览器执行证据、CSP 影响和输出编码修复。反射文本本身不构成 Confirmed。

### SSRF

描述 URL 解析、重定向、DNS 变化、协议限制、受控回连证据和网络出口修复。知识包必须携带禁止访问地址策略。

### 越权 / IDOR

描述身份、角色、资源归属、读写动作和业务状态，提供双身份只读对照和服务端授权修复建议。

## 9. 修复建议生成

修复建议分三层：

- Immediate Mitigation：限速、关闭危险入口、增加校验等短期措施；
- Code Fix：参数化查询、上下文编码、网络 allowlist、对象级授权等根因修复；
- Verification：开发者可执行的单元、集成和复测步骤。

建议必须结合实际 endpoint、参数、框架和证据，不得只输出通用安全口号。

## 10. 质量指标

- Recall@K：确认用知识是否进入前 K 条；
- MRR/nDCG：相关条目排序质量；
- Source Coverage：关键建议具有来源的比例；
- Freshness：过期知识比例；
- Unsafe Recommendation Rate：违反主动探测策略的建议比例，目标为 0；
- Strategy Acceptance Rate：KnowledgePack 建议被 Strategy/Verifier 采用的比例；
- False-positive Reduction：启用 KnowledgeAgent 前后的误报变化；
- Token Efficiency：每个有效知识包的 token 和延迟。

## 11. 缓存与更新

- 同一 scan/family/tech 指纹使用任务级缓存；
- source 更新后按依赖关系失效；
- 索引构建在后台运行并可取消；
- 在线更新不阻塞扫描；
- ConfirmationRule 更新后旧 Finding 保留原版本，不能被静默重解释。
