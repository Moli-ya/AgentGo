# 2026—2027 项目路线图

> 复审日期：2026-07-13

## 当前事实

AgentGo 已有可运行 V1 原型：五个结构化 Agent、不可变 Scope、SecurityPolicy、HTTP/离线 Browser Runner、SQLite、Evidence、三态 Finding、报告、暂停恢复、知识摄取与 40 Case 固定靶场均已实现。2026-07-13 DAY0 复验中，typecheck、19 文件/72 项测试、production build、benchmark manifest 校验和桌面 smoke 均通过；不得引用已撤销的 Day1 完成记录。

V1 的真实主动覆盖仍是四类 GET query 场景：SQLi 布尔差异、反射 XSS 离线 marker、目标响应回显式 SSRF proof、两个测试身份的只读 IDOR。它不是复杂真实 Web 的全覆盖平台，以下内容尚未实现：

- scan-scoped RequestVariant、多来源 Inventory、OpenAPI/HAR 导入和 SPA fetch/XHR 发现；
- SessionVault、CSRF、完整身份/授权矩阵、登录和多步骤 workflow；
- 可信 L2 审批、TestObject、SideEffectEnvelope、CleanupReceipt 和恢复；
- blind OOB、stored/复杂 DOM XSS、Body/Path IDOR、复杂 selector；
- XXE、Traversal、上传、OAuth/JWT/SAML、GraphQL/WebSocket、业务逻辑、协议/缓存和 LLM Web 等模块；
- Registry、Technique 级评测、第三方靶场、多模型重复和消融实验；
- 可用金额成本统计、正式安装生命周期、签名和结题材料。

现有 40 Case 满分只证明固定 fixture 的回归，不证明真实互联网准确率。

DAY0 同时发现固定 benchmark 的 Scope 初始化竞态：`getLatestScope()` 只按毫秒时间排序，同一毫秒的空 identity scope 与更新 scope 可能被读反。首次实跑在第 5 Case 被拒绝，新目录重跑才 40/40 通过。Day1 必须先用单调 revision 或显式 current-scope snapshot 修复并连续复跑，不能用成功重跑掩盖不稳定性。

## 路线调整原则

原路线以四类漏洞为研究核心，OAuth/JWT、上传、GraphQL 和业务逻辑放在 Stretch Goal。根据当前产品目标，这些类别不再是“可有可无”，而是进入 [Web 漏洞覆盖矩阵](planning/web-vulnerability-coverage-matrix.md) 和 [20 天后七波路线](planning/post-20-day-vulnerability-roadmap.md)。

但“进入覆盖目录”不等于对真实业务自动执行高风险验证。每项必须标记为 `active-l1`、`active-l2`、`signal-only`、`fixture-only`、`inventory-only` 或 `forbidden`。RCE、反序列化、smuggling、DoS 和支付等能力即使开发，也只能在安全允许的环境形成最小证据。

当前优先级是后端：Renderer 保持可启动、可使用即可；后端合同稳定后再统一重建前端，不在中间阶段继续向 `App.tsx` 追加临时页面。

## 近期：20 个顺序后端工作包

详细实现、测试和合格交付见 [planning/README.md](planning/README.md)。这些是顺序工作包，不是必须压缩到 20 个自然日的承诺。

| 阶段 | 工作包 | 核心结果 |
|---|---|---|
| 扩展底座 | Day1～Day3 | 事实/覆盖基线，开放 Family/Technique ID、DefinitionRegistry/资格状态、统一 Inventory、opaque refs 和 Scan 模块快照。 |
| 执行硬门禁 | Day4～Day6 | 三阶段请求 hash、EvidenceCapturePolicy、单次 Lease、原子预算、DNS/IP/redirect 加固。 |
| L2 与身份 | Day7～Day10 | Evaluation/Qualification、纯 L2 状态模型、SessionVault/CSRF/AuthorizationMatrix、可信审批与首条 fixture 闭环。 |
| 真实 Web 发现 | Day11～Day13 | 离线 API 描述导入、HTML/JS/source map 静态发现、Brokered BrowserRecon 与依赖合并。 |
| 通用运行时 | Day14～Day15 | 受限 ValidationPlan、角色化 Evidence、统一 Retrieval、四类 V1 行为等价适配和 Coordinator 去 family 分支。 |
| 参考模块 | Day16～Day19 | SQLi、IDOR/BOLA、XSS、SSRF 的复杂安全切片，以及一个无分支被动模块。 |
| 总验收 | Day20 | Registry/Module conformance、legacy/complex benchmark、第三方本地 holdout、迁移恢复、安全门禁和当前桌面 build/smoke。 |

Day20 的完成定义是“可持续扩展的后端平台 + 四个参考主动模块 + 一个扩展证明模块”，不是“所有 Web 漏洞已经完成”。

## 中期：七波漏洞模块覆盖

Day20 后按共享能力而非漏洞名称堆分支：

1. W1 被动分析与安全姿态：JS/API 发现、Headers、TLS、Cookie、CORS、错误泄漏、组件指纹；
2. W2 身份、会话与授权：JWT、OAuth/OIDC、SAML、CSRF、session、BFLA/BOPLA、多租户只读矩阵；
3. W3 复杂 API 协议：GraphQL、WebSocket、Webhook、SSE/异步任务、SOAP/WSDL、gRPC/AsyncAPI 的分级能力；
4. W4 业务状态与受限竞态：用户提供的状态机、不变量、workflow、rate limit、沙箱支付和多租户；
5. W5 通用注入：NoSQL、LDAP、XPath、SSTI、CRLF、HPP、原型污染，以及仅 fixture 的命令/代码 canary；
6. W6 文件/XML与浏览器客户端：XXE、Traversal、上传、archive、反序列化 signal/fixture、SPA/DOM/postMessage/storage；
7. W7 协议实验、组件/供应链与新型 Web：smuggling/cache/HTTP2 隔离实验、CVE 情报、LLM Web 和长期消融研究。

每个 Technique 必须在同一交付中包含 Manifest、Detector、受限 ValidationPlan、ConfirmationRule、EvidenceProfile、Remediation、Knowledge、Fixture、Benchmark、安全测试和 Coverage 更新。缺少任何关键项时只能保持 signal/inventory/fixture 状态。

## 研究评测阶段

在参考模块和主要覆盖波次稳定后再形成论文结论：

- 由两名评审者独立标注 Ground Truth 并解决分歧；
- 固定第三方教学靶场和版本，区分自建 fixture 与外部结果；
- 单 Agent/Multi-Agent、无知识/有知识、无 Verifier/有 Verifier、FTS5/Hybrid Retrieval 消融；
- 多模型、多次重复运行；
- Precision、Recall、F1、FPR、Inconclusive、请求/Token/时间成本、稳定性和恢复率；
- 每个结论保留模型、Prompt、Module、Rule、Fixture、Scope 和代码 commit 版本。

没有这些数据时，不把 Multi-Agent、KnowledgeAgent 或 Verifier 的价值写成已证实结论。

## 前端重建阶段

后端 contracts、pending user action、ValidationAttempt、Coverage、SafetyGate 和 Benchmark summary 稳定后，统一重建桌面前端。该阶段再设计：

- Dashboard、Target/Identity、Scan/Agent、Findings/Evidence、Knowledge；
- 模块/Capability/Coverage 配置；
- Review、Approval、Session、TestObject、Cleanup/Recovery；
- 导入、BrowserRecon、OOB 和工作流可视化；
- 报告、评测与安全门禁视图。

前端只调用 Application contracts，不重新实现 Policy、Detector eligibility、状态机或 Verdict。

## 产品化与结题：2027.03—2027.06

- 完成新前端与后端集成、报告导出和脱敏；
- 完成 NSIS 安装、升级、卸载保留数据矩阵与代码签名；
- 执行最终重复实验并生成图表；
- 完成使用说明、研究总结、软著材料、演示脚本和答辩材料；
- 归档代码、合成/允许公开的数据、Prompt/Module/Rule/Fixture 版本；
- 演示只使用本地靶场或明确授权环境。

## 持续增强项

以下能力不属于完整 Web 漏洞目录本身，只有在核心执行、证据和评测稳定后考虑：

- MCP 工具的自动调用、逐次授权和 Evidence 映射；
- Kali MCP Server Profile；
- Embedding/Hybrid Retrieval 的默认化；
- Rust sidecar、自动更新和代码签名基础设施。

任何增强项都不得绕过 Registry、SecurityPolicy、ExecutionLease、Evidence 或抢占安全门禁和研究评测时间。
