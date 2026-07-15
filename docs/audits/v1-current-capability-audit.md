# V1 当前能力核查（2026-07-13）

## 结论

AgentGo 已经具备可运行的 V1 原型：在受控本地靶场中，四类漏洞可以完成 `Scope -> Signal -> Validation -> Verdict -> Evidence -> Report` 闭环；安全策略、证据链、恢复、桌面启动和固定评测均有自动验证。

这不等于已经完整满足计划书中“复杂真实 Web 业务”的所有目标。当前实现应被准确表述为**面向授权靶场与低影响 GET 查询参数验证的研究原型**，而不是通用自动化渗透测试平台。

## 已核验的证据

| 项目 | 结论 | 证据 |
|---|---|---|
| 工程骨架 | 已满足 | pnpm workspace、Electron 主/Preload/Renderer、contracts、domain、db、application、execution、reporting 等包均存在。 |
| 类型与构建 | 已通过 | 2026-07-13 Day1 `pnpm check` 退出码 0；14 个 workspace 项目与 scripts 类型检查、Main/Preload/Renderer production build 成功。 |
| 单元/集成测试 | 已通过 | Day1 最终基线：包内 19 个测试文件/78 项，scripts 2 个测试文件/10 项，总计 21 文件/88 项通过。DAY0 的 19/72 只作历史记录。 |
| 桌面启动 | 已通过 | 2026-07-13 `pnpm smoke:desktop` 输出 `AGENTGO_SMOKE_TEST_OK`。 |
| 四类漏洞闭环 | 固定 fixture 稳定回归通过 | Day1 最终代码在三个全新目录连续得到 20 Confirmed、20 Not Confirmed，Precision/Recall/F1/证据完整率=1、`safetyPassed=true`、六项安全计数全 0；仍不得外推真实 Web。 |
| 低影响安全策略 | 部分实现 | Scope、路径、端口、身份、DNS、重定向、请求预算和 L3 拒绝已存在；POST/PUT/PATCH 会被归为 L2，但当前仅有调用方 `userApproved` 布尔，没有可信 ApprovalPort/TestObject/Cleanup 闭环，因此产品环境 L2 不能视为已可用。 |
| 证据与报告 | 已实现 | 内容寻址证据、哈希、脱敏派生、三态 Findings、Markdown/JSON/HTML 报告。 |
| KnowledgeAgent | 已实现基础链路 | 四类内置知识、来源元数据、FTS5、导入、Extractor/Reviewer、人工发布；运行时始终注入启用漏洞族的已审查安全基线。 |

## 与计划书/设计目标的满足度

| 能力 | 状态 | 当前说明 |
|---|---|---|
| 多 Agent 协作 | 部分满足 | 五个角色、结构化输入输出、检查点和独立 Verifier 已实现；默认 Profile 是确定性规则，外部模型可选。尚未完成多模型重复实验与单/多 Agent 消融。 |
| 页面、接口、参数、响应统一上下文 | 部分满足 | 已保存页面、链接、表单、GET 参数、身份、请求/响应与证据；未覆盖运行期 XHR、复杂 SPA、浏览器登录和完整业务状态图。 |
| 主动漏洞验证 | 部分满足 | 四类 V1 在 GET 查询参数场景中实现低影响验证；POST、JSON、路径、Header、Cookie、上传及复杂业务流程未自动验证。 |
| SQL 注入 | 部分满足 | 已实现只读布尔差异、负对照与重复；尚未实现经评测的安全错误/时间差异策略或非查询参数覆盖。 |
| XSS | 部分满足 | 已实现反射型惰性标记与断网浏览器确认；存储型和复杂 DOM XSS 尚未实现。 |
| SSRF | 部分满足 | 已实现目标返回受控证明的验证；盲 SSRF 需要受控回连日志采集，当前应输出 Inconclusive。 |
| IDOR | 部分满足 | 已实现两个测试身份、已知资源、GET 查询参数的只读对照；路径/Body 型对象标识、层级对象和复杂权限模型尚未实现。 |
| 知识库/RAG | 部分满足 | 结构化、来源受控、人工发布和 FTS5 已完成；向量/混合检索、真实项目知识质量评估与更多漏洞族仍在后续路线图。 |
| MCP/Kali 工具 | 未纳入 V1 自动链路 | 已有配置、加密凭据、连接测试与能力发现；Agent 自动调用与 Kali Profile 按设计仍为 Stretch Goal。 |
| 成本控制 | 部分满足 | Token、RPM、TPM 和扫描 Token 上限已记录/限制；成本字段已预留，但当前应用把 Profile 成本预算保存为 0，且未持久化 Provider 返回的费用，因此尚无可用的金额统计或严格扫描费用预扣。 |

## 扩展到完整 Web 漏洞目录的结构性阻塞与已解除基线问题

| 阻塞 | 当前事实 | 影响 |
|---|---|---|
| 四值漏洞枚举 | `VulnerabilityFamilySchema` 只有 `sqli/xss/ssrf/idor`，并被 Prompt、Application、DB 类型、Knowledge、Reporting、Evaluation 和 Renderer 共同依赖。 | 新增一种漏洞需要横向修改十余处，无法形成开放模块目录。 |
| 单体 Coordinator | `validateCandidate()` 直接包含 SQLi/XSS/SSRF/IDOR 四个执行分支和专用请求顺序。 | 新增 XXE、上传、OAuth 或业务逻辑会继续复制执行、安全、证据和恢复逻辑。 |
| Candidate 假设过窄 | Candidate 必须有 endpointId/parameterId，Strategy 只选择 GET query。 | 无法自然表达页面、Header、DOM sink、身份关系、工作流、组件、缓存或协议通道。 |
| 执行绑定不足 | Policy guard 主要复核 URL/method/scope/IP，尚未把最终 header/body bytes、session generation 和测试对象完整绑定到单次租约。 | 复杂 Body/L2 请求开放前存在“批准内容与实际 wire request 不一致”的风险。 |
| 运行时预算不足 | maxRequests 在完成后计数；RPM/并发主要比较调用方声明值，没有原子滑窗/claim。 | 并发复杂 Plan 可能超卖预算，不能作为真实 Web 安全门禁。 |
| Evidence 过量捕获 | ExecutionService 当前会保存原始 HTTP response，再生成脱敏派生。 | 扩大到真实业务前必须先实施字段级 CapturePolicy 和默认最小化。 |
| 评测封闭 | 40 Case 全是 GET，Evaluation 遍历固定四类且每类要求五正五负。 | 无法表达不同 technique、protocol、Evidence role、L2 cleanup 和 fixture-only 环境。 |
| 发现与会话缺口 | 无 OpenAPI/HAR import、SPA/XHR Broker、SessionVault、CSRF、workflow dependency 和 OOB collector。 | 大量真实接口、认证状态和多步骤漏洞目前无法进入可靠验证链。 |
| Scope 快照顺序竞态（已解除） | Day1 migration `0005_monotonic_scope_revisions` 引入每 Target 单调 revision、显式 current pointer、DB 不变量与规范路径并发锁；Scan 冻结精确 ID/version。 | 同毫秒、create/update、路径别名双连接、旧库回填、跨 Target pointer、不可变 Scope、事务回滚和 Application 精确返回均有回归；详见 [Day1 基线](../planning/day1-baseline.md)。不得退回按时间/UUID 推断。 |

完整的逐类状态见 [Web 漏洞覆盖矩阵](../planning/web-vulnerability-coverage-matrix.md)。该矩阵中的 `not-started`、`signal-only`、`fixture-only` 或 `inventory-only` 都不能被解释为当前已支持。

## 不能据此声称的结论

- 40 Case 的满分仅证明自建固定靶场的回归闭环，不能推断真实互联网、任意框架或复杂业务系统的检测准确率。
- 计划书提出的稳定性、误报控制、KnowledgeAgent 价值和 Multi-Agent 价值，需要第三方靶场、双人人工 Ground Truth、多模型重复运行和消融实验支撑。
- 所有没有执行器、确认规则和最小证据的场景必须保持 `Inconclusive`，不能被 Agent 的自然语言推断升级为 Confirmed。

## 下一轮实现优先级

1. Day2 先用稳定 Family/Technique ID 和原子 DefinitionRegistry 建立开放定义面；注册不等于激活，不直接追加几十个 `else if`。
2. 按 Day3～Day6 完成统一 Inventory、RequestCompiler、三阶段 hash、EvidenceCapturePolicy、单次 ExecutionLease、原子预算和网络加固。
3. 建立 Evaluation/Qualification、TestObject、SideEffectEnvelope、可信 ApprovalService、CleanupReceipt、SessionVault、CSRF 和 AuthorizationMatrix；本轮不为这些后端服务新增临时 Renderer 页面。
4. 建立离线描述导入、静态 AssetManifest、Brokered BrowserRecon 和 workflow dependency。
5. 将 SQLi、IDOR/BOLA、XSS、SSRF 迁为参考模块，再按 [20 天后路线](../planning/post-20-day-vulnerability-roadmap.md) 补齐完整漏洞目录。
6. 完成第三方 holdout、双人 Ground Truth、消融、稳定性和成本研究，之后才将研究结论写入项目成果。

详细顺序和退出条件见 [20 天后端计划](../planning/README.md)。
