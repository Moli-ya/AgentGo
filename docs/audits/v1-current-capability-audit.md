# V1 当前能力核查（2026-07-10）

## 结论

AgentGo 已经具备可运行的 V1 原型：在受控本地靶场中，四类漏洞可以完成 `Scope -> Signal -> Validation -> Verdict -> Evidence -> Report` 闭环；安全策略、证据链、恢复、桌面启动和固定评测均有自动验证。

这不等于已经完整满足计划书中“复杂真实 Web 业务”的所有目标。当前实现应被准确表述为**面向授权靶场与低影响 GET 查询参数验证的研究原型**，而不是通用自动化渗透测试平台。

## 已核验的证据

| 项目 | 结论 | 证据 |
|---|---|---|
| 工程骨架 | 已满足 | pnpm workspace、Electron 主/Preload/Renderer、contracts、domain、db、application、execution、reporting 等包均存在。 |
| 类型与构建 | 已通过 | `pnpm typecheck`、`pnpm build` 于 2026-07-10 通过。 |
| 单元/集成测试 | 已通过 | `pnpm test`：19 个测试文件、71 项测试通过。 |
| 桌面启动 | 已通过 | `pnpm smoke:desktop` 输出 `AGENTGO_SMOKE_TEST_OK`。 |
| 四类漏洞闭环 | 已通过固定靶场 | `pnpm benchmark:run` 运行 40 个本地正负 Case：20 Confirmed、20 Not Confirmed，Precision/Recall/F1=1，安全硬门禁为 0。 |
| 低影响安全策略 | 已实现 | Scope、路径、端口、身份、DNS、重定向、请求预算、L3 破坏性动作拒绝，以及 POST/PUT/PATCH 的 L2 人工批准边界。 |
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

## 不能据此声称的结论

- 40 Case 的满分仅证明自建固定靶场的回归闭环，不能推断真实互联网、任意框架或复杂业务系统的检测准确率。
- 计划书提出的稳定性、误报控制、KnowledgeAgent 价值和 Multi-Agent 价值，需要第三方靶场、双人人工 Ground Truth、多模型重复运行和消融实验支撑。
- 所有没有执行器、确认规则和最小证据的场景必须保持 `Inconclusive`，不能被 Agent 的自然语言推断升级为 Confirmed。

## 下一轮实现优先级

1. 为 POST/JSON/路径参数设计仅限专用测试对象的 L2 执行器、审批 UI、清理回执和安全回归测试。
2. 增加受控回连服务的日志摄取与唯一关联，支持盲 SSRF 的证据化 Inconclusive/Confirmed 判定。
3. 扩展浏览器会话、SPA/XHR 盘点和请求模板导入，但每个新执行器必须经过 SecurityPolicy。
4. 增加安全错误/时间差异 SQLi、存储型/DOM XSS、复杂 IDOR 的确认规则与正负例。
5. 完成第三方靶场、Ground Truth、消融、稳定性和成本研究，之后才将研究结论写入项目成果。
