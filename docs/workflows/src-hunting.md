# 授权 SRC 漏洞挖掘工作流

## 1. 工作流目标

本流程吸收 SRC/漏洞赏金中的阶段门禁、证据纪律和优先级方法，但服务于教学靶场、自有系统和明确授权目标。默认不进行 WAF 绕过、破坏性利用、影响扩大和真实数据获取。

每个阶段都有进入条件和必须产物。未通过 checkpoint 不进入下一阶段。

## 2. Phase 0：Intake 与授权

必须确认：

- in-scope 域名、IP、端口、路径和应用；
- out-of-scope 项；
- 允许的账号、角色和测试数据；
- 禁止动作；
- 请求速率、并发、时间盒；
- 测试 Header、披露窗口和联系人；
- 是否允许 L2 动作、回连和临时对象。

产物：ScopeSnapshot、IdentityPlan、ProbeBudget。

授权缺失或含糊时只能做离线分析，不得主动发包。

## 3. Phase 1：Passive Recon

输入：

- 用户提供的文档、HAR、接口说明；
- 历史扫描和工作区知识；
- 在规则允许时使用公开、被动资料。

输出：

- 资产和技术栈假设；
- 已知入口；
- 认证方式；
- 候选风险区域；
- 信息来源和更新时间。

被动信息只能生成假设，不能直接产生 Confirmed Finding。

## 4. Phase 2：Safe Active Enumeration

在预算内进行 L1 主动探测：

- 低速页面遍历；
- 表单、链接和 JS endpoint 整理；
- 请求方法、参数来源和内容类型归纳；
- 登录前后、多身份和业务状态对照；
- 响应状态、长度、时间和关键字段基线。

输出统一资产矩阵：

```text
Page -> Endpoint -> Method -> Parameter -> Identity -> State -> Baseline
```

实现状态：V1 已自动完成低速链接/表单盘点与 GET 查询参数基线；JS 运行期 XHR、复杂 SPA 路由、浏览器登录编排以及 POST/JSON Body/路径/Header 参数目前只记录为资产信息，不能自动进入漏洞验证。需要相应执行器、确认规则和安全回归用例后，才能升级为主动验证能力。

本阶段不发送漏洞验证 payload，不做路径爆破式高频枚举。

## 5. Phase 3：Hypothesis 与知识检索

StrategyAgent 和 KnowledgeAgent 对每个候选点生成 ValidationHypothesis：

- 漏洞族；
- 触发依据；
- 参数和身份上下文；
- 适用知识条目；
- 安全验证方案；
- 预期证据和负对照；
- 误报来源；
- 预计请求、时间和风险成本。

候选优先级综合考虑：

- 潜在业务影响；
- 证据强度；
- 测试安全性；
- 验证成本；
- 当前预算；
- 是否覆盖计划书要求的 V1 漏洞族。

## 6. Phase 4：Policy-approved Validation

每个候选目标单独执行：

1. StrategyAgent 提交 ProbeProposal；
2. SecurityPolicy 校验 scope、等级、方法、内容和预算；
3. L2 动作等待人工批准；
4. Runner 执行最小验证；
5. 保存基线、测试、负对照和证据；
6. 达到停止条件立即结束；
7. 必要时执行清理并记录结果。

同一个假设连续失败或重复时，不得无限改写 payload。达到修订上限后输出 Not Confirmed 或 Inconclusive。

## 7. Phase 5：Independent Verification

VerifierAgent 依据版本化 ConfirmationRule 检查：

- 是否可重复；
- 是否有负对照；
- 是否排除了缓存、网络抖动、通用错误和权限差异；
- 证据是否来自实际执行；
- 是否发生非预期副作用；
- scope 和 policyDecision 是否有效；
- 结论是否超出证据。

输出：

- Confirmed；
- Not Confirmed；
- Inconclusive。

不允许使用“看起来像”“大概率存在”等模糊语言替代 Verdict。

## 8. Phase 6：Report 与修复建议

报告至少包含：

- 精确到页面/endpoint/参数/身份的标题；
- 授权和测试环境摘要；
- 可复现步骤；
- 请求响应和截图等证据引用；
- 影响范围，但不夸大；
- CWE/OWASP 映射；
- 根因分析；
- 短期缓解、代码修复和长期治理建议；
- 复测方法；
- Inconclusive 和已排除项目摘要。

修复建议由 KnowledgePack 提供候选内容，再结合实际证据生成，不能直接复制通用模板。

## 9. SRC 证据纪律

- 没有实际 HTTP/浏览器/回连证据，只能记录 Hypothesis。
- 一次异常响应只能形成 Signal。
- 任何截图必须能关联到请求、身份、时间和目标。
- 任何敏感数据只保存证明影响所需的最小片段并脱敏。
- 发现高影响问题后停止扩大影响，转入报告和人工复核。
- WAF 阻断默认不进入绕过流程，而是记录阻断和当前结论边界。

## 10. 失败与恢复

浏览器崩溃、模型超时、会话失效和应用退出时保存 checkpoint。恢复时必须重新校验授权、scope、会话、预算和目标状态，不能直接继续旧动作。
