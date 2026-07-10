# 研究评测与基准计划

## 1. 目的

评测必须回答“Multi-Agent、KnowledgeAgent、主动验证和 Verifier 是否真的带来价值”，而不只是证明应用能够启动。

## 2. 固定测试环境

优先使用本地、可重置、版本固定的授权环境，例如：

- DVWA；
- OWASP Juice Shop；
- WebGoat；
- OWASP crAPI；
- 经过筛选的 Vulhub 场景；
- 项目组自建的最小正例/负例应用。

每个环境记录镜像或 commit、初始化数据、测试账号、已知漏洞、预期安全行为和重置脚本。不得把随机公网目标作为 Ground Truth。

## 3. 样例规模

V1 最低计划：

- 四个漏洞族；
- 每个漏洞族至少 5 个正例；
- 每个漏洞族至少 5 个负例或高相似误报场景；
- 合计不少于 40 个带标签场景；
- 对关键场景重复运行，观察稳定性。

样例不足时必须明确报告覆盖边界，不能用一次演示代替统计结果。

## 4. Ground Truth

每个 Case 保存：

- caseId、targetVersion、family；
- endpoint、parameter、identity 和初始状态；
- expectedVerdict；
- confirmationRule；
- requiredEvidence；
- resetProcedure；
- forbiddenActions；
- 来源和许可证；
- 人工复核人。

Ground Truth 与系统运行输出分开保存，避免 Agent 直接读取答案。

## 5. 对照与消融

至少比较：

1. 规则/固定流程基线；
2. 单 Agent，无知识库；
3. Multi-Agent，无 KnowledgeAgent；
4. Multi-Agent + KnowledgeAgent；
5. Multi-Agent + KnowledgeAgent + Verifier；
6. FTS5 与 Hybrid Retrieval 对照；
7. 有无统一上下文/检查点的稳定性对照。

使用相同目标初始状态、预算和模型配置。模型参数、Prompt 版本和随机性设置必须记录。

## 6. 检测指标

- TP、FP、TN、FN；
- Precision；
- Recall；
- F1；
- False Positive Rate；
- Inconclusive Rate；
- 每个漏洞族单独指标和整体宏平均；
- Confirmed Finding 的证据完整率；
- 修复建议人工评分。

Inconclusive 单独报告，不应为了提高 Recall 强行归入 Confirmed。

## 7. 过程与效率指标

- 任务完成率；
- 平均和 P95 执行时间；
- 请求数、重复请求率；
- 计划修订次数和循环中止次数；
- Prompt/Completion Token；
- 单 Case 费用；
- 检索延迟和 KnowledgePack 大小；
- 崩溃恢复成功率；
- 相同 Case 多次运行的 Verdict 一致性。

## 8. 安全指标

以下为硬门禁：

- out-of-scope 请求数 = 0；
- L3 破坏性动作执行数 = 0；
- 未批准 L2 动作执行数 = 0；
- 明文密钥进入日志/报告数 = 0；
- Confirmed 但无 Evidence/Rule 的数量 = 0；
- 清理失败后继续执行的数量 = 0。

任何硬门禁失败都优先于检测效果，版本不得进入演示或发布。

## 9. KnowledgeAgent 指标

- Recall@5、Recall@10；
- MRR 或 nDCG；
- 来源覆盖率；
- 过期知识比例；
- Unsafe Recommendation Rate；
- 无关知识 token 占比；
- 启用知识库前后的 Precision、请求数和成本变化。

## 10. 实验协议

1. 重置目标和数据库；
2. 固定 scope、身份和预算；
3. 记录 Provider、模型、Prompt 和规则版本；
4. 执行任务并保存完整审计；
5. 自动计算初始指标；
6. 两名成员抽样复核证据；
7. 对争议 Case 标记并更新 Ground Truth 版本；
8. 输出机器可读 JSON 和可读 Markdown 报告。

## 11. 阶段目标

- 2026-08-31 前完成第一版基准并测得基线，不预先编造检测阈值。
- 基线完成后冻结阶段性 Precision/Recall/F1 目标。
- 2027-02 前完成四类漏洞的对照和主要消融。
- 2027-05 前完成最终重复实验、误报分析和结题图表。

## 12. 验收

一期验收至少证明：

- 四类 V1 漏洞都能完成端到端流程；
- Multi-Agent 的作用能够通过任务完成率或稳定性数据解释；
- Verifier 对误报控制有可量化结果；
- KnowledgeAgent 的检索质量和策略贡献可量化；
- 主动探测形成了比被动分析更强的证据，同时未触发安全硬门禁。
