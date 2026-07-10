# AgentGo V1 固定靶场基准

`v1-ground-truth.json` 定义 40 个固定标签 Case：SQLi、XSS、SSRF、IDOR 各 5 个正例和 5 个负例。每个 Case 包含稳定 ID、目标版本、端点、参数、身份计划、预期结论、确认规则、所需证据、重置方式、禁止动作、来源、许可证和人工复核占位。

Ground Truth 必须与扫描输入和模型上下文隔离。运行器只在任务结束后读取预期标签计分，不能把答案传给 Agent。

## 校验 manifest 和指标

```powershell
pnpm benchmark:verify
```

该命令只执行 manifest/指标单元测试，不启动扫描。

## 启动靶场

```powershell
pnpm benchmark:fixture
```

固定靶场版本为 `agentgo-local-fixture/1.0.0`，只监听 `127.0.0.1`。此命令适合人工检查；完整运行器会自动启动和关闭自己的靶场实例。

## 运行 40 Case

```powershell
pnpm benchmark:run --output .\benchmark-results\my-run
```

每个 Case 使用独立 Target、不可变 Scope、身份和 Scan。运行目录包含：

- `predictions.json`：逐 Case 结论、证据引用和效率数据；
- `summary.json`：版本元数据、总体/分族指标和安全门禁；
- `report.md`：可读汇总；
- `data/agentgo.sqlite`：完整运行状态和审计；
- `artifacts/`：内容寻址证据和报告。

目录默认位于被 Git 忽略的 `benchmark-results/`。如需把某次结果作为研究材料入库，必须先人工检查隐私、来源、许可证和可复现信息。

## 当前回归基线

2026-07-10 使用本地确定性 Profile 对固定靶场重跑：

- 40/40 Case 有结论；
- 20 个正例均 Confirmed，20 个负例均 Not Confirmed；
- Precision、Recall、F1、证据完整率均为 1；
- FPR 和 Inconclusive Rate 均为 0；
- out-of-scope、L3、未批准 L2、明文密钥、无证据/规则 Confirmed、清理失败后继续执行均为 0。

该结果是同一项目自建靶场上的确定性回归基线，不能代表真实公网或复杂业务系统上的泛化能力。Ground Truth 的双人人工复核、第三方固定靶场、重复稳定性、真实外部模型和消融实验仍是后续研究任务。
