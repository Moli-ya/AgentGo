# AgentGo 后端优先 20 个顺序工作包索引

本目录是基于 2026-07-13 代码实况重新审查后的执行计划。它服务于两个不同但连续的目标：

1. 20 个顺序工作包内，完成可持续扩展的 Web 漏洞检测后端底座，并将现有 SQLi、XSS、SSRF、IDOR 四类能力迁成参考模块；
2. 20 个工作包后，按覆盖路线持续补齐已知 Web 漏洞类别，而不是继续在 Coordinator 中增加分支。

“覆盖完整 Web 漏洞分类”不等于承诺在真实业务上自动确认所有漏洞。业务逻辑、协议差异、未知漏洞和高风险类别无法由固定规则穷尽；系统必须明确区分 `active-l1`、`active-l2`、`signal-only`、`fixture-only`、`inventory-only` 与 `forbidden`，不能把未执行或不安全的验证写成 `Confirmed`。

当前执行状态：DAY0 与 [Day1](Day1.md) 已于 2026-07-13 完成；Day2 已于 2026-07-15 完成并提交；Day3 已于 2026-07-18 完成，Day4～Day20 仍为 `pending`。Day1 已用单调 Scope revision、显式 current pointer、迁移/回填和并发回归消除 DAY0 的同毫秒竞态，并从最终代码连续完成三次全新 40 Case；事实与限制见 [Day1 基线](day1-baseline.md)。Day2 的逐项实现、固定兼容边界和验证证据见 [Day2 完成审计](../audits/day2-completion-2026-07-15.md)，其 `legacy-v1` 例外仍不构成 qualified/supported 声明。Day3 的统一 Inventory、不可变 Scan 模块快照、旧库迁移、数据最小化和验证证据见 [Day3 完成审计](../audits/day3-completion-2026-07-18.md)；它没有提前实现请求编译、资格化、Vault、导入或浏览器发现。

## 开工前必读

- [DAY0 复核、撤销与重排记录](Day0.md)：当前真实能力、Day1/Day2 撤销证据、依赖修正和本轮边界；
- [Day1 完成记录](Day1.md) 与 [可复现事实基线](day1-baseline.md)：Scope 修复、工具版本、测试/benchmark、合成数据库 hash、Renderer/Git 边界；
- [需求追踪](requirements-traceability.md) 与 [机器可读覆盖目录](web-vulnerability-coverage-catalog.json)：稳定需求/漏洞 ID、当前实现、环境安全上限、资格状态与主责工作包；
- [20 个工作包总览](complex-web-20-day-plan.md)：目标、边界、依赖、共同安全规则和最终验收；
- [后端 V2 架构](backend-v2-architecture.md)：Family/Technique Registry、ValidationPlan、执行与证据模型；
- [Web 漏洞覆盖矩阵](web-vulnerability-coverage-matrix.md)：当前覆盖、允许验证方式、能力缺口和实现波次；
- [复杂 Web/API 接口能力矩阵](complex-web-interface-capability-matrix.md)：逐协议区分解析、盘点、重放、主动验证、身份/会话和资格状态；
- [20 天后覆盖路线](post-20-day-vulnerability-roadmap.md)：完整漏洞目录的后续实现与验收顺序；
- [V1 当前能力核查](../audits/v1-current-capability-audit.md)：不要把现有四类 GET 靶场能力误写成复杂真实 Web 覆盖。

## 20 个顺序工作包

| 阶段 | 工作包 | 结果 |
|---|---|---|
| 分类与扩展底座 | [Day1](Day1.md) ～ [Day3](Day3.md) | 已完成：Day1 建立 Scope/事实/前端冻结，Day2 建立开放 ID、DefinitionRegistry 与执行门禁，Day3 建立统一 Inventory、opaque refs 与已封存 Scan 模块快照。 |
| 确定性执行硬门禁 | [Day4](Day4.md) ～ [Day6](Day6.md) | 请求编译、三阶段哈希、证据捕获、单次租约、原子预算和网络边界。 |
| 评测与 L2 闭环 | [Day7](Day7.md) ～ [Day10](Day10.md) | Ground Truth v2、L2 状态模型、会话/身份/CSRF、可信审批和首条可清理闭环。 |
| 真实 Web 发现与通用运行时 | [Day11](Day11.md) ～ [Day15](Day15.md) | 离线导入、静态资产发现、受策略代理的浏览器发现、ValidationPlan、V1 行为等价适配与通用 Coordinator。 |
| 参考漏洞模块与总验收 | [Day16](Day16.md) ～ [Day20](Day20.md) | 在 Day15 parity bundle 上增强 SQLi、IDOR/BOLA、XSS、SSRF 复杂场景，资格化被动扩展示例并完成全量门禁。 |

Day1～Day20 是带硬退出条件的顺序工作包，不是必须压缩到 20 个自然日的承诺。默认按 1 名主实现者与 Codex 持续协作估算，每包约需 1～3 个有效开发日；退出条件未通过时后续整体顺延。不得通过降低策略、减少负例或跳过迁移测试追赶日期。

## 前端冻结规则

本轮不重建 Renderer，也不新增 Approval、Cleanup、Session、Import、Waiting、XSS Evidence 或 Callback 页面。`apps/desktop/src/renderer/**` 原则上冻结；仅允许修复由后端兼容变更造成的编译或启动回归。新能力通过 contracts、Application integration test、fixture CLI 和 benchmark 验收。每天相关变更至少保证 `pnpm typecheck`，Day20 以及影响桌面边界的工作包运行 `pnpm build` 和 `pnpm smoke:desktop`。

## 每日完成记录

执行当天文档前，先重读 `AGENTS.md`、本总览、目标 Day、上一日完成记录以及实际类型/测试。结束时按 [完成档案规则](../audits/README.md) 新增独立 `docs/audits/dayN-completion-YYYY-MM-DD.md`，不得回写原计划正文伪装完成；档案至少包含：

```markdown
## 完成记录（执行时填写）

- 状态：completed / partial / blocked
- 日期、分支与 commit：
- 实际改动：
- Schema / migration / module / prompt / rule 版本：
- 测试命令与结果：
- 安全门禁与清理结果：
- 未完成、风险和顺延项：
- 生成物与 Git 状态：
```

只有“合格交付”全部有证据时才能填写 `completed`。记录不得包含 Cookie、Token、原始 Evidence、目标敏感数据或本机 secret。
