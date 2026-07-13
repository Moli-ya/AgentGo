# Day 1：事实基线、完整覆盖口径与前端冻结

> 状态：`pending`。先决条件为 [DAY0](Day0.md) 已完成；此前提前实施的 Day1 内容已撤销，不得引用其完成记录。

## 当天目标

在写代码前把“当前确实有什么”“最终希望覆盖什么”“20 天内交付什么”分开记录，建立可复现基线和逐项追踪表。以后任何“已支持”声明必须能回到模块版本、测试套件和 Evidence，而不是来自计划文字。

## 已确认的代码事实

- `packages/contracts/src/workflow.ts` 只接受 `sqli/xss/ssrf/idor`；该类型横跨 Application、DB、Knowledge、Reporting、Evaluation 和 Renderer。
- `DefaultScanCoordinator` 只把 GET query 候选送入四个硬编码验证分支；主动枚举是浅层同域 GET。
- HTTP Runner 能发送 body，但现有 Coordinator 未使用；Browser Runner 是断网 `setContent`，不是 SPA 登录/运行期浏览器自动化。
- 当前固定靶场为 40 个同构 GET Case；测试文件数、用例数、构建和桌面冒烟结果必须在 Day1 执行时重新取证，不得沿用历史完成记录。
- DAY0 已复现 Scope 快照竞态：同一 Target 的创建/更新 Scope 可能具有相同毫秒 `created_at`，`getLatestScope()` 会读回旧的空 identity scope，使 40 Case 单次失败、重跑成功；该问题修复前 benchmark 不具备稳定基线资格。
- 现有前端已经能提供 Dashboard、Target、Scan、Finding、Audit、Knowledge、MCP 和 Settings；本轮不重建 Renderer。

## 必须完成的工作

1. 重读计划书、`AGENT.md`、`AGENTS.md`、architecture/security/audit 文档，以及 contracts、Coordinator、ValidationEngine、Runner、DB、Knowledge、Evaluation、Reporting 的真实实现；在 `requirements-traceability.md` 中逐项映射“已有 / 本轮 / 后续波次 / 非目标”。
2. 审核 `web-vulnerability-coverage-matrix.md`：每个 WSTG/ASVS/API Top 10 与 SRC 实战类别必须有稳定目录 ID、当前成熟度、允许环境、所需 Capability、停止条件和后续波次；不允许出现未定义的“其他漏洞”。
3. 先修复 DAY0 Scope 快照竞态：建立每 Target 单调 revision 或显式 current-scope snapshot 绑定，使 `createScan` 冻结确定的 scope ID/version；不得依赖 `sleep`、随机 UUID 次序或失败重试。提供迁移/回填以及同毫秒双快照、并发更新、旧库、createScan 精确 snapshot 的自动测试。
4. 记录仓库 commit、Node/pnpm/Electron/Playwright/SQLite 版本、测试数、40 Case fixture 版本、数据库 migration 版本和桌面冒烟结果；修正文档中过时的 71 项统计。
5. 冻结 `apps/desktop/src/renderer/**`：建立本轮变更规则，除兼容性修复外不新增 View、导航或交互；新后端先通过 contracts/Application/CLI/fixture 测试验收。
6. 定义支持声明格式：`familyId + techniqueId + moduleVersion + maturity + environment + protocol/selector + benchmarkSuite`。没有该证据链的条目不得标记 supported。
7. 为后续迁移生成只含合成数据的 V1 数据库 baseline，并保存可重建脚本、schema version 和 hash；不得提交真实用户目录或运行 Evidence。
8. 审核 `.gitignore`，确认计划书原件、数据库、凭据、Evidence、`benchmark-results/`、`release/` 和本机缓存不会进入 Git。

## 明确不做

- 不新增 payload、不访问真实业务目标、不扩宽 Scope。
- 不把 20 天计划写成“所有真实 Web 漏洞自动确认”。
- 不修改 Renderer 页面，不借“前端兼容”提前实现审批或导入 UI。

## 预计改动位置

- `docs/planning/requirements-traceability.md`；
- `docs/planning/web-vulnerability-coverage-matrix.md`；
- `docs/audits/v1-current-capability-audit.md`、`docs/roadmap.md`；
- 合成 migration fixture 及其生成/校验脚本；
- `.gitignore`（仅在发现真实遗漏时）。

## 测试与证据

```powershell
pnpm check
pnpm smoke:desktop
pnpm benchmark:verify
pnpm benchmark:run --output .\benchmark-results\day1-baseline
```

- 核对测试文件/用例数与文档一致；
- 核对 benchmark 正/负数量、三态统计与全部安全计数；
- 对相同毫秒时间源、连续 scope update/createScan 和并发 scope update 做故障注入；benchmark 在三个全新输出目录连续通过，任一运行失败都不能只靠重跑掩盖；
- 对合成 baseline 做重复生成 hash、迁移和 secret scan；
- `git status --short` 中不得出现运行数据库、Evidence、结果或凭据。

## 合格交付

- 所有需求和漏洞目录项都有唯一状态与负责人工作包；
- 四条基线命令成功，或失败有可复现证据且后续工作包暂停；
- Scope 快照选择具有明确顺序和冻结 ID/version；DAY0 的同毫秒竞态回归测试稳定通过；
- Renderer 冻结边界已写入文档，现有桌面仍可启动；
- 后续不得再用 V1 固定靶场满分推断真实 Web 准确率。
