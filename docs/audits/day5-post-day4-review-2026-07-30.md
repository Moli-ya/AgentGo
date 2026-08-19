# Day 5 post-Day4 最终复验（2026-07-30）

## 结论

Day 5 的八项计划已在 Day 4 最终代码上完成全量回归，状态为
`completed / uncommitted`。2026-07-29 档案中的实现事实继续有效；其中的测试
数字是 Day 4 收口前历史证据，本档案提供顺序门禁所要求的当前证据。

## 原计划与复验范围

- 原计划：[Day 5：ExecutionGrant、单次 Lease 与统一 Runner Guard](../planning/Day5.md)。
- 历史完成档案：[2026-07-28/29 档案](day5-completion-2026-07-28.md)。
- 架构决策：[ADR-0006](../adr/0006-deterministic-execution-authority.md)。
- 前置 HEAD：`968fb3dfb619e7b07e0c88af15f8b584c0aad634`。
- 复验覆盖 Day 4 新增 contracts、Application、DB migration、EvidenceStore、
  desktop safe-storage composition、报告边界，以及全部 Day 5
  Grant/Lease/Guard/ExecutionPort/redirect/recovery 行为。
- 本轮未创建 Git commit，不伪造 commit 对应关系。

## 八项计划逐项验收

| 计划项 | 状态 | 当前证据与边界 |
|---|---|---|
| 1. `ExecutionGrant` | `completed` | Grant 精确绑定 scan/scope/module/technique/plan/step、三阶段 proof、capability、opaque refs、purpose、预算、有效期、PolicyDecision、固定 capture decision set 与完整性 HMAC。 |
| 2. 单次 `ExecutionLease` | `completed` | 数据库原子 claim；issued/claimed/terminal 与 delivery state 分离；过期、撤销、完成、串行或并发重放均失败关闭。 |
| 3. Runner Guard exact-wire 复核 | `completed` | 发送前只读取一次并冻结整个执行请求与 wire 对象，拒绝 accessor/sparse/额外字段，再重算 Wire HMAC 并复核 method/URL/header/body、identity/session、scope snapshot、capability、purpose、有效期和限制；避免“Guard 看见 A、transport 发送 B”的 getter 竞态。DNS 在 claim 后、dispatch 前复核。 |
| 4. redirect fresh authority | `completed` | 每跳重新编译并签发 fresh PolicyDecision/child Grant/Lease；重新 DNS guard，跨 origin 凭据降级，旧 Authorization/Cookie 残留发送前拒绝。 |
| 5. 唯一 `ExecutionPort` | `completed` | HTTP 和离线 Browser 只经 Application port；architecture test 阻断 Coordinator/Module 的 Runner 依赖与动态旁路；未实现 adapter 明确拒绝。 |
| 6. crash 无重放恢复 | `completed` | claimed-but-unknown 终结为 interrupted/unknown，Scan 进入 `awaiting-user`；恢复 Evidence 不可用也安全终结，绝不自动重发。 |
| 7. L2 bundle ref 占位 | `completed`（合同范围） | approval bundle ref 与每个单步 grant/lease 分离；Day 10 可信批准未存在时 L2 仍禁用。 |
| 8. 禁止裸 decision 执行 | `completed` | 历史 `policyDecisionId` 只保留读取兼容；实际 I/O 只能消费完整性通过且原子 claim 的 Lease。 |

## Day 4 变更后的兼容性证据

- 新增 `0010_protected_evidence_envelopes` 后，0007～0009 的已有执行表、
  trigger、恢复迁移和引用保护仍通过完整数据库回归；
- `EvidenceSummary` 收紧为受保护/非受保护判别联合后，Day 5 固定九项
  hash-only capture decisions 仍通过 Application、DB 和 40 Case 实际链；
- 在线执行没有自行创建 protected original。全新基准库
  `protected_evidence_items = 0`，避免把 Day 4 后端能力误当成 Day 5 新授权；
- `ReportService` 强制脱敏后，40 个报告仍成功生成，普通 Evidence 保存明确
  `redacted: true`；
- desktop 启动会先执行受保护原件到期 sweep，再执行持久化 Evidence orphan
  sweep；运行期间还有非重叠的周期 retention sweep，退出时等待在途清理。
  这些行为均不放宽 no-replay 恢复语义。
- 报告和扫描详情已改为严格脱敏投影；旧非脱敏报告、跨 scan、错类型/MIME、
  错 hash 或 protected original 内容引用都不能读取、导出或标记已导出。

## 最终验证

| 命令或检查 | 退出码 | 结果 |
|---|---:|---|
| `pnpm typecheck` | 0 | 14/15 workspace projects 的已有 typecheck 与 scripts typecheck 全部通过。 |
| `pnpm test` | 0 | 主套件 47 文件 / 461 项；DB baseline 2 文件 / 10 项，全部通过。 |
| Day 5 边界回归 | 0 | execution repository 19 项、authority 8 项、policy 15 项、ExecutionService V2 7 项、redirect 6 项、architecture boundary 6 项，以及 HTTP/Browser runner 15 项均包含在全量结果中；最终跨 Day4/Day5 定向回归为 8 文件 / 92 项。 |
| `pnpm build` | 0 | Electron main/preload/renderer 为 622/88/1873 modules。 |
| `pnpm smoke:desktop` | 0 | `AGENTGO_SMOKE_TEST_OK`。 |
| `pnpm benchmark:verify` | 0 | 1 文件 / 3 项通过。 |
| 全新 40 Case | 0 | 40 个 Scan 均完成；TP 15、TN 20、FP/FN 0、XSS 正例 Inconclusive 5；Precision 1、Recall 0.75、F1 0.8571428571、Evidence completeness 1。 |

全新基准数据库的关键持久化计数：

| 实体 | 数量 |
|---|---:|
| `scans` / `findings` / `reports` | 40 / 40 / 40 |
| `execution_grants` / `execution_leases` | 180 / 180 |
| `tool_calls` / `interactions` | 180 / 180 |
| `execution_capture_decisions` | 1620（每次执行固定 9 项） |
| `execution_lease_evidence` | 360 |
| `protected_evidence_items` | 0 |

安全门禁结果全部为零：

- out-of-scope request；
- destructive L3 execution；
- unapproved L2 execution；
- plaintext secret in log/report；
- Confirmed without Evidence/Rule；
- continued after cleanup failure。

生成物标识与 Day 4 终验采用同一全新 run：

- `summary.json`：
  `96c6cef2d9f515c2864716daf78d5c6b8a134a41a919bc2801f9631ec471cab3`
- `predictions.json`：
  `27ed0d00b7da5cd875a998f80a122d593c4d2d1812b62f5fab4f6d5c6afe8606`
- `report.md`：
  `0037982e7e8c204b2bc5651321230bd7cae9ac0338c3eb3d73d331092f033db3`

同一 run 位于
`benchmark-results/day4-day5-final-2026-07-30-r2`，在上述哈希、数据库
计数和 sentinel 扫描记录完成后已随全部 benchmark 中间产物删除。

## 最终清理与 Git 状态

- 清理前 normal untracked 为 351，全部属于 `.codex-*` 中间文件/目录；
  清理后 `git ls-files --others --exclude-standard` 为 0。
- build、benchmark、release、stale release 和 7 个受保护 Evidence
  测试临时目录均已删除；`apps/desktop/out`、`benchmark-results`、
  `release`、`release-stale-0.1.0` 与测试临时目录均确认不存在。
- 本地 `AGENTS.md`、archive 基线、`node_modules` 和 Git 忽略的本地
  私有文档按边界保留，不作为交付或中间产物。
- 原始 Day1～Day20 计划文件未改；正式 Day4/Day5 变更已 staged，
  未创建 commit。

## 能力边界与后续责任

- Day 5 完成不代表 Day 6 scan 级 request/RPM/concurrency/bytes 原子预算已经
  完成；当前预算仍是 grant/step 边界。
- Day 9/10 前没有 SessionVault、可信 ActorContext/ApprovalService、
  TestObject 和 cleanup，真实目标 L2 继续禁用。
- Day 18 前没有真实 DOM/截图的 Lease provenance 和 reviewer access；
  五个 XSS 正例保持 `Inconclusive` 是正确的证据约束，不是可被隐藏的失败。
- 本结论只适用于固定本地 fixture 和当前版本，不能外推为任意真实站点的检测
  准确率或新漏洞 Technique 已资格化。
