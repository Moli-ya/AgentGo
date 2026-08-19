# Day 5 完成档案（实现 2026-07-28，终验 2026-07-29）

> 后续状态：Day4 最终变更后的当前验证、边界与清理事实见
> [2026-07-30 post-Day4 最终复验](day5-post-day4-review-2026-07-30.md)。
> 下文保留变更前历史工作树与测试数字，不作为当前门禁结果。

## 原计划与范围

- 原计划：[Day 5：ExecutionGrant、单次 Lease 与统一 Runner Guard](../planning/Day5.md)。
- 架构决策：[ADR-0006](../adr/0006-deterministic-execution-authority.md)。
- 前置代码基线 HEAD：
  `968fb3dfb619e7b07e0c88af15f8b584c0aad634`。
- 当前 Git：`completed / uncommitted`；用户未要求创建提交。保留既有
  `.codex-*` 文件，不将其删除、覆盖或计入交付。
- 本次范围：统一 ExecutionAuthority/ExecutionPort、实际 HTTP/离线
  Browser dispatch、单次 Lease、fresh redirect authority、审计证据绑定、
  claimed-but-unknown 无重放恢复、持久化 Evidence GC 和数据库前进迁移。
- 明确非目标：Day6 全局原子预算、Day9 SessionVault、Day10 可信 Approval、
  L2 TestObject/Cleanup、protected-original 和新增漏洞资格。

> 状态：`completed / uncommitted`。2026-07-29 已从最终工作树完成
> typecheck、全量测试、production build、desktop smoke、benchmark
> manifest 校验和全新 40 Case 基准；未因用户未要求提交而伪造 commit。

## 逐项完成情况

| 原计划项 | 状态 | 代码/文档证据 | 事实说明 |
|---|---|---|---|
| 1. `ExecutionGrant` | `completed` | `packages/contracts/src/execution.ts`、`execution-authority.ts` | Grant 绑定 scan/scope/module/technique/plan/step、三阶段 proof、capability、opaque refs、purpose、预算、有效期、PolicyDecision、capture decision set 及 integrity HMAC。 |
| 2. 单次 `ExecutionLease` | `completed` | DB execution repository、migration 0007、authority/policy tests | 原子 claim；issued/claimed/terminal 状态与 delivery 状态分离；串行/并发重放失败关闭。 |
| 3. Runner Guard exact-wire 复核 | `completed` | `execution-policy.ts`、request hash key provider、HTTP/Browser runner tests | 发送前重算 wire HMAC，并复核 method/URL/header/body、refs、scope、capability、purpose、有效期和单步限制；DNS 在 claim 后、dispatch 前验证。 |
| 4. redirect fresh authority | `completed` | ExecutionService V2 redirect integration tests | Runner 不自动跟随；每跳重新编译、fresh PolicyDecision、child Grant、Lease 与 DNS guard；跨 origin 自动 `omit` credential，残留 Authorization/Cookie 等凭据头发送前拒绝。 |
| 5. 唯一 `ExecutionPort` | `completed` | `execution-port.ts`、Coordinator、desktop composition root、architecture test | HTTP 与离线 Browser 通过同一 Application port；Coordinator/Module 直接 Runner import 被架构门禁阻断；未知 adapter 明确拒绝。 |
| 6. crash 无重放恢复 | `completed` | Application recovery、execution repository、migrations 0008/0009 | claimed-but-unknown 终结为 interrupted/unknown，相关 Scan 进入 `awaiting-user` 并记录 checkpoint/event；恢复 Evidence 失败也能安全终结；不自动重放。普通 queued/running 中断且没有 claimed lease 时仍恢复为 `paused`。 |
| 7. L2 bundle ref 占位 | `completed`（合同范围） | execution contracts/grant schema | approval bundle 与单步 lease 分离；没有可信 Approval/TestObject 服务时不能执行 L2。 |
| 8. 禁止裸 decision 执行 | `completed` | ExecutionService/Guard/Runner 接口与架构测试 | 历史 decision ID 可读；实际 Runner 只消费由 Grant 派生并原子 claim 的 Lease，调用方不能用裸 decision 直接执行。 |

## 数据库迁移

| Migration | 作用 |
|---|---|
| `0007_execution_grants_and_leases` | 建立 grants、capture decisions、leases、lease-evidence、Interaction/ToolCall 绑定、exact-wire 与状态触发器。 |
| `0008_execution_recovery_without_artifact` | 以前进迁移允许 interrupted 恢复在 Evidence 不可用时仍安全终结，避免 claimed lease 永久悬挂。 |
| `0009_execution_dispatch_revalidation` | 为既有 0007 数据库补装 dispatch-time identity/scope/capability/budget 重校验。 |

旧 migration 不回写；升级库必须验证已知 trigger 形态后才做精确替换，未知
形态失败关闭。

## 实际 dispatch、redirect 与 Evidence

桌面 Composition Root 创建真实 HTTP Runner 和离线 Browser Runner，并只把
统一 `ExecutionPort` 交给 Coordinator。HTTP 单跳顺序为：

```text
compile
  -> fresh PolicyDecision
  -> Grant + issued Lease
  -> atomic claim + exact-wire Guard
  -> DNS guard
  -> markDispatched
  -> one transport request
  -> markResponseStarted
  -> hash-only Evidence + Interaction audit
  -> terminal Lease
```

Redirect 响应不会由 Runner 自动跟随。Application 先终结当前 hop，再对
reviewed target 重新执行上述链路。scope 外、private/metadata DNS 结果和
跨 origin 残留旧 Authorization 均在下一跳 transport send 前失败关闭。

在线 Evidence 只保存 CapturePolicy 授权的请求/结果 hash-only 摘要，并以
capture decision、Lease、Interaction 和 ToolCall 关联。普通持久化边界
不包含 secret 原文。`protected-original` 仍 unsupported，因此 Day4
总状态保持 partial。

XSS 需要特别限制：当前没有可审阅 DOM/截图 Evidence；即使离线 marker
执行，确定性规则也只能给出 `Inconclusive`，不能 Confirmed。

## 恢复语义

- `not-dispatched`、`possibly-sent`、`response-started` 是持久化 delivery
  事实，不靠内存推断。
- 启动发现 claimed lease 时，不尝试自动重发；它被终结为
  `interrupted / unknown`。
- 若 capture authority 可用，恢复写 hash-only interruption summary；
  EvidenceStore 或 target lookup 不可用时走 0008 允许的无 artifact
  安全终结。
- 相关 Scan 回到 `awaiting-user`，保存 checkpoint 和 warning event，由人工决定
  后续处理。Day5 不创建“自动 retry”授权。
- 恢复证据与租约终结在数据库侧原子绑定；第二次 crash 会复用已终结事实，
  不产生新的执行或悬空证据。
- 启动时只扫描严格内容寻址路径；未知文件、符号链接、junction 和非普通文件
  不会被跟随或删除。跨 EvidenceStore 实例的保存、读取、清理和工作区删除
  共享串行化边界，并以 `BEGIN IMMEDIATE` 保护数据库/文件引用判断。
- 仅在完整引用图确认未被 Lease、Finding、Interaction、Report、Signal、
  AgentRun、Validation、Inventory 或 ConfirmationRule 引用时，才允许删除
  staged Evidence；JSON 引用不可解析时失败关闭。

## 验证证据

| 命令或检查 | 退出码 | 结果 |
|---|---|---|
| Evidence policy / ExecutionService 定向回归 | 0 | 3 文件 / 41 项通过；包含 6 个 redirect 边界 case、生产 definition ID 与 JSON Pointer secret 负例。 |
| `pnpm typecheck` | 0 | 14/15 workspace projects 的现有 typecheck 与 scripts typecheck 全部通过。 |
| `pnpm test` | 0 | 主套件 42 文件 / 430 项通过；DB baseline 套件 2 文件 / 10 项通过。 |
| architecture boundary test | 0 | 全量测试内 1 文件 / 6 项通过；扫描 TS/JS 变体、动态 import/require 与 package dependency，Coordinator/Module 无 Runner 旁路。 |
| `pnpm build` | 0 | Electron main/preload/renderer 分别转换 619/88/1873 个模块并完成 production build。 |
| `pnpm smoke:desktop` | 0 | 输出 `AGENTGO_SMOKE_TEST_OK`。 |
| `pnpm benchmark:verify` | 0 | evaluation manifest/metrics 1 文件 / 3 项通过。 |
| 全新 40 Case：`day5-final-2026-07-29-r4` | 0 | 40 个 Scan 均 `completed/report`；TP 15、TN 20、FP 0、FN 0、XSS 正例 Inconclusive 5；Precision 1、Recall 0.75、F1 0.8571428571、Evidence completeness 1。180 个 Grant/Lease/ToolCall/Interaction 全部成功，360 个 lease-evidence 绑定完整，六项 safety counter 均为 0。 |
| `git diff --check` / Renderer / secret 边界 | 0 | 无 whitespace error；Renderer 功能代码相对前置 HEAD 无差异；最终基准目录未命中测试身份明文或 Day4/Day5 sentinel，且 benchmark 自检 `plaintextSecretsInLogsOrReports=0`。 |

### 首轮失败、根因与修复

2026-07-29 首次全新目录
`benchmark-results/day5-final-2026-07-29` 虽然进程退出 0 且安全计数为 0，
但 40 个 Scan 全部在首个 HTTP 响应后的 Evidence capture 阶段失败，结果为
40 个 Inconclusive、Precision/Recall/F1 均为 0。该失败没有被成功重跑覆盖。

数据库事件链显示策略已允许、响应已开始，但租约以
`execution.audit-persistence-failed` 终结。受控复现进一步确认：
`EvidenceCapturePolicy` 对已通过稳定 ID schema、来自密封模块定义的
`sqli.boolean-differential` 和 `inventory.target-base.read` 又执行了通用
高熵 secret 启发式，因此错误拒绝自身签发的 capture decision。

修复后，严格 decision/context/schema/有效期绑定保持不变，JSON Pointer
仍执行敏感片段拦截，capture-policy label 与 Evidence role 也继续受原门禁；
只有密封 technique/step ID 不再被通用高熵预览规则二次误判。
同时 benchmark runner 新增完整性门禁：任一 Case 的 Scan 不是
`completed` 即以非零错误停止，不能再把基础设施失败汇总成“completed”。
修复后的 r2、r3 与收窄安全豁免后的最终 r4 均得到相同三态计数；
r4 是本档案采用的最终工作树证据。

## 可复现标识

- 完成 commit：未创建（用户未要求提交）。
- 前置 HEAD：
  `968fb3dfb619e7b07e0c88af15f8b584c0aad634`。
- Grant schema：`execution-grant.v1`。
- Lease schema：`execution-lease.v1`。
- Wire proof：`agentgo.wire-request.v2`。
- Grant integrity：`agentgo.execution-grant.v1`。
- Capture decision set：
  `agentgo.execution-capture-decision-set.v1`。
- migrations：`0007`、`0008`、`0009`。
- 未新增 Prompt；未提交运行 DB、原始 Evidence、凭据、benchmark result、
  release 产物或 `.codex-*` 临时文件。
- 最终 benchmark 生成物位于被 Git 忽略的
  `benchmark-results/day5-final-2026-07-29-r4`，不进入版本控制。

## 残余风险与后续依赖

- Day6 仍负责 scan 级 request/RPM/concurrency/bytes 原子
  reserve/settle、精细地址分类和响应资源门禁；Day5 的单步 budget 不能
  外推为 Day6 已完成。
- Day9/10 前没有 SessionVault、可信 ActorContext/ApprovalService、
  TestObject 与 cleanup，因此产品环境 L2 继续禁用。
- `protected-original` 未实现；需要原始 DOM/截图的 XSS 当前只能
  Inconclusive。
- 本轮没有创建 Git commit；后续提交者必须再次检查工作树，不能把既有
  `.codex-*` 文件、运行数据库、Evidence 或 benchmark 结果纳入提交。

## 能力声明边界

本档案只证明已 reviewed 的 HTTP 与离线 Browser I/O 进入统一
Grant/Lease/Guard/ExecutionPort 和审计恢复链。它不证明 Day6 预算、
真实目标 L2、复杂协议、新漏洞 Technique qualification、完整 XSS 或真实
互联网检测效果。
