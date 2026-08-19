# ADR-0006：确定性执行授权、单次租约与统一执行端口

- 状态：Accepted
- 日期：2026-07-28

> 历史状态说明：本 ADR 在 Day5 决策时正确规定在线路径仅允许 hash-only，
> 当时的 `protected-original unsupported` 陈述不回写。Day4 后续新增的
> 受保护原件后端由 [ADR-0007](0007-protected-evidence-envelope.md) 接续；
> Day5 在线 capture authority 仍保持本 ADR 的 hash-only 边界。

## 背景

Day4 已建立纯请求编译、Template/Resolved/Wire 三阶段证明和
EvidenceCapturePolicy，但仅有 `policyDecisionId` 仍不足以授权实际 I/O：
调用方可能在批准后替换 header/body、重复执行、并发双花，或在 redirect
时沿用首跳授权。Coordinator、模块或 Renderer 若能直接持有 Runner，也会
绕过统一的授权、审计与恢复语义。

此外，进程可能在租约 claim 后、终态持久化前崩溃。此时系统无法证明请求
是否已发送，自动重放会产生不可接受的重复副作用。

## 决策

1. 每个实际 I/O 必须先签发不可变 `ExecutionGrant`。Grant 绑定 scan、
   scope/module/technique/plan/step、Template/Resolved/Wire proof、
   capability、opaque identity/session/test-object ref、purpose、预算、
   有效期、PolicyDecision 和 Evidence capture decision set。
2. 每个 Grant 只能通过独立 `ExecutionLease` 执行。Lease 使用
   `issued -> claimed -> completed/failed/expired/revoked` 状态机；
   claim 在 SQLite 中原子完成，串行或并发重放只能有一个成功者。
3. Runner 发送前必须由 Guard 重算并核对精确 wire request，以及
   identity/session、scope、capability、purpose、有效期和单步预算。
   HTTP 在 claim 后解析 DNS，并在 `markDispatched` 前复核地址；离线
   Browser 只能执行 `browser.offline-replay`。
4. 所有调用方只依赖 Application 所有的 `ExecutionPort`。
   Coordinator、漏洞模块和 Renderer 不得直接导入或调用 HTTP/Browser
   Runner；未实现 adapter 只有明确拒绝路径，不创建假实现。
5. HTTP Runner 不自动跟随 redirect。每一跳回到 Application，重新编译
   reviewed request、重新经过 Policy、签发 fresh child Grant/Lease、
   重新解析 DNS。跨 origin 必须把 credential mode 降为 `omit`，且
   `omit` wire 若仍含 Authorization/Cookie 等凭据头必须在发送前拒绝。
6. Guard 在发送前持久化 `not-dispatched -> possibly-sent`，收到响应头后
   再持久化 `response-started`。Evidence capture、Interaction、
   ToolCall、Grant 和 Lease 使用不可变引用形成可审计闭环。
7. 启动恢复把 claimed-but-unknown 租约终结为
   `interrupted / unknown`，把相关 Scan 置为 `awaiting-user` 并产生
   Inconclusive 恢复事实；不自动重放。没有 claimed lease 的普通中断任务
   才恢复为 `paused`。即使恢复 Evidence 无法写入，也必须能安全终结租约。
8. `approvalBundleRef` 只作为未来 L2 合同引用；它不能直接执行，也不能
   替代每个 primary/read/cleanup step 自己的 Grant/Lease。可信审批、
   TestObject 和 cleanup 仍由后续工作包负责。

数据库采用只前进迁移：

- `0007_execution_grants_and_leases`：Grant、capture decisions、Lease、
  Evidence/Interaction/ToolCall 绑定和状态触发器；
- `0008_execution_recovery_without_artifact`：允许恢复在 Evidence
  不可用时仍把 interrupted 租约安全终结；
- `0009_execution_dispatch_revalidation`：为已应用 0007 的数据库补装
  dispatch-time identity/scope/capability/budget 重校验。

## 安全与证据边界

- Grant/Lease 只授权已冻结的单步请求，不是通用 bearer token。
- 旧 `policyDecisionId` 只保留读取兼容；新执行路径不得用裸 decision
  直接调用 Runner。
- Day5 的在线证据路径只持久化由 EvidenceCapturePolicy 授权的
  hash-only 摘要。`protected-original` 仍明确 unsupported；在加密、
  访问控制、保留期和派生关系完成前，不保存或宣称受保护原件。
- 当前 XSS 路径没有可持久化、可审阅的 DOM/截图原件。即使隔离浏览器
  观察到惰性 marker 执行，也只能输出 `Inconclusive`，不能提升为
  `Confirmed`。
- crash staged Evidence 的清理必须与租约终结共享事务判断，并覆盖全部
  已知引用图。启动 GC 只处理严格内容寻址普通文件，不跟随符号链接、
  junction 或未知路径；引用 JSON 无法解析时失败关闭。
- 全局 request/RPM/concurrency/bytes 原子 reserve/settle 和更完整的
  网络资源门禁仍属于 Day6；本 ADR 不提前宣称完成。

## 后果

- 批准意图、实际 wire、执行终态与 Evidence 可以逐步追踪。
- 篡改、重放、并发 claim、跨 origin 凭据沿用和旁路调用在发送前
  失败关闭。
- redirect、审计和恢复需要更多持久化记录与状态转换，但行为可复核，
  且 crash 不再通过自动重试制造第二次 I/O。
- 测试必须覆盖 exact-wire 篡改、lease 双花、redirect fresh authority、
  DNS 地址拒绝、runner 单跳语义、审计原子性和无重放恢复。
