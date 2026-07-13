# Day 5：ExecutionGrant、单次 Lease 与统一 Runner Guard

## 当天目标

让每一次实际 I/O 都只能消费一次、不可篡改的执行租约，并在 Runner 发送前对最终 wire request 重新做恒等检查。模块、Agent、Renderer 都不能直接调用 Runner。

## 必须完成的工作

1. 定义 `ExecutionGrant`：scan/scope/module/technique/plan/step、template/resolved hash、capability、Day3 opaque identity/session/test-object refs、预算、purpose、有效期和 policy decision ref；本日不假设 Vault/TestObject/Approval 服务已存在。
2. 定义 `ExecutionLease` 状态机：issued -> claimed -> completed/failed/expired/revoked；claim 必须数据库原子化，一次租约只允许一个实际动作。
3. Runner Guard 在发送前重新计算 `WireRequestHash/HMAC`，复核 method、URL、header/body、identity/session、scope snapshot、capability、purpose 和剩余预算；不能只比较 URL/method。
4. redirect 每一跳形成新的内部 step/decision/lease 或等价的受限 child grant；重新解析 DNS、移除跨 origin 凭据，不能沿用首跳批准。
5. 当前 HTTP 以及未来 Browser Network Broker、OOB poll、cleanup adapter 均只能通过同一 `ExecutionPort`；未实现 adapter 本日只有 port/capability 拒绝路径，不创建假实现。直接 Runner import 用 lint/architecture test 阻断。
6. crash 后 claimed-but-unknown 不能自动重放；标记 interrupted/Inconclusive，只有确定性只读且无送达可能的步骤才能通过新 lease 重试。
7. 在合同层预留 L2 bundle approval ref 与单步 lease 分离关系；Day10 才接入可信批准。每个未来 primary/read/cleanup 步骤仍必须有独立 grant/lease，不能用 bundle ref 直接执行。
8. 保留现有 `policyDecisionId` 读取兼容，但禁用裸 decisionId 直接执行的新调用路径，安排迁移删除时间。

## 预计改动位置

- `packages/contracts/src/security.ts`、`application.ts`；
- `packages/db/src/schema.ts`、`migrations.ts`、`repository.ts`；
- `packages/application/src/execution-service.ts`、`execution-policy.ts`；
- `packages/http-runner/src/index.ts`、browser-runner port；
- execution/repository/runner tests。

## 测试与证据

- body/header/identity/session/scope/purpose 任一篡改在发网前拒绝；
- 同 lease 串行/并发 claim 只有一次成功，过期/撤销/完成后重放失败；
- crash、timeout、cancel、响应读取失败均有确定结束状态和 Evidence 摘要；
- redirect 到跨域、私网、metadata、scope 外路径或携带旧 Authorization 时拒绝；
- architecture test 证明 Coordinator/Module 不能绕过 ExecutionPort 直接调 Runner；
- 运行 DB/Application/Runner 测试与 `pnpm typecheck`。

## 合格交付

实际 I/O、批准意图和 Evidence 可以一一追踪；任何篡改、重放、并发双花或旁路调用都在网络发送前失败关闭。
