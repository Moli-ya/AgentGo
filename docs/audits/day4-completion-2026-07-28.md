# Day 4 完成度复核与收口档案（实现 2026-07-28，终验 2026-07-29）

> 文件名用于保留本轮收口记录；本档案的总状态是
> `partial / in_progress`，不是 Day4 completed 声明。
>
> 后续状态：Day4 已于 2026-07-30 完成最终收口；当前结论、验证与清理事实
> 见 [最终复核](day4-final-review-2026-07-30.md)。下文保持历史原貌。

## 原计划与范围

- 原计划：[Day 4：纯请求编译、三阶段哈希与 EvidenceCapturePolicy](../planning/Day4.md)。
- 首个切片：[2026-07-19 进度档案](day4-progress-2026-07-19.md)，实现
  commit `8fe55b0963560bfbd0381b32cf8220909e7922ec`。
- 本轮代码基线 HEAD：
  `968fb3dfb619e7b07e0c88af15f8b584c0aad634`。
- 本轮状态：`partial / in_progress / uncommitted`；用户未要求创建提交。
  保留既有 `.codex-*` 文件，不把它们当作 Day4 生成物或清理对象。
- 本次复核范围：确认纯编译、三阶段证明、legacy compatibility adapter、
  hash-only capture-before-store、Interaction/Evidence 审计和恢复链的
  实际接入状态。
- 明确非目标：SessionVault、CSRF、TestObject、可信 L2 Approval、
  protected-original 存储和复杂协议 adapter。

## 逐项完成情况

| 原计划项 | 状态 | 代码/文档证据 | 事实说明 |
|---|---|---|---|
| 1. 无 I/O `ProbeRequestCompiler` | `completed`（已实现切片） | `packages/application/src/request-compiler.ts` 及测试 | 已实现 query/path/header/cookie/form/JSON Pointer；未实现 transport/codec 明确失败关闭。 |
| 2. Template/Resolved/Wire 三阶段证明 | `completed` | contracts、request compiler、request hash key provider | 三类 proof 分域且不可混用；Resolved/Wire 使用短期 key ref/version 和 HMAC commitment。 |
| 3. canonicalization 与 redirect 重编译 | `completed`（已实现范围） | request compiler、legacy adapter、ExecutionService redirect 测试 | 已实现标准 HTTP 编码/排序/Unicode/空值规则；redirect 每跳回到 Application，用 reviewed endpoint 重新编译，不沿用首跳 wire。 |
| 4. Resolver port | `completed`（合同范围） | `DynamicValueResolver`、`SecretRefResolver`、key provider | 测试只使用无真实 secret 的内存替身；Day9 服务未被提前假设为存在。 |
| 5. MutationGenerator metadata | `completed` | request compiler contracts/tests | generator/version、安全语义、capability、selector/codec 和输出预算均进入失败关闭校验。 |
| 6. EvidenceCapturePolicy 与必要原件 | `partial / in_progress` | `evidence-capture-policy.ts`、ExecutionService V2 | hash-only capture-before-store 和 decision-bound Evidence 已接入；`protected-original` 仍返回 `protected-original-unsupported`，尚无加密、访问控制、保留期和脱敏派生闭环。 |
| 7. 异常响应与敏感值 | `completed`（hash-only 范围） | evidence capture policy/tests | oversize、compressed、binary、non-UTF-8、解析失败、DOM/screenshot 等不安全源明确降为 hash-only 或 unsupported，不把自由文本秘密写入普通 Evidence。 |
| 8. legacy compatibility adapter | `completed` | `legacy-v1-request-compiler-adapter.ts`、desktop composition root、`ExecutionPort` | 四类 legacy 请求构造已通过统一 adapter/ExecutionService；Coordinator 不再直接持有 Runner。 |

## 当前闭环与安全边界

Day4 已从“纯函数切片”推进到实际执行链：

```text
reviewed RequestVariant
  -> LegacyV1RequestCompilerAdapter
  -> ProbeRequestCompiler
  -> Template / Resolved / Wire proof
  -> EvidenceCapturePolicy hash-only artifact
  -> atomic Interaction/Evidence binding
  -> crash interruption hash-only recovery
```

这证明统一执行路径不会先把 HTTP body、DOM 或 screenshot 作为普通原件
落库。它不证明原始内容已获得受保护存储能力。

特别是 XSS：当前离线 Browser 结果只形成 hash-only 请求/结果摘要，
没有可供复核者查看的 DOM 或 screenshot Evidence。确定性
`ConfirmationRule` 因而把 marker executed 但缺少可审阅证据的情况保持为
`Inconclusive`；不得写成 Confirmed。

## 验证证据

| 命令或检查 | 退出码 | 结果 |
|---|---|---|
| Evidence policy / ExecutionService 定向回归 | 0 | 3 文件 / 41 项通过；生产 technique/step ID 不再被 secret 启发式误判，JSON Pointer secret 负例继续失败关闭。 |
| `pnpm typecheck` | 0 | 14/15 workspace projects 的现有 typecheck 与 scripts typecheck 全部通过。 |
| `pnpm test` / `pnpm build` | 0 / 0 | 主套件 42 文件 / 430 项、DB baseline 2 文件 / 10 项通过；Electron production build main/preload/renderer 为 619/88/1873 modules。 |
| `pnpm smoke:desktop` / `pnpm benchmark:verify` | 0 / 0 | desktop 输出 `AGENTGO_SMOKE_TEST_OK`；evaluation 1 文件 / 3 项通过。 |
| 全新 40 Case 与 secret 边界 | 0 | 最终 r4 为 TP 15、TN 20、FP/FN 0、XSS 正例 Inconclusive 5，正好保留本档案声明的证据限制；六项 safety counter 为 0，额外明文 sentinel 扫描无匹配。 |

## 可复现标识

- 本轮完成 commit：未创建（用户未要求提交）。
- 代码基线 HEAD：
  `968fb3dfb619e7b07e0c88af15f8b584c0aad634`。
- 关键 proof domain：`agentgo.template-intent.v1`、
  `agentgo.resolved-intent.v1`、`agentgo.wire-request.v2`。
- Capture policy：`evidence-summary-v1` / hash-only 路径。
- 未新增 Prompt；未提交运行数据库、原始 Evidence、凭据、benchmark
  result 或构建产物。

## 残余风险与唯一后续主责

- `protected-original` 的加密、访问控制、保留期、配额和派生关系仍未实现。
  在该能力有独立设计、迁移和验证前，Day4 保持
  `partial / in_progress`，不得用本文件名推断完成。
- 需要原始 DOM/截图才能复核的 XSS 当前只能 Inconclusive；后续受保护
  Evidence 能力与 Day18 XSS 模块共同负责解除。
- Day5 只消费 hash-only capture authority；Day6 继续负责全局原子预算
  与更完整网络资源门禁。

## 能力声明边界

本档案只证明统一 Compiler 与 hash-only CapturePolicy 已进入实际执行和
审计恢复链。它不证明 protected-original、真实复杂 XSS、Session/Vault、
L2 写操作或新漏洞 Technique 已经获得资格。
