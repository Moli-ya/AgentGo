# Day 4 protected-original 最终收口复核（2026-07-30）

## 结论

Day 4 的八项计划已经在当前工作树完成，状态为
`completed / uncommitted`。2026-07-28 档案记录的唯一阻塞项
`protected-original` 已补齐；旧档案继续作为历史事实保留，不回写成当时已经
完成。

本结论只覆盖 Day 4 规定的纯编译、三阶段证明、捕获策略和受保护证据后端。
它不把 Day 18 的真实 DOM/截图采集、审阅和 XSS 确认链提前写成已完成。

## 原计划与基线

- 原计划：[Day 4：纯请求编译、三阶段哈希与 EvidenceCapturePolicy](../planning/Day4.md)。
- 历史完成度复核：[2026-07-28 档案](day4-completion-2026-07-28.md)。
- 架构决策：[ADR-0007](../adr/0007-protected-evidence-envelope.md)。
- 前置 HEAD：`968fb3dfb619e7b07e0c88af15f8b584c0aad634`。
- 本轮未创建 Git commit；不能用计划文字或文件名代替当前代码和测试证据。

## 八项计划逐项验收

| 计划项 | 状态 | 当前证据与边界 |
|---|---|---|
| 1. 无 I/O `ProbeRequestCompiler` | `completed` | `request-compiler.ts` 支持 query/path/header/cookie/form/JSON Pointer；XML、multipart、GraphQL、WebSocket 等未实现路径明确失败关闭。 |
| 2. Template/Resolved/Wire 三类证明 | `completed` | 三类 proof 分域；Resolved/Wire 使用短期 key ref/version 和 HMAC commitment；稳定输入可复现，结构、opaque generation 或 wire bytes 变化可检测。 |
| 3. canonicalization 与 redirect 重编译 | `completed` | 重复 query、URL 编码、Unicode、空值、header、JSON、content length 和歧义输入已有确定规则；redirect 每跳重新编译，不沿用首跳 wire。 |
| 4. Resolver port | `completed`（合同范围） | `SecretRefResolver`、`DynamicValueResolver` 和 request-hash key provider 已定义；测试使用无真实 secret 的内存替身，未冒充 Day 9 SessionVault。 |
| 5. MutationGenerator metadata | `completed` | generator ID/version、安全语义、禁止 capability、selector/codec 和输出大小均进入结构化门禁，不依赖自由文本 `payloadSummary` 授权。 |
| 6. `EvidenceCapturePolicy` 与必要原件 | `completed` | 默认仍最小化/hash-only；完整、非空且获准的 body/DOM/screenshot 可形成严格绑定的 protected artifact，经后端服务加密保存，并生成 metadata-only 脱敏派生。 |
| 7. 异常响应与敏感数据 | `completed` | partial、oversize、empty 降为 hash-only；二进制、压缩、非 UTF-8 可在完整 descriptor 与固定配额内进入加密原件；JSON/XML 失败和敏感选择器均失败关闭或最小化。 |
| 8. legacy compatibility adapter | `completed` | 四类 legacy 请求通过统一 Compiler/adapter；Day 5 线上网络路径继续使用固定九项 hash-only capture authority，Coordinator 未被改回直接 Runner 调用。 |

## protected-original 后端闭环

受保护原件只能从可信 Application 后端进入以下链路：

```text
strict capture context + protected capture decision
  -> EvidenceCapturePolicy
  -> secure byte snapshot
  -> AES-256-GCM ciphertext
  -> OS-protected wrapped data key
  -> protected original metadata + metadata-only derivative + audit
  -> retention expiry / crypto-erase
```

具体门禁如下：

- 合同同时绑定 workspace、target、scan、policy decision、module、technique、
  step、source type、MIME、plaintext hash/size、有效期和固定捕获计划；
- `0010_protected_evidence_envelopes` 是只前进 migration，原件元数据、
  派生关系和创建审计在同一 `BEGIN IMMEDIATE` 事务内提交；
- 原文字节只写入内容寻址 ciphertext，数据密钥由 Electron
  `safeStorage` 对应的 `SecretProtector` 包装；
- scan/workspace 明文大小配额在事务内竞争，重试同一捕获决策幂等；
- 普通 `EvidenceStore.read`、Renderer、报告、导出和普通删除路径均不能读取
  或误处理原件；
- 到期只允许 `available -> expired`，清除 wrapped key/nonce/tag 后再安全删除
  ciphertext；启动恢复与长进程周期 sweep 都已接入，并发 sweep 只有一个
  审计赢家；
- 完整性失败与运行时 key unwrap/audit 故障分离，瞬时运行故障不会把有效原件
  误标为损坏；一旦确认完整性失败，即使恢复旧 ciphertext 也不能逆转；
- migration 与运行时同时核对策略时间窗、保留期、封套 JSON、原件/派生件
  关系和内容哈希；缺失 envelope 的保留类型、截断的 complete capture、
  自引用或错绑定派生件全部失败关闭；
- 扫描详情只输出严格 `EvidenceSummary`；报告输入强制 `redacted: true`，
  且只接受同扫描、类型/MIME/hash 完全匹配的普通脱敏 Evidence。旧的
  `redacted=false` 报告以及 protected original 读取/导出均被拒绝。

## 最终验证

以下命令均在 Day 4 最终代码及其下游 Day 5 代码上重新执行：

| 命令或检查 | 退出码 | 结果 |
|---|---:|---|
| `pnpm typecheck` | 0 | 14/15 workspace projects 的已有 typecheck 与 scripts typecheck 全部通过。 |
| `pnpm test` | 0 | 主套件 47 文件 / 461 项通过；DB baseline 2 文件 / 10 项通过。 |
| protected evidence 定向覆盖 | 0 | policy 32 项、真实 Policy→Store/长进程过期集成 1 项、Store 13 项、migration hardening 6 项、报告/投影 2 项均包含在全量结果中。最终合并定向回归为 8 文件 / 92 项。 |
| `pnpm build` | 0 | Electron production build：main/preload/renderer 分别转换 622/88/1873 个模块。 |
| `pnpm smoke:desktop` | 0 | 输出 `AGENTGO_SMOKE_TEST_OK`。 |
| `pnpm benchmark:verify` | 0 | evaluation manifest/metrics 1 文件 / 3 项通过。 |
| 全新 40 Case | 0 | TP 15、TN 20、FP/FN 0、XSS 正例 Inconclusive 5；Precision 1、Recall 0.75、F1 0.8571428571，六项 safety counter 全为 0。 |

全新基准目录为
`benchmark-results/day4-day5-final-2026-07-30-r2`，只用于本次验收；以下
hash 已在清理前记录，生成物不进入 Git：

- `summary.json` SHA-256：
  `96c6cef2d9f515c2864716daf78d5c6b8a134a41a919bc2801f9631ec471cab3`
- `predictions.json` SHA-256：
  `27ed0d00b7da5cd875a998f80a122d593c4d2d1812b62f5fab4f6d5c6afe8606`
- `report.md` SHA-256：
  `0037982e7e8c204b2bc5651321230bd7cae9ac0338c3eb3d73d331092f033db3`

## 最终工作树与产物清理

- 验证前的 normal untracked 共 351 项，全部为 `.codex-*` 补丁、临时源码
  或替换目录；其中顶层为 346 个文件和 4 个目录。经 `git clean` 精确
  pathspec 预览后已全部删除，最终 normal untracked 为 0。
- 已删除 `apps/desktop/out/`、`benchmark-results/`、`release/`、
  `release-stale-0.1.0/`，以及系统临时目录中的 7 个
  `agentgo-protected-evidence-*` 测试目录；最终逐项确认均不存在。
- 本地协作规则 `AGENTS.md`、既有 archive 基线、本地依赖
  `node_modules/` 和 Git 忽略的本地私有文档不是中间产物，按边界保留。
- Day1～Day20 的原始 `docs/planning/Day*.md` 均无差异；本轮只更新
  Day4/Day5 状态索引、需求追踪和两天的完成档案。
- 正式 Day4/Day5 变更已 staged，但未创建 commit；用户未要求提交。

## 能力边界与后续责任

- Day 4 完成的是受保护原件的后端能力，不是 Renderer 审阅界面。
- Day 5 当前实际 HTTP/离线 Browser 仍固定生成 hash-only Evidence；
  benchmark 数据库中的 `protected_evidence_items` 为 0，证明本轮没有借后端
  能力扩大在线 capture authority。
- Day 18 负责把真实 DOM/截图通过 Lease provenance 接入该后端，并完成
  reviewer access、负对照和 XSS 确认规则。在此之前五个 XSS 正例继续保持
  `Inconclusive`。
- Day 6 的 scan 级原子预算、Day 9 的 SessionVault、Day 10 的可信批准均未
  因本工作包完成而被提前声明。
