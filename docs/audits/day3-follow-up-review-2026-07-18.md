# Day 3 独立补充复核（2026-07-18）

本记录在 [Day3 完成审计](day3-completion-2026-07-18.md) 和 [commit 映射复核](day3-commit-review-2026-07-18.md) 之后，重新对照 [Day3 原计划](../planning/Day3.md)、当前完成日志、架构/安全规范与全仓源码、类型和测试。原实现 commit `7b25b2bdfe8fee351f4bf915eba5efd8c2da2865` 的 43 文件、`+9,362/-276` 统计及原日志中的命令结果均可复现，但固定靶场没有覆盖本次发现的负例，因此原先“0 个未解决 P0/P1/P2”的表述不能单独作为当前结论。

## 结论

Day3 的统一 Inventory、不可变 Scan module snapshot、opaque refs、迁移、Application 写入链和数据最小化十项交付仍成立。本次独立复核发现 3 个 P1 策略缺口和 5 个 P2/一致性问题；代码问题已由 commit `50181583f89b48d163830576805671e04884a44d` 修复，完成日志的一处来源审查表述已在本档案提交中校正。修复后未发现仍会阻断 Day4 开工的 P0/P1/P2。

## 发现与处理

| 级别 | 发现 | 处理与证据 |
|---|---|---|
| P1 | 十六进制 IPv4-mapped IPv6（例如 `::ffff:7f00:1`）曾被归为 `invalid`，而 private 开关可放行 `invalid`，从而绕过独立 loopback 授权。 | 完整展开 mapped IPv6 并继承底层 IPv4 分类；metadata、invalid、unspecified、multicast 永久拒绝；loopback 与 private/link-local 开关分离。新增 mapped loopback/metadata 和授权组合负例。 |
| P1 | `MKCOL`、`MOVE`、`LOCK` 和自定义方法可伪装成 L1，因为策略只拦截少数黑名单方法。 | active-safe 改为 `GET/HEAD/OPTIONS` 白名单；`POST/PUT/PATCH` 继续要求 L2；未知/WebDAV 方法无论声称 L1 或 L2 都失败关闭。 |
| P1 | `allowedIdentityIds=[]` 时，携带任意 `identityId` 的动作可通过。 | 任何提供的 identity 都必须存在于 Scope allowlist；空列表明确表示不允许身份。 |
| P2 | 策略接受带 userinfo 的 URL，存在凭据进入执行/审计边界的风险。 | 在规范化输出前拒绝 username/password，决定中不回显 credential-bearing URL。 |
| P2 | `TargetBaseUrlSchema.safeParse()` 对 malformed URL 会从 `superRefine` 抛出，而不是返回 Zod 失败结果。 | URL 构造改为受控失败并新增 malformed create/parse 回归。 |
| P2 | 独立 snapshot verifier 不校验记录属于调用方正在恢复的 Scan，跨 Scan 防线依赖 repository 查询。 | verifier 必须接收 `expectedScanId`，逐记录核对；Application 与 Coordinator 均传入当前 Scan，新增跨 Scan 拒绝测试。 |
| P2 | HTTP/Browser Runner 抛异常时，ToolCall 会永久停留在 `running`，异常原文还可能沿调用链进入日志。 | 捕获异常、以脱敏错误完成 `failed/cancelled` ToolCall、记录结束事件；HTTP 尝试保守计入预算；向上只抛脱敏错误。 |
| P2 | Strategy 候选只分别确认 endpointId 和 parameterId 存在，没有确认二者的归属关系。 | 候选过滤改为核对 `endpointId -> parameterId` 组合，避免错误组合被静默带入后续阶段。 |
| 文档一致性 | 原日志称所有 link/form 新来源都会触发下一轮 variant review；实际同结构来源复用已审查 variant，同时把新 source 自身记为 `unreviewed`。 | 明确区分结构审查和来源审查：新结构必须审查；同结构新来源不会改变已审查 wire 结构，也不会单独触发 variant-level 等待。 |

## 当前验证证据

| 验证 | 当前结果 |
|---|---|
| `pnpm check` | 退出码 0；14 个 workspace 与 scripts typecheck 通过；主测试 30 文件/281 项、DB baseline 2 文件/10 项通过；Main/Preload/Renderer production build 通过。 |
| 修复定向测试 | contracts、snapshot、ExecutionService、SecurityPolicy 共 4 文件/54 项通过；SecurityPolicy/Capability/PolicyBroker 定向集合 44 项通过。 |
| `pnpm smoke:desktop` | 退出码 0；返回 `AGENTGO_SMOKE_TEST_OK`。 |
| `pnpm benchmark:run -- --output benchmark-results/day3-follow-up-review-2026-07-18` | 全新 40 Case：TP 20、TN 20、FP/FN/Inconclusive 0，Precision/Recall/F1/Evidence completeness 均为 1；六项 safety counter 均为 0。 |
| `git diff --check` | 退出码 0；仅显示 Git 的 Windows LF/CRLF 提示，无 whitespace error。 |

Benchmark、SQLite、Evidence、凭据和构建产物仍由 `.gitignore` 排除，没有进入提交。Renderer 功能代码没有变化。

## 日志解释与残余边界

- 原完成档案记录的是 `7b25b2b` 提交时已执行的事实；本档案补充后续独立审查，不改写那个提交的历史。
- 全局 Registry/Capability snapshot hash 是不可变审计事实；恢复门禁比较的是所选 Definition 和 Capability 的精确语义。无关定义增加不应使历史 Scan 失效。
- repository 仍保留旧 Endpoint/Parameter 兼容投影；当前 legacy 执行语义来自同一个 reviewed Variant，但 Day4 需要让兼容 adapter 直接携带准确的 variant ID、template version、selector 和 structure hash。
- V1 `ExecutionService` 仍会先保存明文原始 HTTP body、DOM 和 screenshot；EvidenceStore 也没有受保护原件的加密/访问级别、capture policy 或具名 role。该已知风险仍由 Day4 的 `EvidenceCapturePolicy` 与 capture-before-store 改造处理，不能把现状称为“受保护原件”。
- query 重复项、path segment 和 form/JSON executable value slot 尚无确定性合同；它们是 Day4 compiler 开工时必须先消除的歧义。

## 不得外推

本次结论只确认 Day3 当前交付和本次负例修复通过现有自动验证；40 Case 仍是固定本地确定性回归，不证明复杂真实 Web、互联网泛化、新漏洞类别、qualification、SessionVault、L2 生命周期或通用请求执行已经完成。
