# Day 3 完成审计（2026-07-18）

## 原计划与范围

- 原计划：[Day3：统一 Inventory、请求变体与 Scan 模块快照](../planning/Day3.md)。
- 前置 commit：`0f460589a706ae2102eecc3630f2a559e26922b1`（Day2 补充复核归档完成后的仓库状态）。
- 本次范围：唯一 scan-scoped Inventory、结构化 RequestVariant/Selector/Source、opaque refs、不可变 Scan module snapshot、旧库迁移、Application 写入/审查入口、Coordinator 消费门禁和字段级数据最小化。
- 明确非目标：Day4 请求编译与三阶段哈希、Day5/6 Lease 与 wire 边界、Day7 qualification、Day9 Vault/TestObject 生命周期、Day11～Day13 导入/静态/浏览器发现、任何新增漏洞模块或 Renderer 功能。

## 逐项完成情况

| 原计划项 | 状态 | 代码/文档证据 | 说明 |
|---|---|---|---|
| 1. Endpoint identity 与 RequestVariant | `completed` | [Inventory contracts](../../packages/contracts/src/inventory.ts)、[DB schema](../../packages/db/src/schema.ts)、[repository](../../packages/db/src/repository.ts) | Endpoint 以 `(scanId, method, canonicalRoute)` 幂等；JSON/form/XML 等变体按结构 hash 共存，保存 codec、transport、header schema、body shape、template version 与脱敏 preview。 |
| 2. 多来源与 provenance | `completed` | [Inventory service](../../packages/application/src/inventory-service.ts)、[repository tests](../../packages/db/src/database.test.ts) | `inventory_sources` 保存 source/provenance hash、受控引用、initiator、confidence、发现时间与 review；同 Scan 重复写入幂等，跨 Scan 绑定失败。 |
| 3. 无值 selector | `completed` | [contracts tests](../../packages/contracts/src/inventory.test.ts)、[domain tests](../../packages/domain/src/inventory.test.ts) | query/path/header/cookie/form/JSON Pointer/XML/multipart/GraphQL/WebSocket selector 只保存结构和示例类型；无 raw value 字段。 |
| 4. codec/transport 扩展点 | `completed` | [Inventory contracts](../../packages/contracts/src/inventory.ts)、[classifier/service](../../packages/application/src/inventory-service.ts)、[Coordinator](../../packages/application/src/scan-coordinator.ts) | 合同覆盖计划枚举；当前只允许已审查的标准 HTTP、无 body、纯 query L1 legacy 变体进入既有执行链，未实现 adapter、自定义 header 或混合 selector 为 `unsupported`/`inventory-only` 或在兼容投影中 fail closed。 |
| 5. review 与 execution class 分离 | `completed` | [Inventory service tests](../../packages/application/src/inventory-service.test.ts)、[Coordinator regression](../../packages/application/src/scan-coordinator.test.ts) | `reviewVariant` 只能记录人工结论；`executionClass` 由 method、codec、transport 与 capability 确定，人工不能把危险语义降级为 L1。target seed 在任何 HTTP/模型/AgentRun 前先进入 review；执行 URL、selector、`dataType` 与 `required` 必须来自同一个 reviewed variant，rejected/retired sibling 不能污染 wire。 |
| 6. immutable Scan module snapshot | `completed` | [snapshot builder/verifier](../../packages/application/src/scan-module-snapshot.ts)、[integration tests](../../packages/application/src/scan-module-snapshot.integration.test.ts)、[migration](../../packages/db/src/migrations.ts) | 每个 Scan 原子写入 module/technique/Definition/rule/evidence/capability/Registry/环境语义并封存；DB 拒绝封存后增删改/解封和未封存执行，开始/恢复时重新核对，缺失或漂移进入 awaiting-user/Inconclusive。 |
| 7. opaque refs | `completed` | [Inventory contracts](../../packages/contracts/src/inventory.ts)、[contract tests](../../packages/contracts/src/inventory.test.ts) | Identity/SessionGeneration/TestObject 引用只含稳定 ID、generation/version、owner/scope binding 与状态摘要；拒绝 credential/token/cookie/CSRF/对象内容。 |
| 8. Application 统一入口 | `completed` | [Inventory service](../../packages/application/src/inventory-service.ts)、[composition root](../../apps/desktop/src/main/index.ts)、[Application exports](../../packages/application/src/index.ts) | `upsertInventory`、`reviewVariant`、`retireVariant` 为 producer 入口；Coordinator 的页面/link/form 发现写入该真源，producer 不能自报 reviewed 或 execution class。 |
| 9. 旧库迁移 | `completed` | migration `0006_unified_inventory_and_module_snapshots`、[DB migration tests](../../packages/db/src/database.test.ts)、[baseline tests](../../scripts/v1-database-baseline.test.ts) | 旧 Endpoint/Parameter/Scan 回填为 inventory-only、unreviewed 和 legacy snapshot；迁移事务回滚、重复打开幂等，产物通过当前 Zod contracts。合同允许的 benign Target query 保持请求语义，危险/非法 seed 显式落到 `.invalid/reconfigure` 并失败关闭；未知历史环境保留 `legacy-unknown`，不伪造可恢复性。 |
| 10. 裁剪、secret 检测与 canonicalization | `completed` | [domain redaction](../../packages/domain/src/inventory.ts)、[execution storage](../../packages/application/src/execution-service.ts)、[DB tests](../../packages/db/src/database.test.ts) | canonical identity 删除 query value；Page/Endpoint、页面标题、header、cookie、body preview、执行 URL/摘要/错误字段和旧库迁移均裁剪 userinfo、敏感字段、高熵 token 与 sentinel。Target seed 按严格合同保留 benign query，危险结构转待重配失败关闭；原始 wire URL 只在执行期间瞬时使用。原始响应 Evidence 的捕获前最小化仍明确留给 Day4。 |

## 关键实现与安全边界

- contracts → domain canonicalization/redaction → Application service → repository/SQLite 是唯一 Inventory 写入链；repository 在事务前后校验合同、hash 与同 Scan 绑定，SQLite trigger 提供最后一道不变量防线。
- Scan 创建时在同一事务写入完整 snapshot 集合并封存；snapshot hash 覆盖选中 Definition、完整 capability descriptor（含 description/risk floor）、Registry、环境与授权语义。未封存、损坏、缺失、语义漂移或 `legacy-unknown` 都不会恢复执行。
- `reviewStatus` 是人工事实，`executionClass` 是确定性分类；两者不相互覆盖。未审查来源只进入 Inventory，现有四类执行只消费明确 reviewed 的安全 legacy 变体。
- Coordinator 在 start 时先建立 target-base Inventory；首次等待用户发生在 `intake`，HTTP 请求、模型调用和 AgentRun 均为 0。review 后恢复仍在 active-enum 入口再次核对 pending 变体；link/form 新来源需要下一轮显式 review。
- legacy 投影从同一个 reviewed variant 的 preview 与 query selector 重建执行 URL，从该 variant 获取 `contentType` 和已复核 provenance `source`，并从该 selector 读取 `valueType`/`required`；旧 `parameters` 表只提供稳定兼容 ID。它不读取 Endpoint 的跨变体兼容字段或 sibling 参数语义；含非 query selector、legacy runner 不会隐式提供的自定义 header、缺失 reviewed source 或 rejected/retired 状态的变体均不进入 wire。
- Target/Page/Endpoint、PolicyDecision、ToolCall、请求/响应摘要和脱敏 Evidence 派生中的 URL 与敏感元数据使用脱敏表示；原始请求目标只在授权与实际 Runner 调用之间瞬时流动，不写数据库或报告。V1 仍可能把完整响应 body 保存为不可变 `original` Evidence，再生成文本脱敏派生；Day3 不把它误报为 capture-before-store。
- Renderer 目录没有功能变化；Main 仅组合注入 `InventoryService`。本次不新增 API provider、依赖型网络调用、主动漏洞类别或 L2 能力。

## 验证证据

| 命令或检查 | 退出码 | 结果 |
|---|---:|---|
| `pnpm check` | 0 | 14 个 workspace 与 scripts typecheck 通过；主测试 30 文件/254 项、DB baseline 2 文件/10 项通过；Main/Preload/Renderer production build 通过。 |
| `pnpm smoke:desktop` | 0 | 返回 `AGENTGO_SMOKE_TEST_OK`；GPU 退出期日志不影响 smoke 判定。 |
| `pnpm benchmark:verify` | 0 | evaluation manifest/metrics 1 文件/3 项通过。 |
| `pnpm benchmark:run -- --output benchmark-results/day3-final-projection-fix-2026-07-18` | 0 | legacy 投影的 selector/contentType/source/header 隔离修复后全新 40 Case：TP 20、TN 20、FP/FN/Inconclusive 0，Precision/Recall/F1/Evidence completeness 均为 1；六项 safety counter 均为 0。 |
| `pnpm db:baseline generate/verify`（忽略目录） | 0 | schema `0006_unified_inventory_and_module_snapshots` 生成后立即复核；数据库与逻辑内容 hash 一致，recordCounts 为 Workspace/Target/Scope/Scan 各 1。 |
| 多轮只读差异/安全复核 | 0 个未解决 P0/P1/P2 | 复核发现的 URL/标题落库、variant URL/selector/contentType/source 执行绑定、混合 selector/custom header 降格、review-before-GET、Target/selector 迁移、snapshot 封存/语义、Unicode 原子性、legacy review 与文档现时态问题均已修复并回归。 |
| `git diff --check`、Renderer diff、生成物忽略检查 | 0 | 无 whitespace error；`apps/desktop/src/renderer/**` 无差异；benchmark/合成数据库目录命中 `.gitignore`，Git 未跟踪 SQLite、Evidence、凭据或运行产物；Day3 过时 pending 表述扫描为 0。 |

## 可复现标识

- 完成 commit：待提交；提交后用独立复核记录固化实现与档案 commit 对应关系。
- 数据库 migration：`0006_unified_inventory_and_module_snapshots`。
- Definition Registry snapshot SHA-256：`d4c45f8c27463729e01d60ab1a1ddfea03039e9dc2967e6ebb52f8c5f17cd9e9`。
- Capability Catalog snapshot SHA-256：`d7f3aa70efd0b55c981e7d5a105e097b32c95d558eeb5e7b7645f17e490a2792`。
- Benchmark schema/fixture/ground truth：`agentgo-benchmark-run/1.0`、`agentgo-local-fixture/1.0.0`、`agentgo-ground-truth/1.0`；确定性模型 `agentgo-rules-v1`。
- Benchmark 生成物：`benchmark-results/day3-final-projection-fix-2026-07-18`，由 `.gitignore` 的 `benchmark-results/` 规则忽略；不进入提交。
- 合成数据库生成物：`benchmark-results/day3-db-baseline-postfix`（同样忽略）；数据库 SHA-256 `09dd454b525f2cd529126af10fcb9f240310bde215bf75bae5bd50b1d92ca011`，逻辑内容 SHA-256 `98fef1fe37a578be80bcd6d9fcbbb1d47869a89486f96a15a3f73678184c37e5`，fixture `agentgo-v1-synthetic-baseline@1`。数据库、Evidence、凭据与构建输出均不得进入 Git。

## 残余风险与后续依赖

- Day3 只建立 Inventory 结构与单一写入链；OpenAPI/HAR/Postman/GraphQL 导入、HTML/JS 静态发现和 brokered browser producer 仍由 Day11～Day13 交付。
- 非标准 codec/transport 当前只可盘点并 fail closed；纯 RequestCompiler、Template/Resolved/Wire 哈希和 EvidenceCapturePolicy 由 Day4 交付，Lease/wire 绑定由 Day5～Day6 交付。
- opaque refs 不实现 Vault、凭据注入、CSRF binding、TestObject ownership/lifecycle 或批准；这些仍由 Day8～Day10 交付。
- V1 ExecutionService 仍可能先保存完整响应 body 为不可变原始 Evidence；Day4 必须交付 CapturePolicy、捕获前字段最小化、敏感字段禁止捕获和受保护原件边界。
- 迁移的历史 Scan 因无法证明当时环境而标记 `legacy-unknown`，恢复会 awaiting-user/Inconclusive；这是有意的失败关闭，不以当前版本猜补历史事实。
- 四类 module 仍是 registered/unqualified 的 `legacy-v1` 兼容能力，Day3 snapshot 不构成 qualification；Day7 接管资格状态后仍需按计划移除例外。
- 40 Case 是固定本地 fixture 回归，只证明该确定性套件没有退化，不证明复杂真实 Web、互联网准确率或新漏洞覆盖。

## 能力声明边界

本档案只证明 Day3 的统一 Inventory 真源、结构化请求变体/来源、opaque 引用、不可变 Scan 模块快照、旧库迁移与数据最小化已经交付；不证明通用请求重放、L2 安全闭环、会话/身份、真实 Web 导入/发现、新漏洞模块、qualified/supported 状态或真实互联网准确率。
