# Day 3：统一 Inventory、请求变体与 Scan 模块快照

## 当天目标

把 endpoint/parameter 模型升级为所有发现源共用的 scan-scoped Inventory，并为真实复杂 Web 预留 body codec、transport、业务依赖和非参数 Subject；同时冻结每次 Scan 使用的模块版本。

## 当前缺口

- `endpoints.source` 是单值，同一 operation 被 link/form/OpenAPI/HAR/XHR 多次发现时会丢失来源。
- 当前 Candidate 默认必须有 endpointId/parameterId，无法表达 Header 配置、DOM、OAuth 流、组件或工作流。
- normalized URL 可能保留真实 query value，扩大敏感数据落库风险。
- 恢复 Scan 时没有 module/capability 版本快照，未来规则升级可能改变中途任务语义。

## 必须完成的工作

1. 保留 Endpoint 为 `(scanId, method, canonical route)`；新增 `request_variants` 表达 content type、body shape、codec、transport、允许 header schema、templateVersion 和脱敏 preview。
2. 新增 `endpoint_sources`/`inventory_sources`：source type/hash、page/evidence ref、initiator、confidence、发现时间和 review 状态；重复导入必须幂等。
3. 定义 selector：query、path、header、cookie、form、JSON Pointer、XML path、multipart part、GraphQL variable、WebSocket field；只保存结构和示例类型，不保存 secret/raw token。
4. 定义 codec/transport 扩展点：none/form/json/xml/multipart/graphql/raw；standard-http/browser/websocket/SSE/OOB/raw-http1/http2。20 天内未实现的 adapter 仍必须在 Capability gate 中 fail closed。
5. 将人工 `reviewStatus` 与确定性 `executionClass` 分开；人工 review 不能把危险 method 或 capability 降级为 L1。
6. 为 Scan 新增 immutable module snapshot：familyId、techniqueId、moduleVersion、strategy/rule/evidence profile version、capability snapshot hash。缺少历史版本时恢复为 awaiting-user/Inconclusive。
7. 定义不含 secret 的 opaque `IdentityRef`、`SessionGenerationRef`、`TestObjectRef`：只表达稳定 ID、generation/version、owner/scope binding 和状态摘要；Day3 不实现 Vault、凭据注入、TestObject 生命周期或批准逻辑。
8. 新增 Application 层统一 `upsertInventory`、`reviewVariant`、`retireVariant`；任何 producer 都不能直接写多套表或自称 reviewed。
9. 迁移旧 Endpoint/Parameter/Scan：旧四类映射 legacy module snapshot，旧数据默认 inventory-only，不伪造人工 review；迁移必须幂等、可回滚测试。
10. 对 URL、header、body preview 做字段级裁剪、高熵 secret 检测和 canonicalization；真实 query value 不再作为 normalized identity 的一部分。

## 预计改动位置

- `packages/contracts/src/application.ts`、`vulnerability.ts`；
- `packages/db/src/schema.ts`、`migrations.ts`、`repository.ts`；
- `packages/application/src/inventory-service.ts`；
- DB/repository/Application tests；
- `docs/architecture/data-model.md`。

## 测试与证据

- 同 route/method 的 JSON、form、XML variant 可共存，多来源重复导入幂等；
- 跨 Scan 数据严格隔离，旧库迁移和重复迁移成功；
- query/header/cookie/body 中 sentinel secret、高熵 token、Authorization 值不落库；
- Renderer/Agent 伪造 reviewed/executionClass/module version 失败；
- 缺失历史 module version 的 Scan 不会偷偷用最新版本恢复；
- opaque identity/session/test-object ref 可稳定参与后续 hash，且不包含 Cookie、Token、CSRF 或真实对象内容；
- 运行 contracts、DB、Application 针对性测试和 `pnpm typecheck`，网络调用数为 0。

## 合格交付

仓库只有一套可追溯 Inventory 真源；所有发现方式都能写入它，而执行资格、模块版本和数据最小化不会由来源自行决定。
