# Day 13：Policy-mediated SPA 动态发现、统一 Producer Merge 与 DependencyGraph

## 当天目标

在固定 fixture 上建立受策略控制的 SPA 运行期发现闭环：浏览器仅消费 Day12 已冻结的 `AssetManifest`，所有导航、子资源和 fetch/XHR 网络都经同一个 `ExecutionPort -> SecurityPolicy -> ExecutionLease -> 原子预算 -> Evidence` 链路；随后把 seed、离线导入、静态分析和动态结果确定性合并到唯一 Inventory，并依据已冻结 ExtractionRule 构建可审计 DependencyGraph。当天不新增 Renderer UI，也不声称支持任意登录 SPA 或所有复杂协议。

## 前置依赖

- Day3 的唯一 Inventory、review 状态和 provenance 模型已经可用；
- Day4～Day6 的 RequestIntent/RequestCompiler、单一 ExecutionPort、SecurityPolicy、ExecutionLease、原子请求/字节/并发预算与 Evidence 链已经通过并发和 redirect 测试；
- Day9 的 SessionVault、Identity generation 与 CSRF 生命周期可供只读 fixture 使用；
- Day10 的可信 Approval 能力存在，但本日动态“发现”不会借 Approval 自动发送未知写动作；
- Day11 的离线 import producer 与 Day12 的 `StaticDiscoveryCandidateBatch`、冻结 `AssetManifest`、冻结 `ExtractionRule` 已准备完成；
- fixture 的 Scope、允许 identity、资源 hash、read-only endpoint 和清理状态可验证。

## 必须完成的工作

1. 定义 `BrowserNetworkBroker` port。Chromium 的 navigation、subresource、fetch/XHR 候选先转换为 `RequestIntent`，再经统一 Scope/Capability 判定、原子预算预留、ExecutionLease 和唯一 ExecutionPort 执行；响应写 Evidence 后才能 `route.fulfill`。Browser 不能直接调用 socket、HttpRunner 或目标地址。
2. 浏览器进程默认零直连。阻断 Service Worker、download、popup、extension、外部协议、WebRTC、QUIC、DNS prefetch/speculation、持久 profile 与未支持的 WebSocket transport；系统级 egress recorder 必须能发现任何绕过 Broker 的连接。
3. 浏览器只能加载 Day12 冻结 `AssetManifest` 中 exact origin/path/resource type/hash/SRI/预算均匹配的资源。manifest 缺失、版本变化、scope snapshot 变化、动态新 origin、redirect 到私网/越界地址或内容 hash 不符时失败关闭，不得临时放宽或在线补 manifest。
4. 首批仅在固定 fixture 执行 reviewed GET/HEAD navigation、manifest 内 script/style/image/font 与已确认只读的 fetch/XHR。未知 GET 先盘点；未知或副作用不明的 POST/PUT/PATCH/DELETE、Beacon、form submit、GraphQL mutation、callback/webhook 只写 Inventory 并进入 awaiting-review，绝不为了“发现接口”而发送。
5. 每次浏览器网络动作必须绑定 scope snapshot、policy decision、lease id、request hash、session/identity generation、预算 reservation、redirect hop 与 evidence ref。请求完成、取消、超时和异常均释放/结算预算，不能出现浏览器私有计数器或第二套执行真相。
6. Set-Cookie 只写入 SessionVault 的受控 sink；浏览器不保留不可审计的第二 Cookie jar。依赖 localStorage/document.cookie token 且无法映射到 SessionVault 的请求标记 unsupported/inventory-only，不允许把值复制进普通日志或 Inventory。
7. 记录 page/frame、initiator、resource type、method、sanitized URL、body shape、response content type/status、source refs 与 capability verdict。DOM、script、response、console 和页面指令均是不可信输入，送模型前必须裁剪、脱敏并保留来源。
8. 建立唯一 `InventoryMergeService`，合并 seed、Day11 OpenAPI/HAR/Postman/GraphQL、Day12 HTML/form/JS/source map 和 Day13 BrowserRecon producer。canonical key 相同只合并 operation 身份，保留全部 source/provenance、互异 Variant、能力状态与冲突；任何 producer 都不能覆盖更严格的 Scope/review/execution class。
9. 生成 `InventoryMergeReport`：按 producer 和 capability 统计新增、合并、冲突、拒绝、超范围、secret-redacted、inventory-only、awaiting-review 与 unsupported 数量，并使报告计数可与数据库确定性对账。
10. 基于 Day12 已冻结 ExtractionRule 建立最小 `DependencyGraph`：request variable、identity/session、CSRF、test object 和 workflow prerequisite。检测循环、缺值、stale evidence、跨 identity/tenant 引用、secret sink 错配与版本漂移；任一问题都暂停相关 plan，不由 Agent 猜值补全。
11. Agent/Knowledge 可以建议新的 rule 或 dependency edge，但 Application 只接受 schema 合法、source 可追溯、Scope 一致且经人工/fixture review 的候选。新候选必须回到 review/freeze 流程，不能在当前浏览器运行中即时生效。
12. 现有离线 BrowserRunner 继续只负责惰性 XSS Evidence；BrowserRecon 使用独立 capability 和调用路径，两者共享统一 policy/evidence 基础设施但不能互相冒充或复用越权 lease。
13. WebSocket、SSE、SOAP/WSDL、gRPC/gRPC-Web、AsyncAPI、GraphQL mutation/subscription、callback/webhook 等没有完整 runner/compiler/policy/fixture adapter 的能力，只合并 endpoint/schema/hint 到 Inventory；发现 URL 不等于支持连接、重放或主动验证。
14. 不新增 Renderer 页面、控制按钮或 IPC 能力。动态发现由后端 fixture harness/integration test 驱动；现有前端只需保持 build、启动和基本导航可用。

## 预计改动位置

- `packages/browser-runner/src/browser-network-broker.ts`、`browser-recon-service.ts`、network hardening；
- `packages/contracts/src/browser.ts`、`discovery.ts`、`inventory.ts`、`workflow-dependency.ts`；
- `packages/application/src/browser-recon-service.ts`、`inventory-merge-service.ts`、`dependency-graph-service.ts`；
- `packages/security-policy`、execution lease/budget integration：仅复用统一链路，不建立浏览器特例出口；
- `packages/db/src/schema.ts`、migration/repository：merge report、dependency graph 与动态 provenance；
- fixture Browser/HTTP/Policy/Application/DB integration tests 与系统级 egress tests；
- `docs/security/threat-model.md`、`docs/architecture/overview.md`、`data-model.md`、`agent-system.md`。

## 测试与证据

- fixture SPA 的 route、manifest asset、read-only fetch/XHR 被发现，page/frame/initiator/provenance 正确；
- POST/PUT/PATCH/DELETE、Beacon、form submit、GraphQL mutation、WebSocket/WebRTC、popup、download、Service Worker 与外部协议全部只盘点或阻断，目标端断言未收到未知写请求；
- 动态跨 origin、scope 外资源、redirect 私网、manifest/SRI/hash/version 漂移均失败关闭；
- egress recorder 证明除 Broker 到唯一 ExecutionPort 的受控 loopback/IPC 通道外没有浏览器网络出口；每个实际目标请求都能反查 policy、lease、预算和 Evidence；
- 并发 navigation/fetch、cancel、timeout、redirect 与 crash 测试证明预算原子预留、准确结算且无负数/泄漏；
- Cookie/session generation 一致，secret 不进入 Inventory、merge report 或普通日志；
- 多 producer 同 operation、多 Variant、冲突 scope、不同 execution class 和重复重放的 merge 测试不丢 provenance，`InventoryMergeReport` 与数据库计数一致；
- DependencyGraph 对正确链路、循环、缺值、stale source、跨 identity/tenant、CSRF 过期与 secret sink 错配均有测试，失败时不会发出后续请求；
- 运行 Browser/HTTP/Policy/Application/contracts/DB integration tests、`pnpm typecheck`，并运行现有 Renderer build/smoke 验证前端没有回归。

## 合格交付

- 固定 SPA 的运行期 HTTP 交互能在零直连条件下被安全盘点，所有实际网络均有单一 ExecutionPort、Policy、Lease、原子预算与 Evidence 证据链；
- 浏览器严格消费冻结 AssetManifest，不能自行加载未批准资源或把未知写动作当作发现手段；
- 所有 producer 通过唯一 merge 服务进入 Inventory，DependencyGraph 只使用已冻结、可追溯的 ExtractionRule，Agent 无法凭语义猜测业务因果；
- 未实现复杂协议仅标记 inventory 能力，不虚构执行覆盖；不新增 Renderer UI，相关后端测试、类型检查与现有前端 build/smoke 全部通过。
