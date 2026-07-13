# Day 12：HTML/JavaScript/Source Map 静态发现、AssetManifest 与 ExtractionRule

## 当天目标

建立完全离线的静态发现生产者：只消费已经导入或已有 Evidence 引用的 HTML、JavaScript 和 Source Map 字节，提取接口候选、资源关系与跨请求取值规则候选，并冻结供 Day13 浏览器使用的 `AssetManifest`。本日没有浏览器导航、HTTP 请求、DNS 查询、远程 source map 下载或其他网络行为，也不负责跨生产者的最终合并与 DependencyGraph 构建。

## 前置依赖

- Day3 的 Inventory/source/provenance schema 与 Scope 规范化能力可复用；
- Day11 已能把离线 API 描述和已提供流量写入 Inventory，并为每份 artifact 提供 hash、媒体类型、来源和 scope verdict；
- Evidence store 能按不可变 ref 读取受控字节，并在读取时复核内容 hash；
- Parser 资源预算、secret classification 与日志脱敏规则可用；
- Day13 尚未启动真实浏览器，`AssetManifest` 必须先完成 review 和冻结。

## 必须完成的工作

1. 定义静态发现输入契约。分析器只接受不可变 artifact/evidence ref、期望 hash、媒体类型、base URL hint、scope snapshot 和资源预算；不得根据 HTML/JS 中的 URL 自行下载缺失资源。
2. HTML parser 盘点 link、form、script、iframe、manifest、base、meta refresh、source map hint、安全相关 meta、内联事件与表单 method/body shape。发现的 URL 全部规范化并经过 Scope，默认只生成 `inventory-only` candidate。
3. 对已有 JavaScript 字节做有界静态提取：fetch/XHR URL、route template、GraphQL endpoint/operation name、WebSocket/SSE URL、sourceMappingURL、API base hint 与明显参数名；不得执行 bundle、动态 import、eval、WASM 或构建脚本。
4. 对已有 Source Map 做有界解析，并保持 generated file、source、line/column 与 candidate 的 provenance。`sourceMappingURL` 只形成待提供资源引用；inline data URL 必须经过大小与媒体类型限制，远程 map 永不自动获取。
5. 建立 parser 限额：单文件与总字节数、AST 节点数、解析时间、递归深度、source 数、字符串候选数、正则步骤与 worker memory。minified、obfuscated、损坏和超限输入返回 confidence/warning，不得回退为无界正则扫描。
6. 产出版本化 `StaticDiscoveryCandidateBatch`。本日只允许同一 artifact 内按确定性 key 去重，不执行 seed、Day11 import、历史 Inventory 与动态浏览器结果之间的全局覆盖或合并；跨生产者 merge 统一留给 Day13。
7. 建立并冻结 `AssetManifest`：每个允许 Day13 加载的资源必须绑定 exact origin、normalized path、resource type、artifact/source ref、content hash、可选 SRI、最大响应字节、scope snapshot、reviewer/fixture attestation 和版本。query 中的 secret 必须先裁剪，通配 origin/path 与未定 hash 默认不合格。
8. 明确浏览器消费约束：Day13 只能消费已冻结且 hash/reviewer/scope 未变化的 AssetManifest；静态发现中新出现但未 review 的资源只能进入 candidate，不能因为被页面引用就获得联网资格。
9. 定义 `ExtractionRule` candidate：source step/response、JSON Pointer、header/cookie、HTML selector、受限 regex capture、类型、validation、secret classification、target variable、identity/tenant scope、版本与 source ref。Agent/Knowledge 只能建议，Application 经过 schema、来源与人工/fixture review 后才能冻结规则。
10. 疑似 secret 只记录分类、位置与受保护 Evidence ref，不在 Inventory、日志或报告复制完整值，也不自动尝试该凭据。页面文本、脚本注释和 source map 内容全部是不可信数据，不能提升为 Agent 指令。
11. 对 GraphQL、WebSocket、SSE、SOAP/gRPC endpoint 或 callback/webhook 只能输出接口 hint 和 `inventory-only` 能力状态；本日没有对应协议 adapter、握手、订阅、重放或主动测试，因此不得宣称执行支持。
12. 不新增 Renderer UI、IPC 或浏览器控制入口；现有 Renderer 只做兼容性 build/smoke，静态发现通过后端测试 harness 调用。

## 预计改动位置

- `packages/contracts/src/discovery.ts`、`inventory.ts`、`extraction-rule.ts`、`asset-manifest.ts`；
- `packages/application/src/discovery/static/**`：HTML、JS、Source Map parser 与 candidate producer；
- `packages/application/src/asset-manifest-service.ts`、`extraction-rule-service.ts`：review、freeze 与版本校验；
- `packages/db/src/schema.ts`、migration/repository：artifact provenance、manifest/rule 版本与审计；
- parser、resource-limit、secret-redaction、manifest freeze integration tests；
- `docs/architecture/data-model.md`、`docs/security/threat-model.md`：零网络边界与不可信内容规则。

## 测试与证据

- HTML/JS/source map 的普通、minified、obfuscated、损坏、恶意、超限、跨域与错误媒体类型样例；
- 静态分析期间 DNS、HTTP、浏览器和模型调用计数均为 0，JS/WASM 不被执行，远程 source map 不被下载；
- base URL、relative URL、meta refresh、form、inline map、SRI 和 scope 外资源均有规范化与拒绝测试；
- AssetManifest 对 hash、SRI、scope snapshot、reviewer、资源类型、响应上限任一变化均失败关闭；未冻结 manifest 不能被 Day13 接受；
- ExtractionRule 的类型错误、secret、非法 selector、灾难性 regex、跨 identity/tenant、过期 source 与未 review 状态均不能冻结；
- `StaticDiscoveryCandidateBatch` 保留精确 source location，且只做 artifact 内去重；测试证明没有提前执行跨 producer 覆盖；
- 运行 static discovery、contracts、Application、DB tests 与 `pnpm typecheck`，并执行现有 Renderer build/smoke 证明未破坏前端可用性。

## 合格交付

- 给定离线 HTML/JS/Source Map，系统能在零网络、零代码执行前提下产出可追溯接口候选与规则候选；
- Day13 所需 AssetManifest 已经按精确资源、hash、Scope 和 reviewer 冻结，浏览器不能自行扩大资源集合；
- 静态生产、全局 merge、动态浏览器和依赖图职责清晰分离，没有同一能力在 Day12/Day13 重复实现；
- 对复杂协议只诚实标注 inventory 能力，不新增 Renderer UI，相关测试、类型检查与前端兼容性验证通过。
