# Day 11：离线接口描述导入与统一 Inventory 写入

## 当天目标

建立仅在后端运行、全程零网络的接口描述导入管线，把人工提供的 OpenAPI、HAR、Postman 与 GraphQL 描述安全地转换为统一 Inventory 数据。导入只解决“系统知道有哪些接口、字段和来源”，不代表这些接口已经具备重放、认证、主动验证或漏洞判定能力；当天不新增文件选择器、导入页面或其他 Renderer UI。

## 前置依赖

- Day3 的 `Inventory`、`Operation`、`RequestVariant`、`SourceRef`、Scope 判定与 review 状态已落库，并有唯一写入端口；
- Day4～Day6 的 RequestCompiler、ExecutionPort、Lease 与预算模型已经存在，但本日导入服务不得调用它们；
- Day8～Day10 的 TestObject、Session/Identity/CSRF 与 Approval 能力已经建立，但导入文件中的认证信息不能直接进入这些可信域；
- 文件内容由后端可信入口以 bytes 或受控 artifact ref 提供；Renderer 不获得文件系统访问能力；
- 所有 parser 版本、格式支持范围和资源上限已经写成可审计配置，缺失配置时失败关闭。

## 必须完成的工作

1. 建立 `ImportPreview -> Commit` 两阶段服务。Preview 只解析、脱敏并返回 operation、variant、source、安全方案、unsupported feature 与 warning；Commit 必须重新校验 scan/workspace 状态、scope snapshot、源 bytes hash、parser version、preview 版本和有效期，任一变化均拒绝提交。
2. 首批完成并分别测试 OpenAPI 3.0、OpenAPI 3.1、Swagger 2.0、HAR 1.2 与 Postman Collection v2.1 的离线 adapter；每个 adapter 必须发布 machine-readable supported profile。OpenAPI 3.1 明确列出支持的 JSON Schema 2020-12 dialect/keyword 子集，Swagger 2.0 明确 host/basePath/schemes/body/security 转换边界；遇到影响语义的未支持字段必须逐项 warning 或拒绝，不能声称完整规范兼容。GraphQL SDL 和用户提供的 introspection result 只提取 type、field、operation、argument/variable 与 endpoint hint，不主动发送 introspection query。
3. 对尚未完整实现的复杂接口 adapter 明确返回能力状态。AsyncAPI、SOAP/WSDL、protobuf descriptor、gRPC reflection export、WebSocket、SSE、callback/webhook 等即使能解析部分描述，也只能产出 `inventory-only` 条目和 unsupported warning；没有经过独立 compiler、runner、policy 与 fixture 验证前，不得标记 replayable 或 executable。
4. 设置格式白名单以及文件大小、文档深度、对象数、operation 数、字符串长度、YAML alias/anchor、压缩包展开比和总解析时间限制。禁止远程 `$ref`、外部实体、模板脚本、插件加载、网络 schema resolution 和其他 parser side effect。
5. OpenAPI server/path、HAR URL、Postman base variable、GraphQL endpoint hint 均经过规范化与 Scope 判定。超范围条目只进入 rejected preview 统计并保留脱敏来源，不写入可 review 的 Variant；相对地址无法确定可信 base 时保持 unresolved。
6. Authorization、Cookie、API Key、Token、密码和真实请求/响应 body 默认裁剪。仅保存 header 名、body schema/shape、参数位置、示例值类型及有长度上限的 sanitized preview；任何 sentinel secret 都不能出现在普通日志、preview、Inventory 或报告字段。
7. 所有导入 Variant 初始均为 `inventory-only/unreviewed`。导入文件声明的安全级别、扩展字段或 vendor metadata 不能自报 reviewed；只有 Day3 的确定性 `reviewVariant` 流程才可能授予 execution class。
8. 统一记录 source hash、媒体类型、parser 名称与版本、原始 operation ref、source confidence、import actor、scope verdict、warning 和 audit ref。重复 Commit 必须幂等，多来源只追加 provenance，不允许后来文件静默覆盖已有来源或 review 结论。
9. 建立确定性字段映射：OpenAPI security scheme、server、parameter、requestBody content type、response schema；HAR initiator、method、URL 与 body shape；Postman variable/collection hierarchy；GraphQL operation/type/variable。每个无法保真的字段必须有明确 warning code 和原 source location。
10. Application API 只接受 bytes 或受控 artifact ref；本日通过 integration test、后端 CLI 或测试 harness 调用。不得新增 Main 文件对话框、IPC 扩展或 Renderer View，也不得为了导入方便让 Renderer 直接访问文件系统。

## 预计改动位置

- `packages/contracts/src/import.ts`：preview、commit、adapter capability、warning 与 provenance schema；
- `packages/application/src/import-service.ts`、`packages/application/src/importers/**`：两阶段服务和各格式 parser；
- `packages/db/src/repository.ts`、schema/migration：复用统一 Inventory port，保存 import audit 与幂等键；
- `packages/security-policy`：只复用 Scope 判定，不增加导入专用网络例外；
- parser、Application、DB integration tests 和离线恶意样例；
- `docs/architecture/data-model.md`、`docs/user-guide.md`：记录“发现/盘点不等于执行支持”的边界。

## 测试与证据

- 每种已声明支持格式及 supported profile 均有最小、复杂、多 server、多 content type、错误编码、损坏、恶意和超限样例；OpenAPI 3.1/Swagger 2.0 未支持关键字不得静默丢弃；
- remote `$ref`、YAML bomb、深层 JSON、巨量 operation、外部实体、压缩炸弹和 parser timeout 均失败关闭；
- Authorization/Cookie/body sentinel 不落库、不进入 preview、普通日志或错误堆栈；
- Scope 外 operation、未知 scheme/codec、unresolved base 和 unsupported GraphQL/复杂协议只产生可定位的拒绝或 warning，不被静默升级；
- preview hash 不一致、preview 过期、scan 状态变化、parser version 变化、重复 commit 和多来源 commit 均有确定性测试；
- network spy/egress recorder 证明 preview 与 commit 的网络请求数均为 0；
- 运行 import parser、Application、DB、contracts 测试以及 `pnpm typecheck`，保存命令、退出码和测试报告引用。

## 合格交付

- 已声明支持的离线描述能安全、幂等、可追溯地进入唯一 Inventory；
- 任何来源都不能夹带凭据、绕过 Scope、触发网络或自我授予执行能力；
- 每一种复杂接口都能从 capability/warning 看出“已完整解析、仅部分盘点或未支持”，不会把 adapter 存在误写成执行或漏洞验证支持；
- Renderer 保持现有可用状态且没有新增 UI；相关后端测试、`pnpm typecheck` 与现有前端 build/smoke 均通过。
