# Day 4：纯请求编译、三阶段哈希与 EvidenceCapturePolicy

## 当天目标

在完全不联网的条件下，把 reviewed Variant 与 selector 变成确定性 RequestIntent，并确保未来批准内容、opaque identity/session/test-object 引用和最终 wire bytes 都可验证；先解决“批准 A、执行 B”和原始响应过量保存问题。Day4 不实现 SessionVault、CSRF 提取器或 TestObject 服务。

## 必须完成的工作

1. 实现无 I/O `ProbeRequestCompiler`，支持 query/path/header/cookie/form/JSON Pointer；XML/multipart/GraphQL/WebSocket 先提供类型和拒绝路径，不做半实现。
2. 定义三个不可混用的摘要：
   - `TemplateIntentHash`：variant/version、selector、mutation generator/version、结构；
   - `ResolvedIntentHash`：Day3 opaque identity/session generation/test-object ref、动态变量槽位及其 resolver version 解析后的结构；
   - `WireRequestHash/HMAC`：实际 URL、method、最终 header 名和值摘要、body bytes。
3. canonicalization 明确 URL 编码、重复 query、header 大小写/顺序、JSON key 顺序、空值、Unicode、content-length 和 redirect 后重编译规则；歧义输入 fail closed。
4. 先定义 `SecretRefResolver`/`DynamicValueResolver` port；测试使用不含真实 secret 的内存替身。真实 SessionVault、Cookie/Token 与 CSRF resolver 到 Day9 才接入；hash/HMAC 和日志不得反推出 secret。
5. 定义 `MutationGenerator` metadata：generatorId/version、结构化安全语义、禁止 capability、最大长度、编码支持；不能只依赖自然语言 `payloadSummary` 判断安全。
6. 建立 `EvidenceCapturePolicy`：按 technique/step/response type 定义状态、长度、时间、选定 header/字段、hash、DOM/screenshot/OOB role；原始 body 默认不保存，必要原件放受保护 Evidence 并生成脱敏派生。
7. 对响应大小、二进制、压缩、非 UTF-8、JSON/XML 解析失败、敏感字段和超大 DOM 定义裁剪/哈希/终止行为。
8. 现有四类 Request 构造通过 compatibility adapter 调用新 Compiler，但 Coordinator 暂不改变联网路径。

## 预计改动位置

- `packages/contracts/src/security.ts`、`application.ts`、`vulnerability.ts`；
- `packages/application/src/request-compiler.ts`、`evidence-capture-policy.ts`；
- `packages/domain/src/vulnerabilities/**`；
- compiler/evidence policy tests；
- `docs/security/threat-model.md`、`docs/architecture/data-model.md`。

## 测试与证据

- 每种已实现 selector 的编码、重复参数、Unicode、空值和 invalid pointer；opaque ref/version 变化必须可检测；
- template/resolved/wire 任一字段变化都使对应 hash 变化，稳定输入重复 hash 一致；
- secret sentinel 不出现在结构化日志、DB fixture、错误和测试快照；
- raw body 默认不保存，允许保存时有 Evidence role、加密/访问边界、hash 和脱敏派生；
- 未实现 codec/transport、歧义 canonicalization、未知 generator/capability 全部拒绝；
- 运行针对性单测、`pnpm typecheck`；网络调用数为 0。

## 合格交付

任何后续模块只能通过同一纯 Compiler 和 EvidenceCapturePolicy 形成请求/证据；批准与最终 wire request 之间已有可验证的确定性绑定。
