# 复杂 Web/API 接口能力矩阵（Day 0）

> 状态：规划基线，不代表已经实现
> 基线日期：2026-07-13
> 适用范围：后端发现、导入、重放、主动验证、会话、鉴权、流式传输与受控回连能力
> 前端边界：20 个工作包只保持现有 Renderer 可用；本矩阵不承诺新增导入、审批或协议调试页面

## 1. 使用规则

本矩阵解决“系统能否处理复杂 Web 接口”这一问题，但不能把“看见一个 URL”写成“支持该协议”，也不能把通用 HTTP Runner 能发送字节等同于已经支持 REST、GraphQL、SOAP、gRPC 或 WebSocket。

对外宣称某项接口“支持”前，必须同时给出以下证据：

1. **发现或导入证据**：输入格式、版本、限制、来源和 Scope 判定均可追踪；
2. **规范化证据**：接口被写入唯一 Inventory，保留 operation、variant、selector、codec、provenance 和 parser version；
3. **重放证据**：实际请求由冻结的 `RequestIntent` 编译，经过 Policy、预算、单次 Lease 和请求哈希复核；
4. **会话与鉴权证据**：secret 仅进入受控 sink，identity/session generation 可追踪，跨身份不会复用旧 grant；
5. **协议证据**：所需 transport、codec、stream state 或 callback state 由专用 adapter 处理，而不是由普通 HTTP 请求“近似代替”；
6. **验证证据**：至少包含正例、异质负例、Inconclusive、停止条件、Evidence profile、安全门禁和三次确定性复跑；
7. **发布证据**：Capability/Module Conformance、迁移恢复、secret scan、`pnpm check` 和相关集成测试通过。

缺少任意一项时，只能使用更窄的事实描述，例如“已离线导入”“已盘点 endpoint”“仅固定 fixture 可重放”或“尚不支持”，不得使用笼统的“支持该协议”。主动验证能力还必须按具体漏洞 Technique 单独声明；协议可重放不等于该协议上的所有漏洞都可验证。

## 2. 状态代码与八个能力维度

| 代码 | 含义 |
|---|---|
| `N` | 未实现；必须明确拒绝或报告 unsupported |
| `I` | 只盘点/只导入；不会自动发包 |
| `R` | 仅人工 review 后可确定性重放 |
| `L1` | 可执行低影响、只读、范围内的主动验证 |
| `L2` | 仅测试对象、逐次可信批准、可回退并完成 cleanup-verify |
| `F` | 只允许固定版本、隔离且具 attestation 的 fixture |
| `P` | 只有局部底座，尚未形成该接口的端到端能力 |

八个能力维度分别是：

- **Discovery**：从 seed、HTML、JavaScript、运行期浏览器或协议描述中发现接口；
- **Import**：从文件或 bytes 安全解析并写入 Inventory；
- **Replay**：由冻结模板和依赖确定性重放，不是复制原始流量；
- **Active validation**：为具体漏洞 Technique 产生对照请求、观察和三态结论；
- **Session**：Cookie、Bearer、CSRF、刷新、过期和 generation 生命周期；
- **Auth**：security scheme、身份矩阵、对象/字段/功能授权语义；
- **Streaming**：连接、帧/消息、背压、时长、重连和消息预算；
- **OOB**：由 AgentGo 控制的唯一回连标记、注册、轮询、消费和归因。

## 3. 当前 V1 的真实基线

截至本基线，仓库中的 V1 具备普通 HTTP GET、重定向逐跳检查、DNS 地址固定、超时/响应大小限制、静态 Cookie/Bearer 测试身份、HTML link/form 盘点和断网 `setContent` 浏览器检查。主动验证只覆盖 `sqli`、`xss`、`ssrf`、`idor` 四类的有限 GET/query 场景；IDOR 使用两个授权测试身份和已知测试资源 ID。HTTP Runner 虽然接受 body，但当前 Coordinator 没有通用 body/codec/selector 编译链。

V1 **没有** OpenAPI/HAR/Postman/AsyncAPI/WSDL 导入器，没有 GraphQL、SOAP、gRPC、WebSocket、SSE 或 raw HTTP 专用 adapter，没有真实流式状态机，也没有真实 OOB Collector。现有 SSRF 是响应内受控 proof，不应写成已支持 OOB。现有 Browser Runner 完全断网，不是登录 SPA 的运行期浏览器自动化。

## 4. 总览矩阵

下表中的“20 包”表示完成全部二十个顺序工作包并通过对应门禁后的目标，不表示 Day 0 或当前代码已经具备。`W1`～`W7` 指二十个工作包之后的长期波次，顺序固定为：W1 被动姿态，W2 身份/Session/JWT-OAuth-SAML/授权，W3 GraphQL/WebSocket/Webhook/SSE/SOAP/gRPC/AsyncAPI，W4 业务状态/多租户/工作流/竞态，W5 注入，W6 文件/XML/浏览器客户端，W7 协议实验/组件供应链/LLM/长期评测。

| 接口族 | 八维目标摘要（Discovery / Import / Replay / Active / Session / Auth / Streaming / OOB） | 当前 V1 | 20 工作包合格交付 | 20 包后波次 |
|---|---|---|---|---|
| 普通 REST/HTTP API | `I / N / P / GET-L1 / P / P / N / N` → `I / I / R / L1+受限L2 / R / R / N / 受控` | HTML/URL/query 局部盘点；四类 GET/query 验证 | 统一 Inventory、reviewed RequestIntent、form/JSON、会话/Lease/Evidence 闭环；只按已迁移 Technique 声明主动能力 | W1 被动姿态；W2 身份授权；W4 状态工作流；W5 注入；W6 浏览器客户端 |
| OpenAPI 3.0 | `N` → `I / I / 条件R / 按Technique / security scheme映射 / schema级 / N / callbacks仅盘点` | 未实现 | Day11 离线 preview/commit；常见 path/parameter/requestBody/security 映射；review 后才可能执行 | W1 扩大被动/schema；W2 auth flow；W3 callbacks；W4 links/工作流 |
| OpenAPI 3.1 | `N` → `I / I(声明子集) / 条件R / 按Technique / 映射 / schema级 / N / callbacks仅盘点` | 未实现 | 支持的 JSON Schema 2020-12 子集必须列清；不支持关键字逐项 warning，禁止声称完整 3.1 | W1 dialect/schema；W2 auth；W3 webhooks；W4 links/工作流 |
| Swagger/OpenAPI 2.0 | `N` → `I / I(声明子集) / 条件R / 按Technique / 映射 / schema级 / N / N` | 未实现 | host/basePath/schemes、parameters/body/security 的确定性转换；不能转换的条目拒绝或 warning | W1 兼容/被动；W2 鉴权流 |
| HAR 1.2 | `N` → `N / I / 条件R / 按Technique / secret ref / header级 / N / N` | 未实现 | 零网络导入；原始 Cookie/Auth/body 默认裁剪；单条 Variant review 后重编译，不盲目原样重放 | W1 被动导入；W2 登录态；W4 跨请求依赖 |
| Postman Collection 2.1 | `N` → `N / I / 条件R / 按Technique / 变量转受控ref / scheme级 / N / N` | 未实现 | collection/folder/request/variable 的安全子集；禁用 pre-request/test script 和动态模板执行 | W1 静态导入；W2 auth flow；W4 reviewed 工作流，脚本仍不执行 |
| GraphQL | `N` → `I / SDL或离线introspection-I / N / N / P / schema级 / N / N` | 未实现 | Day11/13 仅盘点 operation/type/variable/endpoint；Day4 明确拒绝 GraphQL 主动编译 | W3 query/mutation/subscription、field auth、cost 与 L1/L2 |
| SOAP/WSDL | `N` → `N / N / N / N / N / N / N / N` | 未实现 | 只注册类型/拒绝路径；不得因普通 HTTP/XML 可见而声称 SOAP 支持 | W3 SOAP/WSDL 协议闭环；W6 深化 XML 漏洞与解析差异 |
| gRPC | `N` → `N / N / N / N / N / N / N / N` | 未实现 | fail closed；不接受 `.proto`、reflection 或 HTTP/2 通用能力冒充 gRPC | W3 独立 gRPC 协议子波次 |
| gRPC-Web | `N` → `I(仅URL/Content-Type) / N / N / N / P / P / N / N` | 未实现 | Browser/JS 可盘点候选，但不解码 protobuf 帧、不重放 | W3 protobuf/frame/stream；W6 浏览器 Broker 集成加固 |
| WebSocket | `N` → `I(URL) / N / N / N / P / P / N / N` | 未实现 | Day12 静态盘点 URL，Day13 记录动态 intent/initiator 但阻断浏览器直连；无 handshake/message 主动测试 | W3 handshake/消息/授权；W6 浏览器客户端集成 |
| SSE | `N` → `I(URL) / N / N / N / P / P / N / N` | 未实现 | 只盘点；普通 HTTP Runner 不作为 SSE adapter，不建立长连接 | W3 只读连接授权与流状态机；禁止高持续压测 |
| OpenAPI callbacks / Webhooks | `N` → `I / I / N / 仅OOB步骤 / P / P / N / 受控` | 无真实 Collector | 描述中的 callback/webhook 只盘点；Day19 受控 OOB 只服务 SSRF technique，不自动注册目标业务 webhook | W3 callback/webhook 协议与授权；W4 业务副作用状态机 |
| AsyncAPI | `N` → `N / N / N / N / N / N / N / N` | 未实现 | 明确 unsupported；不能用 WebSocket URL 发现冒充 AsyncAPI 支持 | W3 parser、channel/message 和准入 binding；非 Web binding 仍受限 |
| HTML form（urlencoded） | `I / N / N / N / P / N / N / N` → `I / N / R / 受限L2 / R / P / N / N` | 可盘点 form；不提交 | form selector/codec、CSRF 依赖、TestObject、逐次批准、cleanup；参考 SQLi 模块覆盖 | W1 被动盘点；W2 session/CSRF/授权；W4 工作流；W5 注入 |
| multipart/form-data | `N` → `I(结构) / N / N / N / P / N / N / N` | 未实现 | Day3 只建 selector/codec 类型，Day4 拒绝编译；不上传文件 | W6 惰性无害文件、存取 oracle、解析差异与 cleanup |
| 浏览器 SPA | `P / N / 离线P / XSS局部 / N / N / N / N` → `I(固定fixture) / N / 只读R / 离线XSS / R / P / N / N` | 断网 DOM 检查和惰性 XSS marker；非真实 SPA | Day12 冻结 AssetManifest；Day13 Broker 盘点固定 fixture 的 navigation/assets/fetch/XHR，所有网络经 Policy，写动作和 WebSocket 阻断 | W6 登录 SPA、固定 replay bundle、DOM/source-sink 与客户端风险 |
| raw HTTP/1.1/HTTP2 fixture | `N` → `N / N / N / N / N / N / N / N` | 未实现 | 只保留 capability/type 和 fail-closed 门禁；20 包内不创建 production adapter | W7 仅独占、隔离、attested fixture |

## 5. 各接口族详细验收卡

### 5.1 普通 REST/HTTP API

- **发现/导入**：seed、HTML link/form、OpenAPI、HAR、Postman、BrowserRecon 和 JS producer 必须写入同一 Inventory；同一 route/method 的 JSON、form、XML variant 不得互相覆盖。
- **重放/主动验证**：只有 reviewed Variant 能编译。GET/HEAD 可进入 L1；POST/PUT/PATCH 必须按实际副作用判级，只有绑定专用 TestObject、批准和 cleanup 的 L2 才能执行。Method 名称或 `/query` 路径不能证明只读。
- **会话/鉴权**：静态 Cookie/Bearer 要迁入 SessionVault；CSRF 和跨请求提取必须由 review 后的 ExtractionRule 产生；切换 identity 或 refresh 后旧 Lease 失效。
- **流/OOB**：普通 HTTP response body 不是流式协议；仅 callback step 可进入受控 OOB，不接受任意回连地址。
- **20 包证据**：query/path/header/cookie/form/JSON Pointer 编译单测；跨身份、过期 session、redirect、body/hash 篡改负例；L2 pre/post/cleanup-verify；四个 legacy benchmark 不回退。
- **不得宣称**：不能写“支持任意 REST API”“自动理解业务工作流”或“支持所有 body 类型”。

### 5.2 OpenAPI 3.0

- **导入范围**：JSON/YAML、本地 document；servers、paths、operations、parameters、requestBody content type、responses 和 security schemes 映射到 Inventory。远程 `$ref` 永久禁用；本地 ref 必须有深度、节点数和循环上限。
- **重放范围**：导入结果一律 `inventory-only`。只有 scope 内、codec/selector 均受支持且经 review 的 operation 才能生成 RequestIntent；example/default 不自动当作真实 secret 或业务 ID。
- **主动范围**：由已注册 Technique 决定，不由 spec 文件决定。导入文档不能自报“安全测试已授权”。
- **20 包证据**：官方风格 3.0 JSON/YAML 正例；多 server、path-level parameter、requestBody 多 content type、security alternatives；remote ref、循环 ref、YAML bomb、Scope 外 server、secret sentinel 负例；preview/commit 请求数为 0。
- **合格声明**：只有上述字段和测试均通过时可写“支持 OpenAPI 3.0 离线导入”；主动验证须另列具体 Technique。

### 5.3 OpenAPI 3.1

- **关键差异**：必须识别 `openapi: 3.1.x`、`jsonSchemaDialect`、JSON Schema 2020-12 语义和顶层 `webhooks`，不能直接按 3.0 静默解析。
- **20 包范围**：可把 paths/operations/parameters/requestBody/security 的共同子集导入；`unevaluatedProperties`、dynamic ref、复杂 union/conditional 等未实现语义必须逐 operation warning，并阻止依赖这些语义的主动编译。
- **webhooks**：仅形成 callback/channel inventory，不自动向目标注册 webhook，也不自动触发业务事件。
- **证据**：3.1 专属 fixture、dialect 不匹配、复杂 schema、webhooks、混用 3.0/3.1 字段负例；warning 与 rejected operation 数和数据库一致。
- **不得宣称**：共同子集通过不等于“完整支持 OpenAPI 3.1/JSON Schema 2020-12”。

### 5.4 Swagger/OpenAPI 2.0

- **导入范围**：`swagger: 2.0`、host/basePath/schemes、paths、parameters、body/formData、produces/consumes、securityDefinitions；转换必须保存源版本和转换 warning。
- **安全限制**：不自动信任 host 或 scheme；转换后的 URL 重新经过 Scope；`file`、collectionFormat、非标准 vendor extension 和 OAuth flow 未支持时明确拒绝/警告。
- **20 包证据**：body 与 formData、全局/operation security、basePath、数组参数、冲突参数、错误版本和 Scope 外 host；转换前后 operation/selector 计数可核对。
- **合格声明**：只能声明“支持 Swagger 2.0 的已列导入子集”，不能伪装成无损升级到 OpenAPI 3。

### 5.5 HAR 1.2

- **导入**：解析 request URL/method/header 名、query、postData shape、mimeType、response status/content type、initiator/timing 的安全子集；默认不保存真实 body、Cookie、Authorization、Token 或响应对象。
- **重放**：禁止“导入即重放”。选中的 entry 必须重新解析为 Inventory Variant，经 scope、review、secret ref 替换、session generation 和 RequestCompiler 编译；原始 `Content-Length`、Host、Cookie 等不得照抄。
- **证据**：多页/redirect/重复请求、binary body、巨量 entry、损坏 base64、跨域、secret sentinel；import 网络调用为 0；重放请求与冻结 Intent hash 一致。
- **不得宣称**：不能声称 HAR 导入恢复了完整登录态、时间依赖或浏览器行为。

### 5.6 Postman Collection 2.1

- **导入**：支持 collection/folder/request、URL、method、header 名、query、受支持 body shape 和静态变量引用；environment/global/secret 只形成缺失依赖或受控 secret ref。
- **永久边界**：pre-request script、test script、动态 JavaScript、`eval`、任意 package 和网络变量解析都不执行。脚本存在时必须展示 warning，相关 request 默认不可执行。
- **重放/鉴权**：受支持 auth scheme 只映射语义，不保存明文值；review 后由 SessionVault 注入。OAuth 自动登录等复杂 flow 留到 W2。
- **证据**：嵌套变量、循环变量、未定义变量、脚本、文件引用、超限 collection、多 auth scheme；secret 不落普通 DB/日志；重复 commit 幂等。
- **合格声明**：只能声明“Postman Collection v2.1 静态安全子集导入”，不能声明兼容 Postman Runtime。

### 5.7 GraphQL

- **20 包发现/导入**：从离线 SDL、用户提供的 introspection JSON、JS operation name 和 OpenAPI 描述提取 endpoint、operation、type、variable 和来源；不向真实目标自动发送 introspection query。
- **20 包执行**：GraphQL selector/codec 在 RequestCompiler 中明确拒绝，避免半实现；普通 POST JSON 能发送不等于 GraphQL 重放。
- **W3 目标**：规范化 document/variables、query 与 mutation 分级、fragment/alias/depth/cost 上限、field/object/function 授权矩阵、subscription 单独处理。mutation 一律 L2，且仅测试对象；身份与 Session 复用 W2 的统一底座。
- **证据**：introspection disabled、partial schema、custom scalar、fragment cycle、alias/depth、字段级正负身份、mutation cleanup、响应放大停止条件。
- **不得宣称**：未具备 GraphQL document parser、cost 和 field-level oracle 前，不得写“支持 GraphQL 主动扫描”。

### 5.8 SOAP/WSDL

- **20 包状态**：未实现。XML/multipart 类型存在或通用 HTTP 能发送 XML 都不构成 SOAP/WSDL 支持。
- **W3 协议交付**：建立 SOAP 所需的最小安全 XML codec、namespace/XPath selector、WSDL 1.1/2.0、XSD import/include 的离线受限 parser、SOAPAction、binding/style/use 和 WS-Security 声明式模型；W6 再扩展 XXE/XInclude、XML 注入和更广的解析差异 Detector。W3 不得以等待 W6 为由绕过 parser isolation。
- **安全边界**：禁止外部实体、远程 import、任意 schema 下载和真实业务写 operation；含签名/加密的消息不得由通用重写器破坏后继续声称有效验证。
- **合格证据**：WSDL/XSD 循环与 bomb、namespace/binding、SOAP 1.1/1.2、fault、签名负例、零网络 import、fixture 重放和 L2 cleanup。
- **发布口径**：20 包结束仍应显示 `not-supported`，而不是 `inventory-partial`。

### 5.9 gRPC 与 gRPC-Web

- **20 包状态**：gRPC 未实现；gRPC-Web 最多从 JS/BrowserRecon 盘点 URL、Content-Type 和 initiator，不能解码帧或 protobuf。
- **W3 协议交付**：受限 `.proto` 导入、descriptor set、service/method/message schema、unary/client-stream/server-stream/bidi 分类、metadata secret sink、deadline/cancel、HTTP/2 或 gRPC-Web frame adapter；W6 仅负责 gRPC-Web 与真实浏览器 Broker 的客户端集成加固。
- **主动边界**：reflection 不是默认 discovery；streaming/写 method 只能在 attested fixture 或明确测试服务中逐次批准。禁止用大消息、无限流或高并发证明资源耗尽。
- **证据**：unary/stream fixtures、unknown field、oneof、compression、deadline、cancel、metadata auth、跨身份、消息/字节/时长预算和连接清理。
- **发布口径**：只有 URL 盘点时必须写“发现疑似 gRPC-Web endpoint”，不能写“支持 gRPC-Web”。

### 5.10 WebSocket

- **20 包状态**：Day12 可从 JS/source map 静态盘点 WebSocket URL；Day13 的 BrowserNetworkBroker 必须阻断真实浏览器 WebSocket 直连。没有 handshake、frame 或 message adapter，因此 replay/active/streaming 均为 `N`。
- **W3 目标**：handshake origin/subprotocol、Cookie/Bearer session、消息 schema、频道/对象授权、受控 reconnect、有限收发消息和 per-message Evidence。写消息为 L2；W6 再补浏览器页面触发、客户端 source/sink 和 SPA replay 集成。
- **安全边界**：仅测试频道/对象；禁止广播、高频消息、无限订阅和收到真实非测试用户数据后继续；连接、消息数、单帧/总字节、idle/total duration 均有硬上限。
- **证据**：过期 session、跨身份频道、错误 subprotocol、fragment/binary、重连、服务端主动消息、取消/断线恢复和零遗留连接。

### 5.11 SSE

- **20 包状态**：只盘点 URL。普通 HTTP Runner 的一次性 body 读取不提供 event framing、心跳、取消和重连语义，因此不得当作 SSE adapter。
- **W3 目标**：只读连接授权、`Last-Event-ID`、event/id/retry/data 解析、消息/字节/时长预算和确定性取消；默认不做主动写入。
- **安全边界**：禁止高持续连接和压测；收到真实用户事件、超预算、重连风暴或 scope 外 URL 时立即停止并最小化 Evidence。
- **证据**：authorized/unauthorized identities、心跳、分片、断线重连、过期 session、取消和连接泄漏检测。

### 5.12 Callbacks 与 Webhooks

- **导入**：OpenAPI 3.0 callback、3.1 webhook 或其他描述只形成 direction、event、URL template、schema 和依赖 inventory，不授予执行权。
- **20 包 OOB**：`callback-register/poll/consume` 只连接 AgentGo 控制的 Collector，并绑定 scan/candidate/step/token/有效期。Day19 可用于 SSRF 唯一回连证据；不得用于任意业务 webhook 注册。
- **W3 与 W4 分工**：W3 交付 callback/webhook 描述、接收端、鉴权、签名、重放防护和受控 OOB 协议链；创建 subscription、触发订单/支付/通知、接收第三方事件等业务副作用留给 W4 的 SideEffectEnvelope、TestObject 和 cleanup 状态机。
- **安全边界**：callback 地址固定、私网/metadata/用户自填地址拒绝；token 不进模型/报告；重复、迟到、伪造和跨 scan 事件不归因。
- **证据**：唯一 token、错误 token、过期、重复、DNS/HTTP redirect、跨 scan、Collector 不可用、cleanup 与零外部通知。
- **不得宣称**：响应内 URL 回显不是 OOB；成功接收 AgentGo canary 也不等于支持完整 webhook 工作流。

### 5.13 AsyncAPI

- **20 包状态**：未实现，必须 fail closed。发现 WebSocket/SSE URL 或导入 OpenAPI callback 不代表 AsyncAPI 支持。
- **W3 范围**：AsyncAPI 2.x/3.x 必须分别声明；交付 channels、operations、messages、payload/schema、security、correlationId 和经过 allowlist 的 Web 接口 binding。Kafka/AMQP 等非 Web binding 默认只盘点或 fixture-only，不能因 parser 可读就自动连接 broker。
- **执行边界**：本项目是 Web 漏洞系统，非 HTTP broker binding 默认 inventory-only 或 fixture-only；禁止自动连接生产消息队列、发布消息或消费真实用户事件。
- **合格证据**：版本化 parser、远程 ref 禁止、binding allowlist、零网络导入、channel/message 计数、secret scan，以及每种真正交付 binding 的隔离 fixture。

### 5.14 HTML form 与 multipart/form-data

- **HTML form 当前能力**：V1 只能从离线 DOM 盘点 action/method/字段，不提交。20 包内 urlencoded form 通过结构化 selector、CSRF ExtractionRule 和 RequestCompiler 进入 reviewed replay；写操作仅 L2。
- **multipart 当前能力**：20 包只建立类型、selector 和拒绝路径，不实现文件上传。普通 body bytes 或手工拼 boundary 不算支持。
- **W6 multipart 目标**：确定性 boundary、文本字段、惰性无害文件、大小/数量/MIME 上限、专用 TestObject、存储/取回 oracle、派生物盘点和 cleanup-verify。
- **安全边界**：禁止脚本、宏、webshell、真实恶意文件、用户本地任意文件和生产对象；文件公开、执行、扩散或清理失败立即停止。
- **证据**：空/重复/Unicode filename、双扩展、MIME 差异、边界冲突、超限、存取权限、解析差异、重启恢复和零遗留测试文件。

### 5.15 浏览器 SPA

- **当前 V1**：Browser Runner 使用断网 `setContent` 做 DOM 提取和惰性 XSS marker 验证；它不能登录、加载真实资产、执行 fetch/XHR 或维持 SPA session。
- **20 包目标**：只在固定 fixture 建立 `BrowserNetworkBroker`。navigation、asset、fetch/XHR 先转为 RequestIntent，经 Scope/Policy/Lease/HTTP adapter 后 `route.fulfill`；未知 GET、所有写请求、Beacon、WebSocket、WebRTC、Service Worker、download、popup 和外部协议盘点或阻断。
- **会话**：Set-Cookie 只进 SessionVault；浏览器不能形成第二 Cookie jar。依赖 localStorage/document.cookie secret 的请求在 20 包内保持 unsupported/inventory-only。
- **W6 目标**：固定 BrowserReplayBundle、临时 context、多身份、reviewed click/fill/submit、DOM source/sink trace 和最小化截图；任意真实 SPA 无法固定资产和触发链时保持 Signal/Inconclusive。客户端注入验证使用 W5 的 Technique/确认规则，但浏览器执行与 Evidence 边界由 W6 负责。
- **证据**：React/Vue/原生固定 fixture，跨域/redirect、动态 asset、fetch/XHR initiator、egress recorder、secret/storage、bundle hash 变化、崩溃恢复和三次一致复跑。
- **不得宣称**：20 包交付只能写“固定 fixture 的策略中介 SPA 盘点”，不能写“支持任意登录 SPA 自动扫描”。

### 5.16 Raw HTTP fixture

- **20 包状态**：只定义 `raw-http1/http2` 和 `protocol.raw-http-fixture` 的 capability 语义并 fail closed，不实现 adapter，不进入 Desktop production composition root。
- **W7 目标**：仅独占前端代理/后端服务、固定版本、隔离网络和 attestation fixture；支持连接级 bytes、前后端双观测、严格 request/connection budget 和每 Case namespace。
- **安全边界**：request smuggling/desync、cache poisoning/deception 不在真实共享生产链路执行；禁止跨 Case 污染、共享缓存污染、高强度资源测试和协议旁路。
- **证据**：编译依赖隔离、production root 不可导入、双端 trace、连接关闭、Case 间零污染、fixture 健康检查和永久禁止 capability 的 ToolCall 数为 0。
- **发布口径**：在 W7 独立门禁完成前始终显示 `fixture-only / not-implemented`，不得用 Undici HTTP 支持冒充 raw HTTP。

## 6. 横向安全门禁

所有接口族共同服从以下限制：

1. 导入和静态发现均为不可信输入；YAML anchor、JSON/XML 深度、压缩、对象数、字符串长度、解析时间和引用循环必须有硬上限。
2. 导入阶段网络请求数必须为 0；remote `$ref`、WSDL/XSD 外部 import、GraphQL live introspection、gRPC reflection 和 AsyncAPI broker discovery 都不能默认开启。
3. Cookie、Authorization、Token、密码、CSRF 值、callback token、原始业务 body 和非测试用户对象不得明文进入 Inventory、普通日志、模型输入或报告。
4. 所有真实 I/O 必须经过 Scope、Policy、原子预算、单次 Lease 和 actual-request hash 复核；浏览器、流式协议和 callback 不得拥有旁路。
5. L1 只允许可证实的只读、低影响差异验证；L2 只允许 AgentGo 专用测试对象、可信逐次批准、完整 side-effect envelope 和 cleanup-verify。
6. 通用/未绑定 HTTP DELETE 和生产/未知对象删除永久禁止。cleanup 优先使用 fixture/目标明确提供的 reset、revert 或 revoke；若 disposable TestObject 只能通过目标声明的 delete 清理，则仅专用 cleanup capability 可删除 AgentGo 创建且 ownership-attested 的精确对象，并绑定同一批准、资源 ID 与终态复核，不能作为漏洞探测。
7. DROP/TRUNCATE、生产数据增删改、真实账户接管、凭据喷洒、持久化、横向移动、高强度 DoS、恶意文件和越界访问永久禁止。
8. WAF/网关阻断、协议语义缺失、session 不稳定、证据冲突、状态未知或 cleanup 失败均输出 Inconclusive/awaiting-user，并停止后续非恢复动作。

## 7. 20 工作包接口覆盖的验收清单

二十个工作包结束时，复杂接口能力只有同时满足下列结果才合格：

- OpenAPI 3.0、声明子集的 3.1、Swagger 2.0、HAR 1.2、Postman 2.1 和离线 GraphQL 描述均有独立 parser/version、preview/commit、恶意输入和零网络测试；若某 parser 未完成，则 Coverage 必须自动显示 `not-supported`，不能阻塞于模糊的 `partial`。
- 所有导入来源写入同一 Inventory，重复 commit 幂等，同一 operation 的多来源和多 Variant 不丢失 provenance；unsupported 字段、Scope 外条目和 secret-redacted 数量可审计。
- reviewed 普通 HTTP query/path/header/cookie/form/JSON Variant 可以通过同一 RequestCompiler/Policy/Lease/Evidence 链；XML、multipart、GraphQL、WebSocket、SSE、SOAP、gRPC、AsyncAPI 和 raw HTTP 未实现执行 adapter 时均明确 fail closed。
- 固定 SPA fixture 的 navigation/asset/fetch/XHR 只能经 BrowserNetworkBroker；系统级 egress 证据证明浏览器没有第二网络出口。
- 受控 callback Collector 只为已注册 OOB Technique 服务；回连 token 唯一、短期、跨 scan 不可复用，响应内 proof 不计作 OOB。
- SessionVault、Identity、CSRF、Approval、TestObject、cleanup 与 crash recovery 在适用的 HTTP/form 场景闭环；真实 secret 和真实业务对象不进入 benchmark。
- 报告逐接口显示 `supported subset`、`inventory-only`、`fixture-only`、`not-supported` 和限制说明；不能出现一个总布尔值 `supportsComplexApi=true`。
- 至少一个未参与开发的固定版本、可本地重建的外部兼容靶场用于检验普通 REST/OpenAPI 导入与 reviewed GET replay；结果只证明兼容性，不宣称广泛真实 Web 准确率。
- `pnpm check`、module/conformance、parser 安全测试、迁移/恢复、secret scan、`pnpm build` 和 `pnpm smoke:desktop` 通过，现有前端仍可创建/启动/查看 V1 扫描且不承担新的安全决策。

## 8. 必须显式保留的未实现项

完成二十个工作包后，以下能力若尚未进入对应后续波次，必须继续显示为未实现或受限，不得为了“复杂接口全覆盖”而修改文案：

- GraphQL mutation/subscription、字段成本和完整授权矩阵；
- SOAP/WSDL、WS-Security 和复杂 XML schema 重放；
- gRPC/gRPC-Web protobuf 与流式 adapter；
- WebSocket 消息级主动测试和 SSE 长连接授权验证；
- AsyncAPI parser 与任意非 HTTP broker binding；
- multipart 文件生命周期和真实浏览器登录 SPA replay；
- raw HTTP/1.1、HTTP/2 desync 与共享 cache 行为；
- 自动 OAuth/OIDC/SAML 流、任意 Postman script、自动 webhook 注册和真实业务工作流推断。

这些空白是后续 W2、W3、W4、W5、W6、W7 的明确输入，不是可以隐藏的“实现细节”。其中复杂 API 协议集中在 W3，身份与会话复用 W2，业务副作用进入 W4，注入 Technique 进入 W5，文件/XML/浏览器执行进入 W6，raw protocol 研究仍只进入 W7。
