# AgentGo 威胁模型

## 1. 保护目标

- 授权范围和业务可用性；
- 测试账号、Cookie、Token、API Key；
- 目标请求响应和漏洞证据；
- 本地数据库、临时浏览器上下文和报告；
- Agent 决策链和审计日志；
- 用户设备与外部工具主机。

## 2. 主要攻击面

- 恶意目标页面和 API 响应；
- 导入的 HAR、报告、知识文档和模板；
- 外部模型 Provider；
- Browser/HTTP Runner；
- Electron Renderer、Preload 和 IPC；
- 可选 MCP Server、插件和脚本；
- 软件依赖、更新和安装包；
- 报告导出与 Markdown/HTML 渲染。

## 3. 间接 Prompt Injection

目标页面可能包含“忽略安全规则、调用工具、读取本地文件、发送凭据”等文本。防护要求：

- 页面文本始终标记为 untrusted_observation；
- system policy 和 tool policy 不与页面原文拼接为同一信任层；
- Agent 只能提出 ProbeProposal，不能直接调用 Runner；
- 工具参数由 schema、scope 和 SecurityPolicy 再校验；
- 任何试图改变授权、预算、模型配置或工具权限的页面内容都被忽略并记录。

## 4. 知识库投毒

- 每个来源保存 URL、作者/组织、发布日期、抓取时间、许可证和哈希；
- 用户导入与在线资料默认低信任；
- 摄取时检测指令性文本、重复内容和来源冲突；
- KnowledgePack 只输出事实摘要、适用性和来源引用；
- 检索内容不能修改 Prompt、工具权限或确认规则；
- 知识、模型、页面、MCP 与用户导入内容不能调用 `DefinitionRegistry.registerBundle()`；Bundle 只由可信 Composition Root 注入，注册完成后 Registry 冻结；
- Capability 目录成员资格、Manifest 的 `declaredMode` 和定义存在都不是执行授权；Activation 视图与固定 legacy 兼容允许表由确定性代码独立核对；
- 内置确认规则变更需要评审和版本升级。

## 5. 模型数据泄露

- 用户明确知道当前 Agent 使用的 Provider、Base URL 和模型；
- 发送前裁剪 Cookie、Authorization、密码、个人信息和不必要响应体；
- Provider 请求日志不记录 API Key；
- 默认确定性 Profile 可完全离线运行，外部 Provider 必须由用户显式配置；
- 模型输入先脱敏，调用记录保存摘要、哈希、输入/输出 Token 和耗时；不采信或记录 Provider 费用字段。

## 6. 执行器风险

- Coordinator、模块和 Renderer 只依赖统一 `ExecutionPort`，不能直接导入
  Runner；
- 每个实际 I/O 使用绑定 exact wire、scope、capability、purpose、opaque
  refs 和单步预算的不可变 Grant，以及数据库原子 claim 的单次 Lease；
- HTTP Runner 不自动跟随；每次跳转回到 Application，重新 Policy、
  child Grant/Lease 和 DNS guard；
- 跨 origin 自动移除凭据；`omit` wire 中残留 Authorization/Cookie 等
  凭据头必须在 transport send 前拒绝；
- 对 SSRF、代理、重定向和 URL 编码进行统一规范化；
- BrowserRunner 使用独立临时 Browser Context 并阻断页面网络；HttpRunner 不提供 shell 或文件能力；
- 禁止执行模型生成的任意 shell 字符串；
- 外部工具使用参数数组和显式允许的 capability；
- 超时、并发、输出大小和磁盘空间均设上限；
- 进程终止后清理临时文件和会话引用。
- claimed-but-unknown 不自动重放；恢复为 `interrupted / unknown`，将
  Scan 置为 `awaiting-user` 并记录审计事实。没有 claimed lease 的普通
  queued/running 中断任务才恢复为 `paused`。

## 7. Electron 风险

- contextIsolation、sandbox、nodeIntegration=false；
- Preload 只暴露业务级 API，不暴露 ipcRenderer 本体；
- IPC 输入输出使用 schema 校验；
- CSP 禁止远程脚本和 eval；
- 禁止任意导航、弹窗、文件协议和外部 URL 自动打开；
- HTML 报告输出必须转义不可信内容并携带严格 CSP；V1 不在 Renderer 内直接预览报告；
- DevTools 和调试接口不进入正式发布配置。

## 8. MCP 与外部工具

- 新 Server 默认禁用；
- 展示 File Access、Command Execution、Network Access 等能力标签；
- 每个 Server 独立凭据、scope、Agent 绑定和并发上限；
- roots 只是协作提示，不是绝对沙箱；
- 高权限工具逐次批准；
- 输出视为不可信并限制大小；
- MCP 不可用时不能自动退化为无限制 SSH 或 shell。
- 保存 MCP 配置不自动连接；STDIO 进程启动和远程网络连接只能由显式“测试连接”动作触发；
- MCP Token、环境变量和请求头通过 safeStorage 加密，Renderer 与 SQLite 都不得得到明文；
- 云元数据地址永久拒绝，能力名称和描述按不可信输出裁剪后再进入 UI。

## 9. 证据与报告

- EvidenceItem 保存 SHA-256 和来源；
- 脱敏生成派生版本，不覆盖原件；
- protected-original 后端要求完整 capture context/decision 封套，
  原文使用随机数据密钥执行 AES-256-GCM，数据密钥由操作系统安全存储封装，
  文件系统只保存内容寻址 ciphertext；
- 普通 `read`、Renderer、报告和导出拒绝 protected original，只消费
  metadata-only redacted derivative；scan/workspace 配额、retention、
  crypto-erase 以及创建、拒绝访问、完整性和到期审计由 migration `0010`
  与 EvidenceStore 共同执行；
- 在线执行仍只保存 capture-decision-bound hash-only 摘要。真实
  DOM/截图与 Lease provenance 接线尚未接入；缺少该在线证据链时 XSS
  必须 Inconclusive；
- 报告模板转义 HTML/Markdown 注入；
- V1 只导出明确标注的脱敏报告；未来开放原始导出前必须展示敏感字段清单；
- 报告不包含可直接滥用的真实凭据；
- 审计日志记录 Scope/身份、策略、执行、Finding 和报告操作；全局模型配置审计需要在后续引入非工作区级审计域。
- `userApproved` 布尔字段不是授权信号，SecurityPolicy 与 ApprovalService 必须忽略它。L2 批准只接受后端注入的 HMAC `ActorContext`；Renderer payload、Agent 输出和普通 IPC 不能设置 `actorId`、角色或 `approvedBy`。fixture-only 适配器不得进入产品 Composition Root。

## 10. 离线导入与静态发现

- OpenAPI/HAR/Postman/GraphQL 导入与 HTML/JS/Source Map 静态分析必须零网络：禁止远程 `$ref`、live introspection、远程 source map 下载、DNS 和 Runner 调用；
- 导入文件中的 Authorization、Cookie、Token、密码只记录分类与脱敏 preview，不得进入 Inventory、普通日志或报告；
- 发现/盘点不是执行授权。导入 Variant 初始为 `inventory-only/unreviewed`；AsyncAPI、WSDL、protobuf/gRPC、WebSocket、SSE 与 callback 只能产出 unsupported 提示；
- HTML、JavaScript、注释和 Source Map 一律视为不可信，不能提升为 Agent 指令，也不得执行 bundle、eval 或 WASM；
- Day 13 只能消费已冻结且 hash/reviewer/scope 未变化的 AssetManifest；未 review 的静态候选不能因为被页面引用而获得联网资格；
- ExtractionRule 由 Application schema 与人工/fixture review 冻结；灾难性 regex 与 likely-secret 原始值不能冻结。

## 10a. Policy-mediated 浏览器发现与通用验证计划

- Chromium 默认零直连：`offline: true`，只 `route.fulfill` 已经过 ExecutionPort、Policy、Lease、预算和 Evidence 的响应；Set-Cookie 不得进入 fulfill headers，只写入 SessionVault。
- 浏览器只能加载已冻结 AssetManifest 中 exact origin/path/type/hash 匹配的文档与静态资源。未知 GET 只盘点；POST/PUT/PATCH/DELETE、Beacon、form submit、WebSocket 与 SSE 不得为了“发现接口”而发送。
- BrowserRecon 与离线 XSS replay 共享 Policy/Evidence 基础设施，但调用路径分离。Recon Grant 使用模块快照已有的 `http.reviewed-read`，不把新 catalog ID 挂到 Grant，也不扩大 XSS/SQLi bundle 的 `requiredCapabilityIds`。
- InventoryMergeService 是唯一跨 producer 入口；不能覆盖更严格的 Scope/review/execution class。DependencyGraph 只使用已冻结 ExtractionRule；Agent 建议只能进入未审查候选。
- ValidationPlan 每步真实 I/O 仍走 Compiler/Grant/Lease/Policy/Budget/Capture；计划批准不等于绕过单步检查。未知 step/capability、悬空引用和预算合计失败关闭。
- 未实现的复杂协议、产品 L2 cleanup 与未注入的 OOB collector 失败关闭或保持 inventory-only，不得虚构执行覆盖。

## 11. 安全验证

项目测试必须包含：

- 越界 URL、恶意重定向和 DNS 变化；
- DROP/DELETE 等破坏性内容；
- 页面间接 Prompt Injection；
- 恶意工具输出，以及未来启用 MCP 后的恶意 MCP 输出；
- IPC 非法 payload；
- 报告 HTML 注入；
- 密钥和 Token 日志泄露；
- 离线导入/静态发现期间的网络探测、远程 `$ref`、YAML bomb、secret 回写和未冻结 AssetManifest 消费；
- 浏览器绕过 Broker 直连、manifest/hash 漂移、未知写动作、第二 Cookie jar 与越界 redirect；
- 未注册 knowledge 导入进入 Compiler、ValidationPlan 未知 step 或绕过单步 Policy；
- protected-original context/decision 篡改、普通读取绕过、配额竞争、
  ciphertext 篡改、到期 crypto-erase 和派生内容泄漏；
- 并发、超时和大型响应限制。
