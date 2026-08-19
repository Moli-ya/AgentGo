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
- Day4 protected-original 后端要求完整 capture context/decision 封套，
  原文使用随机数据密钥执行 AES-256-GCM，数据密钥由操作系统安全存储封装，
  文件系统只保存内容寻址 ciphertext；
- 普通 `read`、Renderer、报告和导出拒绝 protected original，只消费
  metadata-only redacted derivative；scan/workspace 配额、retention、
  crypto-erase 以及创建、拒绝访问、完整性和到期审计由 migration `0010`
  与 EvidenceStore 共同执行；
- Day5 在线执行仍只保存 capture-decision-bound hash-only 摘要。真实
  DOM/截图与 Lease provenance 接线属于 Day18；缺少该在线证据链时 XSS
  必须 Inconclusive；
- 报告模板转义 HTML/Markdown 注入；
- V1 只导出明确标注的脱敏报告；未来开放原始导出前必须展示敏感字段清单；
- 报告不包含可直接滥用的真实凭据；
- 审计日志记录 Scope/身份、策略、执行、Finding 和报告操作；全局模型配置审计需要在后续引入非工作区级审计域。

## 10. 安全验证

项目测试必须包含：

- 越界 URL、恶意重定向和 DNS 变化；
- DROP/DELETE 等破坏性内容；
- 页面间接 Prompt Injection；
- 恶意工具输出，以及未来启用 MCP 后的恶意 MCP 输出；
- IPC 非法 payload；
- 报告 HTML 注入；
- 密钥和 Token 日志泄露；
- protected-original context/decision 篡改、普通读取绕过、配额竞争、
  ciphertext 篡改、到期 crypto-erase 和派生内容泄漏；
- 并发、超时和大型响应限制。
