# AgentGo V1 使用指南

## 1. 使用前提

AgentGo 只适用于教学靶场、自有系统或已取得明确书面授权的目标。开始前应准备：

- 授权依据或审批单引用；
- 精确的 Origin、路径前缀、端口和有效期；
- 允许使用的测试身份；
- 速率、并发、请求数和时长上限；
- SSRF 场景的受控回调地址；
- IDOR 场景中两个测试身份各自拥有的测试资源 ID。

不要把生产账号、真实用户数据或未授权内网写入测试配置。系统会永久拒绝破坏性写入、云元数据、持久化、横向移动、凭据喷洒和高强度 DoS，但使用者仍需对授权范围负责。

## 2. 启动应用

开发模式：

```powershell
pnpm install
pnpm dev
```

免安装构建位于 `release/win-unpacked/AgentGo.exe`，NSIS 安装器由 `pnpm dist:win` 生成。XSS 隔离验证会调用系统 Microsoft Edge 或 Google Chrome；浏览器只用于断网渲染已取得的 HTML，不会从页面继续发起网络请求。

首次启动会自动完成数据库迁移、内置知识索引和五个本地确定性模型 Profile 的初始化。

## 3. 工作区与安全自检

在“工作台”中创建工作区，用于隔离不同课程、项目或授权任务。点击“运行”执行安全门禁自检：

- 低影响、范围内请求应显示 allowed；
- 破坏性数据库动作应显示 blocked；
- 自检只评估策略，不会发送网络请求。

如果自检不符合预期，不要启动扫描。

## 4. 创建目标和 Scope

在“目标与身份”中填写：

- 名称和 Base URL；
- 审批单、靶场所有权或其他授权引用；
- 允许 Origin；
- 允许和拒绝的路径前缀；
- 是否允许回环或私有网络目标；
- 每分钟请求数和最大并发。

界面根据 Base URL 固定允许端口。Scope 保存后形成不可变快照；后续身份或范围变更会创建新快照，已经创建的扫描继续引用创建时的快照，避免运行中悄然扩大授权。

范围应遵循最小授权原则。访问前和每次重定向时，系统都会重新验证 URL、端口、解析地址和身份，云元数据地址始终拒绝。

## 5. 配置测试身份

支持匿名、Bearer、Cookie、Basic 和自定义 Header。凭据通过 Electron `safeStorage` 加密后保存在本机，SQLite 只保存引用。

勾选“同时创建新的 Scope 快照并纳入该身份”后，身份才可被新扫描选择。删除身份时，应用会先把它从当前 Scope 移除，再删除凭据引用。

IDOR 验证至少需要两个均获授权的测试身份，并为每个身份填写“已知归属测试资源 ID”。系统只做读取对照，不修改或删除资源。

## 6. 配置 Agent 模型

“Agent 与模型”默认包含 Planner、Knowledge、Strategy、Analysis、Verifier 的本地确定性 Profile，可直接运行 V1。

添加外部模型时选择 Agent 角色，填写 OpenAI-compatible Base URL、模型名和 API Key，再点击连接测试。连接测试会真实 POST 到 `chat/completions`，要求模型返回并通过 `{"ok":true}` 的结构化校验；成功只代表该 Profile 的实际推理路径可调用，不代表扫描目标或其他 Provider 已验证。所有调用都经过 `ModelGateway`，执行输入脱敏、结构化输出校验、超时、RPM/TPM、Token 预算和审计。界面只累计输入 Token、输出 Token、总 Token 和调用次数，不记录或估算费用。模型输出只是建议或分析，不能直接绕过 `SecurityPolicy` 执行动作。

## 7. 配置 MCP Server

“MCP Center”支持两种 Transport：

- 本地 STDIO：填写启动命令、逐行参数、工作目录和加密环境变量；
- 远程 Streamable HTTP：填写 HTTP(S) URL、鉴权方式、Token 和加密自定义请求头。

新 Server 默认禁用，保存配置不会连接。点击“测试连接”后，应用才会执行 MCP 初始化握手并发现 tools、resources 和 prompts。本地 STDIO 测试会启动指定进程；远程测试会访问指定 URL，因此必须先核对命令、主机和权限。云元数据地址永久拒绝。

MCP Token、环境变量和自定义请求头只进入 `safeStorage`，SQLite 只保存字段名与凭据引用。可以为 Server 绑定允许使用的 Agent 和 roots；roots 只是协议协作边界，不是操作系统沙箱。当前版本完成配置、连接测试和能力发现，尚不允许 Agent 自动调用 MCP 工具。

## 8. 导入和发布知识情报

“知识库”包含知识检索、导入队列和新建导入。新建时可以粘贴公开情报/PoC 文本，或由用户主动选择不超过 1 MB 的文本、Markdown、JSON、YAML 或源代码文件；来源 URL 只记录元数据，应用不会自动访问。

保存后，在导入详情选择 Knowledge Profile 作为 Extractor、Verifier Profile 作为 Reviewer，再执行“提取并复核”。原文中的 Authorization、Cookie、Token、密码等模式会在入库前脱敏；模型只能生成固定结构候选，不能执行 PoC。检查厂商、产品、漏洞类型、影响版本、HTTP 请求模板、确认规则、修复建议和字段来源后，可以人工修订并发布。只有 `published` 记录会进入知识检索和扫描期 KnowledgeAgent，驳回或待审核记录不会参与扫描。

## 9. 创建和控制扫描

在“扫描与 Agent”中选择：

- 目标和任务名称；
- 必填的“任务与授权背景”，用于向 PlannerAgent 描述业务目标、已知限制和关注点；
- SQL 注入、XSS、SSRF、IDOR 中的一类或多类；
- 当前 Scope 中允许的测试身份；
- Planner、Knowledge、Strategy、Analysis、Verifier 各自使用的模型 Profile；
- 最大请求数和最大运行时长；
- SSRF 所需的受控回调 URL。

任务描述属于不可信业务上下文，不能扩大 Scope、身份或工具权限；不要在其中填写 API Key、Cookie、Authorization、Token 或密码。若选择外部 Profile，创建页会明确列出数据发送的 Profile、Base URL 和模型，任务描述与结构化上下文会先脱敏再发送。创建任务时五个 Profile ID 会被冻结，保证后续 AgentRun 的路由可复现。

回调 URL 也必须位于当前 Scope，且不得指向云元数据或未授权内网。创建后任务为草稿，点击启动进入以下阶段：

```text
授权与范围 -> 被动信息整理 -> 安全主动枚举 -> 假设与知识检索
-> 低影响验证 -> 独立复核 -> 证据报告
```

任务支持暂停、恢复和取消。暂停会中止当前执行并保存 Checkpoint；恢复从已保存状态继续。若应用异常退出，下次启动会将 queued/running 任务恢复为 paused，并记录恢复 Checkpoint 和警告事件，由用户确认后再恢复。

## 10. 理解结论和证据

- `Confirmed`：满足版本化确认规则，且具有所需证据和负对照。
- `Not Confirmed`：已经执行安全验证，但未达到确认标准。
- `Inconclusive`：条件、环境、预算或安全边界不足，不能可靠判断。

扫描详情显示阶段事件、发现的接口、证据数量和 Findings。原始证据采用内容寻址和 SHA-256 完整性校验；文本、JSON 和请求响应会生成脱敏派生。任何单次异常都只能形成 Signal，不能直接成为 Confirmed。

## 11. 生成和导出报告

扫描完成后可生成 Markdown、JSON 或 HTML 报告。桌面界面只生成脱敏版本；HTML 报告会转义不可信内容并带严格 CSP。导出时选择本地路径，应用会记录报告已导出，但不会自动上传或发送给第三方。

报告应由测试人员复核后再提交，尤其要检查授权引用、复现条件、身份、证据引用、影响范围和修复建议。

## 12. 本地数据与备份

生产运行数据位于 Electron 的 `userData` 目录，Windows 通常为 `%APPDATA%\AgentGo`，主要包括：

- `data/agentgo.sqlite`：工作区、Scope、任务、事件、审计和索引；
- `credentials/credentials.json`：操作系统加密后的凭据；
- `artifacts/`：原始和脱敏证据、报告内容。

删除 Target 会清理其数据库记录、未被其他扫描引用的证据文件和测试身份凭据；删除 Workspace 会清理整个工作区目录。运行中任务必须先暂停或取消。安装器配置为卸载时保留应用数据，升级、卸载或迁移前仍建议在应用退出后备份整个目录。不要把这些运行数据、`benchmark-results/`、`release/` 或原始计划书提交到代码仓库。

## 13. 常见问题

### XSS 验证提示 browser-unavailable

确认系统安装了 Microsoft Edge 或 Google Chrome，并位于标准安装路径。应用不下载浏览器，也不会使用任意未知可执行文件。

### 请求被 Scope 拒绝

检查 Origin、端口、路径前缀、身份是否在快照内，以及回环/私网开关。不要为了“让扫描通过”而无依据扩大 Scope，应先核对书面授权。

### 外部模型不可用

先运行 Profile 连接测试，检查 Base URL、模型名和 API Key。该测试会产生一次真实的最小 `chat/completions` 请求。外部模型失败不会让应用绕过本地安全策略；请新建扫描并为该角色选择确定性 Profile，已经创建的扫描仍保留其冻结路由。

### 扫描重启后变为暂停

这是安全恢复机制。查看最后一个警告事件和 Checkpoint，确认目标仍处于授权有效期内，再手动恢复。
