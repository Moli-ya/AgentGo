# 总体架构

## 1. 架构目标

AgentGo 采用“桌面外壳 + 本地编排引擎 + 确定性安全执行层 + Agent 推理层 + 证据与知识层”的结构。设计优先级依次为：

1. 授权边界和真实业务安全；
2. 可复现证据；
3. 完整研究闭环；
4. 桌面响应性和可恢复性；
5. 后续工具扩展能力。

## 2. 逻辑结构

```text
Electron Renderer
  | typed preload API
Electron Main
  | lifecycle / IPC / permission routing
Agent Runtime (utility process or worker)
  | plan / state machine / budgets / checkpoints
  +--> ModelGateway --------> external model providers
  +--> KnowledgeBase -------> local index / curated sources
  +--> SecurityPolicy ------> deterministic allow/deny/approval
  +--> BrowserRunner -------> Playwright
  +--> HttpRunner ----------> HTTP execution
  +--> EvidenceStore -------> SQLite metadata + immutable files
```

Renderer 只展示数据和发起用户意图；Main 负责生命周期和可信 IPC；重任务运行在 Utility Process、Worker Thread 或独立受控进程中。

## 3. 信任边界

- 不可信：目标网页、HTTP 响应、导入知识、模型输出、MCP 输出、用户导入模板。
- 半可信：经过解析和来源标注的 KnowledgeChunk、Agent 中间产物。
- 可信控制面：SecurityPolicy、Zod schema、目标授权快照、预算和状态机。
- 可信存储面：密钥引用、审计日志、不可变证据索引。

任何不可信内容都不能直接改变 system prompt、授权范围、工具权限或安全策略。

## 4. Electron 安全基线

桌面窗口必须启用：

- contextIsolation = true；
- sandbox = true；
- nodeIntegration = false；
- 受限的 Preload 白名单；
- 严格 CSP；
- 禁止任意新窗口和非预期导航；
- IPC channel 和 payload schema 校验；
- Renderer 不直接访问数据库、文件系统、密钥和执行器。

开发模式可以加载本地 Vite 地址，生产模式只能加载打包后的本地资源。

## 5. 包职责

- apps/desktop：Electron Main、Preload、React Renderer。
- packages/contracts：跨进程和跨包共享的版本化类型。
- packages/domain：Target、Scan、Signal、Validation、Finding 等领域模型。
- packages/security-policy：授权范围和主动探测硬门禁。
- packages/agent-runtime：阶段状态机、预算、检查点和 Agent 调度。
- packages/knowledge-base：知识摄取、检索和 KnowledgePack。
- packages/model-gateway：Provider-neutral 模型接口、模型配置和脱敏。
- packages/db：Drizzle schema、迁移和仓储边界。
- packages/browser-runner：Playwright 封装，不包含策略判断。
- packages/http-runner：HTTP 请求执行、重放和响应差异采集。
- packages/reporting：Findings、证据和修复建议的模板化输出。
- packages/mcp-hub：后续可选工具协议层，不属于 V1 阻塞项。

## 6. 依赖方向

```text
renderer -> contracts
main -> contracts + security-policy + application services
agent-runtime -> contracts + domain + model-gateway + knowledge-base
runners -> contracts
infrastructure -> domain ports
domain -> no Electron / no provider SDK / no Playwright
```

禁止业务模块绕过 ModelGateway 直接调用模型，禁止 Runner 绕过 SecurityPolicy 自行执行任务。

## 7. 模型配置

桌面设置页必须为全局和每个 Agent 提供图形化配置：

- Provider；
- Base URL；
- 模型名称；
- API Key 凭据引用；
- 超时、重试、RPM/TPM；
- Token 和费用预算；
- 连接测试；
- 推理、抽取、验证等模型 Profile。

明文 API Key 只进入操作系统凭据存储或 Electron safeStorage 封装，SQLite 只保存 credentialId。

## 8. 数据存储

- SQLite：结构化业务状态、索引、审计摘要。
- Files：HAR、Trace、截图、大型响应、报告附件。
- Credential Store：API Key 和其他长期凭据。
- Browser Profile：按工作区隔离，设置保存期限和一键清除。

证据文件使用内容哈希寻址或至少保存 SHA-256，数据库只保存元数据、路径、哈希和脱敏状态。

## 9. MCP 与 Kali 的定位

MCP Hub 是可替换的工具协议扩展层。核心 Runner 和 ToolBroker 先以内部接口跑通，之后才接入本地 STDIO 或远程 Streamable HTTP Server。

Kali 工具服务器、SSH 维护和高自由度工具编排属于 Stretch Goal。即使未来接入，也必须经过同一 SecurityPolicy、目标范围、人工审批和证据映射，不得获得绕过策略的特殊通道。

## 10. M0 技术验证

M0 必须实际验证而不是只写文档：

- Electron Main/Preload/Renderer 可构建并启动；
- workspace 包能被桌面端导入；
- IPC schema 和安全窗口设置生效；
- SecurityPolicy 能允许安全主动动作并拒绝破坏性动作；
- Vitest、TypeScript 和生产构建可在 Windows 环境通过；
- 后续单独验证 Playwright 打包、SQLite 驱动 ABI 和 Windows 凭据存储。
