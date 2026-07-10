# ADR-0004：启用 MCP Center 配置与能力发现

- 状态：Accepted
- 日期：2026-07-10

## 背景

ADR-0003 将通用 MCP 延后，重新评估条件包括四类漏洞闭环、基准、安全策略和证据体系稳定。上述条件已经满足，产品方进一步明确要求桌面端可以配置 MCP Server。

## 决策

- 桌面端新增独立 `MCP Center`，不把 MCP 配置散落在 Renderer 或模型设置中；
- 支持本地 STDIO 与远程 Streamable HTTP；
- 复用官方 `@modelcontextprotocol/sdk`，不自行实现协议；
- 配置保存不自动连接，新 Server 默认禁用；
- 只有显式连接测试才启动 STDIO 进程或访问远程 URL；
- Token、环境变量和自定义请求头通过 safeStorage 加密，SQLite 只保存 `credentialId` 和字段名；
- 连接测试执行初始化握手并发现 tools、resources、prompts；结果按不可信内容限制数量和长度；
- Server 可以声明 roots、风险标签和允许使用的 Agent，但当前阶段不开放 Agent 自动调用。

## 安全边界

- Renderer 只使用经 Schema 校验的业务 IPC；
- 云元数据地址永久拒绝；
- STDIO 使用命令与参数数组直接启动，不经过 shell 拼接；
- roots 不是绝对沙箱；
- 后续工具调用必须接入 ToolBroker、SecurityPolicy、人工审批、审计和 Evidence 映射后才能启用。

## 后续工作

- MCP 工具逐次授权与 ToolBroker 路由；
- 工具调用审计和 Agent Console 时间线；
- 输出到 EvidenceItem 的结构化映射；
- Kali MCP Profile 与模板库。
