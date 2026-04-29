# AGENT.md

## 1. 文档定位

本文件是 `AgentGo` 项目的总设计文档，也是后续人类开发者与 AI 编程代理共同协作时的统一约束。

它解决四类问题：

1. 这个项目最终要做成什么。
2. 为什么要选择当前的 Windows 桌面技术路线。
3. 整个系统应该如何拆分模块、组织 Agent、管理数据、接入模型。
4. 后续实现时，哪些工程规则必须长期保持一致。

本文件优先级高于零散想法、聊天中的临时设想和未落地的口头约定。未来如果架构发生重大调整，应先更新本文件，再进入开发。

---

## 2. 项目定义

### 2.1 项目名称

`AgentGo`  
基于 Multi-Agent 协作的 Web 漏洞挖掘 Windows 桌面客户端。

### 2.2 项目目标

构建一个面向**教学靶场、授权测试环境、研究原型验证**的 Windows 桌面程序。程序以多 Agent 协作为核心，围绕 Web 应用的页面、接口、参数、响应和状态流转进行分析，辅助完成漏洞初筛、测试编排、结果研判与报告输出。

### 2.3 目标用户

- 高校网络安全教学团队
- 参加 CTF / Web 安全研究的学生团队
- 在授权环境中进行自查的中小研发团队
- 研究 Multi-Agent 在安全测试中落地方式的开发者

### 2.4 产品定位

这是一个**本地优先、桌面优先、研究型工程原型**，不是云平台，不是浏览器插件，也不是纯命令行工具。

最终形态应当具备以下特征：

- 运行在 Windows 桌面，具有完整 GUI。
- 支持用户通过 `API Key` 接入外部大模型服务。
- 能管理多个测试目标、扫描任务、会话状态和结果报告。
- 支持半自动与自动化两种工作模式。
- 支持长期迭代，从课程项目原型逐步演化为可申请软著的软件系统。

### 2.5 非目标

以下内容不作为第一阶段目标：

- 自训练大模型
- 完整替代专业人工渗透测试
- 面向公网的大规模分布式扫描平台
- 高并发 SaaS 服务端
- 直接追求“武器化”利用能力

---

## 3. 核心约束

### 3.1 平台约束

- 主目标平台：`Windows 10/11`
- 程序形态：`桌面客户端`
- 运行方式：`本地安装 + 本地数据目录 + 本地任务执行`
- 对外交付形态：默认提供 `Windows 安装程序（.exe）`，而不是要求他人下载源码后手动运行开发环境

### 3.2 语言约束

用户明确提出**尽量不使用 Python**。因此本项目默认语言策略如下：

- 主语言：`TypeScript`
- 桌面宿主：`Electron`
- 前端界面：`React + TypeScript`
- 本地数据库与任务编排：`Node.js / TypeScript`
- 后续性能热点模块：允许增量引入 `Rust` 作为独立 sidecar 或原生模块

原则：

- 没有明确必要时，不引入 Python。
- 如果未来某个能力只有 Python 生态成熟实现，必须先进行架构评审，再决定是否隔离成可替换工具进程，不能让 Python 成为系统主干。

### 3.3 模型接入约束

大模型接入统一采用 `API Key` 模式，不依赖本地大模型推理作为一期前提。

必须满足：

- 支持配置多个模型提供商
- 支持自定义 `Base URL`
- 支持用户切换不同模型用于不同 Agent
- 支持流式输出
- 支持请求重试、超时、速率限制、成本统计
- 不能把明文 API Key 写入日志、数据库或导出的报告

### 3.4 安全边界约束

本项目只面向**授权目标**。

系统内必须默认存在以下约束：

- 只有加入授权范围的域名、IP、路径才能被测试
- 默认启用速率限制与并发控制
- 默认关闭高风险或破坏性动作
- 会话令牌、Cookie、API Key、敏感头信息必须脱敏存储或受控保存
- 所有扫描活动要有可审计记录

---

## 4. 技术路线总决策

### 4.1 推荐主栈

推荐采用以下主栈作为一期到中期的统一方案：

- 桌面宿主：`Electron`
- UI：`React + TypeScript + Vite`
- 组件库：`Fluent UI`
- 本地运行时：`Node.js LTS`
- 多 Agent 编排：`TypeScript` 自研运行时
- 浏览器自动化：`Playwright`
- HTTP 请求执行：`undici`
- 本地数据库：`SQLite`
- ORM / 查询层：`Drizzle ORM`
- 文本检索：`SQLite FTS5`
- MCP 协议接入：`@modelcontextprotocol/sdk`（TypeScript 官方 SDK）
- 配置校验：`Zod`
- 状态管理：`Zustand + TanStack Query`
- 日志：`Pino`
- 测试：`Vitest + Playwright`
- 打包发布：`electron-builder + NSIS`
- 密钥保管：`keytar` 或 Windows Credential Manager 封装

### 4.2 选择这条路线的原因

#### 4.2.1 为什么不是 Python

- 你已经明确不想以 Python 作为主体语言。
- 本项目需要桌面 UI、浏览器自动化、模型 API 编排、数据库、任务执行和后续产品化；这些在 TypeScript/Electron 生态内可以闭环完成。
- 使用 TypeScript 可以减少“前端一套语言、后端另一套语言”的协作成本。

#### 4.2.2 为什么选 Electron 而不是一开始就上 Tauri / 纯 Rust

`Electron` 更适合作为当前阶段的主宿主，原因如下：

- 浏览器自动化与 Web 安全相关生态在 Node 侧更成熟，和 `Playwright` 组合最自然。
- Electron 的 `main / renderer / utility process` 模型适合把高风险或高负载能力隔离到独立进程。
- Windows 桌面分发、菜单、托盘、文件系统权限、日志与调试链路成熟。
- 对学生项目和长期迭代原型来说，开发效率优先于极致轻量。

`Tauri / Rust` 不排除在二期后引入，但建议只用于：

- 需要更高性能的扫描执行器
- 本地数据加密模块
- 高并发 diff / 解析组件
- 独立 sidecar 服务

#### 4.2.3 为什么不用纯 C# / WinUI 作为主路线

纯 C# 也能做 Windows 桌面，但本项目还包含：

- Playwright 自动化
- Prompt / Agent 编排
- 大量 JSON Schema 和动态工具调用
- 前端快速迭代界面

从整体研发效率、生态一致性和 AI 协作便利性来看，TypeScript 主栈更合适。

### 4.3 技术路线原则

- 一期先保证“能跑通完整链路”，不要过早引入复杂分布式组件。
- 所有核心能力都要模块化，避免未来被某个单一模型提供商、数据库或浏览器引擎绑定。
- 所有模型调用必须走统一网关，不允许在业务代码里四处直接发请求。
- 默认发布物应当是普通用户可双击运行的 Windows 安装包，不能把“拉代码、装依赖、执行命令行”当成正式交付方式。
- 外部架构参考中，`PentAGI` 作为**主参考对象之一**，重点学习其“工具编排自由度、可观测性、记忆增强、模型配置分层”的工程思路，但不照搬其 `Docker-first / server-first` 部署形态。
- Multi-Agent 编排可以参考成熟开源项目的思路，但只借鉴其任务拆解、状态机、工具协议、记忆管理和可观测性设计，不直接照搬其角色命名、目录结构和运行时假设。
- 任何开源编排框架都只能作为“参考对象”或“可替换实现”，不能反向决定本项目的领域模型；本项目始终以 `Target / Scan / Evidence / Finding / SecurityPolicy` 为核心。

---

## 5. 总体架构

系统采用“**桌面外壳 + 本地引擎 + Agent 编排 + 安全执行层 + 知识增强层**”的结构。

```text
+--------------------------------------------------------------+
|                        Windows Desktop                       |
|                  Electron + React Renderer                   |
+-------------------------------+------------------------------+
                                |
                                | Typed IPC
                                v
+--------------------------------------------------------------+
|                      Electron Main Process                   |
|  App 生命周期 | IPC 路由 | 权限控制 | 任务调度 | 进程监管      |
+-------------------------------+------------------------------+
                                |
                +---------------+------------------+
                |                                  |
                v                                  v
+-------------------------------+   +------------------------------+
|   Utility Process: Engine     |   | Utility Process: Browser     |
| Agent Runtime / Queue / DB    |   | Playwright / Session / Trace |
+---------------+---------------+   +---------------+--------------+
                |                                   |
                v                                   v
+-------------------------------+   +------------------------------+
| Model Gateway                 |   | HTTP Runner / Browser Runner |
| Provider Adapters / RAG       |   | Authorized Scope Executor    |
+---------------+---------------+   +---------------+--------------+
                |                                   |
                +------------------+----------------+
                                   |
                                   v
                        +-----------------------+
                        | SQLite + FTS5 + Files |
                        | State / Evidence / KB |
                        +-----------------------+
```

在 MCP 能力上，本程序定位为 **MCP Host**。  
实现方式是：由本地 `mcp-hub` 为每一个已配置的 MCP Server 创建并维护一个独立的 MCP Client 连接，统一交给桌面应用管理。这意味着：

- 桌面应用负责用户体验、权限确认、配置保存、日志和审计
- 每个 MCP Server 都有自己独立的连接、状态、能力列表和错误信息
- Agent 不直接“裸连” MCP Server，而是统一经由 `ToolBroker / MCP Hub` 调用

该设计与 MCP 官方文档中的 `Host -> Client -> Server` 架构一致，并且更适合 Windows 桌面产品形态。

### 5.1 架构分层

#### A. 表现层

负责：

- Windows 桌面 UI
- 用户操作入口
- 实时进度显示
- Agent 控制台
- 结果查看与导出

#### B. 应用层

负责：

- 扫描任务生命周期管理
- IPC 协议
- 权限检查
- 桌面进程之间的数据编排

#### C. 领域层

负责：

- Target / Scan / Finding / Evidence 等核心业务模型
- 多 Agent 任务编排
- 扫描策略、状态迁移、验证规则

#### D. 基础设施层

负责：

- 模型 API 接入
- SQLite 持久化
- Playwright 浏览器控制
- HTTP 请求执行
- 日志、配置、文件存储

---

## 6. 推荐仓库结构

本项目建议采用 `monorepo`。

```text
/apps
  /desktop
    /src
      /main
      /preload
      /renderer
    /resources

/packages
  /contracts
  /domain
  /db
  /model-gateway
  /agent-runtime
  /mcp-hub
  /browser-runner
  /http-runner
  /tool-connectors
  /knowledge-base
  /reporting
  /security-policy
  /shared
  /test-utils

/resources
  /prompts
  /knowledge
  /templates

/docs
  /architecture
  /adr
  /api
  /testing

/scripts

/tests
  /integration
  /e2e
```

### 6.1 各目录职责

#### `/apps/desktop`

桌面宿主应用。包含：

- Electron 主进程
- Preload 安全桥接层
- React 渲染层
- 窗口、菜单、托盘、设置页、任务中心

#### `/packages/contracts`

所有跨进程协议、DTO、事件结构、枚举、JSON Schema 都放这里。  
目标是让：

- Renderer 和 Main 共用类型
- Main 和 Utility Process 共用协议
- 未来 sidecar 迁移时不改业务语义

#### `/packages/domain`

领域模型与业务规则。这里不直接依赖 Electron、Playwright、具体模型厂商 SDK。  
它只表达“系统应该做什么”。

#### `/packages/db`

数据库 schema、迁移、仓储实现、查询聚合逻辑。

#### `/packages/model-gateway`

统一封装所有大模型请求。  
禁止业务代码直接调用 OpenAI、Anthropic、其他兼容接口。

#### `/packages/agent-runtime`

多 Agent 的核心运行时，包括：

- Agent 注册
- Prompt 装配
- 工具调用协议
- ToolBroker 路由
- 上下文记忆
- 任务状态机
- 失败重试
- 结果仲裁

#### `/packages/mcp-hub`

负责本项目的 MCP 客户端能力。包括：

- 本地 `STDIO` MCP Server 接入
- 远程 `Streamable HTTP` MCP Server 接入
- 初始化、能力协商与协议版本管理
- tools / resources / prompts 的发现与缓存
- roots 映射、权限确认与用户审批
- MCP 连接测试、重连、禁用与审计
- 对 `agent-runtime` 暴露统一的 `ToolBroker` 风格接口

#### `/packages/browser-runner`

封装 Playwright。负责：

- 打开浏览器
- 管理登录态
- 页面操作
- 网络监听
- 会话快照
- Trace 保存

#### `/packages/http-runner`

负责纯 HTTP 级别请求执行、响应对比、重放与限速。

#### `/packages/tool-connectors`

负责外部工具接入能力。优先形态是：

- 通过 `MCP Hub` 接入外部工具能力
- 将 Kali 虚拟机配置为一个或多个 MCP Server
- 由 Kali MCP Server 暴露原生工具、脚本、工作流或第三方工具集合
- 将外部工具输出转换为本项目统一的结构化证据

该模块的目标不是限制 Kali 的工具自由度，而是把自由度纳入统一配置、统一审计和统一证据链。  
它应支持：

- 高自由度工具配置
- 多个 MCP Server 并存
- Kali 原生工具自动发现
- 工具能力标签化
- 工具调用结果结构化
- 工具调用过程可观察
- 必要时保留 SSH / CLI Adapter 作为兼容路径

#### `/packages/knowledge-base`

负责：

- 安全情报检索与结构化漏洞知识库
- 检索索引
- 知识分片
- 标签体系
- RAG 检索策略
- 情报源管理
- 增量更新与缓存

#### `/packages/reporting`

负责：

- Findings 聚合
- 证据组织
- Markdown / HTML / PDF 报告导出

#### `/packages/security-policy`

负责所有安全边界控制：

- 授权范围校验
- 速率限制
- 高风险动作开关
- 敏感字段脱敏
- 导出合规控制

---

## 7. 桌面客户端设计

### 7.1 UI 风格方向

这是一个 Windows 桌面安全工具，不是网页后台管理模板。

UI 设计要求：

- 整体风格偏 Windows 桌面专业工具，而不是纯 Web 控制台
- 使用 `Fluent UI` 作为基础组件体系
- 左侧导航 + 顶部上下文栏 + 主工作区多面板布局
- 支持亮色 / 暗色主题，但默认跟随系统
- 强调“任务状态、证据、差异、时间线、Agent 决策链”
- 页面要简洁、干净、低噪音，避免安全工具常见的“信息堆满屏”问题
- 默认界面优先展示当前任务必须看到的信息，高级配置采用折叠区、向导步骤或二级抽屉承载
- 对新用户高频操作采用分步式引导，不要求用户先理解全部系统概念
- `MCP Center`、`Settings`、`Scan Center` 这三类配置页必须优先保证可读性和可操作性，而不是展示参数数量

### 7.2 核心页面

#### 1. 工作区首页 Dashboard

展示：

- 最近任务
- 最近目标
- 漏洞统计
- 模型调用统计
- 错误告警
- 任务恢复入口

#### 2. 目标管理 Target Manager

展示和管理：

- 目标名称
- 授权范围
- 基础 URL
- 登录方式
- 标签
- 测试状态
- 历史扫描记录

#### 3. 会话管理 Session Center

负责：

- 浏览器登录态录入
- Cookie / LocalStorage / Token 捕获
- 会话有效期检测
- 多身份切换

#### 4. 扫描任务中心 Scan Center

负责：

- 创建任务
- 选择目标
- 选择 Agent 配置
- 选择漏洞类型
- 设置并发、速率、深度
- 查看任务进度、阶段、日志

#### 5. Agent 控制台 Agent Console

这是项目特色界面，必须重点设计。  
展示：

- 当前执行 Agent
- 每步输入与输出摘要
- 工具调用记录
- 决策理由
- 异常与重试
- 人工干预点

#### 6. 证据与发现 Findings

展示：

- 漏洞标题
- 风险等级
- 可信度
- 目标页面 / 接口
- 证据链
- 复核状态
- 修复建议

#### 7. 知识库 Knowledge Base

展示：

- 漏洞家族
- 知识条目
- 情报源
- 索引状态
- 最近更新时间
- 检索命中情况
- RAG 召回质量
- Knowledge Pack 预览
- 缓存命中情况
- 人工补充知识

#### 8. MCP 工具中心 MCP Center

这是 MCP 能力的统一入口，必须设计成**清晰、分步、可测试**的页面，而不是把配置项散落到设置页里。  
负责：

- 添加和管理 MCP Server
- 区分 `本地 STDIO` 与 `远程 Streamable HTTP`
- 模板创建与手动创建
- 连接测试
- capability 展示
- tools / resources / prompts 列表
- roots 选择
- 权限审批
- Agent 可用范围绑定
- 启用 / 禁用 / 重连 / 删除

#### 9. 设置 Settings

配置：

- 模型服务商
- API Key
- Base URL
- 默认模型
- MCP 默认策略
- 代理
- 日志级别
- 数据目录
- 浏览器路径
- 自动更新

### 7.3 用户流程

基础流程应当是：

1. 创建工作区
2. 配置模型 API Key
3. 按需进入 `MCP Center` 接入 MCP 工具
4. 添加授权目标
5. 建立或导入登录会话
6. 创建扫描任务
7. 观察 Agent 执行过程
8. 复核 Findings
9. 导出报告

### 7.4 MCP 接入体验要求

MCP 接入必须做到“**用户知道自己在接什么、授了什么权、接好后能不能用**”。

产品要求如下：

- 用户不需要编辑 JSON 配置文件才能接入 MCP
- 用户不需要先读协议文档才能理解接入流程
- 本地与远程 MCP Server 的接入路径要分开显示
- 每一步都要有明确的字段说明、示例和错误提示
- 接入完成前必须能执行连接测试和 capability 发现
- 接入完成后用户必须能看见该 Server 暴露了哪些 tools / resources / prompts
- 用户必须能控制某个 MCP Server 允许被哪些 Agent 或任务模板使用

### 7.5 MCP 接入流程

MCP 接入流程必须设计为向导式，建议固定为以下步骤：

#### 第一步：选择接入类型

用户选择：

- `本地 MCP Server (STDIO)`
- `远程 MCP Server (Streamable HTTP)`

#### 第二步：选择添加方式

用户选择：

- 从常见模板创建
- 手动创建
- 从 Kali MCP Server 模板创建

#### 第三步：填写连接信息

对于本地 `STDIO`：

- 名称
- 启动命令或可执行文件路径
- 参数
- 工作目录
- 环境变量
- 启动超时

对于远程 `Streamable HTTP`：

- 名称
- Server URL
- 认证方式
- Header / Token
- 超时
- 是否允许自定义请求头
- 是否标记为 Kali MCP Server
- 默认工具 namespace 前缀

#### 第四步：执行连接测试

程序应自动完成：

- 初始化握手
- capability discovery
- tools / resources / prompts 列表获取
- 错误信息回显

测试结果必须明确显示：

- 是否连接成功
- 协议版本
- Transport 类型
- Server 名称与版本
- 可用能力数量

#### 第五步：配置 roots 与权限

MCP 官方设计中，roots 用于帮助 server 理解当前工作区边界。  
在本项目中，用户必须能明确选择：

- 哪些本地目录可作为 roots 暴露
- 是否允许 server 读取工作区文件
- 是否允许 server 请求用户补充输入
- 是否允许该 server 被自动任务调用

界面上必须明确说明：

- roots 主要是协作边界，不应被错误宣传成绝对安全边界
- 高权限 server 需要更强的人工确认

#### 第六步：绑定使用范围

用户应当可以选择该 MCP Server 供谁使用：

- 全局可用
- 仅特定 Agent 可用
- 仅特定 Task Template 可用
- 默认禁用，按任务临时启用

#### 第七步：保存并验证可用性

保存后，系统需要立即展示：

- 已接入 server 列表
- 当前状态
- 最近一次连接时间
- 最近一次错误
- 可调用工具概览

### 7.6 MCP 页面设计要求

`MCP Center` 页面必须比传统开发者工具配置页更直观，设计要求如下：

- 默认列表视图保持干净，一行只展示最关键状态
- 详情页分为 `Overview / Tools / Resources / Prompts / Permissions / Logs`
- 错误信息用自然语言解释，不只展示原始异常
- 所有危险权限使用显式确认和醒目标识
- 不把几十个表单字段堆在同一屏；分步或分区展示
- 支持“测试连接”按钮和“查看最近日志”按钮常驻显示
- 支持模板导入，但模板内容必须可见、可编辑、可审查

### 7.7 MCP 集成范围要求

本项目对 MCP 的最低能力要求如下：

- 能作为 MCP Host 连接多个 MCP Server
- 支持 `STDIO` transport
- 支持 `Streamable HTTP` transport
- 支持 tools 发现与调用
- 支持 resources 发现与读取
- 支持 prompts 发现与获取
- 支持 roots 配置
- 支持 connection test
- 支持 per-server enable / disable
- 支持连接失败后的重试和错误展示

v1 暂不强制要求：

- 本项目自己作为 MCP Server 对外暴露能力
- 一开始就支持所有第三方扩展式 transport

### 7.8 安装与分发体验

本项目最终交付给其他人时，目标形态必须是**标准 Windows 安装软件**，而不是“压缩包 + README + 命令行安装步骤”。

对外分发的默认要求如下：

- 用户拿到的是可双击启动的 `Installer.exe`
- 启动后进入常见 Windows 安装向导
- 安装向导中允许用户选择安装目录
- 安装向导中允许用户选择是否创建桌面快捷方式
- 安装完成后自动创建开始菜单入口
- 安装完成后具备卸载入口，并出现在 Windows“应用和功能”列表中
- 安装后的程序可以像普通桌面软件一样从桌面、开始菜单或固定任务栏启动

### 7.9 安装器功能要求

推荐使用 `electron-builder` 的 `NSIS` 目标实现标准安装器，并满足以下功能：

- 支持 `per-user` 安装，必要时预留 `per-machine` 安装能力
- 支持自定义安装路径
- 支持桌面快捷方式与开始菜单快捷方式
- 支持卸载程序
- 支持升级安装时保留用户数据目录
- 支持应用图标、安装器图标、产品名称、版本号、发布者信息配置
- 支持签名能力预留，便于后续正式发布

### 7.10 运行时交付要求

安装包必须尽量做到“装完即可用”，不能把开发环境依赖转嫁给使用者。

必须满足：

- 不要求用户手动安装 Node.js
- 不要求用户手动安装 Python
- 不要求用户手动安装 SQLite
- 不要求用户手动执行命令行初始化脚本

对于浏览器执行层，采用以下策略：

- 优先方案：安装包内置项目所需的浏览器运行组件
- 备选方案：首次启动时由程序内置引导自动下载并配置浏览器组件

无论选择哪种方案，都不能要求普通用户自己打开终端执行 `playwright install` 之类的命令。

### 7.11 发布物策略

正式对外分发时，发布物分为两类：

- 默认发布物：`Windows Installer (.exe)`，面向普通使用者
- 可选发布物：`Portable Zip`，仅用于内部调试、应急排障或比赛环境快速携带

默认不把 portable 包作为主要交付形态。

---

## 8. Multi-Agent 设计

### 8.1 Agent 设计原则

- 每个 Agent 只做一类职责明确的事
- Agent 之间通过结构化消息交接，而不是互相传自然语言长文本
- 每个 Agent 的输入、输出、失败条件、可调用工具必须可定义
- 所有最终结论都必须可追溯到证据，而不是只输出模型判断
- 编排层允许参考开源 Multi-Agent 项目的优秀实践，但必须先映射到本项目的任务边界，再决定是否吸收，不能为了贴合某个开源框架去扭曲本项目的业务流程
- 优先吸收的方法包括：Planner-Executor 分层、可恢复状态机、工具调用协议、结构化中间产物、人工介入节点、失败重试与仲裁机制
- 不直接照搬的内容包括：Agent 名称体系、默认提示词风格、第三方框架耦合的对象模型、与云端服务强绑定的调度方式
- 如果未来引入开源 Agent 框架，其位置应当是 `agent-runtime` 内部的可替换实现层，而不是直接渗透到 UI、领域模型和数据库设计中

### 8.2 一期推荐 Agent 角色

#### A. `ScopeGuardAgent`

职责：

- 检查目标是否在授权范围内
- 检查任务配置是否合法
- 决定哪些动作允许执行

输入：

- Target 配置
- 用户权限配置
- 当前任务计划

输出：

- Scope 校验结果
- 风险提示
- 可执行动作白名单

#### B. `PlannerAgent`

职责：

- 根据目标信息拆解任务步骤
- 决定先做页面探测、接口整理还是会话复用
- 为后续 Agent 分配子任务

输入：

- 目标信息
- 历史扫描摘要
- 当前模式配置

输出：

- ScanPlan
- 阶段列表
- Agent 调度顺序

#### C. `ReconAgent`

职责：

- 识别入口页面
- 整理页面跳转关系
- 捕获页面与接口的基础映射

输入：

- 基础 URL
- 初始会话

输出：

- 站点图谱
- 页面节点
- 接口候选列表

#### D. `InterfaceAgent`

职责：

- 归纳接口、参数、请求体结构
- 提取参数来源和依赖关系
- 标记高价值参数点

输入：

- 网络抓包记录
- 表单信息
- 页面上下文

输出：

- Endpoint Inventory
- Param Catalog
- 可测试点清单

#### E. `KnowledgeAgent`

职责：

- 按漏洞类型、技术栈、上下文检索知识库
- 为后续策略生成提供结构化参考

输入：

- 技术栈标签
- 参数特征
- 历史异常摘要

输出：

- Knowledge Pack
- 相关漏洞模式
- 验证注意事项

#### F. `StrategyAgent`

职责：

- 生成测试策略
- 决定验证顺序
- 约束执行强度

输入：

- Endpoint Inventory
- Knowledge Pack
- 任务模式

输出：

- Test Strategy
- 测试模板
- 验证优先级

#### G. `ExecutionAgent`

职责：

- 调用 Browser Runner / HTTP Runner 执行实际动作
- 管理节流、重试与会话有效性

输入：

- 已批准的 Test Strategy
- Session Context

输出：

- Execution Records
- 请求响应快照
- 异常结果集合

#### H. `AnalysisAgent`

职责：

- 比对响应差异
- 判断是否存在可疑现象
- 提取证据片段

输入：

- Execution Records
- Baseline Responses
- Knowledge Pack

输出：

- Suspicious Cases
- Evidence Candidates
- Confidence 初值

#### I. `VerifierAgent`

职责：

- 对疑似发现进行多轮复核
- 降低误报
- 确认是否满足输出标准
- 按确认规则输出结构化 `Verdict`

输入：

- Suspicious Cases
- Evidence Candidates
- 验证规则

输出：

- Confirmed Findings
- Rejected Findings
- Inconclusive Findings
- 复核说明

#### J. `ReportAgent`

职责：

- 将最终发现整理成结构化报告
- 输出可读结论和修复建议

输入：

- Confirmed Findings
- Evidence Bundle

输出：

- Markdown / HTML / PDF 报告数据

### 8.3 Agent 通信协议

禁止 Agent 之间直接传无边界长文本。  
统一使用结构化对象，例如：

- `ScanPlan`
- `ReconSnapshot`
- `EndpointInventory`
- `KnowledgePack`
- `ExecutionRecord`
- `EvidenceBundle`
- `FindingDraft`

### 8.4 Agent 记忆设计

记忆分为四层：

#### 短期运行记忆

当前任务过程中的临时上下文，保存在内存中，任务结束可释放。

#### 会话记忆

与登录态、Cookie、页面状态、角色身份相关。

#### 任务记忆

与某次扫描任务直接相关，包括：

- 已访问页面
- 已识别接口
- 已执行测试
- 已观测异常
- 已确认 / 已排除发现

#### 长期知识记忆

项目级、可复用知识，包括：

- 漏洞知识条目
- 技术栈识别规则
- 误报模式
- 报告模板

### 8.5 开源项目参考矩阵

截至 `2026-04-29`，本项目已经明确将“参考开源同类项目，但做成自己的东西”作为长期策略。  
这里的“参考”不是复制仓库结构，而是系统性吸收其：

- Agent 角色拆分方式
- 状态机与检查点机制
- 结构化中间产物
- 工具调用协议
- 共享记忆与知识库设计
- 证据链与审计设计
- 人工介入与安全边界设计
- 模型接入与多模型路由方式

本节列出的项目，分为两类：

- 直接参考对象：已经明确在做 agentic / multi-agent 自动化安全测试
- 邻近参考对象：虽然不完全等于本项目目标，但某一部分设计非常值得吸收

#### 8.5.1 直接参考对象

##### A. PentestGPT

项目链接：<https://github.com/GreyDGL/PentestGPT>  
研究论文：<https://www.usenix.org/conference/usenixsecurity24/presentation/deng>

已知特点：

- 2024 年 USENIX Security 论文项目，明确指出长链路渗透测试中 LLM 容易丢失整体上下文
- 当前仓库已升级为 agentic pipeline，并提供 `Session Persistence`
- 采用 `Docker-First` 方式，强调可复现环境和工具预装
- 自带 benchmark 目录与公开评测体系

我们要借鉴的部分：

- 将长链路测试拆成多个自交互模块，以降低单一上下文失控风险
- 会话保存 / 恢复机制
- 基准评测意识，而不是只做“演示可跑”
- 实时步骤展示与执行过程可视化

我们不直接照搬的部分：

- `Python + Docker + CLI/TUI` 为主的运行形态
- 覆盖 `Crypto / PWN / Reversing / Forensics` 等过宽类别的产品边界
- Linux / 容器优先的交付方式

本项目中的落地方式：

- 吸收其“缓解上下文丢失”的思想，固化为 `PlannerAgent + Task Checkpoint + EvidenceBundle`
- 将 `Session Persistence` 做成桌面客户端中的任务恢复与工作区恢复能力
- 用我们自己的 Windows UI 取代终端型交互

##### B. AutoPentest AI

项目链接：<https://github.com/bhavsec/autopentest-ai>

已知特点：

- 明确宣称包含 `4 specialized agent roles`、`7 structured phases`
- 引入阶段质检、`Final Judge`、`zero-context final review`
- 把 `OWASP WSTG` 和 PortSwigger 技术指南直接组织进知识体系
- 强调“不是扫一遍就下结论”，而是阶段化验证与质量门禁

我们要借鉴的部分：

- 阶段门禁机制
- 独立 QA / Judge 角色
- “结论必须经复核”这一工程原则
- 安全知识库与测试流程的强绑定

我们不直接照搬的部分：

- 以 `MCP server + Python` 为中心的实现形态
- 过于庞大的单仓工具集合与规则堆积
- 直接把手工渗透测试清单硬塞成产品功能菜单

本项目中的落地方式：

- 我们的 `VerifierAgent` 直接吸收 `Final Judge` 思路
- `KnowledgeAgent` 参考其 WSTG 化组织方式，但改造成更适合 Web 端桌面产品的结构化知识包
- 将“阶段门禁”固化到扫描状态机，而不是只写在 prompt 中

##### C. CortexAI

项目链接：<https://github.com/theelderemo/cortexai>

已知特点：

- 强调 `SQLite project databases`
- 强调 `immutable evidence collection`
- 强调 `OWASP/CWE classification`
- 把 scope、finding、evidence、audit trail 都视为一等对象

我们要借鉴的部分：

- 项目级数据库思维
- 证据链不可变与可追溯设计
- Findings 自动映射到安全标准
- 多项目隔离管理

我们不直接照搬的部分：

- 纯工具编排式“shell-first”交互形态
- 一上来就偏企业平台化的厚重流程

本项目中的落地方式：

- 继续坚持 `SQLite + Files` 的本地项目数据库设计
- 把 `EvidenceItem`、`Finding`、`AuditLog` 作为核心领域模型
- 在报告层保留 `OWASP / CWE` 映射字段

##### D. PentAGI

项目链接：<https://github.com/vxcontrol/pentagi>

已知特点：

- 采用 `React + TypeScript` 前端
- 后端为 `Go + GraphQL`
- 使用 `PostgreSQL + pgvector`
- 可选启用 `Graphiti + Neo4j` 知识图谱
- 监控体系包含 `OpenTelemetry / Grafana / Jaeger / Loki`
- embedding 被明确用于语义检索、知识存储和记忆管理

我们要借鉴的部分：

- 把它视为**当前最重要的外部架构参考对象之一**
- 前后端职责清晰分离
- 向量记忆和知识检索的工程化实现方式
- 工具编排自由度较高，适合作为“多工具、多连接器、多模型 profile”设计参考
- 对外部工具、模型、观测能力做平台化封装，而不是把能力散在各 agent 中
- 知识图谱作为“可选增强层”的思路
- 可观测性先设计后实现

我们不直接照搬的部分：

- 一期就引入 `pgvector + Neo4j + Graphiti + Grafana + Jaeger + Loki` 的重型基础设施
- 服务化、自托管平台优先的部署方式

本项目中的落地方式：

- 把 `PentAGI` 作为工具编排与配置体系的主要对标对象
- 一期维持 `SQLite FTS5`，二期再引入 embedding 检索
- 知识图谱只作为远期增强项，不能阻塞 v1 落地
- 可观测性理念保留，但实现上先做桌面端可视化日志和 Agent 时间线
- 在工具执行层引入 `MCP Hub + Kali MCP Profiles + ToolBroker` 三层结构，学习其高自由度思想，但维持桌面产品的简洁交互

##### E. PentestAgent

项目链接：<https://github.com/GH05TCREW/pentestagent>

已知特点：

- 明确面向 `black-box security testing`
- 支持预置 `playbooks`
- 支持 `MCP` 双向集成：既能消费外部 MCP server，也能作为 MCP server 暴露自己
- 支持 `spawn_mcp_agent` 生成子代理并行处理

我们要借鉴的部分：

- Playbook 化的任务模板
- 子 Agent 并行委派模型
- 工具层协议化，而不是把工具写死在单个 Agent 内
- “既能当客户端又能当服务端”的扩展思想

我们不直接照搬的部分：

- 以 `CLI + MCP` 为主的交互和扩展方式
- Python-first 的实现形态

本项目中的落地方式：

- 将 `Playbook` 概念映射成 `Task Template / Scan Profile`
- 将 `spawn_mcp_agent` 的思想映射成我们内部的 `Subtask / Child Agent Run`
- 对外是否暴露 MCP，不作为 v1 必选项；先做内部统一 ToolBroker

##### F. Pentest Swarm AI

项目链接：<https://github.com/Armur-Ai/Pentest-Swarm-AI>

已知特点：

- 明确采用 `swarm of AI agents`
- 使用共享 `blackboard`
- 强调 `decentralization`
- 让 agent 通过 trigger predicate 自主被唤醒
- 将 blackboard 设计成可衰减权重的状态空间

我们要借鉴的部分：

- 事件驱动的 agent 唤醒机制
- 中央调度之外的“共享状态驱动协作”
- 不是所有流程都硬编码成固定流水线

我们不直接照搬的部分：

- 一期就引入 `Postgres + pgvector` 风格的黑板式基础设施
- 过强的“全自动 swarm”叙事，导致用户难以理解过程
- 偏 `bug bounty / CTF / offensive chain` 的目标定位

本项目中的落地方式：

- 一期仍以可解释的 `Planner -> Strategy -> Execution -> Verify` 主流程为主
- 二期可以引入“事件触发副 Agent”的轻量机制，例如参数异常触发专门分析 Agent
- 黑板模型先做成内存 + SQLite 事件表，而不是直接上独立数据库系统

#### 8.5.2 邻近参考对象

##### G. Pentest Copilot

项目链接：<https://github.com/bugbasesecurity/pentest-copilot>

已知特点：

- 明确是 AI-driven pentest agent
- 有真实浏览器 agent
- 支持 Burp Suite 集成
- 支持后台 subagent 并行
- 有危险命令审批
- 支持用户自带模型提供商

我们要借鉴的部分：

- 浏览器交互不是附属，而是核心能力
- 自动执行与人工控制共存
- 高风险动作必须显式确认
- UI 和工具执行环境要紧密联动

我们不直接照搬的部分：

- `Kali attack box + Docker` 的核心假设
- 与 Burp / Kali 深度耦合的产品形态
- 将系统本身做成“远端攻击箱控制台”的方向

本项目中的落地方式：

- 强化我们的 `Browser Runner + Session Center + Agent Console`
- 审批机制纳入 `SecurityPolicy`
- 模型配置继续坚持 `API Key + Base URL + Provider Adapter`

##### H. Decepticon

项目链接：<https://github.com/PurpleAILAB/Decepticon>

已知特点：

- 在执行前先生成 `RoE / ConOps / Deconfliction Plan / OPPLAN`
- 文档中单列 `Model profiles and fallback chain`
- 还单列 `Skill system and format spec`
- 更偏 autonomous red team，而不只是 Web 扫描

我们要借鉴的部分：

- 在任何测试动作前先固化授权边界和计划
- 模型 profile 与 fallback chain 的工程化思路
- skill / profile / operation plan 要结构化，而不是散落在 prompt 里

我们不直接照搬的部分：

- 红队全链路、横向移动、C2 等明显超出本项目边界的内容
- 过度军事化/作战化叙事

本项目中的落地方式：

- 将其授权包思路吸收到 `ScopeGuardAgent + TargetScope + Task Approval`
- 为不同 Agent 设计不同的模型 profile，例如 `reasoning / extraction / verification`
- skill system 只保留“知识包 / 模板包 / 规则包”三类轻量实现

##### I. MASAPT

项目链接：<https://github.com/marzekan/MASAPT>

已知特点：

- 是较早期的 multi-agent 自动渗透概念验证
- 明确采用 `Explore -> Exploit -> Report`
- 提出了三层结构：`Explorer -> Coordinator/Exploiters -> Reporter`
- 使用 XMPP / SPADE 进行 agent 通信

我们要借鉴的部分：

- 分层式多 Agent 概念非常清晰
- “探索 / 执行 / 汇总” 的阶段分离非常适合教学和原型
- Coordinator 的中心调度思想在今天仍然成立

我们不直接照搬的部分：

- `Python + XMPP + SPADE` 的实验性实现
- proof-of-concept 级别的安装与使用体验

本项目中的落地方式：

- 把它视为概念源头之一，而不是工程模板
- 继续保留 `Planner / Recon / Execution / Report` 的分层思路
- 用本地 IPC、结构化 contract 和任务状态机替代 XMPP 风格通信

#### 8.5.3 我们真正要吸收的共性

从这些项目中，我们真正要吸收的不是“工具列表越多越好”，而是以下共性：

- 多 Agent 不是为了显得高级，而是为了切分长链路上下文
- 结构化中间产物比自然语言串话更重要
- 复核与 Judge 机制是降低误报的关键
- 浏览器自动化、HTTP 执行、知识库检索必须同时存在
- 可恢复的任务状态机比一次性完整跑通更重要
- 证据链、审计日志、标准映射是工程产品能力，不是锦上添花
- 用户审批、高风险动作确认、授权边界管理必须是系统内建能力

#### 8.5.4 我们明确不走的路

尽管这些项目各有价值，但本项目明确不走以下路线：

- 不做 Linux-only / Docker-only / Kali-only 的工具
- 不把 Python 当作主干语言
- 不把产品做成只能开发者自己在终端里跑的研究脚本
- 不把攻击链扩展到红队全链路和明显超出授权 Web 测试边界的能力
- 不在 v1 就堆砌过重的图数据库、向量数据库、监控栈和微服务

#### 8.5.5 本项目的吸收落地表

开源项目中的可借鉴点，统一映射到本项目如下：

- `PentestGPT` -> `Task Checkpoint / Session Resume / Live Timeline`
- `AutoPentest AI` -> `Phase Gates / Final Judge / KnowledgeAgent + VerifierAgent`
- `CortexAI` -> `SQLite Project DB / Evidence Chain / OWASP-CWE Mapping`
- `PentAGI` -> `Kali MCP Profiles / 高自由度工具编排 / 二期 Embedding 检索 / 远期可观测性增强`
- `PentestAgent` -> `Task Template / Child Agent / ToolBroker`
- `Pentest Swarm AI` -> `事件驱动副 Agent / 轻量 blackboard`
- `Pentest Copilot` -> `Browser Runner / Human Approval / Hybrid UI`
- `Decepticon` -> `ScopeGuard / Model Profiles / Plan Package`
- `MASAPT` -> `分层协作思路的理论来源`

#### 8.5.6 执行要求

未来在本仓库中实现任何新的 Agent 机制、工具协议、记忆设计或调度方式时，默认都要回答以下问题：

1. 这个设计参考了哪个开源项目的哪一类思想？
2. 我们借鉴的是“方法”还是“实现”？
3. 如果只借鉴方法，如何映射到本项目现有领域模型？
4. 为什么它适合 `Windows 桌面客户端 + TypeScript + Electron + API Key` 这条路线？
5. 它会不会破坏本项目的可安装、可交付、可解释和可审计性？

---

## 9. 核心业务流程设计

### 9.1 目标接入流程

1. 用户创建 Target
2. 填写授权范围
3. 配置基础 URL 与可选身份信息
4. 建立会话
5. 系统执行 Scope 校验
6. 成功后进入任务创建阶段

### 9.2 自动探测流程

1. PlannerAgent 生成初始计划
2. ReconAgent 获取页面入口与站点图
3. InterfaceAgent 归纳接口和参数
4. KnowledgeAgent 提供相关知识包
5. StrategyAgent 生成测试策略
6. ExecutionAgent 执行
7. AnalysisAgent 分析
8. VerifierAgent 复核
9. ReportAgent 输出

### 9.3 人工介入点

系统必须支持人工介入，不应把一切做成黑箱自动执行。  
可介入点包括：

- 登录态录入
- 任务模式选择
- 高风险动作确认
- 某类目标的跳过 / 强制执行
- 可疑发现的人工复核
- 报告导出前的编辑

### 9.4 失败恢复

必须支持任务恢复。  
当发生以下情况时，任务应保存快照并可恢复：

- 浏览器进程崩溃
- 模型请求超时
- 会话失效
- 网络错误
- 应用异常退出

---

## 10. 模型接入架构

### 10.1 总原则

所有模型访问统一经过 `ModelGateway`。

禁止：

- 在任意业务模块中直接 `fetch` 某家模型 API
- 在 Prompt 代码中硬编码 API Key
- 在 Agent 内私自定义不同的 provider 调用协议

### 10.2 `ModelGateway` 统一接口

至少提供以下能力：

- `chatCompletion`
- `structuredCompletion`
- `embedding`
- `streamCompletion`
- `countTokens` 或近似预算能力
- `testConnection`

### 10.3 Provider 配置模型

每个 provider 配置包含：

- `id`
- `name`
- `providerType`
- `baseUrl`
- `apiKeyRef`
- `chatModel`
- `embeddingModel`
- `maxContext`
- `rpmLimit`
- `tpmLimit`
- `timeoutMs`
- `retryPolicy`

### 10.4 API Key 存储策略

API Key 不能明文写入 SQLite。  
建议：

- 配置元数据写数据库
- 真正的密钥写入 `keytar` 或 Windows Credential Manager
- 数据库中仅保存 `credentialId`

### 10.5 模型输出协议

所有关键 Agent 输出必须尽量采用结构化结果：

- JSON Schema
- 明确字段
- 明确枚举
- 明确可空字段
- 明确失败原因

不要依赖“让模型自由发挥写一段文字”来承接后续业务逻辑。

### 10.6 Prompt 管理

Prompt 必须版本化管理，建议放在：

```text
/resources/prompts/
  planner.system.md
  recon.system.md
  strategy.system.md
  analysis.system.md
  verifier.system.md
  report.system.md
```

每个 Prompt 文件应拆分为：

- system prompt
- tool usage contract
- output schema
- guardrails
- few-shot 示例

---

## 11. 情报知识库与 RAG 设计

### 11.1 知识库内容范围

知识库的核心定位是**高效率检索相关安全情报**，为 Agent 判断测试策略、确认标准、误报排除和修复建议提供依据。  
它不是攻击脚本仓库，也不是静态漏洞百科。

内容类型包括：

- 漏洞家族定义
- 适用条件
- 常见误报模式
- 响应特征说明
- 验证要点
- 风险分级建议
- 修复建议模板
- CVE / CWE / OWASP / WSTG 映射
- 厂商公告与版本影响范围
- 组件指纹与版本情报
- 公开安全研究摘要
- 历史扫描案例摘要

### 11.2 数据组织方式

建议采用“结构化 + 文档化”的混合方式：

- 结构化数据：JSON / YAML
- 长文档说明：Markdown
- 检索索引：SQLite FTS5
- 情报元数据：SQLite 结构化表
- 大文本原文：文件系统或压缩文本块
- 远期向量索引：可替换 embedding store

### 11.3 情报源管理

情报源应当可配置、可启用、可禁用、可定时更新。  
建议分为：

- 内置知识：项目自带的漏洞家族、确认标准和误报模式
- 本地导入：Markdown、JSON、YAML、PDF 摘要、历史报告
- 公开情报：CVE、CWE、OWASP、WSTG、厂商公告、依赖安全公告
- 用户情报：团队内部经验、靶场记录、已确认案例
- 在线检索：在用户允许联网时，按需查询最新公开资料

所有外部情报进入系统后，都必须被转换为统一的 `IntelDoc` 或 `KnowledgeChunk`，不能让 Agent 直接读取杂乱网页或大段原文。

### 11.4 一期检索方案

一期先采用稳定、易打包、Windows 友好的方案：

- 元数据过滤
- 标签匹配
- `SQLite FTS5` 关键词召回
- 规则加权排序
- 查询归一化
- 别名词典
- 组件名 / CVE / CWE / 技术栈标签快速匹配
- LRU 查询缓存
- 每个任务内的 Knowledge Pack 缓存

### 11.5 高效率检索策略

知识库检索必须优先保证响应速度。  
推荐策略：

- 先查本地索引，再按需在线查询
- 先用结构化过滤缩小范围，再做全文检索
- 先返回小型 `Knowledge Pack`，不要把大段资料塞进模型上下文
- 对同一目标、同一技术栈、同一漏洞族的查询做任务级缓存
- 对 CVE、组件名、框架名、漏洞族建立专用倒排索引
- 对高频知识条目预计算摘要
- 在线情报检索放入后台任务，不阻塞主扫描流程
- 检索结果要包含来源、更新时间、置信等级和适用范围

### 11.6 Knowledge Pack 输出要求

`KnowledgeAgent` 不应把原始文档直接传给后续 Agent。  
它应输出小而结构化的 `KnowledgePack`：

- `query`
- `matchedTopics`
- `vulnFamilies`
- `applicability`
- `verificationRules`
- `falsePositivePatterns`
- `recommendedTools`
- `sourceRefs`
- `freshness`
- `confidence`

其中 `recommendedTools` 可以引用 MCP 工具 namespace，例如：

- `kali.web`
- `kali.http`
- `hexstrike.*`
- `builtin.http-runner`
- `builtin.browser-runner`

### 11.7 二期检索增强

二期可以在不改业务接口的前提下加入：

- Embedding 向量召回
- Hybrid Retrieval
- 误报模式学习
- 基于历史任务的案例相似检索
- 组件指纹到漏洞情报的自动关联
- 在线情报定时同步
- 本地情报质量评分
- 多来源冲突检测

### 11.8 知识条目最小结构

每条知识至少包含：

- `id`
- `title`
- `vulnFamily`
- `techTags`
- `applicableWhen`
- `doNotOverclaim`
- `verificationHints`
- `remediationHints`
- `references`
- `updatedAt`

### 11.9 情报检索性能指标

为了避免知识库拖慢整体系统，建议设定最低性能目标：

- 本地关键词检索 P95 小于 `300ms`
- 本地 Knowledge Pack 生成 P95 小于 `800ms`
- 在线情报查询不阻塞 UI 和主扫描任务
- 单次传给模型的 Knowledge Pack 默认不超过可配置 token 预算
- 情报索引更新必须后台执行，并可暂停、恢复、取消

---

## 12. 浏览器与 HTTP 执行层设计

### 12.1 Browser Runner

由 `Playwright` 封装实现，职责包括：

- 持久化浏览器上下文
- 用户辅助登录
- 页面导航
- DOM 交互
- 表单发现
- 网络请求监听
- Trace / HAR / Screenshot 记录

### 12.2 HTTP Runner

负责更轻量的执行能力：

- 直接发送请求
- 记录响应头、状态码、体积、时间
- 对比基线响应
- 节流与重试

### 12.3 Browser 与 HTTP 的协作原则

- 涉及页面流程、登录跳转、JS 驱动逻辑时优先 Browser Runner
- 涉及批量请求重放、参数对比时优先 HTTP Runner
- 二者共享同一任务上下文，但不能互相篡改未经批准的状态

### 12.4 执行边界

执行层必须受 `SecurityPolicy` 控制。  
至少控制以下维度：

- 域名白名单
- IP 白名单
- 协议限制
- 端口限制
- 请求频率
- 并发数
- 文件上传开关
- 跳转跟随策略

### 12.5 证据采集

执行层应尽量采集下列证据类型：

- 请求摘要
- 响应摘要
- 页面截图
- DOM 片段
- HAR / Trace 文件引用
- 响应差异摘要

### 12.6 Kali MCP Tool Server 设计

Kali 虚拟机在本项目中优先被视为一个**可配置 MCP 工具服务器**，而不是普通 SSH 远程主机。  
推荐形态是：

- Windows 桌面客户端作为 MCP Host
- `MCP Hub` 连接运行在 Kali 虚拟机内的 MCP Server
- Kali MCP Server 暴露 Kali 原生工具、用户自定义脚本、HexStrike AI 类工具集合或其他自动化工作流
- `ToolBroker` 根据任务上下文选择 Browser / HTTP / MCP 工具能力

这意味着：

- Kali 的工具能力应主要通过 MCP capability discovery 暴露
- 工具配置自由度应尽量高，不强制用户为每个工具手写固定适配器
- 系统只对授权范围、审批、审计、并发、超时和证据格式做统一治理
- 不把 Kali 限制成少量预置命令集合

### 12.7 Kali MCP 配置模型

每个 Kali MCP Server 至少包含：

- `id`
- `displayName`
- `transport`
- `serverUrl` 或本地启动命令
- `authRef`
- `hostTags`
- `toolNamespaces`
- `defaultRiskPolicy`
- `allowedTargets`
- `allowedAgents`
- `concurrencyLimit`
- `timeoutPolicy`
- `evidenceMappingPolicy`

Kali MCP Server 暴露的工具应按 namespace 管理，例如：

- `kali.recon`
- `kali.web`
- `kali.http`
- `kali.network`
- `kali.wordlist`
- `kali.custom`
- `hexstrike.*`

namespace 的目的不是限制工具，而是让 UI、日志、审批和 Agent 选择更清晰。

### 12.8 工具自由度与治理原则

本项目不应把 Kali 工具能力限制得过窄。  
合理的治理方式是：

- 允许用户接入多个 Kali MCP Server
- 允许用户通过 MCP 暴露 Kali 原生工具
- 允许用户通过 MCP 暴露自定义工具链
- 允许用户将工具绑定到特定 Agent、Task Template 或目标范围
- 允许工具输出原始日志，同时要求系统生成结构化摘要

系统不应做：

- 不应要求每个工具都内置到桌面客户端代码中
- 不应把工具配置写死成少数几个按钮
- 不应要求用户为了新增 Kali 工具修改主程序代码

系统必须做：

- 每次工具调用都记录任务、Agent、目标、工具名、参数摘要、耗时、退出状态和证据引用
- 高风险工具调用前可要求人工确认
- 工具输出必须能进入 `EvidenceItem`
- 工具执行必须受目标授权范围约束

### 12.9 SSH 的定位

SSH 在本项目中是辅助能力，不是首选工具调用方式。

SSH 可用于：

- 部署或启动 Kali MCP Server
- 检查 Kali 侧服务状态
- 拉取诊断日志
- 在 MCP 不可用时执行受控的维护命令

正常测试任务中，Agent 应优先通过 `MCP Hub` 调用 Kali 能力。  
只有当某个能力暂时无法通过 MCP 暴露时，才考虑 `SSH / CLI Adapter` 作为兼容路径。

### 12.10 可执行验证模式

本项目不追求“武器化利用”，但允许在授权、低破坏、可回退的前提下做**可执行验证**。  
这里的重点是：

- 不是只做模糊探测
- 不是只给“可能存在”这种弱结论
- 而是在合理范围内，通过受控验证明确判断漏洞是否被确认

但工程上不能强迫系统在证据不足时硬给二元答案。  
因此最终结果协议必须采用**非模糊三态**：

- `Confirmed`：已满足确认标准，漏洞存在
- `Not Confirmed`：在当前前提下未达到确认标准，不能确认漏洞存在
- `Inconclusive`：前置条件不足、权限不足、环境不稳定或验证风险过高，需要人工复核

注意：

- `Inconclusive` 不是模糊话术，而是明确状态码
- UI 不应展示“可能有”“大概有”“疑似有点像”这类语言
- 任何最终结论都必须带证据摘要和确认依据

### 12.11 漏洞确认标准

为了尽量做到“每一次探测都有明确结论”，本项目必须为不同漏洞族定义**确认标准**，而不是只依赖模型主观判断。

确认标准的基本原则：

- 必须可复现
- 必须有前后对照
- 必须保留证据
- 必须能解释为什么算确认
- 必须区分“特征信号”与“确认结果”

系统中应把漏洞判断拆成三个层次：

1. `Signal`
   说明：出现了值得关注的异常特征

2. `Validation`
   说明：执行了进一步验证动作，并获得了结构化结果

3. `Verdict`
   说明：基于验证规则给出最终状态 `Confirmed / Not Confirmed / Inconclusive`

这个设计的目标是：

- 避免把一次异常响应直接当成漏洞
- 避免模型用自然语言硬猜
- 让结论更接近“有明确标准的检测报告”，而不是聊天式判断

---

## 13. 数据模型设计

### 13.1 数据存储原则

- 业务数据统一保存在 SQLite
- 大型附件保存在文件系统，数据库只保存路径与摘要
- 日志采用结构化日志文件 + 数据库摘要索引

### 13.2 核心表建议

#### `workspaces`

工作区信息。

#### `targets`

目标信息、授权范围、标签、默认配置。

#### `target_scopes`

域名、IP、路径、端口范围等授权边界。

#### `sessions`

浏览器登录态、身份说明、过期时间、摘要信息。

#### `scans`

一次扫描任务的主记录。

#### `scan_steps`

任务每个阶段的状态记录。

#### `pages`

扫描中识别出的页面节点。

#### `endpoints`

识别出的接口。

#### `parameters`

参数目录及来源。

#### `agent_runs`

各 Agent 的执行记录、输入摘要、输出摘要、耗时和状态。

#### `knowledge_docs`

知识库文档索引。

#### `evidence_items`

证据条目，关联截图、HAR、响应对比等。

#### `findings`

最终发现结果，包含级别、可信度、状态、复核说明。

#### `reports`

导出报告历史。

#### `provider_configs`

模型供应商配置元数据，不含明文 key。

#### `audit_logs`

审计日志。

### 13.3 Findings 数据结构要求

每个 Finding 至少包含：

- `title`
- `targetId`
- `scanId`
- `vulnFamily`
- `severity`
- `confidence`
- `status`
- `verdict`
- `summary`
- `evidenceSummary`
- `confirmationRuleId`
- `validationTraceId`
- `reproducibility`
- `remediation`
- `createdAt`

---

## 14. 任务调度与状态机

### 14.1 调度方式

不引入 Redis、Kafka 这类重型组件。  
桌面本地程序采用：

- SQLite 持久化任务队列
- 内存调度器
- Utility Process 执行

### 14.2 扫描任务状态

建议状态机：

- `draft`
- `queued`
- `running`
- `paused`
- `awaiting_user`
- `retrying`
- `completed`
- `failed`
- `cancelled`

### 14.3 Agent 子任务状态

- `pending`
- `ready`
- `executing`
- `blocked`
- `succeeded`
- `rejected`
- `timed_out`
- `errored`

### 14.4 恢复机制

每个阶段结束时生成 checkpoint，至少包含：

- 当前 Agent
- 已完成步骤
- 会话引用
- 已发现页面 / 接口摘要
- 已执行策略摘要
- 待复核项目

---

## 15. 安全与合规设计

### 15.1 伦理边界

本项目默认场景是：

- 教学靶场
- 授权测试环境
- 自有系统安全自查

任何实现都不应默认面向未授权公网目标。

### 15.2 默认保护措施

- 第一次添加目标必须填写授权说明
- 新建扫描任务时显示授权范围确认
- 高风险模式默认关闭
- 会话凭据默认脱敏展示
- 导出报告默认隐藏敏感令牌
- 默认只允许低破坏、可回退、可审计的验证动作
- 默认不启用持久化、横向移动、隐蔽执行、口令喷洒或破坏性利用链

### 15.3 日志脱敏

以下信息不能直接写入日志：

- API Key
- Cookie 明文
- Authorization Header
- Session Token
- 密码字段

### 15.4 文件系统安全

建议所有应用数据统一落在：

```text
%APPDATA%/AgentGo/
```

或用户自定义目录，并进一步拆分：

- `db/`
- `logs/`
- `artifacts/`
- `browser-profiles/`
- `reports/`
- `backups/`

### 15.5 导出管控

报告导出时应允许用户选择：

- 是否包含截图
- 是否包含原始请求
- 是否包含完整响应
- 是否脱敏 Cookie / Token

### 15.6 MCP 安全边界

MCP 接入不是“连上就行”，而是需要明确权限和审计边界。  
这里的安全策略不是限制 Kali 工具数量，而是治理工具调用的目标范围、审批、并发、日志和证据归档。

必须满足：

- 每个 MCP Server 都要单独启用、单独禁用、单独审计
- 默认新接入的 MCP Server 不自动加入所有 Agent
- `STDIO` Server 与 `Streamable HTTP` Server 要分别展示风险级别
- 远程 MCP Server 推荐使用可信 `HTTPS` 地址；内网 Kali MCP Server 如果使用 `HTTP`，必须由用户显式标记为可信工具主机
- MCP 鉴权信息不能明文写日志或数据库
- roots 选择必须由用户明确确认，不能静默暴露整个工作目录
- 任何具有文件访问、命令执行、网络访问能力的 server 都必须显示能力说明
- 任何 MCP 工具被 Agent 调用时，都要在 Agent Console 和审计日志中留下记录

建议策略：

- v1 同时支持本地 `STDIO` Server 与 Kali 场景下的远程 `Streamable HTTP` Server
- 对远程 MCP Server 增加“自动调用 / 审批后调用 / 仅手动任务可用”的策略开关
- 为高权限 MCP Server 提供醒目的视觉标签，例如 `File Access`、`Command Execution`、`Network Access`

---

## 16. 测试策略

### 16.1 测试分层

#### 单元测试

覆盖：

- 领域规则
- Prompt 输出解析
- JSON Schema 校验
- 风险策略判断
- 数据库仓储

#### 集成测试

覆盖：

- ModelGateway 与 Mock Provider
- Agent Runtime 与 Tool 调用链路
- MCP Hub 与 Mock MCP Server
- STDIO / Streamable HTTP 连接初始化、能力发现与重连
- Browser Runner / HTTP Runner 封装
- 数据库存取流程

#### 端到端测试

覆盖：

- Electron 桌面主流程
- MCP Center 向导式接入流程
- MCP Server 连接测试、权限绑定、启用禁用
- 创建目标、配置模型、启动任务、查看 Findings、导出报告
- 长任务运行时 UI 不冻结
- 情报索引更新时 UI 仍可操作
- MCP / Kali 工具长时间调用时可取消、可恢复、可查看进度

### 16.2 Mock 策略

必须提供：

- Mock 模型服务
- Mock 授权目标站点
- Mock 扫描任务数据

避免所有测试都依赖真实外部 API。

### 16.3 验收标准

一期至少满足以下验收：

- 能启动桌面程序
- 能配置 API Key
- 能创建目标与会话
- 能完成基础页面探测
- 能整理接口与参数
- 能形成至少一条完整的 Agent 工作链路
- 能输出结构化 Findings
- 能导出报告

---

## 17. 日志、监控与可观测性

### 17.1 日志规范

统一使用结构化日志。  
日志字段建议包含：

- `timestamp`
- `level`
- `module`
- `scanId`
- `agentId`
- `targetId`
- `event`
- `durationMs`
- `errorCode`

### 17.2 调试视图

桌面端应提供开发者调试面板，可查看：

- IPC 消息
- Agent 输入输出摘要
- 模型调用耗时
- 浏览器事件
- 数据库写入摘要

### 17.3 成本统计

模型调用要做成本统计，至少记录：

- provider
- model
- prompt tokens
- completion tokens
- estimated cost
- request duration

### 17.4 桌面性能与响应性设计

本项目会同时运行桌面 UI、浏览器自动化、Agent 编排、MCP 工具调用、情报索引和模型请求，必须从架构上避免卡顿。

核心原则：

- Renderer 只负责界面展示和用户交互
- 扫描任务、MCP 调用、浏览器自动化、情报索引、报告生成都不能阻塞 Renderer
- Main Process 只负责生命周期、IPC 路由和进程监管，不承担重计算
- Agent Runtime、MCP Hub、Browser Runner、Knowledge Indexer 应运行在 Utility Process、Worker Thread 或独立 sidecar 中
- 所有长任务必须支持进度事件、取消、超时和失败恢复

### 17.5 后台任务与队列

系统必须采用后台任务队列管理重任务：

- Agent 子任务队列
- MCP 工具调用队列
- Browser 自动化队列
- HTTP 请求队列
- 情报索引更新队列
- 报告导出队列

队列必须支持：

- 并发上限
- 优先级
- 暂停 / 恢复
- 取消
- 超时
- backpressure
- checkpoint

### 17.6 数据库与索引性能

SQLite 可以支撑桌面本地程序，但必须正确使用：

- 启用 WAL 模式
- 为 `scanId`、`targetId`、`agentRunId`、`findingId`、`vulnFamily`、`updatedAt` 建索引
- 对 FTS 表单独维护索引更新任务
- 大型响应体、截图、HAR、Trace 不直接塞进主表
- 日志和证据列表采用分页查询
- UI 列表使用虚拟滚动
- 高频写入使用批量提交或节流提交

### 17.7 性能目标

建议设定以下体验目标：

- 冷启动进入主窗口小于 `5s`
- 普通页面切换小于 `200ms`
- 大型 Findings 列表滚动不卡顿
- Agent Console 追加日志不造成输入延迟
- 单个扫描任务异常不能拖垮整个桌面应用
- MCP 工具长时间运行时，用户仍可切换页面、暂停任务、查看日志
- 情报在线更新和索引构建必须在后台执行，不影响已有扫描任务

---

## 18. 版本路线图

### 18.1 M0: 架构骨架期

目标：

- 搭建 monorepo
- Electron 基础框架
- SQLite 基础 schema
- Settings 页面
- API Key 配置
- MCP Host / Client 架构设计与 contract 草案
- 完成开源同类项目参考矩阵与第一版架构对标文档

### 18.2 M1: 最小闭环期

目标：

- 目标管理
- 基础会话管理
- ReconAgent + PlannerAgent 初版
- Browser Runner 初版
- MCP Center 页面初版
- 本地 `STDIO` MCP Server 接入
- MCP 连接测试与能力发现初版
- `ToolBroker` 初版
- `Kali MCP Server Profile` 设计草案

### 18.3 M2: 检测链路期

目标：

- InterfaceAgent
- KnowledgeAgent
- StrategyAgent
- HTTP Runner
- Evidence 模型
- `Streamable HTTP` MCP Server 接入
- ToolBroker 与 Agent 可用范围绑定
- MCP 权限审批与 roots 配置
- Kali MCP Server 接入
- Kali 工具 namespace 管理
- Tool Profile / Evidence Mapping 机制初版
- SSH 辅助维护能力草案

### 18.4 M3: 复核与报告期

目标：

- AnalysisAgent
- VerifierAgent
- Findings 页面
- 报告导出
- MCP 调用审计展示
- Agent Console 中的 MCP 调用时间线
- Verdict 规则库初版
- `Confirmed / Not Confirmed / Inconclusive` 三态结果协议
- 证据化验证流程
- Kali MCP 工具输出到 EvidenceItem 的结构化映射

### 18.5 M4: 产品化增强期

目标：

- 自动恢复
- 日志检索
- 成本统计
- 多 provider 支持
- 插件化扩展点
- Windows 安装器初版
- 卸载流程
- 开始菜单与桌面快捷方式
- 安装路径选择
- 升级安装保留用户数据
- MCP 模板库与导入导出
- MCP 高权限 Server 风险提示增强
- Kali MCP Profiles 管理页
- 工具 namespace 风险标签与审批增强
- 情报源管理与后台索引更新

### 18.6 M5: 性能优化期

目标：

- 将热点模块下沉到 Rust sidecar
- 优化大任务稳定性
- 增强情报检索与 RAG
- 支持更多身份和任务模板
- 性能压测与卡顿治理

---

## 19. 编码与协作规范

### 19.1 语言使用规范

- 代码标识符统一使用英文
- 文档优先使用中文
- 重要领域对象命名统一，不能同义多名

### 19.2 依赖引入规范

- 新增依赖前先说明用途和替代方案
- 不要同时引入多套重复能力的库
- 不为小问题引入大型框架

### 19.3 跨层调用规范

- Renderer 不直接访问文件系统和数据库
- Renderer 只能通过 Preload 暴露的白名单 API 与 Main 通信
- 业务模块不能直接依赖 Electron UI 层

### 19.4 模型调用规范

- 所有模型调用都必须经过 `ModelGateway`
- 所有 Agent 输出都要经过 schema 校验
- 关键结论必须绑定证据引用

### 19.5 数据库规范

- 统一通过仓储或查询服务访问数据库
- 变更 schema 必须写迁移
- 不允许业务逻辑散落 SQL 字符串

### 19.6 Prompt 规范

- Prompt 视为代码
- 必须版本化
- 必须可测试
- 修改 Prompt 需要记录影响范围

### 19.7 安全策略规范

- 任何新增执行动作都要先接入 `SecurityPolicy`
- 任何新增导出字段都要考虑脱敏
- 任何新增凭据存储都不能明文落库

---

## 20. 给未来 AI 编程代理的明确要求

未来任何 AI 代理在本仓库内工作时，默认遵守以下规则：

1. 优先沿用本文件定义的 TypeScript + Electron + Playwright + SQLite 架构，不要随意改主栈。
2. 没有充分理由，不要引入 Python。
3. 任何模型能力接入都必须走 `ModelGateway`，不要在业务层直接写第三方 SDK 调用。
4. 任何扫描执行能力都必须经过 `SecurityPolicy`。
5. 任何新增外部工具接入，优先评估是否以 `MCP Hub / ToolBroker` 方式接入；不要在多个业务模块里各自私接脚本、SDK 或子进程。
6. 参考开源 Multi-Agent 项目时，只提炼可复用方法，不直接复制其角色设计、目录结构和框架耦合方式。
7. 如果采用某个开源 Agent 框架或其局部机制，必须先证明它服务于本项目现有领域模型，而不是要求本项目去适配它。
8. 新增一个 Agent，必须同时补齐：
   - Prompt
   - 输入输出 schema
   - 运行时注册
   - 日志字段
   - 测试
9. 新增一种发现类型，必须同时补齐：
   - 领域模型
   - Evidence 结构
   - Finding 展示
   - 报告导出
   - 最小测试样例
10. 任何跨进程通信都先定义 contract，再写实现。
11. 任何数据库变更都要可迁移、可回滚、可测试。
12. 任何涉及敏感信息的功能都要先考虑脱敏和本地安全存储。
13. 任何影响长期架构的变更，都先更新本文件。

---

## 21. Definition of Done

一个功能只有同时满足以下条件，才算完成：

- 有明确的用户价值
- 有清晰的输入输出边界
- 已接入现有架构层级
- 有最小测试覆盖
- 有日志与错误处理
- 不绕过安全策略
- 如果该功能属于发布链路或安装体验范围，则必须被纳入标准 Windows 安装包并完成安装、启动、卸载验证
- 文档已更新

---

## 22. 最终建议结论

对于你当前这个长期项目，最稳妥、最适合 Windows 桌面形态、又能兼顾开发效率与后续产品化的路线是：

**以 `Electron + React + TypeScript + Playwright + SQLite` 为主栈，采用本地多进程桌面架构，统一通过 `API Key + ModelGateway` 接入外部大模型服务，并围绕 Planner / Recon / Interface / Knowledge / Strategy / Execution / Analysis / Verifier / Report 这一套可扩展的 Multi-Agent 体系持续迭代；最终对外默认交付为标准 `Windows Installer (.exe)`，让使用者像安装常见桌面软件一样完成安装、创建快捷方式和启动程序。**

这条路线的核心优势是：

- 不依赖 Python
- 适合 Windows 桌面客户端
- 浏览器自动化与模型编排生态成熟
- 易于做出可演示、可测试、可申请软著的完整软件系统
- 未来若性能成为瓶颈，可以把热点模块逐步 Rust 化，而不需要推翻整体架构

本文件从现在开始视为本项目的长期架构基线。
