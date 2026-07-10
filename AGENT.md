# AgentGo 项目设计入口

> 文档状态：当前有效
> 基线日期：2026-07-10
> 项目周期：2026-06 至 2027-06

## 1. 项目定位

AgentGo 是“基于 Multi-Agent 协作的授权 Web 漏洞挖掘与验证系统”的 Windows 桌面研究原型。

系统围绕页面、接口、参数、身份、请求、响应和业务状态构建统一上下文，由多个职责清晰的 Agent 协作完成：

1. 任务规划；
2. 目标与接口整理；
3. 漏洞知识检索；
4. 安全测试策略生成；
5. 低影响主动验证；
6. 响应分析与独立复核；
7. 证据化报告和修复建议。

项目只面向教学靶场、自有系统和有明确授权的测试环境。它不是未授权公网扫描器，也不追求破坏性利用、持久化或横向移动。

## 2. 不变的核心思想

- Windows 桌面、本地优先、可安装交付。
- TypeScript 为主栈，Electron + React 提供桌面体验。
- Playwright 与 HTTP Runner 负责浏览器和协议级测试。
- SQLite + Files 保存任务状态、上下文、证据和报告。
- 所有模型访问统一经过 ModelGateway。
- 多 Agent 通过版本化结构化对象协作，不依赖无边界自然语言串话。
- 所有执行动作先经过确定性的 SecurityPolicy。
- 主动探测是核心能力，但必须低影响、可审计、可回退、有预算。
- 最终结论遵循 Signal -> Validation -> Verdict，并使用 Confirmed / Not Confirmed / Inconclusive 三态协议。
- 所有 Confirmed Finding 必须绑定可复现证据和修复建议。

## 3. V1 研究范围

一期优先跑通以下四类漏洞的端到端闭环：

| 漏洞族 | V1 目标 | 默认边界 |
|---|---|---|
| SQL 注入 | 非写入式差异验证、证据归档 | 禁止 DROP、TRUNCATE、DELETE、UPDATE、INSERT、堆叠写操作 |
| XSS | 使用惰性标记和隔离浏览器确认执行上下文 | 禁止窃取 Cookie、影响真实用户或植入持久恶意内容 |
| SSRF | 仅访问受控回连端点或明确授权的测试服务 | 禁止访问云元数据、未授权内网、回环地址和越界目标 |
| 越权 / IDOR | 使用两个授权测试身份进行只读差异验证 | 禁止修改、删除或公开其他真实用户数据 |

文件上传、OAuth/JWT、业务逻辑、GraphQL 等作为后续扩展。MCP Server 配置、连接测试和能力发现已经接入；Agent 自动调用、Kali 工具服务器和 Rust sidecar 仍是增强项，不能绕过或阻塞 V1 核心闭环。

### V1 自动化能力的明确边界

当前自动验证器只对**授权范围内的 GET 查询参数**执行 L1 低影响验证；它会建立链接、表单和参数清单，但不会自动对 POST、PUT、PATCH、JSON Body、Header、Cookie 或路径参数发起验证。任何可能改变业务状态的请求都必须作为 L2 提案，绑定专用测试对象、清理方案和逐次人工批准。

因此，V1 已证明的是“固定本地靶场上的四类漏洞闭环”，不是对复杂 SPA、登录流程、业务工作流或任意 API 形态的完整覆盖。盲 SSRF、存储型/复杂 DOM XSS、路径/Body 型 IDOR 和复杂业务逻辑仍应保持 `Inconclusive`，直到相应的证据采集与确认规则实现并通过评测。

## 4. Agent 与确定性服务边界

V1 的模型型 Agent：

- PlannerAgent：生成和修订任务计划。
- KnowledgeAgent：构造带来源、适用性和安全约束的 KnowledgePack。
- StrategyAgent：将上下文和知识转化为验证假设与候选测试方案。
- AnalysisAgent：比较基线与测试结果，生成 Signal。
- VerifierAgent：依据版本化确认规则给出 Verdict。

确定性服务：

- SecurityPolicy：授权范围、速率、并发、方法和破坏性动作硬门禁。
- BrowserRunner / HttpRunner：执行获批动作并采集证据。
- EvidenceStore：不可变证据、哈希、脱敏和来源管理。
- Reporting：模板化输出报告、复现步骤和修复建议。
- AgentRuntime：状态机、预算、重试、检查点和结构化消息路由。

模型可以提出动作，但不能自行扩大授权范围，也不能覆盖 SecurityPolicy 的拒绝结果。

## 5. 当前技术基线

- Electron + React + TypeScript + Vite
- pnpm workspace monorepo
- Playwright Core 隔离 BrowserRunner（已接入 DOM、表单、链接和惰性 XSS 标记验证）
- undici HttpRunner（已接入 DNS 固定、逐跳重定向复检和响应证据采集）
- SQLite + Drizzle ORM
- Zod 作为配置、IPC 和 Agent 输出校验层
- Vitest 作为单元和集成测试框架
- electron-builder + NSIS 作为后续 Windows 安装器

架构详情见 docs/architecture/overview.md。

## 6. 当前规范文档

- docs/project-scope.md：目标、非目标和交付边界
- docs/architecture/overview.md：总体架构和仓库结构
- docs/architecture/agent-system.md：Agent、消息协议、记忆和终止条件
- docs/architecture/data-model.md：核心数据实体和可追溯关系
- docs/security/active-probing-policy.md：低影响主动探测分级和硬性禁令
- docs/security/threat-model.md：Agentic、Electron、模型和工具威胁模型
- docs/workflows/src-hunting.md：授权 SRC 漏洞挖掘阶段门禁
- docs/knowledge/knowledge-agent.md：知识库、检索、KnowledgePack 和质量评估
- docs/evaluation/benchmark-plan.md：基准、对照实验和指标
- docs/audits/v1-current-capability-audit.md：当前实现与计划书的可验证满足度及缺口
- docs/roadmap.md：与大创计划对应的阶段安排
- docs/research/related-work.md：开源同类项目研究记录

根目录 AGENTS.md 是人类开发者和 AI 编程代理都必须遵守的精简工程规则。
其中“Codex 开发八荣八耻”属于 MUST 级行为准则，所有实现、调试、重构和验证任务均不得绕过。

## 7. 决策管理

文档中的要求使用以下含义：

- MUST：安全、数据和架构不变量，不能静默绕过。
- SHOULD：默认方案；偏离时必须写 ADR 并说明证据。
- MAY：可选增强，不得阻塞当前里程碑。

重大技术调整先记录到 docs/adr/，再修改实现。历史长版架构基线保存在 docs/archive/architecture-baseline-2026-04-29.md，仅供追溯。
