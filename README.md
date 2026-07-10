# AgentGo

基于 Multi-Agent 协作的授权 Web 漏洞挖掘与验证 Windows 桌面系统。

> 当前状态：M0 架构骨架期。仓库已建立 Electron + React + TypeScript monorepo、确定性安全策略和核心 Agent/知识库契约。

## 项目目标

AgentGo 面向教学靶场、自有系统和有明确授权的测试环境，通过多个职责清晰的 Agent 对 Web 应用的页面、接口、参数、身份、请求、响应和状态流转进行持续分析，形成“规划—知识检索—主动验证—独立复核—证据报告”的完整闭环。

项目强调两件事：

1. 必须保留低影响主动探测能力，否则无法确认真实漏洞。
2. 主动探测必须受确定性安全策略约束，不能破坏真实业务或越出授权范围。

## V1 范围

- SQL 注入
- XSS
- SSRF
- 越权访问 / IDOR

V1 只执行非破坏、可审计的验证动作。数据库 DROP/TRUNCATE 和生产数据增删改、真实账户接管、持久化、横向移动、高强度 DoS 等动作永久禁止。

## 核心流程

```text
Scope Intake
  -> Passive Recon
  -> Safe Active Enumeration
  -> Hypothesis + KnowledgePack
  -> Policy-approved Validation
  -> Independent Verification
  -> Evidence-backed Report
```

最终结论统一为：

- Confirmed：满足版本化确认规则且证据完整。
- Not Confirmed：已完成验证但未达到确认标准。
- Inconclusive：条件不足、环境不稳定或继续验证风险过高。

## 技术架构

- 桌面端：Electron + React + TypeScript + Vite
- 包管理：pnpm workspace
- 浏览器执行：Playwright
- HTTP 执行：undici
- 本地数据：SQLite + Drizzle ORM + Files
- 模型接入：Provider-neutral ModelGateway
- Schema：Zod
- 测试：Vitest

模型型 Agent 负责 Planner、Knowledge、Strategy、Analysis、Verifier；SecurityPolicy、执行器、证据存储和报告生成保持确定性。

## 开始开发

要求：

- Windows 10/11
- Node.js 24+
- pnpm 10+

```powershell
pnpm install
pnpm dev
```

质量检查：

```powershell
pnpm typecheck
pnpm test
pnpm build
pnpm smoke:desktop
```

本机已有的可选开发环境配置见 docs/development-environment.md；项目本身不依赖固定盘符。

## 文档

- docs/README.md：完整文档索引
- docs/workflows/src-hunting.md：授权 SRC 工作流
- docs/security/active-probing-policy.md：主动探测安全规范
- docs/knowledge/knowledge-agent.md：KnowledgeAgent 与知识库设计
- docs/evaluation/benchmark-plan.md：研究评测计划
- docs/roadmap.md：2026—2027 路线图

原始大创申报材料包含个人信息，不作为公开仓库文档发布。

## 合规声明

本项目只允许用于有明确授权的资产。使用者必须遵守目标范围、测试规则、速率限制、数据保护和漏洞披露约定。任何绕过 SecurityPolicy、对真实业务造成破坏或测试未授权目标的行为都不属于项目支持范围。

## License

许可证尚未确定。在许可证明确前，请勿将本项目代码用于对外再分发或商业部署。
