# 同类项目研究与借鉴原则

> 本文记录架构研究，不代表复制或依赖这些项目。外部项目状态会变化，采用前必须重新核对仓库、论文、许可证和维护情况。

## 对照对象

| 项目 | 主要观察维度 | 本项目可能借鉴 | 不直接照搬 |
|---|---|---|---|
| PentestGPT | 长链路上下文、会话恢复、评测 | checkpoint、benchmark 意识 | Python/Docker/终端优先形态 |
| AutoPentest AI | 阶段门禁、独立 Judge | Verifier、质量门禁 | 大型工具集合和实现耦合 |
| CortexAI | SQLite、证据、审计 | 本地项目数据库、证据链 | shell-first 产品形态 |
| PentAGI | 工具/模型配置、记忆、可观测性 | 配置分层、远期工具扩展 | V1 重型服务和监控栈 |
| PentestAgent | playbook、子任务、工具协议 | TaskTemplate、ToolBroker | Python/CLI-first |
| Pentest Swarm AI | blackboard、事件驱动 | 后续轻量事件触发 | V1 全自动 swarm |
| Pentest Copilot | 浏览器、人工审批 | BrowserRunner、Hybrid UI | Kali/Docker 核心假设 |
| Decepticon | RoE、模型 Profile、计划包 | ScopeSnapshot、ModelProfile | 红队全链路 |
| MASAPT | 分层多 Agent | Planner/Analysis/Report 分层 | XMPP/SPADE 实现 |

更长的历史调研只保留在本地开发基线中，不作为当前交付规范。

## 评估维度

新增或更新参考对象时记录：

- 仓库和论文链接；
- 检查日期和 commit/tag；
- 许可证；
- 角色与状态机；
- 工具调用协议；
- 记忆与知识库；
- 证据和评测；
- 安全边界；
- 部署与依赖；
- 可借鉴方法；
- 不适合本项目的部分。

## 借鉴原则

- 借鉴方法，不复制品牌、Prompt、目录和对象模型；
- 先映射到 Target、Scope、Identity、Interaction、Signal、Validation、Evidence、Finding；
- 外部框架只能位于可替换实现层；
- 采用代码、知识或规则前核对许可证和来源；
- 对外部项目的性能或能力描述必须附来源和日期；
- 没有 benchmark 和证据的数据不得作为本项目技术选型的唯一理由。
