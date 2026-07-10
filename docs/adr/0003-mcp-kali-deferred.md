# ADR-0003：通用 MCP 与 Kali 集成延后

- 状态：Accepted
- 日期：2026-07-10

## 背景

MCP 和 Kali 能提高工具扩展性，但会显著增加远程连接、权限、审计、错误处理和 UI 复杂度。大创计划的核心研究问题是 Multi-Agent、知识增强、主动验证和误报控制。

## 决策

V1 先实现内部 ToolBroker、BrowserRunner 和 HttpRunner。通用 MCP Center、远程 Streamable HTTP、Kali Profile 和 SSH 维护列为 Stretch Goals。

## 重新评估条件

- 四类漏洞端到端闭环完成；
- 基准和主要消融完成；
- SecurityPolicy 与 Evidence 映射稳定；
- 项目仍有明确时间和人员预算。
