# 2026—2027 项目路线图

## 当前状态

截至 2026-07-10，项目处于第一阶段：架构、文档、评测设计和桌面骨架建设。

## 角色分工建议

- Architecture Lead：仓库、契约、状态机和跨进程边界；
- Agent Lead：Planner/Strategy/Analysis/Verifier 与 Prompt；
- Knowledge Lead：知识摄取、检索、确认规则和修复建议；
- Security & Evaluation Lead：SecurityPolicy、靶场、Ground Truth 和指标；
- Desktop & QA Lead：Electron UI、构建、安装器、测试和文档。

项目组应在周计划中将实际成员映射到上述角色；关键模块至少一主一审。

## 第一阶段：2026.06—2026.08

目标：形成可运行骨架和一条安全的完整垂直链路。

交付：

- 文档体系、ADR、安全规范和威胁模型；
- Electron + React + TypeScript monorepo 骨架；
- contracts、domain、security-policy、agent-runtime、knowledge-base、db 基础包；
- SecurityPolicy 自检和最小 UI；
- 固定靶场与第一版 Ground Truth；
- 单一漏洞族从 Hypothesis 到 Report 的垂直样例；
- 相关项目对照矩阵。

退出条件：

- pnpm typecheck、test、build 通过；
- 安全动作允许、破坏性动作拒绝的自动测试通过；
- 至少一个真实本地靶场 Case 有完整证据；
- 第一版基线指标已记录。

## 第二阶段：2026.09—2026.11

目标：完成核心 Agent、上下文和知识链路。

交付：

- Planner、Knowledge、Strategy 初版；
- Analysis、Verifier 基础闭环；
- 页面—接口—参数—身份—交互统一上下文；
- BrowserRunner、HttpRunner 初版；
- SQLite 持久化和 checkpoint；
- SQL 注入、XSS 两类知识包和确认规则；
- 模型图形化配置、凭据引用和连接测试；
- 阶段性演示版本。

退出条件：

- 两类漏洞具有正例、负例和误报分析；
- 长任务可暂停、恢复、取消；
- Agent 循环和预算限制生效；
- 每条 Confirmed Finding 可追溯到规则和证据。

## 第三阶段：2026.12—2027.02

目标：扩展四类漏洞并完成主要研究实验。

交付：

- SSRF、越权/IDOR；
- 多身份、资源归属和业务状态对照；
- KnowledgePack 缓存和 Hybrid Retrieval 实验；
- 四类漏洞基准；
- 单 Agent/Multi-Agent、无知识/有知识、无 Verifier/有 Verifier 消融；
- Precision、Recall、F1、FPR、成本和稳定性报告；
- 误报模式库和规则优化。

退出条件：

- 四类漏洞端到端可运行；
- 安全硬门禁全部为 0 违规；
- 主要研究问题具有数据支持；
- 测试环境可重置且实验可重复。

## 第四阶段：2027.03—2027.05

目标：产品化、最终评测和结题材料。

交付：

- Dashboard、Target、Session、Scan、Agent Console、Findings、Knowledge 页面；
- 报告导出与脱敏；
- Windows Installer、卸载和升级保留数据验证；
- 最终重复实验和图表；
- 使用说明、研究总结和软著申报材料；
- 演示脚本和答辩材料。

退出条件：

- 安装、启动、扫描、恢复、导出、卸载流程通过；
- 最终报告可复现；
- 文档和软著材料完整；
- 演示只使用本地靶场或明确授权环境。

## 收尾：2027.06

- 修复结题前问题；
- 归档数据、代码、模型/Prompt/规则版本；
- 完成项目验收和后续研究计划。

## Stretch Goals

只有核心四类漏洞和评测完成后再考虑：

- 通用 MCP Center；
- Kali MCP Server Profile；
- 远程 Streamable HTTP 工具服务器；
- OAuth/JWT、文件上传、GraphQL、业务逻辑扩展；
- Embedding 默认启用；
- Rust sidecar；
- 自动更新和代码签名。

Stretch Goal 不能占用核心评测、证据链和安全策略的时间。
