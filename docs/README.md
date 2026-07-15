# AgentGo 文档索引

## 使用与交付

- [user-guide.md](user-guide.md)：安装、Agent 模型、MCP Server、授权 Scope、身份、扫描控制、报告和数据安全
- [development-environment.md](development-environment.md)：开发、测试、评测和 Windows 打包环境
- [../benchmarks/README.md](../benchmarks/README.md)：固定靶场与 40 Case 基准运行说明

## 项目与架构

- [project-scope.md](project-scope.md)：研究目标、产品边界、V1 范围和交付物
- [architecture/overview.md](architecture/overview.md)：桌面进程、领域层、基础设施层和仓库结构
- [architecture/agent-system.md](architecture/agent-system.md)：Agent 角色、通信协议、记忆与状态机
- [architecture/data-model.md](architecture/data-model.md)：核心实体、证据链和数据库映射

## 安全与测试

- [security/active-probing-policy.md](security/active-probing-policy.md)：主动探测等级、批准规则和永久禁令
- [security/threat-model.md](security/threat-model.md)：恶意页面、外部模型、Electron、MCP 和执行器威胁
- [workflows/src-hunting.md](workflows/src-hunting.md)：授权 SRC 阶段门禁和证据纪律
- [evaluation/benchmark-plan.md](evaluation/benchmark-plan.md)：固定靶场、Ground Truth、指标和消融实验
- [audits/v1-current-capability-audit.md](audits/v1-current-capability-audit.md)：当前代码与计划书功能满足度核查
- [audits/day1-final-review-2026-07-15.md](audits/day1-final-review-2026-07-15.md)：Day1 正式提交前补强、最终数据库 hash 与门禁复核
- [audits/day2-completion-2026-07-15.md](audits/day2-completion-2026-07-15.md)：Day2 开放 ID、Registry、Activation/compatibility 门禁与完整回归证据

## 知识与研究

- [knowledge/knowledge-agent.md](knowledge/knowledge-agent.md)：知识摄取、检索、KnowledgePack、来源和质量评估
- [research/related-work.md](research/related-work.md)：同类开源项目对照与借鉴原则

## 计划与决策

- [roadmap.md](roadmap.md)：当前实现状态、后续研究任务和里程碑
- [planning/README.md](planning/README.md)：后端优先的 20 个顺序工作包、测试与验收索引
- [planning/Day0.md](planning/Day0.md)：当前实况、Day1/Day2 撤销、依赖复审和规划完成记录
- [planning/Day1.md](planning/Day1.md)：Day1 目标、退出门槛和完成记录
- [planning/day1-baseline.md](planning/day1-baseline.md)：Scope 修复、版本、测试/benchmark、合成数据库 hash 与 Git/Renderer 边界
- [planning/requirements-traceability.md](planning/requirements-traceability.md)：稳定需求 ID、支持声明格式、当前/后续/非目标与唯一主责
- [planning/complex-web-20-day-plan.md](planning/complex-web-20-day-plan.md)：20 个工作包的共同边界、顺序依赖和最终验收
- [planning/backend-v2-architecture.md](planning/backend-v2-architecture.md)：开放式漏洞模块、ValidationPlan、执行与证据架构
- [planning/web-vulnerability-coverage-matrix.md](planning/web-vulnerability-coverage-matrix.md)：完整 Web 漏洞目录、当前成熟度、允许环境和实施波次
- [planning/web-vulnerability-coverage-catalog.json](planning/web-vulnerability-coverage-catalog.json)：98 项机器可读覆盖目录、Capability/停止条件/资格状态与来源审计
- [planning/complex-web-interface-capability-matrix.md](planning/complex-web-interface-capability-matrix.md)：复杂 Web/API 协议的解析、盘点、重放、主动验证与安全边界
- [planning/post-20-day-vulnerability-roadmap.md](planning/post-20-day-vulnerability-roadmap.md)：20 天后的七波纯后端覆盖路线
- [adr/](adr/)：重大技术与安全决策记录
