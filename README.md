# AgentGo

基于 Multi-Agent 协作的授权 Web 漏洞挖掘与验证 Windows 桌面系统。

> 当前状态：V1 可运行原型。SQL 注入、XSS、SSRF、越权/IDOR 已接入 `Signal -> Validation -> Verdict -> Evidence -> Report` 完整闭环，并具备本地持久化、异常恢复、评测靶场和 Windows 打包能力。

> 自动验证边界：当前运行器只自动验证授权范围内的 **GET 查询参数**。表单、POST/PUT/PATCH、JSON Body、Header、Cookie、路径参数、复杂 SPA 交互和盲回连场景会被盘点或标记为 `Inconclusive`，不会被静默扩展为真实业务写操作。

## 使用边界

AgentGo 只允许用于教学靶场、自有系统和有明确书面授权的目标。所有主动请求必须同时满足不可变 Scope、身份范围、网络边界、速率/并发预算和 `SecurityPolicy` 决策。

V1 永久拒绝破坏性写入、生产数据增删改、真实账户接管、云元数据访问、持久化、横向移动、凭据喷洒和高强度 DoS。证据充分后立即停止验证，不扩大影响。

`POST`、`PUT` 和 `PATCH` 默认不是 L1 自动动作。只有专用测试对象、可验证清理方案和可信逐次人工批准同时具备时，才可能作为 L2 动作执行；当前 V1 尚无完整 TestObject/Approval/Cleanup 闭环，因此产品环境 L2 保持禁用，相关能力属于后端 V2 计划。

## 已实现功能

- 五 Agent：Planner、Knowledge、Strategy、Analysis、Verifier；所有模型调用统一经过 `ModelGateway`。
- 四类漏洞：SQLi 布尔差异、XSS 隔离浏览器惰性标记、SSRF 目标响应内的受控 proof（非真实 OOB Collector）、IDOR 双授权身份只读对照。
- 确定性执行边界：HTTP DNS/重定向逐跳复检，浏览器断网渲染，L3 动作永久拒绝。
- 本地数据层：SQLite、迁移、不可变 Scope 快照、每 Target 单调 revision/显式 current pointer、Checkpoint、审计和扫描事件。
- 凭据与证据：Electron `safeStorage`、内容寻址证据、SHA-256 完整性校验、脱敏派生。
- 扫描控制：启动、暂停、恢复、取消；异常退出后的未完成任务在下次启动时安全恢复为暂停。
- 结论与报告：Confirmed、Not Confirmed、Inconclusive；Markdown、JSON、HTML 脱敏报告。
- 知识库：四类内置知识、公开情报/PoC 文本导入、Extractor/Reviewer 双 Agent 结构化复核、人工发布、来源/许可证元数据、SQLite FTS5 与中文子串回退检索。
- 桌面边界：Renderer 通过双向 Zod 校验的 IPC 使用应用服务，不能直接访问数据库、文件、凭据或执行器。
- 评测：固定版本本地靶场、40 个正负 Case、指标计算和六项安全硬门禁。

## 技术架构

- Electron + React + TypeScript + Vite
- pnpm workspace
- Node SQLite + Drizzle ORM
- undici HTTP Runner
- Playwright Core 隔离浏览器 Runner
- Zod 契约与 Vitest 测试
- electron-builder + NSIS Windows 交付

## 开发运行

要求 Windows 10/11、Node.js 24+、pnpm 10+。XSS 隔离验证需要系统已安装 Microsoft Edge 或 Google Chrome；Windows 10/11 通常已包含 Edge。

```powershell
pnpm install
pnpm dev
```

首次使用时按以下顺序操作：

1. 在“工作台”创建或选择工作区，并运行安全门禁自检。
2. 在“目标与身份”填写授权依据、Base URL 和最小允许 Scope。
3. IDOR 测试需配置两个明确授权的测试身份及各自已知资源 ID。
4. 可选：在“MCP Center”添加本地 STDIO 或远程 Streamable HTTP Server，手动测试连接并检查能力清单。
5. 在“扫描与 Agent”填写任务与授权背景，选择漏洞族、身份、预算，并为五个 Agent 明确选择模型 Profile；SSRF 回调 URL 也必须位于 Scope 内。
6. 启动任务，查看阶段事件、接口、证据和 Findings；完成后生成并导出脱敏报告。

完整操作说明见 [docs/user-guide.md](docs/user-guide.md)。

## 模型配置

应用首次启动会为五个角色创建本地确定性 Profile，因此无需外部 API 即可运行固定流程和基准。也可以在“Agent 与模型”中添加 OpenAI-compatible Provider，填写 Base URL、模型和 API Key 后执行连接测试。连接测试会真实调用该 Profile 的 `chat/completions` 并校验最小 JSON 响应，不再只检查 `/models` 列表。

创建扫描时会把 Planner、Knowledge、Strategy、Analysis、Verifier 的 Profile ID 固定到任务配置中，运行期间不会因为全局 Profile 顺序变化而悄然换模型。API Key 只进入操作系统加密凭据文件，SQLite 仅保存 `credentialId`。外部模型输入会先脱敏，创建页会明确显示任务描述和结构化上下文将发往哪些 Provider；输出必须通过角色对应的结构化 Schema。模型不能直接调用执行器或改变安全策略。模型管理只累计每个 Profile 的输入、输出和总 Token，不记录或估算费用。

## MCP Server 配置

“MCP Center”支持本地 STDIO 与远程 Streamable HTTP Server。配置保存不会自动连接；只有用户点击“测试连接”才会启动本地命令或访问远程 URL。测试成功后展示 Server 信息及 tools、resources、prompts 清单。MCP Token、环境变量和自定义请求头通过 `safeStorage` 加密，SQLite 只保存字段名和 `credentialId`。新 Server 默认禁用，Agent 自动调用 MCP 工具尚未开放。

## 质量检查

```powershell
pnpm check
pnpm smoke:desktop
pnpm benchmark:verify
```

`pnpm check` 依次执行全仓 TypeScript 检查、Vitest 和桌面构建。`smoke:desktop` 会启动开发构建并验证 Renderer、主进程和安全策略，不会访问外部目标。

## 固定靶场评测

```powershell
# 可选：单独启动靶场供人工检查
pnpm benchmark:fixture

# 自动启动固定靶场并运行 40 Case
pnpm benchmark:run --output .\benchmark-results\my-run
```

2026-07-10 对 `agentgo-local-fixture/1.0.0` 的确定性回归运行结果为：40/40 有结论，20 个正例均 Confirmed，20 个负例均 Not Confirmed，Precision/Recall/F1 和证据完整率均为 1，FPR 为 0，六项安全硬门禁均为 0。

这只是自建、固定、同分布靶场的回归基线，用于证明闭环和防止代码回退；不能据此推断真实互联网或复杂业务系统上的检测效果。Ground Truth 人工复核、第三方靶场、重复稳定性和消融实验仍需按研究计划继续完成。运行结果默认写入被 Git 忽略的 `benchmark-results/`。

2026-07-13 Day1 已修复 [DAY0](docs/planning/Day0.md) 复现的同毫秒 Scope 竞态：每个 Target 使用单调 revision 和显式 current pointer，Scan 冻结精确 scope ID/version，旧库可确定性回填，并由同毫秒、路径别名双连接并发、create/update、事务回滚和 Application 精确返回测试覆盖。最终代码在三个全新目录连续完成 40/40，三次均为 TP 20、TN 20、FP/FN/Inconclusive 0，六项安全计数全 0。完整版本、命令、数据库 hash 与限制见 [Day1 事实基线](docs/planning/day1-baseline.md)；该结果仍只代表自建固定 fixture。

## Windows 打包

```powershell
# 生成免安装目录
pnpm pack:win

# 验证打包后的 EXE 能完成启动与策略自检
pnpm smoke:packaged

# 生成 x64 NSIS 安装器
pnpm dist:win
```

产物位于 `release/`。当前为未签名研究原型，使用默认应用图标，Windows 可能显示信誉提示；这不影响核心功能验证。安装器按用户安装，并配置为卸载时保留应用数据。

## 文档

- [docs/README.md](docs/README.md)：文档索引
- [docs/user-guide.md](docs/user-guide.md)：安装、授权配置、扫描和报告说明
- [docs/security/active-probing-policy.md](docs/security/active-probing-policy.md)：主动探测安全规范
- [docs/architecture/overview.md](docs/architecture/overview.md)：进程和模块边界
- [docs/knowledge/knowledge-agent.md](docs/knowledge/knowledge-agent.md)：知识链路
- [docs/evaluation/benchmark-plan.md](docs/evaluation/benchmark-plan.md)：研究评测计划
- [docs/audits/v1-current-capability-audit.md](docs/audits/v1-current-capability-audit.md)：当前代码与计划书的核查结论
- [docs/planning/Day0.md](docs/planning/Day0.md)：当前实况、Day1/Day2 撤销、二十个工作包依赖复审
- [docs/planning/Day1.md](docs/planning/Day1.md)：Day1 目标与完成记录
- [docs/planning/day1-baseline.md](docs/planning/day1-baseline.md)：Scope 修复、环境版本、测试/benchmark 与合成数据库事实基线
- [docs/planning/requirements-traceability.md](docs/planning/requirements-traceability.md)：稳定需求 ID、支持声明格式和后续主责
- [docs/planning/README.md](docs/planning/README.md)：后端 V2 顺序工作包、漏洞覆盖与复杂接口能力矩阵
- [docs/roadmap.md](docs/roadmap.md)：当前事实与后续研究工作

原始大创申报材料包含个人信息，不作为公开仓库文档发布。

## License

许可证尚未确定。在许可证明确前，请勿将本项目代码用于对外再分发或商业部署。
