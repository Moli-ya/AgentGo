# AgentGo

基于 Multi-Agent 协作的授权 Web 漏洞挖掘与验证 Windows 桌面系统。

> 自动验证边界：当前运行器只自动验证授权范围内的 **GET 查询参数**。表单、POST/PUT/PATCH、JSON Body、Header、Cookie、路径参数、复杂 SPA 交互和盲回连场景会被盘点或标记为 `Inconclusive`，不会被静默扩展为真实业务写操作。

## 使用边界

AgentGo 只允许用于教学靶场、自有系统和有明确书面授权的目标。所有主动请求必须同时满足不可变 Scope、身份范围、网络边界、速率/并发预算和 `SecurityPolicy` 决策。

V1 永久拒绝破坏性写入、生产数据增删改、真实账户接管、云元数据访问、持久化、横向移动、凭据喷洒和高强度 DoS。证据充分后立即停止验证，不扩大影响。

`POST`、`PUT` 和 `PATCH` 默认不是 L1 自动动作。只有专用测试对象、可验证清理方案和可信逐次人工批准同时具备时，才可能作为 L2 动作执行。当前已落地 TestObject/Bundle/Cleanup 纯状态协议，但产品环境在缺少会话绑定与可信批准时保持 L2 禁用，不得对目标发送 L2 请求。

## 已实现功能

- 五 Agent：Planner、Knowledge、Strategy、Analysis、Verifier；所有模型调用统一经过 `ModelGateway`。
- 四类 legacy 路径：SQLi 布尔差异、XSS 隔离浏览器惰性标记、SSRF 目标响应内的受控 proof（非真实 OOB Collector）、IDOR 双授权身份只读对照。当前 XSS 只有 hash-only 执行摘要，没有可审阅 DOM/截图 Evidence，因此 marker 执行只能形成 `Inconclusive`，不能 Confirmed。
- 漏洞扩展底座：开放 `familyId/techniqueId`、严格 Manifest/Bundle、不可变 Capability Catalog、Capability 风险下界校验、原子 DefinitionRegistry、Module Conformance testkit、canonical definition/snapshot hash 和 registered-only Activation 视图。
- 执行资格门禁：CreateScan、start、resume、Candidate 同时核对冻结定义、精确运行时映射与 ActivationCatalog；四类 legacy technique 由 QualificationRecord 取得 `qualified`，未知 ID 和 registered-only 的 `security.headers` 失败关闭。
- 确定性执行边界：三阶段请求证明、不可变 Grant、原子单次 Lease、exact-wire Runner Guard、HTTP DNS/重定向逐跳 fresh authority、浏览器断网渲染和 L3 永久拒绝。
- 原子预算与网络门禁：scan 级请求/RPM/并发/字节/时长在 claim 事务内原子 reserve；精确网络条目与 URL canonicalization fail-closed；HTTP 响应实行 header/解压/压缩比/慢读上限。
- 本地数据层：SQLite、迁移、不可变 Scope 快照、每 Target 单调 revision/显式 current pointer、Checkpoint、审计和扫描事件。
- 凭据与证据：Electron `safeStorage`、内容寻址证据、SHA-256 完整性校验、默认最小化/脱敏写入，以及带加密、后端访问边界、保留期、配额、脱敏派生和到期 crypto-erase 的 `protected-original` 后端存储。实际 DOM/截图捕获与 XSS 证据消费尚未接入在线执行路径。
- 扫描控制：启动、暂停、恢复、取消；普通 queued/running 中断在下次启动时恢复为暂停，claimed-but-unknown 执行则终结为 `interrupted / unknown` 并进入 `awaiting-user`，两者都不自动重放。
- 结论与报告：Confirmed、Not Confirmed、Inconclusive；Markdown、JSON、HTML 脱敏报告。
- 知识库：四类内置知识、公开情报/PoC 文本导入、Extractor/Reviewer 双 Agent 结构化复核、人工发布、来源/许可证元数据、SQLite FTS5 与中文子串回退检索。
- 桌面边界：Renderer 通过双向 Zod 校验的 IPC 使用应用服务，不能直接访问数据库、文件、凭据或执行器。
- 评测：versioned technique suite、40 个 legacy-v1 Case、三态/policy/version-mismatch 元测试、loopback fixture attestation 与六项安全硬门禁。

`resultClass=self-built-fixture` 不得声明 supported。通用模块运行时和 `security.headers` 被动检测执行尚未作为产品能力开放。

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

这只是自建、固定、同分布靶场的回归基线，用于证明闭环和防止代码回退；不能据此推断真实互联网或复杂业务系统上的检测效果。当前预期边界是：XSS 正例在缺少 DOM/截图审阅时保持 `Inconclusive`。运行结果默认写入被 Git 忽略的 `benchmark-results/`。

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
- [benchmarks/README.md](benchmarks/README.md)：固定靶场评测说明

## License

许可证尚未确定。在许可证明确前，请勿将本项目代码用于对外再分发或商业部署。
