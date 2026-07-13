# Day 2：开放式漏洞 ID、Manifest 与 DefinitionRegistry

> 状态：`pending`。Day1 合格退出前不得实施；此前提前实施的 Day2 内容已撤销。

## 当天目标

解除四值枚举这一首要扩展瓶颈，在纯 contracts/domain 层建立版本化漏洞模块协议。当天不改网络行为，先让 SQLi、XSS、SSRF、IDOR 以 legacy bundle 注册并保持原结果。

## 设计约束

- 已有 `sqli/xss/ssrf/idor` 作为永久稳定 ID 保留，避免破坏历史 Scan/Finding；新模块使用同一格式的稳定字符串 ID。
- `familyId` 表示问题域，`techniqueId` 表示具体检测技术；确认规则和成熟度绑定 technique，不能假设一个 family 只有一种验证方式。
- contracts 只校验 ID 格式；是否存在和版本是否可用由冻结 DefinitionRegistry 决定，能否主动执行还必须经过 Day7 qualification record 与 ActivationCatalog。
- DefinitionRegistry 是可信 Composition Root，不支持从知识库、模型输出或运行时下载的任意代码动态注册；`registered-only` 永远不能被当前扫描选择执行。

## 必须完成的工作

1. 新增 `VulnerabilityFamilyIdSchema`、`VulnerabilityTechniqueIdSchema`、`ModuleVersionSchema`，把旧 `VulnerabilityFamily` 暂时作为兼容类型别名；删除业务代码对 `.options` 的依赖。
2. 定义 `VulnerabilityModuleManifest`：ID/版本/显示名/类别/CWE/WSTG/ASVS/API 引用、协议、selector、所需 Capability、允许环境、`declaredMode`、Rule/Evidence/Remediation 和预期 Suite 引用；另定义 `activationStatus/qualifiedEnvironments` 只读视图，不能由 Manifest 自填。
3. 本日只在 Manifest 中声明最小 subject kind/协议/selector 能力；完整 `SubjectRef`、RequestVariant 和持久化关系由 Day3 定义，不能为了通过 Registry 测试提前创造第二套权威接口。
4. 在 `packages/domain` 建立原子 `DefinitionRegistry.registerBundle()` 和 `freeze()`；Bundle 必须同时声明 Detector、SignalKind、Strategy、ConfirmationRule、EvidenceProfile、Remediation，并输出 canonical snapshot/definition hash。
5. 注册时校验 ID/版本唯一、交叉引用完整、未知 Capability 拒绝、声明 active 的 technique 具有负对照和最小 Evidence role；L2 先校验 `requiresTestObject/requiresCleanup` 声明，正式 TestObject/CleanupProtocol 和 FixtureSuite/qualification 深层一致性分别由 Day8/Day7 完成。缺 qualification 不是定义注册失败，而是保持 registered-only。
6. 用 adapter 包装四类现有 metadata/规则引用；本日不迁移具体执行步骤。增加一个 production passive `security.headers` bundle，证明开放 ID 可注册，但在 Day14 通用运行时完成前它必须是 registered-only，不能被当前扫描选择执行。
7. 默认扫描 families 从 contracts 移到 Application 配置；只默认启用已明确兼容的四个 legacy module。Application 执行入口必须同时检查 DefinitionRegistry、runtime support 与 ActivationCatalog，不能因为定义存在就主动运行。
8. 新增 Module Conformance testkit 第一版：缺规则、重复 ID、描述冲突、悬空引用、未知 capability、Active 无负对照/Evidence、冻结后注入均失败；正式 Active-FixtureSuite 激活门禁留给 Day7。
9. 开放字符串 ID 前修复 legacy runtime 的安全兜底：CreateScan、start/resume 和 Candidate 执行前均做 Registry + legacy runtime 双门禁；Coordinator 的 IDOR 必须是显式分支，最终未知 family 直接失败，不能把任何未知 ID 当 IDOR 主动执行。pause/cancel 仍允许安全停止未知历史扫描。
10. Reporting 与当前 Renderer 只做 label fallback/类型兼容；现有选择器仍只显示四个 legacy family，不新增 UI，也不把 `security.headers` 暴露为当前可执行模块。

## 预计改动位置

- `packages/contracts/src/vulnerability.ts`、`workflow.ts`、`index.ts`；
- `packages/domain/src/vulnerabilities/**`；
- `packages/application/src/index.ts`、`scan-coordinator.ts`、`validation-engine.ts`、legacy registry factory；
- Reporting、Evaluation、AgentRuntime 与 Renderer 的最小开放 ID 兼容；
- contracts/domain/application tests；
- `docs/architecture/agent-system.md`、`data-model.md`。

## 测试与证据

- 旧四类值能被新 schema 读取，未知但格式合法的 ID 只能在 Registry 校验后使用；
- 格式非法、重复、引用悬空、未知 Capability、冻结后注册全部失败；
- active-l1/active-l2/signal-only/fixture-only/inventory-only/forbidden 的组合约束正确；
- passive 测试模块接入不修改枚举和现有四类测试；
- 未注册 family、已注册但当前 runtime 不可执行的 `security.headers`、直接写入旧库的未知 family 在 create/start/resume/candidate 四处失败关闭，Runner/ToolCall 为 0；
- 使用根 Vitest 运行 contracts/domain/Application/Reporting/Evaluation/AgentRuntime 针对性测试（当前各 package 没有独立 `test` script），再运行 `pnpm typecheck`、旧 40 Case、build 和 smoke。

## 合格交付

新增一个漏洞目录项不再要求修改 `z.enum`；DefinitionRegistry 能拒绝不完整或越权的 Bundle，registered-only 不能执行，且旧四类数据和前端类型仍保持兼容。
