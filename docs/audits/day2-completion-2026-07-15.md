# Day 2 完成审计（2026-07-15）

本记录核对 [Day2 原计划](../planning/Day2.md) 的实际交付。Day1 已先独立提交为 `e82caf49e1985670022479b347abcc39329d5295`（`feat: complete day1 reproducible baseline`），随后才开始 Day2 实现。原计划没有被重写；仅按人工确认修正了“registered-only 永不执行”与“旧四类行为不得回退”的冲突，加入固定四类 `legacy-v1` 临时兼容例外及 Day7 移除条件。

## 交付结论

Day2 的十项必须工作均已完成：

1. contracts 使用开放、格式受限的 Family/Technique ID 与严格 SemVer；旧 `VulnerabilityFamily` 只保留兼容别名，业务代码不再读取 Zod enum `.options`。
2. 严格 Manifest/Bundle 定义覆盖最小 subject、protocol、selector、Capability、environment、六种 declared mode、六类 Definition 与只读 Activation view；Manifest 不能自填 activation、qualification 或 hash。
3. 未提前创建 Day3 的 `SubjectRef`、RequestVariant、TestObject 或持久化关系。
4. `DefinitionRegistry.registerBundle()` 原子校验并深冻结定义，输出 canonical definition hash 与全局 snapshot hash。
5. Registry 校验 ID/版本、描述一致性、全部交叉引用、Capability 存在及 SecurityPolicy `riskFloor`、Rule/Evidence role 供给、Active 负对照/expected suite、L2 安全声明和未引用 Definition。
6. 四个 V1 adapter 复用现有确认规则；`security.headers.existing-response-audit` 作为 `signal-only` production bundle 注册，但没有运行时映射。
7. 默认四类 family 已从 contracts 移至 Application；显式输入与默认数组均在执行前复制/冻结语义，不能跨异步间隙被调用者改写。
8. `ModuleConformanceTestkit` 提供框架无关的完整注册、预注册冲突、原子拒绝和冻结后注入断言；计划列出的缺规则、重复 ID、描述冲突、悬空引用、未知 Capability、Active 缺负对照/Evidence、冻结后注入均有自动测试。
9. CreateScan、Application start/resume、Coordinator start/resume 和 Candidate 均执行 Definition/runtime/Activation 三门禁。Application 在委托任意 Coordinator 前独立校验；Candidate 在恢复 AgentRun、checkpoint、Runner 或 ToolCall 之前校验。未知 family 不再落入 IDOR 分支；pause/cancel 仍能安全停止未知历史任务。
10. Reporting 使用稳定 ID label fallback；Renderer 仅保留四个 legacy 选项，没有显示或启用 `security.headers`，也没有新增 Day2 UI。

## 临时兼容边界

四类兼容授权只接受 canonical `family/module/technique/version` tuple、固定 definition hash、`active-l1` 模式、当前运行时映射、Application allowlist 和声明环境。替换 module ID、替换 technique、同版本改内容、降级为 `signal-only`、缺运行时映射、未知 family、registered-only `security.headers` 均失败关闭。该路径返回 `authorization=legacy-v1-compatibility`，但 Activation 视图仍为 `registered`，不能作为 qualified/supported 证据。

冻结 Registry snapshot：

- snapshot SHA-256：`d4c45f8c27463729e01d60ab1a1ddfea03039e9dc2967e6ebb52f8c5f17cd9e9`；
- `sqli.legacy-v1@1.0.0`：`42061d63b40babd5b62d2c6f5c5fef692b9189fe854f5d76e0dc101c01acaf5b`；
- `xss.legacy-v1@1.0.0`：`89b2f50d1780bf5f53a2f2f0a8e5ae449a18346e076e2dbe5e69f00e29dfe4b6`；
- `ssrf.legacy-v1@1.0.0`：`490de422192857b8be83125ab74acde2c53212dac8bdf68b879a5904089d4a7f`；
- `idor.legacy-v1@1.0.0`：`67da31d42bdd9144e6c114f20ea1b7eb2348337481a4dc931cd9557d5efe0d02`；
- `security.headers.passive@0.1.0`：`595d49ff389bbd75a05ee49eeb0c8928da0962eba4cf5a16afd47a89ee134851`。

## 独立复核补强

实现完成后进行了两轮只读独立复核，并修复了以下非表面缺口：

- Active L1 引用 L2 Capability 的风险降级；
- 非 Active Rule 引用未供给 Evidence role；
- 任意注入 runtime binding 或同版本内容替换继承 legacy 例外；
- 注入 Coordinator 绕过 Application start/resume 门禁；
- Candidate 在门禁前创建恢复 AgentRun；
- legacy 默认常量运行时可变；
- CreateScan 调用者数组在异步窗口内发生 TOCTOU。

## 最终验证

| 验证 | 结果 |
|---|---|
| `pnpm check` | 退出码 0；14 个 workspace 与 scripts typecheck 通过；包内 24 文件/176 项、scripts 2 文件/10 项测试通过；Main/Preload/Renderer production build 通过。 |
| Day2 核心定向测试 | 5 文件/95 项通过，覆盖 Registry、Capability、固定 hash/mode、执行入口与变异回归。 |
| `pnpm smoke:desktop` | 退出码 0；`AGENTGO_SMOKE_TEST_OK`。 |
| `pnpm benchmark:verify` | 退出码 0；3 项校验通过。 |
| 最终 legacy 40 Case | 40/40 decided；TP 20、TN 20、FP/FN/Inconclusive 0；Precision/Recall/F1/Evidence completeness 均为 1；六项安全计数均为 0。 |
| Git/生成物 | `git diff --check` 无 whitespace error；benchmark、数据库、Evidence、凭据及构建输出保持忽略。 |

最终 benchmark 位于被 Git 忽略的 `benchmark-results/day2-final-security-review-2026-07-15`。

## 明确保留到后续工作包

- 每 Scan 的 module/capability/version/hash 持久化快照仍由 Day3 交付；Day2 的进程级 Registry hash 不能冒充扫描级资格证明。
- QualificationRecord、正式环境资格与移除 legacy 例外仍由 Day7 交付。
- 通用 ValidationPlan runtime 与移除 Coordinator family 分支仍由 Day14～Day15 交付。
- `security.headers` 的实际被动 detector 资格化仍由 Day19 交付。
- 当前 Registry 校验所有 SignalKind 引用存在，但没有擅自规定 Rule 输入必须由同一 Technique 的 Strategy 直接产生；计划尚未定义导入 Signal/既有 Observation 的 producer 语义，该闭环约束留给 Day14 通用 Signal/Confirmation runtime 明确。此项不授予任何新增执行能力。

因此，本次完成的是 Day2 扩展底座和安全门禁，不是新增漏洞检测、正式 qualification、复杂 Web/API 支持或真实目标准确率证明。
