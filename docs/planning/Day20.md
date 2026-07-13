# Day 20：后端全量门禁、覆盖审计与桌面兼容验收

## 当天目标

停止新增功能，完成迁移、模块、评测、安全、报告和当前桌面可用性的全量验收。Day20 交付的是“可持续扩展的后端平台 + 参考模块”，不是“所有 Web 漏洞已经在真实目标自动确认”。

## 必须完成的工作

1. 汇总 Day1～Day19 完成记录；partial/deferred 项保留真实状态、原因、风险和后续波次，禁止修改文字伪装完成。
2. 运行 Registry/Module Conformance：ID/版本/交叉引用、Capability、环境、Rule、Evidence、Remediation、Fixture/Suite、L2 cleanup 和 immutable freeze 全部通过。
3. 验证旧库 -> V2 的合成迁移、重复迁移、Scan module snapshot、暂停/恢复、missing historical module、claimed lease crash 和 cleanup pending 恢复。
4. 运行 legacy 40 Case 与 complex suite：四个参考模块各至少 4 正、4 负、2 Inconclusive，外加 policy/cleanup/secret/lease 安全 Case；同版本重复三次确定性一致。
5. 冻结规则后运行至少一个版本固定、可重置、仅本地访问的第三方 Web/API holdout。开发者不得在看到 holdout Ground Truth 后修改规则再重复计分；确需修复时新建版本并把旧轮记为开发反馈，不能继续当 holdout。
6. 生成 Coverage Report：逐个目录项列 manifest/maturity/environment/adapter/suite/实际结果，并将结果分为 `self-built-fixture`、`external-local-holdout`、`authorized-pilot`、`not-run`；没有完整 Bundle/测试的条目不得标 supported。
7. 审核 `Confirmed`：均有 rule/version/hash、必需 Evidence roles、负对照、module/remediation version；模型/Knowledge/Agent 无提升 verdict 路径；确认规则满足后额外探测请求数为 0。
8. 审核安全计数：out-of-scope、L3、未批准 L2、明文 secret、无证据 Confirmed、Lease 重放、cleanup failed 后非恢复执行全部为 0。
9. 报告明确区分 fixture、真实授权 profile 未运行、signal/inventory 和 active；不把 local mock Collector、FixtureApprovalAdapter 或 fixture Case 写成真实生产验证。没有后端可信人工 ApprovalPort 时，L2 只能标 `fixture-qualified`。
10. 运行 parser/compiler property/fuzz、module dependency boundary、secret scan、Registry canonical snapshot/lockfile、Evidence 加密/密钥轮换/保留期/配额和 HMAC/审批签名密钥生命周期检查。
11. 前端只做兼容回归：不新增页面；现有 Dashboard/Target/Scan/Finding/Audit/Knowledge/MCP/Settings 能启动、基础导航和已有 V1 流程不崩溃。
12. 更新 `AGENT.md`、roadmap、architecture/data/security/knowledge/evaluation/user guide 与覆盖矩阵；旧四类 V1 边界仍保留历史说明，V2 目标不改写历史事实。
13. 审查 Git：不提交计划书原件、运行数据库、Evidence、secret、benchmark results、release 或机器文件；只提交本轮预期改动。

## 预计改动位置

- Registry/Module/Execution/Evaluation 的缺陷修复文件；Day20 不接受新增业务模块；
- `docs/planning/web-vulnerability-coverage-matrix.md`、architecture/data/security/knowledge/evaluation/user guide；
- benchmark/conformance runner 与报告 schema（只修复验收缺口）；
- 现有 desktop 代码原则上不改，除非 contracts 兼容、build 或 smoke 回归必须修复；
- `.gitignore`、版本记录和审计报告。

## 测试与证据

以下命令必须全部执行并保存脱敏摘要：

```powershell
pnpm check
pnpm benchmark:verify
pnpm benchmark:run --output .\benchmark-results\day20-legacy
pnpm benchmark:complex --output .\benchmark-results\day20-complex-run1
pnpm benchmark:complex --output .\benchmark-results\day20-complex-run2
pnpm benchmark:complex --output .\benchmark-results\day20-complex-run3
pnpm benchmark:holdout --output .\benchmark-results\day20-external-holdout
pnpm build
pnpm smoke:desktop
```

`benchmark:complex` 与 `benchmark:holdout` 是本计划应新增的命令；尚未实现时不得伪造输出。holdout 必须固定版本、完全本地、可重置、与开发 fixture 分离并保存来源/license/hash。若桌面构建链实际发生改变，再补对应 packaged smoke；本轮不为临时后端功能专门开发 NSIS 升级/卸载流程。

## 合格交付

- Coordinator 无 family 分支；新 passive 模块无需改主链即可完整报告；
- 四个参考主动模块通过复杂 selector/身份/浏览器/OOB/L2 样例和安全门禁，旧 40 Case 不回退；
- 每次 I/O 具备 Scope、三阶段 hash、Grant/Lease、预算、Policy、Evidence role 和结束状态；
- L2 primary 不重复，cleanup/恢复可审计；secret 不进入 DB/普通 Evidence/日志/报告；
- Coverage Matrix 中所有已知类别都有诚实状态和后续波次，未实现不宣称支持；
- 复杂接口矩阵逐协议标出 parse/inventory/replay/active 的真实级别；第三方 holdout 结果与自建 fixture 分开，不能据此声称广泛真实环境准确率；
- `pnpm check`、benchmark/conformance、迁移恢复、`pnpm build` 和 `pnpm smoke:desktop` 全部通过；
- 当前前端可用，但新后端能力明确等待后续整体前端重建。

## 不合格处理

任何安全计数非零、迁移损坏、Registry 引用不完整、Evidence 缺失、benchmark 不稳定、cleanup 无法恢复或桌面不能启动时，停止交付并记录失败证据。只做小步修复或显式 revert 本轮提交，不使用 reset/checkout 覆盖用户工作区，也不通过降低策略或扩大 Scope 让测试变绿。
