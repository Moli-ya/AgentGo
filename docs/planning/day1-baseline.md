# Day 1 事实与可复现基线（2026-07-13）

> 状态：`completed`
>
> 执行分支：`main`
>
> 执行起点：`2851e915bd30acd5ee3abef22733a86e24f20e85`（`docs: complete day0 backend planning review`）
>
> Git 说明：Day1 在上述提交后的工作区完成；本记录不伪造新的 commit，交付时改动尚未提交。

本记录只证明 Day1 的事实基线、竞态修复、规划契约和本地固定靶场回归已经验收。它不是 DefinitionRegistry、ActivationCatalog 或真实 Web 全覆盖的完成声明，也不产生任何 `supported` 资格记录。

## 1. Day1 八项交付

| 项目 | 结果 | 证据 |
|---|---|---|
| 需求追踪 | 完成 | [需求追踪表](requirements-traceability.md) 使用 77 个稳定需求 ID，区分已有、Day1、后续波次和非目标，并为每项指定唯一主责工作包。 |
| 漏洞覆盖目录 | 完成 | [覆盖矩阵](web-vulnerability-coverage-matrix.md) 与 [机器目录](web-vulnerability-coverage-catalog.json) 保持 98 个唯一 `WEB-*` ID；当前实现、未来安全上限和资格状态分离。 |
| Scope 竞态 | 完成 | migration `0005_monotonic_scope_revisions`、显式 current pointer、单调 revision 及 9 项 Repository 测试。 |
| 工具与测试事实 | 完成 | 本记录 §2～§4；所有命令均在 2026-07-13 的同一工作区执行。 |
| Renderer 冻结 | 完成 | 相对执行起点运行 `git diff --name-only 2851e915 -- apps/desktop/src/renderer` 无输出；build 与 smoke 通过。 |
| 支持声明格式 | 完成 | [需求追踪表 §2](requirements-traceability.md#2-最小支持声明格式) 定义 family、technique、module、maturity、environment、protocol/selector 和 benchmark 切片；Day1 未实现 Registry/资格服务。 |
| 合成 V1 数据库 | 完成 | [生成与校验脚本](../../scripts/v1-database-baseline.ts) 复用真实 migration 列表，并由 [自动测试](../../scripts/v1-database-baseline.test.ts) 验证。 |
| Git 忽略边界 | 完成 | `.gitignore` 覆盖原始计划书、SQLite/sidecar、凭据、Evidence、benchmark、release、本机数据与 cache；生成物未进入 `git status --short`。 |

覆盖目录对来源的处理是 fail closed：WSTG v4.2 建立类别索引；没有权威核对证据的 ASVS 5.0.0 和 OWASP Top 10 2025 精确映射保持 `pending-verification`；SRC 实战场景只作目录审计，不提升当前实现或资格状态。真实目标不发送 TRACE；项目控制 OOB SSRF 的上限为 L1，只有显式纳入 scope 的内部测试服务才可提出 L2。

## 2. 环境与版本

| 项目 | 实际值 | 取证方式 |
|---|---:|---|
| Node.js | `v24.14.0` | `node --version` |
| pnpm | `10.33.2` | `pnpm --version` |
| Electron | `43.1.0` | desktop workspace 安装包及 Electron CLI |
| Electron Vite | `5.0.0` | desktop workspace 安装包 |
| Playwright Core | `1.61.1` | desktop/browser-runner workspace 安装包；不采用机器上的全局 `playwright` CLI 版本 |
| SQLite | `3.51.2` | 当前 Node `node:sqlite` 的 `sqlite_version()` |
| Benchmark fixture | `agentgo-local-fixture/1.0.0` | 三次 `summary.json` metadata |
| Ground Truth | `agentgo-ground-truth/1.0` | 三次 `summary.json` metadata |
| 数据库 migration | `0001`～`0005_monotonic_scope_revisions` | `DATABASE_MIGRATIONS` 与合成 baseline manifest |

Day1 的代码事实仍是 V1 四类固定实现：`sqli/xss/ssrf/idor`。这次没有增加 payload、没有访问真实目标，也没有修改 Renderer。

## 3. Scope 顺序、迁移与冻结语义

`targets.current_scope_id` 是当前 Scope 的权威指针；`target_scopes.revision` 是每个 Target 内不可变快照的单调创建序号。`getLatestScope()` 通过 Target 与 Scope 的 target ID 双重约束读取指针，不再按毫秒时间或 UUID 猜测。DB trigger 拒绝非正整数 revision、跨 Target pointer 和任何 Scope 原地更新，避免已冻结的 ID/version 悄然改变内容。

migration `0005_monotonic_scope_revisions` 对旧库按 `created_at ASC, rowid ASC` 确定性回填 revision，为 `(target_id, revision)` 建立唯一索引，并把每个 Target 的 pointer 回填到最大 revision。创建 Target 初始 Scope、创建新 revision、选择内容相同的历史 Scope、更新 pointer 和冻结 Scan 均经过规范真实路径键串行；写事务使用 `BEGIN IMMEDIATE`，内容相同的历史 Scope 保留原 ID/revision，不制造伪版本。`createScan()` 保存当次读取的精确 `scopeSnapshotId`，事件与审计同时记录 `scopeRevision`，之后 Target pointer 更新不改变已有 Scan。

自动测试覆盖：

- 创建和更新落在同一毫秒，随后创建 Scan 并再次更新；
- 同一 Repository 的五个并发更新得到 revision 2～6；
- 并发创建新 Target 与更新已有 Target 不发生同步 SQLite 事务交错；
- 同一 SQLite 文件通过路径别名打开的两个连接并发更新得到唯一 revision 2、3；
- 只含 migration 0001～0004 的旧库，在同毫秒 Scope 下按插入顺序回填；
- 缺失 Scope、跨 Target pointer、缺失/重复 revision 和 Scope 原地更新被数据库拒绝；
- pointer 更新失败时，新 Scope 与 Target 字段修改整体回滚；
- 切回相同历史快照时复用原 ID/revision；
- Application 返回本次事务产生或选择的精确 Scope，而不是并发后重读猜测。

实现没有使用 `sleep`、UUID 排序或失败重试作为正确性条件。

## 4. 测试、构建与桌面

| 命令 | 结果 |
|---|---|
| `pnpm check` | 退出码 0；14 个 workspace 项目的 TypeScript 检查和 scripts 类型检查通过；包内 19 个测试文件 / 78 项测试通过；scripts 2 个测试文件 / 10 项测试通过；Main、Preload、Renderer production build 成功。 |
| `pnpm smoke:desktop` | 退出码 0；输出 `AGENTGO_SMOKE_TEST_OK`。 |
| `pnpm benchmark:verify` | 退出码 0；1 个测试文件 / 2 项测试通过。 |
| `pnpm test:db-baseline` | 退出码 0；数据库 baseline 4 项、覆盖目录 6 项，共 10 项通过。 |

因此 Day1 当前总自动测试面为 21 个测试文件 / 88 项测试。DAY0 的 19 文件 / 72 项仍只作为历史记录，不再用作当前统计；仓库中没有“71 项”为当前事实的声明。

## 5. 三次全新目录 Benchmark

连续三次运行均使用新的、被 Git 忽略的输出目录：

| 运行 | 时间（UTC） | 结论 | 指标 | 安全门禁 |
|---|---|---|---|---|
| `day1-final-baseline-1` | 06:23:35.573～06:24:23.554 | 40/40；TP 20、TN 20、FP 0、FN 0、Inconclusive 0 | Precision/Recall/F1/Evidence completeness = 1 | 通过，六项计数均 0 |
| `day1-final-baseline-2` | 06:24:34.491～06:25:16.698 | 40/40；TP 20、TN 20、FP 0、FN 0、Inconclusive 0 | Precision/Recall/F1/Evidence completeness = 1 | 通过，六项计数均 0 |
| `day1-final-baseline-3` | 06:25:30.352～06:26:13.663 | 40/40；TP 20、TN 20、FP 0、FN 0、Inconclusive 0 | Precision/Recall/F1/Evidence completeness = 1 | 通过，六项计数均 0 |

六项安全计数分别为：越界请求、L3 破坏动作、未批准 L2、日志/报告明文 secret、无 Evidence/Rule 的 Confirmed、cleanup failure 后继续执行，三次均为 0。输出目录包含运行数据库与 Evidence，按策略保留在本地且不提交。

这三次稳定回归只证明自建、固定、同分布 GET fixture 的确定性闭环，不证明真实互联网、复杂 SPA、登录业务、任意 API selector 或未来漏洞模块的准确率。

## 6. 合成 V1 数据库 Baseline

CLI：

```powershell
pnpm db:baseline generate --output .\benchmark-results\day1-db-baseline
pnpm db:baseline verify --input .\benchmark-results\day1-db-baseline
```

baseline 版本为 `agentgo-v1-synthetic-baseline@1`，只含 1 个 `.invalid` Workspace/Target、1 个 revision 1 Scope 和 1 个从未运行的 draft Scan；Identity、凭据引用、Model Profile、MCP、Evidence、Finding、审计和其他运行表均为空。它复用 `DATABASE_MIGRATIONS`，不复制第二份 schema。

两次全新目录生成和独立 verify 得到相同结果：

- schema：`0005_monotonic_scope_revisions`；
- migration：`0001_agentgo_v1`、`0002_identity_owned_resources`、`0003_mcp_servers_and_token_usage`、`0004_knowledge_intelligence_ingestion`、`0005_monotonic_scope_revisions`；
- SQLite 文件 SHA-256：`bf27d78ce742a63dd15f7dacdfd89bfd0320b025e643cde5c2149e2d0e5b112b`；
- 跨环境逻辑内容 SHA-256：`89a10e291f5dc932613f8d04bcf4c1fa1e7c98dfabf0facbe0f6279d01c562af`；
- `PRAGMA integrity_check=ok`、`foreign_key_check` 无结果、无 WAL/SHM sidecar；
- 自动测试证明重复生成字节一致、应用数据库可重开、篡改的文件/逻辑 hash 会被拒绝。

文件 hash 用于本次已锁定环境的字节复现；逻辑内容 hash 用于跨 SQLite 构建比较。二者都不能替代 schema/migration、完整性和精确 fixture 校验。

## 7. Git、敏感数据与顺延边界

`.gitignore` 的审核样例覆盖 `*.sqlite`、`-wal/-shm`、`*.db`、`credentials*.json`、`evidence/`、`benchmark-results/`、`release/`、`release-stale-*`、`.agentgo/`、`cache/` 和原始 `*.doc/*.docx`。最终交付前再次执行 `git diff --check`、Renderer diff、ignore 路径检查与 `git status --short`。

Day2 仍为 `pending`。DefinitionRegistry、开放 Family/Technique 合同、ActivationCatalog、qualification record、复杂接口导入、L2、Session、TestObject、通用 ValidationPlan 和新增漏洞模块全部顺延到各自主责工作包；Day1 没有抢先创建这些接口。
