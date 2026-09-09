# AgentGo 评测命令与结果类

评测只在评测进程运行。生产 Application 不 import `@agentgo/evaluation`，只加载内容寻址 QualificationRecord。

## 命令

| 命令 | 作用 | 结果类 |
|---|---|---|
| `pnpm benchmark:verify` | schema / suite / fixture 单测 | n/a |
| `pnpm benchmark:run` | 冻结 40-case GET 靶场 | `self-built-fixture` |
| `pnpm benchmark:complex` | `/research/**` 复杂选择器套件 | `self-built-fixture` |
| `pnpm benchmark:holdout` | 项目自建密封本地 holdout pack | `self-built-fixture` |
| `pnpm benchmark:external --base-url http://127.0.0.1:18080` | 固定 Swagger Petstore V3 import + reviewed GET compatibility replay | `external-local-holdout` |
| `pnpm benchmark:compare` | 比较多次 run 的 verdict/safety/P-R-F1 | n/a |
| `pnpm conformance` | Registry / architecture / qualification | n/a |
| `pnpm recovery` | Day20 迁移/恢复 playbook（复用现有测试） | n/a |
| `pnpm findings:audit` | 审核 benchmark DB 中的 Confirmed Finding | n/a |
| `pnpm fuzz` | compiler/boundary/snapshot/evidence/HMAC 门禁 | n/a |
| `pnpm secret-scan` | 源码高置信 secret 扫描 | n/a |

## 诚实边界

- 40-case 与 complex 都是项目自建 fixture。QualificationRecord 的 `resultClass=self-built-fixture` 不是 supported 声明。
- `benchmark:holdout` 的 pack 是**项目自建密封靶场**（`agentgo-local-holdout/1.0.0`），与 `/cases`、`/research` 分离，**不是** Juice Shop / DVWA 等第三方产品。不得写成第三方产品或真实环境准确率。
- 第三方本地 holdout 使用 Swagger Petstore V3 固定镜像（见 `benchmarks/external-rest-openapi/`）；2026-09-07 已在 WSL Docker 引擎中完成 OpenAPI import、两条 reviewed read-only GET 的 Policy/Grant/Lease 回放和独立 artifact。结果只证明兼容与策略链路，不提供漏洞准确率。
- `authorized-pilot` 未运行：仓库没有书面授权的真实目标。
- complex 套件会跑完并保持同版本三次确定性。不得在看到计分后改冻结确认规则刷绿；确需修复时新建输出目录并把旧轮保留。
- Juice Shop / DVWA 等其他第三方产品未 vendoring；本项目选定的 Swagger Petstore V3 外部 holdout 已完成兼容回放。`benchmark:holdout` 仍只证明项目自建密封 pack，不能替代外部 artifact。
- L2 在没有后端可信人工 ApprovalPort 时只标 `fixture-qualified`。
- 远程生产 OOB Collector 协议已定义，状态 `not-run`。
- 生成物写在被忽略的 `benchmark-results/`，不入库。
