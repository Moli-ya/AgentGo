# Day 4 首个实现切片（2026-07-19）

> 2026-07-28 后续复核见
> [Day4 完成度复核与收口档案](day4-completion-2026-07-28.md)。统一
> Compiler/adapter/hash-only capture 已接入，但 `protected-original` 仍
> unsupported，因此在该历史时点 Day4 总状态继续为
> `partial / in_progress`。2026-07-30 的当前完成结论见
> [Day4 最终复核](day4-final-review-2026-07-30.md)；本档不回写旧事实。

## 状态与范围

- 状态：`partial / in_progress`，不构成 Day4 完成声明。
- 原计划：[Day 4：纯请求编译、三阶段哈希与 EvidenceCapturePolicy](../planning/Day4.md)。
- 分支：`main`；首个实现切片与本档案初版 commit `8fe55b0963560bfbd0381b32cf8220909e7922ec`。
- 本切片只建立无联网的合同、纯请求编译器和纯证据捕获策略；没有改变 Coordinator、Runner、数据库或 Renderer 的现有联网/持久化路径。

## 计划映射

| Day4 工作 | 当前状态 | 本切片事实 |
|---|---|---|
| 无 I/O `ProbeRequestCompiler` | 部分完成 | 已支持 query、path、header、cookie、form 与 JSON Pointer；非标准 transport/codec 失败关闭。尚未接入现有四类请求构造。 |
| Template / Resolved / Wire 三阶段证明 | 本切片完成 | Template 使用分域 SHA-256；Resolved 对动态/secret 值使用带 key ref/version 的 HMAC commitment；最终 wire 使用分域 HMAC。三者类型不可混用。 |
| canonicalization | 部分完成 | 已覆盖 URL/path、重复 query/form/cookie、header 大小写与顺序、JSON key 顺序、Unicode NFC、空 body 和 content-length；redirect 后重新编译尚未实现。 |
| resolver ports | 本切片完成 | 已定义同步 `DynamicValueResolver`、`SecretRefResolver` 与 key-provider 端口；测试仅使用内存替身，未实现 Day9 SessionVault/TestObject 服务。 |
| MutationGenerator metadata | 本切片完成 | 已加入版本、确定性声明、结构化安全语义、required/forbidden capability、selector/codec 支持和输出预算，并在 compiler 中失败关闭不安全组合。 |
| EvidenceCapturePolicy | 部分完成 | 已建立严格 decision/context/result、结构化 artifact payload、完整/部分 source hash、最小 JSON/OOB 证据和 decision-bound OOB HMAC；自由文本、DOM、screenshot、XML、二进制及不安全响应只留 hash。 |
| 响应异常与敏感值规则 | 本切片完成 | partial、oversize、compressed、non-UTF-8、JSON parse/selection 失败均产生显式 hash-only 结果；JSON 字符串值不持久化。 |
| 四类 legacy compatibility adapter | 未开始 | 旧 Coordinator/ExecutionService 仍走原请求构造与证据保存路径，不能把本切片描述为统一执行门禁已经生效。 |

## 独立安全复核

实现过程中用恶意 getter/Proxy、动态超大值、额外 JSON 字段、getter/cyclic resolver 输出、拼接 Evidence artifact、低熵 secret 和无效 OOB key/commitment 做了负例复核。复核发现的以下阻断问题均要求在本切片提交前有回归证据：

- 已验证的请求对象与最终快照之间曾可被切换，能够把已检查的 GET 换成 DELETE；入口现改为 descriptor-safe 单次捕获、规范化深冻结后再执行全部门禁。
- 三阶段证明最初未绑定 execution/review/lifecycle/capability 授权语义；现要求这些字段进入 Template proof 并级联影响 Resolved/Wire proof。
- 动态 resolver 最初缺少 URL/header/body/整份 wire 的总字节预算；现对收到的值执行分层限额，并在派生 URL/body/wire 的过程中失败关闭。
- Evidence artifact 最初允许任意 `content` 字符串；现改为严格 discriminated payload，并锁定 state、reason、source、hash、decision、policy 与 OOB commitment。
- 自由文本启发式脱敏会漏掉低熵 secret；现不再持久化自由文本，JSON 字符串也只输出固定脱敏标记。
- OOB commitment 最初信任 port 自报 digest；现由 policy 使用受控 key 在本地计算，并绑定 decision、policy、source hash 与 token。

## 验证证据

| 验证 | 提交前结果 |
|---|---|
| `pnpm --filter @agentgo/contracts typecheck` | 退出码 0。 |
| `pnpm --filter @agentgo/application typecheck` | 退出码 0。 |
| `pnpm vitest run packages/contracts/src/security.test.ts packages/contracts/src/inventory.test.ts packages/contracts/src/vulnerability.test.ts packages/application/src/request-compiler.test.ts packages/application/src/evidence-capture-policy.test.ts` | 退出码 0；5 文件/89 项通过，其中 compiler 13 项、evidence policy 25 项。 |
| `pnpm check` | 退出码 0；14 个 workspace 与 scripts typecheck 通过；主测试 33 文件/329 项、DB baseline 2 文件/10 项通过；Main/Preload/Renderer production build 通过。 |
| `git diff --check` | 退出码 0；仅 Windows LF/CRLF 提示，无 whitespace error。 |

提交前工作树只包含本切片合同、application 纯函数/测试和进度文档；实现与档案初版已由 commit `8fe55b0963560bfbd0381b32cf8220909e7922ec` 固定，本次后续文档提交只补充该映射。

## 合同与生成物边界

- 新增 proof domain：`agentgo.template-intent.v1`、`agentgo.resolved-intent.v1`、`agentgo.wire-request.v1`。
- 新增 evidence domain/schema：`agentgo.evidence-source.v1`、`agentgo.oob-token-commitment.v1`、`evidence-capture-artifact.v1`。
- MutationGenerator metadata、request value source、mutation target 与 Evidence capture contract 都是本切片的 `v1` 首版；未新增 Prompt 或数据库 migration。
- 没有把 benchmark、SQLite、raw Evidence、构建产物或真实 secret 加入版本控制；本切片也没有生成新的运行时 benchmark 结论。

## 尚未完成与已知风险

- Day4 第 8 项 compatibility adapter、redirect 重新编译规则、`docs/security/threat-model.md` 和 `docs/architecture/data-model.md` 更新尚未完成。
- 新 compiler 与 capture policy 尚未接入 Coordinator、ExecutionService、Runner 或 EvidenceStore；任何后续模块“只能通过同一 Compiler/Policy”的 Day4 合格交付尚未满足。
- 现有 ExecutionService 仍可能先把 raw HTTP body、DOM 或 screenshot 交给旧 EvidenceStore。本切片不声称已消除这条现存路径。
- EvidenceStore 的 `(scanId, sha, type)` 去重仍可能复用不属于同一 interaction/role/policy 的 metadata；本切片没有 schema migration。
- `protected-original` 明确返回 `unsupported`。在加密、访问控制、保留期与派生关系落地前，不允许把明文 `0600` 文件称为受保护原件。
- JSON selection 只可信任受控 `EvidenceCapturePolicy` 的直接输出；没有 raw source 时，Zod schema 不能重放 JSON Pointer，也不声称提供 selection derivation 的密码学证明。未来 capture-before-store adapter 必须保留该可信调用边界。
- 本切片未新增网络执行、数据库写入、Prompt、Renderer 或真实 secret fixture；它不扩大当前受支持漏洞类别或 qualification 声明。

## 不得外推

本记录只证明 Day4 的第一段纯函数基础正在实现。它不证明审批到实际联网执行的完整闭环、redirect/DNS/IP 边界、单次 Lease、原子预算、L2 TestObject 清理、会话/Vault 或真实复杂 Web 已经完成。
