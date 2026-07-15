# Day 1 最终提交前复核（2026-07-15）

本记录补充 Day 1 在正式 Git 提交前的最终代码复核。原有 Day 1/Day 2 计划文件保持不变；本记录只保存最终代码的修复与验证事实，不扩大能力或资格声明。

## 复核修复

- migration `0005_monotonic_scope_revisions` 增加 current Scope head 防清空约束。Target 已建立权威 head 后，原生 SQL 不能把 `current_scope_id` 更新为 `NULL`；失败后原 head 保持可读，后续 Scan 仍冻结原 Scope ID/revision。
- Scope hash 在计算前规范化 `validFrom`/`validUntil`。表示同一时刻的等价 ISO 8601 文本复用同一快照，不再制造内容等价的重复 revision。
- 上述行为均加入 Repository 自动回归；没有修改 Renderer、网络行为、payload、Scope 上限或漏洞族范围。

## 最终验证

| 验证 | 最终结果 |
|---|---|
| `pnpm check` | 退出码 0；14 个 workspace 与 scripts 类型检查通过；包内 19 文件/78 项、scripts 2 文件/10 项测试通过；Main/Preload/Renderer production build 通过。 |
| `pnpm smoke:desktop` | 退出码 0；`AGENTGO_SMOKE_TEST_OK`。 |
| `pnpm benchmark:verify` | 退出码 0；2 项校验通过。 |
| 三次全新目录 legacy benchmark | 每次 40/40；TP 20、TN 20、FP/FN/Inconclusive 0；Precision/Recall/F1/Evidence completeness 均为 1；六项安全计数均为 0。 |
| 合成数据库双生成与 verify | 两次字节一致且独立校验通过；逻辑内容 hash 不变。 |
| Renderer / Git 边界 | 相对 `2851e915` 的 Renderer diff 为空；运行数据库、Evidence、凭据、benchmark 和 release 生成物均被忽略。 |

最终合成数据库事实：

- schema/migration：`0005_monotonic_scope_revisions`；
- fixture：`agentgo-v1-synthetic-baseline@1`；
- SQLite 文件 SHA-256：`d616bbd443d6f2a8ab4ee77652abbedc438371e242ce40c4e9554c0f3aedd93c`；
- 逻辑内容 SHA-256：`89a10e291f5dc932613f8d04bcf4c1fa1e7c98dfabf0facbe0f6279d01c562af`。

`day1-baseline.md` 中 2026-07-13 的旧文件 hash 只描述修复前的历史取证；本记录中的文件 hash 对应最终待提交代码。固定自建 fixture 的满分仍不得外推为真实互联网、复杂 SPA、登录业务或任意 API selector 的准确率。
