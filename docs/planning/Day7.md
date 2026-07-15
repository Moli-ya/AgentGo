# Day 7：Evaluation Core、Ground Truth v2 与 Qualification Registry

## 当天目标

在新增复杂模块之前建立可扩展评测骨架。评测单位从“枚举中每类五正五负”升级为 versioned technique suite，能够表达协议、selector、证据角色、三态、环境证明和安全失败。

## 必须完成的工作

1. 定义 `BenchmarkSuiteManifest`：familyId、techniqueId、moduleVersion、fixtureVersion、协议/codec/selector、required cases、允许 maturity 和环境 attestation。
2. 扩展 Ground Truth：expected verdict/reason code、required evidence roles、可选 identity/workflow/test-object requirement、risk level、允许请求上限和禁止 capability；Day7 只实现 legacy 能力实际需要的字段语义。
3. Case 至少分为 positive、negative、inconclusive、policy-denied、version-mismatch；预留 cleanup-failure 类型，但其可执行语义在 Day8～Day10 完成后才激活，不能用占位结果通过门禁。
4. 将现有 loopback fixture 整理为 versioned 基础 fixture：保持四类 legacy GET 行为，增加稳定 attestation、随机端口、出站隔离和确定 reset。多 method/form/JSON、两身份、CSRF、临时对象、受控 OOB 按 Day8～Day10 与 Day16～Day19 增量加入，不在 Day7 提前伪造依赖。
5. Fixture 只能绑定 loopback/随机端口，使用合成身份与数据；reset 只操作 fixture namespace。任何未来 cleanup endpoint 必须遵循 Day8 专用 cleanup capability，不能复用通用危险删除路径。
6. Benchmark runner 从 Registry 发现 suite，不再遍历 `VulnerabilityFamilySchema.options`；缺 Prediction、未知 technique、版本不匹配、Evidence role 缺失必须失败。
7. 指标按 family/technique/protocol/selector/maturity/环境分别统计；`Inconclusive`、not-run 和 policy deny 不混入 Not Confirmed。
8. 修正 recovery 指标：恢复成功必须存在真实中断与成功恢复链；cleanup 指标在 Day8 状态机接入前明确标记 `not-applicable`，不得硬编码为成功。
9. 保留旧 40 Case 作为 `legacy-v1` suite；迁移期间结果必须完全一致。
10. 将 Definition 与 Activation 分离：Suite runner 生成绑定 definition/build/fixture/suite hash 的 `QualificationRecord`；生产 `ActivationCatalog` 只加载记录，不 import fixture 代码。缺记录、记录过期或环境不匹配的 active technique 保持 registered-only。Day2 固定四类 `legacy-v1` 临时兼容例外不得被当作资格记录；四类取得有效、环境匹配的记录后，必须由正式 ActivationCatalog 路径接管并移除该例外。

## 预计改动位置

- `packages/contracts/src/evaluation.ts` 或相关 schema；
- `packages/evaluation/src/index.ts`、`local-fixture.ts`、runner；
- `packages/vulnerability-modules/src/testkit/**`（若 Day2 架构采用此包）；
- fixture/evaluation tests；
- `docs/evaluation/benchmark-plan.md`、`benchmarks/README.md`。

## 测试与证据

- manifest/suite/fixture 版本匹配、重复 ID、缺 Evidence role、未知 Prediction 的失败测试；
- positive/negative/Inconclusive/policy/version-mismatch 每种至少一个元测试；cleanup 类型先验证 schema/未激活拒绝，执行闭环留到 Day10；
- fixture 两次 reset 后 hash/状态一致，无非 loopback 出站；
- 旧 40 Case 的 verdict、Evidence 和安全计数不回退；
- benchmark 同版本连续三次结果稳定；qualification hash 任一输入变化即失效，production composition 不加载 fixture package；
- 运行 evaluation/fixture 测试、`pnpm benchmark:verify`、legacy benchmark 和 `pnpm typecheck`。

## 合格交付

后续每个 technique 都有独立、可验证的 suite 合同；没有 fixture/规则/Evidence 的模块不能仅凭注册表名称进入 active 状态。
