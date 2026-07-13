# Day 14：通用 ValidationPlan 运行时与统一 Knowledge Retrieval

## 当天目标

实现与漏洞类别无关的 ValidationPlan DSL/Executor，并把两条 KnowledgePack 组装路径合并为一个 Registry-aware RetrievalService。模块只声明“做什么”，通用运行时决定“是否、何时、如何安全执行”。

## 容量与拆分规则

这是二十个工作包中职责最重的一包。若 ValidationPlan runtime 在计划、持久化、恢复和安全测试完成后已达到单包容量上限，则显式拆为 Day14A（DSL/Executor/Evidence）与 Day14B（Retrieval 合并/legacy plan adapter），整体顺延 Day15；两部分都通过前不得把 Day14 标为 completed，也不得为了保持编号跳过 Knowledge 双路径收敛。

## 必须完成的工作

1. 定义受限 step union：passive-analysis、http-request、browser-offline-replay、browser-mediated-read、extract-value、state-observe、identity-switch、callback-register/poll/consume、bounded-parallel-group、compare/aggregate、cleanup、cleanup-verify。
2. 每步必须携带 stepId、family/technique/module/strategy version、SubjectRefs、CapabilityIds、risk/environment、intent ref、Evidence roles、预算、timeout、stop conditions；L2 还需 TestObject/Cleanup ref。
3. 模块不得提供任意 callback、Runner 或 Repository；`ValidationPlanCompiler` 输出纯数据，Executor 只接受 Registry 中已知 step/capability/schema。
4. 实现 `validation_plan_runs`、`validation_step_runs`、`validation_observations`、`validation_evidence_bindings`；Evidence 按 role/ordinal/profile/version 绑定，而不是固定三个响应列。
5. Step 每次真实 I/O 走 Day4～Day6 的 Compiler/Grant/Lease/Policy/Budget/Capture；Plan 批准不等于绕过单步检查。
6. 支持串行、多身份切换、OOB 等待和有界并发；并发组只允许 Registry/Policy 声明的最大 fan-out，race/raw protocol 默认 fixture-only。
7. 实现统一 `RetrievalService`，替换 `knowledge-base.buildKnowledgePack` 与 Coordinator `buildKnowledgeOutput` 的重复组装；输入 scan module snapshot、technique、Subject、context 和 safety constraints。
8. KnowledgePack 每条建议必须带 source/rule/negative-control/forbidden-capability/remediation refs；未注册 technique 只形成 unmapped intelligence，不进入 Compiler。
9. 用四个 legacy adapter plan 覆盖当前三响应/双身份/浏览器/OOB-like 形状，为 Day15 去分支做准备；不改变当前 verdict。

## 预计改动位置

- `packages/contracts/src/validation.ts`、`vulnerability.ts`；
- `packages/domain/src/vulnerabilities/**`；
- `packages/application/src/validation-plan-executor.ts`、`retrieval-service.ts`；
- `packages/db/src/schema.ts`、migrations/repository；
- `packages/knowledge-base/src/index.ts`；
- plan/runtime/retrieval tests。

## 测试与证据

- 所有 step schema、未知 step/capability、悬空引用、预算合计和环境限制；
- 多身份、浏览器离线、OOB wait、L2 cleanup、有界并发的合成 Plan；
- 每个 I/O 都存在独立 Lease/Policy/Evidence role，失败后后续 step 按 stop condition 停止；
- Knowledge 两旧入口结果迁移一致，未注册/未审查内容不能成为可执行策略；
- legacy 四类旧 40 Case verdict 不回退；
- 运行 Application/DB/Knowledge/Evaluation tests 和 `pnpm typecheck`。

## 合格交付

新增漏洞模块可以组合通用步骤而无需复制执行、安全、证据和恢复逻辑；知识检索只有一个可信入口且不能注册代码。
