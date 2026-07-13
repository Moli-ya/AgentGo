# Day 15：V1 行为等价适配、通用 Coordinator 与安全恢复

## 当天目标

先把 SQLi、XSS、SSRF、IDOR 当前 V1 行为逐项迁入四个 legacy-parity bundle，再把 `DefaultScanCoordinator` 缩减为 phase/checkpoint/队列/awaiting-user 编排器。Day15 只要求行为等价和唯一执行真源；复杂 selector、多身份、真实 OOB、运行期浏览器和 L2 增强分别在 Day16～Day19 完成。

## 必须完成的工作

1. 定义通用 Candidate：candidateId、family/technique/module version、SubjectRefs、variant/dependency refs、identity/test object/matrix refs、reason、expected signal、suggested strategy；parameter 不再是必填。
2. `DetectorService` 对 frozen Inventory/Observation 运行纯 Detector，输出 CandidateSeed；Agent 建议经 schema/Registry/Scope 校验后只能补充排序和解释。
3. `CandidateCompiler` 结合 review、Scope、session、dependency、TestObject、Capability、环境和预算选择 strategy 或返回 inventory-only/awaiting-user/forbidden；Agent 不决定风险等级。
4. 持久化 `CandidateAttempt`：planned、awaiting-approval/session/input、running、cleanup-pending、interrupted、cancelled、failed、completed、inconclusive、rejected；关联 plan/step/bundle/grant/evidence refs。
5. `runPhase` 返回 `PhaseOutcome`：completed、awaiting-user、paused、failed；只有 completed 才推进 checkpoint，不能把等待审批写成 phase-completed。
6. resume 重新校验 scope/module/strategy/rule/variant/dependency/session/test object/approval/lease/预算；缺历史版本、primary 送达不明或 cleanup pending 时不自动重放。
7. 将四类当前 `validateCandidate()` 行为完整迁入 legacy-parity module adapter + ValidationPlan/ConfirmationEngine；逐类建立旧输入、请求序列、Evidence role、verdict/reason、停止条件和报告字段的 golden parity 断言。Coordinator 不 import `assessSqli/assessXss/assessSsrf/assessIdor`。
8. `FindingAssembler` 从 Registry 获取标签、severity guidance、EvidenceProfile、Remediation；Reporting 使用 descriptor fallback，不再维护封闭 `Record<family,label>`。
9. 增加 architecture test：Coordinator 源码中不得出现 family switch/if、payload generator、Runner 直调、SQLi/XSS/SSRF/IDOR 专用常量。
10. 每类按“adapter shadow（不发第二次请求）-> golden compare -> 单一真源切换 -> 删除旧分支”小步迁移。任何时刻只允许一个路径实际 I/O；若任一 family 未通过 40 Case 和恢复测试，Day16 顺延，不能保留第二条执行真源。
11. 在 Day15 完成记录中逐类列出 parity 状态。未迁移 family 使 Day15 保持 partial，不能因 Coordinator 外观已拆分就标 completed。

## 预计改动位置

- `packages/application/src/scan-coordinator.ts` 拆分；
- `packages/application/src/detector-service.ts`、`candidate-compiler.ts`、`finding-assembler.ts`；
- `packages/domain/src/vulnerabilities/**`；
- `packages/reporting/src/index.ts`；
- `packages/db/src/schema.ts`、repository；
- coordinator/recovery/architecture/report tests。

## 测试与证据

- mixed active/signal/inventory/forbidden candidates 的排序、等待、拒绝和完成；
- pause/cancel/crash/session expiry/module missing/cleanup pending 恢复，不重复实际 I/O；
- 模型输出未知 technique、伪造 capability、无 Subject/Rule/Strategy 被拒绝；
- 新增 passive 测试 module 后 Coordinator 源码与测试 fixture 不需改分支；
- legacy 40 Case、报告标签、Evidence 引用和安全计数不回退；
- architecture/instrumentation 证明一次 Candidate 只产生一组实际 I/O，legacy 与 generic 路径绝不双跑；
- 运行 `pnpm check` 和通用架构约束测试。

## 合格交付

四类 V1 已在通用运行时上行为等价，且仓库只有一个联网执行真源；Coordinator 不再知道具体漏洞验证步骤。Day16～Day19 只在这些相同 bundle 上增强，不能再次发明迁移路径。
