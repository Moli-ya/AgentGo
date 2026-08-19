# ADR-0007：受保护 Evidence 授权封套、加密原件与脱敏派生

- 状态：Accepted
- 日期：2026-07-30

## 背景

Day4 规定原始 HTTP body、DOM 或 screenshot 默认不得保存；确有必要时，
原件必须进入受保护 Evidence，并同时形成可供普通报告消费的脱敏派生。
此前 `EvidenceCapturePolicy` 对 `protected-original` 失败关闭，现有
`EvidenceStore.save()` 又只依赖普通文件权限，不能满足加密、访问边界、
保留期、配额、派生关系和离线完整性验证要求。

单独增加“加密写文件”仍不够：调用者可能拼接 context、decision、plan 或
workspace，原件与派生可能分步提交，普通读取接口也可能意外返回明文。

## 决策

1. `protected-original` 只适用于 `http-response-body`、`dom-snapshot`
   和 `browser-screenshot` 的完整、非空字节。partial、oversize 和空输入
   降级为 hash-only；OOB token 永久不进入原件路径。
2. 受保护 artifact 必须自包含严格校验的 `captureContext`、
   `captureDecision`、source hash、ProtectionPlan 和 retention。外层
   scan/policy/technique/step/source/role/capture policy 必须与封套逐字段
   相等；retention 只能由 `occurredAt + authorized duration` 推导。
3. Application 使用后端专用 `ProtectedEvidenceCaptureService` 组合纯
   Policy 与 Store。服务只处理受保护决策窄类型，对同一安全字节快照先
   形成 artifact、再持久化，最后清零快照；该入口不加入 Renderer IPC。
4. Store 不接受调用者提供 workspace。它从已允许且仍在有效期内的
   `PolicyDecision -> ProbeProposal -> Scan -> Target` 推导 workspace，
   并重新校验原字节长度和 SHA-256。
5. 每份原件使用随机 AES-256-GCM data key 和 nonce；data key 由 Electron
   `safeStorage` 所代表的 OS `SecretProtector` 包装。AAD 覆盖完整严格
   artifact、Evidence ID、workspace 和 domain。磁盘只保存内容寻址的
   ciphertext，SQLite 保存 plaintext hash、storage hash、封套和包装密钥。
6. 原件、protected metadata、唯一 metadata-only redacted derivative
   和固定结构的 `evidence.protected.created` 审计在同一
   `BEGIN IMMEDIATE` 中提交。失败只留下可识别的无引用内容寻址文件，并
   立即或在启动 GC 中清理。
7. 普通 `save()` 只接受显式 `redacted` 内容；保留类型只能走 protected
   API。普通 `read()`、报告、Renderer 和 generic discard 永久拒绝受保护
   原件。当前只提供不返回明文的 backend integrity verification。
8. scan/workspace plaintext quota 由授权 plan 明确给出并在原子事务中
   计算。到期任务不接受调用者时间参数；只使用注入 clock，以条件更新的
   唯一获胜者清除 wrapped key/nonce/tag、写到期审计并安全删除无共享引用
   的 ciphertext。metadata、hash 和派生关系继续保留。
9. 迁移 `0010_protected_evidence_envelopes` 是只前进的新增能力。既有
   Evidence 不会被重新标记为已加密；数据库 trigger 约束完整 JSON 封套、
   原件/派生绑定、不可变字段和 crypto-erase 状态转换。
10. 验证只在明确的 ciphertext/hash/GCM/plaintext mismatch 时把
    integrity 标为 failed，并与失败审计同事务提交。OS unwrap 或审计写入
    的瞬时故障不得误标完好证据。

## 非目标与后续边界

- Day5 的真实 HTTP/离线 Browser 执行仍使用固定 hash-only capture
  authority；本 ADR 不修改九个 Day5 capture decisions。
- 把真实 DOM/screenshot 原件绑定到 Grant、Lease、wire 和 Interaction，
  并在可信审批下向复核器短时提供内容，属于 Day18。完成前 XSS marker
  executed 仍必须是 `Inconclusive`。
- 全局原子网络预算属于 Day6；可信 L2 Approval、SessionVault 和
  TestObject/Cleanup 分别属于后续顺序工作包。
- protected API 的可信边界是 Main/Application 后端。Renderer、模型输出
  和外部工具不能自行签发 capture decision 或获得解密内容。

## 后果

- Day4 具备可验证的 protected-original 后端闭环，同时保持默认不保存原文。
- 普通报告只能看到 metadata-only 派生，无法因调用参数关闭脱敏。
- 原件访问能力刻意小于存储能力；这避免在 Day18 的审批和复核语义完成前
  提前扩大敏感数据暴露面。
- 测试必须覆盖真实 Policy→Store sentinel、原子回滚、配额竞争、幂等、
  SQL 缺字段、不可变派生、篡改、瞬时 unwrap/audit 故障、并发到期和
  workspace cascade。
