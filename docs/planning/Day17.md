# Day 17：IDOR/BOLA 参考模块 V2 增强与只读授权矩阵

## 当天目标

在 Day15 已切换且行为等价的 IDOR bundle 上增强 path/query/JSON response 对象关系，并用 AuthorizationMatrix 排除公开、共享、管理员、跨租户和对象层级误报；不得另建并行执行模块。

## 支持边界

- 只使用用户提供的两个或多个专用测试身份和已知归属的合成资源；不枚举真实用户对象。
- 真实授权环境默认只读 GET/HEAD 对照；写越权、删除、邀请、角色变更仅产生 signal 或专用 fixture L2，不影响真实对象。
- 一旦证明非拥有者可读取最小测试对象即停止，不扩大 ID 范围、不批量下载。

## 必须完成的工作

1. Manifest 至少定义 `authz.bola.read-differential`，并预留 BFLA、BOPLA/mass-assignment、cross-tenant、parent-child technique；未完成项保持 signal/inventory 状态。
2. Subject 使用 identity relation、resource ownership、operation 和 selector，不再强制把“对象 ID”视为普通 parameter。
3. Detector 结合 OpenAPI/route/response schema、identity inventory、owner/test object refs 产生候选；随机整数或 UUID 本身不能证明资源 ID。
4. Plan 至少包含 owner baseline、other-identity same resource、other-identity own resource、public/shared control；按 Matrix 需要加入 admin/tenant/parent control。
5. Session switch 必须使用独立 generation/lease；Evidence 记录身份 label/hash，不保存 Cookie/Token。
6. Response normalization 比较 status、资源 identity/owner 字段、selected shape/field hash 和授权错误语义；仅“两个 200 长度相似”不足以 Confirmed。
7. ConfirmationRule 要求已知归属、非拥有者返回目标对象的稳定最小证据、负对照和 Matrix 一致；公开/共享/admin/缓存/网关错误均排除或 Inconclusive。
8. Fixture 至少 4 正、4 负、2 Inconclusive，覆盖 path/query、跨 tenant、公开对象、共享对象、管理员、parent-child、session 过期和动态内容。
9. Remediation 指向服务端对象级授权、tenant 约束、deny-by-default、集中 policy 和回归矩阵；不以不可猜 ID 作为根本修复。

## 预计改动位置

- `packages/vulnerability-modules/src/idor/**` 或 `authz/**`；
- Identity/AuthorizationMatrix integration；
- fixture/suite/knowledge/reporting；
- authz module/conformance/integration tests。

## 测试与证据

- owner/other/public/shared/admin/tenant/parent 组合矩阵；
- session generation、跨身份 Cookie 隔离、cache-control 和 stale response；
- response 中目标 resource identity 缺失时不 Confirmed；
- 未知归属、身份不足、session expired、矩阵冲突均 awaiting-user/Inconclusive；
- 无资源枚举、无写动作、无批量数据 Evidence；
- legacy IDOR Case 不回退，运行 module suite/benchmark/conformance 和 `pnpm typecheck`。

## 合格交付

系统能在已知测试资源上主动确认只读 BOLA/IDOR，并用显式业务授权矩阵减少误报；未实现的写越权/BFLA 不被冒充为已支持。
