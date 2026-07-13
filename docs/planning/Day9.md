# Day 9：SessionVault、Identity、CSRF 与多身份基础

## 当天目标

在 Day 8 的纯 L2 协议之上，先建立真实 Web 验证必需的短期会话、身份归属、CSRF 和授权预期基础，使 Bundle 能获得确定性的 `identityContextVersion`、`sessionGeneration` 与 `csrfBindingVersion`。当天仍不实现可信审批、不执行 L2 primary/cleanup，也不新增 Renderer UI。

Day 9 的核心交付是“安全地表示和绑定会话及身份”，不是自动登录或代替用户猜测权限。只有该基础通过测试后，Day 10 才能把批准精确绑定到某个会话 generation，并在 loopback fixture 上执行首条 L2 闭环。

## 前置条件与边界

- Day 8 的 TestObject、L2ActionBundle、状态机和 cleanup capability schema 已完成且通过纯状态测试。
- 复用现有 Target、Scope、Identity、credential ref、HTTP redirect 和脱敏能力；新增能力不得绕过 model-gateway/security-policy/execution 边界。
- 凭据只接受用户明确提供的专用测试身份材料；不自动登录、不刷新 token、不尝试密码、不绕过 MFA/CAPTCHA，不执行 OAuth/SAML/OIDC 流程。
- 不创建 ActorContext/ApprovalService，不接受 `userApproved`，不把 Bundle 推进到 `approved` 或 `running-*`。
- 不在真实目标或 Day 7 fixture 上执行可变状态请求；允许纯单元测试和不出网的 HTTP/session 适配器测试。
- Renderer 保持现有可用性，不新增 Session、Identity 或批准页面；Main/Preload 只在已有兼容确有必要时作最小合同适配。

## 具体工作

### 1. 建立版本化 IdentityContext

定义 `IdentityContext`，至少包含：

- `identityId`、`identityContextVersion`、target/scope/tenant 绑定；
- 用户确认的 role、owner label、用途和可使用的 operation；
- credential 类型引用、来源、有效期和敏感等级，不包含明文 secret；
- 允许参与对照的身份集合和互斥约束；
- 归属证明/人工确认的审计引用。

模型、Agent、页面内容和工具输出都不能推断真实角色、tenant、对象归属或“应该可见”的资源。身份材料缺失、版本变化或人工确认过期时，相关候选进入 `awaiting-user`，不能自动换用其他身份。

### 2. 建立受保护的 SessionVault

实现后端进程内或等价受保护的 `SessionVault`：

- 按 target/origin/identity 隔离 Cookie jar、静态 Bearer/API key ref 和可选 Basic credential ref；
- 维护 Domain、Path、SameSite、Secure、HttpOnly、expiry 和 host-only 等 Cookie 语义；
- 每次创建、轮换、注销、清空或重新注入都增加不可回退的 `sessionGeneration`；
- DB 仅保存必要 metadata、credential ref 和状态，不保存 Cookie、Authorization、Token、密码或 CSRF 明文；
- pause/resume、进程重启和 vault 丢失后要求用户重建/重新注入，旧 generation 不得复活。

Set-Cookie 必须进入私有 sink；原始值不得流入普通 Evidence、日志、错误、报告、IPC 或 Renderer。凭据访问只通过最小能力接口，调用方不能枚举 vault 全量内容。

### 3. 绑定 HTTP 请求与 session generation

- 请求编译结果只引用 session handle/generation，不复制 secret 到可持久化 Candidate 或 Proposal；
- grant/lease 开始前和发送前都校验 generation，一旦轮换立即使旧候选、旧 grant 和未来批准失效；
- 跨 origin redirect 必须剥离 Cookie/Authorization；secure downgrade、Domain/Path/public suffix 和 expiry 使用确定性规则；
- 同一 scan 的不同 identity 使用隔离 jar，不允许 Cookie 串用、fallback 或隐式共享；
- 报告只显示 identity label、session 状态、generation 和失效原因，不显示 Cookie 名值全集或 token 片段。

### 4. 建立 CSRF 提取与注入协议

定义版本化 CSRF binding：

- 来源页面/响应字段、HTML selector/JSONPath/header/form field、提取规则版本；
- token 的 identity、session generation、origin、method/path 和有效期绑定；
- 单值规则、编码规则、注入位置和使用次数限制；
- 缺失、多值歧义、过期、跨身份、跨 origin 或来源响应不可信时的 `awaiting-user`/`inconclusive` 原因码。

CSRF 明文只存在于受保护的短期存储和最终发送阶段；Candidate、DB、普通 Evidence、日志和报告只保存脱敏摘要/hash 与 `csrfBindingVersion`。不得用模型生成或猜测 token。

### 5. 建立授权预期矩阵

定义 `AuthorizationMatrix`，至少包含：

- subject identity、resource owner、tenant、role、operation；
- 用户确认的 expected visibility/state、基线身份和对照身份；
- TestObject/owned resource 的精确引用与版本；
- 人工来源、证据引用、有效期和矩阵版本。

IDOR/BOLA/BFLA 和业务权限验证只能读取该矩阵，不能把 HTTP 200、页面文本、模型判断或身份命名当作正常权限真值。矩阵不完整时，只能产生待补充信息或 signal，不能主动执行身份对照。

### 6. 将 Day 9 绑定值接入 Day 8 Bundle

- 由确定性 Application Service 为 Bundle 填充 `identityContextVersion`、`sessionGeneration`、`csrfBindingVersion` 和 `authorizationMatrixVersion`；
- 任一引用变化时生成新 Bundle hash，旧 Bundle 进入 expired/revoked，不可原地“刷新”；
- 此操作只把 `draft` 推进到“具备提交批准资格”的 `pending-approval` 候选，不等同于批准；
- 仍需 Day 10 的可信 ActorContext/ApprovalService，且批准必须绑定这些版本。

### 7. 明确不支持与等待用户路径

本日明确不支持自动 login/refresh/logout、密码喷洒、凭据轮换尝试、MFA/CAPTCHA 绕过、OAuth/SAML/OIDC 登录编排和生产身份接管。遇到 session 过期、MFA/CAPTCHA、CSRF 歧义或身份归属不明，统一进入 `awaiting-user`，不得继续猜测或降级到匿名身份。

## 预计改动位置

- `packages/contracts/src/application.ts`、`packages/contracts/src/security.ts`：IdentityContext、session/CSRF/授权矩阵引用；
- `packages/application/src/session-vault.ts`、`identity-service.ts`、CSRF/authorization matrix 服务；
- `packages/db/src/credential-store.ts` 及 schema/repository metadata：仅保存引用、版本和非敏感状态；
- `packages/http-runner/src/index.ts`：私有 Cookie sink、redirect stripping 和 generation 校验适配；
- session、credential、CSRF、authorization matrix 和 secret-flow 测试；
- `docs/security/threat-model.md`、`docs/architecture/data-model.md`：同步信任边界与生命周期。

不得新增 ApprovalService、L2ProbeOrchestrator、Renderer View 或真实目标 L2 执行入口。

## 测试与验收证据

- Cookie：Domain/Path/expiry/SameSite/Secure/HttpOnly/host-only、Set-Cookie rotation、public suffix、secure downgrade 和跨 origin stripping；
- 隔离：两个 identity/tenant 的 cookie jar 不串用，匿名身份不会继承已认证凭据；
- generation：注入、轮换、清空、重建和 pause/resume 后旧 Candidate/Bundle/grant 引用全部失效；
- CSRF：正确提取、缺失、多值、过期、错误 identity/session/origin/path/method 和规则版本变化；
- 授权矩阵：owner/tenant/role/operation 的确定性读取、版本失效和缺项失败关闭；
- 等待用户：MFA、CAPTCHA、session expired、归属不明进入 `awaiting-user`，没有自动凭据尝试；
- secret sentinel：Cookie/Bearer/API key/Basic/CSRF 不出现在 DB、普通 Evidence、日志、错误、审计 payload、报告或 Renderer；
- 执行 credential/session/http adapter/Application 测试与 `pnpm typecheck`；L2 primary/cleanup 调用次数必须为 0。

## 合格交付

- 后端能以版本化、隔离、最小暴露的方式表达短期 session、多身份、CSRF 和授权预期；
- Day 8 Bundle 可被精确绑定到 identity/session/CSRF/矩阵版本，但仍不能绕过 Day 10 批准进入执行态；
- 会话轮换立即作废旧 Bundle/grant，secret 不进入普通持久化或展示路径；
- 不存在自动登录、凭据猜测、身份 fallback、真实目标写请求或 Renderer 新 UI；
- 交付证据明确写为“L2 基础就绪、尚未批准/执行”，不能声称已完成 L2 闭环。
