# Day 19：SSRF 参考模块 V2 增强、受控 OOB 与被动模块激活

## 当天目标

在 Day15 已切换且行为等价的 SSRF bundle 上完成回显/盲 SSRF 受控证据链，并把 Day2 仅登记的 `security.headers` descriptor 实现、评测和资格化为被动模块，证明新增 family/technique 不需要修改 Coordinator。不得创建第二条 SSRF 执行路径；任一安全门禁未通过则顺延。

## 支持边界

- 只访问项目控制的随机 token 回连端点或 scope 精确列出的测试服务；不访问 localhost、云元数据、未授权私网和真实第三方。
- 不探测端口、不读取回连响应中的敏感数据、不沿 redirect 越界、不做 DNS rebinding 绕过。
- OOB Confirmed 必须有服务端可归因事件；浏览器/本机直接访问、历史/重复/过期 token 均不得计入。

## 必须完成的工作

1. Manifest 定义 `ssrf.reflected-proof` 与 `ssrf.oob-callback`；前者要求目标响应返回受控 proof，后者使用 callback register/poll/consume steps。
2. 建立 `CallbackCollectorPort` 和 loopback adapter：生成高熵单次 token，绑定 scan/candidate/step/target/time window；记录协议、server-side source metadata、去重和完整性 hash。
3. 远程 Collector 只定义经过认证、TLS、租户隔离、时钟/重放防护的数据协议；20 天无真实服务则明确 `not-run`，不得用 mock 冒充生产 OOB。
4. SSRF Detector 结合 URL-like selector、OpenAPI/JS/response 语义和 allowed destination；普通 URL 参数不直接判漏洞。
5. Plan 包含 baseline、controlled destination、negative token/control、redirect/DNS policy checks 和 bounded poll；达到证据或窗口即停止。
6. ConfirmationRule 排除客户端发起、Browser Broker、本机健康检查、历史 token、重复投递和无 target correlation；WAF/超时/collector unavailable 为 Inconclusive。
7. Fixture 至少 4 正、4 负、2 Inconclusive：回显、blind OOB、allow-list 正常代理、客户端 fetch、旧 token、redirect 越界、collector down 和动态响应。
8. 为 Day2 `registered-only` descriptor 增加生产级被动实现 `security.headers.baseline`：只分析已获响应的 HSTS/CSP/frame/content-type/referrer/cache/cookie 属性，输出版本化 Evidence/Remediation；不新增网络请求。Suite 通过后生成 qualification record 并由 ActivationCatalog 激活，不能再次注册同 ID/版本。
9. 用 architecture/conformance test 证明添加 `security.headers` 未编辑 Coordinator family 分支、封闭标签表或 benchmark 枚举；报告从 Registry descriptor 获取标签。

## 预计改动位置

- `packages/vulnerability-modules/src/ssrf/**`、`security-headers/**`；
- Callback port/loopback adapter；
- Network Policy、fixture/suite/knowledge/reporting；
- SSRF/header module/conformance/integration tests。

## 测试与证据

- token 唯一、过期、重放、并发、cross-scan/cross-tenant、时钟边界；
- metadata/private/loopback/redirect/DNS rebinding/非 HTTP scheme 在真实目标 profile 下拒绝；
- 客户端/Browser/Broker 事件不会误判服务端 SSRF；
- collector down/WAF/timeout 输出 Inconclusive；
- security.headers 零新增请求，缺失/多值/代理改写和非 HTTPS 场景表述正确；
- legacy SSRF Case 不回退，运行 module suites/benchmark/conformance 和 `pnpm typecheck`。

## 合格交付

SSRF 的回显与 OOB 证据可准确关联且不访问危险网络；Day2 的被动 descriptor 已在不改主链的前提下升级为 qualified detector，证明架构不是四类换皮。
