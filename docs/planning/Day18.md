# Day 18：XSS 参考模块 V2 增强——反射、离线 DOM 与测试对象存储

## 当天目标

在 Day15 已切换且行为等价的 XSS bundle 上拆分不同风险 technique：真实授权环境的惰性反射 marker、断网 DOM 执行确认，以及经 L2 批准的专用测试对象存储场景。任何 payload 都不得外传数据或影响真实用户，不得另建并行执行模块。

## 支持边界

- marker 只能执行本地布尔/DOM 属性证明，无 Cookie/Token/localStorage 读取、网络外传、弹窗骚扰或持久化控制。
- 反射不等于执行；必须结合上下文、编码和隔离浏览器 Evidence。
- 存储型只写专用测试对象/目录，完成读取证明后立即 cleanup；cleanup 失败停止整个对象队列。
- 任意真实用户触发、社会工程、CSP 绕过、WAF 规避不在自动流程。

## 必须完成的工作

1. Manifest 定义 `xss.reflected-marker`、`xss.dom-offline-replay`、`xss.stored-test-object`，分别标记 L1、L1/offline、L2。
2. Detector 记录 HTML/attribute/URL/script/JSON/DOM sink 上下文、编码链、CSP 和 source；仅文本反射可形成 signal，但不能直接 Confirmed。
3. Mutation generator 使用随机惰性 marker 和严格字符集/长度；静态语义检查禁止网络 API、storage/cookie 访问、持久化、事件骚扰和外部资源。
4. 反射 Plan：baseline -> marker request -> response capture -> offline Browser replay -> negative encoded control；Browser 无网络出口。
5. DOM Plan 只重放 Day12 静态 AssetManifest 与 Day13 Broker 捕获的固定 bundle/DOM 和批准 source；不让任意 live page 在验证阶段自由联网。
6. 存储 Plan：pre-read -> L2 write test object -> isolated read -> offline execution -> cleanup -> verify；每步 Evidence role 和 stop condition 明确。
7. ConfirmationRule 区分 reflected-only、executable-context、CSP blocked、sanitized、DOM marker executed、stored persisted；CSP blocked 的风险表述与 verdict 规则版本化。
8. Fixture 至少 4 正、4 负、2 Inconclusive，覆盖 HTML/attribute/JSON、正确编码、sanitizer、CSP、DOM source/sink、存储 cleanup 和动态 nonce。
9. Remediation 按输出上下文编码、模板 auto-escape、safe DOM API、sanitization、Trusted Types/CSP defense-in-depth 和复测方式生成。

## 预计改动位置

- `packages/vulnerability-modules/src/xss/**`；
- Browser offline replay/Evidence profile；
- L2 fixture、suite、knowledge、reporting；
- XSS module/conformance/integration tests。

## 测试与证据

- marker grammar/property test 证明无网络、Cookie/storage、持久化和危险 API；
- HTML/attribute/script/URL/JSON context 的编码正负例；
- Browser egress recorder 为 0，screenshot/DOM Evidence 与 scan/step 对应；
- stored success 后状态回基线；cleanup fail 后无普通执行；
- 仅反射、CSP blocked、sanitized、页面不稳定和 Browser crash 的三态准确；
- legacy XSS Case 不回退，运行 module suite/benchmark/conformance 和 `pnpm typecheck`。

## 合格交付

XSS 主动验证能够证明执行上下文而不窃取数据或影响真实用户；三种 technique 的风险、证据和清理边界清晰可审计。
