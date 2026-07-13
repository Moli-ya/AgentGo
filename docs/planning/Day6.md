# Day 6：原子预算、网络边界与响应资源门禁

## 当天目标

把当前“请求完成后计数”和“比较调用方声明 RPM/并发”的软限制，升级为运行时不可超卖的原子预算；同时补齐 DNS、redirect、IP 分类和响应资源边界，为复杂 Web 流量开放前建立硬门禁。

## 必须完成的工作

1. 建立 scan/target/identity/technique 多维预算账户：总请求、滑动窗口 RPM、并发、发送/接收字节、单响应上限、重定向跳数、OOB poll、浏览器动作、计划时长。
2. 预算在发网前原子 reserve，完成后 settle；cancel/timeout/crash 按可证明状态释放或保守消耗。并发 claim 不得超过 Scope 与 Scan 较小上限。
3. 每个 ValidationPlan step 显式声明最大请求/字节/timeout/重复数和 stop condition；模块只能申请，Policy 决定上限，Agent 不能提高。
4. URL canonicalization 覆盖 userinfo、默认端口、IPv4 非标准表示、IPv6 zone、IDN/punycode、双编码路径、反斜杠和 scheme confusion；解析歧义 fail closed。
5. 每跳 DNS resolve/pin/复核；metadata 永久禁止。private、loopback、link-local、reserved、unspecified、multicast 分别建模，不能由一个 `allowPrivateNetworkTargets` 模糊放开所有危险类别。
6. 私网/回环只有 scope 精确列出 host/IP/CIDR/port/purpose 后才可用；SSR​​F 目标侧地址和 AgentGo 自身执行地址分开校验。
7. redirect 重新检查 origin/path/port/IP/identity/credential stripping/剩余预算；协议降级、非 HTTP(S)、超跳、重解析变化立即停止。
8. HTTP 响应实行 header/body/解压后大小限制、压缩炸弹比率限制、慢读超时和连接取消；证据保存遵循 Day4 CapturePolicy。
9. 为 Policy reason code 和安全计数新增稳定枚举，便于 benchmark 精确断言，而不是只匹配错误文本。

## 预计改动位置

- `packages/security-policy/src/index.ts`；
- `packages/http-runner/src/index.ts`；
- `packages/application/src/execution-service.ts`；
- `packages/db/src/schema.ts`、`repository.ts`；
- security-policy/http-runner/execution tests；
- `docs/security/active-probing-policy.md`。

## 测试与证据

- 高并发 reserve 不会超卖 request/RPM/concurrency/bytes；超时和 crash 后计数一致；
- IPv4/IPv6/IDN/重编码/metadata/私网/回环/保留地址测试表全部符合 fail-closed 预期；
- DNS rebinding、redirect chain、跨 origin Authorization/Cookie 剥离和每跳预算；
- 5 MiB 以上、压缩炸弹、慢响应、无限 redirect、chunk 中断均安全终止；
- 原有公开/明确 loopback fixture 不回退；
- 运行 policy/runner/Application/DB 测试与 `pnpm typecheck`。

## 合格交付

任何模块都不能超卖请求、并发或响应资源，也不能利用 URL、DNS、redirect 或地址分类歧义离开授权边界。
