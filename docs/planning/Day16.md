# Day 16：SQL 注入参考模块 V2 增强与复杂 Selector

## 当天目标

在 Day15 已切换且行为等价的 SQLi bundle 上增加 reviewed query/path 与批准 form/JSON selector，使其成为第一个满足完整 V2 DoD 的参考模块。不得创建与 Day15 adapter 并行的第二个 SQLi module 或联网路径。

## 支持边界

- 真实授权环境：只允许非写入式布尔差异和受限错误信号；不读取真实业务数据。
- POST form/JSON：仅专用 TestObject/fixture 或明确测试租户，经 L2 bundle 批准；不能把“查询接口”名称当作只读证明。
- 时间差异：20 天内仅 fixture/显式研究 profile，严格低并发、短 timeout 和少量重复；默认真实业务不主动执行。
- 堆叠查询、UNION 数据提取、文件读写、命令执行、DROP/TRUNCATE/INSERT/UPDATE/DELETE 永久禁止。

## 必须完成的工作

1. Manifest 定义 `sqli.boolean-differential`、`sqli.error-signal` 和 `sqli.bounded-time-differential` 的独立 maturity/capability/environment，不用一个 family 规则概括全部。
2. Detector 根据 parameter type/name、response shape、source confidence、reviewed variant 和 codec 产生 Candidate；不得只靠参数名 regex，也不得把普通 500 直接判 SQLi。
3. Strategy 形成 baseline、true-control、false-control、repeat/negative 的有序 Plan；每个 mutation 来自版本化安全 generator，并通过 destructive semantic gate。
4. query/path/form/JSON Pointer 使用同一 RequestCompiler；header/cookie 本日只盘点，避免未经充分评测扩大主动面。
5. normalization 覆盖 status、selected JSON shape/field hash、HTML/text、动态 UUID/time/数字、缓存 header 和稳定相似度；保存规则版本和阈值。
6. ConfirmationRule 要求可重复的 true/false 对照、稳定 baseline、负对照和最小 Evidence roles；WAF、抖动、普通异常、超时不足均为 Inconclusive。
7. Knowledge/Remediation 包含参数化查询、ORM 正确绑定、最小权限、统一错误处理和复测方法；不得建议用 WAF 替代根因修复。
8. Fixture 至少新增 4 个逻辑不同正例、4 个负例、2 个 Inconclusive：query/path/form/JSON、缓存/随机内容/普通 500/WAF/慢响应等异质场景。
9. 安全 suite 覆盖破坏性 token、写语句语义、超预算、未批准 POST、scope 外、规则缺失和 Evidence 缺失；全部不能发出危险请求或 Confirmed。

## 预计改动位置

- `packages/vulnerability-modules/src/sqli/**` 或 Day2 确定的模块目录；
- Registry composition；
- `packages/evaluation` fixture/suite；
- Knowledge/Reporting 映射；
- SQLi module/conformance/integration tests。

## 测试与证据

- 各 selector/codec 的 canonical request 与 mutation 位置正确；
- 正/负/Inconclusive 逐例断言 reason code、Evidence role 和请求上限；
- WAF/抖动/缓存/500/timeout 不误报；
- destructive SQL semantic corpus 在 Compiler/Policy 双层拒绝，实际请求计数为 0；
- L2 form/JSON 完成 cleanup，失败时后续冻结；
- legacy SQLi 10 Case 不回退，运行 module suite、conformance、benchmark、`pnpm typecheck`。

## 合格交付

SQLi 不再是 Coordinator 分支；模块可在受控真实 Web selector 上做非破坏主动验证，并能明确区分 Confirmed、Not Confirmed 和 Inconclusive。
