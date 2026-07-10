# ADR-0001：TypeScript + Electron 桌面主栈

- 状态：Accepted
- 日期：2026-07-10

## 背景

项目需要 Windows GUI、浏览器自动化、模型 API、多 Agent 编排、本地数据库、证据展示和安装包。申报书提到团队具备 Python 基础，但最终产品希望避免多语言主干和开发环境依赖。

## 决策

V1 使用 TypeScript + Electron + React，Playwright 和 HTTP Runner 也运行在 Node/TypeScript 生态。Python 不作为主干运行时。

## 理由

- 前后端和编排共享类型；
- 与 Playwright、JSON Schema、模型 SDK 和 MCP 生态衔接自然；
- Electron 适合 Windows 安装和多进程隔离；
- AI 编程协作和原型迭代成本较低。

## 风险与验证

- 团队 TypeScript/Electron 经验需要通过 M0 骨架和培训验证；
- Playwright 浏览器会增加安装包体积；
- SQLite 原生驱动与 Electron ABI 需要单独 Spike；
- Electron 安全基线必须自动检查；
- 如果未来出现明确性能瓶颈，只在 profiling 后引入 Rust sidecar。
