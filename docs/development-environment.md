# AgentGo 开发与交付环境

## 通用要求

- Windows 10/11 x64
- Node.js 24+
- pnpm 10+
- Git
- Microsoft Edge 或 Google Chrome，用于隔离 XSS 渲染测试

验证环境：

```powershell
node --version
pnpm --version
git --version
```

项目不依赖固定盘符。SQLite 随 Node/Electron 运行时提供，最终用户不需要安装 SQLite CLI；Playwright Core 使用系统浏览器，不需要下载 Playwright 浏览器包。

## 安装和开发

```powershell
pnpm install
pnpm dev
```

Renderer 浏览器预览只能用于界面调试，写数据库、凭据、扫描和导出等功能必须在 Electron 中运行。

仓库中的 `scripts/use-local-env.ps1` 和 `scripts/configure-system-env.ps1` 仅是特定开发机的可选便利脚本，包含本机路径假设，不是项目运行前提，也不应在未知机器上直接执行管理员级脚本。

## 质量门禁

```powershell
pnpm check
pnpm smoke:desktop
pnpm benchmark:verify
```

- `pnpm check`：全仓类型检查、全部 Vitest、Electron 生产构建。
- `pnpm smoke:desktop`：启动 Electron，等待 Renderer 就绪并验证安全策略；使用内存数据库，不访问外部目标。
- `pnpm benchmark:verify`：校验 40 Case manifest 和指标实现，不执行完整扫描。

单独调试测试可使用：

```powershell
pnpm vitest run packages/application/src/application-service.test.ts
pnpm --filter @agentgo/application typecheck
```

## 固定靶场评测

```powershell
pnpm benchmark:fixture
pnpm benchmark:run --output .\benchmark-results\my-run
```

`benchmark:run` 会自行启动只监听 `127.0.0.1` 的固定靶场，并保存数据库、证据、预测、JSON 汇总和 Markdown 报告。输出目录已被 Git 忽略。不要让 Agent 读取 `benchmarks/v1-ground-truth.json` 中的预期标签。

## Windows 交付

```powershell
pnpm pack:win
pnpm smoke:packaged
pnpm dist:win
```

- `pack:win`：生成 `release/win-unpacked/AgentGo.exe`。
- `smoke:packaged`：验证打包应用可初始化数据库、IPC、Renderer 和策略自检。
- `dist:win`：生成 x64 NSIS 安装器。

打包直接复用工作区已安装的 Electron 发行目录，因此 Electron 本体无需在每次构建时重新下载；首次生成 NSIS 安装器仍可能需要联网获取 electron-builder 的已校验工具包。

当前原型未配置代码签名和自定义图标。正式分发前需要准备证书、签名策略、图标和安装/升级/卸载矩阵测试。

## 凭据和环境变量

API Key 不写入仓库或普通 `.env` 文件。运行时由 Electron `safeStorage` 加密，数据库只保存引用。CI 或本地命令如确需临时环境变量，应由调用环境注入，并确保日志不输出其值。

## Git 边界

以下内容属于本地材料或生成物，不应提交：

- 原始 `.doc` / `.docx` 计划书；
- 应用运行数据、凭据和证据；
- `benchmark-results/`；
- `release/`；
- 开发者个人指令文件和本机环境配置。
