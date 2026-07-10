# AgentGo 开发环境

## 通用要求

- Windows 10/11
- Node.js 24+
- pnpm 10+
- Git

验证：

```powershell
node --version
pnpm --version
git --version
```

克隆后在仓库根目录运行：

```powershell
pnpm install
pnpm typecheck
pnpm test
pnpm dev
```

项目不能依赖某个固定盘符才能构建。所有缓存和工具路径都应允许通过环境变量覆盖。

## 当前本机可选环境

当前开发机将工具和缓存集中在 D:\surrounding 下，包括 Git、Node.js、pnpm、SQLite、Playwright、Electron 缓存和 Rust。这是本机优化，不是项目的通用前置条件。

如果新 PowerShell 尚未获得这些路径，可以在仓库根目录执行：

```powershell
. .\scripts\use-local-env.ps1
```

如确实需要写入系统级环境变量，可在管理员 PowerShell 中执行：

```powershell
.\scripts\configure-system-env.ps1
```

系统级配置是可选项；普通贡献者不应为了运行项目而必须执行管理员脚本。

## GitHub

GitHub CLI 登录：

```powershell
gh auth login
```

登录后可使用 git push 或 gh 管理远端仓库。

## 后续环境项

- Playwright 浏览器通过项目脚本安装或由应用首次启动引导；
- SQLite 驱动随应用打包，不要求最终用户安装 SQLite CLI；
- Rust 仅用于未来经过 profiling 确认的热点模块；
- API Key 不写入 .env 示例以外的仓库文件，运行时进入操作系统凭据存储。
