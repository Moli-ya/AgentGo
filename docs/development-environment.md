# AgentGo 开发环境

本项目约定开发环境统一放在 `D:\surrounding\<环境程序名>` 下，避免工具和缓存散落到系统盘。

## 已准备目录

- `D:\surrounding\git`：Git，当前为指向 `D:\Git` 的目录联接。
- `D:\surrounding\node`：Node.js / npm。
- `D:\surrounding\pnpm`：pnpm shim 与 pnpm store。
- `D:\surrounding\npm-cache`：npm cache。
- `D:\surrounding\sqlite`：SQLite CLI。
- `D:\surrounding\gh`：GitHub CLI。
- `D:\surrounding\playwright`：Playwright browser cache，已预拉取 Chromium。
- `D:\surrounding\electron-cache`：Electron download cache。
- `D:\surrounding\electron-builder-cache`：electron-builder cache。
- `D:\surrounding\rust`：Rust / Cargo / rustup。

## 当前工具版本

- Git: `2.51.0.windows.2`
- Node.js: `v24.14.0`
- npm: `11.12.1`
- pnpm: `10.33.2`
- SQLite: `3.50.4`
- GitHub CLI: `2.92.0`
- Rust: `1.95.0`
- Cargo: `1.95.0`

## 使用方式

新开 PowerShell 后，如果 PATH 尚未刷新，可以在仓库根目录执行：

```powershell
. .\scripts\use-local-env.ps1
```

GitHub CLI 已安装，但需要单独登录：

```powershell
gh auth login
```

完成登录后，后续可以直接使用 `git push` 或 `gh` 管理 GitHub 仓库。
