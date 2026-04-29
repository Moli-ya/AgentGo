$ErrorActionPreference = "Stop"

$root = "D:\surrounding"

$env:COREPACK_HOME = Join-Path $root "corepack"
$env:PNPM_HOME = Join-Path $root "pnpm"
$env:PLAYWRIGHT_BROWSERS_PATH = Join-Path $root "playwright"
$env:ELECTRON_CACHE = Join-Path $root "electron-cache"
$env:ELECTRON_BUILDER_CACHE = Join-Path $root "electron-builder-cache"
$env:CARGO_HOME = Join-Path $root "rust\cargo"
$env:RUSTUP_HOME = Join-Path $root "rust\rustup"
$env:npm_config_cache = Join-Path $root "npm-cache"
$env:npm_config_prefix = Join-Path $root "node"

$paths = @(
  (Join-Path $root "git\cmd"),
  (Join-Path $root "node"),
  (Join-Path $root "pnpm"),
  (Join-Path $root "sqlite\bin"),
  (Join-Path $root "gh\bin"),
  (Join-Path $root "go\go\bin"),
  (Join-Path $root "rust\cargo\bin")
)

$existing = $env:PATH -split ";" | Where-Object { $_ }
$orderedPaths = $paths.Clone()
[array]::Reverse($orderedPaths)
foreach ($path in $orderedPaths) {
  if ($existing -notcontains $path) {
    $env:PATH = "$path;$env:PATH"
  }
}

Write-Host "AgentGo local development environment loaded from $root"
