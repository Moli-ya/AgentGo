$ErrorActionPreference = "Stop"

$logPath = "D:\surrounding\system-env-config.log"
New-Item -ItemType Directory -Force -Path (Split-Path $logPath) | Out-Null
"[$(Get-Date -Format o)] configure-system-env.ps1 started" | Out-File -FilePath $logPath -Encoding utf8 -Append

$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  "[$(Get-Date -Format o)] not elevated" | Out-File -FilePath $logPath -Encoding utf8 -Append
  throw "This script must be run from an elevated PowerShell session."
}
"[$(Get-Date -Format o)] elevated session confirmed" | Out-File -FilePath $logPath -Encoding utf8 -Append

$root = "D:\surrounding"

$pathEntries = @(
  (Join-Path $root "node"),
  (Join-Path $root "pnpm"),
  (Join-Path $root "git\cmd"),
  (Join-Path $root "gh\bin"),
  (Join-Path $root "sqlite\bin"),
  (Join-Path $root "rust\cargo\bin")
)

$machinePath = [Environment]::GetEnvironmentVariable("Path", "Machine")
$existingEntries = @()
if ($machinePath) {
  $existingEntries = $machinePath -split ";" | Where-Object { $_ -and $_.Trim() }
}

$seen = New-Object "System.Collections.Generic.HashSet[string]" ([StringComparer]::OrdinalIgnoreCase)
$nextEntries = New-Object "System.Collections.Generic.List[string]"

foreach ($entry in $pathEntries) {
  if ($seen.Add($entry)) {
    $nextEntries.Add($entry)
  }
}

foreach ($entry in $existingEntries) {
  if ($seen.Add($entry)) {
    $nextEntries.Add($entry)
  }
}

$environmentKey = "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment"
$nextPath = $nextEntries -join ";"
$missingPathEntries = @($pathEntries | Where-Object { $existingEntries -notcontains $_ })
if ($missingPathEntries.Count -gt 0) {
  [Environment]::SetEnvironmentVariable("Path", $nextPath, "Machine")
  "[$(Get-Date -Format o)] machine Path updated" | Out-File -FilePath $logPath -Encoding utf8 -Append
}
else {
  "[$(Get-Date -Format o)] machine Path already contains required entries" | Out-File -FilePath $logPath -Encoding utf8 -Append
}

$machineVariables = @{
  "COREPACK_HOME" = Join-Path $root "corepack"
  "PNPM_HOME" = Join-Path $root "pnpm"
  "PLAYWRIGHT_BROWSERS_PATH" = Join-Path $root "playwright"
  "ELECTRON_CACHE" = Join-Path $root "electron-cache"
  "ELECTRON_BUILDER_CACHE" = Join-Path $root "electron-builder-cache"
  "CARGO_HOME" = Join-Path $root "rust\cargo"
  "RUSTUP_HOME" = Join-Path $root "rust\rustup"
  "npm_config_cache" = Join-Path $root "npm-cache"
  "npm_config_prefix" = Join-Path $root "node"
}

foreach ($name in $machineVariables.Keys) {
  & reg.exe add $environmentKey /v $name /t REG_SZ /d $machineVariables[$name] /f | Out-Null
  "[$(Get-Date -Format o)] machine variable updated: $name=$($machineVariables[$name])" | Out-File -FilePath $logPath -Encoding utf8 -Append
}

$signature = @"
using System;
using System.Runtime.InteropServices;

public static class EnvironmentBroadcaster {
  [DllImport("user32.dll", SetLastError = true, CharSet = CharSet.Auto)]
  public static extern IntPtr SendMessageTimeout(
    IntPtr hWnd,
    uint Msg,
    UIntPtr wParam,
    string lParam,
    uint fuFlags,
    uint uTimeout,
    out UIntPtr lpdwResult);
}
"@

Add-Type -TypeDefinition $signature -ErrorAction SilentlyContinue
$result = [UIntPtr]::Zero
[EnvironmentBroadcaster]::SendMessageTimeout(
  [IntPtr]0xffff,
  0x001A,
  [UIntPtr]::Zero,
  "Environment",
  0x0002,
  5000,
  [ref]$result
) | Out-Null

Write-Host "System-level AgentGo development environment configured under $root"
Write-Host "Open a new terminal and run: node -v; pnpm --version; git --version; gh --version; sqlite3 --version; rustc --version; cargo --version"
"[$(Get-Date -Format o)] configure-system-env.ps1 completed" | Out-File -FilePath $logPath -Encoding utf8 -Append
