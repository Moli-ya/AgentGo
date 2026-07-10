$ErrorActionPreference = "Stop"

$repositoryRoot = Split-Path -Parent $PSScriptRoot
$executable = Join-Path $repositoryRoot "release\win-unpacked\AgentGo.exe"

if (-not (Test-Path -LiteralPath $executable -PathType Leaf)) {
  throw "Packaged AgentGo executable was not found at $executable. Run pnpm pack:win first."
}

$stdoutPath = Join-Path $env:TEMP "agentgo-packaged-smoke-$PID.stdout.log"
$stderrPath = Join-Path $env:TEMP "agentgo-packaged-smoke-$PID.stderr.log"
$previousSmokeValue = $env:AGENTGO_SMOKE_TEST

try {
  $env:AGENTGO_SMOKE_TEST = "1"
  $process = Start-Process `
    -FilePath $executable `
    -PassThru `
    -Wait `
    -WindowStyle Hidden `
    -RedirectStandardOutput $stdoutPath `
    -RedirectStandardError $stderrPath

  $stdout = if (Test-Path -LiteralPath $stdoutPath) {
    Get-Content -Raw -LiteralPath $stdoutPath
  }
  else {
    ""
  }
  $stderr = if (Test-Path -LiteralPath $stderrPath) {
    Get-Content -Raw -LiteralPath $stderrPath
  }
  else {
    ""
  }

  if ($process.ExitCode -ne 0 -or $stdout -notmatch "AGENTGO_SMOKE_TEST_OK") {
    throw "Packaged AgentGo smoke test failed (exit $($process.ExitCode)). stdout: $stdout stderr: $stderr"
  }

  Write-Output "AGENTGO_PACKAGED_SMOKE_TEST_OK"
}
finally {
  if ($null -eq $previousSmokeValue) {
    Remove-Item Env:AGENTGO_SMOKE_TEST -ErrorAction SilentlyContinue
  }
  else {
    $env:AGENTGO_SMOKE_TEST = $previousSmokeValue
  }
  Remove-Item -LiteralPath $stdoutPath -Force -ErrorAction SilentlyContinue
  Remove-Item -LiteralPath $stderrPath -Force -ErrorAction SilentlyContinue
}
