$ErrorActionPreference = "Stop"

$previousSmokeValue = $env:AGENTGO_SMOKE_TEST

try {
  $env:AGENTGO_SMOKE_TEST = "1"
  & pnpm --filter "@agentgo/desktop" exec electron "out/main/index.js"

  if ($LASTEXITCODE -ne 0) {
    throw "AgentGo desktop smoke test failed with exit code $LASTEXITCODE."
  }
}
finally {
  if ($null -eq $previousSmokeValue) {
    Remove-Item Env:AGENTGO_SMOKE_TEST -ErrorAction SilentlyContinue
  }
  else {
    $env:AGENTGO_SMOKE_TEST = $previousSmokeValue
  }
}
