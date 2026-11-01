param([Parameter(Mandatory=$true)][string]$SpecFile)
# GitNexus cross-shell launcher (2026-11-01).
# Symptom: spawning node.exe directly from WSL makes the child cwd an UNC path
#   (\\wsl.localhost\...), so gitnexus scans via UNC and hangs (4 min, 0% CPU, no output).
# Fix: run through PowerShell with a Windows cwd (same command returns in ~4.7s).
# Args channel: a JSON spec file (-SpecFile <C:\...\spec.json>) because PS 5.1 treats
#   `--json` as a parameter name, and custom env vars are dropped across WSL->Windows interop.
# NOTE: keep this file ASCII-only - PS 5.1 reads BOM-less UTF-8 as ANSI and chokes on CJK.
$ErrorActionPreference = "Stop"
$spec = Get-Content -Raw -Encoding UTF8 $SpecFile | ConvertFrom-Json
if ($spec.env) {
  foreach ($p in $spec.env.PSObject.Properties) {
    Set-Item -Path ("env:" + $p.Name) -Value ([string]$p.Value)
  }
}
Set-Location $spec.cwd
$nodeExe = $spec.node
$jsPath = $spec.js
$gxArgs = @()
foreach ($a in $spec.args) { $gxArgs += [string]$a }
& $nodeExe $jsPath @gxArgs
exit $LASTEXITCODE
