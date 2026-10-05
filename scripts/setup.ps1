$ErrorActionPreference = 'Stop'
$ecdatRoot = Split-Path -Parent $PSScriptRoot
Set-Location -LiteralPath $ecdatRoot
$ecdatBundledNode = Join-Path $env:USERPROFILE '.cache/codex-runtimes/codex-primary-runtime/dependencies/node/bin'
if (Test-Path -LiteralPath (Join-Path $ecdatBundledNode 'node.exe')) { $env:PATH = "$ecdatBundledNode;$env:PATH" }
$ecdatNodeVersion = & node -p 'parseInt(process.versions.node)'
if ($LASTEXITCODE -ne 0 -or [int]$ecdatNodeVersion -lt 24) { throw 'Install Node.js 24 or newer for hybrid TLS and ML-DSA support.' }
if (Test-Path -LiteralPath '.venv') {
    $venvValid = $false
    try { & '.venv/Scripts/python.exe' --version *> $null; if ($LASTEXITCODE -eq 0) { $venvValid = $true } } catch {}
    if (!$venvValid) { Remove-Item -Recurse -Force '.venv' -ErrorAction SilentlyContinue }
}
if (!(Test-Path -LiteralPath '.venv/Scripts/python.exe')) { python -m venv .venv }
& '.venv/Scripts/python.exe' -m pip install -r requirements.lock
if ($LASTEXITCODE -ne 0) { throw 'Python dependency setup failed' }
Push-Location apps/web
try { npm.cmd ci; if ($LASTEXITCODE -ne 0) { throw 'Web dependency setup failed' }; npm.cmd run build; if ($LASTEXITCODE -ne 0) { throw 'Web build failed' } } finally { Pop-Location }
Push-Location packages/chain
try { npm.cmd ci; if ($LASTEXITCODE -ne 0) { throw 'Chain dependency setup failed' } } finally { Pop-Location }
if (!(Test-Path -LiteralPath '.env')) { Copy-Item -LiteralPath '.env.example' -Destination '.env' }
Write-Output 'Setup complete. See README.md for native, isolated and AI profiles.'
