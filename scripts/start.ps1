param([switch]$Isolated, [switch]$NoWorker, [switch]$StartAI)
$ErrorActionPreference = 'Stop'
$ecdatRoot = Split-Path -Parent $PSScriptRoot
Set-Location -LiteralPath $ecdatRoot
if (!(Test-Path -LiteralPath '.venv/Scripts/python.exe')) { throw 'Run scripts/setup.ps1 first.' }
if (Get-NetTCPConnection -LocalPort 8000 -State Listen -ErrorAction SilentlyContinue) {
    throw 'Port 8000 is already in use. If ECDAT is running, open it or run scripts/stop.ps1 before restarting.'
}
if (Test-Path -LiteralPath '.env') {
    foreach ($ecdatLine in Get-Content -LiteralPath '.env') {
        if ($ecdatLine -match '^([A-Za-z_][A-Za-z_0-9]*)=(.*)$') {
            [Environment]::SetEnvironmentVariable($matches[1], $matches[2], 'Process')
        }
    }
}
$env:PYTHONPATH = Join-Path $ecdatRoot 'services/api'
$env:ECDAT_DEMO = '1'
$env:ECDAT_WORKER = '0'
if ($Isolated) { $env:ECDAT_PROFILE = 'isolated' }
if ($env:ECDAT_DATABASE_URL -match '@127\.0\.0\.1:5433/ecdat(?:\?|$)') {
    # Only start the service for the supplied local compose endpoint.
    & docker compose up -d postgres
    if ($LASTEXITCODE -ne 0) { throw 'Start Docker Desktop, then rerun. Local PostgreSQL could not start.' }
    $ecdatDatabaseReady = $false
    for ($ecdatAttempt=0; $ecdatAttempt -lt 20; $ecdatAttempt++) {
        & docker compose exec -T postgres pg_isready -U ecdat -d ecdat *> $null
        if ($LASTEXITCODE -eq 0) { $ecdatDatabaseReady=$true; break }
        Start-Sleep -Milliseconds 500
    }
    if (!$ecdatDatabaseReady) { throw 'Local PostgreSQL is not ready. Inspect docker compose logs postgres.' }
}
$env:PGCONNECT_TIMEOUT = '10'
New-Item -ItemType Directory -Force '.ecdat/logs' | Out-Null
$ecdatPython = Join-Path $ecdatRoot '.venv/Scripts/python.exe'
& $ecdatPython -m alembic upgrade head
if ($LASTEXITCODE -ne 0) { throw 'Database initialization failed' }
$ecdatApi = Start-Process -FilePath $ecdatPython -ArgumentList '-m','uvicorn','ecdat.main:app','--host','127.0.0.1','--port','8000' -WorkingDirectory $ecdatRoot -WindowStyle Hidden -PassThru -RedirectStandardOutput '.ecdat/logs/api.log' -RedirectStandardError '.ecdat/logs/api-error.log'
$ecdatPids = @{api=$ecdatApi.Id}
if (!$NoWorker) {
    $ecdatWorker = Start-Process -FilePath $ecdatPython -ArgumentList '-m','ecdat.worker' -WorkingDirectory $ecdatRoot -WindowStyle Hidden -PassThru -RedirectStandardOutput '.ecdat/logs/worker.log' -RedirectStandardError '.ecdat/logs/worker-error.log'
    $ecdatPids.worker = $ecdatWorker.Id
}
$ecdatPids | ConvertTo-Json | Set-Content -LiteralPath '.ecdat/processes.json'
$ecdatReady = $false
for ($ecdatAttempt=0; $ecdatAttempt -lt 30; $ecdatAttempt++) {
    try { $null = Invoke-RestMethod 'http://127.0.0.1:8000/api/health' -TimeoutSec 2; $ecdatReady=$true; break } catch { Start-Sleep -Milliseconds 500 }
}
if (!$ecdatReady) { throw 'ECDAT did not become ready. Inspect .ecdat/logs/api-error.log.' }
if ($StartAI) { & (Join-Path $PSScriptRoot 'start-ai.ps1') }
Write-Output 'ECDAT ready at http://127.0.0.1:8000. Logs are in .ecdat/logs.'
