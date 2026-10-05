param([switch]$PullModel)
$ErrorActionPreference = 'Stop'
$ecdatRoot = Split-Path -Parent $PSScriptRoot
$ecdatState = Join-Path $ecdatRoot '.ecdat'
$ecdatModel = 'qwen3:1.7b'
if (Test-Path -LiteralPath (Join-Path $ecdatRoot '.env')) {
    foreach ($ecdatLine in Get-Content -LiteralPath (Join-Path $ecdatRoot '.env')) {
        if ($ecdatLine -match '^ECDAT_AI_MODEL=(.+)$') { $ecdatModel = $matches[1] }
        if ($ecdatLine -match '^ECDAT_AI_PROVIDER=(.+)$' -and $matches[1] -ne 'ollama') {
            throw 'This installation selects a cloud provider. Local Ollama startup is unnecessary.'
        }
    }
}
$ecdatOllama = Join-Path $ecdatState 'tools/ollama/ollama.exe'
if (!(Test-Path -LiteralPath $ecdatOllama)) {
    $ecdatInstalled = Get-Command ollama -ErrorAction SilentlyContinue
    if (!$ecdatInstalled) { throw 'Install Ollama from https://ollama.com/download/windows, then rerun this script.' }
    $ecdatOllama = $ecdatInstalled.Source
}
$env:OLLAMA_HOST = 'http://127.0.0.1:11434'
$env:OLLAMA_MODELS = Join-Path $ecdatState 'models'
$env:OLLAMA_NUM_PARALLEL = '1'
$env:OLLAMA_MAX_LOADED_MODELS = '1'
$env:OLLAMA_NO_CLOUD = '1'
New-Item -ItemType Directory -Force (Join-Path $ecdatState 'logs') | Out-Null
$ecdatTags = $null
try { $ecdatTags = Invoke-RestMethod 'http://127.0.0.1:11434/api/tags' -TimeoutSec 2 } catch {}
if (!$ecdatTags) {
    $ecdatServer = Start-Process -FilePath $ecdatOllama -ArgumentList 'serve' -WorkingDirectory $ecdatRoot -WindowStyle Hidden -PassThru -RedirectStandardOutput (Join-Path $ecdatState 'logs/ollama.log') -RedirectStandardError (Join-Path $ecdatState 'logs/ollama-error.log')
    @{pid=$ecdatServer.Id; executable=$ecdatOllama} | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $ecdatState 'ollama-process.json')
    for ($ecdatAttempt=0; $ecdatAttempt -lt 20; $ecdatAttempt++) {
        try { $ecdatTags = Invoke-RestMethod 'http://127.0.0.1:11434/api/tags' -TimeoutSec 2; break } catch { Start-Sleep -Milliseconds 500 }
    }
    if (!$ecdatTags) { throw 'Ollama did not become ready. Inspect .ecdat/logs/ollama-error.log.' }
}
if ($ecdatModel -notin @($ecdatTags.models.name)) {
    if (!$PullModel) { throw "Ollama is ready but $ecdatModel is missing. Rerun with -PullModel to download it." }
    & $ecdatOllama pull $ecdatModel
    if ($LASTEXITCODE -ne 0) { throw 'Model download failed.' }
}
Write-Output "Local AI ready with $ecdatModel. The model loads on the first request and unloads afterward."
