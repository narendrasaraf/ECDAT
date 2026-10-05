$ErrorActionPreference='Stop'
$ecdatRoot=Split-Path -Parent $PSScriptRoot
$ecdatProcessFile=Join-Path $ecdatRoot '.ecdat/processes.json'
if (!(Test-Path -LiteralPath $ecdatProcessFile)) { return }
$ecdatPids=Get-Content -LiteralPath $ecdatProcessFile | ConvertFrom-Json
$ecdatPython=Join-Path $ecdatRoot '.venv\Scripts\python.exe'
foreach($ecdatPid in @($ecdatPids.api,$ecdatPids.worker)) {
    $ecdatProcess=Get-CimInstance Win32_Process -Filter "ProcessId=$ecdatPid"
    if ($ecdatProcess -and $ecdatProcess.ExecutablePath -eq $ecdatPython) {
        # Windows venv launchers have a child interpreter; stop only this verified tree.
        Get-CimInstance Win32_Process -Filter "ParentProcessId=$ecdatPid" | Where-Object {$_.Name -eq 'python.exe'} | ForEach-Object {Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue}
        Stop-Process -Id $ecdatPid -Force -ErrorAction SilentlyContinue
    }
}
Write-Output 'ECDAT API and its worker stopped.'
