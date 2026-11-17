# Windows runner: starts a game with every tracer on, analyses the result and writes two zips.
# Usage (PowerShell, from the unpacked build folder):
#   .\recomp\run-analysis.ps1 -Game "D:\games\orbitals\exefs\main" [-Out .\out]
# Play, then close the game. Send out\lichii-logs-summary.zip first; it is a few MB.
param(
    [Parameter(Mandatory = $true)][string]$Game,
    [string]$Out = ".\out",
    [string]$Cli = ".\eden-cli.exe",
    [string]$Python = "python"
)
$ErrorActionPreference = "Stop"
$Here = Split-Path -Parent $MyInvocation.MyCommand.Path
New-Item -ItemType Directory -Force $Out | Out-Null
$Out = (Resolve-Path $Out).Path
$env:LICHII_BLOCK_TRACE = "$Out\blocks.jsonl"
$env:EDEN_NX2_SVC_TRACE = "1"
$env:EDEN_NX2_IPC_TRACE = "1"
$env:EDEN_NX2_IPC_SUMMARY = "1"
$env:EDEN_NX2_MEM_TRACE = "1"
$env:EDEN_NX2_FS_READ_TRACE = "1"
$env:EDEN_NX2_DEBUG_SERVER = "127.0.0.1:6545"
$env:EDEN_NX2_DEBUG_DIR = "$Out\debug"
Set-Content -Path $env:LICHII_BLOCK_TRACE -Value "" -NoNewline
& $Cli --filter "*:Info Loader:Debug Kernel_SVC:Info Service:Info" -g $Game 2>&1 | Tee-Object -FilePath "$Out\eden_log.txt"
$exefs = Split-Path -Parent $Game
& $Python "$Here\analyze_trace.py" --blocks $env:LICHII_BLOCK_TRACE --log "$Out\eden_log.txt" --exefs $exefs --out "$Out\analysis"
& $Python "$Here\make_bundle.py" $Out
Write-Host "`nSend this file: $Out\lichii-logs-summary.zip"
