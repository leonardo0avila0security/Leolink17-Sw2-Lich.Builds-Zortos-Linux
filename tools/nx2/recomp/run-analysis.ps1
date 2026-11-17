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
$HavePython = $null -ne (Get-Command $Python -ErrorAction SilentlyContinue)
if ($HavePython) {
    $exefs = Split-Path -Parent $Game
    & $Python "$Here\analyze_trace.py" --blocks $env:LICHII_BLOCK_TRACE --log "$Out\eden_log.txt" --exefs $exefs --out "$Out\analysis"
    & $Python "$Here\make_bundle.py" $Out
    Write-Host "`nSend this file: $Out\lichii-logs-summary.zip"
    return
}

# No Python: build the digest in PowerShell and zip the raw files. The analysis is done later
# from lichii-logs-full.zip.
Write-Host "`nPython not found: writing the log digest and zip without the analysis step."
$lines = Get-Content "$Out\eden_log.txt" -ErrorAction SilentlyContinue
$digest = @("log lines: $($lines.Count)", "", "## Start of log")
$digest += ($lines | Select-Object -First 2000 | Select-String -Pattern 'Lichii Version|Booting game|loaded module|Vulkan|GPU|driver' | Select-Object -First 200 | ForEach-Object { $_.Line })
$digest += @("", "## Distinct warnings/errors (count, first occurrence)")
$groups = $lines | Where-Object { $_ -match 'error|warn|critical|fail|unimplemented|unknown|abort|crash|assert|fault|not supported|stub|invalid' } |
    Group-Object { ($_ -replace '0x[0-9a-fA-F]+|\d+', '#') } | Sort-Object Count -Descending | Select-Object -First 300
foreach ($g in $groups) { $digest += ("{0,7}  {1}" -f $g.Count, $g.Group[0].Substring(0, [Math]::Min(400, $g.Group[0].Length))) }
$digest += @("", "## Last 300 lines") + ($lines | Select-Object -Last 300)
Set-Content "$Out\log_digest.txt" $digest

Remove-Item "$Out\lichii-logs-*.zip" -ErrorAction SilentlyContinue
Compress-Archive -Path "$Out\log_digest.txt" -DestinationPath "$Out\lichii-logs-summary.zip"
$files = Get-ChildItem $Out -File | Where-Object { $_.Extension -ne ".zip" }
Compress-Archive -Path $files.FullName -DestinationPath "$Out\lichii-logs-full.zip" -CompressionLevel Optimal
foreach ($z in "lichii-logs-summary.zip", "lichii-logs-full.zip") {
    "{0}  {1:N1} MiB" -f "$Out\$z", ((Get-Item "$Out\$z").Length / 1MB) | Write-Host
}
Write-Host "`nSend lichii-logs-summary.zip first, then lichii-logs-full.zip if you can."
