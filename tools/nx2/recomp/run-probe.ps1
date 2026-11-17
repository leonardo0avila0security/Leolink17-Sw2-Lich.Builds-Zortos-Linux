# Runs Orbitals in Lichii with the GDB stub and lichii-probe.exe attached: the real values the game's
# SDK returns where orbitals-recomp substitutes its own (frame history, the RenderThread and flip
# tracker waits). See README.md, "Probing".
# Usage (PowerShell, from the unpacked build folder):
#   .\recomp\run-probe.ps1 -Game "C:\...\exefs\main" [-Seconds 180] [-Spec .\recomp\orbitals_blocker.json]
# Play normally: the probe stops after -Seconds or when every probe reached its hit limit; the game
# keeps running afterwards. Close the game, then send out-probe\probes_summary.txt (a text file).
param(
    [Parameter(Mandatory = $true)][string]$Game,
    [string]$Out = ".\out-probe",
    [string]$Cli = ".\eden-cli.exe",
    [int]$Port = 6543,
    [int]$Seconds = 180,
    [string]$Spec = "",
    [string]$GuiConfig = "$env:APPDATA\lichii\config\qt-config.ini"
)
$ErrorActionPreference = "Stop"
$Here = Split-Path -Parent $MyInvocation.MyCommand.Path
if (-not $Spec) { $Spec = Join-Path $Here "orbitals_blocker.json" }
if (-not (Test-Path -LiteralPath $Game -PathType Leaf)) { throw "Game file not found: $Game" }
$Probe = Join-Path $Here "lichii-probe.exe"
if (-not (Test-Path $Probe)) { throw "lichii-probe.exe missing next to this script" }
New-Item -ItemType Directory -Force $Out | Out-Null
$Out = (Resolve-Path $Out).Path
$exefs = Split-Path -Parent $Game

$env:EDEN_NX2_IPC_TRACE = "1"
$cliArgs = @("-d", "$Port", "-g", "`"$Game`"")
$cliCfg = $null
if (Test-Path $GuiConfig) {
    $cliCfg = Join-Path $env:TEMP "lichii-cli-config.ini"   # holds tokens: never put it in $Out
    Copy-Item $GuiConfig $cliCfg -Force
    $cliArgs = @("-c", "`"$cliCfg`"") + $cliArgs
}
Remove-Item "$Out\*" -Force -ErrorAction SilentlyContinue
# Lichii writes its log to its own folder; the console copy can be empty when redirected.
$cliDir = Split-Path -Parent (Resolve-Path $Cli)
$appLogs = @("$cliDir\user\log\eden_log.txt", "$env:APPDATA\lichii\log\eden_log.txt")
$since = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds() - 2
$emu = Start-Process -FilePath (Resolve-Path $Cli) -ArgumentList $cliArgs -PassThru -NoNewWindow `
    -RedirectStandardError "$Out\eden_log.txt" -RedirectStandardOutput "$Out\eden_stdout.txt"
Write-Host "Lichii started (pid $($emu.Id)). The probe attaches once the game has loaded."

$logArgs = @("--log", "$Out\eden_log.txt", "--log", "$Out\eden_stdout.txt")
foreach ($l in $appLogs) { $logArgs += @("--log", $l) }
& $Probe --port $Port @logArgs --since $since --exefs $exefs `
    --spec $Spec --out "$Out\probes.jsonl" --summary "$Out\probes_summary.txt" --seconds $Seconds

Write-Host "`nProbing finished. Keep playing or close the game."
$emu.WaitForExit()
if ($cliCfg) { Remove-Item $cliCfg -Force -ErrorAction SilentlyContinue }
foreach ($l in $appLogs) {
    if ((Test-Path $l) -and ((Get-Item $l).LastWriteTimeUtc -gt [DateTimeOffset]::FromUnixTimeSeconds($since).UtcDateTime)) {
        Copy-Item $l "$Out\lichii_log.txt" -Force
        Write-Host "Lichii's log copied to $Out\lichii_log.txt"
    }
}
Write-Host "Send this file: $Out\probes_summary.txt"
Write-Host "(and $Out\probes.jsonl through the analysis-data release if asked)"
