# Internet Download Manager License Patch - installer (manual mode)
#
# Places the patch engine in C:\ProgramData\IdmPatch, backs up the current
# IDMan.exe, then patches the installed build. Manual mode: no scheduled task,
# no watcher - after an IDM update, re-run patch-now.cmd (or this installer).
#
# -Uninstall : restore the original IDMan.exe from the pristine backup.

[CmdletBinding()]
param(
    [string]$InstallDir = "C:\ProgramData\IdmPatch",
    [string]$Target,
    [int]$WaitForExitSeconds = 60,
    [switch]$Uninstall
)

$ErrorActionPreference = "Stop"

if (-not $Target) {
    $Target = Join-Path ${env:ProgramFiles(x86)} 'Internet Download Manager\IDMan.exe'
}

function Assert-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $p = New-Object Security.Principal.WindowsPrincipal($id)
    if (-not $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Host "  [x] this script must run as admin" -ForegroundColor Red
        exit 1
    }
}
Assert-Admin

$engine = Join-Path $InstallDir "IdmPatch.ps1"
if (-not (Test-Path -LiteralPath $engine)) { $engine = Join-Path $PSScriptRoot "IdmPatch.ps1" }
$cli = Join-Path $InstallDir "IdmCli.cs"
if (-not (Test-Path -LiteralPath $cli)) { $cli = Join-Path $PSScriptRoot "IdmCli.cs" }

if (-not (Test-Path -LiteralPath $engine)) {
    Write-Host "  [x] engine not found: $engine" -ForegroundColor Red
    exit 2
}

New-Item -ItemType Directory -Path $InstallDir -Force -ErrorAction SilentlyContinue | Out-Null

# keep the helper beside the engine - the engine resolves IdmCli.cs relative to itself
if ((Resolve-Path -LiteralPath $engine).Path -ne (Join-Path $InstallDir "IdmPatch.ps1")) {
    Copy-Item -LiteralPath $engine -Destination (Join-Path $InstallDir "IdmPatch.ps1") -Force
    $engine = Join-Path $InstallDir "IdmPatch.ps1"
}
if ($cli -and (Test-Path -LiteralPath $cli)) {
    if ((Resolve-Path -LiteralPath $cli).Path -ne (Join-Path $InstallDir "IdmCli.cs")) {
        Copy-Item -LiteralPath $cli -Destination (Join-Path $InstallDir "IdmCli.cs") -Force
        $cli = Join-Path $InstallDir "IdmCli.cs"
    }
}

if ($Uninstall) {
    Write-Host "=== Uninstall: restoring original IDMan.exe ==="
    & powershell -NoProfile -ExecutionPolicy Bypass -File $engine -Restore -Target $Target -WaitForExitSeconds $WaitForExitSeconds
    $code = $LASTEXITCODE
    if ($code -eq 0) {
        Write-Host ""
        Write-Host "  [ok] original IDMan.exe restored" -ForegroundColor Green
        Remove-Item -LiteralPath $InstallDir -Recurse -Force -ErrorAction SilentlyContinue
        exit 0
    }
    Write-Host "  [x] restore failed (exit $code)" -ForegroundColor Red
    exit $code
}

Write-Host "=== Install IDM License Patch ==="
Write-Host "  engine : $InstallDir"
Write-Host "  target : $Target"
Write-Host ""
& powershell -NoProfile -ExecutionPolicy Bypass -File $engine -Target $Target -WaitForExitSeconds $WaitForExitSeconds
$code = $LASTEXITCODE

Write-Host ""
switch ($code) {
    0 { Write-Host "  [ok] patched - launch Internet Download Manager" -ForegroundColor Green }
    1 { Write-Host "  [x] not elevated" -ForegroundColor Red }
    2 { Write-Host "  [x] target missing or not an i386 PE" -ForegroundColor Red }
    3 { Write-Host "  [x] IDMan.exe locked - close IDM and re-run patch-now.cmd" -ForegroundColor Yellow }
    4 { Write-Host "  [x] this IDM build is not recognised - nothing written" -ForegroundColor Yellow }
    5 { Write-Host "  [x] verify/swap failed - file left on its original build" -ForegroundColor Red }
    default { Write-Host "  [x] engine exited with $code" -ForegroundColor Red }
}
exit $code
