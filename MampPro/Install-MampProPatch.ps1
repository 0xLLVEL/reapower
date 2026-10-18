# MAMP PRO License Patch - installer (manual mode)
#
# Places the patch engine in C:\ProgramData\MampProPatch, backs up the current
# MAMPPRO.dll, then patches the installed build. Manual mode: no scheduled task,
# no watcher - after a MAMP update, re-run patch-now.cmd (or this installer).
#
# -Uninstall : restore the original MAMPPRO.dll from the newest backup.

[CmdletBinding()]
param(
    [string]$InstallDir = "C:\ProgramData\MampProPatch",
    [string]$Target     = "C:\MAMPPRO\net\MAMPPRO.dll",
    [int]$WaitForExitSeconds = 120,
    [switch]$Uninstall
)

$ErrorActionPreference = "Stop"

function Assert-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $p = New-Object Security.Principal.WindowsPrincipal($id)
    if (-not $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Host "  [x] this script must run as admin" -ForegroundColor Red
        exit 1
    }
}
Assert-Admin

$engine = Join-Path $InstallDir "MampProPatch.ps1"
if (-not (Test-Path -LiteralPath $engine)) { $engine = Join-Path $PSScriptRoot "MampProPatch.ps1" }

# ------------------------------------------------------------------ uninstall
if ($Uninstall) {
    Write-Host ""
    Write-Host "MAMP PRO patch - uninstall" -ForegroundColor Cyan
    & $engine -Target $Target -BackupDir $InstallDir -Restore
    exit $LASTEXITCODE
}

# ------------------------------------------------------------------ install
Write-Host ""
Write-Host "MAMP PRO patch - install" -ForegroundColor Cyan
Write-Host ("  target : " + $Target)
Write-Host ("  dir    : " + $InstallDir)

if (-not (Test-Path -LiteralPath $Target)) { Write-Host "  [x] MAMPPRO.dll not found" -ForegroundColor Red; exit 2 }

New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
New-Item -ItemType Directory -Force -Path (Join-Path $InstallDir "backup") | Out-Null

foreach ($f in @("MampProPatch.ps1", "MampCli.cs")) {
    Copy-Item -LiteralPath (Join-Path $PSScriptRoot $f) -Destination $InstallDir -Force
    Write-Host ("  installed: " + (Join-Path $InstallDir $f)) -ForegroundColor Green
}

# first-run backup: only once, so the pristine build of THIS version is kept
$bak = Join-Path $InstallDir "backup\MAMPPRO.dll.orig"
if (-not (Test-Path -LiteralPath $bak)) {
    Copy-Item -LiteralPath $Target -Destination $bak -Force
    Write-Host ("  backup -> " + $bak) -ForegroundColor Green
} else {
    Write-Host ("  backup already exists: " + $bak) -ForegroundColor DarkGray
}

# apply now (the engine refreshes backup\MAMPPRO.dll.orig itself when it sees a vendor build)
& (Join-Path $InstallDir "MampProPatch.ps1") -Target $Target -BackupDir $InstallDir -WaitForExitSeconds $WaitForExitSeconds
$rc = $LASTEXITCODE

Write-Host ""
if ($rc -eq 0) {
    Write-Host ("  SHA256 = " + (Get-FileHash -LiteralPath $Target -Algorithm SHA256).Hash) -ForegroundColor DarkGray
    Write-Host "  done." -ForegroundColor Green
} elseif ($rc -eq 3) {
    Write-Host "  MAMP PRO is running - exit it from the tray, then run install.cmd again" -ForegroundColor Yellow
} elseif ($rc -eq 4) {
    Write-Host "  this MAMP build is not recognised - nothing was written (see -DryRun)" -ForegroundColor Yellow
}
exit $rc
