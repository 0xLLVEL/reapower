# TablePlus License Patch - installer
#
# Places the patch engine in C:\ProgramData\TablePlusPatch, patches the currently
# installed TablePlus, then registers a scheduled task so the patch is re-applied
# automatically after a TablePlus update (WinSparkle overwrites the exe).
#
# -Uninstall : remove the task + restore the original exe from backup.

[CmdletBinding()]
param(
    [string]$InstallDir = "C:\ProgramData\TablePlusPatch",
    [string]$Target = "C:\Program Files\TablePlus\TablePlus.exe",
    [int]$IntervalMinutes = 10,
    [switch]$Uninstall,
    [switch]$NoTask
)

$ErrorActionPreference = "Stop"
$taskName = "TablePlus License Patch"

function Assert-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $p = New-Object Security.Principal.WindowsPrincipal($id)
    if (-not $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Host "  [x] this script must run as admin" -ForegroundColor Red
        exit 1
    }
}
Assert-Admin

function Remove-Task([string]$name) {
    $t = Get-ScheduledTask -TaskName $name -ErrorAction SilentlyContinue
    if ($t) {
        Unregister-ScheduledTask -TaskName $name -Confirm:$false
        Write-Host "  task removed: $name" -ForegroundColor Green
    } else {
        Write-Host "  no such task: $name" -ForegroundColor DarkGray
    }
}

# ------------------------------------------------------------------ uninstall
if ($Uninstall) {
    Write-Host ""
    Write-Host "TablePlus patch - uninstall" -ForegroundColor Cyan
    Remove-Task $taskName

    $bak = "$Target.bak"
    $bak2 = Join-Path $InstallDir "backup\TablePlus.exe.orig"
    $src = $null
    if (Test-Path -LiteralPath $bak) { $src = $bak }
    elseif (Test-Path -LiteralPath $bak2) { $src = $bak2 }

    if (Get-Process -Name TablePlus -ErrorAction SilentlyContinue) {
        Write-Host "  close TablePlus first, then run uninstall again" -ForegroundColor Yellow
        exit 3
    }
    if ($src) {
        Copy-Item -LiteralPath $src -Destination $Target -Force
        Write-Host ("  exe restored from " + $src) -ForegroundColor Green
        Write-Host ("  SHA256 = " + (Get-FileHash -LiteralPath $Target -Algorithm SHA256).Hash)
    } else {
        Write-Host "  no exe backup - skipping restore" -ForegroundColor Yellow
    }
    exit 0
}

# ------------------------------------------------------------------ install
Write-Host ""
Write-Host "TablePlus patch - install" -ForegroundColor Cyan
Write-Host ("  target : " + $Target)
Write-Host ("  dir    : " + $InstallDir)

if (-not (Test-Path -LiteralPath $Target)) { Write-Host "  [x] TablePlus.exe not found" -ForegroundColor Red; exit 2 }

New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
New-Item -ItemType Directory -Force -Path (Join-Path $InstallDir "backup") | Out-Null

foreach ($f in @("TablePlusPatch.ps1", "TPCli.cs")) {
    Copy-Item -LiteralPath (Join-Path $PSScriptRoot $f) -Destination $InstallDir -Force
    Write-Host ("  installed: " + (Join-Path $InstallDir $f)) -ForegroundColor Green
}

# clean backup (once only)
$bak2 = Join-Path $InstallDir "backup\TablePlus.exe.orig"
$curSha = (Get-FileHash -LiteralPath $Target -Algorithm SHA256).Hash
if (-not (Test-Path -LiteralPath $bak2)) {
    Copy-Item -LiteralPath $Target -Destination $bak2 -Force
    Write-Host ("  backup -> " + $bak2) -ForegroundColor Green
} else {
    Write-Host ("  backup already exists: " + $bak2) -ForegroundColor DarkGray
}

# apply now
& (Join-Path $InstallDir "TablePlusPatch.ps1") -Target $Target -BackupDir $InstallDir -WaitForExitSeconds 120

# ------------------------------------------------------------------ task
if (-not $NoTask) {
    Remove-Task $taskName

    $arg = '-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "' +
           (Join-Path $InstallDir "TablePlusPatch.ps1") + '" -Target "' + $Target +
           '" -BackupDir "' + $InstallDir + '" -WaitForExitSeconds 120'

    $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument $arg
    $tLogon = New-ScheduledTaskTrigger -AtLogOn
    $tPoll  = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(5) `
                -RepetitionInterval (New-TimeSpan -Minutes $IntervalMinutes) `
                -RepetitionDuration (New-TimeSpan -Days 3650)
    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
                -StartWhenAvailable -MultipleInstances IgnoreNew `
                -ExecutionTimeLimit (New-TimeSpan -Minutes 15)
    $principal = New-ScheduledTaskPrincipal -UserId "$env:USERDOMAIN\$env:USERNAME" `
                -LogonType Interactive -RunLevel Highest

    Register-ScheduledTask -TaskName $taskName -Action $action -Trigger @($tLogon, $tPoll) `
        -Settings $settings -Principal $principal `
        -Description "Re-applies the TablePlus license gate patch after an update." | Out-Null
    Write-Host ("  task registered: " + $taskName + "  (logon + every $IntervalMinutes min, RunLevel Highest)") -ForegroundColor Green
}

Write-Host ""
Write-Host ("  SHA256 after = " + (Get-FileHash -LiteralPath $Target -Algorithm SHA256).Hash)
Write-Host "  done." -ForegroundColor Green
