# TablePlus License Patch - installer
#
# Places the patch engine and its watcher in C:\ProgramData\TablePlusPatch, patches
# the currently installed TablePlus, then registers a scheduled task that starts
# the watcher once per session.
#
# The old task polled every 10 minutes: 144 powershell births and ~21 GB of reads a
# day, all to conclude "nothing changed". The task now starts an event-driven
# watcher instead, which runs the engine only when TablePlus is actually opened.
# See TablePlusPatchWatch.ps1.
#
# -Uninstall : stop the watcher, remove the task + restore the original exe from backup.

[CmdletBinding()]
param(
    [string]$InstallDir    = "C:\ProgramData\TablePlusPatch",
    [string]$Target        = "C:\Program Files\TablePlus\TablePlus.exe",
    [int]$FallbackHours    = 6,
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

function Stop-Watcher {
    # Match on the command line, not the image name: the watcher is a plain
    # powershell.exe and killing every powershell.exe would be rude.
    $killed = @()
    Get-CimInstance Win32_Process -Filter "Name='powershell.exe'" -ErrorAction SilentlyContinue |
        Where-Object { $_.ProcessId -ne $PID -and $_.CommandLine -like "*TablePlusPatchWatch.ps1*" } |
        ForEach-Object {
            try {
                Invoke-CimMethod -InputObject $_ -MethodName Terminate | Out-Null
                $killed += $_.ProcessId
            } catch {
                Write-Host ("  could not stop watcher pid " + $_.ProcessId + ": " + $_.Exception.Message) -ForegroundColor Yellow
            }
        }
    if ($killed.Count) { Write-Host ("  watcher stopped (pid " + ($killed -join ", ") + ")") -ForegroundColor Green }
    else               { Write-Host  "  watcher not running" -ForegroundColor DarkGray }
}

# ------------------------------------------------------------------ uninstall
if ($Uninstall) {
    Write-Host ""
    Write-Host "TablePlus patch - uninstall" -ForegroundColor Cyan
    Stop-Watcher
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

# Stop the previous watcher before overwriting the script it is running.
Stop-Watcher

foreach ($f in @("TablePlusPatch.ps1", "TPCli.cs", "TablePlusPatchWatch.ps1")) {
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

    $watch = Join-Path $InstallDir "TablePlusPatchWatch.ps1"
    $ps    = Join-Path $env:SystemRoot "System32\WindowsPowerShell\v1.0\powershell.exe"
    $arg   = '-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "' + $watch + '" -Quiet'

    $action = New-ScheduledTaskAction -Execute $ps -Argument $arg

    $tLogon = New-ScheduledTaskTrigger -AtLogOn
    # First fire a full $FallbackHours away, not a couple of minutes: the installer
    # starts the watcher itself, so a near-term start only lands on a live watcher,
    # gets refused by IgnoreNew, and parks 0x800710E0 in LastTaskResult beside a
    # healthy task.
    $tNet   = New-ScheduledTaskTrigger -Once -At ((Get-Date).AddHours($FallbackHours)) `
                -RepetitionInterval (New-TimeSpan -Hours $FallbackHours) `
                -RepetitionDuration (New-TimeSpan -Days 3650)

    try {
        $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
                    -StartWhenAvailable -MultipleInstances IgnoreNew `
                    -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)
    } catch {
        $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
                    -StartWhenAvailable -MultipleInstances IgnoreNew
    }
    # The watcher is meant to live for the whole session; the default PT72H
    # would kill it every three days.
    $settings.ExecutionTimeLimit = "PT0S"

    $principal = New-ScheduledTaskPrincipal -UserId "$env:USERDOMAIN\$env:USERNAME" `
                -LogonType Interactive -RunLevel Highest

    Register-ScheduledTask -TaskName $taskName -Action $action -Trigger @($tLogon, $tNet) `
        -Settings $settings -Principal $principal `
        -Description "Runs the TablePlus patch engine when TablePlus.exe starts after an update (event-driven, no polling)." | Out-Null
    Write-Host ("  task registered: " + $taskName + "  (logon + " + $FallbackHours + "h fallback, RunLevel Highest)") -ForegroundColor Green

    Start-ScheduledTask -TaskName $taskName
    Start-Sleep -Seconds 4
    $watchProc = @(Get-CimInstance Win32_Process -Filter "Name='powershell.exe'" -ErrorAction SilentlyContinue |
        Where-Object { $_.CommandLine -like "*TablePlusPatchWatch.ps1*" })
    if ($watchProc.Count) {
        Write-Host ("  watcher running: pid " + (($watchProc | ForEach-Object { $_.ProcessId }) -join ", ")) -ForegroundColor Green
    } else {
        Write-Host "  watcher not up yet - check the log" -ForegroundColor Yellow
    }
    Write-Host ("  log: " + (Join-Path $InstallDir "watch.log")) -ForegroundColor DarkGray
}

Write-Host ""
Write-Host ("  SHA256 after = " + (Get-FileHash -LiteralPath $Target -Algorithm SHA256).Hash)
Write-Host "  done." -ForegroundColor Green
