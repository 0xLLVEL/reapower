# Herd License Patch - installer
#
# Places the patch engine in C:\ProgramData\HerdPatch, bakes the shim into the
# Herd that is installed right now, then registers a scheduled task so the bake
# is re-applied automatically after a Herd update (electron-updater replaces
# resources\app.asar wholesale and the patch is gone by design).
#
#   Install-HerdPatch.ps1              install + patch now
#   Install-HerdPatch.ps1 -Force       install + re-bake even if already patched
#   Install-HerdPatch.ps1 -Uninstall   remove the task + restore the archive

[CmdletBinding()]
param(
    [string] $InstallDir      = 'C:\ProgramData\HerdPatch',
    [string] $HerdDir         = 'C:\Program Files\Herd',
    [int]    $IntervalMinutes = 10,
    [switch] $Uninstall,
    [switch] $NoTask,
    [switch] $Force
)

$ErrorActionPreference = 'Stop'
$taskName  = 'Herd License Patch'
$startMark = '/* ---- herd-pro ---- */'
$endMark   = '/* ---- /herd-pro ---- */'

$Asar   = Join-Path $HerdDir 'resources\app.asar'
$Backup = Join-Path $InstallDir 'backup\app.asar.orig'

function Assert-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $p  = New-Object Security.Principal.WindowsPrincipal($id)
    if (-not $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Host '  [x] this script must run as admin' -ForegroundColor Red
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

function Test-Patched([string]$path) {
    if (-not (Test-Path -LiteralPath $path)) { return $false }
    $fs = [System.IO.File]::Open($path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
    try {
        $take = [Math]::Min([int64]8192, $fs.Length)
        $buf  = New-Object byte[] ([int]$take)
        $fs.Position = $fs.Length - $take
        [void]$fs.Read($buf, 0, [int]$take)
        return ([System.Text.Encoding]::ASCII.GetString($buf).IndexOf($endMark) -ge 0)
    } finally { $fs.Dispose() }
}

# ------------------------------------------------------------------ uninstall
if ($Uninstall) {
    Write-Host ''
    Write-Host 'Herd license patch - uninstall' -ForegroundColor Cyan
    Remove-Task $taskName

    if (Test-Path -LiteralPath $Backup) {
        Get-Process -Name Herd -ErrorAction SilentlyContinue | ForEach-Object {
            try { $_.CloseMainWindow() | Out-Null } catch {}
        }
        Start-Sleep -Seconds 3
        Get-Process -Name Herd -ErrorAction SilentlyContinue | Stop-Process -Force
        Start-Sleep -Seconds 2
        Copy-Item -LiteralPath $Backup -Destination $Asar -Force
        Write-Host ("  archive restored from " + $Backup) -ForegroundColor Green
        Write-Host ("  SHA256 = " + (Get-FileHash -LiteralPath $Asar -Algorithm SHA256).Hash)
    } else {
        Write-Host '  no archive backup - skipping restore' -ForegroundColor Yellow
    }
    exit 0
}

# -------------------------------------------------------------------- install
Write-Host ''
Write-Host 'Herd license patch - install' -ForegroundColor Cyan
Write-Host ("  herd   : " + $HerdDir)
Write-Host ("  dir    : " + $InstallDir)

if (-not (Test-Path -LiteralPath $Asar)) { Write-Host "  [x] $Asar not found" -ForegroundColor Red; exit 2 }

New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
New-Item -ItemType Directory -Force -Path (Split-Path -Parent $Backup) | Out-Null

foreach ($f in @('HerdPatch.ps1', 'HerdShim.js')) {
    Copy-Item -LiteralPath (Join-Path $PSScriptRoot $f) -Destination $InstallDir -Force
    Write-Host ("  installed: " + (Join-Path $InstallDir $f)) -ForegroundColor Green
}

# The loader that gets baked has to come from a pristine archive. Prefer the
# in-place app.asar.orig (this tool's manual equivalent), otherwise take one
# from the live archive while it is still a vendor build.
if (-not (Test-Path -LiteralPath $Backup)) {
    $inPlace = Join-Path (Split-Path -Parent $Asar) 'app.asar.orig'
    if ((Test-Path -LiteralPath $inPlace) -and -not (Test-Patched $inPlace)) {
        Copy-Item -LiteralPath $inPlace -Destination $Backup -Force
        Write-Host ("  backup  : from in-place " + $inPlace) -ForegroundColor Green
    } elseif (-not (Test-Patched $Asar)) {
        Copy-Item -LiteralPath $Asar -Destination $Backup -Force
        Write-Host ("  backup  : from the installed archive") -ForegroundColor Green
    } else {
        Write-Host '  [x] the archive is already patched and no pristine copy exists.' -ForegroundColor Red
        Write-Host '      reinstall Herd first, then run this again.' -ForegroundColor Red
        exit 6
    }
} else {
    Write-Host ("  backup  : already present (" + $Backup + ")") -ForegroundColor DarkGray
}

# apply now
$engineArgs = @{ HerdDir = $HerdDir; StateDir = $InstallDir; Restart = $true }
if ($Force) { $engineArgs['Force'] = $true }
& (Join-Path $InstallDir 'HerdPatch.ps1') @engineArgs

# ----------------------------------------------------------------------- task
if (-not $NoTask) {
    Remove-Task $taskName

    $arg = '-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "' +
           (Join-Path $InstallDir 'HerdPatch.ps1') + '" -HerdDir "' + $HerdDir +
           '" -StateDir "' + $InstallDir + '" -Restart -Quiet'

    $action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument $arg
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
        -Description 'Re-bakes the Herd license shim into resources\app.asar after an update.' | Out-Null
    Write-Host ("  task    : " + $taskName + "  (logon + every $IntervalMinutes min, RunLevel Highest)") -ForegroundColor Green
}

Write-Host ''
Write-Host ("  SHA256 after = " + (Get-FileHash -LiteralPath $Asar -Algorithm SHA256).Hash)
Write-Host ("  shim log     = " + (Join-Path $env:APPDATA 'Herd\herd-pro.log'))
Write-Host '  done.' -ForegroundColor Green
