<#
  Install-ServBayAutoPatch.ps1
  Run once, as Administrator. Installs the auto-patcher and an event-driven
  watcher that re-applies the patch the moment ServBay is opened after an update.

  What it registers
    Task name : ServBay AutoPatch
    Triggers  : at logon  +  a 6-hour safety net (a no-op while the watcher lives)
    Run level : Highest (elevated, so it can stop/start ServBay and write
                into C:\ServBay\app without a UAC prompt)
    Action    : powershell -File C:\ProgramData\ServBayPatch\ServBayAutoPatchWatch.ps1 -Quiet

  The task no longer polls. It starts the watcher once per session, and the
  watcher blocks on the Windows process-start trace and runs the engine only
  when ServBay.exe actually starts. See ServBayAutoPatchWatch.ps1.

  The 6-hour trigger is a fallback, not a poll: the task is registered with
  MultipleInstances=IgnoreNew, so while the watcher is alive the fallback fires
  into nothing. It only matters if the watcher died during the session.

  -Uninstall : stop the watcher and remove the task. The patched ServBay.dll is
               left in place, and C:\ProgramData\ServBayPatch is kept.
#>
[CmdletBinding()]
param(
    [string]$Source     = $PSScriptRoot,
    [string]$StateDir   = 'C:\ProgramData\ServBayPatch',
    [string]$TaskName   = 'ServBay AutoPatch',
    [int]$FallbackHours = 6,
    [switch]$Uninstall
)
$ErrorActionPreference = 'Stop'

$id = [Security.Principal.WindowsIdentity]::GetCurrent()
$pr = New-Object Security.Principal.WindowsPrincipal($id)
if (-not $pr.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Install-ServBayAutoPatch.ps1 must run as Administrator.'
}

$engine = Join-Path $StateDir 'ServBayAutoPatch.ps1'
$watch  = Join-Path $StateDir 'ServBayAutoPatchWatch.ps1'

function Stop-Watcher {
    $killed = @()
    Get-CimInstance Win32_Process -Filter "Name='powershell.exe'" -ErrorAction SilentlyContinue |
        Where-Object { $_.ProcessId -ne $PID -and $_.CommandLine -like '*ServBayAutoPatchWatch.ps1*' } |
        ForEach-Object {
            try {
                Invoke-CimMethod -InputObject $_ -MethodName Terminate | Out-Null
                $killed += $_.ProcessId
            } catch {
                Write-Host ("  could not stop watcher pid {0}: {1}" -f $_.ProcessId, $_.Exception.Message) -ForegroundColor Yellow
            }
        }
    if ($killed.Count) { Write-Host ("watcher   -> stopped (pid {0})" -f ($killed -join ', ')) }
    else               { Write-Host  'watcher   -> no running instance' -ForegroundColor DarkGray }
}

function Remove-PatchTask {
    if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) {
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
        Write-Host ("task      -> removed: {0}" -f $TaskName)
    } else {
        Write-Host ("task      -> no such task: {0}" -f $TaskName) -ForegroundColor DarkGray
    }
}

# ------------------------------------------------------------------ uninstall
if ($Uninstall) {
    Write-Host ''
    Write-Host 'ServBay AutoPatch - uninstall' -ForegroundColor Cyan
    Stop-Watcher
    Remove-PatchTask
    Write-Host ''
    Write-Host ("Files in {0} were kept (log + pristine backups)." -f $StateDir)
    Write-Host 'The patched ServBay.dll stays patched until ServBay updates itself.'
    return
}

# ------------------------------------------------------------------ install
if (-not (Test-Path -LiteralPath $StateDir)) { New-Item -ItemType Directory -Path $StateDir -Force | Out-Null }
New-Item -ItemType Directory -Path (Join-Path $StateDir 'backup') -Force | Out-Null

foreach ($f in @((Join-Path $Source 'ServBayAutoPatch.ps1'), (Join-Path $Source 'ServBayAutoPatchWatch.ps1'))) {
    if (-not (Test-Path -LiteralPath $f)) { throw ('missing: ' + $f) }
}

Stop-Watcher
Remove-PatchTask

Copy-Item -LiteralPath (Join-Path $Source 'ServBayAutoPatch.ps1')      -Destination $engine -Force
Copy-Item -LiteralPath (Join-Path $Source 'ServBayAutoPatchWatch.ps1') -Destination $watch  -Force
Write-Host ("engine    -> {0}" -f $engine)
Write-Host ("watcher   -> {0}" -f $watch)

$ps = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
$action = New-ScheduledTaskAction -Execute $ps `
    -Argument ('-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "{0}" -Quiet' -f $watch)

$trigLogon = New-ScheduledTaskTrigger -AtLogOn
$trigNet   = New-ScheduledTaskTrigger -Once -At ((Get-Date).AddMinutes(2)) `
    -RepetitionInterval (New-TimeSpan -Hours $FallbackHours) `
    -RepetitionDuration (New-TimeSpan -Days 3650)

$principal = New-ScheduledTaskPrincipal -UserId ('{0}\{1}' -f $env:USERDOMAIN, $env:USERNAME) `
    -LogonType Interactive -RunLevel Highest

# RestartCount/RestartInterval only help if the task fails outright; the watcher
# re-arms itself for everything else. Fall back if the parameter set is missing.
try {
    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
        -StartWhenAvailable -MultipleInstances IgnoreNew `
        -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)
} catch {
    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
        -StartWhenAvailable -MultipleInstances IgnoreNew
}
# The watcher is meant to live for the whole session. The default is PT72H,
# which would kill it every three days.
$settings.ExecutionTimeLimit = 'PT0S'

Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigLogon, $trigNet `
    -Principal $principal -Settings $settings -Force `
    -Description 'Runs the ServBay patch engine when ServBay.exe starts after an update (event-driven, no polling).' | Out-Null
Write-Host ("task      -> {0}  (logon + {1}h fallback, RunLevel Highest)" -f $TaskName, $FallbackHours)

Write-Host ''
Write-Host '--- first run (patches now, restarts ServBay if it was running) ---'
& $engine

Write-Host ''
Write-Host '--- watcher ---'
Start-ScheduledTask -TaskName $TaskName
Start-Sleep -Seconds 4
$watchProc = @(Get-CimInstance Win32_Process -Filter "Name='powershell.exe'" -ErrorAction SilentlyContinue |
    Where-Object { $_.CommandLine -like '*ServBayAutoPatchWatch.ps1*' })
if ($watchProc.Count) {
    Write-Host ("running   -> pid {0}, blocked on the process-start trace" -f (($watchProc | ForEach-Object { $_.ProcessId }) -join ', ')) -ForegroundColor Green
} else {
    Write-Host 'running   -> not up yet; check the log below' -ForegroundColor Yellow
}

Write-Host ''
Write-Host '--- status ---'
Get-ScheduledTask -TaskName $TaskName | Select-Object TaskName, State | Format-Table -AutoSize
Write-Host ("log       : {0}\watch.log  (watcher),  {0}\autopatch.log  (engine)" -f $StateDir)
Write-Host ("rollback  : {0}\backup\*.dll  (copy over C:\ServBay\app\ServBay.dll)" -f $StateDir)
Write-Host  'remove    : uninstall.cmd'
