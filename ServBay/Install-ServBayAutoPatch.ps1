<#
  Install-ServBayAutoPatch.ps1
  Run once, as Administrator. Installs the auto-patcher and a scheduled task
  that re-applies the patch within ~2 minutes of any ServBay update.

  What it registers
    Task name : ServBay AutoPatch
    Triggers  : at logon  +  every 2 minutes (10 years)
    Run level : Highest (elevated, so it can stop/start ServBay and write
                into C:\ServBay\app without a UAC prompt)
    Action    : powershell -File C:\ProgramData\ServBayPatch\ServBayAutoPatch.ps1 -Quiet
#>
[CmdletBinding()]
param(
    [string]$Source     = $PSScriptRoot,
    [string]$StateDir   = 'C:\ProgramData\ServBayPatch',
    [string]$TaskName   = 'ServBay AutoPatch',
    [int]$IntervalMin   = 2
)
$ErrorActionPreference = 'Stop'

$id = [Security.Principal.WindowsIdentity]::GetCurrent()
$pr = New-Object Security.Principal.WindowsPrincipal($id)
if (-not $pr.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Install-ServBayAutoPatch.ps1 must run as Administrator.'
}

if (-not (Test-Path -LiteralPath $StateDir)) { New-Item -ItemType Directory -Path $StateDir -Force | Out-Null }
New-Item -ItemType Directory -Path (Join-Path $StateDir 'backup') -Force | Out-Null

$engine = Join-Path $Source 'ServBayAutoPatch.ps1'
if (-not (Test-Path -LiteralPath $engine)) { throw "engine not found: $engine" }
$target = Join-Path $StateDir 'ServBayAutoPatch.ps1'
Copy-Item -LiteralPath $engine -Destination $target -Force
Write-Host ("engine    -> {0}" -f $target)

$ps = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
$action = New-ScheduledTaskAction -Execute $ps `
    -Argument ('-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "{0}" -Quiet' -f $target)

$trigLogon = New-ScheduledTaskTrigger -AtLogOn
$trigPoll  = New-ScheduledTaskTrigger -Once -At ((Get-Date).AddMinutes(1)) `
    -RepetitionInterval (New-TimeSpan -Minutes $IntervalMin) `
    -RepetitionDuration (New-TimeSpan -Days 3650)

$principal = New-ScheduledTaskPrincipal -UserId ('{0}\{1}' -f $env:USERDOMAIN, $env:USERNAME) `
    -LogonType Interactive -RunLevel Highest

$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
    -StartWhenAvailable -MultipleInstances IgnoreNew -ExecutionTimeLimit (New-TimeSpan -Minutes 15)

Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigLogon, $trigPoll `
    -Principal $principal -Settings $settings -Force `
    -Description 'Re-applies the ServBay entitlement patch after every ServBay update.' | Out-Null
Write-Host ("task      -> {0} (logon + every {1} min, RunLevel Highest)" -f $TaskName, $IntervalMin)

Write-Host ''
Write-Host '--- first run (patches now, restarts ServBay if it was running) ---'
& $target

Write-Host ''
Write-Host '--- status ---'
Get-ScheduledTask -TaskName $TaskName | Select-Object TaskName, State | Format-Table -AutoSize
$info = Get-ScheduledTaskInfo -TaskName $TaskName
Write-Host ("last run  : {0}  result: 0x{1:X8}" -f $info.LastRunTime, $info.LastTaskResult)
Write-Host ("next run  : {0}" -f $info.NextRunTime)
Write-Host ("log       : {0}\autopatch.log" -f $StateDir)
Write-Host ("rollback  : {0}\backup\*.dll  (copy over C:\ServBay\app\ServBay.dll)" -f $StateDir)
Write-Host ("remove    : Unregister-ScheduledTask -TaskName '{0}' -Confirm:`$false" -f $TaskName)
