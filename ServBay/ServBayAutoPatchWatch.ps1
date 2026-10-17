<#
  ServBayAutoPatchWatch.ps1
  ------------------------------------------------------------------
  Event-driven trigger for ServBayAutoPatch.ps1.

  The old task polled: "at logon + every 2 minutes, for 10 years".
  Every poll spawned a powershell.exe (1.16 s) that SHA256'd a 17 MB
  DLL (90 ms) to conclude "nothing changed" -- roughly 720 process
  births a day. This watcher replaces the timer.

  It starts once per session, then blocks on the Windows process-start
  trace and invokes the engine only when ServBay is actually opened.

  Idle cost: 0% CPU, 0 bytes read, 0 polls. One powershell.exe
  (~70 MB working set) is the entire price.

  Detection
    Win32_ProcessStartTrace is an ETW-backed WMI class: the kernel
    pushes an event the moment the process is created. It is NOT the
    polled __InstanceCreationEvent -- no WITHIN clause, no timer.

  Verified on Windows 11 / PowerShell 5.1
    Register-CimIndicationEvent + Wait-Event   -> delivered in ~1.0 s
    Wait-Event -Timeout                        -> returns empty, on time
    unregister + re-register                   -> fires again
    ManagementEventWatcher.WaitForNextEvent()  -> deliberately NOT used:
      .NET Framework has no TimeSpan overload for it, and scriptblock
      EventArrived handlers never run while the main thread is blocked.

  Contract
    * Requires Administrator. Win32_ProcessStartTrace is admin-only.
    * The engine runs as a CHILD process. Both engines call `exit` at
      top level, so dot-sourcing them would take the watcher down too.
    * A pass is capped at -PassTimeoutSeconds and the child is killed if
      it overruns, so a hung engine cannot wedge the watcher.
    * Every -IdleSeconds the subscription is torn down and rebuilt. That
      is the self-heal, and the heartbeat: it recovers from a WMI restart
      or a sleep/resume that killed the trace session underneath us, and
      the "armed" line stops appearing if the watcher dies.
    * Events within -DebounceSeconds of the last pass are dropped.
      ServBay restarts itself after a patch, which would otherwise
      re-fire us once per real patch.
    * -RetryExitCodes (default 3 = "the target is still locked by the
      running app") puts the watcher into a pending state: it then wakes
      every -PendingRetrySeconds and retries until the patch lands.
      A session with nothing pending still never wakes.
    * -Once runs a single pass and exits. Used for testing and by the
      installer's first run.

  Log
    <StateDir>\watch.log   what the watcher did, when, and the exit code of
                           every engine pass. The engine's own log holds the
                           detail: <StateDir>\autopatch.log
#>
[CmdletBinding()]
param(
    [string]   $Engine      = (Join-Path $PSScriptRoot 'ServBayAutoPatch.ps1'),
    [string]   $ProcessName = 'ServBay.exe',
    [string[]] $EngineArgs  = @('-Quiet'),
    [string]   $StateDir    = 'C:\ProgramData\ServBayPatch',
    [int]      $DebounceSeconds    = 20,
    [int]      $PassTimeoutSeconds = 900,
    [int]      $IdleSeconds        = 900,
    [int]      $PendingRetrySeconds = 60,
    [int[]]    $RetryExitCodes      = @(3),
    [switch]   $Once,
    [switch]   $Quiet
)
$ErrorActionPreference = 'Stop'

$script:LogPath  = Join-Path $StateDir 'watch.log'
$script:SourceId = 'ServBayAutoPatchWatch'
$script:PsExe    = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
$script:LastPass = [datetime]::MinValue

function Write-Log {
    param([string]$Text, [string]$Tag = 'INFO')

    $line = '{0}  {1,-6} {2}' -f (Get-Date).ToString('yyyy-MM-dd HH:mm:ss'), $Tag, $Text
    if ((Test-Path -LiteralPath $script:LogPath) -and
        (Get-Item -LiteralPath $script:LogPath).Length -gt 262144) {
        Move-Item -LiteralPath $script:LogPath -Destination ($script:LogPath + '.1') -Force
    }
    Add-Content -LiteralPath $script:LogPath -Value $line -Encoding UTF8
    if (-not $Quiet) { Write-Host $line }
}

function Assert-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $pr = New-Object Security.Principal.WindowsPrincipal($id)
    if (-not $pr.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'ServBayAutoPatchWatch.ps1 must run as Administrator - Win32_ProcessStartTrace is admin-only.'
    }
}

function Format-Arg([string]$Value) {
    if ($Value -match '\s' -and $Value -notmatch '^".*"$') { return '"' + $Value + '"' }
    return $Value
}

function Register-Trace {
    Register-CimIndicationEvent `
        -Query ("SELECT * FROM Win32_ProcessStartTrace WHERE ProcessName='{0}'" -f $ProcessName) `
        -SourceIdentifier $script:SourceId -ErrorAction Stop | Out-Null
}

function Unregister-Trace {
    Unregister-Event -SourceIdentifier $script:SourceId -ErrorAction SilentlyContinue
    Get-Job -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -eq $script:SourceId } |
        Remove-Job -Force -ErrorAction SilentlyContinue
}

function Invoke-Pass {
    param([string]$Reason)

    $script:LastPass = Get-Date
    $sw   = [Diagnostics.Stopwatch]::StartNew()
    $exit = -1
    $argList = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', (Format-Arg $Engine)) +
               @($EngineArgs | ForEach-Object { Format-Arg $_ })

    try {
        # Deliberately no -RedirectStandardOutput / -RedirectStandardError here.
        # A redirected Start-Process hands back a Process object that does not
        # own the handle, and reading .ExitCode then throws "Process was not
        # started by this object" -- while the exit code is the entire point of
        # this call, and redirection would also defeat the hard timeout below.
        # The engine keeps its own log anyway.
        $child = Start-Process -FilePath $script:PsExe -ArgumentList $argList -PassThru -WindowStyle Hidden
        if ($child.WaitForExit($PassTimeoutSeconds * 1000)) {
            $exit = $child.ExitCode
        } else {
            $child.Kill()
            $exit = -2
            Write-Log ('engine exceeded {0}s - killed' -f $PassTimeoutSeconds) 'WARN'
        }
    } catch {
        Write-Log ('engine launch failed: ' + $_.Exception.Message) 'FAIL'
    }
    $sw.Stop()

    $tag = if ($exit -in @(0, 3)) { 'OK' } else { 'WARN' }
    Write-Log ('pass reason={0} exit={1} {2:N0} ms' -f $Reason, $exit, $sw.Elapsed.TotalMilliseconds) $tag

    return $exit
}

# ------------------------------------------------------------------ preflight
Assert-Admin
if (-not (Test-Path -LiteralPath $StateDir)) { New-Item -ItemType Directory -Force -Path $StateDir | Out-Null }
if (-not (Test-Path -LiteralPath $Engine))   { throw ('engine not found: ' + $Engine) }
$Engine = (Resolve-Path -LiteralPath $Engine).Path

Write-Log ('watch start   pid={0}  engine={1}' -f $PID, $Engine)
Write-Log ('watching      ProcessName=''{0}''  detection=ETW push  polls=0  debounce={1}s  rearm={2}s' -f $ProcessName, $DebounceSeconds, $IdleSeconds)

$exit = Invoke-Pass 'startup'

if ($Once) {
    Write-Log 'once mode - exiting'
    return
}

$pending = ($RetryExitCodes -contains $exit)
if ($pending) { Write-Log ('patch pending - target still locked, retrying every {0}s' -f $PendingRetrySeconds) 'WARN' }

# ------------------------------------------------------------------ event loop
while ($true) {
    try {
        Register-Trace
    } catch {
        Write-Log ('could not arm the trace subscription: ' + $_.Exception.Message) 'FAIL'
        Write-Log 'retrying in 30s' 'FAIL'
        Start-Sleep -Seconds 30
        continue
    }

    Write-Log ('armed ProcessName=''{0}'' - blocked on the kernel trace, zero polls' -f $ProcessName)

    try {
        while ($true) {
            $waitFor = if ($pending) { $PendingRetrySeconds } else { $IdleSeconds }
            $event   = Wait-Event -SourceIdentifier $script:SourceId -Timeout $waitFor

            if (-not $event) {
                if (-not $pending) { break }
                $exit    = Invoke-Pass 'retry (locked)'
                $pending = ($RetryExitCodes -contains $exit)
                if (-not $pending) { Write-Log 'patch landed - back to event-only waiting' }
                continue
            }

            $seen = @()
            foreach ($e in @(Get-Event -SourceIdentifier $script:SourceId)) {
                $pname = $e.SourceEventArgs.NewEvent.ProcessName
                if ($pname) { $seen += $pname }
                Remove-Event -EventIdentifier $e.EventIdentifier -ErrorAction SilentlyContinue
            }
            if ($seen.Count -eq 0) { continue }

            $label = ($seen | Select-Object -Unique) -join ','
            $since = ((Get-Date) - $script:LastPass).TotalSeconds
            if ($since -lt $DebounceSeconds) {
                Write-Log ('event {0} dropped - {1:N1}s since last pass (debounce {2}s)' -f $label, $since, $DebounceSeconds)
                continue
            }

            $exit    = Invoke-Pass ('launch ' + $label)
            $pending = ($RetryExitCodes -contains $exit)
            if ($pending) { Write-Log ('patch pending - target still locked, retrying every {0}s' -f $PendingRetrySeconds) 'WARN' }
        }
        Write-Log ('idle {0}s - subscription re-armed' -f $IdleSeconds)
    } catch {
        Write-Log ('wait failed: ' + $_.Exception.Message) 'FAIL'
        Start-Sleep -Seconds 10
    } finally {
        Unregister-Trace
    }
}
