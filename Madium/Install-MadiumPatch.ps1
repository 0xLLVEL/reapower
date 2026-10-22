# Madium - Entitlement Unlock (native x64 patch + local auth endpoint)
#
# Installs the patch into the local Madium client and manages the state that
# goes with it:
#
#   1. backs up Madium.exe
#   2. writes the six gate patches, the auth host redirect and the pinned
#      Ed25519 verifying key
#   3. generates (once) the Ed25519 keypair the local auth endpoint signs with
#   4. installs the local auth endpoint and starts it
#
# Uninstall restores the pristine binary, stops the endpoint and removes the
# keypair.
#
# Exit codes:
#   0  done
#   1  access denied (not elevated)
#   2  target missing
#   5  verify/swap failure (file left on disk untouched)

[CmdletBinding()]
param(
    [string]$Target,
    [string]$StateDir,
    [switch]$Uninstall,
    [switch]$DryRun,
    [int]$Port = 8080,
    [switch]$Quiet
)

$ErrorActionPreference = 'Stop'

$Here = Split-Path -Parent $MyInvocation.MyCommand.Path
$Tools = Join-Path $Here 'tools'
$DefaultTarget = Join-Path $env:LOCALAPPDATA 'Madium\Bin\Madium.exe'
if (-not $Target) { $Target = $DefaultTarget }

if (-not $StateDir) { $StateDir = Join-Path $Here 'state' }
$KeyPair = Join-Path $StateDir 'keypair.json'
$KeyPairPub = Join-Path $StateDir 'keypair.pub'
$MockScript = Join-Path $Tools 'madium_mockauth.py'
$PidFile = Join-Path $StateDir 'mockauth.pid'
$LogFile = Join-Path $StateDir 'mockauth.log'

function Write-Log([string]$Message, [string]$Level = 'info') {
    if ($Quiet) { return }
    $tag = switch ($Level) {
        'warn' { '[!]' }
        'bad'  { '[x]' }
        'good' { '[+]' }
        default { '[i]' }
    }
    Write-Host "$tag $Message"
}

function Find-Python {
    foreach ($candidate in @('python', 'python3', 'py')) {
        $cmd = Get-Command $candidate -ErrorAction SilentlyContinue
        if ($cmd) { return $cmd.Source }
    }
    return $null
}

function Stop-Endpoint {
    # Stop the endpoint of *this* install only. The pid file is the primary
    # handle; the command line scan is the fallback for a stale pid file, and it
    # matches on this install's keypair so an endpoint of another install - a
    # different port, a different state directory - keeps running.
    $stopped = $false
    if (Test-Path -LiteralPath $PidFile) {
        $mockPid = (Get-Content -LiteralPath $PidFile -Raw).Trim()
        if ($mockPid -match '^\d+$') {
            Stop-Process -Id ([int]$mockPid) -Force -ErrorAction SilentlyContinue
            $stopped = $true
        }
        Remove-Item -LiteralPath $PidFile -Force -ErrorAction SilentlyContinue
    }
    foreach ($candidate in (Get-Process -Name 'python' -ErrorAction SilentlyContinue)) {
        try {
            $cmdLineOf = (Get-CimInstance Win32_Process -Filter "ProcessId = $($candidate.Id)").CommandLine
        } catch {
            $cmdLineOf = ''
        }
        if ($cmdLineOf -and $cmdLineOf -like '*madium_mockauth.py*' -and $cmdLineOf -like "*$KeyPair*") {
            Stop-Process -Id $candidate.Id -Force -ErrorAction SilentlyContinue
            $stopped = $true
        }
    }
    return $stopped
}

# ---------------------------------------------------------------- uninstall

if ($Uninstall) {
    if (Stop-Endpoint) { Write-Log 'stopped the local auth endpoint' 'good' }

    $backup = "$Target.bak"
    if (Test-Path -LiteralPath $backup) {
        Copy-Item -LiteralPath $backup -Destination $Target -Force
        Write-Log "restored pristine binary from $backup" 'good'
    } else {
        Write-Log "no backup found at $backup" 'warn'
    }

    foreach ($file in @($KeyPair, $KeyPairPub)) {
        if (Test-Path -LiteralPath $file) { Remove-Item -LiteralPath $file -Force }
    }
    Write-Log 'removed the local keypair' 'good'
    exit 0
}

# ---------------------------------------------------------------- install

if (-not (Test-Path -LiteralPath $Target)) {
    Write-Log "target not found: $Target" 'bad'
    exit 2
}

$python = Find-Python
if (-not $python) {
    Write-Log 'python not found on PATH - the local auth endpoint needs it' 'bad'
    exit 5
}

if (-not (Test-Path -LiteralPath $StateDir)) {
    New-Item -ItemType Directory -Path $StateDir -Force | Out-Null
}

# 1. keypair - generate once, reuse afterwards. Both halves have to be present:
# keeping a public key whose private half was deleted leaves the endpoint unable
# to sign anything, and the client then rejects every verdict.
$pubHex = $null
$keyPairIntact = (Test-Path -LiteralPath $KeyPair) -and (Test-Path -LiteralPath $KeyPairPub)
if ($keyPairIntact) {
    $pubHex = (Get-Content -LiteralPath $KeyPairPub -Raw).Trim()
    Write-Log "reusing the existing keypair ($KeyPairPub)"
} else {
    if ((Test-Path -LiteralPath $KeyPairPub) -or (Test-Path -LiteralPath $KeyPair)) {
        Write-Log 'keypair is incomplete - regenerating it' 'warn'
    } else {
        Write-Log "generating an Ed25519 keypair in $StateDir"
    }
    $genOut = & $python $MockScript --generate-key-only --key-pair $KeyPair 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Log "keypair generation failed: $genOut" 'bad'
        exit 5
    }
    $pubHex = ($genOut | Select-Object -Last 1).ToString().Trim()
    if ($pubHex -notmatch '^[0-9a-fA-F]{64}$') {
        Write-Log "keypair generation returned an unexpected public key: $pubHex" 'bad'
        exit 5
    }
    Set-Content -LiteralPath $KeyPairPub -Value $pubHex -Encoding ascii
    Write-Log "public key $pubHex"
}

# 2. patch
$patchArgs = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', (Join-Path $Here 'MadiumPatch.ps1'),
    '-Target', $Target, '-Profile', 'full', '-Port', $Port, '-Redirect', "127.0.0.1:$Port", '-PubKey', $pubHex)
if ($DryRun) { $patchArgs += '-DryRun' }
& powershell @patchArgs
if ($LASTEXITCODE -ne 0) {
    Write-Log "patch failed with exit code $LASTEXITCODE" 'bad'
    exit $LASTEXITCODE
}

if ($DryRun) {
    Write-Log 'dry run - nothing installed' 'warn'
    exit 0
}

# 2b. self-verify - every component of the bypass has to be in the patched state on
# disk. Without this the installer would happily report success after patching a
# single site, which is exactly how the missing -Profile switch went unnoticed.
Write-Log 'verifying the patch on disk'
$verifyArgs = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', (Join-Path $Here 'MadiumPatch.ps1'),
    '-Target', $Target, '-Profile', 'full', '-Verify')
$verifyOut = & powershell @verifyArgs
$verifyExit = $LASTEXITCODE
if (-not $Quiet) { $verifyOut | ForEach-Object { Write-Host $_ } }
if ($verifyExit -ne 0) {
    Write-Log 'verification failed' 'bad'
    exit $verifyExit
}

$byteSites = @($verifyOut | Select-String -Pattern '^\s*(expiry|hwid|clock|status|sig1|sig2)\s')
$patchedByteSites = @($byteSites | Where-Object { $_.Line -match '\bpatched\b' })
$unknownByteSites = @($byteSites | Where-Object { $_.Line -match '\bunknown\b' })
$hostLine = @($verifyOut | Where-Object { $_ -match '^\s*host\s' })
$hostLenLine = @($verifyOut | Where-Object { $_ -match '^\s*hostlen\s' })
$pubkeyLine = @($verifyOut | Where-Object { $_ -match '^\s*pubkey\s' })

if ($unknownByteSites.Count -gt 0) {
    Write-Log "$($unknownByteSites.Count) site(s) are in an unknown state - refusing to continue" 'bad'
    exit 5
}
if ($patchedByteSites.Count -ne 6) {
    Write-Log "only $($patchedByteSites.Count) of 6 byte sites are patched" 'bad'
    Write-Log 'the bypass would be incomplete - refusing to continue' 'bad'
    exit 5
}
if ($hostLine.Count -ne 1 -or $hostLine[0] -notmatch 'redirected') {
    Write-Log 'the auth host was not redirected - refusing to continue' 'bad'
    exit 5
}
if ($hostLenLine.Count -ne 1) {
    Write-Log 'the auth host length field could not be read back - refusing to continue' 'bad'
    exit 5
}
if ($pubkeyLine.Count -ne 1) {
    Write-Log 'the pinned key could not be read back - refusing to continue' 'bad'
    exit 5
}
Write-Log "verified on disk: $($patchedByteSites.Count) byte sites, auth host redirected, pinned key in place" 'good'

# 3. start the local auth endpoint
# stop a previous instance of *this* install first
if (Stop-Endpoint) { Write-Log 'stopped the previous endpoint' }

Write-Log "starting the local auth endpoint on 127.0.0.1:$Port"
# The server detaches itself: it is spawned with its own handles so it never keeps
# the caller's stdout pipe open, which would otherwise make the caller wait for
# the whole lifetime of the server.
& $python $MockScript --port $Port --key-pair $KeyPair --quiet --log $LogFile --daemon --pid-file $PidFile
if ($LASTEXITCODE -ne 0) {
    Write-Log "the local auth endpoint failed to start" 'bad'
    exit 5
}

$endpointPid = $null
for ($i = 0; $i -lt 60; $i++) {
    Start-Sleep -Milliseconds 250
    if (Test-Path -LiteralPath $PidFile) {
        $raw = (Get-Content -LiteralPath $PidFile -Raw).Trim()
        if ($raw -match '^\d+$') { $endpointPid = [int]$raw; break }
    }
}
if (-not $endpointPid) {
    Write-Log "the local auth endpoint did not come up - see $LogFile" 'bad'
    exit 5
}

$alive = $false
for ($i = 0; $i -lt 40; $i++) {
    try {
        $probe = Invoke-WebRequest -Uri "http://127.0.0.1:$Port/" -UseBasicParsing -TimeoutSec 2
        if ($probe.StatusCode -eq 200) { $alive = $true; break }
    } catch {
        Start-Sleep -Milliseconds 250
    }
}
if (-not $alive) {
    Write-Log "the local auth endpoint is not answering on 127.0.0.1:$Port - see $LogFile" 'bad'
    exit 5
}

Write-Log "local auth endpoint running, pid $endpointPid" 'good'
Write-Log "logs: $LogFile"
Write-Log ''
Write-Log 'Open Madium and sign in with any credentials.' 'good'
Write-Log 'The endpoint must stay running while the client is open.'
exit 0
