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

$StateDir = Join-Path $Here 'state'
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

# ---------------------------------------------------------------- uninstall

if ($Uninstall) {
    if (Test-Path -LiteralPath $PidFile) {
        $mockPid = (Get-Content -LiteralPath $PidFile -Raw).Trim()
        if ($mockPid -match '^\d+$') {
            Stop-Process -Id ([int]$mockPid) -Force -ErrorAction SilentlyContinue
        }
        Remove-Item -LiteralPath $PidFile -Force -ErrorAction SilentlyContinue
        Write-Log 'stopped the local auth endpoint' 'good'
    }

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

# 1. keypair - generate once, reuse afterwards
$pubHex = $null
if (Test-Path -LiteralPath $KeyPairPub) {
    $pubHex = (Get-Content -LiteralPath $KeyPairPub -Raw).Trim()
    Write-Log "reusing the existing keypair ($KeyPairPub)"
} else {
    Write-Log "generating an Ed25519 keypair in $StateDir"
    $genOut = & $python $MockScript --generate-key-only --key-pair $KeyPair 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Log "keypair generation failed: $genOut" 'bad'
        exit 5
    }
    $pubHex = ($genOut | Select-Object -Last 1).ToString().Trim()
    Set-Content -LiteralPath $KeyPairPub -Value $pubHex -Encoding ascii
    Write-Log "public key $pubHex"
}

# 2. patch
$patchArgs = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', (Join-Path $Here 'MadiumPatch.ps1'),
    '-Target', $Target, '-Port', $Port, '-PubKey', $pubHex)
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

# 3. start the local auth endpoint
if (Test-Path -LiteralPath $PidFile) {
    $oldPid = (Get-Content -LiteralPath $PidFile -Raw).Trim()
    if ($oldPid -match '^\d+$') {
        Stop-Process -Id ([int]$oldPid) -Force -ErrorAction SilentlyContinue
    }
    Remove-Item -LiteralPath $PidFile -Force -ErrorAction SilentlyContinue
}

Write-Log "starting the local auth endpoint on 127.0.0.1:$Port"
$proc = Start-Process -FilePath $python -ArgumentList @(
    $MockScript, '--port', $Port, '--key-pair', $KeyPair, '--quiet'
) -WindowStyle Hidden -RedirectStandardOutput $LogFile -RedirectStandardError "$LogFile.err" -PassThru
Set-Content -LiteralPath $PidFile -Value $proc.Id -Encoding ascii

Start-Sleep -Seconds 2
if ($proc.HasExited) {
    Write-Log "the local auth endpoint exited immediately - see $LogFile.err" 'bad'
    exit 5
}

Write-Log "local auth endpoint running, pid $($proc.Id)" 'good'
Write-Log "logs: $LogFile"
Write-Log ''
Write-Log 'Open Madium and sign in with any credentials.' 'good'
Write-Log 'The endpoint must stay running while the client is open.'
exit 0
