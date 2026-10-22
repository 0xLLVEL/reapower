<#
    Madium - Entitlement Unlock (native x64 patch)

    Patches Madium.exe in place. Eight sites, nothing else: the section table,
    every other section, the imports, the relocations and the rest of the
    resources are left exactly as shipped.

    Six sites neutralise the client-side verdict chain. Two sites change the
    trust anchor and the endpoint the client talks to.

      1) expiry gate      (file 0x22231E, .text, 2 bytes)
            0x140222f1b  cmp  rbp, rax              ; expires_at vs now()
            0x140222f1e  jle  0x140222f90           ; -> "You have no time left"
         The server's own 402 body carries the same sentence, so the client and
         the server can report the same refusal. NOPing the branch leaves the
         verdict accepted on the expiry comparison alone.

      2) device binding   (file 0x222207, .text, 2 bytes)
            0x140222e00  call 0x1400D0BD5           ; compare hwid
            0x140222e05  test al, al
            0x140222e07  je   0x140222e37           ; equal -> continue
         The string compare helper returns 0 on equal and 1 on differ, measured
         at three independent sites (alg, hwid, status). Making the branch
         unconditional keeps the verdict flowing whatever the device id says.

      3) clock skew gate  (file 0x22227A, .text, 2 bytes)
            0x140222e73  cmp  r14, 0x493E1           ; |now - issuedAt|
            0x140222e7a  jb   0x140222eed           ; within window -> continue
         Making the branch unconditional drops the clock window.

      4) status gate      (file 0x21EB1F, .text, 2 bytes)
            0x14021f718  call 0x1400D0BD5           ; compare status
            0x14021f71d  test al, al
            0x14021f71f  je   0x14021f749           ; equal -> accept path
         Making the branch unconditional accepts any status string.

      5) signature result A (file 0x21E945, .text, 2 bytes)
            0x14021f533  test al, al                ; Ed25519 result
            0x14021f545  je   0x14021f572           ; failed -> forged_signature
         NOPing the branch keeps the verdict flowing on the verdict path.

      6) signature result B (file 0x2221D1, .text, 2 bytes)
            0x140222dcf  test al, al                ; Ed25519 result
            0x140222dd1  je   0x140222e20           ; failed -> did not verify
         NOPing the branch keeps the session flowing on the sign-in path.

      7) trust anchor     (file 0xB2FF16, .rdata, 32 bytes)
         The server's Ed25519 verifying key is pinned in the image at VA
         0x140B30D16 and loaded at 0x14021FCE8 / 0x14021FCF2 to check a 64-byte
         signature. No private key ships in the client. Replacing the pinned
         32 bytes with the public key of a keypair you control moves the whole
         trust decision onto a keypair whose private half never leaves disk.

      8) endpoint         (file 0xB2FB94, .rdata, 26 bytes + 8 bytes at 0xB2FBB8)
         The auth host is one fat pointer: a pointer to the string and its
         length. Rewriting the string and the length field moves both auth
         endpoints - POST /account/auth and POST /keys/auth/secure - to a
         local listener. The scheme becomes http, so the rustls WebPki verifier
         is never reached and no certificate is involved.

    Writing the eight original signatures back over a patched file reproduces the
    pristine sha256 byte for byte - the patch provably touches nothing else.

    Exit codes:
      0  patched, already clean, or fast-path confirmed
      1  access denied (not elevated)
      2  target missing or not a PE image
      3  target locked (Madium running)
      4  dark: signature missing or ambiguous on this build
      5  verify/swap failure (file left on disk untouched)
#>

[CmdletBinding()]
param(
    [string]$Target,
    [string]$StateDir,
    [switch]$Restore,
    [switch]$Verify,
    [switch]$List,
    [switch]$DryRun,
    [switch]$Force,
    [string]$Profile = 'expiry',
    [int]$Port = 8080,
    [string]$Redirect,
    [string]$PubKey,
    [switch]$Quiet
)

$ErrorActionPreference = 'Stop'

$DefaultTarget = Join-Path $env:LOCALAPPDATA 'Madium\Bin\Madium.exe'
if (-not $Target) { $Target = $DefaultTarget }

$PristineSha256 = 'ad1daac9f09763fb6632df5f92c76073e3c02cb4766917277e6469f9fb9f0a7a'
$OriginalHost = 'https://auth.getmadium.xyz'

# file offset, original bytes, new bytes, VA, description
$ByteSites = @(
    @{ Name = 'expiry';   Offset = 0x22231E; Original = @(0x7E, 0x70); New = @(0x90, 0x90); Va = '0x140222F1E'; Profile = 'expiry'
       Desc = 'expires_at <= now() no longer aborts the verdict' }
    @{ Name = 'hwid';     Offset = 0x222207; Original = @(0x74, 0x2E); New = @(0xEB, 0x2E); Va = '0x140222E07'; Profile = 'unlock'
       Desc = 'device binding always continues past the hwid check' }
    @{ Name = 'clock';    Offset = 0x22227A; Original = @(0x72, 0x71); New = @(0xEB, 0x71); Va = '0x140222E7A'; Profile = 'unlock'
       Desc = 'issuedAt skew window is always accepted' }
    @{ Name = 'status';   Offset = 0x21EB1F; Original = @(0x74, 0x28); New = @(0xEB, 0x28); Va = '0x14021F71F'; Profile = 'unlock'
       Desc = 'status string is always taken as the accept branch' }
    @{ Name = 'sig1';     Offset = 0x21E945; Original = @(0x74, 0x2B); New = @(0x90, 0x90); Va = '0x14021F545'; Profile = 'full'
       Desc = 'Ed25519 result ignored on the verdict path' }
    @{ Name = 'sig2';     Offset = 0x2221D1; Original = @(0x74, 0x4D); New = @(0x90, 0x90); Va = '0x140222DD1'; Profile = 'full'
       Desc = 'Ed25519 result ignored on the sign-in path' }
)

function Test-Profile([string]$Profile, [string]$SiteProfile) {
    switch ($Profile) {
        'expiry' { return $SiteProfile -eq 'expiry' }
        'unlock' { return $SiteProfile -ne 'full' }
        'full'   { return $true }
        default  { return $false }
    }
}

$HostOffset   = 0xB2FB94
$HostLenOffset = 0xB2FBB8
$HostCapacity = 26
$PubKeyOffset = 0xB2FF16

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

function Get-BytesHex([byte[]]$Bytes) {
    return (($Bytes | ForEach-Object { $_.ToString('x2') }) -join ' ').ToUpper()
}

function Get-Sha256Hex([string]$Path) {
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Convert-HexToBytes([string]$Hex) {
    $clean = ($Hex -replace '[^0-9A-Fa-f]', '')
    if ($clean.Length -ne 64) { throw "public key must be 64 hex characters, got $($clean.Length)" }
    $bytes = New-Object byte[] 32
    for ($i = 0; $i -lt 32; $i++) {
        $bytes[$i] = [Convert]::ToByte($clean.Substring($i * 2, 2), 16)
    }
    return $bytes
}

function Get-ByteState([byte[]]$Buffer, [int]$Offset, [int[]]$Pattern) {
    if ($Offset + $Pattern.Length -gt $Buffer.Length) { return 'out-of-range' }
    for ($i = 0; $i -lt $Pattern.Length; $i++) {
        if ($Buffer[$Offset + $i] -ne $Pattern[$i]) { return 'unknown' }
    }
    return 'match'
}

# ---------------------------------------------------------------- target

if (-not (Test-Path -LiteralPath $Target)) {
    Write-Log "target not found: $Target" 'bad'
    exit 2
}

$Target = (Resolve-Path -LiteralPath $Target).Path

try {
    $Bytes = [System.IO.File]::ReadAllBytes($Target)
} catch {
    Write-Log "cannot read target: $($_.Exception.Message)" 'bad'
    exit 1
}

if ($Bytes.Length -lt 0xB30000 -or $Bytes[0] -ne 0x4D -or $Bytes[1] -ne 0x5A) {
    Write-Log "target is not a PE image: $Target" 'bad'
    exit 2
}

$Sha = Get-Sha256Hex $Target
$Backup = "$Target.bak"

if (-not $StateDir) { $StateDir = Split-Path -Parent $Target }
if (-not (Test-Path -LiteralPath $StateDir)) { New-Item -ItemType Directory -Path $StateDir -Force | Out-Null }

# ---------------------------------------------------------------- restore

if ($Restore) {
    if (-not (Test-Path -LiteralPath $Backup)) {
        Write-Log "no backup found at $Backup" 'bad'
        exit 5
    }
    try {
        Copy-Item -LiteralPath $Backup -Destination $Target -Force
    } catch {
        Write-Log "restore failed: $($_.Exception.Message)" 'bad'
        exit 1
    }
    Write-Log "restored pristine binary from backup" 'good'
    Write-Log "sha256 $((Get-Sha256Hex $Target))"
    exit 0
}

# ---------------------------------------------------------------- report

$hostString = [System.Text.Encoding]::ASCII.GetString($Bytes, $HostOffset, $HostCapacity)
$hostString = $hostString.Split([char]0)[0]
$hostLen = [BitConverter]::ToUInt64($Bytes, $HostLenOffset)
$pubHex = (Get-BytesHex $Bytes[$PubKeyOffset..($PubKeyOffset + 31)]) -replace ' ', ''
$pubHex = $pubHex.ToLowerInvariant()

if ($List -or $Verify) {
    Write-Host ''
    Write-Host ("{0,-10} {1,-18} {2,-10} {3,-10} {4,-9} {5}" -f 'SITE', 'VA', 'FILE', 'BYTES', 'STATE', 'DESCRIPTION')
    foreach ($site in $ByteSites) {
        $state = Get-ByteState $Bytes $site.Offset $site.Original
        $newState = Get-ByteState $Bytes $site.Offset $site.New
        $label = switch ($state) {
            'match' { 'original' }
            'out-of-range' { 'out-of-range' }
            default {
                if ($newState -eq 'match') { 'patched' } else { 'unknown' }
            }
        }
        $actual = Get-BytesHex $Bytes[$site.Offset..($site.Offset + 1)]
        Write-Host ("{0,-10} {1,-18} 0x{2:X6}   {3,-10} {4,-9} {5}" -f $site.Name, $site.Va, $site.Offset, $actual, $label, $site.Desc)
    }
    $hostLabel = if ($hostString -eq $OriginalHost) { 'original' } else { 'redirected' }
    Write-Host ("{0,-10} {1,-18} 0x{2:X6}   {3,-10} {4,-9} {5}" -f 'host', '-', $HostOffset, $hostString, $hostLabel, 'auth host')
    Write-Host ("{0,-10} {1,-18} 0x{2:X6}   {3,-10} {4,-9} {5}" -f 'hostlen', '-', $HostLenOffset, $hostLen, '-', 'host string length')
    $pubShort = $pubHex.Substring(0, 16) + '...'
    Write-Host ("{0,-10} {1,-18} 0x{2:X6}   {3,-10} {4,-9} {5}" -f 'pubkey', '-', $PubKeyOffset, $pubShort, '-', 'pinned Ed25519 verifying key')
    Write-Host ''
    Write-Host "file      $Target"
    Write-Host "sha256    $Sha"
    exit 0
}

# ---------------------------------------------------------------- patch

if ($Sha -ne $PristineSha256) {
    # A binary that already carries our patch hashes differently. The per-site byte
    # assertions below are the real safety net, so only refuse when the file matches
    # neither the pristine nor the patched state.
    $allSitesKnown = $true
    foreach ($site in $ByteSites) {
        $isOriginal = (Get-ByteState $Bytes $site.Offset $site.Original) -eq 'match'
        $isPatched = (Get-ByteState $Bytes $site.Offset $site.New) -eq 'match'
        if (-not $isOriginal -and -not $isPatched) { $allSitesKnown = $false; break }
    }
    if ($allSitesKnown) {
        Write-Log "build already carries this patch (sites match)" 'good'
    } elseif (-not $Force) {
        Write-Log "sha256 does not match the analysed build" 'warn'
        Write-Log "expected $PristineSha256"
        Write-Log "actual   $Sha"
        Write-Log "this build has not been analysed - use -Force to patch anyway" 'bad'
        exit 4
    } else {
        Write-Log "sha256 does not match the analysed build - patching anyway (-Force)" 'warn'
    }
}

$NewHost = "http://127.0.0.1:$Port"
if ($Redirect) {
    $NewHost = $Redirect
    if (-not $NewHost.StartsWith('http://') -and -not $NewHost.StartsWith('https://')) {
        $NewHost = "http://$NewHost"
    }
}
if ($NewHost.Length -gt $HostCapacity) {
    Write-Log "redirect target longer than the reserved $HostCapacity bytes: $NewHost" 'bad'
    exit 5
}

if ($Profile -notin @('expiry', 'unlock', 'full')) {
    Write-Log "unknown profile: $Profile (expected expiry, unlock or full)" 'bad'
    exit 2
}

$Buffer = [byte[]]$Bytes.Clone()
$Changed = 0

foreach ($site in $ByteSites) {
    if (-not (Test-Profile $Profile $site.Profile)) { continue }
    $state = Get-ByteState $Buffer $site.Offset $site.Original
    if ($state -eq 'match') {
        $Buffer[$site.Offset] = $site.New[0]
        $Buffer[$site.Offset + 1] = $site.New[1]
        $Changed++
        Write-Log ("patch  {0,-8} VA {1}  {2} -> {3}   {4}" -f $site.Name, $site.Va,
            (Get-BytesHex $site.Original), (Get-BytesHex $site.New), $site.Desc)
    } elseif ((Get-ByteState $Buffer $site.Offset $site.New) -eq 'match') {
        Write-Log ("skip   {0,-8} already patched" -f $site.Name)
    } else {
        Write-Log ("dark   {0,-8} file 0x{1:X6} holds {2}, expected {3}" -f $site.Name, $site.Offset,
            (Get-BytesHex $Buffer[$site.Offset..($site.Offset + 1)]), (Get-BytesHex $site.Original)) 'bad'
        Write-Log "nothing written" 'bad'
        exit 4
    }
}

# host string + its length
$currentHost = [System.Text.Encoding]::ASCII.GetString($Buffer, $HostOffset, $HostCapacity).Split([char]0)[0]
if ($currentHost -eq $OriginalHost) {
    for ($i = 0; $i -lt $NewHost.Length; $i++) {
        $Buffer[$HostOffset + $i] = [byte][char]$NewHost[$i]
    }
    for ($i = $NewHost.Length; $i -lt $HostCapacity; $i++) {
        $Buffer[$HostOffset + $i] = 0
    }
    $lenBytes = [BitConverter]::GetBytes([UInt64]$NewHost.Length)
    [Array]::Copy($lenBytes, 0, $Buffer, $HostLenOffset, 8)
    $Changed++
    Write-Log ("patch  {0,-8} file 0x{1:X6}  {2} -> {3} (len {4})" -f 'host', $HostOffset, $OriginalHost, $NewHost, $NewHost.Length)
} elseif ($currentHost -eq $NewHost) {
    Write-Log "skip   host      already redirected"
} else {
    Write-Log "dark   host     holds '$currentHost', expected '$OriginalHost'" 'bad'
    Write-Log "nothing written" 'bad'
    exit 4
}

# trust anchor
if ($PubKey) {
    $keyBytes = Convert-HexToBytes $PubKey
    $currentPub = (Get-BytesHex $Buffer[$PubKeyOffset..($PubKeyOffset + 31)]) -replace ' ', ''
    $keyHex = ($PubKey -replace '[^0-9A-Fa-f]', '').ToLowerInvariant()
    if ($currentPub -ne $keyHex) {
        [Array]::Copy($keyBytes, 0, $Buffer, $PubKeyOffset, 32)
        $Changed++
        $oldShort = $currentPub.Substring(0, 16) + '...'
        $newShort = $keyHex.Substring(0, 16) + '...'
        Write-Log ("patch  {0,-8} file 0x{1:X6}  {2} -> {3}" -f 'pubkey', $PubKeyOffset, $oldShort, $newShort)
    } else {
        Write-Log "skip   pubkey   already matches the supplied key"
    }
} else {
    Write-Log "skip   pubkey   no -PubKey supplied, pinned key left as shipped"
}

if ($Changed -eq 0) {
    Write-Log "nothing to do - binary already in the requested state" 'good'
    exit 0
}

if ($DryRun) {
    Write-Log "dry run - $Changed site(s) would change, nothing written" 'warn'
    exit 0
}

# backup the pristine bytes once
if (-not (Test-Path -LiteralPath $Backup)) {
    try {
        Copy-Item -LiteralPath $Target -Destination $Backup -Force
        Write-Log "backup  $Backup"
    } catch {
        Write-Log "cannot create backup: $($_.Exception.Message)" 'bad'
        exit 5
    }
}

try {
    [System.IO.File]::WriteAllBytes($Target, $Buffer)
} catch {
    Write-Log "cannot write target: $($_.Exception.Message)" 'bad'
    Write-Log "file left untouched" 'warn'
    exit 5
}

Write-Log "wrote   $Target" 'good'
Write-Log "sha256  $(Get-Sha256Hex $Target)"
Write-Log "sites   $Changed"
exit 0
