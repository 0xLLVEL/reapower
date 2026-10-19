# Internet Download Manager - License Gate Patch (Windows x86)
#
# Patches IDMan.exe in place. Fifty-five bytes across five sites, nothing
# else: the section table, every other section, the imports, the relocations
# and the rest of the resources are left exactly as shipped.
#
# Sites 1 and 2 neutralise the licence enforcement gates. Site 5 neutralises
# the self-integrity dialog "The main IDM executive file is damaged" that IDM
# raises on the download path. Sites 3 and 4 are presentational only - they
# change what the About dialog says, not what the program does. Sites 1-3
# read the trial global 0x77BD24; none of them write it, and no state that
# gates a download is touched.
#
#   1) startup validator  (file 0x04FF40, .text, 3 bytes)
#        original prologue: 55 8D AC 24 DC FB FF FF 81 EC 24 04 00 00 ...
#        new               : 31 C0 C3            (xor eax,eax ; ret)
#
#   2) nag / exit gate    (file 0x04C2F0, .text, 6 bytes)
#        original prologue: 55 8D AC 24 9C F7 FF FF 81 EC 64 08 00 00 ...
#        new               : B8 01 00 00 00 C3   (mov eax,1 ; ret)
#
#   3) About: version suffix (file 0x002DD6, .text, 2 bytes)
#        CAboutDlg::OnInitDialog chooses between the two literals
#        "Trial" (0x696E50) and "Full" (0x696E48) with
#            39 1D 24 BD 77 00   cmp dword [0x77BD24], ebx  ; ebx = 0
#            74 07               je   -> "Full"
#            68 50 6E 69 00      push "Trial"
#            EB 05               jmp  -> past "Full"
#            68 48 6E 69 00      push "Full"
#        Flipping 74 -> EB makes the branch unconditional, so the version
#        line reads "... Full" instead of "... Trial" on every build.
#
#   4) About: licensee line (file 0x38DB5C, .rsrc, 42 bytes)
#        The dialog template for RT_DIALOG id=100 ships the static control
#        0x049D with the placeholder "Unregistered Version". Runtime only
#        replaces it when [0x77BD24] == 0 *and* HKLM holds a licensee name,
#        so on a trial build the placeholder is what stays on screen.
#        Replaced in place, UTF-16, same character count, same byte count:
#        "Registered Version" plus two trailing spaces. The resource parser
#        walks item boundaries off the string terminator, which is why the
#        replacement has to be exactly as long as what it replaces.
#
#   5) damaged-file dialog gate (file 0x09AF78, .text, 2 bytes)
#        The download path tests IDM's own self-check flag right before it
#        starts pulling bytes:
#
#            83 3D A0 93 78 00 00   cmp dword [0x7893A0], 0   ; damage flag
#            74 0D                  je   -> continue the download
#            E8 9A D2 00 00         call 0xA8E20               ; raise the dialog
#
#        0xA8E20 is the dialog itself: it counts down the "Continue
#        downloading (n)" button and then dispatches on the current language
#        through jump table 0x4A8DB0 - all fifteen cases are the same
#        "main IDM executive file is damaged" message in fifteen languages.
#        The flag it tests has exactly one writer (0x9A5F0: mov eax,1;
#        mov [0x7893A0],eax - one arm of the runtime dispatcher) and exactly
#        one reader, this cmp. Replacing the test with `EB 14`
#        (jmp -> 0x9BB8E) puts the download on the same path a clean flag
#        would have taken, so the dialog has no way in from anywhere.
#
# Sites 1 and 2 are replaced at the prologue, before any stack frame is
# allocated, so neither touches ESP, EBP or any callee-saved register on the
# way out. The caller's stack stays balanced and the return value lands in
# EAX, which is exactly what the callers read. The rest of each original body
# becomes dead code behind the ret and is never reached. Sites 3 and 5 change
# one branch each and site 4 changes one string: no register, no stack slot,
# no global, no flag.
#
# Writing the five original signatures back over a patched file reproduces the
# pristine sha256 byte for byte - the patch provably touches nothing else.
#
# Exit codes:
#   0  patched, already clean, or fast-path confirmed
#   1  access denied (not elevated)
#   2  target missing, not a PE, or not an i386 image
#   3  target locked (IDM running)
#   4  dark: signature missing or ambiguous on this build
#   5  verify/swap failure (file left on disk untouched)

[CmdletBinding()]
param(
    [string]$Target,
    [string]$StateDir,
    [switch]$Restore,
    [switch]$DryRun,
    [switch]$Force,
    [int]$WaitForExitSeconds = 0,
    [switch]$Quiet
)

$ErrorActionPreference = 'Stop'

$Script:ExitOk       = 0
$Script:ExitDenied   = 1
$Script:ExitNoTarget = 2
$Script:ExitLocked   = 3
$Script:ExitDark     = 4
$Script:ExitVerify   = 5

$Script:PristineSha = 'E3FC655A335E17A6FDD09A9B315291D0C8863180F0D801E5DD7433C9E56AFBD8'
$Script:PatchedSha  = '3406A8105779F5BFAE41A05A2349306FBBCE2D8546CF3DC83F63AA9256B4CABD'

if (-not $Target) {
    $Target = Join-Path ${env:ProgramFiles(x86)} 'Internet Download Manager\IDMan.exe'
}
if (-not $StateDir) {
    $StateDir = Join-Path $env:ProgramData 'IdmPatch'
}

# Identity of each site.
#
#   Offset  known file offset on the pristine build (exact tier)
#   Section PE section the signature is scanned in (shape tier)
#   Sig     byte signature that is unique inside that section (shape tier)
#   Patch   replacement bytes, written over the first bytes of Sig
#
# Sig is deliberately cut before the SEH handler's `push imm32` on sites 1 and
# 2: that immediate is an absolute address, relocated by the loader, so it is
# the one part of the prologue that is not a stable cross-build identity. Disk
# bytes are the unrelocated form and are identical on every machine for a given
# build. Sites 3 and 4 are literal data - a branch byte and a UTF-16 string -
# so neither has a relocation in it either. Site 5's signature is the damage
# flag's absolute address plus a short-jump byte: no relative call, no
# relocated immediate, nothing that moves when the surrounding code does.
$Sites = @(
    [pscustomobject]@{
        Name    = 'startup_validator'
        Label   = 'startup validator -> status 0 (clean)'
        Offset  = 0x04FF40
        Section = '.text'
        Sig     = '558dac24dcfbffff81ec240400006aff6870'
        Patch   = '31c0c3'
    },
    [pscustomobject]@{
        Name    = 'nag_exit_gate'
        Label   = 'nag / exit gate -> return 1 (continue)'
        Offset  = 0x04C2F0
        Section = '.text'
        Sig     = '558dac249cf7ffff81ec640800'
        Patch   = 'B801000000C3'
    },
    [pscustomobject]@{
        Name    = 'about_version_full'
        Label   = 'About version suffix -> always "Full" (was "Trial")'
        Offset  = 0x002DD6
        Section = '.text'
        #   39 1D 24 BD 77 00   cmp dword [0x77BD24], ebx
        #   74 07               je   -> push "Full"
        #   68 50 6E 69 00      push "Trial"
        #   EB 05               jmp  -> past "Full"
        #   68 48 6E 69 00      push "Full"
        Sig     = '740768506E6900EB0568486E6900'
        Patch   = 'EB07'
    },
    [pscustomobject]@{
        Name    = 'about_licensee_text'
        Label   = 'About licensee line -> "Registered Version" (was "Unregistered Version")'
        Offset  = 0x38DB5C
        Section = '.rsrc'
        # UTF-16, 20 characters plus terminator, both strings. The resource
        # parser advances to the next dialog item off the terminator, so the
        # replacement must be exactly the length of the original.
        Sig     = '55006e0072006500670069007300740065007200650064002000560065007200730069006f006e000000'
        Patch   = '52006500670069007300740065007200650064002000560065007200730069006f006e00200020000000'
    },
    [pscustomobject]@{
        Name    = 'damaged_dialog_gate'
        Label   = 'download self-check gate -> skip the "damaged file" dialog'
        Offset  = 0x09AF78
        Section = '.text'
        #   83 3D A0 93 78 00 00   cmp dword [0x7893A0], 0   ; self-check flag
        #   74 0D                  je   -> continue the download
        #   E8 9A D2 00 00         call 0xA8E20               ; raise the dialog
        # The cmp is the flag's only reader; EB 14 jumps straight past the
        # call to the same continue-path a clean flag already took.
        Sig     = '833DA093780000740D'
        Patch   = 'EB14'
    }
)

function Write-Note {
    param([string]$Message, [string]$Color = 'Gray')
    if (-not $Quiet) { Write-Host $Message -ForegroundColor $Color }
}

function Resolve-NativeCli {
    param([string]$CliPath, [string]$EngineDir)
    foreach ($c in @($CliPath,
                     (Join-Path $EngineDir 'IdmCli.cs'),
                     (Join-Path $PSScriptRoot 'IdmCli.cs'))) {
        if ($c -and (Test-Path -LiteralPath $c)) { return (Resolve-Path -LiteralPath $c).Path }
    }
    return $null
}

function Read-State {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { return $null }
    try {
        $raw = Get-Content -LiteralPath $Path -Raw -ErrorAction Stop
        if ([string]::IsNullOrWhiteSpace($raw)) { return $null }
        return $raw | ConvertFrom-Json -ErrorAction Stop
    } catch {
        Write-Note "  [!] state.json unreadable ($($_.Exception.Message)) - ignoring" 'Yellow'
        return $null
    }
}

function Save-State {
    param([string]$Path, [hashtable]$Data)
    $tmp = "$Path.tmp"
    ($Data | ConvertTo-Json -Depth 6) | Set-Content -LiteralPath $tmp -Encoding UTF8 -ErrorAction Stop
    Move-Item -LiteralPath $tmp -Destination $Path -Force -ErrorAction Stop
}

function Test-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $p  = New-Object Security.Principal.WindowsPrincipal($id)
    return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# A running image is held open by the loader and cannot be opened for write.
function Test-FileWritable {
    param([string]$Path)
    try {
        $fs = [System.IO.File]::Open($Path, [System.IO.FileMode]::Open,
              [System.IO.FileAccess]::Write, [System.IO.FileShare]::Read)
        $fs.Close(); $fs.Dispose()
        return $true
    } catch { return $false }
}

function Wait-TargetExit {
    param([int]$Seconds)
    if ($Seconds -le 0) { return }
    $deadline = (Get-Date).AddSeconds($Seconds)
    while ((Get-Date) -lt $deadline) {
        if (-not (Get-Process -Name 'IDMan' -ErrorAction SilentlyContinue)) { return }
        Start-Sleep -Milliseconds 400
    }
}

function Copy-ItemSafe {
    param([string]$From, [string]$To)
    Copy-Item -LiteralPath $From -Destination $To -Force -ErrorAction Stop
    $a = (Get-FileHash -LiteralPath $From -Algorithm SHA256).Hash
    $b = (Get-FileHash -LiteralPath $To   -Algorithm SHA256).Hash
    if ($a -ne $b) { throw "backup hash mismatch: $From -> $To" }
}

function Find-Backup {
    param([string]$Dir)
    if (-not (Test-Path -LiteralPath $Dir)) { return $null }
    # identify the backup by hash, never by filename - any name is acceptable
    $cands = Get-ChildItem -LiteralPath $Dir -File -ErrorAction SilentlyContinue |
             Sort-Object LastWriteTimeUtc -Descending
    foreach ($c in $cands) {
        if ((Get-FileHash -LiteralPath $c.FullName -Algorithm SHA256).Hash -eq $Script:PristineSha) {
            return $c.FullName
        }
    }
    return $null
}

# A failure to write has two distinct causes and they are not interchangeable:
# close IDM, or elevate. Diagnose from the file, not from who we are - a target
# the caller can already write needs no elevation at all.
function Assert-Writable {
    param([string]$Path)
    if (Test-FileWritable -Path $Path) { return }
    $running = Get-Process -Name 'IDMan' -ErrorAction SilentlyContinue
    if ($running) {
        Write-Host "  [x] IDMan.exe is locked (PID $($running.Id)) - close Internet Download Manager first" -ForegroundColor Red
        exit $Script:ExitLocked
    }
    if (-not (Test-Admin)) {
        Write-Host "  [x] run elevated (right-click -> Run as administrator)" -ForegroundColor Red
        exit $Script:ExitDenied
    }
    Write-Host "  [x] IDMan.exe is locked by another process" -ForegroundColor Red
    exit $Script:ExitLocked
}

# ---------------------------------------------------------------------------
# preflight
# ---------------------------------------------------------------------------
if (-not $Target -or -not (Test-Path -LiteralPath $Target)) {
    Write-Host "  [x] target not found: $Target" -ForegroundColor Red
    Write-Note "      install IDM first, or pass -Target <path-to-IDMan.exe>" 'DarkGray'
    exit $Script:ExitNoTarget
}

$Target = (Resolve-Path -LiteralPath $Target).Path
New-Item -ItemType Directory -Path $StateDir -Force -ErrorAction SilentlyContinue | Out-Null
$StatePath = Join-Path $StateDir 'state.json'
$backup    = Join-Path $StateDir 'IDMan.exe.orig'
$darkNotifiedPath = Join-Path $StateDir 'dark-notified.json'

# ---------------------------------------------------------------------------
# restore
# ---------------------------------------------------------------------------
if ($Restore) {
    $src = Find-Backup -Dir $StateDir
    if (-not $src) {
        Write-Host "  [x] no pristine backup found in $StateDir" -ForegroundColor Red
        exit $Script:ExitNoTarget
    }
    Assert-Writable -Path $Target
    try {
        Copy-ItemSafe -From $src -To $Target
    } catch {
        Write-Host "  [x] restore failed: $($_.Exception.Message)" -ForegroundColor Red
        exit $Script:ExitVerify
    }
    $h = (Get-FileHash -LiteralPath $Target -Algorithm SHA256).Hash
    if ($h -ne $Script:PristineSha) {
        Write-Host "  [x] restored file does not hash to the pristine build" -ForegroundColor Red
        exit $Script:ExitVerify
    }
    if (Test-Path -LiteralPath $StatePath) { Remove-Item -LiteralPath $StatePath -Force -ErrorAction SilentlyContinue }
    if (Test-Path -LiteralPath $darkNotifiedPath) { Remove-Item -LiteralPath $darkNotifiedPath -Force -ErrorAction SilentlyContinue }
    Write-Host "  [ok] original IDMan.exe restored ($($h.Substring(0,16))...)" -ForegroundColor Green
    exit $Script:ExitOk
}

# ---------------------------------------------------------------------------
# fast path: already at the hash this engine last confirmed good
#
# Two conditions, not one. lastGoodSha alone is not enough: a state.json written
# by an older engine records the hash of *its* patch set, and a newer engine
# with more sites would see that hash match, declare "already patched", and
# never apply the sites it added. Requiring the state's target hash to be this
# engine's own makes a stale state fall through to a real run instead.
# ---------------------------------------------------------------------------
$curSha = (Get-FileHash -LiteralPath $Target -Algorithm SHA256).Hash
$state  = Read-State -Path $StatePath

$stateIsCurrent = $state -and
                  $state.patchedSha -and
                  $state.patchedSha -eq $Script:PatchedSha

if ($stateIsCurrent -and $state.lastGoodSha -and -not $Force -and $state.lastGoodSha -eq $curSha) {
    Write-Host "  [fast] already patched, hash confirmed ($($curSha.Substring(0,16))...)" -ForegroundColor Green
    exit $Script:ExitOk
}
if ($state -and $state.lastGoodSha -and $state.lastGoodSha -eq $curSha -and -not $stateIsCurrent) {
    Write-Note "  [i] state.json is from an older patch set - re-checking all sites" 'DarkGray'
}
if ($curSha -eq $Script:PristineSha -and -not $Force) {
    # pristine but state missing - fall through to a normal patch run
    Write-Note "  [i] pristine build detected - proceeding" 'DarkGray'
}

# ---------------------------------------------------------------------------
# lock / waiting
# ---------------------------------------------------------------------------
$running = Get-Process -Name 'IDMan' -ErrorAction SilentlyContinue
if ($running) {
    if ($WaitForExitSeconds -gt 0) {
        Write-Note "  [i] IDMan running (PID $($running.Id)) - waiting up to ${WaitForExitSeconds}s" 'Yellow'
        Wait-TargetExit -Seconds $WaitForExitSeconds
        $running = Get-Process -Name 'IDMan' -ErrorAction SilentlyContinue
    }
    if ($running) {
        Write-Host "  [x] IDMan.exe is locked (PID $($running.Id)) - close IDM first" -ForegroundColor Red
        exit $Script:ExitLocked
    }
}
Assert-Writable -Path $Target

# ---------------------------------------------------------------------------
# load
# ---------------------------------------------------------------------------
$cliPath = Resolve-NativeCli -CliPath $null -EngineDir $PSScriptRoot
if (-not $cliPath) {
    Write-Host "  [x] IdmCli.cs not found next to IdmPatch.ps1" -ForegroundColor Red
    exit $Script:ExitNoTarget
}
if (-not ('IdmCli' -as [type])) {
    try {
        Add-Type -Path $cliPath -ErrorAction Stop
    } catch {
        Write-Host "  [x] cannot compile IdmCli.cs: $($_.Exception.Message)" -ForegroundColor Red
        exit $Script:ExitNoTarget
    }
}

$cli = New-Object IdmCli
try {
    $cli.Load($Target)
} catch {
    Write-Host "  [x] not a usable PE image: $($_.Exception.Message)" -ForegroundColor Red
    exit $Script:ExitNoTarget
}

if ($cli.Machine -ne 0x14C) {
    Write-Host ("  [x] expected an i386 image (0x14C), found 0x{0:X4}" -f $cli.Machine) -ForegroundColor Red
    exit $Script:ExitNoTarget
}

$onDisk = $cli.ShaRange(0, [int]$cli.Length)

# ---------------------------------------------------------------------------
# classify every site (all-or-nothing)
# ---------------------------------------------------------------------------
if (-not $Quiet) {
    Write-Host "  target : $Target"
    Write-Host ("  size   : {0:N0} bytes  machine: 0x{1:X4}  base: 0x{2:X8}" -f $cli.Length, $cli.Machine, $cli.ImageBase)
    foreach ($l in $cli.Lines) { Write-Note "           $l" 'DarkGray' }
    Write-Host ("  sha256 : {0}" -f $onDisk)
    Write-Host ""
}

$plan       = @()
$alreadyAll = $true
$dark       = @()
$seenOffset = @{}

foreach ($site in $Sites) {
    $entry = [ordered]@{
        name   = $site.Name
        label  = $site.Label
        offset = $null
        tier   = $null
        before = $null
        after  = $site.Patch.ToLower()
        hits   = 0
    }

    # tier 0: this exact byte pattern is already in place at the known offset
    if ($cli.RegionEquals($site.Offset, $site.Patch)) {
        $entry.offset = $site.Offset
        $entry.tier   = 'already'
        $entry.before = $site.Patch.ToLower()
        $entry.hits   = 1
        $plan += [pscustomobject]$entry
        continue
    }
    $alreadyAll = $false

    $sigHex = $site.Sig.ToLower()
    $hits   = $cli.FindInSection($site.Section, $sigHex)
    if ($hits.Length -eq 1 -and $hits[0] -eq -1) {
        $dark += "$($site.Name): section $($site.Section) not present"
        break
    }
    $entry.hits = $hits.Length

    # tier 1: pristine layout - known offset, signature must be sitting on it
    if ($onDisk -eq $Script:PristineSha) {
        if ($hits.Length -eq 1 -and $hits[0] -eq $site.Offset) {
            $entry.offset = $site.Offset
            $entry.tier   = 'exact'
        } else {
            $dark += "$($site.Name): pristine build but signature at $($hits -join ','), expected $($site.Offset)"
        }
    } else {
        # tier 2: a different build - accept the signature only if it is unique
        if ($hits.Length -eq 1) {
            $entry.offset = $hits[0]
            $entry.tier   = 'shape'
        } elseif ($hits.Length -eq 0) {
            $dark += "$($site.Name): signature not found in $($site.Section) (build changed)"
        } else {
            $dark += "$($site.Name): signature ambiguous - $($hits.Count) hits at $($hits | ForEach-Object { '0x{0:X}' -f $_ })"
        }
    }

    if ($entry.offset -ne $null -and $seenOffset.ContainsKey($entry.offset)) {
        $dark += "$($site.Name): offset collides with $($seenOffset[$entry.offset])"
    } elseif ($entry.offset -ne $null) {
        $seenOffset[$entry.offset] = $site.Name
    }

    if ($entry.tier) {
        $entry.before = $cli.ReadHex($entry.offset, $site.Patch.Length / 2)
        $plan += [pscustomobject]$entry
    }
}

if ($alreadyAll -and $plan.Count -eq $Sites.Count) {
    if (-not $state -or $state.lastGoodSha -ne $onDisk) {
        Save-State -Path $StatePath -Data @{
            version        = 1
            target         = $Target
            lastGoodSha    = $onDisk
            patchedSha     = $Script:PatchedSha
            patchedOffsets = @($Sites | ForEach-Object { '0x{0:X}' -f $_.Offset })
            patchedBytes   = ($Sites | ForEach-Object { $_.Patch.Length / 2 } | Measure-Object -Sum).Sum
            tier           = 'already'
            lastRunUtc     = (Get-Date).ToUniversalTime().ToString('o')
        }
    }
    Write-Host "  [ok] already patched - all $($Sites.Count) sites in place" -ForegroundColor Green
    exit $Script:ExitOk
}

if ($dark.Count -gt 0) {
    Write-Host "  [x] refusing: signature does not match this build" -ForegroundColor Red
    foreach ($d in $dark) { Write-Host "      - $d" -ForegroundColor Red }
    Write-Note "      nothing was written - file left untouched" 'DarkGray'

    $notified = Read-State -Path $darkNotifiedPath
    if (-not $notified -or $notified.sha -ne $onDisk) {
        Save-State -Path $darkNotifiedPath -Data @{
            sha        = $onDisk
            firstSeen  = (Get-Date).ToUniversalTime().ToString('o')
            problems   = @($dark)
        }
        if (-not $Quiet) {
            Write-Host ""
            Write-Host "  [!] IDM build not recognised - one notice per build (state in $StateDir)" -ForegroundColor Yellow
        }
    }
    exit $Script:ExitDark
}

# ---------------------------------------------------------------------------
# report plan
# ---------------------------------------------------------------------------
if (-not $Quiet) {
    foreach ($e in $plan) {
        Write-Host ("  {0,-18} {1,-6} @ 0x{2:X6}  {3} -> {4}" -f `
            $e.name, $e.tier, $e.offset, $e.before, $e.after)
    }
    Write-Host ""
}

if ($DryRun) {
    Write-Host "  [dry] no changes written" -ForegroundColor Yellow
    exit $Script:ExitOk
}

# ---------------------------------------------------------------------------
# backup (only when the target is still the pristine build)
# ---------------------------------------------------------------------------
if (-not (Test-Path -LiteralPath $backup) -or
    (Get-FileHash -LiteralPath $backup -Algorithm SHA256).Hash -ne $Script:PristineSha) {
    New-Item -ItemType Directory -Path $StateDir -Force -ErrorAction SilentlyContinue | Out-Null
    try {
        Copy-ItemSafe -From $Target -To $backup
        Write-Note "  [i] pristine backup -> $backup" 'DarkGray'
    } catch {
        Write-Host "  [x] cannot write backup: $($_.Exception.Message)" -ForegroundColor Red
        exit $Script:ExitVerify
    }
}

# ---------------------------------------------------------------------------
# apply in memory, write to temp, verify, atomic swap
# ---------------------------------------------------------------------------
foreach ($site in $Sites) {
    $e = $plan | Where-Object { $_.name -eq $site.Name } | Select-Object -First 1
    if (-not $e) { exit $Script:ExitVerify }
    $cli.WriteBytes($e.offset, $site.Patch)
}

$expectedSha = $cli.BufferSha()
if ($expectedSha -ne $Script:PatchedSha -and $onDisk -eq $Script:PristineSha) {
    Write-Host "  [x] in-memory image does not hash to the expected patched build" -ForegroundColor Red
    Write-Note "      expected $($Script:PatchedSha)" 'DarkGray'
    Write-Note "      got      $expectedSha" 'DarkGray'
    exit $Script:ExitVerify
}

$temp = "$Target.idmpatch.tmp"
try {
    $cli.Save($temp)
} catch {
    Write-Host "  [x] cannot write temp file: $($_.Exception.Message)" -ForegroundColor Red
    if (Test-Path -LiteralPath $temp) { Remove-Item -LiteralPath $temp -Force -ErrorAction SilentlyContinue }
    exit $Script:ExitVerify
}

try {
    $tempSha = (Get-FileHash -LiteralPath $temp -Algorithm SHA256).Hash
    if ($tempSha -ne $expectedSha) {
        throw "temp hash $tempSha != expected $expectedSha"
    }
    if ((Get-Item -LiteralPath $temp).Length -ne $cli.Length) {
        throw "temp size mismatch"
    }
} catch {
    Write-Host "  [x] post-write verification failed: $($_.Exception.Message)" -ForegroundColor Red
    Remove-Item -LiteralPath $temp -Force -ErrorAction SilentlyContinue
    exit $Script:ExitVerify
}

try {
    Move-Item -LiteralPath $temp -Destination $Target -Force -ErrorAction Stop
} catch {
    Write-Host "  [x] atomic swap failed: $($_.Exception.Message)" -ForegroundColor Red
    Remove-Item -LiteralPath $temp -Force -ErrorAction SilentlyContinue
    exit $Script:ExitVerify
}

$finalSha = (Get-FileHash -LiteralPath $Target -Algorithm SHA256).Hash
if ($finalSha -ne $expectedSha) {
    Write-Host "  [x] final file hash mismatch - restoring pristine" -ForegroundColor Red
    try {
        Copy-ItemSafe -From $backup -To $Target
    } catch { }
    exit $Script:ExitVerify
}

Save-State -Path $StatePath -Data @{
    version        = 1
    target         = $Target
    lastGoodSha    = $finalSha
    pristineSha    = $Script:PristineSha
    patchedSha     = $Script:PatchedSha
    patchedOffsets = @($plan | ForEach-Object { '0x{0:X}' -f $_.offset })
    patchedBytes   = ($plan | ForEach-Object { $_.after.Length / 2 } | Measure-Object -Sum).Sum
    tier           = ($plan | ForEach-Object { $_.tier } | Select-Object -Unique) -join ','
    lastRunUtc     = (Get-Date).ToUniversalTime().ToString('o')
}
if (Test-Path -LiteralPath $darkNotifiedPath) {
    Remove-Item -LiteralPath $darkNotifiedPath -Force -ErrorAction SilentlyContinue
}

$patchedTotal = ($plan | ForEach-Object { $_.after.Length / 2 } | Measure-Object -Sum).Sum
Write-Host "  [ok] $($Sites.Count) sites patched, $patchedTotal bytes total" -ForegroundColor Green
Write-Note ("       sha256 {0}" -f $finalSha) 'DarkGray'
Write-Note "       next IDM update overwrites the binary - re-run patch-now.cmd" 'DarkGray'
exit $Script:ExitOk
