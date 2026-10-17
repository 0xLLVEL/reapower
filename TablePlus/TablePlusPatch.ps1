# TablePlus — License Gate Patch (Windows x64)
#
# Patches two license gates inside TablePlus.exe in place, without touching the
# metadata tables at all:
#
#   1) TablePlus.Source.Service.LicenseService::IsLicensed
#        original IL : 02 7B F6 13 00 04 2A   (ldarg.0; ldfld isValidLicense; ret)
#        new IL      : 17 2A                  (ldc.i4.1; ret)
#
#   2) TablePlus.Source.Service.LicenseService::get_DayBeforeExpiration
#        original IL : 02 7B F7 13 00 04 6F 35 43 00 06 2A
#        new IL      : 20 0F 27 00 00 2A       (ldc.i4 9999; ret)
#
# This script is built to run REPEATEDLY (scheduled task) after a TablePlus
# update. Decision order, per site:
#
#   1. method is located by NAME in the metadata (not by offset)   -> survives moves
#   2. SHA-256 of IL == patched value  -> already patched, skip
#   3. SHA-256 of IL == pristine value -> patch it (tier "exact")
#   4. opcode shape still matches      -> patch it (tier "shape": TablePlus
#                                         recompiled, field/token shifted)
#   5. anything else                   -> NOT touched, recorded + notified
#
# If the declaring type disappears there is a safety net: every method sharing
# the same short name whose shape matches gets patched (tier "fuzzy").

[CmdletBinding()]
param(
    [string]$Target = "C:\Program Files\TablePlus\TablePlus.exe",
    [switch]$DryRun,
    [switch]$Restore,
    [string]$BackupDir,
    [int]$WaitForExitSeconds = 0,
    [switch]$Force,
    [switch]$NoNotify
)

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

# -1 = wildcard
$script:Site = @(
    @{
        Name          = "TablePlus.Source.Service.LicenseService::IsLicensed"
        Simple        = "IsLicensed"
        Namespace     = "TablePlus.Source.Service"
        Label         = "IsLicensed"
        Pristine      = "f951d7b7ac40545b9d0d4a899003d5314fd99b8951f4ba22e9f94f4386ca03aa"
        Patched       = "3e652f9ec0ddcdd64c52c9cba261a1f70bba3ffa41ff4296d6eba45e6514b378"
        Il            = [byte[]](0x17, 0x2A)
        Shapes        = @(, [int[]](0x02, 0x7B, -1, -1, -1, -1, 0x2A))            # ldarg.0; ldfld; ret
        PatchedShapes = @(, [int[]](0x17, 0x2A))                                  # ldc.i4.1; ret
    },
    @{
        Name          = "TablePlus.Source.Service.LicenseService::get_DayBeforeExpiration"
        Simple        = "get_DayBeforeExpiration"
        Namespace     = "TablePlus.Source.Service"
        Label         = "get_DayBeforeExpiration"
        Pristine      = "0a8887382ffd440d314c339ecf298d6c1d552318e806e459f6c393a76383271f"
        Patched       = "f9b9a361ce548af8ab6c7e145721799dc9255eb732d964832d92b9034b85496a"
        Il            = [byte[]](0x20, 0x0F, 0x27, 0x00, 0x00, 0x2A)              # ldc.i4 9999 ; ret
        Shapes        = @(
                            [int[]](0x02, 0x7B, -1, -1, -1, -1, 0x6F, -1, -1, -1, -1, 0x2A),  # ldarg.0; ldfld; callvirt; ret
                            [int[]](0x02, 0x7B, -1, -1, -1, -1, 0x2A)                         # ldarg.0; ldfld; ret
                        )
        PatchedShapes = @(, [int[]](0x20, -1, -1, -1, -1, 0x2A))                  # ldc.i4 imm32 ; ret
    }
)

function Write-Line([string]$text, [string]$color = "Gray") {
    Write-Host $text -ForegroundColor $color
}

function Test-Shape([byte[]]$il, $shapes) {
    foreach ($s in $shapes) {
        if ($il.Length -ne $s.Length) { continue }
        $ok = $true
        for ($i = 0; $i -lt $s.Length; $i++) {
            if ($s[$i] -ge 0 -and $il[$i] -ne $s[$i]) { $ok = $false; break }
        }
        if ($ok) { return $true }
    }
    return $false
}

function Get-BytesHex([byte[]]$b) { ($b | ForEach-Object { "{0:X2}" -f $_ }) -join "" }

function Notify([string]$text) {
    if ($NoNotify -or -not [Environment]::UserInteractive) { return }
    try {
        Add-Type -AssemblyName System.Windows.Forms -ErrorAction Stop
        [void][System.Windows.Forms.MessageBox]::Show($text, "TablePlus License Patch", "OK", "Warning")
    } catch {
        try { & msg.exe $env:USERNAME $text 2>$null } catch { }
    }
}

function Read-State {
    $s = @{ lastGood = ""; warned = @(); when = "" }
    if (Test-Path -LiteralPath $stateFile) {
        try {
            $j = Get-Content -LiteralPath $stateFile -Raw | ConvertFrom-Json
            if ($j.lastGood) { $s.lastGood = [string]$j.lastGood }
            if ($j.warned)   { $s.warned   = @($j.warned) }
        } catch { }
    }
    return $s
}
function Write-State($s) {
    $s.when = (Get-Date).ToString("s")
    $s | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $stateFile -Encoding UTF8 -ErrorAction SilentlyContinue
}

function Warn-Once {
    # Keyed per-SITE (label + reason / unknown IL hash), not per file SHA:
    # after a TablePlus update the file SHA changes even when the problem is the same.
    $keys = @()
    foreach ($u in $unknown) { $keys += $u }
    $st = Read-State
    $prev = @($st.warned)
    $fresh = @($keys | Where-Object { $prev -notcontains $_ })
    if ($fresh.Count -eq 0) {
        Write-Line "  (warning for this build was already sent - not repeated)" DarkGray
        return
    }
    $all = @($prev + $fresh)
    if ($all.Count -gt 50) { $all = $all[($all.Count - 50)..($all.Count - 1)] }
    $st.warned = $all
    Write-State $st
    $txt = "TablePlus was updated and its license gate can NOT be patched automatically yet.`r`n`r`n" +
           "build  : " + $shaBefore + "`r`n" +
           "target : " + $Target + "`r`n`r`n" +
           ($fresh -join "`r`n") + "`r`n`r`n" +
           "Details: TablePlusPatch.ps1 -DryRun"
    Notify $txt
    Write-Line ("  [!] " + $fresh.Count + " dark site(s) - notification sent") Red
}

# ---------------------------------------------------------------- preflight
if (-not (Test-Path -LiteralPath $Target)) {
    Write-Line "  target not found: $Target" Red
    exit 2
}
$Target = (Resolve-Path -LiteralPath $Target).Path
if (-not $BackupDir) { $BackupDir = Split-Path -Parent $Target }
New-Item -ItemType Directory -Force -Path $BackupDir | Out-Null
$stateFile = Join-Path $BackupDir "state.json"

# ---------------------------------------------------------------- restore
if ($Restore) {
    $cands = @()
    if (Test-Path -LiteralPath "$Target.bak") { $cands += "$Target.bak" }
    $cands += (Join-Path $BackupDir "backup\TablePlus.exe.orig")
    $src = $cands | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
    if (-not $src) { Write-Line "  no backup available" Red; exit 2 }
    if (Get-Process -Name TablePlus -ErrorAction SilentlyContinue) {
        Write-Line "  TablePlus is still running, close it first" Red; exit 3
    }
    Copy-Item -LiteralPath $src -Destination $Target -Force
    Write-Line ("  restored from " + $src) Green
    Write-Line ("  SHA256 = " + (Get-FileHash -LiteralPath $Target -Algorithm SHA256).Hash)
    exit 0
}

$shaBefore = (Get-FileHash -LiteralPath $Target -Algorithm SHA256).Hash

# ---------------------------------------------------------------- fast path
# If the file on disk is byte-identical to the last patch result there is no need
# to read 156 MB of metadata - one SHA-256 is enough. This is what makes the
# 10-minute poll cheap, and what keeps a running TablePlus from having to be waited on.
if (-not $DryRun -and -not $Force) {
    $st = Read-State
    if ($st.lastGood -eq $shaBefore) {
        Write-Line ("  already clean (fast path, sha " + $shaBefore.Substring(0,16) + ") - done") Green
        exit 0
    }
}

# ---------------------------------------------------------------- live process?
$proc = Get-Process -Name TablePlus -ErrorAction SilentlyContinue
if ($proc) {
    if ($WaitForExitSeconds -gt 0) {
        Write-Line ("  TablePlus running (PID " + (($proc | ForEach-Object { $_.Id }) -join ",") + "), waiting up to $WaitForExitSeconds s...") Yellow
        $deadline = (Get-Date).AddSeconds($WaitForExitSeconds)
        while ((Get-Process -Name TablePlus -ErrorAction SilentlyContinue) -and (Get-Date) -lt $deadline) { Start-Sleep -Milliseconds 500 }
    }
    if (Get-Process -Name TablePlus -ErrorAction SilentlyContinue) {
        Write-Line "  TablePlus is still running - file is locked." Red
        exit 3
    }
}

# ---------------------------------------------------------------- load
if (-not ("TPCli" -as [type])) {
    Add-Type -Path (Join-Path $PSScriptRoot "TPCli.cs") -ErrorAction Stop
}
$cli = New-Object TPCli
$cli.Load($Target)
Write-Line ""
Write-Line "TablePlus license gate patch"
Write-Line ("  target : " + $Target)
Write-Line ("  size   : {0:n0} bytes" -f (Get-Item -LiteralPath $Target).Length)
Write-Line ("  method : {0:n0}" -f $cli.Count)
Write-Line ("  sha256 : " + $shaBefore)
Write-Line ""

# ---------------------------------------------------------------- classification
$plan    = @()
$unknown = @()
$already = 0
$pristineSeen = $false

foreach ($s in $script:Site) {
    Write-Line ("  " + $s.Name) White

    $row = $cli.FindRow($s.Name)
    $tier = "exact"

    if ($row -lt 0) {
        # safety net: same short name under any declaring type
        $seen = @()
        foreach ($r in $cli.FindRowsByName($s.Simple)) {
            $ilx = $cli.IlBytes($r)
            if (Test-Shape $ilx $s.Shapes) { $seen += $r }
            elseif (Test-Shape $ilx $s.PatchedShapes) { $seen += ("p:" + $r) }
        }
        $doneHit = $seen | Where-Object { "$_" -like "p:*" }
        if ($doneHit) {
            $already++
            Write-Line ("      already patched (fuzzy) at " + $cli.NameOf(([string]$doneHit[0]).Substring(2))) Green
            continue
        }
        $seen = @($seen | Where-Object { "$_" -notlike "p:*" })
        if ($seen.Count -gt 1) {
            # more than one candidate: narrow to the same namespace first
            $nsPref = $s.Namespace + "."
            $narrow = @($seen | Where-Object { $cli.NameOf([int]$_).StartsWith($nsPref) })
            if ($narrow.Count -eq 1) { $seen = $narrow }
        }
        if ($seen.Count -eq 1) {
            $row = [int]$seen[0]
            $tier = "fuzzy"
            Write-Line ("      declaring type changed -> found as " + $cli.NameOf($row)) Yellow
        } else {
            Write-Line "      method not found" Yellow
            $unknown += $s.Label + " (method not found)"
            continue
        }
    }

    $il    = $cli.IlBytes($row)
    $cur   = $cli.IlSha($row)
    Write-Line ("      rva 0x{0:X8}  body 0x{1:X}  il@0x{2:X}  ilSize {3}" -f $cli.Rva($row), $cli.BodyStart($row), $cli.IlStart($row), $il.Length)
    Write-Line ("      current IL  : " + (Get-BytesHex $il)) DarkGray

    if ($cur -eq $s.Patched) {
        Write-Line "      already patched (hash) - skipped" Green
        $already++
        continue
    }
    if ($cur -ne $s.Pristine -and (Test-Shape $il $s.PatchedShapes)) {
        Write-Line "      already patched (shape) - skipped" Green
        $already++
        continue
    }
    if ($cur -ne $s.Pristine) {
        if (Test-Shape $il $s.Shapes) {
            $tier = "shape"
            Write-Line "      IL differs from this release but shape matches -> tier shape" Yellow
        } else {
            Write-Line "      unknown IL (shape differs too) - NOT touched" Red
            Write-Line ("      sha = " + $cur) Red
            $unknown += $s.Label + " (unknown IL)"
            continue
        }
    }

    $pristineSeen = $true
    Write-Line ("      new IL      : " + (Get-BytesHex $s.Il) + "   [" + $tier + "]") Cyan
    $plan += @{ Site = $s; Row = $row; NewIl = $s.Il; Tier = $tier }
}

Write-Line ""

# ---------------------------------------------------------------- decision
if ($DryRun) {
    Write-Line ("  DRY RUN: {0} to patch, {1} already patched, {2} unknown" -f $plan.Count, $already, $unknown.Count) Yellow
    foreach ($u in $unknown) { Write-Line ("    [!] " + $u) Red }
    exit 0
}
if ($plan.Count -eq 0) {
    if ($unknown.Count -gt 0) {
        # partially dark: do NOT record lastGood, so every cycle keeps rescanning
        Write-Line ("  nothing patchable, {0} dark site(s)" -f $unknown.Count) Red
        Warn-Once
        exit 4
    }
    $st = Read-State
    $st.lastGood = $shaBefore
    Write-State $st
    Write-Line "  already clean - nothing changed" Green
    exit 0
}

# ---------------------------------------------------------------- backup
# The backup is refreshed only when this file is still a vendor build (a site was pristine).
# So when TablePlus updates, .orig follows the new version automatically - not the old one.
$origDir = Join-Path $BackupDir "backup"
New-Item -ItemType Directory -Force -Path $origDir | Out-Null
$orig = Join-Path $origDir "TablePlus.exe.orig"
if ($pristineSeen) {
    Copy-Item -LiteralPath $Target -Destination $orig -Force
    Add-Content -LiteralPath (Join-Path $BackupDir "versions.txt") -Value (
        "{0}  sha256={1}  size={2}" -f (Get-Date).ToString("yyyy-MM-dd HH:mm:ss"), $shaBefore, (Get-Item -LiteralPath $Target).Length
    ) -ErrorAction SilentlyContinue
    Write-Line ("  vendor build backed up -> " + $orig) Green
}
if (-not (Test-Path -LiteralPath "$Target.bak")) {
    Copy-Item -LiteralPath $Target -Destination "$Target.bak" -Force
    Write-Line ("  in-place backup       -> " + "$Target.bak") DarkGray
}

# ---------------------------------------------------------------- apply
foreach ($p in $plan) {
    if (-not $cli.PatchIl($p.Row, $p.NewIl)) {
        Write-Line ("  FAILED to patch " + $p.Site.Label) Red
        exit 5
    }
    Write-Line ("  patched [{0}]: {1}" -f $p.Tier, $p.Site.Label) Green
}

$tmp = "$Target.tp-new"
$cli.Save($tmp)
Move-Item -LiteralPath $tmp -Destination $Target -Force

$shaAfter = (Get-FileHash -LiteralPath $Target -Algorithm SHA256).Hash
$st = Read-State
$st.lastGood = $shaAfter
Write-State $st
Write-Line ""
Write-Line ("  sha256 before : " + $shaBefore)
Write-Line ("  sha256 after  : " + $shaAfter)
Write-Line ("  {0} patched, {1} skipped, {2} dark" -f $plan.Count, $already, $unknown.Count) Green

try {
    Add-Content -LiteralPath (Join-Path $BackupDir "tableplus-patch.log") -Value (
        "{0}  {1}  before={2}  after={3}  patched={4}  skipped={5}  unknown={6}" -f
        (Get-Date).ToString("yyyy-MM-dd HH:mm:ss"), $Target, $shaBefore, $shaAfter, $plan.Count, $already, $unknown.Count
    ) -ErrorAction SilentlyContinue
} catch { }

if ($unknown.Count -gt 0) { Warn-Once }
exit 0
