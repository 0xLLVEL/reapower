# MAMP PRO - License Gate Patch (Windows x64)
#
# Patches four method bodies inside C:\MAMPPRO\net\MAMPPRO.dll in place, without
# touching any metadata table, heap or stream:
#
#   1) MAMPPRO4.App::CheckDataForStartup            (FAT, 1436 B, has EH)
#        original IL : 1436 bytes of trial/demo/expired gating
#        new IL      : 02 6F <StartApp> 2A   (ldarg.0; callvirt StartApp; ret, 7 B)
#
#   2) MAMPPRO4.Utility.AppUtility::IsBought         (FAT, 24 B)
#        original IL : newobj InitDataCache ... bne.un.s ... ldc.i4.1/0; ret
#        new IL      : 17 2A                 (ldc.i4.1; ret)
#
#   3) MAMPPRO4.Views.ControlPanel::MenuItem_Click_2 (FAT, 189 B, has EH)
#        serial dialog trigger -> new IL: 2A (ret)
#
#   4) MAMPPRO4.Windows.ThreeButtonMessageBox::secbtn_Click_1 (FAT, 74 B)
#        serial dialog trigger 2 -> new IL: 02 14 28 <set_serialtext> 2A
#        (ldarg.0; ldnull; call set_serialtext; ret - reuses its own cancel tail)
#
# All four bodies are FAT: the replacement keeps the 12-byte header and the RVA,
# clears MoreSects (0x8) and InitLocals (0x10) - the new bodies have no EH section
# and no locals - keeps MaxStack, writes the new CodeSize, nulls LocalVarSigTok
# and zero-fills the surplus bytes of the old body.
#
# Decision order, per site (the matcher, TablePlus-style):
#
#   1. method found by NAME in the metadata               -> survives moves
#   2. SHA-256 of IL == patched value   -> already patched, skip
#   3. opcode shape == patched shape    -> already patched, skip
#   4. SHA-256 of IL == pristine value  -> patch (tier "exact")
#   5. opcode shape still matches       -> patch (tier "shape")
#   6. anything else                    -> NOT touched, recorded + notified
#
# Fail-hard: ANY dark site means NO site is written (exit 4). The four gates must
# end up patched as a set - a half-patched MAMP still shows the serial dialog.
#
# Module-wide gate: every `newobj` of an MAMPPRO4.EnterSerial::.ctor must belong
# to the two trigger methods (or EnterSerial::OK_Click for the argument ctor).
# A third construction site means another path opens the dialog -> refuse (exit 4).

[CmdletBinding()]
param(
    [string]$Target = "C:\MAMPPRO\net\MAMPPRO.dll",
    [string]$BackupDir = "C:\ProgramData\MampProPatch",
    [switch]$DryRun,
    [switch]$Restore,
    [int]$WaitForExitSeconds = 0,
    [switch]$Force,
    [switch]$NoNotify
)

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

function Sh([int[]]$p) { @{ Len = $p.Length; P = $p } }
function ShLen([int]$len, [int[]]$p) { @{ Len = $len; P = $p } }

# -1 = wildcard operand byte
$script:Site = @(
    @{
        Name          = "MAMPPRO4.App::CheckDataForStartup"
        Simple        = "CheckDataForStartup"
        Namespace     = "MAMPPRO4.App"
        Label         = "CheckDataForStartup (startup gate)"
        Callee        = "MAMPPRO4.App::StartApp"
        Opcode        = 0x6F                    # callvirt
        Prefix        = [byte[]](0x02, 0x6F)    # ldarg.0; <call>
        Suffix        = [byte[]](0x2A)
        Pristine      = "ea4e5d38ccc9badb79d150fd98753ccd6d2387f79c8df77367aab018ec002d96"
        Patched       = "20094782101e967ed71dc2c8c9677ab40d2b2929e0064d524c5215304273a4b4"
        Shapes        = @( (ShLen 1436 ([int[]](0x28, -1, -1, -1, -1, 0x13, -1, 0x12, -1,
                                              0x23, -1, -1, -1, -1, -1, -1, -1, -1, 0xC0))) )
        PatchedShapes = @( (Sh ([int[]](0x02, 0x6F, -1, -1, -1, -1, 0x2A))) )
        Trigger       = $false
    },
    @{
        Name          = "MAMPPRO4.Utility.AppUtility::IsBought"
        Simple        = "IsBought"
        Namespace     = "MAMPPRO4.Utility"
        Label         = "IsBought (bought flag)"
        Callee        = $null
        Opcode        = 0
        Prefix        = $null
        Suffix        = $null
        NewIlFixed    = [byte[]](0x17, 0x2A)
        Pristine      = "760df438c1348e92850e5cb966774778cfab357f27c16e4e90fdad65521ae295"
        Patched       = "3e652f9ec0ddcdd64c52c9cba261a1f70bba3ffa41ff4296d6eba45e6514b378"
        Shapes        = @( (Sh ([int[]](0x73, -1, -1, -1, -1, 0x14, 0x02, 0x6F, -1, -1, -1, -1,
                                       0x0A, 0x06, 0x2C, -1, 0x06, 0x1C, 0x33, -1, 0x17, 0x2A, 0x16, 0x2A))) )
        PatchedShapes = @( (Sh ([int[]](0x17, 0x2A))) )
        Trigger       = $false
    },
    @{
        Name          = "MAMPPRO4.Views.ControlPanel::MenuItem_Click_2"
        Simple        = "MenuItem_Click_2"
        Namespace     = "MAMPPRO4.Views"
        Label         = "MenuItem_Click_2 (dialog trigger 1)"
        Callee        = $null
        Opcode        = 0
        Prefix        = $null
        Suffix        = $null
        NewIlFixed    = [byte[]](0x2A)
        Pristine      = "d9aee0f8fa157fd2b269be9e119d58ff286f7dd022fb1536ee1309ccde75ed96"
        Patched       = "684888c0ebb17f374298b65ee2807526c066094c701bcc7ebbe1c1095f494fc1"
        Shapes        = @( (ShLen 189 ([int[]](0x73, -1, -1, -1, -1, 0x0A, 0x06, 0x6F, -1, -1, -1, -1,
                                              0x26, 0x06, 0x6F, -1, -1, -1, -1, 0x39))) )
        PatchedShapes = @( (Sh ([int[]](0x2A))) )
        Trigger       = $true
    },
    @{
        Name          = "MAMPPRO4.Windows.ThreeButtonMessageBox::secbtn_Click_1"
        Simple        = "secbtn_Click_1"
        Namespace     = "MAMPPRO4.Windows"
        Label         = "secbtn_Click_1 (dialog trigger 2)"
        Callee        = "MAMPPRO4.Windows.ThreeButtonMessageBox::set_serialtext"
        Opcode        = 0x28                    # call
        Prefix        = [byte[]](0x02, 0x14, 0x28) # ldarg.0; ldnull; <call>
        Suffix        = [byte[]](0x2A)
        Pristine      = "59edc250078bb30224cc2f3acb5ddc5e0e3cd0249145f1419e28b9d5638a6f18"
        Patched       = "0b12372047abea6a3a85d1cfdcfc8f2b29697344ba3320074eb3bdc95f551f12"
        Shapes        = @( (Sh ([int[]](0x02, 0x16, 0x28, -1, -1, -1, -1, 0x73, -1, -1, -1, -1,
                                       0x0A, 0x06, 0x6F, -1, -1, -1, -1, 0x26, 0x06, 0x6F, -1, -1, -1, -1,
                                       0x2C, -1, 0x02, 0x17, 0x28, -1, -1, -1, -1,
                                       0x02, 0x06, 0x6F, -1, -1, -1, -1, 0x28, -1, -1, -1, -1,
                                       0x02, 0x17, 0x73, -1, -1, -1, -1, 0x28, -1, -1, -1, -1,
                                       0x02, 0x28, -1, -1, -1, -1, 0x2A, 0x02, 0x14, 0x28, -1, -1, -1, -1, 0x2A))) )
        PatchedShapes = @( (Sh ([int[]](0x02, 0x14, 0x28, -1, -1, -1, -1, 0x2A))) )
        Trigger       = $true
    }
)

function Write-Line([string]$text, [string]$color = "Gray") {
    Write-Host $text -ForegroundColor $color
}

function Test-Shapes([byte[]]$il, $shapes) {
    foreach ($s in $shapes) {
        if ($il.Length -ne $s.Len) { continue }
        $p = $s.P
        $ok = $true
        for ($i = 0; $i -lt $p.Length; $i++) {
            if ($p[$i] -ge 0 -and [int]$il[$i] -ne $p[$i]) { $ok = $false; break }
        }
        if ($ok) { return $true }
    }
    return $false
}

function Get-BytesHex([byte[]]$b) { ($b | ForEach-Object { "{0:X2}" -f $_ }) -join "" }

function Get-Sha([byte[]]$b) {
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($sha.ComputeHash($b)) -replace "-", "").ToLowerInvariant() }
    finally { $sha.Dispose() }
}

function Get-TokenBytes([int]$row) {
    $t = 0x06000000 -bor $row
    [byte[]](($t -band 0xFF), (($t -shr 8) -band 0xFF), (($t -shr 16) -band 0xFF), (($t -shr 24) -band 0xFF))
}

function Get-TokenRow([byte[]]$il, [int]$at) {
    return [int]$il[$at + 1] -bor ([int]$il[$at + 2] -shl 8) -bor ([int]$il[$at + 3] -shl 16) -bor ([int]$il[$at + 4] -shl 24)
}

# rows of every method that mentions <token> after <op> inside its own IL
function Find-OperandUsers($cli, [int]$op, [int]$token) {
    $hit = @()
    for ($r = 1; $r -le $cli.Count; $r++) {
        if ($cli.IlSize($r) -lt 5) { continue }   # abstract / extern methods have no body
        $il = $cli.IlBytes($r)
        if ($il.Length -lt 5) { continue }
        for ($i = 0; $i + 5 -le $il.Length; $i++) {
            if ([int]$il[$i] -ne $op) { continue }
            if ((Get-TokenRow $il $i) -eq $token) { $hit += $r; break }
        }
    }
    return $hit
}

function Test-FileWritable([string]$path) {
    try {
        $fs = [IO.File]::Open($path, [IO.FileMode]::Open, [IO.FileAccess]::Write, [IO.FileShare]::None)
        $fs.Close()
        return $true
    } catch [IO.IOException] {
        return $false
    } catch [UnauthorizedAccessException] {
        return $true    # locked by a writer is IOException; ACL problems surface later with a clear message
    }
}

function Notify([string]$text) {
    if ($NoNotify -or -not [Environment]::UserInteractive) { return }
    try {
        Add-Type -AssemblyName System.Windows.Forms -ErrorAction Stop
        [void][System.Windows.Forms.MessageBox]::Show($text, "MAMP PRO License Patch", "OK", "Warning")
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
    # Keyed per-SITE label + reason, not per file SHA: after a MAMP update the
    # file SHA changes even when the problem is the same.
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
    $txt = "MAMP PRO was updated and its license gate can NOT be patched automatically yet.`r`n`r`n" +
           "build  : " + $shaBefore + "`r`n" +
           "target : " + $Target + "`r`n`r`n" +
           ($fresh -join "`r`n") + "`r`n`r`n" +
           "Details: MampProPatch.ps1 -DryRun"
    Notify $txt
    Write-Line ("  [!] " + $fresh.Count + " dark site(s) - notification sent") Red
}

# ---------------------------------------------------------------- preflight
if (-not (Test-Path -LiteralPath $Target)) {
    Write-Line "  target not found: $Target" Red
    exit 2
}
$Target = (Resolve-Path -LiteralPath $Target).Path
New-Item -ItemType Directory -Force -Path $BackupDir | Out-Null
New-Item -ItemType Directory -Force -Path (Join-Path $BackupDir "backup") | Out-Null
$stateFile = Join-Path $BackupDir "state.json"

# ---------------------------------------------------------------- restore
if ($Restore) {
    $cands = @(
        (Join-Path $BackupDir "backup\MAMPPRO.dll.orig"),
        "$Target.bak",
        "$Target.orig"
    )
    $src = $cands | Where-Object { $_ -and (Test-Path -LiteralPath $_) } | Select-Object -First 1
    if (-not $src) { Write-Line "  no backup available" Red; exit 2 }
    if (-not (Test-FileWritable $Target)) {
        Write-Line "  MAMPPRO.dll is locked - MAMP PRO is running, exit it from the tray first" Red
        exit 3
    }
    Copy-Item -LiteralPath $src -Destination $Target -Force
    Write-Line ("  restored from " + $src) Green
    Write-Line ("  SHA256 = " + (Get-FileHash -LiteralPath $Target -Algorithm SHA256).Hash)
    $st = Read-State
    $st.lastGood = ""
    Write-State $st
    exit 0
}

$shaBefore = (Get-FileHash -LiteralPath $Target -Algorithm SHA256).Hash

# ---------------------------------------------------------------- fast path
# Byte-identical to the last patch result -> one SHA-256 is enough, no metadata parse.
if (-not $DryRun -and -not $Force) {
    $st = Read-State
    if ($st.lastGood -eq $shaBefore) {
        Write-Line ("  already clean (fast path, sha " + $shaBefore.Substring(0,16) + ") - done") Green
        exit 0
    }
}

# ---------------------------------------------------------------- locked?
if (-not (Test-FileWritable $Target)) {
    if ($WaitForExitSeconds -gt 0) {
        $live = @(Get-Process -Name MAMPPRO, LauncherMAMPPRO -ErrorAction SilentlyContinue)
        Write-Line ("  MAMP PRO running (PID " + (($live | ForEach-Object { $_.Id }) -join ",") + "), waiting up to $WaitForExitSeconds s...") Yellow
        $deadline = (Get-Date).AddSeconds($WaitForExitSeconds)
        while ((-not (Test-FileWritable $Target)) -and (Get-Date) -lt $deadline) { Start-Sleep -Milliseconds 500 }
    }
    if (-not (Test-FileWritable $Target)) {
        Write-Line "  MAMPPRO.dll is locked - MAMP PRO is running, exit it from the tray first" Red
        exit 3
    }
}

# ---------------------------------------------------------------- load
if (-not ("MampCli" -as [type])) {
    Add-Type -Path (Join-Path $PSScriptRoot "MampCli.cs") -ErrorAction Stop
}
$cli = New-Object MampCli
try { $cli.Load($Target) }
catch { Write-Line ("  not a loadable CLI assembly: " + $_.Exception.Message) Red; exit 2 }

Write-Line ""
Write-Line "MAMP PRO license gate patch"
Write-Line ("  target : " + $Target)
Write-Line ("  size   : {0:n0} bytes" -f (Get-Item -LiteralPath $Target).Length)
Write-Line ("  method : {0:n0}" -f $cli.Count)
Write-Line ("  sha256 : " + $shaBefore)
Write-Line ""

# build each replacement: the two call sites resolve their callee by NAME
# (their MethodDef tokens move between MAMP builds), the rest are fixed bytes
foreach ($s in $script:Site) {
    if ($s.Callee) {
        $cr = $cli.FindRow($s.Callee)
        if ($cr -ge 0) { $s.NewIl = [byte[]]($s.Prefix + (Get-TokenBytes $cr) + $s.Suffix) }
    } elseif ($s.NewIlFixed) {
        $s.NewIl = [byte[]]$s.NewIlFixed
    }
    if ($s.NewIl) { $s.NewIlSha = Get-Sha $s.NewIl }
}

# ---------------------------------------------------------------- classification
$plan    = @()
$unknown = @()
$already = 0
$pristineSeen = $false
$rows    = @{}     # site label -> row (located, any tier), used by the ctor gate

foreach ($s in $script:Site) {
    Write-Line ("  " + $s.Name) White

    $row = $cli.FindRow($s.Name)
    $tier = "exact"

    if ($row -lt 0) {
        # safety net: same short name under any declaring type
        $seen = @()
        foreach ($r in $cli.FindRowsByName($s.Simple)) {
            if ($cli.IlSize($r) -lt 1) { continue }
            $ilx = $cli.IlBytes($r)
            if (Test-Shapes $ilx $s.Shapes) { $seen += $r }
            elseif (Test-Shapes $ilx $s.PatchedShapes) { $seen += ("p:" + $r) }
        }
        $doneHit = @($seen | Where-Object { "$_" -like "p:*" })
        if ($doneHit.Count -gt 0) {
            $already++
            $rows[$s.Label] = [int]$doneHit[0].Substring(2)
            Write-Line ("      already patched (fuzzy) at " + $cli.NameOf($rows[$s.Label])) Green
            continue
        }
        $seen = @($seen | Where-Object { "$_" -notlike "p:*" })
        if ($seen.Count -gt 1) {
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
    $rows[$s.Label] = $row

    $il    = $cli.IlBytes($row)
    $cur   = $cli.IlSha($row)
    Write-Line ("      rva 0x{0:X8}  body 0x{1:X}  il@0x{2:X}  ilSize {3}  hdr {4}  fat 0x{5:X4}  maxstack {6}" -f `
        $cli.Rva($row), $cli.BodyStart($row), $cli.IlStart($row), $il.Length, `
        $(if ($cli.HeaderKind($row) -eq 3) { "FAT" } else { "TINY" }), $cli.FatFlags($row), $cli.MaxStack($row))
    if ($il.Length -le 96) { Write-Line ("      current IL  : " + (Get-BytesHex $il)) DarkGray }
    else                   { Write-Line ("      current IL  : " + $il.Length + " bytes, sha " + $cur.Substring(0, 16) + "...") DarkGray }

    if ($cur -eq $s.Patched) {
        Write-Line "      already patched (hash) - skipped" Green
        $already++
        continue
    }
    if (Test-Shapes $il $s.PatchedShapes) {
        Write-Line "      already patched (shape) - skipped" Green
        $already++
        continue
    }
    if ($cur -eq $s.Pristine) {
        # exact-name location keeps "exact"; a fuzzy (renamed type) location keeps "fuzzy"
        if ($tier -ne "fuzzy") { $tier = "exact" }
    } elseif (Test-Shapes $il $s.Shapes) {
        if ($tier -ne "fuzzy") { $tier = "shape" }
        Write-Line "      IL differs from this release but shape matches -> tier shape" Yellow
    } else {
        Write-Line "      unknown IL (shape differs too) - NOT touched" Red
        Write-Line ("      sha = " + $cur) Red
        $unknown += $s.Label + " (unknown IL " + $cur.Substring(0, 16) + ")"
        continue
    }

    if (-not $s.NewIl) {
        Write-Line ("      callee not found: " + $s.Callee + " - NOT touched") Red
        $unknown += $s.Label + " (callee not found: " + $s.Callee + ")"
        continue
    }

    $pristineSeen = $true
    Write-Line ("      new IL      : " + (Get-BytesHex $s.NewIl) + "   [" + $tier + "]  sha " + $s.NewIlSha.Substring(0, 16)) Cyan
    $plan += @{ Site = $s; Row = $row; Tier = $tier }
}

Write-Line ""

# ---------------------------------------------------------- module-wide ctor gate
# Every construction of an MAMPPRO4.EnterSerial::.ctor must be explainable:
# the two trigger methods may build the paramless dialog ctor, and
# EnterSerial::OK_Click may build the argument ctor. Anything else is a path
# this patch does not know -> refuse, do not write half a fix.
$script:DlgTok = 0
$ctorRows = @()
try { $ctorRows = @($cli.FindRowsInType("MAMPPRO4.EnterSerial", ".ctor")) } catch { }
$trigRows = @()
foreach ($lbl in @("MenuItem_Click_2 (dialog trigger 1)", "secbtn_Click_1 (dialog trigger 2)")) {
    if ($rows.ContainsKey($lbl)) { $trigRows += $rows[$lbl] }
}
$allowed = @($trigRows)
$okRow = $cli.FindRow("MAMPPRO4.EnterSerial::OK_Click")
if ($okRow -ge 0) { $allowed += $okRow }

if ($plan.Count -gt 0) {
    if ($ctorRows.Count -eq 0) {
        $unknown += "EnterSerial ctor gate (MAMPPRO4.EnterSerial::.ctor not found)"
        Write-Line "  [gate] MAMPPRO4.EnterSerial::.ctor not found - NOT touched" Red
    }
    foreach ($c in $ctorRows) {
        $tok = 0x06000000 -bor $c
        $users = @(Find-OperandUsers $cli 0x73 $tok)
        $strays = @($users | Where-Object { $allowed -notcontains $_ })
        if ($strays.Count -gt 0) {
            $names = ($strays | ForEach-Object { $cli.NameOf($_) }) -join ", "
            $unknown += "EnterSerial ctor 0x06$($c.ToString('X6')) also built by: $names"
            Write-Line ("  [gate] EnterSerial ctor also constructed by: " + $names) Red
        }
        # the dialog ctor is the one the TRIGGER methods build (OK_Click legitimately
        # builds the argument ctor - that one is not ours to kill)
        if (($users | Where-Object { $trigRows -contains $_ }).Count -gt 0) { $script:DlgTok = $tok }
    }
    if ($script:DlgTok -eq 0) {
        # no live trigger constructs any ctor - both triggers must then already
        # be patched (they are in the plan otherwise), treat as pass with no scan
        Write-Line "  [gate] no live trigger -> ctor scan skipped (triggers already patched)" DarkGray
    } else {
        Write-Line ("  [gate] dialog ctor 0x06{0:X6} - construction sites inside allowed set" -f ($script:DlgTok -band 0xFFFFFF)) Green
    }
}

# ---------------------------------------------------------------- decision
if ($DryRun) {
    Write-Line ("  DRY RUN: {0} to patch, {1} already patched, {2} unknown" -f $plan.Count, $already, $unknown.Count) Yellow
    foreach ($u in $unknown) { Write-Line ("    [!] " + $u) Red }
    if ($unknown.Count -gt 0) { exit 4 }
    exit 0
}
if ($unknown.Count -gt 0) {
    # fail hard: all four gates must be patched as a set, never half
    Write-Line ("  REFUSED: {0} dark site(s) - nothing written" -f $unknown.Count) Red
    Warn-Once
    exit 4
}
if ($plan.Count -eq 0) {
    $st = Read-State
    $st.lastGood = $shaBefore
    Write-State $st
    Write-Line "  already clean - nothing changed" Green
    exit 0
}

# ---------------------------------------------------------------- backup
$origDir = Join-Path $BackupDir "backup"
$orig = Join-Path $origDir "MAMPPRO.dll.orig"
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

# ---------------------------------------------------------------- apply (in memory)
foreach ($p in $plan) {
    if (-not $cli.PatchIl($p.Row, $p.Site.NewIl)) {
        Write-Line ("  FAILED to patch " + $p.Site.Label + " (body too small?)") Red
        exit 5
    }
    $got = $cli.IlSha($p.Row)
    if ($got -ne $p.Site.NewIlSha) {
        Write-Line ("  FAILED verify after write: " + $p.Site.Label) Red
        Write-Line ("    expected " + $p.Site.NewIlSha) Red
        Write-Line ("    got      " + $got) Red
        exit 5
    }
    Write-Line ("  patched [{0}]: {1}" -f $p.Tier, $p.Site.Label) Green
}

# end state: all four sites must carry their patched shape
foreach ($s in $script:Site) {
    $r = $cli.FindRow($s.Name)
    if ($r -lt 0) { $r = $rows[$s.Label] }
    if (-not $r -or -not (Test-Shapes ($cli.IlBytes($r)) $s.PatchedShapes)) {
        Write-Line ("  FAILED end-state verify: " + $s.Label) Red
        exit 5
    }
}
# end state: nothing constructs the dialog anymore
if ($script:DlgTok -gt 0) {
    $left = @(Find-OperandUsers $cli 0x73 $script:DlgTok)
    if ($left.Count -gt 0) {
        Write-Line ("  FAILED: dialog ctor still constructed by " + (($left | ForEach-Object { $cli.NameOf($_) }) -join ", ")) Red
        exit 5
    }
}

# ---------------------------------------------------------------- save + atomic swap
$tmp = "$Target.mamp-new"
try {
    $cli.Save($tmp)
} catch [UnauthorizedAccessException] {
    Write-Line ("  access denied writing " + $tmp + " - run patch-now.cmd / install.cmd elevated") Red
    exit 1
} catch [IOException] {
    Write-Line ("  cannot write the patched copy: " + $_.Exception.Message) Red
    exit 5
}

# re-read the file we are about to install and verify it independently
$verify = New-Object MampCli
try { $verify.Load($tmp) } catch {
    Write-Line ("  FAILED re-read of the patched copy: " + $_.Exception.Message) Red
    Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue
    exit 5
}
foreach ($s in $script:Site) {
    # MethodDef rows are untouched by the patch, so the classified row is still valid
    # even when the declaring type was renamed (fuzzy tier)
    $r = $verify.FindRow($s.Name)
    if ($r -lt 0) { $r = $rows[$s.Label] }
    if (-not $r) { Write-Line ("  FAILED re-read: lost " + $s.Name) Red; Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue; exit 5 }
    $got = $verify.IlSha($r)
    if ($got -ne $s.NewIlSha -and -not (Test-Shapes ($verify.IlBytes($r)) $s.PatchedShapes)) {
        Write-Line ("  FAILED re-read verify: " + $s.Label) Red
        Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue
        exit 5
    }
}
if ($script:DlgTok -gt 0) {
    $left = @(Find-OperandUsers $verify 0x73 $script:DlgTok)
    if ($left.Count -gt 0) {
        Write-Line "  FAILED re-read verify: dialog ctor still constructed" Red
        Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue
        exit 5
    }
}

try {
    Move-Item -LiteralPath $tmp -Destination $Target -Force
} catch {
    Write-Line ("  FAILED to swap in the patched file: " + $_.Exception.Message) Red
    Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue
    exit 5
}

$shaAfter = (Get-FileHash -LiteralPath $Target -Algorithm SHA256).Hash
$st = Read-State
$st.lastGood = $shaAfter
Write-State $st
Write-Line ""
Write-Line ("  sha256 before : " + $shaBefore)
Write-Line ("  sha256 after  : " + $shaAfter)
Write-Line ("  {0} patched, {1} skipped, {2} dark" -f $plan.Count, $already, $unknown.Count) Green

try {
    Add-Content -LiteralPath (Join-Path $BackupDir "mamp-patch.log") -Value (
        "{0}  {1}  before={2}  after={3}  patched={4}  skipped={5}  unknown={6}" -f
        (Get-Date).ToString("yyyy-MM-dd HH:mm:ss"), $Target, $shaBefore, $shaAfter, $plan.Count, $already, $unknown.Count
    ) -ErrorAction SilentlyContinue
} catch { }

exit 0
