<#
  patch_servbay.ps1
  In-place IL patcher for ServBay.dll (v1.34.4.2610, .NET 9, x64, not strong-named).

  What it does
    Rewrites the body of the entitlement gate methods with a constant-return stub.
    Bodies live in the .text section; new bodies are TINY-format (maxstack 8, <=3 bytes)
    and always smaller than the original FAT bodies, so the surplus bytes are simply
    left as unreachable padding. MethodDef.RVA is unchanged, so no metadata rewrite
    is required -- this is a pure byte patch.

  Safety
    - Verifies every target body's current header (FAT + expected CodeSize) before writing.
    - Verifies no two MethodDefs share a target RVA (would patch an unrelated method).
    - Writes a one-time .bak before touching the original.

  Usage
    # dry run against a copy
    .\patch_servbay.ps1 -Path .\ServBay.dll -DryRun
    # apply, keep backup
    .\patch_servbay.ps1 -Path .\ServBay.dll
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$Path,
    [switch]$DryRun,
    [switch]$NoBackup
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

# ---------------------------------------------------------------------------
# Targets: declaring type + method + expected body fingerprint
#   Token    : MethodDef token as reported by the metadata inspector
#   Rva      : MethodDef.RVA (body header address)
#   IlSize   : expected original CodeSize (variant check)
#   Value    : constant the stub returns
#                true  -> bool true
#                false -> bool false
#                Ordinal -> enum ordinal (ldc.i4.<n>)
# ---------------------------------------------------------------------------
$Targets = @(
    # --- entitlement predicates: force "entitled" ---------------------------
    @{ Name='EntitlementStore.IsVipEntitled()';      Token='0x060030dd'; Rva=2229464; IlSize=233; Value='true'  }
    @{ Name='EntitlementService.IsEntitledVip';      Token='0x060030c5'; Rva=2226496; IlSize=130; Value='true'  }
    @{ Name='EntitlementService.IsPaidEntitlement';  Token='0x060030c6'; Rva=2226640; IlSize=96;  Value='true'  }
    @{ Name='LicenseVerifier.Verify';                Token='0x0600311b'; Rva=2232120; IlSize=122; Value='true'  }
    @{ Name='EntitlementCredentialAudit.Verdict';    Token='0x060030ca'; Rva=2226868; IlSize=93;  Value='Ordinal:3' }
    # --- gates: force "do not block" ---------------------------------------
    # BridgeVIPGate.ShouldBlock(method,isVip) => GatedMethods.Contains(method) && !isVip
    @{ Name='BridgeVIPGate.ShouldBlock';             Token='0x0600305d'; Rva=2219158; IlSize=20;  Value='false' }
    # AiGatewayVipOnlyEndpoints.RequiresVip(request,path) => vip-only route table lookup
    @{ Name='AiGatewayVipOnlyEndpoints.RequiresVip'; Token='0x06002d5b'; Rva=2160940; IlSize=161; Value='false' }
)

# --- ECMA-335 constants -----------------------------------------------------
$CorILMethod_TinyFormat = 0x02
$CorILMethod_FatFormat  = 0x03

$Op = @{
    Ldc_I4_0 = 0x16; Ldc_I4_1 = 0x17; Ldc_I4_2 = 0x18; Ldc_I4_3 = 0x19
    Ldc_I4_4 = 0x1A; Ldc_I4_5 = 0x1B; Ldc_I4_6 = 0x1C; Ldc_I4_7 = 0x1D
    Ldc_I4_8 = 0x1E; Ldc_I4_M1 = 0x15; Ldc_I4_S = 0x1F; Ldc_I4 = 0x20
    Ret = 0x2A
}

function Read-U16([byte[]]$b,[int]$o){ [BitConverter]::ToUInt16($b,$o) }
function Read-U32([byte[]]$b,[int]$o){ [BitConverter]::ToUInt32($b,$o) }

# ---------------------------------------------------------------------------
# PE / section table
# ---------------------------------------------------------------------------
function Get-PeInfo([byte[]]$b){
    $pe = Read-U32 $b 0x3C
    if ([Text.Encoding]::ASCII.GetString($b,$pe,4) -ne "PE`0`0"){ throw "Not a PE file" }
    $coff = $pe + 4
    $numSec  = Read-U16 $b ($coff + 2)
    $optSize = Read-U16 $b ($coff + 16)
    $optOff  = $coff + 20
    $magic   = Read-U16 $b $optOff
    $isPe32P = ($magic -eq 0x20B)
    $secTab  = $optOff + $optSize
    $dirBase = if ($isPe32P) { $optOff + 112 } else { $optOff + 96 }
    $cliDirRva  = Read-U32 $b  $dirBase       # index 0 holds Export... no: dir index 14 = CLI
    $dirs = @()
    for ($i=0;$i -lt 16;$i++){ $dirs += @{ Rva = (Read-U32 $b ($dirBase + $i*8)); Size = (Read-U32 $b ($dirBase + $i*8 + 4)) } }
    $sections = @()
    for ($i=0;$i -lt $numSec;$i++){
        $s = $secTab + $i*40
        $sections += @{
            Name    = [Text.Encoding]::ASCII.GetString($b,$s,8).Trim([char]0)
            VA      = Read-U32 $b ($s+12)
            VSize   = Read-U32 $b ($s+8)
            RawPtr  = Read-U32 $b ($s+20)
            RawSize = Read-U32 $b ($s+16)
        }
    }
    return @{ Sections = $sections; CliRva = $dirs[14].Rva; CliSize = $dirs[14].Size }
}

function Rva-To-Offset($pe,[uint32]$rva){
    foreach ($s in $pe.Sections){
        if ($rva -ge $s.VA -and $rva -lt ($s.VA + [math]::Max($s.VSize,$s.RawSize))){
            return [int]($rva - $s.VA + $s.RawPtr)
        }
    }
    throw ("RVA 0x{0:X} not mapped to a section" -f $rva)
}

# ---------------------------------------------------------------------------
# CLI metadata -> MethodDef RVA list
# ---------------------------------------------------------------------------
function Get-MethodDefRvas([byte[]]$b,$pe){
    $cliOff = Rva-To-Offset $pe $pe.CliRva
    $mdRva  = Read-U32 $b ($cliOff + 8)          # Metadata RVA (absolute)
    $cliOff = Rva-To-Offset $pe $mdRva           # metadata root file offset
    if ([Text.Encoding]::ASCII.GetString($b,$cliOff,4) -ne "BSJB"){ throw "No BSJB metadata signature" }
    $verLen = Read-U32 $b ($cliOff + 12)
    $p = $cliOff + 16 + $verLen
    $p += 2                                  # Flags
    $numStreams = Read-U16 $b $p; $p += 2
    $streams = @{}
    for ($i=0;$i -lt $numStreams;$i++){
        $soff = Read-U32 $b $p; $ssize = Read-U32 $b ($p+4); $p += 8
        $sb = New-Object Text.StringBuilder
        while ($b[$p] -ne 0){ [void]$sb.Append([char]$b[$p]); $p++ }
        $p++                                   # NUL
        $p = [int]([math]::Ceiling($p/4.0)*4)  # pad to 4
        $streams[$sb.ToString()] = @{ Off = $cliOff + $soff; Size = $ssize }
    }
    $tbl = $streams['#~']; if (-not $tbl){ $tbl = $streams['#-'] }
    if (-not $tbl){ throw "No #~ table stream" }

    $t = $tbl.Off
    $heapSizes = $b[$t + 6]
    $strIdx  = if ($heapSizes -band 1) {4} else {2}
    $guidIdx = if ($heapSizes -band 2) {4} else {2}
    $blobIdx = if ($heapSizes -band 4) {4} else {2}
    $valid = [BitConverter]::ToUInt64($b, $t + 8)
    $tp = $t + 24
    $rows = @{}
    for ($i=0;$i -lt 64;$i++){
        if ($valid -band ([uint64]1 -shl $i)){ $rows[$i] = Read-U32 $b $tp; $tp += 4 }
    }
    $rc = { param($i) if ($rows.ContainsKey($i)) { $rows[$i] } else { 0 } }

    function IdxSize([int]$count){ if ($count -ge 65536){4} else {2} }
    function CodedSize([int[]]$counts,[int]$tagBits){
        $max = 0; foreach ($c in $counts){ if ($c -gt $max){ $max = $c } }
        if ($max -lt [math]::Pow(2,(16 - $tagBits))){2} else {4}
    }

    $moduleCount     = & $rc 0x00
    $typeRefCount    = & $rc 0x01
    $typeDefCount    = & $rc 0x02
    $fieldPtrCount   = & $rc 0x03
    $fieldCount      = & $rc 0x04
    $methodPtrCount  = & $rc 0x05
    $methodDefCount  = & $rc 0x06
    $paramCount      = & $rc 0x08
    $moduleRefCount  = & $rc 0x1A
    $typeSpecCount   = & $rc 0x1B
    $assemblyRefCnt  = & $rc 0x23

    $resolutionScopeSize = CodedSize @($moduleCount,$moduleRefCount,$assemblyRefCnt,$typeRefCount) 2
    $typeDefOrRefSize    = CodedSize @($typeDefCount,$typeRefCount,$typeSpecCount) 2
    $fieldIdxSize        = IdxSize $fieldCount
    $methodDefIdxSize    = IdxSize $methodDefCount
    $paramIdxSize        = IdxSize $paramCount

    $rowSize = @{}
    $rowSize[0x00] = 2 + $strIdx + 3*$guidIdx
    $rowSize[0x01] = $resolutionScopeSize + 2*$strIdx
    $rowSize[0x02] = 4 + 2*$strIdx + $typeDefOrRefSize + $fieldIdxSize + $methodDefIdxSize
    $rowSize[0x03] = $fieldIdxSize
    $rowSize[0x04] = 2 + $strIdx + $blobIdx
    $rowSize[0x05] = $methodDefIdxSize
    $rowSize[0x06] = 4 + 2 + 2 + $strIdx + $blobIdx + $paramIdxSize

    $dataStart = $tp
    $cursor = $dataStart
    for ($i=0;$i -lt 0x06;$i++){
        if ($rows.ContainsKey($i)){ $cursor += $rowSize[$i] * $rows[$i] }
    }
    $methodDefStart = $cursor
    $stride = $rowSize[0x06]

    $list = New-Object System.Collections.Generic.List[object]
    for ($r=0;$r -lt $methodDefCount;$r++){
        $rp = $methodDefStart + $r*$stride
        $list.Add(@{ Row = $r+1; Rva = (Read-U32 $b $rp) })
    }
    return @{ Methods = $list; Counts = $rows; RowSize = $stride; MethodDefStart = $methodDefStart }
}

function Get-TinyBody([string]$value){
    switch -regex ($value){
        '^true$'  { return ,@($Op.Ldc_I4_1, $Op.Ret) }
        '^false$' { return ,@($Op.Ldc_I4_0, $Op.Ret) }
        '^Ordinal:(\d+)$' {
            $n = [int]$Matches[1]
            if ($n -lt 8){ return ,@((0x16 + $n), $Op.Ret) }
            return ,@($Op.Ldc_I4_S, [byte]$n, $Op.Ret)
        }
        default { throw "Unsupported stub value: $value" }
    }
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
$full = (Resolve-Path $Path).Path
Write-Host "Target : $full"
$b = [IO.File]::ReadAllBytes($full)
Write-Host ("Size   : {0:n0} bytes" -f $b.Length)

$pe = Get-PeInfo $b
$md = Get-MethodDefRvas $b $pe
Write-Host ("MethodDef rows: {0}   rowSize={1}" -f $md.Methods.Count, $md.RowSize)

# --- duplicate-RVA guard ----------------------------------------------------
$plan = @()
$skipped = @()
foreach ($t in $Targets){
    $off = Rva-To-Offset $pe $t.Rva
    $hdr = $b[$off]
    $fmt = $hdr -band 3
    if ($fmt -ne $CorILMethod_FatFormat -and $fmt -ne $CorILMethod_TinyFormat){
        throw ("{0}: body at RVA 0x{1:X} has unknown header 0x{2:X2}" -f $t.Name,$t.Rva,$hdr)
    }
    $codeSize = if ($fmt -eq 3){ Read-U32 $b ($off+4) } else { $hdr -shr 2 }
    if ($fmt -eq $CorILMethod_TinyFormat -and $codeSize -eq 2){
        $skipped += $t.Name
        continue
    }
    if ($codeSize -ne $t.IlSize){
        throw ("{0}: CodeSize mismatch at RVA 0x{1:X} (found {2}, expected {3}) - wrong build?" -f $t.Name,$t.Rva,$codeSize,$t.IlSize)
    }
    $dupes = @($md.Methods | Where-Object { $_.Rva -eq $t.Rva })
    if ($dupes.Count -gt 1){
        throw ("{0}: RVA 0x{1:X} is shared by {2} MethodDefs (rows {3}) - refusing" -f $t.Name,$t.Rva,$dupes.Count, (($dupes | ForEach-Object { $_.Row }) -join ','))
    }
    $stub = Get-TinyBody $t.Value
    $plan += @{ T = $t; Off = $off; CodeSize = $codeSize; Fmt = $fmt; Stub = $stub; ShareRow = $dupes[0].Row }
}

if ($skipped.Count -gt 0){
    Write-Host ""
    Write-Host "Already patched (skipped):"
    foreach ($s in $skipped){ Write-Host ("  {0}" -f $s) }
}

Write-Host ""
Write-Host "Plan:"
foreach ($p in $plan){
    $stubHex = ($p.Stub | ForEach-Object { $_.ToString('X2') }) -join ' '
    Write-Host ("  {0,-38} {1}  RVA=0x{2:X8} off={3,-8} fat(il={4})  -> tiny[{5}]  row={6}" -f `
        $p.T.Name,$p.T.Token,$p.T.Rva,$p.Off,$p.CodeSize,$stubHex,$p.ShareRow)
}

if ($DryRun){ Write-Host "`nDryRun: no bytes written."; return }

# --- backup -----------------------------------------------------------------
if (-not $NoBackup -and -not (Test-Path "$full.bak")){
    Copy-Item -LiteralPath $full -Destination "$full.bak"
    Write-Host "`nBackup: $full.bak"
}

# --- apply ------------------------------------------------------------------
foreach ($p in $plan){
    $body = New-Object System.Collections.Generic.List[byte]
    $body.Add([byte]((($p.Stub.Count -shl 2) -bor $CorILMethod_TinyFormat)))
    foreach ($x in $p.Stub){ $body.Add([byte]$x) }
    $buf = $body.ToArray()
    [Array]::Copy($buf, 0, $b, $p.Off, $buf.Length)
}

$out = $full
[IO.File]::WriteAllBytes($out, $b)
Write-Host "`nPatched: $out"

# --- verify -----------------------------------------------------------------
$v = [IO.File]::ReadAllBytes($out)
Write-Host "`nVerify:"
foreach ($p in $plan){
    $o = $p.Off
    $hdr = $v[$o]
    $fmt = $hdr -band 3
    $size = if ($fmt -eq 3){ Read-U32 $v ($o+4) } else { $hdr -shr 2 }
    $il = @($v[($o+1)..($o+$size)]) | ForEach-Object { $_.ToString('X2') }
    Write-Host ("  {0,-38} fmt={1} ilSize={2}  IL: {3}" -f $p.T.Name,$fmt,$size,($il -join ' '))
    if ($fmt -ne $CorILMethod_TinyFormat){ throw ("{0}: patch did not land" -f $p.T.Name) }
}
Write-Host "`nDone."
