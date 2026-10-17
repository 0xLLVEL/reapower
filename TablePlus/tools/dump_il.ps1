<#
  dump_il.ps1 — print the CIL body of MethodDef tokens, decoding ldstr from the #US heap.
  Usage:
    .\dump_il.ps1 -Path <dll> -Tokens 0x06009ea2,0x06009ea3,0x060073b1
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$Path,
    [Parameter(Mandatory=$true)][string[]]$Tokens
)
$ErrorActionPreference = 'Stop'
# -File passes the list as one comma-joined string; normalize it
$Tokens = @($Tokens | ForEach-Object { "$_" -split ',' } | Where-Object { $_ -ne '' })
function U16([byte[]]$b,[int]$o){ [BitConverter]::ToUInt16($b,$o) }
function U32([byte[]]$b,[int]$o){ [BitConverter]::ToUInt32($b,$o) }

$full = (Resolve-Path $Path).Path
$b = [IO.File]::ReadAllBytes($full)

# ---------- PE ----------
$pe = U32 $b 0x3C
$coff = $pe + 4
$numSec  = U16 $b ($coff + 2)
$optSize = U16 $b ($coff + 16)
$optOff  = $coff + 20
$is64 = ((U16 $b $optOff) -eq 0x20B)
$secTab = $optOff + $optSize
$dirBase = if ($is64) { $optOff + 112 } else { $optOff + 96 }
$cliRva = U32 $b ($dirBase + 14*8)
$sections = @()
for ($i=0;$i -lt $numSec;$i++){
  $s = $secTab + $i*40
  $sections += @{ VA = (U32 $b ($s+12)); VSize = (U32 $b ($s+8)); RawPtr = (U32 $b ($s+20)); RawSize = (U32 $b ($s+16)) }
}
function Rva2Off([uint32]$rva){
  foreach ($s in $sections){ if ($rva -ge $s.VA -and $rva -lt ($s.VA + [math]::Max($s.VSize,$s.RawSize))){ return [int]($rva - $s.VA + $s.RawPtr) } }
  throw ("RVA 0x{0:X} unmapped" -f $rva)
}

# ---------- metadata ----------
$cliOff = Rva2Off $cliRva
$mdRva  = U32 $b ($cliOff + 8)
$root   = Rva2Off $mdRva
$verLen = U32 $b ($root + 12)
$p = $root + 16 + $verLen + 2
$numStreams = U16 $b $p; $p += 2
$streams = @{}
for ($i=0;$i -lt $numStreams;$i++){
  $soff = U32 $b $p; $ssz = U32 $b ($p+4); $p += 8
  $sb = New-Object Text.StringBuilder
  while ($b[$p] -ne 0){ [void]$sb.Append([char]$b[$p]); $p++ }
  $p++
  $p = [int]([math]::Ceiling($p/4.0)*4)
  $streams[$sb.ToString()] = @{ Off = $root + $soff; Size = $ssz }
}
$usBase = $streams['#US'].Off

function Get-UserString([int]$idx){
  if ($idx -eq 0){ return "" }
  $q = $usBase + $idx
  $b0 = $b[$q]
  if (($b0 -band 0x80) -eq 0){ $len = $b0; $q += 1 }
  elseif (($b0 -band 0xC0) -eq 0x80){ $len = (($b0 -band 0x3F) -shl 8) -bor $b[$q+1]; $q += 2 }
  else { $len = (($b0 -band 0x1F) -shl 24) -bor ($b[$q+1] -shl 16) -bor ($b[$q+2] -shl 8) -bor $b[$q+3]; $q += 4 }
  # last byte is the terminal flag byte
  $charBytes = $len - 1
  return [Text.Encoding]::Unicode.GetString($b, $q, $charBytes)
}

# ---------- #~ ----------
$t = $streams['#~'].Off
$heapSizes = $b[$t + 6]
$strIdx  = if ($heapSizes -band 1){4}else{2}
$guidIdx = if ($heapSizes -band 2){4}else{2}
$blobIdx = if ($heapSizes -band 4){4}else{2}
$valid = [BitConverter]::ToUInt64($b, $t + 8)
$tp = $t + 24
$rows = @{}
for ($i=0;$i -lt 64;$i++){ if ($valid -band ([uint64]1 -shl $i)){ $rows[$i] = U32 $b $tp; $tp += 4 } }
function RC([int]$i){ if ($rows.ContainsKey($i)){ $rows[$i] } else { 0 } }
function IdxSize([int]$c){ if ($c -ge 65536){4}else{2} }
function CodedSize([int[]]$counts,[int]$bits){ $m=0; foreach($c in $counts){ if($c -gt $m){$m=$c} }; if ($m -lt [math]::Pow(2,(16-$bits))){2}else{4} }

$resScope = CodedSize @((RC 0x00),(RC 0x1A),(RC 0x23),(RC 0x01)) 2
$tdrSize  = CodedSize @((RC 0x02),(RC 0x01),(RC 0x1B)) 2
$fieldIdx = IdxSize (RC 0x04)
$methIdx  = IdxSize (RC 0x06)
$paramIdx = IdxSize (RC 0x08)

$rowSize = @{}
$rowSize[0x00] = 2 + $strIdx + 3*$guidIdx
$rowSize[0x01] = $resScope + 2*$strIdx
$rowSize[0x02] = 4 + 2*$strIdx + $tdrSize + $fieldIdx + $methIdx
$rowSize[0x03] = $fieldIdx
$rowSize[0x04] = 2 + $strIdx + $blobIdx
$rowSize[0x05] = $methIdx
$rowSize[0x06] = 4 + 2 + 2 + $strIdx + $blobIdx + $paramIdx

$cursor = $tp
for ($i=0;$i -lt 0x06;$i++){ if ($rows.ContainsKey($i)){ $cursor += $rowSize[$i] * $rows[$i] } }
$mdStart = $cursor
$stride  = $rowSize[0x06]

foreach ($tokStr in $Tokens){
  $tok = [uint32]$tokStr
  $row = [int]($tok -band 0x00FFFFFF)
  $rp = $mdStart + ($row-1)*$stride
  $rva = U32 $b $rp
  if ($rva -eq 0){ Write-Output ("{0}  row={1}  RVA=0 (no body)" -f $tokStr,$row); continue }
  $off = Rva2Off $rva
  $hdr = $b[$off]; $fmt = $hdr -band 3
  if ($fmt -eq 2){ $ilSize = $hdr -shr 2; $ilOff = $off + 1 }
  elseif ($fmt -eq 3){ $ilSize = U32 $b ($off+4); $ilOff = $off + 12 }
  else { throw ("{0}: unknown header 0x{1:X2}" -f $tokStr,$hdr) }
  Write-Output ("{0}  row={1}  RVA=0x{2:X8}  fileOff={3}  fmt={4}  ilSize={5}" -f $tokStr,$row,$rva,$off,$fmt,$ilSize)
  $hex = @($b[$ilOff..($ilOff+$ilSize-1)]) | ForEach-Object { $_.ToString('X2') }
  Write-Output ("    IL: " + ($hex -join ' '))
  # walk for ldstr (0x72) to pull the literal
  $i = 0
  $lits = @()
  while ($i -lt $ilSize){
    $op = $b[$ilOff+$i]
    if ($op -eq 0x72 -and ($i + 4) -lt $ilSize){
      $mt = U32 $b ($ilOff+$i+1)
      $usIdx = [int]($mt -band 0x00FFFFFF)
      if ($usIdx -ne 0){
        try { $lits += (Get-UserString $usIdx) } catch { $lits += "<decode-fail>" }
      }
      $i += 5; continue
    }
    if ($op -eq 0x7B -or $op -eq 0x7D -or $op -eq 0x28 -or $op -eq 0x6F -or $op -eq 0x73 -or $op -eq 0x7E -or $op -eq 0x80 -or $op -eq 0x74 -or $op -eq 0x71 -or $op -eq 0x8C -or $op -eq 0x8D -or $op -eq 0xD0){ $i += 5; continue }
    if ($op -eq 0x28 -or $op -eq 0x0A){ }
    if ($op -ge 0x2B -and $op -le 0x37){ $i += 2; continue }   # short branch
    if ($op -ge 0x38 -and $op -le 0x44){ $i += 5; continue }   # long branch
    if ($op -eq 0x45){ $i += 5; continue }                     # switch
    if ($op -ge 0x10 -and $op -le 0x13){ $i += 2; continue }   # ldarg.s / ldloc.s / starg.s / stloc.s
    if ($op -eq 0x1F -or $op -eq 0x20 -or $op -eq 0x21 -or $op -eq 0x22){ $i += 5; continue } # ldc.i4.x
    $i += 1
  }
  if ($lits.Count){ Write-Output ("    ldstr: " + ($lits | ForEach-Object { '"' + $_ + '"' } | Select-Object -First 8 -Unique) -join ' ') }
  Write-Output ""
}
