<#
  dump_pe.ps1 - native PE inspector for IDMan.exe.

  Prints the DOS/COFF/optional headers, the section table, the SHA-256 of the
  file, and the raw bytes at a given file offset or RVA. Optionally scans a
  section for a byte signature and reports every hit - this is what proves a
  signature is unambiguous before the engine trusts it.

  Usage:
    .\dump_pe.ps1 -Path <IDMan.exe>
    .\dump_pe.ps1 -Path <IDMan.exe> -Offset 0x4FF40 -Length 48
    .\dump_pe.ps1 -Path <IDMan.exe> -Scan -Sig 558dac24dcfbffff81ec240400006aff6870
    .\dump_pe.ps1 -Path <IDMan.exe> -VAddr 0x230B40
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$Path,
    [string]$Offset,
    [string]$VAddr,
    [int]$Length = 64,
    [switch]$Scan,
    [string]$Sig
)

$ErrorActionPreference = 'Stop'
if (-not (Test-Path -LiteralPath $Path)) { throw "not found: $Path" }

$d = [System.IO.File]::ReadAllBytes((Resolve-Path -LiteralPath $Path).Path)
function U16([int]$o) { return [BitConverter]::ToUInt16($d, $o) }
function U32([int]$o) { return [BitConverter]::ToUInt32($d, $o) }

$lfanew = [BitConverter]::ToInt32($d, 0x3C)
if ([BitConverter]::ToUInt32($d, $lfanew) -ne 0x4550) { throw "no PE signature" }
$coff   = $lfanew + 4
$optsz  = U16 ($coff + 16)
$opt    = $coff + 20
$magic  = U16 $opt
$secoff = $opt + $optsz
$nsec   = U16 ($coff + 2)

$sha = (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash

Write-Host ("{0}" -f (Split-Path -Leaf $Path))
Write-Host ("  sha256     : {0}" -f $sha)
Write-Host ("  size       : {0:N0}" -f $d.Length)
Write-Host ("  e_lfanew   : 0x{0:X}" -f $lfanew)
Write-Host ("  machine    : 0x{0:X4}{1}" -f (U16 $coff), $(if ((U16 $coff) -eq 0x14C) { " (i386)" } else { " (NOT i386)" }))
Write-Host ("  sections   : {0}" -f $nsec)
Write-Host ("  opt hdr    : 0x{0:X4} ({1})" -f $magic, $(if ($magic -eq 0x10B) { "PE32" } else { "PE32+" }))
Write-Host ("  imagebase  : 0x{0:X8}" -f (U32 ($opt + 28)))
Write-Host ("  timestamp  : 0x{0:X8}" -f (U32 ($coff + 4)))
Write-Host ("  dllchars   : 0x{0:X4}" -f (U16 ($opt + 70)))

Write-Host ""
Write-Host "  sections:"
$secs = @()
for ($i = 0; $i -lt $nsec; $i++) {
    $o = $secoff + $i * 40
    $name = [System.Text.Encoding]::ASCII.GetString($d, $o, 8).TrimEnd([char]0)
    $s = [pscustomobject]@{
        Name = $name
        VA   = U32 ($o + 12)
        VSize= U32 ($o + 8)
        RawP = U32 ($o + 20)
        RawS = U32 ($o + 16)
    }
    $secs += $s
    Write-Host ("    {0,-8} VA=0x{1:X8} VSize=0x{2:X8} RawPtr=0x{3:X8} RawSize=0x{4:X8}" -f `
        $s.Name, $s.VA, $s.VSize, $s.RawP, $s.RawS)
}

function Get-FileOffset([uint32]$rva) {
    foreach ($s in $secs) {
        if ($rva -ge $s.VA -and $rva -lt ($s.VA + [Math]::Max($s.VSize, $s.RawS))) {
            return [int]($s.RawP + ($rva - $s.VA))
        }
    }
    return -1
}
function Format-HexLine([byte[]]$bytes, [int]$base) {
    $hex = ($bytes | ForEach-Object { $_.ToString('x2') }) -join ' '
    $asc = -join ($bytes | ForEach-Object { if ($_ -ge 0x20 -and $_ -lt 0x7F) { [char]$_ } else { '.' } })
    return ("    {0:X8}  {1,-47}  {2}" -f $base, $hex, $asc)
}

if ($VAddr) {
    $rva = [Convert]::ToUInt32($VAddr, 16)
    $fo = Get-FileOffset $rva
    Write-Host ""
    Write-Host ("  rva 0x{0:X8} -> file 0x{1:X8}" -f $rva, $fo)
    if ($fo -ge 0) {
        $len = [Math]::Min($Length, $d.Length - $fo)
        for ($i = 0; $i -lt $len; $i += 16) {
            $chunk = $d[$fo + $i .. ([Math]::Min($fo + $i + 15, $fo + $len - 1))]
            Write-Host (Format-HexLine $chunk ($fo + $i))
        }
    }
    return
}

if ($Offset) {
    $fo = [Convert]::ToInt32($Offset, 16)
    if ($fo -lt 0 -or $fo -ge $d.Length) { throw "offset out of range" }
    $secName = 'none'
    foreach ($s in $secs) {
        if ($fo -ge $s.RawP -and $fo -lt ($s.RawP + $s.RawS)) { $secName = $s.Name; break }
    }
    Write-Host ""
    Write-Host ("  file 0x{0:X8}  (section: {1})" -f $fo, $secName)
    $len = [Math]::Min($Length, $d.Length - $fo)
    for ($i = 0; $i -lt $len; $i += 16) {
        $chunk = $d[$fo + $i .. ([Math]::Min($fo + $i + 15, $fo + $len - 1))]
        Write-Host (Format-HexLine $chunk ($fo + $i))
    }
    return
}

if ($Scan) {
    if (-not $Sig) { throw "-Scan needs -Sig <hex>" }
    # NOTE: deliberately not named $sig - PowerShell variables are case-insensitive,
    # so a local called $sig would alias the $Sig parameter and clobber it.
    $hex = ($Sig -replace '[^0-9a-fA-F]', '')
    if ($hex.Length -eq 0 -or ($hex.Length % 2) -ne 0) {
        throw "signature must contain an even number of hex digits (got '$Sig')"
    }
    $needle = New-Object byte[] ($hex.Length / 2)
    for ($i = 0; $i -lt $needle.Length; $i++) { $needle[$i] = [Convert]::ToByte($hex.Substring($i * 2, 2), 16) }

    $text = $secs | Where-Object { $_.Name -eq '.text' } | Select-Object -First 1
    if (-not $text) { throw "no .text section" }

    $hits = @()
    $start = [int]$text.RawP
    $end   = [Math]::Min([int]($text.RawP + $text.RawS), $d.Length)
    for ($i = $start; $i + $needle.Length -lt $end; $i++) {
        $ok = $true
        for ($j = 0; $j -lt $needle.Length; $j++) { if ($d[$i + $j] -ne $needle[$j]) { $ok = $false; break } }
        if ($ok) { $hits += $i }
    }

    Write-Host ""
    Write-Host ("  sig     : {0}  ({1} bytes)" -f $hex, $needle.Length)
    Write-Host ("  scanned : .text 0x{0:X8}..0x{1:X8}" -f $start, $end)
    Write-Host ("  hits    : {0}" -f $hits.Count)
    foreach ($h in $hits) {
        Write-Host ("    file 0x{0:X8}   {1}" -f $h, (($d[$h .. ($h + [Math]::Min(23, $needle.Length + 7))] | ForEach-Object { $_.ToString('x2') }) -join ' '))
    }
    if ($hits.Count -eq 1) { Write-Host "  verdict : UNIQUE - safe for the shape tier" -ForegroundColor Green }
    elseif ($hits.Count -eq 0) { Write-Host "  verdict : ABSENT - build changed, engine will refuse" -ForegroundColor Yellow }
    else { Write-Host "  verdict : AMBIGUOUS - engine will refuse (exit 4)" -ForegroundColor Red }
    return
}

Write-Host ""
Write-Host "  pass -Offset 0x.., -VAddr 0x.., or -Scan -Sig <hex>"
