param(
    [Parameter(Mandatory=$true)][string]$Source,
    [Parameter(Mandatory=$true)][string]$Out,
    [int]$Keep = 50331648
)
# Build a "well-formed" derived artifact for REA:
# byte-identical prefix of Source (default 48 MiB), PE header adjusted
# so it only describes the area that actually exists.
# Metadata + IL bytes are NOT changed at all at the same offsets.

Add-Type -Path (Join-Path $PSScriptRoot 'Pe.cs') -ErrorAction SilentlyContinue

$src = [IO.File]::ReadAllBytes($Source)
if ($src.Length -lt $Keep) { $Keep = $src.Length }
$b = New-Object byte[] $Keep
[Array]::Copy($src, 0, $b, 0, $Keep)

$peOff  = [BitConverter]::ToInt32($b, 0x3C)
$optOff = $peOff + 24
$optSz  = [int][BitConverter]::ToUInt16($b, $peOff + 20)
$secOff = $optOff + $optSz
$is64   = ([BitConverter]::ToUInt16($b, $optOff) -eq 0x20B)

$keepRaw = $Keep - 0x200
[BitConverter]::GetBytes([uint32]$keepRaw).CopyTo($b, $secOff + 8)    # VirtualSize
[BitConverter]::GetBytes([uint32]$keepRaw).CopyTo($b, $secOff + 16)   # SizeOfRawData
[BitConverter]::GetBytes([uint32]0x200).CopyTo($b, $secOff + 20)      # PointerToRawData
[BitConverter]::GetBytes([uint16]1).CopyTo($b, $peOff + 6)            # NumberOfSections
[Array]::Clear($b, $secOff + 40, 40)                                  # drop the 2nd section entry
[BitConverter]::GetBytes([uint32](0x2000 + $keepRaw)).CopyTo($b, $optOff + 56)  # SizeOfImage

$ddOff = $optOff + ($(if ($is64) { 112 } else { 96 }))
$cliDir = $ddOff + 14 * 8
$cliRva = [BitConverter]::ToUInt32($b, $cliDir)
if ($cliRva -eq 0 -or $cliRva -ge $Keep) {
    throw "not a managed assembly in this range: CLI header (COM descriptor directory) is empty or beyond $Keep bytes"
}
for ($i = 0; $i -lt 16; $i++) {
    $rva = [BitConverter]::ToUInt32($b, $ddOff + $i * 8)
    $sz  = [BitConverter]::ToUInt32($b, $ddOff + $i * 8 + 4)
    if ($rva -ne 0 -and ($rva -ge $Keep -or ($rva + $sz) -gt $Keep)) { [Array]::Clear($b, $ddOff + $i * 8, 8) }
}
$cliOff = $cliRva - 0x2000 + 0x200
if ($cliOff -lt 0 -or $cliOff + 72 -gt $Keep) {
    throw "CLI header at rva 0x$("{0:X}" -f $cliRva) maps outside the kept range; raise -Keep"
}
foreach ($f in @(24, 32, 40, 48, 56, 64)) {
    $rva = [BitConverter]::ToUInt32($b, $cliOff + $f)
    $sz  = [BitConverter]::ToUInt32($b, $cliOff + $f + 4)
    if ($rva -ne 0 -and ($rva -ge $Keep -or ($rva + $sz) -gt $Keep)) { [Array]::Clear($b, $cliOff + $f, 8) }
}
[IO.File]::WriteAllBytes($Out, $b)
Write-Output ("  REA artifact: {0}  ({1:n0} bytes, byte-identical prefix of the source)" -f $Out, $Keep)
Write-Output ("  SHA256     : " + (Get-FileHash $Out -Algorithm SHA256).Hash)
