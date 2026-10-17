param(
  [string]$Dll  = "C:\ServBay\app\ServBay.dll",
  [string]$Exe  = "C:\ServBay\app\ServBay.exe",
  [string]$Here = "C:\Users\ezan\AppData\Local\Temp\opencode\servbay-patch"
)
$ErrorActionPreference = "Stop"
Set-Location $Here

Write-Output "=== 1. stop ServBay ==="
$procs = Get-CimInstance Win32_Process -Filter "Name LIKE 'ServBay%'" -ErrorAction SilentlyContinue
foreach ($p in $procs) {
  Write-Output ("  terminate {0} PID {1}" -f $p.Name, $p.ProcessId)
  try { $p | Invoke-CimMethod -MethodName Terminate | Out-Null } catch {}
}
Start-Sleep -Seconds 3

Write-Output "=== 2. pindahkan #US ke [17244932,17244960) (masih di dalam VirtualSize .text) ==="
Add-Type -Path "$Here\Usx3.cs" -ErrorAction Stop
$u = New-Object Usx3
$u.Load($Dll)
$b = [IO.File]::ReadAllBytes($Dll)

$P = 17244932                      # awal area bebas terakhir yang ter-map
$need = 25
$mapEnd = 17244960                 # batas akhir .text yang ter-map (VA 0x2000 + VSize 0x1072120)
if (($P + $need) -gt $mapEnd) { throw "slot tidak cukup" }

$blk = New-Object byte[] $need
$blk[0] = 0x00
$blk[1] = 0x18
$utf = [Text.Encoding]::Unicode.GetBytes("ServBay Pro")
[Array]::Copy($utf, 0, $blk, 2, $utf.Length)
$blk[24] = 0x00
[Array]::Copy($blk, 0, $b, $P, $need)

[BitConverter]::GetBytes([uint32]($P - $u.MdBase)).CopyTo($b, $u.UsEntryPos)
[BitConverter]::GetBytes([uint32]$need).CopyTo($b, $u.UsSizePos)
[IO.File]::WriteAllBytes($Dll, $b)
Write-Output ("  #US -> off rel MdBase = {0}  (abs {1})  size {2}  token 0x70000001" -f ($P-$u.MdBase), $P, $need)

Write-Output "=== 3. verifikasi byte ==="
$v = [IO.File]::ReadAllBytes($Dll)
foreach ($s in @(1577109,2678828,2678895)) {
  $h=""; for($i=0;$i -lt 5;$i++){ $h += ("{0:X2} " -f $v[$s+$i]) }
  Write-Output ("  site {0}: {1}" -f $s,$h)
}
$h2=""; for($i=0;$i -lt 25;$i++){ $h2 += ("{0:X2} " -f $v[$P+$i]) }
Write-Output ("  #US  {0}: {1}" -f $P,$h2)
Write-Output ("  entry: off={0} size={1}" -f [BitConverter]::ToUInt32($v,$u.UsEntryPos), [BitConverter]::ToUInt32($v,$u.UsSizePos))

Write-Output "=== 4. jalankan ServBay (tangkap output) ==="
Remove-Item "$Here\sb_out.txt","$Here\sb_err.txt" -ErrorAction SilentlyContinue
$p = Start-Process -FilePath $Exe -PassThru -RedirectStandardOutput "$Here\sb_out.txt" -RedirectStandardError "$Here\sb_err.txt"
Write-Output ("  PID " + $p.Id)
Start-Sleep -Seconds 20
$still = Get-Process -Id $p.Id -ErrorAction SilentlyContinue
if ($still) {
  Write-Output "  MASIH JALAN"
} else {
  Write-Output ("  MATI. ExitCode = " + $p.ExitCode)
}
Write-Output "--- stdout ---"
if (Test-Path "$Here\sb_out.txt") { Get-Content "$Here\sb_out.txt" -Tail 40 | Write-Output }
Write-Output "--- stderr ---"
if (Test-Path "$Here\sb_err.txt") { Get-Content "$Here\sb_err.txt" -Tail 60 | Write-Output }
