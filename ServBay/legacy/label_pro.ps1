param(
  [string]$Dll  = "C:\ServBay\app\ServBay.dll",
  [string]$Exe  = "C:\ServBay\app\ServBay.exe",
  [string]$Here = "C:\Users\ezan\AppData\Local\Temp\opencode\servbay-patch",
  [switch]$NoRestart
)
$ErrorActionPreference = "Stop"
Set-Location $Here

function Stop-ServBay {
  $procs = Get-CimInstance Win32_Process -Filter "Name LIKE 'ServBay%'" -ErrorAction SilentlyContinue
  if (-not $procs) { Write-Output "  (tidak ada proses ServBay)"; return }
  foreach ($p in $procs) {
    Write-Output ("  terminate PID {0} {1}" -f $p.ProcessId, $p.Name)
    try { $p | Invoke-CimMethod -MethodName Terminate | Out-Null } catch { Write-Output ("    gagal: " + $_.Exception.Message) }
  }
  for ($i = 0; $i -lt 30; $i++) {
    Start-Sleep -Milliseconds 500
    if (-not (Get-Process -Name ServBay -ErrorAction SilentlyContinue)) { break }
  }
  Start-Sleep -Milliseconds 800
}

Write-Output "=== 1. stop ServBay ==="
Stop-ServBay

Write-Output "=== 2. patch ==="
Add-Type -Path "$Here\Usx3.cs" -ErrorAction Stop
$u = New-Object Usx3
$u.Load($Dll)
$b = [IO.File]::ReadAllBytes($Dll)

$SITES = @(1577109, 2678828, 2678895)
$LDSTR = [byte[]](0x72, 0x01, 0x00, 0x00, 0x70)
$P     = 17245120

$already = $true
foreach ($s in $SITES) {
  if (-not ($b[$s] -eq 0x72 -and $b[$s+1] -eq 0x01)) { $already = $false }
}
if ($already) {
  Write-Output "  sudah dipatch sebelumnya, lewati"
} else {
  foreach ($s in $SITES) {
    if (-not ($b[$s] -eq 0x28 -and $b[$s+1] -eq 0x7B -and $b[$s+2] -eq 0x8C -and $b[$s+3] -eq 0x00 -and $b[$s+4] -eq 0x06)) {
      throw ("site {0} bukan 'call 0x06008C7B'" -f $s)
    }
  }
  for ($i = 0; $i -lt 32; $i++) { if ($b[$P+$i] -ne 0) { throw "slot #US baru tidak zero" } }

  $blk = New-Object byte[] 25
  $blk[0] = 0x00
  $blk[1] = 0x18
  $utf = [Text.Encoding]::Unicode.GetBytes("ServBay Pro")
  [Array]::Copy($utf, 0, $blk, 2, $utf.Length)
  $blk[24] = 0x00
  [Array]::Copy($blk, 0, $b, $P, 25)

  [BitConverter]::GetBytes([uint32]($P - $u.MdBase)).CopyTo($b, $u.UsEntryPos)
  [BitConverter]::GetBytes([uint32]25).CopyTo($b, $u.UsSizePos)

  foreach ($s in $SITES) { [Array]::Copy($LDSTR, 0, $b, $s, 5) }

  [IO.File]::WriteAllBytes($Dll, $b)
  Write-Output ("  ditulis. #US -> off={0} size=25 token=0x70000001" -f ($P - $u.MdBase))
}

$v = [IO.File]::ReadAllBytes($Dll)
foreach ($s in $SITES) {
  $h = ""; for ($i=0; $i -lt 5; $i++) { $h += ("{0:X2} " -f $v[$s+$i]) }
  Write-Output ("  site {0}: {1}" -f $s, $h)
}
$h2 = ""; for ($i=0; $i -lt 25; $i++) { $h2 += ("{0:X2} " -f $v[$P+$i]) }
Write-Output ("  slot {0}: {1}" -f $P, $h2)
Write-Output ("  #US off={0} size={1}" -f [BitConverter]::ToUInt32($v,$u.UsEntryPos), [BitConverter]::ToUInt32($v,$u.UsSizePos))
Write-Output ("  SHA256 = " + (Get-FileHash $Dll -Algorithm SHA256).Hash)

if (-not $NoRestart) {
  Write-Output "=== 3. start ServBay ==="
  Start-Process -FilePath $Exe
  Start-Sleep -Seconds 12
  $p = Get-Process -Name ServBay -ErrorAction SilentlyContinue
  if ($p) { Write-Output ("  jalan, PID {0}" -f $p.Id) } else { Write-Output "  TIDAK jalan" }
}
