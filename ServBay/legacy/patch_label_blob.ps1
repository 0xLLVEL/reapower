param(
  [string]$Dll = "C:\ServBay\app\ServBay.dll",
  [string]$Here = "C:\Users\ezan\AppData\Local\Temp\opencode\servbay-patch"
)
$ErrorActionPreference = "Stop"
Set-Location $Here

$cs = @'
using System;
using System.IO;
using System.Text;
using System.Collections.Generic;

public class BlobPatch {
    public const int S = 14180902;   // base array blob (FieldRVA field 0x04004D74, rva 0xD88026)
    public static byte[] Full;       // file bytes

    public static void Load(string path) { Full = File.ReadAllBytes(path); }

    public static byte Key(int i) { return (byte)((i ^ 170) & 0xFF); }

    public static string At(int off, int len) {
        byte[] o = new byte[len];
        for (int k = 0; k < len; k++) { int i = off + k; o[k] = (byte)(Full[S + i] ^ Key(i)); }
        return Encoding.UTF8.GetString(o);
    }

    public static void Write(int off, string s) {
        byte[] t = Encoding.UTF8.GetBytes(s);
        for (int k = 0; k < t.Length; k++) { int i = off + k; Full[S + i] = (byte)(t[k] ^ Key(i)); }
    }

    public static string Scan(string needle) {
        StringBuilder sb = new StringBuilder();
        int n = 501022;
        byte[] p = new byte[n];
        for (int i = 0; i < n; i++) p[i] = (byte)(Full[S + i] ^ Key(i));
        string all = Encoding.UTF8.GetString(p);
        int idx = 0; int c = 0;
        while ((idx = all.IndexOf(needle, idx)) >= 0 && c < 40) {
            int a = Math.Max(0, idx - 6), len = Math.Min(70, all.Length - a);
            string seg = all.Substring(a, len).Replace("\n","\\n").Replace("\r","").Replace("\0",".");
            sb.AppendLine(string.Format("    [{0}] len-nya bisa beda -> ...{1}", idx, seg));
            idx += needle.Length; c++;
        }
        if (c == 0) sb.AppendLine("    (tidak ada)");
        return sb.ToString();
    }
}
'@
Set-Content -Path .\BlobPatch.cs -Value $cs -Encoding ASCII
Add-Type -Path .\BlobPatch.cs -ErrorAction Stop

Write-Output "=== stop ServBay (kalau jalan) ==="
Get-CimInstance Win32_Process -Filter "Name LIKE 'ServBay%'" -ErrorAction SilentlyContinue | ForEach-Object {
  Write-Output ("  terminate " + $_.Name); try { $_ | Invoke-CimMethod -MethodName Terminate | Out-Null } catch {}
}
Start-Sleep -Seconds 3

[BlobPatch]::Load($Dll)
Write-Output "=== string 'ServBay *' di dalam blob (kandidat label plan) ==="
foreach ($t in @("ServBay Free","ServBay Pro","ServBay Team")) {
  Write-Output ("  -- '{0}'" -f $t)
  Write-Output ([BlobPatch]::Scan($t))
}

Write-Output "=== PATCH: blob[329651..329663] 'ServBay Free' -> 'ServBay Pro ' (panjang sama 12) ==="
$before = [BlobPatch]::At(329651, 12)
[BlobPatch]::Write(329651, "ServBay Pro ")
$after  = [BlobPatch]::At(329651, 12)
Write-Output ("  sebelum: '{0}'" -f $before)
Write-Output ("  sesudah: '{0}'" -f $after)

[IO.File]::WriteAllBytes($Dll, [BlobPatch]::Full)
Copy-Item $Dll ".\ServBay.dll.p8" -Force
Write-Output ("  SHA256 = " + (Get-FileHash $Dll -Algorithm SHA256).Hash)
Write-Output ("  SHA256 p7 = " + (Get-FileHash ".\ServBay.dll.p7" -Algorithm SHA256).Hash)
