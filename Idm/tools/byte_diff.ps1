<#
  byte_diff.ps1 — enumerate every differing byte between two builds of the same file.

  Usage:
    .\byte_diff.ps1 -A <original.exe> -B <patched.exe> [-Limit 40]

  Prints the total count, then the first -Limit offsets with both bytes, and
  confirms the file sizes match. Used to prove a patch is exactly N bytes and
  nothing else.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$A,
    [Parameter(Mandatory=$true)][string]$B,
    [int]$Limit = 40
)
$ErrorActionPreference = 'Stop'

if (-not ("ByteDiff" -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.IO;
using System.Text;
public class ByteDiff {
    public static string Run(string a, string b, int limit) {
        byte[] x = File.ReadAllBytes(a), y = File.ReadAllBytes(b);
        if (x.Length != y.Length) return "size differs: " + x.Length + " vs " + y.Length;
        StringBuilder sb = new StringBuilder();
        int n = 0;
        for (int i = 0; i < x.Length; i++) {
            if (x[i] == y[i]) continue;
            n++;
            if (n <= limit) sb.AppendLine(string.Format("  @0x{0:X}\torig={1:X2}\tpatched={2:X2}", i, x[i], y[i]));
        }
        sb.Insert(0, string.Format("total differing bytes: {0}{1}", n, Environment.NewLine));
        return sb.ToString();
    }
}
'@ -Language CSharp
}

Write-Output ("A (original) = " + (Get-FileHash $A -Algorithm SHA256).Hash)
Write-Output ("B (patched)  = " + (Get-FileHash $B -Algorithm SHA256).Hash)
Write-Output ([ByteDiff]::Run((Resolve-Path $A).Path, (Resolve-Path $B).Path, $Limit))
