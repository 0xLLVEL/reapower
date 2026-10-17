# compare_asar.ps1 — prove an ASAR rewrite changed exactly one entry and nothing else.
#
# Two independent checks:
#   1. header  - flatten both parsed trees to `path::property -> value` and diff
#   2. data    - compare the two data regions byte for byte
#
# Because ASAR file entries store `offset` relative to the start of the data
# region, a header that grows or shrinks slides the whole region without
# invalidating a single offset. Check 1 proves the offsets did not move; check 2
# proves the bytes behind them did not move either.
#
#   .\compare_asar.ps1 -Original .\app.asar.orig -Patched .\app.asar `
#                      -Skip 'out/main/index.js'

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string] $Original,
    [Parameter(Mandatory = $true)][string] $Patched,
    [string] $Skip = 'out/main/index.js'
)

$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Web.Extensions

$JS = New-Object System.Web.Script.Serialization.JavaScriptSerializer
$JS.MaxJsonLength = [int]::MaxValue
$JS.RecursionLimit = 256

function Read-Exactly([System.IO.Stream]$s, [int]$count, [int]$at) {
    $s.Position = $at
    $buf = New-Object byte[] $count
    $got = 0
    while ($got -lt $count) {
        $n = $s.Read($buf, $got, $count - $got)
        if ($n -le 0) { break }
        $got += $n
    }
    return ,$buf
}

# 150 MB compared in a C# loop: PowerShell's own byte loop takes minutes.
Add-Type -TypeDefinition @"
using System;
using System.IO;

public static class AsarDiff
{
    public static long FirstDifference(Stream a, long aOffset, Stream b, long bOffset, long count)
    {
        const int Chunk = 8 * 1024 * 1024;
        byte[] x = new byte[Chunk];
        byte[] y = new byte[Chunk];
        long done = 0;
        while (done < count)
        {
            int n = (int)Math.Min((long)Chunk, count - done);
            a.Position = aOffset + done; ReadFull(a, x, n);
            b.Position = bOffset + done; ReadFull(b, y, n);
            for (int i = 0; i < n; i++)
            {
                if (x[i] != y[i]) return done + i;
            }
            done += n;
        }
        return -1;
    }

    private static void ReadFull(Stream s, byte[] buf, int n)
    {
        int got = 0;
        while (got < n)
        {
            int r = s.Read(buf, got, n - got);
            if (r <= 0) throw new EndOfStreamException("short read");
            got += r;
        }
    }
}
"@

function Read-Asar([string]$path) {
    $fs = [System.IO.File]::Open($path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
    $lead = Read-Exactly $fs 8 0
    $headerSize = [BitConverter]::ToUInt32($lead, 4)
    $hdr = Read-Exactly $fs ([int]$headerSize) 8
    $jsonLen = [BitConverter]::ToUInt32($hdr, 4)
    $json = [System.Text.Encoding]::UTF8.GetString($hdr, 8, [int]$jsonLen)
    return [pscustomobject]@{
        Path = $path; Stream = $fs; FileSize = $fs.Length
        HeaderSize = [int]$headerSize; DataStart = 8 + [int]$headerSize
        Tree = $JS.DeserializeObject($json)
    }
}

function Add-Flat($node, [string]$NodePath, $Map, [ref]$Count) {
    if (-not ($node -is [System.Collections.IDictionary])) { return }
    foreach ($k in @($node.Keys)) {
        $v = $node[$k]
        if ($k -eq 'files' -and $v -is [System.Collections.IDictionary]) {
            foreach ($c in @($v.Keys)) {
                $childPath = $NodePath
                if ($childPath) { $childPath = "$childPath/$c" } else { $childPath = $c }
                $Count.Value++
                Add-Flat $v[$c] $childPath $Map $Count
            }
        } elseif ($v -is [System.Collections.IDictionary]) {
            Add-Flat $v "$NodePath::$k" $Map $Count
        } elseif ($v -is [System.Collections.IEnumerable] -and -not ($v -is [string])) {
            $parts = New-Object System.Collections.Generic.List[string]
            foreach ($e in $v) { $parts.Add([string]$e) }
            $Map["$NodePath::$k"] = ($parts -join ',')
        } else {
            $Map["$NodePath::$k"] = [string]$v
        }
    }
}

$a = Read-Asar $Original
$b = Read-Asar $Patched

try {
    $ma = New-Object 'System.Collections.Generic.Dictionary[string,string]'
    $mb = New-Object 'System.Collections.Generic.Dictionary[string,string]'
    $ca = 0; $cb = 0
    Add-Flat $a.Tree '' $ma ([ref]$ca)
    Add-Flat $b.Tree '' $mb ([ref]$cb)

    Write-Host ''
    Write-Host 'ASAR compare' -ForegroundColor Cyan
    Write-Host ("  A (original) = " + (Get-FileHash -LiteralPath $Original -Algorithm SHA256).Hash)
    Write-Host ("  B (patched)  = " + (Get-FileHash -LiteralPath $Patched  -Algorithm SHA256).Hash)
    Write-Host ("  size A       = " + ('{0,15:N0}' -f $a.FileSize) + " bytes")
    Write-Host ("  size B       = " + ('{0,15:N0}' -f $b.FileSize) + " bytes")
    Write-Host ("  entries      = " + ('{0,15:N0}' -f $ca) + "  /  " + ('{0:N0}' -f $cb))

    $prefix = "$Skip::"
    $diffs  = New-Object System.Collections.Generic.List[string]
    foreach ($kv in $ma.GetEnumerator()) {
        if ($kv.Key.StartsWith($prefix)) { continue }
        if (-not $mb.ContainsKey($kv.Key))      { $diffs.Add(("{0} : dropped" -f $kv.Key)); continue }
        if ($mb[$kv.Key] -ne $kv.Value)         { $diffs.Add(("{0} : '{1}' -> '{2}'" -f $kv.Key, $kv.Value, $mb[$kv.Key])) }
    }
    foreach ($kv in $mb.GetEnumerator()) {
        if ($kv.Key.StartsWith($prefix)) { continue }
        if (-not $ma.ContainsKey($kv.Key)) { $diffs.Add(("{0} : invented" -f $kv.Key)) }
    }
    Write-Host ("  header diffs = " + $diffs.Count + " outside " + $Skip)
    foreach ($d in $diffs) { Write-Host ("      " + $d) -ForegroundColor Red }

    $prefixA = "$Skip::"
    Write-Host ''
    Write-Host ("  inside " + $Skip + ":")
    foreach ($kv in $ma.GetEnumerator()) {
        if (-not $kv.Key.StartsWith($prefixA)) { continue }
        $now = '<absent>'
        if ($mb.ContainsKey($kv.Key)) { $now = $mb[$kv.Key] }
        if ($now -ne $kv.Value) { Write-Host ("      {0} : '{1}' -> '{2}'" -f $kv.Key, $kv.Value, $now) }
    }

    # ---- data region, byte for byte
    $lenA = $a.FileSize - $a.DataStart
    $lenB = $b.FileSize - $b.DataStart
    $common = [Math]::Min($lenA, $lenB)
    $firstDiff = [AsarDiff]::FirstDifference($a.Stream, [int64]$a.DataStart, $b.Stream, [int64]$b.DataStart, [int64]$common)

    Write-Host ''
    if ($firstDiff -ge 0) {
        Write-Host ("  data region  : FIRST DIFFERENCE at offset " + $firstDiff) -ForegroundColor Red
    } else {
        Write-Host ("  data region  : " + ('{0:N0}' -f $common) + " bytes compared byte for byte - identical") -ForegroundColor Green
    }
    Write-Host ("  appended     : " + ('{0:N0}' -f ($lenB - $lenA)) + " bytes at the end of B")
} finally {
    $a.Stream.Dispose()
    $b.Stream.Dispose()
}
