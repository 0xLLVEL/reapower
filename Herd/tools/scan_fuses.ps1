# scan_fuses.ps1 — read the Electron fuse wire out of an Electron executable.
#
# Electron bakes a small wire into the binary: a 32-byte sentinel followed by
# [1 byte schema version][1 byte fuse count][N bytes of state], where each state
# byte is '0' (disabled), '1' (enabled) or 'r' (removed).
#
# For this patch two of them matter:
#   EnableEmbeddedAsarIntegrityValidation  - if enabled, a rebuilt app.asar is
#                                            rejected before any JS runs
#   OnlyLoadAppFromAsar                    - if enabled, resources\app is not a
#                                            valid fallback
#
#   .\scan_fuses.ps1 -Exe 'C:\Program Files\Herd\Herd.exe'
#
# The haystack search is a C# loop: PowerShell indexing over a 250 MB binary
# takes minutes, the compiled scan is sub-second.

[CmdletBinding()]
param([Parameter(Mandatory = $true)][string] $Exe)

$ErrorActionPreference = 'Stop'

Add-Type -TypeDefinition @"
using System;

public static class FuseWire
{
    public static long Find(byte[] haystack, byte[] needle)
    {
        if (needle.Length == 0 || haystack.Length < needle.Length) return -1;
        byte first = needle[0];
        int limit = haystack.Length - needle.Length;
        for (int i = 0; i <= limit; i++)
        {
            if (haystack[i] != first) continue;
            int j = 1;
            while (j < needle.Length && haystack[i + j] == needle[j]) j++;
            if (j == needle.Length) return i;
        }
        return -1;
    }
}
"@

$WIRE  = 'dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX'
$NAMES = @(
    'RunAsNode',
    'EnableCookieEncryption',
    'EnableNodeOptionsEnvironmentVariable',
    'EnableNodeCliInspectArguments',
    'EnableEmbeddedAsarIntegrityValidation',
    'OnlyLoadAppFromAsar',
    'LoadBrowserProcessSpecificV8Snapshot',
    'GrantFileProtocolExtraPrivileges'
)

$bytes  = [System.IO.File]::ReadAllBytes($Exe)
$needle = [System.Text.Encoding]::ASCII.GetBytes($WIRE)
$at = [FuseWire]::Find($bytes, $needle)

if ($at -lt 0) { Write-Host 'fuse wire not found' -ForegroundColor Red; exit 1 }

$version = $bytes[$at + $WIRE.Length]
$count   = $bytes[$at + $WIRE.Length + 1]

Write-Host ''
Write-Host 'Electron fuses' -ForegroundColor Cyan
Write-Host ("  exe            : " + $Exe)
Write-Host ("  exe size       : " + ('{0:N0}' -f $bytes.Length) + " bytes")
Write-Host ("  wire offset    : " + $at)
Write-Host ("  schema version : " + $version)
Write-Host ("  fuse count     : " + $count)
Write-Host ''
for ($i = 0; $i -lt $count; $i++) {
    $c = [char]$bytes[$at + $WIRE.Length + 2 + $i]
    $state = '?'; $color = 'Gray'
    if ($c -eq '1') { $state = 'ENABLED';  $color = 'Yellow' }
    if ($c -eq '0') { $state = 'disabled'; $color = 'DarkGray' }
    if ($c -eq 'r') { $state = 'REMOVED';  $color = 'DarkGray' }
    $name = "fuse#$i"
    if ($i -lt $NAMES.Count) { $name = $NAMES[$i] }
    Write-Host ("  {0,-2} {1,-42} {2}" -f $i, $name, $state) -ForegroundColor $color
}
