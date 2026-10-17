# Herd License Patch — engine
#
# Rebuilds Herd's resources\app.asar with HerdShim.js appended to the
# out/main/index.js entry, so the app starts licensed with no launcher, no
# inspector port and no runtime dependency. Every other file in the archive
# keeps its exact offset and its exact bytes.
#
#   HerdPatch.ps1                     patch now (skips if already patched)
#   HerdPatch.ps1 -DryRun             report only, writes nothing
#   HerdPatch.ps1 -Force              re-bake even if already patched
#   HerdPatch.ps1 -Restore            put the pristine archive back
#
# The scheduled task polls this with -Quiet; the poll costs one 8 KiB tail read
# on the fast path, so it never re-parses a 156 MB archive for nothing.

[CmdletBinding()]
param(
    [string] $HerdDir            = 'C:\Program Files\Herd',
    [string] $StateDir           = 'C:\ProgramData\HerdPatch',
    [string] $Asar               = $null,   # default <HerdDir>\resources\app.asar
    [string] $Shim               = $null,   # default <script dir>\HerdShim.js
    [string] $Backup             = $null,   # default <StateDir>\backup\app.asar.orig
    [string] $Entry              = 'out/main/index.js',
    [int]    $WaitForExitSeconds = 120,
    [switch] $DryRun,
    [switch] $Restore,
    [switch] $Force,
    [switch] $Restart,
    [switch] $Quiet
)

$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Web.Extensions

$START_MARK = '/* ---- herd-pro ---- */'
$END_MARK   = '/* ---- /herd-pro ---- */'
$TAIL_BYTES = 8192

# PowerShell's own ConvertFrom-Json/ConvertTo-Json need ~70 s on a 5.1 MB asar
# header. The .NET JavaScriptSerializer does the same round-trip in about a
# second, which is what makes -Restore and -Force usable interactively.
$JS = New-Object System.Web.Script.Serialization.JavaScriptSerializer
$JS.MaxJsonLength = [int]::MaxValue
$JS.RecursionLimit = 256

$scriptDir = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Path }
if (-not $Asar)   { $Asar   = Join-Path $HerdDir 'resources\app.asar' }
if (-not $Shim)   { $Shim   = Join-Path $scriptDir 'HerdShim.js' }
if (-not $Backup) { $Backup = Join-Path $StateDir 'backup\app.asar.orig' }

function Say([string]$m) {
    if ($Quiet) { return }
    Write-Host $m
}

function Fail([string]$m, [int]$code) {
    Write-Host ("  [x] " + $m) -ForegroundColor Red
    exit $code
}

# The engine checks whether it can actually write next to the archive rather
# than who is running it, so a side-by-side install path works unelevated.
function Assert-Writable {
    if ($DryRun) { return }
    $probe = Join-Path (Split-Path -Parent $Asar) '.herd-pro.writetest'
    try {
        [System.IO.File]::WriteAllBytes($probe, [byte[]](0))
        Remove-Item -LiteralPath $probe -Force
    } catch {
        Fail "cannot write to $(Split-Path -Parent $Asar) - run as Administrator" 1
    }
}

# --------------------------------------------------------------------------- io

function Read-Exactly([System.IO.Stream]$s, [int]$count, [int]$at) {
    $s.Position = $at
    $buf = New-Object byte[] $count
    $got = 0
    while ($got -lt $count) {
        $n = $s.Read($buf, $got, $count - $got)
        if ($n -le 0) { break }
        $got += $n
    }
    if ($got -ne $count) { throw "short read at $at ($got of $count bytes)" }
    return ,$buf
}

# ASAR layout:
#   [u32 4][u32 headerPickleSize][u32 headerPicklePayload][u32 jsonLen][json .. <=3 pad][data ..]
# File entries store `offset` relative to the START OF THE DATA REGION, so when
# the header grows or shrinks the data region slides and every existing offset
# stays valid untouched.
function Read-Asar([string]$path) {
    $fs = [System.IO.File]::Open($path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
    try {
        $size = $fs.Length
        $lead = Read-Exactly $fs 8 0
        $sizePickle = [BitConverter]::ToUInt32($lead, 0)
        $headerSize = [BitConverter]::ToUInt32($lead, 4)
        if ($sizePickle -ne 4) { throw "unexpected size-pickle payload ($sizePickle)" }
        $hdr = Read-Exactly $fs ([int]$headerSize) 8
        $jsonLen = [BitConverter]::ToUInt32($hdr, 4)
        $json = [System.Text.Encoding]::UTF8.GetString($hdr, 8, [int]$jsonLen)
        return [pscustomobject]@{
            Path       = $path
            Stream     = $fs
            FileSize   = $size
            HeaderSize = [int]$headerSize
            DataStart  = 8 + [int]$headerSize
            JsonLen    = [int]$jsonLen
            Json       = $json
            Tree       = $JS.DeserializeObject($json)
        }
    } catch {
        $fs.Dispose()
        throw
    }
}

function Get-AsarEntry($tree, [string]$relPath) {
    $node = $tree
    foreach ($part in $relPath.Split('/')) {
        if (-not $part) { continue }
        if (-not ($node -is [System.Collections.IDictionary])) { return $null }
        if (-not $node.ContainsKey('files')) { return $null }
        $files = $node['files']
        if (-not $files.ContainsKey($part)) { return $null }
        $node = $files[$part]
    }
    return $node
}

function Get-EntryBytes($asar, $entry) {
    $off = [int64]$entry['offset']
    $len = [int]$entry['size']
    return (Read-Exactly $asar.Stream $len ([int]($asar.DataStart + $off)))
}

function Get-Sha256([string]$path) {
    return (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash
}

function Test-Patched([string]$path) {
    $fs = [System.IO.File]::Open($path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
    try {
        $take = [Math]::Min([int64]$TAIL_BYTES, $fs.Length)
        $tail = Read-Exactly $fs ([int]$take) ([int]($fs.Length - $take))
        return ([System.Text.Encoding]::ASCII.GetString($tail).IndexOf($END_MARK) -ge 0)
    } finally { $fs.Dispose() }
}

# --------------------------------------------------------------- verification

# Flattens a parsed header into `path::property -> value` and diffs the two
# maps. The target entry is skipped: it is the one thing the patch is allowed
# to change. This is what proves the JSON round-trip did not silently drop or
# rewrite a sibling entry.
function Add-Flat($node, [string]$NodePath, $Map) {
    if (-not ($node -is [System.Collections.IDictionary])) { return }
    foreach ($k in @($node.Keys)) {
        $v = $node[$k]
        if ($k -eq 'files' -and $v -is [System.Collections.IDictionary]) {
            foreach ($c in @($v.Keys)) {
                $childPath = $NodePath
                if ($childPath) { $childPath = "$childPath/$c" } else { $childPath = $c }
                Add-Flat $v[$c] $childPath $Map
            }
        } elseif ($v -is [System.Collections.IDictionary]) {
            Add-Flat $v "$NodePath::$k" $Map
        } elseif ($v -is [System.Collections.IEnumerable] -and -not ($v -is [string])) {
            $parts = New-Object System.Collections.Generic.List[string]
            foreach ($e in $v) { $parts.Add([string]$e) }
            $Map["$NodePath::$k"] = ($parts -join ',')
        } else {
            $Map["$NodePath::$k"] = [string]$v
        }
    }
}

function Compare-AsarTree($A, $B, [string]$Skip, $Out) {
    $ma = New-Object 'System.Collections.Generic.Dictionary[string,string]'
    $mb = New-Object 'System.Collections.Generic.Dictionary[string,string]'
    Add-Flat $A '' $ma
    Add-Flat $B '' $mb
    $prefix = "$Skip::"
    foreach ($kv in $ma.GetEnumerator()) {
        if ($kv.Key.StartsWith($prefix)) { continue }
        if (-not $mb.ContainsKey($kv.Key)) { $Out.Add(("{0} : dropped by the rebuild" -f $kv.Key)); continue }
        if ($mb[$kv.Key] -ne $kv.Value)     { $Out.Add(("{0} : '{1}' -> '{2}'" -f $kv.Key, $kv.Value, $mb[$kv.Key])) }
    }
    foreach ($kv in $mb.GetEnumerator()) {
        if ($kv.Key.StartsWith($prefix)) { continue }
        if (-not $ma.ContainsKey($kv.Key)) { $Out.Add(("{0} : invented by the rebuild" -f $kv.Key)) }
    }
}

# ---------------------------------------------------------------------- patch

function Invoke-Patch {
    Assert-Writable

    foreach ($p in @($Asar, $Shim)) {
        if (-not (Test-Path -LiteralPath $p)) { Fail "missing: $p" 2 }
    }

    Say ''
    Say 'Herd license patch'
    Say ("  target : " + $Asar)
    Say ("  size   : " + ('{0:N0}' -f (Get-Item -LiteralPath $Asar).Length) + " bytes")

    if ((Test-Patched $Asar) -and -not $Force) {
        Say '  already patched (tail marker present) - nothing to do'
        exit 0
    }

    # the loader has to come from a pristine archive - the live one may already
    # carry the shim, and baking shim-on-shim would grow on every poll
    if (-not (Test-Path -LiteralPath $Backup)) {
        $inPlace = Join-Path (Split-Path -Parent $Asar) 'app.asar.orig'
        if (Test-Path -LiteralPath $inPlace) {
            $Backup = $inPlace
            Say ("  source : " + $Backup + " (in-place backup)")
        }
    }
    if (-not (Test-Path -LiteralPath $Backup)) { Fail "no pristine archive to build from (expected $Backup)" 6 }
    if (Test-Patched $Backup) { Fail "backup $Backup is itself patched - restore or reinstall Herd first" 6 }

    $orig = Read-Asar $Backup
    try {
        $node = Get-AsarEntry $orig.Tree $Entry
        if ($null -eq $node) { Fail "entry not found in archive: $Entry" 7 }
        if ($node.ContainsKey('files')) { Fail "$Entry is a directory, not a file" 7 }
        if ($node.ContainsKey('unpacked') -and $node['unpacked']) { Fail "$Entry is unpacked and cannot be baked" 7 }

        $loader = Get-EntryBytes $orig $node
        # The shim is source text, so normalise its line endings before baking.
        # Otherwise the payload — and therefore the archive hash — would depend
        # on how the repository happened to be checked out.
        $shimText = [System.Text.Encoding]::UTF8.GetString([System.IO.File]::ReadAllBytes($Shim))
        $shim     = [System.Text.Encoding]::UTF8.GetBytes($shimText.Replace("`r`n", "`n"))
        $nl     = [byte[]](0x0A)
        $sm     = [System.Text.Encoding]::ASCII.GetBytes($START_MARK)
        $em     = [System.Text.Encoding]::ASCII.GetBytes($END_MARK)

        # loader \n /* ---- herd-pro ---- */ \n <shim> \n /* ---- /herd-pro ---- */ \n
        $payload = New-Object byte[] ($loader.Length + $shim.Length + $sm.Length + $em.Length + 4)
        $at = 0
        [Array]::Copy($loader, 0, $payload, $at, $loader.Length); $at += $loader.Length
        [Array]::Copy($nl, 0, $payload, $at, 1); $at += 1
        [Array]::Copy($sm, 0, $payload, $at, $sm.Length); $at += $sm.Length
        [Array]::Copy($nl, 0, $payload, $at, 1); $at += 1
        [Array]::Copy($shim, 0, $payload, $at, $shim.Length); $at += $shim.Length
        [Array]::Copy($nl, 0, $payload, $at, 1); $at += 1
        [Array]::Copy($em, 0, $payload, $at, $em.Length); $at += $em.Length
        [Array]::Copy($nl, 0, $payload, $at, 1); $at += 1

        $oldDataSize = $orig.FileSize - $orig.DataStart

        Say ("  entry  : " + $Entry)
        Say ("           " + ('{0:N0}' -f [int]$node['size']) + " -> " + ('{0:N0}' -f $at) + " bytes  (+" + ($at - [int]$node['size']) + ")")
        Say ("  loader : " + ('{0:N0}' -f $loader.Length) + " bytes from pristine archive")

        # the content changed on purpose, so the shipped digest no longer applies
        $null = $node.Remove('integrity')
        $node['size']   = $at
        $node['offset'] = "$oldDataSize"

        $jsonBytes = [System.Text.Encoding]::UTF8.GetBytes($JS.Serialize($orig.Tree))
        $pad = (4 - ($jsonBytes.Length % 4)) % 4
        $newHeaderSize = 8 + $jsonBytes.Length + $pad
        $newDataStart  = 8 + $newHeaderSize

        # prove the round-trip before a single byte is written
        $problems = New-Object System.Collections.Generic.List[string]
        Compare-AsarTree -A ($JS.DeserializeObject($orig.Json)) -B ($JS.DeserializeObject([System.Text.Encoding]::UTF8.GetString($jsonBytes))) -Skip $Entry -Out $problems
        if ($problems.Count -gt 0) {
            Say ("  [x] rebuilt header differs from the original in " + $problems.Count + " place(s):")
            $problems | Select-Object -First 20 | ForEach-Object { Say ("      " + $_) }
            Fail 'refusing to write a header that does not round-trip' 8
        }
        Say ("  header : " + ('{0:N0}' -f $orig.HeaderSize) + " -> " + ('{0:N0}' -f $newHeaderSize) + " bytes")
        Say '  check  : rebuilt header round-trips with every sibling entry identical'

        $newFileSize = $newDataStart + $oldDataSize + $payload.Length
        Say ("  result : " + ('{0:N0}' -f $orig.FileSize) + " -> " + ('{0:N0}' -f $newFileSize) + " bytes")

        if ($DryRun) {
            Say ''
            Say '  DRY RUN: nothing written'
            exit 0
        }

        $tmp = "$Asar.herd-pro.tmp"
        if (Test-Path -LiteralPath $tmp) { Remove-Item -LiteralPath $tmp -Force }

        $header = New-Object byte[] $newDataStart
        [BitConverter]::GetBytes([uint32]4).CopyTo($header, 0)
        [BitConverter]::GetBytes([uint32]$newHeaderSize).CopyTo($header, 4)
        # header-pickle payload length == buffer length - 4. Electron's asar reader
        # rejects the archive outright if this field is wrong, and the failure is
        # silent: the window never appears and no JS ever runs.
        [BitConverter]::GetBytes([uint32]($newHeaderSize - 4)).CopyTo($header, 8)
        [BitConverter]::GetBytes([uint32]$jsonBytes.Length).CopyTo($header, 12)
        $jsonBytes.CopyTo($header, 16)

        $out = [System.IO.File]::Open($tmp, [System.IO.FileMode]::Create, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
        try {
            $out.Write($header, 0, $header.Length)
            $src = $orig.Stream
            $src.Position = $orig.DataStart
            $buf = New-Object byte[] (8 * 1024 * 1024)
            $remaining = [int64]$oldDataSize
            while ($remaining -gt 0) {
                $n = [int][Math]::Min([int64]$buf.Length, $remaining)
                $r = $src.Read($buf, 0, $n)
                if ($r -le 0) { throw 'unexpected EOF copying the data region' }
                $out.Write($buf, 0, $r)
                $remaining -= $r
            }
            $out.Write($payload, 0, $payload.Length)
            $out.Flush()
        } finally { $out.Dispose() }

        Move-Item -LiteralPath $tmp -Destination $Asar -Force
        Say ("  sha256 : " + (Get-Sha256 $Asar))
        Say '  patched.' -ForegroundColor Green
    } finally { $orig.Stream.Dispose() }
}

function Invoke-Restore {
    Assert-Writable
    if (-not (Test-Path -LiteralPath $Backup)) { Fail "no pristine archive at $Backup" 6 }
    Say ''
    Say 'Herd license patch - restore'
    Say ("  from : " + $Backup)
    Say ("  to   : " + $Asar)
    if ($DryRun) { Say '  DRY RUN: nothing written'; exit 0 }
    Copy-Item -LiteralPath $Backup -Destination $Asar -Force
    Say ("  sha256 : " + (Get-Sha256 $Asar))
    Say '  restored.' -ForegroundColor Green
}

# ------------------------------------------------------------------ lifecycle

function Stop-HerdIfRunning {
    $procs = @(Get-Process -Name Herd -ErrorAction SilentlyContinue)
    if ($procs.Count -eq 0) { return $false }
    Say ("  herd   : " + $procs.Count + " process(es) running - closing")
    foreach ($p in $procs) { try { $p.CloseMainWindow() | Out-Null } catch {} }
    $deadline = (Get-Date).AddSeconds($WaitForExitSeconds)
    while ((Get-Date) -lt $deadline) {
        if (-not (Get-Process -Name Herd -ErrorAction SilentlyContinue)) { return $true }
        Start-Sleep -Milliseconds 500
    }
    if (Get-Process -Name Herd -ErrorAction SilentlyContinue) {
        Say '  herd   : still running - terminating'
        Get-Process -Name Herd -ErrorAction SilentlyContinue | Stop-Process -Force
        Start-Sleep -Milliseconds 2000
    }
    return $true
}

function Start-HerdBack {
    $exe = Join-Path $HerdDir 'Herd.exe'
    if (Test-Path -LiteralPath $exe) { Start-Process -FilePath $exe | Out-Null; Say '  herd   : restarted' }
}

# ----------------------------------------------------------------------- main

if (-not (Test-Path -LiteralPath $Asar)) { Fail "target not found: $Asar" 2 }

# Fast path first, before anything touches the running app: the scheduled poll
# runs every ten minutes and must not close Herd just to find nothing to do.
if (-not $Restore -and -not $Force -and (Test-Patched $Asar)) {
    Say ''
    Say 'Herd license patch'
    Say ("  target : " + $Asar)
    Say '  already patched (tail marker present) - nothing to do'
    exit 0
}

$wasRunning = $false
if (-not $DryRun) { try { $wasRunning = Stop-HerdIfRunning } catch {} }

$code = 0
try {
    if ($Restore) { Invoke-Restore } else { Invoke-Patch }
} catch {
    Write-Host ("  [x] " + $_.Exception.Message) -ForegroundColor Red
    Write-Host ("  [x] " + $_.InvocationInfo.PositionMessage) -ForegroundColor DarkGray
    $code = 9
}

if ($wasRunning -and $Restart -and $code -eq 0) { Start-HerdBack }
exit $code
