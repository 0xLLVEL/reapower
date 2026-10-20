param(
    [ValidateSet('Status', 'Apply', 'Revert')]
    [string]$Mode = 'Status',

    [string]$AsarPath = (Join-Path $env:LOCALAPPDATA 'Programs\Lunar Client\resources\app.asar'),

    [string]$BackupDir = (Join-Path $env:LOCALAPPDATA 'LunarPatch\backup')
)

$ErrorActionPreference = 'Stop'

# Stage 4 - launcher branding, and the ad slot.
#
# Every edit below is length-preserving, which is the whole reason this stage can exist
# at all: an asar stores a per-file size and an absolute offset in its header, so a file
# that changes length would move every file after it and force a header rebuild. Net-zero
# edits leave the header byte-identical and the data section in place, so this patcher only
# ever rewrites bytes inside a file it located through the real header.
#
# The ads are not client-side flags. use-show-ad.js exports vn (the <Ad> component), which
# returns null unless metadata.ads has an entry for the placement AND the caller passes
# willShowAd. Only then does it render the <owadview> element and, unless hidePlusCta is
# set, the "Lunar Plus" upsell button. Both live inside vn's single return, so closing the
# gate at the top removes the ad and the upsell together. The renderer also gates on
# window.electron.isOverwolf() - this build is 3.7.25-ow, so that is always true, which is
# why the slot is live here and not on the non-Overwolf build.
#
# There is a hidden setting, bypass-lunar-plus-ad-exemption, but it forces the ad ON
# (use-show-ad.js returns o(!0) immediately when it is set). It is not a kill switch.
#
# The window title comes only from <title> in dist/html/main.html - the renderer never
# calls document.setTitle, so patching the tag is sufficient and no router hook exists.

$LiveAsar = Join-Path $env:LOCALAPPDATA 'Programs\Lunar Client\resources\app.asar'

function Test-LivePath
{
    param([string]$Path)
    if ([string]::IsNullOrEmpty($Path)) { return $false }
    try { return [IO.Path]::GetFullPath($Path) -eq [IO.Path]::GetFullPath($LiveAsar) } catch { return $false }
}

$Sites = @(
    [pscustomobject]@{
        File = '/dist/assets/use-show-ad.js'
        Name = 'ad.upsell-gate'
        Note = 'vn() always returns null - no <owadview>, no Lunar Plus CTA'
        Find = 'if(!(a&&e.willShowAd))return null;'
        Repl = 'if(!(!1/*xxxxxxxxx*/))return null;'
    },
    [pscustomobject]@{
        File = '/dist/html/main.html'
        Name = 'brand.window-title'
        Note = 'the one place the title is authored; no runtime setter exists'
        Find = '<title>Home - Lunar Client</title>'
        Repl = '<title>Home - Ratman4080  </title>'
    },
    [pscustomobject]@{
        File = '/dist/html/main.html'
        Name = 'brand.boot-logo'
        Note = 'the boot splash is an inline base64 webp; blanking its opacity removes it'
        Find = 'height:auto;opacity:.9;'
        Repl = 'height:auto;opacity:0 ;'
    },
    [pscustomobject]@{
        File = '/dist/html/main.html'
        Name = 'brand.logo-alt'
        Note = 'alt text on the boot splash image'
        Find = 'alt="Lunar Client"'
        Repl = 'alt="Ratman4080  "'
    }
)

# ---------------------------------------------------------------------------
# asar container
# ---------------------------------------------------------------------------

function Get-AsarInfo
{
    param([string]$Path)

    $fs = [IO.File]::OpenRead($Path)
    try
    {
        $head = New-Object byte[] 16
        [void]$fs.Read($head, 0, 16)
        if ([BitConverter]::ToUInt32($head, 0) -ne 4) { throw 'not an asar: first uint32 is not 4' }
        $jsonLen = [BitConverter]::ToUInt32($head, 12)
        $jbuf = New-Object byte[] $jsonLen
        [void]$fs.Read($jbuf, 0, $jsonLen)
    }
    finally { $fs.Dispose() }

    $tree = [Text.Encoding]::UTF8.GetString($jbuf) | ConvertFrom-Json
    $dataStart = 16 + $jsonLen
    $dataStart += (4 - ($dataStart % 4)) % 4

    return [pscustomobject]@{ Tree = $tree; DataStart = $dataStart; JsonLen = $jsonLen }
}

function Find-AsarNode
{
    param($Node, [string]$Want, [string]$Prefix = '')

    foreach ($p in $Node.files.PSObject.Properties)
    {
        $full = $Prefix + '/' + $p.Name
        if ($p.Value.PSObject.Properties['files'])
        {
            $hit = Find-AsarNode -Node $p.Value -Want $Want -Prefix $full
            if ($null -ne $hit) { return $hit }
        }
        elseif ($full -eq $Want) { return $p.Value }
    }
    return $null
}

function Read-AsarBytes
{
    param([string]$Path, [long]$Start, [long]$Length)
    $fs = [IO.File]::OpenRead($Path)
    try
    {
        $fs.Seek($Start, 'Begin') | Out-Null
        $buf = New-Object byte[] $Length
        $got = 0
        while ($got -lt $Length)
        {
            $n = $fs.Read($buf, $got, $Length - $got)
            if ($n -le 0) { throw 'short read from asar' }
            $got += $n
        }
        return $buf
    }
    finally { $fs.Dispose() }
}

function Write-AsarBytes
{
    param([string]$Path, [long]$Start, [byte[]]$Bytes)
    $fs = [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::Write, [IO.FileShare]::ReadWrite)
    try
    {
        $fs.Seek($Start, 'Begin') | Out-Null
        $fs.Write($Bytes, 0, $Bytes.Length)
    }
    finally { $fs.Dispose() }
}

function Get-Occurrences
{
    param([byte[]]$Hay, [string]$Needle)
    $n = [Text.Encoding]::UTF8.GetBytes($Needle)
    $hits = @()
    for ($i = 0; $i -le $Hay.Length - $n.Length; $i++)
    {
        $ok = $true
        for ($j = 0; $j -lt $n.Length; $j++)
        {
            if ($Hay[$i + $j] -ne $n[$j]) { $ok = $false; break }
        }
        if ($ok) { $hits += $i }
    }
    # NOT ",$hits": wrapping would hand the caller a one-element array containing the array,
    # so .Count would read 1 for every search. Plain return unrolls through the pipeline and
    # @() at the call site rebuilds 0 / 1 / n correctly.
    return $hits
}

function Splice-Bytes
{
    param([byte[]]$Hay, [int]$Pos, [int]$Len, [byte[]]$With)

    $out = New-Object byte[] ($Hay.Length - $Len + $With.Length)
    [Array]::Copy($Hay, 0, $out, 0, $Pos)
    [Array]::Copy($With, 0, $out, $Pos, $With.Length)
    [Array]::Copy($Hay, $Pos + $Len, $out, $Pos + $With.Length, $Hay.Length - $Pos - $Len)
    return $out
}

function Get-SpanSha
{
    param([string]$Text)
    $sha = [Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($Text))) -replace '-', '').ToLower() }
    finally { $sha.Dispose() }
}

# ---------------------------------------------------------------------------
# dispatch
# ---------------------------------------------------------------------------

# Status only reads, so an open launcher cannot race it. Apply and Revert rewrite bytes in
# a file the running app already has open, which is the case that needs closing first.
if ($Mode -ne 'Status' -and (Test-LivePath $AsarPath) -and (Get-Process -Name 'Lunar Client' -ErrorAction SilentlyContinue))
{
    throw 'Lunar Client is running - close it first'
}

if (-not (Test-Path $AsarPath)) { throw ("asar not found: {0}" -f $AsarPath) }

$info = Get-AsarInfo -Path $AsarPath
$before = (Get-FileHash $AsarPath -Algorithm SHA256).Hash.ToLower()
$sizeBefore = (Get-Item $AsarPath).Length

Write-Output ("asar     : {0}" -f $AsarPath)
Write-Output ("sha256   : {0}" -f $before)
Write-Output ("size     : {0} bytes   data starts at {1}" -f $sizeBefore, $info.DataStart)
Write-Output ("header   : {0} byte json, 4-aligned" -f $info.JsonLen)
Write-Output ""

if ($Mode -eq 'Apply' -and $before -ne $null -and (Test-Path (Join-Path $BackupDir 'app.asar.stage4.pristine')))
{
    # keep the first pristine copy; a second Apply must not overwrite it with staged bytes
}
elseif ($Mode -eq 'Apply')
{
    if (-not (Test-Path $BackupDir)) { New-Item -ItemType Directory -Path $BackupDir -Force | Out-Null }
    Copy-Item $AsarPath (Join-Path $BackupDir 'app.asar.stage4.pristine') -Force
    Write-Output ("backup   : {0}" -f (Join-Path $BackupDir 'app.asar.stage4.pristine'))
}

$rows = foreach ($s in $Sites)
{
    $node = Find-AsarNode -Node $info.Tree -Want $s.File
    if ($null -eq $node) { throw ("entry not in asar: {0}" -f $s.File) }

    $start = $info.DataStart + [long]$node.offset
    $blob = Read-AsarBytes -Path $AsarPath -Start $start -Length $node.size
    $text = [Text.Encoding]::UTF8.GetString($blob)

    $nFind = @(Get-Occurrences -Hay $blob -Needle $s.Find).Count
    $nRepl = @(Get-Occurrences -Hay $blob -Needle $s.Repl).Count

    if ($s.Find.Length -ne $s.Repl.Length) { throw ("{0}: net-zero violated, {1} != {2}" -f $s.Name, $s.Find.Length, $s.Repl.Length) }

    $state =
        if ($nFind -eq 1 -and $nRepl -eq 0) { 'unpatched' }
        elseif ($nFind -eq 0 -and $nRepl -eq 1) { 'patched' }
        else { throw ("{0}: expected exactly 1 of each span in {1}, found find={2} repl={3}" -f $s.Name, $s.File, $nFind, $nRepl) }

    [pscustomobject]@{
        Site  = $s.Name
        File  = $s.File
        State = $state
        Bytes = $node.size
        Sha   = (Get-SpanSha $s.Find).Substring(0, 16)
        Note  = $s.Note
        Spec  = $s
        Start = $start
        Text  = $text
        Blob  = $blob
        Size  = $node.size
    }
}

$rows | Select-Object Site, State, Bytes, Sha, Note | Format-Table -AutoSize | Out-String -Width 200 | Write-Output

if ($Mode -eq 'Status')
{
    $done = @($rows | Where-Object { $_.State -eq 'patched' }).Count
    Write-Output ("state    : {0}/{1} patched" -f $done, $rows.Count)
    return
}

$todo = if ($Mode -eq 'Apply') { @($rows | Where-Object { $_.State -eq 'unpatched' }) } else { @($rows | Where-Object { $_.State -eq 'patched' }) }

if ($todo.Count -eq 0)
{
    Write-Output ("state    : nothing to do - already {0}" -f $Mode.ToLower())
    return
}

# Group by file: one read, one in-memory edit, one write per file, so two sites that share
# a file (main.html has three) cannot overwrite each other's work.
#
# The splice runs on bytes, never on a decoded string. These bundles are not uniformly
# UTF-8 - round-tripping main.html through .NET's UTF8 decoder silently substituted
# U+FFFD for at least one byte sequence and changed the asar hash without changing its
# size, which made Revert fail to return to the original sha. Byte splicing is exact.
foreach ($group in ($todo | Group-Object -Property File))
{
    $node = Find-AsarNode -Node $info.Tree -Want $group.Name
    $start = $info.DataStart + [long]$node.offset
    $blob = Read-AsarBytes -Path $AsarPath -Start $start -Length $node.size

    foreach ($r in $group.Group)
    {
        $from = if ($Mode -eq 'Apply') { $r.Spec.Find } else { $r.Spec.Repl }
        $to   = if ($Mode -eq 'Apply') { $r.Spec.Repl } else { $r.Spec.Find }

        $fromBytes = [Text.Encoding]::UTF8.GetBytes($from)
        $toBytes = [Text.Encoding]::UTF8.GetBytes($to)

        $hits = @(Get-Occurrences -Hay $blob -Needle $from)
        if ($hits.Count -ne 1) { throw ("{0}: {1} occurrence(s) of the source span, expected 1" -f $r.Site, $hits.Count) }

        $blob = Splice-Bytes -Hay $blob -Pos $hits[0] -Len $fromBytes.Length -With $toBytes
        Write-Output ("spliced  : {0,-20} {1}" -f $r.Site, $(if ($Mode -eq 'Apply') { "$from -> $to" } else { "$to <- $from" }))
    }

    if ($blob.Length -ne $node.size) { throw ("{0}: size drifted {1} -> {2}, header would need a rebuild" -f $group.Name, $node.size, $blob.Length) }

    Write-AsarBytes -Path $AsarPath -Start $start -Bytes $blob
    Write-Output ("written  : {0}  ({1} bytes, offset {2})" -f $group.Name, $blob.Length, $start)
}

$after = (Get-FileHash $AsarPath -Algorithm SHA256).Hash.ToLower()
$sizeAfter = (Get-Item $AsarPath).Length

Write-Output ""
Write-Output ("size     : {0} -> {1}   (must be identical)" -f $sizeBefore, $sizeAfter)
if ($sizeAfter -ne $sizeBefore) { throw 'asar size changed - header is now wrong' }
Write-Output ("sha256   : {0}" -f $after)

# re-verify from disk, not from memory
$check = Get-AsarInfo -Path $AsarPath
foreach ($s in $Sites)
{
    $node = Find-AsarNode -Node $check.Tree -Want $s.File
    $blob = Read-AsarBytes -Path $AsarPath -Start ($check.DataStart + [long]$node.offset) -Length $node.size
    $expect = if ($Mode -eq 'Apply') { $s.Repl } else { $s.Find }
    $n = @(Get-Occurrences -Hay $blob -Needle $expect).Count
    Write-Output ("verify   : {0,-20} {1} x'{2}' {3}" -f $s.Name, $n, $expect.Substring(0, [Math]::Min(28, $expect.Length)), $(if ($n -eq 1) { 'OK' } else { 'FAIL' }))
    if ($n -ne 1) { throw ("verification failed for {0}" -f $s.Name) }
}
