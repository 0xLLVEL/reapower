param(
    [ValidateSet('Status', 'Apply', 'Revert', 'Stage2Status', 'Stage2Apply', 'Stage2Revert')]
    [string]$Mode = 'Status',

    [string]$ExePath = (Join-Path $env:LOCALAPPDATA 'Programs\Lunar Client\Lunar Client.exe'),

    [string]$AsarPath = (Join-Path $env:LOCALAPPDATA 'Programs\Lunar Client\resources\app.asar'),

    [string]$AccountsPath = (Join-Path $env:USERPROFILE '.lunarclient\settings\game\accounts.json'),

    [string]$BackupDir = (Join-Path $env:LOCALAPPDATA 'LunarPatch\backup')
)

$ErrorActionPreference = 'Stop'

# Path defaults are spelled out in the param block (which has to stay the first statement),
# so restate them here: these decide whether Lunar being open actually matters. It only does
# for the live files - a launcher already running cannot race a sandbox copy.
$LiveExe      = Join-Path $env:LOCALAPPDATA 'Programs\Lunar Client\Lunar Client.exe'
$LiveAsar     = Join-Path $env:LOCALAPPDATA 'Programs\Lunar Client\resources\app.asar'
$LiveAccounts = Join-Path $env:USERPROFILE '.lunarclient\settings\game\accounts.json'

function Test-LivePath
{
    param([string]$Path)
    if ([string]::IsNullOrEmpty($Path)) { return $false }
    try { $full = [IO.Path]::GetFullPath($Path) } catch { return $false }
    foreach ($live in @($LiveExe, $LiveAsar, $LiveAccounts))
    {
        if ($full -eq [IO.Path]::GetFullPath($live)) { return $true }
    }
    return $false
}

$PristineSha = 'c1d3f36dba310629aedec239b6c55a2f1cfe21e6930dff2ee0440c169718628e'
$PatchedSha = 'cc94512fa4ac83d88a1eea94a24d8d066d037f411b96cf7d23cb3eca3a3c36d7'
$FuseMarker = 'dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX'

# stage 2 - ownership gate. app.asar carries main.js at a fixed offset; both edits
# are length-preserving, so the asar header never changes.
$AsarPristineSha = '40c417203aabaf1fe01ac4c0482beada823c86f3762aaa72e122aa5c339c20ae'
$AsarPatchedSha  = '4334600f59637c33c116bc6585bf3859534cc5d9acec901955a66c5d096e04ee'
$AsarSize        = 25797518
$HeaderLen       = 347756
$MainOffset      = 4939
$MainSize        = 5754280

$S2LrText  = 'stage2: ownership gate disabled (LR)'
$S2LrNew   = 'LR=async e=>!0/*' + $S2LrText + (' ' * (331 - 16 - $S2LrText.Length - 3)) + '*/,'
$S2CallNew = '{username:r.minecraftProfile.name,uuid:r.minecraftProfile.id,nameChangeData:void 0,attributes:void 0}'

$S2Sites = @(
    [pscustomobject]@{
        Name      = 'auth.LR.ownership-check'
        OldAnchor = 'LR=async e=>{let t=IR();'
        NewAnchor = 'LR=async e=>!0/*'
        OldSpan   = 398
        NewSpan   = 331
        OldSha    = '4fa3e75ed8f87282f933fb05b92e31559877933260d290f4ef1d8cee8a90c3ea'
        NewText   = $S2LrNew
        Note      = 'entitlements check always true - both NO_OWNERSHIP throws die'
    },
    [pscustomobject]@{
        Name      = 'launch.profile-call'
        OldAnchor = 'await zR(r.accessToken,r.remoteId)'
        NewAnchor = '{username:r.minecraftProfile.name,uuid:r.minecraftProfile.id'
        OldSpan   = 34
        NewSpan   = 101
        OldSha    = '9f28452edf8466648d3d7697be31864c45b696b2b6a490b205f3ef4d78fba38b'
        NewText   = $S2CallNew
        Note      = 'profile from accounts.json - attributes void 0 short-circuits multiplayer/ban checks'
    }
)

foreach ($s in $S2Sites) { if ($s.NewText.Length -ne $s.NewSpan) { throw ("internal: new span {0} is {1} chars, expected {2}" -f $s.Name, $s.NewText.Length, $s.NewSpan) } }
$oldTotal = 0; $newTotal = 0
foreach ($s in $S2Sites) { $oldTotal += $s.OldSpan; $newTotal += $s.NewSpan }
if ($oldTotal -ne $newTotal) { throw 'internal: stage 2 spans are not net-zero' }

# minecraftProfile.id MUST look like a random v4 UUID: mN() only strips dashes when
# fN=/^(...4...|[89ab]...)$/ matches, so a non-v4 id breaks getAccount(dashedId) and the
# AssetServer client dies with SR.NO_ACCOUNT before it ever opens a socket.
$S2AccountId   = '9f8e7d6c5b4a49289706f5e4d3c2b1a0'
$S2LocalId     = '7a1f0c3b-5d9e-4f68-a2b7-c1d0e3f5a9b4'
# AccountManager.load() rejects an account when accessTokenExpiresAt is MORE than 14 days in
# the future. Bytecode at 226..243: aload iat; invokestatic Instant.now(); ldc2_w 14; getstatic
# DAYS; invokevirtual plus; invokevirtual isAfter; ifeq -> accept. plus pops DAYS, 14L then now
# as RECEIVER, so isAfter runs on iat: iat.isAfter(now.plus(14, DAYS)). It is an anti-tamper
# check, which is why 2099-12-31 was rejected while a real 1-hour MS token passes.
# Window is (now - 14d, now + 14d]. Use +12h: it mimics a live token and stays clear of any
# isBefore(now) "expired" branch that would fire a RefreshAccount the launcher cannot satisfy.
# 13 days, not 12 hours. `executeWithAccessToken` refreshes when accessTokenExpiresAt is
# before now, and that refresh goes out over the network to a session this setup cannot
# establish - so a lapsed timestamp does not degrade the account, it stops it launching
# until someone refreshes it. The 14-day ceiling in the load check sits on `iat`, read
# out of the token, not on this field; `$S2WindowDays` below is what bounds it, and the
# two are deliberately one day apart.
$S2ExpiresAt   = (Get-Date).ToUniversalTime().AddDays(13).ToString('yyyy-MM-ddTHH:mm:ss.fff') + 'Z'
$S2WindowDays  = 14
$S2AccountsNew = @"
{
  "accounts": {
    "$S2LocalId": {
      "accessToken": "stage2-offline-access-token",
      "accessTokenExpiresAt": "$S2ExpiresAt",
      "localId": "$S2LocalId",
      "refreshToken": "stage2-offline-refresh-token",
      "minecraftProfile": {
        "id": "$S2AccountId",
        "name": "Ratman4080"
      },
      "remoteId": "$S2LocalId",
      "type": "Xbox",
      "username": "Ratman4080",
      "eligibleForMigration": false,
      "hasMultipleProfiles": false,
      "legacy": false,
      "persistent": true,
      "userProperties": []
    }
  },
  "activeAccountLocalId": "$S2LocalId"
}
"@

Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;

public static class LP
{
    public static byte[] Ascii(string s)
    {
        return System.Text.Encoding.ASCII.GetBytes(s);
    }

    public static int[] FindAll(byte[] haystack, byte[] needle)
    {
        List<int> hits = new List<int>();
        int limit = haystack.Length - needle.Length;
        for (int i = 0; i <= limit; i++)
        {
            int j = 0;
            while (j < needle.Length && haystack[i + j] == needle[j]) j++;
            if (j == needle.Length) hits.Add(i);
        }
        return hits.ToArray();
    }

    public static int OrdinalIndexOf(string s, string token)
    {
        return s.IndexOf(token, StringComparison.Ordinal);
    }

    public static string Sha256(string path)
    {
        using (System.Security.Cryptography.SHA256 h = System.Security.Cryptography.SHA256.Create())
        using (System.IO.FileStream fs = System.IO.File.OpenRead(path))
        {
            byte[] d = h.ComputeHash(fs);
            System.Text.StringBuilder sb = new System.Text.StringBuilder(d.Length * 2);
            for (int i = 0; i < d.Length; i++) sb.Append(d[i].ToString("x2"));
            return sb.ToString();
        }
    }

    public static string Sha256Bytes(byte[] data)
    {
        using (System.Security.Cryptography.SHA256 h = System.Security.Cryptography.SHA256.Create())
        {
            byte[] d = h.ComputeHash(data);
            System.Text.StringBuilder sb = new System.Text.StringBuilder(d.Length * 2);
            for (int i = 0; i < d.Length; i++) sb.Append(d[i].ToString("x2"));
            return sb.ToString();
        }
    }
}
'@

function Get-Sites
{
    $agg = 'owepm.aggregate'
    $note = 'validator: blocked flag forced false'
    return @(
        [pscustomobject]@{ Name = 'fuse.asar-integrity-validation'; Pattern = $FuseMarker; PatchIndex = 38; From = [byte]0x31; To = [byte]0x30; Note = 'fuse idx 4: 1 -> 0 (asar content check off)' },
        [pscustomobject]@{ Name = "$agg.present"; Pattern = 'o.blocked&&(u=!0,p=o.blockReason)'; PatchIndex = -1; From = [byte]0x30; To = [byte]0x31; Note = $note },
        [pscustomobject]@{ Name = "$agg.jwt"; Pattern = '!u&&n.blocked&&(u=!0,p=n.blockReason)'; PatchIndex = -1; From = [byte]0x30; To = [byte]0x31; Note = $note },
        [pscustomobject]@{ Name = "$agg.signed"; Pattern = '!u&&s.blocked&&(u=!0,p=s.blockReason)'; PatchIndex = -1; From = [byte]0x30; To = [byte]0x31; Note = $note },
        [pscustomobject]@{ Name = "$agg.fuse"; Pattern = '!u&&c.blocked&&(u=!0,p=c.blockReason)'; PatchIndex = -1; From = [byte]0x30; To = [byte]0x31; Note = $note },
        [pscustomobject]@{ Name = "$agg.signature"; Pattern = '!u&&g.blocked&&(u=!0,p=g.blockReason)'; PatchIndex = -1; From = [byte]0x30; To = [byte]0x31; Note = $note },
        [pscustomobject]@{ Name = "$agg.exception"; Pattern = 'd||(u=!0,p="validation exception: "'; PatchIndex = -1; From = [byte]0x30; To = [byte]0x31; Note = $note },
        [pscustomobject]@{ Name = 'owepm.fatalCatch'; Pattern = 'blocked:!0,blockReason:"validation fatal error"'; PatchIndex = -1; From = [byte]0x30; To = [byte]0x31; Note = 'validator: outer catch never blocks' }
    )
}

function Resolve-Site
{
    param([pscustomobject]$Site)
    if ($Site.PatchIndex -ge 0) { return $Site }
    $key = 'u=!0'
    if ($Site.Name -eq 'owepm.fatalCatch') { $key = 'blocked:!0' }
    $at = [LP]::OrdinalIndexOf($Site.Pattern, $key)
    if ($at -lt 0) { throw ("internal: patch key '{0}' missing from pattern '{1}'" -f $key, $Site.Pattern) }
    $clone = [pscustomobject]@{ Name = $Site.Name; Pattern = $Site.Pattern; PatchIndex = $at + 3; From = $Site.From; To = $Site.To; Note = $Site.Note }
    if ($Site.Name -eq 'owepm.fatalCatch') { $clone.PatchIndex = $at + 9 }
    return $clone
}

function Get-Plan
{
    param([byte[]]$Buffer, [pscustomobject[]]$Sites)
    $plan = @()
    foreach ($raw in $Sites)
    {
        $site = Resolve-Site -Site $raw
        $orig = [LP]::FindAll($Buffer, [LP]::Ascii($site.Pattern))
        $found = @()
        foreach ($hit in $orig) { $found += @{ Offset = [long]$hit + $site.PatchIndex; State = 'original' } }

        if ($site.PatchIndex -lt $site.Pattern.Length)
        {
            $patchedBytes = [LP]::Ascii($site.Pattern)
            $patchedBytes[$site.PatchIndex] = $site.To
            foreach ($hit in ([LP]::FindAll($Buffer, $patchedBytes))) { $found += @{ Offset = [long]$hit + $site.PatchIndex; State = 'patched' } }
        }

        if ($found.Count -ne 1)
        {
            throw ("pattern '{0}' resolved to {1} candidate(s), expected 1 - binary layout changed, refusing to touch it" -f $site.Name, $found.Count)
        }

        $entry = $found[0]
        $actual = $Buffer[$entry.Offset]
        $state = if ($actual -eq $site.From) { 'original' }
                 elseif ($actual -eq $site.To) { 'patched' }
                 else { 'unexpected' }

        $plan += [pscustomobject]@{
            Site   = $site.Name
            Offset = [long]$entry.Offset
            State  = $state
            From   = $site.From
            To     = $site.To
            Note   = $site.Note
        }
    }
    return $plan
}

function Write-Plan
{
    param([object[]]$Plan, [string]$OverrideState)
    $Plan | ForEach-Object {
        [pscustomobject]@{
            Site   = $_.Site
            Offset = ('0x{0:x8}' -f $_.Offset)
            State  = if ($OverrideState) { $OverrideState } else { $_.State }
            Note   = $_.Note
        }
    } | Format-Table -AutoSize | Out-String | Write-Output
}

function Get-MainSegment
{
    param([byte[]]$Asar)
    if ($Asar.Length -ne $AsarSize) { throw ("asar is {0} bytes, expected {1} - not the known build" -f $Asar.Length, $AsarSize) }
    if ([BitConverter]::ToUInt32($Asar, 0) -ne 4) { throw 'asar header magic mismatch' }
    $hdrLen = [BitConverter]::ToUInt32($Asar, 12)
    if ($hdrLen -ne $HeaderLen) { throw ("asar header is {0} bytes, expected {1}" -f $hdrLen, $HeaderLen) }
    $base = 16 + [int]$hdrLen
    if (-not ($Asar[$base] -eq 0x89 -and $Asar[$base + 1] -eq 0x50 -and $Asar[$base + 2] -eq 0x4E -and $Asar[$base + 3] -eq 0x47)) { throw 'asar data base not found - header layout changed' }
    try
    {
        $json = [Text.Encoding]::UTF8.GetString($Asar, 16, [int]$hdrLen) | ConvertFrom-Json
        $entry = $json.files.'dist-electron'.files.'electron'.files.'main.js'
        if (-not $entry) { throw 'entry missing' }
        if ([int64]$entry.size -ne $MainSize -or [string]$entry.offset -ne [string]$MainOffset) { throw 'entry offset/size mismatch' }
    }
    catch { Write-Warning ("asar header json cross-check skipped: {0}" -f $_.Exception.Message) }
    $start = $base + $MainOffset
    if (($start + $MainSize) -gt $Asar.Length) { throw 'main.js range falls outside the asar' }
    $seg = New-Object byte[] $MainSize
    [Array]::Copy($Asar, $start, $seg, 0, $MainSize)
    return , $seg
}

function Get-SiteState
{
    param([byte[]]$Seg, [pscustomobject]$Site)
    $state = 'none'
    $offset = [long]-1
    foreach ($pair in @(@($Site.OldAnchor, $Site.OldSpan, $Site.OldSha, 'original'), @($Site.NewAnchor, $Site.NewSpan, $null, 'patched')))
    {
        foreach ($hit in [LP]::FindAll($Seg, [LP]::Ascii($pair[0])))
        {
            if (($hit + [int]$pair[1]) -gt $Seg.Length) { continue }
            $slice = New-Object byte[] ([int]$pair[1])
            [Array]::Copy($Seg, $hit, $slice, 0, [int]$pair[1])
            $actual = [LP]::Sha256Bytes($slice)
            if ($pair[2]) { if ($actual -ne $pair[2]) { throw ("{0}: anchor matched but the surrounding span is unknown - build changed" -f $Site.Name) } }
            elseif ($actual -ne [LP]::Sha256Bytes([LP]::Ascii($Site.NewText))) { throw ("{0}: patched anchor matched but the span is not ours" -f $Site.Name) }
            if ($state -ne 'none') { throw ("{0}: {1} candidate spans resolved, expected 1" -f $Site.Name, 2) }
            $state = [string]$pair[3]
            $offset = [long]$hit
        }
    }
    if ($state -eq 'none') { throw ("{0}: neither the original nor the patched span is present" -f $Site.Name) }
    return [pscustomobject]@{ Site = $Site; State = $state; Offset = $offset }
}

function New-PatchedSegment
{
    param([byte[]]$Seg, [object[]]$Found)
    $sorted = @($Found | Sort-Object Offset)
    $pieces = New-Object System.Collections.Generic.List[byte[]]
    $pos = 0
    $total = 0
    foreach ($f in $sorted)
    {
        if ($f.Offset -lt $pos) { throw 'internal: stage 2 spans overlap' }
        $curSpan = if ($f.State -eq 'original') { $f.Site.OldSpan } else { $f.Site.NewSpan }
        $headLen = [int]$f.Offset - $pos
        if ($headLen -gt 0)
        {
            $head = New-Object byte[] $headLen
            [Array]::Copy($Seg, $pos, $head, 0, $headLen)
            $pieces.Add($head)
            $total += $headLen
        }
        if ($f.State -eq 'original')
        {
            $repl = [LP]::Ascii($f.Site.NewText)
            $pieces.Add($repl)
            $total += $repl.Length
        }
        else
        {
            $keep = New-Object byte[] $curSpan
            [Array]::Copy($Seg, [int]$f.Offset, $keep, 0, $curSpan)
            $pieces.Add($keep)
            $total += $curSpan
        }
        $pos = [int]$f.Offset + $curSpan
    }
    $tailLen = $Seg.Length - $pos
    if ($tailLen -lt 0) { throw 'internal: stage 2 spans run past the end of the segment' }
    if ($tailLen -gt 0)
    {
        $tail = New-Object byte[] $tailLen
        [Array]::Copy($Seg, $pos, $tail, 0, $tailLen)
        $pieces.Add($tail)
        $total += $tailLen
    }
    if ($total -ne $Seg.Length) { throw ("net-zero violated: rebuilt main.js is {0} bytes, expected {1}" -f $total, $Seg.Length) }
    $out = New-Object byte[] $total
    $o = 0
    foreach ($p in $pieces) { [Array]::Copy($p, 0, $out, $o, $p.Length); $o += $p.Length }
    return , $out
}

function Show-AccountsStatus
{
    if (-not (Test-Path $AccountsPath)) { Write-Output 'accounts : missing'; return }
    try { $j = [Text.Encoding]::UTF8.GetString([IO.File]::ReadAllBytes($AccountsPath)) | ConvertFrom-Json }
    catch { Write-Output ("accounts : INVALID json - {0}" -f $_.Exception.Message); return }
    $props = @($j.accounts.PSObject.Properties)
    Write-Output ("accounts : {0} entry/entries, active = {1}" -f $props.Count, $j.activeAccountLocalId)
    $now = (Get-Date).ToUniversalTime()
    foreach ($p in $props)
    {
        $a = $p.Value
        $future = $false
        try { $future = ([datetime]$a.accessTokenExpiresAt).ToUniversalTime() -gt $now } catch { }
        Write-Output ("  {0,-12} type={1,-6} exp={2} future={3} refresh={4} uuid={5}" -f $a.username, $a.type, $a.accessTokenExpiresAt, $future, [bool]$a.refreshToken, $a.minecraftProfile.id)
        if (-not $future) { Write-Warning 'accessTokenExpiresAt is not in the future - the launcher will try to refresh the fake token and fail' }
        if (-not $a.refreshToken) { Write-Warning 'refreshToken is empty - the UI flags this account as invalid' }
        if ($p.Name -ne $j.activeAccountLocalId) { Write-Warning ("account key {0} is not activeAccountLocalId" -f $p.Name) }
    }
}

function Write-Accounts
{
    if (Test-Path $AccountsPath)
    {
        $backup = Join-Path $BackupDir 'accounts.json.pristine'
        if (-not (Test-Path $backup)) { Copy-Item $AccountsPath $backup -Force; Write-Output ("backup   : {0}" -f $backup) }
    }
    $dir = Split-Path -Parent $AccountsPath
    if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }

    # Preserve whatever is already there. account-manager.ps1 may have added accounts, and
    # stamping the template over the top would silently destroy them - which matters because
    # "re-run patch-stage2.cmd after every update" is the documented recovery path. The
    # template is only written into a file that is missing, unparseable or empty, which is
    # the state a pristine install starts in and the state Stage2Revert restores.
    $keep = $null
    if (Test-Path $AccountsPath)
    {
        try { $keep = [Text.Encoding]::UTF8.GetString([IO.File]::ReadAllBytes($AccountsPath)) | ConvertFrom-Json } catch { $keep = $null }
    }
    $entries = @()
    if ($null -ne $keep -and $null -ne $keep.accounts)
    {
        foreach ($p in $keep.accounts.PSObject.Properties) { $entries += $p }
    }

    if ($entries.Count -eq 0)
    {
        [IO.File]::WriteAllText($AccountsPath, $S2AccountsNew)
        Write-Output ("accounts : {0}  1 entry written" -f $AccountsPath)
        return
    }

    # Keep the accounts, but bring every expiry back inside the load() window: outside
    # (now, now+14d] the account is either rejected with (2) or triggers a refresh that a
    # fake refresh token cannot satisfy.
    $now = (Get-Date).ToUniversalTime()
    $bumped = 0
    foreach ($p in $entries)
    {
        $exp = $null
        try { $exp = ([datetime]$p.Value.accessTokenExpiresAt).ToUniversalTime() } catch { }
        $outside = ($null -eq $exp) -or ($exp -le $now) -or ($exp -gt $now.AddDays($S2WindowDays))
        if ($outside) { $p.Value.accessTokenExpiresAt = $S2ExpiresAt; $bumped++ }
    }

    if (-not $keep.PSObject.Properties['activeAccountLocalId'] -or -not $keep.activeAccountLocalId)
    {
        $entry = [pscustomobject]@{ Name = $entries[0].Name }
        if ($keep.PSObject.Properties['activeAccountLocalId']) { $keep.activeAccountLocalId = $entry.Name }
        else { $keep | Add-Member -NotePropertyName activeAccountLocalId -NotePropertyValue $entry.Name }
    }

    [IO.File]::WriteAllText($AccountsPath, ($keep | ConvertTo-Json -Depth 8), (New-Object Text.UTF8Encoding($false)))
    Write-Output ("accounts : {0}  {1} kept, {2} expiry refreshed" -f $AccountsPath, $entries.Count, $bumped)
}

function Invoke-Stage2
{
    param([string]$Requested)

    if (-not (Test-Path $AsarPath)) { throw ("target not found: {0}" -f $AsarPath) }
    if ($Requested -ne 'Stage2Status' -and ((Test-LivePath $AsarPath) -or (Test-LivePath $AccountsPath)) -and (Get-Process -Name 'Lunar Client' -ErrorAction SilentlyContinue)) { throw 'Lunar Client is running - close it first' }

    $bytes = [IO.File]::ReadAllBytes($AsarPath)
    $sha = [LP]::Sha256Bytes($bytes)
    $build = if ($sha -eq $AsarPristineSha) { 'PRISTINE' } elseif ($sha -eq $AsarPatchedSha) { 'PATCHED' } else { 'UNKNOWN' }

    if ($Requested -eq 'Stage2Status')
    {
        Write-Output ("asar     : {0}" -f $AsarPath)
        Write-Output ("sha256   : {0}" -f $sha)
        Write-Output ("size     : {0} bytes" -f $bytes.Length)
        Write-Output ("build    : {0}" -f $build)
        Write-Output ""
        if ($build -eq 'UNKNOWN')
        {
            Write-Output 'main.js  : not inspected - the asar is not a known build'
        }
        else
        {
            $seg = Get-MainSegment -Asar $bytes
            $rows = @()
            foreach ($site in $S2Sites) { $rows += Get-SiteState -Seg $seg -Site $site }
            $rows | ForEach-Object {
                [pscustomobject]@{
                    Site   = $_.Site.Name
                    Offset = ('main.js+0x{0:x}' -f $_.Offset)
                    State  = $_.State
                    Note   = $_.Site.Note
                }
            } | Format-Table -AutoSize | Out-String | Write-Output
            $patchedCount = @($rows | Where-Object { $_.State -eq 'patched' }).Count
            $word = if ($patchedCount -eq $S2Sites.Length) { 'PATCHED' } elseif ($patchedCount -eq 0) { 'ORIGINAL' } else { 'PARTIAL' }
            Write-Output ("state    : {0} ({1}/{2})" -f $word, $patchedCount, $S2Sites.Length)
        }
        Write-Output ""
        Show-AccountsStatus
        return
    }

    if ($build -eq 'UNKNOWN') { throw 'asar is not the known 3.7.25-ow build - refusing to touch it' }

    if ($Requested -eq 'Stage2Revert')
    {
        $backup = Join-Path $BackupDir 'app.asar.pristine'
        if (-not (Test-Path $backup)) { throw ("no asar backup at {0} - reinstall Lunar Client to get a clean app.asar" -f $backup) }
        if ([LP]::Sha256($backup) -ne $AsarPristineSha) { throw 'asar backup integrity check failed - refusing to restore' }
        Copy-Item $backup $AsarPath -Force
        Write-Output ("asar     : restored from backup")
        Write-Output ("sha256   : {0}" -f [LP]::Sha256($AsarPath))
        $acctBackup = Join-Path $BackupDir 'accounts.json.pristine'
        if (Test-Path $acctBackup) { Copy-Item $acctBackup $AccountsPath -Force; Write-Output ("accounts : restored from backup") }
        else { Write-Warning 'no accounts.json backup - the written file is left in place' }
        return
    }

    $seg = Get-MainSegment -Asar $bytes
    $found = @()
    foreach ($site in $S2Sites) { $found += Get-SiteState -Seg $seg -Site $site }
    $newSeg = New-PatchedSegment -Seg $seg -Found $found

    $newAsar = New-Object byte[] $bytes.Length
    [Array]::Copy($bytes, 0, $newAsar, 0, $bytes.Length)
    [Array]::Copy($newSeg, 0, $newAsar, (16 + $HeaderLen + $MainOffset), $MainSize)
    $newSha = [LP]::Sha256Bytes($newAsar)
    if ($newSha -ne $AsarPatchedSha) { throw ("rebuilt asar sha {0} does not match the expected {1} - aborting before any write" -f $newSha, $AsarPatchedSha) }

    if (-not (Test-Path $BackupDir)) { New-Item -ItemType Directory -Path $BackupDir -Force | Out-Null }
    if ($build -eq 'PRISTINE')
    {
        $backup = Join-Path $BackupDir 'app.asar.pristine'
        Copy-Item $AsarPath $backup -Force
        Write-Output ("backup   : {0}" -f $backup)
    }
    $temp = "$AsarPath.lunarnew"
    [IO.File]::WriteAllBytes($temp, $newAsar)
    Move-Item $temp $AsarPath -Force

    $check = [LP]::Sha256($AsarPath)
    if ($check -ne $AsarPatchedSha) { throw 'post-write asar verification failed' }
    Write-Output ("asar     : {0}" -f $AsarPath)
    Write-Output ("sha256   : {0}" -f $check)
    Write-Output ("state    : PATCHED ({0}/{1} spans, header untouched, {2} bytes)" -f $S2Sites.Length, $S2Sites.Length, $AsarSize)
    Write-Output ""
    Write-Accounts
    Write-Output ""
    Show-AccountsStatus
}

if ($Mode -like 'Stage2*')
{
    Invoke-Stage2 -Requested $Mode
    return
}

if (-not (Test-Path $ExePath)) { throw ("target not found: {0}" -f $ExePath) }

$sites = Get-Sites
$shaBefore = [LP]::Sha256($ExePath)
$bytes = [IO.File]::ReadAllBytes($ExePath)
$plan = Get-Plan -Buffer $bytes -Sites $sites

$bad = @($plan | Where-Object { $_.State -eq 'unexpected' })
if ($bad.Count -gt 0)
{
    Write-Plan -Plan $plan
    throw ("{0} byte(s) at unexpected values - target is not a known build" -f $bad.Count)
}

if ($Mode -eq 'Status')
{
    Write-Output ("exe      : {0}" -f $ExePath)
    Write-Output ("sha256   : {0}" -f $shaBefore)
    Write-Output ("size     : {0} bytes" -f $bytes.Length)
    if ($shaBefore -eq $PristineSha) { Write-Output "build    : PRISTINE (stock 3.7.25-ow)" }
    elseif ($shaBefore -eq $PatchedSha) { Write-Output "build    : PATCHED (lunar bypass)" }
    else { Write-Output "build    : UNKNOWN" }
    Write-Output ""
    Write-Plan -Plan $plan
    $patched = @($plan | Where-Object { $_.State -eq 'patched' }).Count
    if ($patched -eq $plan.Length) { Write-Output ("state    : PATCHED ({0}/{1})" -f $patched, $plan.Length) }
    elseif ($patched -eq 0) { Write-Output ("state    : ORIGINAL (0/{0})" -f $plan.Length) }
    else { Write-Output ("state    : PARTIAL ({0}/{1}) - rerun Apply to finish" -f $patched, $plan.Length) }
    return
}

if ((Test-LivePath $ExePath) -and (Get-Process -Name 'Lunar Client' -ErrorAction SilentlyContinue))
{
    throw 'Lunar Client is running - close it first'
}

if ($Mode -eq 'Revert')
{
    $backup = Join-Path $BackupDir 'LunarClient.exe.pristine'
    if (Test-Path $backup)
    {
        if ([LP]::Sha256($backup) -ne $PristineSha) { throw "backup integrity check failed - refusing to restore" }
        Copy-Item $backup $ExePath -Force
        Write-Output ("reverted from backup : {0}" -f $backup)
        Write-Output ("sha256               : {0}" -f [LP]::Sha256($ExePath))
        return
    }
    $todo = @($plan | Where-Object { $_.State -eq 'patched' })
    if ($todo.Count -eq 0) { Write-Output 'already original - nothing to revert'; return }
    foreach ($entry in $todo) { $bytes[$entry.Offset] = $entry.From }
    $temp = "$ExePath.lunarrevert"
    [IO.File]::WriteAllBytes($temp, $bytes)
    Move-Item $temp $ExePath -Force
    $after = Get-Plan -Buffer ([IO.File]::ReadAllBytes($ExePath)) -Sites $sites
    $left = @($after | Where-Object { $_.State -eq 'patched' }).Count
    if ($left -ne 0) { throw 'post-revert verification failed' }
    Write-Output ("reverted {0} byte(s) in place" -f $todo.Count)
    Write-Output ("sha256               : {0}" -f [LP]::Sha256($ExePath))
    return
}

$todo = @($plan | Where-Object { $_.State -eq 'original' })
if ($todo.Count -eq 0)
{
    Write-Output 'already patched - nothing to do'
    return
}

foreach ($entry in $todo)
{
    if ($bytes[$entry.Offset] -ne $entry.From)
    {
        throw ("byte mismatch at 0x{0:x8} ({1})" -f $entry.Offset, $entry.Site)
    }
}

if (-not (Test-Path $BackupDir)) { New-Item -ItemType Directory -Path $BackupDir -Force | Out-Null }
$backupPath = Join-Path $BackupDir 'LunarClient.exe.pristine'
if (-not (Test-Path $backupPath))
{
    Copy-Item $ExePath $backupPath -Force
    Write-Output ("backup               : {0}" -f $backupPath)
}
elseif ([LP]::Sha256($backupPath) -ne $PristineSha)
{
    throw 'existing backup does not match the known pristine build - refusing to overwrite'
}

foreach ($entry in $todo) { $bytes[$entry.Offset] = $entry.To }
$temp = "$ExePath.lunarnew"
[IO.File]::WriteAllBytes($temp, $bytes)
Move-Item $temp $ExePath -Force

$shaAfter = [LP]::Sha256($ExePath)
$verify = Get-Plan -Buffer ([IO.File]::ReadAllBytes($ExePath)) -Sites $sites
$left = @($verify | Where-Object { $_.State -ne 'patched' }).Count
if ($left -ne 0) { throw 'post-write verification failed' }

Write-Output ("patched              : {0} byte(s) across {1} site(s)" -f $todo.Count, $plan.Length)
Write-Output ("sha256               : {0}" -f $shaAfter)
Write-Plan -Plan $verify -OverrideState 'patched'
