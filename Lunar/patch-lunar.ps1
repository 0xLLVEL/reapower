param(
    [ValidateSet('Status', 'Apply', 'Revert')]
    [string]$Mode = 'Status',

    [string]$ExePath = (Join-Path $env:LOCALAPPDATA 'Programs\Lunar Client\Lunar Client.exe'),

    [string]$BackupDir = (Join-Path $env:LOCALAPPDATA 'LunarPatch\backup')
)

$ErrorActionPreference = 'Stop'

$PristineSha = 'c1d3f36dba310629aedec239b6c55a2f1cfe21e6930dff2ee0440c169718628e'
$PatchedSha = 'cc94512fa4ac83d88a1eea94a24d8d066d037f411b96cf7d23cb3eca3a3c36d7'
$FuseMarker = 'dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX'

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

if (Get-Process -Name 'Lunar Client' -ErrorAction SilentlyContinue)
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
