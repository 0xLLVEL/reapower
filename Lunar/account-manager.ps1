param(
    [ValidateSet('List', 'Show', 'Add', 'Use', 'Remove', 'Refresh', 'Validate', 'Backup', 'Restore')]
    [string]$Mode = 'List',

    [string]$Name,

    [string]$AccountsPath = (Join-Path $env:USERPROFILE '.lunarclient\settings\game\accounts.json'),

    [string]$BackupDir = (Join-Path $env:LOCALAPPDATA 'LunarPatch\backup'),

    # accessTokenExpiresAt is written as now + this many hours.
    [ValidateRange(1, 336)]
    [int]$ExpiresHours = 12
)

$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------------------
# Why these numbers exist
# ---------------------------------------------------------------------------
# AccountManager.load() has one reject after the schema mask accepts the file:
#   if (iat.isAfter(Instant.now().plus(14, ChronoUnit.DAYS))) -> "invalid (2)" -> remove
# So an expiry MORE than 14 days out is an anti-tamper failure and the account is dropped
# before map.put ever runs - which is also what produces {"accounts": {}} on disk.
# The opposite bound is executeWithAccessToken: dayjs(accessTokenExpiresAt).isBefore(now)
# fires refreshAccountInternal, which throws INVALID_SESSION on a fake refresh token.
# Usable window: (now, now + 14d]. 12h sits inside it and mimics a live MS token.
$WindowDays = 14

# minecraftProfile.id must be 32 LOWERCASE hex AND v4-shaped, because mN() only strips the
# dashes pN() added when fN (strict v4: version nibble 4, variant [89ab]) matches.
# A non-v4 id makes getAccount(dashedId) miss and the AssetServer client dies with
# SR.NO_ACCOUNT before it opens a socket.
$Hex32 = '^[0-9a-f]{32}$'
$V4Dashed = '^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'

$DateFormat = 'yyyy-MM-ddTHH:mm:ss.fffZ'
$SnapshotName = 'accounts.manager.json'

# The launcher rewrites this file itself: valibot (hEe/mEe) parses it and re-serialises,
# dropping keys the mask does not know - the original script wrote "userProperties": []
# and the live file has no such key and puts activeAccountLocalId first. This is the
# launcher's own output shape, so what we write round-trips without being rewritten.
$AccountFields = @(
    'accessToken', 'accessTokenExpiresAt', 'eligibleForMigration', 'hasMultipleProfiles',
    'legacy', 'persistent', 'localId', 'refreshToken', 'minecraftProfile', 'remoteId',
    'type', 'username'
)

function Get-UtcNow { return (Get-Date).ToUniversalTime() }

function New-V4Hex32
{
    $b = New-Object byte[] 16
    $rng = [Security.Cryptography.RandomNumberGenerator]::Create()
    $rng.GetBytes($b)
    $rng.Dispose()
    $b[6] = [byte](($b[6] -band 0x0F) -bor 0x40)
    $b[8] = [byte](($b[8] -band 0x3F) -bor 0x80)
    $sb = New-Object Text.StringBuilder 32
    foreach ($x in $b) { [void]$sb.Append($x.ToString('x2')) }
    return $sb.ToString()
}

function ConvertTo-Dashed([string]$hex32)
{
    return ('{0}-{1}-{2}-{3}-{4}' -f $hex32.Substring(0, 8), $hex32.Substring(8, 4),
        $hex32.Substring(12, 4), $hex32.Substring(16, 4), $hex32.Substring(20, 12))
}

function Get-ExpiryString([int]$Hours)
{
    return (Get-UtcNow).AddHours($Hours).ToString($DateFormat)
}

function Read-AccountsFile
{
    if (-not (Test-Path $AccountsPath)) { return $null }
    try { return [Text.Encoding]::UTF8.GetString([IO.File]::ReadAllBytes($AccountsPath)) | ConvertFrom-Json }
    catch { throw ("accounts.json is not parseable - {0}" -f $_.Exception.Message) }
}

function Backup-AccountsFile
{
    if (-not (Test-Path $AccountsPath)) { return $null }
    if (-not (Test-Path $BackupDir)) { New-Item -ItemType Directory -Path $BackupDir -Force | Out-Null }
    $target = Join-Path $BackupDir 'accounts.json.pristine'
    if (-not (Test-Path $target))
    {
        Copy-Item $AccountsPath $target -Force
        Write-Output ("backup   : {0}" -f $target)
    }
    return $target
}

function Save-AccountsFile
{
    param([object]$Document)
    $dir = Split-Path -Parent $AccountsPath
    if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    $json = $Document | ConvertTo-Json -Depth 8
    $temp = "$AccountsPath.amnew"
    [IO.File]::WriteAllText($temp, $json, (New-Object Text.UTF8Encoding($false)))
    Move-Item $temp $AccountsPath -Force
    $back = Read-AccountsFile
    if ($null -eq $back) { throw 'post-write verification failed: file will not parse' }
    Write-Output ("written : {0}" -f $AccountsPath)
}

function New-AccountObject
{
    param([string]$Username)

    $profileId = New-V4Hex32
    $localId = ConvertTo-Dashed (New-V4Hex32)

    return [pscustomobject][ordered]@{
        accessToken           = 'stage2-offline-access-token'
        accessTokenExpiresAt  = Get-ExpiryString $ExpiresHours
        eligibleForMigration  = $false
        hasMultipleProfiles   = $false
        legacy                = $false
        persistent            = $true
        localId               = $localId
        refreshToken          = 'stage2-offline-refresh-token'
        minecraftProfile      = [pscustomobject][ordered]@{ id = $profileId; name = $Username }
        remoteId              = $localId
        type                  = 'Xbox'
        username              = $Username
    }
}

function Get-AccountEntries
{
    param([object]$Doc)
    if ($null -eq $Doc) { return @() }
    if ($null -eq $Doc.accounts) { return @() }
    $out = @()
    foreach ($p in $Doc.accounts.PSObject.Properties)
    {
        $out += [pscustomobject]@{ Key = $p.Name; Account = $p.Value }
    }
    return $out
}

function Resolve-Account
{
    param([object]$Doc, [string]$Requested)

    if ([string]::IsNullOrWhiteSpace($Requested)) { throw '-Name is required for this mode' }
    $all = @(Get-AccountEntries -Doc $Doc)
    if ($all.Count -eq 0) { throw 'no accounts in the file - run -Mode Add first' }

    $hits = @($all | Where-Object {
        $_.Key -eq $Requested -or
        $_.Account.username -eq $Requested -or
        $_.Account.minecraftProfile.name -eq $Requested -or
        $_.Key.StartsWith($Requested, [StringComparison]::OrdinalIgnoreCase)
    })

    if ($hits.Count -eq 0)
    {
        $avail = ($all | ForEach-Object { $_.Account.username }) -join ', '
        throw ("no account matches '{0}' - available: {1}" -f $Requested, $avail)
    }
    if ($hits.Count -gt 1)
    {
        $dupes = ($hits | ForEach-Object { '{0} ({1})' -f $_.Account.username, $_.Key }) -join ', '
        throw ("'{0}' matches {1} accounts: {2} - use the full localId" -f $Requested, $hits.Count, $dupes)
    }
    return $hits[0]
}

function Resolve-AccountSilently
{
    param([object]$Doc, [string]$Requested)

    $all = @(Get-AccountEntries -Doc $Doc)
    foreach ($e in $all)
    {
        if ($e.Key -eq $Requested -or $e.Account.username -eq $Requested -or
            $e.Account.minecraftProfile.name -eq $Requested -or
            $e.Key.StartsWith($Requested, [StringComparison]::OrdinalIgnoreCase)) { return $e }
    }
    return $null
}

function Get-AccountViolations
{
    param([object]$Doc, [string]$Key, [object]$Account)

    $now = Get-UtcNow
    $ceiling = $now.AddDays($WindowDays)
    $v = @()

    function Add-V([string]$Severity, [string]$Code, [string]$Message)
    {
        $script:violations += [pscustomobject]@{
            Account  = $Account.username
            Key      = $Key
            Severity = $Severity
            Code     = $Code
            Message  = $Message
        }
    }

    $script:violations = @()

    # --- blockers: load() will reject, or the file will be discarded whole ---
    if (-not ($Account.accessTokenExpiresAt -match $DateFormat -or $Account.accessTokenExpiresAt -match '^\d{4}-\d{2}-\d{2}T'))
    {
        Add-V 'FAIL' 'expiry.unparseable' ("accessTokenExpiresAt is not an ISO timestamp: {0}" -f $Account.accessTokenExpiresAt)
    }
    else
    {
        $exp = ([datetime]$Account.accessTokenExpiresAt).ToUniversalTime()
        if ($exp -gt $ceiling)
        {
            Add-V 'FAIL' '(2).window' ("expiry {0} is past now+{1}d - AccountManager.load() logs invalid (2), removes the account before map.put, and the next flush writes an empty accounts map" -f $Account.accessTokenExpiresAt, $WindowDays)
        }
        elseif ($exp -le $now)
        {
            Add-V 'WARN' 'expiry.past' ("expired at {0} - executeWithAccessToken fires refreshAccountInternal, which throws INVALID_SESSION on a fake refresh token" -f $Account.accessTokenExpiresAt)
        }
    }

    if (-not $Account.minecraftProfile)
    {
        Add-V 'FAIL' 'profile.missing' 'minecraftProfile is absent - valibot mask will discard the whole file'
    }
    else
    {
        $profileHex = [string]$Account.minecraftProfile.id
        if ($profileHex -notmatch $Hex32)
        {
            Add-V 'FAIL' 'profile.id.shape' ("minecraftProfile.id must be 32 lowercase hex, got '{0}'" -f $profileHex)
        }
        elseif ((ConvertTo-Dashed $profileHex) -notmatch $V4Dashed)
        {
            Add-V 'WARN' 'profile.id.notv4' ("id {0} fails the strict v4 check (fN) - mN() will not strip dashes, getAccount() misses, AssetServer dies with SR.NO_ACCOUNT" -f $profileHex)
        }
    }

    if ($Key -ne [string]$Account.localId)
    {
        Add-V 'FAIL' 'key.localid' ("accounts key '{0}' does not equal localId '{1}'" -f $Key, $Account.localId)
    }

    if ($Key -ne [string]$Doc.activeAccountLocalId)
    {
        Add-V 'WARN' 'key.inactive' 'this account is not activeAccountLocalId'
    }

    # --- warnings: loads, but degraded ---
    if ([string]::IsNullOrEmpty([string]$Account.refreshToken))
    {
        Add-V 'WARN' 'refresh.empty' 'refreshToken is empty - initAuthInternal sets invalid: !e.refreshToken and the UI flags the account'
    }
    if ([string]::IsNullOrEmpty([string]$Account.accessToken))
    {
        Add-V 'WARN' 'access.empty' 'accessToken is empty'
    }
    if ([string]::IsNullOrEmpty([string]$Account.username))
    {
        Add-V 'FAIL' 'username.empty' 'username is empty - load() logs against it and the dup check keys on it'
    }
    if ($Account.minecraftProfile -and [string]$Account.username -ne [string]$Account.minecraftProfile.name)
    {
        Add-V 'WARN' 'name.mismatch' ("username '{0}' != minecraftProfile.name '{1}'" -f $Account.username, $Account.minecraftProfile.name)
    }

    return $script:violations
}

function Get-DocumentViolations
{
    param([object]$Doc)

    $all = @()
    if ($null -eq $Doc)
    {
        return @([pscustomobject]@{ Account = '-'; Key = '-'; Severity = 'FAIL'; Code = 'file.missing'; Message = 'accounts.json does not exist' })
    }
    $entries = @(Get-AccountEntries -Doc $Doc)
    if ($entries.Count -eq 0)
    {
        $all += [pscustomobject]@{ Account = '-'; Key = '-'; Severity = 'FAIL'; Code = 'file.empty'; Message = '{"accounts": {}} - every account was rejected, rerun -Mode Add or patch-stage2.cmd' }
    }

    $active = [string]$Doc.activeAccountLocalId
    if ([string]::IsNullOrEmpty($active))
    {
        $all += [pscustomobject]@{ Account = '-'; Key = '-'; Severity = 'FAIL'; Code = 'active.missing'; Message = 'activeAccountLocalId is not set' }
    }
    elseif (-not ($entries | Where-Object { $_.Key -eq $active }))
    {
        $all += [pscustomobject]@{ Account = '-'; Key = $active; Severity = 'FAIL'; Code = 'active.dangling'; Message = ("activeAccountLocalId '{0}' is not a key in accounts" -f $active) }
    }

    foreach ($e in $entries) { $all += Get-AccountViolations -Doc $Doc -Key $e.Key -Account $e.Account }
    return $all
}

function Show-Violations
{
    param([object[]]$Violations, [switch]$ThrowOnFail)

    $fails = @($Violations | Where-Object { $_.Severity -eq 'FAIL' })
    $warns = @($Violations | Where-Object { $_.Severity -eq 'WARN' })

    if ($Violations.Count -eq 0)
    {
        Write-Output "check   : PASS - no violations"
        return
    }

    $Violations |
        Sort-Object @{ Expression = { if ($_.Severity -eq 'FAIL') { 0 } else { 1 } } }, Account, Code |
        Select-Object Severity, Account, Code, Message |
        Format-Table -AutoSize -Wrap |
        Out-String -Width 200 |
        Write-Output

    Write-Output ("check   : {0} FAIL, {1} WARN" -f $fails.Count, $warns.Count)
    if ($ThrowOnFail -and $fails.Count -gt 0) { throw ("{0} blocking violation(s)" -f $fails.Count) }
}

function Show-List
{
    param([object]$Doc)

    $entries = @(Get-AccountEntries -Doc $Doc)
    if ($entries.Count -eq 0)
    {
        Write-Output 'accounts : empty - {"accounts": {}}'
        Write-Output '           run -Mode Add, or re-run patch-stage2.cmd'
        return
    }

    $now = Get-UtcNow
    $rows = foreach ($e in $entries)
    {
        $a = $e.Account
        $exp = $null
        $left = $null
        $state = 'unparseable'
        try
        {
            $exp = ([datetime]$a.accessTokenExpiresAt).ToUniversalTime()
            $delta = $exp - $now
            $left = if ($delta.TotalSeconds -gt 0) { [string][timespan]::FromSeconds([math]::Floor($delta.TotalSeconds)) } else { '-' }
            if ($delta.TotalSeconds -le 0) { $state = 'EXPIRED' }
            elseif ($exp -gt $now.AddDays($WindowDays)) { $state = '(2) REJECT' }
            else { $state = 'ok' }
        }
        catch { }

        [pscustomobject]@{
            Active = if ($e.Key -eq $Doc.activeAccountLocalId) { '*' } else { '' }
            Name   = $a.username
            Window = $state
            Left   = $left
            V4     = if ([string]$a.minecraftProfile.id -match $Hex32 -and (ConvertTo-Dashed $a.minecraftProfile.id) -match $V4Dashed) { 'ok' } else { 'BAD' }
            Refresh = if ([string]::IsNullOrEmpty([string]$a.refreshToken)) { 'EMPTY' } else { 'ok' }
            Uuid   = [string]$a.minecraftProfile.id
            Key    = $e.Key
        }
    }

    $rows | Format-Table -AutoSize | Out-String -Width 200 | Write-Output
    Write-Output ("active  : {0}   entries: {1}   window: now + {2}h (ceiling now + {3}d)" -f $Doc.activeAccountLocalId, $entries.Count, $ExpiresHours, $WindowDays)
    Write-Output ""
    Show-Violations -Violations (Get-DocumentViolations -Doc $Doc)
}

function Show-One
{
    param([object]$Doc, [object]$Hit)

    $a = $Hit.Account
    Write-Output ("key      : {0}" -f $Hit.Key)
    Write-Output ("username : {0}" -f $a.username)
    Write-Output ("profile  : {0}  ({1})" -f $a.minecraftProfile.name, $a.minecraftProfile.id)
    Write-Output ("dashed   : {0}" -f (ConvertTo-Dashed $a.minecraftProfile.id))
    Write-Output ("type     : {0}" -f $a.type)
    Write-Output ("localId  : {0}" -f $a.localId)
    Write-Output ("remoteId : {0}" -f $a.remoteId)
    Write-Output ("expires  : {0}" -f $a.accessTokenExpiresAt)
    Write-Output ("active   : {0}" -f ($Hit.Key -eq $Doc.activeAccountLocalId))
    Write-Output ""
    Write-Output "--- account object ---"
    $a | ConvertTo-Json -Depth 6 | Write-Output
    Write-Output ""
    Show-Violations -Violations (Get-AccountViolations -Doc $Doc -Key $Hit.Key -Account $a)
}

# ---------------------------------------------------------------------------
# dispatch
# ---------------------------------------------------------------------------

$doc = Read-AccountsFile
$mutating = $Mode -in @('Add', 'Use', 'Remove', 'Refresh', 'Restore')

# The launcher rewrites accounts.json on exit, so a write racing it is lost. That only
# matters when the target IS the live file - a sandbox copy is safe to poke at any time.
$DefaultAccountsPath = Join-Path $env:USERPROFILE '.lunarclient\settings\game\accounts.json'
$isLive = [string]$AccountsPath -eq [IO.Path]::GetFullPath($DefaultAccountsPath)

if ($mutating -and $isLive -and (Get-Process -Name 'Lunar Client' -ErrorAction SilentlyContinue))
{
    throw 'Lunar Client is running - it rewrites accounts.json on exit, so close it first'
}

switch ($Mode)
{
    'List'
    {
        if ($null -eq $doc) { Write-Output ("accounts : missing - {0}" -f $AccountsPath); return }
        Write-Output ("file     : {0}" -f $AccountsPath)
        Show-List -Doc $doc
    }

    'Show'
    {
        if ($null -eq $doc) { throw ("accounts : missing - {0}" -f $AccountsPath) }
        Show-One -Doc $doc -Hit (Resolve-Account -Doc $doc -Requested $Name)
    }

    'Add'
    {
        if ([string]::IsNullOrWhiteSpace($Name)) { throw '-Name is required for -Mode Add' }
        if ($null -eq $doc) { $doc = [pscustomobject][ordered]@{ activeAccountLocalId = ''; accounts = [pscustomobject][ordered]@{} } }

        $clash = Resolve-AccountSilently -Doc $doc -Requested $Name
        if ($null -ne $clash) { throw ("account '{0}' already exists (key {1}) - pick another name, or -Mode Remove first" -f $Name, $clash.Key) }

        $fresh = New-AccountObject -Username $Name
        $doc.accounts | Add-Member -NotePropertyName $fresh.localId -NotePropertyValue $fresh -Force
        if ([string]::IsNullOrEmpty([string]$doc.activeAccountLocalId)) { $doc.activeAccountLocalId = $fresh.localId }

        Backup-AccountsFile | Out-Null
        Save-AccountsFile -Document $doc
        Write-Output ("added    : {0}" -f $Name)
        Write-Output ("profile  : {0}" -f $fresh.minecraftProfile.id)
        Write-Output ("key      : {0}" -f $fresh.localId)
        Write-Output ("expires  : {0}  (now + {1}h, ceiling now + {2}d)" -f $fresh.accessTokenExpiresAt, $ExpiresHours, $WindowDays)
    }

    'Use'
    {
        $hit = Resolve-Account -Doc $doc -Requested $Name
        $doc.activeAccountLocalId = $hit.Key
        Save-AccountsFile -Document $doc
        Write-Output ("active   : {0}  ({1})" -f $hit.Account.username, $hit.Key)
    }

    'Remove'
    {
        $hit = Resolve-Account -Doc $doc -Requested $Name
        $entries = @(Get-AccountEntries -Doc $doc)
        if ($entries.Count -le 1) { throw 'last account - removing it leaves {"accounts": {}}; use -Mode Add first if you want a replacement' }

        $doc.accounts.PSObject.Properties.Remove($hit.Key)
        if ($doc.activeAccountLocalId -eq $hit.Key)
        {
            $next = @(Get-AccountEntries -Doc $doc)[0]
            $doc.activeAccountLocalId = $next.Key
            Write-Output ("active   : {0}  (reassigned)" -f $next.Account.username)
        }
        Save-AccountsFile -Document $doc
        Write-Output ("removed  : {0}  (key {1})" -f $hit.Account.username, $hit.Key)
    }

    'Refresh'
    {
        $targets = if ($Name) { @(Resolve-Account -Doc $doc -Requested $Name) } else { @(Get-AccountEntries -Doc $doc) }
        if ($targets.Count -eq 0) { throw 'no accounts to refresh' }
        $stamp = Get-ExpiryString $ExpiresHours
        foreach ($t in $targets) { $t.Account.accessTokenExpiresAt = $stamp }
        Save-AccountsFile -Document $doc
        Write-Output ("refresh  : {0} account(s) -> {1}" -f $targets.Count, $stamp)
    }

    'Validate'
    {
        Show-Violations -Violations (Get-DocumentViolations -Doc $doc) -ThrowOnFail
    }

    'Backup'
    {
        if (-not (Test-Path $AccountsPath)) { throw ("accounts : missing - {0}" -f $AccountsPath) }
        if (-not (Test-Path $BackupDir)) { New-Item -ItemType Directory -Path $BackupDir -Force | Out-Null }
        $target = Join-Path $BackupDir $SnapshotName
        Copy-Item $AccountsPath $target -Force
        Write-Output ("snapshot : {0}" -f $target)
        Write-Output ("bytes    : {0}" -f (Get-Item $target).Length)
    }

    'Restore'
    {
        $src = Join-Path $BackupDir $SnapshotName
        if (-not (Test-Path $src)) { throw ("no snapshot at {0} - run -Mode Backup first" -f $src) }
        $probe = [Text.Encoding]::UTF8.GetString([IO.File]::ReadAllBytes($src)) | ConvertFrom-Json
        if ($null -eq $probe.accounts) { throw 'snapshot has no accounts block - refusing to restore' }
        Copy-Item $src $AccountsPath -Force
        Write-Output ("restored : {0}" -f $AccountsPath)
        Show-List -Doc (Read-AccountsFile)
    }
}
