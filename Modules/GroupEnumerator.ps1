<#
.SYNOPSIS
    Cross-domain group membership enumeration module

.DESCRIPTION
    Enumerates Active Directory group members across multiple domains via LDAPS.
    Supports CSV input in Domain,GroupName or DOMAIN\GroupName backslash format.
    Returns standardized @{ Data = ...; Errors = @() } hashtables throughout.

.NOTES
    Requires the ADLdap.ps1 module (dot-sourced from the same directory).
    ADLdap wraps System.DirectoryServices.Protocols.LdapConnection so this tool
    works against DCs that enforce LDAP Channel Binding / Signing.

    Connection strategy is delegated to New-AdLdapConnection: LDAPS-Verified
    first, then optional fallbacks (LDAPS cert-bypass, LDAP 389 sign+seal)
    controlled by Config.AllowInsecure.

    Uses objectCategory (indexed) for all LDAP group/user filters.
    Compatible with PowerShell 5.1 and 7+.
#>

function New-GroupEnumConfig {
    <#
    .SYNOPSIS
        Loads group-enum-config.json with defaults fallback

    .DESCRIPTION
        Reads config JSON file and merges values over a built-in defaults hashtable.
        Any key absent from the file will use the default value.

    .PARAMETER ConfigPath
        Path to group-enum-config.json. If omitted or file not found, all defaults apply.

    .OUTPUTS
        Hashtable of merged config values
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory = $false)]
        [string]$ConfigPath
    )

    # Built-in defaults -- every key the tool needs
    $defaults = @{
        LdapPageSize         = 1000
        LdapTimeout          = 120
        MaxMemberCount       = 5000
        SkipLargeGroups      = $true
        LargeGroupThreshold  = 5000
        SkipGroups           = @('Domain Users', 'Domain Computers', 'Authenticated Users')
        FuzzyPrefixes        = @('GG_', 'USV_', 'SG_', 'DL_', 'GL_')
        FuzzyMinScore        = 0.7
        OutputDirectory      = 'Output'
        DefaultTheme         = 'dark'
        CachePath            = 'Cache'
        CacheEnabled         = $true
        AllowInsecure        = $false
        LogEnabled           = $true
        LogPath              = 'Logs'
        LogLevel             = 'INFO'
        Enumeration          = @{ Incremental = $false }
        # v3 defaults
        StateBackend         = 'json'
        SqliteDbPath         = 'State/group-enumerator.db'
        GarbageCollectDays   = 90
        ChangeTracking       = @{
            Enabled            = $false
            UnifiedState       = $true
            StatePath          = 'State'
            StateFile          = 'membership-state.json'
            ChangeLogFile      = 'changelog.jsonl'
            DefaultChangeType  = 'Both'
            MaxChangeLogSizeMB = 50
            RetentionDays      = 0
        }
        Reporting            = @{
            GovernanceReport   = $false
            ComplianceReport   = $false
            ExecutiveDashboard = $false
            LeadershipSummary  = $false
            IdentityDetailThreshold = 3
        }
    }

    if (-not $ConfigPath -or -not (Test-Path $ConfigPath)) {
        Write-Verbose "Group enum config file not found at '$ConfigPath'. Using defaults."
        return $defaults
    }

    try {
        $json = Get-Content -Path $ConfigPath -Raw -ErrorAction Stop
        $parsed = $json | ConvertFrom-Json -ErrorAction Stop

        # Merge parsed values over defaults
        $config = $defaults.Clone()

        # Keys with nested structure that need deep-merge (partial JSON overrides
        # should inherit missing sub-keys from defaults, not replace the whole block)
        $nestedKeys = @('ChangeTracking', 'Reporting', 'Enumeration')

        foreach ($property in $parsed.PSObject.Properties) {
            $key   = $property.Name
            $value = $property.Value

            # Deep-merge for nested config sections
            if ($key -in $nestedKeys -and $value -is [PSCustomObject] -and $defaults.ContainsKey($key)) {
                $merged = @{}
                foreach ($dk in $defaults[$key].Keys) { $merged[$dk] = $defaults[$key][$dk] }
                foreach ($subProp in $value.PSObject.Properties) {
                    # A null in JSON means "use the default", not "set to null".
                    if ($null -ne $subProp.Value) { $merged[$subProp.Name] = $subProp.Value }
                }
                $config[$key] = $merged
            }
            # PSCustomObject arrays come through as PSCustomObject or Object[] -- convert to PS array
            elseif ($value -is [System.Collections.IEnumerable] -and $value -isnot [string]) {
                $config[$key] = @($value)
            } elseif ($null -ne $value) {
                # Skip explicit null so it can't zero a built-in default (e.g. LdapTimeout -> 0).
                $config[$key] = $value
            }
        }

        return $config

    } catch {
        Write-Warning "Failed to parse config file '$ConfigPath': $_. Using defaults."
        return $defaults
    }
}

function Test-GroupDistinguishedName {
    <#
    .SYNOPSIS
        True when a CSV group value is a full distinguished name (CN=...,DC=...), not a plain name.
    .DESCRIPTION
        A group DN always starts with CN= and ends in one or more DC= components, e.g.
        "CN=GG_IT_Admins,OU=Groups,OU=Corp,DC=corp,DC=com". Plain CNs -- even oddly named ones --
        do not end in a DC= chain, so this stays $false for them. Used to decide whether to bind
        Base-scope directly to the object (DN) or run a CN subtree search (plain name).
    #>
    [OutputType([bool])]
    param([string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value)) { return $false }
    return [bool]($Value -match '(?i)^CN=.+(,DC=[^,]+)+$')
}

function Get-DomainFromGroupDn {
    <#
    .SYNOPSIS
        Derive the domain FQDN from a DN's DC= components (CN=...,DC=corp,DC=com -> corp.com).
    #>
    [OutputType([string])]
    param([string]$Dn)
    if ([string]::IsNullOrWhiteSpace($Dn)) { return '' }
    $dcs = [regex]::Matches($Dn, '(?i)(?:^|,)DC=([^,]+)') | ForEach-Object { $_.Groups[1].Value }
    return ($dcs -join '.')
}

function Import-GroupList {
    <#
    .SYNOPSIS
        Parses a CSV file into an array of domain/group pairs

    .DESCRIPTION
        Supports two CSV formats:
          1. Standard:   headers Domain,GroupName  -- one row per group
          2. Backslash:  header Group              -- values like DOMAIN\GroupName

        Format is auto-detected by inspecting the header row.
        A -DefaultDomain is used when the CSV contains no domain information.

        A group value may be a plain name (resolved by CN) OR a full distinguished name
        (e.g. "CN=GG_IT_Admins,OU=Groups,DC=corp,DC=com"), auto-detected per row. For a DN the
        domain is derived from its DC= components, so the Domain column is optional on DN rows.

    .PARAMETER CsvPath
        Full path to the input CSV file

    .PARAMETER DefaultDomain
        Domain to assign when no domain is present in the CSV row

    .OUTPUTS
        Array of hashtables: @{ Domain = "X"; GroupName = "Y"; IsDistinguishedName = $false }
    #>
    [CmdletBinding()]
    [OutputType([array])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$CsvPath,

        [Parameter(Mandatory = $false)]
        [string]$DefaultDomain = ''
    )

    if (-not (Test-Path $CsvPath)) {
        throw "CSV file not found: $CsvPath"
    }

    # Read the whole file in one atomic call that opens, reads, and closes the
    # handle immediately, THEN parse the in-memory text. This decouples file I/O
    # from parsing so no read handle can linger past this line -- even if parsing
    # or downstream format validation throws. (ReadAllText auto-detects a BOM and
    # defaults to UTF-8.) Mirrors the WriteAllText pattern used for cache/CSV output.
    try {
        $csvText = [System.IO.File]::ReadAllText($CsvPath)
        $rows = @($csvText | ConvertFrom-Csv)
    } catch {
        throw "Failed to read CSV '$CsvPath': $_"
    }

    if (-not $rows -or $rows.Count -eq 0) {
        # Comma-wrap so an empty CSV returns an empty ARRAY, matching the
        # non-empty path's ', $results' shape. A bare '@()' unrolls to $null for
        # the caller, diverging from the populated case.
        return , @()
    }

    # Detect format by inspecting the property names of the first row
    $headers = $rows[0].PSObject.Properties.Name

    # Normalise header names for comparison (case-insensitive)
    $headerLower = $headers | ForEach-Object { $_.ToLower() }

    $isStandard   = ($headerLower -contains 'domain') -and ($headerLower -contains 'groupname')
    $isBackslash  = ($headerLower -contains 'group') -and -not $isStandard

    if (-not $isStandard -and -not $isBackslash) {
        $msg = @(
            "Unrecognised CSV format in '$CsvPath'."
            "  Found headers: $($headers -join ', ')"
            ''
            '  Two formats are supported:'
            ''
            '  [1] Two-column format -- headers must be exactly: Domain,GroupName'
            '      Domain,GroupName'
            '      CORP,Domain Admins'
            '      CORP,Enterprise Admins'
            '      EUROPE,Helpdesk'
            ''
            '  [2] Single-column format -- header must be exactly: Group'
            '      Group'
            '      CORP\Domain Admins'
            '      CORP\Enterprise Admins'
            '      EUROPE\Helpdesk'
            ''
            '  Headers are case-insensitive. Sample files: Templates\groups-example-*.csv'
        ) -join [Environment]::NewLine
        throw $msg
    }

    $results = @()

    foreach ($row in $rows) {
        $domain    = ''
        $groupName = ''

        if ($isStandard) {
            # Coerce to string first: a short/partial row leaves a missing cell as
            # $null, and $null.Trim() throws. "$(...)" turns $null into '' safely so
            # the blank-row guard below can skip it instead of crashing.
            $domain    = "$($row.Domain)".Trim()
            $groupName = "$($row.GroupName)".Trim()
        } else {
            # Backslash format: "DOMAIN\GroupName"
            $raw = "$($row.Group)".Trim()
            if ($raw -match '^([^\\]+)\\(.+)$') {
                $domain    = $matches[1].Trim()
                $groupName = $matches[2].Trim()
            } else {
                # No backslash -- treat entire value as group name
                $domain    = $DefaultDomain
                $groupName = $raw
            }
        }

        if (-not $groupName) {
            continue  # Skip blank rows
        }

        # A full DN is self-contained: derive the domain from its DC= components so the Domain
        # column is optional on DN rows (and the DN is authoritative -- the object can only be
        # bound in its own domain, so a DN's domain wins over a differing column value).
        $isDn = Test-GroupDistinguishedName $groupName
        if ($isDn) {
            $dnDomain = Get-DomainFromGroupDn $groupName
            if ($dnDomain) { $domain = $dnDomain }
        }

        # Fall back to DefaultDomain if domain still empty
        if (-not $domain) {
            $domain = $DefaultDomain
        }

        $results += @{
            Domain              = $domain
            GroupName           = $groupName
            IsDistinguishedName = $isDn
        }
    }

    return , $results
}


# ---------------------------------------------------------------------------
# Private helper: Resolve-MemberDnToRecord
# Given a member DN, pick the right pooled context (cross-forest aware),
# handle ForeignSecurityPrincipal indirection, and return a member record
# hashtable in the standard shape expected by Get-GroupMembersDirect.
# ---------------------------------------------------------------------------
function script:Resolve-MemberDnToRecord {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory = $true)]  [string]$MemberDN,
        [Parameter(Mandatory = $true)]  [hashtable]$LocalContext,
        [Parameter(Mandatory = $true)]  [string]$LocalDomain,
        [Parameter(Mandatory = $false)] [hashtable]$Pool,
        [Parameter(Mandatory = $false)] [int]$TimeoutSeconds = 120,
        [Parameter(Mandatory = $false)] [string[]]$IncludeAttributes = @()
    )

    $userAttrs = @('sAMAccountName','displayName','mail','userAccountControl','distinguishedName')
    $extraAttrs = @($IncludeAttributes | Where-Object { $_ } | ForEach-Object { $_.Trim() })
    if ($extraAttrs.Count -gt 0) {
        $userAttrs = $userAttrs + $extraAttrs
    }

    # Helper: build member hashtable from search result, including extra attributes
    $buildMemberRecord = {
        param([hashtable]$m, [string]$domain)
        $uac = if ($m.ContainsKey('userAccountControl')) { [int]$m.userAccountControl } else { 0 }
        $record = @{
            SamAccountName    = if ($m.ContainsKey('sAMAccountName')) { $m.sAMAccountName } else { $null }
            DisplayName       = if ($m.ContainsKey('displayName'))    { $m.displayName }    else { $null }
            Email             = if ($m.ContainsKey('mail'))           { $m.mail }           else { $null }
            Enabled           = (($uac -band 2) -eq 0)
            Domain            = $domain
            DistinguishedName = $m.DistinguishedName
        }
        # Add extra requested attributes
        foreach ($attr in $extraAttrs) {
            $attrLower = $attr.ToLower()
            $attrVal = if ($m.ContainsKey($attrLower)) { $m.$attrLower } elseif ($m.ContainsKey($attr)) { $m.$attr } else { $null }
            # Special handling: manager is a DN -- resolve to display name plus the
            # manager's own sAMAccountName and email (one extra Base lookup).
            if ($attrLower -eq 'manager' -and $attrVal -and $queryCtx) {
                $mgrName = $null
                $mgrSam  = $null
                $mgrMail = $null
                try {
                    $mgrHit = Invoke-AdLdapSearch -Context $queryCtx -BaseDN $attrVal `
                        -Filter '(objectCategory=person)' -Scope Base `
                        -Attributes @('displayName','sAMAccountName','mail') -TimeoutSeconds $TimeoutSeconds
                    if ($mgrHit.Count -gt 0) {
                        $mgrName = if ($mgrHit[0].ContainsKey('displayName'))    { $mgrHit[0].displayName }    else { $null }
                        $mgrSam  = if ($mgrHit[0].ContainsKey('sAMAccountName')) { $mgrHit[0].sAMAccountName } else { $null }
                        $mgrMail = if ($mgrHit[0].ContainsKey('mail'))           { $mgrHit[0].mail }           else { $null }
                    }
                } catch { }
                $record['Manager']               = $(if ($mgrName) { $mgrName } elseif ($mgrSam) { $mgrSam } else { $attrVal })
                $record['ManagerDN']             = $attrVal
                $record['ManagerSamAccountName'] = $(if ($mgrSam)  { $mgrSam }  else { '' })
                $record['ManagerEmail']          = $(if ($mgrMail) { $mgrMail } else { '' })
            } else {
                $record[$attr] = $attrVal
            }
        }
        return $record
    }

    $partial = @{
        SamAccountName    = $null
        DisplayName       = $null
        Email             = $null
        Enabled           = $null
        Domain            = $LocalDomain
        DistinguishedName = $MemberDN
    }

    # --- FSP indirection: resolve SID via foreign pooled context ---
    if ($MemberDN -match 'CN=ForeignSecurityPrincipals') {
        if (-not $Pool) { return $partial }
        try {
            $fspHit = Invoke-AdLdapSearch -Context $LocalContext -BaseDN $MemberDN -Scope Base `
                -Filter '(objectClass=*)' `
                -Attributes @('objectSid','distinguishedName') `
                -BinaryAttributes @('objectSid') `
                -TimeoutSeconds $TimeoutSeconds
        } catch { return $partial }
        if ($fspHit.Count -eq 0 -or -not $fspHit[0].ContainsKey('objectSid')) { return $partial }

        $sidBytes = [byte[]]$fspHit[0].objectSid
        $userSid  = ConvertTo-AdLdapSidString -SidBytes $sidBytes
        # Foreign domain SID = user SID minus the trailing RID
        $foreignDomainSid = $userSid -replace '-\d+$', ''

        # Find pooled context whose domain SID matches
        $target = $null
        $targetDomain = $null
        foreach ($entry in $Pool.Domains.GetEnumerator()) {
            $ctx = $entry.Value
            $poolSid = Get-AdLdapDomainSid -Pool $Pool -Context $ctx
            if ($poolSid -and ($poolSid -eq $foreignDomainSid)) {
                $target = $ctx
                $targetDomain = $entry.Key
                break
            }
        }
        if (-not $target) { return $partial }

        # Lookup in the foreign context by SID (binary filter)
        $sidFilter = ConvertTo-AdLdapSidFilter -SidBytes $sidBytes
        try {
            $userHit = Invoke-AdLdapSearch -Context $target -BaseDN $target.BaseDN -Scope Subtree `
                -Filter "(&(objectCategory=person)(objectSid=$sidFilter))" `
                -Attributes $userAttrs `
                -TimeoutSeconds $TimeoutSeconds
        } catch { return $partial }
        if ($userHit.Count -eq 0) { return $partial }

        $m = $userHit[0]
        $queryCtx = $target  # Set for manager resolution in buildMemberRecord
        return (& $buildMemberRecord $m $targetDomain)
    }

    # --- Direct cross-domain DN routing ---
    # If the member DN lives in a different pooled domain, route to that context
    $queryCtx    = $LocalContext
    $queryDomain = $LocalDomain
    if ($Pool) {
        $routed = Get-AdLdapContextForDN -Pool $Pool -DistinguishedName $MemberDN
        if ($routed -and $routed.BaseDN -ne $LocalContext.BaseDN) {
            $queryCtx = $routed
            # Find the domain key for the routed context
            foreach ($entry in $Pool.Domains.GetEnumerator()) {
                if ($entry.Value -eq $routed) { $queryDomain = $entry.Key; break }
            }
        }
    }

    try {
        $hit = Invoke-AdLdapSearch -Context $queryCtx -BaseDN $MemberDN `
            -Filter '(objectCategory=person)' -Scope Base `
            -Attributes $userAttrs `
            -TimeoutSeconds $TimeoutSeconds
    } catch {
        return $partial
    }

    if ($hit.Count -eq 0) { return $partial }
    $m = $hit[0]
    return (& $buildMemberRecord $m $queryDomain)
}

function Get-GroupRangedMemberDNs {
    <#
    .SYNOPSIS
        Returns ALL member DNs of a group, following AD's ranged-attribute
        retrieval for groups larger than the directory's MaxValRange (~1500).

    .DESCRIPTION
        Active Directory caps a multi-valued attribute at MaxValRange (default
        1500) values per response. A group with more members comes back not as
        'member' but as 'member;range=0-1499'; the remaining values must be
        pulled in follow-up queries ('member;range=1500-*', ...). The original
        code only read the plain 'member' key, so any group over ~1500 members
        appeared to have ZERO members -- which also defeated the large-group
        threshold/skip decision (0 is never >= the threshold).

        This helper handles all three cases:
          * plain 'member'            -> small group, returned as-is (common path)
          * 'member;range=0-1499' ... -> follow ranges until the terminal block
          * no member attribute       -> genuinely empty group (0 DNs)

        StopAfter lets the caller short-circuit once enough DNs have been seen
        to make a skip decision, so a huge group isn't fully paged just to be
        skipped.

    .OUTPUTS
        [pscustomobject] @{ DNs = [string[]]; Ranged = [bool]; Complete = [bool] }
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory = $true)][hashtable]$GroupEntry,
        [Parameter(Mandatory = $true)][hashtable]$Context,
        [Parameter(Mandatory = $true)][string]$GroupDN,
        [Parameter()][int]$PageSize = 1000,
        [Parameter()][int]$TimeoutSeconds = 30,
        [Parameter()][int]$StopAfter = 0,
        [Parameter()][scriptblock]$BlockFetcher
    )

    $dns = New-Object System.Collections.Generic.List[string]

    # Common path: plain 'member' (group at or below MaxValRange ~1500).
    if ($GroupEntry.ContainsKey('member') -and $GroupEntry['member']) {
        if ($GroupEntry.member -is [array]) { foreach ($d in $GroupEntry.member) { if ($d) { $dns.Add([string]$d) } } }
        else                                { $dns.Add([string]$GroupEntry.member) }
        return [pscustomobject]@{ DNs = $dns.ToArray(); Ranged = $false; Complete = $true }
    }

    # Is the member attribute ranged (group exceeds MaxValRange)?
    $hasRange = (@($GroupEntry.Keys | Where-Object { $_ -match '^member;range=' }).Count -gt 0)
    if (-not $hasRange) {
        # No member attribute at all -> genuinely empty group.
        return [pscustomobject]@{ DNs = @(); Ranged = $false; Complete = $true }
    }

    # Default block fetcher reads each range block directly via the raw
    # System.DirectoryServices.Protocols layer. (Invoke-AdLdapSearch DOES return
    # ranged values correctly -- verified live: raw GetValues yields 1500 -- but it
    # emits a comma-wrapped array ',$results.ToArray()' whose single-entry
    # consumption is error-prone: wrapping the call in @() re-nests it so [0] is the
    # inner Hashtable[] rather than the entry hashtable, and indexing that by a
    # string key returns nothing. Reading the block directly sidesteps that pitfall.)
    # Injectable so the loop logic is unit-testable without a live directory.
    if (-not $BlockFetcher) {
        $BlockFetcher = {
            param($Ctx, $Dn, $Start, $Timeout)
            $conn = $Ctx.Connection
            $req = New-Object System.DirectoryServices.Protocols.SearchRequest(
                $Dn, '(objectClass=*)',
                [System.DirectoryServices.Protocols.SearchScope]::Base,
                @("member;range=$Start-*"))
            $req.TimeLimit = [TimeSpan]::FromSeconds($Timeout)
            $resp = $conn.SendRequest($req)
            if ($resp.Entries.Count -eq 0) { return $null }
            $entry = $resp.Entries[0]
            $rk = @($entry.Attributes.AttributeNames | Where-Object { $_ -match '^member;range=' })[0]
            if (-not $rk) { return [pscustomobject]@{ DNs = @(); Terminal = $true; NextStart = $null } }
            $vals = $entry.Attributes[$rk].GetValues([string])
            $terminal = ($rk -match '-\*\s*$')
            $nextStart = $null
            if (-not $terminal -and $rk -match '-(\d+)\s*$') { $nextStart = [int]$Matches[1] + 1 }
            return [pscustomobject]@{ DNs = @($vals); Terminal = $terminal; NextStart = $nextStart }
        }
    }

    $start = 0; $guard = 0; $complete = $false
    while ($true) {
        if (++$guard -gt 10000) { break }                                # never loop forever
        $blk = & $BlockFetcher $Context $GroupDN $start $TimeoutSeconds
        if ($null -eq $blk) { break }
        foreach ($d in @($blk.DNs)) { if ($d) { $dns.Add([string]$d) } }
        if ($blk.Terminal) { $complete = $true; break }
        if ($StopAfter -gt 0 -and $dns.Count -ge $StopAfter) { break }   # enough to decide a skip
        if ($null -eq $blk.NextStart) { break }
        $start = [int]$blk.NextStart
    }

    return [pscustomobject]@{ DNs = $dns.ToArray(); Ranged = $true; Complete = $complete }
}

function Get-GroupMembersDirect {
    <#
    .SYNOPSIS
        Low-level group enumerator on top of ADLdap helpers.

    .DESCRIPTION
        When a ConnectionPool is supplied, contexts are pulled from the pool
        (opened lazily, reused, disposed by the pool owner). When no pool is
        supplied, a one-shot connection is opened and closed for this call
        (backward-compatible with the single-call mode used by unit tests).

        Cross-forest member resolution is active when a pool is supplied:
        member DNs routed to the correct pooled domain, and
        ForeignSecurityPrincipal entries resolved by SID against the foreign
        pooled context.

    .OUTPUTS
        Hashtable: @{ Members; DistinguishedName; MemberCount; Skipped; SkipReason; Errors }
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory = $true)]  [string]$Domain,
        [Parameter(Mandatory = $true)]  [string]$GroupName,
        [Parameter(Mandatory = $false)] [PSCredential]$Credential,
        [Parameter(Mandatory = $false)] [hashtable]$Config = @{},
        [Parameter(Mandatory = $false)] [hashtable]$ConnectionPool,
        [Parameter(Mandatory = $false)] [string[]]$IncludeAttributes = @(),
        [Parameter(Mandatory = $false)] [switch]$CaptureNesting,
        [Parameter(Mandatory = $false)] [switch]$GroupIsDistinguishedName
    )

    $errors        = @()
    $members       = @()
    $groupDN       = $null
    $memberCount   = 0
    $whenChanged   = $null
    $isNested      = $null    # $null = not determined this run
    $nestedGroupDNs = @()

    $pageSize         = if ($Config.LdapPageSize)              { $Config.LdapPageSize }        else { 1000 }
    $timeoutSeconds   = if ($Config.LdapTimeout)               { $Config.LdapTimeout }         else { 120 }
    # Use $null checks (not truthiness) so an explicit 0 in config is honoured
    # rather than silently reverting to the hard-coded default.
    $maxMemberCount   = if ($null -ne $Config.MaxMemberCount)     { $Config.MaxMemberCount }      else { 5000 }
    $skipLargeGroups  = if ($null -ne $Config.SkipLargeGroups)    { $Config.SkipLargeGroups }     else { $true }
    $largeGroupThresh = if ($null -ne $Config.LargeGroupThreshold) { $Config.LargeGroupThreshold } else { 5000 }
    $skipGroupNames   = if ($Config.SkipGroups)                { $Config.SkipGroups }          else { @() }
    $allowInsecure    = if ($null -ne $Config.AllowInsecure)   { $Config.AllowInsecure }       else { $false }

    if ($skipGroupNames -contains $GroupName) {
        return @{
            Members = @(); DistinguishedName = $null; MemberCount = 0
            Skipped = $true
            SkipReason = "Group '$GroupName' is in the SkipGroups list"
            Errors = @()
        }
    }

    $ctx = $null
    $ownCtx = $false    # true when we opened the ctx ourselves (must close in finally)
    try {
        Write-GroupEnumLog -Level 'DEBUG' -Operation 'LdapConnect' `
            -Message "Obtaining LDAP connection to '$Domain'" `
            -Context @{ domain = $Domain; groupName = $GroupName; pooled = [bool]$ConnectionPool }

        try {
            if ($ConnectionPool) {
                $ctx = Get-AdLdapPooledContext -Pool $ConnectionPool -Domain $Domain
            } else {
                $connParams = @{
                    Server         = $Domain
                    TimeoutSeconds = $timeoutSeconds
                }
                if ($Credential)    { $connParams.Credential    = $Credential }
                if ($allowInsecure) { $connParams.AllowInsecure = $true }
                $ctx = New-AdLdapConnection @connParams
                $ownCtx = $true
            }
        } catch {
            Write-GroupEnumLog -Level 'ERROR' -Operation 'LdapConnect' `
                -Message "Could not connect to '$Domain'" `
                -Context @{ domain = $Domain; error = $_.ToString() }
            throw
        }

        Write-GroupEnumLog -Level 'INFO' -Operation 'LdapConnect' `
            -Message "Using connection to '$Domain' via $($ctx.Tier)" `
            -Context @{ domain = $Domain; tier = $ctx.Tier; port = $ctx.Port; baseDN = $ctx.BaseDN; pooled = (-not $ownCtx) }

        if ($ctx.Tier -ne 'LDAPS-Verified') {
            $errors += "WARNING: Using tier '$($ctx.Tier)' (port $($ctx.Port)) for domain '$Domain'. Verified LDAPS was not available."
        }

        # Find the group. A full DN binds Base-scope straight to the object (one precise lookup;
        # disambiguates duplicate CNs across OUs); a plain name uses the indexed CN subtree search.
        if ($GroupIsDistinguishedName) {
            try {
                $groupHits = Invoke-AdLdapSearch -Context $ctx -BaseDN $GroupName -Scope Base `
                    -Filter '(objectCategory=group)' `
                    -Attributes @('distinguishedName','cn','member','whenChanged') `
                    -TimeoutSeconds $timeoutSeconds
            } catch {
                # A non-existent DN raises NoSuchObject on a Base bind -- report it cleanly rather
                # than letting the whole run fault.
                return @{
                    Members = @(); DistinguishedName = $null; MemberCount = 0
                    Skipped = $true
                    SkipReason = "Group DN '$GroupName' could not be resolved in domain '$Domain' ($($_.Exception.Message.Trim()))"
                    Errors = $errors + @("Group DN not resolvable")
                }
            }
            if ($groupHits.Count -eq 0) {
                return @{
                    Members = @(); DistinguishedName = $null; MemberCount = 0
                    Skipped = $true
                    SkipReason = "DN '$GroupName' exists but is not a group"
                    Errors = $errors + @("DN is not a group")
                }
            }
        } else {
            $cnFilterValue = Escape-AdLdapFilterValue $GroupName
            $groupHits = Invoke-AdLdapSearch -Context $ctx `
                -Filter "(&(objectCategory=group)(cn=$cnFilterValue))" `
                -Attributes @('distinguishedName','cn','member','whenChanged') `
                -PageSize $pageSize -TimeoutSeconds $timeoutSeconds

            if ($groupHits.Count -eq 0) {
                return @{
                    Members = @(); DistinguishedName = $null; MemberCount = 0
                    Skipped = $true
                    SkipReason = "Group '$GroupName' not found in domain '$Domain'"
                    Errors = $errors + @("Group not found")
                }
            }
        }

        $g = $groupHits[0]
        $groupDN = $g.DistinguishedName
        if ($g.ContainsKey('whenChanged')) { $whenChanged = [string]$g.whenChanged }

        # Nesting intel (incremental gate): one cheap, indexed, attribute-only query
        # for child groups that are DIRECT members of this group. Only run when asked
        # so legacy/non-incremental runs are not burdened.
        if ($CaptureNesting -and $groupDN) {
            try {
                $dnFilter = Escape-AdLdapFilterValue $groupDN
                $childHits = Invoke-AdLdapSearch -Context $ctx `
                    -Filter "(&(objectCategory=group)(memberOf=$dnFilter))" `
                    -Attributes @('distinguishedName') `
                    -PageSize $pageSize -TimeoutSeconds $timeoutSeconds
                $nestedGroupDNs = @($childHits | ForEach-Object { [string]$_.DistinguishedName } | Where-Object { $_ })
                $isNested = ($nestedGroupDNs.Count -gt 0)
            } catch {
                # Detection failure -> leave $isNested unknown ($null) so the gate
                # conservatively full-enumerates next run.
                $isNested = $null
            }
        }

        # Collect member DNs, following AD's ranged retrieval for groups larger
        # than MaxValRange (~1500) so large groups are counted correctly -- and
        # therefore skipped (or fully enumerated) correctly instead of silently
        # reporting 0 members. StopAfter lets a soon-to-be-skipped huge group
        # short-circuit once it has clearly crossed the threshold.
        $rangeStop = if ($skipLargeGroups) { $largeGroupThresh } else { 0 }
        $rangedResult = Get-GroupRangedMemberDNs -GroupEntry $g -Context $ctx -GroupDN $groupDN `
            -PageSize $pageSize -TimeoutSeconds $timeoutSeconds -StopAfter $rangeStop
        $rawMemberDNs = @($rangedResult.DNs)
        $memberCount = $rawMemberDNs.Count

        if ($skipLargeGroups -and $memberCount -ge $largeGroupThresh) {
            # When StopAfter short-circuited the ranged read, $memberCount is the
            # count gathered so far (>= threshold), NOT the true membership. Say
            # "at least N" and flag it so reports don't present a truncated count
            # as exact.
            $countComplete = [bool]$rangedResult.Complete
            $countWord     = if ($countComplete) { "$memberCount" } else { "at least $memberCount" }
            return @{
                Members = @(); DistinguishedName = $groupDN; MemberCount = $memberCount
                MemberCountComplete = $countComplete
                ResolvedName = [string]$g.cn
                Skipped = $true
                SkipReason = "Group '$GroupName' has $countWord members (threshold: $largeGroupThresh)"
                Errors = $errors
            }
        }

        $memberDNsToQuery = if ($rawMemberDNs.Count -gt $maxMemberCount) {
            $errors += "Warning: Member count ($($rawMemberDNs.Count)) exceeds MaxMemberCount ($maxMemberCount). Results truncated."
            $rawMemberDNs[0..($maxMemberCount - 1)]
        } else {
            $rawMemberDNs
        }

        foreach ($memberDN in $memberDNsToQuery) {
            try {
                $record = Resolve-MemberDnToRecord -MemberDN $memberDN `
                    -LocalContext $ctx -LocalDomain $Domain `
                    -Pool $ConnectionPool -TimeoutSeconds $timeoutSeconds `
                    -IncludeAttributes $IncludeAttributes
                $members += $record
            } catch {
                $errors += "Failed to query member '$memberDN': $($_.Exception.Message.Trim())"
            }
        }

        return @{
            Members           = $members
            DistinguishedName = $groupDN
            ResolvedName      = [string]$g.cn
            MemberCount       = $memberCount
            Skipped           = $false
            SkipReason        = $null
            WhenChanged       = $whenChanged
            IsNested          = $isNested
            NestedGroupDNs    = $nestedGroupDNs
            Errors            = $errors
        }

    } finally {
        if ($ctx -and $ownCtx) { Close-AdLdapConnection $ctx }
    }
}

function Get-GroupMembers {
    <#
    .SYNOPSIS
        Enumerates members of a single AD group via LDAPS

    .DESCRIPTION
        Top-level enumeration function. Validates parameters, applies SkipGroups
        and LargeGroupThreshold checks, then delegates to Get-GroupMembersDirect
        for the actual LDAP work.

        Returns the standard module return shape:
          @{ Data = @{ GroupName; Domain; DistinguishedName; MemberCount; Members;
                       Skipped; SkipReason }; Errors = @() }

    .PARAMETER Domain
        NetBIOS name or FQDN of the target domain

    .PARAMETER GroupName
        Common name (CN) of the group to enumerate

    .PARAMETER Credential
        Optional PSCredential. Omit to use current Windows identity (Kerberos).

    .PARAMETER Config
        Configuration hashtable from New-GroupEnumConfig (or raw hashtable with same keys)

    .OUTPUTS
        Hashtable: @{ Data = @{...}; Errors = @() }
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Domain,

        [Parameter(Mandatory = $true)]
        [string]$GroupName,

        [Parameter(Mandatory = $false)]
        [PSCredential]$Credential,

        [Parameter(Mandatory = $false)]
        [hashtable]$Config = @{},

        [Parameter(Mandatory = $false)]
        [hashtable]$ConnectionPool,

        [Parameter(Mandatory = $false)]
        [string[]]$IncludeAttributes = @(),

        [Parameter(Mandatory = $false)]
        [switch]$CaptureNesting,

        [Parameter(Mandatory = $false)]
        [switch]$GroupIsDistinguishedName
    )

    $errors = @()

    if ([string]::IsNullOrWhiteSpace($Domain)) {
        return @{
            Data   = $null
            Errors = @("Domain parameter is required and cannot be empty")
        }
    }

    if ([string]::IsNullOrWhiteSpace($GroupName)) {
        return @{
            Data   = $null
            Errors = @("GroupName parameter is required and cannot be empty")
        }
    }

    try {
        $directParams = @{
            Domain     = $Domain
            GroupName  = $GroupName
            Credential = $Credential
            Config     = $Config
        }
        if ($ConnectionPool) { $directParams.ConnectionPool = $ConnectionPool }
        if ($IncludeAttributes.Count -gt 0) { $directParams.IncludeAttributes = $IncludeAttributes }
        if ($CaptureNesting) { $directParams.CaptureNesting = $true }
        if ($GroupIsDistinguishedName) { $directParams.GroupIsDistinguishedName = $true }
        $raw = Get-GroupMembersDirect @directParams

        if ($raw.Errors.Count -gt 0) {
            $errors += $raw.Errors
        }

        # When the input was a DN, surface the resolved CN as the group name so reports, the
        # privileged-name predicate, and change tracking all key off the real name (not the raw DN).
        $effectiveName = if ($GroupIsDistinguishedName -and $raw.ResolvedName) { [string]$raw.ResolvedName } else { $GroupName }

        $data = @{
            GroupName         = $effectiveName
            Domain            = $Domain
            DistinguishedName = $raw.DistinguishedName
            MemberCount       = $raw.MemberCount
            Members           = $raw.Members
            Skipped           = $raw.Skipped
            SkipReason        = $raw.SkipReason
            WhenChanged       = $raw.WhenChanged
            IsNested          = $raw.IsNested
            NestedGroupDNs    = $raw.NestedGroupDNs
        }

        return @{
            Data   = $data
            Errors = $errors
        }

    } catch {
        $errors += "Unexpected error enumerating group '$Domain\$GroupName': $_"
        return @{
            Data   = @{
                GroupName         = $GroupName
                Domain            = $Domain
                DistinguishedName = $null
                MemberCount       = 0
                Members           = @()
                Skipped           = $false
                SkipReason        = $null
            }
            Errors = $errors
        }
    }
}
