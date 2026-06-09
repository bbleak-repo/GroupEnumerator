<#
.SYNOPSIS
    Stale and disabled account detection for AD migration readiness

.DESCRIPTION
    Queries Active Directory for lastLogonTimestamp and userAccountControl on a set
    of user accounts to classify them as Active, Disabled, Stale, or NeverLoggedIn.

    Accounts classified as Disabled or Stale should be excluded from migration
    Change Requests (they have no active session to migrate).

    Key behaviours:
      - Uses the shared ADLdap helpers (New-AdLdapConnection / Invoke-AdLdapSearch)
        built on System.DirectoryServices.Protocols.LdapConnection. Tiered LDAPS/LDAP
        negotiation is controlled by Config.AllowInsecure.
      - Each user is queried with a Base-scope search on their DistinguishedName
        (most efficient: avoids full subtree scans)
      - lastLogonTimestamp staleness threshold is Config.StaleAccountDays (default 90)
      - FileTime conversion handles special "never" sentinel values (0 and Int64.MaxValue)
      - Single LdapConnection is reused across all member queries and closed in finally
      - Structured logging via Write-GroupEnumLog (must be loaded in session)

.NOTES
    Requires ADLdap.ps1 and GroupEnumLogger.ps1 to be dot-sourced first.
    Compatible with PowerShell 5.1 and 7+. Targets Windows Active Directory only.
    Uses objectCategory (indexed) for all LDAP filters; never uses objectClass.

    lastLogonTimestamp replication note:
      AD replicates lastLogonTimestamp only when it differs from the stored value by
      more than 9-14 days. Accounts active in the last 14 days may appear "stale"
      if the timestamp has not replicated yet. The threshold should be set at least
      14 days above the desired detection window to avoid false positives.
#>

# ---------------------------------------------------------------------------
# Public: ConvertFrom-FileTime
# ---------------------------------------------------------------------------
function ConvertFrom-FileTime {
    <#
    .SYNOPSIS
        Converts an AD FILETIME (Int64) value to a nullable DateTime (UTC)

    .DESCRIPTION
        Active Directory stores timestamps as Windows FILETIME values: the number of
        100-nanosecond intervals since 1 January 1601 UTC.

        Two sentinel values indicate "never":
          0                    - attribute not set or account has never logged in
          9223372036854775807  - Int64.MaxValue, used by AD for "no expiry / never"

        Both return $null. All other values are converted via [DateTime]::FromFileTimeUtc().

    .PARAMETER FileTime
        The raw FILETIME value as an Int64 (or value convertible to Int64).

    .OUTPUTS
        [DateTime] in UTC, or $null for the two "never" sentinel values.

    .EXAMPLE
        $dt = ConvertFrom-FileTime -FileTime $lastLogonTimestampRaw
        if ($null -eq $dt) { "Never logged in" } else { $dt.ToString('yyyy-MM-dd') }
    #>
    [CmdletBinding()]
    [OutputType([nullable[datetime]])]
    param(
        [Parameter(Mandatory = $true)]
        [object]$FileTime
    )

    try {
        $ft = [Int64]$FileTime
    } catch {
        return $null
    }

    # Sentinel: 0 = never set, Int64.MaxValue = "no expiry" / never
    if ($ft -eq 0 -or $ft -eq [Int64]::MaxValue) {
        return $null
    }

    try {
        return [DateTime]::FromFileTimeUtc($ft)
    } catch {
        return $null
    }
}

# ---------------------------------------------------------------------------
# Public: Get-AccountStaleness
# ---------------------------------------------------------------------------
function Get-AccountStaleness {
    <#
    .SYNOPSIS
        Classifies a set of AD user accounts as Active, Disabled, Stale, or NeverLoggedIn

    .DESCRIPTION
        For each user in the Members array, performs a Base-scope LDAP query on the
        user's DistinguishedName to retrieve lastLogonTimestamp. Combined with the
        Enabled flag already present in the member hashtable (sourced from
        userAccountControl bit 2), each account is classified into one of four buckets:

          Disabled      - Enabled = $false regardless of lastLogonTimestamp
          NeverLoggedIn - Enabled = $true, lastLogonTimestamp is absent or a sentinel value
          Stale         - Enabled = $true, last logon older than StaleAccountDays threshold
          Active        - Enabled = $true, last logon within the threshold window

        Accounts in Disabled, NeverLoggedIn, and Stale buckets should be flagged
        as skip candidates in migration Change Requests.

        Requires ADLdap.ps1 and Write-GroupEnumLog to be loaded in session.

    .PARAMETER Members
        Array of user hashtables as returned by Resolve-NestedGroupMembers or
        Get-GroupMembersDirect. Each entry must contain at minimum:
          DistinguishedName - string DN used for Base-scope query
          Enabled           - $true/$false from userAccountControl bit 2
          SamAccountName    - used for logging (can be $null)

    .PARAMETER Domain
        NetBIOS name or FQDN of the domain to query for lastLogonTimestamp.
        Must match the domain the members were retrieved from.

    .PARAMETER Credential
        Optional PSCredential. Omit for integrated Windows auth (Kerberos).

    .PARAMETER Config
        Configuration hashtable. Relevant keys:
          StaleAccountDays - days without login before "stale" classification (default 90)
          LdapTimeout      - per-query timeout seconds (default 120)
          AllowInsecure    - allow LDAP (389) fallback (default $false)

    .OUTPUTS
        Hashtable:
          Disabled      - user hashtables with Enabled = $false
          Stale         - user hashtables with last logon beyond the threshold
          Active        - user hashtables with recent logon
          NeverLoggedIn - user hashtables with no lastLogonTimestamp value
          Summary       - @{ TotalChecked; DisabledCount; StaleCount; ActiveCount;
                              NeverLoggedInCount; StaleThresholdDays }
          Errors        - array of error strings (non-fatal, per-user failures)

    .EXAMPLE
        $staleness = Get-AccountStaleness -Members $result.FlatMembers `
            -Domain 'CORP' -Credential $cred -Config $cfg
        $staleness.Summary | Format-Table
        $staleness.Stale   | Select-Object SamAccountName, LastLogon | Format-Table
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory = $true)]
        [array]$Members,

        [Parameter(Mandatory = $true)]
        [string]$Domain,

        [Parameter(Mandatory = $false)]
        [PSCredential]$Credential,

        [Parameter(Mandatory = $false)]
        [hashtable]$Config = @{},

        [Parameter(Mandatory = $false)]
        [hashtable]$ConnectionPool
    )

    $errors = @()

    $staleDays      = if ($Config.StaleAccountDays -and $Config.StaleAccountDays -gt 0) {
        $Config.StaleAccountDays
    } else { 90 }
    $timeoutSeconds = if ($Config.LdapTimeout)  { $Config.LdapTimeout }  else { 120 }
    $allowInsecure  = if ($null -ne $Config.AllowInsecure) { $Config.AllowInsecure } else { $false }

    $cutoffDate = [DateTime]::UtcNow.AddDays(-$staleDays)

    $disabled      = [System.Collections.ArrayList]::new()
    $stale         = [System.Collections.ArrayList]::new()
    $active        = [System.Collections.ArrayList]::new()
    $neverLoggedIn = [System.Collections.ArrayList]::new()

    Write-GroupEnumLog -Level 'INFO' -Operation 'StaleDetect' `
        -Message "Starting staleness check for $($Members.Count) member(s) in domain '$Domain'" `
        -Context @{ domain = $Domain; memberCount = $Members.Count; staleDays = $staleDays; cutoff = $cutoffDate.ToString('yyyy-MM-dd') }

    # Open (or acquire from pool) a single LdapConnection and reuse it across all per-member Base-scope queries.
    $ctx = $null
    $ownCtx = $false
    try {
        Write-GroupEnumLog -Level 'DEBUG' -Operation 'LdapConnect' `
            -Message "Obtaining LDAP connection to '$Domain'" `
            -Context @{ domain = $Domain; allowInsecure = $allowInsecure; pooled = [bool]$ConnectionPool }

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
            return @{
                Disabled      = @()
                Stale         = @()
                Active        = @()
                NeverLoggedIn = @()
                Summary       = @{
                    TotalChecked       = 0
                    DisabledCount      = 0
                    StaleCount         = 0
                    ActiveCount        = 0
                    NeverLoggedInCount = 0
                    StaleThresholdDays = $staleDays
                }
                Errors = @("Cannot connect to domain '$Domain': $($_.ToString())")
            }
        }

        Write-GroupEnumLog -Level 'INFO' -Operation 'LdapConnect' `
            -Message "Connected to '$Domain' via $($ctx.Tier)" `
            -Context @{ domain = $Domain; tier = $ctx.Tier; port = $ctx.Port; baseDN = $ctx.BaseDN; pooled = (-not $ownCtx) }

        if ($ctx.Tier -ne 'LDAPS-Verified') {
            $errors += "WARNING: Using tier '$($ctx.Tier)' (port $($ctx.Port)) for domain '$Domain'. Verified LDAPS was not available."
        }

    foreach ($member in $Members) {
        $dn  = $member.DistinguishedName
        $sam = $(if ($member.SamAccountName) { $member.SamAccountName } else { $dn })

        # Skip entries that lack a DN (contacts, partial entries from Get-GroupMembersDirect)
        if (-not $dn) {
            Write-GroupEnumLog -Level 'DEBUG' -Operation 'StaleDetect' `
                -Message "Skipping member with no DistinguishedName (sam: $sam)" `
                -Context @{ sam = $sam }
            continue
        }

        # Bucket 1: already-disabled (no need to query AD for lastLogon)
        if ($member.Enabled -eq $false) {
            $enriched = $member.Clone()
            $enriched.LastLogon          = $null
            $enriched.LastLogonRaw       = $null
            $enriched.StalenessCategory  = 'Disabled'

            $null = $disabled.Add($enriched)

            Write-GroupEnumLog -Level 'DEBUG' -Operation 'StaleDetect' `
                -Message "Account '$sam' is disabled -- skipping lastLogon query" `
                -Context @{ sam = $sam; dn = $dn; category = 'Disabled' }
            continue
        }

        # Query AD for lastLogonTimestamp
        $lastLogonDt      = $null
        $lastLogonRaw     = $null
        $queryFailed      = $false
        $wasDisabledLive  = $false

        try {
            $memberHits = Invoke-AdLdapSearch -Context $ctx -BaseDN $dn `
                -Filter '(objectCategory=person)' -Scope Base `
                -Attributes @('lastLogonTimestamp','userAccountControl') `
                -TimeoutSeconds $timeoutSeconds

            if ($memberHits -and $memberHits.Count -gt 0) {
                $mr = $memberHits[0]

                # Re-check userAccountControl from the live query (in case Enabled was stale)
                $uacLive = if ($mr.ContainsKey('userAccountControl')) {
                    [int]$mr.userAccountControl
                } else { $null }

                if ($null -ne $uacLive -and ($uacLive -band 2) -ne 0) {
                    # Account became disabled since enumeration.
                    $enriched = $member.Clone()
                    $enriched.Enabled           = $false
                    $enriched.LastLogon          = $null
                    $enriched.LastLogonRaw       = $null
                    $enriched.StalenessCategory  = 'Disabled'

                    $null = $disabled.Add($enriched)

                    Write-GroupEnumLog -Level 'DEBUG' -Operation 'StaleDetect' `
                        -Message "Account '$sam' is disabled (UAC re-check) -- moving to Disabled bucket" `
                        -Context @{ sam = $sam; dn = $dn; category = 'Disabled' }

                    $wasDisabledLive = $true
                }

                if (-not $wasDisabledLive -and $mr.ContainsKey('lastLogonTimestamp')) {
                    $lastLogonRaw = $mr.lastLogonTimestamp
                    $lastLogonDt  = ConvertFrom-FileTime -FileTime $lastLogonRaw
                }

            } else {
                Write-GroupEnumLog -Level 'WARN' -Operation 'StaleDetect' `
                    -Message "Base-scope query for '$sam' returned no results (DN may be stale or cross-domain)" `
                    -Context @{ sam = $sam; dn = $dn }
                $errors += "No results for user '$sam' (DN: $dn) -- may be a cross-domain or deleted account"
                $queryFailed = $true
            }

        } catch {
            $errors += "Failed to query lastLogonTimestamp for '$sam' (DN: $dn): $_"

            Write-GroupEnumLog -Level 'ERROR' -Operation 'StaleDetect' `
                -Message "LDAP query failed for '$sam': $_" `
                -Context @{ sam = $sam; dn = $dn; error = $_.ToString() }

            $queryFailed = $true
        }

        # Skip classification if the live UAC check already bucketed this account, or the query failed
        if ($wasDisabledLive -or $queryFailed) { continue }

        # Classify the account
        $enriched = $member.Clone()
        $enriched.LastLogon    = $lastLogonDt
        $enriched.LastLogonRaw = $lastLogonRaw

        if ($null -eq $lastLogonDt) {
            # Bucket 2: NeverLoggedIn
            $enriched.StalenessCategory = 'NeverLoggedIn'
            $null = $neverLoggedIn.Add($enriched)

            Write-GroupEnumLog -Level 'DEBUG' -Operation 'StaleDetect' `
                -Message "Account '$sam' has no lastLogonTimestamp -- classified as NeverLoggedIn" `
                -Context @{ sam = $sam; dn = $dn; category = 'NeverLoggedIn' }

        } elseif ($lastLogonDt -lt $cutoffDate) {
            # Bucket 3: Stale
            $enriched.StalenessCategory = 'Stale'
            $null = $stale.Add($enriched)

            $daysAgo = [int]([DateTime]::UtcNow - $lastLogonDt).TotalDays

            Write-GroupEnumLog -Level 'DEBUG' -Operation 'StaleDetect' `
                -Message "Account '$sam' last logged in $daysAgo days ago -- classified as Stale (threshold: $staleDays days)" `
                -Context @{ sam = $sam; dn = $dn; lastLogon = $lastLogonDt.ToString('yyyy-MM-dd'); daysAgo = $daysAgo; threshold = $staleDays; category = 'Stale' }

        } else {
            # Bucket 4: Active
            $enriched.StalenessCategory = 'Active'
            $null = $active.Add($enriched)

            $daysAgo = [int]([DateTime]::UtcNow - $lastLogonDt).TotalDays

            Write-GroupEnumLog -Level 'DEBUG' -Operation 'StaleDetect' `
                -Message "Account '$sam' last logged in $daysAgo days ago -- classified as Active" `
                -Context @{ sam = $sam; dn = $dn; lastLogon = $lastLogonDt.ToString('yyyy-MM-dd'); daysAgo = $daysAgo; category = 'Active' }
        }
    }

    } finally {
        if ($ctx -and $ownCtx) { Close-AdLdapConnection $ctx }
    }

    $disabledCount      = $disabled.Count
    $staleCount         = $stale.Count
    $activeCount        = $active.Count
    $neverLoggedInCount = $neverLoggedIn.Count
    $totalChecked       = $disabledCount + $staleCount + $activeCount + $neverLoggedInCount

    if ($staleCount -gt 0) {
        Write-GroupEnumLog -Level 'WARN' -Operation 'StaleDetect' `
            -Message "$staleCount stale account(s) found in domain '$Domain' (threshold: $staleDays days)" `
            -Context @{ domain = $Domain; staleCount = $staleCount; staleDays = $staleDays; cutoff = $cutoffDate.ToString('yyyy-MM-dd') }
    }

    Write-GroupEnumLog -Level 'INFO' -Operation 'StaleDetect' `
        -Message "Staleness check complete for domain '$Domain': $totalChecked checked, $activeCount active, $disabledCount disabled, $staleCount stale, $neverLoggedInCount never logged in" `
        -Context @{
            domain             = $Domain
            totalChecked       = $totalChecked
            activeCount        = $activeCount
            disabledCount      = $disabledCount
            staleCount         = $staleCount
            neverLoggedInCount = $neverLoggedInCount
            staleDays          = $staleDays
            errorCount         = $errors.Count
        }

    return @{
        Disabled      = @($disabled)
        Stale         = @($stale)
        Active        = @($active)
        NeverLoggedIn = @($neverLoggedIn)
        Summary       = @{
            TotalChecked       = $totalChecked
            DisabledCount      = $disabledCount
            StaleCount         = $staleCount
            ActiveCount        = $activeCount
            NeverLoggedInCount = $neverLoggedInCount
            StaleThresholdDays = $staleDays
        }
        Errors = $errors
    }
}

# ---------------------------------------------------------------------------
# Public: Get-StaleAccountSummary
# ---------------------------------------------------------------------------
function Get-StaleAccountSummary {
    <#
    .SYNOPSIS
        Aggregates staleness data across multiple group results into a report-ready summary

    .DESCRIPTION
        Accepts an array of group result objects that each contain a Staleness key
        (as returned by Get-AccountStaleness) and computes totals across all groups.
        Intended for the executive summary section of migration reports.

        Each element in GroupResults must be a hashtable with at minimum:
          GroupName  - string name of the group
          Domain     - string domain of the group
          Staleness  - the hashtable returned by Get-AccountStaleness for that group

    .PARAMETER GroupResults
        Array of group result hashtables with Staleness sub-hashtables attached.

    .OUTPUTS
        Hashtable:
          TotalUsers         - total unique users considered across all groups
          TotalActive        - total classified as Active
          TotalDisabled      - total classified as Disabled
          TotalStale         - total classified as Stale
          TotalNeverLoggedIn - total with no lastLogonTimestamp
          SkipCandidates     - total recommended to skip in migration
                               (sum of Disabled + Stale + NeverLoggedIn)
          ReadyForMigration  - total Active users (migration candidates)
          MigrationReadinessPct - percentage (0-100) of users that are Active
          GroupBreakdown     - per-group summary array
                               (GroupName, Domain, Active, Disabled, Stale, NeverLoggedIn, SkipCount)
          StaleThresholdDays - the threshold from the first group's Summary (or $null)

    .EXAMPLE
        # After running Get-AccountStaleness for each group:
        $groupResults = @(
            @{ GroupName = 'GG_Team1'; Domain = 'CORP'; Staleness = $staleness1 },
            @{ GroupName = 'GG_Team2'; Domain = 'CORP'; Staleness = $staleness2 }
        )
        $summary = Get-StaleAccountSummary -GroupResults $groupResults
        "Migration readiness: $($summary.MigrationReadinessPct)%"
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory = $true)]
        [array]$GroupResults
    )

    $totalActive        = 0
    $totalDisabled      = 0
    $totalStale         = 0
    $totalNeverLoggedIn = 0
    $staleThreshold     = $null
    $groupBreakdown     = [System.Collections.ArrayList]::new()

    foreach ($groupResult in $GroupResults) {
        $gName     = $(if ($groupResult.GroupName) { $groupResult.GroupName } else { 'Unknown' })
        $gDomain   = $(if ($groupResult.Domain)    { $groupResult.Domain }    else { 'Unknown' })
        $staleness = $groupResult.Staleness

        if (-not $staleness) {
            Write-GroupEnumLog -Level 'WARN' -Operation 'StaleAccountSummary' `
                -Message "Group '$gName' has no Staleness data -- skipping in summary" `
                -Context @{ group = $gName; domain = $gDomain }
            continue
        }

        $gActive   = if ($staleness.Summary.ActiveCount)        { $staleness.Summary.ActiveCount }        else { 0 }
        $gDisabled = if ($staleness.Summary.DisabledCount)       { $staleness.Summary.DisabledCount }       else { 0 }
        $gStale    = if ($staleness.Summary.StaleCount)          { $staleness.Summary.StaleCount }          else { 0 }
        $gNever    = if ($staleness.Summary.NeverLoggedInCount)  { $staleness.Summary.NeverLoggedInCount }  else { 0 }
        $gSkip     = $gDisabled + $gStale + $gNever

        $totalActive        += $gActive
        $totalDisabled      += $gDisabled
        $totalStale         += $gStale
        $totalNeverLoggedIn += $gNever

        if ($null -eq $staleThreshold -and $staleness.Summary.StaleThresholdDays) {
            $staleThreshold = $staleness.Summary.StaleThresholdDays
        }

        $null = $groupBreakdown.Add(@{
            GroupName       = $gName
            Domain          = $gDomain
            Active          = $gActive
            Disabled        = $gDisabled
            Stale           = $gStale
            NeverLoggedIn   = $gNever
            SkipCount       = $gSkip
        })
    }

    $totalUsers    = $totalActive + $totalDisabled + $totalStale + $totalNeverLoggedIn
    $skipTotal     = $totalDisabled + $totalStale + $totalNeverLoggedIn
    $readinessPct  = if ($totalUsers -gt 0) {
        [math]::Round(($totalActive / $totalUsers) * 100, 1)
    } else { 0 }

    Write-GroupEnumLog -Level 'INFO' -Operation 'StaleAccountSummary' `
        -Message "Stale account summary across $($GroupResults.Count) group(s): $totalUsers total, $totalActive active ($readinessPct% ready), $skipTotal skip candidates" `
        -Context @{
            groupCount          = $GroupResults.Count
            totalUsers          = $totalUsers
            totalActive         = $totalActive
            totalDisabled       = $totalDisabled
            totalStale          = $totalStale
            totalNeverLoggedIn  = $totalNeverLoggedIn
            skipCandidates      = $skipTotal
            migrationReadinessPct = $readinessPct
        }

    return @{
        TotalUsers              = $totalUsers
        TotalActive             = $totalActive
        TotalDisabled           = $totalDisabled
        TotalStale              = $totalStale
        TotalNeverLoggedIn      = $totalNeverLoggedIn
        SkipCandidates          = $skipTotal
        ReadyForMigration       = $totalActive
        MigrationReadinessPct   = $readinessPct
        GroupBreakdown          = @($groupBreakdown)
        StaleThresholdDays      = $staleThreshold
    }
}
