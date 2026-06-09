<#
.SYNOPSIS
    Incremental-enumeration gate: decide whether a group can be skipped this run.

.DESCRIPTION
    Supports the orchestrator's opt-in -Incremental mode. Instead of fully
    enumerating every group's members each run, we read just the group's
    `whenChanged` timestamp (one cheap attribute, no member expansion) and compare
    it to the value recorded in the previous run's JSON cache. If a group has not
    changed since then, the orchestrator reuses the cached membership instead of
    re-pulling it.

    Correctness boundary (verified live 2026-05-28):
      - A DIRECT member add/remove bumps the group's own `whenChanged`. So a flat
        group (no nested group members) is safe to gate on its own timestamp.
      - A NESTED parent's `whenChanged` does NOT move when a child group's
        membership changes. So in v1 a nested group (cached IsNested = true) is
        ALWAYS fully enumerated -- never skipped -- to avoid that blind spot.

    This gate detects MEMBERSHIP changes only. Per-member attribute drift (stale
    flags, manager/title, etc.) is not reflected for skipped groups; the orchestrator
    disables skipping when -DetectStale is set and warns when -IncludeAttributes is.

.NOTES
    No emoji in code. Depends on ADLdap.ps1 (Invoke-AdLdapSearch,
    Escape-AdLdapFilterValue) being dot-sourced first.
#>

# ---------------------------------------------------------------------------
# Public: ConvertFrom-AdGeneralizedTime
# ---------------------------------------------------------------------------
function ConvertFrom-AdGeneralizedTime {
    <#
    .SYNOPSIS
        Parses an AD generalized-time string (e.g. '20260528132404.0Z') to [datetime] (UTC).

    .OUTPUTS
        [datetime] (UTC) on success, or $null if the value is missing/unparseable.
    #>
    [CmdletBinding()]
    [OutputType([object])]
    param(
        [Parameter(Mandatory = $false)]
        [string]$Value
    )

    if ([string]::IsNullOrWhiteSpace($Value)) { return $null }

    # Format: yyyyMMddHHmmss[.f]Z -- take the leading 14 digits.
    $m = [regex]::Match($Value, '^(\d{14})')
    if (-not $m.Success) { return $null }

    $dt = [datetime]::MinValue
    $ok = [datetime]::TryParseExact(
        $m.Groups[1].Value, 'yyyyMMddHHmmss',
        [System.Globalization.CultureInfo]::InvariantCulture,
        [System.Globalization.DateTimeStyles]::AssumeUniversal -bor [System.Globalization.DateTimeStyles]::AdjustToUniversal,
        [ref]$dt)
    if (-not $ok) { return $null }
    return $dt
}

# ---------------------------------------------------------------------------
# Public: Test-GroupUnchanged
# ---------------------------------------------------------------------------
function Test-GroupUnchanged {
    <#
    .SYNOPSIS
        Pure decision: can this group be skipped (reused from cache) this run?

    .PARAMETER CurrentStamp
        The group's current `whenChanged` string read live this run.

    .PARAMETER CachedData
        The cached group's Data hashtable from the prior run (must carry WhenChanged
        and IsNested to be skippable).

    .OUTPUTS
        [bool] $true only when the group is flat (not nested), both timestamps parse,
        and the current timestamp is <= the cached one. Conservative: any ambiguity
        returns $false (=> the caller fully enumerates).
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $false)]
        [string]$CurrentStamp,

        [Parameter(Mandatory = $false)]
        $CachedData
    )

    if ($null -eq $CachedData) { return $false }
    # Skip ONLY when the group is definitively known-flat. IsNested = $true (nested)
    # or $null (unknown -- e.g. a cache from before nesting was captured) both force a
    # full enumeration, avoiding the nested-child blind spot.
    if ($CachedData.IsNested -ne $false) { return $false }
    # Must have a prior baseline timestamp to compare against.
    if ([string]::IsNullOrWhiteSpace([string]$CachedData.WhenChanged)) { return $false }
    if ([string]::IsNullOrWhiteSpace($CurrentStamp)) { return $false }

    $cur    = ConvertFrom-AdGeneralizedTime -Value $CurrentStamp
    $cached = ConvertFrom-AdGeneralizedTime -Value ([string]$CachedData.WhenChanged)
    if ($null -eq $cur -or $null -eq $cached) { return $false }

    # Unchanged when the live timestamp has not advanced past the cached baseline.
    return ($cur -le $cached)
}

# ---------------------------------------------------------------------------
# Public: Get-GroupChangeStamp
# ---------------------------------------------------------------------------
function Test-GroupReuseEligible {
    <#
    .SYNOPSIS
        Single authoritative incremental-reuse decision for one group: may it be
        reused from the prior cache this run?

    .DESCRIPTION
        Encapsulates the cache lookup + the Test-GroupUnchanged predicate so the
        orchestrator has ONE call. Previously the orchestrator pre-gated on a copy of
        Test-GroupUnchanged's nested/whenChanged conditions; that duplicate could
        drift out of sync. Test-GroupUnchanged remains the single source of truth for
        the conditions (flat group, both timestamps parse, live stamp not advanced).

    .PARAMETER PriorCacheLookup
        Hashtable keyed "DOMAIN|GroupName" of prior cached entries (@{ Data = ... }).
    .PARAMETER Key
        The "DOMAIN|GroupName" lookup key for the current group (must match the cache
        key format produced by Get-CacheFromSqlite / the JSON cache).
    .PARAMETER CurrentStamp
        The group's current whenChanged stamp read live this run.

    .OUTPUTS
        [bool] -- $true only when the group is cached and Test-GroupUnchanged passes.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [hashtable]$PriorCacheLookup,
        [string]$Key,
        [string]$CurrentStamp
    )
    if ($null -eq $PriorCacheLookup -or -not $PriorCacheLookup.ContainsKey($Key)) { return $false }
    $cached = $PriorCacheLookup[$Key]
    if ($null -eq $cached) { return $false }
    return [bool](Test-GroupUnchanged -CurrentStamp $CurrentStamp -CachedData $cached.Data)
}

function Get-GroupChangeStamp {
    <#
    .SYNOPSIS
        Reads a group's current `whenChanged` (one cheap attribute-only LDAP query).

    .PARAMETER Context
        A pooled/standalone connection context from ADLdap.ps1.

    .PARAMETER GroupName
        Group CN to look up.

    .PARAMETER PageSize / TimeoutSeconds
        Passed through to Invoke-AdLdapSearch.

    .OUTPUTS
        The `whenChanged` string, or $null if the group was not found / on error.
    #>
    [CmdletBinding()]
    [OutputType([object])]
    param(
        [Parameter(Mandatory = $true)]  [hashtable]$Context,
        [Parameter(Mandatory = $true)]  [string]$GroupName,
        [Parameter(Mandatory = $false)] [int]$PageSize = 1000,
        [Parameter(Mandatory = $false)] [int]$TimeoutSeconds = 120
    )

    try {
        $cnEsc = Escape-AdLdapFilterValue $GroupName
        $hits = Invoke-AdLdapSearch -Context $Context `
            -Filter "(&(objectCategory=group)(cn=$cnEsc))" `
            -Attributes @('whenChanged', 'distinguishedName') `
            -PageSize $PageSize -TimeoutSeconds $TimeoutSeconds -SizeLimit 2
        if ($hits.Count -eq 0) { return $null }
        # Ambiguous CN (same CN under multiple OUs): we can't pick a definitive
        # change stamp, so return $null and let the incremental gate conservatively
        # re-enumerate rather than trusting an arbitrary $hits[0].
        if ($hits.Count -gt 1) { return $null }
        if ($hits[0].ContainsKey('whenChanged')) { return [string]$hits[0].whenChanged }
        return $null
    } catch {
        return $null
    }
}
