<#
.SYNOPSIS
    Cross-domain group membership enumeration orchestrator

.DESCRIPTION
    Reads a CSV of domain/group pairs, enumerates members from each AD domain via
    System.DirectoryServices.Protocols.LdapConnection (the modern LDAP stack that
    works against DCs enforcing LDAP Channel Binding / Signing), optionally runs
    fuzzy cross-domain name matching, and produces an HTML report and/or JSON cache.

    Works equally well for single-domain inventory and multi-forest migration
    readiness. Cross-domain and cross-forest features are opt-in switches.

    Core features:
    - CSV input in Domain,GroupName or DOMAIN\GroupName backslash format
    - Per-domain connection pooling (one LdapConnection reused across all groups)
    - Tiered connection strategy with optional cert-verification bypass and
      Kerberos sign+seal fallback on 389 (-AllowInsecure)
    - Dark/light HTML reports, JSON cache for offline report regeneration
    - Structured JSON Lines logs with per-tier LdapConnect events

    V2 features (enabled by switches):
    - Nested group resolution to flat user lists (-ResolveNested)
    - Stale/disabled account detection (-DetectStale)
    - Fuzzy cross-domain group name matching via Levenshtein (-FuzzyMatch)
    - Cross-domain user correlation and gap analysis (-AnalyzeGaps)
    - Cross-forest member resolution when multiple domains are pooled:
      direct foreign DN routing and ForeignSecurityPrincipal SID lookup
    - Application-level readiness from CSV mapping (-AppMappingCsv)
    - SMTP delivery of migration readiness report (-SendEmail)

.PARAMETER CsvPath
    Full path to the CSV file containing groups to enumerate.
    Supports Domain,GroupName column format or DOMAIN\GroupName single-column format.

.PARAMETER Credential
    Optional PSCredential used for all LDAP binds.
    When omitted, the current Windows identity (Kerberos) is used.

.PARAMETER FuzzyMatch
    Enable fuzzy cross-domain group name matching using Levenshtein similarity.

.PARAMETER ConfigPath
    Path to group-enum-config.json. Defaults to .\Config\group-enum-config.json.
    If the file is missing, built-in defaults are used.

.PARAMETER OutputPath
    Output directory for generated files. Overrides config OutputDirectory setting.

.PARAMETER FromCache
    Skip LDAP enumeration and load previously saved JSON data for report regeneration.

.PARAMETER CachePath
    Path to the JSON cache file when using -FromCache.
    Also controls where the cache file is written when not using -FromCache.
    Defaults to config CachePath directory.

.PARAMETER Theme
    Initial HTML report theme: "dark" (default) or "light".
    The user can toggle in-browser after opening the report.

.PARAMETER JsonOnly
    Generate only the JSON cache file. Skip HTML report generation.

.PARAMETER NoCache
    Skip saving the JSON cache file after enumeration.

.PARAMETER ResolveNested
    Flatten nested group memberships to a single-level user list for each group.
    Requires LDAPS connectivity to resolve child groups.

.PARAMETER AnalyzeGaps
    Run migration gap analysis against matched group pairs.
    Implies user correlation. Requires -FuzzyMatch to have produced matched pairs.

.PARAMETER DetectStale
    Flag stale and disabled accounts in enumerated group membership.
    Stale threshold is controlled by -StaleDays or config StaleAccountDays (default 90).

.PARAMETER AppMappingCsv
    Optional path to a CSV mapping application names to AD group pairs.
    Columns: AppName,SourceGroup,TargetGroup,Notes

.PARAMETER SendEmail
    Send the migration readiness summary email after report generation.
    Requires Email section in config to be populated and Enabled = true.

.PARAMETER StaleDays
    Override the StaleAccountDays config value. 0 = use config value.

.PARAMETER TrackChanges
    Enable persistent daily change tracking. Maintains a local state.json plus an
    append-only changelog.jsonl per group set and emits a change-feed CSV of users
    added/removed since the last run. First run seeds the baseline (no changes
    reported). Works for one domain or many (groups keyed by DOMAIN\GroupName).
    Additive companion to the snapshot-diff drift mode (-BaselinePath/-PreviousRunPath).

.PARAMETER ChangeType
    Which changes to write to the change-feed CSV: Added, Removed, or Both (default).
    Use -ChangeType Removed for a SailPoint removals feed.

.PARAMETER StatePath
    Directory for the change-tracking state and change log. Defaults to config
    ChangeTracking.StatePath, else a 'State' folder under the script root.

.PARAMETER ExportMembersCsv
    Also write a flat roster CSV of every enumerated member alongside the normal
    run (Domain, GroupName, SamAccountName, DisplayName, Email, Enabled). One row
    per group membership. Independent of change tracking; pair with -ResolveNested
    to flatten nested groups to users.

.PARAMETER ChangePeriod
    When used with -TrackChanges and report switches (-GovernanceReport,
    -ComplianceReport, -ExecutiveDashboard, -LeadershipSummary), reads back
    historical change events from the changelog for the specified time window
    and passes them to the report generators. Without this parameter, reports
    only show changes detected in the current run.
    Valid values: Day, Week, Month, Quarter.

.PARAMETER ChangeDays
    Custom change-history window as a number of days back (e.g. 14). An alternative to the
    -ChangePeriod presets. Takes precedence over -ChangePeriod.

.PARAMETER ChangeSince
    Explicit start date/time for the change-history window (e.g. '2026-05-01'). Takes
    precedence over both -ChangeDays and -ChangePeriod.

.PARAMETER Incremental
    Opt-in optimization for large/daily runs. For each group, read only its
    'whenChanged' timestamp and, if unchanged since the previous run's cache, reuse
    the cached membership instead of re-pulling all members. Flat groups are gated;
    nested groups are always fully enumerated (a parent's whenChanged does not move
    when a child group changes). Falls back to a full run on the first run / cache
    miss. Detects MEMBERSHIP changes only -- per-member attribute freshness
    (-IncludeAttributes) is point-in-time for skipped groups, and -DetectStale
    auto-disables skipping. Can also be defaulted per-environment via config
    Enumeration.Incremental. Ignored with -FromCache; falls back to full with -NoCache.

.EXAMPLE
    .\Invoke-GroupEnumerator.ps1 -CsvPath .\groups.csv
    Simplest single-domain inventory. Produces V1 HTML + JSON cache.

.EXAMPLE
    .\Invoke-GroupEnumerator.ps1 -CsvPath .\groups.csv -ResolveNested -DetectStale
    Single-domain inventory with nested group flattening and stale account flagging.

.EXAMPLE
    .\Invoke-GroupEnumerator.ps1 -CsvPath .\groups.csv -FuzzyMatch
    Cross-domain fuzzy match. Verified LDAPS only (Tier 1).

.EXAMPLE
    .\Invoke-GroupEnumerator.ps1 -CsvPath .\groups.csv -FuzzyMatch -AnalyzeGaps -DetectStale -ResolveNested -AllowInsecure
    Full two-forest migration readiness pipeline with all fallback tiers enabled.

.EXAMPLE
    .\Invoke-GroupEnumerator.ps1 -CsvPath .\groups.csv -FromCache -CachePath .\Cache\groups-20260415-103821.json
    Offline re-render of an HTML report from a saved JSON cache. No AD access.

.EXAMPLE
    $cred = Get-Credential
    .\Invoke-GroupEnumerator.ps1 -CsvPath .\groups.csv -FuzzyMatch -Credential $cred
    Pass explicit credentials (Kerberos integrated auth otherwise).

.NOTES
    Author: EntraID Team
    Requires: PowerShell 5.1 or PowerShell 7+

    Connection tiers (tried in order, highest security first):
      Tier 1: LDAPS 636, cert verification strict       (always attempted)
      Tier 2: LDAPS 636, cert verification bypassed     (requires -AllowInsecure)
      Tier 3: LDAP  389, SASL sign + seal (Kerberos)    (requires -AllowInsecure)
      Tier 4: LDAP  389, no signing/sealing             (not reachable via switches)

    Run with no arguments or -Help for a usage summary with examples.
    Run 'Get-Help .\Invoke-GroupEnumerator.ps1 -Detailed' for full parameter docs.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$CsvPath,

    [Parameter(Mandatory = $false)]
    [switch]$Help,

    [Parameter(Mandatory = $false)]
    [PSCredential]$Credential,

    [Parameter(Mandatory = $false)]
    [switch]$FuzzyMatch,

    [Parameter(Mandatory = $false)]
    [string]$ConfigPath,

    [Parameter(Mandatory = $false)]
    [string]$OutputPath,

    [Parameter(Mandatory = $false)]
    [switch]$FromCache,

    [Parameter(Mandatory = $false)]
    [string]$CachePath,

    [Parameter(Mandatory = $false)]
    [ValidateSet('dark', 'light')]
    [string]$Theme = 'dark',

    [Parameter(Mandatory = $false)]
    [switch]$JsonOnly,

    [Parameter(Mandatory = $false)]
    [switch]$NoCache,

    [Parameter(Mandatory = $false)]
    [switch]$AllowInsecure,

    [Parameter(Mandatory = $false)]
    [switch]$ResolveNested,

    [Parameter(Mandatory = $false)]
    [switch]$AnalyzeGaps,

    [Parameter(Mandatory = $false)]
    [switch]$DetectStale,

    [Parameter(Mandatory = $false)]
    [string]$AppMappingCsv,

    [Parameter(Mandatory = $false)]
    [switch]$SendEmail,

    [Parameter(Mandatory = $false)]
    [int]$StaleDays = 0,

    [Parameter(Mandatory = $false)]
    [string]$MigratingTo,

    [Parameter(Mandatory = $false)]
    [string]$TargetSearchBase,

    [Parameter(Mandatory = $false)]
    [string[]]$IncludeAttributes = @(),

    [Parameter(Mandatory = $false)]
    [string]$BaselinePath,

    [Parameter(Mandatory = $false)]
    [string]$PreviousRunPath,

    [Parameter(Mandatory = $false)]
    [switch]$TrackChanges,

    [Parameter(Mandatory = $false)]
    [ValidateSet('Added', 'Removed', 'Both')]
    [string]$ChangeType = 'Both',

    [Parameter(Mandatory = $false)]
    [string]$StatePath,

    [Parameter(Mandatory = $false)]
    [switch]$ExportMembersCsv,

    [Parameter(Mandatory = $false)]
    [switch]$Incremental,

    [Parameter(Mandatory = $false)]
    [switch]$PassThru,

    [Parameter(Mandatory = $false)]
    [ValidateSet('sqlite', 'json')]
    [string]$StateBackend,

    [Parameter(Mandatory = $false)]
    [switch]$Legacy,

    [Parameter(Mandatory = $false)]
    [switch]$GovernanceReport,

    [Parameter(Mandatory = $false)]
    [switch]$ComplianceReport,

    [Parameter(Mandatory = $false)]
    [switch]$ExecutiveDashboard,

    [Parameter(Mandatory = $false)]
    [switch]$LeadershipSummary,

    [Parameter(Mandatory = $false)]
    [switch]$AllReports,

    [Parameter(Mandatory = $false)]
    [switch]$BaselineReports,

    [Parameter(Mandatory = $false)]
    [ValidateSet('roster', 'access-cert', 'privileged', 'sod', 'orphaned', 'inventory', 'empty-stale', 'nested-audit', 'exec-summary', 'change-attestation')]
    [string[]]$BaselineReport,

    [Parameter(Mandatory = $false)]
    [ValidateSet('Day', 'Week', 'Month', 'Quarter')]
    [string]$ChangePeriod,

    # Custom change-history window (alternatives to the -ChangePeriod presets).
    # Precedence: -ChangeSince > -ChangeDays > -ChangePeriod.
    [Parameter(Mandatory = $false)]
    [ValidateRange(0, 36500)]
    [int]$ChangeDays = 0,

    [Parameter(Mandatory = $false)]
    [Nullable[datetime]]$ChangeSince = $null,

    # ---- Composable reporting (additive) ----
    # Pick report COMPONENTS and assemble them into one report. Order is
    # preserved top-to-bottom; append :half to a key to make it half-width
    # (two consecutive half-width components sit side-by-side). e.g.
    #   -ReportComponents kpi-cards,heatmap,top-n:half,group-table:half
    # Valid keys come from the component registry (kpi-cards, heatmap, tree,
    # diff, top-n, group-table). NOTE: like -BaselineReport, pass a real array
    # (or invoke via -Command) so commas are parsed as list items.
    [Parameter(Mandatory = $false)]
    [string[]]$ReportComponents,

    [Parameter(Mandatory = $false)]
    [string]$ComponentReportTitle = 'Composable Group Report',

    [Parameter(Mandatory = $false)]
    [ValidateSet('light', 'dark')]
    [string]$ComponentReportTheme = 'light'
)

$ErrorActionPreference = 'Stop'
$scriptRoot = $PSScriptRoot

# Tool version constant -- flows to all report generators via $config.ToolVersion
$script:ToolVersion = '3.0.0'

# Tier-downgrade messages (e.g. "WARNING: Using tier 'LDAPS-Unverified' ...")
# are carried in the Errors array of every group result for legacy compatibility,
# but they describe a successful enumeration via a fallback tier, not a failure.
# These helpers let the orchestrator separate the two so the summary doesn't
# misreport a successful run as having errors.
function Get-FatalErrors {
    param($Errors)
    if (-not $Errors) { return @() }
    return @($Errors | Where-Object { $_ -notlike 'WARNING: Using tier*' })
}
function Get-TierWarnings {
    param($Errors)
    if (-not $Errors) { return @() }
    return @($Errors | Where-Object { $_ -like 'WARNING: Using tier*' })
}

# Get-MigrationGapAnalysis emits a nested schema:
#   @{ GroupPair=@{...}; Readiness=@{ Percent; ...Count }; Items=@( @{ SourceUser; TargetUser; ... } ); Errors }
# Get-OverallMigrationReadiness emits:
#   @{ OverallPercent; TotalCRItems; ReadyGroups; ... }
# Export-MigrationReport historically reads a flat shape that the test suite
# constructs manually before calling: SourceGroup, TargetGroup, ReadinessPercent,
# CrCount, Items[].SourceSam/TargetSam, OverallReadiness.ReadinessPercent, etc.
# Until the report module is rewritten to read the producer schema, the
# orchestrator flattens here to keep the live report's data matching the tests.
function ConvertTo-FlatGapResult {
    param($Gap)
    if (-not $Gap) { return $null }
    $rd = $Gap.Readiness
    $crCount = 0
    if ($rd) {
        $crCount = [int]$(if ($rd.AddToGroupCount)     { $rd.AddToGroupCount }     else { 0 }) +
                   [int]$(if ($rd.NotProvisionedCount) { $rd.NotProvisionedCount } else { 0 }) +
                   [int]$(if ($rd.OrphanedCount)       { $rd.OrphanedCount }       else { 0 })
    }
    $flatItems = @()
    if ($Gap.Items) {
        foreach ($it in $Gap.Items) {
            $flat = @{}
            foreach ($k in $it.Keys) { $flat[$k] = $it[$k] }
            if (-not $flat.ContainsKey('SourceSam') -and $it.SourceUser -and $it.SourceUser.SamAccountName) {
                $flat.SourceSam = $it.SourceUser.SamAccountName
            }
            if (-not $flat.ContainsKey('TargetSam') -and $it.TargetUser -and $it.TargetUser.SamAccountName) {
                $flat.TargetSam = $it.TargetUser.SamAccountName
            }
            $flatItems += $flat
        }
    }
    return @{
        SourceGroup      = if ($Gap.GroupPair) { $Gap.GroupPair.SourceGroup } else { '' }
        TargetGroup      = if ($Gap.GroupPair) { $Gap.GroupPair.TargetGroup } else { '' }
        SourceDomain     = if ($Gap.GroupPair) { $Gap.GroupPair.SourceDomain } else { '' }
        TargetDomain     = if ($Gap.GroupPair) { $Gap.GroupPair.TargetDomain } else { '' }
        ReadinessPercent = if ($rd) { $rd.Percent } else { 0 }
        SourceCount      = if ($rd) { $rd.TotalSourceMembers } else { 0 }
        TargetCount      = if ($rd) { $rd.TotalTargetMembers } else { 0 }
        CrCount          = $crCount
        Items            = $flatItems
        Readiness        = $rd
        GroupPair        = $Gap.GroupPair
        Errors           = $Gap.Errors
    }
}

function ConvertTo-FlatOverallReadiness {
    param($Overall)
    if (-not $Overall) { return $null }
    # Note: hashtable keys are case-insensitive, so TotalCrItems also
    # satisfies readers that ask for TotalCRItems, and OverallPercent the
    # same for ReadinessPercent. Only one casing of each may appear here.
    return @{
        ReadinessPercent = $Overall.OverallPercent
        ReadyGroups      = $Overall.ReadyGroups
        InProgressGroups = $Overall.InProgressGroups
        BlockedGroups    = $Overall.BlockedGroups
        TotalCrItems     = $Overall.TotalCRItems
        GroupCount       = $Overall.GroupCount
        CRByType         = $Overall.CRByType
        CRByPriority     = $Overall.CRByPriority
    }
}

# ---------------------------------------------------------------------------
# Usage / help output when invoked with no args or -Help
# ---------------------------------------------------------------------------
function Show-Usage {
    $self = Split-Path -Leaf $PSCommandPath
    $lines = @(
        ''
        'Cross-Domain Group Enumerator'
        '============================='
        'Enumerates Active Directory group membership via LdapConnection.'
        'Works for single-domain inventory and cross-forest migration readiness.'
        ''
        'USAGE'
        "  .\$self -CsvPath <file> [options]"
        "  .\$self -Help"
        ''
        'REQUIRED'
        '  -CsvPath <path>          CSV of groups to enumerate'
        '                             Format 1: headers Domain,GroupName  (e.g. CORP,Domain Admins)'
        '                             Format 2: header  Group             (e.g. CORP\Domain Admins)'
        '                             Samples:  Templates\groups-example-standard.csv'
        '                                       Templates\groups-example-backslash.csv'
        ''
        'CONNECTIVITY'
        '  -Credential <pscred>     Pass explicit creds (default = current user via Kerberos)'
        '  -AllowInsecure           Enable fallback tiers when Tier 1 (verified LDAPS) fails:'
        '                             Tier 2: LDAPS 636 with cert bypass'
        '                             Tier 3: LDAP  389 with Kerberos sign+seal'
        ''
        'ANALYSIS SWITCHES'
        '  -ResolveNested           Flatten nested group memberships (recursive)'
        '  -DetectStale             Flag disabled and inactive accounts'
        '  -FuzzyMatch              Cross-domain fuzzy group name matching (Levenshtein)'
        '  -AnalyzeGaps             Migration gap analysis + Change Requests (needs -FuzzyMatch)'
        '  -AppMappingCsv <path>    Optional app-to-group readiness mapping'
        '  -StaleDays <n>           Override stale threshold (default: config value, 90)'
        ''
        'OUTPUT / CACHE'
        '  -OutputPath <dir>        Output directory for reports (default: ./Output)'
        '  -CachePath <path>        Cache file (for -FromCache) or directory (for writes)'
        '  -FromCache               Skip LDAP; regenerate reports from a saved cache'
        '  -JsonOnly                Write JSON cache only, skip HTML report'
        '  -NoCache                 Skip writing the JSON cache'
        '  -Theme dark|light        Initial HTML theme (default: dark)'
        '  -ConfigPath <path>       Override config file location'
        '  -SendEmail               Send the migration report via SMTP (config must enable this)'
        ''
        'CHANGE TRACKING'
        '  -TrackChanges            Enable persistent daily change tracking (state.json + changelog)'
        '  -ChangeType Added|Removed|Both  Filter the change-feed CSV (default: Both)'
        '  -ChangePeriod Day|Week|Month|Quarter  Time window for report change history'
        '  -ChangeDays <n>          Custom change-history window, n days back (overrides -ChangePeriod)'
        '  -ChangeSince <date>      Explicit change-history start date (overrides -ChangeDays)'
        '                             Without this, reports show only the current run changes'
        '  -StatePath <dir>         Override state directory (default: config or ./State)'
        ''
        'REPORT TYPES'
        '  -GovernanceReport        Generate SailPoint-style Access Governance Report (audit tier)'
        '  -ComplianceReport        Generate Compliance Audit Report (audit tier)'
        '  -ExecutiveDashboard      Generate Executive Dashboard with SVG charts'
        '  -LeadershipSummary       Generate 1-page Leadership Summary'
        '  -AllReports              Generate all v3 report types'
        ''
        'EXAMPLES'
        ''
        '  # Simplest single-domain inventory (V1 report)'
        "  .\$self -CsvPath .\groups.csv"
        ''
        '  # Single-domain with nested resolution + stale detection'
        "  .\$self -CsvPath .\groups.csv -ResolveNested -DetectStale"
        ''
        '  # Cross-domain fuzzy match, verified LDAPS only'
        "  .\$self -CsvPath .\groups.csv -FuzzyMatch"
        ''
        '  # Full two-forest migration readiness pipeline with fallback tiers'
        "  .\$self -CsvPath .\groups.csv -FuzzyMatch -AnalyzeGaps -DetectStale -ResolveNested -AllowInsecure"
        ''
        '  # Offline re-render from a saved cache (no AD access)'
        "  .\$self -CsvPath .\groups.csv -FromCache -CachePath .\Cache\groups-20260415-103821.json"
        ''
        '  # With explicit credentials'
        '  $cred = Get-Credential'
        "  .\$self -CsvPath .\groups.csv -FuzzyMatch -Credential `$cred"
        ''
        'MORE'
        "  Full parameter docs:  Get-Help .\$self -Detailed"
        '  Quick start:          docs/QUICKSTART.md'
        '  Developer notes:      docs/DEV-GUIDE.md'
        ''
    )
    $lines | ForEach-Object { Write-Host $_ }
}

# -CsvPath is required for a live run, but NOT for -FromCache (the cache IS the data; the
# output name is derived from the cache filename). This lets "report from a saved run" work
# without a CSV (e.g. the GUI's "Use saved data" / "Generate Reports from Saved Data").
$missingCsv = (-not $CsvPath) -and -not ($FromCache -and $CachePath)
if ($Help -or $missingCsv) {
    Show-Usage
    if (-not $Help -and $missingCsv) {
        Write-Host 'ERROR: -CsvPath is required (or use -FromCache with -CachePath to report from a saved cache).' -ForegroundColor Red
        exit 2
    }
    exit 0
}

# ---------------------------------------------------------------------------
# Resolve config path default
# ---------------------------------------------------------------------------
if (-not $ConfigPath) {
    $ConfigPath = Join-Path $scriptRoot 'Config\group-enum-config.json'
}

# ---------------------------------------------------------------------------
# Dot-source required modules
# ---------------------------------------------------------------------------
Write-Host 'Loading modules...' -ForegroundColor Cyan

$moduleFiles = @(
    'ADLdap.ps1',
    'GroupEnumLogger.ps1',
    'GroupEnumerator.ps1',
    'FuzzyMatcher.ps1',
    'GroupReportGenerator.ps1',
    'NestedGroupResolver.ps1',
    'UserCorrelation.ps1',
    'GapAnalysis.ps1',
    'StaleAccountDetector.ps1',
    'AppMapping.ps1',
    'MigrationReportGenerator.ps1',
    'EmailSummary.ps1',
    'DomainUserLookup.ps1',
    'MembershipDrift.ps1',
    'PathResolution.ps1',
    'StateDatabase.ps1',
    'MembershipState.ps1',
    'IncrementalGate.ps1',
    'GovernanceReportGenerator.ps1',
    'ComplianceReportGenerator.ps1'
)

foreach ($moduleFile in $moduleFiles) {
    $modulePath = Join-Path $scriptRoot "Modules\$moduleFile"
    if (Test-Path $modulePath) {
        . $modulePath
        Write-Host "  Loaded: $moduleFile" -ForegroundColor Gray
    } else {
        Write-Error "Required module not found: $modulePath"
        exit 1
    }
}

# Baseline governance report generators (additive; one self-contained module each).
$baselineModuleDir = Join-Path $scriptRoot 'Modules\BaselineReports'
if (Test-Path $baselineModuleDir) {
    foreach ($bm in (Get-ChildItem -Path $baselineModuleDir -Filter '*.ps1' -File -ErrorAction SilentlyContinue | Sort-Object Name)) {
        . $bm.FullName
        Write-Host "  Loaded: BaselineReports\$($bm.Name)" -ForegroundColor DarkGray
    }
}

# Composable report component library (additive; RC00 framework loads first by
# alphabetical order, then each self-registering component module).
$componentModuleDir = Join-Path $scriptRoot 'Modules\ReportComponents'
if (Test-Path $componentModuleDir) {
    foreach ($cm in (Get-ChildItem -Path $componentModuleDir -Filter '*.ps1' -File -ErrorAction SilentlyContinue | Sort-Object Name)) {
        . $cm.FullName
        Write-Host "  Loaded: ReportComponents\$($cm.Name)" -ForegroundColor DarkGray
    }
}

Write-Host ''

# ---------------------------------------------------------------------------
# Main execution
# ---------------------------------------------------------------------------
$connectionPool = $null
try {
    # ---- Load configuration ----
    Write-Host 'Loading configuration...' -ForegroundColor Cyan
    $config = New-GroupEnumConfig -ConfigPath $ConfigPath

    # Ensure ToolVersion is always set so report generators pick it up
    if (-not $config.ToolVersion) {
        $config['ToolVersion'] = $script:ToolVersion
    }

    # -AllowInsecure switch overrides config (switch takes precedence)
    if ($AllowInsecure) {
        $config.AllowInsecure = $true
    }

    Write-Host "  Config source: $(if (Test-Path $ConfigPath) { $ConfigPath } else { 'built-in defaults' })" -ForegroundColor Gray
    if ($config.AllowInsecure) {
        Write-Host '  ** AllowInsecure: LDAP 389 fallback enabled (tries LDAPS 636 first) **' -ForegroundColor Yellow
    }
    Write-Host ''

    # ---- Resolve stale threshold (v2 -- before logging so it appears in context) ----
    $staleDays = if ($StaleDays -gt 0) {
        $StaleDays
    } elseif ($config.StaleAccountDays) {
        $config.StaleAccountDays
    } else {
        90
    }

    # ---- State backend resolution (param > config > default) ----
    $effectiveBackend = if ($StateBackend) { $StateBackend }
        elseif ($config.StateBackend) { [string]$config.StateBackend }
        else { 'json' }

    # Python availability check for SQLite
    if ($effectiveBackend -eq 'sqlite') {
        if (-not (Test-PythonAvailable)) {
            Write-Host 'WARNING: SQLite backend requested but Python3 not available. Falling back to JSON.' -ForegroundColor Yellow
            $effectiveBackend = 'json'
        }
    }

    # SQLite database path resolution (see Modules/PathResolution.ps1 for the precedence rules
    # + rationale). Extracted to a pure helper so the logic is unit-testable.
    $dbPath = Resolve-GeSqliteDbPath `
        -ConfigSqliteDbPath $config.SqliteDbPath `
        -StatePathParam     $StatePath `
        -StatePathExplicit  ($PSBoundParameters.ContainsKey('StatePath') -and [bool]$StatePath) `
        -ConfigCtStatePath  $(if ($config.ChangeTracking) { $config.ChangeTracking.StatePath } else { $null }) `
        -ScriptRoot         $scriptRoot

    # Ensure the DB's parent directory exists (a custom -StatePath may not exist yet).
    $dbParent = [System.IO.Path]::GetDirectoryName($dbPath)
    if ($dbParent -and -not (Test-Path -LiteralPath $dbParent)) {
        New-Item -ItemType Directory -Path $dbParent -Force | Out-Null
    }

    # ---- Resolve the change-history window (presets / custom days / explicit since-date) ----
    $changeWindow       = Resolve-ChangeWindow -ChangePeriod $ChangePeriod -ChangeDays $ChangeDays -ChangeSince $ChangeSince
    $changeWindowActive = [bool]$changeWindow.Active
    $changeWindowLabel  = $changeWindow.Label
    $changeWindowSince  = $changeWindow.SinceDate

    # Unified state mode (v2) vs legacy per-CSV mode
    $unifiedState = if ($Legacy) { $false }
        elseif ($config.ChangeTracking -and $null -ne $config.ChangeTracking.UnifiedState) { [bool]$config.ChangeTracking.UnifiedState }
        else { $true }

    # Report switches resolution (param OR config)
    $doGovernanceReport = $GovernanceReport -or $AllReports -or ($config.Reporting -and $config.Reporting.GovernanceReport)
    $doComplianceReport = $ComplianceReport -or $AllReports -or ($config.Reporting -and $config.Reporting.ComplianceReport)
    $doExecutiveDashboard = $ExecutiveDashboard -or $AllReports -or ($config.Reporting -and $config.Reporting.ExecutiveDashboard)
    $doLeadershipSummary = $LeadershipSummary -or $AllReports -or ($config.Reporting -and $config.Reporting.LeadershipSummary)

    # ---- Initialize logging ----
    $logState = Initialize-GroupEnumLog -Config $config -ScriptRoot $scriptRoot
    if ($logState.Enabled) {
        Write-Host "  Log file: $($logState.LogFilePath)" -ForegroundColor Gray
        Write-Host "  Log level: $($logState.LogLevel)" -ForegroundColor Gray
    } else {
        Write-Host '  Logging: disabled' -ForegroundColor Gray
    }
    Write-Host ''

    Write-GroupEnumLog -Level 'INFO' -Operation 'Config' `
        -Message "Configuration loaded" -Context @{
            configPath      = $ConfigPath
            allowInsecure   = $config.AllowInsecure
            fuzzyMatch      = [bool]$FuzzyMatch
            theme           = $Theme
            resolveNested   = [bool]$ResolveNested
            analyzeGaps     = [bool]$AnalyzeGaps
            detectStale     = [bool]$DetectStale
            staleDays       = $staleDays
            appMappingCsv   = $(if ($AppMappingCsv) { $AppMappingCsv } else { '' })
            sendEmail       = [bool]$SendEmail
        }

    # ---- Resolve output directory ----
    $resolvedOutputDir = if ($OutputPath) {
        $OutputPath
    } elseif ($config.OutputDirectory) {
        if ([System.IO.Path]::IsPathRooted($config.OutputDirectory)) {
            $config.OutputDirectory
        } else {
            Join-Path $scriptRoot $config.OutputDirectory
        }
    } else {
        Join-Path $scriptRoot 'Output'
    }

    if (-not (Test-Path $resolvedOutputDir)) {
        New-Item -ItemType Directory -Path $resolvedOutputDir -Force | Out-Null
        Write-Host "  Created output directory: $resolvedOutputDir" -ForegroundColor Gray
    }

    # ---- Timestamps + output file names ----
    $timestamp    = Get-Date -Format 'yyyyMMdd-HHmmss'
    $csvLeaf      = if ($CsvPath) {
        [System.IO.Path]::GetFileNameWithoutExtension($CsvPath)
    } elseif ($CachePath) {
        # From-Cache without a CSV: derive a clean leaf from the cache filename
        # (<leaf>-yyyyMMdd-HHmmss.json -> <leaf>).
        [System.IO.Path]::GetFileNameWithoutExtension($CachePath) -replace '-\d{8}-\d{6}$', ''
    } else { 'report' }
    $jsonFileName = "${csvLeaf}-${timestamp}.json"
    $htmlFileName = "${csvLeaf}-${timestamp}.html"

    # ---- Resolve cache directory / path (pure helper; see Modules/PathResolution.ps1) ----
    # -CachePath is a cache FILE for -FromCache (read) but a DIRECTORY for writes; a directory
    # value becomes the cache dir so both the write target and the incremental previous-cache
    # lookup resolve against it.
    $cachePaths        = Resolve-GeCachePaths -CachePathParam $CachePath -FromCache:([bool]$FromCache) -ConfigCachePath $config.CachePath -ScriptRoot $scriptRoot -JsonFileName $jsonFileName
    $cacheDir          = $cachePaths.CacheDir
    $cachePathIsDir    = $cachePaths.IsDir
    $resolvedCachePath = $cachePaths.ResolvedCachePath

    if (-not (Test-Path $cacheDir)) {
        New-Item -ItemType Directory -Path $cacheDir -Force | Out-Null
    }

    $resolvedHtmlPath = Join-Path $resolvedOutputDir $htmlFileName

    # ---- Auto-migrate JSON state to SQLite (first SQLite run only) ----
    if ($effectiveBackend -eq 'sqlite' -and -not (Test-Path $dbPath)) {
        $migrateStateDir = if ($StatePath) {
            if ([System.IO.Path]::IsPathRooted($StatePath)) { $StatePath } else { Join-Path $scriptRoot $StatePath }
        } elseif ($config.ChangeTracking -and $config.ChangeTracking.StatePath) {
            if ([System.IO.Path]::IsPathRooted($config.ChangeTracking.StatePath)) { $config.ChangeTracking.StatePath } else { Join-Path $scriptRoot $config.ChangeTracking.StatePath }
        } else {
            Join-Path $scriptRoot 'State'
        }
        if (Test-Path $migrateStateDir) {
            $existingStateFiles = Get-ChildItem -Path $migrateStateDir -Filter '*-membership-state.json' -File -ErrorAction SilentlyContinue
            if ($existingStateFiles.Count -gt 0) {
                Write-Host "Migrating $($existingStateFiles.Count) JSON state file(s) to SQLite..." -ForegroundColor Cyan
                Invoke-JsonToSqliteMigration -DbPath $dbPath -StateDir $migrateStateDir
            }
        }
    }

    # =========================================================================
    # BRANCH A: Load from JSON cache (skip LDAP)
    # =========================================================================
    if ($FromCache) {
        Write-Host 'Loading data from cache...' -ForegroundColor Cyan

        if (-not $CachePath) {
            Write-Error '-CachePath is required when using -FromCache'
            exit 1
        }

        if (-not (Test-Path $CachePath)) {
            Write-Error "Cache file not found: $CachePath"
            exit 1
        }

        $cacheData   = Import-GroupDataJson -JsonPath $CachePath
        $groupResults = $cacheData.Groups
        $matchResults = $cacheData.MatchResults

        $totalGroups = $groupResults.Count
        $domains     = @($groupResults | ForEach-Object { $_.Data.Domain } | Sort-Object -Unique)

        Write-Host "  Loaded $totalGroups groups from cache ($($domains -join ', '))" -ForegroundColor Gray
        Write-Host ''

        # Optionally re-run fuzzy matching on cached data
        if ($FuzzyMatch -and -not $matchResults) {
            Write-Host 'Running fuzzy match on cached data...' -ForegroundColor Cyan
            $prefixes  = if ($config.FuzzyPrefixes) { @($config.FuzzyPrefixes) } else { @() }
            $minScore  = if ($null -ne $config.FuzzyMinScore)  { [double]$config.FuzzyMinScore }  else { 0.7 }
            $matchResults = Find-MatchingGroups -GroupResults $groupResults `
                -Prefixes $prefixes -MinScore $minScore
            Write-Host "  Matched: $($matchResults.Matched.Count) pairs, Unmatched: $($matchResults.Unmatched.Count)" -ForegroundColor Gray
            Write-Host ''
        }

    # =========================================================================
    # BRANCH B: Live LDAP enumeration
    # =========================================================================
    } else {
        # ---- Validate CSV ----
        if (-not (Test-Path $CsvPath)) {
            Write-Error "CSV file not found: $CsvPath"
            exit 1
        }

        # ---- Import group list ----
        Write-Host "Importing group list from: $CsvPath" -ForegroundColor Cyan
        $groupList = Import-GroupList -CsvPath $CsvPath

        if (-not $groupList -or $groupList.Count -eq 0) {
            Write-Warning @"
No groups found in CSV '$CsvPath'. Nothing to enumerate.

Check that the file:
  - has a header row (Domain,GroupName  OR  Group)
  - has at least one non-blank data row
  - uses DOMAIN\GroupName values if using the single-column 'Group' format

Sample files: Templates\groups-example-standard.csv
              Templates\groups-example-backslash.csv
"@
            exit 0
        }

        $domains      = @($groupList | ForEach-Object { $_.Domain } | Sort-Object -Unique)
        $domainCount  = ($domains | Where-Object { $_ -ne '' }).Count

        Write-Host "  Found $($groupList.Count) groups across $domainCount domain(s): $($domains -join ', ')" -ForegroundColor Gray
        Write-Host ''

        Write-GroupEnumLog -Level 'INFO' -Operation 'CsvImport' `
            -Message "Imported $($groupList.Count) groups from CSV" -Context @{
                csvPath    = $CsvPath
                groupCount = $groupList.Count
                domains    = ($domains -join ', ')
            }

        # ---- Pre-flight: DNS + TCP reachability per unique domain ----
        # If a domain can't be reached at all (off-network, VPN down, wrong
        # DNS suffix, firewall blocking LDAP ports), every group on it would
        # otherwise hit the same multi-second LDAP bind timeout. Catch it
        # once here, log it once, and short-circuit each group with a clean
        # error.
        #
        # Probes: DNS first, then TCP 636 (tier 1/2). If -AllowInsecure also
        # probes 389 (tier 3). A domain is considered unreachable when none of
        # the available tiers' ports are open.
        function Test-DomainTcpPort {
            param([string]$Host_, [int]$Port, [int]$TimeoutMs = 2500)
            # Resolve every A/AAAA record and probe each: the service is "up" if
            # ANY address accepts the port. Multi-homed DCs (and stale DNS) often
            # publish several addresses where only one is reachable; connecting
            # by hostname tests just one address and would false-negative when
            # that one is unreachable -- blocking enumeration even though the
            # LDAP layer (which tries all addresses) would succeed.
            $addresses = @()
            try { $addresses = @([System.Net.Dns]::GetHostAddresses($Host_)) } catch { return $false }
            if ($addresses.Count -eq 0) { return $false }
            foreach ($addr in $addresses) {
                $client = $null
                try {
                    $client = [System.Net.Sockets.TcpClient]::new()
                    $iar = $client.BeginConnect($addr, $Port, $null, $null)
                    if ($iar.AsyncWaitHandle.WaitOne($TimeoutMs)) {
                        $client.EndConnect($iar)
                        if ($client.Connected) { return $true }
                    }
                } catch {
                    # unreachable on this address -- try the next
                } finally {
                    if ($client) { $client.Close() }
                }
            }
            return $false
        }

        $unreachableDomains = @{}
        $domainsToProbe = @($domains | Where-Object { $_ -and $_.Trim() -ne '' })
        $allowInsecure  = [bool]$config.AllowInsecure

        if ($domainsToProbe.Count -gt 0) {
            Write-Host 'Pre-flight: probing domains...' -ForegroundColor Cyan
            foreach ($d in $domainsToProbe) {
                $dnsOk    = $false
                $tcp636   = $false
                $tcp389   = $false
                $dnsErr   = $null

                try {
                    $null = [System.Net.Dns]::GetHostAddresses($d)
                    $dnsOk = $true
                } catch {
                    $dnsErr = $_.Exception.Message
                }

                if ($dnsOk) {
                    $tcp636 = Test-DomainTcpPort -Host_ $d -Port 636
                    if ($allowInsecure -and -not $tcp636) {
                        $tcp389 = Test-DomainTcpPort -Host_ $d -Port 389
                    }
                }

                $reachable = $dnsOk -and ($tcp636 -or ($allowInsecure -and $tcp389))

                if ($reachable) {
                    $tierNote = if ($tcp636) { '636 open' } else { '389 open (insecure)' }
                    Write-Host "  $d ... reachable ($tierNote)" -ForegroundColor DarkGray
                    Write-GroupEnumLog -Level 'DEBUG' -Operation 'PreflightProbe' `
                        -Message "Domain '$d' reachable" -Context @{
                            domain = $d; dns = $dnsOk; tcp636 = $tcp636; tcp389 = $tcp389
                        }
                } else {
                    if (-not $dnsOk) {
                        $reason = "DNS lookup failed ($dnsErr)"
                    } elseif (-not $allowInsecure) {
                        $reason = 'TCP 636 closed (pass -AllowInsecure to also try 389)'
                    } else {
                        $reason = 'TCP 636 and TCP 389 both closed'
                    }
                    $unreachableDomains[$d] = $reason
                    Write-Host "  $d ... UNREACHABLE ($reason)" -ForegroundColor Red
                    Write-GroupEnumLog -Level 'ERROR' -Operation 'PreflightProbe' `
                        -Message "Domain '$d' unreachable: $reason" -Context @{
                            domain = $d; dns = $dnsOk; tcp636 = $tcp636; tcp389 = $tcp389; reason = $reason
                        }
                }
            }
            if ($unreachableDomains.Count -gt 0) {
                Write-Host ''
                Write-Host "WARNING: $($unreachableDomains.Count) domain(s) unreachable." -ForegroundColor Yellow
                Write-Host '  Common causes: VPN not connected, off-domain workstation, DNS suffix missing,' -ForegroundColor Yellow
                Write-Host '                 firewall blocking LDAP ports, wrong domain spelling in the CSV.' -ForegroundColor Yellow
                if (-not $allowInsecure) {
                    Write-Host '  If your DC only listens on 389, re-run with -AllowInsecure.' -ForegroundColor Yellow
                }
                Write-Host '  Groups on unreachable domains will be marked as errors without LDAP retries.' -ForegroundColor Yellow
            }
            Write-Host ''
        }

        # ---- Enumerate each group ----
        Write-Host 'Enumerating group members...' -ForegroundColor Cyan

        $groupResults   = @()
        $totalErrors    = 0
        $skippedCount   = 0
        $totalProcessed = 0
        $totalInList    = $groupList.Count

        # Shared connection pool: one LdapConnection per domain, reused across
        # all groups in that domain. Also enables cross-forest member routing
        # and ForeignSecurityPrincipal SID resolution between pooled domains.
        $poolParams = @{
            AllowInsecure  = [bool]$config.AllowInsecure
            TimeoutSeconds = [int]$config.LdapTimeout
        }
        if ($Credential) { $poolParams.Credential = $Credential }
        $connectionPool = New-AdLdapConnectionPool @poolParams

        # ---- SQLite run lifecycle: start run ----
        $runId = $null
        if ($effectiveBackend -eq 'sqlite') {
            $runId = Start-EnumerationRun -DbPath $dbPath -CsvName $csvLeaf
        }

        # ---- Incremental enumeration setup (opt-in via -Incremental or config) ----
        # Resolve effective mode with guards, then load the previous run's cache for
        # this CSV leaf as the comparison baseline. Skipping reuses cached membership
        # for groups whose 'whenChanged' has not advanced.
        $configIncremental = $false
        if ($config.Enumeration -and ($null -ne $config.Enumeration.Incremental)) {
            $configIncremental = [bool]$config.Enumeration.Incremental
        }
        $incrementalEffective = ($Incremental -or $configIncremental)
        $priorCacheLookup = @{}
        $reusedCount = 0

        if ($incrementalEffective) {
            if ($FromCache) {
                $incrementalEffective = $false   # Branch A handles -FromCache; no-op here
            } elseif ($NoCache) {
                Write-Host 'Incremental requested but -NoCache is set: no cache basis -- running a full enumeration.' -ForegroundColor Yellow
                $incrementalEffective = $false
            } elseif ($DetectStale) {
                Write-Host 'Incremental auto-disabled because -DetectStale is set (staleness needs fresh per-user data).' -ForegroundColor Yellow
                $incrementalEffective = $false
            }
        }

        if ($incrementalEffective) {
            if ($IncludeAttributes.Count -gt 0) {
                Write-Host 'Note: with -Incremental, attribute columns for unchanged (reused) groups are as of the last full pull; membership stays current.' -ForegroundColor DarkYellow
            }

            if ($effectiveBackend -eq 'sqlite') {
                # SQLite: get cache from database
                $sqliteCache = Get-CacheFromSqlite -DbPath $dbPath -CsvName $csvLeaf
                if ($sqliteCache -and $sqliteCache.Count -gt 0) {
                    $priorCacheLookup = $sqliteCache
                    Write-Host "Incremental: comparing against SQLite cache ($($priorCacheLookup.Count) cached group(s))." -ForegroundColor Cyan
                } else {
                    Write-Host 'Incremental: no prior cache in SQLite -- full enumeration this run (baseline).' -ForegroundColor Gray
                }
            } else {
                # JSON: existing file-based cache lookup
                $priorCacheFile = $null
                try {
                    $priorCacheFile = (Get-ChildItem -Path $cacheDir -Filter "${csvLeaf}-*.json" -File -ErrorAction SilentlyContinue |
                        Sort-Object LastWriteTime -Descending | Select-Object -First 1).FullName
                } catch { $priorCacheFile = $null }

                if ($priorCacheFile) {
                    try {
                        $priorData = Import-GroupDataJson -JsonPath $priorCacheFile
                        foreach ($pg in $priorData.Groups) {
                            if ($pg.Data -and $pg.Data.Domain -and $pg.Data.GroupName) {
                                $priorCacheLookup["$($pg.Data.Domain)|$($pg.Data.GroupName)"] = $pg
                            }
                        }
                        Write-Host "Incremental: comparing against $priorCacheFile ($($priorCacheLookup.Count) cached group(s))." -ForegroundColor Cyan
                    } catch {
                        Write-Host "Incremental: could not read prior cache ($_). Running a full enumeration." -ForegroundColor Yellow
                        $priorCacheLookup = @{}
                    }
                } else {
                    Write-Host 'Incremental: no prior cache for this group set -- full enumeration this run (baseline).' -ForegroundColor Gray
                }
            }
            Write-Host ''
        }

        foreach ($entry in $groupList) {
            $totalProcessed++
            $progressPct = [int](($totalProcessed / $totalInList) * 100)
            Write-Host "  [$totalProcessed/$totalInList] $($entry.Domain)\$($entry.GroupName)..." -NoNewline -ForegroundColor Gray

            # Short-circuit groups in domains that failed the pre-flight DNS probe
            if ($unreachableDomains.ContainsKey($entry.Domain)) {
                $reason = $unreachableDomains[$entry.Domain]
                $totalErrors++
                Write-Host " [SKIPPED: domain unreachable]" -ForegroundColor Red
                $groupResults += @{
                    Data = @{
                        GroupName         = $entry.GroupName
                        Domain            = $entry.Domain
                        DistinguishedName = $null
                        MemberCount       = 0
                        Members           = @()
                        Skipped           = $false
                        SkipReason        = $null
                    }
                    Errors = @("Domain '$($entry.Domain)' unreachable - $reason. Check VPN/DNS/CSV spelling.")
                }
                continue
            }

            try {
                # ---- Incremental gate: reuse cached membership if unchanged ----
                # Single decision via Test-GroupReuseEligible (cache lookup +
                # Test-GroupUnchanged); no duplicated nested/whenChanged guard to drift.
                if ($incrementalEffective) {
                    $key = "$($entry.Domain)|$($entry.GroupName)"
                    if ($priorCacheLookup.ContainsKey($key)) {
                        $gateCtx = $null
                        try { $gateCtx = Get-AdLdapPooledContext -Pool $connectionPool -Domain $entry.Domain } catch { $gateCtx = $null }
                        if ($gateCtx) {
                            $curStamp = Get-GroupChangeStamp -Context $gateCtx -GroupName $entry.GroupName `
                                -PageSize ([int]$config.LdapPageSize) -TimeoutSeconds ([int]$config.LdapTimeout)
                            if (Test-GroupReuseEligible -PriorCacheLookup $priorCacheLookup -Key $key -CurrentStamp $curStamp) {
                                $reusedData = $priorCacheLookup[$key].Data
                                $reusedData.ReusedFromCache = $true
                                $groupResults += @{ Data = $reusedData; Errors = @() }
                                $reusedCount++
                                Write-Host " unchanged - reused ($($reusedData.MemberCount) members)" -ForegroundColor DarkCyan
                                Write-GroupEnumLog -Level 'INFO' -Operation 'IncrementalSkip' `
                                    -Message "Reused cached membership for $($entry.Domain)\$($entry.GroupName) (unchanged)" -Context @{
                                        domain = $entry.Domain; groupName = $entry.GroupName; members = $reusedData.MemberCount
                                    }
                                continue
                            }
                        }
                    }
                }

                $enumParams = @{
                    Domain         = $entry.Domain
                    GroupName      = $entry.GroupName
                    Config         = $config
                    ConnectionPool = $connectionPool
                }
                if ($Credential) {
                    $enumParams.Credential = $Credential
                }
                if ($IncludeAttributes.Count -gt 0) {
                    $enumParams.IncludeAttributes = $IncludeAttributes
                }
                if ($incrementalEffective) {
                    $enumParams.CaptureNesting = $true
                }
                if ($entry.IsDistinguishedName) {
                    $enumParams.GroupIsDistinguishedName = $true
                }

                $result = Get-GroupMembers @enumParams

                $fatalErrs = Get-FatalErrors $result.Errors
                $tierWarns = Get-TierWarnings $result.Errors

                if ($fatalErrs.Count -gt 0) {
                    $totalErrors += $fatalErrs.Count
                    Write-Host " [ERRORS: $($fatalErrs.Count)]" -ForegroundColor Red
                    Write-GroupEnumLog -Level 'WARN' -Operation 'EnumerateGroup' `
                        -Message "Errors enumerating $($entry.Domain)\$($entry.GroupName)" -Context @{
                            domain    = $entry.Domain
                            groupName = $entry.GroupName
                            errors    = ($fatalErrs -join '; ')
                        }
                } elseif ($result.Data.Skipped) {
                    $skippedCount++
                    Write-Host " [SKIPPED: $($result.Data.SkipReason)]" -ForegroundColor DarkYellow
                    Write-GroupEnumLog -Level 'INFO' -Operation 'SkipGroup' `
                        -Message "Skipped $($entry.Domain)\$($entry.GroupName)" -Context @{
                            domain     = $entry.Domain
                            groupName  = $entry.GroupName
                            skipReason = $result.Data.SkipReason
                        }
                } else {
                    $tierSuffix = if ($tierWarns.Count -gt 0) { ' [tier downgrade]' } else { '' }
                    $tierColor  = if ($tierWarns.Count -gt 0) { 'Yellow' } else { 'Green' }
                    Write-Host " $($result.Data.MemberCount) members$tierSuffix" -ForegroundColor $tierColor
                    Write-GroupEnumLog -Level 'DEBUG' -Operation 'EnumerateGroup' `
                        -Message "Enumerated $($entry.Domain)\$($entry.GroupName)" -Context @{
                            domain      = $entry.Domain
                            groupName   = $entry.GroupName
                            memberCount = $result.Data.MemberCount
                        }
                }

                $groupResults += $result

            } catch {
                $totalErrors++
                Write-Host " [FAILED: $_]" -ForegroundColor Red
                Write-GroupEnumLog -Level 'ERROR' -Operation 'EnumerateGroup' `
                    -Message "Failed to enumerate $($entry.Domain)\$($entry.GroupName): $_" -Context @{
                        domain    = $entry.Domain
                        groupName = $entry.GroupName
                        error     = $_.ToString()
                        stack     = $_.ScriptStackTrace
                    }
                $groupResults += @{
                    Data   = @{
                        GroupName         = $entry.GroupName
                        Domain            = $entry.Domain
                        DistinguishedName = $null
                        MemberCount       = 0
                        Members           = @()
                        Skipped           = $false
                        SkipReason        = $null
                    }
                    Errors = @("Enumeration failed: $_")
                }
            }
        }

        Write-Host ''

        if ($incrementalEffective) {
            $enumeratedCount = $totalProcessed - $reusedCount
            Write-Host "Incremental coverage: $reusedCount reused (unchanged), $enumeratedCount enumerated of $totalInList group(s)." -ForegroundColor Cyan
            Write-GroupEnumLog -Level 'INFO' -Operation 'IncrementalSummary' `
                -Message "Incremental run: $reusedCount reused, $enumeratedCount enumerated" -Context @{
                    reused = $reusedCount; enumerated = $enumeratedCount; total = $totalInList
                }
            Write-Host ''
        }

        # ---- Fuzzy matching ----
        $matchResults = $null
        if ($FuzzyMatch) {
            Write-Host 'Running fuzzy cross-domain matching...' -ForegroundColor Cyan
            $prefixes = if ($config.FuzzyPrefixes) { @($config.FuzzyPrefixes) } else { @() }
            $minScore = if ($null -ne $config.FuzzyMinScore)  { [double]$config.FuzzyMinScore }  else { 0.7 }

            $matchResults = Find-MatchingGroups -GroupResults $groupResults `
                -Prefixes $prefixes -MinScore $minScore

            Write-Host "  Matched: $($matchResults.Matched.Count) pairs, Unmatched: $($matchResults.Unmatched.Count)" -ForegroundColor Gray
            Write-Host ''

            Write-GroupEnumLog -Level 'INFO' -Operation 'FuzzyMatch' `
                -Message "Fuzzy matching complete" -Context @{
                    matchedPairs    = $matchResults.Matched.Count
                    unmatchedGroups = $matchResults.Unmatched.Count
                    minScore        = $minScore
                    prefixes        = ($prefixes -join ', ')
                }
        }

        # ---- Save JSON cache ----
        if (-not $NoCache) {
            Write-Host "Saving JSON cache to: $resolvedCachePath" -ForegroundColor Cyan
            try {
                $null = Export-GroupDataJson `
                    -GroupResults $groupResults `
                    -MatchResults $matchResults `
                    -OutputPath   $resolvedCachePath `
                    -CsvSource    $CsvPath
                Write-Host "  Saved: $resolvedCachePath" -ForegroundColor Gray
            } catch {
                Write-Warning "Failed to save JSON cache: $_"
            }
            Write-Host ''
        }

        # ---- Save cache snapshot to SQLite (for incremental gate) ----
        if ($effectiveBackend -eq 'sqlite' -and $null -ne $runId -and $runId -gt 0) {
            try {
                Save-MembershipStateSqlite -DbPath $dbPath -RunId $runId -GroupResults $groupResults
            } catch {
                Write-Warning "Failed to save SQLite cache snapshot: $_"
            }
        }
    }

    # =========================================================================
    # V2: Migration Readiness Analysis (when -AnalyzeGaps or -ResolveNested)
    # =========================================================================

    # V2 result containers -- all null/empty by default so v1 path is unchanged
    $staleResults       = $null
    $correlationResults = @{}
    $gapResults         = @()
    $overallReadiness   = $null
    $appReadiness       = $null
    $gapCsvPath         = $null
    $crSummaryPath      = $null
    $crText             = ''

    $runStale       = $DetectStale -or $AnalyzeGaps
    $runCorrelation = $AnalyzeGaps -and $matchResults -and $matchResults.Matched.Count -gt 0
    $runGaps        = $AnalyzeGaps -and $runCorrelation

    # ---- Step 1: Nested Group Resolution ----
    if ($ResolveNested) {
        Write-Host 'Resolving nested group memberships...' -ForegroundColor Cyan

        $nestedResolved   = 0
        $nestedUsersTotal = 0

        foreach ($groupResult in $groupResults) {
            # Filter out benign tier-downgrade warnings (string-prefixed
            # "WARNING: Using tier ...") before deciding whether to skip.
            # They indicate successful enumeration via a fallback tier, not a
            # real error, and downstream processing should still run.
            $fatalErrs = @($groupResult.Errors | Where-Object { $_ -notlike 'WARNING: Using tier*' })
            if ($groupResult.Data.Skipped -or $fatalErrs.Count -gt 0) { continue }

            $nestedParams = @{
                Domain         = $groupResult.Data.Domain
                GroupName      = $groupResult.Data.GroupName
                Config         = $config
                ConnectionPool = $connectionPool
            }
            if ($Credential) { $nestedParams.Credential = $Credential }

            try {
                $flatResult = Resolve-NestedGroupMembers @nestedParams

                if ($flatResult.FlatMembers.Count -gt 0) {
                    $groupResult.Data.Members     = $flatResult.FlatMembers
                    $groupResult.Data.MemberCount = $flatResult.TotalUsersFound
                    $nestedResolved++
                    $nestedUsersTotal += $flatResult.TotalUsersFound

                    if ($flatResult.MaxDepthReached) {
                        Write-Host "  $($groupResult.Data.Domain)\$($groupResult.Data.GroupName): $($flatResult.TotalUsersFound) users [max depth reached]" -ForegroundColor Yellow
                    }
                }

                if ($flatResult.Errors -and $flatResult.Errors.Count -gt 0) {
                    foreach ($e in $flatResult.Errors) {
                        Write-GroupEnumLog -Level 'WARN' -Operation 'NestedResolve' `
                            -Message "Nested resolve error for $($groupResult.Data.Domain)\$($groupResult.Data.GroupName): $e" `
                            -Context @{ domain = $groupResult.Data.Domain; groupName = $groupResult.Data.GroupName }
                    }
                }
            } catch {
                Write-Warning "Nested resolution failed for $($groupResult.Data.Domain)\$($groupResult.Data.GroupName): $_"
                Write-GroupEnumLog -Level 'ERROR' -Operation 'NestedResolve' `
                    -Message "Nested resolution failed: $_" `
                    -Context @{ domain = $groupResult.Data.Domain; groupName = $groupResult.Data.GroupName; error = $_.ToString() }
            }
        }

        Write-Host "  Resolved $nestedResolved group(s) -- $nestedUsersTotal total flat members" -ForegroundColor Gray
        Write-Host ''

        Write-GroupEnumLog -Level 'INFO' -Operation 'NestedResolve' `
            -Message "Nested group resolution complete: $nestedResolved groups, $nestedUsersTotal total users" `
            -Context @{ groupsResolved = $nestedResolved; totalUsers = $nestedUsersTotal }
    }

    # ---- Step 2: Stale Account Detection ----
    if ($runStale) {
        Write-Host 'Detecting stale and disabled accounts...' -ForegroundColor Cyan

        $staleResults   = @{}
        $staleTotalFlag = 0

        foreach ($groupResult in $groupResults) {
            # Filter out benign tier-downgrade warnings (string-prefixed
            # "WARNING: Using tier ...") before deciding whether to skip.
            # They indicate successful enumeration via a fallback tier, not a
            # real error, and downstream processing should still run.
            $fatalErrs = @($groupResult.Errors | Where-Object { $_ -notlike 'WARNING: Using tier*' })
            if ($groupResult.Data.Skipped -or $fatalErrs.Count -gt 0) { continue }
            if (-not $groupResult.Data.Members -or $groupResult.Data.Members.Count -eq 0) { continue }

            $staleKey = "$($groupResult.Data.Domain)|$($groupResult.Data.GroupName)"

            # Pass a copy of config with the resolved stale threshold
            $staleConfig = $config.Clone()
            $staleConfig.StaleAccountDays = $staleDays

            $staleParams = @{
                Members        = $groupResult.Data.Members
                Domain         = $groupResult.Data.Domain
                Config         = $staleConfig
                ConnectionPool = $connectionPool
            }
            if ($Credential) { $staleParams.Credential = $Credential }

            try {
                $staleResult = Get-AccountStaleness @staleParams
                $staleResults[$staleKey] = $staleResult

                $flagged = $staleResult.Summary.DisabledCount + $staleResult.Summary.StaleCount + $staleResult.Summary.NeverLoggedInCount
                $staleTotalFlag += $flagged

                Write-GroupEnumLog -Level 'DEBUG' -Operation 'StaleDetect' `
                    -Message "Staleness check: $($groupResult.Data.Domain)\$($groupResult.Data.GroupName)" `
                    -Context @{
                        domain    = $groupResult.Data.Domain
                        groupName = $groupResult.Data.GroupName
                        active    = $staleResult.Summary.ActiveCount
                        disabled  = $staleResult.Summary.DisabledCount
                        stale     = $staleResult.Summary.StaleCount
                        never     = $staleResult.Summary.NeverLoggedInCount
                    }
            } catch {
                Write-Warning "Stale detection failed for $($groupResult.Data.Domain)\$($groupResult.Data.GroupName): $_"
                Write-GroupEnumLog -Level 'ERROR' -Operation 'StaleDetect' `
                    -Message "Stale detection failed: $_" `
                    -Context @{ domain = $groupResult.Data.Domain; groupName = $groupResult.Data.GroupName; error = $_.ToString() }
            }
        }

        Write-Host "  $staleTotalFlag stale/disabled account(s) flagged across $($staleResults.Count) group(s)" -ForegroundColor Gray
        Write-Host ''

        Write-GroupEnumLog -Level 'INFO' -Operation 'StaleDetect' `
            -Message "Stale account detection complete: $staleTotalFlag accounts flagged" `
            -Context @{ totalFlagged = $staleTotalFlag; groupsChecked = $staleResults.Count }
    }

    # ---- Step 3: User Correlation ----
    if ($runCorrelation) {
        Write-Host 'Running cross-domain user correlation...' -ForegroundColor Cyan

        $totalCorrelated   = 0
        $totalHighConf     = 0
        $totalMediumConf   = 0
        $totalLowConf      = 0

        # Build a lookup of GroupName -> group result for member access
        $groupResultByKey = @{}
        foreach ($gr in $groupResults) {
            $k = "$($gr.Data.Domain)|$($gr.Data.GroupName)"
            $groupResultByKey[$k] = $gr
        }

        foreach ($pair in $matchResults.Matched) {
            $srcKey = "$($pair.SourceDomain)|$($pair.SourceGroup)"
            $tgtKey = "$($pair.TargetDomain)|$($pair.TargetGroup)"

            $srcResult = $groupResultByKey[$srcKey]
            $tgtResult = $groupResultByKey[$tgtKey]

            if (-not $srcResult -or -not $tgtResult) { continue }

            $srcMembers = if ($srcResult.Data.Members) { @($srcResult.Data.Members) } else { @() }
            $tgtMembers = if ($tgtResult.Data.Members) { @($tgtResult.Data.Members) } else { @() }

            $corrKey = "$($pair.SourceDomain)\$($pair.SourceGroup)|$($pair.TargetDomain)\$($pair.TargetGroup)"

            $corrParams = @{
                SourceMembers  = $srcMembers
                TargetMembers  = $tgtMembers
                Config         = $config
            }

            try {
                $corrResult = Find-UserCorrelations @corrParams
                $correlationResults[$corrKey] = $corrResult

                $totalCorrelated += $corrResult.Summary.CorrelatedCount
                $totalHighConf   += $corrResult.Summary.HighConfidence
                $totalMediumConf += $corrResult.Summary.MediumConfidence
                $totalLowConf    += $corrResult.Summary.LowConfidence

            } catch {
                Write-Warning "User correlation failed for pair ${corrKey}: $_"
                Write-GroupEnumLog -Level 'ERROR' -Operation 'UserCorrelation' `
                    -Message "User correlation failed for pair ${corrKey}: $_" `
                    -Context @{ corrKey = $corrKey; error = $_.ToString() }
            }
        }

        Write-Host "  $totalCorrelated correlation(s) found: High=$totalHighConf, Medium=$totalMediumConf, Low=$totalLowConf" -ForegroundColor Gray
        Write-Host ''

        Write-GroupEnumLog -Level 'INFO' -Operation 'UserCorrelation' `
            -Message "User correlation complete across $($correlationResults.Count) group pair(s)" `
            -Context @{
                pairs         = $correlationResults.Count
                correlated    = $totalCorrelated
                highConf      = $totalHighConf
                mediumConf    = $totalMediumConf
                lowConf       = $totalLowConf
            }
    }

    # ---- Step 4: Gap Analysis ----
    if ($runGaps) {
        Write-Host 'Running migration gap analysis...' -ForegroundColor Cyan

        $groupResultByKey = @{}
        foreach ($gr in $groupResults) {
            $k = "$($gr.Data.Domain)|$($gr.Data.GroupName)"
            $groupResultByKey[$k] = $gr
        }

        foreach ($pair in $matchResults.Matched) {
            $corrKey = "$($pair.SourceDomain)\$($pair.SourceGroup)|$($pair.TargetDomain)\$($pair.TargetGroup)"

            if (-not $correlationResults.ContainsKey($corrKey)) { continue }

            $srcKey = "$($pair.SourceDomain)|$($pair.SourceGroup)"
            $tgtKey = "$($pair.TargetDomain)|$($pair.TargetGroup)"

            $srcResult = $groupResultByKey[$srcKey]
            $tgtResult = $groupResultByKey[$tgtKey]

            if (-not $srcResult -or -not $tgtResult) { continue }

            $corrResult = $correlationResults[$corrKey]

            # Stale data for this source group (keyed by Domain|GroupName)
            $srcStaleKey   = "$($pair.SourceDomain)|$($pair.SourceGroup)"
            $staleForGroup = if ($staleResults -and $staleResults.ContainsKey($srcStaleKey)) {
                $staleResults[$srcStaleKey]
            } else { $null }

            $gapParams = @{
                SourceGroupResult = $srcResult
                TargetGroupResult = $tgtResult
                CorrelationResult = $corrResult
                StaleResult       = $staleForGroup
                Config            = $config
            }

            try {
                $gapResult   = Get-MigrationGapAnalysis @gapParams
                $gapResults += $gapResult
            } catch {
                Write-Warning "Gap analysis failed for pair ${corrKey}: $_"
                Write-GroupEnumLog -Level 'ERROR' -Operation 'GapAnalysis' `
                    -Message "Gap analysis failed for pair ${corrKey}: $_" `
                    -Context @{ corrKey = $corrKey; error = $_.ToString() }
            }
        }

        # Overall readiness summary
        if ($gapResults.Count -gt 0) {
            $appReadinessForOverall = $null

            $overallReadiness = Get-OverallMigrationReadiness -GapResults $gapResults `
                -AppReadiness $appReadinessForOverall

            Write-Host "  Overall readiness: $($overallReadiness.OverallPercent)% -- $($overallReadiness.TotalCRItems) CR item(s) across $($gapResults.Count) group pair(s)" -ForegroundColor Gray
        } else {
            Write-Host '  No gap results generated (no matched pairs with correlations)' -ForegroundColor Yellow
        }

        Write-Host ''

        Write-GroupEnumLog -Level 'INFO' -Operation 'GapAnalysis' `
            -Message "Gap analysis complete: $($gapResults.Count) group pairs analyzed" `
            -Context @{
                pairsAnalyzed    = $gapResults.Count
                overallPercent   = $(if ($overallReadiness) { $overallReadiness.OverallPercent } else { 0 })
                totalCRItems     = $(if ($overallReadiness) { $overallReadiness.TotalCRItems }   else { 0 })
            }
    }

    # ---- Step 4b: Domain Existence Resolution (-MigratingTo) ----
    if ($MigratingTo -and $gapResults.Count -gt 0) {
        Write-Host "Resolving domain existence in '$MigratingTo'..." -ForegroundColor Cyan

        $resolvedSearchBase = $TargetSearchBase

        if (-not $resolvedSearchBase) {
            Write-Host '  No -TargetSearchBase provided. Detecting current user OU...' -ForegroundColor Gray
            $ouDetect = Get-CurrentUserOU -Domain $MigratingTo -Credential $Credential -Config $config
            if ($ouDetect.Detected -and $ouDetect.ParentOU) {
                Write-Host "  Detected your OU: $($ouDetect.ParentOU)" -ForegroundColor Cyan
                $useDetected = Read-Host "  Use this OU as SearchBase? [Y/n]"
                if (-not $useDetected -or $useDetected -imatch '^y') {
                    $resolvedSearchBase = $ouDetect.ParentOU
                    Write-Host "  Using detected OU: $resolvedSearchBase" -ForegroundColor Green
                } else {
                    Write-Host '  Searching from domain root (may be slower)' -ForegroundColor Yellow
                }
            } else {
                Write-Host "  Could not detect user OU: $($ouDetect.Error)" -ForegroundColor Yellow
                Write-Host '  Searching from domain root' -ForegroundColor Yellow
            }
        }

        if ($resolvedSearchBase) {
            $sbCheck = Test-SearchBaseExists -Domain $MigratingTo -SearchBase $resolvedSearchBase `
                -Credential $Credential -Config $config
            if (-not $sbCheck.Exists) {
                Write-Host "  SearchBase NOT FOUND: $resolvedSearchBase" -ForegroundColor Red
                $continueChoice = Read-Host '  Continue searching from domain root instead? [Y/n]'
                if (-not $continueChoice -or $continueChoice -imatch '^y') {
                    $resolvedSearchBase = $null
                } else {
                    $MigratingTo = $null
                }
            } else {
                Write-Host '  SearchBase validated' -ForegroundColor Green
            }
        }

        if ($MigratingTo) {
            $notProvCount = @($gapResults | ForEach-Object { $_.Items } |
                Where-Object { $_.Status -eq 'NotProvisioned' }).Count
            if ($notProvCount -gt 0) {
                Write-Host "  Searching target domain for $notProvCount unmatched user(s)..." -ForegroundColor Gray
                $gapResults = Resolve-DomainExistence -GapResults $gapResults `
                    -TargetDomain $MigratingTo -TargetSearchBase $resolvedSearchBase `
                    -Credential $Credential -Config $config
                $existsCount = @($gapResults | ForEach-Object { $_.Items } | Where-Object { $_.Status -eq 'ExistsNotInGroup' }).Count
                $notInDomCount = @($gapResults | ForEach-Object { $_.Items } | Where-Object { $_.Status -eq 'NotInDomain' }).Count
                Write-Host "  Results: $existsCount exist in domain, $notInDomCount not in domain" -ForegroundColor Gray
                $overallReadiness = Get-OverallMigrationReadiness -GapResults $gapResults
                Write-Host "  Updated readiness: $($overallReadiness.OverallPercent)%" -ForegroundColor Gray
            } else {
                Write-Host '  No NotProvisioned users to search for' -ForegroundColor Gray
            }
            Write-Host ''
        }
    }

    # ---- Step 4c: Membership Drift Detection ----
    $driftResult = $null
    if (($BaselinePath -or $PreviousRunPath) -and $groupResults.Count -gt 0) {
        Write-Host 'Detecting membership drift...' -ForegroundColor Cyan
        $resolvedPreviousPath = $PreviousRunPath
        if (-not $resolvedPreviousPath -and -not $FromCache) {
            $resolvedPreviousPath = Get-LatestCacheFile -CacheDirectory $cacheDir -ExcludePath $resolvedCachePath
            if ($resolvedPreviousPath) {
                Write-Host "  Auto-detected previous run: $resolvedPreviousPath" -ForegroundColor Gray
            }
        }
        $driftResult = Get-MembershipDrift -CurrentGroupResults $groupResults `
            -BaselinePath $BaselinePath -PreviousRunPath $resolvedPreviousPath
        $blSummary = $driftResult.OverallSummary.BaselineComparison
        $prSummary = $driftResult.OverallSummary.PreviousComparison
        if ($BaselinePath -and $blSummary.GroupsCompared -gt 0) {
            Write-Host "  vs Baseline: +$($blSummary.TotalAdded) added, -$($blSummary.TotalRemoved) removed across $($blSummary.GroupsWithChanges) group(s)" -ForegroundColor $(if ($blSummary.GroupsWithChanges -gt 0) { 'Yellow' } else { 'Gray' })
        }
        if ($resolvedPreviousPath -and $prSummary.GroupsCompared -gt 0) {
            Write-Host "  vs Previous: +$($prSummary.TotalAdded) added, -$($prSummary.TotalRemoved) removed across $($prSummary.GroupsWithChanges) group(s)" -ForegroundColor $(if ($prSummary.GroupsWithChanges -gt 0) { 'Yellow' } else { 'Gray' })
        }
        if ($driftResult.FromPrevious.Count -gt 0) {
            $driftCsvPath = Join-Path $resolvedOutputDir "${csvLeaf}-drift-previous-${timestamp}.csv"
            $null = Export-DriftReportCsv -DriftResult $driftResult -OutputPath $driftCsvPath -ComparisonType 'Previous'
            Write-Host "  Drift CSV: $driftCsvPath" -ForegroundColor Gray
        }
        Write-Host ''
    }

    # ---- Step 4d: Membership Change Tracking (persistent ledger) ----
    # Additive daily-change mode. Maintains a local state.json + append-only
    # changelog.jsonl per group set and emits a SailPoint-ready change-feed CSV
    # keyed on sAMAccountName. Independent of, and does not alter, the snapshot-diff
    # drift path above.
    if ($TrackChanges -and $groupResults.Count -gt 0) {
        Write-Host 'Tracking membership changes (persistent ledger)...' -ForegroundColor Cyan

        $stateDir = if ($StatePath) {
            if ([System.IO.Path]::IsPathRooted($StatePath)) { $StatePath } else { Join-Path $scriptRoot $StatePath }
        } elseif ($config.ChangeTracking -and $config.ChangeTracking.StatePath) {
            if ([System.IO.Path]::IsPathRooted($config.ChangeTracking.StatePath)) { $config.ChangeTracking.StatePath } else { Join-Path $scriptRoot $config.ChangeTracking.StatePath }
        } else {
            Join-Path $scriptRoot 'State'
        }
        if (-not (Test-Path $stateDir)) { $null = New-Item -ItemType Directory -Path $stateDir -Force }

        if ($unifiedState) {
            # v2: single unified state file for all groups
            $stateFile = Join-Path $stateDir 'group-enumerator-state.json'
            $logFile   = Join-Path $stateDir 'changelog.jsonl'
        } else {
            # Legacy: per-CSV state files (v1 naming)
            $stateFile = Join-Path $stateDir "${csvLeaf}-membership-state.json"
            $logFile   = Join-Path $stateDir "${csvLeaf}-changelog.jsonl"
        }

        # Auto-migrate legacy JSON state to unified format (first v2 run only)
        if ($unifiedState -and $effectiveBackend -eq 'json') {
            if (-not (Test-Path $stateFile)) {
                $legacyStateFiles = Get-ChildItem -Path $stateDir -Filter '*-membership-state.json' -File -ErrorAction SilentlyContinue
                if ($legacyStateFiles -and $legacyStateFiles.Count -gt 0) {
                    Write-Host "Migrating $($legacyStateFiles.Count) legacy JSON state file(s) to unified format..." -ForegroundColor Cyan
                    $migrationReport = Merge-LegacyState -StateDir $stateDir -OutputStateFile $stateFile -OutputChangeLog $logFile
                    Write-Host "  Merged: $($migrationReport.GroupsMerged) group(s) from $($migrationReport.FilesProcessed) file(s), $($migrationReport.ChangeLogEntries) changelog entries" -ForegroundColor Green
                    if ($migrationReport.DuplicateGroups -gt 0) {
                        Write-Host "  Note: $($migrationReport.DuplicateGroups) duplicate group(s) resolved (kept most recent)" -ForegroundColor Yellow
                    }
                }
            }
        }

        $state  = Import-MembershipStateAuto -Path $stateFile -Backend $effectiveBackend -DbPath $dbPath -CsvLeaf $csvLeaf
        $update = Update-MembershipStateAuto -State $state -CurrentGroupResults $groupResults -Backend $effectiveBackend -DbPath $dbPath -CsvLeaf $csvLeaf
        # $null = ... : the SQLite backend's Save/Add wrappers return values (a path,
        # a snapshot count) that would otherwise leak onto the pipeline as stray output.
        $null = Save-MembershipStateAuto -NewState $update.NewState -Path $stateFile -Backend $effectiveBackend -DbPath $dbPath -RunId $(if ($runId) { $runId } else { 0 }) -GroupResults $groupResults
        $null = Add-ChangeLogEntriesAuto -Changes $update.Changes -Path $logFile -Backend $effectiveBackend -DbPath $dbPath

        # Changelog rotation (JSON backend only -- SQLite manages its own storage)
        if ($effectiveBackend -eq 'json') {
            $rotMaxSizeMB = if ($config.ChangeTracking -and $null -ne $config.ChangeTracking.MaxChangeLogSizeMB) {
                [double]$config.ChangeTracking.MaxChangeLogSizeMB
            } else { 50 }
            $rotRetentionDays = if ($config.ChangeTracking -and $null -ne $config.ChangeTracking.RetentionDays) {
                [int]$config.ChangeTracking.RetentionDays
            } else { 0 }

            if ($rotMaxSizeMB -gt 0 -or $rotRetentionDays -gt 0) {
                $rotResult = Invoke-ChangeLogRotation -Path $logFile -MaxSizeMB $rotMaxSizeMB -RetentionDays $rotRetentionDays
                if ($rotResult.Rotated) {
                    Write-Host "  Changelog archived: $($rotResult.Archived)" -ForegroundColor Gray
                }
                if ($rotResult.TrimmedCount -gt 0) {
                    Write-Host "  Changelog trimmed: $($rotResult.TrimmedCount) old entries removed ($($rotResult.RemainingCount) remaining)" -ForegroundColor Gray
                }
            }
        }

        if ($update.Summary.Failed) {
            Write-Host '  Change tracking FAILED for this run -- state was NOT updated (see warnings above). Changes were not recorded.' -ForegroundColor Yellow
            Write-GroupEnumLog -Level 'ERROR' -Operation 'ChangeTracking' `
                -Message "Change tracking failed for $csvLeaf -- update-state returned no result" -Context @{ csv = $csvLeaf; backend = $effectiveBackend }
        } elseif ($update.Summary.IsFirstRun) {
            Write-Host "  First run -- baseline seeded for $($update.Summary.GroupsTracked) group(s). No changes reported." -ForegroundColor Gray
        } else {
            $changeColor = if ($update.Summary.TotalAdded -gt 0 -or $update.Summary.TotalRemoved -gt 0) { 'Yellow' } else { 'Gray' }
            Write-Host "  Changes: +$($update.Summary.TotalAdded) added, -$($update.Summary.TotalRemoved) removed across $($update.Summary.GroupsChanged) group(s)" -ForegroundColor $changeColor
            if ($update.Summary.GroupsSeeded -gt 0) {
                Write-Host "  Newly tracked (seeded, not reported as adds): $($update.Summary.GroupsSeeded) group(s)" -ForegroundColor Gray
            }
        }

        # Determine which changes to export: if -ChangePeriod is set, use the
        # period-filtered changes for the CSV feed (SailPoint-ready); otherwise
        # use the current run's changes.
        # Wrap in @(...) so a $null (e.g. SQLite first-run emits no Changes) coerces to
        # an empty array -- Export-ChangeFeedCsv accepts @() but not $null.
        $feedChanges = @(if ($changeWindowActive -and $reportChangeData -and $reportChangeData.Changes) {
            $reportChangeData.Changes
        } else {
            $update.Changes
        })
        $changeCsvPath = Join-Path $resolvedOutputDir "${csvLeaf}-changes-$($ChangeType.ToLower())-${timestamp}.csv"
        $null = Export-ChangeFeedCsv -Changes $feedChanges -OutputPath $changeCsvPath -ChangeType $ChangeType
        $feedLabel = if ($changeWindowActive) { "$ChangeType, $changeWindowLabel" } else { $ChangeType }
        Write-Host "  Change feed CSV ($feedLabel): $changeCsvPath" -ForegroundColor Gray

        if (-not $JsonOnly) {
            $changeHtmlPath = Join-Path $resolvedOutputDir "${csvLeaf}-changes-${timestamp}.html"
            $null = Export-ChangeReportHtml -Changes $feedChanges -OutputPath $changeHtmlPath `
                -ChangeType $ChangeType -Summary $update.Summary -Theme $Theme -Title "Membership Changes - $csvLeaf"
            Write-Host "  Change report HTML: $changeHtmlPath" -ForegroundColor Gray
        }

        Write-Host "  State file: $stateFile" -ForegroundColor Gray

        # ---- Run History Summary: brief historical comparison ----
        if (-not $update.Summary.IsFirstRun) {
            try {
                $histLogFile = if ($unifiedState) {
                    Join-Path $stateDir 'changelog.jsonl'
                } else {
                    Join-Path $stateDir "${csvLeaf}-changelog.jsonl"
                }
                if (Test-Path $histLogFile) {
                    $weekChanges = Read-ChangeLog -Path $histLogFile -LastWeek
                    $weekAdded   = @($weekChanges | Where-Object { $_.Action -eq 'Added' }).Count
                    $weekRemoved = @($weekChanges | Where-Object { $_.Action -eq 'Removed' }).Count

                    $histLine = "  History: vs last run: +$($update.Summary.TotalAdded)/-$($update.Summary.TotalRemoved)"
                    $histLine += " | vs last week: +${weekAdded}/-${weekRemoved}"
                    $histColor = if (($weekAdded + $weekRemoved) -gt 0) { 'Yellow' } else { 'Gray' }
                    Write-Host $histLine -ForegroundColor $histColor
                }
            } catch {
                # Non-critical -- skip silently
            }
        }

        Write-Host ''
    }

    # ---- Step 5: App Mapping ----
    if ($AppMappingCsv) {
        Write-Host "Loading application mapping from: $AppMappingCsv" -ForegroundColor Cyan

        try {
            $appMappings = Import-AppMapping -CsvPath $AppMappingCsv

            if ($appMappings.Count -gt 0 -and $gapResults.Count -gt 0) {
                $appReadiness = Get-AppReadiness -AppMappings $appMappings -GapResults $gapResults

                Write-Host "  $($appReadiness.Summary.TotalApps) app(s): $($appReadiness.Summary.ReadyApps) ready, $($appReadiness.Summary.InProgressApps) in progress, $($appReadiness.Summary.BlockedApps) blocked" -ForegroundColor Gray

                Write-GroupEnumLog -Level 'INFO' -Operation 'AppMapping' `
                    -Message "App readiness calculated for $($appReadiness.Summary.TotalApps) application(s)" `
                    -Context @{
                        totalApps      = $appReadiness.Summary.TotalApps
                        readyApps      = $appReadiness.Summary.ReadyApps
                        inProgressApps = $appReadiness.Summary.InProgressApps
                        blockedApps    = $appReadiness.Summary.BlockedApps
                        notAnalyzed    = $appReadiness.Summary.NotAnalyzedApps
                    }
            } elseif ($appMappings.Count -gt 0) {
                Write-Host '  App mappings loaded but no gap results available -- skipping app readiness calculation' -ForegroundColor Yellow
                Write-GroupEnumLog -Level 'WARN' -Operation 'AppMapping' `
                    -Message 'App mappings loaded but no gap results available for readiness calculation'
            }
        } catch {
            Write-Warning "App mapping failed: $_"
            Write-GroupEnumLog -Level 'ERROR' -Operation 'AppMapping' `
                -Message "App mapping failed: $_" -Context @{ error = $_.ToString() }
        }

        Write-Host ''
    }

    # ---- Step 6: Export Gap Analysis CSV and CR Summary ----
    if ($AnalyzeGaps -and $gapResults.Count -gt 0) {
        Write-Host 'Exporting gap analysis artefacts...' -ForegroundColor Cyan

        $gapCsvFileName = "${csvLeaf}-gaps-${timestamp}.csv"
        $gapCsvPath     = Join-Path $resolvedOutputDir $gapCsvFileName

        try {
            $null = Export-GapAnalysisCsv -GapResults $gapResults -OutputPath $gapCsvPath
            Write-Host "  Gap analysis CSV: $gapCsvPath" -ForegroundColor Gray

            Write-GroupEnumLog -Level 'INFO' -Operation 'ExportCsv' `
                -Message "Gap analysis CSV exported" -Context @{ path = $gapCsvPath }
        } catch {
            Write-Warning "Failed to export gap analysis CSV: $_"
            Write-GroupEnumLog -Level 'ERROR' -Operation 'ExportCsv' `
                -Message "Gap analysis CSV export failed: $_" -Context @{ error = $_.ToString() }
        }

        if ($overallReadiness) {
            $crSummaryFileName = "${csvLeaf}-cr-summary-${timestamp}.txt"
            $crSummaryPath     = Join-Path $resolvedOutputDir $crSummaryFileName

            try {
                $crText = Export-ChangeRequestSummary -GapResults $gapResults `
                    -OverallReadiness $overallReadiness

                [System.IO.File]::WriteAllText(
                    $crSummaryPath,
                    $crText,
                    [System.Text.UTF8Encoding]::new($false)
                )
                Write-Host "  CR summary: $crSummaryPath" -ForegroundColor Gray

                Write-GroupEnumLog -Level 'INFO' -Operation 'ExportCR' `
                    -Message "CR summary exported" -Context @{ path = $crSummaryPath }
            } catch {
                Write-Warning "Failed to export CR summary: $_"
                Write-GroupEnumLog -Level 'ERROR' -Operation 'ExportCR' `
                    -Message "CR summary export failed: $_" -Context @{ error = $_.ToString() }
                $crText = ''
            }
        }

        Write-Host ''
    }

    # =========================================================================
    # Flatten per-group stale results for report generators
    # =========================================================================
    # $staleResults is keyed by "DOMAIN|GroupName" -> @{ Disabled; Stale; Active; NeverLoggedIn; Summary }.
    # All report generators expect a flat structure: @{ Disabled = @(...); Stale = @(...); Active = @() }.
    # Flatten here once so every report consumer gets the expected shape.
    $flatStaleResults = $null
    if ($staleResults -and $staleResults.Count -gt 0) {
        $flatStaleResults = @{
            Disabled      = @()
            Stale         = @()
            Active        = @()
            NeverLoggedIn = @()
        }
        $seen = @{}
        foreach ($staleKey in $staleResults.Keys) {
            $sr = $staleResults[$staleKey]
            if ($sr.Disabled) {
                foreach ($d in $sr.Disabled) {
                    $uid = "$($d.Domain)|$($d.SamAccountName)"
                    if (-not $seen.ContainsKey($uid)) {
                        $flatStaleResults.Disabled += $d
                        $seen[$uid] = $true
                    }
                }
            }
            if ($sr.Stale) {
                foreach ($s in $sr.Stale) {
                    $uid = "$($s.Domain)|$($s.SamAccountName)"
                    if (-not $seen.ContainsKey($uid)) {
                        $flatStaleResults.Stale += $s
                        $seen[$uid] = $true
                    }
                }
            }
            if ($sr.Active) {
                foreach ($a in $sr.Active) {
                    $uid = "$($a.Domain)|$($a.SamAccountName)"
                    if (-not $seen.ContainsKey($uid)) {
                        $flatStaleResults.Active += $a
                        $seen[$uid] = $true
                    }
                }
            }
            if ($sr.NeverLoggedIn) {
                foreach ($n in $sr.NeverLoggedIn) {
                    $uid = "$($n.Domain)|$($n.SamAccountName)"
                    if (-not $seen.ContainsKey($uid)) {
                        $flatStaleResults.NeverLoggedIn += $n
                        $seen[$uid] = $true
                    }
                }
            }
        }
    }

    # =========================================================================
    # Report generation (both branches converge here)
    # =========================================================================
    if (-not $JsonOnly) {
        Write-Host "Generating HTML report: $resolvedHtmlPath" -ForegroundColor Cyan

        if ($AnalyzeGaps -and $gapResults.Count -gt 0) {
            # V2: migration readiness report.
            # Flatten producer schema into the shape the report module reads.
            $flatGapResults     = @($gapResults | ForEach-Object { ConvertTo-FlatGapResult $_ })
            $flatOverall        = ConvertTo-FlatOverallReadiness $overallReadiness

            $null = Export-MigrationReport `
                -GroupResults      $groupResults `
                -MatchResults      $matchResults `
                -GapResults        $flatGapResults `
                -OverallReadiness  $flatOverall `
                -CorrelationResults $correlationResults `
                -StaleResults      $flatStaleResults `
                -AppReadiness      $appReadiness `
                -OutputPath        $resolvedHtmlPath `
                -Theme             $Theme `
                -Config            $config
        } else {
            # V1: standard group comparison report
            $null = Export-GroupReport `
                -GroupResults $groupResults `
                -MatchResults $matchResults `
                -OutputPath   $resolvedHtmlPath `
                -Theme        $Theme `
                -Config       $config
        }

        Write-Host "  Report: $resolvedHtmlPath" -ForegroundColor Gray
        Write-Host ''
    }

    # ---- Members roster CSV (-ExportMembersCsv) ----
    # Additive full-inventory dump of every enumerated member, written alongside
    # the normal HTML/JSON outputs. Runs independently of -TrackChanges.
    if ($ExportMembersCsv -and $groupResults.Count -gt 0) {
        $membersCsvPath = Join-Path $resolvedOutputDir "${csvLeaf}-members-${timestamp}.csv"
        $null = Export-MembersCsv -GroupResults $groupResults -OutputPath $membersCsvPath -Attributes $IncludeAttributes
        Write-Host "Members roster CSV: $membersCsvPath" -ForegroundColor Cyan
        Write-Host ''
    }

    # ---- New Report Types (v3) ----

    # ---- ChangePeriod: read historical changes for report enrichment ----
    # When -ChangePeriod is set and -TrackChanges is on, read back the changelog
    # for the specified window and build a synthetic change tracking data object
    # that reports use in place of (or merged with) the current run's changes.
    $reportChangeData = $null
    if ($changeWindowActive -and $TrackChanges -and $groupResults.Count -gt 0) {
        try {
            $periodLogFile = if ($unifiedState) {
                Join-Path $stateDir 'changelog.jsonl'
            } else {
                Join-Path $stateDir "${csvLeaf}-changelog.jsonl"
            }

            if (Test-Path $periodLogFile) {
                # Unified: any window (preset / custom days / explicit date) resolves to a -Since cutoff.
                $readParams = @{ Path = $periodLogFile; Since = $changeWindowSince }
                $periodChanges = Read-ChangeLog @readParams

                $periodAdded   = @($periodChanges | Where-Object { $_.Action -eq 'Added' }).Count
                $periodRemoved = @($periodChanges | Where-Object { $_.Action -eq 'Removed' }).Count
                $periodGroupsChanged = @($periodChanges | ForEach-Object { "$($_.Domain)|$($_.GroupName)" } | Sort-Object -Unique).Count

                $reportChangeData = @{
                    Changes = @($periodChanges)
                    Summary = @{
                        TotalAdded    = $periodAdded
                        TotalRemoved  = $periodRemoved
                        GroupsChanged = $periodGroupsChanged
                        GroupsTracked = if ($update) { $update.Summary.GroupsTracked } else { 0 }
                        GroupsSeeded  = 0
                        IsFirstRun    = $false
                    }
                }

                Write-Host "  Change window ($changeWindowLabel): $periodAdded added, $periodRemoved removed across $periodGroupsChanged group(s)" -ForegroundColor Gray
            }
        } catch {
            Write-Host "WARNING: Failed to read changelog for window '$changeWindowLabel': $_" -ForegroundColor Yellow
        }
    }

    # Fall back to current-run changes if no period data was built
    if (-not $reportChangeData -and $TrackChanges -and $update) {
        $reportChangeData = $update
    }

    # Count how many v3 reports were requested
    $v3ReportCount = @($doGovernanceReport, $doExecutiveDashboard, $doComplianceReport, $doLeadershipSummary) | Where-Object { $_ } | Measure-Object | Select-Object -ExpandProperty Count
    if ($v3ReportCount -gt 0) {
        $v3StaleData = if ($DetectStale -and $flatStaleResults) { $flatStaleResults } else { $null }
        $v3ReportNum = 0
        Write-Host "Generating v3 reports ($v3ReportCount report(s) requested)..." -ForegroundColor Cyan
    }

    if ($doGovernanceReport) {
        $v3ReportNum++
        $govReportPath = Join-Path $resolvedOutputDir "${csvLeaf}-governance-${timestamp}.html"
        $govChangeData = $reportChangeData
        try {
            Write-Host "  [$v3ReportNum/$v3ReportCount] Access Governance Report..." -ForegroundColor Gray -NoNewline
            $generatedGovPath = Export-GovernanceReport -GroupResults $groupResults -OutputPath $govReportPath `
                -StaleResults $v3StaleData -ChangeTrackingData $govChangeData -Config $config -Title "Access Governance Report - $csvLeaf"
            Write-Host " done" -ForegroundColor Green
            Write-Host "    -> $generatedGovPath" -ForegroundColor DarkGray
        } catch {
            Write-Host " FAILED" -ForegroundColor Red
            Write-Host "    -> $_" -ForegroundColor Yellow
            Write-GroupEnumLog -Level 'ERROR' -Operation 'ReportGeneration' `
                -Message "Governance report generation failed: $_" -Context @{ error = $_.ToString(); path = $govReportPath }
        }
    }

    if ($doExecutiveDashboard) {
        $v3ReportNum++
        $execReportPath = Join-Path $resolvedOutputDir "${csvLeaf}-executive-${timestamp}.html"
        try {
            Write-Host "  [$v3ReportNum/$v3ReportCount] Executive Dashboard..." -ForegroundColor Gray -NoNewline
            $generatedExecPath = Export-ExecutiveDashboard -GroupResults $groupResults -OutputPath $execReportPath `
                -StaleResults $v3StaleData `
                -ChangeTrackingData $reportChangeData `
                -Config $config -Title "Executive Dashboard - $csvLeaf"
            Write-Host " done" -ForegroundColor Green
            Write-Host "    -> $generatedExecPath" -ForegroundColor DarkGray
        } catch {
            Write-Host " FAILED" -ForegroundColor Red
            Write-Host "    -> $_" -ForegroundColor Yellow
            Write-GroupEnumLog -Level 'ERROR' -Operation 'ReportGeneration' `
                -Message "Executive dashboard generation failed: $_" -Context @{ error = $_.ToString(); path = $execReportPath }
        }
    }

    if ($doComplianceReport) {
        $v3ReportNum++
        $compReportPath = Join-Path $resolvedOutputDir "${csvLeaf}-compliance-${timestamp}.html"
        $compDrift = if ($driftResult) { $driftResult } else { $null }
        try {
            Write-Host "  [$v3ReportNum/$v3ReportCount] Compliance Audit Report..." -ForegroundColor Gray -NoNewline
            $generatedCompPath = Export-ComplianceReport -GroupResults $groupResults -OutputPath $compReportPath `
                -StaleResults $v3StaleData `
                -ChangeTrackingData $reportChangeData `
                -DriftResult $compDrift -Config $config -Title "Compliance Audit Report - $csvLeaf"
            Write-Host " done" -ForegroundColor Green
            Write-Host "    -> $generatedCompPath" -ForegroundColor DarkGray
        } catch {
            Write-Host " FAILED" -ForegroundColor Red
            Write-Host "    -> $_" -ForegroundColor Yellow
            Write-GroupEnumLog -Level 'ERROR' -Operation 'ReportGeneration' `
                -Message "Compliance report generation failed: $_" -Context @{ error = $_.ToString(); path = $compReportPath }
        }
    }

    if ($doLeadershipSummary) {
        $v3ReportNum++
        $leaderReportPath = Join-Path $resolvedOutputDir "${csvLeaf}-leadership-${timestamp}.html"
        try {
            Write-Host "  [$v3ReportNum/$v3ReportCount] Leadership Summary..." -ForegroundColor Gray -NoNewline
            $generatedLeaderPath = Export-LeadershipSummary -GroupResults $groupResults -OutputPath $leaderReportPath `
                -StaleResults $v3StaleData `
                -ChangeTrackingData $reportChangeData `
                -Config $config -Title "Leadership Summary - $csvLeaf"
            Write-Host " done" -ForegroundColor Green
            Write-Host "    -> $generatedLeaderPath" -ForegroundColor DarkGray
        } catch {
            Write-Host " FAILED" -ForegroundColor Red
            Write-Host "    -> $_" -ForegroundColor Yellow
            Write-GroupEnumLog -Level 'ERROR' -Operation 'ReportGeneration' `
                -Message "Leadership summary generation failed: $_" -Context @{ error = $_.ToString(); path = $leaderReportPath }
        }
    }

    if ($v3ReportCount -gt 0) {
        Write-Host ''
    }

    # ---- Baseline governance reports (-BaselineReports = all 10; -BaselineReport = specific) ----
    if ($BaselineReports -or ($BaselineReport -and @($BaselineReport).Count -gt 0)) {
        # Single catalog: key -> generator + data source. All 10 are always
        # available so any subset (or all) can be requested; nothing is removed.
        $baselineCatalog = @(
            @{ Key = 'roster';             Fn = 'Export-MembershipSnapshotRosterReport';       Type = 'groups' }
            @{ Key = 'access-cert';        Fn = 'Export-AccessCertificationAttestationReport'; Type = 'groups' }
            @{ Key = 'privileged';         Fn = 'Export-PrivilegedGroupReviewReport';          Type = 'groups' }
            @{ Key = 'sod';                Fn = 'Export-SodToxicComembershipReport';           Type = 'groups' }
            @{ Key = 'orphaned';           Fn = 'Export-OrphanedDisabledMembersReport';        Type = 'groups' }
            @{ Key = 'inventory';          Fn = 'Export-GroupInventoryCatalogReport';          Type = 'groups' }
            @{ Key = 'empty-stale';        Fn = 'Export-EmptyStaleGroupsReport';               Type = 'groups' }
            @{ Key = 'nested-audit';       Fn = 'Export-NestedMembershipAuditReport';          Type = 'groups' }
            @{ Key = 'exec-summary';       Fn = 'Export-GovernanceExecutiveSummaryReport';     Type = 'groups' }
            @{ Key = 'change-attestation'; Fn = 'Export-MembershipChangeAttestationReport';    Type = 'changelog' }
        )
        $selectedKeys = if ($BaselineReports) { @($baselineCatalog | ForEach-Object { $_.Key }) } else { @($BaselineReport) }
        Write-Host "Generating baseline governance reports ($(@($selectedKeys).Count) selected)..." -ForegroundColor Cyan

        # Resolve the changelog once (for the changelog-driven report)
        $blStateDir = if ($config.ChangeTracking -and $config.ChangeTracking.StatePath) {
            if ([System.IO.Path]::IsPathRooted($config.ChangeTracking.StatePath)) { $config.ChangeTracking.StatePath } else { Join-Path $scriptRoot $config.ChangeTracking.StatePath }
        } else { Join-Path $scriptRoot 'State' }
        $blChangelog = Join-Path $blStateDir 'changelog.jsonl'

        $baselineCount = 0
        foreach ($key in $selectedKeys) {
            $entry = $baselineCatalog | Where-Object { $_.Key -eq $key } | Select-Object -First 1
            if (-not $entry -or -not (Get-Command $entry.Fn -ErrorAction SilentlyContinue)) { continue }
            $bp = Join-Path $resolvedOutputDir "${csvLeaf}-$($entry.Key)-${timestamp}.html"
            try {
                if ($entry.Type -eq 'changelog') {
                    if (-not (Test-Path $blChangelog)) { Write-Host "  [skip] $($entry.Key) (no changelog found)" -ForegroundColor DarkYellow; continue }
                    $null = & $entry.Fn -ChangeLogPath $blChangelog -OutputPath $bp
                } else {
                    $null = & $entry.Fn -GroupResults $groupResults -OutputPath $bp
                }
                Write-Host "  [ok] $($entry.Key)" -ForegroundColor Gray; $baselineCount++
            } catch {
                Write-Host "  [FAIL] $($entry.Key): $_" -ForegroundColor Yellow
                Write-GroupEnumLog -Level 'ERROR' -Operation 'ReportGeneration' -Message "Baseline report $($entry.Key) failed: $_" -Context @{ error = $_.ToString() }
            }
        }
        Write-Host "  Baseline reports generated: $baselineCount" -ForegroundColor White
        Write-Host ''
    }

    # ---- Composable component report (-ReportComponents) ----
    if ($ReportComponents -and @($ReportComponents).Count -gt 0) {
        if (-not (Get-Command New-ComposableReport -ErrorAction SilentlyContinue)) {
            Write-Host '  [skip] -ReportComponents: composable engine not loaded' -ForegroundColor DarkYellow
        } else {
            # Normalize the requested list so a quoted comma-string
            # (-ReportComponents 'a,b,c', bound as ONE element) behaves the same as
            # the unquoted array form (-ReportComponents a,b,c). See Expand-RCComponentList.
            $rcRequested = @(Expand-RCComponentList -Components $ReportComponents)

            # Validate requested keys against the registry (allow optional :half/:full suffix).
            $rcValidKeys = @(Get-RCComponentKeys)
            $rcBadKeys = @()
            foreach ($rc in $rcRequested) {
                $rcKey = (([string]$rc) -replace ':(half|full)\s*$', '').Trim()
                if ($rcKey -and ($rcValidKeys -notcontains $rcKey)) { $rcBadKeys += $rcKey }
            }
            if ($rcBadKeys.Count -gt 0) {
                Write-Host ("  [skip] -ReportComponents: unknown component(s): {0}. Valid: {1}" -f ($rcBadKeys -join ', '), ($rcValidKeys -join ', ')) -ForegroundColor Yellow
            } else {
                Write-Host "Generating composable component report ($(@($rcRequested).Count) components)..." -ForegroundColor Cyan

                # Changelog for change-driven components (diff).
                $rcStateDir = if ($config.ChangeTracking -and $config.ChangeTracking.StatePath) {
                    if ([System.IO.Path]::IsPathRooted($config.ChangeTracking.StatePath)) { $config.ChangeTracking.StatePath } else { Join-Path $scriptRoot $config.ChangeTracking.StatePath }
                } else { Join-Path $scriptRoot 'State' }
                $rcChangelog = Join-Path $rcStateDir 'changelog.jsonl'

                # Stale data only when -DetectStale actually ran (else null -> components gate).
                # Derive directly from $flatStaleResults (always built when stale detection ran)
                # rather than $v3StaleData, which is only set in the v3-reports path -- so a
                # components-only run (no -AllReports/-GovernanceReport) still gets stale data
                # and RC08's stale/never-logged-in enrichment activates.
                $rcStale = if ($DetectStale -and $flatStaleResults) { $flatStaleResults } else { $null }

                $rcContext = New-RCContext -GroupResults $groupResults `
                    -StaleResults $rcStale `
                    -ChangeLogPath $rcChangelog `
                    -Metadata @{ Tool = 'Group Enumerator'; Version = $script:ToolVersion } `
                    -Theme $ComponentReportTheme
                $rcOut = Join-Path $resolvedOutputDir "${csvLeaf}-composed-${timestamp}.html"
                try {
                    $null = New-ComposableReport -Components $rcRequested -Context $rcContext -Title $ComponentReportTitle -Theme $ComponentReportTheme -OutputPath $rcOut
                    Write-Host "  [ok] composable report: $rcOut" -ForegroundColor Gray
                } catch {
                    Write-Host "  [FAIL] composable report: $_" -ForegroundColor Yellow
                    Write-GroupEnumLog -Level 'ERROR' -Operation 'ReportGeneration' -Message "Composable report failed: $_" -Context @{ error = $_.ToString() }
                }
            }
        }
        Write-Host ''
    }

    # ---- Email (if -SendEmail) ----
    if ($SendEmail) {
        Write-Host 'Sending migration summary email...' -ForegroundColor Cyan

        $emailOverallReadiness = if ($overallReadiness) {
            $overallReadiness
        } else {
            # Supply empty readiness so Send-MigrationSummaryEmail can build a minimal subject
            @{
                OverallPercent   = 0
                GroupCount       = $groupResults.Count
                ReadyGroups      = 0
                InProgressGroups = 0
                BlockedGroups    = 0
                TotalCRItems     = 0
                CRByPriority     = @{ P1 = 0; P2 = 0; P3 = 0 }
            }
        }

        $emailParams = @{
            HtmlReportPath   = $resolvedHtmlPath
            Config           = $config
            OverallReadiness = $emailOverallReadiness
            CRSummaryText    = $crText
        }
        if ($Credential) { $emailParams.Credential = $Credential }

        try {
            $emailResult = Send-MigrationSummaryEmail @emailParams

            if ($emailResult.Sent) {
                Write-Host "  Email sent to: $($emailResult.Recipients -join ', ')" -ForegroundColor Gray
                Write-GroupEnumLog -Level 'INFO' -Operation 'Email' `
                    -Message "Migration summary email sent" `
                    -Context @{
                        recipients = ($emailResult.Recipients -join ', ')
                        subject    = $emailResult.Subject
                    }
            } else {
                Write-Warning "Email send failed: $($emailResult.Error)"
                Write-GroupEnumLog -Level 'WARN' -Operation 'Email' `
                    -Message "Email send failed: $($emailResult.Error)" `
                    -Context @{ error = $emailResult.Error }
            }
        } catch {
            Write-Warning "Email delivery error: $_"
            Write-GroupEnumLog -Level 'ERROR' -Operation 'Email' `
                -Message "Email delivery error: $_" -Context @{ error = $_.ToString() }
        }

        Write-Host ''
    }

    # ---- SQLite run lifecycle: complete run ----
    if ($effectiveBackend -eq 'sqlite' -and $null -ne $runId -and $runId -gt 0) {
        try {
            # Keys MUST be PascalCase: state_db.py complete-run reads them
            # case-sensitively (metrics.get("GroupsEnumerated", 0), ...). snake_case
            # here silently persisted 0 into every run metric column.
            $runMetrics = @{
                GroupsEnumerated = @($groupResults | Where-Object { -not $_.Data.Skipped }).Count
                GroupsSkipped = @($groupResults | Where-Object { $_.Data.Skipped }).Count
                GroupsReused = $(if ($reusedCount) { $reusedCount } else { 0 })
                TotalMembers = ($groupResults | Where-Object { -not $_.Data.Skipped } | ForEach-Object { $_.Data.Members.Count } | Measure-Object -Sum).Sum
                ChangesDetected = $(if ($update) { $update.Summary.TotalAdded + $update.Summary.TotalRemoved } else { 0 })
            }
            Complete-EnumerationRun -DbPath $dbPath -RunId $runId -Metrics $runMetrics
        } catch {
            Write-Warning "Failed to complete SQLite run record: $_"
        }
    }

    # =========================================================================
    # Summary
    # =========================================================================
    $skippedFinal = @($groupResults | Where-Object { $_.Data.Skipped })
    # Separate fatal errors from tier-downgrade warnings so the summary
    # doesn't misreport a successful fallback-tier run as "errored".
    $errGroups  = @($groupResults | Where-Object { (Get-FatalErrors $_.Errors).Count -gt 0 })
    $warnGroups = @($groupResults | Where-Object {
        (Get-TierWarnings $_.Errors).Count -gt 0 -and (Get-FatalErrors $_.Errors).Count -eq 0
    })
    # "Enumerated" = group result that came back without a fatal error or skip.
    # Pre-flight unreachable groups have Skipped=false but populate Errors, and
    # must not be counted as enumerated even though we looped past them.
    $enumerated   = @($groupResults | Where-Object {
        -not $_.Data.Skipped -and (Get-FatalErrors $_.Errors).Count -eq 0
    })
    $totalMembers = 0
    foreach ($e in $enumerated) { $totalMembers += [int]$e.Data.MemberCount }

    Write-Host '========================================' -ForegroundColor Cyan
    Write-Host 'Summary' -ForegroundColor Cyan
    Write-Host '========================================' -ForegroundColor Cyan
    Write-Host "  Groups processed : $($groupResults.Count)" -ForegroundColor White
    Write-Host "  Enumerated       : $($enumerated.Count)" -ForegroundColor White
    Write-Host "  Skipped          : $($skippedFinal.Count)" -ForegroundColor $(if ($skippedFinal.Count -gt 0) { 'Yellow' } else { 'White' })
    Write-Host "  Total members    : $totalMembers" -ForegroundColor White
    Write-Host "  Groups with errors  : $($errGroups.Count)" -ForegroundColor $(if ($errGroups.Count -gt 0) { 'Red' } else { 'White' })
    if ($warnGroups.Count -gt 0) {
        Write-Host "  Groups with warnings: $($warnGroups.Count) (tier downgrade)" -ForegroundColor Yellow
    }

    if ($FuzzyMatch -and $matchResults) {
        Write-Host "  Matched pairs    : $($matchResults.Matched.Count)" -ForegroundColor White
        Write-Host "  Unmatched groups : $($matchResults.Unmatched.Count)" -ForegroundColor White
    }

    # V2 summary lines
    if ($ResolveNested) {
        $nestedCount = @($groupResults | Where-Object { -not $_.Data.Skipped }).Count
        Write-Host "  Nested resolved  : $nestedCount group(s)" -ForegroundColor White
    }

    if ($runStale -and $staleResults) {
        $totalFlagged = 0
        foreach ($sr in $staleResults.Values) {
            $totalFlagged += $sr.Summary.DisabledCount + $sr.Summary.StaleCount + $sr.Summary.NeverLoggedInCount
        }
        Write-Host "  Stale flagged    : $totalFlagged account(s)" -ForegroundColor $(if ($totalFlagged -gt 0) { 'Yellow' } else { 'White' })
    }

    if ($runCorrelation -and $correlationResults.Count -gt 0) {
        Write-Host "  Correlations     : $totalCorrelated (High=$totalHighConf Medium=$totalMediumConf Low=$totalLowConf)" -ForegroundColor White
    }

    if ($overallReadiness) {
        Write-Host "  Readiness        : $($overallReadiness.OverallPercent)%" -ForegroundColor $(
            if ($overallReadiness.OverallPercent -ge 80) { 'Green' }
            elseif ($overallReadiness.OverallPercent -ge 50) { 'Yellow' }
            else { 'Red' }
        )
        $p1 = $overallReadiness.CRByPriority.P1
        $p2 = $overallReadiness.CRByPriority.P2
        $p3 = $overallReadiness.CRByPriority.P3
        Write-Host "  Change Requests  : $($overallReadiness.TotalCRItems) total (P1=$p1 P2=$p2 P3=$p3)" -ForegroundColor White
    }

    if ($TrackChanges -and $update) {
        $totalChanges = $update.Summary.TotalAdded + $update.Summary.TotalRemoved
        Write-Host "  Changes detected : +$($update.Summary.TotalAdded) / -$($update.Summary.TotalRemoved)" -ForegroundColor $(if ($totalChanges -gt 0) { 'Yellow' } else { 'White' })
        if ($changeWindowActive -and $reportChangeData) {
            Write-Host "  Report window    : $changeWindowLabel ($($reportChangeData.Summary.TotalAdded + $reportChangeData.Summary.TotalRemoved) change(s))" -ForegroundColor White
        }
    }

    if ($v3ReportCount -gt 0) {
        Write-Host "  V3 reports       : $v3ReportCount generated" -ForegroundColor White
    }

    if (-not $JsonOnly) {
        Write-Host "  HTML report      : $resolvedHtmlPath" -ForegroundColor Cyan
    }
    if (-not $NoCache -and -not $FromCache) {
        Write-Host "  JSON cache       : $resolvedCachePath" -ForegroundColor Cyan
    }
    if ($gapCsvPath) {
        Write-Host "  Gap analysis CSV : $gapCsvPath" -ForegroundColor Cyan
    }
    if ($crSummaryPath) {
        Write-Host "  CR summary       : $crSummaryPath" -ForegroundColor Cyan
    }

    # Close logger and show path
    $logPath = Close-GroupEnumLog -Summary @{
        groupsProcessed  = $groupResults.Count
        enumerated       = $enumerated.Count
        skipped          = $skippedFinal.Count
        totalMembers     = $totalMembers
        errorGroups      = $errGroups.Count
        matchedPairs     = if ($matchResults) { $matchResults.Matched.Count } else { 0 }
        overallReadiness = if ($overallReadiness) { $overallReadiness.OverallPercent } else { $null }
        totalCRItems     = if ($overallReadiness) { $overallReadiness.TotalCRItems }   else { 0 }
    }
    if ($logPath) {
        Write-Host "  Log file         : $logPath" -ForegroundColor Cyan
    }

    Write-Host ''

    if ($errGroups.Count -gt 0) {
        Write-Host 'Groups with errors:' -ForegroundColor Red
        foreach ($eg in $errGroups) {
            Write-Host "  $($eg.Data.Domain)\$($eg.Data.GroupName):" -ForegroundColor Red
            foreach ($e in (Get-FatalErrors $eg.Errors)) {
                Write-Host "    - $e" -ForegroundColor Red
            }
        }
        Write-Host ''
    }

    if ($warnGroups.Count -gt 0) {
        # Roll up the distinct tier-downgrade reasons into a single concise note
        # instead of repeating the same warning per group.
        $tierReasons = @{}
        foreach ($wg in $warnGroups) {
            foreach ($w in (Get-TierWarnings $wg.Errors)) {
                if (-not $tierReasons.ContainsKey($w)) { $tierReasons[$w] = 0 }
                $tierReasons[$w]++
            }
        }
        Write-Host 'Tier downgrades (data still enumerated successfully):' -ForegroundColor Yellow
        foreach ($k in $tierReasons.Keys) {
            Write-Host "  ($($tierReasons[$k]) group(s)) $k" -ForegroundColor Yellow
        }
        Write-Host ''
    }

    # Return results object only when caller asks for it (-PassThru).
    # Default behaviour: don't pollute the console with a hashtable dump after
    # the formatted summary above.
    if ($PassThru) {
        $pipelineResult = @{
            GroupResults        = $groupResults
            MatchResults        = $matchResults
            Config              = $config
            OutputPath          = if (-not $JsonOnly) { $resolvedHtmlPath } else { $null }
            CachePath           = if (-not $NoCache -and -not $FromCache) { $resolvedCachePath } else { $null }
            GapResults          = $gapResults
            OverallReadiness    = $overallReadiness
            CorrelationResults  = $correlationResults
            StaleResults        = $staleResults
            AppReadiness        = $appReadiness
            GapCsvPath          = $gapCsvPath
            CRSummaryPath       = $crSummaryPath
        }
        return $pipelineResult
    }

} catch {
    Write-Host ''
    Write-Host "FATAL ERROR: $_" -ForegroundColor Red
    Write-Host $_.ScriptStackTrace -ForegroundColor DarkRed
    Write-GroupEnumLog -Level 'ERROR' -Operation 'Fatal' `
        -Message "Fatal error: $_" -Context @{
            error = $_.ToString()
            stack = $_.ScriptStackTrace
        }
    $null = Close-GroupEnumLog -Summary @{ fatalError = $_.ToString() }
    exit 1
} finally {
    if ($connectionPool) {
        try { Close-AdLdapConnectionPool $connectionPool } catch { }
    }
}
