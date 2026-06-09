<#
.SYNOPSIS
    Access Governance Report and Executive Dashboard generator for Group Enumerator v3.

.DESCRIPTION
    Generates two report types from group enumeration data:

    1. Access Governance Report (Audit Tier) -- Identity-centric view: WHO has access
       to WHAT groups. Uses inline CSS only, table-based layout, Word-compatible.
       No JavaScript, no <style> blocks, no <details>/<summary>.

    2. Executive Dashboard (Executive Tier) -- High-level KPI dashboard with SVG donut
       charts, card-based grid, and embedded CSS. Minimal JS for chart animations.

    Both reports consume the standard GroupResults array produced by Get-GroupMembers,
    plus optional StaleResults and ChangeTrackingData for risk flags and change history.

    The identity-entitlement map inverts the default data model from "groups with members"
    to "identities with entitlements", enabling SailPoint-style access certification views.

.NOTES
    Version: 3.0.0
    HTML escaping: manual replacement of &, <, >, ", ' (no System.Web dependency)
    File writes use UTF-8 without BOM via [System.IO.File]::WriteAllText
    Template loading via [System.IO.File]::ReadAllText with UTF-8
    Placeholder replacement via .Replace() (NOT -replace) to avoid regex issues
    No emoji in PowerShell code (per project conventions)
    Template paths resolved at dot-source time via $PSScriptRoot
#>

# ---- Tool version constant ----
$script:GovernanceReportVersion = '3.0.0'

# ---- Resolve template paths at load time ----
$script:GovReportModuleDir     = $PSScriptRoot
$script:GovReportProjectRoot   = Split-Path -Parent $script:GovReportModuleDir
$script:GovReportTemplatePath  = Join-Path (Join-Path $script:GovReportProjectRoot 'Templates') 'governance-report-template.html'
$script:ExecDashTemplatePath   = Join-Path (Join-Path $script:GovReportProjectRoot 'Templates') 'executive-dashboard-template.html'

# ---- Import ReportHelpers if available ----
# Discovery order: (1) config key ReportHelpers.FrameworkPath, (2) environment
# variable REPORT_HELPERS_PATH, (3) relative path from Modules/ to the framework.
$script:ReportHelpersLoaded = $false
try {
    $rhCandidates = @(
        # Candidate 1: environment variable
        $env:REPORT_HELPERS_PATH
        # Candidate 2: relative path (works when project is at its standard location)
        (Join-Path $PSScriptRoot '..\..\..\.claude-frameworks\report-framework\helpers\ReportHelpers.psm1')
    )

    foreach ($rhCandidate in $rhCandidates) {
        if ($rhCandidate -and (Test-Path $rhCandidate)) {
            Import-Module $rhCandidate -Force -ErrorAction SilentlyContinue
            $script:ReportHelpersLoaded = $true
            break
        }
    }
}
catch {
    # ReportHelpers not available; fall back to inline implementations
}

# ---------------------------------------------------------------------------
# Internal: Escape-GovernanceHtml
# ---------------------------------------------------------------------------
function Escape-GovernanceHtml {
    <#
    .SYNOPSIS
        HTML-encodes a string without requiring System.Web.
    #>
    param([string]$Text)
    if (-not $Text) { return '' }

    # Try ReportHelpers first
    if ($script:ReportHelpersLoaded) {
        try { return Escape-ReportHtml -Text $Text } catch {}
    }

    # Inline fallback -- order matters: & first to avoid double-encoding
    $Text = $Text.Replace('&', '&amp;')
    $Text = $Text.Replace('<', '&lt;')
    $Text = $Text.Replace('>', '&gt;')
    $Text = $Text.Replace('"', '&quot;')
    $Text = $Text.Replace("'", '&#39;')
    return $Text
}

# ---------------------------------------------------------------------------
# Internal: Get-GovernanceStatusBadge
# ---------------------------------------------------------------------------
function Get-GovernanceStatusBadge {
    <#
    .SYNOPSIS
        Returns an inline-styled status badge span for audit reports.
    #>
    param(
        [string]$Status,
        [switch]$InlineStyles
    )

    # Try ReportHelpers first
    if ($script:ReportHelpersLoaded -and $InlineStyles) {
        try {
            $map = @{
                'Active'   = '#339933'
                'Stale'    = '#FF8800'
                'Disabled' = '#CC3333'
                'Unknown'  = '#777777'
            }
            return Build-StatusBadge -Status $Status -StatusColorMap $map -InlineStyles
        }
        catch {}
    }

    $escapedStatus = Escape-GovernanceHtml $Status
    $color = switch ($Status.ToLower()) {
        'active'   { '#339933' }
        'stale'    { '#FF8800' }
        'disabled' { '#CC3333' }
        default    { '#777777' }
    }

    if ($InlineStyles) {
        return "<span style=""display:inline-block; padding:2px 10px; border-radius:99px; font-size:12px; font-weight:bold; letter-spacing:0.3px; background-color:$color; color:#ffffff;"">$escapedStatus</span>"
    }
    else {
        return "<span class=""badge"" style=""background-color:$color; color:#ffffff;"">$escapedStatus</span>"
    }
}

# ---------------------------------------------------------------------------
# Public: Export-GovernanceReport
# ---------------------------------------------------------------------------
function Export-GovernanceReport {
    <#
    .SYNOPSIS
        Generates an Access Governance Report (Audit Tier) HTML file.

    .DESCRIPTION
        Produces an identity-centric view showing WHO has access to WHAT groups.
        All inline CSS, no JavaScript, table-based layout for Word compatibility.
        Uses the SailPoint audit colour palette.

    .PARAMETER GroupResults
        Array of group result hashtables from Get-GroupMembers.
        Each element: @{ Data = @{ GroupName; Domain; Members; MemberCount; Skipped }; Errors = @() }

    .PARAMETER OutputPath
        Full path for the output HTML file.

    .PARAMETER StaleResults
        Optional hashtable from stale account detection.
        Keys: Disabled = @(...); Stale = @(...); Active = @(...)

    .PARAMETER ChangeTrackingData
        Optional hashtable from Update-MembershipState.
        Keys: Changes = @(...); Summary = @{...}

    .PARAMETER Config
        Configuration hashtable. Used for ToolVersion.

    .PARAMETER Title
        Report title. Defaults to 'Access Governance Report'.

    .OUTPUTS
        String path to the generated HTML file.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [array]$GroupResults,

        [Parameter(Mandatory = $true)]
        [string]$OutputPath,

        [Parameter(Mandatory = $false)]
        [hashtable]$StaleResults = $null,

        [Parameter(Mandatory = $false)]
        [hashtable]$ChangeTrackingData = $null,

        [Parameter(Mandatory = $false)]
        [hashtable]$Config = @{},

        [Parameter(Mandatory = $false)]
        [string]$Title = 'Access Governance Report'
    )

    try {
        $timestamp   = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
        $toolVersion = if ($Config.ToolVersion) { $Config.ToolVersion } else { $script:GovernanceReportVersion }

        # Load template
        $templatePath = $script:GovReportTemplatePath
        if (Test-Path $templatePath) {
            $template = [System.IO.File]::ReadAllText($templatePath, [System.Text.Encoding]::UTF8)
        }
        else {
            throw "Governance report template not found: $templatePath"
        }

        # Load palette
        $palette = @{
            primary   = '#336699'
            secondary = '#339933'
            danger    = '#CC3333'
            warning   = '#FF8800'
            muted     = '#777777'
            border    = '#e0e0e0'
            headerBg  = '#34495e'
            headerText = '#ffffff'
            rowAlt    = '#f9f9f9'
            accent    = '#336699'
        }
        if ($script:ReportHelpersLoaded) {
            try {
                $loadedPalette = Get-ReportPalette -Tier 'audit'
                if ($loadedPalette -and $loadedPalette.colors) { $palette = $loadedPalette.colors }
            }
            catch { }
        }

        # Build identity-entitlement map
        $identityMap = Build-IdentityEntitlementMap -GroupResults $GroupResults

        # Build enumerated results (excluding skipped)
        $enumerated = @($GroupResults | Where-Object { $_.Data.Skipped -ne $true })

        # Build HTML blocks
        $executiveSummaryHtml = Build-GovernanceKpiCardsHtml `
            -IdentityMap $identityMap `
            -GroupResults $GroupResults `
            -StaleResults $StaleResults `
            -Palette $palette `
            -InlineStyles

        $accessCertHtml = Build-AccessCertificationHtml `
            -IdentityMap $identityMap `
            -StaleResults $StaleResults `
            -Palette $palette

        # Resolve identity detail threshold from config (default 3)
        $identityThreshold = 3
        if ($Config.Reporting -and $null -ne $Config.Reporting.IdentityDetailThreshold) {
            $identityThreshold = [int]$Config.Reporting.IdentityDetailThreshold
        }

        $identityDetailsHtml = Build-IdentityEntitlementDetailsHtml `
            -IdentityMap $identityMap `
            -Palette $palette `
            -Threshold $identityThreshold

        $riskFlagsHtml = Build-RiskFlagSummaryHtml `
            -GroupResults $GroupResults `
            -StaleResults $StaleResults `
            -Palette $palette `
            -IdentityMap $identityMap

        $hasRiskFlags = $false
        if ($StaleResults -and (
            ($StaleResults.Disabled -and $StaleResults.Disabled.Count -gt 0) -or
            ($StaleResults.Stale -and $StaleResults.Stale.Count -gt 0))) {
            $hasRiskFlags = $true
        }
        $riskFlagsDisplay = if ($hasRiskFlags) { 'block' } else { 'none' }

        $changeHistoryHtml = Build-ChangeHistorySummaryHtml `
            -ChangeTrackingData $ChangeTrackingData `
            -Palette $palette

        $hasChanges = $false
        if ($ChangeTrackingData -and $ChangeTrackingData.Changes -and $ChangeTrackingData.Changes.Count -gt 0) {
            $hasChanges = $true
        }
        $changeHistoryDisplay = if ($hasChanges) { 'block' } else { 'none' }

        $complianceTimelineHtml = Build-ComplianceTimelineHtml `
            -ChangeTrackingData $ChangeTrackingData `
            -Palette $palette
        $complianceTimelineDisplay = if ($hasChanges) { 'block' } else { 'none' }

        # Build footer
        $correlationId = [guid]::NewGuid().ToString('N').Substring(0, 12).ToUpper()
        $footerHtml = ''
        if ($script:ReportHelpersLoaded) {
            try {
                $footerHtml = Build-ReportFooter -ToolVersion $toolVersion `
                    -GeneratedBy 'Group Enumerator - Access Governance' `
                    -CorrelationId $correlationId `
                    -Palette $palette -InlineStyles
            }
            catch { }
        }
        if (-not $footerHtml) {
            $footerParts = @(
                "Group Enumerator - Access Governance"
                "v$(Escape-GovernanceHtml $toolVersion)"
                "Generated: $(Escape-GovernanceHtml $timestamp)"
                "Correlation ID: $correlationId"
            )
            $footerHtml = $footerParts -join ' &nbsp;|&nbsp; '
        }

        # Replace placeholders -- use .Replace() (not -replace) to avoid regex issues
        $template = $template.Replace('{{TITLE}}',                      [string]$Title)
        $template = $template.Replace('{{SUBTITLE}}',                   'Identity-Centric Access Governance View')
        $template = $template.Replace('{{TIMESTAMP}}',                  [string]$timestamp)
        $template = $template.Replace('{{TOOL_VERSION}}',               [string]$toolVersion)
        $template = $template.Replace('{{EXECUTIVE_SUMMARY}}',          [string]$executiveSummaryHtml)
        $template = $template.Replace('{{ACCESS_CERT_TABLE}}',          [string]$accessCertHtml)
        $template = $template.Replace('{{IDENTITY_DETAILS}}',           [string]$identityDetailsHtml)
        $template = $template.Replace('{{RISK_FLAGS}}',                 [string]$riskFlagsHtml)
        $template = $template.Replace('{{RISK_FLAGS_DISPLAY}}',         [string]$riskFlagsDisplay)
        $template = $template.Replace('{{CHANGE_HISTORY}}',             [string]$changeHistoryHtml)
        $template = $template.Replace('{{CHANGE_HISTORY_DISPLAY}}',     [string]$changeHistoryDisplay)
        $template = $template.Replace('{{COMPLIANCE_TIMELINE}}',        [string]$complianceTimelineHtml)
        $template = $template.Replace('{{COMPLIANCE_TIMELINE_DISPLAY}}',[string]$complianceTimelineDisplay)
        $template = $template.Replace('{{FOOTER}}',                     [string]$footerHtml)

        # Write output -- UTF-8 no BOM
        $outDir = Split-Path $OutputPath -Parent
        if ($outDir -and -not (Test-Path $outDir)) {
            $null = New-Item -ItemType Directory -Path $outDir -Force
        }
        [System.IO.File]::WriteAllText($OutputPath, $template, [System.Text.UTF8Encoding]::new($false))

        # Log if available
        if (Get-Command -Name 'Write-GroupEnumLog' -ErrorAction SilentlyContinue) {
            Write-GroupEnumLog -Level 'INFO' -Operation 'ReportGeneration' -Message "Governance report generated: $OutputPath"
        }
        else {
            Write-Verbose "Governance report generated: $OutputPath"
        }

        return $OutputPath
    }
    catch {
        throw "Export-GovernanceReport failed: $_"
    }
}

# ---------------------------------------------------------------------------
# Public: Export-ExecutiveDashboard
# ---------------------------------------------------------------------------
function Export-ExecutiveDashboard {
    <#
    .SYNOPSIS
        Generates an Executive Dashboard (Executive Tier) HTML file.

    .DESCRIPTION
        Produces a high-level KPI dashboard with SVG donut charts, card-based grid
        layout, and embedded CSS. Minimal JS for chart animations only.

    .PARAMETER GroupResults
        Array of group result hashtables from Get-GroupMembers.

    .PARAMETER OutputPath
        Full path for the output HTML file.

    .PARAMETER StaleResults
        Optional hashtable from stale account detection.

    .PARAMETER ChangeTrackingData
        Optional hashtable from Update-MembershipState.

    .PARAMETER Config
        Configuration hashtable. Used for ToolVersion.

    .PARAMETER Title
        Report title. Defaults to 'Executive Dashboard'.

    .OUTPUTS
        String path to the generated HTML file.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [array]$GroupResults,

        [Parameter(Mandatory = $true)]
        [string]$OutputPath,

        [Parameter(Mandatory = $false)]
        [hashtable]$StaleResults = $null,

        [Parameter(Mandatory = $false)]
        [hashtable]$ChangeTrackingData = $null,

        [Parameter(Mandatory = $false)]
        [hashtable]$Config = @{},

        [Parameter(Mandatory = $false)]
        [string]$Title = 'Executive Dashboard'
    )

    try {
        $timestamp   = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
        $toolVersion = if ($Config.ToolVersion) { $Config.ToolVersion } else { $script:GovernanceReportVersion }

        # Load template
        $templatePath = $script:ExecDashTemplatePath
        if (Test-Path $templatePath) {
            $template = [System.IO.File]::ReadAllText($templatePath, [System.Text.Encoding]::UTF8)
        }
        else {
            throw "Executive dashboard template not found: $templatePath"
        }

        # Load palette
        $palette = @{
            primary   = '#1B2A4A'
            secondary = '#2CA58D'
            danger    = '#E74C3C'
            warning   = '#F39C12'
            muted     = '#8B8680'
            border    = '#dcdde1'
            headerBg  = '#1B2A4A'
            headerText = '#ffffff'
            rowAlt    = '#f8f9fc'
            accent    = '#2CA58D'
        }
        if ($script:ReportHelpersLoaded) {
            try {
                $loadedPalette = Get-ReportPalette -Tier 'executive'
                if ($loadedPalette -and $loadedPalette.colors) { $palette = $loadedPalette.colors }
            }
            catch { }
        }

        # Build identity map for KPI calculations
        $identityMap = Build-IdentityEntitlementMap -GroupResults $GroupResults

        # Build HTML blocks
        $kpiCardsHtml = Build-GovernanceKpiCardsHtml `
            -IdentityMap $identityMap `
            -GroupResults $GroupResults `
            -StaleResults $StaleResults `
            -Palette $palette `
            -ChangeTrackingData $ChangeTrackingData

        $chartsHtml = Build-ExecutiveChartsHtml `
            -GroupResults $GroupResults `
            -StaleResults $StaleResults `
            -ChangeTrackingData $ChangeTrackingData `
            -IdentityMap $identityMap

        $domainStatusHtml = Build-DomainStatusTableHtml `
            -GroupResults $GroupResults `
            -Palette $palette

        # Change velocity section
        $changeVelocityHtml = ''
        $changeVelocityDisplay = 'none'
        if ($ChangeTrackingData -and $ChangeTrackingData.Summary) {
            $summary = $ChangeTrackingData.Summary
            $added   = if ($null -ne $summary.TotalAdded)   { [int]$summary.TotalAdded }   else { 0 }
            $removed = if ($null -ne $summary.TotalRemoved) { [int]$summary.TotalRemoved } else { 0 }
            $maxVel  = [Math]::Max($added, $removed)
            if ($maxVel -eq 0) { $maxVel = 1 }

            $addedPct   = [Math]::Round(($added / $maxVel) * 100)
            $removedPct = [Math]::Round(($removed / $maxVel) * 100)

            $changeVelocityHtml = @"
<div class="velocity-bar">
    <span class="bar-label">Added</span>
    <div class="bar-track">
        <div class="bar-fill" data-percent="$addedPct" style="width:${addedPct}%; background:#2CA58D;">$added</div>
    </div>
</div>
<div class="velocity-bar">
    <span class="bar-label">Removed</span>
    <div class="bar-track">
        <div class="bar-fill" data-percent="$removedPct" style="width:${removedPct}%; background:#E74C3C;">$removed</div>
    </div>
</div>
<p style="font-size:0.85em; color:#8B8680; margin-top:12px;">Changes detected since last enumeration run. Groups tracked: $([int]$summary.GroupsTracked).</p>
"@
            if ($added -gt 0 -or $removed -gt 0) {
                $changeVelocityDisplay = 'block'
            }
        }

        # Build footer
        $footerHtml = ''
        if ($script:ReportHelpersLoaded) {
            try {
                $footerHtml = Build-ReportFooter -ToolVersion $toolVersion `
                    -GeneratedBy 'Group Enumerator - Executive Dashboard' `
                    -Palette $palette
            }
            catch { }
        }
        if (-not $footerHtml) {
            $footerParts = @(
                "Group Enumerator - Executive Dashboard"
                "v$(Escape-GovernanceHtml $toolVersion)"
                "Generated: $(Escape-GovernanceHtml $timestamp)"
            )
            $footerHtml = '<p>' + ($footerParts -join ' &nbsp;|&nbsp; ') + '</p>'
        }

        # Replace placeholders
        $template = $template.Replace('{{TITLE}}',                    [string]$Title)
        $template = $template.Replace('{{TIMESTAMP}}',                [string]$timestamp)
        $template = $template.Replace('{{TOOL_VERSION}}',             [string]$toolVersion)
        $template = $template.Replace('{{KPI_CARDS}}',                [string]$kpiCardsHtml)
        $template = $template.Replace('{{CHARTS}}',                   [string]$chartsHtml)
        $template = $template.Replace('{{DOMAIN_STATUS}}',            [string]$domainStatusHtml)
        $template = $template.Replace('{{CHANGE_VELOCITY}}',          [string]$changeVelocityHtml)
        $template = $template.Replace('{{CHANGE_VELOCITY_DISPLAY}}',  [string]$changeVelocityDisplay)
        $template = $template.Replace('{{FOOTER}}',                   [string]$footerHtml)

        # Write output -- UTF-8 no BOM
        $outDir = Split-Path $OutputPath -Parent
        if ($outDir -and -not (Test-Path $outDir)) {
            $null = New-Item -ItemType Directory -Path $outDir -Force
        }
        [System.IO.File]::WriteAllText($OutputPath, $template, [System.Text.UTF8Encoding]::new($false))

        # Log if available
        if (Get-Command -Name 'Write-GroupEnumLog' -ErrorAction SilentlyContinue) {
            Write-GroupEnumLog -Level 'INFO' -Operation 'ReportGeneration' -Message "Executive dashboard generated: $OutputPath"
        }
        else {
            Write-Verbose "Executive dashboard generated: $OutputPath"
        }

        return $OutputPath
    }
    catch {
        throw "Export-ExecutiveDashboard failed: $_"
    }
}

# ---------------------------------------------------------------------------
# Internal: Build-IdentityEntitlementMap
# ---------------------------------------------------------------------------
function Build-IdentityEntitlementMap {
    <#
    .SYNOPSIS
        Inverts the data model from "groups with members" to "identities with entitlements".

    .PARAMETER GroupResults
        Array of group result hashtables.

    .OUTPUTS
        Hashtable keyed by "DOMAIN|sam" with values:
        @{ Identity = @{ SamAccountName; DisplayName; Email; Domain; Enabled };
           Groups = @(@{ Domain; GroupName; MemberCount }, ...) }
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [array]$GroupResults
    )

    $map = @{}

    foreach ($gr in $GroupResults) {
        if (-not $gr.Data) { continue }
        if ($gr.Data.Skipped -eq $true) { continue }

        $domain    = if ($gr.Data.Domain)    { [string]$gr.Data.Domain }    else { '' }
        $groupName = if ($gr.Data.GroupName) { [string]$gr.Data.GroupName } else { '' }
        $memberCount = if ($null -ne $gr.Data.MemberCount) { [int]$gr.Data.MemberCount } else { 0 }

        $members = if ($gr.Data.Members -is [array]) { $gr.Data.Members }
                   elseif ($gr.Data.Members) { @(, $gr.Data.Members) }
                   else { @() }

        foreach ($m in $members) {
            $sam = if ($m.SamAccountName) { [string]$m.SamAccountName } else { '' }
            if (-not $sam) { continue }

            # Build a composite key using domain + sam for cross-domain uniqueness
            $memberDomain = if ($m.Domain) { [string]$m.Domain } else { $domain }
            $key = "$memberDomain|$($sam.ToLower())"

            if (-not $map.ContainsKey($key)) {
                $map[$key] = @{
                    Identity = @{
                        SamAccountName = $sam
                        DisplayName    = if ($m.DisplayName) { [string]$m.DisplayName } else { '' }
                        Email          = if ($m.Email) { [string]$m.Email } else { '' }
                        Domain         = $memberDomain
                        Enabled        = $m.Enabled
                    }
                    Groups = [System.Collections.Generic.List[hashtable]]::new()
                }
            }

            # Add group membership
            $map[$key].Groups.Add(@{
                Domain      = $domain
                GroupName   = $groupName
                MemberCount = $memberCount
            })
        }
    }

    return $map
}

# ---------------------------------------------------------------------------
# Internal: Build-GovernanceKpiCardsHtml
# ---------------------------------------------------------------------------
function Build-GovernanceKpiCardsHtml {
    <#
    .SYNOPSIS
        Generates KPI summary cards for governance reports and executive dashboards.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$IdentityMap,

        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [array]$GroupResults,

        [Parameter()]
        [hashtable]$StaleResults = $null,

        [Parameter()]
        [hashtable]$Palette = @{},

        [Parameter()]
        [switch]$InlineStyles,

        [Parameter()]
        [hashtable]$ChangeTrackingData = $null
    )

    $totalIdentities = $IdentityMap.Count
    $enumerated = @($GroupResults | Where-Object { $_.Data.Skipped -ne $true })
    $totalGroups = $enumerated.Count

    # Empty groups (zero members) produce no identities, so they are otherwise
    # invisible in this identity-centric report. Surface them by name -- an empty
    # group is itself a governance signal (a candidate for review/removal).
    $emptyGroupNames = @(
        $enumerated |
            Where-Object { @($_.Data.Members).Count -eq 0 } |
            ForEach-Object { "$($_.Data.Domain)\$($_.Data.GroupName)" }
    )
    $emptyGroupsNote = ''
    if ($emptyGroupNames.Count -gt 0) {
        $emptyList = Escape-GovernanceHtml ($emptyGroupNames -join ', ')
        $emptyGroupsNote = "<div style=""margin:8px 0 20px; padding:10px 14px; border-left:3px solid #FF8800; background:#fff8f0; font-size:12px; color:#555555;""><strong>Empty groups (no members):</strong> $emptyList</div>"
    }

    # Count identities with multiple group memberships
    $multiGroupCount = 0
    foreach ($key in $IdentityMap.Keys) {
        if ($IdentityMap[$key].Groups.Count -gt 1) { $multiGroupCount++ }
    }

    # Risk flag count (stale + disabled)
    $riskCount = 0
    if ($StaleResults) {
        if ($StaleResults.Disabled) { $riskCount += $StaleResults.Disabled.Count }
        if ($StaleResults.Stale)    { $riskCount += $StaleResults.Stale.Count }
    }

    # Changes count
    $changesCount = 0
    if ($ChangeTrackingData -and $ChangeTrackingData.Summary) {
        $changesCount = [int]$ChangeTrackingData.Summary.TotalAdded + [int]$ChangeTrackingData.Summary.TotalRemoved
    }

    if ($InlineStyles) {
        # Audit tier: table-based KPI cards
        $accentClr  = if ($Palette.accent -or $Palette.primary) { if ($Palette.accent) { $Palette.accent } else { $Palette.primary } } else { '#336699' }
        $successClr = if ($Palette.secondary) { $Palette.secondary } else { '#339933' }
        $dangerClr  = if ($Palette.danger) { $Palette.danger } else { '#CC3333' }
        $warningClr = if ($Palette.warning) { $Palette.warning } else { '#FF8800' }
        $borderClr  = if ($Palette.border) { $Palette.border } else { '#e0e0e0' }

        $cards = @(
            @{ Label = 'TOTAL IDENTITIES';     Value = $totalIdentities;  Color = $accentClr  }
            @{ Label = 'GROUPS MONITORED';      Value = $totalGroups;      Color = $accentClr  }
            @{ Label = 'MULTI-GROUP MEMBERS';   Value = $multiGroupCount;  Color = $warningClr }
            @{ Label = 'RISK FLAGS';            Value = $riskCount;        Color = if ($riskCount -gt 0) { $dangerClr } else { $successClr } }
        )

        $html = [System.Text.StringBuilder]::new()
        [void]$html.Append('<table cellpadding="0" cellspacing="0" border="0" style="width:100%; margin-bottom:20px;"><tr>')
        foreach ($card in $cards) {
            if ($script:ReportHelpersLoaded) {
                try {
                    [void]$html.Append((Build-SummaryCard -Label $card.Label -Value $card.Value -ColorHex $card.Color -Palette $Palette -InlineStyles))
                    continue
                }
                catch { }
            }
            [void]$html.Append(@"
<td style="padding:16px 20px; text-align:center; border:1px solid $borderClr; vertical-align:top; background:#ffffff; width:25%;">
    <div style="font-size:28px; font-weight:bold; color:$($card.Color); line-height:1.1;">$($card.Value)</div>
    <div style="font-size:11px; color:#777777; text-transform:uppercase; letter-spacing:0.5px; margin-top:6px;">$($card.Label)</div>
</td>
"@)
        }
        [void]$html.Append('</tr></table>')
        if ($emptyGroupsNote) { [void]$html.Append($emptyGroupsNote) }
        return $html.ToString()
    }
    else {
        # Executive tier: CSS-class-based KPI cards
        $cards = @(
            @{ Label = 'Total Groups';     Value = $totalGroups;      AccentClass = 'accent-primary' }
            @{ Label = 'Total Identities'; Value = $totalIdentities;  AccentClass = ''               }
            @{ Label = 'Changes';          Value = $changesCount;     AccentClass = 'accent-warning'  }
            @{ Label = 'Risk Score';        Value = $riskCount;        AccentClass = if ($riskCount -gt 0) { 'accent-danger' } else { '' } }
        )

        $lines = foreach ($card in $cards) {
            $accClass = if ($card.AccentClass) { " $($card.AccentClass)" } else { '' }
            @"
<div class="kpi-card$accClass">
    <div class="kpi-value">$($card.Value)</div>
    <div class="kpi-label">$($card.Label)</div>
</div>
"@
        }
        $cardsHtml = $lines -join "`n"
        if ($emptyGroupsNote) { $cardsHtml += "`n$emptyGroupsNote" }
        return $cardsHtml
    }
}

# ---------------------------------------------------------------------------
# Internal: Build-AccessCertificationHtml
# ---------------------------------------------------------------------------
function Build-AccessCertificationHtml {
    <#
    .SYNOPSIS
        Builds the access certification table (per-identity view).
        Sorted by group count descending (most entitled first).
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$IdentityMap,

        [Parameter()]
        [hashtable]$StaleResults = $null,

        [Parameter()]
        [hashtable]$Palette = @{}
    )

    if ($IdentityMap.Count -eq 0) {
        return '<p style="padding:12px; color:#777777; font-style:italic; text-align:center;">No identity data available.</p>'
    }

    # Build a lookup of stale/disabled SAMs for status determination
    $staleSet    = @{}
    $disabledSet = @{}
    if ($StaleResults) {
        if ($StaleResults.Stale) {
            foreach ($acct in $StaleResults.Stale) {
                $k = if ($acct.SamAccountName) { $acct.SamAccountName.ToLower() } else { '' }
                if ($k) { $staleSet[$k] = $true }
            }
        }
        if ($StaleResults.Disabled) {
            foreach ($acct in $StaleResults.Disabled) {
                $k = if ($acct.SamAccountName) { $acct.SamAccountName.ToLower() } else { '' }
                if ($k) { $disabledSet[$k] = $true }
            }
        }
    }

    # Sort identities by group count descending
    $sorted = $IdentityMap.GetEnumerator() | Sort-Object { $_.Value.Groups.Count } -Descending

    # Try ReportHelpers Build-HtmlTable
    if ($script:ReportHelpersLoaded) {
        try {
            $rows = [System.Collections.Generic.List[hashtable]]::new()
            foreach ($entry in $sorted) {
                $identity = $entry.Value.Identity
                $groups   = $entry.Value.Groups
                $samLower = if ($identity.SamAccountName) { $identity.SamAccountName.ToLower() } else { '' }

                $status = 'Active'
                if ($disabledSet.ContainsKey($samLower)) { $status = 'Disabled' }
                elseif ($staleSet.ContainsKey($samLower)) { $status = 'Stale' }
                elseif ($identity.Enabled -eq $false)     { $status = 'Disabled' }

                $groupNames = ($groups | ForEach-Object { "$($_.Domain)\$($_.GroupName)" }) -join ', '

                $rows.Add(@{
                    DisplayName    = if ($identity.DisplayName) { $identity.DisplayName } else { '' }
                    SamAccountName = if ($identity.SamAccountName) { $identity.SamAccountName } else { '' }
                    Email          = if ($identity.Email) { $identity.Email } else { '' }
                    Domain         = if ($identity.Domain) { $identity.Domain } else { '' }
                    Entitlements   = $groupNames
                    GroupCount     = $groups.Count
                    Status         = $status
                })
            }

            $statusMap = @{
                'Active'   = '#339933'
                'Stale'    = '#FF8800'
                'Disabled' = '#CC3333'
            }

            $formatter = {
                param($row, $col, $val)
                if ($col -eq 'Status') {
                    return Build-StatusBadge -Status ([string]$val) -StatusColorMap $statusMap -InlineStyles
                }
                return Escape-ReportHtml ([string]$val)
            }

            return Build-HtmlTable -Rows $rows `
                -Columns @('DisplayName', 'SamAccountName', 'Email', 'Domain', 'Entitlements', 'GroupCount', 'Status') `
                -Headers @('Identity', 'SAM Account', 'Email', 'Domain', 'Entitlements', 'Groups', 'Status') `
                -Palette $Palette `
                -InlineStyles `
                -RightAlignColumns @('GroupCount') `
                -CellFormatter $formatter
        }
        catch {
            # Fall through to manual table building
        }
    }

    # Manual table building for audit tier (inline CSS)
    $headerBg   = if ($Palette.headerBg)   { $Palette.headerBg }   else { '#34495e' }
    $headerText = if ($Palette.headerText) { $Palette.headerText } else { '#ffffff' }
    $borderClr  = if ($Palette.border)     { $Palette.border }     else { '#e0e0e0' }
    $rowAltClr  = if ($Palette.rowAlt)     { $Palette.rowAlt }     else { '#f9f9f9' }

    $html = [System.Text.StringBuilder]::new(4096)
    [void]$html.Append('<table cellpadding="0" cellspacing="0" border="0" style="width:100%; border-collapse:collapse; font-family:Arial,Helvetica,sans-serif; font-size:13px; margin-bottom:20px;">')

    # Header
    [void]$html.Append('<thead><tr>')
    $headers = @('Identity', 'SAM Account', 'Email', 'Domain', 'Entitlements', 'Groups', 'Status')
    foreach ($h in $headers) {
        $align = if ($h -eq 'Groups') { 'right' } else { 'left' }
        [void]$html.Append("<th style=""background:$headerBg; color:$headerText; padding:8px 10px; text-align:$align; font-size:13px;"">$h</th>")
    }
    [void]$html.Append('</tr></thead>')

    [void]$html.Append('<tbody>')
    $rowIdx = 0
    foreach ($entry in $sorted) {
        $identity = $entry.Value.Identity
        $groups   = $entry.Value.Groups

        $samLower = if ($identity.SamAccountName) { $identity.SamAccountName.ToLower() } else { '' }
        $status = 'Active'
        if ($disabledSet.ContainsKey($samLower)) { $status = 'Disabled' }
        elseif ($staleSet.ContainsKey($samLower)) { $status = 'Stale' }
        elseif ($identity.Enabled -eq $false)     { $status = 'Disabled' }

        $displayName = Escape-GovernanceHtml $(if ($identity.DisplayName) { $identity.DisplayName } else { '' })
        $sam         = Escape-GovernanceHtml $(if ($identity.SamAccountName) { $identity.SamAccountName } else { '' })
        $email       = Escape-GovernanceHtml $(if ($identity.Email) { $identity.Email } else { '' })
        $domain      = Escape-GovernanceHtml $(if ($identity.Domain) { $identity.Domain } else { '' })
        $groupNames  = Escape-GovernanceHtml (($groups | ForEach-Object { "$($_.Domain)\$($_.GroupName)" }) -join ', ')
        $groupCount  = $groups.Count
        $statusBadge = Get-GovernanceStatusBadge -Status $status -InlineStyles

        $isAlt    = (($rowIdx % 2) -eq 1)
        $rowStyle = if ($isAlt) { " style=""background:$rowAltClr;""" } else { '' }

        [void]$html.Append("<tr$rowStyle>")
        [void]$html.Append("<td style=""padding:8px 10px; border-bottom:1px solid $borderClr;"">$displayName</td>")
        [void]$html.Append("<td style=""padding:8px 10px; border-bottom:1px solid $borderClr;"">$sam</td>")
        [void]$html.Append("<td style=""padding:8px 10px; border-bottom:1px solid $borderClr;"">$email</td>")
        [void]$html.Append("<td style=""padding:8px 10px; border-bottom:1px solid $borderClr;"">$domain</td>")
        [void]$html.Append("<td style=""padding:8px 10px; border-bottom:1px solid $borderClr;"">$groupNames</td>")
        [void]$html.Append("<td style=""padding:8px 10px; border-bottom:1px solid $borderClr; text-align:right;"">$groupCount</td>")
        [void]$html.Append("<td style=""padding:8px 10px; border-bottom:1px solid $borderClr;"">$statusBadge</td>")
        [void]$html.Append('</tr>')

        $rowIdx++
    }
    [void]$html.Append('</tbody></table>')

    return $html.ToString()
}

# ---------------------------------------------------------------------------
# Internal: Build-IdentityEntitlementDetailsHtml
# ---------------------------------------------------------------------------
function Build-IdentityEntitlementDetailsHtml {
    <#
    .SYNOPSIS
        Per-identity detail sections for identities meeting the group threshold.
    .DESCRIPTION
        Shows detailed per-group breakdown for identities whose group membership
        count meets or exceeds the threshold. Default threshold is 3, configurable
        via the -Threshold parameter or config key Reporting.IdentityDetailThreshold.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$IdentityMap,

        [Parameter()]
        [hashtable]$Palette = @{},

        [Parameter()]
        [int]$Threshold = 3
    )

    if ($Threshold -lt 1) { $Threshold = 1 }

    # Filter to identities meeting the threshold
    $highEntitlement = $IdentityMap.GetEnumerator() |
        Where-Object { $_.Value.Groups.Count -ge $Threshold } |
        Sort-Object { $_.Value.Groups.Count } -Descending

    if (-not $highEntitlement -or @($highEntitlement).Count -eq 0) {
        return "<p style=""padding:12px; color:#777777; font-style:italic; text-align:center;"">No identities with $Threshold or more group memberships.</p>"
    }

    $headerBg   = if ($Palette.headerBg)   { $Palette.headerBg }   else { '#34495e' }
    $headerText = if ($Palette.headerText) { $Palette.headerText } else { '#ffffff' }
    $borderClr  = if ($Palette.border)     { $Palette.border }     else { '#e0e0e0' }
    $accentClr  = if ($Palette.accent -or $Palette.primary) { if ($Palette.accent) { $Palette.accent } else { $Palette.primary } } else { '#336699' }
    $rowAltClr  = if ($Palette.rowAlt)     { $Palette.rowAlt }     else { '#f9f9f9' }

    $sections = [System.Text.StringBuilder]::new(4096)

    foreach ($entry in $highEntitlement) {
        $identity = $entry.Value.Identity
        $groups   = $entry.Value.Groups

        $displayName = Escape-GovernanceHtml $(if ($identity.DisplayName) { $identity.DisplayName } else { $identity.SamAccountName })
        $domain      = Escape-GovernanceHtml $(if ($identity.Domain) { $identity.Domain } else { '' })
        $sam         = Escape-GovernanceHtml $(if ($identity.SamAccountName) { $identity.SamAccountName } else { '' })

        [void]$sections.Append("<h3 style=""font-family:Arial,Helvetica,sans-serif; color:$accentClr; margin-top:18px; margin-bottom:8px; font-size:14px;"">$displayName ($sam) - $domain</h3>")

        [void]$sections.Append('<table cellpadding="0" cellspacing="0" border="0" style="width:100%; border-collapse:collapse; font-family:Arial,Helvetica,sans-serif; font-size:13px; margin-bottom:16px;">')
        [void]$sections.Append('<thead><tr>')
        [void]$sections.Append("<th style=""background:$headerBg; color:$headerText; padding:8px 10px; text-align:left; font-size:13px;"">Group Name</th>")
        [void]$sections.Append("<th style=""background:$headerBg; color:$headerText; padding:8px 10px; text-align:left; font-size:13px;"">Domain</th>")
        [void]$sections.Append("<th style=""background:$headerBg; color:$headerText; padding:8px 10px; text-align:right; font-size:13px;"">Member Count</th>")
        [void]$sections.Append('</tr></thead><tbody>')

        $rowIdx = 0
        foreach ($g in ($groups | Sort-Object { $_.GroupName })) {
            $gName  = Escape-GovernanceHtml $(if ($g.GroupName) { $g.GroupName } else { '' })
            $gDomain = Escape-GovernanceHtml $(if ($g.Domain) { $g.Domain } else { '' })
            $gCount  = if ($null -ne $g.MemberCount) { [int]$g.MemberCount } else { 0 }

            $isAlt    = (($rowIdx % 2) -eq 1)
            $rowStyle = if ($isAlt) { " style=""background:$rowAltClr;""" } else { '' }

            [void]$sections.Append("<tr$rowStyle>")
            [void]$sections.Append("<td style=""padding:8px 10px; border-bottom:1px solid $borderClr;"">$gName</td>")
            [void]$sections.Append("<td style=""padding:8px 10px; border-bottom:1px solid $borderClr;"">$gDomain</td>")
            [void]$sections.Append("<td style=""padding:8px 10px; border-bottom:1px solid $borderClr; text-align:right;"">$gCount</td>")
            [void]$sections.Append('</tr>')
            $rowIdx++
        }

        [void]$sections.Append('</tbody></table>')
    }

    return $sections.ToString()
}

# ---------------------------------------------------------------------------
# Internal: Build-RiskFlagSummaryHtml
# ---------------------------------------------------------------------------
function Build-RiskFlagSummaryHtml {
    <#
    .SYNOPSIS
        Risk flags section: stale accounts, disabled accounts tables.
        Inline CSS for audit tier.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [array]$GroupResults,

        [Parameter()]
        [hashtable]$StaleResults = $null,

        [Parameter()]
        [hashtable]$Palette = @{},

        [Parameter()]
        [hashtable]$IdentityMap = $null
    )

    if (-not $StaleResults) {
        return '<p style="padding:12px; color:#777777; font-style:italic; text-align:center;">No stale account data available.</p>'
    }

    $disabled = if ($StaleResults.Disabled) { @($StaleResults.Disabled) } else { @() }
    $stale    = if ($StaleResults.Stale)    { @($StaleResults.Stale)    } else { @() }

    if ($disabled.Count -eq 0 -and $stale.Count -eq 0) {
        return '<p style="padding:12px; color:#339933; text-align:center; font-weight:bold;">No risk flags detected. All accounts are active.</p>'
    }

    $headerBg   = if ($Palette.headerBg)   { $Palette.headerBg }   else { '#34495e' }
    $headerText = if ($Palette.headerText) { $Palette.headerText } else { '#ffffff' }
    $borderClr  = if ($Palette.border)     { $Palette.border }     else { '#e0e0e0' }
    $rowAltClr  = if ($Palette.rowAlt)     { $Palette.rowAlt }     else { '#f9f9f9' }
    $dangerClr  = if ($Palette.danger)     { $Palette.danger }     else { '#CC3333' }
    $warningClr = if ($Palette.warning)    { $Palette.warning }    else { '#FF8800' }

    # Use pre-built identity map if provided; otherwise build one
    if (-not $IdentityMap) {
        $IdentityMap = Build-IdentityEntitlementMap -GroupResults $GroupResults
    }
    $identityMap = $IdentityMap

    $html = [System.Text.StringBuilder]::new(2048)

    # Combined risk flags table
    [void]$html.Append('<table cellpadding="0" cellspacing="0" border="0" style="width:100%; border-collapse:collapse; font-family:Arial,Helvetica,sans-serif; font-size:13px; margin-bottom:20px;">')
    [void]$html.Append('<thead><tr>')
    foreach ($h in @('Identity', 'Domain', 'Groups', 'Days Since Logon', 'Status', 'Action Required')) {
        [void]$html.Append("<th style=""background:$headerBg; color:$headerText; padding:8px 10px; text-align:left; font-size:13px;"">$h</th>")
    }
    [void]$html.Append('</tr></thead><tbody>')

    $rowIdx = 0

    # Disabled accounts (red)
    foreach ($acct in $disabled) {
        $sam    = if ($acct.SamAccountName) { [string]$acct.SamAccountName } else { '' }
        $domain = if ($acct.Domain)         { [string]$acct.Domain }         else { '' }
        $key    = "$domain|$($sam.ToLower())"

        $groupList = ''
        if ($identityMap.ContainsKey($key)) {
            $groupList = ($identityMap[$key].Groups | ForEach-Object { "$($_.Domain)\$($_.GroupName)" }) -join ', '
        }

        $isAlt    = (($rowIdx % 2) -eq 1)
        $rowBg    = "background:rgba(204,51,51,0.06);"
        if ($isAlt) { $rowBg = "background:rgba(204,51,51,0.10);" }

        $statusBadge = Get-GovernanceStatusBadge -Status 'Disabled' -InlineStyles

        [void]$html.Append("<tr style=""$rowBg"">")
        [void]$html.Append("<td style=""padding:8px 10px; border-bottom:1px solid $borderClr;"">$(Escape-GovernanceHtml $sam)</td>")
        [void]$html.Append("<td style=""padding:8px 10px; border-bottom:1px solid $borderClr;"">$(Escape-GovernanceHtml $domain)</td>")
        [void]$html.Append("<td style=""padding:8px 10px; border-bottom:1px solid $borderClr;"">$(Escape-GovernanceHtml $groupList)</td>")
        [void]$html.Append("<td style=""padding:8px 10px; border-bottom:1px solid $borderClr;"">N/A</td>")
        [void]$html.Append("<td style=""padding:8px 10px; border-bottom:1px solid $borderClr;"">$statusBadge</td>")
        [void]$html.Append("<td style=""padding:8px 10px; border-bottom:1px solid $borderClr;"">Remove from groups</td>")
        [void]$html.Append('</tr>')
        $rowIdx++
    }

    # Stale accounts (orange)
    foreach ($acct in $stale) {
        $sam       = if ($acct.SamAccountName)   { [string]$acct.SamAccountName }   else { '' }
        $domain    = if ($acct.Domain)           { [string]$acct.Domain }           else { '' }
        $daysSince = if ($null -ne $acct.DaysSinceLogon) { [string][int]$acct.DaysSinceLogon } else { 'Unknown' }
        $key       = "$domain|$($sam.ToLower())"

        $groupList = ''
        if ($identityMap.ContainsKey($key)) {
            $groupList = ($identityMap[$key].Groups | ForEach-Object { "$($_.Domain)\$($_.GroupName)" }) -join ', '
        }

        $isAlt = (($rowIdx % 2) -eq 1)
        $rowBg = "background:rgba(255,136,0,0.06);"
        if ($isAlt) { $rowBg = "background:rgba(255,136,0,0.10);" }

        $statusBadge = Get-GovernanceStatusBadge -Status 'Stale' -InlineStyles

        [void]$html.Append("<tr style=""$rowBg"">")
        [void]$html.Append("<td style=""padding:8px 10px; border-bottom:1px solid $borderClr;"">$(Escape-GovernanceHtml $sam)</td>")
        [void]$html.Append("<td style=""padding:8px 10px; border-bottom:1px solid $borderClr;"">$(Escape-GovernanceHtml $domain)</td>")
        [void]$html.Append("<td style=""padding:8px 10px; border-bottom:1px solid $borderClr;"">$(Escape-GovernanceHtml $groupList)</td>")
        [void]$html.Append("<td style=""padding:8px 10px; border-bottom:1px solid $borderClr;"">$(Escape-GovernanceHtml $daysSince)</td>")
        [void]$html.Append("<td style=""padding:8px 10px; border-bottom:1px solid $borderClr;"">$statusBadge</td>")
        [void]$html.Append("<td style=""padding:8px 10px; border-bottom:1px solid $borderClr;"">Review access</td>")
        [void]$html.Append('</tr>')
        $rowIdx++
    }

    [void]$html.Append('</tbody></table>')

    # Recommendation
    $totalRisk = $disabled.Count + $stale.Count
    [void]$html.Append("<p style=""background:rgba(255,136,0,0.08); border:1px solid rgba(255,136,0,0.3); border-radius:4px; padding:12px 16px; font-size:13px; color:$warningClr; margin-top:12px;"">$totalRisk accounts flagged for review. Disabled accounts should be removed from group memberships. Stale accounts require access recertification.</p>")

    return $html.ToString()
}

# ---------------------------------------------------------------------------
# Internal: Build-ChangeHistorySummaryHtml
# ---------------------------------------------------------------------------
function Build-ChangeHistorySummaryHtml {
    <#
    .SYNOPSIS
        Recent adds/removes summary table from change tracking data.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter()]
        [hashtable]$ChangeTrackingData = $null,

        [Parameter()]
        [hashtable]$Palette = @{}
    )

    if (-not $ChangeTrackingData -or -not $ChangeTrackingData.Changes -or $ChangeTrackingData.Changes.Count -eq 0) {
        return '<p style="padding:12px; color:#777777; font-style:italic; text-align:center;">No change tracking data available. Run with -TrackChanges to enable membership drift detection.</p>'
    }

    $changes = @($ChangeTrackingData.Changes)
    $summary = $ChangeTrackingData.Summary
    $added   = if ($null -ne $summary.TotalAdded)   { [int]$summary.TotalAdded }   else { 0 }
    $removed = if ($null -ne $summary.TotalRemoved) { [int]$summary.TotalRemoved } else { 0 }

    $headerBg   = if ($Palette.headerBg)   { $Palette.headerBg }   else { '#34495e' }
    $headerText = if ($Palette.headerText) { $Palette.headerText } else { '#ffffff' }
    $borderClr  = if ($Palette.border)     { $Palette.border }     else { '#e0e0e0' }
    $rowAltClr  = if ($Palette.rowAlt)     { $Palette.rowAlt }     else { '#f9f9f9' }
    $successClr = if ($Palette.secondary)  { $Palette.secondary }  else { '#339933' }
    $dangerClr  = if ($Palette.danger)     { $Palette.danger }     else { '#CC3333' }

    $html = [System.Text.StringBuilder]::new(2048)

    # Summary line
    [void]$html.Append("<p style=""font-family:Arial,Helvetica,sans-serif; font-size:14px; margin-bottom:12px;"">")
    [void]$html.Append("<span style=""color:$successClr; font-weight:bold;"">$added Added</span>")
    [void]$html.Append(" &nbsp;|&nbsp; ")
    [void]$html.Append("<span style=""color:$dangerClr; font-weight:bold;"">$removed Removed</span>")
    [void]$html.Append(" since last run</p>")

    # Changes table
    [void]$html.Append('<table cellpadding="0" cellspacing="0" border="0" style="width:100%; border-collapse:collapse; font-family:Arial,Helvetica,sans-serif; font-size:13px; margin-bottom:20px;">')
    [void]$html.Append('<thead><tr>')
    foreach ($h in @('Timestamp', 'Identity', 'Group', 'Domain', 'Action')) {
        [void]$html.Append("<th style=""background:$headerBg; color:$headerText; padding:8px 10px; text-align:left; font-size:13px;"">$h</th>")
    }
    [void]$html.Append('</tr></thead><tbody>')

    $rowIdx = 0
    foreach ($change in $changes) {
        $ts     = Escape-GovernanceHtml $(if ($change.Timestamp) { $change.Timestamp } else { '' })
        $sam    = Escape-GovernanceHtml $(if ($change.SamAccountName) { $change.SamAccountName } else { '' })
        $group  = Escape-GovernanceHtml $(if ($change.GroupName) { $change.GroupName } else { '' })
        $domain = Escape-GovernanceHtml $(if ($change.Domain) { $change.Domain } else { '' })
        $action = if ($change.Action) { [string]$change.Action } else { '' }

        $actionColor = if ($action -eq 'Added') { $successClr } else { $dangerClr }
        $actionBadge = "<span style=""display:inline-block; padding:2px 10px; border-radius:99px; font-size:12px; font-weight:bold; background-color:$actionColor; color:#ffffff;"">$(Escape-GovernanceHtml $action)</span>"

        $isAlt    = (($rowIdx % 2) -eq 1)
        $rowStyle = if ($isAlt) { " style=""background:$rowAltClr;""" } else { '' }

        [void]$html.Append("<tr$rowStyle>")
        [void]$html.Append("<td style=""padding:8px 10px; border-bottom:1px solid $borderClr;"">$ts</td>")
        [void]$html.Append("<td style=""padding:8px 10px; border-bottom:1px solid $borderClr;"">$sam</td>")
        [void]$html.Append("<td style=""padding:8px 10px; border-bottom:1px solid $borderClr;"">$group</td>")
        [void]$html.Append("<td style=""padding:8px 10px; border-bottom:1px solid $borderClr;"">$domain</td>")
        [void]$html.Append("<td style=""padding:8px 10px; border-bottom:1px solid $borderClr;"">$actionBadge</td>")
        [void]$html.Append('</tr>')
        $rowIdx++
    }

    [void]$html.Append('</tbody></table>')

    return $html.ToString()
}

# ---------------------------------------------------------------------------
# Internal: Build-ComplianceTimelineHtml
# ---------------------------------------------------------------------------
function Build-ComplianceTimelineHtml {
    <#
    .SYNOPSIS
        Shows when each identity's access was first/last observed from change tracking.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter()]
        [hashtable]$ChangeTrackingData = $null,

        [Parameter()]
        [hashtable]$Palette = @{}
    )

    if (-not $ChangeTrackingData -or -not $ChangeTrackingData.Changes -or $ChangeTrackingData.Changes.Count -eq 0) {
        return '<p style="padding:12px; color:#777777; font-style:italic; text-align:center;">No compliance timeline data available.</p>'
    }

    $changes = @($ChangeTrackingData.Changes)

    # Build per-identity timeline from change events
    $timeline = @{}
    foreach ($change in $changes) {
        $sam = if ($change.SamAccountName) { $change.SamAccountName } else { continue }
        $ts  = if ($change.Timestamp) { [string]$change.Timestamp } else { '' }
        $group = if ($change.GroupName) { $change.GroupName } else { '' }

        # Parse for CHRONOLOGICAL comparison; raw string -lt/-gt is lexical and
        # wrong for mixed timestamp formats / timezone offsets.
        $tsDate = [datetime]::MinValue
        $tsOk = [datetime]::TryParse($ts, [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::None, [ref]$tsDate)

        $key = $sam.ToLower()
        if (-not $timeline.ContainsKey($key)) {
            $timeline[$key] = @{
                SamAccountName = $sam
                FirstSeen      = $ts
                LastSeen       = $ts
                FirstSeenDt    = $(if ($tsOk) { $tsDate } else { [datetime]::MaxValue })
                LastSeenDt     = $(if ($tsOk) { $tsDate } else { [datetime]::MinValue })
                Groups         = [System.Collections.Generic.HashSet[string]]::new()
            }
        }

        # Update first/last seen by parsed date (keep the original string for display)
        if ($tsOk -and $tsDate -lt $timeline[$key].FirstSeenDt) { $timeline[$key].FirstSeen = $ts; $timeline[$key].FirstSeenDt = $tsDate }
        if ($tsOk -and $tsDate -gt $timeline[$key].LastSeenDt)  { $timeline[$key].LastSeen  = $ts; $timeline[$key].LastSeenDt  = $tsDate }
        if ($group) { [void]$timeline[$key].Groups.Add($group) }
    }

    if ($timeline.Count -eq 0) {
        return '<p style="padding:12px; color:#777777; font-style:italic; text-align:center;">No timeline entries found.</p>'
    }

    $headerBg   = if ($Palette.headerBg)   { $Palette.headerBg }   else { '#34495e' }
    $headerText = if ($Palette.headerText) { $Palette.headerText } else { '#ffffff' }
    $borderClr  = if ($Palette.border)     { $Palette.border }     else { '#e0e0e0' }
    $rowAltClr  = if ($Palette.rowAlt)     { $Palette.rowAlt }     else { '#f9f9f9' }

    $html = [System.Text.StringBuilder]::new(2048)

    [void]$html.Append('<table cellpadding="0" cellspacing="0" border="0" style="width:100%; border-collapse:collapse; font-family:Arial,Helvetica,sans-serif; font-size:13px; margin-bottom:20px;">')
    [void]$html.Append('<thead><tr>')
    foreach ($h in @('Identity', 'First Seen', 'Last Seen', 'Groups')) {
        [void]$html.Append("<th style=""background:$headerBg; color:$headerText; padding:8px 10px; text-align:left; font-size:13px;"">$h</th>")
    }
    [void]$html.Append('</tr></thead><tbody>')

    $rowIdx = 0
    foreach ($entry in ($timeline.Values | Sort-Object { $_.SamAccountName })) {
        $sam       = Escape-GovernanceHtml $entry.SamAccountName
        $firstSeen = Escape-GovernanceHtml $entry.FirstSeen
        $lastSeen  = Escape-GovernanceHtml $entry.LastSeen
        $groupList = Escape-GovernanceHtml ($entry.Groups -join ', ')

        $isAlt    = (($rowIdx % 2) -eq 1)
        $rowStyle = if ($isAlt) { " style=""background:$rowAltClr;""" } else { '' }

        [void]$html.Append("<tr$rowStyle>")
        [void]$html.Append("<td style=""padding:8px 10px; border-bottom:1px solid $borderClr;"">$sam</td>")
        [void]$html.Append("<td style=""padding:8px 10px; border-bottom:1px solid $borderClr;"">$firstSeen</td>")
        [void]$html.Append("<td style=""padding:8px 10px; border-bottom:1px solid $borderClr;"">$lastSeen</td>")
        [void]$html.Append("<td style=""padding:8px 10px; border-bottom:1px solid $borderClr;"">$groupList</td>")
        [void]$html.Append('</tr>')
        $rowIdx++
    }

    [void]$html.Append('</tbody></table>')

    return $html.ToString()
}

# ---------------------------------------------------------------------------
# Internal: Build-ExecutiveChartsHtml
# ---------------------------------------------------------------------------
function Build-ExecutiveChartsHtml {
    <#
    .SYNOPSIS
        SVG donut charts for the executive dashboard.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [array]$GroupResults,

        [Parameter()]
        [hashtable]$StaleResults = $null,

        [Parameter()]
        [hashtable]$ChangeTrackingData = $null,

        [Parameter()]
        [hashtable]$IdentityMap = $null
    )

    # Use pre-built identity map if provided; otherwise build one
    if (-not $IdentityMap) {
        $IdentityMap = Build-IdentityEntitlementMap -GroupResults $GroupResults
    }
    $identityMap = $IdentityMap
    $totalIdentities = $identityMap.Count

    # Calculate health segments based on stale/disabled ratios
    $healthyCount  = $totalIdentities
    $atRiskCount   = 0
    $criticalCount = 0

    if ($StaleResults) {
        $staleCount    = if ($StaleResults.Stale)    { $StaleResults.Stale.Count }    else { 0 }
        $disabledCount = if ($StaleResults.Disabled) { $StaleResults.Disabled.Count } else { 0 }
        $atRiskCount   = $staleCount
        $criticalCount = $disabledCount
        $healthyCount  = [Math]::Max(0, $totalIdentities - $atRiskCount - $criticalCount)
    }

    $segments = @(
        @{ Label = 'Healthy';  Value = $healthyCount;  Color = '#2CA58D' }
        @{ Label = 'At Risk';  Value = $atRiskCount;   Color = '#F39C12' }
        @{ Label = 'Critical'; Value = $criticalCount; Color = '#E74C3C' }
    )

    $healthPct = if ($totalIdentities -gt 0) {
        [Math]::Round(($healthyCount / $totalIdentities) * 100)
    } else { 100 }

    $donutHtml = ''
    if ($script:ReportHelpersLoaded) {
        try {
            $donutHtml = Build-DonutChart -Segments $segments -Size 160 -CenterText "${healthPct}%" -StrokeWidth 24
        }
        catch { }
    }

    if (-not $donutHtml) {
        # Manual SVG donut
        $donutHtml = Build-ManualDonutSvg -Segments $segments -Size 160 -CenterText "${healthPct}%" -StrokeWidth 24
    }

    $html = [System.Text.StringBuilder]::new(1024)

    # Group Health donut
    [void]$html.Append('<div class="chart-container">')
    [void]$html.Append('<h3>Identity Health</h3>')
    [void]$html.Append($donutHtml)
    [void]$html.Append('</div>')

    # Group Size Distribution donut
    $enumerated = @($GroupResults | Where-Object { $_.Data.Skipped -ne $true })
    $smallGroups  = @($enumerated | Where-Object { [int]$_.Data.MemberCount -le 10 }).Count
    $mediumGroups = @($enumerated | Where-Object { [int]$_.Data.MemberCount -gt 10 -and [int]$_.Data.MemberCount -le 50 }).Count
    $largeGroups  = @($enumerated | Where-Object { [int]$_.Data.MemberCount -gt 50 }).Count

    $sizeSegments = @(
        @{ Label = 'Small (1-10)';  Value = $smallGroups;  Color = '#2CA58D' }
        @{ Label = 'Medium (11-50)'; Value = $mediumGroups; Color = '#F39C12' }
        @{ Label = 'Large (50+)';   Value = $largeGroups;  Color = '#1B2A4A' }
    )

    $sizeDonutHtml = ''
    if ($script:ReportHelpersLoaded) {
        try {
            $sizeDonutHtml = Build-DonutChart -Segments $sizeSegments -Size 160 -CenterText "$($enumerated.Count)" -StrokeWidth 24
        }
        catch { }
    }

    if (-not $sizeDonutHtml) {
        $sizeDonutHtml = Build-ManualDonutSvg -Segments $sizeSegments -Size 160 -CenterText "$($enumerated.Count)" -StrokeWidth 24
    }

    [void]$html.Append('<div class="chart-container">')
    [void]$html.Append('<h3>Group Size Distribution</h3>')
    [void]$html.Append($sizeDonutHtml)
    [void]$html.Append('</div>')

    return $html.ToString()
}

# ---------------------------------------------------------------------------
# Internal: Build-ManualDonutSvg
# ---------------------------------------------------------------------------
function Build-ManualDonutSvg {
    <#
    .SYNOPSIS
        Fallback SVG donut chart when ReportHelpers is not available.
    #>
    param(
        [hashtable[]]$Segments,
        [int]$Size = 160,
        [string]$CenterText = '',
        [int]$StrokeWidth = 24
    )

    $halfSize      = $Size / 2
    $radius        = ($Size - $StrokeWidth) / 2
    $circumference = 2 * [Math]::PI * $radius

    $total = 0
    foreach ($seg in $Segments) { $total += [double]$seg.Value }

    if ($total -le 0) {
        return "<svg width=""$Size"" height=""$Size"" viewBox=""0 0 $Size $Size""><circle cx=""$halfSize"" cy=""$halfSize"" r=""$radius"" fill=""none"" stroke=""#e0e0e0"" stroke-width=""$StrokeWidth""/></svg>"
    }

    $svg = [System.Text.StringBuilder]::new(1024)
    [void]$svg.Append("<div style=""display:inline-block; vertical-align:top;"">")
    [void]$svg.Append("<svg width=""$Size"" height=""$Size"" viewBox=""0 0 $Size $Size"" style=""transform:rotate(-90deg);"">")

    $offset = 0
    foreach ($seg in $Segments) {
        $segValue  = [double]$seg.Value
        if ($segValue -le 0) { continue }
        $segColor  = if ($seg.Color) { $seg.Color } else { '#cccccc' }
        $segLength = ($segValue / $total) * $circumference
        $gapLength = $circumference - $segLength

        $dashArray  = "$([Math]::Round($segLength, 2)) $([Math]::Round($gapLength, 2))"
        $dashOffset = [Math]::Round(-$offset, 2)

        [void]$svg.Append("<circle cx=""$halfSize"" cy=""$halfSize"" r=""$radius"" fill=""none"" stroke=""$segColor"" stroke-width=""$StrokeWidth"" stroke-dasharray=""$dashArray"" stroke-dashoffset=""$dashOffset""/>")
        $offset += $segLength
    }

    if ($CenterText) {
        $escapedCenter = Escape-GovernanceHtml $CenterText
        [void]$svg.Append("<g style=""transform:rotate(90deg); transform-origin:center;""><text x=""$halfSize"" y=""$halfSize"" text-anchor=""middle"" dominant-baseline=""central"" font-family=""Arial,Helvetica,sans-serif"" font-size=""18"" font-weight=""bold"" fill=""#333333"">$escapedCenter</text></g>")
    }

    [void]$svg.Append('</svg>')
    [void]$svg.Append('</div>')

    # Legend
    [void]$svg.Append('<div style="display:inline-block; vertical-align:top; margin-left:12px; font-size:12px; line-height:1.8;">')
    foreach ($seg in $Segments) {
        $segColor = if ($seg.Color) { $seg.Color } else { '#cccccc' }
        $segLabel = Escape-GovernanceHtml ([string]$seg.Label)
        $segValue = Escape-GovernanceHtml ([string]$seg.Value)
        [void]$svg.Append("<div><span style=""display:inline-block; width:12px; height:12px; background:$segColor; border-radius:2px; margin-right:6px; vertical-align:middle;""></span>$segLabel ($segValue)</div>")
    }
    [void]$svg.Append('</div>')

    return $svg.ToString()
}

# ---------------------------------------------------------------------------
# Internal: Build-DomainStatusTableHtml
# ---------------------------------------------------------------------------
function Build-DomainStatusTableHtml {
    <#
    .SYNOPSIS
        Per-domain summary table for the executive dashboard.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [array]$GroupResults,

        [Parameter()]
        [hashtable]$Palette = @{}
    )

    $enumerated = @($GroupResults | Where-Object { $_.Data.Skipped -ne $true })
    $domains = @($enumerated | ForEach-Object { $_.Data.Domain } | Sort-Object -Unique)

    if ($domains.Count -eq 0) {
        return '<p style="padding:12px; color:#8B8680; font-style:italic; text-align:center;">No domain data available.</p>'
    }

    $rows = [System.Collections.Generic.List[hashtable]]::new()
    foreach ($d in $domains) {
        $domainResults = @($enumerated | Where-Object { $_.Data.Domain -eq $d })
        $groupCount    = $domainResults.Count
        $memberTotal   = 0
        foreach ($gr in $domainResults) {
            if ($null -ne $gr.Data.MemberCount) { $memberTotal += [int]$gr.Data.MemberCount }
        }
        $avgMembers = if ($groupCount -gt 0) { [Math]::Round($memberTotal / $groupCount, 1) } else { 0 }

        $rows.Add(@{
            Domain       = $d
            Groups       = $groupCount
            TotalMembers = $memberTotal
            AvgMembers   = $avgMembers
        })
    }

    # Try ReportHelpers
    if ($script:ReportHelpersLoaded) {
        try {
            return Build-HtmlTable -Rows $rows `
                -Columns @('Domain', 'Groups', 'TotalMembers', 'AvgMembers') `
                -Headers @('Domain', 'Groups', 'Total Members', 'Avg Members/Group') `
                -Palette $Palette `
                -RightAlignColumns @('Groups', 'TotalMembers', 'AvgMembers') `
                -Sortable
        }
        catch { }
    }

    # Fallback: manual table (executive tier uses CSS classes)
    $html = [System.Text.StringBuilder]::new(1024)
    [void]$html.Append('<table><thead><tr>')
    [void]$html.Append('<th>Domain</th><th>Groups</th><th>Total Members</th><th>Avg Members/Group</th>')
    [void]$html.Append('</tr></thead><tbody>')

    foreach ($row in $rows) {
        $d = Escape-GovernanceHtml $row.Domain
        [void]$html.Append("<tr><td>$d</td><td class=""text-right"">$($row.Groups)</td><td class=""text-right"">$($row.TotalMembers)</td><td class=""text-right"">$($row.AvgMembers)</td></tr>")
    }

    [void]$html.Append('</tbody></table>')

    return $html.ToString()
}
