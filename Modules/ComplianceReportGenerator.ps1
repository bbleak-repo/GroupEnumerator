<#
.SYNOPSIS
    Compliance audit report and leadership summary generation module.

.DESCRIPTION
    Generates two report types for the Group Enumerator tool:
      - Compliance Audit Report (Tier 3 - Audit): inline CSS, table-based,
        Word-compatible. Point-in-time audit evidence with change tracking,
        drift analysis, and reviewer sign-off sections.
      - Leadership Summary (Tier 5 - Leadership): inline CSS, 1-page,
        print/PDF optimized. Director-level rollup with KPI metrics and
        action items.

    Both reports follow the GovernanceToolkit visual style:
      - All inline CSS (no <style> blocks, no <script>)
      - Table-based layout for Word copy-paste compatibility
      - Font: Arial, Helvetica, sans-serif
      - Color palette: Blue #336699, Green #339933, Red #CC3333,
        Orange #FF8800, Gray #777777
      - Headers: #34495e background, white text
      - Alternating rows: #f9f9f9

.NOTES
    HTML escaping: manual replacement of &, <, >, ", ' (no System.Web dependency)
    File writes use UTF-8 without BOM via [System.IO.File]::WriteAllText
    Template path resolved at dot-source time via $PSScriptRoot
    No emoji in PowerShell code (per project conventions)
#>

# ---- Tool version constant ----
$script:ComplianceReportVersion = '3.0.0'

# ---- Resolve template paths at load time ----
$script:ComplianceReportModuleDir   = $PSScriptRoot
$script:ComplianceReportProjectRoot = Split-Path -Parent $script:ComplianceReportModuleDir
$script:ComplianceTemplatePath      = Join-Path (Join-Path $script:ComplianceReportProjectRoot 'Templates') 'compliance-report-template.html'
$script:LeadershipTemplatePath      = Join-Path (Join-Path $script:ComplianceReportProjectRoot 'Templates') 'leadership-summary-template.html'

# ---- Attempt to load ReportHelpers framework ----
# Note: this module uses inline CSS for Word compatibility and does NOT depend
# on ReportHelpers at runtime. The import is best-effort for potential future use.
try {
    $helpersPath = Join-Path $PSScriptRoot '..\..\..\.claude-frameworks\report-framework\helpers\ReportHelpers.psm1'
    if (-not (Test-Path $helpersPath)) {
        # Try environment variable fallback
        $envPath = $env:REPORT_HELPERS_PATH
        if ($envPath -and (Test-Path $envPath)) {
            $helpersPath = $envPath
        }
    }
    if (Test-Path $helpersPath) {
        Import-Module $helpersPath -Force -ErrorAction SilentlyContinue
    }
} catch {
    # ReportHelpers not available; compliance module uses all-inline CSS
}

# ---- Default palette (audit tier from GovernanceToolkit) ----
$script:AuditPalette = @{
    primary    = '#336699'
    secondary  = '#339933'
    danger     = '#CC3333'
    warning    = '#FF8800'
    muted      = '#777777'
    background = '#f0f2f5'
    surface    = '#ffffff'
    text       = '#333333'
    border     = '#e0e0e0'
    headerBg   = '#34495e'
    headerText = '#ffffff'
    rowAlt     = '#f9f9f9'
    accent     = '#336699'
}

$script:LeadershipPalette = @{
    primary    = '#336699'
    secondary  = '#339933'
    danger     = '#CC3333'
    warning    = '#FF8800'
    muted      = '#999999'
    background = '#ffffff'
    surface    = '#ffffff'
    text       = '#333333'
    border     = '#dddddd'
    headerBg   = '#336699'
    headerText = '#ffffff'
    rowAlt     = '#f5f5f5'
    accent     = '#336699'
}

# ---------------------------------------------------------------------------
# Internal: Escape-ComplianceHtml
# ---------------------------------------------------------------------------
function Escape-ComplianceHtml {
    <#
    .SYNOPSIS
        HTML-encodes a string without requiring System.Web.
    #>
    param([string]$Text)
    if (-not $Text) { return '' }
    $Text = $Text.Replace('&', '&amp;')
    $Text = $Text.Replace('<', '&lt;')
    $Text = $Text.Replace('>', '&gt;')
    $Text = $Text.Replace('"', '&quot;')
    $Text = $Text.Replace("'", '&#39;')
    return $Text
}

# ---------------------------------------------------------------------------
# Public: Export-ComplianceReport
# ---------------------------------------------------------------------------
function Export-ComplianceReport {
    <#
    .SYNOPSIS
        Generates an HTML compliance audit report with point-in-time evidence.

    .DESCRIPTION
        Audit Tier report: all inline CSS, no JavaScript, Word-compatible.
        Includes group membership snapshots, change log, drift analysis,
        remediation status, and reviewer sign-off sections.

    .PARAMETER GroupResults
        Array of group result hashtables from Get-GroupMembers.
        Each element: @{ Data = @{ GroupName; Domain; Members; MemberCount; Skipped; SkipReason }; Errors = @() }

    .PARAMETER OutputPath
        Full file path for the output HTML file.

    .PARAMETER StaleResults
        Hashtable from Get-StaleAccounts or $null.
        Keys: Disabled = @(...); Stale = @(...); Active = @(...)

    .PARAMETER ChangeTrackingData
        Hashtable from Update-MembershipState or $null.
        Keys: Changes = @( @{ Timestamp; Domain; GroupName; SamAccountName; DisplayName; Email; Action } );
              Summary = @{ TotalAdded; TotalRemoved; GroupsChanged; GroupsTracked; GroupsSeeded; IsFirstRun }

    .PARAMETER DriftResult
        Hashtable from Get-MembershipDrift or $null.
        Keys: FromBaseline = @{ "DOMAIN|GroupName" = @{ Added; Removed; ... } };
              FromPrevious = @{ ... }; OverallSummary = @{ ... }

    .PARAMETER Config
        Configuration hashtable. Used for ToolVersion etc.

    .PARAMETER Title
        Report title. Defaults to 'Compliance Audit Report'.

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
        [hashtable]$DriftResult = $null,

        [Parameter(Mandatory = $false)]
        [hashtable]$Config = @{},

        [Parameter(Mandatory = $false)]
        [string]$Title = 'Compliance Audit Report'
    )

    try {
        $timestamp   = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
        $toolVersion = if ($Config.ToolVersion) { $Config.ToolVersion } else { $script:ComplianceReportVersion }
        $palette     = $script:AuditPalette

        # Load template
        $templatePath = $script:ComplianceTemplatePath
        if (Test-Path $templatePath) {
            $template = [System.IO.File]::ReadAllText($templatePath, [System.Text.Encoding]::UTF8)
        } else {
            throw "Compliance report template not found: $templatePath"
        }

        # Filter to enumerated groups only
        $enumerated = @($GroupResults | Where-Object { $_.Data.Skipped -ne $true })

        # Build HTML sections
        $executiveSummaryHtml = Build-CompliancePostureHtml -GroupResults $GroupResults -StaleResults $StaleResults -Palette $palette
        $executiveSummaryHtml += Build-ComplianceKpiCardsHtml -GroupResults $GroupResults -StaleResults $StaleResults -ChangeTrackingData $ChangeTrackingData -Palette $palette

        $groupSnapshotHtml = Build-GroupMembershipSnapshotHtml -GroupResults $enumerated -Palette $palette

        $changeLogHtml    = Build-ChangeLogSummaryHtml -ChangeTrackingData $ChangeTrackingData -Palette $palette
        $changeLogDisplay = if ($ChangeTrackingData -and $ChangeTrackingData.Changes -and $ChangeTrackingData.Changes.Count -gt 0) { 'block' } else { 'none' }

        $driftHtml    = Build-DriftAnalysisHtml -DriftResult $DriftResult -Palette $palette
        $driftDisplay = if ($DriftResult -and (($DriftResult.FromBaseline -and $DriftResult.FromBaseline.Count -gt 0) -or ($DriftResult.FromPrevious -and $DriftResult.FromPrevious.Count -gt 0))) { 'block' } else { 'none' }

        $remediationHtml    = Build-RemediationStatusHtml -GroupResults $GroupResults -StaleResults $StaleResults -Palette $palette
        $hasRemediation     = $false
        if ($StaleResults) {
            $disabledCount = if ($StaleResults.Disabled) { $StaleResults.Disabled.Count } else { 0 }
            $staleCount    = if ($StaleResults.Stale)    { $StaleResults.Stale.Count }    else { 0 }
            if (($disabledCount + $staleCount) -gt 0) { $hasRemediation = $true }
        }
        $remediationDisplay = if ($hasRemediation) { 'block' } else { 'none' }

        $signOffHtml = Build-ReviewerSignOffHtml -Palette $palette

        $footerText = "Group Enumerator v$toolVersion &nbsp;|&nbsp; Generated: $timestamp &nbsp;|&nbsp; Compliance Audit Report"

        # Replace placeholders using .Replace() (NOT -replace)
        $template = $template.Replace('{{TITLE}}',                  [string]$Title)
        $template = $template.Replace('{{SUBTITLE}}',               'Group Membership Audit Evidence')
        $template = $template.Replace('{{TIMESTAMP}}',              [string]$timestamp)
        $template = $template.Replace('{{TOOL_VERSION}}',           [string]$toolVersion)
        $template = $template.Replace('{{EXECUTIVE_SUMMARY}}',      [string]$executiveSummaryHtml)
        $template = $template.Replace('{{GROUP_SNAPSHOT}}',          [string]$groupSnapshotHtml)
        $template = $template.Replace('{{CHANGE_LOG}}',             [string]$changeLogHtml)
        $template = $template.Replace('{{CHANGE_LOG_DISPLAY}}',     [string]$changeLogDisplay)
        $template = $template.Replace('{{DRIFT_ANALYSIS}}',         [string]$driftHtml)
        $template = $template.Replace('{{DRIFT_ANALYSIS_DISPLAY}}', [string]$driftDisplay)
        $template = $template.Replace('{{REMEDIATION_STATUS}}',     [string]$remediationHtml)
        $template = $template.Replace('{{REMEDIATION_DISPLAY}}',    [string]$remediationDisplay)
        $template = $template.Replace('{{REVIEWER_SIGNOFF}}',       [string]$signOffHtml)
        $template = $template.Replace('{{FOOTER}}',                 [string]$footerText)

        # Write output
        $outDir = Split-Path $OutputPath -Parent
        if ($outDir -and -not (Test-Path $outDir)) {
            $null = New-Item -ItemType Directory -Path $outDir -Force
        }
        [System.IO.File]::WriteAllText($OutputPath, $template, [System.Text.UTF8Encoding]::new($false))

        Write-Verbose "Compliance audit report generated: $OutputPath"
        return $OutputPath

    } catch {
        throw "Export-ComplianceReport failed: $_"
    }
}

# ---------------------------------------------------------------------------
# Public: Export-LeadershipSummary
# ---------------------------------------------------------------------------
function Export-LeadershipSummary {
    <#
    .SYNOPSIS
        Generates a 1-page HTML leadership summary report.

    .DESCRIPTION
        Leadership Tier report: all inline CSS, no JavaScript, Word-compatible,
        print/PDF optimized. Contains key metrics, compliance posture statement,
        action items, and domain summary.

    .PARAMETER GroupResults
        Array of group result hashtables from Get-GroupMembers.

    .PARAMETER OutputPath
        Full file path for the output HTML file.

    .PARAMETER StaleResults
        Hashtable from Get-StaleAccounts or $null.

    .PARAMETER ChangeTrackingData
        Hashtable from Update-MembershipState or $null.

    .PARAMETER Config
        Configuration hashtable. Used for ToolVersion etc.

    .PARAMETER Title
        Report title. Defaults to 'Leadership Summary'.

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
        [string]$Title = 'Leadership Summary'
    )

    try {
        $timestamp   = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
        $dateOnly    = Get-Date -Format 'yyyy-MM-dd'
        $toolVersion = if ($Config.ToolVersion) { $Config.ToolVersion } else { $script:ComplianceReportVersion }
        $palette     = $script:LeadershipPalette

        # Load template
        $templatePath = $script:LeadershipTemplatePath
        if (Test-Path $templatePath) {
            $template = [System.IO.File]::ReadAllText($templatePath, [System.Text.Encoding]::UTF8)
        } else {
            throw "Leadership summary template not found: $templatePath"
        }

        # Build HTML sections
        $metricsHtml    = Build-LeadershipMetricsTableHtml -GroupResults $GroupResults -StaleResults $StaleResults -ChangeTrackingData $ChangeTrackingData -Palette $palette
        $complianceHtml = Build-ComplianceStatementHtml -GroupResults $GroupResults -StaleResults $StaleResults -Palette $palette
        $actionHtml     = Build-LeadershipActionItemsHtml -GroupResults $GroupResults -StaleResults $StaleResults -Palette $palette
        $domainHtml     = Build-LeadershipDomainSummaryHtml -GroupResults $GroupResults -StaleResults $StaleResults -Palette $palette

        $footerText = "Report generated $timestamp by Group Enumerator v$toolVersion"

        # Replace placeholders
        $template = $template.Replace('{{TITLE}}',                [string]$Title)
        $template = $template.Replace('{{DATE}}',                 [string]$dateOnly)
        $template = $template.Replace('{{METRICS_TABLE}}',        [string]$metricsHtml)
        $template = $template.Replace('{{COMPLIANCE_STATEMENT}}', [string]$complianceHtml)
        $template = $template.Replace('{{ACTION_ITEMS}}',         [string]$actionHtml)
        $template = $template.Replace('{{DOMAIN_SUMMARY}}',       [string]$domainHtml)
        $template = $template.Replace('{{FOOTER}}',               [string]$footerText)

        # Write output
        $outDir = Split-Path $OutputPath -Parent
        if ($outDir -and -not (Test-Path $outDir)) {
            $null = New-Item -ItemType Directory -Path $outDir -Force
        }
        [System.IO.File]::WriteAllText($OutputPath, $template, [System.Text.UTF8Encoding]::new($false))

        Write-Verbose "Leadership summary generated: $OutputPath"
        return $OutputPath

    } catch {
        throw "Export-LeadershipSummary failed: $_"
    }
}

# ---------------------------------------------------------------------------
# Internal: Get-CompliancePosture
# ---------------------------------------------------------------------------
function Get-DistinctMemberCount {
    <#
    .SYNOPSIS
        Distinct member identities (by SamAccountName) across enumerated groups --
        a user in N groups counts once. Use this for "identities" metrics rather
        than summing MemberCount (which counts memberships).
    #>
    param([array]$GroupResults)
    $set = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($e in @($GroupResults | Where-Object { $_.Data.Skipped -ne $true })) {
        $members = $e.Data.Members
        if ($members) {
            foreach ($m in $members) { $sam = [string]$m.SamAccountName; if ($sam) { [void]$set.Add($sam) } }
        }
    }
    return $set.Count
}

function Get-CompliancePosture {
    <#
    .SYNOPSIS
        Calculates compliance posture percentage from group results and stale data.
    .DESCRIPTION
        Compliance posture = active clean members / total members.
        Stale and disabled accounts reduce the score.
    #>
    param(
        [array]$GroupResults,
        [hashtable]$StaleResults
    )

    # Denominator = DISTINCT member identities (a user in N groups counts once), so
    # it is in the same unit as the numerator, which counts distinct flagged
    # ACCOUNTS. Summing MemberCount would count multi-group users repeatedly and
    # make the posture % meaningless (and could drive it to a false 0/RED).
    $totalMembers = Get-DistinctMemberCount -GroupResults $GroupResults
    if ($totalMembers -eq 0) { return 100 }

    # Numerator = distinct flagged accounts (dedup by SAM across Disabled + Stale;
    # flatStaleResults already dedups but guard against per-group duplicates).
    $riskSet = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    if ($StaleResults) {
        foreach ($bucket in @($StaleResults.Disabled, $StaleResults.Stale)) {
            if ($bucket) { foreach ($r in $bucket) { $sam = [string]$r.SamAccountName; if ($sam) { [void]$riskSet.Add($sam) } } }
        }
    }
    $riskCount = $riskSet.Count

    $cleanCount = $totalMembers - $riskCount
    if ($cleanCount -lt 0) { $cleanCount = 0 }
    $pct = [int][Math]::Round(($cleanCount / $totalMembers) * 100)
    return $pct
}

# ---------------------------------------------------------------------------
# Internal: Get-PostureColor
# ---------------------------------------------------------------------------
function Get-PostureColor {
    <#
    .SYNOPSIS
        Returns the appropriate color hex for a compliance percentage.
        Green >= 90%, Orange 70-89%, Red < 70%
    #>
    param([int]$Percent)
    if ($Percent -ge 90) { return '#339933' }
    if ($Percent -ge 70) { return '#FF8800' }
    return '#CC3333'
}

# ---------------------------------------------------------------------------
# Internal: Get-PostureLabel
# ---------------------------------------------------------------------------
function Get-PostureLabel {
    param([int]$Percent)
    if ($Percent -ge 90) { return 'GREEN' }
    if ($Percent -ge 70) { return 'AMBER' }
    return 'RED'
}

# ---------------------------------------------------------------------------
# Internal: Build-CompliancePostureHtml
# ---------------------------------------------------------------------------
function Build-CompliancePostureHtml {
    <#
    .SYNOPSIS
        Generates the compliance posture indicator with percentage.
    #>
    param(
        [array]$GroupResults,
        [hashtable]$StaleResults,
        [hashtable]$Palette
    )

    # Risk posture requires stale/disabled detection (-DetectStale). Without it
    # there is no risk data, so do NOT claim "100% compliant" -- show Not Assessed.
    if ($null -eq $StaleResults) {
        $warn = if ($Palette.warning) { $Palette.warning } else { '#FF8800' }
        return @"
<table cellpadding="0" cellspacing="0" border="0" style="width:100%; margin-bottom:20px;">
<tr>
    <td style="width:120px; text-align:center; vertical-align:middle; padding:16px;">
        <svg width="100" height="100" viewBox="0 0 100 100">
            <circle cx="50" cy="50" r="42" fill="none" stroke="#e0e0e0" stroke-width="8"/>
            <text x="50" y="48" text-anchor="middle" font-family="Arial,Helvetica,sans-serif" font-size="14" font-weight="bold" fill="$warn">N/A</text>
            <text x="50" y="63" text-anchor="middle" font-family="Arial,Helvetica,sans-serif" font-size="9" fill="#777777">Not Assessed</text>
        </svg>
    </td>
    <td style="vertical-align:middle; padding:16px;">
        <p style="font-family:Arial,Helvetica,sans-serif; font-size:18px; font-weight:bold; color:$warn; margin:0 0 4px 0;">Compliance Posture: Not Assessed</p>
        <p style="font-family:Arial,Helvetica,sans-serif; font-size:13px; color:#555555; margin:0;">Disabled/stale account risk was not evaluated. Re-run with <strong>-DetectStale</strong> to compute compliance posture.</p>
    </td>
</tr>
</table>
"@
    }

    $pct        = Get-CompliancePosture -GroupResults $GroupResults -StaleResults $StaleResults
    $color      = Get-PostureColor -Percent $pct
    $label      = Get-PostureLabel -Percent $pct

    $html = @"
<table cellpadding="0" cellspacing="0" border="0" style="width:100%; margin-bottom:20px;">
<tr>
    <td style="width:120px; text-align:center; vertical-align:middle; padding:16px;">
        <svg width="100" height="100" viewBox="0 0 100 100">
            <circle cx="50" cy="50" r="42" fill="none" stroke="#e0e0e0" stroke-width="8"/>
            <circle cx="50" cy="50" r="42" fill="none" stroke="$color" stroke-width="8"
                    stroke-dasharray="$([Math]::Round(($pct / 100) * 264, 1)) $([Math]::Round(264 - (($pct / 100) * 264), 1))"
                    stroke-dashoffset="66" stroke-linecap="butt"/>
            <text x="50" y="46" text-anchor="middle" font-family="Arial,Helvetica,sans-serif" font-size="20" font-weight="bold" fill="$color">$pct%</text>
            <text x="50" y="62" text-anchor="middle" font-family="Arial,Helvetica,sans-serif" font-size="10" fill="#777777">$label</text>
        </svg>
    </td>
    <td style="vertical-align:middle; padding:16px;">
        <p style="font-family:Arial,Helvetica,sans-serif; font-size:18px; font-weight:bold; color:$color; margin:0 0 4px 0;">Compliance Posture: $label</p>
        <p style="font-family:Arial,Helvetica,sans-serif; font-size:13px; color:#555555; margin:0;">$pct% of monitored group members are in a compliant state (active, non-stale accounts).</p>
    </td>
</tr>
</table>
"@

    return $html
}

# ---------------------------------------------------------------------------
# Internal: Build-ComplianceKpiCardsHtml
# ---------------------------------------------------------------------------
function Build-ComplianceKpiCardsHtml {
    <#
    .SYNOPSIS
        Generates inline KPI cards in table layout for the executive summary.
    #>
    param(
        [array]$GroupResults,
        [hashtable]$StaleResults,
        [hashtable]$ChangeTrackingData,
        [hashtable]$Palette
    )

    $enumerated   = @($GroupResults | Where-Object { $_.Data.Skipped -ne $true })
    $totalGroups  = $enumerated.Count
    $totalMembers = 0
    foreach ($e in $enumerated) {
        if ($null -ne $e.Data.MemberCount) { $totalMembers += [int]$e.Data.MemberCount }
    }

    $changeCount = 0
    if ($ChangeTrackingData -and $ChangeTrackingData.Summary) {
        $changeCount = [int]$ChangeTrackingData.Summary.TotalAdded + [int]$ChangeTrackingData.Summary.TotalRemoved
    }

    $riskItems = 0
    if ($StaleResults) {
        if ($StaleResults.Disabled) { $riskItems += $StaleResults.Disabled.Count }
        if ($StaleResults.Stale)    { $riskItems += $StaleResults.Stale.Count }
    }

    $borderClr = if ($Palette.border) { $Palette.border } else { '#e0e0e0' }

    $cards = @(
        @{ Label = 'Total Groups';  Value = $totalGroups;  Color = '#336699' }
        @{ Label = 'Total Members'; Value = $totalMembers; Color = '#336699' }
        @{ Label = 'Changes';       Value = $changeCount;  Color = if ($changeCount -gt 0) { '#FF8800' } else { '#339933' } }
        @{ Label = 'Risk Items';    Value = $riskItems;    Color = if ($riskItems -gt 0)   { '#CC3333' } else { '#339933' } }
    )

    $html = [System.Text.StringBuilder]::new()
    [void]$html.Append('<table cellpadding="0" cellspacing="0" border="0" style="width:100%; margin-bottom:20px;">')
    [void]$html.Append('<tr>')

    foreach ($card in $cards) {
        [void]$html.Append("<td style=""padding:16px 20px; text-align:center; border:1px solid $borderClr; vertical-align:top; background:#ffffff;"">")
        [void]$html.Append("<div style=""font-size:28px; font-weight:bold; color:$($card.Color); line-height:1.1;"">$($card.Value)</div>")
        [void]$html.Append("<div style=""font-size:11px; color:#777777; text-transform:uppercase; letter-spacing:0.5px; margin-top:6px;"">$(Escape-ComplianceHtml $card.Label)</div>")
        [void]$html.Append('</td>')
    }

    [void]$html.Append('</tr>')
    [void]$html.Append('</table>')

    return $html.ToString()
}

# ---------------------------------------------------------------------------
# Internal: Build-GroupMembershipSnapshotHtml
# ---------------------------------------------------------------------------
function Build-GroupMembershipSnapshotHtml {
    <#
    .SYNOPSIS
        Generates point-in-time audit evidence tables for each enumerated group.
    #>
    param(
        [array]$GroupResults,
        [hashtable]$Palette
    )

    if (-not $GroupResults -or $GroupResults.Count -eq 0) {
        return '<p style="font-family:Arial,Helvetica,sans-serif; color:#777777; font-style:italic;">No group data available.</p>'
    }

    $headerBg   = if ($Palette.headerBg)   { $Palette.headerBg }   else { '#34495e' }
    $headerText = if ($Palette.headerText) { $Palette.headerText } else { '#ffffff' }
    $borderClr  = if ($Palette.border)     { $Palette.border }     else { '#e0e0e0' }
    $rowAlt     = if ($Palette.rowAlt)     { $Palette.rowAlt }     else { '#f9f9f9' }

    # Sort by domain then group name
    $sorted = $GroupResults | Sort-Object { $_.Data.Domain }, { $_.Data.GroupName }

    $html = [System.Text.StringBuilder]::new(8192)

    foreach ($gr in $sorted) {
        $data      = $gr.Data
        $groupName = Escape-ComplianceHtml $data.GroupName
        $domain    = Escape-ComplianceHtml $data.Domain
        $count     = if ($null -ne $data.MemberCount) { [int]$data.MemberCount } else { 0 }
        $members   = if ($data.Members -is [array]) { $data.Members }
                     elseif ($data.Members) { @(, $data.Members) }
                     else { @() }

        # Group header
        [void]$html.Append("<h3 style=""font-family:Arial,Helvetica,sans-serif; color:#2c3e50; font-size:14px; margin-top:20px; margin-bottom:8px;"">$groupName")
        [void]$html.Append(" <span style=""color:#777777; font-weight:normal;"">($domain)</span>")
        [void]$html.Append(" <span style=""display:inline-block; padding:2px 10px; border-radius:99px; font-size:12px; font-weight:bold; letter-spacing:0.3px; background-color:#336699; color:#ffffff;"">$count members</span>")
        [void]$html.Append('</h3>')

        if ($members.Count -eq 0) {
            [void]$html.Append('<p style="font-family:Arial,Helvetica,sans-serif; color:#777777; font-style:italic; margin-left:10px;">No members in this group.</p>')
            continue
        }

        # Member table
        [void]$html.Append("<table cellpadding=""0"" cellspacing=""0"" border=""0"" style=""width:100%; border-collapse:collapse; font-family:Arial,Helvetica,sans-serif; font-size:13px; margin-bottom:20px;"">")
        [void]$html.Append('<thead><tr>')
        [void]$html.Append("<th style=""background:$headerBg; color:$headerText; padding:8px 10px; text-align:left; font-family:Arial,Helvetica,sans-serif; font-size:13px;"">SAM Account</th>")
        [void]$html.Append("<th style=""background:$headerBg; color:$headerText; padding:8px 10px; text-align:left; font-family:Arial,Helvetica,sans-serif; font-size:13px;"">Display Name</th>")
        [void]$html.Append("<th style=""background:$headerBg; color:$headerText; padding:8px 10px; text-align:left; font-family:Arial,Helvetica,sans-serif; font-size:13px;"">Email</th>")
        [void]$html.Append("<th style=""background:$headerBg; color:$headerText; padding:8px 10px; text-align:left; font-family:Arial,Helvetica,sans-serif; font-size:13px;"">Status</th>")
        [void]$html.Append('</tr></thead>')
        [void]$html.Append('<tbody>')

        $rowIdx = 0
        foreach ($m in ($members | Sort-Object SamAccountName)) {
            $sam  = Escape-ComplianceHtml $(if ($m.SamAccountName) { $m.SamAccountName } else { '' })
            $dn   = Escape-ComplianceHtml $(if ($m.DisplayName)    { $m.DisplayName }    else { '' })
            $mail = Escape-ComplianceHtml $(if ($m.Email)           { $m.Email }          else { '' })

            # Determine status
            $statusHtml  = ''
            $isStale     = $false
            $isDisabled  = $false

            if ($m.Enabled -eq $false) {
                $isDisabled = $true
            }

            # Check stale via DaysSinceLogon if available
            if ($null -ne $m.DaysSinceLogon -and [int]$m.DaysSinceLogon -gt 90) {
                $isStale = $true
            }

            if ($isDisabled) {
                $statusHtml = '<span style="display:inline-block; padding:2px 10px; border-radius:99px; font-size:12px; font-weight:bold; letter-spacing:0.3px; background-color:#CC3333; color:#ffffff;">Disabled</span>'
            } elseif ($isStale) {
                $statusHtml = '<span style="display:inline-block; padding:2px 10px; border-radius:99px; font-size:12px; font-weight:bold; letter-spacing:0.3px; background-color:#FF8800; color:#ffffff;">Stale</span>'
            } elseif ($m.Enabled -eq $true) {
                $statusHtml = '<span style="display:inline-block; padding:2px 10px; border-radius:99px; font-size:12px; font-weight:bold; letter-spacing:0.3px; background-color:#339933; color:#ffffff;">Active</span>'
            } else {
                $statusHtml = '<span style="display:inline-block; padding:2px 10px; border-radius:99px; font-size:12px; font-weight:bold; letter-spacing:0.3px; background-color:#777777; color:#ffffff;">Unknown</span>'
            }

            $rowStyle = if (($rowIdx % 2) -eq 1) { " style=""background:$rowAlt;""" } else { '' }
            [void]$html.Append("<tr$rowStyle>")
            [void]$html.Append("<td style=""padding:8px 10px; border-bottom:1px solid $borderClr; vertical-align:top;"">$sam</td>")
            [void]$html.Append("<td style=""padding:8px 10px; border-bottom:1px solid $borderClr; vertical-align:top;"">$dn</td>")
            [void]$html.Append("<td style=""padding:8px 10px; border-bottom:1px solid $borderClr; vertical-align:top;"">$mail</td>")
            [void]$html.Append("<td style=""padding:8px 10px; border-bottom:1px solid $borderClr; vertical-align:top;"">$statusHtml</td>")
            [void]$html.Append('</tr>')
            $rowIdx++
        }

        [void]$html.Append('</tbody></table>')
    }

    return $html.ToString()
}

# ---------------------------------------------------------------------------
# Internal: Build-ChangeLogSummaryHtml
# ---------------------------------------------------------------------------
function Build-ChangeLogSummaryHtml {
    <#
    .SYNOPSIS
        Generates the change log summary table from change tracking data.
    #>
    param(
        [hashtable]$ChangeTrackingData,
        [hashtable]$Palette
    )

    if (-not $ChangeTrackingData) {
        return '<p style="font-family:Arial,Helvetica,sans-serif; color:#777777; font-style:italic;">No change tracking data available.</p>'
    }

    # Changes is a flat array with .Action = 'Added' or 'Removed'
    $allChanges = if ($ChangeTrackingData.Changes) { @($ChangeTrackingData.Changes) } else { @() }
    $added   = @($allChanges | Where-Object { $_.Action -eq 'Added' })
    $removed = @($allChanges | Where-Object { $_.Action -eq 'Removed' })

    if ($added.Count -eq 0 -and $removed.Count -eq 0) {
        return '<p style="font-family:Arial,Helvetica,sans-serif; color:#339933; font-weight:bold;">No membership changes detected since the last run.</p>'
    }

    $headerBg   = if ($Palette.headerBg)   { $Palette.headerBg }   else { '#34495e' }
    $headerText = if ($Palette.headerText) { $Palette.headerText } else { '#ffffff' }
    $borderClr  = if ($Palette.border)     { $Palette.border }     else { '#e0e0e0' }
    $rowAlt     = if ($Palette.rowAlt)     { $Palette.rowAlt }     else { '#f9f9f9' }

    $html = [System.Text.StringBuilder]::new()

    # Summary line
    [void]$html.Append("<p style=""font-family:Arial,Helvetica,sans-serif; font-size:13px; margin-bottom:12px;"">")
    [void]$html.Append("<span style=""color:#339933; font-weight:bold;"">$($added.Count) additions</span>, ")
    [void]$html.Append("<span style=""color:#CC3333; font-weight:bold;"">$($removed.Count) removals</span> detected.")
    [void]$html.Append('</p>')

    # Table
    [void]$html.Append("<table cellpadding=""0"" cellspacing=""0"" border=""0"" style=""width:100%; border-collapse:collapse; font-family:Arial,Helvetica,sans-serif; font-size:13px; margin-bottom:20px;"">")
    [void]$html.Append('<thead><tr>')
    [void]$html.Append("<th style=""background:$headerBg; color:$headerText; padding:8px 10px; text-align:left; font-family:Arial,Helvetica,sans-serif; font-size:13px;"">Timestamp</th>")
    [void]$html.Append("<th style=""background:$headerBg; color:$headerText; padding:8px 10px; text-align:left; font-family:Arial,Helvetica,sans-serif; font-size:13px;"">Group</th>")
    [void]$html.Append("<th style=""background:$headerBg; color:$headerText; padding:8px 10px; text-align:left; font-family:Arial,Helvetica,sans-serif; font-size:13px;"">Identity</th>")
    [void]$html.Append("<th style=""background:$headerBg; color:$headerText; padding:8px 10px; text-align:left; font-family:Arial,Helvetica,sans-serif; font-size:13px;"">Action</th>")
    [void]$html.Append('</tr></thead>')
    [void]$html.Append('<tbody>')

    $rowIdx = 0
    $fallbackTs = Escape-ComplianceHtml (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')

    foreach ($item in $added) {
        $ts       = if ($item.Timestamp) { Escape-ComplianceHtml ([string]$item.Timestamp) } else { $fallbackTs }
        $group    = Escape-ComplianceHtml $(if ($item.GroupName) { "$($item.Domain)\$($item.GroupName)" } elseif ($item.Group) { $item.Group } else { '' })
        $identity = Escape-ComplianceHtml $(if ($item.SamAccountName) { $item.SamAccountName } elseif ($item.Identity) { $item.Identity } else { '' })
        $rowStyle = if (($rowIdx % 2) -eq 1) { " style=""background:$rowAlt;""" } else { '' }

        [void]$html.Append("<tr$rowStyle>")
        [void]$html.Append("<td style=""padding:8px 10px; border-bottom:1px solid $borderClr; vertical-align:top;"">$ts</td>")
        [void]$html.Append("<td style=""padding:8px 10px; border-bottom:1px solid $borderClr; vertical-align:top;"">$group</td>")
        [void]$html.Append("<td style=""padding:8px 10px; border-bottom:1px solid $borderClr; vertical-align:top;"">$identity</td>")
        [void]$html.Append("<td style=""padding:8px 10px; border-bottom:1px solid $borderClr; vertical-align:top;""><span style=""display:inline-block; padding:2px 10px; border-radius:99px; font-size:12px; font-weight:bold; background-color:#339933; color:#ffffff;"">Added</span></td>")
        [void]$html.Append('</tr>')
        $rowIdx++
    }

    foreach ($item in $removed) {
        $ts       = if ($item.Timestamp) { Escape-ComplianceHtml ([string]$item.Timestamp) } else { $fallbackTs }
        $group    = Escape-ComplianceHtml $(if ($item.GroupName) { "$($item.Domain)\$($item.GroupName)" } elseif ($item.Group) { $item.Group } else { '' })
        $identity = Escape-ComplianceHtml $(if ($item.SamAccountName) { $item.SamAccountName } elseif ($item.Identity) { $item.Identity } else { '' })
        $rowStyle = if (($rowIdx % 2) -eq 1) { " style=""background:$rowAlt;""" } else { '' }

        [void]$html.Append("<tr$rowStyle>")
        [void]$html.Append("<td style=""padding:8px 10px; border-bottom:1px solid $borderClr; vertical-align:top;"">$ts</td>")
        [void]$html.Append("<td style=""padding:8px 10px; border-bottom:1px solid $borderClr; vertical-align:top;"">$group</td>")
        [void]$html.Append("<td style=""padding:8px 10px; border-bottom:1px solid $borderClr; vertical-align:top;"">$identity</td>")
        [void]$html.Append("<td style=""padding:8px 10px; border-bottom:1px solid $borderClr; vertical-align:top;""><span style=""display:inline-block; padding:2px 10px; border-radius:99px; font-size:12px; font-weight:bold; background-color:#CC3333; color:#ffffff;"">Removed</span></td>")
        [void]$html.Append('</tr>')
        $rowIdx++
    }

    [void]$html.Append('</tbody></table>')

    return $html.ToString()
}

# ---------------------------------------------------------------------------
# Internal: Build-DriftAnalysisHtml
# ---------------------------------------------------------------------------
function Build-DriftAnalysisHtml {
    <#
    .SYNOPSIS
        Generates the drift comparison table against baseline.
    #>
    param(
        [hashtable]$DriftResult,
        [hashtable]$Palette
    )

    # Get-MembershipDrift returns @{ FromBaseline; FromPrevious; OverallSummary }.
    # Each is a hashtable keyed by "DOMAIN|GroupName" -> @{ Added; Removed; Unchanged; Summary }.
    # Prefer FromBaseline if available; fall back to FromPrevious.
    $driftData = $null
    if ($DriftResult) {
        if ($DriftResult.FromBaseline -and $DriftResult.FromBaseline.Count -gt 0) {
            $driftData = $DriftResult.FromBaseline
        } elseif ($DriftResult.FromPrevious -and $DriftResult.FromPrevious.Count -gt 0) {
            $driftData = $DriftResult.FromPrevious
        }
    }

    if (-not $driftData -or $driftData.Count -eq 0) {
        return '<p style="font-family:Arial,Helvetica,sans-serif; color:#777777; font-style:italic;">No drift analysis data available. Run with -BaselinePath to enable drift comparison.</p>'
    }

    $headerBg   = if ($Palette.headerBg)   { $Palette.headerBg }   else { '#34495e' }
    $headerText = if ($Palette.headerText) { $Palette.headerText } else { '#ffffff' }
    $borderClr  = if ($Palette.border)     { $Palette.border }     else { '#e0e0e0' }
    $rowAlt     = if ($Palette.rowAlt)     { $Palette.rowAlt }     else { '#f9f9f9' }

    $html = [System.Text.StringBuilder]::new()

    [void]$html.Append("<table cellpadding=""0"" cellspacing=""0"" border=""0"" style=""width:100%; border-collapse:collapse; font-family:Arial,Helvetica,sans-serif; font-size:13px; margin-bottom:20px;"">")
    [void]$html.Append('<thead><tr>')
    [void]$html.Append("<th style=""background:$headerBg; color:$headerText; padding:8px 10px; text-align:left; font-family:Arial,Helvetica,sans-serif; font-size:13px;"">Group Name</th>")
    [void]$html.Append("<th style=""background:$headerBg; color:$headerText; padding:8px 10px; text-align:left; font-family:Arial,Helvetica,sans-serif; font-size:13px;"">Domain</th>")
    [void]$html.Append("<th style=""background:$headerBg; color:$headerText; padding:8px 10px; text-align:right; font-family:Arial,Helvetica,sans-serif; font-size:13px;"">Baseline</th>")
    [void]$html.Append("<th style=""background:$headerBg; color:$headerText; padding:8px 10px; text-align:right; font-family:Arial,Helvetica,sans-serif; font-size:13px;"">Current</th>")
    [void]$html.Append("<th style=""background:$headerBg; color:$headerText; padding:8px 10px; text-align:right; font-family:Arial,Helvetica,sans-serif; font-size:13px;"">Added</th>")
    [void]$html.Append("<th style=""background:$headerBg; color:$headerText; padding:8px 10px; text-align:right; font-family:Arial,Helvetica,sans-serif; font-size:13px;"">Removed</th>")
    [void]$html.Append("<th style=""background:$headerBg; color:$headerText; padding:8px 10px; text-align:left; font-family:Arial,Helvetica,sans-serif; font-size:13px;"">Status</th>")
    [void]$html.Append('</tr></thead>')
    [void]$html.Append('<tbody>')

    $rowIdx = 0
    foreach ($key in ($driftData.Keys | Sort-Object)) {
        $g = $driftData[$key]
        $parts = $key -split '\|', 2
        $domain    = if ($parts.Count -ge 1) { $parts[0] } else { '' }
        $groupName = if ($parts.Count -ge 2) { $parts[1] } else { $key }

        $groupNameEsc  = Escape-ComplianceHtml $groupName
        $domainEsc     = Escape-ComplianceHtml $domain
        $addedCount    = if ($g.Summary -and $null -ne $g.Summary.AddedCount)   { [int]$g.Summary.AddedCount }   else { if ($g.Added) { $g.Added.Count } else { 0 } }
        $removedCount  = if ($g.Summary -and $null -ne $g.Summary.RemovedCount) { [int]$g.Summary.RemovedCount } else { if ($g.Removed) { $g.Removed.Count } else { 0 } }
        $unchangedCount = if ($g.Unchanged) { $g.Unchanged.Count } else { 0 }
        $baselineCount = $unchangedCount + $removedCount
        $currentCount  = $unchangedCount + $addedCount

        # Determine drift severity
        $totalDelta = $addedCount + $removedCount
        $driftPct   = if ($baselineCount -gt 0) { [int][Math]::Round(($totalDelta / $baselineCount) * 100) } else { 0 }

        if ($totalDelta -eq 0) {
            $statusColor = '#339933'
            $statusLabel = 'Stable'
        } elseif ($driftPct -lt 10) {
            $statusColor = '#FF8800'
            $statusLabel = 'Minor Drift'
        } else {
            $statusColor = '#CC3333'
            $statusLabel = 'Major Drift'
        }

        $statusBadge = "<span style=""display:inline-block; padding:2px 10px; border-radius:99px; font-size:12px; font-weight:bold; letter-spacing:0.3px; background-color:$statusColor; color:#ffffff;"">$statusLabel</span>"

        $rowStyle = if (($rowIdx % 2) -eq 1) { " style=""background:$rowAlt;""" } else { '' }
        [void]$html.Append("<tr$rowStyle>")
        [void]$html.Append("<td style=""padding:8px 10px; border-bottom:1px solid $borderClr; vertical-align:top;"">$groupNameEsc</td>")
        [void]$html.Append("<td style=""padding:8px 10px; border-bottom:1px solid $borderClr; vertical-align:top;"">$domainEsc</td>")
        [void]$html.Append("<td style=""padding:8px 10px; border-bottom:1px solid $borderClr; vertical-align:top; text-align:right;"">$baselineCount</td>")
        [void]$html.Append("<td style=""padding:8px 10px; border-bottom:1px solid $borderClr; vertical-align:top; text-align:right;"">$currentCount</td>")
        [void]$html.Append("<td style=""padding:8px 10px; border-bottom:1px solid $borderClr; vertical-align:top; text-align:right; color:#339933; font-weight:bold;"">+$addedCount</td>")
        [void]$html.Append("<td style=""padding:8px 10px; border-bottom:1px solid $borderClr; vertical-align:top; text-align:right; color:#CC3333; font-weight:bold;"">-$removedCount</td>")
        [void]$html.Append("<td style=""padding:8px 10px; border-bottom:1px solid $borderClr; vertical-align:top;"">$statusBadge</td>")
        [void]$html.Append('</tr>')
        $rowIdx++
    }

    [void]$html.Append('</tbody></table>')

    return $html.ToString()
}

# ---------------------------------------------------------------------------
# Internal: Build-ReviewerSignOffHtml
# ---------------------------------------------------------------------------
function Build-ReviewerSignOffHtml {
    <#
    .SYNOPSIS
        Generates the empty sign-off table for manual completion.
    #>
    param(
        [hashtable]$Palette
    )

    $headerBg   = if ($Palette.headerBg)   { $Palette.headerBg }   else { '#34495e' }
    $headerText = if ($Palette.headerText) { $Palette.headerText } else { '#ffffff' }
    $borderClr  = if ($Palette.border)     { $Palette.border }     else { '#e0e0e0' }

    $html = [System.Text.StringBuilder]::new()

    [void]$html.Append('<p style="font-family:Arial,Helvetica,sans-serif; font-size:12px; color:#777777; font-style:italic; margin-bottom:12px;">This section requires manual completion. Print or copy to Word for sign-off.</p>')

    [void]$html.Append("<table cellpadding=""0"" cellspacing=""0"" border=""0"" style=""width:100%; border-collapse:collapse; font-family:Arial,Helvetica,sans-serif; font-size:13px; margin-bottom:20px;"">")
    [void]$html.Append('<thead><tr>')
    [void]$html.Append("<th style=""background:$headerBg; color:$headerText; padding:8px 10px; text-align:left; font-family:Arial,Helvetica,sans-serif; font-size:13px;"">Reviewer Name</th>")
    [void]$html.Append("<th style=""background:$headerBg; color:$headerText; padding:8px 10px; text-align:left; font-family:Arial,Helvetica,sans-serif; font-size:13px;"">Title / Role</th>")
    [void]$html.Append("<th style=""background:$headerBg; color:$headerText; padding:8px 10px; text-align:left; font-family:Arial,Helvetica,sans-serif; font-size:13px;"">Date</th>")
    [void]$html.Append("<th style=""background:$headerBg; color:$headerText; padding:8px 10px; text-align:left; font-family:Arial,Helvetica,sans-serif; font-size:13px;"">Signature</th>")
    [void]$html.Append("<th style=""background:$headerBg; color:$headerText; padding:8px 10px; text-align:left; font-family:Arial,Helvetica,sans-serif; font-size:13px;"">Comments</th>")
    [void]$html.Append('</tr></thead>')
    [void]$html.Append('<tbody>')

    # 4 empty rows for sign-off
    for ($i = 0; $i -lt 4; $i++) {
        [void]$html.Append('<tr>')
        [void]$html.Append("<td style=""padding:20px 10px; border-bottom:1px solid $borderClr;"">&nbsp;</td>")
        [void]$html.Append("<td style=""padding:20px 10px; border-bottom:1px solid $borderClr;"">&nbsp;</td>")
        [void]$html.Append("<td style=""padding:20px 10px; border-bottom:1px solid $borderClr;"">&nbsp;</td>")
        [void]$html.Append("<td style=""padding:20px 10px; border-bottom:1px solid $borderClr;"">&nbsp;</td>")
        [void]$html.Append("<td style=""padding:20px 10px; border-bottom:1px solid $borderClr;"">&nbsp;</td>")
        [void]$html.Append('</tr>')
    }

    [void]$html.Append('</tbody></table>')

    return $html.ToString()
}

# ---------------------------------------------------------------------------
# Internal: Build-RemediationStatusHtml
# ---------------------------------------------------------------------------
function Build-RemediationStatusHtml {
    <#
    .SYNOPSIS
        Generates the remediation status table for flagged accounts.
    #>
    param(
        [array]$GroupResults,
        [hashtable]$StaleResults,
        [hashtable]$Palette
    )

    if (-not $StaleResults) {
        return '<p style="font-family:Arial,Helvetica,sans-serif; color:#777777; font-style:italic;">No stale account data available. Run with -IncludeStale to enable.</p>'
    }

    $disabled = if ($StaleResults.Disabled) { @($StaleResults.Disabled) } else { @() }
    $stale    = if ($StaleResults.Stale)    { @($StaleResults.Stale)    } else { @() }

    if ($disabled.Count -eq 0 -and $stale.Count -eq 0) {
        return '<p style="font-family:Arial,Helvetica,sans-serif; color:#339933; font-weight:bold;">No accounts flagged for remediation.</p>'
    }

    $headerBg   = if ($Palette.headerBg)   { $Palette.headerBg }   else { '#34495e' }
    $headerText = if ($Palette.headerText) { $Palette.headerText } else { '#ffffff' }
    $borderClr  = if ($Palette.border)     { $Palette.border }     else { '#e0e0e0' }
    $rowAlt     = if ($Palette.rowAlt)     { $Palette.rowAlt }     else { '#f9f9f9' }

    $html = [System.Text.StringBuilder]::new()

    [void]$html.Append("<p style=""font-family:Arial,Helvetica,sans-serif; font-size:13px; margin-bottom:12px;"">")
    [void]$html.Append("<span style=""color:#CC3333; font-weight:bold;"">$($disabled.Count) disabled</span> and ")
    [void]$html.Append("<span style=""color:#FF8800; font-weight:bold;"">$($stale.Count) stale</span> accounts require action.")
    [void]$html.Append('</p>')

    [void]$html.Append("<table cellpadding=""0"" cellspacing=""0"" border=""0"" style=""width:100%; border-collapse:collapse; font-family:Arial,Helvetica,sans-serif; font-size:13px; margin-bottom:20px;"">")
    [void]$html.Append('<thead><tr>')
    [void]$html.Append("<th style=""background:$headerBg; color:$headerText; padding:8px 10px; text-align:left; font-family:Arial,Helvetica,sans-serif; font-size:13px;"">Identity</th>")
    [void]$html.Append("<th style=""background:$headerBg; color:$headerText; padding:8px 10px; text-align:left; font-family:Arial,Helvetica,sans-serif; font-size:13px;"">Domain</th>")
    [void]$html.Append("<th style=""background:$headerBg; color:$headerText; padding:8px 10px; text-align:left; font-family:Arial,Helvetica,sans-serif; font-size:13px;"">Group(s)</th>")
    [void]$html.Append("<th style=""background:$headerBg; color:$headerText; padding:8px 10px; text-align:left; font-family:Arial,Helvetica,sans-serif; font-size:13px;"">Issue Type</th>")
    [void]$html.Append("<th style=""background:$headerBg; color:$headerText; padding:8px 10px; text-align:right; font-family:Arial,Helvetica,sans-serif; font-size:13px;"">Days</th>")
    [void]$html.Append("<th style=""background:$headerBg; color:$headerText; padding:8px 10px; text-align:left; font-family:Arial,Helvetica,sans-serif; font-size:13px;"">Action Required</th>")
    [void]$html.Append('</tr></thead>')
    [void]$html.Append('<tbody>')

    $rowIdx = 0

    foreach ($acct in $disabled) {
        $sam     = Escape-ComplianceHtml $(if ($acct.SamAccountName) { $acct.SamAccountName } else { '' })
        $domain  = Escape-ComplianceHtml $(if ($acct.Domain)         { $acct.Domain }         else { '' })
        $groups  = Escape-ComplianceHtml $(if ($acct.Groups) { ($acct.Groups -join ', ') } elseif ($acct.GroupName) { $acct.GroupName } else { '' })
        $rowStyle = if (($rowIdx % 2) -eq 1) { " style=""background:$rowAlt;""" } else { '' }

        [void]$html.Append("<tr$rowStyle>")
        [void]$html.Append("<td style=""padding:8px 10px; border-bottom:1px solid $borderClr; vertical-align:top;"">$sam</td>")
        [void]$html.Append("<td style=""padding:8px 10px; border-bottom:1px solid $borderClr; vertical-align:top;"">$domain</td>")
        [void]$html.Append("<td style=""padding:8px 10px; border-bottom:1px solid $borderClr; vertical-align:top;"">$groups</td>")
        [void]$html.Append("<td style=""padding:8px 10px; border-bottom:1px solid $borderClr; vertical-align:top;""><span style=""display:inline-block; padding:2px 10px; border-radius:99px; font-size:12px; font-weight:bold; background-color:#CC3333; color:#ffffff;"">Disabled Account</span></td>")
        [void]$html.Append("<td style=""padding:8px 10px; border-bottom:1px solid $borderClr; vertical-align:top; text-align:right;"">--</td>")
        [void]$html.Append("<td style=""padding:8px 10px; border-bottom:1px solid $borderClr; vertical-align:top;"">Remove from group or re-enable</td>")
        [void]$html.Append('</tr>')
        $rowIdx++
    }

    foreach ($acct in $stale) {
        $sam     = Escape-ComplianceHtml $(if ($acct.SamAccountName) { $acct.SamAccountName } else { '' })
        $domain  = Escape-ComplianceHtml $(if ($acct.Domain)         { $acct.Domain }         else { '' })
        $groups  = Escape-ComplianceHtml $(if ($acct.Groups) { ($acct.Groups -join ', ') } elseif ($acct.GroupName) { $acct.GroupName } else { '' })
        $days    = if ($null -ne $acct.DaysSinceLogon) { [string][int]$acct.DaysSinceLogon } else { '' }
        $rowStyle = if (($rowIdx % 2) -eq 1) { " style=""background:$rowAlt;""" } else { '' }

        [void]$html.Append("<tr$rowStyle>")
        [void]$html.Append("<td style=""padding:8px 10px; border-bottom:1px solid $borderClr; vertical-align:top;"">$sam</td>")
        [void]$html.Append("<td style=""padding:8px 10px; border-bottom:1px solid $borderClr; vertical-align:top;"">$domain</td>")
        [void]$html.Append("<td style=""padding:8px 10px; border-bottom:1px solid $borderClr; vertical-align:top;"">$groups</td>")
        [void]$html.Append("<td style=""padding:8px 10px; border-bottom:1px solid $borderClr; vertical-align:top;""><span style=""display:inline-block; padding:2px 10px; border-radius:99px; font-size:12px; font-weight:bold; background-color:#FF8800; color:#ffffff;"">Stale Account</span></td>")
        [void]$html.Append("<td style=""padding:8px 10px; border-bottom:1px solid $borderClr; vertical-align:top; text-align:right;"">$days</td>")
        [void]$html.Append("<td style=""padding:8px 10px; border-bottom:1px solid $borderClr; vertical-align:top;"">Review activity and consider removal</td>")
        [void]$html.Append('</tr>')
        $rowIdx++
    }

    [void]$html.Append('</tbody></table>')

    return $html.ToString()
}

# ---------------------------------------------------------------------------
# Internal: Build-LeadershipMetricsTableHtml
# ---------------------------------------------------------------------------
function Build-LeadershipMetricsTableHtml {
    <#
    .SYNOPSIS
        Generates a 2x3 grid of key metrics for the leadership report.
    #>
    param(
        [array]$GroupResults,
        [hashtable]$StaleResults,
        [hashtable]$ChangeTrackingData,
        [hashtable]$Palette
    )

    $enumerated   = @($GroupResults | Where-Object { $_.Data.Skipped -ne $true })
    $totalGroups  = $enumerated.Count
    $totalMembers = 0
    foreach ($e in $enumerated) {
        if ($null -ne $e.Data.MemberCount) { $totalMembers += [int]$e.Data.MemberCount }
    }

    $domains      = @($enumerated | ForEach-Object { $_.Data.Domain } | Sort-Object -Unique)
    $domainCount  = $domains.Count

    $changeCount = 0
    if ($ChangeTrackingData -and $ChangeTrackingData.Summary) {
        $changeCount = [int]$ChangeTrackingData.Summary.TotalAdded + [int]$ChangeTrackingData.Summary.TotalRemoved
    }

    $riskItems = 0
    if ($StaleResults) {
        if ($StaleResults.Disabled) { $riskItems += $StaleResults.Disabled.Count }
        if ($StaleResults.Stale)    { $riskItems += $StaleResults.Stale.Count }
    }

    $posturePct   = Get-CompliancePosture -GroupResults $GroupResults -StaleResults $StaleResults
    $postureColor = Get-PostureColor -Percent $posturePct
    $postureLabel = Get-PostureLabel -Percent $posturePct

    $borderClr = if ($Palette.border) { $Palette.border } else { '#dddddd' }

    $metrics = @(
        @( @{ Label = 'Total Groups Monitored'; Value = $totalGroups;  Color = '#336699' },
           @{ Label = 'Total Identities';       Value = (Get-DistinctMemberCount -GroupResults $GroupResults); Color = '#336699' },
           @{ Label = 'Domains Covered';         Value = $domainCount;  Color = '#336699' } ),
        @( @{ Label = 'Active Changes';    Value = $changeCount;  Color = if ($changeCount -gt 0) { '#FF8800' } else { '#339933' } },
           @{ Label = 'Risk Items';         Value = $riskItems;    Color = if ($riskItems -gt 0)   { '#CC3333' } else { '#339933' } },
           @{ Label = 'Compliance Posture'; Value = "$posturePct% $postureLabel"; Color = $postureColor } )
    )

    $html = [System.Text.StringBuilder]::new()
    [void]$html.Append("<table cellpadding=""0"" cellspacing=""0"" border=""0"" style=""width:100%; margin-bottom:16px;"">")

    foreach ($row in $metrics) {
        [void]$html.Append('<tr>')
        foreach ($cell in $row) {
            [void]$html.Append("<td style=""padding:14px 18px; text-align:center; border:1px solid $borderClr; vertical-align:top; background:#ffffff; width:33%;"">")
            [void]$html.Append("<div style=""font-size:24px; font-weight:bold; color:$($cell.Color); line-height:1.1;"">$(Escape-ComplianceHtml ([string]$cell.Value))</div>")
            [void]$html.Append("<div style=""font-size:10px; color:#999999; text-transform:uppercase; letter-spacing:0.5px; margin-top:5px;"">$(Escape-ComplianceHtml $cell.Label)</div>")
            [void]$html.Append('</td>')
        }
        [void]$html.Append('</tr>')
    }

    [void]$html.Append('</table>')

    return $html.ToString()
}

# ---------------------------------------------------------------------------
# Internal: Build-ComplianceStatementHtml
# ---------------------------------------------------------------------------
function Build-ComplianceStatementHtml {
    <#
    .SYNOPSIS
        Generates the compliance posture statement paragraph.
    #>
    param(
        [array]$GroupResults,
        [hashtable]$StaleResults,
        [hashtable]$Palette
    )

    $enumerated   = @($GroupResults | Where-Object { $_.Data.Skipped -ne $true })
    $totalGroups  = $enumerated.Count
    $domains      = @($enumerated | ForEach-Object { $_.Data.Domain } | Sort-Object -Unique)
    $domainCount  = $domains.Count

    $posturePct   = Get-CompliancePosture -GroupResults $GroupResults -StaleResults $StaleResults
    $postureColor = Get-PostureColor -Percent $posturePct
    $postureLabel = Get-PostureLabel -Percent $posturePct
    $dateStr      = Get-Date -Format 'yyyy-MM-dd'

    $riskItems = 0
    if ($StaleResults) {
        if ($StaleResults.Disabled) { $riskItems += $StaleResults.Disabled.Count }
        if ($StaleResults.Stale)    { $riskItems += $StaleResults.Stale.Count }
    }

    $html = [System.Text.StringBuilder]::new()
    [void]$html.Append('<div style="font-family:Arial,Helvetica,sans-serif; font-size:13px; line-height:1.6; margin-bottom:16px;">')
    [void]$html.Append("<p style=""margin:0 0 8px 0;"">As of <strong>$dateStr</strong>, <strong>$totalGroups</strong> groups across <strong>$domainCount</strong> domain(s) are being monitored for membership compliance.</p>")
    if ($null -ne $StaleResults) {
        [void]$html.Append("<p style=""margin:0 0 8px 0;"">Compliance posture is <span style=""color:$postureColor; font-weight:bold;"">$postureLabel</span> at <span style=""color:$postureColor; font-weight:bold;"">$posturePct%</span>.")
        if ($riskItems -gt 0) {
            [void]$html.Append(" There are <span style=""color:#CC3333; font-weight:bold;"">$riskItems item(s)</span> requiring attention.")
        } else {
            [void]$html.Append(' No items require immediate attention.')
        }
        [void]$html.Append('</p>')
    } else {
        [void]$html.Append("<p style=""margin:0 0 8px 0;"">Risk posture was <strong>not assessed</strong> in this run. Re-run with <strong>-DetectStale</strong> to evaluate disabled/stale accounts and compute compliance posture.</p>")
    }
    [void]$html.Append('</div>')

    return $html.ToString()
}

# ---------------------------------------------------------------------------
# Internal: Build-LeadershipActionItemsHtml
# ---------------------------------------------------------------------------
function Build-LeadershipActionItemsHtml {
    <#
    .SYNOPSIS
        Generates a numbered list of action items (max 5).
    #>
    param(
        [array]$GroupResults,
        [hashtable]$StaleResults,
        [hashtable]$Palette
    )

    $items = [System.Collections.Generic.List[string]]::new()

    # Check for disabled accounts
    $disabledCount = 0
    if ($StaleResults -and $StaleResults.Disabled) {
        $disabledCount = $StaleResults.Disabled.Count
    }
    if ($disabledCount -gt 0) {
        # Group disabled by domain for reporting
        $disabledDomains = @($StaleResults.Disabled | ForEach-Object { $_.Domain } | Sort-Object -Unique)
        $domainList = ($disabledDomains | ForEach-Object { Escape-ComplianceHtml $_ }) -join ', '
        $items.Add("Review $disabledCount disabled account(s) in $domainList domain(s) and remove from monitored groups.")
    }

    # Check for stale accounts
    $staleCount = 0
    if ($StaleResults -and $StaleResults.Stale) {
        $staleCount = $StaleResults.Stale.Count
    }
    if ($staleCount -gt 0) {
        $staleDomains = @($StaleResults.Stale | ForEach-Object { $_.Domain } | Sort-Object -Unique)
        $domainList = ($staleDomains | ForEach-Object { Escape-ComplianceHtml $_ }) -join ', '
        $items.Add("Investigate $staleCount stale account(s) in $domainList domain(s) for continued access justification.")
    }

    # Check for empty groups
    $emptyGroups = @($GroupResults | Where-Object { $_.Data.Skipped -ne $true -and [int]$_.Data.MemberCount -eq 0 })
    if ($emptyGroups.Count -gt 0) {
        $items.Add("Review $($emptyGroups.Count) empty group(s) for decommissioning or repopulation.")
    }

    # Check for errors in enumeration
    $errorGroups = @($GroupResults | Where-Object { $_.Errors -and $_.Errors.Count -gt 0 })
    if ($errorGroups.Count -gt 0) {
        $items.Add("Resolve enumeration errors in $($errorGroups.Count) group(s) -- may indicate permission or connectivity issues.")
    }

    # Check for skipped groups
    $skippedGroups = @($GroupResults | Where-Object { $_.Data.Skipped -eq $true })
    if ($skippedGroups.Count -gt 0) {
        $items.Add("Review $($skippedGroups.Count) skipped group(s) and determine if they should be included in future audits.")
    }

    # Limit to 5 items
    if ($items.Count -gt 5) {
        $items = [System.Collections.Generic.List[string]]::new($items.GetRange(0, 5))
    }

    if ($items.Count -eq 0) {
        return '<p style="font-family:Arial,Helvetica,sans-serif; font-size:13px; color:#339933; font-weight:bold;">No action items at this time. All monitored groups are in good standing.</p>'
    }

    $html = [System.Text.StringBuilder]::new()
    [void]$html.Append('<ol style="font-family:Arial,Helvetica,sans-serif; font-size:13px; line-height:1.8; margin:0; padding-left:24px;">')

    foreach ($item in $items) {
        [void]$html.Append("<li style=""margin-bottom:6px;"">$item</li>")
    }

    [void]$html.Append('</ol>')

    return $html.ToString()
}

# ---------------------------------------------------------------------------
# Internal: Build-LeadershipDomainSummaryHtml
# ---------------------------------------------------------------------------
function Build-LeadershipDomainSummaryHtml {
    <#
    .SYNOPSIS
        Generates the domain summary table for the leadership report.
    #>
    param(
        [array]$GroupResults,
        [hashtable]$StaleResults,
        [hashtable]$Palette
    )

    $enumerated = @($GroupResults | Where-Object { $_.Data.Skipped -ne $true })
    $domains    = @($enumerated | ForEach-Object { $_.Data.Domain } | Sort-Object -Unique)

    if ($domains.Count -eq 0) {
        return '<p style="font-family:Arial,Helvetica,sans-serif; color:#777777; font-style:italic;">No domain data available.</p>'
    }

    $headerBg   = if ($Palette.headerBg)   { $Palette.headerBg }   else { '#34495e' }
    $headerText = if ($Palette.headerText) { $Palette.headerText } else { '#ffffff' }
    $borderClr  = if ($Palette.border)     { $Palette.border }     else { '#dddddd' }
    $rowAlt     = if ($Palette.rowAlt)     { $Palette.rowAlt }     else { '#f5f5f5' }

    $html = [System.Text.StringBuilder]::new()
    [void]$html.Append("<table cellpadding=""0"" cellspacing=""0"" border=""0"" style=""width:100%; border-collapse:collapse; font-family:Arial,Helvetica,sans-serif; font-size:13px; margin-bottom:16px;"">")
    [void]$html.Append('<thead><tr>')
    [void]$html.Append("<th style=""background:$headerBg; color:$headerText; padding:8px 10px; text-align:left; font-family:Arial,Helvetica,sans-serif; font-size:13px;"">Domain</th>")
    [void]$html.Append("<th style=""background:$headerBg; color:$headerText; padding:8px 10px; text-align:right; font-family:Arial,Helvetica,sans-serif; font-size:13px;"">Groups</th>")
    [void]$html.Append("<th style=""background:$headerBg; color:$headerText; padding:8px 10px; text-align:right; font-family:Arial,Helvetica,sans-serif; font-size:13px;"">Members</th>")
    [void]$html.Append("<th style=""background:$headerBg; color:$headerText; padding:8px 10px; text-align:left; font-family:Arial,Helvetica,sans-serif; font-size:13px;"">Status</th>")
    [void]$html.Append('</tr></thead>')
    [void]$html.Append('<tbody>')

    $rowIdx = 0
    foreach ($d in $domains) {
        $domainGroups  = @($enumerated | Where-Object { $_.Data.Domain -eq $d })
        $groupCount    = $domainGroups.Count
        $memberCount   = 0
        foreach ($dg in $domainGroups) {
            if ($null -ne $dg.Data.MemberCount) { $memberCount += [int]$dg.Data.MemberCount }
        }

        # Determine domain status
        $domainRiskItems = 0
        if ($StaleResults) {
            if ($StaleResults.Disabled) {
                $domainRiskItems += @($StaleResults.Disabled | Where-Object { $_.Domain -eq $d }).Count
            }
            if ($StaleResults.Stale) {
                $domainRiskItems += @($StaleResults.Stale | Where-Object { $_.Domain -eq $d }).Count
            }
        }

        if ($domainRiskItems -eq 0) {
            $statusColor = '#339933'
            $statusLabel = 'Healthy'
        } elseif ($memberCount -gt 0 -and ($domainRiskItems / $memberCount) -lt 0.1) {
            $statusColor = '#FF8800'
            $statusLabel = 'Attention'
        } else {
            $statusColor = '#CC3333'
            $statusLabel = 'At Risk'
        }

        $statusBadge = "<span style=""display:inline-block; padding:2px 10px; border-radius:99px; font-size:12px; font-weight:bold; letter-spacing:0.3px; background-color:$statusColor; color:#ffffff;"">$statusLabel</span>"

        $escapedDomain = Escape-ComplianceHtml $d
        $rowStyle = if (($rowIdx % 2) -eq 1) { " style=""background:$rowAlt;""" } else { '' }

        [void]$html.Append("<tr$rowStyle>")
        [void]$html.Append("<td style=""padding:8px 10px; border-bottom:1px solid $borderClr; vertical-align:top;"">$escapedDomain</td>")
        [void]$html.Append("<td style=""padding:8px 10px; border-bottom:1px solid $borderClr; vertical-align:top; text-align:right;"">$groupCount</td>")
        [void]$html.Append("<td style=""padding:8px 10px; border-bottom:1px solid $borderClr; vertical-align:top; text-align:right;"">$memberCount</td>")
        [void]$html.Append("<td style=""padding:8px 10px; border-bottom:1px solid $borderClr; vertical-align:top;"">$statusBadge</td>")
        [void]$html.Append('</tr>')
        $rowIdx++
    }

    [void]$html.Append('</tbody></table>')

    return $html.ToString()
}
