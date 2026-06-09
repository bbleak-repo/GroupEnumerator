<#
.SYNOPSIS
    HTML migration readiness report generation module (v2).

.DESCRIPTION
    Generates a migration readiness HTML report extending the v1 GroupReportGenerator design.
    Adds per-group readiness dashboards, gap analysis, user correlation, stale account,
    app readiness, and Change Request summary sections.
    The v1 GroupReportGenerator.ps1 must already be dot-sourced (Build-MatchedTableHtml etc.
    are called directly since they share a session scope).

.NOTES
    HTML escaping: manual replacement of &, <, >, ", ' (no System.Web dependency)
    File writes use UTF-8 without BOM via [System.IO.File]::WriteAllText
    No emoji in PowerShell code (per project conventions)
    Template path resolved at dot-source time via $PSScriptRoot
#>

# ---- Tool version constant ----
$script:MigrationReportVersion = '2.1.0'

# ---- Resolve template path at load time (dot-source context has valid $PSScriptRoot) ----
$script:MigrationReportModuleDir    = $PSScriptRoot
$script:MigrationReportProjectRoot  = Split-Path -Parent $script:MigrationReportModuleDir
$script:MigrationReportTemplatePath = Join-Path (Join-Path $script:MigrationReportProjectRoot 'Templates') 'migration-report-template.html'

# ---------------------------------------------------------------------------
# Internal: Escape-Html (local copy -- this module is dot-sourced independently)
# ---------------------------------------------------------------------------
function Escape-MigrationHtml {
    <#
    .SYNOPSIS
        HTML-encodes a string without requiring System.Web.
    #>
    param([string]$Text)
    if (-not $Text) { return '' }
    $Text = $Text -replace '&',  '&amp;'
    $Text = $Text -replace '<',  '&lt;'
    $Text = $Text -replace '>',  '&gt;'
    $Text = $Text -replace '"',  '&quot;'
    $Text = $Text -replace "'",  '&#39;'
    return $Text
}

# ---------------------------------------------------------------------------
# Public: Export-MigrationReport
# ---------------------------------------------------------------------------
function Export-MigrationReport {
    <#
    .SYNOPSIS
        Generates a full migration readiness HTML report.

    .PARAMETER GroupResults
        Array of group result hashtables from Get-GroupMembers.
        Each element: @{ Data = @{ GroupName; Domain; Members; MemberCount; Skipped; SkipReason }; Errors = @() }

    .PARAMETER MatchResults
        Hashtable from Find-MatchingGroups, or $null.
        Expected keys: Matched (array), Unmatched (array)

    .PARAMETER GapResults
        Array of gap analysis results from Get-MigrationGapAnalysis.
        Each element: @{ SourceGroup; TargetGroup; SourceDomain; TargetDomain;
                         ReadinessPercent; Items = @(...); CrCount }

    .PARAMETER OverallReadiness
        Hashtable from Get-OverallMigrationReadiness.
        Keys: ReadinessPercent, ReadyGroups, InProgressGroups, BlockedGroups, TotalCrItems

    .PARAMETER CorrelationResults
        Hashtable keyed by "SourceDomain\SourceGroup|TargetDomain\TargetGroup".
        Values: @{ Correlated=@(...); UnmatchedSource=@(...); UnmatchedTarget=@(...); NeedsReview=@(...) }

    .PARAMETER StaleResults
        Hashtable from Get-StaleAccounts or $null.
        Keys: Disabled = @(...); Stale = @(...); Active = @(...)

    .PARAMETER AppReadiness
        Hashtable from Get-AppReadiness or $null.
        Keys: Apps = @( @{ Name; SourceGroup; TargetGroup; ReadinessPercent; GapCount; Status } )

    .PARAMETER OutputPath
        Full file path for the output HTML file.

    .PARAMETER Theme
        Initial theme: "dark" (default) or "light".

    .PARAMETER Config
        Configuration hashtable. Used for ToolVersion etc.

    .OUTPUTS
        String path to the generated HTML file.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [array]$GroupResults,

        [Parameter(Mandatory = $false)]
        [hashtable]$MatchResults = $null,

        [Parameter(Mandatory = $false)]
        [AllowEmptyCollection()]
        [array]$GapResults = @(),

        [Parameter(Mandatory = $false)]
        [hashtable]$OverallReadiness = $null,

        [Parameter(Mandatory = $false)]
        [hashtable]$CorrelationResults = $null,

        [Parameter(Mandatory = $false)]
        [hashtable]$StaleResults = $null,

        [Parameter(Mandatory = $false)]
        [hashtable]$AppReadiness = $null,

        [Parameter(Mandatory = $true)]
        [string]$OutputPath,

        [Parameter(Mandatory = $false)]
        [ValidateSet('dark', 'light')]
        [string]$Theme = 'dark',

        [Parameter(Mandatory = $false)]
        [hashtable]$Config = @{}
    )

    try {
        $timestamp   = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
        $toolVersion = if ($Config.ToolVersion) { $Config.ToolVersion } else { $script:MigrationReportVersion }

        $templatePath = $script:MigrationReportTemplatePath
        if (Test-Path $templatePath) {
            $template = [System.IO.File]::ReadAllText($templatePath, [System.Text.Encoding]::UTF8)
        } else {
            throw "Migration report template not found: $templatePath"
        }

        # ---- Collect domains ----
        $domains = @($GroupResults | ForEach-Object { $_.Data.Domain } | Sort-Object -Unique)

        # ---- Separate skipped / enumerated ----
        $skippedResults  = @($GroupResults | Where-Object { $_.Data.Skipped -eq $true })
        $enumerated      = @($GroupResults | Where-Object { $_.Data.Skipped -ne $true })

        $totalMembers = 0
        foreach ($e in $enumerated) {
            if ($null -ne $e.Data.MemberCount) { $totalMembers += [int]$e.Data.MemberCount }
        }

        # ---- Categorise match results ----
        $matchedItems   = @()
        $unmatchedItems = @()

        if ($MatchResults -and $MatchResults.Matched)   { $matchedItems   = @($MatchResults.Matched) }
        if ($MatchResults -and $MatchResults.Unmatched) { $unmatchedItems = @($MatchResults.Unmatched) }
        elseif (-not $MatchResults)                     { $unmatchedItems = $enumerated | ForEach-Object { $_.Data } }

        $totalGroups    = $GroupResults.Count
        $matchedCount   = $matchedItems.Count
        $unmatchedCount = $unmatchedItems.Count
        $skippedCount   = $skippedResults.Count

        # ---- Overall readiness defaults ----
        $readinessPct    = 0
        $readyGroups     = 0
        $inProgressGroups = 0
        $blockedGroups   = 0
        $totalCrItems    = 0

        if ($OverallReadiness) {
            $readinessPct     = if ($null -ne $OverallReadiness.ReadinessPercent) { [int]$OverallReadiness.ReadinessPercent }  else { 0 }
            $readyGroups      = if ($null -ne $OverallReadiness.ReadyGroups)      { [int]$OverallReadiness.ReadyGroups }       else { 0 }
            $inProgressGroups = if ($null -ne $OverallReadiness.InProgressGroups) { [int]$OverallReadiness.InProgressGroups } else { 0 }
            $blockedGroups    = if ($null -ne $OverallReadiness.BlockedGroups)    { [int]$OverallReadiness.BlockedGroups }     else { 0 }
            $totalCrItems     = if ($null -ne $OverallReadiness.TotalCrItems)     { [int]$OverallReadiness.TotalCrItems }      else { 0 }
        } elseif ($GapResults -and $GapResults.Count -gt 0) {
            # Derive from gap results when no explicit OverallReadiness supplied
            $totalCrItems = 0
            $pctSum       = 0
            foreach ($gr in $GapResults) {
                if ($null -ne $gr.CrCount)          { $totalCrItems += [int]$gr.CrCount }
                if ($null -ne $gr.ReadinessPercent) { $pctSum       += [int]$gr.ReadinessPercent }
            }
            $readinessPct    = if ($GapResults.Count -gt 0) { [int]($pctSum / $GapResults.Count) } else { 0 }
            $readyGroups     = @($GapResults | Where-Object { $_.ReadinessPercent -ge 80 }).Count
            $inProgressGroups = @($GapResults | Where-Object { $_.ReadinessPercent -ge 50 -and $_.ReadinessPercent -lt 80 }).Count
            $blockedGroups   = @($GapResults | Where-Object { $_.ReadinessPercent -lt 50 }).Count
        }

        # ---- Domain summary for header ----
        $domainSummaryHtml = Build-MigrationDomainSummaryHtml -Domains $domains -GroupResults $GroupResults

        # ---- Build all HTML blocks ----
        $executiveSummaryHtml = Build-ExecutiveSummaryHtml `
            -ReadinessPct     $readinessPct `
            -TotalGroups      $totalGroups `
            -ReadyGroups      $readyGroups `
            -InProgressGroups $inProgressGroups `
            -BlockedGroups    $blockedGroups `
            -TotalCrItems     $totalCrItems

        $readinessDashboardHtml = Build-ReadinessDashboardHtml -GapResults $GapResults

        $appReadinessHtml    = Build-AppReadinessHtml -AppReadiness $AppReadiness
        $appReadinessDisplay = if ($AppReadiness -and $AppReadiness.Apps -and $AppReadiness.Apps.Count -gt 0) { 'block' } else { 'none' }

        $gapDetailHtml       = Build-GapDetailSectionsHtml -GapResults $GapResults

        $correlationHtml     = Build-CorrelationSectionsHtml -CorrelationResults $CorrelationResults

        $flaggedReviewHtml   = Build-FlaggedReviewHtml -CorrelationResults $CorrelationResults

        $staleHtml           = Build-StaleAccountsHtml -StaleResults $StaleResults
        $staleDisplay        = if ($StaleResults -and ($StaleResults.Disabled.Count -gt 0 -or $StaleResults.Stale.Count -gt 0)) { 'block' } else { 'none' }

        $crSummaryResult     = Build-CRSummaryHtml -GapResults $GapResults
        $crSummaryHtml       = $crSummaryResult.Html
        $crTextContent       = Escape-MigrationHtml $crSummaryResult.PlainText

        # ---- v1 summary blocks (functions loaded from GroupReportGenerator.ps1) ----
        $summaryCardsHtml   = Build-SummaryCardsHtml `
            -TotalGroups    $totalGroups `
            -TotalMembers   $totalMembers `
            -MatchedCount   $matchedCount `
            -UnmatchedCount $unmatchedCount `
            -SkippedCount   $skippedCount

        $matchedTableHtml   = Build-MatchedTableHtml   -MatchedItems $matchedItems   -GroupResults $GroupResults
        $unmatchedTableHtml = Build-UnmatchedTableHtml -UnmatchedItems $unmatchedItems
        $skippedTableHtml   = Build-SkippedTableHtml   -SkippedResults $skippedResults

        $detailSectionsHtml = Build-AllDetailSectionsHtml `
            -MatchedItems   $matchedItems `
            -UnmatchedItems $unmatchedItems `
            -GroupResults   $GroupResults

        # ---- Report title ----
        $domainList = $domains -join ' vs '
        $title = if ($domainList) { "Migration Readiness Report: $domainList" } else { 'Migration Readiness Report' }

        # ---- Apply initial theme ----
        # Use String.Replace (not -replace) for all substitutions: the values
        # are HTML fragments holding user-supplied data (group names, SAMs,
        # display names) that may contain '$', which -replace would interpret
        # as a regex backreference and silently drop.
        $themeClass = if ($Theme -eq 'light') { 'theme-light' } else { 'theme-dark' }
        $template = $template.Replace('<html lang="en" class="theme-dark">', "<html lang=`"en`" class=`"$themeClass`">")

        # ---- Replace placeholders ----
        $template = $template.Replace('{{TITLE}}',                   [string]$title)
        $template = $template.Replace('{{TIMESTAMP}}',               [string]$timestamp)
        $template = $template.Replace('{{TOOL_VERSION}}',            [string]$toolVersion)
        $template = $template.Replace('{{DOMAIN_SUMMARY}}',          [string]$domainSummaryHtml)
        $template = $template.Replace('{{EXECUTIVE_SUMMARY}}',       [string]$executiveSummaryHtml)
        $template = $template.Replace('{{READINESS_DASHBOARD}}',     [string]$readinessDashboardHtml)
        $template = $template.Replace('{{APP_READINESS}}',           [string]$appReadinessHtml)
        $template = $template.Replace('{{APP_READINESS_DISPLAY}}',   [string]$appReadinessDisplay)
        $template = $template.Replace('{{GAP_DETAIL_SECTIONS}}',     [string]$gapDetailHtml)
        $template = $template.Replace('{{CORRELATION_SECTIONS}}',    [string]$correlationHtml)
        $template = $template.Replace('{{FLAGGED_REVIEW}}',          [string]$flaggedReviewHtml)
        $template = $template.Replace('{{STALE_ACCOUNTS}}',          [string]$staleHtml)
        $template = $template.Replace('{{STALE_DISPLAY}}',           [string]$staleDisplay)
        $template = $template.Replace('{{CR_SUMMARY}}',              [string]$crSummaryHtml)
        $template = $template.Replace('{{CR_TEXT}}',                 [string]$crTextContent)
        $template = $template.Replace('{{SUMMARY_CARDS}}',           [string]$summaryCardsHtml)
        $template = $template.Replace('{{MATCHED_TABLE}}',           [string]$matchedTableHtml)
        $template = $template.Replace('{{UNMATCHED_TABLE}}',         [string]$unmatchedTableHtml)
        $template = $template.Replace('{{SKIPPED_TABLE}}',           [string]$skippedTableHtml)
        $template = $template.Replace('{{DETAIL_SECTIONS}}',         [string]$detailSectionsHtml)
        $template = $template.Replace('{{TOTAL_GROUPS}}',            [string]$totalGroups)
        $template = $template.Replace('{{TOTAL_MEMBERS}}',           [string]$totalMembers)
        $template = $template.Replace('{{MATCHED_COUNT}}',           [string]$matchedCount)
        $template = $template.Replace('{{UNMATCHED_COUNT}}',         [string]$unmatchedCount)
        $template = $template.Replace('{{SKIPPED_COUNT}}',           [string]$skippedCount)
        $template = $template.Replace('{{OVERALL_READINESS}}',       [string]$readinessPct)
        $template = $template.Replace('{{READY_GROUPS}}',            [string]$readyGroups)
        $template = $template.Replace('{{INPROGRESS_GROUPS}}',       [string]$inProgressGroups)
        $template = $template.Replace('{{BLOCKED_GROUPS}}',          [string]$blockedGroups)
        $template = $template.Replace('{{TOTAL_CR_ITEMS}}',          [string]$totalCrItems)

        # ---- Write output ----
        [System.IO.File]::WriteAllText($OutputPath, $template, [System.Text.UTF8Encoding]::new($false))

        Write-GroupEnumLog -Level 'INFO' -Operation 'ReportGeneration' -Message "Migration report generated: $OutputPath"
        return $OutputPath

    } catch {
        throw "Export-MigrationReport failed: $_"
    }
}

# ---------------------------------------------------------------------------
# Internal: Build-MigrationDomainSummaryHtml
# ---------------------------------------------------------------------------
function Build-MigrationDomainSummaryHtml {
    param(
        [string[]]$Domains,
        [array]$GroupResults
    )

    if (-not $Domains -or $Domains.Count -eq 0) { return '' }

    $parts = foreach ($d in $Domains) {
        $count = @($GroupResults | Where-Object { $_.Data.Domain -eq $d }).Count
        "<strong>$(Escape-MigrationHtml $d)</strong>: $count groups"
    }

    return '<p>' + ($parts -join ' &nbsp;|&nbsp; ') + '</p>'
}

# ---------------------------------------------------------------------------
# Public: Build-ExecutiveSummaryHtml
# ---------------------------------------------------------------------------
function Build-ExecutiveSummaryHtml {
    <#
    .SYNOPSIS
        Generates HTML for the executive summary stat cards, including the
        prominent overall readiness ring.
    #>
    [CmdletBinding()]
    param(
        [int]$ReadinessPct,
        [int]$TotalGroups,
        [int]$ReadyGroups,
        [int]$InProgressGroups,
        [int]$BlockedGroups,
        [int]$TotalCrItems
    )

    $ringClass = Get-ReadinessColorClass -Percent $ReadinessPct

    $ringCard = @"
<div class="readiness-ring-card">
    <div class="readiness-ring $ringClass">$ReadinessPct%</div>
    <div class="stat-body">
        <div class="stat-value $ringClass" style="font-size:1.5em;">$ReadinessPct% Ready</div>
        <div class="stat-label">Overall Migration Readiness</div>
    </div>
</div>
"@

    $cards = @(
        @{ Icon = '&#128101;'; IconClass = 'blue';   ValueClass = '';       Value = $TotalGroups;      Label = 'Groups Analyzed'  }
        @{ Icon = '&#9989;';   IconClass = 'green';  ValueClass = 'green';  Value = $ReadyGroups;      Label = 'Ready'            }
        @{ Icon = '&#9203;';   IconClass = 'amber';  ValueClass = 'amber';  Value = $InProgressGroups; Label = 'In Progress'      }
        @{ Icon = '&#128683;'; IconClass = 'red';    ValueClass = 'red';    Value = $BlockedGroups;    Label = 'Blocked'          }
        @{ Icon = '&#128203;'; IconClass = 'purple'; ValueClass = '';       Value = $TotalCrItems;     Label = 'Total CR Items'   }
    )

    $cardLines = foreach ($card in $cards) {
        $vcClass = if ($card.ValueClass) { " class=`"$($card.ValueClass)`"" } else { '' }
        @"
<div class="stat-card">
    <div class="stat-icon $($card.IconClass)">$($card.Icon)</div>
    <div class="stat-body">
        <div class="stat-value$vcClass">$($card.Value)</div>
        <div class="stat-label">$($card.Label)</div>
    </div>
</div>
"@
    }

    return $ringCard + "`n" + ($cardLines -join "`n")
}

# ---------------------------------------------------------------------------
# Public: Build-ReadinessDashboardHtml
# ---------------------------------------------------------------------------
function Build-ReadinessDashboardHtml {
    <#
    .SYNOPSIS
        Generates tbody rows for the per-group readiness dashboard table.
    #>
    [CmdletBinding()]
    param(
        [AllowEmptyCollection()]
        [array]$GapResults
    )

    if (-not $GapResults -or $GapResults.Count -eq 0) {
        return '<tr><td colspan="6" class="empty-state">No gap analysis data available</td></tr>'
    }

    $rows = foreach ($g in $GapResults) {
        $srcGroup  = Escape-MigrationHtml $(if ($g.SourceGroup)  { $g.SourceGroup }  else { '' })
        $tgtGroup  = Escape-MigrationHtml $(if ($g.TargetGroup)  { $g.TargetGroup }  else { '' })
        $srcDomain = Escape-MigrationHtml $(if ($g.SourceDomain) { $g.SourceDomain } else { '' })
        $tgtDomain = Escape-MigrationHtml $(if ($g.TargetDomain) { $g.TargetDomain } else { '' })

        $pairLabel = if ($srcDomain) { "$srcDomain\$srcGroup -&gt; $tgtDomain\$tgtGroup" } else { "$srcGroup -&gt; $tgtGroup" }

        $pct       = if ($null -ne $g.ReadinessPercent) { [int]$g.ReadinessPercent } else { 0 }
        $srcCount  = if ($null -ne $g.SourceCount)      { [int]$g.SourceCount }      else { 0 }
        $tgtCount  = if ($null -ne $g.TargetCount)      { [int]$g.TargetCount }      else { 0 }
        $crCount   = if ($null -ne $g.CrCount)          { [int]$g.CrCount }          else { 0 }

        $colorClass = Get-ReadinessColorClass -Percent $pct
        $progressHtml = Build-ProgressBarHtml -Percent $pct

        $statusLabel = if ($pct -ge 80)    { 'Ready' }
                       elseif ($pct -ge 50) { 'In Progress' }
                       else                 { 'Blocked' }
        $statusBadgeHtml = Get-StatusBadgeHtml -Status $statusLabel

        "<tr><td>$pairLabel</td><td>$srcCount</td><td>$tgtCount</td><td>$progressHtml</td><td>$statusBadgeHtml</td><td>$crCount</td></tr>"
    }

    return $rows -join "`n"
}

# ---------------------------------------------------------------------------
# Public: Build-AppReadinessHtml
# ---------------------------------------------------------------------------
function Build-AppReadinessHtml {
    <#
    .SYNOPSIS
        Generates tbody rows for the app readiness table.
        Returns empty string if no app data.
    #>
    [CmdletBinding()]
    param(
        [hashtable]$AppReadiness
    )

    if (-not $AppReadiness -or -not $AppReadiness.Apps -or $AppReadiness.Apps.Count -eq 0) {
        return '<tr><td colspan="6" class="empty-state">No application mapping data available</td></tr>'
    }

    $rows = foreach ($app in $AppReadiness.Apps) {
        $name      = Escape-MigrationHtml $(if ($app.Name)         { $app.Name }        else { '' })
        $srcGroup  = Escape-MigrationHtml $(if ($app.SourceGroup)  { $app.SourceGroup } else { '' })
        $tgtGroup  = Escape-MigrationHtml $(if ($app.TargetGroup)  { $app.TargetGroup } else { '' })
        $pct       = if ($null -ne $app.ReadinessPercent) { [int]$app.ReadinessPercent } else { 0 }
        $gapCount  = if ($null -ne $app.GapCount)         { [int]$app.GapCount }         else { 0 }

        $progressHtml    = Build-ProgressBarHtml -Percent $pct
        $statusBadgeHtml = Get-StatusBadgeHtml -Status $(if ($app.Status) { $app.Status } else { 'Unknown' })

        "<tr><td>$name</td><td>$srcGroup</td><td>$tgtGroup</td><td>$progressHtml</td><td>$gapCount</td><td>$statusBadgeHtml</td></tr>"
    }

    return $rows -join "`n"
}

# ---------------------------------------------------------------------------
# Public: Build-GapDetailSectionsHtml
# ---------------------------------------------------------------------------
function Build-GapDetailSectionsHtml {
    <#
    .SYNOPSIS
        Generates collapsible detail sections for each group pair gap analysis.
    #>
    [CmdletBinding()]
    param(
        [AllowEmptyCollection()]
        [array]$GapResults
    )

    if (-not $GapResults -or $GapResults.Count -eq 0) {
        return '<p class="empty-state">No gap analysis data available.</p>'
    }

    $sections = [System.Collections.Generic.List[string]]::new()

    foreach ($g in $GapResults) {
        $srcGroup  = if ($g.SourceGroup)  { $g.SourceGroup }  else { 'Unknown' }
        $tgtGroup  = if ($g.TargetGroup)  { $g.TargetGroup }  else { 'Unknown' }
        $srcDomain = if ($g.SourceDomain) { $g.SourceDomain } else { '' }
        $tgtDomain = if ($g.TargetDomain) { $g.TargetDomain } else { '' }

        $pairLabel = if ($srcDomain) {
            "$(Escape-MigrationHtml $srcDomain)\$(Escape-MigrationHtml $srcGroup) -&gt; $(Escape-MigrationHtml $tgtDomain)\$(Escape-MigrationHtml $tgtGroup)"
        } else {
            "$(Escape-MigrationHtml $srcGroup) -&gt; $(Escape-MigrationHtml $tgtGroup)"
        }

        $pct       = if ($null -ne $g.ReadinessPercent) { [int]$g.ReadinessPercent } else { 0 }
        $crCount   = if ($null -ne $g.CrCount)          { [int]$g.CrCount }          else { 0 }
        $items     = if ($g.Items) { @($g.Items) } else { @() }

        $summaryMeta = "$pct% ready &nbsp;|&nbsp; $crCount CR items"

        # Build inner table rows
        $tableRows = if ($items.Count -gt 0) {
            $itemRows = foreach ($item in $items) {
                $statusBadge   = Get-StatusBadgeHtml   -Status   $(if ($item.Status)   { $item.Status }   else { 'Unknown' })
                $priorityBadge = Get-PriorityBadgeHtml -Priority $(if ($item.Priority) { $item.Priority } else { 'Info'    })
                $confBadge     = Get-ConfidenceBadgeHtml -Confidence $(if ($item.CorrelationConfidence) { $item.CorrelationConfidence } else { '' })

                $srcUser = Escape-MigrationHtml $(if ($item.SourceSam)   { $item.SourceSam }   else { '' })
                $tgtUser = Escape-MigrationHtml $(if ($item.TargetSam)   { $item.TargetSam }   else { '&mdash;' })
                $action  = Escape-MigrationHtml $(if ($item.Action)      { $item.Action }      else { '' })

                "<tr><td>$statusBadge</td><td>$priorityBadge</td><td>$srcUser</td><td>$tgtUser</td><td>$confBadge</td><td>$action</td></tr>"
            }

            @"
<div class="table-wrap">
<table>
    <thead>
        <tr>
            <th data-sort="string">Status <span class="sort-indicator">&#8597;</span></th>
            <th data-sort="string">Priority <span class="sort-indicator">&#8597;</span></th>
            <th data-sort="string">Source User <span class="sort-indicator">&#8597;</span></th>
            <th data-sort="string">Target User <span class="sort-indicator">&#8597;</span></th>
            <th data-sort="string">Confidence <span class="sort-indicator">&#8597;</span></th>
            <th data-sort="string">Action <span class="sort-indicator">&#8597;</span></th>
        </tr>
    </thead>
    <tbody>
        $($itemRows -join "`n        ")
    </tbody>
</table>
</div>
"@
        } else {
            '<p class="empty-state">No gap items for this group pair.</p>'
        }

        $sections.Add(@"
<details class="group-detail">
    <summary>
        <span class="badge badge-migration">Gap</span>
        <span class="summary-name">$pairLabel</span>
        <span class="summary-meta">$summaryMeta</span>
    </summary>
    <div class="group-detail-body">
        $tableRows
    </div>
</details>
"@)
    }

    return $sections -join "`n"
}

# ---------------------------------------------------------------------------
# Public: Build-CorrelationSectionsHtml
# ---------------------------------------------------------------------------
function Build-CorrelationSectionsHtml {
    <#
    .SYNOPSIS
        Generates collapsible correlation report sections per group pair.
        Rows with NeedsReview are highlighted amber.
    #>
    [CmdletBinding()]
    param(
        [hashtable]$CorrelationResults
    )

    if (-not $CorrelationResults -or $CorrelationResults.Count -eq 0) {
        return '<p class="empty-state">No user correlation data available.</p>'
    }

    $sections = [System.Collections.Generic.List[string]]::new()

    foreach ($key in $CorrelationResults.Keys | Sort-Object) {
        $result = $CorrelationResults[$key]

        $correlated     = if ($result.Correlated)      { @($result.Correlated)      } else { @() }
        $unmatchedSrc   = if ($result.UnmatchedSource) { @($result.UnmatchedSource) } else { @() }
        $unmatchedTgt   = if ($result.UnmatchedTarget) { @($result.UnmatchedTarget) } else { @() }
        $needsReview    = if ($result.NeedsReview)     { @($result.NeedsReview)     } else { @() }

        $allItems     = @($correlated) + @($needsReview)
        $totalItems   = $allItems.Count + $unmatchedSrc.Count + $unmatchedTgt.Count
        $reviewCount  = $needsReview.Count

        $escapedKey   = Escape-MigrationHtml $key
        $summaryMeta  = "$totalItems users"
        if ($reviewCount -gt 0) { $summaryMeta += " &nbsp;|&nbsp; $reviewCount need review" }

        # Build table rows from correlated + review items
        $tableRows = if ($allItems.Count -gt 0 -or $unmatchedSrc.Count -gt 0) {
            $rows = [System.Collections.Generic.List[string]]::new()

            foreach ($item in $allItems) {
                $isReview = ($needsReview -contains $item) -or ($item.NeedsReview -eq $true)
                $rowClass = if ($isReview) { ' class="needs-review"' } else { '' }

                # Correlation items carry nested SourceUser/TargetUser hashtables
                # (from Find-UserCorrelations), not flat Source*/Target* fields.
                $srcSam   = Escape-MigrationHtml $(if ($item.SourceUser -and $item.SourceUser.SamAccountName) { $item.SourceUser.SamAccountName } else { '' })
                $srcEmail = Escape-MigrationHtml $(if ($item.SourceUser -and $item.SourceUser.Email)          { $item.SourceUser.Email }          else { '' })
                $tgtSam   = Escape-MigrationHtml $(if ($item.TargetUser -and $item.TargetUser.SamAccountName) { $item.TargetUser.SamAccountName } else { '' })
                $tgtEmail = Escape-MigrationHtml $(if ($item.TargetUser -and $item.TargetUser.Email)          { $item.TargetUser.Email }          else { '' })
                $matchType = Escape-MigrationHtml $(if ($item.MatchType)  { $item.MatchType }   else { '' })
                $confBadge = Get-ConfidenceBadgeHtml -Confidence $(if ($item.Confidence) { $item.Confidence } else { '' })
                $reviewFlag = if ($isReview) { '<span class="badge badge-p2">Review</span>' } else { '' }

                $rows.Add("<tr$rowClass><td>$srcSam</td><td>$srcEmail</td><td>$tgtSam</td><td>$tgtEmail</td><td>$matchType</td><td>$confBadge</td><td>$reviewFlag</td></tr>")
            }

            foreach ($item in $unmatchedSrc) {
                $srcSam   = Escape-MigrationHtml $(if ($item.SourceSam)   { $item.SourceSam }   else { if ($item.SamAccountName) { $item.SamAccountName } else { '' } })
                $srcEmail = Escape-MigrationHtml $(if ($item.Email)       { $item.Email }       else { '' })
                $confBadge = Get-ConfidenceBadgeHtml -Confidence 'None'
                $rows.Add("<tr><td>$srcSam</td><td>$srcEmail</td><td>&mdash;</td><td>&mdash;</td><td>No match</td><td>$confBadge</td><td><span class='badge badge-notprovisioned'>Not Provisioned</span></td></tr>")
            }

            @"
<div class="table-wrap">
<table>
    <thead>
        <tr>
            <th data-sort="string">Source SAM <span class="sort-indicator">&#8597;</span></th>
            <th data-sort="string">Source Email <span class="sort-indicator">&#8597;</span></th>
            <th data-sort="string">Target SAM <span class="sort-indicator">&#8597;</span></th>
            <th data-sort="string">Target Email <span class="sort-indicator">&#8597;</span></th>
            <th data-sort="string">Match Type <span class="sort-indicator">&#8597;</span></th>
            <th data-sort="string">Confidence <span class="sort-indicator">&#8597;</span></th>
            <th data-sort="string">Needs Review <span class="sort-indicator">&#8597;</span></th>
        </tr>
    </thead>
    <tbody>
        $($rows -join "`n        ")
    </tbody>
</table>
</div>
"@
        } else {
            '<p class="empty-state">No correlation data for this group pair.</p>'
        }

        $sections.Add(@"
<details class="group-detail">
    <summary>
        <span class="badge badge-matched">Correlation</span>
        <span class="summary-name">$escapedKey</span>
        <span class="summary-meta">$summaryMeta</span>
    </summary>
    <div class="group-detail-body">
        $tableRows
    </div>
</details>
"@)
    }

    return $sections -join "`n"
}

# ---------------------------------------------------------------------------
# Public: Build-FlaggedReviewHtml
# ---------------------------------------------------------------------------
function Build-FlaggedReviewHtml {
    <#
    .SYNOPSIS
        Generates a flat table of all NeedsReview items across all group pairs.
    #>
    [CmdletBinding()]
    param(
        [hashtable]$CorrelationResults
    )

    if (-not $CorrelationResults -or $CorrelationResults.Count -eq 0) {
        return '<tr><td colspan="5" class="empty-state">No flagged items</td></tr>'
    }

    $allFlagged = [System.Collections.Generic.List[object]]::new()
    foreach ($key in $CorrelationResults.Keys | Sort-Object) {
        $result = $CorrelationResults[$key]
        if ($result.NeedsReview) {
            foreach ($item in $result.NeedsReview) {
                $allFlagged.Add($item)
            }
        }
    }

    if ($allFlagged.Count -eq 0) {
        return '<tr><td colspan="5" class="empty-state">No items flagged for review</td></tr>'
    }

    $rows = foreach ($item in $allFlagged) {
        # Correlation items carry nested SourceUser/TargetUser hashtables and a
        # Confidence string (no numeric Score), so the 4th column is Confidence.
        $srcUser    = Escape-MigrationHtml $(if ($item.SourceUser -and $item.SourceUser.SamAccountName) { $item.SourceUser.SamAccountName } else { '' })
        $tgtUser    = Escape-MigrationHtml $(if ($item.TargetUser -and $item.TargetUser.SamAccountName) { $item.TargetUser.SamAccountName } else { '' })
        $matchType  = Escape-MigrationHtml $(if ($item.MatchType)    { $item.MatchType }    else { '' })
        $conf       = Escape-MigrationHtml $(if ($item.Confidence)   { $item.Confidence }   else { '' })
        $reason     = Escape-MigrationHtml $(if ($item.ReviewReason) { $item.ReviewReason } else { '' })
        "<tr class='needs-review'><td>$srcUser</td><td>$tgtUser</td><td>$matchType</td><td>$conf</td><td>$reason</td></tr>"
    }

    return $rows -join "`n"
}

# ---------------------------------------------------------------------------
# Public: Build-StaleAccountsHtml
# ---------------------------------------------------------------------------
function Build-StaleAccountsHtml {
    <#
    .SYNOPSIS
        Generates disabled and stale account tables.
        Returns empty-state message if no stale data.
    #>
    [CmdletBinding()]
    param(
        [hashtable]$StaleResults
    )

    if (-not $StaleResults) {
        return '<p class="empty-state">No stale account data available.</p>'
    }

    $disabled    = if ($StaleResults.Disabled) { @($StaleResults.Disabled) } else { @() }
    $stale       = if ($StaleResults.Stale)    { @($StaleResults.Stale)    } else { @() }
    $totalSkip   = $disabled.Count + $stale.Count

    $html = [System.Text.StringBuilder]::new()

    # ---- Disabled accounts ----
    [void]$html.Append('<div class="stale-subsection">')
    [void]$html.Append('<h3>Disabled Accounts</h3>')

    if ($disabled.Count -eq 0) {
        [void]$html.Append('<p class="empty-state">No disabled accounts found.</p>')
    } else {
        $rows = foreach ($acct in $disabled) {
            $sam    = Escape-MigrationHtml $(if ($acct.SamAccountName) { $acct.SamAccountName } else { '' })
            $dn     = Escape-MigrationHtml $(if ($acct.DisplayName)    { $acct.DisplayName }    else { '' })
            $email  = Escape-MigrationHtml $(if ($acct.Email)          { $acct.Email }          else { '' })
            $domain = Escape-MigrationHtml $(if ($acct.Domain)         { $acct.Domain }         else { '' })
            "<tr><td>$sam</td><td>$dn</td><td>$email</td><td>$domain</td><td><span class='badge badge-disabled'>Disabled</span></td></tr>"
        }

        $disabledTable = @"
<div class="table-wrap">
<table>
    <thead>
        <tr>
            <th data-sort="string">SamAccountName <span class="sort-indicator">&#8597;</span></th>
            <th data-sort="string">Display Name <span class="sort-indicator">&#8597;</span></th>
            <th data-sort="string">Email <span class="sort-indicator">&#8597;</span></th>
            <th data-sort="string">Domain <span class="sort-indicator">&#8597;</span></th>
            <th data-sort="string">Status <span class="sort-indicator">&#8597;</span></th>
        </tr>
    </thead>
    <tbody>
        $($rows -join "`n        ")
    </tbody>
</table>
</div>
"@
        [void]$html.Append($disabledTable)
    }

    [void]$html.Append('</div>')

    # ---- Stale accounts ----
    [void]$html.Append('<div class="stale-subsection">')
    [void]$html.Append('<h3>Stale Accounts (inactive past threshold)</h3>')

    if ($stale.Count -eq 0) {
        [void]$html.Append('<p class="empty-state">No stale accounts found.</p>')
    } else {
        $rows = foreach ($acct in $stale) {
            $sam         = Escape-MigrationHtml $(if ($acct.SamAccountName)   { $acct.SamAccountName }   else { '' })
            $dn          = Escape-MigrationHtml $(if ($acct.DisplayName)      { $acct.DisplayName }      else { '' })
            $email       = Escape-MigrationHtml $(if ($acct.Email)            { $acct.Email }            else { '' })
            $domain      = Escape-MigrationHtml $(if ($acct.Domain)           { $acct.Domain }           else { '' })
            $lastLogon   = Escape-MigrationHtml $(if ($acct.LastLogonDate)    { $acct.LastLogonDate }    else { 'Never' })
            $daysSince   = if ($null -ne $acct.DaysSinceLogon) { [string][int]$acct.DaysSinceLogon } else { '' }
            "<tr><td>$sam</td><td>$dn</td><td>$email</td><td>$domain</td><td>$lastLogon</td><td>$daysSince</td></tr>"
        }

        $staleTable = @"
<div class="table-wrap">
<table>
    <thead>
        <tr>
            <th data-sort="string">SamAccountName <span class="sort-indicator">&#8597;</span></th>
            <th data-sort="string">Display Name <span class="sort-indicator">&#8597;</span></th>
            <th data-sort="string">Email <span class="sort-indicator">&#8597;</span></th>
            <th data-sort="string">Domain <span class="sort-indicator">&#8597;</span></th>
            <th data-sort="string">Last Logon <span class="sort-indicator">&#8597;</span></th>
            <th data-sort="num">Days Since Logon <span class="sort-indicator">&#8597;</span></th>
        </tr>
    </thead>
    <tbody>
        $($rows -join "`n        ")
    </tbody>
</table>
</div>
"@
        [void]$html.Append($staleTable)
    }

    [void]$html.Append('</div>')

    # ---- Recommendation ----
    if ($totalSkip -gt 0) {
        [void]$html.Append("<div class='stale-recommendation'>These $totalSkip accounts should be excluded from migration. Mark them as 'Skip' in the gap analysis to remove from CR count.</div>")
    }

    return $html.ToString()
}

# ---------------------------------------------------------------------------
# Public: Build-CRSummaryHtml
# ---------------------------------------------------------------------------
function Build-CRSummaryHtml {
    <#
    .SYNOPSIS
        Generates Change Request summary HTML grouped by priority.
        Returns a hashtable: @{ Html = '...'; PlainText = '...' }
    #>
    [CmdletBinding()]
    param(
        [AllowEmptyCollection()]
        [array]$GapResults
    )

    if (-not $GapResults -or $GapResults.Count -eq 0) {
        return @{
            Html      = '<p class="empty-state">No gap analysis data to generate Change Requests from.</p>'
            PlainText = ''
        }
    }

    # Flatten all gap items from all groups
    $allItems = [System.Collections.Generic.List[object]]::new()
    foreach ($g in $GapResults) {
        if ($g.Items) {
            foreach ($item in $g.Items) {
                $allItems.Add(@{
                    Item        = $item
                    SourceGroup = $(if ($g.SourceGroup)  { $g.SourceGroup }  else { '' })
                    TargetGroup = $(if ($g.TargetGroup)  { $g.TargetGroup }  else { '' })
                    SourceDomain = $(if ($g.SourceDomain) { $g.SourceDomain } else { '' })
                    TargetDomain = $(if ($g.TargetDomain) { $g.TargetDomain } else { '' })
                })
            }
        }
    }

    $p1Items   = @($allItems | Where-Object { $_.Item.Priority -eq 'P1' })
    $p2Items   = @($allItems | Where-Object { $_.Item.Priority -eq 'P2' })
    $p3Items   = @($allItems | Where-Object { $_.Item.Priority -eq 'P3' })
    $infoItems = @($allItems | Where-Object { -not $_.Item.Priority -or $_.Item.Priority -eq 'Info' })

    $htmlBuilder = [System.Text.StringBuilder]::new()
    $ptBuilder   = [System.Text.StringBuilder]::new()

    [void]$ptBuilder.AppendLine('CHANGE REQUEST SUMMARY')
    [void]$ptBuilder.AppendLine('======================')
    [void]$ptBuilder.AppendLine("Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')")
    [void]$ptBuilder.AppendLine('')

    $prioritySections = @(
        @{ Priority = 'P1'; Label = 'P1 - Provisioning Required'; Items = $p1Items;   BadgeClass = 'badge-p1' }
        @{ Priority = 'P2'; Label = 'P2 - Group Membership Adds'; Items = $p2Items;   BadgeClass = 'badge-p2' }
        @{ Priority = 'P3'; Label = 'P3 - Reviews &amp; Orphans'; Items = $p3Items;   BadgeClass = 'badge-p3' }
        @{ Priority = 'Info'; Label = 'Info - Other Actions';     Items = $infoItems; BadgeClass = 'badge-info' }
    )

    foreach ($section in $prioritySections) {
        $items = $section.Items
        if ($items.Count -eq 0) { continue }

        $escapedLabel = $section.Label  # May contain &amp; already
        $badgeHtml    = "<span class='badge $($section.BadgeClass)'>$($section.Priority)</span>"

        [void]$htmlBuilder.Append("<div class='cr-priority-section'>")
        [void]$htmlBuilder.Append("<div class='cr-priority-header'>")
        [void]$htmlBuilder.Append("    $badgeHtml")
        [void]$htmlBuilder.Append("    <h3>$escapedLabel</h3>")
        [void]$htmlBuilder.Append("    <span class='cr-count-pill'>$($items.Count) items</span>")
        [void]$htmlBuilder.Append("</div>")

        # Plain text section
        $ptLabel = $section.Label -replace '&amp;', '&'
        [void]$ptBuilder.AppendLine("[$($section.Priority)] $ptLabel ($($items.Count) items)")
        [void]$ptBuilder.AppendLine(('-' * 60))

        # Build table rows
        $rows = foreach ($entry in $items) {
            $item     = $entry.Item
            $srcGroup = Escape-MigrationHtml $(if ($entry.SourceGroup) { $entry.SourceGroup } else { '' })
            $tgtGroup = Escape-MigrationHtml $(if ($entry.TargetGroup) { $entry.TargetGroup } else { '' })
            $srcUser  = Escape-MigrationHtml $(if ($item.SourceSam)    { $item.SourceSam }    else { '' })
            $tgtUser  = Escape-MigrationHtml $(if ($item.TargetSam)    { $item.TargetSam }    else { '' })
            $action   = Escape-MigrationHtml $(if ($item.Action)       { $item.Action }       else { '' })
            $status   = Get-StatusBadgeHtml  -Status $(if ($item.Status) { $item.Status } else { 'Unknown' })

            # Plain text row
            $ptSrcUser = if ($item.SourceSam) { $item.SourceSam } else { '' }
            $ptTgtUser = if ($item.TargetSam) { $item.TargetSam } else { '' }
            $ptAction  = if ($item.Action)    { $item.Action }    else { '' }
            [void]$ptBuilder.AppendLine("  Source: $ptSrcUser -> Target: $ptTgtUser | Action: $ptAction | Group: $($entry.SourceGroup) -> $($entry.TargetGroup)")

            "<tr><td>$status</td><td>$srcGroup</td><td>$tgtGroup</td><td>$srcUser</td><td>$tgtUser</td><td>$action</td></tr>"
        }
        [void]$ptBuilder.AppendLine('')

        $tableHtml = @"
<div class="table-wrap">
<table>
    <thead>
        <tr>
            <th data-sort="string">Status <span class="sort-indicator">&#8597;</span></th>
            <th data-sort="string">Source Group <span class="sort-indicator">&#8597;</span></th>
            <th data-sort="string">Target Group <span class="sort-indicator">&#8597;</span></th>
            <th data-sort="string">Source User <span class="sort-indicator">&#8597;</span></th>
            <th data-sort="string">Target User <span class="sort-indicator">&#8597;</span></th>
            <th data-sort="string">Action <span class="sort-indicator">&#8597;</span></th>
        </tr>
    </thead>
    <tbody>
        $($rows -join "`n        ")
    </tbody>
</table>
</div>
"@

        [void]$htmlBuilder.Append($tableHtml)
        [void]$htmlBuilder.Append('</div>')
    }

    if ($htmlBuilder.Length -eq 0) {
        [void]$htmlBuilder.Append('<p class="empty-state">No Change Request items found.</p>')
    }

    return @{
        Html      = $htmlBuilder.ToString()
        PlainText = $ptBuilder.ToString()
    }
}

# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

function Get-ReadinessColorClass {
    <#
    .SYNOPSIS
        Returns a CSS colour class name based on readiness percentage.
        green >= 80%, amber >= 50%, red < 50%
    #>
    param([int]$Percent)
    if ($Percent -ge 80) { return 'green' }
    if ($Percent -ge 50) { return 'amber' }
    return 'red'
}

function Build-ProgressBarHtml {
    <#
    .SYNOPSIS
        Returns an inline CSS progress bar HTML snippet for a readiness percentage.
    #>
    param([int]$Percent)
    $colorClass = Get-ReadinessColorClass -Percent $Percent
    $pctText    = "$Percent%"
    return @"
<div class="progress-cell">
    <div class="progress-wrap" style="flex:1">
        <div class="progress-bar $colorClass" data-pct="$Percent" style="width:0%"></div>
    </div>
    <span class="progress-pct">$pctText</span>
</div>
"@
}

function Get-StatusBadgeHtml {
    <#
    .SYNOPSIS
        Returns a <span class="badge ..."> for a migration status string.
        Handles: Ready, AddToGroup, Add to Group, NotProvisioned, Not Provisioned,
                 OrphanedAccess, Orphaned Access, Skip, In Progress, Blocked.
    #>
    param([string]$Status)

    $normalized = ($Status -replace '\s', '').ToLower()

    switch ($normalized) {
        'ready'            { return "<span class='badge badge-ready'>Ready</span>" }
        'addtogroup'       { return "<span class='badge badge-addtogroup'>Add to Group</span>" }
        'existsnotingroup' { return "<span class='badge badge-addtogroup'>Exists - Add to Group</span>" }
        'notprovisioned'   { return "<span class='badge badge-notprovisioned'>Not Provisioned</span>" }
        'notindomain'      { return "<span class='badge badge-notprovisioned'>Not In Domain</span>" }
        'orphanedaccess'   { return "<span class='badge badge-orphanedaccess'>Orphaned Access</span>" }
        'skip'             { return "<span class='badge badge-skip'>Skip</span>" }
        'skip-stale'       { return "<span class='badge badge-skip'>Skip (Stale)</span>" }
        'skip-disabled'    { return "<span class='badge badge-skip'>Skip (Disabled)</span>" }
        'inprogress'       { return "<span class='badge badge-addtogroup'>In Progress</span>" }
        'blocked'          { return "<span class='badge badge-notprovisioned'>Blocked</span>" }
        default            { return "<span class='badge badge-skip'>$(Escape-MigrationHtml $Status)</span>" }
    }
}

function Get-PriorityBadgeHtml {
    <#
    .SYNOPSIS
        Returns a <span class="badge ..."> for a priority string (P1/P2/P3/Info).
    #>
    param([string]$Priority)

    switch ($Priority.ToUpper()) {
        'P1'   { return "<span class='badge badge-p1'>P1</span>" }
        'P2'   { return "<span class='badge badge-p2'>P2</span>" }
        'P3'   { return "<span class='badge badge-p3'>P3</span>" }
        default { return "<span class='badge badge-info'>Info</span>" }
    }
}

function Get-ConfidenceBadgeHtml {
    <#
    .SYNOPSIS
        Returns a <span class="badge ..."> for a correlation confidence string.
        Handles: High, Medium, Low, None (empty treated as no badge).
    #>
    param([string]$Confidence)

    if (-not $Confidence) { return '' }

    switch ($Confidence.ToLower()) {
        'high'   { return "<span class='badge badge-high'>High</span>" }
        'medium' { return "<span class='badge badge-medium'>Medium</span>" }
        'low'    { return "<span class='badge badge-low'>Low</span>" }
        'none'   { return "<span class='badge badge-skip'>None</span>" }
        default  { return "<span class='badge badge-skip'>$(Escape-MigrationHtml $Confidence)</span>" }
    }
}
