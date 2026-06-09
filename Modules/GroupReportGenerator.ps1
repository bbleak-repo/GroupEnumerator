<#
.SYNOPSIS
    HTML report generation module for cross-domain group enumeration tool.

.DESCRIPTION
    Generates professional HTML reports comparing group membership across domains.
    Supports dark/light theme toggle, collapsible per-group detail sections,
    diff-highlighted side-by-side member tables, and JSON cache import/export.

.NOTES
    HTML escaping: manual replacement of &, <, >, ", ' (no System.Web dependency)
    File writes use UTF-8 without BOM via [System.IO.File]::WriteAllText
    No emoji in PowerShell code (per project conventions)
#>

# ---- Tool version constant ----
$script:GroupReportVersion = '1.0.0'

# ---- Resolve template path at load time (dot-source context has valid $PSScriptRoot) ----
$script:GroupReportModuleDir  = $PSScriptRoot
$script:GroupReportProjectRoot = Split-Path -Parent $script:GroupReportModuleDir
$script:GroupReportTemplatePath = Join-Path (Join-Path $script:GroupReportProjectRoot 'Templates') 'group-report-template.html'

# ---------------------------------------------------------------------------
# Public: Export-GroupReport
# ---------------------------------------------------------------------------
function Export-GroupReport {
    <#
    .SYNOPSIS
        Generates an HTML group membership comparison report.

    .PARAMETER GroupResults
        Array of group result hashtables from Get-GroupMembers.
        Each element: @{ Data = @{ GroupName; Domain; Members; MemberCount; Skipped; SkipReason }; Errors = @() }

    .PARAMETER MatchResults
        Hashtable from Find-MatchingGroups, or $null when fuzzy matching was not used.
        Expected keys: Matched (array), Unmatched (array)

    .PARAMETER OutputPath
        Full file path for the output HTML file.

    .PARAMETER Theme
        Initial theme: "dark" (default) or "light". User can toggle in browser.

    .PARAMETER Config
        Configuration hashtable (from group-enum-config.json). Used for tool version etc.

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
        $toolVersion = if ($Config.ToolVersion) { $Config.ToolVersion } else { $script:GroupReportVersion }

        # Use template path resolved at module load time
        $templatePath = $script:GroupReportTemplatePath

        if (Test-Path $templatePath) {
            $template = [System.IO.File]::ReadAllText($templatePath, [System.Text.Encoding]::UTF8)
        } else {
            throw "Template not found: $templatePath"
        }

        # Collect unique domains for header
        $domains = @($GroupResults | ForEach-Object { $_.Data.Domain } | Sort-Object -Unique)

        # Compute skipped separately (they appear in summary but not detail diff)
        $skippedResults   = @($GroupResults | Where-Object { $_.Data.Skipped -eq $true })
        $enumerated       = @($GroupResults | Where-Object { $_.Data.Skipped -ne $true })

        # Aggregate totals
        $totalMembers = 0
        foreach ($e in $enumerated) { $totalMembers += [int]$e.Data.MemberCount }

        # ---- Domain mode: matched/unmatched only make sense across >=2 domains ----
        # Fuzzy matching requires two distinct domains (FuzzyMatcher), so a
        # single-domain run has nothing to match. In that case we present the
        # enumerated groups simply as "Groups" rather than mislabelling them all
        # as "unmatched".
        $reportDomains = @($enumerated | ForEach-Object { $_.Data.Domain } | Where-Object { $_ } | Sort-Object -Unique)
        $isCrossDomain = ($null -ne $MatchResults) -or ($reportDomains.Count -ge 2)

        # ---- Categorise results ----
        $matchedItems   = @()
        $unmatchedItems = @()

        if ($isCrossDomain) {
            if ($MatchResults -and $MatchResults.Matched) {
                $matchedItems   = @($MatchResults.Matched)
            }
            if ($MatchResults -and $MatchResults.Unmatched) {
                $unmatchedItems = @($MatchResults.Unmatched)
            } elseif (-not $MatchResults) {
                $unmatchedItems = $enumerated | ForEach-Object { $_.Data }
            }
        } else {
            # Single domain: the enumerated groups are simply "Groups".
            $unmatchedItems = $enumerated | ForEach-Object { $_.Data }
        }

        $totalGroups   = $GroupResults.Count
        $matchedCount  = $matchedItems.Count
        $unmatchedCount = $unmatchedItems.Count
        $skippedCount  = $skippedResults.Count

        # ---- Build domain summary line for header ----
        $domainSummaryHtml = Build-DomainSummaryHtml -Domains $domains -GroupResults $GroupResults

        # ---- Build HTML blocks ----
        $summaryCardsHtml  = Build-SummaryCardsHtml `
            -TotalGroups   $totalGroups   `
            -TotalMembers  $totalMembers  `
            -MatchedCount  $matchedCount  `
            -UnmatchedCount $unmatchedCount `
            -SkippedCount  $skippedCount `
            -SingleDomain:(-not $isCrossDomain)

        $matchedTableHtml   = Build-MatchedTableHtml   -MatchedItems $matchedItems -GroupResults $GroupResults
        $unmatchedTableHtml = Build-UnmatchedTableHtml -UnmatchedItems $unmatchedItems
        $skippedTableHtml   = Build-SkippedTableHtml   -SkippedResults $skippedResults

        $detailSectionsHtml = Build-AllDetailSectionsHtml `
            -MatchedItems   $matchedItems   `
            -UnmatchedItems $unmatchedItems `
            -GroupResults   $GroupResults

        # ---- Report title ----
        $domainList = $domains -join ' vs '
        $title = if ($domainList) { "Group Membership Report: $domainList" } else { 'Group Membership Report' }

        # ---- Apply initial theme class ----
        # Use String.Replace (not -replace) for all substitutions: the values
        # are HTML fragments holding user-supplied data (group names, SAMs,
        # display names) that may contain '$', which -replace would interpret
        # as a regex backreference and silently drop.
        $themeClass = if ($Theme -eq 'light') { 'theme-light' } else { 'theme-dark' }
        $template = $template.Replace('<html lang="en" class="theme-dark">', "<html lang=`"en`" class=`"$themeClass`">")

        # ---- Replace placeholders ----
        $template = $template.Replace('{{TITLE}}',          [string]$title)
        $template = $template.Replace('{{TIMESTAMP}}',      [string]$timestamp)
        $template = $template.Replace('{{TOOL_VERSION}}',   [string]$toolVersion)
        $template = $template.Replace('{{DOMAIN_SUMMARY}}', [string]$domainSummaryHtml)
        $template = $template.Replace('{{SUMMARY_CARDS}}',  [string]$summaryCardsHtml)
        $template = $template.Replace('{{MATCHED_TABLE}}',  [string]$matchedTableHtml)
        $template = $template.Replace('{{UNMATCHED_TABLE}}',[string]$unmatchedTableHtml)
        $template = $template.Replace('{{SKIPPED_TABLE}}',  [string]$skippedTableHtml)
        $template = $template.Replace('{{DETAIL_SECTIONS}}',[string]$detailSectionsHtml)
        $template = $template.Replace('{{TOTAL_GROUPS}}',   [string]$totalGroups)
        $template = $template.Replace('{{TOTAL_MEMBERS}}',  [string]$totalMembers)
        $template = $template.Replace('{{MATCHED_COUNT}}',  [string]$matchedCount)
        $template = $template.Replace('{{UNMATCHED_COUNT}}',[string]$unmatchedCount)
        $template = $template.Replace('{{SKIPPED_COUNT}}',  [string]$skippedCount)
        # Domain-aware: hide the Matched section + relabel the groups table in single-domain mode.
        $template = $template.Replace('{{MATCHED_DISPLAY}}', $(if ($isCrossDomain) { '' } else { 'display:none' }))
        $template = $template.Replace('{{GROUPS_HEADING}}',  $(if ($isCrossDomain) { 'Unmatched Groups' } else { 'Groups' }))

        # ---- Write output ----
        [System.IO.File]::WriteAllText($OutputPath, $template, [System.Text.UTF8Encoding]::new($false))

        Write-Verbose "Group report generated: $OutputPath"
        return $OutputPath

    } catch {
        throw "Export-GroupReport failed: $_"
    }
}

# ---------------------------------------------------------------------------
# Public: Export-GroupDataJson
# ---------------------------------------------------------------------------
function Export-GroupDataJson {
    <#
    .SYNOPSIS
        Saves group enumeration data to a JSON cache file.

    .PARAMETER GroupResults
        Array of group result hashtables.

    .PARAMETER MatchResults
        Hashtable from Find-MatchingGroups, or $null.

    .PARAMETER OutputPath
        Full file path for the output JSON file.

    .PARAMETER CsvSource
        Original CSV path, stored in metadata for traceability.

    .OUTPUTS
        String path to the generated JSON file.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [array]$GroupResults,

        [Parameter(Mandatory = $false)]
        [hashtable]$MatchResults = $null,

        [Parameter(Mandatory = $true)]
        [string]$OutputPath,

        [Parameter(Mandatory = $false)]
        [string]$CsvSource = ''
    )

    try {
        $domains = @($GroupResults | ForEach-Object { $_.Data.Domain } | Sort-Object -Unique)

        $jsonData = @{
            Metadata = @{
                GeneratedTimestamp = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
                ToolVersion        = $script:GroupReportVersion
                CsvSource          = $CsvSource
                Domains            = $domains
                FuzzyMatchEnabled  = ($null -ne $MatchResults)
            }
            Groups       = $GroupResults
            MatchResults = $MatchResults
        }

        $jsonContent = $jsonData | ConvertTo-Json -Depth 6
        [System.IO.File]::WriteAllText($OutputPath, $jsonContent, [System.Text.UTF8Encoding]::new($false))

        Write-Verbose "Group data cached: $OutputPath"
        return $OutputPath

    } catch {
        throw "Export-GroupDataJson failed: $_"
    }
}

# ---------------------------------------------------------------------------
# Public: Export-MembersCsv
# ---------------------------------------------------------------------------
function Export-MembersCsv {
    <#
    .SYNOPSIS
        Exports a flat roster of all enumerated group members to CSV.

    .DESCRIPTION
        One row per (group, member): Domain, GroupName, SamAccountName, DisplayName,
        Email, Enabled. A user who belongs to several listed groups appears once per
        group. This is a full-inventory ("everyone in the list") export, additive and
        independent of change tracking. Use -ResolveNested upstream to flatten nested
        groups down to users before enumeration if desired.

    .PARAMETER GroupResults
        Array of group result hashtables from enumeration.

    .PARAMETER OutputPath
        Full path for the output CSV.

    .PARAMETER Attributes
        Optional extra attribute names (the same list passed to -IncludeAttributes
        during enumeration) to append as columns, e.g. 'manager','title'. The values
        must already be present on each member record. 'manager' is expanded into two
        columns -- Manager (resolved display name) and ManagerDN -- to match how the
        enumerator stores it. Unknown/missing values render as empty.

    .OUTPUTS
        String path to the generated CSV.
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
        [string[]]$Attributes = @()
    )

    # RFC 4180 field escaping: quote any field containing a comma, quote, CR or LF
    # and double embedded quotes, so a DisplayName like 'Smith, "Bob"' cannot shift columns.
    function ConvertTo-MemberCsvField {
        param([string]$Value)
        if ($null -eq $Value) { return '' }
        if ($Value -match '[",\r\n]') { return '"' + ($Value -replace '"', '""') + '"' }
        return $Value
    }

    try {
        # Resolve extra attribute columns. 'manager' expands to Manager + ManagerDN,
        # mirroring how Get-GroupMembers stores the DN-resolved manager.
        $attrCols = [System.Collections.Generic.List[hashtable]]::new()
        foreach ($a in @($Attributes | Where-Object { $_ } | ForEach-Object { $_.Trim() })) {
            if ($a -ieq 'manager') {
                $attrCols.Add(@{ Header = 'Manager';               Key = 'Manager' })
                $attrCols.Add(@{ Header = 'ManagerSamAccountName'; Key = 'ManagerSamAccountName' })
                $attrCols.Add(@{ Header = 'ManagerEmail';          Key = 'ManagerEmail' })
                $attrCols.Add(@{ Header = 'ManagerDN';             Key = 'ManagerDN' })
            } else {
                $attrCols.Add(@{ Header = $a; Key = $a })
            }
        }

        $rows = [System.Collections.Generic.List[string]]::new()
        $headerFields = @('Domain', 'GroupName', 'SamAccountName', 'DisplayName', 'Email', 'Enabled') + @($attrCols | ForEach-Object { $_.Header })
        $rows.Add((@($headerFields | ForEach-Object { ConvertTo-MemberCsvField ([string]$_) }) -join ','))

        foreach ($gr in $GroupResults) {
            if (-not $gr.Data) { continue }
            $domain = [string]$gr.Data.Domain
            $group  = [string]$gr.Data.GroupName
            $members = if ($gr.Data.Members -is [array]) { $gr.Data.Members }
                       elseif ($gr.Data.Members) { @(, $gr.Data.Members) }
                       else { @() }

            foreach ($m in $members) {
                $fields = [System.Collections.Generic.List[string]]::new()
                $fields.Add([string]$domain)
                $fields.Add([string]$group)
                $fields.Add([string]$m.SamAccountName)
                $fields.Add([string]$m.DisplayName)
                $fields.Add([string]$m.Email)
                $fields.Add([string]$m.Enabled)
                foreach ($col in $attrCols) {
                    $fields.Add([string]($m.$($col.Key)))
                }
                $rows.Add((@($fields | ForEach-Object { ConvertTo-MemberCsvField $_ }) -join ','))
            }
        }

        $outDir = Split-Path $OutputPath -Parent
        if ($outDir -and -not (Test-Path $outDir)) {
            $null = New-Item -ItemType Directory -Path $outDir -Force
        }
        [System.IO.File]::WriteAllText($OutputPath, ($rows -join "`r`n"), [System.Text.UTF8Encoding]::new($false))

        Write-Verbose "Members roster CSV written: $OutputPath ($($rows.Count - 1) rows)"
        return $OutputPath

    } catch {
        throw "Export-MembersCsv failed: $_"
    }
}

# ---------------------------------------------------------------------------
# Public: Import-GroupDataJson
# ---------------------------------------------------------------------------
function Import-GroupDataJson {
    <#
    .SYNOPSIS
        Loads cached group enumeration data from a JSON file.

    .PARAMETER JsonPath
        Path to the JSON cache file created by Export-GroupDataJson.

    .OUTPUTS
        Hashtable with keys: Groups, MatchResults, Metadata
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$JsonPath
    )

    try {
        if (-not (Test-Path $JsonPath)) {
            throw "Cache file not found: $JsonPath"
        }

        $raw  = Get-Content -Path $JsonPath -Raw
        $data = $raw | ConvertFrom-Json

        # Convert PSCustomObject trees back to hashtables
        $groups = @($data.Groups | ForEach-Object {
            @{
                Data   = ConvertTo-Hashtable $_.Data
                Errors = @($_.Errors)
            }
        })

        $matchResults = $null
        if ($data.MatchResults) {
            $matchResults = @{
                Matched   = @($data.MatchResults.Matched   | ForEach-Object { ConvertTo-Hashtable $_ })
                Unmatched = @($data.MatchResults.Unmatched | ForEach-Object { ConvertTo-Hashtable $_ })
            }
        }

        $metadata = ConvertTo-Hashtable $data.Metadata

        Write-Verbose "Cache loaded: $JsonPath"
        return @{
            Groups       = $groups
            MatchResults = $matchResults
            Metadata     = $metadata
        }

    } catch {
        throw "Import-GroupDataJson failed: $_"
    }
}

# ---------------------------------------------------------------------------
# Internal: ConvertTo-Hashtable
# ---------------------------------------------------------------------------
function ConvertTo-Hashtable {
    <#
    .SYNOPSIS
        Recursively converts a PSCustomObject to a hashtable.
    #>
    param([Parameter(ValueFromPipeline = $true)] $InputObject)

    process {
        if ($null -eq $InputObject)                    { return $null }
        if ($InputObject -is [System.Collections.IList]) {
            return @($InputObject | ForEach-Object { ConvertTo-Hashtable $_ })
        }
        if ($InputObject -isnot [System.Management.Automation.PSCustomObject] -and
            $InputObject -isnot [System.Management.Automation.PSObject]) {
            return $InputObject
        }

        $ht = @{}
        foreach ($prop in $InputObject.PSObject.Properties) {
            $ht[$prop.Name] = ConvertTo-Hashtable $prop.Value
        }
        return $ht
    }
}

# ---------------------------------------------------------------------------
# Internal: Escape-Html
# ---------------------------------------------------------------------------
function Escape-Html {
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
# Internal: Build-DomainSummaryHtml
# ---------------------------------------------------------------------------
function Build-DomainSummaryHtml {
    param(
        [string[]]$Domains,
        [array]$GroupResults
    )

    if (-not $Domains -or $Domains.Count -eq 0) {
        return ''
    }

    $parts = foreach ($d in $Domains) {
        $count = @($GroupResults | Where-Object { $_.Data.Domain -eq $d }).Count
        "<strong>$(Escape-Html $d)</strong>: $count groups"
    }

    return '<p>' + ($parts -join ' &nbsp;|&nbsp; ') + '</p>'
}

# ---------------------------------------------------------------------------
# Public: Build-SummaryCardsHtml
# ---------------------------------------------------------------------------
function Build-SummaryCardsHtml {
    <#
    .SYNOPSIS
        Generates HTML for the summary stat cards row.
    #>
    [CmdletBinding()]
    param(
        [int]$TotalGroups,
        [int]$TotalMembers,
        [int]$MatchedCount,
        [int]$UnmatchedCount,
        [int]$SkippedCount,
        [switch]$SingleDomain
    )

    if ($SingleDomain) {
        # Single domain: matched/unmatched is meaningless (no second domain to
        # compare against), so those cards are omitted. Skipped stays -- it is the
        # large/over-threshold enumeration skip, independent of domain count.
        $cards = @(
            @{ Icon = '&#128101;'; IconClass = 'blue';  Value = $TotalGroups;  Label = 'Total Groups'   }
            @{ Icon = '&#128100;'; IconClass = 'blue';  Value = $TotalMembers; Label = 'Total Members'  }
            @{ Icon = '&#9940;';   IconClass = 'slate'; Value = $SkippedCount; Label = 'Skipped Groups' }
        )
    } else {
        $cards = @(
            @{ Icon = '&#128101;'; IconClass = 'blue';  Value = $TotalGroups;    Label = 'Total Groups'    }
            @{ Icon = '&#128100;'; IconClass = 'blue';  Value = $TotalMembers;   Label = 'Total Members'   }
            @{ Icon = '&#9989;';   IconClass = 'green'; Value = $MatchedCount;   Label = 'Matched Groups'  }
            @{ Icon = '&#9888;';   IconClass = 'amber'; Value = $UnmatchedCount; Label = 'Unmatched Groups'}
            @{ Icon = '&#9940;';   IconClass = 'slate'; Value = $SkippedCount;   Label = 'Skipped Groups'  }
        )
    }

    $lines = foreach ($card in $cards) {
        @"
<div class="stat-card">
    <div class="stat-icon $($card.IconClass)">$($card.Icon)</div>
    <div class="stat-body">
        <div class="stat-value">$($card.Value)</div>
        <div class="stat-label">$($card.Label)</div>
    </div>
</div>
"@
    }

    return $lines -join "`n"
}

# ---------------------------------------------------------------------------
# Public: Build-MatchedTableHtml
# ---------------------------------------------------------------------------
function Build-MatchedTableHtml {
    <#
    .SYNOPSIS
        Generates tbody rows for the matched groups comparison table.

    .PARAMETER MatchedItems
        Array of matched group pairs from FuzzyMatcher.
        Each item: @{ NormalizedName; Groups = @( @{ Domain; GroupName; MemberCount }, ... ); Score }

    .PARAMETER GroupResults
        Full group results array (used to confirm member counts when needed).
    #>
    [CmdletBinding()]
    param(
        [array]$MatchedItems,
        [array]$GroupResults
    )

    if (-not $MatchedItems -or $MatchedItems.Count -eq 0) {
        return '<tr><td colspan="6" class="empty-state">No matched groups</td></tr>'
    }

    $rows = foreach ($item in $MatchedItems) {
        $norm = Escape-Html $(if ($item.NormalizedName) { $item.NormalizedName } else { '(unknown)' })

        $groups = @($item.Groups)
        $g1 = if ($groups.Count -ge 1) { $groups[0] } else { $null }
        $g2 = if ($groups.Count -ge 2) { $groups[1] } else { $null }

        $dom1   = if ($g1) { Escape-Html "$($g1.Domain)\$($g1.GroupName)" } else { '&mdash;' }
        $count1 = if ($g1) { [int]$g1.MemberCount } else { 0 }

        $dom2   = if ($g2) { Escape-Html "$($g2.Domain)\$($g2.GroupName)" } else { '&mdash;' }
        $count2 = if ($g2) { [int]$g2.MemberCount } else { 0 }

        $delta  = $count2 - $count1
        $deltaHtml = Get-DeltaHtml -Delta $delta

        "<tr><td>$norm</td><td>$dom1</td><td>$count1</td><td>$dom2</td><td>$count2</td><td>$deltaHtml</td></tr>"
    }

    return $rows -join "`n"
}

# ---------------------------------------------------------------------------
# Internal: Build-UnmatchedTableHtml
# ---------------------------------------------------------------------------
function Build-UnmatchedTableHtml {
    param([array]$UnmatchedItems)

    if (-not $UnmatchedItems -or $UnmatchedItems.Count -eq 0) {
        return '<tr><td colspan="2" class="empty-state">No unmatched groups</td></tr>'
    }

    $rows = foreach ($item in $UnmatchedItems) {
        # UnmatchedItems may be @{ Domain; GroupName; MemberCount } or the full Data hashtable
        $domain    = if ($item.Domain)    { Escape-Html $item.Domain }    else { '' }
        $groupName = if ($item.GroupName) { Escape-Html $item.GroupName } else { '' }
        $count     = if ($null -ne $item.MemberCount) { [int]$item.MemberCount } else { 0 }
        "<tr><td>$domain\$groupName</td><td>$count</td></tr>"
    }

    return $rows -join "`n"
}

# ---------------------------------------------------------------------------
# Internal: Build-SkippedTableHtml
# ---------------------------------------------------------------------------
function Build-SkippedTableHtml {
    param([array]$SkippedResults)

    if (-not $SkippedResults -or $SkippedResults.Count -eq 0) {
        return '<tr><td colspan="2" class="empty-state">No skipped groups</td></tr>'
    }

    $rows = foreach ($result in $SkippedResults) {
        $d    = $result.Data
        $name = Escape-Html "$($d.Domain)\$($d.GroupName)"
        $rsn  = Escape-Html $(if ($d.SkipReason) { $d.SkipReason } else { 'Skipped' })
        "<tr><td>$name</td><td>$rsn</td></tr>"
    }

    return $rows -join "`n"
}

# ---------------------------------------------------------------------------
# Internal: Get-DeltaHtml
# ---------------------------------------------------------------------------
function Get-DeltaHtml {
    param([int]$Delta)
    if ($Delta -gt 0) {
        return "<span class='delta-pos'>+$Delta &#8593;</span>"
    } elseif ($Delta -lt 0) {
        return "<span class='delta-neg'>$Delta &#8595;</span>"
    } else {
        return "<span class='delta-zero'>&mdash;</span>"
    }
}

# ---------------------------------------------------------------------------
# Internal: Build-AllDetailSectionsHtml
# ---------------------------------------------------------------------------
function Build-AllDetailSectionsHtml {
    param(
        [array]$MatchedItems,
        [array]$UnmatchedItems,
        [array]$GroupResults
    )

    $sections = [System.Collections.Generic.List[string]]::new()

    # Matched groups: side-by-side diff
    foreach ($item in $MatchedItems) {
        $sections.Add( (Build-DetailSectionHtml -MatchItem $item -GroupResults $GroupResults -IsMatched $true) )
    }

    # Unmatched groups: single member table
    foreach ($item in $UnmatchedItems) {
        $sections.Add( (Build-DetailSectionHtml -MatchItem $null -UnmatchedGroup $item -GroupResults $GroupResults -IsMatched $false) )
    }

    if ($sections.Count -eq 0) {
        return '<p class="empty-state">No group details available.</p>'
    }

    return $sections -join "`n"
}

# ---------------------------------------------------------------------------
# Public: Build-DetailSectionHtml
# ---------------------------------------------------------------------------
function Build-DetailSectionHtml {
    <#
    .SYNOPSIS
        Generates a collapsible detail section for one group or matched pair.
    #>
    [CmdletBinding()]
    param(
        # For matched groups
        [hashtable]$MatchItem,
        # For unmatched groups
        [hashtable]$UnmatchedGroup,
        [array]$GroupResults,
        [bool]$IsMatched
    )

    if ($IsMatched -and $MatchItem) {
        return Build-MatchedDetailSection -MatchItem $MatchItem -GroupResults $GroupResults
    } else {
        return Build-UnmatchedDetailSection -UnmatchedGroup $UnmatchedGroup -GroupResults $GroupResults
    }
}

# ---------------------------------------------------------------------------
# Internal: Build-MatchedDetailSection
# ---------------------------------------------------------------------------
function Build-MatchedDetailSection {
    param(
        [hashtable]$MatchItem,
        [array]$GroupResults
    )

    $normalizedName = if ($MatchItem.NormalizedName) { $MatchItem.NormalizedName } else { '(unknown)' }
    $groups = @($MatchItem.Groups)

    $g1Data = if ($groups.Count -ge 1) { Find-GroupResult -GroupResults $GroupResults -Domain $groups[0].Domain -GroupName $groups[0].GroupName } else { $null }
    $g2Data = if ($groups.Count -ge 2) { Find-GroupResult -GroupResults $GroupResults -Domain $groups[1].Domain -GroupName $groups[1].GroupName } else { $null }

    $label1 = if ($g1Data) { Escape-Html "$($g1Data.Domain)\$($g1Data.GroupName)" } else { 'Domain 1' }
    $label2 = if ($g2Data) { Escape-Html "$($g2Data.Domain)\$($g2Data.GroupName)" } else { 'Domain 2' }

    $members1 = if ($g1Data -and $g1Data.Members) { @($g1Data.Members) } else { @() }
    $members2 = if ($g2Data -and $g2Data.Members) { @($g2Data.Members) } else { @() }

    # Build sets for diff
    $sams1 = @($members1 | ForEach-Object { if ($_.SamAccountName) { $_.SamAccountName.ToLower() } else { '' } })
    $sams2 = @($members2 | ForEach-Object { if ($_.SamAccountName) { $_.SamAccountName.ToLower() } else { '' } })

    $count1 = $members1.Count
    $count2 = $members2.Count
    $delta  = $count2 - $count1

    $summaryMeta = "$count1 vs $count2 members | delta: $(if($delta -ge 0){ '+' })$delta"
    $badgeClass  = 'badge-matched'
    $badgeText   = 'Matched'

    # Build per-row diff class for each member list
    $table1Html = Build-MemberTableWithDiff -Members $members1 -OtherSams $sams2 -DiffClass 'diff-only-a'
    $table2Html = Build-MemberTableWithDiff -Members $members2 -OtherSams $sams1 -DiffClass 'diff-only-b'

    $escapedNorm = Escape-Html $normalizedName

    return @"
<details class="group-detail">
    <summary>
        <span class="badge $badgeClass">$badgeText</span>
        <span class="summary-name">$escapedNorm</span>
        <span class="summary-meta">$summaryMeta</span>
    </summary>
    <div class="group-detail-body">
        <div class="diff-legend">
            <span class="diff-legend-item"><span class="diff-legend-swatch swatch-only-a"></span>Only in $label1</span>
            <span class="diff-legend-item"><span class="diff-legend-swatch swatch-only-b"></span>Only in $label2</span>
            <span class="diff-legend-item"><span class="diff-legend-swatch swatch-both"></span>Present in both</span>
        </div>
        <div class="members-comparison">
            <div>
                <div class="col-label">$label1 ($count1 members)</div>
                $table1Html
            </div>
            <div>
                <div class="col-label">$label2 ($count2 members)</div>
                $table2Html
            </div>
        </div>
    </div>
</details>
"@
}

# ---------------------------------------------------------------------------
# Internal: Build-UnmatchedDetailSection
# ---------------------------------------------------------------------------
function Build-UnmatchedDetailSection {
    param(
        [hashtable]$UnmatchedGroup,
        [array]$GroupResults
    )

    $domain    = if ($UnmatchedGroup.Domain)    { $UnmatchedGroup.Domain }    else { '' }
    $groupName = if ($UnmatchedGroup.GroupName) { $UnmatchedGroup.GroupName } else { '(unknown)' }

    $groupData = Find-GroupResult -GroupResults $GroupResults -Domain $domain -GroupName $groupName
    $members   = if ($groupData -and $groupData.Members) { @($groupData.Members) } else { @() }
    $count     = $members.Count

    $escapedLabel = Escape-Html "$domain\$groupName"
    $tableHtml    = ConvertTo-MemberTableHtml -Members $members

    return @"
<details class="group-detail">
    <summary>
        <span class="badge badge-unmatched">Unmatched</span>
        <span class="summary-name">$escapedLabel</span>
        <span class="summary-meta">$count members</span>
    </summary>
    <div class="group-detail-body">
        $tableHtml
    </div>
</details>
"@
}

# ---------------------------------------------------------------------------
# Internal: Find-GroupResult
# ---------------------------------------------------------------------------
function Find-GroupResult {
    param(
        [array]$GroupResults,
        [string]$Domain,
        [string]$GroupName
    )

    $match = $GroupResults | Where-Object {
        $_.Data.Domain -eq $Domain -and $_.Data.GroupName -eq $GroupName
    } | Select-Object -First 1

    if ($match) { return $match.Data }
    return $null
}

# ---------------------------------------------------------------------------
# Internal: Build-MemberTableWithDiff
# ---------------------------------------------------------------------------
function Build-MemberTableWithDiff {
    <#
    .SYNOPSIS
        Builds a member table where rows not present in the other domain are highlighted.

    .PARAMETER Members
        Array of member hashtables.

    .PARAMETER OtherSams
        Array of lowercased SamAccountNames from the other domain (for diff).

    .PARAMETER DiffClass
        CSS class to apply to rows unique to this domain.
    #>
    param(
        [array]$Members,
        [array]$OtherSams,
        [string]$DiffClass
    )

    if (-not $Members -or $Members.Count -eq 0) {
        return '<p class="empty-state">No members</p>'
    }

    $rows = foreach ($m in ($Members | Sort-Object SamAccountName)) {
        $sam  = Escape-Html $(if ($m.SamAccountName) { $m.SamAccountName } else { '' })
        $dn   = Escape-Html $(if ($m.DisplayName)    { $m.DisplayName }    else { '' })
        $mail = Escape-Html $(if ($m.Email)           { $m.Email }          else { '' })

        $enabledBool = $m.Enabled
        $statusHtml  = Get-EnabledBadgeHtml -Enabled $enabledBool

        $samLower = if ($m.SamAccountName) { $m.SamAccountName.ToLower() } else { '' }
        $rowClass = if ($OtherSams -notcontains $samLower) { " class='$DiffClass'" } else { '' }

        "<tr$rowClass><td>$sam</td><td>$dn</td><td>$mail</td><td>$statusHtml</td></tr>"
    }

    $count  = $Members.Count
    $html   = @"
<div class="table-wrap">
<table>
    <thead>
        <tr>
            <th data-sort="string">SamAccountName <span class="sort-indicator">&#8597;</span></th>
            <th data-sort="string">Display Name <span class="sort-indicator">&#8597;</span></th>
            <th data-sort="string">Email <span class="sort-indicator">&#8597;</span></th>
            <th data-sort="string">Status <span class="sort-indicator">&#8597;</span></th>
        </tr>
    </thead>
    <tbody>
        $($rows -join "`n        ")
    </tbody>
</table>
</div>
"@
    return $html
}

# ---------------------------------------------------------------------------
# Public: ConvertTo-MemberTableHtml
# ---------------------------------------------------------------------------
function ConvertTo-MemberTableHtml {
    <#
    .SYNOPSIS
        Generates a simple member table (no diff highlighting).

    .PARAMETER Members
        Array of member hashtables with SamAccountName, DisplayName, Email, Enabled.
    #>
    [CmdletBinding()]
    param(
        [array]$Members
    )

    if (-not $Members -or $Members.Count -eq 0) {
        return '<p class="empty-state">No members</p>'
    }

    $count = $Members.Count
    $rows  = foreach ($m in ($Members | Sort-Object SamAccountName)) {
        $idx  = [array]::IndexOf($Members, $m) + 1
        $sam  = Escape-Html $(if ($m.SamAccountName) { $m.SamAccountName } else { '' })
        $dn   = Escape-Html $(if ($m.DisplayName)    { $m.DisplayName }    else { '' })
        $mail = Escape-Html $(if ($m.Email)           { $m.Email }          else { '' })
        $statusHtml = Get-EnabledBadgeHtml -Enabled $m.Enabled
        "<tr><td>$idx</td><td>$sam</td><td>$dn</td><td>$mail</td><td>$statusHtml</td></tr>"
    }

    return @"
<div class="table-wrap">
<table>
    <thead>
        <tr>
            <th data-sort="num">#</th>
            <th data-sort="string">SamAccountName <span class="sort-indicator">&#8597;</span></th>
            <th data-sort="string">Display Name <span class="sort-indicator">&#8597;</span></th>
            <th data-sort="string">Email <span class="sort-indicator">&#8597;</span></th>
            <th data-sort="string">Status <span class="sort-indicator">&#8597;</span></th>
        </tr>
    </thead>
    <tbody>
        $($rows -join "`n        ")
    </tbody>
</table>
</div>
"@
}

# ---------------------------------------------------------------------------
# Internal: Get-EnabledBadgeHtml
# ---------------------------------------------------------------------------
function Get-EnabledBadgeHtml {
    param($Enabled)
    if ($Enabled -eq $true) {
        return '<span class="badge badge-enabled">Enabled</span>'
    } elseif ($Enabled -eq $false) {
        return '<span class="badge badge-disabled">Disabled</span>'
    } else {
        return '<span class="badge" style="background:rgba(148,163,184,0.15);color:var(--text-muted)">Unknown</span>'
    }
}
