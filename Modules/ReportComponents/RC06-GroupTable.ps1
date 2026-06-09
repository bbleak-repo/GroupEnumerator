<#
.SYNOPSIS
    RC06 - Group Table component. Condensed one-row-per-group roster.
.DESCRIPTION
    The clean, condensed default view: GroupName, Domain, direct MemberCount,
    Nested, Skipped. Numbers-only. Sorted by member count descending. Domain
    column is shown only when more than one domain is present.

    Options:
      Sort [string]  - 'count' (default) or 'name'.
      MaxRows [int]  - cap rows (default 1000), largest first.
    Self-registers on load.
#>

function New-RCGroupTableComponent {
    [CmdletBinding()]
    [OutputType([string])]
    param([hashtable]$Context, [hashtable]$Options = @{}, [hashtable]$Palette)

    $multiDomain = (@($Context.Domains).Count -ge 2)

    $rows = New-Object System.Collections.Generic.List[object]
    foreach ($g in @($Context.GroupResults)) {
        $d = Get-RCProp $g 'Data'
        if ($null -eq $d) { continue }
        $rows.Add([pscustomobject]@{
            Name    = [string](Get-RCProp $d 'GroupName')
            Domain  = [string](Get-RCProp $d 'Domain')
            Count   = Get-RCDirectCount $d
            Nested  = (Get-RCProp $d 'IsNested') -eq $true
            Skipped = (Get-RCProp $d 'Skipped') -eq $true
        })
    }

    $sortMode = if ($Options.ContainsKey('Sort')) { [string]$Options['Sort'] } else { 'count' }
    if ($sortMode -eq 'name') {
        $sorted = @($rows | Sort-Object Domain, Name)
    } else {
        $sorted = @($rows | Sort-Object -Property @{ Expression = 'Count'; Descending = $true }, @{ Expression = 'Name'; Descending = $false })
    }

    $maxRows = 1000
    if ($Options.ContainsKey('MaxRows')) { try { $maxRows = [int]$Options['MaxRows'] } catch { } }
    $totalRows = $sorted.Count
    $truncNote = ''
    if ($totalRows -gt $maxRows) {
        $sorted = $sorted[0..($maxRows - 1)]
        $truncNote = ('<div class="rc-note" style="margin-top:10px;">Showing {0} of {1} groups (MaxRows cap).</div>' -f $maxRows, $totalRows)
    }

    if (@($sorted).Count -eq 0) {
        return '<section class="rc-section"><h2 class="rc-section-h">Group Table</h2><div class="rc-note">No groups to display.</div></section>'
    }

    $domHead = if ($multiDomain) { '<th>Domain</th>' } else { '' }

    $body = New-Object System.Text.StringBuilder
    foreach ($r in $sorted) {
        $nm = ConvertTo-RCHtmlText $r.Name
        $domCell = if ($multiDomain) { ('<td>{0}</td>' -f (ConvertTo-RCHtmlText $r.Domain)) } else { '' }
        $nestBadge = if ($r.Nested) { '<span class="rc-badge neutral">Yes</span>' } else { '<span class="rc-badge neutral">No</span>' }
        $skipBadge = if ($r.Skipped) { '<span class="rc-badge warn">Yes</span>' } else { '<span class="rc-badge neutral">No</span>' }
        [void]$body.AppendLine(('<tr><td>{0}</td>{1}<td class="num">{2}</td><td>{3}</td><td>{4}</td></tr>' -f $nm, $domCell, $r.Count, $nestBadge, $skipBadge))
    }

    # Sum only enumerated (non-skipped) groups so the estate total agrees with the
    # rest of the RC family (kpi-cards/heatmap/top-n all exclude skipped). Skipped
    # groups are still shown as rows, flagged.
    $totalMembers = (($sorted | Where-Object { -not $_.Skipped }) | Measure-Object -Property Count -Sum).Sum
    if ($null -eq $totalMembers) { $totalMembers = 0 }

    return @"
<section class="rc-section">
<h2 class="rc-section-h">Group Table</h2>
<p class="rc-section-d">Condensed roster &mdash; one row per group (numbers-only). $totalRows groups, $totalMembers direct members (enumerated; skipped groups excluded from the total).</p>
<table class="rc-table">
<thead><tr><th>Group</th>$domHead<th class="num">Members</th><th>Nested</th><th>Skipped</th></tr></thead>
<tbody>
$($body.ToString())</tbody>
</table>
$truncNote
</section>
"@
}

Register-RCComponent -Key 'group-table' -DisplayName 'Condensed Group Table' `
    -Description 'One row per group: name, domain, member count, nested, skipped.' `
    -FunctionName 'New-RCGroupTableComponent' -Requires @('GroupResults') `
    -DefaultOptions @{ Sort = 'count'; MaxRows = 1000 }
