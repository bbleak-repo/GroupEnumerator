<#
.SYNOPSIS
    RC07 - Governance Risk Flags component. Surfaces risk signals that are derivable
    from the enumerated data alone (no -DetectStale required): disabled members sitting
    in groups, empty groups, oversized/skipped groups, and nested groups. Numbers-only;
    optionally lists the groups carrying the most disabled members.
.DESCRIPTION
    A quick governance snapshot for reviewers: "what should I look at?" Disabled accounts
    are read straight from each member's Enabled flag, so this works on any enumeration
    (live or -FromCache) without the stale detector.

    Options:
      TopGroups [int] - rows in the "groups with disabled members" table (default 10).
    Self-registers on load.
#>

function New-RCRiskFlagsComponent {
    [CmdletBinding()]
    [OutputType([string])]
    param([hashtable]$Context, [hashtable]$Options = @{}, [hashtable]$Palette)

    function _rcCard {
        param([object]$N, [string]$L, [string]$Cls = '')
        $c = if ($Cls) { " $Cls" } else { '' }
        return ('<div class="rc-card{0}"><div class="n">{1}</div><div class="l">{2}</div></div>' -f $c, $N, (ConvertTo-RCHtmlText $L))
    }

    $all     = @($Context.GroupResults)
    $enum    = @($Context.Enumerated)
    $skipped = @($all | Where-Object { (Get-RCProp (Get-RCProp $_ 'Data') 'Skipped') -eq $true })
    $nested  = @($enum | Where-Object { (Get-RCProp (Get-RCProp $_ 'Data') 'IsNested') -eq $true })

    $empty = 0
    $disabledTotal = 0
    $disabledDistinct = New-Object 'System.Collections.Generic.HashSet[string]'
    $groupRisk = New-Object System.Collections.Generic.List[object]
    foreach ($g in $enum) {
        $d = Get-RCProp $g 'Data'
        if ((Get-RCDirectCount $d) -le 0) { $empty++ }
        $gd = 0
        foreach ($m in @(Get-RCProp $d 'Members')) {
            if ($null -eq $m) { continue }
            if ((Get-RCProp $m 'Enabled') -eq $false) {
                $disabledTotal++; $gd++
                $sam = [string](Get-RCProp $m 'SamAccountName')
                $key = if ([string]::IsNullOrWhiteSpace($sam)) { [string](Get-RCProp $m 'DistinguishedName') } else { $sam.ToLowerInvariant() }
                if (-not [string]::IsNullOrWhiteSpace($key)) { [void]$disabledDistinct.Add($key) }
            }
        }
        if ($gd -gt 0) {
            $groupRisk.Add([pscustomobject]@{ Name = [string](Get-RCProp $d 'GroupName'); Domain = [string](Get-RCProp $d 'Domain'); Disabled = $gd })
        }
    }

    $cards = New-Object System.Text.StringBuilder
    [void]$cards.Append((_rcCard -N $disabledDistinct.Count -L 'Disabled Members' -Cls $(if ($disabledDistinct.Count -gt 0) { 'danger' } else { 'ok' })))
    [void]$cards.Append((_rcCard -N $empty           -L 'Empty Groups'     -Cls $(if ($empty -gt 0) { 'warn' } else { '' })))
    [void]$cards.Append((_rcCard -N $skipped.Count   -L 'Oversized/Skipped' -Cls $(if ($skipped.Count -gt 0) { 'warn' } else { '' })))
    [void]$cards.Append((_rcCard -N $nested.Count    -L 'Nested Groups'    -Cls $(if ($nested.Count -gt 0) { 'accent' } else { '' })))

    $top = 10
    if ($Options.ContainsKey('TopGroups')) { try { $top = [int]$Options['TopGroups'] } catch { } }
    $multiDomain = (@($Context.Domains).Count -ge 2)
    $ranked = @($groupRisk | Sort-Object -Property @{ Expression = 'Disabled'; Descending = $true }, @{ Expression = 'Name'; Descending = $false })
    $tableHtml = ''
    if ($ranked.Count -gt 0) {
        $shown = if ($ranked.Count -gt $top) { $ranked[0..($top - 1)] } else { $ranked }
        $domHead = if ($multiDomain) { '<th>Domain</th>' } else { '' }
        $rows = New-Object System.Text.StringBuilder
        foreach ($r in $shown) {
            $domCell = if ($multiDomain) { ('<td>{0}</td>' -f (ConvertTo-RCHtmlText $r.Domain)) } else { '' }
            [void]$rows.AppendLine(('<tr><td>{0}</td>{1}<td class="num">{2}</td></tr>' -f (ConvertTo-RCHtmlText $r.Name), $domCell, $r.Disabled))
        }
        $cap = if ($ranked.Count -gt $top) { ('<div class="rc-note" style="margin-top:10px;">Showing the {0} groups with the most disabled members of {1}.</div>' -f $top, $ranked.Count) } else { '' }
        $tableHtml = @"
<table class="rc-table" style="margin-top:14px;">
<thead><tr><th>Group</th>$domHead<th class="num">Disabled Members</th></tr></thead>
<tbody>
$($rows.ToString())</tbody>
</table>
$cap
"@
    }

    return @"
<section class="rc-section">
<h2 class="rc-section-h">Governance Risk Flags</h2>
<p class="rc-section-d">Risk signals from the enumerated estate (numbers-only). Disabled accounts are read from member status &mdash; no stale-detection run required.</p>
<div class="rc-cards">$($cards.ToString())</div>
$tableHtml
</section>
"@
}

Register-RCComponent -Key 'risk-flags' -DisplayName 'Governance Risk Flags' `
    -Description 'Risk snapshot: disabled members, empty groups, oversized/skipped, nested.' `
    -FunctionName 'New-RCRiskFlagsComponent' -Requires @('GroupResults') `
    -DefaultOptions @{ TopGroups = 10 }
