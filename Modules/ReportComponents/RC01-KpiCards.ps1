<#
.SYNOPSIS
    RC01 - KPI Cards component. Headline counts for a composition.
.DESCRIPTION
    Numbers-only summary cards: total groups, enumerated, skipped, total direct
    members, empty groups, domains, and (when stale detection ran) at-risk members.
    Requires only GroupResults. Self-registers on load.
#>

function New-RCKpiCardsComponent {
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

    $totalMembers = 0; $empty = 0
    # Distinct accounts across the estate, keyed the same way B10 keys its
    # 'Distinct Members' headline (SamAccountName lowercased, DN fallback) so the
    # two reports' member headlines mean the same thing.
    $distinctSet = New-Object 'System.Collections.Generic.HashSet[string]'
    foreach ($g in $enum) {
        $d = Get-RCProp $g 'Data'
        $c = Get-RCDirectCount $d
        $totalMembers += $c
        if ($c -le 0) { $empty++ }
        foreach ($m in @(Get-RCProp $d 'Members')) {
            if ($null -eq $m) { continue }
            $sam = [string](Get-RCProp $m 'SamAccountName')
            $key = if ([string]::IsNullOrWhiteSpace($sam)) { [string](Get-RCProp $m 'DistinguishedName') } else { $sam.ToLowerInvariant() }
            if (-not [string]::IsNullOrWhiteSpace($key)) { [void]$distinctSet.Add($key) }
        }
    }
    $distinctMembers = $distinctSet.Count
    $domains = @($Context.Domains).Count

    $cards = New-Object System.Text.StringBuilder
    [void]$cards.Append((_rcCard -N $all.Count -L 'Groups' -Cls 'accent'))
    [void]$cards.Append((_rcCard -N $enum.Count -L 'Enumerated'))
    [void]$cards.Append((_rcCard -N $skipped.Count -L 'Skipped' -Cls $(if ($skipped.Count -gt 0) { 'warn' } else { '' })))
    [void]$cards.Append((_rcCard -N $totalMembers -L 'Direct Members'))
    [void]$cards.Append((_rcCard -N $distinctMembers -L 'Distinct Members'))
    [void]$cards.Append((_rcCard -N $empty -L 'Empty Groups' -Cls $(if ($empty -gt 0) { 'warn' } else { '' })))
    [void]$cards.Append((_rcCard -N $domains -L 'Domains'))

    if ($null -ne $Context.StaleResults) {
        $risk = 0
        $dis = Get-RCProp $Context.StaleResults 'Disabled'; if ($dis) { $risk += @($dis).Count }
        $sta = Get-RCProp $Context.StaleResults 'Stale';    if ($sta) { $risk += @($sta).Count }
        [void]$cards.Append((_rcCard -N $risk -L 'At-Risk Members' -Cls $(if ($risk -gt 0) { 'danger' } else { 'ok' })))
    }

    return @"
<section class="rc-section">
<h2 class="rc-section-h">Summary</h2>
<p class="rc-section-d">Headline counts across the monitored estate (numbers-only).</p>
<div class="rc-cards">$($cards.ToString())</div>
</section>
"@
}

Register-RCComponent -Key 'kpi-cards' -DisplayName 'Summary KPI Cards' `
    -Description 'Headline counts: groups, members, empty groups, domains, at-risk.' `
    -FunctionName 'New-RCKpiCardsComponent' -Requires @('GroupResults')
