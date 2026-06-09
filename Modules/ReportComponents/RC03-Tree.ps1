<#
.SYNOPSIS
    RC03 - Drill-down Tree component. Expandable group -> members hierarchy.
.DESCRIPTION
    Each group is a collapsible node (HTML <details>). The summary shows the
    group name, direct member count, and a Nested badge. By default the body is
    numbers-only (enabled / disabled / total breakdown). When Options.Expand is
    set, the body lists individual members (DisplayName / SamAccountName + an
    enabled badge) -- "counted by default, listed when expanded".

    Options:
      Expand [bool]  - list member identities inside each node (default $false).
      MaxGroups [int]- cap the number of nodes rendered (default 250).
    Self-registers on load.
#>

function New-RCTreeComponent {
    [CmdletBinding()]
    [OutputType([string])]
    param([hashtable]$Context, [hashtable]$Options = @{}, [hashtable]$Palette)

    $expand = ($Options.ContainsKey('Expand') -and [bool]$Options['Expand'])
    $maxGroups = 250
    if ($Options.ContainsKey('MaxGroups')) { try { $maxGroups = [int]$Options['MaxGroups'] } catch { } }

    $nodes = @($Context.Enumerated | Sort-Object -Property @{ Expression = { Get-RCDirectCount (Get-RCProp $_ 'Data') }; Descending = $true })
    $total = $nodes.Count
    $truncNote = ''
    if ($total -gt $maxGroups) {
        $truncNote = ('<div class="rc-note" style="margin-top:10px;">Showing the {0} largest of {1} groups (MaxGroups cap).</div>' -f $maxGroups, $total)
        $nodes = $nodes[0..($maxGroups - 1)]
    }

    if (@($nodes).Count -eq 0) {
        return '<section class="rc-section"><h2 class="rc-section-h">Membership Tree</h2><div class="rc-note">No enumerated groups to display.</div></section>'
    }

    $body = New-Object System.Text.StringBuilder
    foreach ($g in $nodes) {
        $d        = Get-RCProp $g 'Data'
        $name     = ConvertTo-RCHtmlText (Get-RCProp $d 'GroupName')
        $count    = Get-RCDirectCount $d
        $isNested = (Get-RCProp $d 'IsNested') -eq $true
        $members  = @(Get-RCProp $d 'Members')

        # 3-state like B01/B09: don't fold "unknown" (no Enabled attribute, e.g.
        # when -IncludeAttributes was off) into the enabled count.
        $enabled = 0; $disabled = 0; $unknown = 0
        foreach ($m in $members) {
            $en = Get-RCProp $m 'Enabled'
            if ($en -eq $false) { $disabled++ }
            elseif ($en -eq $true) { $enabled++ }
            else { $unknown++ }
        }

        $nestBadge = if ($isNested) { ' <span class="rc-badge neutral">nested</span>' } else { '' }
        [void]$body.AppendLine('<details>')
        [void]$body.AppendLine(('<summary>{0} <span class="tw">&mdash; {1} members</span>{2}</summary>' -f $name, $count, $nestBadge))

        if ($expand -and $members.Count -gt 0) {
            foreach ($m in ($members | Sort-Object @{ Expression = { [string](Get-RCProp $_ 'DisplayName') } })) {
                $dn  = [string](Get-RCProp $m 'DisplayName'); if (-not $dn) { $dn = [string](Get-RCProp $m 'SamAccountName') }
                $sam = [string](Get-RCProp $m 'SamAccountName')
                $en  = (Get-RCProp $m 'Enabled') -ne $false
                $eb  = if ($en) { '<span class="rc-badge ok">enabled</span>' } else { '<span class="rc-badge danger">disabled</span>' }
                [void]$body.AppendLine(('<div class="rc-leaf">{0} <span class="c">{1}</span> {2}</div>' -f (ConvertTo-RCHtmlText $dn), (ConvertTo-RCHtmlText $sam), $eb))
            }
        } else {
            $unknownNote = if ($unknown -gt 0) { ' &middot; Unknown: ' + $unknown } else { '' }
            [void]$body.AppendLine(('<div class="rc-leaf">Enabled: {0} &middot; Disabled: {1}{2} &middot; Total: {3}</div>' -f $enabled, $disabled, $unknownNote, $count))
        }
        [void]$body.AppendLine('</details>')
    }

    $modeNote = if ($expand) { 'Expanded: member identities listed per group.' } else { 'Numbers-only: expand a group to see its enabled/disabled breakdown.' }

    return @"
<section class="rc-section">
<h2 class="rc-section-h">Membership Tree</h2>
<p class="rc-section-d">$modeNote</p>
<div class="rc-tree">$($body.ToString())</div>
$truncNote
</section>
"@
}

Register-RCComponent -Key 'tree' -DisplayName 'Drill-down Membership Tree' `
    -Description 'Expandable group -> members hierarchy; numbers by default, identities when expanded.' `
    -FunctionName 'New-RCTreeComponent' -Requires @('GroupResults') `
    -DefaultOptions @{ Expand = $false; MaxGroups = 250 }
