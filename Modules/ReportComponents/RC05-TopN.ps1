<#
.SYNOPSIS
    RC05 - Top-N Bars component. Largest groups as horizontal bars.
.DESCRIPTION
    Ranks enumerated groups by direct member count and draws the top N as
    horizontal bars (bar width proportional to the largest group). Numbers-only.

    Options:
      N [int]  - how many groups to show (default 10).
    Self-registers on load.
#>

function New-RCTopNComponent {
    [CmdletBinding()]
    [OutputType([string])]
    param([hashtable]$Context, [hashtable]$Options = @{}, [hashtable]$Palette)

    $n = 10
    if ($Options.ContainsKey('N')) { try { $n = [int]$Options['N'] } catch { } }
    if ($n -lt 1) { $n = 1 }

    $items = New-Object System.Collections.Generic.List[object]
    foreach ($g in @($Context.Enumerated)) {
        $d = Get-RCProp $g 'Data'
        $items.Add([pscustomobject]@{ Name = [string](Get-RCProp $d 'GroupName'); Count = Get-RCDirectCount $d })
    }
    $sorted = @($items | Sort-Object -Property @{ Expression = 'Count'; Descending = $true }, @{ Expression = 'Name'; Descending = $false })
    $totalGroups = $sorted.Count

    if ($totalGroups -eq 0) {
        return '<section class="rc-section"><h2 class="rc-section-h">Top Groups by Size</h2><div class="rc-note">No enumerated groups to display.</div></section>'
    }

    $top = if ($totalGroups -gt $n) { $sorted[0..($n - 1)] } else { $sorted }
    $maxCount = ($top | Measure-Object -Property Count -Maximum).Maximum
    if ($null -eq $maxCount -or $maxCount -le 0) { $maxCount = 1 }

    $body = New-Object System.Text.StringBuilder
    foreach ($it in $top) {
        $pct = [int][Math]::Round(($it.Count / [double]$maxCount) * 100)
        if ($pct -lt 2 -and $it.Count -gt 0) { $pct = 2 }
        $nm = ConvertTo-RCHtmlText $it.Name
        [void]$body.AppendLine(('<div class="rc-bar-row"><span class="rc-bar-label" title="{0}">{0}</span><span class="rc-bar-track"><span class="rc-bar-fill" style="width:{1}%;"></span></span><span class="rc-bar-val">{2}</span></div>' -f $nm, $pct, $it.Count))
    }

    $shownNote = if ($totalGroups -gt $n) { ('Top {0} of {1} groups.' -f $n, $totalGroups) } else { ('All {0} groups.' -f $totalGroups) }

    return @"
<section class="rc-section">
<h2 class="rc-section-h">Top Groups by Size</h2>
<p class="rc-section-d">$shownNote Ranked by direct member count.</p>
<div class="rc-bars">$($body.ToString())</div>
</section>
"@
}

Register-RCComponent -Key 'top-n' -DisplayName 'Top-N Groups (bars)' `
    -Description 'Largest groups as horizontal bars, ranked by member count.' `
    -FunctionName 'New-RCTopNComponent' -Requires @('GroupResults') `
    -DefaultOptions @{ N = 10 }
