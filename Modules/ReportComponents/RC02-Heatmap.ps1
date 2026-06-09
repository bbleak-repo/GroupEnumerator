<#
.SYNOPSIS
    RC02 - Heatmap component. Member-count density grid, one cell per group.
.DESCRIPTION
    Each enumerated group becomes a coloured cell; colour is interpolated on a
    log scale between the theme's HeatLow and HeatHigh tokens so a few very large
    groups don't wash out the rest. Cell shows the direct member count; the group
    name is the hover title. Numbers-only.

    Options:
      MaxCells [int]  - cap the grid (default 400). Largest groups are kept and
                        the cap is reported (no silent truncation).
    Self-registers on load.
#>

function New-RCHeatmapComponent {
    [CmdletBinding()]
    [OutputType([string])]
    param([hashtable]$Context, [hashtable]$Options = @{}, [hashtable]$Palette)

    function _rcHexLerp {
        param([string]$A, [string]$B, [double]$T)
        $a = $A.TrimStart('#'); $b = $B.TrimStart('#')
        $ar = [Convert]::ToInt32($a.Substring(0, 2), 16); $ag = [Convert]::ToInt32($a.Substring(2, 2), 16); $ab = [Convert]::ToInt32($a.Substring(4, 2), 16)
        $br = [Convert]::ToInt32($b.Substring(0, 2), 16); $bg = [Convert]::ToInt32($b.Substring(2, 2), 16); $bb = [Convert]::ToInt32($b.Substring(4, 2), 16)
        $r = [int][Math]::Round($ar + ($br - $ar) * $T)
        $g = [int][Math]::Round($ag + ($bg - $ag) * $T)
        $bl = [int][Math]::Round($ab + ($bb - $ab) * $T)
        return ('#{0:x2}{1:x2}{2:x2}' -f $r, $g, $bl)
    }
    function _rcTextOn {
        param([string]$Hex)
        $h = $Hex.TrimStart('#')
        $r = [Convert]::ToInt32($h.Substring(0, 2), 16); $g = [Convert]::ToInt32($h.Substring(2, 2), 16); $b = [Convert]::ToInt32($h.Substring(4, 2), 16)
        $lum = (0.299 * $r) + (0.587 * $g) + (0.114 * $b)
        if ($lum -gt 150) { return '#1f2430' } else { return '#ffffff' }
    }

    $maxCells = 400
    if ($Options.ContainsKey('MaxCells')) { try { $maxCells = [int]$Options['MaxCells'] } catch { } }
    if ($maxCells -lt 1) { $maxCells = 1 }

    $items = New-Object System.Collections.Generic.List[object]
    foreach ($g in @($Context.Enumerated)) {
        $d = Get-RCProp $g 'Data'
        $items.Add([pscustomobject]@{
            Name  = [string](Get-RCProp $d 'GroupName')
            Count = Get-RCDirectCount $d
        })
    }
    $sorted = @($items | Sort-Object -Property @{ Expression = 'Count'; Descending = $true }, @{ Expression = 'Name'; Descending = $false })
    $total  = $sorted.Count

    $truncNote = ''
    if ($total -gt $maxCells) {
        $shown = $sorted[0..($maxCells - 1)]
        $truncNote = ('<div class="rc-note" style="margin-top:12px;">Showing the {0} largest of {1} groups (MaxCells cap).</div>' -f $maxCells, $total)
    } else {
        $shown = $sorted
    }

    if (@($shown).Count -eq 0) {
        return '<section class="rc-section"><h2 class="rc-section-h">Member-Count Heatmap</h2><div class="rc-note">No enumerated groups to display.</div></section>'
    }

    $counts = @($shown | ForEach-Object { $_.Count })
    $min = ($counts | Measure-Object -Minimum).Minimum
    $max = ($counts | Measure-Object -Maximum).Maximum
    $logMin = [Math]::Log([double]$min + 1.0)
    $logMax = [Math]::Log([double]$max + 1.0)
    $span   = $logMax - $logMin

    $cells = New-Object System.Text.StringBuilder
    foreach ($it in $shown) {
        $frac = if ($span -le 0) { if ($it.Count -gt 0) { 1.0 } else { 0.0 } } else { ([Math]::Log([double]$it.Count + 1.0) - $logMin) / $span }
        if ($frac -lt 0) { $frac = 0 }; if ($frac -gt 1) { $frac = 1 }
        $bg  = _rcHexLerp -A $Palette.HeatLow -B $Palette.HeatHigh -T $frac
        $fg  = _rcTextOn -Hex $bg
        $ttl = ConvertTo-RCHtmlText ('{0} ({1} members)' -f $it.Name, $it.Count)
        [void]$cells.Append(('<div class="rc-cell" style="background:{0};color:{1};" title="{2}">{3}</div>' -f $bg, $fg, $ttl, $it.Count))
    }

    return @"
<section class="rc-section">
<h2 class="rc-section-h">Member-Count Heatmap</h2>
<p class="rc-section-d">One cell per group, coloured by direct member count (log scale). Hover a cell for the group name.</p>
<div class="rc-heatmap">$($cells.ToString())</div>
<div class="rc-heat-legend"><span>$min</span><span class="rc-heat-bar"></span><span>$max</span><span>direct members</span></div>
$truncNote
</section>
"@
}

Register-RCComponent -Key 'heatmap' -DisplayName 'Member-Count Heatmap' `
    -Description 'Density grid: one cell per group, coloured by member count (log scale).' `
    -FunctionName 'New-RCHeatmapComponent' -Requires @('GroupResults') `
    -DefaultOptions @{ MaxCells = 400 }
