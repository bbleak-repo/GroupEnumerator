<#
.SYNOPSIS
    RC04 - Change Diff component. Per-group adds / removes from the changelog.
.DESCRIPTION
    Reads the membership changelog (JSONL of Added/Removed events) and shows a
    per-group delta: +adds / -removes within the window. Numbers-only. Requires
    change data (Context.Changes or a readable Context.ChangeLogPath).

    Options:
      Days [int]     - restrict to the last N days (from the most recent event).
                       Default 0 = entire changelog.
      MaxGroups [int]- cap the rows shown (default 100), busiest first.
    Self-registers on load.
#>

function New-RCDiffComponent {
    [CmdletBinding()]
    [OutputType([string])]
    param([hashtable]$Context, [hashtable]$Options = @{}, [hashtable]$Palette)

    # ---- Acquire events: prefer pre-parsed Context.Changes, else read JSONL ----
    $events = New-Object System.Collections.Generic.List[object]
    if ($Context.Changes -and @($Context.Changes).Count -gt 0) {
        foreach ($e in @($Context.Changes)) { $events.Add($e) }
    } elseif ($Context.ChangeLogPath -and (Test-Path -LiteralPath $Context.ChangeLogPath)) {
        foreach ($line in (Get-Content -LiteralPath $Context.ChangeLogPath -Encoding UTF8)) {
            if ([string]::IsNullOrWhiteSpace($line)) { continue }
            try { $o = $line | ConvertFrom-Json } catch { continue }
            if ($null -ne $o) { $events.Add($o) }
        }
    }

    if ($events.Count -eq 0) {
        return '<section class="rc-section"><h2 class="rc-section-h">Change Diff</h2><div class="rc-note">No change events available.</div></section>'
    }

    # ---- Parse timestamps; optional last-N-days window ----
    $parsed = New-Object System.Collections.Generic.List[object]
    foreach ($o in $events) {
        $rawTs = [string](Get-RCProp $o 'Timestamp')
        $dt = [datetime]::MinValue
        [void][datetime]::TryParse($rawTs, [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::None, [ref]$dt)
        $parsed.Add([pscustomobject]@{
            When   = $dt
            Domain = [string](Get-RCProp $o 'Domain')
            Group  = [string](Get-RCProp $o 'GroupName')
            Action = [string](Get-RCProp $o 'Action')
        })
    }

    $days = 0
    if ($Options.ContainsKey('Days')) { try { $days = [int]$Options['Days'] } catch { } }
    $windowNote = 'entire changelog'
    if ($days -gt 0) {
        $dated = @($parsed | Where-Object { $_.When -ne [datetime]::MinValue })
        if ($dated.Count -gt 0) {
            $latest = ($dated | Sort-Object When -Descending | Select-Object -First 1).When
            $cutoff = $latest.AddDays(-$days)
            $parsed = @($parsed | Where-Object { $_.When -ge $cutoff })
            $windowNote = ('last {0} day(s) (since {1})' -f $days, $cutoff.ToString('yyyy-MM-dd'))
        } else {
            # A window was requested but no event has a parseable timestamp, so it
            # can't be applied -- say so rather than silently labelling it "entire
            # changelog" while showing everything.
            $windowNote = ('last {0} day(s) requested, but no events have a parseable timestamp -- showing all' -f $days)
        }
    }

    # ---- Aggregate per group ----
    # Added / Removed are tallied explicitly; everything else (e.g. legacy
    # 'Modified'/blank actions) is counted as 'Other' so the totals reconcile
    # with B08, which reports Added/Removed/Other over the same changelog.
    $agg = @{}
    foreach ($r in $parsed) {
        $key = ('{0}\{1}' -f $r.Domain, $r.Group)
        if (-not $agg.ContainsKey($key)) { $agg[$key] = [pscustomobject]@{ Name = $r.Group; Domain = $r.Domain; Add = 0; Rem = 0; Oth = 0 } }
        if ($r.Action -eq 'Added') { $agg[$key].Add++ }
        elseif ($r.Action -eq 'Removed') { $agg[$key].Rem++ }
        else { $agg[$key].Oth++ }
    }

    $maxGroups = 100
    if ($Options.ContainsKey('MaxGroups')) { try { $maxGroups = [int]$Options['MaxGroups'] } catch { } }

    $rowsAll = @($agg.Values | Sort-Object -Property @{ Expression = { $_.Add + $_.Rem + $_.Oth }; Descending = $true }, @{ Expression = 'Name'; Descending = $false })
    $totalGroups = $rowsAll.Count
    $totalAdd = ($rowsAll | Measure-Object -Property Add -Sum).Sum
    $totalRem = ($rowsAll | Measure-Object -Property Rem -Sum).Sum
    $totalOth = ($rowsAll | Measure-Object -Property Oth -Sum).Sum
    if ($null -eq $totalAdd) { $totalAdd = 0 }; if ($null -eq $totalRem) { $totalRem = 0 }; if ($null -eq $totalOth) { $totalOth = 0 }

    $truncNote = ''
    $rows = $rowsAll
    if ($totalGroups -gt $maxGroups) {
        $rows = $rowsAll[0..($maxGroups - 1)]
        $truncNote = ('<div class="rc-note" style="margin-top:10px;">Showing the {0} busiest of {1} changed groups.</div>' -f $maxGroups, $totalGroups)
    }

    if (@($rows).Count -eq 0) {
        return ('<section class="rc-section"><h2 class="rc-section-h">Change Diff</h2><div class="rc-note">No membership changes in window ({0}).</div></section>' -f (ConvertTo-RCHtmlText $windowNote))
    }

    $anyOther = $totalOth -gt 0
    $body = New-Object System.Text.StringBuilder
    foreach ($r in $rows) {
        $nm = ConvertTo-RCHtmlText $r.Name
        $othCell = if ($anyOther) { ('<span class="rc-diff-oth" style="color:{0};font-variant-numeric:tabular-nums;">~{1}</span>' -f $Palette.Muted, $r.Oth) } else { '' }
        [void]$body.AppendLine(('<div class="rc-diff-row"><span class="rc-diff-name">{0}</span><span class="rc-diff-add">+{1}</span><span class="rc-diff-rem">-{2}</span>{3}</div>' -f $nm, $r.Add, $r.Rem, $othCell))
    }

    return @"
<section class="rc-section">
<h2 class="rc-section-h">Change Diff</h2>
<p class="rc-section-d">Per-group membership delta &mdash; window: $(ConvertTo-RCHtmlText $windowNote). Totals: <span class="rc-diff-add">+$totalAdd</span> / <span class="rc-diff-rem">-$totalRem</span>$(if ($anyOther) { " / <span class=`"rc-diff-oth`" style=`"color:$($Palette.Muted);`">~$totalOth other</span>" }) across $totalGroups group(s).</p>
<div class="rc-diff">$($body.ToString())</div>
$truncNote
</section>
"@
}

Register-RCComponent -Key 'diff' -DisplayName 'Membership Change Diff' `
    -Description 'Per-group adds/removes from the changelog; optional last-N-days window.' `
    -FunctionName 'New-RCDiffComponent' -Requires @('ChangeLog') `
    -DefaultOptions @{ Days = 0; MaxGroups = 100 }
