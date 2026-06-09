<#
.SYNOPSIS
    Time-windowed membership-change report. Reads a changelog.jsonl (the JSON the
    tool writes: {Timestamp, Domain, GroupName, SamAccountName, DisplayName, Action})
    and renders +adds / -removes bucketed across rolling windows (24h / 7d / 30d /
    90d / all-time), using the dates in the JSON. Fully offline -- no DC.

    Additive: complements Export-ChangeReportHtml (single-period) with a
    multi-window activity summary.
#>

function ConvertTo-TimelineHtmlSafe {
    param([string]$Text)
    if ([string]::IsNullOrEmpty($Text)) { return '' }
    return ($Text -replace '&', '&amp;' -replace '<', '&lt;' -replace '>', '&gt;' -replace '"', '&quot;' -replace "'", '&#39;')
}

function Export-ChangeTimelineReport {
    <#
    .PARAMETER ChangeLogPath
        Path to changelog.jsonl (one JSON change event per line).
    .PARAMETER OutputPath
        Destination .html.
    .PARAMETER Windows
        Rolling windows in days. Default 1,7,30,90.
    .PARAMETER MaxDetailRows
        Cap on the detail table (most-recent first). Default 500; truncation is
        stated in the report, never silent.
    .OUTPUTS
        The output path (string).
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string]$ChangeLogPath,
        [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string]$OutputPath,
        [Parameter()][int[]]$Windows = @(1, 7, 30, 90),
        [Parameter()][int]$MaxDetailRows = 500,
        [Parameter()][string]$Title = 'Membership Change Timeline',
        [Parameter()][ValidateSet('dark', 'light')][string]$Theme = 'dark'
    )

    if (-not (Test-Path $ChangeLogPath)) { throw "Changelog not found: $ChangeLogPath" }

    # --- parse events ---
    $events = New-Object System.Collections.Generic.List[object]
    foreach ($line in [System.IO.File]::ReadAllLines($ChangeLogPath)) {
        $t = $line.Trim(); if (-not $t) { continue }
        try { $e = $t | ConvertFrom-Json } catch { continue }
        [datetime]$ts = [datetime]::MinValue
        if (-not [datetime]::TryParse([string]$e.Timestamp, [ref]$ts)) { continue }
        $events.Add([pscustomobject]@{ Ts = $ts; Domain = [string]$e.Domain; Group = [string]$e.GroupName; User = [string]$e.SamAccountName; Display = [string]$e.DisplayName; Action = [string]$e.Action })
    }

    $now = Get-Date
    $total = $events.Count
    $minTs = if ($total) { ($events | Measure-Object Ts -Minimum).Minimum } else { $null }
    $maxTs = if ($total) { ($events | Measure-Object Ts -Maximum).Maximum } else { $null }

    # --- window buckets ---
    $cards = New-Object System.Collections.Generic.List[string]
    foreach ($w in ($Windows | Sort-Object)) {
        $cut = $now.AddDays(-$w)
        $inWin = @($events | Where-Object { $_.Ts -ge $cut })
        $a = @($inWin | Where-Object { $_.Action -eq 'Added' }).Count
        $r = @($inWin | Where-Object { $_.Action -eq 'Removed' }).Count
        $label = if ($w -eq 1) { 'Last 24 hours' } else { "Last $w days" }
        $cards.Add("<div class=""kpi""><div class=""l"">$label</div><div><span class=""add"">+$a</span> &nbsp; <span class=""rem"">-$r</span></div></div>")
    }
    $allA = @($events | Where-Object { $_.Action -eq 'Added' }).Count
    $allR = @($events | Where-Object { $_.Action -eq 'Removed' }).Count
    $cards.Add("<div class=""kpi""><div class=""l"">All time</div><div><span class=""add"">+$allA</span> &nbsp; <span class=""rem"">-$allR</span></div></div>")

    # Rolling windows are relative to report-generation time (now). If the most
    # recent event predates every window, all buckets read 0/0 -- warn so a
    # historical/stale changelog isn't misread as "no recent activity = healthy".
    $largestWindow = if (@($Windows).Count -gt 0) { (@($Windows) | Measure-Object -Maximum).Maximum } else { 0 }
    $staleBanner = ''
    if ($total -gt 0 -and $largestWindow -gt 0 -and $maxTs -lt $now.AddDays(-$largestWindow)) {
        $ageDays = [int][math]::Floor(($now - $maxTs).TotalDays)
        $staleBanner = "<div class=""sub"" style=""color:#e5a13a;margin-bottom:14px"">Note: the most recent change is $($maxTs.ToString('yyyy-MM-dd')) ($ageDays day(s) ago) &mdash; older than every rolling window below, so those windows show zero. Windows are relative to report-generation time, not the data.</div>"
    }

    # --- detail rows (most recent first, capped) ---
    $sorted = @($events | Sort-Object Ts -Descending)
    # Guard MaxDetailRows <= 0: $sorted[0..(-1)] would wrongly select first+last.
    $shown = if ($MaxDetailRows -le 0) { @() } elseif ($sorted.Count -gt $MaxDetailRows) { $sorted[0..($MaxDetailRows - 1)] } else { $sorted }
    $detail = New-Object System.Collections.Generic.List[string]
    foreach ($e in $shown) {
        $cls = if ($e.Action -eq 'Removed') { 'rem' } else { 'add' }
        $sign = if ($e.Action -eq 'Removed') { '-' } else { '+' }
        $detail.Add("<tr><td class=""mono"">$($e.Ts.ToString('yyyy-MM-dd HH:mm'))</td><td>$(ConvertTo-TimelineHtmlSafe $e.Domain)</td><td>$(ConvertTo-TimelineHtmlSafe $e.Group)</td><td>$(ConvertTo-TimelineHtmlSafe $e.User)</td><td class=""$cls"">$sign $(ConvertTo-TimelineHtmlSafe $e.Action)</td></tr>")
    }
    $truncNote = if ($sorted.Count -gt $MaxDetailRows) { " (showing $MaxDetailRows most recent of $($sorted.Count))" } else { '' }

    if ($Theme -eq 'light') { $bg='#f5f6f8';$card='#fff';$fg='#1b1f24';$muted='#6b7280';$border='#e2e5ea';$accent='#2563eb';$head='#eef1f5' }
    else { $bg='#11151c';$card='#1b2230';$fg='#e6e9ef';$muted='#94a3b8';$border='#2b3444';$accent='#5b9dff';$head='#222c3c' }
    $tEsc = ConvertTo-TimelineHtmlSafe $Title
    $genTs = $now.ToString('yyyy-MM-dd HH:mm:ss')
    $range = if ($minTs) { "$($minTs.ToString('yyyy-MM-dd HH:mm')) -> $($maxTs.ToString('yyyy-MM-dd HH:mm'))" } else { 'no events' }

    $html = @"
<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><title>$tEsc</title>
<style>
 body{margin:0;background:$bg;color:$fg;font-family:Segoe UI,Arial,sans-serif;font-size:14px}
 .wrap{max-width:1100px;margin:0 auto;padding:24px}
 h1{font-size:20px;margin:0 0 4px}.sub{color:$muted;font-size:12px;margin-bottom:18px}
 .kpis{display:flex;gap:12px;flex-wrap:wrap;margin-bottom:18px}
 .kpi{background:$card;border:1px solid $border;border-radius:8px;padding:14px 18px;min-width:130px}
 .kpi .l{font-size:11px;color:$muted;text-transform:uppercase;letter-spacing:.5px;margin-bottom:6px} .kpi div span{font-size:20px;font-weight:700}
 input{background:$card;border:1px solid $border;color:$fg;border-radius:6px;padding:8px 10px;width:280px;margin-bottom:10px}
 table{width:100%;border-collapse:collapse;background:$card;border:1px solid $border;border-radius:8px;overflow:hidden}
 th,td{text-align:left;padding:7px 12px;border-bottom:1px solid $border}th{background:$head;font-size:12px;text-transform:uppercase;color:$muted}
 .add{color:#3ecf8e}.rem{color:#e5677b}.mono{font-family:Consolas,monospace;color:$muted}
</style></head><body><div class="wrap">
<h1>$tEsc</h1><div class="sub">Generated $genTs &nbsp;|&nbsp; source: $(ConvertTo-TimelineHtmlSafe (Split-Path $ChangeLogPath -Leaf)) &nbsp;|&nbsp; $total events &nbsp;|&nbsp; range: $range</div>
$staleBanner
<div class="kpis">
$($cards -join "`n")
</div>
<input id="f" placeholder="Filter changes..." onkeyup="flt()">
<table id="t"><thead><tr><th>When</th><th>Domain</th><th>Group</th><th>User</th><th>Change</th></tr></thead><tbody>
$($detail -join "`n")
</tbody></table>
<div class="sub" style="margin-top:10px">Detail rows: $($shown.Count)$truncNote</div>
</div>
<script>function flt(){var q=document.getElementById('f').value.toLowerCase(),r=document.querySelectorAll('#t tbody tr');r.forEach(function(x){x.style.display=x.textContent.toLowerCase().indexOf(q)>-1?'':'none';});}</script>
</body></html>
"@

    $dir = Split-Path -Parent $OutputPath
    if ($dir -and -not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    [System.IO.File]::WriteAllText($OutputPath, $html, [System.Text.UTF8Encoding]::new($false))
    return $OutputPath
}
