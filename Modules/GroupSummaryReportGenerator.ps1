<#
.SYNOPSIS
    Condensed group-summary report -- a clean "what groups exist and their member
    counts" view, without the per-member detail tables of the full report.

    Additive: does not modify Export-GroupReport. Takes the same GroupResults
    shape (or load a cache via -FromCache caller) and renders one filterable
    table plus KPI totals. Output is small and fast even for hundreds of groups.
#>

function ConvertTo-SummaryHtmlSafe {
    param([string]$Text)
    if ([string]::IsNullOrEmpty($Text)) { return '' }
    return ($Text -replace '&', '&amp;' -replace '<', '&lt;' -replace '>', '&gt;' -replace '"', '&quot;' -replace "'", '&#39;')
}

function Export-GroupSummaryReport {
    <#
    .SYNOPSIS
        Writes a condensed HTML report: one row per group (Domain, Group,
        Members, Nested, Status) with KPI totals and a live text filter.

    .PARAMETER GroupResults
        Array of @{ Data = @{ Domain; GroupName; MemberCount; Members; IsNested; Skipped; SkipReason }; Errors }.

    .PARAMETER OutputPath
        Destination .html path.

    .PARAMETER Title
        Optional report title.

    .PARAMETER Theme
        'dark' (default) or 'light'.

    .OUTPUTS
        The output path (string).
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [array]$GroupResults,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$OutputPath,

        [Parameter()][string]$Title = 'Group Summary',
        [Parameter()][ValidateSet('dark', 'light')][string]$Theme = 'dark'
    )

    $rows = New-Object System.Collections.Generic.List[string]
    $totalMembers = 0
    $domains = @{}
    $skipped = 0
    $enumeratedGroups = 0

    foreach ($g in ($GroupResults | Sort-Object { $_.Data.Domain }, { $_.Data.GroupName })) {
        $d = $g.Data
        if (-not $d) { continue }
        $domain = ConvertTo-SummaryHtmlSafe ([string]$d.Domain)
        $name   = ConvertTo-SummaryHtmlSafe ([string]$d.GroupName)
        $count  = [int]$d.MemberCount
        $domains[[string]$d.Domain] = $true
        $isNested = if ($d.IsNested) { 'Yes' } else { '' }
        if ($d.Skipped) {
            $skipped++
            $status = "Skipped: $(ConvertTo-SummaryHtmlSafe ([string]$d.SkipReason))"
            $statusClass = 'skip'
        } else {
            $enumeratedGroups++
            $totalMembers += $count
            $status = 'OK'
            $statusClass = 'ok'
        }
        $rows.Add("<tr><td>$domain</td><td>$name</td><td class=""num"">$count</td><td class=""ctr"">$isNested</td><td class=""$statusClass"">$status</td></tr>")
    }

    # palette
    if ($Theme -eq 'light') {
        $bg = '#f5f6f8'; $card = '#ffffff'; $fg = '#1b1f24'; $muted = '#6b7280'; $border = '#e2e5ea'; $accent = '#2563eb'; $head = '#eef1f5'
    } else {
        $bg = '#11151c'; $card = '#1b2230'; $fg = '#e6e9ef'; $muted = '#94a3b8'; $border = '#2b3444'; $accent = '#5b9dff'; $head = '#222c3c'
    }
    $ts = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
    $tEsc = ConvertTo-SummaryHtmlSafe $Title

    $html = @"
<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><title>$tEsc</title>
<style>
 body{margin:0;background:$bg;color:$fg;font-family:Segoe UI,Arial,sans-serif;font-size:14px}
 .wrap{max-width:1100px;margin:0 auto;padding:24px}
 h1{font-size:20px;margin:0 0 4px} .sub{color:$muted;font-size:12px;margin-bottom:18px}
 .kpis{display:flex;gap:12px;flex-wrap:wrap;margin-bottom:18px}
 .kpi{background:$card;border:1px solid $border;border-radius:8px;padding:14px 18px;min-width:120px}
 .kpi .v{font-size:24px;font-weight:700;color:$accent} .kpi .l{font-size:11px;color:$muted;text-transform:uppercase;letter-spacing:.5px}
 input{background:$card;border:1px solid $border;color:$fg;border-radius:6px;padding:8px 10px;width:280px;margin-bottom:10px}
 table{width:100%;border-collapse:collapse;background:$card;border:1px solid $border;border-radius:8px;overflow:hidden}
 th,td{text-align:left;padding:8px 12px;border-bottom:1px solid $border} th{background:$head;cursor:pointer;font-size:12px;text-transform:uppercase;color:$muted}
 td.num,td.ctr{text-align:right} td.ctr{text-align:center}
 .ok{color:#3ecf8e} .skip{color:#f0a45b}
 tfoot td{font-weight:700;background:$head}
 .sub a{color:$accent}
</style></head><body><div class="wrap">
<h1>$tEsc</h1><div class="sub">Generated $ts &nbsp;|&nbsp; condensed view (group + member counts only)</div>
<div class="kpis">
 <div class="kpi"><div class="v">$($GroupResults.Count)</div><div class="l">Groups</div></div>
 <div class="kpi"><div class="v">$totalMembers</div><div class="l">Total Members</div></div>
 <div class="kpi"><div class="v">$($domains.Count)</div><div class="l">Domains</div></div>
 <div class="kpi"><div class="v">$skipped</div><div class="l">Skipped</div></div>
</div>
<input id="f" placeholder="Filter groups..." onkeyup="flt()">
<table id="t"><thead><tr><th>Domain</th><th>Group</th><th>Members</th><th>Nested</th><th>Status</th></tr></thead>
<tbody>
$($rows -join "`n")
</tbody>
<tfoot><tr><td colspan="2">$enumeratedGroups enumerated group(s)</td><td class="num">$totalMembers</td><td colspan="2"></td></tr></tfoot>
</table></div>
<script>
function flt(){var q=document.getElementById('f').value.toLowerCase(),r=document.querySelectorAll('#t tbody tr');
 r.forEach(function(x){x.style.display=x.textContent.toLowerCase().indexOf(q)>-1?'':'none';});}
</script></body></html>
"@

    $dir = Split-Path -Parent $OutputPath
    if ($dir -and -not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    [System.IO.File]::WriteAllText($OutputPath, $html, [System.Text.UTF8Encoding]::new($false))
    return $OutputPath
}
