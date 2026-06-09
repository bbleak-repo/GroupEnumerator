<#
.SYNOPSIS
    B07 - Empty & Stale Groups Findings (BASELINE report module).

.DESCRIPTION
    Parameterized product module. Operates on the GroupResults array passed by the
    caller (same shape used by all Group-Enumerator report generators) plus an
    optional membership changelog (JSONL) for staleness detection.

    Produces a findings-only HTML report listing groups that are EMPTY (zero direct
    members) or STALE (no membership change within the documented staleness threshold
    of 90 days). Groups with no changelog history at all are always treated as stale.

    Account treatment: NUMBERS-ONLY. No member names, SamAccountNames, or e-mail
    addresses are rendered; the report contains counts and derived dates only.
    (HTML-escaping is applied to the group name, which is the only free-text value
    placed into the document.)

    Self-contained: dot-sources nothing; no baked-in input or output paths.
    Writes UTF-8 (no BOM) via [System.IO.File]::WriteAllText.

.NOTES
    Spec id  : B07-empty-stale-groups
    Function : Export-EmptyStaleGroupsReport
    Inputs   : $GroupResults (array), $ChangeLogPath (optional JSONL path)
    Output   : $OutputPath (HTML file); returns the output path as a string.
#>

function ConvertTo-B07HtmlSafe {
    param([object]$Value)
    if ($null -eq $Value) { return '' }
    $s = [string]$Value
    $s = $s.Replace('&', '&amp;')
    $s = $s.Replace('<', '&lt;')
    $s = $s.Replace('>', '&gt;')
    $s = $s.Replace('"', '&quot;')
    $s = $s.Replace("'", '&#39;')
    return $s
}

function ConvertTo-B07PSObject {
    # Normalize the -FromCache hashtable shape (and nested members) to
    # PSCustomObjects so the PSObject-based property checks below work for both
    # cache (hashtable) and live (object) inputs.
    param([object]$InputObject)
    if ($InputObject -is [System.Collections.IDictionary]) {
        $ht = @{}
        foreach ($k in $InputObject.Keys) { $ht[[string]$k] = ConvertTo-B07PSObject $InputObject[$k] }
        return [pscustomobject]$ht
    }
    if (($InputObject -is [System.Collections.IEnumerable]) -and ($InputObject -isnot [string])) {
        return @(foreach ($item in $InputObject) { ConvertTo-B07PSObject $item })
    }
    return $InputObject
}

function Export-EmptyStaleGroupsReport {
    <#
    .SYNOPSIS
        Writes a findings-only HTML report: empty groups and stale groups
        (no membership change within the staleness threshold).

    .PARAMETER GroupResults
        Array of @{ Data = @{ Domain; GroupName; MemberCount; IsNested; Skipped;
        Members = @(@{ SamAccountName; DisplayName; Email; Enabled }) }; Errors = @() }.

    .PARAMETER OutputPath
        Destination .html path. Parent directory is created if absent.

    .PARAMETER ChangeLogPath
        Optional path to a changelog.jsonl file (one JSON change event per line:
        { Timestamp, Domain, GroupName, ... }). When supplied, per-group last-change
        dates are derived from it. When omitted, all non-skipped groups with zero
        members are reported as empty, and all non-empty groups are reported as stale
        (no changelog history available).

    .PARAMETER Title
        Optional report title shown in the HTML heading.

    .PARAMETER Theme
        'auto' (default), 'dark', or 'light'. 'auto' follows the viewer's OS
        (prefers-color-scheme) and exposes a runtime toggle; 'dark'/'light' force an
        initial theme (the in-page toggle + localStorage can still override). Colours
        come from the shared accessible palette (Modules\BaselineReports\B00-report-theme.ps1),
        every pair WCAG-AA in both themes; @media print always forces light for evidence/PDF.

    .PARAMETER StalenessThresholdDays
        Days without a membership change before a group is considered stale.
        Default is 90.

    .OUTPUTS
        The resolved output path (string).
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

        [Parameter()]
        [string]$ChangeLogPath,

        [Parameter()]
        [string]$Title = 'Empty &amp; Stale Groups Findings',

        [Parameter()]
        [ValidateSet('auto', 'dark', 'light')]
        [string]$Theme = 'auto',

        [Parameter()]
        [int]$StalenessThresholdDays = 90
    )

    # -------------------------------------------------------------------------
    # Build per-group "last membership change" map from the changelog, if provided.
    # Key: Domain|GroupName (matches how the exploratory script keyed the map).
    # -------------------------------------------------------------------------
    $lastChange = @{}

    if ($ChangeLogPath -and (Test-Path -LiteralPath $ChangeLogPath)) {
        foreach ($line in [System.IO.File]::ReadAllLines($ChangeLogPath)) {
            $trimmed = $line.Trim()
            if ([string]::IsNullOrWhiteSpace($trimmed)) { continue }
            $evt = $null
            try { $evt = $trimmed | ConvertFrom-Json } catch { continue }
            if ($null -eq $evt) { continue }

            $domain = if ($evt.PSObject.Properties.Name -contains 'Domain')    { [string]$evt.Domain }    else { '' }
            $gname  = if ($evt.PSObject.Properties.Name -contains 'GroupName') { [string]$evt.GroupName } else { '' }
            if ([string]::IsNullOrEmpty($gname)) { continue }

            $ts = $null
            if ($evt.PSObject.Properties.Name -contains 'Timestamp' -and $evt.Timestamp) {
                try { $ts = [datetimeoffset]::Parse([string]$evt.Timestamp) } catch { $ts = $null }
            }
            if ($null -eq $ts) { continue }

            $key = $domain + '|' + $gname
            if (-not $lastChange.ContainsKey($key) -or $ts -gt $lastChange[$key]) {
                $lastChange[$key] = $ts
            }
        }
    }

    $now = [datetimeoffset]::Now

    # -------------------------------------------------------------------------
    # Evaluate every group; keep only findings (empty OR stale).
    # -------------------------------------------------------------------------
    $findings     = New-Object System.Collections.Generic.List[object]
    $totalGroups  = 0
    $skippedCount = 0

    foreach ($wrapper in $GroupResults) {
        if ($null -eq $wrapper -or $null -eq $wrapper.Data) { continue }
        $d = ConvertTo-B07PSObject $wrapper.Data

        # Skipped groups were never fully enumerated; exclude from findings to
        # avoid false "empty" flags, but count them for the header.
        $isSkipped = $false
        if ($d.PSObject.Properties.Name -contains 'Skipped') {
            $isSkipped = [bool]$d.Skipped
        }
        if ($isSkipped) { $skippedCount++; continue }

        $totalGroups++

        $domain = if ($d.PSObject.Properties.Name -contains 'Domain')    { [string]$d.Domain }    else { '' }
        $gname  = if ($d.PSObject.Properties.Name -contains 'GroupName') { [string]$d.GroupName } else { '(unnamed)' }

        # Direct member count: prefer the materialized Members array length;
        # fall back to the recorded MemberCount field.
        $memberCount = 0
        if ($d.PSObject.Properties.Name -contains 'Members' -and $d.Members) {
            $memberCount = @($d.Members).Count
        } elseif ($d.PSObject.Properties.Name -contains 'MemberCount' -and $null -ne $d.MemberCount) {
            $memberCount = [int]$d.MemberCount
        }

        $isEmpty = ($memberCount -le 0)

        # Last membership change from changelog (Domain|GroupName key).
        $key  = $domain + '|' + $gname
        $last = $null
        if ($lastChange.ContainsKey($key)) { $last = $lastChange[$key] }

        $daysSince   = $null
        $lastDisplay = 'Never (no changelog entry)'
        if ($null -ne $last) {
            $daysSince   = [int][math]::Floor(($now - $last).TotalDays)
            $lastDisplay = $last.ToString('yyyy-MM-dd')
        }

        # Stale if no changelog history at all, or last change older than threshold.
        $isStale = $false
        if ($null -eq $last) {
            $isStale = $true
        } elseif ($daysSince -ge $StalenessThresholdDays) {
            $isStale = $true
        }

        if (-not ($isEmpty -or $isStale)) { continue }

        $reason = if ($isEmpty) { 'NoMembers' } else { 'NoRecentChange' }
        $action = 'Review for deletion'

        $findings.Add([pscustomobject]@{
            GroupName            = $gname
            MemberCount          = $memberCount
            LastMembershipChange = $lastDisplay
            DaysSinceLastChange  = $daysSince
            StaleReason          = $reason
            RecommendedAction    = $action
            IsEmpty              = $isEmpty
        }) | Out-Null
    }

    # Sort: empties first (red), then stale by most days since change descending.
    $ordered = @($findings | Sort-Object `
        @{ Expression = { -not $_.IsEmpty } }, `
        @{ Expression = {
            if ($null -eq $_.DaysSinceLastChange) { [int]::MaxValue }
            else { [int]$_.DaysSinceLastChange }
          }; Descending = $true }, `
        @{ Expression = { $_.GroupName } })

    $emptyCount = @($findings | Where-Object {  $_.IsEmpty }).Count
    $staleCount = @($findings | Where-Object { -not $_.IsEmpty }).Count

    # -------------------------------------------------------------------------
    # Build table rows HTML
    # -------------------------------------------------------------------------
    $rowsSb = New-Object System.Text.StringBuilder
    if ($ordered.Count -eq 0) {
        [void]$rowsSb.Append(
            '<tr><td colspan="6" class="none">No empty or stale groups found. ' +
            'All enumerated groups had membership activity within the last ' +
            $StalenessThresholdDays + ' days.</td></tr>')
    } else {
        foreach ($r in $ordered) {
            $rowClass   = if ($r.IsEmpty) { 'empty' } else { 'stale' }
            $days       = if ($null -eq $r.DaysSinceLastChange) { 'n/a' } else { [string]$r.DaysSinceLastChange }
            $reasonBadge = if ($r.StaleReason -eq 'NoMembers') {
                '<span class="badge badge-red">&#9679; NoMembers</span>'
            } else {
                '<span class="badge badge-stale">&#9650; NoRecentChange</span>'
            }
            [void]$rowsSb.Append('<tr class="' + $rowClass + '">')
            [void]$rowsSb.Append('<td class="name">'   + (ConvertTo-B07HtmlSafe $r.GroupName)           + '</td>')
            [void]$rowsSb.Append('<td class="num">'    + [string]$r.MemberCount                         + '</td>')
            [void]$rowsSb.Append('<td>'                + (ConvertTo-B07HtmlSafe $r.LastMembershipChange) + '</td>')
            [void]$rowsSb.Append('<td class="num">'    + $days                                           + '</td>')
            [void]$rowsSb.Append('<td>'                + $reasonBadge                                    + '</td>')
            [void]$rowsSb.Append('<td class="action">' + (ConvertTo-B07HtmlSafe $r.RecommendedAction)   + '</td>')
            [void]$rowsSb.Append('</tr>')
        }
    }
    $rowsHtml    = $rowsSb.ToString()
    $generatedOn = $now.ToString('yyyy-MM-dd HH:mm zzz')

    # Shared accessible theme layer (palettes + toggle + print). 'auto' follows the OS;
    # an explicit 'dark'/'light' seeds the initial data-theme (toggle/localStorage can override).
    $themeCss    = Get-GEReportThemeCss
    $toggleHtml  = Get-GEReportThemeToggleHtml
    $themeScript = Get-GEReportThemeScript
    $themeAttr   = if ($Theme -eq 'dark' -or $Theme -eq 'light') { " data-theme=`"$Theme`"" } else { '' }

    # -------------------------------------------------------------------------
    # Render HTML  (colours come from the shared var(--...) tokens; AA in both themes)
    # -------------------------------------------------------------------------
    $html = @"
<!DOCTYPE html>
<html lang="en"$themeAttr>
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>Empty &amp; Stale Groups Findings (B07)</title>
<style>
  :root { color-scheme: light dark; }
$themeCss
  * { box-sizing: border-box; }
  body {
    font-family: 'Segoe UI', Tahoma, Arial, sans-serif;
    margin: 0; padding: 0; background: var(--bg); color: var(--ink);
  }
  .wrap { max-width: 1100px; margin: 0 auto; padding: 28px 22px 56px; }
  header.report {
    background: var(--header-bg); color: #fff; border-radius: 10px;
    padding: 22px 26px; margin-bottom: 22px;
    box-shadow: 0 2px 8px rgba(0,0,0,.18);
  }
  header.report h1 { margin: 0 0 6px; font-size: 22px; }
  header.report .sub { font-size: 13px; opacity: .9; }
  .threshold {
    display: inline-block; margin-top: 12px; padding: 6px 12px;
    background: rgba(255,255,255,.12); border: 1px solid rgba(255,255,255,.28); border-radius: 6px;
    font-size: 13px; font-weight: 600;
  }
  .summary { display: flex; flex-wrap: wrap; gap: 14px; margin-bottom: 22px; }
  /* Cards + findings table use the shared surface/ink tokens, so text contrast is AA in
     BOTH light and dark (dark mode = dark surface + light ink; print forces light). */
  .card {
    flex: 1 1 160px; background: var(--surface); color: var(--ink); border-radius: 8px; padding: 14px 16px;
    border: 1px solid var(--line); box-shadow: 0 1px 3px rgba(0,0,0,.06);
  }
  .card .k { font-size: 12px; text-transform: uppercase; letter-spacing: .04em; color: var(--muted); }
  .card .v { font-size: 26px; font-weight: 700; margin-top: 4px; color: var(--ink); }
  .card.red   .v { color: var(--crit); }
  .card.stale .v { color: var(--low); }
  table { width: 100%; border-collapse: collapse; background: var(--surface);
    border-radius: 8px; overflow: hidden; box-shadow: 0 1px 3px rgba(0,0,0,.08); }
  thead th {
    background: var(--header-bg); color: #fff; text-align: left; font-size: 12px;
    text-transform: uppercase; letter-spacing: .03em; padding: 11px 12px;
  }
  tbody td { padding: 10px 12px; font-size: 13px; color: var(--ink); border-top: 1px solid var(--line); vertical-align: top; }
  tbody td.num { text-align: right; font-variant-numeric: tabular-nums; }
  tbody td.name { font-weight: 600; }
  tbody td.action { font-weight: 600; }
  /* Row tint + a left-border accent + the text badge = status conveyed three ways
     (colour, position, text) so it survives greyscale and colour-blindness (WCAG 1.4.1).
     Row tints are theme tokens (light tint in light mode, dark tint in dark mode) and the
     cell ink stays var(--ink), so text-on-tint is AA either way. */
  tbody tr.empty { background: var(--row-crit-bg); }
  tbody tr.empty td:first-child { border-left: 4px solid var(--crit); }
  tbody tr.stale { background: var(--row-low-bg); }
  tbody tr.stale td:first-child { border-left: 4px solid var(--low); }
  td.none { text-align: center; color: var(--muted); font-style: italic; padding: 26px 12px; }
  .badge { display: inline-block; padding: 2px 9px; border-radius: 11px; font-size: 11px; font-weight: 700; }
  .badge-red   { background: var(--badge-crit-bg); color: var(--badge-crit-ink); }
  .badge-stale { background: var(--badge-low-bg); color: var(--badge-low-ink); }
  .legend { margin-top: 16px; font-size: 12px; color: var(--muted); }
  .legend .sw { display: inline-block; width: 12px; height: 12px; border-radius: 3px; vertical-align: middle; margin: 0 5px 0 14px; }
  .legend .sw.red   { background: var(--row-crit-bg); border: 1px solid var(--crit); }
  .legend .sw.stale { background: var(--row-low-bg); border: 1px solid var(--low); }
  footer.note { margin-top: 22px; font-size: 11px; color: var(--muted); }
</style>
</head>
<body>
$toggleHtml
<div class="wrap">
  <header class="report">
    <h1>Empty &amp; Stale Groups Findings</h1>
    <div class="sub">Findings-only report (B07). Groups with zero direct members, or no membership change within the staleness threshold. Account treatment: numbers-only.</div>
    <div class="threshold">Staleness threshold: $StalenessThresholdDays days &nbsp;&bull;&nbsp; Generated $generatedOn</div>
  </header>

  <section class="summary">
    <div class="card">       <div class="k">Groups Evaluated</div><div class="v">$totalGroups</div></div>
    <div class="card">       <div class="k">Skipped (excluded)</div><div class="v">$skippedCount</div></div>
    <div class="card red">   <div class="k">Empty (0 members)</div><div class="v">$emptyCount</div></div>
    <div class="card stale"> <div class="k">Stale (&ge; $StalenessThresholdDays d)</div><div class="v">$staleCount</div></div>
  </section>

  <table>
    <thead>
      <tr>
        <th>Group Name</th>
        <th style="text-align:right">Member Count (direct)</th>
        <th>Last Membership Change</th>
        <th style="text-align:right">Days Since Last Change</th>
        <th>Stale Reason</th>
        <th>Recommended Action</th>
      </tr>
    </thead>
    <tbody>
      $rowsHtml
    </tbody>
  </table>

  <div class="legend">
    <strong>Legend:</strong>
    <span class="sw red"></span> Empty (brick) &mdash; zero direct members
    <span class="sw stale"></span> Stale (olive) &mdash; no membership change within $StalenessThresholdDays days
  </div>

  <footer class="note">
    Last membership change is derived from the changelog (latest Added/Removed event per group).
    Groups with no changelog history are treated as stale (no recent change). Read-only; offline.
  </footer>
</div>
$themeScript
</body>
</html>
"@

    # -------------------------------------------------------------------------
    # Write output (UTF-8 no BOM)
    # -------------------------------------------------------------------------
    $dir = Split-Path -Parent $OutputPath
    if ($dir -and -not (Test-Path -LiteralPath $dir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
    }
    [System.IO.File]::WriteAllText($OutputPath, $html, [System.Text.UTF8Encoding]::new($false))
    return $OutputPath
}
