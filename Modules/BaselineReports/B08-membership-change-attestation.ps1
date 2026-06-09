<#
.SYNOPSIS
    B08 - Membership Change Delta / Attestation Log

.DESCRIPTION
    Parameterized product module. Reads a changelog (JSONL) of group membership
    Added/Removed events and emits a single self-contained HTML attestation log.

    Every membership change in the review window is listed as one row, sorted by
    Timestamp DESCENDING (most recent first). Each row carries empty
    AuthorizedChange / TicketRef columns for reviewer annotation. Added vs Removed
    events are visually distinguished. Account treatment is FULL-LIST: every event
    is shown, nothing is summarised or truncated.

    Satisfies the "who changed what, when" control (SOC 2 CC6.3 / SOX 404 /
    PCI Req 8) by evidencing every group membership change between formal reviews.

    Self-contained: dot-sources nothing.
#>

function ConvertTo-AttestationHtmlSafe {
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

function Export-MembershipChangeAttestationReport {
    <#
    .SYNOPSIS
        Writes a self-contained HTML membership-change attestation log from a
        changelog JSONL file.

    .PARAMETER ChangeLogPath
        Path to changelog.jsonl: one JSON event per line.
        Expected fields: Timestamp, Domain, GroupName, SamAccountName, DisplayName, Action.

    .PARAMETER OutputPath
        Destination .html path.

    .PARAMETER Title
        Optional report title override.

    .PARAMETER Theme
        'auto' (default, follows OS), 'dark', or 'light'. Runtime toggle + print-forces-light;
        colours inherit the shared accessible palette (B00-report-theme.ps1).

    .OUTPUTS
        The output path (string).
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()][string]$ChangeLogPath,
        [Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()][string]$OutputPath,
        [Parameter()][string]$Title,
        [Parameter()][ValidateSet('auto','dark','light')][string]$Theme = 'auto'
    )

    $ReportId   = 'B08-membership-change-attestation'
    $ReportName = 'Membership Change Delta / Attestation Log'
    if ([string]::IsNullOrWhiteSpace($Title)) { $Title = $ReportName }

    # -----------------------------------------------------------------------
    # Helpers (private to this invocation)
    # -----------------------------------------------------------------------
    function _FormatTimestamp {
        param([string]$Raw)
        if ([string]::IsNullOrWhiteSpace($Raw)) { return '' }
        $dt = [datetime]::MinValue
        if ([datetime]::TryParse(
                $Raw,
                [System.Globalization.CultureInfo]::InvariantCulture,
                [System.Globalization.DateTimeStyles]::None,
                [ref]$dt)) {
            return $dt.ToString('yyyy-MM-dd HH:mm:ss')
        }
        return $Raw
    }

    # -----------------------------------------------------------------------
    # Load CHANGELOG (primary input). One JSON object per non-empty line.
    # -----------------------------------------------------------------------
    if (-not (Test-Path -LiteralPath $ChangeLogPath)) {
        throw "Changelog not found: $ChangeLogPath"
    }

    $events   = New-Object System.Collections.Generic.List[object]
    $badLines = 0
    foreach ($line in (Get-Content -LiteralPath $ChangeLogPath -Encoding UTF8)) {
        if ([string]::IsNullOrWhiteSpace($line)) { continue }
        try {
            $o = $line | ConvertFrom-Json
        } catch {
            $badLines++
            continue
        }
        if ($null -eq $o) { continue }

        $rawTs = if ($o.PSObject.Properties.Name -contains 'Timestamp') { [string]$o.Timestamp } else { '' }
        $sortDt = [datetime]::MinValue
        [void][datetime]::TryParse(
            $rawTs,
            [System.Globalization.CultureInfo]::InvariantCulture,
            [System.Globalization.DateTimeStyles]::None,
            [ref]$sortDt)

        $events.Add([pscustomobject]@{
            SortKey        = $sortDt
            TimestampHuman = _FormatTimestamp -Raw $rawTs
            Domain         = if ($o.PSObject.Properties.Name -contains 'Domain')         { [string]$o.Domain }         else { '' }
            GroupName      = if ($o.PSObject.Properties.Name -contains 'GroupName')      { [string]$o.GroupName }      else { '' }
            SamAccountName = if ($o.PSObject.Properties.Name -contains 'SamAccountName') { [string]$o.SamAccountName } else { '' }
            DisplayName    = if ($o.PSObject.Properties.Name -contains 'DisplayName')    { [string]$o.DisplayName }    else { '' }
            Email          = if ($o.PSObject.Properties.Name -contains 'Email')          { [string]$o.Email }          else { '' }
            Action         = if ($o.PSObject.Properties.Name -contains 'Action')         { [string]$o.Action }         else { '' }
        })
    }

    # Sort Timestamp DESC (most recent first). Stable secondary keys for determinism.
    $sorted = $events | Sort-Object -Property `
        @{ Expression = 'SortKey';   Descending = $true },
        @{ Expression = 'Domain';    Descending = $false },
        @{ Expression = 'GroupName'; Descending = $false },
        @{ Expression = 'Action';    Descending = $false }

    $totalEvents  = $sorted.Count
    $addedCount   = ($sorted | Where-Object { $_.Action -eq 'Added' }   | Measure-Object).Count
    $removedCount = ($sorted | Where-Object { $_.Action -eq 'Removed' } | Measure-Object).Count
    $otherCount   = $totalEvents - $addedCount - $removedCount

    # Window bounds (from parseable timestamps only)
    $dated = $sorted | Where-Object { $_.SortKey -ne [datetime]::MinValue }
    if ($dated.Count -gt 0) {
        $windowStart = ($dated | Select-Object -Last  1).TimestampHuman
        $windowEnd   = ($dated | Select-Object -First 1).TimestampHuman
    } else {
        $windowStart = 'n/a'
        $windowEnd   = 'n/a'
    }

    $generatedAt = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')

    # -----------------------------------------------------------------------
    # Shared accessible theme: inherit the audited canonical palette (B00) into B08's local token
    # names + keep the added/removed semantic colours; runtime light/dark machinery via the generator.
    # -----------------------------------------------------------------------
    $pal = Get-GEReportThemePalette
    $b08Light = [ordered]@{
        bg = $pal.Light['bg']; card = $pal.Light['surface']; 'surface-alt' = $pal.Light['surface-alt']
        ink = $pal.Light['ink']; muted = $pal.Light['muted']; line = $pal.Light['line']; accent = $pal.Light['header-bg']
        'added-bg' = '#e8f7ec'; 'added-ink' = '#1d7a3a'; 'added-bar' = '#2faa55'
        'removed-bg' = '#fdeaea'; 'removed-ink' = '#b22929'; 'removed-bar' = '#d94141'; anno = '#fff9e6'
    }
    $b08Dark = [ordered]@{
        bg = $pal.Dark['bg']; card = $pal.Dark['surface']; 'surface-alt' = $pal.Dark['surface-alt']
        ink = $pal.Dark['ink']; muted = $pal.Dark['muted']; line = $pal.Dark['line']; accent = $pal.Dark['header-bg']
        'added-bg' = '#0e2a18'; 'added-ink' = '#4ade80'; 'added-bar' = '#2faa55'
        'removed-bg' = '#2a0e0e'; 'removed-ink' = '#f87171'; 'removed-bar' = '#d94141'; anno = '#2a2710'
    }
    $themeCss  = Get-GEThemedRootCss -Light $b08Light -Dark $b08Dark -ExtraRootCss (Get-GEReportThemeBadgeCss)
    $themeAttr = if ($Theme -eq 'dark' -or $Theme -eq 'light') { " data-theme=`"$Theme`"" } else { '' }

    # -----------------------------------------------------------------------
    # Build HTML
    # -----------------------------------------------------------------------
    $sb = New-Object System.Text.StringBuilder

    [void]$sb.AppendLine('<!DOCTYPE html>')
    [void]$sb.AppendLine(('<html lang="en"{0}>' -f $themeAttr))
    [void]$sb.AppendLine('<head>')
    [void]$sb.AppendLine('<meta charset="utf-8" />')
    [void]$sb.AppendLine('<meta name="viewport" content="width=device-width, initial-scale=1" />')
    [void]$sb.AppendLine(('<title>{0} - {1}</title>' -f (ConvertTo-AttestationHtmlSafe $ReportId), (ConvertTo-AttestationHtmlSafe $Title)))
    [void]$sb.AppendLine('<style>')
    [void]$sb.AppendLine(':root{color-scheme:light dark;}')
    [void]$sb.AppendLine($themeCss)
    [void]$sb.AppendLine(@'
*{box-sizing:border-box;}
body{margin:0;background:var(--bg);color:var(--ink);
font-family:Segoe UI,Tahoma,Arial,sans-serif;font-size:13px;line-height:1.45;}
.wrap{max-width:1280px;margin:0 auto;padding:24px;}
header.rpt{background:var(--accent);color:#fff;border-radius:10px;padding:20px 24px;margin-bottom:18px;}
header.rpt h1{margin:0 0 4px;font-size:20px;}
header.rpt .sub{font-size:13px;opacity:.9;}
header.rpt .id{font-family:Consolas,monospace;font-size:12px;opacity:.8;}
.meta{display:flex;flex-wrap:wrap;gap:12px;margin:16px 0;}
.card{background:var(--card);border:1px solid var(--line);border-radius:8px;
padding:12px 16px;min-width:150px;flex:1;}
.card .k{font-size:11px;text-transform:uppercase;letter-spacing:.04em;color:var(--muted);}
.card .v{font-size:22px;font-weight:600;margin-top:2px;}
.card.added .v{color:var(--added-ink);}
.card.removed .v{color:var(--removed-ink);}
.legend{margin:10px 0 16px;font-size:12px;color:var(--muted);}
.pill{display:inline-block;padding:2px 9px;border-radius:11px;font-weight:600;font-size:11px;
letter-spacing:.02em;}
.pill.added{background:var(--added-bg);color:var(--added-ink);}
.pill.removed{background:var(--removed-bg);color:var(--removed-ink);}
.pill.other{background:var(--surface-alt);color:var(--muted);}
.tablewrap{background:var(--card);border:1px solid var(--line);border-radius:8px;overflow:hidden;}
table{border-collapse:collapse;width:100%;}
thead th{position:sticky;top:0;background:var(--surface-alt);text-align:left;padding:9px 12px;
font-size:11px;text-transform:uppercase;letter-spacing:.03em;color:var(--muted);
border-bottom:2px solid var(--line);white-space:nowrap;}
tbody td{padding:8px 12px;border-bottom:1px solid var(--line);vertical-align:top;}
tbody tr:hover{background:var(--surface-alt);}
tr.added{background:var(--added-bg);}
tr.added td:first-child{box-shadow:inset 4px 0 0 var(--added-bar);}
tr.removed{background:var(--removed-bg);}
tr.removed td:first-child{box-shadow:inset 4px 0 0 var(--removed-bar);}
td.ts{font-family:Consolas,monospace;white-space:nowrap;}
td.member .dn{font-weight:600;}
td.member .sam{color:var(--muted);font-family:Consolas,monospace;font-size:12px;}
td.member .em{color:var(--muted);font-size:12px;}
td.anno{background:var(--anno);min-width:120px;border-left:1px dashed var(--line);}
.empty{padding:30px;text-align:center;color:var(--muted);}
footer.rpt{margin-top:18px;font-size:11px;color:var(--muted);text-align:center;}
'@)
    [void]$sb.AppendLine('</style>')
    [void]$sb.AppendLine('</head>')
    [void]$sb.AppendLine('<body>')
    [void]$sb.AppendLine((Get-GEReportThemeToggleHtml))
    [void]$sb.AppendLine('<div class="wrap">')

    # Header
    [void]$sb.AppendLine('<header class="rpt">')
    [void]$sb.AppendLine(('<h1>{0}</h1>' -f (ConvertTo-AttestationHtmlSafe $Title)))
    [void]$sb.AppendLine('<div class="sub">All Added/Removed group membership events over the review window &mdash; who/what/when. Sorted by timestamp, most recent first.</div>')
    [void]$sb.AppendLine(('<div class="id">{0}</div>' -f (ConvertTo-AttestationHtmlSafe $ReportId)))
    [void]$sb.AppendLine('</header>')

    # Summary cards
    [void]$sb.AppendLine('<div class="meta">')
    [void]$sb.AppendLine(('<div class="card"><div class="k">Total Events</div><div class="v">{0}</div></div>' -f $totalEvents))
    [void]$sb.AppendLine(('<div class="card added"><div class="k">Added</div><div class="v">{0}</div></div>' -f $addedCount))
    [void]$sb.AppendLine(('<div class="card removed"><div class="k">Removed</div><div class="v">{0}</div></div>' -f $removedCount))
    if ($otherCount -gt 0) {
        [void]$sb.AppendLine(('<div class="card"><div class="k">Other</div><div class="v">{0}</div></div>' -f $otherCount))
    }
    [void]$sb.AppendLine(('<div class="card"><div class="k">Window Start</div><div class="v" style="font-size:14px;">{0}</div></div>' -f (ConvertTo-AttestationHtmlSafe $windowStart)))
    [void]$sb.AppendLine(('<div class="card"><div class="k">Window End</div><div class="v" style="font-size:14px;">{0}</div></div>' -f (ConvertTo-AttestationHtmlSafe $windowEnd)))
    [void]$sb.AppendLine('</div>')

    [void]$sb.AppendLine('<div class="legend">Legend: <span class="pill added">Added</span> membership granted &nbsp; <span class="pill removed">Removed</span> membership revoked. The <strong>Authorized Change?</strong> and <strong>Ticket Ref</strong> columns are intentionally blank for reviewer annotation (attestation evidence for SOC 2 CC6.3 / SOX 404 / PCI Req 8).</div>')

    # Table
    [void]$sb.AppendLine('<div class="tablewrap">')
    if ($totalEvents -eq 0) {
        [void]$sb.AppendLine('<div class="empty">No membership change events recorded in the changelog for this window.</div>')
    } else {
        [void]$sb.AppendLine('<table>')
        [void]$sb.AppendLine('<thead><tr>')
        [void]$sb.AppendLine('<th>Timestamp</th><th>Domain</th><th>Group Name</th><th>Member</th><th>Action</th><th>Authorized Change?</th><th>Ticket Ref</th>')
        [void]$sb.AppendLine('</tr></thead>')
        [void]$sb.AppendLine('<tbody>')

        foreach ($e in $sorted) {
            $act = $e.Action
            switch ($act) {
                'Added'   { $rowClass = 'added';   $pillClass = 'added' }
                'Removed' { $rowClass = 'removed'; $pillClass = 'removed' }
                default   { $rowClass = '';        $pillClass = 'other' }
            }

            $dn  = ConvertTo-AttestationHtmlSafe $e.DisplayName
            $sam = ConvertTo-AttestationHtmlSafe $e.SamAccountName
            $em  = ConvertTo-AttestationHtmlSafe $e.Email

            $memberCell = ''
            if ($dn)  { $memberCell += ('<div class="dn">{0}</div>'  -f $dn) }
            if ($sam) { $memberCell += ('<div class="sam">{0}</div>' -f $sam) }
            if ($em)  { $memberCell += ('<div class="em">{0}</div>'  -f $em) }
            if (-not $memberCell) { $memberCell = '<span class="sam">(unknown)</span>' }

            $actText = if ($act) { ConvertTo-AttestationHtmlSafe $act } else { '(n/a)' }

            [void]$sb.AppendLine(('<tr class="{0}">' -f $rowClass))
            [void]$sb.AppendLine(('<td class="ts">{0}</td>'          -f (ConvertTo-AttestationHtmlSafe $e.TimestampHuman)))
            [void]$sb.AppendLine(('<td>{0}</td>'                     -f (ConvertTo-AttestationHtmlSafe $e.Domain)))
            [void]$sb.AppendLine(('<td>{0}</td>'                     -f (ConvertTo-AttestationHtmlSafe $e.GroupName)))
            [void]$sb.AppendLine(('<td class="member">{0}</td>'      -f $memberCell))
            [void]$sb.AppendLine(('<td><span class="pill {0}">{1}</span></td>' -f $pillClass, $actText))
            [void]$sb.AppendLine('<td class="anno">&nbsp;</td>')
            [void]$sb.AppendLine('<td class="anno">&nbsp;</td>')
            [void]$sb.AppendLine('</tr>')
        }

        [void]$sb.AppendLine('</tbody>')
        [void]$sb.AppendLine('</table>')
    }
    [void]$sb.AppendLine('</div>')

    # Footer
    [void]$sb.AppendLine('<footer class="rpt">')
    [void]$sb.AppendLine(('Generated {0} &bull; Source changelog: {1} &bull; {2} event(s), full-list (every change shown).' -f `
        (ConvertTo-AttestationHtmlSafe $generatedAt),
        (ConvertTo-AttestationHtmlSafe $ChangeLogPath),
        $totalEvents))
    if ($badLines -gt 0) {
        [void]$sb.AppendLine(('<br/><span style="color:#b22929;">{0} malformed changelog line(s) skipped.</span>' -f $badLines))
    }
    [void]$sb.AppendLine('</footer>')

    [void]$sb.AppendLine('</div>')
    [void]$sb.AppendLine((Get-GEReportThemeScript))
    [void]$sb.AppendLine('</body></html>')

    # -----------------------------------------------------------------------
    # Write output -- UTF-8 without BOM
    # -----------------------------------------------------------------------
    $outDir = Split-Path -Parent $OutputPath
    if ($outDir -and -not (Test-Path -LiteralPath $outDir)) {
        New-Item -ItemType Directory -Path $outDir -Force | Out-Null
    }

    $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($OutputPath, $sb.ToString(), $utf8NoBom)

    return $OutputPath
}
