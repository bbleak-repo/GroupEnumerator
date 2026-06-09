<#
.SYNOPSIS
    B06 - Group Inventory / Catalog (BASELINE report module)

.DESCRIPTION
    Parameterized product module. Accepts group results via -GroupResults and
    emits one HTML row per group: the baseline directory inventory auditors use
    to spot groups with no members or anomalous structure.

    Account treatment: numbers-only. No individual account identities are
    rendered anywhere in this report; member information is reduced to direct
    counts and derived hygiene flags only.

    Column order follows the spec: identity first (GroupName, Domain), then
    structural fields (IsNested, Skipped), then metric fields (MemberCount),
    then risk/flag fields last (IsEmpty, NoMembers).

.NOTES
    Readable / auditable by design (no encoded or hidden PowerShell).
    Self-contained: dot-sources nothing; no hardcoded input/output paths.
#>

function ConvertTo-B06HtmlText {
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

function Get-B06Prop {
    # Safe property accessor that tolerates missing members under StrictMode.
    param([object]$Object, [string]$Name)
    if ($null -eq $Object) { return $null }
    # Dual-mode: -FromCache passes hashtables; live enumeration passes objects.
    if ($Object -is [System.Collections.IDictionary]) {
        if ($Object.Contains($Name)) { return $Object[$Name] }
        return $null
    }
    $p = $Object.PSObject.Properties[$Name]
    if ($null -eq $p) { return $null }
    return $p.Value
}

function Get-B06BoolBadge {
    param([bool]$Value, [bool]$YesIsBad = $true)
    if ($Value) {
        $cls = if ($YesIsBad) { 'yes' } else { 'no' }
        return ('<span class="badge {0}">Yes</span>' -f $cls)
    } else {
        return '<span class="badge no">No</span>'
    }
}

function Export-GroupInventoryCatalogReport {
    <#
    .SYNOPSIS
        Writes a B06 Group Inventory / Catalog HTML report: one row per group
        with structural and hygiene metadata (numbers-only; no account identities).

    .PARAMETER GroupResults
        Array of group result objects with shape:
        @{ Data = @{ Domain; GroupName; MemberCount; IsNested; Skipped;
                     Members = @(@{ SamAccountName; DisplayName; Email; Enabled }) };
           Errors = @() }

    .PARAMETER OutputPath
        Destination .html file path.

    .PARAMETER Title
        Optional report title override.

    .PARAMETER Theme
        'dark' (default) or 'light'. Controls the colour palette.

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

        [Parameter()][string]$Title = 'Group Inventory / Catalog',

        [Parameter()][ValidateSet('auto', 'dark', 'light')][string]$Theme = 'auto'
    )

    Set-StrictMode -Version 2.0

    # Hygiene threshold: a group at/below this direct count is flagged IsEmpty.
    $EmptyMemberThreshold = 0

    # -----------------------------------------------------------------------
    # Build one inventory record per group
    # -----------------------------------------------------------------------
    $rows = New-Object System.Collections.Generic.List[object]

    foreach ($g in $GroupResults) {
        $data = Get-B06Prop $g 'Data'
        if ($null -eq $data) { continue }

        $domain    = Get-B06Prop $data 'Domain'
        $groupName = Get-B06Prop $data 'GroupName'
        $isNested  = Get-B06Prop $data 'IsNested'
        $skipped   = Get-B06Prop $data 'Skipped'

        # Direct member count: prefer the recorded MemberCount, fall back to
        # the length of the Members array so the catalog stays accurate even
        # if the stored count is absent.
        $memberCount = Get-B06Prop $data 'MemberCount'
        $members     = Get-B06Prop $data 'Members'
        $directCount = $null
        if ($null -ne $memberCount) {
            $directCount = [int]$memberCount
        } elseif ($null -ne $members) {
            $directCount = @($members).Count
        } else {
            $directCount = 0
        }

        # Normalise structural fields for display.
        $isNestedDisplay = if ($null -eq $isNested) { 'Unknown' } elseif ([bool]$isNested) { 'Yes' } else { 'No' }
        $skippedBool     = if ($null -eq $skipped) { $false } else { [bool]$skipped }

        # Derived hygiene flags.
        $noMembers = ($directCount -le 0)
        $isEmpty   = ($directCount -le $EmptyMemberThreshold)

        $flagged = ($isEmpty -or $noMembers -or $skippedBool)

        $rows.Add([pscustomobject]@{
            GroupName       = [string]$groupName
            Domain          = [string]$domain
            IsNestedDisplay = $isNestedDisplay
            Skipped         = $skippedBool
            MemberCount     = $directCount
            IsEmpty         = $isEmpty
            NoMembers       = $noMembers
            Flagged         = $flagged
        })
    }

    # Stable, auditor-friendly sort: domain then group name.
    $sorted = $rows | Sort-Object Domain, GroupName

    $total        = @($sorted).Count
    $flaggedCount = @($sorted | Where-Object { $_.Flagged }).Count
    $clean        = $total - $flaggedCount

    # -----------------------------------------------------------------------
    # Colour palette
    # -----------------------------------------------------------------------
    # Shared accessible theme: B06 was hard-coded light (both "themes" identical). It uses exactly
    # the canonical token names, so it consumes Get-GEReportThemeCss directly; the component CSS below
    # references var(--...) tokens -> AA in both themes + runtime toggle + print-forces-light.
    $themeCss   = Get-GEReportThemeCss
    $themeAttr  = if ($Theme -eq 'dark' -or $Theme -eq 'light') { " data-theme=`"$Theme`"" } else { '' }
    $cssPalette = @'
* { box-sizing: border-box; }
body { font-family: Segoe UI, Tahoma, Arial, sans-serif; margin: 0; padding: 24px;
       background: var(--bg); color: var(--ink); font-size: 14px; }
.title-block { background: var(--header-bg); color: #fff; padding: 18px 22px; border-radius: 8px 8px 0 0; }
.title-block h1 { margin: 0 0 4px 0; font-size: 20px; }
.title-block .subtitle { color: rgba(255,255,255,.82); font-size: 13px; margin: 0 0 12px 0; }
.meta { display: flex; flex-wrap: wrap; gap: 8px 28px; font-size: 12.5px; color: rgba(255,255,255,.82); }
.meta div span.k { color: rgba(255,255,255,.6); }
.panel { background: var(--surface); border: 1px solid var(--line); border-top: none;
         border-radius: 0 0 8px 8px; overflow: hidden; }
table { border-collapse: collapse; width: 100%; }
thead th { background: var(--surface-alt); text-align: left; padding: 9px 12px; font-size: 12px;
           text-transform: uppercase; letter-spacing: .03em; color: var(--muted);
           border-bottom: 2px solid var(--line); white-space: nowrap; }
tbody td { padding: 8px 12px; border-bottom: 1px solid var(--line); color: var(--ink); }
tbody tr:nth-child(even) { background: var(--surface-alt); }
tbody tr.flagged { background: var(--row-crit-bg); }
tbody tr.flagged:nth-child(even) { background: var(--row-crit-bg); }
.num { text-align: right; font-variant-numeric: tabular-nums; }
.col-group-headers th.struct { background: var(--surface-alt); }
.col-group-headers th.metric { background: var(--surface-alt); }
.col-group-headers th.flag { background: var(--row-crit-bg); }
.badge { display: inline-block; padding: 1px 8px; border-radius: 10px; font-size: 11.5px;
         font-weight: 600; }
.badge.yes { background: var(--badge-crit-bg); color: var(--badge-crit-ink); }
.badge.no { background: var(--badge-ok-bg); color: var(--badge-ok-ink); }
.badge.neutral { background: var(--surface-alt); color: var(--muted); }
.footer { padding: 12px 16px; background: var(--surface-alt); border-top: 1px solid var(--line);
          font-size: 13px; color: var(--ink); border-radius: 0 0 8px 8px; }
.footer strong { color: var(--ink); }
.legend { margin: 14px 2px 0; font-size: 12px; color: var(--muted); }
'@

    # -----------------------------------------------------------------------
    # Render HTML
    # -----------------------------------------------------------------------
    $asOf   = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss zzz')
    $tEsc   = ConvertTo-B06HtmlText $Title

    $sb = New-Object System.Text.StringBuilder
    [void]$sb.AppendLine('<!DOCTYPE html>')
    [void]$sb.AppendLine(('<html lang="en"{0}>' -f $themeAttr))
    [void]$sb.AppendLine('<head>')
    [void]$sb.AppendLine('<meta charset="utf-8">')
    [void]$sb.AppendLine('<meta name="viewport" content="width=device-width, initial-scale=1">')
    [void]$sb.AppendLine(('<title>{0}</title>' -f $tEsc))
    [void]$sb.AppendLine('<style>')
    [void]$sb.AppendLine(':root { color-scheme: light dark; }')
    [void]$sb.AppendLine($themeCss)
    [void]$sb.AppendLine($cssPalette)
    [void]$sb.AppendLine('</style>')
    [void]$sb.AppendLine('</head>')
    [void]$sb.AppendLine('<body>')
    [void]$sb.AppendLine((Get-GEReportThemeToggleHtml))

    # Title block
    [void]$sb.AppendLine('<div class="title-block">')
    [void]$sb.AppendLine(('<h1>{0}</h1>' -f $tEsc))
    [void]$sb.AppendLine('<p class="subtitle">Baseline directory inventory &mdash; one row per group with structural and hygiene metadata (numbers-only).</p>')
    [void]$sb.AppendLine('<div class="meta">')
    [void]$sb.AppendLine(('<div><span class="k">As of:</span> {0}</div>' -f (ConvertTo-B06HtmlText $asOf)))
    [void]$sb.AppendLine(('<div><span class="k">Threshold (IsEmpty):</span> direct members &le; {0}</div>' -f $EmptyMemberThreshold))
    [void]$sb.AppendLine('<div><span class="k">Threshold (NoMembers):</span> direct members = 0</div>')
    [void]$sb.AppendLine('</div>')
    [void]$sb.AppendLine('</div>')

    # Table
    [void]$sb.AppendLine('<div class="panel">')
    [void]$sb.AppendLine('<table>')
    [void]$sb.AppendLine('<thead>')
    # Grouping header row to make the identity/structural/metric/flag bands explicit.
    [void]$sb.AppendLine('<tr class="col-group-headers">')
    [void]$sb.AppendLine('<th colspan="2">Identity</th>')
    [void]$sb.AppendLine('<th colspan="2" class="struct">Structural</th>')
    [void]$sb.AppendLine('<th colspan="1" class="metric">Metric</th>')
    [void]$sb.AppendLine('<th colspan="2" class="flag">Risk / Flags</th>')
    [void]$sb.AppendLine('</tr>')
    [void]$sb.AppendLine('<tr>')
    [void]$sb.AppendLine('<th>GroupName</th>')
    [void]$sb.AppendLine('<th>Domain</th>')
    [void]$sb.AppendLine('<th>IsNested</th>')
    [void]$sb.AppendLine('<th>Skipped</th>')
    [void]$sb.AppendLine('<th class="num">MemberCount (direct)</th>')
    [void]$sb.AppendLine('<th>IsEmpty</th>')
    [void]$sb.AppendLine('<th>NoMembers</th>')
    [void]$sb.AppendLine('</tr>')
    [void]$sb.AppendLine('</thead>')
    [void]$sb.AppendLine('<tbody>')

    foreach ($r in $sorted) {
        $rowCls = if ($r.Flagged) { ' class="flagged"' } else { '' }

        $nestedBadge =
            if ($r.IsNestedDisplay -eq 'Unknown') { '<span class="badge neutral">Unknown</span>' }
            elseif ($r.IsNestedDisplay -eq 'Yes')  { '<span class="badge neutral">Yes</span>' }
            else                                    { '<span class="badge neutral">No</span>' }

        [void]$sb.AppendLine(('<tr{0}>' -f $rowCls))
        [void]$sb.AppendLine(('<td class="group-name">{0}</td>' -f (ConvertTo-B06HtmlText $r.GroupName)))
        [void]$sb.AppendLine(('<td>{0}</td>' -f (ConvertTo-B06HtmlText $r.Domain)))
        [void]$sb.AppendLine(('<td>{0}</td>' -f $nestedBadge))
        [void]$sb.AppendLine(('<td>{0}</td>' -f (Get-B06BoolBadge -Value $r.Skipped -YesIsBad $true)))
        [void]$sb.AppendLine(('<td class="num">{0}</td>' -f $r.MemberCount))
        [void]$sb.AppendLine(('<td>{0}</td>' -f (Get-B06BoolBadge -Value $r.IsEmpty -YesIsBad $true)))
        [void]$sb.AppendLine(('<td>{0}</td>' -f (Get-B06BoolBadge -Value $r.NoMembers -YesIsBad $true)))
        [void]$sb.AppendLine('</tr>')
    }

    [void]$sb.AppendLine('</tbody>')
    [void]$sb.AppendLine('</table>')

    # Row-count footer
    [void]$sb.AppendLine('<div class="footer">')
    [void]$sb.AppendLine(('<strong>Total: {0} groups</strong> | Flagged: {1} | Clean: {2}' -f $total, $flaggedCount, $clean))
    [void]$sb.AppendLine('</div>')
    [void]$sb.AppendLine('</div>')

    [void]$sb.AppendLine('<p class="legend">Numbers-only report: member detail is reduced to direct counts and hygiene flags; no individual account identities are listed. A group is <em>Flagged</em> when IsEmpty, NoMembers, or Skipped is Yes.</p>')

    [void]$sb.AppendLine((Get-GEReportThemeScript))
    [void]$sb.AppendLine('</body>')
    [void]$sb.AppendLine('</html>')

    # -----------------------------------------------------------------------
    # Write output (UTF-8, no BOM)
    # -----------------------------------------------------------------------
    $outDir = Split-Path -Parent $OutputPath
    if ($outDir -and -not (Test-Path -LiteralPath $outDir)) {
        New-Item -ItemType Directory -Path $outDir -Force | Out-Null
    }

    $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($OutputPath, $sb.ToString(), $utf8NoBom)

    return $OutputPath
}
