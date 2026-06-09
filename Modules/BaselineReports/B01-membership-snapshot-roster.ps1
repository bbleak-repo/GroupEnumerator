<#
.SYNOPSIS
    B01 - Group Membership Snapshot Roster (parameterized module).

    Baseline certification artifact. Expands every reviewed group into one row
    per member-group pair (full-list account treatment, never aggregated).
    Emits a self-contained, banded HTML roster grouped by group name, identity
    facts first, then account status, then group context.

    Self-contained: dot-sources nothing, includes its own HTML-escape helper,
    and is read-only (never writes back to any cache or state file).
#>

function Export-MembershipSnapshotRosterReport {
    <#
    .SYNOPSIS
        Writes a banded HTML membership roster: one row per member-group pair,
        grouped by group name. Full-list account treatment (every member shown,
        never aggregated).

    .PARAMETER GroupResults
        Array of @{ Data = @{ Domain; GroupName; MemberCount; IsNested; Skipped;
        Members = @(@{ SamAccountName; DisplayName; Email; Enabled }) }; Errors = @() }.

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
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [array]$GroupResults,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$OutputPath,

        [Parameter()][string]$Title,

        [Parameter()][ValidateSet('auto', 'dark', 'light')][string]$Theme = 'auto'
    )

    # --- HTML-escape helper (self-contained, dot-sources nothing) ---------------
    function ConvertTo-B01HtmlText {
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

    function Format-B01Bool {
        param($Value)
        if ($null -eq $Value) { return 'Unknown' }
        if ($Value -is [bool]) { if ($Value) { return 'Yes' } else { return 'No' } }
        $t = [string]$Value
        if ($t -match '^(?i)true$')  { return 'Yes' }
        if ($t -match '^(?i)false$') { return 'No' }
        if ([string]::IsNullOrWhiteSpace($t)) { return 'Unknown' }
        return $t
    }

    # --- Build flat roster: one row per member-group pair -----------------------
    # accountTreatment = full-list: include EVERY member of EVERY in-scope group.
    $groupBlocks = New-Object System.Collections.Generic.List[object]
    $totalRows   = 0
    $totalGroups = 0
    $domainsSeen = New-Object System.Collections.Generic.HashSet[string]

    foreach ($g in $GroupResults) {
        if (-not $g) { continue }

        # Support both PSCustomObject (from JSON) and hashtable inputs
        $hasProp = {
            param($obj, $name)
            if ($obj -is [System.Collections.Hashtable]) { return $obj.ContainsKey($name) }
            return ($obj.PSObject.Properties.Name -contains $name)
        }
        $getProp = {
            param($obj, $name)
            if ($obj -is [System.Collections.Hashtable]) { return $obj[$name] }
            return $obj.$name
        }

        if (-not (& $hasProp $g 'Data') -or -not (& $getProp $g 'Data')) { continue }
        $d = & $getProp $g 'Data'

        $skipped = $false
        if (& $hasProp $d 'Skipped') {
            $rawSkipped = & $getProp $d 'Skipped'
            if ($null -ne $rawSkipped) { $skipped = [bool]$rawSkipped }
        }

        $groupName = ''
        if (& $hasProp $d 'GroupName') { $groupName = [string](& $getProp $d 'GroupName') }
        $domain = ''
        if (& $hasProp $d 'Domain') { $domain = [string](& $getProp $d 'Domain') }
        if ($domain) { [void]$domainsSeen.Add($domain) }

        $memberCount = $null
        if (& $hasProp $d 'MemberCount') { $memberCount = & $getProp $d 'MemberCount' }

        $isNested = $null
        if (& $hasProp $d 'IsNested') { $isNested = & $getProp $d 'IsNested' }

        $members = @()
        if ((& $hasProp $d 'Members') -and (& $getProp $d 'Members')) {
            $members = @(& $getProp $d 'Members')
        }

        $totalGroups++

        $rows = New-Object System.Collections.Generic.List[object]
        if (-not $skipped) {
            foreach ($m in $members) {
                if (-not $m) { continue }
                $mHasProp = {
                    param($name)
                    if ($m -is [System.Collections.Hashtable]) { return $m.ContainsKey($name) }
                    return ($m.PSObject.Properties.Name -contains $name)
                }
                $mGetProp = {
                    param($name)
                    if ($m -is [System.Collections.Hashtable]) { return $m[$name] }
                    return $m.$name
                }
                $rows.Add([pscustomobject]@{
                    DisplayName    = if (& $mHasProp 'DisplayName')    { [string](& $mGetProp 'DisplayName') }    else { '' }
                    SamAccountName = if (& $mHasProp 'SamAccountName') { [string](& $mGetProp 'SamAccountName') } else { '' }
                    Email          = if (& $mHasProp 'Email')          { [string](& $mGetProp 'Email') }          else { '' }
                    Enabled        = if (& $mHasProp 'Enabled')        { & $mGetProp 'Enabled' }                  else { $null }
                })
                $totalRows++
            }
        }

        $groupBlocks.Add([pscustomobject]@{
            GroupName   = $groupName
            Domain      = $domain
            MemberCount = $memberCount
            IsNested    = $isNested
            Skipped     = $skipped
            Rows        = $rows
        })
    }

    # Group-anchored ordering: alphabetical by domain then group name.
    $groupBlocks = @($groupBlocks | Sort-Object @{Expression={$_.Domain}}, @{Expression={$_.GroupName}})

    $asOf = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss zzz')

    # Derive scope domains from data
    $scopeDomains = @($domainsSeen)

    # Resolve title
    $reportTitle = if ($Title) { $Title } else { 'Group Membership Snapshot Roster' }

    # Shared accessible theme: inherit the audited canonical palette into B01's local token names
    # and author the dark side; navy "head" is only a fill (white text) -- headings use --accent so
    # they stay AA in dark. Runtime toggle + print-forces-light via the generator.
    $pal = Get-GEReportThemePalette
    $b01Light = [ordered]@{ ink = $pal.Light['ink']; muted = $pal.Light['muted']; line = $pal.Light['line']; band = $pal.Light['surface-alt']; head = $pal.Light['header-bg']; sub = $pal.Light['surface-alt']; subink = $pal.Light['ink']; accent = $pal.Light['accent']; bg = $pal.Light['bg']; surface = $pal.Light['surface']; ok = $pal.Light['ok']; crit = $pal.Light['crit']; warn = $pal.Light['warn'] }
    $b01Dark  = [ordered]@{ ink = $pal.Dark['ink'];  muted = $pal.Dark['muted'];  line = $pal.Dark['line'];  band = $pal.Dark['surface-alt'];  head = $pal.Dark['header-bg'];  sub = $pal.Dark['surface-alt'];  subink = $pal.Dark['ink'];  accent = $pal.Dark['accent'];  bg = $pal.Dark['bg'];  surface = $pal.Dark['surface'];  ok = $pal.Dark['ok'];  crit = $pal.Dark['crit'];  warn = $pal.Dark['warn'] }
    $themeCss  = Get-GEThemedRootCss -Light $b01Light -Dark $b01Dark -ExtraRootCss (Get-GEReportThemeBadgeCss)
    $themeAttr = if ($Theme -eq 'dark' -or $Theme -eq 'light') { " data-theme=`"$Theme`"" } else { '' }

    # --- Render HTML (shared var(--...) tokens; AA in both themes) --------------
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.AppendLine('<!DOCTYPE html>')
    [void]$sb.AppendLine(('<html lang="en"{0}><head><meta charset="utf-8">' -f $themeAttr))
    [void]$sb.AppendLine('<meta name="viewport" content="width=device-width, initial-scale=1">')
    [void]$sb.AppendLine(('<title>{0}</title>' -f (ConvertTo-B01HtmlText $reportTitle)))
    [void]$sb.AppendLine('<style>')
    [void]$sb.AppendLine(':root { color-scheme: light dark; }')
    [void]$sb.AppendLine($themeCss)
    [void]$sb.AppendLine(@'
  * { box-sizing:border-box; }
  body { margin:0; padding:0 0 48px; font-family:Segoe UI,Tahoma,Arial,sans-serif;
         color:var(--ink); background:var(--bg); font-size:13px; }
  .title-block { padding:22px 28px 16px; border-bottom:3px solid var(--accent); }
  .title-block h1 { margin:0 0 4px; font-size:21px; color:var(--accent); }
  .title-block .subject { margin:0 0 12px; color:var(--muted); font-size:13px; }
  .meta { display:flex; flex-wrap:wrap; gap:8px 28px; font-size:12px; }
  .meta .kv { display:flex; gap:6px; }
  .meta .k { color:var(--muted); }
  .meta .v { font-weight:600; }
  .wrap { padding:0 28px; }
  table { border-collapse:collapse; width:100%; margin-top:18px; background:var(--surface);
          border:1px solid var(--line); }
  thead th { position:sticky; top:0; z-index:3; background:var(--head); color:#fff;
             text-align:left; padding:8px 10px; font-size:11px; letter-spacing:.04em;
             text-transform:uppercase; border-right:1px solid rgba(255,255,255,.15); white-space:nowrap; }
  thead th:last-child { border-right:none; }
  tbody td { padding:6px 10px; border-bottom:1px solid var(--line);
             border-right:1px solid var(--line); vertical-align:top; }
  tbody td:last-child { border-right:none; }
  tbody tr.band-1 td { background:var(--band); }
  tbody tr.member:hover td { background:var(--band); }
  tr.group-sub td { position:sticky; top:34px; z-index:2; background:var(--sub);
                    color:var(--subink); font-weight:700; padding:8px 10px;
                    border-top:2px solid var(--accent); }
  .gs-name { font-size:13px; }
  .gs-meta { font-weight:500; color:var(--muted); font-size:11.5px; margin-left:10px; }
  .gs-skip { color:var(--crit); font-weight:700; }
  .status-yes { color:var(--ok); font-weight:600; }
  .status-no  { color:var(--crit); font-weight:600; }
  .status-unk { color:var(--muted); }
  .mono { font-family:Consolas,Menlo,monospace; }
  .nested-yes { color:var(--warn); font-weight:600; }
  .empty-note { padding:10px; color:var(--muted); font-style:italic; }
  .footer { padding:18px 28px 0; color:var(--muted); font-size:11px; }
</style>
'@)
    [void]$sb.AppendLine('</head><body>')
    [void]$sb.AppendLine((Get-GEReportThemeToggleHtml))

    # Title block
    [void]$sb.AppendLine('<div class="title-block">')
    [void]$sb.AppendLine(('  <h1>{0}</h1>' -f (ConvertTo-B01HtmlText $reportTitle)))
    [void]$sb.AppendLine('  <p class="subject">Point-in-time flat export &mdash; one row per member-group pair. Each access grant can be individually certified or revoked.</p>')
    [void]$sb.AppendLine('  <div class="meta">')
    [void]$sb.AppendLine(('    <div class="kv"><span class="k">As of:</span><span class="v">{0}</span></div>' -f (ConvertTo-B01HtmlText $asOf)))
    $scopeText = if ($scopeDomains -and $scopeDomains.Count -gt 0) { ($scopeDomains -join ', ') } else { '(unspecified)' }
    [void]$sb.AppendLine(('    <div class="kv"><span class="k">Scope:</span><span class="v">{0}</span></div>' -f (ConvertTo-B01HtmlText $scopeText)))
    [void]$sb.AppendLine(('    <div class="kv"><span class="k">Total groups:</span><span class="v">{0}</span></div>' -f $totalGroups))
    [void]$sb.AppendLine(('    <div class="kv"><span class="k">Total rows:</span><span class="v">{0}</span></div>' -f $totalRows))
    [void]$sb.AppendLine('  </div>')
    [void]$sb.AppendLine('</div>')

    [void]$sb.AppendLine('<div class="wrap">')

    if ($groupBlocks.Count -eq 0) {
        [void]$sb.AppendLine('  <p class="empty-note">No groups found in the provided data.</p>')
    } else {
        [void]$sb.AppendLine('<table>')
        [void]$sb.AppendLine('  <thead><tr>')
        [void]$sb.AppendLine('    <th>DisplayName</th><th>SamAccountName</th><th>Email</th>')
        [void]$sb.AppendLine('    <th>Enabled</th>')
        [void]$sb.AppendLine('    <th>GroupName</th><th>Domain</th><th>MemberCount</th><th>IsNested</th>')
        [void]$sb.AppendLine('  </tr></thead>')
        [void]$sb.AppendLine('  <tbody>')

        foreach ($block in $groupBlocks) {
            $gName = ConvertTo-B01HtmlText $block.GroupName
            $gDom  = ConvertTo-B01HtmlText $block.Domain
            $mc    = if ($null -ne $block.MemberCount) { [string]$block.MemberCount } else { '?' }
            $rowCount = $block.Rows.Count
            $nestedDisp = Format-B01Bool $block.IsNested

            $subMeta = "Domain: $gDom &nbsp;|&nbsp; MemberCount: $mc &nbsp;|&nbsp; Rows: $rowCount &nbsp;|&nbsp; IsNested: $nestedDisp"
            $skipTag = ''
            if ($block.Skipped) { $skipTag = ' <span class="gs-skip">[SKIPPED &mdash; not enumerated]</span>' }

            [void]$sb.AppendLine('    <tr class="group-sub"><td colspan="8">')
            [void]$sb.AppendLine(("      <span class=`"gs-name`">{0}</span><span class=`"gs-meta`">{1}</span>{2}" -f $gName, $subMeta, $skipTag))
            [void]$sb.AppendLine('    </td></tr>')

            if ($rowCount -eq 0) {
                $note = if ($block.Skipped) { 'Group skipped during enumeration; no members captured.' } else { 'No members.' }
                [void]$sb.AppendLine(('    <tr class="member"><td colspan="8" class="empty-note">{0}</td></tr>' -f $note))
                continue
            }

            $i = 0
            foreach ($r in $block.Rows) {
                $bandClass = if ($i % 2 -eq 1) { 'band-1' } else { 'band-0' }
                $i++

                $dn  = ConvertTo-B01HtmlText $r.DisplayName
                $sam = ConvertTo-B01HtmlText $r.SamAccountName
                $em  = ConvertTo-B01HtmlText $r.Email

                if ($null -eq $r.Enabled) {
                    $enCell = '<span class="status-unk">Unknown</span>'
                } elseif ([bool]$r.Enabled) {
                    $enCell = '<span class="status-yes">Enabled</span>'
                } else {
                    $enCell = '<span class="status-no">Disabled</span>'
                }

                $nestedCell = if ($nestedDisp -eq 'Yes') { ('<span class="nested-yes">{0}</span>' -f $nestedDisp) } else { $nestedDisp }

                [void]$sb.AppendLine(('    <tr class="member {0}">' -f $bandClass))
                [void]$sb.AppendLine(('      <td>{0}</td><td class="mono">{1}</td><td>{2}</td>' -f $dn, $sam, $em))
                [void]$sb.AppendLine(('      <td>{0}</td>' -f $enCell))
                [void]$sb.AppendLine(('      <td>{0}</td><td>{1}</td><td>{2}</td><td>{3}</td>' -f $gName, $gDom, $mc, $nestedCell))
                [void]$sb.AppendLine('    </tr>')
            }
        }

        [void]$sb.AppendLine('  </tbody>')
        [void]$sb.AppendLine('</table>')
    }

    [void]$sb.AppendLine('</div>')
    [void]$sb.AppendLine(('<div class="footer">Baseline artifact B01 &mdash; Membership Snapshot Roster. Full-list account treatment (every member shown, never aggregated). Generated {0}.</div>' -f (ConvertTo-B01HtmlText $asOf)))
    [void]$sb.AppendLine((Get-GEReportThemeScript))
    [void]$sb.AppendLine('</body></html>')

    # --- Write output -----------------------------------------------------------
    $outDir = Split-Path -Parent $OutputPath
    if ($outDir -and -not (Test-Path -LiteralPath $outDir)) {
        New-Item -ItemType Directory -Path $outDir -Force | Out-Null
    }
    [System.IO.File]::WriteAllText($OutputPath, $sb.ToString(), (New-Object System.Text.UTF8Encoding($false)))

    return $OutputPath
}
