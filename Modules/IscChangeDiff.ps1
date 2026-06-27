<#
.SYNOPSIS
    ISC Change Diff - turn a groups-isc-changes-both*.csv change feed into a clean,
    two-section adds/removes report (SailPoint-style).

.DESCRIPTION
    Pure, dependency-free module. Reads the SailPoint-ready change feed produced by the
    enumerator (Export-ChangeFeedCsv: columns Change,Domain,GroupName,SamAccountName,
    DisplayName,Email; Change in {Added,Removed}) and renders a single self-contained,
    light, paste-friendly HTML report with:

      * KPI summary cards (added / removed / groups affected / net),
      * an ADDED section as a per-USER list (one row per user with the groups they joined),
      * a REMOVED section as a removal TABLE (one row per group/user removal).

    Visual language mirrors the SailPoint-GovernanceToolkit delta reports: green ADDED /
    red REMOVED badges, dark table headers, alternating rows, system fonts, inline styles
    (survives copy-paste into Outlook/Word). Light-only by design for evidence/email use.

    Three layers, cleanly separated:
      Import-IscChangeFeed   pure read   -> normalized row objects
      Get-IscChangeDiff      pure shape  -> @{ Adds; Removes; Summary }
      New-IscChangeDiffHtml  side-effect -> writes the HTML, returns the path

    Self-contained: dot-sources nothing. Privileged highlighting is optional (caller passes a
    scriptblock predicate, e.g. from New-RCPrivilegedPredicate) so the module stays decoupled.
#>

function ConvertTo-IscDiffHtmlSafe {
    # HTML-encode a value for safe interpolation into element text/attributes.
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

function Import-IscChangeFeed {
    <#
    .SYNOPSIS
        Read a groups-isc-changes-both*.csv feed into normalized row objects.
    .DESCRIPTION
        Tolerant reader: uses Import-Csv (RFC 4180 aware) and maps the canonical columns,
        defaulting any missing column to ''. Change is normalized to 'Added'/'Removed'
        (case-insensitive; 'add'/'remove' singular forms accepted) so feeds from slightly
        different exporters still classify. Unknown Change values are preserved verbatim
        and counted as 'Other'.
    .PARAMETER Path
        Path to the CSV feed.
    .OUTPUTS
        Array of [pscustomobject] with: Change, Domain, GroupName, SamAccountName, DisplayName, Email.
    #>
    [OutputType([array])]
    param([Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string]$Path)

    if (-not (Test-Path -LiteralPath $Path)) { throw "Change feed not found: $Path" }

    $raw = @(Import-Csv -LiteralPath $Path)
    $out = New-Object System.Collections.Generic.List[object]

    foreach ($r in $raw) {
        $names = $r.PSObject.Properties.Name
        $col = {
            param($n)
            if ($names -contains $n) { $v = $r.$n; if ($null -eq $v) { '' } else { ([string]$v).Trim() } } else { '' }
        }
        $rawChange = & $col 'Change'
        switch -regex ($rawChange) {
            '^(?i)add(ed)?$'    { $change = 'Added';   break }
            '^(?i)remove(d)?$'  { $change = 'Removed'; break }
            default             { $change = $rawChange }
        }

        $out.Add([pscustomobject]@{
            Change         = $change
            Domain         = & $col 'Domain'
            GroupName      = & $col 'GroupName'
            SamAccountName = & $col 'SamAccountName'
            DisplayName    = & $col 'DisplayName'
            Email          = & $col 'Email'
        })
    }

    return , $out.ToArray()
}

function Get-IscChangeDiff {
    <#
    .SYNOPSIS
        Shape normalized feed rows into a clean adds/removes diff (pure; no I/O).
    .DESCRIPTION
        ADDS are consolidated per user (keyed on sAMAccountName, the SailPoint correlation key):
        one record per user carrying the distinct groups they were added to. REMOVES stay as a
        flat removal table: one record per group/user removal. Summary carries the headline counts.
    .PARAMETER Rows
        Normalized rows from Import-IscChangeFeed (or any objects exposing the same properties).
    .PARAMETER PrivilegedNamePredicate
        Optional scriptblock taking a group name and returning $true for privileged groups
        (e.g. from New-RCPrivilegedPredicate). When supplied, groups/rows are flagged Privileged
        so the renderer can badge them. Omit for no privileged highlighting.
    .OUTPUTS
        Hashtable: @{ Adds = [array]; Removes = [array]; Summary = [hashtable] }.
    #>
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][array]$Rows,
        [scriptblock]$PrivilegedNamePredicate
    )

    $rows = @($Rows)

    $isPriv = {
        param($g)
        if (-not $PrivilegedNamePredicate) { return $false }
        try { return [bool](& $PrivilegedNamePredicate $g) } catch { return $false }
    }

    $addRows = @($rows | Where-Object { $_.Change -eq 'Added' })
    $remRows = @($rows | Where-Object { $_.Change -eq 'Removed' })
    $other   = $rows.Count - $addRows.Count - $remRows.Count

    # ---- ADDS: consolidate per user (case-insensitive sam key; empty sam -> per-row key) ----
    $byUser = [ordered]@{}
    $anon = 0
    foreach ($a in $addRows) {
        $sam = [string]$a.SamAccountName
        $key = if ($sam) { $sam.ToLowerInvariant() } else { $anon++; "(anon-$anon)" }
        if (-not $byUser.Contains($key)) {
            $byUser[$key] = [pscustomobject]@{
                SamAccountName = $sam
                DisplayName    = [string]$a.DisplayName
                Email          = [string]$a.Email
                Domains        = New-Object System.Collections.Generic.List[string]
                Groups         = New-Object System.Collections.Generic.List[object]
                AnyPrivileged  = $false
                _seenGroups    = New-Object 'System.Collections.Generic.HashSet[string]'
            }
        }
        $u = $byUser[$key]
        if (-not $u.DisplayName -and $a.DisplayName) { $u.DisplayName = [string]$a.DisplayName }
        if (-not $u.Email -and $a.Email)             { $u.Email = [string]$a.Email }
        if ($a.Domain -and -not $u.Domains.Contains([string]$a.Domain)) { $u.Domains.Add([string]$a.Domain) }

        $gname = [string]$a.GroupName
        $gkey = ('{0}|{1}' -f [string]$a.Domain, $gname).ToLowerInvariant()
        if ($u._seenGroups.Add($gkey)) {
            $priv = [bool](& $isPriv $gname)
            if ($priv) { $u.AnyPrivileged = $true }
            $u.Groups.Add([pscustomobject]@{ Name = $gname; Domain = [string]$a.Domain; Privileged = $priv })
        }
    }

    $adds = @(
        foreach ($u in $byUser.Values) {
            [pscustomobject]@{
                SamAccountName = $u.SamAccountName
                DisplayName    = $u.DisplayName
                Email          = $u.Email
                Domains        = @($u.Domains)
                Groups         = @($u.Groups | Sort-Object @{ Expression = { -not $_.Privileged } }, @{ Expression = { $_.Name } })
                GroupCount     = $u.Groups.Count
                AnyPrivileged  = $u.AnyPrivileged
            }
        }
    )
    $adds = @($adds | Sort-Object @{ Expression = { if ($_.DisplayName) { $_.DisplayName } else { $_.SamAccountName } } }, SamAccountName)

    # ---- REMOVES: flat removal table, one row per removal ----
    $removes = @(
        foreach ($r in $remRows) {
            [pscustomobject]@{
                GroupName      = [string]$r.GroupName
                Domain         = [string]$r.Domain
                SamAccountName = [string]$r.SamAccountName
                DisplayName    = [string]$r.DisplayName
                Email          = [string]$r.Email
                Privileged     = [bool](& $isPriv ([string]$r.GroupName))
            }
        }
    )
    $removes = @($removes | Sort-Object @{ Expression = { -not $_.Privileged } }, GroupName, @{ Expression = { if ($_.DisplayName) { $_.DisplayName } else { $_.SamAccountName } } })

    # ---- distinct counts ----
    $groupKeys = New-Object 'System.Collections.Generic.HashSet[string]'
    foreach ($x in $rows) {
        if ($x.Change -eq 'Added' -or $x.Change -eq 'Removed') {
            [void]$groupKeys.Add(('{0}|{1}' -f [string]$x.Domain, [string]$x.GroupName).ToLowerInvariant())
        }
    }
    $remUsers = New-Object 'System.Collections.Generic.HashSet[string]'
    foreach ($r in $remRows) { if ($r.SamAccountName) { [void]$remUsers.Add(([string]$r.SamAccountName).ToLowerInvariant()) } }

    $summary = @{
        AddEvents              = $addRows.Count
        RemoveEvents           = $remRows.Count
        OtherRows              = $other
        TotalRows              = $rows.Count
        UsersAdded             = $adds.Count
        UsersRemoved           = $remUsers.Count
        GroupsAffected         = $groupKeys.Count
        NetChange              = $addRows.Count - $remRows.Count
        PrivilegedAddUsers     = @($adds   | Where-Object { $_.AnyPrivileged }).Count
        PrivilegedRemoveEvents = @($removes | Where-Object { $_.Privileged }).Count
    }

    return @{ Adds = $adds; Removes = $removes; Summary = $summary }
}

function New-IscChangeDiffHtml {
    <#
    .SYNOPSIS
        Render an adds/removes diff to a self-contained, light, paste-friendly HTML report.
    .PARAMETER Diff
        The hashtable from Get-IscChangeDiff (@{ Adds; Removes; Summary }).
    .PARAMETER OutputPath
        Destination .html path (parent dirs created as needed).
    .PARAMETER Title
        Optional report title.
    .PARAMETER SourceLabel
        Optional source description (e.g. the CSV path) shown in the header/footer.
    .PARAMETER GeneratedAt
        Optional pre-formatted generated-at string (defaults to now).
    .OUTPUTS
        The output path (string).
    #>
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)][hashtable]$Diff,
        [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string]$OutputPath,
        [string]$Title = 'ISC Membership Changes',
        [string]$SourceLabel = '',
        [string]$GeneratedAt = ''
    )

    if (-not $GeneratedAt) { $GeneratedAt = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss') }
    $adds    = @($Diff.Adds)
    $removes = @($Diff.Removes)
    $s       = $Diff.Summary

    # ---- SailPoint-style palette + inline style tokens (Word/Outlook paste-safe) ----
    $font       = "-apple-system,'Segoe UI',Segoe,Roboto,Helvetica,Arial,sans-serif"
    $ink        = '#2c3e50'
    $headBg     = '#34495e'
    $green      = '#339933'
    $red        = '#CC3333'
    $privBg     = '#7a0014'
    $altBg      = '#f9f9f9'
    $line       = '#e0e0e0'
    $thStyle    = "background:$headBg;color:#fff;padding:8px 10px;text-align:left;font-family:$font;font-size:12px;font-weight:600;white-space:nowrap;"
    $tdStyle    = "padding:7px 10px;border-bottom:1px solid $line;vertical-align:top;font-family:$font;font-size:13px;color:$ink;"
    $samStyle   = "font-family:Consolas,'Courier New',monospace;font-size:12px;color:#566;"
    $badgeAdd   = "display:inline-block;padding:2px 8px;border-radius:3px;font-size:11px;font-weight:bold;color:#fff;background:$green;"
    $badgeRem   = "display:inline-block;padding:2px 8px;border-radius:3px;font-size:11px;font-weight:bold;color:#fff;background:$red;"
    $badgePriv  = "display:inline-block;padding:1px 6px;border-radius:3px;font-size:10px;font-weight:bold;color:#fff;background:$privBg;margin-left:5px;"
    $kpiStyle   = "display:inline-block;min-width:104px;margin:0 10px 10px 0;padding:10px 14px;border:1px solid #d4dce6;border-radius:6px;background:#f6f9fc;font-family:$font;vertical-align:top;"
    $tableStyle = "border-collapse:collapse;width:100%;margin:4px 0 8px;font-family:$font;"
    $emptyStyle = "color:#777;font-style:italic;font-family:$font;font-size:13px;padding:6px 0 12px;"

    $enc = { param($v) ConvertTo-IscDiffHtmlSafe $v }
    $privBadge = "<span style=`"$badgePriv`">PRIV</span>"

    $kpi = {
        param($n, $label, $color)
        $c = if ($color) { $color } else { '#1f3a5f' }
        "<div style=`"$kpiStyle`"><div style=`"font-size:22px;font-weight:700;color:$c;line-height:1.1;`">$n</div><div style=`"font-size:11px;color:#566;text-transform:uppercase;letter-spacing:.04em;margin-top:3px;`">$label</div></div>"
    }

    $sb = New-Object System.Text.StringBuilder

    [void]$sb.AppendLine('<!DOCTYPE html>')
    [void]$sb.AppendLine('<html lang="en">')
    [void]$sb.AppendLine('<head>')
    [void]$sb.AppendLine('<meta charset="utf-8" />')
    [void]$sb.AppendLine('<meta name="viewport" content="width=device-width, initial-scale=1" />')
    [void]$sb.AppendLine(('<title>{0}</title>' -f (& $enc $Title)))
    [void]$sb.AppendLine(('<style>body{{margin:0;background:#ffffff;color:{0};font-family:{1};font-size:13px;line-height:1.45;}} .wrap{{max-width:1200px;margin:0 auto;padding:24px;}} a{{color:#1f3a5f;}}</style>' -f $ink, $font))
    [void]$sb.AppendLine('</head>')
    [void]$sb.AppendLine('<body>')
    [void]$sb.AppendLine('<div class="wrap">')

    # ---- header ----
    [void]$sb.AppendLine(('<h1 style="font-family:{0};color:{1};border-bottom:2px solid {2};padding-bottom:6px;font-size:21px;margin:0 0 6px;">{3}</h1>' -f $font, $ink, $headBg, (& $enc $Title)))
    $metaBits = @("generated $GeneratedAt")
    if ($SourceLabel) { $metaBits += ('source: {0}' -f (& $enc $SourceLabel)) }
    [void]$sb.AppendLine(('<div style="font-family:{0};color:#777;font-size:12px;margin-bottom:16px;">{1}</div>' -f $font, ($metaBits -join ' &middot; ')))

    # ---- KPI cards ----
    [void]$sb.AppendLine('<div style="margin-bottom:8px;">')
    [void]$sb.AppendLine((& $kpi $s.AddEvents 'Added' $green))
    [void]$sb.AppendLine((& $kpi $s.RemoveEvents 'Removed' $red))
    [void]$sb.AppendLine((& $kpi $s.GroupsAffected 'Groups affected' $headBg))
    $netStr = if ($s.NetChange -gt 0) { '+' + $s.NetChange } else { [string]$s.NetChange }
    $netColor = if ($s.NetChange -gt 0) { $green } elseif ($s.NetChange -lt 0) { $red } else { '#888' }
    [void]$sb.AppendLine((& $kpi $netStr 'Net change' $netColor))
    if ($s.PrivilegedAddUsers -gt 0 -or $s.PrivilegedRemoveEvents -gt 0) {
        [void]$sb.AppendLine((& $kpi ($s.PrivilegedAddUsers + $s.PrivilegedRemoveEvents) 'Privileged' $privBg))
    }
    [void]$sb.AppendLine('</div>')

    # ===================== ADDED (per-user list) =====================
    [void]$sb.AppendLine(('<h2 style="font-family:{0};color:{1};border-bottom:2px solid {2};padding-bottom:6px;font-size:16px;margin-top:26px;"><span style="{3}">ADDED</span> Users ({4})</h2>' -f $font, $ink, $green, $badgeAdd, $s.UsersAdded))
    if ($adds.Count -eq 0) {
        [void]$sb.AppendLine(('<div style="{0}">No additions in this feed.</div>' -f $emptyStyle))
    } else {
        [void]$sb.AppendLine(('<table style="{0}">' -f $tableStyle))
        [void]$sb.AppendLine(('<thead><tr><th style="{0}">User</th><th style="{0}">Account</th><th style="{0}">Email</th><th style="{0}">Groups added</th></tr></thead>' -f $thStyle))
        [void]$sb.AppendLine('<tbody>')
        $i = 0
        foreach ($u in $adds) {
            $bg = if ($i % 2 -eq 1) { " background:$altBg;" } else { '' }
            $i++
            $dn = if ($u.DisplayName) { & $enc $u.DisplayName } else { '<span style="color:#999;">(no name)</span>' }
            $grpParts = @(
                foreach ($g in $u.Groups) {
                    $txt = & $enc $g.Name
                    if ($g.Privileged) { "$txt$privBadge" } else { $txt }
                }
            )
            $grpCell = if ($grpParts.Count -gt 0) { $grpParts -join ', ' } else { '<span style="color:#999;">&mdash;</span>' }
            [void]$sb.AppendLine('<tr style="' + $bg + '">' +
                ('<td style="{0}">{1}</td>' -f $tdStyle, $dn) +
                ('<td style="{0}{1}">{2}</td>' -f $tdStyle, $samStyle, (& $enc $u.SamAccountName)) +
                ('<td style="{0}">{1}</td>' -f $tdStyle, (& $enc $u.Email)) +
                ('<td style="{0}">{1}</td>' -f $tdStyle, $grpCell) +
                '</tr>')
        }
        [void]$sb.AppendLine('</tbody></table>')
    }

    # ===================== REMOVED (removal table) =====================
    [void]$sb.AppendLine(('<h2 style="font-family:{0};color:{1};border-bottom:2px solid {2};padding-bottom:6px;font-size:16px;margin-top:26px;"><span style="{3}">REMOVED</span> ({4})</h2>' -f $font, $ink, $red, $badgeRem, $removes.Count))
    if ($removes.Count -eq 0) {
        [void]$sb.AppendLine(('<div style="{0}">No removals in this feed.</div>' -f $emptyStyle))
    } else {
        [void]$sb.AppendLine(('<table style="{0}">' -f $tableStyle))
        [void]$sb.AppendLine(('<thead><tr><th style="{0}">Group</th><th style="{0}">User</th><th style="{0}">Account</th><th style="{0}">Email</th><th style="{0}">Domain</th></tr></thead>' -f $thStyle))
        [void]$sb.AppendLine('<tbody>')
        $i = 0
        foreach ($r in $removes) {
            $bg = if ($i % 2 -eq 1) { " background:$altBg;" } else { '' }
            $i++
            $grp = (& $enc $r.GroupName)
            if ($r.Privileged) { $grp = "$grp$privBadge" }
            $dn = if ($r.DisplayName) { & $enc $r.DisplayName } else { '<span style="color:#999;">(no name)</span>' }
            [void]$sb.AppendLine('<tr style="' + $bg + '">' +
                ('<td style="{0}">{1}</td>' -f $tdStyle, $grp) +
                ('<td style="{0}">{1}</td>' -f $tdStyle, $dn) +
                ('<td style="{0}{1}">{2}</td>' -f $tdStyle, $samStyle, (& $enc $r.SamAccountName)) +
                ('<td style="{0}">{1}</td>' -f $tdStyle, (& $enc $r.Email)) +
                ('<td style="{0}">{1}</td>' -f $tdStyle, (& $enc $r.Domain)) +
                '</tr>')
        }
        [void]$sb.AppendLine('</tbody></table>')
    }

    # ---- footer ----
    $foot = "Generated $GeneratedAt"
    if ($SourceLabel) { $foot += ' &middot; source: ' + (& $enc $SourceLabel) }
    $foot += (' &middot; {0} added event(s), {1} removed event(s) across {2} group(s).' -f $s.AddEvents, $s.RemoveEvents, $s.GroupsAffected)
    if ($s.OtherRows -gt 0) { $foot += (' {0} row(s) with an unrecognized Change value were ignored.' -f $s.OtherRows) }
    [void]$sb.AppendLine(('<div style="margin-top:22px;padding-top:10px;border-top:1px solid {0};font-family:{1};font-size:11px;color:#888;">{2}</div>' -f $line, $font, $foot))

    [void]$sb.AppendLine('</div>')
    [void]$sb.AppendLine('</body></html>')

    # ---- write UTF-8 without BOM ----
    $outDir = Split-Path -Parent $OutputPath
    if ($outDir -and -not (Test-Path -LiteralPath $outDir)) {
        New-Item -ItemType Directory -Path $outDir -Force | Out-Null
    }
    [System.IO.File]::WriteAllText($OutputPath, $sb.ToString(), [System.Text.UTF8Encoding]::new($false))
    return $OutputPath
}
