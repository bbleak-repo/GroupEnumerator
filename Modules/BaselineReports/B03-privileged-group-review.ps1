<#
.SYNOPSIS
    B03 - Privileged / Sensitive Group Membership Review (parameterized module).

.DESCRIPTION
    Baseline report module. Isolates Tier-0 / Tier-1 group membership for
    elevated-scrutiny review.

    Privileged groups are detected by NAME HEURISTICS (Admins, Operators,
    Schema, Enterprise, Domain, Backup, Account/Server/Print Operators,
    DnsAdmins, Protected Users, Cert/Key admins, etc.) PLUS the IsNested
    context flag (a nested administrative group is itself a privilege path).

    For every privileged group a separate high-scrutiny section is emitted,
    with ONE ROW PER MEMBER (accountTreatment = full-list). Each row carries:
        - NestingPath              (how the member arrives at the group)
        - Direct vs. Inherited     (membership flag)
        - Account Status (Enabled) (Enabled / DISABLED)
    Disabled accounts that retain privileged membership are highlighted red:
    a disabled member in a privileged group is treated as a critical finding.

    When the supplied GroupResults contain no privileged-named groups (e.g. a
    generic scale-test dataset), the report renders an explicit "no privileged
    groups detected" state rather than fabricating data.

    Self-contained: includes its own HTML-escape helper, dot-sources nothing.
    Writes UTF-8 (no BOM) HTML to $OutputPath. Returns $OutputPath.

.NOTES
    Report id  : B03-privileged-group-review
    Engine     : Windows PowerShell 5.1 compatible
    Contract   : matches GroupSummaryReportGenerator.ps1 parameter shape
#>

function ConvertTo-B03PSObject {
    # Normalize the -FromCache hashtable shape (and nested members) to
    # PSCustomObjects so the PSObject-based property checks below work for both
    # cache (hashtable) and live (object) inputs.
    param([object]$InputObject)
    if ($InputObject -is [System.Collections.IDictionary]) {
        $ht = @{}
        foreach ($k in $InputObject.Keys) { $ht[[string]$k] = ConvertTo-B03PSObject $InputObject[$k] }
        return [pscustomobject]$ht
    }
    if (($InputObject -is [System.Collections.IEnumerable]) -and ($InputObject -isnot [string])) {
        return @(foreach ($item in $InputObject) { ConvertTo-B03PSObject $item })
    }
    return $InputObject
}

function Export-PrivilegedGroupReviewReport {
    <#
    .SYNOPSIS
        Writes a privileged-group membership review HTML report from the
        supplied GroupResults array.

    .PARAMETER GroupResults
        Array of @{ Data=@{ Domain; GroupName; MemberCount; IsNested; Skipped;
        Members=@(@{SamAccountName; DisplayName; Email; Enabled}) }; Errors=@() }

    .PARAMETER OutputPath
        Destination .html path.

    .PARAMETER Title
        Optional report title override.

    .PARAMETER Theme
        'dark' (default) or 'light'. Currently dark palette is fully implemented;
        light uses the same palette (matching source report behavior).

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

        [Parameter()][string]$Title = 'Privileged / Sensitive Group Membership Review',

        [Parameter()]
        [ValidateSet('auto', 'dark', 'light')]
        [string]$Theme = 'auto'
    )

    # ------------------------------------------------------------------------
    # HTML-escape helper (self-contained, no dot-source)
    # ------------------------------------------------------------------------
    function ConvertTo-B03HtmlText {
        param([object]$Value)
        if ($null -eq $Value) { return '' }
        $s = [string]$Value
        $s = $s -replace '&', '&amp;'
        $s = $s -replace '<', '&lt;'
        $s = $s -replace '>', '&gt;'
        $s = $s -replace '"', '&quot;'
        $s = $s -replace "'", '&#39;'
        return $s
    }

    # ------------------------------------------------------------------------
    # Privileged-name heuristic (Tier-0 / Tier-1)
    # ------------------------------------------------------------------------
    function Test-B03PrivilegedName {
        param([string]$GroupName)
        if ([string]::IsNullOrWhiteSpace($GroupName)) { return $false }

        $patterns = @(
            '\bdomain\s*admins?\b',
            '\benterprise\s*admins?\b',
            '\bschema\s*admins?\b',
            '\badministrators?\b',
            '\badmins?\b',
            '\b\w*operators?\b',
            '\bbackup\s*operators?\b',
            '\baccount\s*operators?\b',
            '\bserver\s*operators?\b',
            '\bprint\s*operators?\b',
            '\bcryptographic\s*operators?\b',
            '\breplicator\b',
            '\bdns\s*admins?\b',
            '\bdnsadmins?\b',
            '\bprotected\s*users?\b',
            '\bkey\s*admins?\b',
            '\bcert(ificate)?\s*(publishers?|admins?)\b',
            '\bgroup\s*policy\s*creator',
            '\bdomain\s*controllers?\b',
            '\benterprise\s*(read[-\s]?only\s*)?domain\s*controllers?\b',
            '\bremote\s*desktop\s*users?\b',
            '\bpki\b',
            '\bhelpdesk\b',
            '\bservice\s*desk\b',
            '\bsccm\s*admins?\b',
            '\btier\s*[01]\b',
            '\bprivileged?\b',
            '\belevated?\b',
            '\bsuper\s*users?\b',
            '\bsudo(ers)?\b',
            '\broot\b',
            '\bglobal\s*admins?\b',
            '\bsecurity\s*admins?\b',
            '\bexchange\s*admins?\b',
            '\bvcenter\s*admins?\b',
            '\bvsphere\s*admins?\b',
            '\bda_\w+', '\bea_\w+', '\bsa_\w+',
            '_admins?\b', '_adm\b', 'adm_\w+'
        )

        foreach ($p in $patterns) {
            if ($GroupName -imatch $p) { return $true }
        }
        return $false
    }

    function Get-B03PrivReason {
        param([string]$GroupName, [bool]$IsNested)
        $reasons = @()
        if (Test-B03PrivilegedName -GroupName $GroupName) { $reasons += 'name heuristic' }
        if ($IsNested) { $reasons += 'nested-group context' }
        if ($reasons.Count -eq 0) { return '' }
        return ($reasons -join ' + ')
    }

    # ------------------------------------------------------------------------
    # Process GroupResults parameter data
    # ------------------------------------------------------------------------
    $cacheGroups = @()
    if ($GroupResults -and $GroupResults.Count -gt 0) {
        $cacheGroups = @($GroupResults)
    }

    $totalCacheGroups   = $cacheGroups.Count
    $totalPrivGroups    = 0
    $totalPrivMembers   = 0
    $totalDisabledFlags = 0
    $totalInherited     = 0

    $privSections = New-Object System.Collections.Generic.List[object]

    foreach ($g in $cacheGroups) {
        if ($null -eq $g -or $null -eq $g.Data) { continue }
        $d = ConvertTo-B03PSObject $g.Data

        $groupName = if ($d.PSObject.Properties.Name -contains 'GroupName') { [string]$d.GroupName } else { '' }
        $domain    = if ($d.PSObject.Properties.Name -contains 'Domain')    { [string]$d.Domain }    else { '' }
        $isNested  = $false
        if ($d.PSObject.Properties.Name -contains 'IsNested' -and $null -ne $d.IsNested) {
            $isNested = [bool]$d.IsNested
        }
        $skipped = $false
        if ($d.PSObject.Properties.Name -contains 'Skipped' -and $null -ne $d.Skipped) {
            $skipped = [bool]$d.Skipped
        }
        $groupDN = if ($d.PSObject.Properties.Name -contains 'DistinguishedName') { [string]$d.DistinguishedName } else { '' }
        $nestedDNs = @()
        if ($d.PSObject.Properties.Name -contains 'NestedGroupDNs' -and $d.NestedGroupDNs) {
            $nestedDNs = @($d.NestedGroupDNs)
        }

        $isPriv = (Test-B03PrivilegedName -GroupName $groupName) -or $isNested
        if (-not $isPriv) { continue }

        $totalPrivGroups++
        $reason = Get-B03PrivReason -GroupName $groupName -IsNested $isNested

        $members = @()
        if ($d.PSObject.Properties.Name -contains 'Members' -and $d.Members) {
            $members = @($d.Members)
        }

        $rows = New-Object System.Collections.Generic.List[object]
        foreach ($mem in $members) {
            if ($null -eq $mem) { continue }
            $sam   = if ($mem.PSObject.Properties.Name -contains 'SamAccountName') { [string]$mem.SamAccountName } else { '' }
            $disp  = if ($mem.PSObject.Properties.Name -contains 'DisplayName')    { [string]$mem.DisplayName }    else { '' }
            $email = if ($mem.PSObject.Properties.Name -contains 'Email')          { [string]$mem.Email }          else { '' }
            $enabled = $true
            if ($mem.PSObject.Properties.Name -contains 'Enabled' -and $null -ne $mem.Enabled) {
                $enabled = [bool]$mem.Enabled
            }

            # Direct vs. Inherited: members enumerated under a non-nested group
            # are Direct; when the group has nested context, members are Inherited.
            $isInherited = $false
            if ($isNested) { $isInherited = $true }

            $nestingPath = $groupName
            if ($isInherited) {
                if ($nestedDNs.Count -gt 0) {
                    $nestedCn = ($nestedDNs[0] -replace '^CN=', '') -replace ',.*$', ''
                    $nestingPath = "$groupName -> $nestedCn -> $sam"
                } else {
                    $nestingPath = "$groupName -> (nested) -> $sam"
                }
            } else {
                $nestingPath = "$groupName -> $sam"
            }

            if (-not $enabled) { $totalDisabledFlags++ }
            if ($isInherited)  { $totalInherited++ }
            $totalPrivMembers++

            $rows.Add([pscustomobject]@{
                Sam         = $sam
                DisplayName = $disp
                Email       = $email
                Enabled     = $enabled
                Inherited   = $isInherited
                NestingPath = $nestingPath
            })
        }

        # Sort: disabled first (highest scrutiny), then inherited, then by name.
        $sortedRows = $rows | Sort-Object @{Expression = { -not $_.Enabled }; Descending = $true },
                                          @{Expression = { $_.Inherited };   Descending = $true },
                                          @{Expression = { $_.DisplayName }}

        $disabledInGroup = @($rows | Where-Object { -not $_.Enabled }).Count

        $privSections.Add([pscustomobject]@{
            GroupName     = $groupName
            Domain        = $domain
            IsNested      = $isNested
            Skipped       = $skipped
            Reason        = $reason
            GroupDN       = $groupDN
            Rows          = $sortedRows
            MemberCount   = $rows.Count
            DisabledCount = $disabledInGroup
        })
    }

    # Sort sections: groups with disabled members first (critical), then by name.
    $privSectionsSorted = @($privSections |
        Sort-Object @{Expression = { $_.DisabledCount }; Descending = $true },
                    @{Expression = { $_.GroupName }})

    # ------------------------------------------------------------------------
    # Build HTML
    # ------------------------------------------------------------------------
    $ReportId    = 'B03-privileged-group-review'
    $ReportTitle = if ($Title) { $Title } else { 'Privileged / Sensitive Group Membership Review' }
    $generatedAt = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss zzz')

    # Shared accessible theme: inherit the audited canonical palette into B03's local names (was
    # dark-only) + author the light side; the purple "inherited via nesting" tokens are given AA
    # values in both themes. Runtime toggle + print-forces-light via the generator.
    $pal = Get-GEReportThemePalette
    $b03Light = [ordered]@{ bg = $pal.Light['bg']; panel = $pal.Light['surface']; panel2 = $pal.Light['surface-alt']; ink = $pal.Light['ink']; muted = $pal.Light['muted']; line = $pal.Light['line']; accent = $pal.Light['accent']; crit = $pal.Light['crit']; critbg = $pal.Light['row-crit-bg']; warn = $pal.Light['warn']; ok = $pal.Light['ok']; inherit = '#6b3fa0'; inheritbg = '#f0e9fb' }
    $b03Dark  = [ordered]@{ bg = $pal.Dark['bg'];  panel = $pal.Dark['surface'];  panel2 = $pal.Dark['surface-alt'];  ink = $pal.Dark['ink'];  muted = $pal.Dark['muted'];  line = $pal.Dark['line'];  accent = $pal.Dark['accent'];  crit = $pal.Dark['crit'];  critbg = $pal.Dark['row-crit-bg'];  warn = $pal.Dark['warn'];  ok = $pal.Dark['ok'];  inherit = '#c8a8f0'; inheritbg = '#241a38' }
    $themeBlock = Get-GEThemedRootCss -Light $b03Light -Dark $b03Dark -ExtraRootCss (Get-GEReportThemeBadgeCss)
    $themeAttr  = if ($Theme -eq 'dark' -or $Theme -eq 'light') { " data-theme=`"$Theme`"" } else { '' }

    $css = @"
:root { color-scheme: light dark; }
$themeBlock
*{box-sizing:border-box;}
body{margin:0;background:var(--bg);color:var(--ink);
  font-family:'Segoe UI',Tahoma,Arial,sans-serif;font-size:14px;line-height:1.5;}
.wrap{max-width:1180px;margin:0 auto;padding:28px 22px 60px;}
header.report{border-bottom:2px solid var(--line);padding-bottom:18px;margin-bottom:24px;}
h1{font-size:24px;margin:0 0 4px;}
.sub{color:var(--muted);font-size:13px;}
.badges{margin-top:14px;display:flex;flex-wrap:wrap;gap:10px;}
.badge{background:var(--panel);border:1px solid var(--line);border-radius:6px;
  padding:8px 12px;font-size:12px;}
.badge b{display:block;font-size:18px;color:var(--ink);}
.badge.crit b{color:var(--crit);}
.badge.muted b{color:var(--muted);}
.objective{background:var(--panel);border:1px solid var(--line);border-left:3px solid var(--accent);
  border-radius:6px;padding:14px 16px;margin-bottom:26px;color:var(--muted);font-size:13px;}
.objective b{color:var(--ink);}
section.grp{background:var(--panel);border:1px solid var(--line);border-radius:8px;
  margin-bottom:22px;overflow:hidden;}
section.grp.has-crit{border-color:var(--crit);}
.grp-head{padding:14px 18px;background:var(--panel2);border-bottom:1px solid var(--line);
  display:flex;flex-wrap:wrap;align-items:baseline;gap:12px;}
.grp-head h2{font-size:17px;margin:0;}
.grp-head .dom{color:var(--muted);font-size:12px;}
.tag{font-size:11px;padding:2px 8px;border-radius:10px;border:1px solid var(--line);}
.tag.priv{color:var(--warn);border-color:var(--warn);}
.tag.nested{color:var(--inherit);border-color:var(--inherit);}
.tag.crit{color:var(--crit);border-color:var(--crit);background:var(--critbg);}
.tag.skip{color:var(--muted);}
.grp-meta{padding:6px 18px;color:var(--muted);font-size:12px;border-bottom:1px solid var(--line);
  word-break:break-all;}
table{width:100%;border-collapse:collapse;}
th{text-align:left;font-size:11px;text-transform:uppercase;letter-spacing:.04em;
  color:var(--muted);padding:9px 14px;border-bottom:1px solid var(--line);font-weight:600;}
td{padding:9px 14px;border-bottom:1px solid var(--line);vertical-align:top;font-size:13px;}
tr:last-child td{border-bottom:none;}
tr.disabled td{background:var(--critbg);}
tr.disabled td:first-child{box-shadow:inset 3px 0 0 var(--crit);}
.status{font-weight:600;}
.status.en{color:var(--ok);}
.status.dis{color:var(--crit);}
.flag{font-size:11px;padding:2px 7px;border-radius:4px;border:1px solid var(--line);}
.flag.direct{color:var(--ok);border-color:var(--ok);}
.flag.inherit{color:var(--inherit);border-color:var(--inherit);background:var(--inheritbg);}
.path{font-family:Consolas,'Courier New',monospace;font-size:12px;color:var(--muted);word-break:break-all;}
.churn{font-size:11px;color:var(--warn);}
.empty{background:var(--panel);border:1px dashed var(--line);border-radius:8px;
  padding:34px;text-align:center;color:var(--muted);}
.empty b{display:block;color:var(--ink);font-size:16px;margin-bottom:6px;}
footer{margin-top:34px;color:var(--muted);font-size:11px;border-top:1px solid var(--line);padding-top:14px;}
.legend{display:flex;flex-wrap:wrap;gap:16px;margin-top:8px;font-size:11px;color:var(--muted);}
.legend span{display:inline-flex;align-items:center;gap:6px;}
.sw{width:12px;height:12px;border-radius:3px;display:inline-block;}
"@

    $sb = New-Object System.Text.StringBuilder
    [void]$sb.AppendLine('<!DOCTYPE html>')
    [void]$sb.AppendLine(('<html lang="en"{0}><head><meta charset="utf-8">' -f $themeAttr))
    [void]$sb.AppendLine('<meta name="viewport" content="width=device-width, initial-scale=1">')
    [void]$sb.AppendLine("<title>$(ConvertTo-B03HtmlText $ReportTitle)</title>")
    [void]$sb.AppendLine("<style>$css</style>")
    [void]$sb.AppendLine('</head><body>')
    [void]$sb.AppendLine((Get-GEReportThemeToggleHtml))
    [void]$sb.AppendLine('<div class="wrap">')

    # Header
    [void]$sb.AppendLine('<header class="report">')
    [void]$sb.AppendLine("<h1>$(ConvertTo-B03HtmlText $ReportTitle)</h1>")
    [void]$sb.AppendLine("<div class=""sub"">Report <b>$(ConvertTo-B03HtmlText $ReportId)</b> &middot; Tier-0 / Tier-1 elevated-scrutiny review &middot; generated $(ConvertTo-B03HtmlText $generatedAt)</div>")

    # Badges
    [void]$sb.AppendLine('<div class="badges">')
    [void]$sb.AppendLine("<div class=""badge""><b>$totalCacheGroups</b>groups scanned</div>")
    [void]$sb.AppendLine("<div class=""badge""><b>$totalPrivGroups</b>privileged groups</div>")
    [void]$sb.AppendLine("<div class=""badge""><b>$totalPrivMembers</b>privileged members</div>")
    [void]$sb.AppendLine("<div class=""badge""><b>$totalInherited</b>inherited (nested)</div>")
    $dbCls = if ($totalDisabledFlags -gt 0) { 'badge crit' } else { 'badge muted' }
    [void]$sb.AppendLine("<div class=""$dbCls""><b>$totalDisabledFlags</b>disabled w/ privilege</div>")
    [void]$sb.AppendLine('</div>')
    [void]$sb.AppendLine('</header>')

    # Objective
    [void]$sb.AppendLine('<div class="objective"><b>Objective.</b> Isolate Tier-0 / Tier-1 group membership for elevated review, flagging indirect (nested) membership and disabled accounts that retain privilege &mdash; the highest-scrutiny tier auditors require quarterly. Privileged groups are detected by name heuristics (Admins, Operators, Schema, Enterprise, Domain, custom elevated) plus nested-group context. <b style="color:var(--crit)">A disabled account inside a privileged group is a critical finding.</b></div>')

    if ($privSectionsSorted.Count -eq 0) {
        [void]$sb.AppendLine('<div class="empty"><b>No privileged groups detected.</b>')
        [void]$sb.AppendLine("Scanned $totalCacheGroups group(s); none matched the privileged/sensitive name heuristics or nested-group context. ")
        [void]$sb.AppendLine('This is an expected, clean result for non-administrative datasets &mdash; nothing requires elevated-scrutiny review.</div>')
    } else {
        foreach ($sec in $privSectionsSorted) {
            $hasCrit = $sec.DisabledCount -gt 0
            $secCls  = if ($hasCrit) { 'grp has-crit' } else { 'grp' }
            [void]$sb.AppendLine("<section class=""$secCls"">")

            # Section head
            [void]$sb.AppendLine('<div class="grp-head">')
            [void]$sb.AppendLine("<h2>$(ConvertTo-B03HtmlText $sec.GroupName)</h2>")
            if ($sec.Domain) { [void]$sb.AppendLine("<span class=""dom"">$(ConvertTo-B03HtmlText $sec.Domain)</span>") }
            [void]$sb.AppendLine('<span class="tag priv">PRIVILEGED</span>')
            if ($sec.IsNested) { [void]$sb.AppendLine('<span class="tag nested">NESTED</span>') }
            if ($sec.Skipped)  { [void]$sb.AppendLine('<span class="tag skip">SKIPPED IN ENUM</span>') }
            if ($hasCrit) { [void]$sb.AppendLine("<span class=""tag crit"">$($sec.DisabledCount) DISABLED</span>") }
            [void]$sb.AppendLine('</div>')

            # Section meta
            $metaBits = @()
            if ($sec.Reason)  { $metaBits += "Detected via: $(ConvertTo-B03HtmlText $sec.Reason)" }
            $metaBits += "$($sec.MemberCount) member(s)"
            if ($sec.GroupDN) { $metaBits += "DN: $(ConvertTo-B03HtmlText $sec.GroupDN)" }
            [void]$sb.AppendLine("<div class=""grp-meta"">$($metaBits -join ' &middot; ')</div>")

            if ($sec.MemberCount -eq 0) {
                [void]$sb.AppendLine('<div class="grp-meta">No members enumerated for this privileged group.</div>')
            } else {
                [void]$sb.AppendLine('<table><thead><tr>')
                [void]$sb.AppendLine('<th>Member (Display Name)</th><th>SamAccountName</th><th>Email</th><th>Membership</th><th>Account Status</th><th>Nesting Path</th>')
                [void]$sb.AppendLine('</tr></thead><tbody>')

                foreach ($r in $sec.Rows) {
                    $rowCls = if (-not $r.Enabled) { ' class="disabled"' } else { '' }
                    [void]$sb.AppendLine("<tr$rowCls>")
                    [void]$sb.AppendLine("<td>$(ConvertTo-B03HtmlText $r.DisplayName)</td>")
                    [void]$sb.AppendLine("<td>$(ConvertTo-B03HtmlText $r.Sam)</td>")
                    [void]$sb.AppendLine("<td>$(ConvertTo-B03HtmlText $r.Email)</td>")
                    if ($r.Inherited) {
                        [void]$sb.AppendLine('<td><span class="flag inherit">Inherited</span></td>')
                    } else {
                        [void]$sb.AppendLine('<td><span class="flag direct">Direct</span></td>')
                    }
                    if ($r.Enabled) {
                        [void]$sb.AppendLine('<td><span class="status en">Enabled</span></td>')
                    } else {
                        [void]$sb.AppendLine('<td><span class="status dis">DISABLED &#9888;</span></td>')
                    }
                    [void]$sb.AppendLine("<td><span class=""path"">$(ConvertTo-B03HtmlText $r.NestingPath)</span></td>")
                    [void]$sb.AppendLine('</tr>')
                }
                [void]$sb.AppendLine('</tbody></table>')
            }
            [void]$sb.AppendLine('</section>')
        }
    }

    # Legend + footer
    [void]$sb.AppendLine('<div class="legend">')
    [void]$sb.AppendLine('<span><span class="sw" style="background:var(--critbg);box-shadow:inset 3px 0 0 var(--crit)"></span> Disabled account retaining privilege (critical)</span>')
    [void]$sb.AppendLine('<span><span class="sw" style="background:var(--inheritbg);border:1px solid var(--inherit)"></span> Inherited via nested group</span>')
    [void]$sb.AppendLine('<span><span class="sw" style="border:1px solid var(--ok)"></span> Direct membership</span>')
    [void]$sb.AppendLine('</div>')

    [void]$sb.AppendLine('<footer>')
    [void]$sb.AppendLine("Baseline report $(ConvertTo-B03HtmlText $ReportId) &middot; accountTreatment=full-list (one row per member, no truncation) &middot; offline / read-only &middot; names and emails HTML-escaped.")
    [void]$sb.AppendLine('</footer>')

    [void]$sb.AppendLine((Get-GEReportThemeScript))
    [void]$sb.AppendLine('</div></body></html>')

    # ------------------------------------------------------------------------
    # Write output (UTF-8, no BOM)
    # ------------------------------------------------------------------------
    $outDir = Split-Path -Parent $OutputPath
    if ($outDir -and -not (Test-Path -LiteralPath $outDir)) {
        New-Item -ItemType Directory -Path $outDir -Force | Out-Null
    }
    [System.IO.File]::WriteAllText($OutputPath, $sb.ToString(), (New-Object System.Text.UTF8Encoding($false)))

    return $OutputPath
}
