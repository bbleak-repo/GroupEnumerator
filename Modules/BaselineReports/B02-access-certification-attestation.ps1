<#
.SYNOPSIS
    B02 - Access Certification / UAR Sign-off Sheet
    -----------------------------------------------
    Parameterized BASELINE report generator module.

    Subject ........... per-group membership rendered as a reviewer
                        attestation worksheet.
    accountTreatment .. full-list  (EVERY member is rendered as one
                        certifiable row -- no sampling, no collapsing)
    Presentation ...... attestation cover sheet (scope, review period,
                        control owner, attestation statement, signature
                        line) followed by a group-sectioned roster with
                        empty annotation columns:
                          - Reviewer Decision (Approve / Revoke / Escalate)
                          - Justification
                          - Review Date
                          - Reviewer Name
                        Account Status surfaced per row. Rows within each
                        group sorted disabled-first, then by display name.
                        Color cues for disabled members are also encoded
                        with a glyph + bold weight so they remain legible
                        when printed in greyscale.

    Objective: the formal sign-off artifact auditors sample from. One
    certifiable row per entitlement with a three-value decision column and
    a mandatory justification field, plus an attestation cover page.
    "If it is not documented, auditors treat it as never happened."

    This module dot-sources NOTHING and does not modify any existing repo file.
#>

function ConvertTo-B02PSObject {
    # Normalize the -FromCache hashtable shape (and nested members) to
    # PSCustomObjects so the PSObject-based property checks below work for both
    # cache (hashtable) and live (object) inputs.
    param([object]$InputObject)
    if ($InputObject -is [System.Collections.IDictionary]) {
        $ht = @{}
        foreach ($k in $InputObject.Keys) { $ht[[string]$k] = ConvertTo-B02PSObject $InputObject[$k] }
        return [pscustomobject]$ht
    }
    if (($InputObject -is [System.Collections.IEnumerable]) -and ($InputObject -isnot [string])) {
        return @(foreach ($item in $InputObject) { ConvertTo-B02PSObject $item })
    }
    return $InputObject
}

function Export-AccessCertificationAttestationReport {
    <#
    .SYNOPSIS
        Writes an Access Certification / UAR Sign-off Sheet HTML report.

    .DESCRIPTION
        Renders a full-list attestation worksheet: one certifiable row per
        entitlement, with Reviewer Decision, Justification, Review Date, and
        Reviewer Name columns for manual completion. Includes an attestation
        cover sheet with scope metadata and signature lines.

    .PARAMETER GroupResults
        Array of @{ Data = @{ Domain; GroupName; MemberCount; IsNested; Skipped;
        Members = @(@{ SamAccountName; DisplayName; Email; Enabled }) }; Errors = @() }.

    .PARAMETER OutputPath
        Destination .html path. Parent directory is created if absent.

    .PARAMETER Title
        Optional report title override.

    .PARAMETER Theme
        'dark' (default) or 'light'. Note: this report uses a print-optimised
        light stylesheet regardless of theme; the parameter is accepted for
        contract compatibility.

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

        [Parameter()][string]$Title,

        [Parameter()][ValidateSet('auto', 'dark', 'light')][string]$Theme = 'auto'
    )

    # --- Helpers --------------------------------------------------------------
    function ConvertTo-B02HtmlSafe {
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

    function ConvertTo-B02Bool {
        # Tolerant coercion: $true/'true'/'True'/'1' -> true; everything else false.
        param([object]$Value)
        if ($null -eq $Value) { return $false }
        if ($Value -is [bool]) { return $Value }
        $s = ([string]$Value).Trim()
        if ($s -eq '') { return $false }
        return ($s -ieq 'true' -or $s -eq '1')
    }

    function Get-B02Prop {
        param([object]$Obj, [string]$Name, [object]$Default = $null)
        if ($null -eq $Obj) { return $Default }
        if ($Obj.PSObject.Properties.Name -contains $Name) {
            $v = $Obj.$Name
            if ($null -eq $v) { return $Default }
            return $v
        }
        return $Default
    }

    # --- Build per-group certifiable rosters ----------------------------------
    # accountTreatment = full-list : EVERY member becomes exactly one row.
    $sections = New-Object System.Collections.Generic.List[object]

    $grandRows     = 0
    $grandEnabled  = 0
    $grandDisabled = 0

    foreach ($entry in $GroupResults) {
        if ($null -eq $entry) { continue }
        $entry = ConvertTo-B02PSObject $entry
        $d = $entry
        if ($entry.PSObject.Properties.Name -contains 'Data' -and $null -ne $entry.Data) { $d = $entry.Data }
        if ($null -eq $d) { continue }

        $domain    = [string](Get-B02Prop $d 'Domain'    '')
        $groupName = [string](Get-B02Prop $d 'GroupName' '')
        $isNested  = ConvertTo-B02Bool (Get-B02Prop $d 'IsNested' $false)
        $skipped   = ConvertTo-B02Bool (Get-B02Prop $d 'Skipped'  $false)

        $declaredCount = 0
        $dc = Get-B02Prop $d 'MemberCount' $null
        if ($null -ne $dc) { [int]::TryParse([string]$dc, [ref]$declaredCount) | Out-Null }

        # Materialize every member row (full-list treatment).
        $memberRows = New-Object System.Collections.Generic.List[object]
        $members = Get-B02Prop $d 'Members' $null
        if ($null -ne $members) {
            foreach ($m in $members) {
                if ($null -eq $m) { continue }
                $enabled = ConvertTo-B02Bool (Get-B02Prop $m 'Enabled' $false)
                $memberRows.Add([pscustomobject]@{
                    SamAccountName = [string](Get-B02Prop $m 'SamAccountName' '')
                    DisplayName    = [string](Get-B02Prop $m 'DisplayName'    '')
                    Email          = [string](Get-B02Prop $m 'Email'          '')
                    Enabled        = $enabled
                })
            }
        }

        # Sort within group: disabled-first, then by display name (case-insensitive),
        # falling back to SamAccountName when display name is blank.
        $sortedMembers = @($memberRows | Sort-Object `
            @{ Expression = { if ($_.Enabled) { 1 } else { 0 } }; Descending = $false }, `
            @{ Expression = { $n = $_.DisplayName; if ([string]::IsNullOrWhiteSpace($n)) { $_.SamAccountName } else { $n } }; Descending = $false })

        $secEnabled  = @($sortedMembers | Where-Object { $_.Enabled }).Count
        $secDisabled = $sortedMembers.Count - $secEnabled

        $grandRows     += $sortedMembers.Count
        $grandEnabled  += $secEnabled
        $grandDisabled += $secDisabled

        $sections.Add([pscustomobject]@{
            Domain        = $domain
            GroupName     = $groupName
            IsNested      = $isNested
            Skipped       = $skipped
            DeclaredCount = $declaredCount
            Members       = $sortedMembers
            Enabled       = $secEnabled
            Disabled      = $secDisabled
        })
    }

    # Sort sections by domain then group name for a stable, reviewer-friendly order.
    $orderedSections = @($sections | Sort-Object `
        @{ Expression = 'Domain'; Descending = $false }, `
        @{ Expression = 'GroupName'; Descending = $false })

    # --- Metadata for cover sheet -------------------------------------------
    $generatedAt  = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss zzz')
    $totalGroups  = $orderedSections.Count
    $distinctDoms = @($orderedSections | ForEach-Object { $_.Domain } | Where-Object { $_ -ne '' } | Sort-Object -Unique)
    $scopeDomains = if ($distinctDoms.Count -gt 0) { ($distinctDoms -join ', ') } else { 'Not specified' }
    $reviewPeriod = 'Not available'

    # --- Render HTML ---------------------------------------------------------
    # Shared accessible theme: this fillable sign-off sheet is print-first, but it now themes on
    # screen too (auto=follow OS, toggle) with @media print forcing light. Colours inherit the
    # canonical palette; the fillable controls + localStorage + print JS are unchanged.
    $themeCss   = Get-GEReportThemeCss
    $themeAttr  = if ($Theme -eq 'dark' -or $Theme -eq 'light') { " data-theme=`"$Theme`"" } else { '' }
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.AppendLine('<!DOCTYPE html>')
    [void]$sb.AppendLine(('<html lang="en"{0}><head><meta charset="utf-8">' -f $themeAttr))
    [void]$sb.AppendLine('<meta name="viewport" content="width=device-width, initial-scale=1">')
    [void]$sb.AppendLine('<title>Access Certification / UAR Sign-off Sheet</title>')
    [void]$sb.AppendLine('<style>')
    [void]$sb.AppendLine(':root { color-scheme: light dark; }')
    [void]$sb.AppendLine($themeCss)
    [void]$sb.AppendLine(@'
* { box-sizing: border-box; }
body {
    font-family: "Segoe UI", system-ui, -apple-system, Arial, sans-serif;
    margin: 0; padding: 28px; background:var(--bg); color:var(--ink);
    -webkit-print-color-adjust: exact; print-color-adjust: exact;
}
.page {
    max-width: 1180px; margin: 0 auto 26px; background:var(--surface);
    border:1px solid var(--line); border-radius:8px;
    box-shadow:0 1px 4px rgba(0,0,0,.08); padding: 30px 34px;
}

/* ---- Cover sheet ---- */
.cover h1 { font-size: 1.7rem; margin:0 0 2px; letter-spacing:.01em; }
.cover .docid { color:var(--muted); font-size:.82rem; margin:0 0 20px; }
.cover .grid { display:grid; grid-template-columns: 200px 1fr; gap:0; border:1px solid var(--line); border-radius:6px; overflow:hidden; margin-bottom:22px; }
.cover .grid .k { background:var(--surface-alt); border-bottom:1px solid var(--line); border-right:1px solid var(--line); padding:9px 13px; font-size:.8rem; font-weight:700; color:var(--ink); }
.cover .grid .v { border-bottom:1px solid var(--line); padding:9px 13px; font-size:.85rem; color:var(--ink); }
.cover .grid .k:last-of-type, .cover .grid .v:last-of-type { border-bottom:none; }
.attest { border-left:4px solid var(--accent); background:var(--surface-alt); padding:14px 18px; border-radius:0 6px 6px 0; margin-bottom:24px; }
.attest h2 { font-size:.95rem; margin:0 0 8px; color:var(--accent); text-transform:uppercase; letter-spacing:.05em; }
.attest p { margin:0; font-size:.88rem; line-height:1.5; color:var(--ink); }
.siglines { display:grid; grid-template-columns: 1fr 1fr; gap:34px; margin-top:30px; }
.sig { border-top:1.5px solid var(--ink); padding-top:6px; font-size:.78rem; color:var(--muted); }
.legend { margin-top:26px; font-size:.78rem; color:var(--muted); }
.legend .swatch { display:inline-block; width:13px; height:13px; border-radius:3px; vertical-align:-2px; margin:0 5px 0 0; border:1px solid var(--warn); background:var(--row-warn-bg); }

/* ---- Group sections ---- */
.section-head { display:flex; flex-wrap:wrap; align-items:baseline; gap:12px; margin: 6px 0 12px; padding-bottom:8px; border-bottom:2px solid var(--accent); }
.section-head h2 { font-size:1.18rem; margin:0; color:var(--accent); }
.section-head .dom { font-size:.82rem; color:var(--muted); }
.section-head .tags { margin-left:auto; display:flex; gap:8px; }
.tag { font-size:.72rem; padding:3px 9px; border-radius:11px; border:1px solid var(--line); background:var(--surface-alt); color:var(--ink); }
.tag.warn { background:var(--row-warn-bg); border-color:var(--warn); color:var(--warn); font-weight:600; }
.tag.dis  { background:var(--row-warn-bg); border-color:var(--warn); color:var(--warn); font-weight:600; }

table { border-collapse: collapse; width:100%; }
thead th {
    background:var(--header-bg); color:#fff; text-align:left; padding:8px 10px;
    font-size:.72rem; letter-spacing:.03em; text-transform:uppercase; vertical-align:bottom;
}
thead th.deccol { background:var(--header-bg); filter:brightness(.85); }
tbody td { padding:7px 10px; border-bottom:1px solid var(--line); font-size:.82rem; vertical-align:top; color:var(--ink); }
tbody tr:nth-child(even) { background:var(--surface-alt); }
td.num { text-align:right; font-variant-numeric: tabular-nums; }
.status-en  { color:var(--ok); font-weight:600; }
.status-dis { color:var(--crit); font-weight:700; }

/* Disabled-member row: color cue PLUS glyph + bold so it survives greyscale. */
tr.row-disabled td { background:var(--row-warn-bg) !important; }
tr.row-disabled td:first-child { border-left:4px solid var(--warn); }
.dis-mark { font-weight:700; }

/* Empty annotation cells the reviewer fills in. */
.fill { background:var(--surface-alt); }
td.fill { min-width:120px; }
.decision-hint { color:var(--muted); font-size:.72rem; font-style:italic; }
.just-box { min-height:34px; border:1px dashed var(--line); border-radius:4px; }
.date-box, .name-box { min-height:24px; border-bottom:1px solid var(--line); }

.foot-note { color:var(--muted); font-size:.72rem; margin-top:18px; line-height:1.5; }

/* ---- Interactive toolbar (screen only) ---- */
.toolbar { position: sticky; top:0; z-index:50; background:var(--header-bg); color:#fff; padding:10px 18px; display:flex; gap:14px; align-items:center; flex-wrap:wrap; box-shadow:0 1px 5px rgba(0,0,0,.25); }
.toolbar button { font-size:.85rem; padding:7px 14px; border-radius:5px; border:none; cursor:pointer; background:#5b9bd5; color:#fff; font-weight:600; }
.toolbar button.secondary { background:#41506a; }
.toolbar button:hover { filter:brightness(1.08); }
.tb-progress { font-size:.82rem; color:#dce6f2; }
.tb-saved { font-size:.8rem; color:#bdf5c8; opacity:0; transition:opacity .3s; margin-left:auto; }
.tb-nostore { font-size:.78rem; color:#ffd9a8; display:none; }
.save-note { color:var(--muted); font-size:.76rem; margin:-12px 0 18px; }

/* ---- Fillable controls (replace the hand-fill cells) ---- */
.cover-input { width:340px; max-width:100%; font:inherit; font-size:.85rem; padding:5px 8px; border:1px solid var(--line); border-radius:4px; background:var(--surface); color:var(--ink); }
.deccell { white-space:nowrap; }
.deccell label.dec { display:inline-flex; align-items:center; gap:3px; font-size:.74rem; margin-right:9px; cursor:pointer; }
.dec-app { color:var(--ok); } .dec-rev { color:var(--crit); } .dec-esc { color:var(--warn); }
textarea.just { width:100%; min-width:150px; min-height:36px; font:inherit; font-size:.78rem; padding:4px 6px; border:1px solid var(--line); border-radius:4px; resize:vertical; background:var(--surface); color:var(--ink); }
input.dt, input.nm { font:inherit; font-size:.78rem; padding:4px 6px; border:1px solid var(--line); border-radius:4px; background:var(--surface); color:var(--ink); }
input.nm { width:120px; }

@media print {
    body { background:#fff; padding:0; }
    .page { box-shadow:none; border:none; border-radius:0; margin:0 0 12px; max-width:none; page-break-after: always; }
    .section { page-break-inside: auto; }
    tr { page-break-inside: avoid; }
    thead { display: table-header-group; }
    /* hide on-screen chrome; render filled controls as clean ink */
    .no-print, .toolbar, .save-note { display:none !important; }
    textarea.just { border:1px solid #888; resize:none; overflow:visible; }
    input.dt, input.nm, .cover-input { border:none; border-bottom:1px solid #555; border-radius:0; padding-left:0; }
    .deccell label.dec { margin-right:6px; }
}
'@)
    [void]$sb.AppendLine('</style></head><body>')
    [void]$sb.AppendLine((Get-GEReportThemeToggleHtml))

    # ===================== INTERACTIVE TOOLBAR (screen only) ==================
    [void]$sb.AppendLine('<div class="toolbar no-print">')
    [void]$sb.AppendLine('<button id="b02-print" type="button">&#128424; Print / Save as PDF</button>')
    [void]$sb.AppendLine('<button id="b02-clear" type="button" class="secondary">Clear saved entries</button>')
    [void]$sb.AppendLine('<span id="b02-progress" class="tb-progress">0 of 0 entitlements decided</span>')
    [void]$sb.AppendLine('<span id="b02-nostore" class="tb-nostore">&#9888; Local saving unavailable here &mdash; entries will not persist after closing.</span>')
    [void]$sb.AppendLine('<span id="b02-saved" class="tb-saved">&#10003; Saved on this browser</span>')
    [void]$sb.AppendLine('</div>')

    # ===================== COVER SHEET =======================================
    [void]$sb.AppendLine('<div class="page cover">')
    [void]$sb.AppendLine('<h1>Access Certification &mdash; User Access Review Sign-off Sheet</h1>')
    [void]$sb.AppendLine('<p class="docid">Report B02 &middot; Access Certification / UAR Sign-off Sheet &middot; account treatment: full-list (one certifiable row per entitlement)</p>')
    [void]$sb.AppendLine('<p class="save-note no-print">Fill in decisions, justifications, dates and names below &mdash; entries are saved automatically <b>in this browser</b> as you type, so you can close and resume. When complete, use <b>Print / Save as PDF</b> for the signed evidence copy. (Saved entries are local to this machine/browser; clear them with <b>Clear saved entries</b>.)</p>')

    [void]$sb.AppendLine('<div class="grid">')
    [void]$sb.AppendLine("<div class=""k"">Review Scope</div><div class=""v"">$(ConvertTo-B02HtmlSafe $scopeDomains) &mdash; $totalGroups group(s), $grandRows entitlement row(s)</div>")
    [void]$sb.AppendLine("<div class=""k"">Review Period</div><div class=""v"">$(ConvertTo-B02HtmlSafe $reviewPeriod)</div>")
    [void]$sb.AppendLine('<div class="k">Control Owner</div><div class="v"><input type="text" class="cover-input" data-key="cover_owner" placeholder="print name &amp; title"></div>')
    [void]$sb.AppendLine('<div class="k">Reviewer / Certifier</div><div class="v"><input type="text" class="cover-input" data-key="cover_reviewer" placeholder="print name &amp; title"></div>')
    [void]$sb.AppendLine("<div class=""k"">Enabled Accounts</div><div class=""v"">$grandEnabled</div>")
    [void]$sb.AppendLine("<div class=""k"">Disabled Accounts</div><div class=""v"">$grandDisabled (flagged for priority review)</div>")
    [void]$sb.AppendLine("<div class=""k"">Evidence Generated</div><div class=""v"">$(ConvertTo-B02HtmlSafe $generatedAt)</div>")
    [void]$sb.AppendLine('</div>')

    [void]$sb.AppendLine('<div class="attest">')
    [void]$sb.AppendLine('<h2>Attestation Statement</h2>')
    [void]$sb.AppendLine('<p>I, the undersigned reviewer, attest that I have examined each access entitlement listed in this worksheet for the stated review period. For every row I have recorded a decision of <b>Approve</b>, <b>Revoke</b>, or <b>Escalate</b> and provided a written justification. I certify that approved access remains appropriate to the individual&#39;s current role and business need, that access marked for revocation will be removed through the established access-management process, and that escalations have been routed to the responsible owner for resolution. I understand that access not documented in this review is treated by auditors as never having been reviewed.</p>')
    [void]$sb.AppendLine('</div>')

    [void]$sb.AppendLine('<div class="siglines">')
    [void]$sb.AppendLine('<div class="sig">Reviewer signature &amp; date</div>')
    [void]$sb.AppendLine('<div class="sig">Control owner / approver signature &amp; date</div>')
    [void]$sb.AppendLine('</div>')

    [void]$sb.AppendLine('<div class="legend"><span class="swatch"></span> Highlighted rows marked &ldquo;[DISABLED]&rdquo; denote accounts that are currently disabled in the directory and are sorted to the top of each group for priority review. Color and the bold [DISABLED] marker both encode status so the sheet remains legible in greyscale print.</div>')
    [void]$sb.AppendLine('</div>') # end cover page

    # ===================== GROUP ROSTER SECTIONS =============================
    foreach ($sec in $orderedSections) {
        [void]$sb.AppendLine('<div class="page section">')

        [void]$sb.AppendLine('<div class="section-head">')
        [void]$sb.AppendLine("<h2>$(ConvertTo-B02HtmlSafe $sec.GroupName)</h2>")
        [void]$sb.AppendLine("<span class=""dom"">$(ConvertTo-B02HtmlSafe $sec.Domain)</span>")
        [void]$sb.AppendLine('<span class="tags">')
        [void]$sb.AppendLine("<span class=""tag"">Members: $($sec.Members.Count)</span>")
        [void]$sb.AppendLine("<span class=""tag"">Enabled: $($sec.Enabled)</span>")
        if ($sec.Disabled -gt 0) {
            [void]$sb.AppendLine("<span class=""tag dis"">Disabled: $($sec.Disabled)</span>")
        } else {
            [void]$sb.AppendLine("<span class=""tag"">Disabled: 0</span>")
        }
        if ($sec.IsNested) { [void]$sb.AppendLine('<span class="tag warn">Nested</span>') }
        if ($sec.Skipped)  { [void]$sb.AppendLine('<span class="tag warn">Skipped</span>') }
        [void]$sb.AppendLine('</span>')
        [void]$sb.AppendLine('</div>')

        [void]$sb.AppendLine('<table>')
        [void]$sb.AppendLine('<thead><tr>')
        [void]$sb.AppendLine('<th class="num">#</th>')
        [void]$sb.AppendLine('<th>Display Name</th>')
        [void]$sb.AppendLine('<th>SamAccountName</th>')
        [void]$sb.AppendLine('<th>Email</th>')
        [void]$sb.AppendLine('<th>Account Status</th>')
        [void]$sb.AppendLine('<th class="deccol">Reviewer Decision<br><span class="decision-hint">Approve / Revoke / Escalate</span></th>')
        [void]$sb.AppendLine('<th class="deccol">Justification <span class="decision-hint">(required)</span></th>')
        [void]$sb.AppendLine('<th class="deccol">Review Date</th>')
        [void]$sb.AppendLine('<th class="deccol">Reviewer Name</th>')
        [void]$sb.AppendLine('</tr></thead>')
        [void]$sb.AppendLine('<tbody>')

        if ($sec.Members.Count -eq 0) {
            [void]$sb.AppendLine('<tr><td class="num">&mdash;</td><td colspan="8" style="color:#9aa3b0;font-style:italic;">No members enumerated for this group.</td></tr>')
        }
        else {
            $i = 0
            foreach ($m in $sec.Members) {
                $i++
                # Stable per-entitlement key (domain|group|sam) so saved decisions survive
                # report regeneration of the same review scope.
                $rid = (("$($sec.Domain)_$($sec.GroupName)_$($m.SamAccountName)") -replace '[^A-Za-z0-9]', '_')
                $rowClass = if (-not $m.Enabled) { ' class="row-disabled"' } else { '' }
                if ($m.Enabled) {
                    $statusCell = '<span class="status-en">Enabled</span>'
                } else {
                    $statusCell = '<span class="status-dis dis-mark">&#9632; [DISABLED]</span>'
                }
                [void]$sb.Append("<tr$rowClass>")
                [void]$sb.Append("<td class=""num"">$i</td>")
                [void]$sb.Append("<td>$(ConvertTo-B02HtmlSafe $m.DisplayName)</td>")
                [void]$sb.Append("<td>$(ConvertTo-B02HtmlSafe $m.SamAccountName)</td>")
                [void]$sb.Append("<td>$(ConvertTo-B02HtmlSafe $m.Email)</td>")
                [void]$sb.Append("<td>$statusCell</td>")
                [void]$sb.Append("<td class=""fill deccell""><label class=""dec dec-app""><input type=""radio"" name=""dec_$rid"" value=""Approve"" data-key=""${rid}_decision""> Approve</label><label class=""dec dec-rev""><input type=""radio"" name=""dec_$rid"" value=""Revoke"" data-key=""${rid}_decision""> Revoke</label><label class=""dec dec-esc""><input type=""radio"" name=""dec_$rid"" value=""Escalate"" data-key=""${rid}_decision""> Escalate</label></td>")
                [void]$sb.Append("<td class=""fill""><textarea class=""just"" rows=""2"" data-key=""${rid}_just"" placeholder=""Justification (required)""></textarea></td>")
                [void]$sb.Append("<td class=""fill""><input type=""date"" class=""dt"" data-key=""${rid}_date""></td>")
                [void]$sb.Append("<td class=""fill""><input type=""text"" class=""nm"" data-key=""${rid}_name"" placeholder=""Reviewer""></td>")
                [void]$sb.AppendLine('</tr>')
            }
        }

        [void]$sb.AppendLine('</tbody></table>')
        [void]$sb.AppendLine('<p class="foot-note">Every member above is rendered as a discrete certifiable entitlement (full-list treatment). Each row requires a Reviewer Decision and a written Justification before the sheet is considered complete. Disabled accounts are sorted first within the group.</p>')
        [void]$sb.AppendLine('</div>') # end section page
    }

    # ===================== PERSISTENCE + PRINT SCRIPT ========================
    # Namespace keys by review scope so the SAME review resumes across regenerations,
    # while a different scope/period gets its own saved set.
    $b02Ns = 'geb02_' + (("$scopeDomains|$reviewPeriod") -replace '[^A-Za-z0-9]', '_')
    [void]$sb.AppendLine(@"
<script>
(function(){
  var NS = '$b02Ns';
  var store = null;
  try { store = window.localStorage; var t='__b02t'; store.setItem(t,'1'); store.removeItem(t); } catch(e){ store=null; }
  var ctrls = Array.prototype.slice.call(document.querySelectorAll('[data-key]'));
  function fullKey(el){ return NS + '_' + el.getAttribute('data-key'); }
  var ind = document.getElementById('b02-saved'); var savedTmr = null;
  function flashSaved(){ if(!ind) return; ind.style.opacity='1'; if(savedTmr) clearTimeout(savedTmr); savedTmr=setTimeout(function(){ ind.style.opacity='0'; },1200); }
  function updateProgress(){
    var groups={}, decided=0, total=0;
    ctrls.forEach(function(el){ if(el.type==='radio'){ if(!(el.name in groups)) groups[el.name]=false; if(el.checked) groups[el.name]=true; } });
    Object.keys(groups).forEach(function(n){ total++; if(groups[n]) decided++; });
    var p=document.getElementById('b02-progress'); if(p) p.textContent = decided+' of '+total+' entitlements decided';
  }
  function save(el){
    if(store){ try {
      if(el.type==='radio'){ if(el.checked) store.setItem(fullKey(el), el.value); }
      else if(el.type==='checkbox'){ store.setItem(fullKey(el), el.checked?'1':'0'); }
      else { store.setItem(fullKey(el), el.value); }
    } catch(e){} }
    flashSaved(); updateProgress();
  }
  function restore(){
    if(!store) return;
    ctrls.forEach(function(el){
      var v=null; try { v=store.getItem(fullKey(el)); } catch(e){}
      if(v===null) return;
      if(el.type==='radio'){ if(el.value===v) el.checked=true; }
      else if(el.type==='checkbox'){ el.checked=(v==='1'); }
      else { el.value=v; }
    });
  }
  ctrls.forEach(function(el){ el.addEventListener('change', function(){ save(el); }); el.addEventListener('input', function(){ save(el); }); });
  var pbtn=document.getElementById('b02-print'); if(pbtn) pbtn.addEventListener('click', function(){ window.print(); });
  var cbtn=document.getElementById('b02-clear'); if(cbtn) cbtn.addEventListener('click', function(){
    if(!confirm('Clear all saved decisions for this review on this browser? This cannot be undone.')) return;
    if(store){ try { var rm=[]; for(var i=0;i<store.length;i++){ var key=store.key(i); if(key && key.indexOf(NS+'_')===0) rm.push(key); } rm.forEach(function(key){ store.removeItem(key); }); } catch(e){} }
    location.reload();
  });
  if(!store){ var n=document.getElementById('b02-nostore'); if(n) n.style.display='inline'; }
  window.addEventListener('beforeprint', function(){ document.querySelectorAll('textarea.just').forEach(function(t){ t.dataset.h=t.style.height; t.style.height='auto'; t.style.height=t.scrollHeight+'px'; }); });
  window.addEventListener('afterprint', function(){ document.querySelectorAll('textarea.just').forEach(function(t){ t.style.height=t.dataset.h||''; }); });
  restore(); updateProgress();
})();
</script>
"@)
    [void]$sb.AppendLine((Get-GEReportThemeScript))
    [void]$sb.AppendLine('</body></html>')

    # --- Write output --------------------------------------------------------
    $outDir = Split-Path -Parent $OutputPath
    if ($outDir -and -not (Test-Path -LiteralPath $outDir)) {
        New-Item -ItemType Directory -Path $outDir -Force | Out-Null
    }
    [System.IO.File]::WriteAllText($OutputPath, $sb.ToString(), [System.Text.UTF8Encoding]::new($false))
    return $OutputPath
}
