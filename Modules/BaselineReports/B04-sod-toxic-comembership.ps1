<#
.SYNOPSIS
    B04 - SoD / Toxic Co-Membership Violations Register (parameterized module).

.DESCRIPTION
    Baseline report module. Self-contained, offline, read-only.

    Subject: Users who are simultaneously members of two or more CONFLICTING
    groups. The atomic violation primitive is the group intersection:
    "user IN Group A AND user IN Group B" where (A,B) is a named conflict rule.

    accountTreatment = "counts-plus-expandable":
      - Headline / register shows COUNTS (violation count, distinct users,
        conflicting-member count per rule).
      - Each violation row is EXPANDABLE to reveal the individual user identity
        and per-side account-enabled state.

    DESIGN NOTE on the rule set: declares a NAMED rule set ("AD Lab SoD Rule
    Set v1") that assigns auditable role aliases to specific group names and
    then declares weighted conflict pairs between those roles. The rule set is
    data, defined in one place below; swap the $RuleSet block to re-target
    real group names without touching the engine.

    Dot-sources nothing; no module imports; no AD calls.
#>

function ConvertTo-SodHtmlSafe {
    param([string]$Text)
    if ($null -eq $Text) { return '' }
    $t = [string]$Text
    $t = $t.Replace('&','&amp;').Replace('<','&lt;').Replace('>','&gt;').Replace('"','&quot;').Replace("'",'&#39;')
    return $t
}

function ConvertTo-B04PSObject {
    # Normalize the -FromCache hashtable shape (and nested members) to
    # PSCustomObjects so the PSObject-based property checks below work for both
    # cache (hashtable) and live (object) inputs.
    param([object]$InputObject)
    if ($InputObject -is [System.Collections.IDictionary]) {
        $ht = @{}
        foreach ($k in $InputObject.Keys) { $ht[[string]$k] = ConvertTo-B04PSObject $InputObject[$k] }
        return [pscustomobject]$ht
    }
    if (($InputObject -is [System.Collections.IEnumerable]) -and ($InputObject -isnot [string])) {
        return @(foreach ($item in $InputObject) { ConvertTo-B04PSObject $item })
    }
    return $InputObject
}

function Export-SodToxicComembershipReport {
    <#
    .SYNOPSIS
        Writes a B04 SoD / Toxic Co-Membership Violations Register HTML report.

    .PARAMETER GroupResults
        Array of @{ Data = @{ Domain; GroupName; MemberCount; IsNested; Skipped;
        Members = @(@{ SamAccountName; DisplayName; Email; Enabled }) }; Errors = @() }.

    .PARAMETER OutputPath
        Destination .html file path.

    .PARAMETER Title
        Optional report title override.

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

        [Parameter()][string]$Title = 'B04 - SoD / Toxic Co-Membership Violations Register',

        [Parameter()][ValidateSet('auto','dark','light')][string]$Theme = 'auto'
    )

    $ErrorActionPreference = 'Stop'

    # ===========================================================================
    # NAMED CONFLICT RULE SET (data, not logic)
    # ---------------------------------------------------------------------------
    # RoleAliases: human-auditable name -> actual group name in the directory.
    # Conflicts : ordered list of toxic pairs expressed in role-alias terms, each
    #             with a stable RuleId, descriptive name, risk tier and rationale.
    # Risk tiers: Critical > High > Medium > Low  (sorted DESC in the register).
    # ===========================================================================
    $RuleSetName    = 'AD Lab SoD Rule Set v1'
    $RuleSetVersion = '1.0'

    $RoleAliases = [ordered]@{
        'Finance-Payments'      = 'GG_Scale_0001'   # raises / releases payments
        'Finance-Approvals'     = 'GG_Scale_0002'   # approves payments
        'Vendor-Master'         = 'GG_Scale_0003'   # creates/edits vendor records
        'Procurement-PO'        = 'GG_Scale_0004'   # raises purchase orders
        'Identity-Admin'        = 'GG_Scale_0005'   # manages user accounts
        'Security-Audit'        = 'GG_Scale_0006'   # reviews / attests access
        'HR-PayrollEdit'        = 'GG_Scale_0007'   # edits payroll data
        'HR-PayrollApprove'     = 'GG_Scale_0008'   # approves payroll run
        'DBA-Prod'              = 'GG_Scale_0009'   # production database admin
        'Dev-CodeDeploy'        = 'GG_Scale_0010'   # deploys code to prod
        'Backup-Operator'       = 'GG_Scale_0011'   # can restore/overwrite data
        'Backup-Approver'       = 'GG_Scale_0012'   # approves restores
        'GL-JournalPost'        = 'GG_Scale_0014'   # posts general-ledger journals
        'GL-JournalReview'      = 'GG_Scale_0016'   # reviews GL journals
    }

    # Each conflict references RoleAliases above by key.
    $Conflicts = @(
        [pscustomobject]@{ RuleId='SOD-001'; Name='Initiate & Approve Payments';        RoleA='Finance-Payments';  RoleB='Finance-Approvals';  Risk='Critical'; Rationale='Same identity can both raise and approve a payment (classic fraud path).' }
        [pscustomobject]@{ RuleId='SOD-002'; Name='Vendor Master & Payments';           RoleA='Vendor-Master';     RoleB='Finance-Payments';   Risk='Critical'; Rationale='Can create a fictitious vendor and pay it.' }
        [pscustomobject]@{ RuleId='SOD-003'; Name='Payroll Edit & Approve';             RoleA='HR-PayrollEdit';    RoleB='HR-PayrollApprove';  Risk='Critical'; Rationale='Can alter payroll and self-approve the run.' }
        [pscustomobject]@{ RuleId='SOD-004'; Name='Identity Admin & Security Audit';     RoleA='Identity-Admin';    RoleB='Security-Audit';     Risk='High';     Rationale='Provisioner also reviews access -- self-attestation of own grants.' }
        [pscustomobject]@{ RuleId='SOD-005'; Name='Prod DBA & Code Deploy';             RoleA='DBA-Prod';          RoleB='Dev-CodeDeploy';     Risk='High';     Rationale='Same identity writes code and controls the production datastore.' }
        [pscustomobject]@{ RuleId='SOD-006'; Name='Procurement & Vendor Master';        RoleA='Procurement-PO';    RoleB='Vendor-Master';      Risk='High';     Rationale='Can raise a PO against a vendor record they themselves maintain.' }
        [pscustomobject]@{ RuleId='SOD-007'; Name='Backup Operator & Approver';         RoleA='Backup-Operator';   RoleB='Backup-Approver';    Risk='Medium';   Rationale='Can perform and self-approve a destructive restore.' }
        [pscustomobject]@{ RuleId='SOD-008'; Name='GL Post & Review';                   RoleA='GL-JournalPost';    RoleB='GL-JournalReview';   Risk='Medium';   Rationale='Posts and reviews their own general-ledger journals.' }
        [pscustomobject]@{ RuleId='SOD-009'; Name='Procurement & Approvals';            RoleA='Procurement-PO';    RoleB='Finance-Approvals';  Risk='Low';      Rationale='Light conflict: PO raiser overlaps payment approval pool.' }
    )

    $RiskRank = @{ 'Critical'=4; 'High'=3; 'Medium'=2; 'Low'=1 }

    # -----------------------------------------------------------------------
    # Helper: risk colour
    # -----------------------------------------------------------------------
    function _Get-RiskColor {
        param([string]$Risk)
        switch ($Risk) {
            'Critical' { '#b00020' }
            'High'     { '#d9531e' }
            'Medium'   { '#c79100' }
            'Low'      { '#2e7d32' }
            default    { '#607d8b' }
        }
    }

    # -----------------------------------------------------------------------
    # Build group index from parameter data
    # group name -> @{ Members = @{ sam -> memberObj }; Domain; Skipped }
    # -----------------------------------------------------------------------
    $groupIndex = @{}
    foreach ($g in $GroupResults) {
        $d = $g.Data
        if ($null -eq $d) { continue }
        $d = ConvertTo-B04PSObject $d
        $name = [string]$d.GroupName
        if ([string]::IsNullOrWhiteSpace($name)) { continue }
        $members = @{}
        if ($d.PSObject.Properties.Name -contains 'Members' -and $d.Members) {
            foreach ($m in $d.Members) {
                $sam = [string]$m.SamAccountName
                if ([string]::IsNullOrWhiteSpace($sam)) { continue }
                if (-not $members.ContainsKey($sam)) { $members[$sam] = $m }
            }
        }
        $skipped = $false
        if ($d.PSObject.Properties.Name -contains 'Skipped') { $skipped = [bool]$d.Skipped }
        $groupIndex[$name] = [pscustomobject]@{
            Domain      = [string]$d.Domain
            Members     = $members
            Skipped     = $skipped
            MemberCount = $members.Count
        }
    }

    # -----------------------------------------------------------------------
    # Resolve role aliases to actual groups present in the data.
    # -----------------------------------------------------------------------
    $resolvedRole    = @{}
    $unresolvedRoles = @()
    foreach ($alias in $RoleAliases.Keys) {
        $grp = $RoleAliases[$alias]
        if ($groupIndex.ContainsKey($grp)) { $resolvedRole[$alias] = $grp }
        else { $unresolvedRoles += ('{0} -> {1}' -f $alias, $grp) }
    }

    # -----------------------------------------------------------------------
    # Engine: evaluate each conflict rule (intersection of the two role groups).
    # -----------------------------------------------------------------------
    $violations  = New-Object System.Collections.ArrayList
    $ruleStats   = New-Object System.Collections.ArrayList
    $activeRules = @()

    foreach ($rule in $Conflicts) {
        $haveA = $resolvedRole.ContainsKey($rule.RoleA)
        $haveB = $resolvedRole.ContainsKey($rule.RoleB)
        if (-not ($haveA -and $haveB)) {
            [void]$ruleStats.Add([pscustomobject]@{
                RuleId=''; Name=$rule.Name; Risk=$rule.Risk
                RuleIdVal=$rule.RuleId
                GroupA='(unresolved)'; GroupB='(unresolved)'
                ViolationCount=0; Evaluable=$false; Rationale=$rule.Rationale
            })
            # fix: set RuleId directly
            $ruleStats[$ruleStats.Count-1].RuleId = $rule.RuleId
            continue
        }
        $gaName = $resolvedRole[$rule.RoleA]
        $gbName = $resolvedRole[$rule.RoleB]
        $ga = $groupIndex[$gaName]
        $gb = $groupIndex[$gbName]
        $activeRules += $rule

        $count = 0
        foreach ($sam in $ga.Members.Keys) {
            if (-not $gb.Members.ContainsKey($sam)) { continue }
            $count++
            $mA = $ga.Members[$sam]
            $mB = $gb.Members[$sam]
            $disp = [string]$mA.DisplayName
            if ([string]::IsNullOrWhiteSpace($disp)) { $disp = [string]$mB.DisplayName }
            $email = ''
            if ($mA.PSObject.Properties.Name -contains 'Email' -and $mA.Email) { $email = [string]$mA.Email }
            elseif ($mB.PSObject.Properties.Name -contains 'Email' -and $mB.Email) { $email = [string]$mB.Email }
            $enA = $true; if ($mA.PSObject.Properties.Name -contains 'Enabled') { $enA = [bool]$mA.Enabled }
            $enB = $true; if ($mB.PSObject.Properties.Name -contains 'Enabled') { $enB = [bool]$mB.Enabled }

            [void]$violations.Add([pscustomobject]@{
                RuleId      = $rule.RuleId
                RuleName    = $rule.Name
                Risk        = $rule.Risk
                RiskRank    = $RiskRank[$rule.Risk]
                Sam         = $sam
                DisplayName = $disp
                Email       = $email
                Domain      = [string]$ga.Domain
                GroupA      = $gaName
                GroupB      = $gbName
                RoleA       = $rule.RoleA
                RoleB       = $rule.RoleB
                EnabledA    = $enA
                EnabledB    = $enB
                Rationale   = $rule.Rationale
            })
        }

        [void]$ruleStats.Add([pscustomobject]@{
            RuleId=$rule.RuleId; Name=$rule.Name; Risk=$rule.Risk
            GroupA=$gaName; GroupB=$gbName
            ViolationCount=$count; Evaluable=$true; Rationale=$rule.Rationale
        })
    }

    # Sort register: Risk DESC, then RuleId, then user
    $violSorted = $violations | Sort-Object -Property @{Expression='RiskRank';Descending=$true}, RuleId, Sam

    # Headline counts (counts-plus-expandable: headline is counts)
    $totalViolations = $violations.Count
    $distinctUsers   = ($violations | Select-Object -ExpandProperty Sam -Unique | Measure-Object).Count
    $critCount       = @($violations | Where-Object { $_.Risk -eq 'Critical' }).Count
    $highCount       = @($violations | Where-Object { $_.Risk -eq 'High' }).Count
    $medCount        = @($violations | Where-Object { $_.Risk -eq 'Medium' }).Count
    $lowCount        = @($violations | Where-Object { $_.Risk -eq 'Low' }).Count

    # -----------------------------------------------------------------------
    # Build Conflict Matrix axis + pair lookup
    # -----------------------------------------------------------------------
    $axisRoles = @()
    foreach ($alias in $RoleAliases.Keys) {
        $used = $false
        foreach ($r in $Conflicts) { if ($r.RoleA -eq $alias -or $r.RoleB -eq $alias) { $used = $true; break } }
        if ($used) { $axisRoles += $alias }
    }
    $pairLookup = @{}
    foreach ($r in $Conflicts) {
        $k1 = ('{0}|{1}' -f $r.RoleA, $r.RoleB)
        $k2 = ('{0}|{1}' -f $r.RoleB, $r.RoleA)
        $pairLookup[$k1] = $r
        $pairLookup[$k2] = $r
    }

    # -----------------------------------------------------------------------
    # Render HTML
    # -----------------------------------------------------------------------
    $generated = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss zzz')
    $titleEsc  = ConvertTo-SodHtmlSafe $Title

    # Shared accessible theme: chrome (bg/surface/ink/muted/line), severity card-text, table chrome
    # and the amber note inherit/track the canonical palette (both themes + toggle + print-light).
    # The severity MATRIX tiles + row badges stay fixed self-contained light tiles -- there the
    # colour IS the data (a legend-backed heatmap), kept constant across themes by design.
    $pal = Get-GEReportThemePalette
    $b04Light = [ordered]@{ bg = $pal.Light['bg']; panel = $pal.Light['surface']; surfalt = $pal.Light['surface-alt']; ink = $pal.Light['ink']; muted = $pal.Light['muted']; line = $pal.Light['line']; warn = $pal.Light['warn']; rowwarn = $pal.Light['row-warn-bg']; sevcrit = '#b00020'; sevhigh = '#c2451a'; sevmed = '#8a6d00'; sevlow = '#2e7d32' }
    $b04Dark  = [ordered]@{ bg = $pal.Dark['bg'];  panel = $pal.Dark['surface'];  surfalt = $pal.Dark['surface-alt'];  ink = $pal.Dark['ink'];  muted = $pal.Dark['muted'];  line = $pal.Dark['line'];  warn = $pal.Dark['warn'];  rowwarn = $pal.Dark['row-warn-bg'];  sevcrit = '#f3766b'; sevhigh = '#ff9e6b'; sevmed = '#e0b84a'; sevlow = '#5cbf6f' }
    $themeBlock = Get-GEThemedRootCss -Light $b04Light -Dark $b04Dark -ExtraRootCss (Get-GEReportThemeBadgeCss)
    $themeAttr  = if ($Theme -eq 'dark' -or $Theme -eq 'light') { " data-theme=`"$Theme`"" } else { '' }
    $toggleHtml = Get-GEReportThemeToggleHtml

    $sb = New-Object System.Text.StringBuilder

    [void]$sb.Append(@"
<!DOCTYPE html>
<html lang="en"$themeAttr>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>$titleEsc</title>
<style>
  :root { color-scheme: light dark; }
$themeBlock
  *{ box-sizing:border-box; }
  body{ margin:0; background:var(--bg); color:var(--ink);
        font-family:Segoe UI,Roboto,Helvetica,Arial,sans-serif; font-size:14px; line-height:1.45; }
  .wrap{ max-width:1280px; margin:0 auto; padding:24px; }
  header.rpt{ background:linear-gradient(135deg,#1f2d3d,#33475b); color:#fff;
        border-radius:10px; padding:22px 26px; margin-bottom:18px; }
  header.rpt h1{ margin:0 0 4px; font-size:22px; }
  header.rpt .sub{ color:#cdd9e3; font-size:13px; }
  .ruleset{ margin-top:12px; display:inline-block; background:rgba(255,255,255,.12);
        border:1px solid rgba(255,255,255,.25); border-radius:6px; padding:6px 12px; font-size:12.5px; }
  .ruleset b{ color:#fff; }
  .cards{ display:flex; flex-wrap:wrap; gap:12px; margin:18px 0; }
  .card{ background:var(--panel); border:1px solid var(--line); border-radius:9px;
        padding:14px 16px; min-width:150px; flex:1 1 150px; }
  .card .n{ font-size:26px; font-weight:700; }
  .card .l{ color:var(--muted); font-size:12px; text-transform:uppercase; letter-spacing:.04em; }
  .card.crit .n{ color:var(--sevcrit); } .card.high .n{ color:var(--sevhigh); }
  .card.med .n{ color:var(--sevmed); } .card.low .n{ color:var(--sevlow); }
  section{ background:var(--panel); border:1px solid var(--line); border-radius:9px;
        padding:18px 20px; margin-bottom:20px; }
  section h2{ margin:0 0 4px; font-size:17px; }
  section .hint{ color:var(--muted); font-size:12.5px; margin-bottom:14px; }
  table{ border-collapse:collapse; width:100%; font-size:13px; }
  th,td{ text-align:left; padding:8px 10px; border-bottom:1px solid var(--line); vertical-align:top; }
  th{ background:var(--surfalt); font-size:12px; text-transform:uppercase; letter-spacing:.03em; color:var(--muted); }
  tr.viol{ cursor:pointer; }
  tr.viol:hover{ background:var(--surfalt); }
  tr.detail > td{ background:var(--surfalt); border-top:none; }
  .riskpill{ display:inline-flex; align-items:center; gap:6px; font-weight:600; white-space:nowrap; }
  .swatch{ width:11px; height:11px; border-radius:50%; display:inline-block; border:1px solid rgba(0,0,0,.25); }
  .mono{ font-family:Consolas,Menlo,monospace; font-size:12px; }
  .gname{ font-family:Consolas,Menlo,monospace; font-size:12px; color:var(--ink); }
  .role{ color:var(--muted); font-size:11.5px; }
  .badge-dis{ background:#fdecea; color:#b00020; border:1px solid #f5c6cb; border-radius:4px; padding:1px 6px; font-size:11px; }
  .badge-en{ background:#e8f5e9; color:#2e7d32; border:1px solid #c8e6c9; border-radius:4px; padding:1px 6px; font-size:11px; }
  .expand{ color:var(--muted); font-size:11px; }
  .matrix td,.matrix th{ text-align:center; font-size:11.5px; padding:6px 4px; }
  .matrix th.rowhdr{ text-align:left; white-space:nowrap; }
  .mx-crit{ background:#f9d2da; color:#7a0016; font-weight:700; }
  .mx-high{ background:#f6dccb; color:#8a3410; font-weight:700; }
  .mx-med { background:#f6ecc6; color:#7a5c00; font-weight:700; }
  .mx-low { background:#d7ecd9; color:#1e5a22; font-weight:700; }
  .mx-diag{ background:#e9eef2; color:#9aa7b3; }
  .mx-empty{ background:#fafcfd; color:#cfd8de; }
  .legend{ display:flex; flex-wrap:wrap; gap:14px; margin-top:12px; font-size:12px; color:var(--muted); }
  .legend span{ display:inline-flex; align-items:center; gap:6px; }
  .footnote{ color:var(--muted); font-size:11.5px; margin-top:8px; }
  .warn{ background:var(--rowwarn); border:1px solid var(--warn); border-radius:6px; padding:8px 12px; font-size:12.5px; color:var(--ink); margin-bottom:14px; }
</style>
</head>
<body>
$toggleHtml
<div class="wrap">
"@)

    # Header
    [void]$sb.Append('<header class="rpt">')
    [void]$sb.Append(('<h1>{0}</h1>' -f $titleEsc))
    [void]$sb.Append('<div class="sub">Report B04 &middot; group co-membership as the proxy for a conflicting entitlement combination. Each violation = one user holding both groups of a named conflict pair.</div>')
    [void]$sb.Append(('<div class="ruleset">Rule set in force: <b>{0}</b> (v{1}) &middot; {2} conflict rules &middot; {3} evaluable against this data &middot; generated {4}</div>' -f `
        (ConvertTo-SodHtmlSafe $RuleSetName), (ConvertTo-SodHtmlSafe $RuleSetVersion), $Conflicts.Count, $activeRules.Count, (ConvertTo-SodHtmlSafe $generated)))
    [void]$sb.Append('</header>')

    if ($unresolvedRoles.Count -gt 0) {
        [void]$sb.Append('<div class="warn"><b>Note:</b> ' + $unresolvedRoles.Count + ' role alias(es) in the rule set did not resolve to a group present in this data; rules depending on them are listed as not-evaluable. Resolve by editing the $RoleAliases map. Unresolved: ' + (ConvertTo-SodHtmlSafe ($unresolvedRoles -join '; ')) + '</div>')
    }

    # Summary cards (counts-plus-expandable: headline is counts)
    [void]$sb.Append('<div class="cards">')
    [void]$sb.Append(('<div class="card"><div class="n">{0}</div><div class="l">Active Violations</div></div>' -f $totalViolations))
    [void]$sb.Append(('<div class="card"><div class="n">{0}</div><div class="l">Distinct Users</div></div>' -f $distinctUsers))
    [void]$sb.Append(('<div class="card crit"><div class="n">{0}</div><div class="l">Critical</div></div>' -f $critCount))
    [void]$sb.Append(('<div class="card high"><div class="n">{0}</div><div class="l">High</div></div>' -f $highCount))
    [void]$sb.Append(('<div class="card med"><div class="n">{0}</div><div class="l">Medium</div></div>' -f $medCount))
    [void]$sb.Append(('<div class="card low"><div class="n">{0}</div><div class="l">Low</div></div>' -f $lowCount))
    [void]$sb.Append('</div>')

    # ---- Conflict Matrix ----
    [void]$sb.Append('<section>')
    [void]$sb.Append('<h2>Conflict Matrix</h2>')
    [void]$sb.Append('<div class="hint">Upper-triangle view of the named rule set. A coloured cell = a declared toxic pair between the two roles; the Rule ID is printed in the cell. This is the control surface; the register below is its evaluation against live membership.</div>')
    [void]$sb.Append('<table class="matrix"><thead><tr><th class="rowhdr">Role &#9660; \\ Role &#9654;</th>')
    foreach ($cRole in $axisRoles) {
        $g = ''
        if ($resolvedRole.ContainsKey($cRole)) { $g = $resolvedRole[$cRole] }
        [void]$sb.Append(('<th title="{0}">{1}</th>' -f (ConvertTo-SodHtmlSafe $g), (ConvertTo-SodHtmlSafe $cRole)))
    }
    [void]$sb.Append('</tr></thead><tbody>')
    for ($r = 0; $r -lt $axisRoles.Count; $r++) {
        $rRole = $axisRoles[$r]
        $gRow = ''; if ($resolvedRole.ContainsKey($rRole)) { $gRow = $resolvedRole[$rRole] }
        [void]$sb.Append(('<tr><th class="rowhdr" title="{0}">{1}</th>' -f (ConvertTo-SodHtmlSafe $gRow), (ConvertTo-SodHtmlSafe $rRole)))
        for ($c = 0; $c -lt $axisRoles.Count; $c++) {
            $cRole = $axisRoles[$c]
            if ($c -lt $r) { [void]$sb.Append('<td class="mx-empty"></td>'); continue }   # lower triangle blank
            if ($c -eq $r) { [void]$sb.Append('<td class="mx-diag">&middot;</td>'); continue }
            $key = ('{0}|{1}' -f $rRole, $cRole)
            if ($pairLookup.ContainsKey($key)) {
                $rule = $pairLookup[$key]
                $cls = switch ($rule.Risk) { 'Critical'{'mx-crit'} 'High'{'mx-high'} 'Medium'{'mx-med'} 'Low'{'mx-low'} default{'mx-empty'} }
                [void]$sb.Append(('<td class="{0}" title="{1} ({2}): {3}">{4}<br><span style="font-weight:400">{2}</span></td>' -f `
                    $cls, (ConvertTo-SodHtmlSafe $rule.RuleId), (ConvertTo-SodHtmlSafe $rule.Risk), (ConvertTo-SodHtmlSafe $rule.Name), (ConvertTo-SodHtmlSafe $rule.RuleId)))
            } else {
                [void]$sb.Append('<td class="mx-empty"></td>')
            }
        }
        [void]$sb.Append('</tr>')
    }
    [void]$sb.Append('</tbody></table>')
    [void]$sb.Append('<div class="legend">')
    [void]$sb.Append('<span><span class="swatch" style="background:#b00020"></span>Critical</span>')
    [void]$sb.Append('<span><span class="swatch" style="background:#d9531e"></span>High</span>')
    [void]$sb.Append('<span><span class="swatch" style="background:#c79100"></span>Medium</span>')
    [void]$sb.Append('<span><span class="swatch" style="background:#2e7d32"></span>Low</span>')
    [void]$sb.Append('</div>')
    [void]$sb.Append('</section>')

    # ---- Per-rule rollup (counts) ----
    [void]$sb.Append('<section>')
    [void]$sb.Append('<h2>Rule Set Roster &amp; Counts</h2>')
    [void]$sb.Append('<div class="hint">Every rule in ' + (ConvertTo-SodHtmlSafe $RuleSetName) + ', its resolved groups and violation count. Counts-first; the register expands to the underlying accounts.</div>')
    [void]$sb.Append('<table><thead><tr><th>Rule ID</th><th>Conflict Rule</th><th>Risk</th><th>Group A</th><th>Group B</th><th>Violations</th></tr></thead><tbody>')
    foreach ($rs in ($ruleStats | Sort-Object -Property @{Expression={ $RiskRank[$_.Risk] };Descending=$true}, RuleId)) {
        $col = _Get-RiskColor $rs.Risk
        $cntCell = if ($rs.Evaluable) { [string]$rs.ViolationCount } else { 'n/a' }
        [void]$sb.Append('<tr>')
        [void]$sb.Append(('<td class="mono">{0}</td>' -f (ConvertTo-SodHtmlSafe $rs.RuleId)))
        [void]$sb.Append(('<td>{0}<div class="role">{1}</div></td>' -f (ConvertTo-SodHtmlSafe $rs.Name), (ConvertTo-SodHtmlSafe $rs.Rationale)))
        [void]$sb.Append(('<td><span class="riskpill"><span class="swatch" style="background:{0}"></span>{1}</span></td>' -f $col, (ConvertTo-SodHtmlSafe $rs.Risk)))
        [void]$sb.Append(('<td class="gname">{0}</td>' -f (ConvertTo-SodHtmlSafe $rs.GroupA)))
        [void]$sb.Append(('<td class="gname">{0}</td>' -f (ConvertTo-SodHtmlSafe $rs.GroupB)))
        [void]$sb.Append(('<td><b>{0}</b></td>' -f $cntCell))
        [void]$sb.Append('</tr>')
    }
    [void]$sb.Append('</tbody></table>')
    [void]$sb.Append('</section>')

    # ---- Active Violations Register ----
    [void]$sb.Append('<section>')
    [void]$sb.Append('<h2>Active Violations Register</h2>')
    [void]$sb.Append('<div class="hint">One row per user-per-conflict-pair, sorted by Risk (descending). Click a row to expand the underlying account detail (account-enabled state per side, email, domain). Risk is shown as colour <b>and</b> text.</div>')
    if ($totalViolations -eq 0) {
        [void]$sb.Append('<p class="footnote">No active violations detected for the evaluable rules in this rule set.</p>')
    } else {
        [void]$sb.Append('<table><thead><tr><th>Risk</th><th>Rule</th><th>User</th><th>Group A</th><th>Group B</th><th></th></tr></thead><tbody>')
        $rowId = 0
        foreach ($v in $violSorted) {
            $rowId++
            $col = _Get-RiskColor $v.Risk
            $detId = "d$rowId"
            # main (expandable) row
            [void]$sb.Append(("<tr class='viol' onclick=""var e=document.getElementById('$detId');e.style.display=(e.style.display=='table-row')?'none':'table-row';"">"))
            [void]$sb.Append(('<td><span class="riskpill"><span class="swatch" style="background:{0}"></span>{1}</span></td>' -f $col, (ConvertTo-SodHtmlSafe $v.Risk)))
            [void]$sb.Append(('<td><span class="mono">{0}</span><div class="role">{1}</div></td>' -f (ConvertTo-SodHtmlSafe $v.RuleId), (ConvertTo-SodHtmlSafe $v.RuleName)))
            [void]$sb.Append(('<td>{0}<div class="role mono">{1}</div></td>' -f (ConvertTo-SodHtmlSafe $v.DisplayName), (ConvertTo-SodHtmlSafe $v.Sam)))
            [void]$sb.Append(('<td><span class="gname">{0}</span><div class="role">{1}</div></td>' -f (ConvertTo-SodHtmlSafe $v.GroupA), (ConvertTo-SodHtmlSafe $v.RoleA)))
            [void]$sb.Append(('<td><span class="gname">{0}</span><div class="role">{1}</div></td>' -f (ConvertTo-SodHtmlSafe $v.GroupB), (ConvertTo-SodHtmlSafe $v.RoleB)))
            [void]$sb.Append('<td class="expand">&#9660; expand</td>')
            [void]$sb.Append('</tr>')
            # detail row (the underlying accounts)
            $enA = if ($v.EnabledA) { '<span class="badge-en">enabled</span>' } else { '<span class="badge-dis">disabled</span>' }
            $enB = if ($v.EnabledB) { '<span class="badge-en">enabled</span>' } else { '<span class="badge-dis">disabled</span>' }
            [void]$sb.Append(("<tr class='detail' id='$detId' style='display:none'><td colspan='6'>"))
            [void]$sb.Append('<table style="width:100%;font-size:12.5px">')
            [void]$sb.Append('<tr><th>Field</th><th>' + (ConvertTo-SodHtmlSafe $v.GroupA) + ' (A)</th><th>' + (ConvertTo-SodHtmlSafe $v.GroupB) + ' (B)</th></tr>')
            [void]$sb.Append('<tr><td>Account enabled</td><td>' + $enA + '</td><td>' + $enB + '</td></tr>')
            [void]$sb.Append('</table>')
            [void]$sb.Append('<div class="footnote">User: <b>' + (ConvertTo-SodHtmlSafe $v.DisplayName) + '</b> &middot; sam <span class="mono">' + (ConvertTo-SodHtmlSafe $v.Sam) + '</span> &middot; ' + (ConvertTo-SodHtmlSafe $v.Email) + ' &middot; domain ' + (ConvertTo-SodHtmlSafe $v.Domain) + '<br>Why this is toxic: ' + (ConvertTo-SodHtmlSafe $v.Rationale) + '</div>')
            [void]$sb.Append('</td></tr>')
        }
        [void]$sb.Append('</tbody></table>')
    }
    [void]$sb.Append('</section>')

    # Footer
    [void]$sb.Append('<p class="footnote">Violation primitive = group intersection (user in Group A AND Group B). accountTreatment: counts-plus-expandable. No directory or repository files were modified.</p>')
    [void]$sb.Append((Get-GEReportThemeScript))
    [void]$sb.Append('</div></body></html>')

    # -----------------------------------------------------------------------
    # Write output (UTF-8, no BOM)
    # -----------------------------------------------------------------------
    $outDir = Split-Path -Parent $OutputPath
    if ($outDir -and -not (Test-Path -LiteralPath $outDir)) {
        New-Item -ItemType Directory -Path $outDir -Force | Out-Null
    }
    $utf8 = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($OutputPath, $sb.ToString(), $utf8)
    return $OutputPath
}
