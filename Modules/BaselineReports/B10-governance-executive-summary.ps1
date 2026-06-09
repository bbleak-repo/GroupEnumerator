<#
.SYNOPSIS
    B10 Governance Executive Summary -- parameterized product module.

    Aggregate access-review sign-off dashboard. accountTreatment = "numbers-only":
    NO account/member names or emails are rendered anywhere in the output. Every
    metric is an aggregate count. Group names are likewise not enumerated. The only
    proper-noun-ish text rendered is domain/scope context, HTML-escaped defensively.

    Self-contained: dot-sources nothing; no hardcoded input or output paths.

    PowerShell 5.1 compatible.
#>

function ConvertTo-B10HtmlSafe {
    param([Parameter(ValueFromPipeline = $true)][AllowNull()]$Text)
    process {
        if ($null -eq $Text) { return '' }
        $s = [string]$Text
        $s = $s.Replace('&', '&amp;')
        $s = $s.Replace('<', '&lt;')
        $s = $s.Replace('>', '&gt;')
        $s = $s.Replace('"', '&quot;')
        $s = $s.Replace("'", '&#39;')
        return $s
    }
}

function Get-B10Prop {
    # Safe property accessor for PSCustomObject under StrictMode.
    param($Object, [string]$Name)
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

# Common privileged-group name fragments (case-insensitive substring match).
# Heuristic only -- offline, name-based. Tune as needed for the environment.
$script:B10PrivilegedPatterns = @(
    'admin', 'domain admins', 'enterprise admins', 'schema admins',
    'administrators', 'account operators', 'backup operators',
    'server operators', 'print operators', 'dnsadmins', 'group policy creator',
    'krbtgt', 'cert publishers', 'privileged', 'priv_', '_priv', 'tier0', 'tier 0',
    'global admin', 'security admin', 'root'
)

function Test-B10IsPrivilegedGroup {
    param([string]$GroupName)
    if ([string]::IsNullOrWhiteSpace($GroupName)) { return $false }
    $g = $GroupName.ToLowerInvariant()
    foreach ($pat in $script:B10PrivilegedPatterns) {
        if ($g.Contains($pat)) { return $true }
    }
    return $false
}

function Export-GovernanceExecutiveSummaryReport {
    <#
    .SYNOPSIS
        Writes a governance executive summary HTML dashboard from GroupResults data.

    .PARAMETER GroupResults
        Array of @{ Data=@{ Domain; GroupName; MemberCount; IsNested; Skipped;
        Members=@(@{SamAccountName; DisplayName; Email; Enabled}) }; Errors=@() }

    .PARAMETER OutputPath
        Destination .html file path.

    .PARAMETER Title
        Optional report title override.

    .PARAMETER Theme
        'dark' (default) or 'light'. The source design uses a light palette;
        this parameter is accepted for contract compliance and reserved for future use.

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

        [Parameter()][string]$Title = 'Governance Executive Summary',

        [Parameter()][ValidateSet('auto', 'dark', 'light')][string]$Theme = 'auto'
    )

    # --------------------------------------------------------------------------
    # Aggregate metrics (numbers only -- accountTreatment: numbers-only)
    # --------------------------------------------------------------------------
    $totalGroups          = 0
    $totalMemberRows      = 0     # sum of member rows across groups (with dupes)
    $distinctMemberSet    = New-Object 'System.Collections.Generic.HashSet[string]'
    $disabledMemberRows   = 0
    $emptyOrStaleGroups   = 0
    $nestedGroups         = 0
    $privilegedGroups     = 0
    $privMemberRows       = 0
    $skippedGroups        = 0

    # Map member key -> set of privileged groups they belong to (for SoD).
    $privMembershipMap = @{}

    # Collect domain strings for scope context.
    $domainSet = New-Object 'System.Collections.Generic.HashSet[string]'

    foreach ($g in $GroupResults) {
        $data = Get-B10Prop $g 'Data'
        if ($null -eq $data) { continue }

        $totalGroups++

        $groupName  = [string](Get-B10Prop $data 'GroupName')
        $domainVal  = [string](Get-B10Prop $data 'Domain')
        $isNested   = Get-B10Prop $data 'IsNested'
        $skipped    = Get-B10Prop $data 'Skipped'
        $memberCnt  = Get-B10Prop $data 'MemberCount'
        $membersRaw = Get-B10Prop $data 'Members'
        $members    = @()
        if ($null -ne $membersRaw) { $members = @($membersRaw) }

        if (-not [string]::IsNullOrWhiteSpace($domainVal)) {
            [void]$domainSet.Add($domainVal)
        }

        $isPriv = Test-B10IsPrivilegedGroup -GroupName $groupName
        if ($isPriv) { $privilegedGroups++ }

        if ($isNested -eq $true) { $nestedGroups++ }

        $isSkipped = ($skipped -eq $true)
        if ($isSkipped) { $skippedGroups++ }

        # Effective member count: prefer enumerated members; fall back to MemberCount.
        $effectiveCount = $members.Count
        if ($effectiveCount -eq 0 -and $null -ne $memberCnt) {
            try { $effectiveCount = [int]$memberCnt } catch { $effectiveCount = 0 }
        }

        # Empty/stale: zero effective members OR skipped (not enumerated this cycle).
        if ($effectiveCount -eq 0 -or $isSkipped) { $emptyOrStaleGroups++ }

        foreach ($m in $members) {
            $totalMemberRows++
            $sam     = [string](Get-B10Prop $m 'SamAccountName')
            $enabled = Get-B10Prop $m 'Enabled'

            $key = if ([string]::IsNullOrWhiteSpace($sam)) {
                [string](Get-B10Prop $m 'DistinguishedName')
            } else { $sam.ToLowerInvariant() }
            if (-not [string]::IsNullOrWhiteSpace($key)) {
                [void]$distinctMemberSet.Add($key)
            }

            # Disabled member sitting inside a group = governance finding.
            if ($enabled -eq $false) { $disabledMemberRows++ }

            if ($isPriv) {
                $privMemberRows++
                if (-not [string]::IsNullOrWhiteSpace($key)) {
                    if (-not $privMembershipMap.ContainsKey($key)) {
                        $privMembershipMap[$key] = New-Object 'System.Collections.Generic.HashSet[string]'
                    }
                    [void]$privMembershipMap[$key].Add($groupName)
                }
            }
        }
    }

    # SoD conflicts: a member who is a direct member of 2+ DISTINCT privileged groups.
    $sodConflicts = 0
    foreach ($k in $privMembershipMap.Keys) {
        if ($privMembershipMap[$k].Count -ge 2) { $sodConflicts++ }
    }

    $distinctMembers   = $distinctMemberSet.Count
    # Changelog not loaded in parameterized mode (no baked-in path); change metrics = 0.
    $membershipChanges = 0
    $addedChanges      = 0
    $removedChanges    = 0

    $scopeDomains = if ($domainSet.Count -gt 0) { ($domainSet | Sort-Object) -join ', ' } else { 'N/A' }

    # --------------------------------------------------------------------------
    # RAG evaluation
    # --------------------------------------------------------------------------
    function New-B10Metric {
        param(
            [string]$Name,
            [int]$Value,
            [string]$Target,
            [string]$Status,
            [string]$Tier,
            [string]$Note
        )
        [pscustomobject]@{
            Name   = $Name
            Value  = $Value
            Target = $Target
            Status = $Status
            Tier   = $Tier
            Note   = $Note
        }
    }

    function Get-B10FindingStatus {
        param([int]$Value, [int]$AmberAt = 1, [int]$RedAt = 1)
        if ($Value -ge $RedAt)   { return 'red' }
        if ($Value -ge $AmberAt) { return 'amber' }
        return 'green'
    }

    $metrics = New-Object System.Collections.Generic.List[object]

    # Scope totals -- informational (always green: they describe scope, not risk).
    $metrics.Add( (New-B10Metric -Name 'Total groups in scope'    -Value $totalGroups      -Target 'All in-scope groups enumerated' -Status 'green' -Tier 'Scope'     -Note 'Count of groups present in this review cycle.') )
    $metrics.Add( (New-B10Metric -Name 'Total members (distinct)' -Value $distinctMembers  -Target 'Reviewed in full'               -Status 'green' -Tier 'Scope'     -Note 'Distinct accounts across all in-scope groups.') )
    $metrics.Add( (New-B10Metric -Name 'Total membership rows'    -Value $totalMemberRows   -Target 'Reviewed in full'               -Status 'green' -Tier 'Scope'     -Note 'Group-member edges (an account may appear in several groups).') )
    $metrics.Add( (New-B10Metric -Name 'Nested groups'            -Value $nestedGroups      -Target 'Documented & justified'         -Status (Get-B10FindingStatus -Value $nestedGroups -AmberAt 1 -RedAt 999999) -Tier 'Structure' -Note 'Groups nested inside other groups; review for transitive exposure.') )

    # Findings -- want 0.
    $metrics.Add( (New-B10Metric -Name 'Disabled members in groups'  -Value $disabledMemberRows -Target '0'                          -Status (Get-B10FindingStatus -Value $disabledMemberRows -AmberAt 1 -RedAt 1) -Tier 'Hygiene'   -Note 'Disabled accounts still holding group membership (stale entitlement).') )
    $metrics.Add( (New-B10Metric -Name 'Privileged-group members'     -Value $privMemberRows     -Target 'Minimized & justified'      -Status (Get-B10FindingStatus -Value $privMemberRows -AmberAt 1 -RedAt 999999) -Tier 'Privilege' -Note 'Membership rows in groups matching privileged naming patterns.') )
    $metrics.Add( (New-B10Metric -Name 'SoD conflicts found'          -Value $sodConflicts       -Target '0'                          -Status (Get-B10FindingStatus -Value $sodConflicts -AmberAt 1 -RedAt 1) -Tier 'Privilege' -Note 'Accounts holding membership in 2+ privileged groups simultaneously.') )
    $metrics.Add( (New-B10Metric -Name 'Empty / stale groups'         -Value $emptyOrStaleGroups -Target '0'                          -Status (Get-B10FindingStatus -Value $emptyOrStaleGroups -AmberAt 1 -RedAt 1) -Tier 'Hygiene'   -Note 'Groups with no members or skipped (not enumerated) this cycle.') )

    # Change volume -- informational; 0 when no changelog is available.
    $changeStatus = if ($membershipChanges -le 250) { 'green' } else { 'amber' }
    $metrics.Add( (New-B10Metric -Name 'Membership changes this period' -Value $membershipChanges -Target 'Within expected churn' -Status $changeStatus -Tier 'Change' -Note "Added=$addedChanges, Removed=$removedChanges (changelog not loaded in parameterized mode).") )

    # --------------------------------------------------------------------------
    # Overall sign-off signal
    # --------------------------------------------------------------------------
    $redCount   = @($metrics | Where-Object { $_.Status -eq 'red' }).Count
    $amberCount = @($metrics | Where-Object { $_.Status -eq 'amber' }).Count

    $overallStatus = 'green'
    $overallLabel  = 'PASS'
    if ($redCount -gt 0) {
        $overallStatus = 'red'; $overallLabel = 'FAIL - REMEDIATION REQUIRED'
    }
    elseif ($amberCount -gt 0) {
        $overallStatus = 'amber'; $overallLabel = 'PASS WITH EXCEPTIONS'
    }

    # --------------------------------------------------------------------------
    # Dates / context
    # --------------------------------------------------------------------------
    $nowLocal   = Get-Date
    $reviewDate = $nowLocal.ToString('yyyy-MM-dd')
    $nextReview = $nowLocal.AddDays(90).ToString('yyyy-MM-dd')   # quarterly access review cadence

    $kpiGroups      = $totalGroups
    $kpiMembers     = $distinctMembers
    $findingsTotal  = $disabledMemberRows + $sodConflicts + $emptyOrStaleGroups
    $kpiPriv        = $privMemberRows

    # --------------------------------------------------------------------------
    # Build HTML
    # --------------------------------------------------------------------------
    $sb = New-Object System.Text.StringBuilder

    function Add-B10Line { param([string]$Text) [void]$sb.AppendLine($Text) }

    $statusBadge = {
        param($s)
        switch ($s) {
            'green' { 'GREEN' }
            'amber' { 'AMBER' }
            'red'   { 'RED' }
            default { 'N/A' }
        }
    }

    $tEsc    = ConvertTo-B10HtmlSafe $Title
    $ovBadge = & $statusBadge $overallStatus

    # Shared accessible theme: chrome (page/panel/ink/muted/line + kpi/thead surface-alt) themes;
    # the RAG green/amber/red pill tokens are kept as fixed self-contained semantic tiles (the colour
    # IS the verdict), and the flag KPI number uses a per-theme red. Runtime toggle + print-light.
    $pal = Get-GEReportThemePalette
    $b10Light = [ordered]@{ ink = $pal.Light['ink']; muted = $pal.Light['muted']; line = $pal.Light['line']; panel = $pal.Light['surface']; page = $pal.Light['bg']; surfalt = $pal.Light['surface-alt']; sevred = '#b42318' }
    $b10Dark  = [ordered]@{ ink = $pal.Dark['ink'];  muted = $pal.Dark['muted'];  line = $pal.Dark['line'];  panel = $pal.Dark['surface'];  page = $pal.Dark['bg'];  surfalt = $pal.Dark['surface-alt'];  sevred = '#f3766b' }
    $b10Rag = @'
  --green:#1e7d44; --green-bg:#e7f5ec; --amber:#9a6700; --amber-bg:#fff4d6; --red:#b42318; --red-bg:#fdecea;
'@
    $themeBlock = Get-GEThemedRootCss -Light $b10Light -Dark $b10Dark -ExtraRootCss ((Get-GEReportThemeBadgeCss) + "`n" + $b10Rag)
    $themeAttr  = if ($Theme -eq 'dark' -or $Theme -eq 'light') { " data-theme=`"$Theme`"" } else { '' }

    Add-B10Line '<!DOCTYPE html>'
    Add-B10Line ('<html lang="en"' + $themeAttr + '>')
    Add-B10Line '<head>'
    Add-B10Line '<meta charset="utf-8" />'
    Add-B10Line '<meta name="viewport" content="width=device-width, initial-scale=1" />'
    Add-B10Line ('<title>' + $tEsc + '</title>')
    Add-B10Line '<style>'
    Add-B10Line ':root{ color-scheme: light dark; }'
    Add-B10Line $themeBlock
    Add-B10Line @'
*{box-sizing:border-box;}
body{margin:0;background:var(--page);color:var(--ink);
  font-family:Segoe UI,-apple-system,Helvetica,Arial,sans-serif;font-size:14px;line-height:1.45;}
.page{max-width:980px;margin:24px auto;background:var(--panel);
  border:1px solid var(--line);border-radius:10px;padding:28px 34px 36px;
  box-shadow:0 1px 3px rgba(0,0,0,.06);}
header.rpt{display:flex;justify-content:space-between;align-items:flex-start;
  border-bottom:2px solid var(--ink);padding-bottom:14px;margin-bottom:18px;gap:18px;}
header.rpt h1{font-size:22px;margin:0 0 4px;}
header.rpt .sub{color:var(--muted);font-size:12.5px;}
.overall{text-align:right;min-width:210px;}
.overall .pill{display:inline-block;padding:8px 16px;border-radius:24px;
  font-weight:700;font-size:15px;letter-spacing:.4px;border:2px solid;}
.pill.green{color:var(--green);background:var(--green-bg);border-color:var(--green);}
.pill.amber{color:var(--amber);background:var(--amber-bg);border-color:var(--amber);}
.pill.red{color:var(--red);background:var(--red-bg);border-color:var(--red);}
.overall .meta{color:var(--muted);font-size:11.5px;margin-top:6px;}
.kpis{display:grid;grid-template-columns:repeat(4,1fr);gap:14px;margin:6px 0 22px;}
.kpi{border:1px solid var(--line);border-radius:8px;padding:14px 16px;background:var(--surfalt);}
.kpi .n{font-size:30px;font-weight:700;line-height:1;}
.kpi .l{color:var(--muted);font-size:12px;margin-top:7px;text-transform:uppercase;letter-spacing:.4px;}
.kpi.flag .n{color:var(--sevred);}
.ctx{display:grid;grid-template-columns:repeat(3,1fr);gap:8px 22px;
  font-size:12.5px;color:var(--muted);margin-bottom:18px;}
.ctx b{color:var(--ink);font-weight:600;}
h2.sec{font-size:14px;text-transform:uppercase;letter-spacing:.6px;color:var(--muted);
  margin:22px 0 10px;border-bottom:1px solid var(--line);padding-bottom:6px;}
table{width:100%;border-collapse:collapse;font-size:13px;}
thead th{text-align:left;background:var(--surfalt);border-bottom:2px solid var(--line);
  padding:9px 10px;font-size:11.5px;text-transform:uppercase;letter-spacing:.4px;color:var(--muted);}
tbody td{padding:9px 10px;border-bottom:1px solid var(--line);vertical-align:top;}
tbody tr:last-child td{border-bottom:none;}
td.num{font-variant-numeric:tabular-nums;font-weight:700;text-align:right;white-space:nowrap;}
td.tier{white-space:nowrap;color:var(--muted);font-size:12px;}
.rag{display:inline-block;min-width:62px;text-align:center;padding:3px 8px;border-radius:5px;
  font-weight:700;font-size:11px;letter-spacing:.5px;border:1px solid;}
.rag.green{color:var(--green);background:var(--green-bg);border-color:var(--green);}
.rag.amber{color:var(--amber);background:var(--amber-bg);border-color:var(--amber);}
.rag.red{color:var(--red);background:var(--red-bg);border-color:var(--red);}
td.note{color:var(--muted);font-size:12px;}
.signoff{margin-top:26px;border-top:2px solid var(--ink);padding-top:16px;
  display:grid;grid-template-columns:1fr 1fr;gap:18px 30px;}
.signoff .field{border-bottom:1px solid var(--ink);padding-bottom:4px;min-height:34px;
  display:flex;align-items:flex-end;}
.signoff .lab{font-size:11px;text-transform:uppercase;letter-spacing:.5px;color:var(--muted);margin-bottom:3px;}
.attest{grid-column:1 / -1;font-size:12px;color:var(--muted);margin-top:4px;}
.footer{margin-top:20px;font-size:11px;color:var(--muted);border-top:1px solid var(--line);padding-top:10px;}
.warns{background:var(--amber-bg);border:1px solid var(--amber);border-radius:6px;
  padding:8px 12px;font-size:12px;color:var(--amber);margin-bottom:16px;}
@media print{body{background:#fff;}.page{box-shadow:none;border:none;margin:0;max-width:100%;}}
'@
    Add-B10Line '</style>'
    Add-B10Line '</head>'
    Add-B10Line '<body>'
    Add-B10Line (Get-GEReportThemeToggleHtml)
    Add-B10Line '<div class="page">'

    # Header + overall pill
    Add-B10Line '<header class="rpt">'
    Add-B10Line '  <div>'
    Add-B10Line ('    <h1>' + $tEsc + '</h1>')
    Add-B10Line '    <div class="sub">Access-review sign-off dashboard &mdash; aggregate review-cycle metrics across all groups and members</div>'
    Add-B10Line '  </div>'
    Add-B10Line '  <div class="overall">'
    Add-B10Line ('    <span class="pill ' + $overallStatus + '">' + (ConvertTo-B10HtmlSafe $overallLabel) + '</span>')
    Add-B10Line ('    <div class="meta">Overall RAG: ' + $ovBadge + '<br/>' + $redCount + ' red &middot; ' + $amberCount + ' amber</div>')
    Add-B10Line '  </div>'
    Add-B10Line '</header>'

    # KPI tiles
    Add-B10Line '<div class="kpis">'
    Add-B10Line ('  <div class="kpi"><div class="n">' + $kpiGroups + '</div><div class="l">Groups in Scope</div></div>')
    Add-B10Line ('  <div class="kpi"><div class="n">' + $kpiMembers + '</div><div class="l">Distinct Members</div></div>')
    $findingClass = if ($findingsTotal -gt 0) { 'kpi flag' } else { 'kpi' }
    Add-B10Line ('  <div class="' + $findingClass + '"><div class="n">' + $findingsTotal + '</div><div class="l">Findings (Total)</div></div>')
    Add-B10Line ('  <div class="kpi"><div class="n">' + $kpiPriv + '</div><div class="l">Privileged Members</div></div>')
    Add-B10Line '</div>'

    # Context strip
    Add-B10Line '<div class="ctx">'
    Add-B10Line ('  <div><b>Scope:</b> ' + (ConvertTo-B10HtmlSafe $scopeDomains) + '</div>')
    Add-B10Line ('  <div><b>Review completed:</b> ' + (ConvertTo-B10HtmlSafe $reviewDate) + '</div>')
    Add-B10Line ('  <div><b>Next review due:</b> ' + (ConvertTo-B10HtmlSafe $nextReview) + '</div>')
    Add-B10Line ('  <div><b>Review cadence:</b> Quarterly (90 days)</div>')
    Add-B10Line ('  <div><b>Report:</b> B10 Governance Executive Summary</div>')
    Add-B10Line ('  <div><b>Generated:</b> ' + (ConvertTo-B10HtmlSafe ($nowLocal.ToString('yyyy-MM-dd HH:mm:ss'))) + '</div>')
    Add-B10Line '</div>'

    # Metrics table
    Add-B10Line '<h2 class="sec">Metrics &amp; Thresholds</h2>'
    Add-B10Line '<table>'
    Add-B10Line '<thead><tr>'
    Add-B10Line '  <th>Metric</th><th>Risk Tier</th><th style="text-align:right;">Value</th><th>Target / Threshold</th><th>RAG</th><th>Notes</th>'
    Add-B10Line '</tr></thead>'
    Add-B10Line '<tbody>'
    foreach ($m in $metrics) {
        $rag = & $statusBadge $m.Status
        Add-B10Line '<tr>'
        Add-B10Line ('  <td>' + (ConvertTo-B10HtmlSafe $m.Name) + '</td>')
        Add-B10Line ('  <td class="tier">' + (ConvertTo-B10HtmlSafe $m.Tier) + '</td>')
        Add-B10Line ('  <td class="num">' + $m.Value + '</td>')
        Add-B10Line ('  <td>' + (ConvertTo-B10HtmlSafe $m.Target) + '</td>')
        Add-B10Line ('  <td><span class="rag ' + $m.Status + '">' + $rag + '</span></td>')
        Add-B10Line ('  <td class="note">' + (ConvertTo-B10HtmlSafe $m.Note) + '</td>')
        Add-B10Line '</tr>'
    }
    Add-B10Line '</tbody>'
    Add-B10Line '</table>'

    # Sign-off block
    Add-B10Line '<h2 class="sec">Review Completion &amp; Sign-Off</h2>'
    Add-B10Line '<div class="signoff">'
    Add-B10Line '  <div><div class="lab">Reviewer / Approver (print name)</div><div class="field">&nbsp;</div></div>'
    Add-B10Line '  <div><div class="lab">Title / Role</div><div class="field">&nbsp;</div></div>'
    Add-B10Line '  <div><div class="lab">Signature</div><div class="field">&nbsp;</div></div>'
    Add-B10Line ('  <div><div class="lab">Date signed</div><div class="field">' + (ConvertTo-B10HtmlSafe $reviewDate) + '</div></div>')
    Add-B10Line ('  <div class="attest">I attest that the access entitlements summarized above have been reviewed for the period ending <b>' + (ConvertTo-B10HtmlSafe $reviewDate) + '</b>. Overall determination: <b>' + (ConvertTo-B10HtmlSafe $overallLabel) + '</b>. Next scheduled review: <b>' + (ConvertTo-B10HtmlSafe $nextReview) + '</b>.</div>')
    Add-B10Line '</div>'

    # Footer
    Add-B10Line '<div class="footer">'
    Add-B10Line ('  Generated ' + (ConvertTo-B10HtmlSafe ($nowLocal.ToString('yyyy-MM-dd HH:mm:ss zzz'))) + ' &middot; Report B10 Governance Executive Summary &middot; account treatment: numbers-only (no member names or emails rendered) &middot; privileged-group and SoD figures are offline name-based heuristics.')
    Add-B10Line '</div>'

    Add-B10Line '</div>'  # .page
    Add-B10Line (Get-GEReportThemeScript)
    Add-B10Line '</body>'
    Add-B10Line '</html>'

    # --------------------------------------------------------------------------
    # Write output
    # --------------------------------------------------------------------------
    $outDir = Split-Path -Parent $OutputPath
    if ($outDir -and -not (Test-Path -LiteralPath $outDir)) {
        New-Item -ItemType Directory -Path $outDir -Force | Out-Null
    }

    $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($OutputPath, $sb.ToString(), $utf8NoBom)

    return $OutputPath
}
