<#
.SYNOPSIS
    B09 - Nested Membership / Effective-Access Audit (parameterized module)

.DESCRIPTION
    Renders a self-contained HTML report that reveals EFFECTIVE (transitive)
    membership hidden by group nesting, so reviewers certify effective access
    rather than direct-only membership.

    For every group it reports:
        - IsNested flag
        - direct MemberCount
        - effective (transitive) member count

    For nested groups it produces a Findings sub-table per group containing:
        - NestingPath breadcrumb ("GroupA > GroupB")
        - Direct vs Inherited per effective member
        - NestingDepth (longest chain depth)
        - Circular-reference flag (when a nesting cycle is detected)
        - Threshold note: WARN when NestingDepth >= 3

    accountTreatment = "counts-plus-expandable":
        Account-level detail (the per-member Direct/Inherited rows) is rendered
        as collapsed, expandable <details> blocks; headline numbers are counts.

    PowerShell 5.1 compatible. Dot-sources nothing. Modifies no repository file
    other than writing its own HTML output.
#>

function ConvertTo-B09HtmlSafe {
    param([object]$Text)
    if ($null -eq $Text) { return '' }
    $s = [string]$Text
    $s = $s -replace '&', '&amp;'
    $s = $s -replace '<', '&lt;'
    $s = $s -replace '>', '&gt;'
    $s = $s -replace '"', '&quot;'
    $s = $s -replace "'", '&#39;'
    return $s
}

function Get-B09Prop {
    param([object]$Obj, [string]$Name, $Default = $null)
    if ($null -eq $Obj) { return $Default }
    # Dual-mode: -FromCache passes hashtables; live enumeration passes objects.
    if ($Obj -is [System.Collections.IDictionary]) {
        if ($Obj.Contains($Name)) { return $Obj[$Name] }
        return $Default
    }
    $p = $Obj.PSObject.Properties[$Name]
    if ($null -eq $p) { return $Default }
    return $p.Value
}

function Export-NestedMembershipAuditReport {
    <#
    .SYNOPSIS
        Writes a B09 Nested Membership / Effective-Access Audit HTML report.

    .PARAMETER GroupResults
        Array of group result objects, each with shape:
          @{
            Data   = @{ Domain; GroupName; MemberCount; IsNested; Skipped; SkipReason;
                        DistinguishedName; NestedGroupDNs;
                        Members = @(@{ SamAccountName; DisplayName; Email; Enabled;
                                       DistinguishedName }) }
            Errors = @()
          }

    .PARAMETER OutputPath
        Destination .html path. Parent directory is created if absent.

    .PARAMETER Title
        Optional report title override.

    .PARAMETER Theme
        'dark' (default) or 'light'. Currently the report uses a dark palette
        regardless of this value (matching the source design); the parameter is
        accepted for API consistency with sibling generators.

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

        [Parameter()][string]$Title = 'B09 - Nested Membership / Effective-Access Audit',

        [Parameter()][ValidateSet('auto', 'dark', 'light')][string]$Theme = 'auto'
    )

    # -------------------------------------------------------------------------
    # Normalize group records & build indexes
    # -------------------------------------------------------------------------
    $nodes  = @{}
    $byDn   = @{}
    $byName = @{}
    $order  = New-Object System.Collections.ArrayList

    foreach ($g in $GroupResults) {
        $d = Get-B09Prop $g 'Data'
        if ($null -eq $d) { continue }

        $name = [string](Get-B09Prop $d 'GroupName')
        $dn   = [string](Get-B09Prop $d 'DistinguishedName')

        $nodeKey = if ($dn)   { $dn.ToLowerInvariant() }
                   elseif ($name) { 'name:' + $name.ToLowerInvariant() }
                   else { 'anon:' + [guid]::NewGuid().ToString() }

        $members    = @(Get-B09Prop $d 'Members')
        $nestedDns  = @(Get-B09Prop $d 'NestedGroupDNs')

        $node = [ordered]@{
            Key            = $nodeKey
            Name           = $name
            Domain         = [string](Get-B09Prop $d 'Domain')
            Dn             = $dn
            IsNestedFlag   = [bool](Get-B09Prop $d 'IsNested' $false)
            Skipped        = [bool](Get-B09Prop $d 'Skipped' $false)
            SkipReason     = [string](Get-B09Prop $d 'SkipReason')
            DeclaredMC     = Get-B09Prop $d 'MemberCount'
            DirectUsers    = New-Object System.Collections.ArrayList
            ChildGroupKeys = New-Object System.Collections.ArrayList
            ChildRawRefs   = New-Object System.Collections.ArrayList
            NestedDnRefs   = @($nestedDns)
        }

        foreach ($m in $members) { [void]$node.DirectUsers.Add($m) }

        $nodes[$nodeKey] = $node
        if ($dn)   { $byDn[$dn.ToLowerInvariant()]     = $nodeKey }
        if ($name) { $byName[$name.ToLowerInvariant()] = $nodeKey }
        [void]$order.Add($nodeKey)
    }

    # Second pass: resolve nesting edges
    foreach ($key in $order) {
        $node = $nodes[$key]

        foreach ($ndn in $node.NestedDnRefs) {
            if (-not $ndn) { continue }
            $lk = ([string]$ndn).ToLowerInvariant()
            if ($byDn.ContainsKey($lk)) {
                [void]$node.ChildGroupKeys.Add($byDn[$lk])
            } else {
                [void]$node.ChildRawRefs.Add([string]$ndn)
            }
        }

        # Defensive group-as-member detection
        $keepUsers = New-Object System.Collections.ArrayList
        foreach ($m in $node.DirectUsers) {
            $msam = [string](Get-B09Prop $m 'SamAccountName')
            $mdn  = [string](Get-B09Prop $m 'DistinguishedName')
            $childKey = $null
            if ($mdn -and $byDn.ContainsKey($mdn.ToLowerInvariant())) {
                $childKey = $byDn[$mdn.ToLowerInvariant()]
            } elseif ($msam -and $byName.ContainsKey($msam.ToLowerInvariant())) {
                $childKey = $byName[$msam.ToLowerInvariant()]
            }
            if ($childKey -and $childKey -ne $key) {
                [void]$node.ChildGroupKeys.Add($childKey)
            } else {
                [void]$keepUsers.Add($m)
            }
        }
        $node.DirectUsers = $keepUsers
    }

    # Reverse edges (parent tracking)
    foreach ($key in $order) { $nodes[$key].ParentKeys = New-Object System.Collections.ArrayList }
    foreach ($key in $order) {
        foreach ($ck in $nodes[$key].ChildGroupKeys) {
            if ($nodes.ContainsKey($ck)) { [void]$nodes[$ck].ParentKeys.Add($key) }
        }
    }

    # -------------------------------------------------------------------------
    # Transitive resolution per group (effective membership + nesting context)
    # -------------------------------------------------------------------------
    # Walk-Node is defined inside the function scope; uses $script: refs for
    # the per-root accumulators so that recursion works in PS 5.1.
    function Walk-B09Node {
        param(
            [string]$NodeKey,
            [int]$Depth,
            [System.Collections.ArrayList]$PathNames,
            [System.Collections.Generic.HashSet[string]]$Stack
        )

        $cur = $script:b09Nodes[$NodeKey]
        $isDirect = ($Depth -eq 0)

        foreach ($u in $cur.DirectUsers) {
            $sam  = [string](Get-B09Prop $u 'SamAccountName')
            $disp = [string](Get-B09Prop $u 'DisplayName')
            $idKey = if ($sam)  { $sam.ToLowerInvariant() }
                     elseif ($disp) { 'disp:' + $disp.ToLowerInvariant() }
                     else { 'anon:' + [guid]::NewGuid() }
            if (-not $script:b09Eff.ContainsKey($idKey)) {
                $script:b09Eff[$idKey] = [ordered]@{
                    Member  = $u
                    Direct  = $isDirect
                    ViaPath = if ($isDirect) { '(direct)' } else { ($PathNames -join ' > ') }
                }
            } else {
                if ($isDirect) {
                    $script:b09Eff[$idKey].Direct  = $true
                    $script:b09Eff[$idKey].ViaPath = '(direct)'
                }
            }
        }

        foreach ($ck in $cur.ChildGroupKeys) {
            if (-not $script:b09Nodes.ContainsKey($ck)) { continue }
            $childName = $script:b09Nodes[$ck].Name
            if ($Stack.Contains($ck)) {
                $script:b09Circ = $true
                $cyclePath = New-Object System.Collections.ArrayList
                foreach ($p in $PathNames) { [void]$cyclePath.Add($p) }
                [void]$cyclePath.Add($childName + ' (CYCLE)')
                [void]$script:b09Chains.Add(($cyclePath -join ' > '))
                continue
            }
            $newDepth = $Depth + 1
            if ($newDepth -gt $script:b09Depth.Value) { $script:b09Depth.Value = $newDepth }

            $np = New-Object System.Collections.ArrayList
            foreach ($p in $PathNames) { [void]$np.Add($p) }
            [void]$np.Add($childName)
            [void]$script:b09Chains.Add(($np -join ' > '))

            [void]$Stack.Add($ck)
            Walk-B09Node -NodeKey $ck -Depth $newDepth -PathNames $np -Stack $Stack
            [void]$Stack.Remove($ck)
        }
    }

    $script:b09Nodes = $nodes

    $analysis = @{}
    foreach ($rootKey in $order) {
        $root = $nodes[$rootKey]

        $script:b09Eff    = @{}
        $script:b09Circ   = $false
        $script:b09Chains = New-Object System.Collections.ArrayList
        $depthBox = [ref]0
        $script:b09Depth  = $depthBox

        $stack = New-Object 'System.Collections.Generic.HashSet[string]'
        [void]$stack.Add($rootKey)
        $startPath = New-Object System.Collections.ArrayList
        [void]$startPath.Add($root.Name)
        Walk-B09Node -NodeKey $rootKey -Depth 0 -PathNames $startPath -Stack $stack

        $effective      = $script:b09Eff
        $directCount    = @($root.DirectUsers).Count
        $effectiveCount = $effective.Count
        $inheritedCount = 0
        foreach ($k in $effective.Keys) { if (-not $effective[$k].Direct) { $inheritedCount++ } }

        $hasChildren = (@($root.ChildGroupKeys).Count -gt 0) -or (@($root.ChildRawRefs).Count -gt 0)
        $hasParents  = (@($root.ParentKeys).Count -gt 0)
        $isNested    = $root.IsNestedFlag -or $hasChildren -or $hasParents

        $analysis[$rootKey] = [ordered]@{
            Node            = $root
            IsNested        = $isNested
            HasChildren     = $hasChildren
            HasParents      = $hasParents
            DirectCount     = $directCount
            EffectiveCount  = $effectiveCount
            InheritedCount  = $inheritedCount
            NestingDepth    = $depthBox.Value
            Circular        = $script:b09Circ
            Effective       = $effective
            Chains          = @($script:b09Chains)
            WarnDepth       = ($depthBox.Value -ge 3)
        }
    }

    # -------------------------------------------------------------------------
    # Summary counts
    # -------------------------------------------------------------------------
    $totalGroups   = $order.Count
    $nestedKeys    = @($order | Where-Object { $analysis[$_].IsNested })
    $nestedCount   = $nestedKeys.Count
    $warnKeys      = @($order | Where-Object { $analysis[$_].WarnDepth })
    $warnCount     = $warnKeys.Count
    $circularKeys  = @($order | Where-Object { $analysis[$_].Circular })
    $circularCount = $circularKeys.Count
    $maxDepthAll   = 0
    foreach ($k in $order) { if ($analysis[$k].NestingDepth -gt $maxDepthAll) { $maxDepthAll = $analysis[$k].NestingDepth } }

    $generatedAt = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss zzz')
    $titleEsc    = ConvertTo-B09HtmlSafe $Title

    # -------------------------------------------------------------------------
    # HTML rendering
    # -------------------------------------------------------------------------
    $sb = New-Object System.Text.StringBuilder

    # Shared accessible theme: inherit the audited canonical palette into B09's local token names
    # (was dark-only) + author the light side; status chips use the solid AA badge tokens so they
    # are correct in BOTH themes. Runtime toggle + print-forces-light via the generator.
    $pal = Get-GEReportThemePalette
    $b09Light = [ordered]@{ bg = $pal.Light['bg']; panel = $pal.Light['surface']; panel2 = $pal.Light['surface-alt']; ink = $pal.Light['ink']; muted = $pal.Light['muted']; line = $pal.Light['line']; accent = $pal.Light['accent']; warn = $pal.Light['warn']; bad = $pal.Light['crit']; good = $pal.Light['ok']; chip = $pal.Light['surface-alt'] }
    $b09Dark  = [ordered]@{ bg = $pal.Dark['bg'];  panel = $pal.Dark['surface'];  panel2 = $pal.Dark['surface-alt'];  ink = $pal.Dark['ink'];  muted = $pal.Dark['muted'];  line = $pal.Dark['line'];  accent = $pal.Dark['accent'];  warn = $pal.Dark['warn'];  bad = $pal.Dark['crit'];  good = $pal.Dark['ok'];  chip = $pal.Dark['surface-alt'] }
    $themeBlock = Get-GEThemedRootCss -Light $b09Light -Dark $b09Dark -ExtraRootCss (Get-GEReportThemeBadgeCss)
    $themeAttr  = if ($Theme -eq 'dark' -or $Theme -eq 'light') { " data-theme=`"$Theme`"" } else { '' }

    $css = @"
<style>
  :root { color-scheme: light dark; }
$themeBlock
  *{box-sizing:border-box}
  body{margin:0;background:var(--bg);color:var(--ink);font:14px/1.5 "Segoe UI",Roboto,Arial,sans-serif}
  .wrap{max-width:1200px;margin:0 auto;padding:24px}
  h1{font-size:22px;margin:0 0 4px}
  h2{font-size:16px;margin:28px 0 10px;border-bottom:1px solid var(--line);padding-bottom:6px}
  .sub{color:var(--muted);margin:0 0 18px}
  .cards{display:flex;flex-wrap:wrap;gap:12px;margin:18px 0}
  .card{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:14px 16px;min-width:150px;flex:1}
  .card .n{font-size:26px;font-weight:700}
  .card .l{color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.04em}
  .card.warn .n{color:var(--warn)} .card.bad .n{color:var(--bad)} .card.good .n{color:var(--good)}
  .tabs{display:flex;gap:6px;margin:14px 0 0;border-bottom:1px solid var(--line)}
  .tab{padding:9px 16px;cursor:pointer;color:var(--muted);border:1px solid transparent;border-bottom:none;border-radius:8px 8px 0 0}
  .tab.active{color:var(--ink);background:var(--panel);border-color:var(--line)}
  .paneltab{display:none;background:var(--panel);border:1px solid var(--line);border-top:none;border-radius:0 0 10px 10px;padding:16px}
  .paneltab.active{display:block}
  table{width:100%;border-collapse:collapse;margin:4px 0 8px}
  th,td{text-align:left;padding:8px 10px;border-bottom:1px solid var(--line);vertical-align:top}
  th{color:var(--muted);font-weight:600;font-size:12px;text-transform:uppercase;letter-spacing:.03em}
  tr:hover td{background:var(--chip)}
  .chip{display:inline-block;padding:2px 8px;border-radius:999px;background:var(--chip);color:var(--ink);font-size:12px}
  .chip.nested{background:var(--chip);color:var(--accent)}
  .chip.flat{background:var(--chip);color:var(--muted)}
  .chip.warn{background:var(--badge-warn-bg);color:var(--badge-warn-ink)}
  .chip.bad{background:var(--badge-crit-bg);color:var(--badge-crit-ink)}
  .chip.good{background:var(--badge-ok-bg);color:var(--badge-ok-ink)}
  .crumb{font-family:Consolas,monospace;color:var(--accent)}
  details{margin:4px 0;background:var(--panel2);border:1px solid var(--line);border-radius:8px;padding:6px 10px}
  details>summary{cursor:pointer;color:var(--accent);outline:none}
  details table{margin-top:8px}
  .mono{font-family:Consolas,monospace}
  .note{background:var(--panel2);border-left:3px solid var(--warn);padding:10px 14px;border-radius:6px;margin:10px 0;color:var(--ink)}
  .empty{color:var(--muted);padding:18px;text-align:center;font-style:italic}
  .findbox{background:var(--panel2);border:1px solid var(--line);border-radius:10px;padding:12px 14px;margin:12px 0}
  .findbox h3{margin:0 0 6px;font-size:15px}
  .meta{color:var(--muted);font-size:12px}
  code{background:var(--chip);padding:1px 5px;border-radius:4px}
</style>
"@

    [void]$sb.AppendLine(('<!doctype html><html lang="en"{0}><head><meta charset="utf-8">' -f $themeAttr))
    [void]$sb.AppendLine('<meta name="viewport" content="width=device-width,initial-scale=1">')
    [void]$sb.AppendLine('<title>' + $titleEsc + '</title>')
    [void]$sb.AppendLine($css)
    [void]$sb.AppendLine('</head><body>')
    [void]$sb.AppendLine((Get-GEReportThemeToggleHtml))
    [void]$sb.AppendLine('<div class="wrap">')

    [void]$sb.AppendLine('<h1>' + $titleEsc + '</h1>')
    [void]$sb.AppendLine('<p class="sub">B09 &mdash; reveal effective (transitive) membership hidden by group nesting, so reviewers certify <strong>effective</strong> access rather than direct-only membership. Generated ' + (ConvertTo-B09HtmlSafe $generatedAt) + '.</p>')
    [void]$sb.AppendLine('<p class="meta">Groups evaluated: <span class="mono">' + $totalGroups + '</span></p>')

    # KPI cards
    $nestedCls   = if ($nestedCount)   { 'warn' } else { 'good' }
    $warnCls     = if ($warnCount)     { 'bad'  } else { 'good' }
    $circularCls = if ($circularCount) { 'bad'  } else { 'good' }
    [void]$sb.AppendLine('<div class="cards">')
    [void]$sb.AppendLine('<div class="card"><div class="n">' + $totalGroups + '</div><div class="l">Groups</div></div>')
    [void]$sb.AppendLine('<div class="card ' + $nestedCls + '"><div class="n">' + $nestedCount + '</div><div class="l">Nested groups</div></div>')
    [void]$sb.AppendLine('<div class="card ' + $warnCls + '"><div class="n">' + $warnCount + '</div><div class="l">Depth &ge; 3 (warn)</div></div>')
    [void]$sb.AppendLine('<div class="card ' + $circularCls + '"><div class="n">' + $circularCount + '</div><div class="l">Circular refs</div></div>')
    [void]$sb.AppendLine('<div class="card"><div class="n">' + $maxDepthAll + '</div><div class="l">Max nesting depth</div></div>')
    [void]$sb.AppendLine('</div>')

    # Threshold note
    [void]$sb.AppendLine('<div class="note"><strong>Threshold note:</strong> nesting depth <strong>&ge; 3</strong> is flagged as a warning. Deep nesting makes effective access hard for reviewers to reason about; certify the full <span class="crumb">NestingPath</span> chain, not just direct members.</div>')

    # Tabs
    [void]$sb.AppendLine('<div class="tabs">')
    [void]$sb.AppendLine('<div class="tab active" data-tab="findings" onclick="showTab(this)">Findings (nested only)</div>')
    [void]$sb.AppendLine('<div class="tab" data-tab="all" onclick="showTab(this)">All Groups (informational)</div>')
    [void]$sb.AppendLine('</div>')

    # ---- Findings tab (nested groups only) ----
    [void]$sb.AppendLine('<div class="paneltab active" id="tab-findings">')
    if ($nestedCount -eq 0) {
        [void]$sb.AppendLine('<div class="empty">No nested groups detected. All groups resolve to direct membership only &mdash; effective access equals direct membership.</div>')
    } else {
        foreach ($key in $nestedKeys) {
            $a = $analysis[$key]
            $n = $a.Node
            $gname     = ConvertTo-B09HtmlSafe $n.Name
            $depthChip = if ($a.WarnDepth) {
                '<span class="chip bad">depth ' + $a.NestingDepth + ' &mdash; WARN</span>'
            } else {
                '<span class="chip warn">depth ' + $a.NestingDepth + '</span>'
            }
            $circChip = if ($a.Circular) { ' <span class="chip bad">CIRCULAR</span>' } else { '' }

            [void]$sb.AppendLine('<div class="findbox">')
            [void]$sb.AppendLine('<h3>' + $gname + ' ' + $depthChip + $circChip + '</h3>')
            [void]$sb.AppendLine('<p class="meta">Domain: <span class="mono">' + (ConvertTo-B09HtmlSafe $n.Domain) + '</span> &nbsp;|&nbsp; Direct members: <strong>' + $a.DirectCount + '</strong> &nbsp;|&nbsp; Effective (transitive): <strong>' + $a.EffectiveCount + '</strong> &nbsp;|&nbsp; Inherited via nesting: <strong>' + $a.InheritedCount + '</strong></p>')

            # Nesting path breadcrumbs
            if (@($a.Chains).Count -gt 0) {
                [void]$sb.AppendLine('<p class="meta">Nesting paths:</p>')
                foreach ($chain in $a.Chains) {
                    [void]$sb.AppendLine('<div class="crumb">' + (ConvertTo-B09HtmlSafe $chain) + '</div>')
                }
            }
            if (@($n.ChildRawRefs).Count -gt 0) {
                foreach ($raw in $n.ChildRawRefs) {
                    [void]$sb.AppendLine('<div class="crumb">' + $gname + ' &gt; <span class="chip flat">unresolved: ' + (ConvertTo-B09HtmlSafe $raw) + '</span></div>')
                }
            }

            # Expandable per-member Direct/Inherited table (counts-plus-expandable)
            $eff = $a.Effective
            [void]$sb.AppendLine('<details><summary>Effective members &mdash; ' + $a.EffectiveCount + ' (' + $a.DirectCount + ' direct / ' + $a.InheritedCount + ' inherited)</summary>')
            if ($eff.Count -eq 0) {
                [void]$sb.AppendLine('<div class="empty">No resolved members.</div>')
            } else {
                [void]$sb.AppendLine('<table><thead><tr><th>SamAccountName</th><th>Display name</th><th>Email</th><th>Enabled</th><th>Access</th><th>Via (nesting path)</th></tr></thead><tbody>')
                $memberRows = New-Object System.Collections.ArrayList
                foreach ($mk in $eff.Keys) {
                    $e = $eff[$mk]
                    $m = $e.Member
                    [void]$memberRows.Add([pscustomobject]@{
                        Sam     = [string](Get-B09Prop $m 'SamAccountName')
                        Display = [string](Get-B09Prop $m 'DisplayName')
                        Email   = [string](Get-B09Prop $m 'Email')
                        Enabled = Get-B09Prop $m 'Enabled'
                        Direct  = [bool]$e.Direct
                        Via     = [string]$e.ViaPath
                    })
                }
                foreach ($r in ($memberRows | Sort-Object @{e={$_.Direct};Descending=$true}, Sam)) {
                    $accessChip = if ($r.Direct) { '<span class="chip good">Direct</span>' } else { '<span class="chip warn">Inherited</span>' }
                    $enChip     = if ($r.Enabled -eq $false) { '<span class="chip bad">Disabled</span>' } else { '<span class="chip">Enabled</span>' }
                    [void]$sb.AppendLine('<tr><td class="mono">' + (ConvertTo-B09HtmlSafe $r.Sam) + '</td><td>' + (ConvertTo-B09HtmlSafe $r.Display) + '</td><td class="mono">' + (ConvertTo-B09HtmlSafe $r.Email) + '</td><td>' + $enChip + '</td><td>' + $accessChip + '</td><td class="crumb">' + (ConvertTo-B09HtmlSafe $r.Via) + '</td></tr>')
                }
                [void]$sb.AppendLine('</tbody></table>')
            }
            [void]$sb.AppendLine('</details>')
            [void]$sb.AppendLine('</div>')
        }
    }
    [void]$sb.AppendLine('</div>')

    # ---- All Groups tab (topology / informational) ----
    [void]$sb.AppendLine('<div class="paneltab" id="tab-all">')
    [void]$sb.AppendLine('<table><thead><tr><th>Group</th><th>Domain</th><th>Nested?</th><th>Direct members</th><th>Effective members</th><th>Nesting depth</th><th>Circular?</th></tr></thead><tbody>')
    foreach ($key in $order) {
        $a = $analysis[$key]
        $n = $a.Node
        $nestedChip = if ($a.IsNested) { '<span class="chip nested">Nested</span>' } else { '<span class="chip flat">Flat</span>' }
        $depthCell  = if ($a.WarnDepth) {
            '<span class="chip bad">' + $a.NestingDepth + '</span>'
        } elseif ($a.NestingDepth -gt 0) {
            '<span class="chip warn">' + $a.NestingDepth + '</span>'
        } else { '0' }
        $circCell = if ($a.Circular) { '<span class="chip bad">Yes</span>' } else { 'No' }
        $effCell  = if ($a.EffectiveCount -ne $a.DirectCount) { '<strong>' + $a.EffectiveCount + '</strong>' } else { [string]$a.EffectiveCount }
        [void]$sb.AppendLine('<tr><td class="mono">' + (ConvertTo-B09HtmlSafe $n.Name) + '</td><td class="mono">' + (ConvertTo-B09HtmlSafe $n.Domain) + '</td><td>' + $nestedChip + '</td><td>' + $a.DirectCount + '</td><td>' + $effCell + '</td><td>' + $depthCell + '</td><td>' + $circCell + '</td></tr>')
    }
    [void]$sb.AppendLine('</tbody></table>')
    [void]$sb.AppendLine('<p class="meta">Effective member count differs from direct count only when membership is inherited through nested groups (shown in bold). In a flat directory these columns match.</p>')
    [void]$sb.AppendLine('</div>')

    # Footer + JS tab switcher
    [void]$sb.AppendLine('<p class="meta" style="margin-top:24px">Report B09 &mdash; account detail rendered as collapsed, expandable per-group blocks (accountTreatment: counts-plus-expandable). All names and emails HTML-escaped.</p>')

    $js = @'
<script>
function showTab(el){
  var tabs=document.querySelectorAll('.tab');for(var i=0;i<tabs.length;i++){tabs[i].classList.remove('active');}
  var panes=document.querySelectorAll('.paneltab');for(var j=0;j<panes.length;j++){panes[j].classList.remove('active');}
  el.classList.add('active');
  document.getElementById('tab-'+el.getAttribute('data-tab')).classList.add('active');
}
</script>
'@
    [void]$sb.AppendLine($js)
    [void]$sb.AppendLine((Get-GEReportThemeScript))
    [void]$sb.AppendLine('</div></body></html>')

    # -------------------------------------------------------------------------
    # Write output (UTF-8 no BOM)
    # -------------------------------------------------------------------------
    $outDir = Split-Path -Parent $OutputPath
    if ($outDir -and -not (Test-Path -LiteralPath $outDir)) {
        New-Item -ItemType Directory -Force -Path $outDir | Out-Null
    }
    [System.IO.File]::WriteAllText($OutputPath, $sb.ToString(), [System.Text.UTF8Encoding]::new($false))
    return $OutputPath
}
