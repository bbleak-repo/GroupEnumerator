<#
.SYNOPSIS
    RC08 - Privileged-Access Risk component. Flags DISABLED accounts that still hold
    membership in PRIVILEGED groups -- a classic critical governance finding (a
    deactivated or never-cleaned-up account retaining admin rights).
.DESCRIPTION
    Privileged groups are identified by a name heuristic (admins / operators / domain
    controllers / protected users / key & cert admins / privileged / root / sudo / etc.).
    This is a deliberately FOCUSED, high-confidence snapshot -- the exhaustive,
    authoritative privileged classification lives in the B03 baseline report (Privileged
    Group Review); RC08 is the quick at-a-glance risk surface. Disabled status
    is read straight from each member's Enabled flag, so this works on any enumeration
    (live or -FromCache) with no -DetectStale run required.

    Numbers-only headline + a table of the at-risk (privileged group -> disabled account)
    pairs, since naming the account is the actionable point of the finding.

    Options:
      MaxRows [int] - cap the at-risk table (default 100).
    Self-registers on load.
#>

function Test-RCPrivilegedName {
    # Focused privileged-name heuristic (aligned with, not identical to, B03's exhaustive
    # list -- RC08 is a snapshot, B03 is the authoritative review).
    param([string]$Name)
    if ([string]::IsNullOrWhiteSpace($Name)) { return $false }
    # Treat _ - . as word separators so naming-convention names like "GG_IT_Admins" or
    # "corp-domain-admins" match the \b...\b patterns ('_' is a regex word char, so it would
    # otherwise suppress the boundary before "Admins" and the group would be missed).
    $norm = ($Name -replace '[_\.\-]+', ' ')
    $patterns = @(
        '\bdomain\s*admins?\b', '\benterprise\s*admins?\b', '\bschema\s*admins?\b',
        '\badministrators?\b', '\badmins?\b', '\b\w*operators?\b', '\breplicator\b',
        '\bdns\s*admins?\b', '\bprotected\s*users?\b', '\bkey\s*admins?\b',
        '\bcert(ificate)?\s*(publishers?|admins?)\b', '\bgroup\s*policy\s*creator',
        '\bdomain\s*controllers?\b', '\bprivileged?\b', '\belevated?\b',
        '\bsuper\s*users?\b', '\bsudo(ers)?\b', '\broot\b', '\bglobal\s*admins?\b',
        '\bsecurity\s*admins?\b', '\btier\s*[01]\b'
    )
    foreach ($p in $patterns) { if ($norm -imatch $p) { return $true } }
    return $false
}

function New-RCPrivilegedPredicate {
    <#
    .SYNOPSIS
        Build a privileged-group predicate { param($name) -> [bool] } that environments can tailor.
        Test-RCPrivilegedName is name-pattern based (admin/operators/tier-0/...), so it MISSES
        privileged roles that don't contain those words (CyberArk, IAM, AWS, PAM, Vault, ...). This
        factory lets a caller add custom regex, replace the built-ins entirely, or treat EVERY group
        as privileged (for estates where all tracked roles are privileged).
    .PARAMETER ExtraPatterns
        Extra case-insensitive regex fragments, OR'd in (matched against the raw name AND a
        separator-normalised form, so 'GG_AWS_PowerUsers' matches 'AWS'). e.g. 'CyberArk','\bIAM\b','AWS','PAM','Vault'.
    .PARAMETER All
        Treat every non-empty group name as privileged.
    .PARAMETER ReplaceBuiltins
        Use ONLY ExtraPatterns; skip the built-in admin/operator detection.
    .OUTPUTS [scriptblock]
    #>
    [OutputType([scriptblock])]
    param(
        [string[]]$ExtraPatterns = @(),
        [switch]$All,
        [switch]$ReplaceBuiltins
    )
    $extra       = @($ExtraPatterns | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    $allFlag     = [bool]$All
    $useBuiltins = -not $ReplaceBuiltins
    # Capture the built-in detector as a scriptblock VARIABLE so GetNewClosure() snapshots it.
    # (GetNewClosure captures variables, not functions; without this the returned predicate fails
    # with "Test-RCPrivilegedName is not recognized" whenever it runs in a scope where RC08 was
    # dot-sourced at script scope rather than global.)
    $builtinFn = ${function:Test-RCPrivilegedName}
    return {
        param($Name)
        if ([string]::IsNullOrWhiteSpace($Name)) { return $false }
        if ($allFlag) { return $true }
        if ($useBuiltins -and (& $builtinFn $Name)) { return $true }
        if ($extra.Count -gt 0) {
            $norm = ($Name -replace '[_\.\-]+', ' ')
            foreach ($p in $extra) { try { if (($Name -imatch $p) -or ($norm -imatch $p)) { return $true } } catch { } }
        }
        return $false
    }.GetNewClosure()
}

function Get-RCPrivilegedRiskData {
    <#
    .SYNOPSIS
        Pure computation behind RC08: classify privileged-group members as at-risk
        (Disabled / Never logged in / Stale). Shared by the HTML component AND the scriptable
        governance gate (Invoke-PrivilegedRiskCheck.ps1) so the logic lives in one place.
    .OUTPUTS
        @{ PrivilegedGroups=[string[]]; AtRisk=@(@{Group;Domain;Sam;Status});
           DisabledCount; NeverCount; StaleCount; DistinctAtRisk; HasStaleData }
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param([hashtable]$Context, [scriptblock]$PrivilegedNamePredicate = $null)

    $enum = @($Context.Enumerated)

    # Optional stale enrichment: when a -DetectStale run supplied StaleResults, ALSO flag
    # privileged-group members that are STALE or NEVER-LOGGED-IN. The orchestrator flattens
    # StaleResults into Stale / NeverLoggedIn lists keyed by Domain|SamAccountName.
    $staleSet = New-Object 'System.Collections.Generic.HashSet[string]'
    $neverSet = New-Object 'System.Collections.Generic.HashSet[string]'
    $staleRes = Get-RCProp $Context 'StaleResults'
    $hasStale = $false
    if ($staleRes) {
        $hasStale = $true
        foreach ($s in @(Get-RCProp $staleRes 'Stale')) {
            if ($null -eq $s) { continue }
            [void]$staleSet.Add(('{0}|{1}' -f [string](Get-RCProp $s 'Domain'), [string](Get-RCProp $s 'SamAccountName')).ToLowerInvariant())
        }
        foreach ($n in @(Get-RCProp $staleRes 'NeverLoggedIn')) {
            if ($null -eq $n) { continue }
            [void]$neverSet.Add(('{0}|{1}' -f [string](Get-RCProp $n 'Domain'), [string](Get-RCProp $n 'SamAccountName')).ToLowerInvariant())
        }
    }

    $privGroups = New-Object System.Collections.Generic.List[object]
    $atRisk = New-Object System.Collections.Generic.List[object]
    $distinctAtRisk = New-Object 'System.Collections.Generic.HashSet[string]'
    foreach ($g in $enum) {
        $d = Get-RCProp $g 'Data'
        $name = [string](Get-RCProp $d 'GroupName')
        $isPriv = if ($PrivilegedNamePredicate) { try { [bool](& $PrivilegedNamePredicate $name) } catch { $false } } else { Test-RCPrivilegedName $name }
        if (-not $isPriv) { continue }
        $privGroups.Add($name)
        $gDomain = [string](Get-RCProp $d 'Domain')
        foreach ($m in @(Get-RCProp $d 'Members')) {
            if ($null -eq $m) { continue }
            $sam = [string](Get-RCProp $m 'SamAccountName')
            $isDisabled = ((Get-RCProp $m 'Enabled') -eq $false)
            $mDomain = [string](Get-RCProp $m 'Domain'); if ([string]::IsNullOrWhiteSpace($mDomain)) { $mDomain = $gDomain }
            $mKey = ('{0}|{1}' -f $mDomain, $sam).ToLowerInvariant()
            # Severity order: a disabled account is definitive; a never-used (never-logged-in)
            # privileged account is a likely-forgotten provisioning; stale is general inactivity.
            $isNever = (-not $isDisabled) -and ($neverSet.Count -gt 0) -and $neverSet.Contains($mKey)
            $isStale = (-not $isDisabled) -and (-not $isNever) -and ($staleSet.Count -gt 0) -and $staleSet.Contains($mKey)
            if ($isDisabled -or $isNever -or $isStale) {
                $status = if ($isDisabled) { 'Disabled' } elseif ($isNever) { 'Never logged in' } else { 'Stale' }
                $atRisk.Add([pscustomobject]@{ Group = $name; Domain = $gDomain; Sam = $sam; Status = $status })
                $key = if ([string]::IsNullOrWhiteSpace($sam)) { [string](Get-RCProp $m 'DistinguishedName') } else { $sam.ToLowerInvariant() }
                if (-not [string]::IsNullOrWhiteSpace($key)) { [void]$distinctAtRisk.Add($key) }
            }
        }
    }
    # NB: use .ToArray(), not @($list) -- @() on a List[object] of PSCustomObjects throws
    # "Argument types do not match" in PS 5.1 (piping the list is fine, bare @() is not).
    $atRiskArr = $atRisk.ToArray()
    $result = @{}
    $result['PrivilegedGroups'] = $privGroups.ToArray()
    $result['AtRisk']           = $atRiskArr
    $result['DisabledCount']    = @($atRiskArr | Where-Object { $_.Status -eq 'Disabled' }).Count
    $result['NeverCount']       = @($atRiskArr | Where-Object { $_.Status -eq 'Never logged in' }).Count
    $result['StaleCount']       = @($atRiskArr | Where-Object { $_.Status -eq 'Stale' }).Count
    $result['DistinctAtRisk']   = $distinctAtRisk.Count
    $result['HasStaleData']     = $hasStale
    return $result
}

function New-RCPrivilegedRiskComponent {
    [CmdletBinding()]
    [OutputType([string])]
    param([hashtable]$Context, [hashtable]$Options = @{}, [hashtable]$Palette)

    function _rcCard {
        param([object]$N, [string]$L, [string]$Cls = '')
        $c = if ($Cls) { " $Cls" } else { '' }
        return ('<div class="rc-card{0}"><div class="n">{1}</div><div class="l">{2}</div></div>' -f $c, $N, (ConvertTo-RCHtmlText $L))
    }

    $multiDomain = (@($Context.Domains).Count -ge 2)

    # Computation is shared with the scriptable gate -- see Get-RCPrivilegedRiskData.
    $data          = Get-RCPrivilegedRiskData -Context $Context
    $privGroups    = @($data.PrivilegedGroups)
    $atRisk        = @($data.AtRisk)
    $hasStale      = [bool]$data.HasStaleData
    $disabledCount = [int]$data.DisabledCount
    $neverCount    = [int]$data.NeverCount
    $staleCount    = [int]$data.StaleCount
    $distinctCount = [int]$data.DistinctAtRisk

    $cards = New-Object System.Text.StringBuilder
    [void]$cards.Append((_rcCard -N $privGroups.Count -L 'Privileged Groups' -Cls 'accent'))
    [void]$cards.Append((_rcCard -N $disabledCount -L 'Disabled In Privileged' -Cls $(if ($disabledCount -gt 0) { 'danger' } else { 'ok' })))
    if ($hasStale) {
        [void]$cards.Append((_rcCard -N $neverCount -L 'Never Logged In' -Cls $(if ($neverCount -gt 0) { 'danger' } else { 'ok' })))
        [void]$cards.Append((_rcCard -N $staleCount -L 'Stale In Privileged' -Cls $(if ($staleCount -gt 0) { 'warn' } else { 'ok' })))
    }
    [void]$cards.Append((_rcCard -N $distinctCount -L 'At-Risk Accounts' -Cls $(if ($distinctCount -gt 0) { 'danger' } else { 'ok' })))

    $maxRows = 100
    if ($Options.ContainsKey('MaxRows')) { try { $maxRows = [int]$Options['MaxRows'] } catch { } }

    $tableHtml = ''
    if ($atRisk.Count -gt 0) {
        $sorted = @($atRisk | Sort-Object Group, Sam)
        $truncNote = ''
        if ($sorted.Count -gt $maxRows) { $truncNote = ('<div class="rc-note" style="margin-top:10px;">Showing {0} of {1} at-risk memberships.</div>' -f $maxRows, $sorted.Count); $sorted = $sorted[0..($maxRows - 1)] }
        $domHead = if ($multiDomain) { '<th>Domain</th>' } else { '' }
        $rows = New-Object System.Text.StringBuilder
        foreach ($r in $sorted) {
            $domCell = if ($multiDomain) { ('<td>{0}</td>' -f (ConvertTo-RCHtmlText $r.Domain)) } else { '' }
            $badgeCls = if ($r.Status -eq 'Stale') { 'warn' } else { 'danger' }
            [void]$rows.AppendLine(('<tr><td>{0}</td>{1}<td>{2}</td><td><span class="rc-badge {3}">{4}</span></td></tr>' -f (ConvertTo-RCHtmlText $r.Group), $domCell, (ConvertTo-RCHtmlText $r.Sam), $badgeCls, (ConvertTo-RCHtmlText $r.Status)))
        }
        $tableHtml = @"
<table class="rc-table" style="margin-top:14px;">
<thead><tr><th>Privileged Group</th>$domHead<th>Account</th><th>Status</th></tr></thead>
<tbody>
$($rows.ToString())</tbody>
</table>
$truncNote
"@
    } else {
        $cleanWhat = if ($hasStale) { 'disabled, never-used, or stale accounts' } else { 'disabled accounts' }
        $tableHtml = ('<div class="rc-note" style="margin-top:12px;">No {0} found in privileged groups. (Privileged groups are identified by name heuristic; see the B03 baseline report for the authoritative review.)</div>' -f $cleanWhat)
    }

    return @"
<section class="rc-section">
<h2 class="rc-section-h">Privileged-Access Risk</h2>
<p class="rc-section-d">Disabled accounts &mdash; and, when a stale-detection run is available, never-logged-in and stale accounts &mdash; that still hold privileged-group membership: a critical access-governance finding. Privileged groups are matched by name heuristic; disabled status is read from member state (always available); never-logged-in and stale status come from the optional -DetectStale pass.</p>
<div class="rc-cards">$($cards.ToString())</div>
$tableHtml
</section>
"@
}

Register-RCComponent -Key 'privileged-risk' -DisplayName 'Privileged-Access Risk' `
    -Description 'Disabled accounts still in privileged groups (critical governance finding).' `
    -FunctionName 'New-RCPrivilegedRiskComponent' -Requires @('GroupResults') `
    -DefaultOptions @{ MaxRows = 100 }
