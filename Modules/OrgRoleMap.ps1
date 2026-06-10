<#
.SYNOPSIS
    Org Role Map - build a manager->group->user COUNT view over an org tree derived from AD's
    `manager` attribute, so an auditor can see WHERE in the business privileged (or otherwise
    tracked) group roles concentrate. Counts only (no user names) by default.

.DESCRIPTION
    Three strictly separated layers (only the AD/IO layer touches LDAP):

      1. PURE      - Build-OrgTree, Get-OrgRoleAggregate, Add-OrgDeltaToTree, ConvertTo-OrgMemberRefs
                     (+ helpers). Hashtable in -> hashtable out. No AD, no file IO. Unit-testable
                     with fixtures (Tests/Test-OrgRoleMap.ps1).
      2. RENDER    - New-OrgRoleMapHtml. Aggregate -> self-contained HTML string (inline SVG spatial
                     map + static accessible/printable table + B00 accessible theme). Written
                     UTF-8 no-BOM.
      3. AD/IO     - Resolve-ManagerChain, Build-OrgTreeCache. Walk manager chains upward via the
                     pooled LDAP context (Modules/ADLdap.ps1) and persist State/org-tree.json. Runs
                     ONLY on FULL builds; DELTA/ADHOC reuse the cached artifact without a DC.

    Privilege classification is INJECTED as a scriptblock predicate (reuse Test-RCPrivilegedName from
    RC08) so this module is not coupled to the detector. Mirrors the membership-churn feature shape.

.NOTES
    Module   : OrgRoleMap
    Pure fns : ConvertTo-OrgMemberRefs, Build-OrgTree, Get-OrgRoleAggregate, Add-OrgDeltaToTree
    Render   : New-OrgRoleMapHtml
    AD/IO    : Resolve-ManagerChain, Build-OrgTreeCache
#>

# Synthetic node that collects records that cannot be placed in the hierarchy (no manager + no
# reports, cross-domain/cyclic/orphaned, or members missing from the org-tree cache). A large
# bucket here is itself a finding (service accounts / orphaned privileged accounts).
$script:OrgUnmanagedDn    = '__unmanaged__'
$script:OrgUnmanagedLabel = '(No manager listed - service or executive accounts)'

# -----------------------------------------------------------------------------
# Dual-mode accessors (hashtable from -FromCache, or PSObject/PSCustomObject from live/JSON)
# -----------------------------------------------------------------------------
function Get-OrgProp {
    param([object]$Object, [string]$Name)
    if ($null -eq $Object) { return $null }
    if ($Object -is [System.Collections.IDictionary]) {
        if ($Object.Contains($Name)) { return $Object[$Name] }
        return $null
    }
    $p = $Object.PSObject.Properties[$Name]
    if ($null -eq $p) { return $null }
    return $p.Value
}

function ConvertTo-OrgHtmlText {
    param([object]$Value)
    if ($null -eq $Value) { return '' }
    $s = [string]$Value
    $s = $s.Replace('&', '&amp;').Replace('<', '&lt;').Replace('>', '&gt;').Replace('"', '&quot;').Replace("'", '&#39;')
    return $s
}

function Get-OrgNodeEntries {
    # Enumerate a Nodes map regardless of whether it's a hashtable (fixtures / -FromCache) or a
    # PSCustomObject (ConvertFrom-Json). Returns array of @{ Key; Node }.
    param([object]$Nodes)
    if ($null -eq $Nodes) { return @() }
    if ($Nodes -is [System.Collections.IDictionary]) {
        return @($Nodes.Keys | ForEach-Object { @{ Key = [string]$_; Node = $Nodes[$_] } })
    }
    return @($Nodes.PSObject.Properties | ForEach-Object { @{ Key = $_.Name; Node = $_.Value } })
}

function Get-OrgDnKey {
    # Stable join key: lowercased DN. DN is globally unique across domains; Sam is not.
    # Escaping-insensitive: a value/manager DN escaped as hex (\2C) and the same DN escaped as a
    # character (\,) must produce the SAME key, or a person whose `manager` attribute and
    # `distinguishedName` differ only in escape style (common with comma-in-name accounts like
    # "CN=Last\, First,OU=People") would fail to link to their manager and become a phantom
    # (unknown) root. Normalize hex escapes (\XX) to the character-escape form so \2C == \, etc.
    # This only changes escape STYLE (no unescaping), so it cannot collide distinct DNs.
    param([string]$Dn)
    if ([string]::IsNullOrWhiteSpace($Dn)) { return '' }
    $s = $Dn.Trim()
    if ($s.IndexOf('\') -ge 0) {
        $s = [regex]::Replace($s, '\\([0-9A-Fa-f]{2})', { param($m) '\' + [char][Convert]::ToInt32($m.Groups[1].Value, 16) })
    }
    return $s.ToLowerInvariant()
}

# -----------------------------------------------------------------------------
# PURE: flatten GroupResults -> one membership ref per (member, tracked group)
# -----------------------------------------------------------------------------
function ConvertTo-OrgMemberRefs {
    <#
    .SYNOPSIS  Flatten enumerator/cache GroupResults into membership refs the aggregator consumes.
    .PARAMETER GroupResults  Array of @{ Data = @{ GroupName; Domain; Members = @(records) }; ... }.
    .PARAMETER PrivilegedNamePredicate  Optional { param($name) [bool] } to mark a group privileged.
    .PARAMETER TrackedGroups  Optional explicit group-name allow-list (wildcards supported). When
               omitted, all groups are included (caller may pass -PrivilegedOnly to filter later).
    .PARAMETER PrivilegedOnly  Keep only refs whose group is privileged (needs the predicate).
    .OUTPUTS  Array of @{ Dn; DnKey; Sam; Domain; Display; Group; Privileged }.
    #>
    param(
        [object[]]$GroupResults,
        [scriptblock]$PrivilegedNamePredicate = $null,
        [string[]]$TrackedGroups = $null,
        [switch]$PrivilegedOnly
    )
    $refs = New-Object System.Collections.Generic.List[object]
    foreach ($g in $GroupResults) {
        if ($null -eq $g) { continue }
        $d = Get-OrgProp $g 'Data'
        if ($null -eq $d) { continue }
        if ([bool](Get-OrgProp $d 'Skipped')) { continue }

        $group  = [string](Get-OrgProp $d 'GroupName')
        $domain = [string](Get-OrgProp $d 'Domain')
        if ([string]::IsNullOrWhiteSpace($group)) { continue }

        if ($TrackedGroups -and $TrackedGroups.Count -gt 0) {
            $match = $false
            foreach ($t in $TrackedGroups) { if ($group -like $t) { $match = $true; break } }
            if (-not $match) { continue }
        }

        $isPriv = $false
        if ($PrivilegedNamePredicate) { try { $isPriv = [bool](& $PrivilegedNamePredicate $group) } catch { $isPriv = $false } }
        if ($PrivilegedOnly -and -not $isPriv) { continue }

        $members = Get-OrgProp $d 'Members'
        if (-not $members) { continue }
        foreach ($m in @($members)) {
            $dn  = [string](Get-OrgProp $m 'DistinguishedName')
            $sam = [string](Get-OrgProp $m 'SamAccountName')
            $refs.Add([pscustomobject]@{
                Dn         = $dn
                DnKey      = (Get-OrgDnKey $dn)
                Sam        = $sam
                Domain     = $domain
                Display    = [string](Get-OrgProp $m 'DisplayName')
                Group      = $group
                Privileged = $isPriv
            }) | Out-Null
        }
    }
    return , $refs.ToArray()
}

# -----------------------------------------------------------------------------
# PURE: build a (single-hop) org-tree cache straight from cache/enumeration records
# (no DC). Members carry ManagerDN (enumerated with -IncludeAttributes manager); managers
# who are themselves members link up multi-level naturally, others become Resolved=$false stubs.
# -----------------------------------------------------------------------------
function ConvertTo-OrgTreeCacheFromRecords {
    param([Parameter(Mandatory = $true)][AllowEmptyCollection()][object[]]$GroupResults)
    $nodes = @{}
    $mgrDns = New-Object System.Collections.Generic.List[string]
    foreach ($g in $GroupResults) {
        $d = Get-OrgProp $g 'Data'; if ($null -eq $d) { continue }
        $dom = [string](Get-OrgProp $d 'Domain')
        foreach ($m in @(Get-OrgProp $d 'Members')) {
            if ($null -eq $m) { continue }
            $dn = [string](Get-OrgProp $m 'DistinguishedName'); if ([string]::IsNullOrWhiteSpace($dn)) { continue }
            $mgr = [string](Get-OrgProp $m 'ManagerDN'); if (-not $mgr) { $mgr = [string](Get-OrgProp $m 'ManagerDn') }
            $en = Get-OrgProp $m 'Enabled'; $en = if ($null -eq $en) { $true } else { [bool]$en }
            $k = Get-OrgDnKey $dn
            # real records win over any stub already created for this DN
            $mailVal = [string](Get-OrgProp $m 'Mail'); if (-not $mailVal) { $mailVal = [string](Get-OrgProp $m 'Email') }
            $nodes[$k] = @{ Dn = $dn; Sam = [string](Get-OrgProp $m 'SamAccountName'); Display = [string](Get-OrgProp $m 'DisplayName'); Domain = $dom; Enabled = $en; ManagerDn = $mgr; Resolved = $true; Synthetic = $false; EmployeeId = [string](Get-OrgProp $m 'EmployeeID'); Upn = [string](Get-OrgProp $m 'UserPrincipalName'); Mail = $mailVal; ObjectGuid = [string](Get-OrgProp $m 'ObjectGuid') }
            if ($mgr) { [void]$mgrDns.Add($mgr) }
        }
    }
    foreach ($mdn in $mgrDns) {
        $k = Get-OrgDnKey $mdn
        if (-not $nodes.ContainsKey($k)) { $nodes[$k] = @{ Dn = $mdn; Sam = ''; Display = ''; Domain = (Get-OrgDomainFromDn $mdn); Enabled = $true; ManagerDn = $null; Resolved = $false; Synthetic = $true; EmployeeId = ''; Upn = ''; Mail = ''; ObjectGuid = '' } }
    }
    return @{ Metadata = @{ Version = '1.0'; BuiltUtc = ((Get-Date).ToUniversalTime().ToString('o')); BuiltByMode = 'FromRecords-SingleHop'; DepthCap = 1; NodeCount = $nodes.Count; DomainsResolved = @(); DomainsUnreachable = @(); Issues = @('single-hop-from-cache') }; Nodes = $nodes }
}

# -----------------------------------------------------------------------------
# PURE: service-account predicate { param($Dn,$Sam,$Display) -> [bool] }
# -----------------------------------------------------------------------------
function New-OrgServiceAccountPredicate {
    <#
    .SYNOPSIS  Build a predicate that flags service accounts so a no-manager service account reads
               as EXPECTED rather than a data-quality gap. Matches by containing OU and/or by a
               SamAccountName/displayName regex.
    .PARAMETER OrgUnits      OU names whose members are service accounts, e.g. 'ServiceAccounts','Svc Accounts'.
    .PARAMETER NamePatterns  Regex fragments matched against sAMAccountName and displayName, e.g. 'svc[-_]','\bsa-'.
    .OUTPUTS [scriptblock]
    #>
    [OutputType([scriptblock])]
    param([string[]]$OrgUnits = @(), [string[]]$NamePatterns = @())
    $ous  = @($OrgUnits     | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | ForEach-Object { [regex]::Escape($_.Trim()) })
    $pats = @($NamePatterns | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    return {
        param($Dn, $Sam, $Display)
        if ($Dn) { foreach ($ou in $ous) { if ($Dn -imatch ('(?i)(?:^|,)OU=' + $ou + '(?:,|$)')) { return $true } } }
        foreach ($p in $pats) { try { if (($Sam -and ($Sam -imatch $p)) -or ($Display -and ($Display -imatch $p))) { return $true } } catch { } }
        return $false
    }.GetNewClosure()
}

# -----------------------------------------------------------------------------
# PURE: assemble the in-memory org tree from the flat org-tree cache
# -----------------------------------------------------------------------------
function Build-OrgTree {
    <#
    .SYNOPSIS  Reconstruct parent->child edges from a flat DN-keyed org-tree cache.
    .PARAMETER OrgTreeCache  @{ Metadata=@{...}; Nodes=@{ "<dnlower>" = @{ Dn;Sam;Display;Domain;
               Enabled;ManagerDn;Resolved;Synthetic } } } (hashtable or ConvertFrom-Json object).
    .OUTPUTS  @{ NodesByDn=@{dnkey=node}; RootDns=@(); UnmanagedBucketDn; Issues=@() }
              where each node gains ChildDns=@() and Depth (int).
              No-manager nodes WITH reports become roots; no-manager leaves and cyclic/unreachable
              nodes attach to the synthetic __unmanaged__ bucket. Counts-safe (no member data here).
    #>
    param(
        [Parameter(Mandatory = $true)][object]$OrgTreeCache,
        [Parameter()][scriptblock]$ServiceAccountPredicate = $null
    )

    $issues  = New-Object System.Collections.Generic.List[string]
    $byDn    = @{}

    foreach ($e in (Get-OrgNodeEntries (Get-OrgProp $OrgTreeCache 'Nodes'))) {
        $n   = $e.Node
        $dn  = [string](Get-OrgProp $n 'Dn')
        $key = if ([string]::IsNullOrWhiteSpace($e.Key)) { Get-OrgDnKey $dn } else { $e.Key.ToLowerInvariant() }
        if ([string]::IsNullOrWhiteSpace($key)) { continue }
        $mdn  = [string](Get-OrgProp $n 'ManagerDn')
        $sam  = [string](Get-OrgProp $n 'Sam')
        $disp = [string](Get-OrgProp $n 'Display')
        # Classify service accounts (OU / name pattern) so a no-manager service account is read as
        # EXPECTED, not a data-quality gap. Tag is computed here and rolled up in the aggregate.
        $isSvc = $false
        if ($ServiceAccountPredicate) { try { $isSvc = [bool](& $ServiceAccountPredicate $dn $sam $disp) } catch { $isSvc = $false } }
        $byDn[$key] = @{
            Dn            = $dn
            DnKey         = $key
            Sam           = $sam
            Display       = $disp
            Domain        = [string](Get-OrgProp $n 'Domain')
            Enabled       = $(if ($null -eq (Get-OrgProp $n 'Enabled')) { $true } else { [bool](Get-OrgProp $n 'Enabled') })
            ManagerDn     = $mdn
            ManagerDnKey  = (Get-OrgDnKey $mdn)
            Resolved      = $(if ($null -eq (Get-OrgProp $n 'Resolved')) { $true } else { [bool](Get-OrgProp $n 'Resolved') })
            ChildDns      = (New-Object System.Collections.Generic.List[string])
            Depth         = -1
            IsUnmanaged   = $false
            IsServiceAccount = $isSvc
        }
    }

    # Synthetic unmanaged bucket
    $byDn[$script:OrgUnmanagedDn] = @{
        Dn = '__UNMANAGED__'; DnKey = $script:OrgUnmanagedDn; Sam = ''; Display = $script:OrgUnmanagedLabel
        Domain = ''; Enabled = $true; ManagerDn = $null; ManagerDnKey = ''
        Resolved = $true; ChildDns = (New-Object System.Collections.Generic.List[string]); Depth = 0; IsUnmanaged = $true
    }

    # Build parent->child edges; collect no/dangling-manager nodes as root candidates.
    $rootCandidates = New-Object System.Collections.Generic.List[string]
    foreach ($key in @($byDn.Keys)) {
        if ($key -eq $script:OrgUnmanagedDn) { continue }
        $node = $byDn[$key]
        $mk   = $node.ManagerDnKey
        if ($mk -and $byDn.ContainsKey($mk)) {
            [void]$byDn[$mk].ChildDns.Add($key)
        } else {
            if ($mk) { [void]$issues.Add("dangling-manager:$($node.Dn)") }  # manager set but not in cache
            [void]$rootCandidates.Add($key)
        }
    }

    # Root candidates WITH reports = real org roots; childless ones -> unmanaged bucket.
    $roots = New-Object System.Collections.Generic.List[string]
    foreach ($key in $rootCandidates) {
        if ($byDn[$key].ChildDns.Count -gt 0) {
            [void]$roots.Add($key)
        } else {
            [void]$byDn[$script:OrgUnmanagedDn].ChildDns.Add($key)
            $byDn[$key].IsUnmanaged = $true
        }
    }

    # Assign depth via BFS from roots, then from the unmanaged bucket. One shared visited set so
    # cyclic edges can't loop and every node is reached exactly once.
    $visited = New-Object 'System.Collections.Generic.HashSet[string]'
    $bfs = {
        param($startKey, $startDepth)
        $queue = New-Object System.Collections.Generic.Queue[object]
        if (-not $visited.Add($startKey)) { return }
        $byDn[$startKey].Depth = $startDepth
        $queue.Enqueue($startKey)
        while ($queue.Count -gt 0) {
            $k = $queue.Dequeue()
            foreach ($c in $byDn[$k].ChildDns) {
                if ($visited.Add($c)) { $byDn[$c].Depth = $byDn[$k].Depth + 1; $queue.Enqueue($c) }
            }
        }
    }
    foreach ($r in $roots) { & $bfs $r 0 }

    # Any real node still unvisited (and not already parked under unmanaged as a no-manager leaf)
    # is part of a cycle / unreachable subtree -> attach to unmanaged.
    foreach ($key in @($byDn.Keys)) {
        if ($key -eq $script:OrgUnmanagedDn) { continue }
        if (-not $visited.Contains($key) -and -not $byDn[$key].IsUnmanaged) {
            [void]$issues.Add("cycle-or-orphan:$($byDn[$key].Dn)")
            [void]$byDn[$script:OrgUnmanagedDn].ChildDns.Add($key)
            $byDn[$key].IsUnmanaged = $true
        }
    }
    & $bfs $script:OrgUnmanagedDn 0   # depths for the unmanaged subtree (visited-guarded)

    return @{
        NodesByDn         = $byDn
        RootDns           = $roots.ToArray()
        UnmanagedBucketDn = $script:OrgUnmanagedDn
        Issues            = $issues.ToArray()
    }
}

# -----------------------------------------------------------------------------
# PURE: per-account manager-chain health (the 7-state classifier, P1)
# -----------------------------------------------------------------------------
function Get-OrgChainHealth {
    <#
    .SYNOPSIS  Classify one AD account's manager chain as a routing CONTROL: walk upward from the
               account toward the DECLARED OrgTop (cycle-guarded, per-hop Enabled) and return the
               chain state + whether an access review could route to a valid independent approver.
    .DESCRIPTION
        PURE: hashtable/PSCustomObject in -> [pscustomobject] out. No AD, no IO, no Get-Date, no
        closures. The caller (Invoke-OrgRoleMap / Export-AdReconciliationModel) resolves config
        OrgTopSam / -OrgTop param to a DN, then to a DnKey, and passes it as -OrgTopDnKey; this
        declared top is the ONLY thing that distinguishes Healthy from OrphanSubRoot (research
        principle: the org top is declared, not inferred).

        Walk idiom mirrors Resolve-ManagerChain (HashSet visited + DepthCap; advance via the node's
        ManagerDn DN string -> Get-OrgDnKey to find the parent node). Dual-mode node access via
        Get-OrgProp so it works on hashtable fixtures (-FromCache) AND ConvertFrom-Json objects.
        Enabled defaults to $true (mirrors Build-OrgTree). A manager is "not found" when its DnKey is
        absent from the map OR its node is a Resolved=$false stub (an unresolvable/deleted manager DN).

      ChainState precedence (first match wins):
        1. Cyclic           - the upward walk revisits a DN (or the start DnKey is empty/unknown loop).
        2. ManagerNotFound  - a hop's manager DN is set but unresolvable (absent / Resolved=$false stub).
        3. OrgTop           - the start account IS the declared OrgTop (top of the one sanctioned tree).
        4. NoManager        - the start account has no manager and is NOT the OrgTop (worst routing).
        5. terminal reached - the walk ends at a no-manager node:
             terminal == OrgTop -> ManagerDisabledInChain (some hop disabled) else Healthy
             terminal != OrgTop -> OrphanSubRoot (skip-level dead-ends below the real top)

      SkipLevelViable is TRUE only when the chain STRICTLY ABOVE the first break is non-empty, every
      node in it is Enabled, and it tops out at the declared OrgTop -- i.e. escalation past the break
      still reaches a valid independent approver. For a clean Healthy chain there is no break, so the
      "above the break" segment is the chain above the account: viable when that segment is non-empty,
      fully enabled, and reaches OrgTop. OrgTop itself and a bare NoManager have nothing above them.

    .PARAMETER Nodes        DN-keyed node map (hashtable from -FromCache, or PSCustomObject from
                            ConvertFrom-Json). Each node: Dn, ManagerDn (raw DN string), Enabled,
                            Resolved. This is the cache's .Nodes collection (NOT Build-OrgTree output).
    .PARAMETER DnKey        The account's DnKey (already Get-OrgDnKey'd, but re-normalized defensively).
    .PARAMETER OrgTopDnKey  The declared org top's DN or DnKey (re-normalized via Get-OrgDnKey). Empty
                            string => no declared top => any clean terminal reads as OrphanSubRoot.
    .PARAMETER DepthCap     Max hops before bailing (mirrors Resolve-ManagerChain's guard). Default 50.
    .OUTPUTS  [pscustomobject] { DnKey; ChainState; BreakReason; BreakDepth; SkipLevelViable;
              ChainToTop (string[], CEO-down); ReachesOrgTop; Depth; HasDisabledHop }.
              HasDisabledHop is TRUE when ANY node in the walked chain is disabled, INDEPENDENT of the
              ChainState (which only reports ManagerDisabledInChain when the chain also reaches OrgTop).
    #>
    [OutputType([pscustomobject])]
    param(
        [object]$Nodes,
        [string]$DnKey,
        [string]$OrgTopDnKey = '',
        [int]$DepthCap = 50
    )

    $startKey = Get-OrgDnKey $DnKey
    $topKey   = Get-OrgDnKey $OrgTopDnKey

    # Lookup helper (dual-mode): DnKey -> node object (or $null).
    $getNode = {
        param([string]$k)
        if ([string]::IsNullOrWhiteSpace($k)) { return $null }
        if ($null -eq $Nodes) { return $null }
        if ($Nodes -is [System.Collections.IDictionary]) {
            if ($Nodes.Contains($k)) { return $Nodes[$k] }
            return $null
        }
        $p = $Nodes.PSObject.Properties[$k]
        if ($null -eq $p) { return $null }
        return $p.Value
    }
    # A node counts as a real, resolved manager when present AND not a Resolved=$false stub.
    $isResolvedNode = {
        param($node)
        if ($null -eq $node) { return $false }
        $r = Get-OrgProp $node 'Resolved'
        if ($null -eq $r) { return $true }   # default resolved (mirror Build-OrgTree)
        return [bool]$r
    }
    $nodeEnabled = {
        param($node)
        $e = Get-OrgProp $node 'Enabled'
        if ($null -eq $e) { return $true }   # default enabled (mirror Build-OrgTree line 239)
        return [bool]$e
    }

    # Result scaffold.
    $state         = 'Healthy'
    $breakReason   = $null
    $breakDepth    = $null
    $skipViable    = $false
    $reachesTop    = $false
    $startNode     = & $getNode $startKey

    # Degenerate: the account itself isn't a resolvable node -> treat as ManagerNotFound at depth 0.
    if (-not (& $isResolvedNode $startNode)) {
        return [pscustomobject]@{
            DnKey = $startKey; ChainState = 'ManagerNotFound'
            BreakReason = 'start-account-unresolved'; BreakDepth = 0
            SkipLevelViable = $false; ChainToTop = @(); ReachesOrgTop = $false; Depth = 0
            HasDisabledHop = $false
        }
    }

    # Walk UPWARD collecting the chain (account-up order). Mirror Resolve-ManagerChain's guard.
    $visited   = New-Object 'System.Collections.Generic.HashSet[string]'
    $chainUp   = New-Object System.Collections.Generic.List[string]   # [account, mgr, mgr2, ... terminal]
    $enabledUp = New-Object System.Collections.Generic.List[bool]     # parallel Enabled per chain node
    $current   = $startKey
    $depth     = 0
    $cyclic    = $false
    $notFound  = $false

    while ($current -and $depth -lt $DepthCap) {
        if (-not $visited.Add($current)) { $cyclic = $true; break }
        $node = & $getNode $current
        if (-not (& $isResolvedNode $node)) {
            # A manager DN that points at an absent node / unresolved stub. (The start node is already
            # guaranteed resolved above, so this only fires for a manager hop.)
            $notFound = $true
            break
        }
        [void]$chainUp.Add($current)
        [void]$enabledUp.Add([bool](& $nodeEnabled $node))
        $mgrDn  = [string](Get-OrgProp $node 'ManagerDn')
        $mgrKey = Get-OrgDnKey $mgrDn
        if (-not $mgrKey) { break }                 # terminal: no manager
        if ($mgrKey -eq $current) { $cyclic = $true; break }  # self-managed = cycle
        $current = $mgrKey
        $depth++
    }
    if ($depth -ge $DepthCap -and $current -and -not $cyclic -and -not $notFound) {
        # Ran past the cap without terminating -> treat the unbounded chain as a cycle (data-integrity).
        $cyclic = $true
    }

    # Terminal node = last successfully-walked node (top of the resolved chain), if any.
    $terminalKey = if ($chainUp.Count -gt 0) { $chainUp[$chainUp.Count - 1] } else { '' }
    $anyDisabled = $false
    foreach ($en in $enabledUp) { if (-not $en) { $anyDisabled = $true; break } }

    # ---- Classify by documented precedence -------------------------------------------------------
    if ($cyclic) {
        $state = 'Cyclic'; $breakReason = 'chain-revisits-dn'
        $breakDepth = ($chainUp.Count - 1); if ($breakDepth -lt 0) { $breakDepth = 0 }
    }
    elseif ($notFound) {
        $state = 'ManagerNotFound'; $breakReason = 'manager-dn-unresolvable'
        $breakDepth = $chainUp.Count   # break occurs at the hop just above the last resolved node
    }
    elseif ($startKey -and $topKey -and $startKey -eq $topKey) {
        $state = 'OrgTop'; $reachesTop = $true
    }
    else {
        # Did the start account even have a manager? (chainUp[0] is the account itself)
        $startNoMgr = $false
        if ($chainUp.Count -ge 1) {
            $sn = & $getNode $chainUp[0]
            $startNoMgr = [string]::IsNullOrWhiteSpace([string](Get-OrgProp $sn 'ManagerDn'))
        }
        if ($startNoMgr) {
            $state = 'NoManager'; $breakReason = 'no-manager-and-not-org-top'; $breakDepth = 0
        }
        elseif ($topKey -and $terminalKey -eq $topKey) {
            $reachesTop = $true
            if ($anyDisabled) { $state = 'ManagerDisabledInChain'; $breakReason = 'manager-disabled-in-chain' }
            else { $state = 'Healthy' }
        }
        else {
            # Reached a no-manager terminal that is NOT the declared top (or no top declared).
            $state = 'OrphanSubRoot'; $breakReason = 'terminal-not-org-top'
            $breakDepth = ($chainUp.Count - 1); if ($breakDepth -lt 0) { $breakDepth = 0 }
        }
    }

    # ChainToTop: CEO-down DN-key path (reverse of the upward walk).
    $chainToTop = @($chainUp.ToArray())
    [array]::Reverse($chainToTop)

    # ---- SkipLevelViable: is the chain STRICTLY ABOVE the break a valid escalation surface? -------
    # Find the index (in account-up order) of the first broken node. For a disabled-in-chain break
    # that's the first disabled node; for a clean Healthy chain there is no break -> use the account
    # itself (index 0) so "above the break" = the managers above the account.
    if ($state -eq 'Healthy' -or $state -eq 'ManagerDisabledInChain') {
        $breakIdx = -1
        for ($i = 0; $i -lt $enabledUp.Count; $i++) { if (-not $enabledUp[$i]) { $breakIdx = $i; break } }
        if ($breakIdx -lt 0) { $breakIdx = 0 }   # Healthy: nothing disabled -> measure above the account
        # Segment strictly above the break: indices (breakIdx+1 .. end).
        $aboveFrom = $breakIdx + 1
        if ($aboveFrom -le ($chainUp.Count - 1)) {
            $segOk = $true
            for ($i = $aboveFrom; $i -lt $chainUp.Count; $i++) { if (-not $enabledUp[$i]) { $segOk = $false; break } }
            $topsAtOrgTop = ($topKey -and ($terminalKey -eq $topKey))
            $skipViable = ($segOk -and $topsAtOrgTop)
        } else {
            $skipViable = $false   # nothing above -> no skip-level target
        }
    }
    else {
        $skipViable = $false
    }

    return [pscustomobject]@{
        DnKey           = $startKey
        ChainState      = $state
        BreakReason     = $breakReason
        BreakDepth      = $breakDepth
        SkipLevelViable = [bool]$skipViable
        ChainToTop      = $chainToTop
        ReachesOrgTop   = [bool]$reachesTop
        Depth           = ($chainUp.Count - 1)
        # HasDisabledHop: a standalone control-gap flag — TRUE when ANY node in the walked chain is
        # disabled, INDEPENDENT of overall reachability. The ManagerDisabledInChain ChainState only
        # fires when the chain also reaches OrgTop, so a disabled hop inside an otherwise-broken chain
        # (OrphanSubRoot/Cyclic/ManagerNotFound) would silently lose its MGR_DISABLED_IN_CHAIN finding
        # if callers keyed off ChainState alone. This flag lets the export fire that finding on ANY
        # disabled hop (drift catalog sec.6: "a hop is disabled"), regardless of chain reachability.
        HasDisabledHop  = [bool]$anyDisabled
    }
}

# -----------------------------------------------------------------------------
# PURE: build the versioned AD reconciliation model (Phase 2 — the product)
# -----------------------------------------------------------------------------
function Export-AdReconciliationModel {
    <#
    .SYNOPSIS  Build a stable, mergeable, per-identity AD reconciliation model (3 collections + ranked
               join keys + recon scaffold + pre-aggregated summary) and optionally emit it as versioned
               UTF-8 no-BOM JSON + a CSV twin. This is the AD leg of the AD<->ISC<->HR reconciliation.
    .DESCRIPTION
        PURE: dictionaries/arrays in -> [pscustomobject] out (+ optional file IO when -JsonPath/-CsvPath
        set). No AD, no Get-Date, no closures over external state. The function only READS the input
        dictionaries (never mutates them — same 'no node mutation' contract upheld by Get-OrgChainHealth).

        Mirrors architecture sec.5. Three identity-keyed collections (ISC Identity/Account/Entitlement
        shape):
          identities[]   — one per AD account (cache .Nodes), the source-of-truth.
          managerEdges[] — child->parent edge per identity with a resolved manager present in the map.
          accessGrants[] — one per MemberRef (the named access evidence).

        DETERMINISM IS THE CONTRACT (byte-stable diffs run-over-run):
          - identities sorted by dnKey; accessGrants by (groupKey,dnKey); managerEdges by
            (childDnKey,parentDnKey). All DN keys via Get-OrgDnKey.
          - objectGuid is the stable anchor: it is a FIELD per identity, but identities are KEYED/SORTED
            by dnKey, so a rename that keeps the GUID but changes the DN re-sorts deterministically and
            stays ONE identity (no add/remove churn).
          - Every hashtable that becomes a JSON object uses [ordered]@{} so key order is fixed; list
            items are [pscustomobject] (literal property order). JSON newlines normalized to "`n" before
            writing so re-run bytes match regardless of ConvertTo-Json line endings.

        joinKeyResolved RANKS employeeID > mail > upn > samDomain, recording source+confidence by reusing
        the Modules/UserCorrelation.ps1 tiers (email/employeeID = High, upn = Medium, sam = Low):
          employeeId -> source 'employeeID'        confidence 'High'
          mail       -> source 'mail'              confidence 'High'
          upn        -> source 'userPrincipalName' confidence 'Medium'
          samDomain  -> source 'samDomain'         confidence 'Low'  (always non-empty -> never 'None').

        SCAFFOLD ONLY (P2): recon.findings stays [] and summary.headline.privilegedUnreviewable stays 0;
        Phase 3a fills findings/headline/provenance additively. iscReviewerEmployeeId/iscActive/hrActive
        are declared null (AD fills its side only).

    .PARAMETER OrgTreeCache  @{ Metadata; Nodes } — the SAME cache shape Get-OrgChainHealth/Build-OrgTree
                             consume. .Nodes is the DN-keyed node map carrying Dn/Sam/Display/Domain/
                             Enabled/ManagerDn/Resolved/Synthetic/EmployeeId/Upn/ObjectGuid. Identities
                             source-of-truth (hashtable from -FromCache OR ConvertFrom-Json object).
    .PARAMETER MemberRefs    Output of ConvertTo-OrgMemberRefs (Dn,DnKey,Sam,Domain,Display,Group,
                             Privileged). Source for accessGrants[] AND the per-identity privileged overlay.
    .PARAMETER GroupResults  Optional raw GroupResults (refs already carry Group+Domain+Privileged; prefer refs).
    .PARAMETER OrgTopDnKey   Declared OrgTop (DN or key); passed straight to Get-OrgChainHealth per identity.
    .PARAMETER PrivilegedNamePredicate  Group-name predicate { param($name)->[bool] } (already applied to
                             refs.Privileged; kept for parity/future).
    .PARAMETER JoinKeyAttribute  The configured primary join key name (default 'employeeID'); drives the
                             joinKeyCoveragePct denominator/source match. Pure passthrough.
    .PARAMETER JsonPath      If set, write UTF-8 no-BOM JSON here.
    .PARAMETER CsvPath       If set, write the identities CSV twin here.
    .PARAMETER ToolVersion   Caller-supplied version string stamped into generated.toolVersion (NOT Get-Date
                             — kept PURE/deterministic).
    .OUTPUTS  [pscustomobject] model (returned regardless of whether files were written).
    #>
    [OutputType([pscustomobject])]
    param(
        [object]$OrgTreeCache,
        [object[]]$MemberRefs = @(),
        [object[]]$GroupResults = @(),
        [string]$OrgTopDnKey = '',
        [scriptblock]$PrivilegedNamePredicate = $null,
        [string]$JoinKeyAttribute = 'employeeID',
        [string]$JsonPath = '',
        [string]$CsvPath = '',
        [string]$ToolVersion = '',
        # ---- P3a per-source provenance (PURE passthrough; the impure boundary computes these) --------
        [string]$SnapshotAsOfUtc = '',   # caller-supplied; NOT Get-Date inside the function
        [string]$ExtractedAtUtc  = '',   # caller-supplied
        [string]$Scope           = '',   # group set / forest scope label
        [string]$ConfigHash      = '',   # caller computes SHA-256 of effective config
        [string]$ContentHash     = ''    # caller computes SHA-256 of the names/CSV artifact
    )

    $nodes = Get-OrgProp $OrgTreeCache 'Nodes'

    # ---- Index MemberRefs by identity DnKey: privileged overlay + per-identity grant-key list -------
    # groupKey = lowercased group name (the stable cross-source access key).
    $refsByDn   = @{}   # dnKey -> List[ref]
    foreach ($r in @($MemberRefs)) {
        if ($null -eq $r) { continue }
        $rk = [string](Get-OrgProp $r 'DnKey')
        if ([string]::IsNullOrWhiteSpace($rk)) { $rk = Get-OrgDnKey ([string](Get-OrgProp $r 'Dn')) }
        if ([string]::IsNullOrWhiteSpace($rk)) { continue }
        if (-not $refsByDn.ContainsKey($rk)) { $refsByDn[$rk] = New-Object System.Collections.Generic.List[object] }
        [void]$refsByDn[$rk].Add($r)
    }

    # ---- Resolve a ranked join key (employeeID > mail > upn > samDomain) ------------------------------
    $resolveJoinKey = {
        param([string]$EmpId, [string]$Mail, [string]$Upn, [string]$SamDomain)
        if (-not [string]::IsNullOrWhiteSpace($EmpId)) { return [ordered]@{ value = $EmpId;     source = 'employeeID';        confidence = 'High'   } }
        if (-not [string]::IsNullOrWhiteSpace($Mail))  { return [ordered]@{ value = $Mail;      source = 'mail';              confidence = 'High'   } }
        if (-not [string]::IsNullOrWhiteSpace($Upn))   { return [ordered]@{ value = $Upn;       source = 'userPrincipalName'; confidence = 'Medium' } }
        return [ordered]@{ value = $SamDomain; source = 'samDomain'; confidence = 'Low' }
    }

    # Derive the first OU= RDN from a DN ('' when none). DN-parse only, no escaping changes.
    $firstOu = {
        param([string]$Dn)
        if ([string]::IsNullOrWhiteSpace($Dn)) { return '' }
        $m = [regex]::Match($Dn, '(?i)(?:^|,)OU=([^,]+)')
        if ($m.Success) { return $m.Groups[1].Value }
        return ''
    }

    # ---- ChainState counts scaffold: fully-populated over the 7 states (stable JSON keys) ------------
    $chainStates = @('OrgTop', 'Healthy', 'ManagerDisabledInChain', 'NoManager', 'OrphanSubRoot', 'Cyclic', 'ManagerNotFound')
    $chainStateCounts = [ordered]@{}
    foreach ($s in $chainStates) { $chainStateCounts[$s] = 0 }

    # ---- Build identities[] (one per cache node) + managerEdges[] ------------------------------------
    $identities = New-Object System.Collections.Generic.List[object]
    $edges      = New-Object System.Collections.Generic.List[object]
    $joinKeyMatchCount = 0   # identities whose resolved source == the configured join key
    $idTotal = 0

    # ---- P3a confirmed AD-only findings: per-code tallies + headline + unmatchedAd staging ----------
    # findingCounts keys in FIXED declared order (JSON byte-stability); all six pre-populated at 0.
    $findingCounts = [ordered]@{
        CHAIN_BROKEN           = 0
        PRIV_UNREVIEWABLE      = 0
        MGR_DISABLED_IN_CHAIN  = 0
        JOINKEY_MISSING        = 0
        AD_NOT_IN_HR           = 0
        MAIL_NE_UPN            = 0
    }
    $privUnreviewableCount = 0
    $unmatchedAd = New-Object System.Collections.Generic.List[object]

    foreach ($e in (Get-OrgNodeEntries $nodes)) {
        $node  = $e.Node
        $dn    = [string](Get-OrgProp $node 'Dn')
        $dnKey = if ([string]::IsNullOrWhiteSpace($e.Key)) { Get-OrgDnKey $dn } else { (Get-OrgDnKey $e.Key) }
        if ([string]::IsNullOrWhiteSpace($dnKey)) { continue }

        # ---- Skip synthetic / unresolved manager STUB nodes (NOT real AD accounts) -------------------
        # The real CLI paths (ConvertTo-OrgTreeCacheFromRecords + the live deep walk) fabricate a
        # Resolved=$false / Synthetic=$true stub for every manager DN that isn't itself an enumerated
        # member. Architecture sec.5 defines identities[] as "one per AD account"; a manager stub is not
        # an account. Emitting it would: (1) create a phantom identity with sam='' whose joinKeyResolved
        # falls to {source:'samDomain'} with an EMPTY value — violating the documented "samDomain always
        # non-empty -> never None" invariant; (2) fabricate JOINKEY_MISSING/AD_NOT_IN_HR/CHAIN_BROKEN
        # findings and an empty-sam unmatchedAd row; (3) inflate collectionCounts/recordCount/findingCounts
        # and the joinKeyCoveragePct denominator. So skip such nodes entirely (additive; resolved nodes
        # — Resolved absent => default true, or Resolved=$true — are unaffected).
        $resolvedProp  = Get-OrgProp $node 'Resolved'
        $isResolved    = if ($null -eq $resolvedProp) { $true } else { [bool]$resolvedProp }
        $syntheticProp = Get-OrgProp $node 'Synthetic'
        $isSynthetic   = if ($null -eq $syntheticProp) { $false } else { [bool]$syntheticProp }
        if ((-not $isResolved) -or $isSynthetic) { continue }

        $sam     = [string](Get-OrgProp $node 'Sam')
        $domain  = [string](Get-OrgProp $node 'Domain')
        $display = [string](Get-OrgProp $node 'Display')
        $empId   = [string](Get-OrgProp $node 'EmployeeId')
        $upn     = [string](Get-OrgProp $node 'Upn')
        $mail    = [string](Get-OrgProp $node 'Mail')   # staged onto node (record path: member.Email; live path: LDAP mail)
        $guid    = [string](Get-OrgProp $node 'ObjectGuid')
        $en      = Get-OrgProp $node 'Enabled'; $enabled = if ($null -eq $en) { $true } else { [bool]$en }
        $ou      = & $firstOu $dn
        $samDomain = if ($sam) { "$domain\$sam" } else { '' }

        # Privileged overlay: TRUE if ANY MemberRef for this dnKey is privileged.
        $privileged = $false
        $idGrantKeys = New-Object System.Collections.Generic.List[string]
        if ($refsByDn.ContainsKey($dnKey)) {
            foreach ($r in $refsByDn[$dnKey]) {
                if ([bool](Get-OrgProp $r 'Privileged')) { $privileged = $true }
                $gk = ([string](Get-OrgProp $r 'Group')).ToLowerInvariant()
                if ($gk) { [void]$idGrantKeys.Add($gk) }
            }
        }
        $myGrantKeys = @($idGrantKeys | Sort-Object -Unique)

        # Manager block: look up the manager node via Get-OrgDnKey(ManagerDn).
        $mgrDn  = [string](Get-OrgProp $node 'ManagerDn')
        $mgrKey = Get-OrgDnKey $mgrDn
        $mgrNode = $null
        if ($mgrKey) {
            if ($nodes -is [System.Collections.IDictionary]) { if ($nodes.Contains($mgrKey)) { $mgrNode = $nodes[$mgrKey] } }
            else { $mp = $nodes.PSObject.Properties[$mgrKey]; if ($mp) { $mgrNode = $mp.Value } }
        }
        $mgrResolved = $false
        $mgrEmpId    = ''
        $mgrEnabled  = $true
        if ($null -ne $mgrNode) {
            $mr = Get-OrgProp $mgrNode 'Resolved'
            $mgrResolved = if ($null -eq $mr) { $true } else { [bool]$mr }
            if ($mgrResolved) { $mgrEmpId = [string](Get-OrgProp $mgrNode 'EmployeeId') }
            $me = Get-OrgProp $mgrNode 'Enabled'; $mgrEnabled = if ($null -eq $me) { $true } else { [bool]$me }
        }

        # Chain health (declared OrgTop distinguishes Healthy from OrphanSubRoot).
        $health = Get-OrgChainHealth -Nodes $nodes -DnKey $dnKey -OrgTopDnKey $OrgTopDnKey
        $state  = [string]$health.ChainState
        if ($chainStateCounts.Contains($state)) { $chainStateCounts[$state] = $chainStateCounts[$state] + 1 }

        $jk = & $resolveJoinKey $empId $mail $upn $samDomain
        # joinKeyCoveragePct KPI: an 'employeeID'-source hit means the configured JoinKeyAttribute was
        # populated. GroupEnumerator.ps1 maps the configured attribute (employeeID by default, but also
        # employeeNumber / a custom extensionAttribute per architecture sec.3) UPSTREAM into the node's
        # EmployeeId field, so the ranked source label is always the literal 'employeeID' regardless of
        # which attribute name was configured. Treat that 'employeeID' source as satisfying ANY configured
        # JoinKeyAttribute; also accept an exact source==JoinKeyAttribute match for non-default cases where
        # a later tier happens to be named after the configured attribute. (Was: literal-'employeeID'
        # branch only fired when JoinKeyAttribute -ieq 'employeeID', collapsing coverage to 0% for custom
        # join keys even when every account carried it.)
        if ([string]$jk.source -eq 'employeeID') { $joinKeyMatchCount++ }
        elseif ([string]$jk.source -eq $JoinKeyAttribute) { $joinKeyMatchCount++ }
        $idTotal++

        # ---- P3a confirmed AD-only findings (process language, no blame; status always 'confirmed') --
        # Each finding: FIXED key order code/severity/status/message/subjectDnKey/subjectJoinKey.
        # CHAIN_BROKEN underlies PRIV_UNREVIEWABLE (privileged overlay). Determinism: sorted by code below.
        $idFindings = New-Object System.Collections.Generic.List[object]
        $subjectJk  = [string]$jk.value
        $empMissing = [string]::IsNullOrWhiteSpace($empId)
        # The chain is "broken" (cannot route a review to OrgTop) when it does not reach the declared top
        # AND the account is not the OrgTop itself. NoManager/OrphanSubRoot/Cyclic/ManagerNotFound qualify;
        # ManagerDisabledInChain still reachesOrgTop=true so it is NOT a CHAIN_BROKEN (handled separately).
        $chainBroken = ((-not $health.ReachesOrgTop) -and ($state -ne 'OrgTop'))

        if ($empMissing) {
            $sev = if ($privileged) { 'High' } else { 'Medium' }
            $idFindings.Add([pscustomobject]@{
                code = 'JOINKEY_MISSING'; severity = $sev; status = 'confirmed'
                message = 'No employeeID present; cross-source join falls back to a weaker key.'
                subjectDnKey = $dnKey; subjectJoinKey = $subjectJk
            }) | Out-Null
            $findingCounts['JOINKEY_MISSING'] = $findingCounts['JOINKEY_MISSING'] + 1

            # AD_NOT_IN_HR: no HR/SuccessFactors anchor key (proxy = no employeeID for AD-only P3a).
            $idFindings.Add([pscustomobject]@{
                code = 'AD_NOT_IN_HR'; severity = 'Medium'; status = 'confirmed'
                message = 'AD account has no HR anchor key; staged for HR reconciliation.'
                subjectDnKey = $dnKey; subjectJoinKey = $subjectJk
            }) | Out-Null
            $findingCounts['AD_NOT_IN_HR'] = $findingCounts['AD_NOT_IN_HR'] + 1
            $unmatchedAd.Add([pscustomobject]@{
                dnKey = $dnKey; objectGuid = $guid; sam = $sam; samDomain = $samDomain; reason = 'no-hr-anchor-key'
            }) | Out-Null
        }

        if ($chainBroken) {
            $idFindings.Add([pscustomobject]@{
                code = 'CHAIN_BROKEN'; severity = 'High'; status = 'confirmed'
                message = ('Manager chain does not reach the declared org top (state {0}; {1}); the access review cannot route to an independent approver.' -f $state, $(if ($health.BreakReason) { $health.BreakReason } else { 'no-route' }))
                subjectDnKey = $dnKey; subjectJoinKey = $subjectJk
            }) | Out-Null
            $findingCounts['CHAIN_BROKEN'] = $findingCounts['CHAIN_BROKEN'] + 1

            if ($privileged) {
                # PRIV_UNREVIEWABLE: the headline overlay (CHAIN_BROKEN AND privileged). Fires IN ADDITION.
                $idFindings.Add([pscustomobject]@{
                    code = 'PRIV_UNREVIEWABLE'; severity = 'Critical'; status = 'confirmed'
                    message = 'Privileged account whose access review cannot route to a valid approver (broken manager chain).'
                    subjectDnKey = $dnKey; subjectJoinKey = $subjectJk
                }) | Out-Null
                $findingCounts['PRIV_UNREVIEWABLE'] = $findingCounts['PRIV_UNREVIEWABLE'] + 1
                $privUnreviewableCount++
            }
        }

        # MGR_DISABLED_IN_CHAIN fires on ANY disabled hop in the chain, INDEPENDENT of overall
        # reachability (drift catalog sec.6: "a hop is disabled"). Get-OrgChainHealth only assigns the
        # ManagerDisabledInChain ChainState when the chain ALSO reaches OrgTop; a disabled hop inside an
        # otherwise-broken chain (OrphanSubRoot/Cyclic/ManagerNotFound) would silently lose this confirmed
        # SOX finding if we keyed off the state alone. So key off the standalone HasDisabledHop flag — it
        # co-fires alongside CHAIN_BROKEN when both gaps are present in the same chain.
        if ([bool]$health.HasDisabledHop) {
            $idFindings.Add([pscustomobject]@{
                code = 'MGR_DISABLED_IN_CHAIN'; severity = 'Medium'; status = 'confirmed'
                message = 'A manager in the chain is disabled; a hop needs time-bound remediation regardless of whether the chain reaches the org top.'
                subjectDnKey = $dnKey; subjectJoinKey = $subjectJk
            }) | Out-Null
            $findingCounts['MGR_DISABLED_IN_CHAIN'] = $findingCounts['MGR_DISABLED_IN_CHAIN'] + 1
        }

        if ((-not [string]::IsNullOrWhiteSpace($mail)) -and (-not [string]::IsNullOrWhiteSpace($upn)) -and ($mail -ine $upn)) {
            $idFindings.Add([pscustomobject]@{
                code = 'MAIL_NE_UPN'; severity = 'Low'; status = 'confirmed'
                message = 'mail and userPrincipalName diverge; the email-based cross-source join surface is weaker.'
                subjectDnKey = $dnKey; subjectJoinKey = $subjectJk
            }) | Out-Null
            $findingCounts['MAIL_NE_UPN'] = $findingCounts['MAIL_NE_UPN'] + 1
        }

        $idFindingsSorted = @($idFindings | Sort-Object -Property code)

        $identities.Add([pscustomobject]@{
            dnKey       = $dnKey
            objectGuid  = $guid
            sam         = $sam
            domain      = $domain
            ou          = $ou
            displayName = $display
            joinKeys    = [ordered]@{ employeeId = $empId; mail = $mail; upn = $upn; samDomain = $samDomain }
            joinKeyResolved = [ordered]@{ value = [string]$jk.value; source = [string]$jk.source; confidence = [string]$jk.confidence }
            enabled     = $enabled
            privileged  = $privileged
            manager     = [ordered]@{ dnKey = $mgrKey; employeeId = $mgrEmpId; resolved = $mgrResolved }
            chain       = [ordered]@{
                toTop           = @($health.ChainToTop)
                depth           = [int]$health.Depth
                state           = $state
                breakReason     = $health.BreakReason
                breakDepth      = $health.BreakDepth
                skipLevelViable = [bool]$health.SkipLevelViable
                reachesOrgTop   = [bool]$health.ReachesOrgTop
            }
            accessGrants = $myGrantKeys
            recon       = [ordered]@{
                adManagerEmployeeId    = $mgrEmpId
                iscReviewerEmployeeId  = $null
                iscActive              = $null
                hrActive               = $null
                findings               = @($idFindingsSorted)
            }
        }) | Out-Null

        # managerEdge: only when the manager node is present AND resolved (a real parent in the map).
        if ($mgrKey -and $null -ne $mgrNode -and $mgrResolved) {
            $depthFromTop = if ($null -ne $health.Depth) { [int]$health.Depth } else { -1 }
            $edges.Add([pscustomobject]@{
                childDnKey       = $dnKey
                childEmployeeId  = $empId
                parentDnKey      = $mgrKey
                parentEmployeeId = $mgrEmpId
                childEnabled     = $enabled
                parentEnabled    = $mgrEnabled
                depthFromTop     = $depthFromTop
            }) | Out-Null
        }
    }

    # ---- Build top-level accessGrants[] (one per MemberRef) ------------------------------------------
    $grants = New-Object System.Collections.Generic.List[object]
    foreach ($r in @($MemberRefs)) {
        if ($null -eq $r) { continue }
        $rk = [string](Get-OrgProp $r 'DnKey')
        if ([string]::IsNullOrWhiteSpace($rk)) { $rk = Get-OrgDnKey ([string](Get-OrgProp $r 'Dn')) }
        $gname = [string](Get-OrgProp $r 'Group')
        $grants.Add([pscustomobject]@{
            dnKey      = $rk
            groupKey   = $gname.ToLowerInvariant()
            groupName  = $gname
            domain     = [string](Get-OrgProp $r 'Domain')
            privileged = [bool](Get-OrgProp $r 'Privileged')
            nested     = $false
            viaGroup   = ''
        }) | Out-Null
    }

    # ---- SORT all three collections (the determinism contract) --------------------------------------
    $identitiesSorted = @($identities | Sort-Object -Property dnKey)
    $edgesSorted      = @($edges | Sort-Object -Property childDnKey, parentDnKey)
    $grantsSorted     = @($grants | Sort-Object -Property groupKey, dnKey)
    $unmatchedAdSorted = @($unmatchedAd | Sort-Object -Property dnKey)

    # ---- joinKeyCoveragePct: % of identities whose resolved source is the configured join key --------
    $coveragePct = if ($idTotal -gt 0) { [int][math]::Round((($joinKeyMatchCount / $idTotal) * 100), 0) } else { 0 }

    $summary = [ordered]@{
        byDivision        = @()
        chainStateCounts  = $chainStateCounts
        headline          = [ordered]@{ privilegedUnreviewable = $privUnreviewableCount }
        joinKeyCoveragePct = $coveragePct
        findingCounts     = $findingCounts
    }

    $model = [pscustomobject]@{
        schemaVersion = '1.0.0'
        generated     = [ordered]@{
            toolVersion      = $ToolVersion
            collectionCounts = [ordered]@{
                identities   = @($identitiesSorted).Count
                managerEdges = @($edgesSorted).Count
                accessGrants = @($grantsSorted).Count
                unmatchedAd  = @($unmatchedAdSorted).Count
            }
            # ---- P3a per-source provenance (AD filled; ISC/HR declared-but-empty) ----
            provenance = [ordered]@{
                ad  = [ordered]@{ sourceSystem = 'AD';  authority = 'downstream';    snapshotAsOfUtc = $SnapshotAsOfUtc; extractedAtUtc = $ExtractedAtUtc; toolVersion = $ToolVersion; scope = $Scope; recordCount = @($identitiesSorted).Count; configHash = $ConfigHash; contentHash = $ContentHash }
                isc = [ordered]@{ sourceSystem = 'ISC'; authority = 'downstream';    snapshotAsOfUtc = $null;            extractedAtUtc = $null;           toolVersion = $null;        scope = $null;   recordCount = $null;                          configHash = $null;       contentHash = $null }
                hr  = [ordered]@{ sourceSystem = 'HR';  authority = 'authoritative'; snapshotAsOfUtc = $null;            extractedAtUtc = $null;           toolVersion = $null;        scope = $null;   recordCount = $null;                          configHash = $null;       contentHash = $null }
            }
        }
        identities    = @($identitiesSorted)
        managerEdges  = @($edgesSorted)
        accessGrants  = @($grantsSorted)
        unmatchedAd   = @($unmatchedAdSorted)
        summary       = $summary
    }

    # ---- Emit JSON (UTF-8 no-BOM, newline-normalized for byte-stability) ----------------------------
    if (-not [string]::IsNullOrWhiteSpace($JsonPath)) {
        $json = $model | ConvertTo-Json -Depth 12
        $json = $json -replace "`r`n", "`n"
        [System.IO.File]::WriteAllText($JsonPath, $json, [System.Text.UTF8Encoding]::new($false))
    }

    # ---- Emit CSV twin (flat identity rows, no-BOM, newline-normalized) ------------------------------
    if (-not [string]::IsNullOrWhiteSpace($CsvPath)) {
        $rows = foreach ($i in $identitiesSorted) {
            [pscustomobject]@{
                dnKey             = $i.dnKey
                objectGuid        = $i.objectGuid
                sam               = $i.sam
                domain            = $i.domain
                ou                = $i.ou
                displayName       = $i.displayName
                employeeId        = $i.joinKeys.employeeId
                mail              = $i.joinKeys.mail
                upn               = $i.joinKeys.upn
                samDomain         = $i.joinKeys.samDomain
                joinKeyValue      = $i.joinKeyResolved.value
                joinKeySource     = $i.joinKeyResolved.source
                joinKeyConfidence = $i.joinKeyResolved.confidence
                enabled           = $i.enabled
                privileged        = $i.privileged
                managerDnKey      = $i.manager.dnKey
                managerEmployeeId = $i.manager.employeeId
                chainState        = $i.chain.state
                reachesOrgTop     = $i.chain.reachesOrgTop
                skipLevelViable   = $i.chain.skipLevelViable
                breakReason       = $i.chain.breakReason
                chainDepth        = $i.chain.depth
                accessGrantCount  = @($i.accessGrants).Count
                findingCount      = @($i.recon.findings).Count
                findingCodes      = (@($i.recon.findings | ForEach-Object { $_.code }) -join ';')
            }
        }
        $csv = @($rows) | ConvertTo-Csv -NoTypeInformation
        $csvText = ($csv -join "`n")
        $csvText = $csvText -replace "`r`n", "`n"
        [System.IO.File]::WriteAllText($CsvPath, $csvText, [System.Text.UTF8Encoding]::new($false))
    }

    return $model
}

# -----------------------------------------------------------------------------
# PURE: roll group-membership COUNTS up the tree (counts only; distinct-user sets discarded)
# -----------------------------------------------------------------------------
function Get-OrgRoleAggregate {
    <#
    .SYNOPSIS  Attach per-node direct + subtree COUNTS of tracked-group memberships to the org tree.
    .PARAMETER OrgTree      Output of Build-OrgTree.
    .PARAMETER MemberRefs   Output of ConvertTo-OrgMemberRefs (one per member,group).
    .OUTPUTS  @{ Nodes=@{dnkey=aggregateNode}; Roots=@(); Summary=@{...} }.
              Counts-only invariant: distinct-user HashSets are computed transiently then discarded;
              only counts are stored.
    #>
    param(
        [Parameter(Mandatory = $true)][hashtable]$OrgTree,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][object[]]$MemberRefs
    )
    $byDn = $OrgTree.NodesByDn

    # Index refs by member DN; refs whose DN isn't a node -> unmanaged bucket (can't be placed).
    $refsByDn = @{}
    foreach ($r in $MemberRefs) {
        $k = [string](Get-OrgProp $r 'DnKey')
        if ([string]::IsNullOrWhiteSpace($k) -or -not $byDn.ContainsKey($k)) { $k = $script:OrgUnmanagedDn }
        if (-not $refsByDn.ContainsKey($k)) { $refsByDn[$k] = New-Object System.Collections.Generic.List[object] }
        [void]$refsByDn[$k].Add($r)
    }

    # Build aggregate nodes (counts only) with Direct figures from this node's own refs.
    $agg = @{}
    foreach ($key in $byDn.Keys) {
        $src = $byDn[$key]
        $mine = if ($refsByDn.ContainsKey($key)) { $refsByDn[$key] } else { @() }
        $directRefs  = @($mine)
        $directPriv  = @($directRefs | Where-Object { $_.Privileged }).Count
        $directGrps  = @($directRefs | ForEach-Object { $_.Group } | Sort-Object -Unique).Count
        $agg[$key] = @{
            DnKey = $key; Dn = $src.Dn; Sam = $src.Sam; Display = $src.Display; Domain = $src.Domain
            Enabled = $src.Enabled; Resolved = $src.Resolved; IsUnmanaged = $src.IsUnmanaged
            IsServiceAccount = $(if ($null -eq $src.IsServiceAccount) { $false } else { [bool]$src.IsServiceAccount })
            ChildDns = @($src.ChildDns); Depth = $src.Depth
            DirectGroupRefs = $directRefs.Count; DirectDistinctGroups = $directGrps; DirectPriv = $directPriv
            SubtreeGroupRefs = 0; SubtreePrivRefs = 0; SubtreeDistinctUsers = 0
            DeltaAdded = 0; DeltaRemoved = 0; DeltaPrivAdded = 0; DeltaPrivRemoved = 0
        }
    }

    # Subtree rollups via memoised DFS (visiting-guard breaks any residual cycle edges).
    $memo = @{}; $visiting = @{}
    $compute = $null
    $compute = {
        param($key)
        if ($memo.ContainsKey($key)) { return $memo[$key] }
        if ($visiting.ContainsKey($key)) { return @{ Refs = 0; Priv = 0; Users = (New-Object 'System.Collections.Generic.HashSet[string]') } }
        $visiting[$key] = $true
        $a = $agg[$key]
        $refs = $a.DirectGroupRefs
        $priv = $a.DirectPriv
        $users = New-Object 'System.Collections.Generic.HashSet[string]'
        if ($a.DirectGroupRefs -gt 0) { [void]$users.Add($key) }
        foreach ($c in $a.ChildDns) {
            if (-not $agg.ContainsKey($c)) { continue }
            $cr = & $compute $c
            $refs += $cr.Refs
            $priv += $cr.Priv
            foreach ($u in $cr.Users) { [void]$users.Add($u) }
        }
        $a.SubtreeGroupRefs     = $refs
        $a.SubtreePrivRefs      = $priv
        $a.SubtreeDistinctUsers = $users.Count
        $res = @{ Refs = $refs; Priv = $priv; Users = $users }
        $memo[$key] = $res
        $visiting.Remove($key) | Out-Null
        return $res
    }
    foreach ($r in $OrgTree.RootDns) { [void](& $compute $r) }
    [void](& $compute $OrgTree.UnmanagedBucketDn)
    # Any node not reached by the above (defensive) still has its Direct counts as Subtree.
    foreach ($key in $agg.Keys) {
        if (-not $memo.ContainsKey($key)) {
            $a = $agg[$key]
            $a.SubtreeGroupRefs = $a.DirectGroupRefs; $a.SubtreePrivRefs = $a.DirectPriv
            $a.SubtreeDistinctUsers = $(if ($a.DirectGroupRefs -gt 0) { 1 } else { 0 })
        }
    }

    $maxDepth = 0; foreach ($k in $agg.Keys) { if ($agg[$k].Depth -gt $maxDepth) { $maxDepth = $agg[$k].Depth } }
    $unmanaged = $agg[$OrgTree.UnmanagedBucketDn]

    # Leadership headline metrics (additive). Distinct PEOPLE (by DN) - not assignments - so the
    # report can show "N people hold access" alongside "M access assignments" (one person, many roles).
    # Counts only: distinct-DN sets are computed transiently here and discarded (no names stored).
    $distinctAccess = @($MemberRefs | Where-Object { $_.DnKey } | ForEach-Object { $_.DnKey } | Sort-Object -Unique).Count
    $distinctPriv   = @($MemberRefs | Where-Object { $_.Privileged -and $_.DnKey } | ForEach-Object { $_.DnKey } | Sort-Object -Unique).Count
    # Managers = real (non-bucket) people who have at least one direct report.
    $mgrCount = @($agg.Values | Where-Object { -not $_.IsUnmanaged -and @($_.ChildDns).Count -gt 0 }).Count
    $nodeCount = ($agg.Keys.Count - 1)   # exclude synthetic bucket
    $icCount = [math]::Max(0, $nodeCount - $mgrCount)
    $topNodes = @($agg.Values |
        Where-Object { -not $_.IsUnmanaged -and $_.SubtreePrivRefs -gt 0 } |
        Sort-Object @{ Expression = { $_.SubtreePrivRefs }; Descending = $true }, @{ Expression = { $_.Display } } |
        Select-Object -First 10 |
        ForEach-Object { @{ Display = $_.Display; Sam = $_.Sam; Domain = $_.Domain; SubtreePrivRefs = $_.SubtreePrivRefs; SubtreeGroupRefs = $_.SubtreeGroupRefs } })

    # Split the no-manager bucket into EXPECTED service accounts vs PEOPLE that need review, so a
    # legitimate service account (OU=ServiceAccounts / name pattern) doesn't inflate the data-quality
    # finding. Bucket children are the no-manager accounts (usually leaves; cyclic fragments use
    # their subtree counts).
    $svcUsers = 0; $svcPriv = 0; $pplUsers = 0; $pplPriv = 0
    foreach ($ck in $unmanaged.ChildDns) {
        if (-not $agg.ContainsKey($ck)) { continue }
        $cn = $agg[$ck]
        if ($cn.IsServiceAccount) { $svcUsers += $cn.SubtreeDistinctUsers; $svcPriv += $cn.SubtreePrivRefs }
        else { $pplUsers += $cn.SubtreeDistinctUsers; $pplPriv += $cn.SubtreePrivRefs }
    }

    $summary = @{
        NodeCount            = $nodeCount   # exclude synthetic bucket
        RootCount            = @($OrgTree.RootDns).Count
        MaxDepth             = $maxDepth
        TotalMemberRefs      = @($MemberRefs).Count
        TotalPrivRefs        = @($MemberRefs | Where-Object { $_.Privileged }).Count
        DistinctPeopleWithAccess = $distinctAccess
        DistinctPeopleWithPriv   = $distinctPriv
        ManagerCount             = $mgrCount
        IndividualContributorCount = $icCount
        UnmanagedRefs        = $unmanaged.SubtreeGroupRefs
        UnmanagedPrivRefs    = $unmanaged.SubtreePrivRefs
        UnmanagedDistinctUsers = $unmanaged.SubtreeDistinctUsers
        ServiceAccountDistinctUsers  = $svcUsers
        ServiceAccountPrivRefs       = $svcPriv
        UnmanagedPeopleDistinctUsers = $pplUsers
        UnmanagedPeoplePrivRefs      = $pplPriv
        TopConcentratedNodes = $topNodes
        Issues               = @($OrgTree.Issues)
    }

    return @{ Nodes = $agg; Roots = @($OrgTree.RootDns); UnmanagedBucketDn = $OrgTree.UnmanagedBucketDn; Summary = $summary }
}

# -----------------------------------------------------------------------------
# PURE: overlay DELTA change events onto the aggregate (DELTA mode)
# -----------------------------------------------------------------------------
function Add-OrgDeltaToTree {
    <#
    .SYNOPSIS  Place changelog Added/Removed events onto org nodes (+/- per branch) for DELTA mode.
               The changelog has NO manager field, so resolve Domain|Sam -> node DN from the tree.
    .PARAMETER Aggregate  Output of Get-OrgRoleAggregate (mutated in place: Delta* counts).
    .PARAMETER ChangeEvents  Array of @{ Domain; GroupName; SamAccountName; Action(Added|Removed); ... }.
    .PARAMETER PrivilegedNamePredicate  Optional { param($name) [bool] }.
    .OUTPUTS  @{ Matched; Unmatched } counts. Unmatched events land on the unmanaged bucket.
    #>
    param(
        [Parameter(Mandatory = $true)][hashtable]$Aggregate,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][object[]]$ChangeEvents,
        [scriptblock]$PrivilegedNamePredicate = $null
    )
    $nodes = $Aggregate.Nodes

    # Domain|Sam -> DnKey from the aggregate nodes (Sam unique per domain, not globally).
    $samToDn = @{}
    foreach ($k in $nodes.Keys) {
        $n = $nodes[$k]
        if ($n.Sam) { $samToDn[("{0}|{1}" -f $n.Domain, $n.Sam).ToLowerInvariant()] = $k }
    }

    # Ancestor lookup: child -> parent (built from ChildDns).
    $parentOf = @{}
    foreach ($k in $nodes.Keys) { foreach ($c in $nodes[$k].ChildDns) { $parentOf[$c] = $k } }

    $matched = 0; $unmatched = 0
    foreach ($ev in $ChangeEvents) {
        $sam    = [string](Get-OrgProp $ev 'SamAccountName')
        $domain = [string](Get-OrgProp $ev 'Domain')
        $action = [string](Get-OrgProp $ev 'Action')
        $group  = [string](Get-OrgProp $ev 'GroupName')
        if ([string]::IsNullOrWhiteSpace($sam)) { continue }
        $isPriv = $false
        if ($PrivilegedNamePredicate) { try { $isPriv = [bool](& $PrivilegedNamePredicate $group) } catch { $isPriv = $false } }

        $skey = ("{0}|{1}" -f $domain, $sam).ToLowerInvariant()
        $target = if ($samToDn.ContainsKey($skey)) { $samToDn[$skey] } else { $script:OrgUnmanagedDn }
        if ($samToDn.ContainsKey($skey)) { $matched++ } else { $unmatched++ }

        # Increment this node and propagate up the ancestor chain (visited-guarded).
        $cur = $target; $seen = New-Object 'System.Collections.Generic.HashSet[string]'
        while ($cur -and $nodes.ContainsKey($cur) -and $seen.Add($cur)) {
            $n = $nodes[$cur]
            if ($action -eq 'Added')   { $n.DeltaAdded++;   if ($isPriv) { $n.DeltaPrivAdded++ } }
            elseif ($action -eq 'Removed') { $n.DeltaRemoved++; if ($isPriv) { $n.DeltaPrivRemoved++ } }
            $cur = if ($parentOf.ContainsKey($cur)) { $parentOf[$cur] } else { $null }
        }
    }

    $Aggregate.Summary['DeltaMatched']   = $matched
    $Aggregate.Summary['DeltaUnmatched'] = $unmatched
    return @{ Matched = $matched; Unmatched = $unmatched }
}

# -----------------------------------------------------------------------------
# RENDER: self-contained HTML (inline SVG spatial map + accessible table + B00 theme)
# -----------------------------------------------------------------------------
function New-OrgRoleMapHtml {
    <#
    .SYNOPSIS  Render the aggregate to a single self-contained HTML file: an inline-SVG spatial org
               map (deterministic layout precomputed here in PowerShell; vanilla JS only for
               pan/zoom/expand - NO external libraries) PLUS a static, accessible, printable TABLE
               (the canonical evidence artifact), themed via the shared B00 accessible palette.
    .PARAMETER Aggregate   Output of Get-OrgRoleAggregate (optionally with Add-OrgDeltaToTree applied).
    .PARAMETER MemberRefs  The same refs fed to the aggregate (used to build the per (node,group) table).
    .PARAMETER Mode        'Full' | 'Delta' | 'Adhoc' (banner + delta columns).
    .PARAMETER OutputPath  Destination .html (UTF-8 no-BOM).
    .OUTPUTS  The output path (string).
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)][hashtable]$Aggregate,
        [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string]$OutputPath,
        [Parameter()][AllowEmptyCollection()][object[]]$MemberRefs = @(),
        [Parameter()][ValidateSet('Full', 'Delta', 'Adhoc')][string]$Mode = 'Full',
        [Parameter()][string]$Title = 'Org Role Map',
        [Parameter()][ValidateSet('auto', 'dark', 'light')][string]$Theme = 'auto',
        [Parameter()][int]$DefaultOpenDepth = 2,
        [Parameter()][string]$WindowLabel = '',
        [Parameter()][string]$OrgTreeBuiltUtc = '',
        [Parameter()][string]$StaleWarning = '',
        [Parameter()][int]$MaxTableRows = 800,
        [Parameter()][switch]$ManagersOnly,
        [Parameter()][int]$ManagersOnlyThreshold = 400
    )

    $nodes = $Aggregate.Nodes
    $isDelta = ($Mode -eq 'Delta')

    # ---- Scale guard: for large orgs, draw only the management hierarchy + the synthetic buckets
    # and roll individual contributors (leaf people) up into their manager's counts. The spatial
    # layout's width grows with the number of LEAVES, so thousands of ICs blow the SVG out
    # horizontally (illegible, and too wide to rasterise to PNG). Drawing managers-only keeps it
    # legible; the per-person detail still lives in the table below. Auto-engages past the threshold
    # (raise -ManagersOnlyThreshold to disable). A "manager" = any node with >=1 report; the
    # no-manager bucket has reports too, so it stays as a single node showing its count.
    $autoCollapsed = $false
    if (-not $ManagersOnly -and $nodes.Count -gt $ManagersOnlyThreshold) { $ManagersOnly = $true; $autoCollapsed = $true }
    $drawn = New-Object 'System.Collections.Generic.HashSet[string]'
    if ($ManagersOnly) {
        foreach ($k in $nodes.Keys) {
            if (@($nodes[$k].ChildDns | Where-Object { $nodes.ContainsKey($_) }).Count -gt 0) { [void]$drawn.Add($k) }
        }
    }
    $managersShown = $drawn.Count
    $icRolled = if ($ManagersOnly) { [math]::Max(0, $nodes.Count - $drawn.Count) } else { 0 }

    # ---- Render tree: a virtual root over the real roots + the unmanaged bucket --------------
    $ROOT = '__root__'
    $parentOf = @{}
    foreach ($k in $nodes.Keys) { foreach ($c in $nodes[$k].ChildDns) { if (-not $parentOf.ContainsKey($c)) { $parentOf[$c] = $k } } }
    $rootChildren = @(@($Aggregate.Roots) + @($Aggregate.UnmanagedBucketDn)) | Where-Object { $nodes.ContainsKey($_) }
    foreach ($rc in $rootChildren) { $parentOf[$rc] = $ROOT }

    $childrenOf = {
        param($key)
        if ($key -eq $ROOT) {
            if ($ManagersOnly) { return @($rootChildren | Where-Object { $drawn.Contains($_) }) }
            return @($rootChildren)
        }
        if (-not $nodes.ContainsKey($key)) { return @() }
        $ch = @($nodes[$key].ChildDns | Where-Object { $nodes.ContainsKey($_) })
        if ($ManagersOnly) { $ch = @($ch | Where-Object { $drawn.Contains($_) }) }
        return @($ch | Sort-Object `
            @{ Expression = { $nodes[$_].SubtreePrivRefs }; Descending = $true }, `
            @{ Expression = { $nodes[$_].SubtreeGroupRefs }; Descending = $true }, `
            @{ Expression = { $nodes[$_].Display } })
    }
    $labelOf = {
        param($key)
        if ($key -eq $ROOT) { return 'Organization' }
        $n = $nodes[$key]
        if ([string]::IsNullOrWhiteSpace($n.Display)) { if ($n.Sam) { return $n.Sam } else { return '(unknown)' } }
        return $n.Display
    }

    # ---- Deterministic tidy layout (post-order; leaves get sequential x, parents centre) ------
    $layout = @{}
    $script:__xc = 0
    $visited = New-Object 'System.Collections.Generic.HashSet[string]'
    $assign = $null
    $assign = {
        param($key, $depth)
        if (-not $visited.Add($key)) { return }
        $kids = & $childrenOf $key
        if (@($kids).Count -eq 0) {
            $layout[$key] = @{ X = $script:__xc; Depth = $depth }; $script:__xc++
        } else {
            $first = $null; $last = $null
            foreach ($c in $kids) { & $assign $c ($depth + 1); if ($layout.ContainsKey($c)) { if ($null -eq $first) { $first = $layout[$c].X }; $last = $layout[$c].X } }
            $mid = if ($null -ne $first) { ($first + $last) / 2.0 } else { $v = $script:__xc; $script:__xc++; $v }
            $layout[$key] = @{ X = $mid; Depth = $depth }
        }
    }
    & $assign $ROOT 0

    # ---- Heat banding from privileged concentration -----------------------------------------
    $maxPriv = 0; foreach ($k in $nodes.Keys) { if ($nodes[$k].SubtreePrivRefs -gt $maxPriv) { $maxPriv = $nodes[$k].SubtreePrivRefs } }
    $bandOf = {
        param($key)
        if ($key -eq $ROOT) { return 0 }
        $v = $nodes[$key].SubtreePrivRefs
        if ($maxPriv -le 0 -or $v -le 0) { return 0 }
        $r = $v / [double]$maxPriv
        if ($r -ge 0.75) { return 4 } elseif ($r -ge 0.5) { return 3 } elseif ($r -ge 0.25) { return 2 } else { return 1 }
    }

    # ---- SVG geometry ------------------------------------------------------------------------
    $xGap = 150; $yGap = 96; $mx = 80; $my = 60
    $maxX = 0; $maxD = 0
    foreach ($k in $layout.Keys) { if ($layout[$k].X -gt $maxX) { $maxX = $layout[$k].X }; if ($layout[$k].Depth -gt $maxD) { $maxD = $layout[$k].Depth } }
    $svgW = [int]($maxX * $xGap + $mx * 2 + 240)
    $svgH = [int]($maxD * $yGap + $my * 2 + 40)
    if ($svgW -lt 640) { $svgW = 640 }; if ($svgH -lt 360) { $svgH = 360 }

    $edgeSb = New-Object System.Text.StringBuilder
    $nodeSb = New-Object System.Text.StringBuilder
    foreach ($key in ($layout.Keys | Sort-Object { $layout[$_].Depth })) {
        $L = $layout[$key]
        $cx = [int]($L.X * $xGap + $mx); $cy = [int]($L.Depth * $yGap + $my)
        $par = if ($parentOf.ContainsKey($key)) { $parentOf[$key] } else { '' }
        $hidden = ($L.Depth -gt $DefaultOpenDepth)
        $cls = if ($hidden) { 'orgnode hid' } else { 'orgnode' }
        if ($par -and $layout.ContainsKey($par)) {
            $pp = $layout[$par]; $px = [int]($pp.X * $xGap + $mx); $py = [int]($pp.Depth * $yGap + $my)
            $ehid = if ($hidden) { 'orgedge hid' } else { 'orgedge' }
            [void]$edgeSb.Append(('<path class="{0}" data-key="{1}" d="M{2},{3} C{2},{6} {4},{6} {4},{5}" />' -f $ehid, (ConvertTo-OrgHtmlText $key), $px, ($py + 14), $cx, ($cy - 14), [int](($py + $cy) / 2)))
        }
        if ($key -eq $ROOT) {
            $rlabel = 'Whole organization (' + $Aggregate.Summary.TotalPrivRefs + ' privileged assignments)'
            [void]$nodeSb.Append(('<g class="orgnode root" data-key="{0}" data-parent="" data-depth="0" data-priv="0" data-haskids="1" tabindex="0" role="treeitem" aria-label="{1}"><rect x="{2}" y="{3}" rx="6" width="190" height="34" class="rootbox"/><text x="{4}" y="{5}" class="rootlabel">{1}</text></g>' -f $ROOT, (ConvertTo-OrgHtmlText $rlabel), ($cx - 95), ($cy - 17), $cx, ($cy + 5)))
            continue
        }
        $n = $nodes[$key]
        $kids = & $childrenOf $key
        $hasKids = if (@($kids).Count -gt 0) { 1 } else { 0 }
        $band = & $bandOf $key
        $rad = [int](7 + [math]::Min(20, [math]::Sqrt([double]([math]::Max($n.SubtreeGroupRefs, 1))) * 3))
        $lab = & $labelOf $key
        $countTxt = if ($ManagersOnly) { "$($n.SubtreeDistinctUsers) ppl / $($n.SubtreePrivRefs) priv" } else { "$($n.SubtreePrivRefs) priv / $($n.SubtreeGroupRefs) total" }
        $deltaTxt = ''
        if ($isDelta -and (($n.DeltaAdded + $n.DeltaRemoved) -gt 0)) { $deltaTxt = "<tspan class='dadd'>+$($n.DeltaAdded)</tspan> <tspan class='drem'>-$($n.DeltaRemoved)</tspan>" }
        $flag = ''
        if ($n.IsUnmanaged) { $flag = ' &#9650;' } elseif (-not $n.Enabled) { $flag = ' &#9888;' }
        $aria = ("{0}: {1} privileged of {2} total access assignments in this person's whole team" -f $lab, $n.SubtreePrivRefs, $n.SubtreeGroupRefs)
        [void]$nodeSb.Append(('<g class="{0}" data-key="{1}" data-parent="{2}" data-depth="{3}" data-priv="{4}" data-haskids="{5}" tabindex="0" role="treeitem" aria-label="{6}">' -f $cls, (ConvertTo-OrgHtmlText $key), (ConvertTo-OrgHtmlText $par), $L.Depth, $n.SubtreePrivRefs, $hasKids, (ConvertTo-OrgHtmlText $aria)))
        [void]$nodeSb.Append(('<circle class="dot heat{0}" cx="{1}" cy="{2}" r="{3}"/>' -f $band, $cx, $cy, $rad))
        if ($hasKids -eq 1) { [void]$nodeSb.Append(('<text class="toggle" x="{0}" y="{1}">{2}</text>' -f $cx, ($cy + 4), '-')) }
        [void]$nodeSb.Append(('<text class="nlabel" x="{0}" y="{1}">{2}{3}</text>' -f ($cx + $rad + 6), ($cy - 1), (ConvertTo-OrgHtmlText $lab), $flag))
        [void]$nodeSb.Append(('<text class="ncount" x="{0}" y="{1}">{2}</text>' -f ($cx + $rad + 6), ($cy + 12), (ConvertTo-OrgHtmlText $countTxt)))
        if ($deltaTxt) { [void]$nodeSb.Append(('<text class="ndelta" x="{0}" y="{1}">{2}</text>' -f ($cx + $rad + 6), ($cy + 24), $deltaTxt)) }
        [void]$nodeSb.Append('</g>')
    }

    # ---- Static table: per (node, group) subtree counts (the accessible/print artifact) ------
    $pairCount = @{}; $pairPriv = @{}
    $ancestors = {
        param($key)
        $chain = New-Object System.Collections.Generic.List[string]
        $cur = $key; $seen = New-Object 'System.Collections.Generic.HashSet[string]'
        while ($cur -and $nodes.ContainsKey($cur) -and $seen.Add($cur)) { [void]$chain.Add($cur); $cur = if ($parentOf.ContainsKey($cur)) { $parentOf[$cur] } else { $null } }
        return $chain
    }
    foreach ($r in $MemberRefs) {
        $dk = [string](Get-OrgProp $r 'DnKey')
        if ([string]::IsNullOrWhiteSpace($dk) -or -not $nodes.ContainsKey($dk)) { $dk = $Aggregate.UnmanagedBucketDn }
        $grp = [string](Get-OrgProp $r 'Group')
        $pv  = [bool](Get-OrgProp $r 'Privileged')
        foreach ($a in (& $ancestors $dk)) {
            $pk = "$a`n$grp"
            if (-not $pairCount.ContainsKey($pk)) { $pairCount[$pk] = 0 }
            $pairCount[$pk]++
            if ($pv) { $pairPriv[$pk] = $true }
        }
    }
    $pathOf = {
        param($key)
        $names = New-Object System.Collections.Generic.List[string]
        foreach ($a in (& $ancestors $key)) { [void]$names.Add((& $labelOf $a)) }
        $names.Reverse(); return ($names -join ' > ')
    }
    $tableRows = @($pairCount.Keys | Sort-Object { - $pairCount[$_] }, { $_ })
    $rowTrunc = $false
    if ($tableRows.Count -gt $MaxTableRows) { $rowTrunc = $true; $tableRows = $tableRows[0..($MaxTableRows - 1)] }
    # Disambiguate rows whose displayed path collides -- distinct DNs/GUIDs that render the same
    # name (duplicate/colliding accounts, or unresolved "(unknown)" managers). Append the account's
    # SamAccountName (or its OU) so identical-looking rows can be told apart.
    $nodePath = @{}; $pathSeen = @{}
    foreach ($pk0 in $tableRows) {
        $nk0 = ($pk0 -split "`n", 2)[0]
        if (-not $nodePath.ContainsKey($nk0)) { $ps0 = & $pathOf $nk0; $nodePath[$nk0] = $ps0; $pathSeen[$ps0] = ([int]$pathSeen[$ps0]) + 1 }
    }
    $disambOf = {
        param($nk)
        $ps = $nodePath[$nk]
        if ([int]$pathSeen[$ps] -le 1) { return '' }
        $nd = if ($nodes.ContainsKey($nk)) { $nodes[$nk] } else { $null }
        if ($nd -and $nd.Sam) { return " ($($nd.Sam))" }
        if ($nd -and $nd.Dn) { $ou = ([regex]::Match([string]$nd.Dn, '(?i)OU=([^,]+)')).Groups[1].Value; if ($ou) { return " [OU=$ou]" } }
        return ''
    }
    $rowSb = New-Object System.Text.StringBuilder
    if (@($tableRows).Count -eq 0) {
        [void]$rowSb.Append('<tr><td colspan="4" class="none">No tracked access could be mapped to the org chart.</td></tr>')
    } else {
        foreach ($pk in $tableRows) {
            $parts = $pk -split "`n", 2
            $nodeKey = $parts[0]; $grp = if ($parts.Count -gt 1) { $parts[1] } else { '' }
            $isPriv = $pairPriv.ContainsKey($pk)
            $badge = if ($isPriv) { '<span class="badge bpriv">Privileged</span>' } else { '<span class="badge btrack">Standard</span>' }
            [void]$rowSb.Append('<tr>')
            [void]$rowSb.Append('<td class="path">' + (ConvertTo-OrgHtmlText ($nodePath[$nodeKey] + (& $disambOf $nodeKey))) + '</td>')
            [void]$rowSb.Append('<td>' + (ConvertTo-OrgHtmlText $grp) + '</td>')
            [void]$rowSb.Append('<td class="num">' + $pairCount[$pk] + '</td>')
            [void]$rowSb.Append('<td>' + $badge + '</td>')
            [void]$rowSb.Append('</tr>')
        }
    }
    $truncNote = if ($rowTrunc) { "<p class='trunc'>Showing the top $MaxTableRows team/group combinations by size; more exist.</p>" } else { '' }

    # ---- Theme + chrome ----------------------------------------------------------------------
    $themeCss    = Get-GEReportThemeCss
    $toggleHtml  = Get-GEReportThemeToggleHtml
    $themeScript = Get-GEReportThemeScript
    $themeAttr   = if ($Theme -eq 'dark' -or $Theme -eq 'light') { " data-theme=`"$Theme`"" } else { '' }
    $S = $Aggregate.Summary
    $genOn = (Get-Date).ToString('d MMM yyyy')
    # Friendly mode wording for a leadership audience (no engineer jargon).
    $modeFriendly = switch ($Mode) {
        'Full'  { 'Full snapshot' }
        'Delta' { 'Changes since last review' }
        'Adhoc' { 'On-demand snapshot' }
        default { $Mode }
    }
    $modeLine = $modeFriendly
    if ($WindowLabel) { $modeLine += " &bull; Period: " + (ConvertTo-OrgHtmlText $WindowLabel) }
    if ($OrgTreeBuiltUtc) {
        $builtFriendly = $OrgTreeBuiltUtc
        try { $builtFriendly = ([datetime]$OrgTreeBuiltUtc).ToLocalTime().ToString('d MMM yyyy') } catch { }
        $modeLine += " &bull; Directory data as of " + (ConvertTo-OrgHtmlText $builtFriendly)
    }
    $staleBanner = if ($StaleWarning) { '<div class="stale" role="alert">&#9888; ' + (ConvertTo-OrgHtmlText $StaleWarning) + '</div>' } else { '' }
    $collapseHtml = if ($ManagersOnly) {
        $verb = if ($autoCollapsed) { ("Large org (" + ($icRolled + $managersShown) + " people): showing managers only") } else { 'Managers-only view' }
        '<p class="maphint" style="margin-top:6px">&#9650; ' + (ConvertTo-OrgHtmlText ("$verb -- $managersShown manager/branch node(s); $icRolled individual contributor(s) rolled into their manager's counts. Full per-person detail is in the table below.")) + '</p>'
    } else { '' }
    $deltaKpi = if ($isDelta) { ('<div class="card"><div class="k">Access changes placed / unplaced</div><div class="v">{0} / {1}</div><div class="kdef">Changes we could / could not tie to a person on the chart</div></div>' -f $S['DeltaMatched'], $S['DeltaUnmatched']) } else { '' }

    # Manager / individual split is shown as one combined card.
    $mgrCount = if ($null -ne $S['ManagerCount']) { $S['ManagerCount'] } else { 0 }
    $icCount  = if ($null -ne $S['IndividualContributorCount']) { $S['IndividualContributorCount'] } else { 0 }
    $distAccess = if ($null -ne $S['DistinctPeopleWithAccess']) { $S['DistinctPeopleWithAccess'] } else { 0 }
    $distPriv   = if ($null -ne $S['DistinctPeopleWithPriv']) { $S['DistinctPeopleWithPriv'] } else { 0 }
    # Service accounts (no manager = expected) split out from people-with-no-manager (review).
    $svcUsers     = if ($null -ne $S['ServiceAccountDistinctUsers']) { $S['ServiceAccountDistinctUsers'] } else { 0 }
    $pplNoMgrPriv = if ($null -ne $S['UnmanagedPeoplePrivRefs']) { $S['UnmanagedPeoplePrivRefs'] } else { $S.UnmanagedPrivRefs }
    $svcCardHtml  = if ($svcUsers -gt 0) { '<div class="card"><div class="k">Service accounts (no manager)</div><div class="v">' + $svcUsers + '</div><div class="kdef">Accounts with no manager that are expected to have none (service/automation)</div></div>' } else { '' }

    $html = @"
<!DOCTYPE html>
<html lang="en"$themeAttr>
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>$(ConvertTo-OrgHtmlText $Title) (Org Role Map)</title>
<style>
  :root { color-scheme: light dark; }
$themeCss
  * { box-sizing: border-box; }
  body { font-family: 'Segoe UI', Tahoma, Arial, sans-serif; margin: 0; background: var(--bg); color: var(--ink); }
  .wrap { max-width: 1280px; margin: 0 auto; padding: 24px 20px 56px; }
  header.report { background: var(--header-bg); color: #fff; border-radius: 10px; padding: 20px 24px; margin-bottom: 18px; box-shadow: 0 2px 8px rgba(0,0,0,.18); }
  header.report h1 { margin: 0 0 6px; font-size: 21px; }
  header.report .sub { font-size: 13px; opacity: .92; }
  .stale { background: var(--badge-warn-bg); color: var(--badge-warn-ink); padding: 9px 14px; border-radius: 6px; font-weight: 600; margin-bottom: 16px; }
  .cards { display: flex; flex-wrap: wrap; gap: 12px; margin-bottom: 18px; }
  .card { flex: 1 1 150px; background: var(--surface); color: var(--ink); border: 1px solid var(--line); border-radius: 8px; padding: 12px 14px; }
  .card .k { font-size: 11px; text-transform: uppercase; letter-spacing: .04em; color: var(--muted); }
  .card .v { font-size: 24px; font-weight: 700; margin-top: 4px; }
  .card .kdef { font-size: 11px; color: var(--muted); margin-top: 5px; line-height: 1.35; }
  .card.crit .v { color: var(--crit); }
  .privacy { background: var(--surface); color: var(--muted); border: 1px solid var(--line); border-left: 3px solid var(--accent); border-radius: 6px; padding: 9px 14px; font-size: 12px; margin: 0 0 16px; }
  h2 { font-size: 15px; margin: 22px 0 8px; }
  .maptools { display: flex; flex-wrap: wrap; gap: 8px; align-items: center; margin-bottom: 8px; }
  .maptools button { font: 600 12px/1 'Segoe UI', Arial, sans-serif; padding: 6px 10px; border-radius: 6px; cursor: pointer; background: var(--surface); color: var(--ink); border: 1px solid var(--line); }
  .maptools button:hover { border-color: var(--accent); }
  .maphint { color: var(--muted); font-size: 12px; }
  .mapframe { border: 1px solid var(--line); border-radius: 8px; background: var(--surface); overflow: hidden; height: 560px; }
  svg.orgmap { width: 100%; height: 100%; cursor: grab; touch-action: none; }
  svg.orgmap.grabbing { cursor: grabbing; }
  .orgedge { fill: none; stroke: var(--line); stroke-width: 1.5; }
  .orgnode .dot { stroke: var(--surface); stroke-width: 1.5; }
  .dot.heat0 { fill: var(--muted); } .dot.heat1 { fill: var(--ok); } .dot.heat2 { fill: var(--low); }
  .dot.heat3 { fill: var(--warn); } .dot.heat4 { fill: var(--crit); }
  .nlabel { fill: var(--ink); font: 600 12px 'Segoe UI', Arial, sans-serif; }
  .ncount { fill: var(--muted); font: 11px 'Consolas', monospace; }
  .ndelta { font: 700 11px 'Consolas', monospace; }
  .ndelta .dadd { fill: var(--ok); } .ndelta .drem { fill: var(--crit); }
  .toggle { fill: var(--surface); font: 700 13px 'Consolas', monospace; text-anchor: middle; pointer-events: none; }
  .rootbox { fill: var(--header-bg); stroke: var(--accent); }
  .rootlabel { fill: #fff; font: 700 12px 'Segoe UI', Arial, sans-serif; text-anchor: middle; }
  .orgnode { cursor: pointer; } .orgnode:focus { outline: 2px solid var(--accent); }
  .hid { display: none; }
  table { width: 100%; border-collapse: collapse; background: var(--surface); border: 1px solid var(--line); border-radius: 8px; overflow: hidden; }
  thead th { background: var(--header-bg); color: #fff; text-align: left; font-size: 11px; text-transform: uppercase; letter-spacing: .03em; padding: 9px 11px; }
  tbody td { padding: 8px 11px; font-size: 13px; color: var(--ink); border-top: 1px solid var(--line); vertical-align: top; }
  tbody td.num { text-align: right; font-variant-numeric: tabular-nums; }
  tbody td.path { font-weight: 600; }
  td.none { text-align: center; color: var(--muted); font-style: italic; padding: 22px; }
  .badge { display: inline-block; padding: 2px 8px; border-radius: 11px; font-size: 11px; font-weight: 700; }
  .badge.bpriv { background: var(--badge-crit-bg); color: var(--badge-crit-ink); }
  .badge.btrack { background: var(--badge-low-bg); color: var(--badge-low-ink); }
  .trunc, footer.note { color: var(--muted); font-size: 12px; margin-top: 12px; }
  .legend { background: var(--surface); border: 1px solid var(--line); border-radius: 8px; padding: 12px 16px; margin-top: 12px; font-size: 12.5px; color: var(--ink); }
  .legend p { margin: 0 0 6px; } .legend ul { margin: 0; padding-left: 18px; } .legend li { margin: 3px 0; color: var(--muted); }
  .legend strong { color: var(--ink); }
  @media print { .mapframe, .maptools { display: none !important; } .printonly { display: block !important; } }
  .printonly { display: none; }
</style>
</head>
<body>
$toggleHtml
<div class="wrap">
  <header class="report">
    <h1>$(ConvertTo-OrgHtmlText $Title)</h1>
    <div class="sub">Where privileged access concentrates across the organization &mdash; counts only, no names. $modeLine &bull; Generated $genOn</div>
  </header>
  $staleBanner
  <p class="privacy">This report shows counts only &mdash; no individual names, usernames, or accounts are included. It is safe to share with leadership and to keep as an audit record.</p>
  <section class="cards">
    <div class="card"><div class="k">People mapped</div><div class="v">$($S.NodeCount)</div><div class="kdef">Everyone placed on the org chart in this review</div></div>
    <div class="card"><div class="k">People with tracked access</div><div class="v">$distAccess</div><div class="kdef">Individuals holding at least one tracked role (people, not assignments)</div></div>
    <div class="card crit"><div class="k">People with privileged access</div><div class="v">$distPriv</div><div class="kdef">Individuals holding at least one privileged role</div></div>
    <div class="card"><div class="k">Managers vs individuals</div><div class="v">$mgrCount &middot; $icCount</div><div class="kdef">$mgrCount manage others &bull; $icCount individual contributors</div></div>
    <div class="card"><div class="k">Privileged access assignments</div><div class="v">$($S.TotalPrivRefs)</div><div class="kdef">Total privileged roles held (one person can hold several)</div></div>
    <div class="card$(if ($pplNoMgrPriv -gt 0) { ' crit' } else { '' })"><div class="k">Privileged access, no manager (review)</div><div class="v">$pplNoMgrPriv</div><div class="kdef">$(if ($pplNoMgrPriv -gt 0) { 'On people whose manager is blank &mdash; a directory gap to review (service accounts counted separately)' } else { 'None &mdash; good' })</div></div>
    $svcCardHtml
    $deltaKpi
  </section>

  <h2>Organization map</h2>
  <div class="maptools">
    <button type="button" id="om-expand">Expand all</button>
    <button type="button" id="om-collapse">Collapse all</button>
    <button type="button" id="om-priv">Show privileged branches</button>
    <button type="button" id="om-reset">Reset view</button>
    <button type="button" id="om-png">Save as image</button>
    <span class="maphint">Drag to move &bull; scroll to zoom &bull; click a person to show or hide their team. Save as image for slides; the full breakdown is in the table below.</span>
  </div>
  $collapseHtml
  <div class="mapframe">
    <svg class="orgmap" viewBox="0 0 $svgW $svgH" preserveAspectRatio="xMidYMin meet" role="tree" aria-label="Org role map; full detail in the table below" aria-describedby="om-table">
      <g id="om-pan">
        <g id="om-edges">$($edgeSb.ToString())</g>
        <g id="om-nodes">$($nodeSb.ToString())</g>
      </g>
    </svg>
  </div>
  <div class="legend">
    <p><strong>How to read the map</strong></p>
    <ul>
      <li><strong>Circle size</strong> = how much tracked access sits under that person, counting everyone who reports up to them. Bigger circle = more access concentrated in that part of the org.</li>
      <li><strong>Circle colour</strong> = how much of that access is <em>privileged</em>. Grey/green = little or none; amber and red = heavy privileged concentration &mdash; the areas to look at first.</li>
      <li><strong>The number under each circle</strong> reads <em>privileged / total</em> &mdash; e.g. &ldquo;6 priv / 12 total&rdquo; means 6 of 12 assignments in that team are privileged.</li>
      <li><strong>Symbols:</strong> &#9650; no manager listed &middot; &#9888; account is disabled.</li>
    </ul>
  </div>
  <p class="printonly">The interactive map is omitted from print; see the table below for the full breakdown.</p>

  <h2>Where access sits (by team and group)</h2>
  $truncNote
  <table id="om-table">
    <thead><tr><th>Reporting line (top &rarr; manager)</th><th>Access group / role</th><th style="text-align:right">People with this access</th><th>Access type</th></tr></thead>
    <tbody>$($rowSb.ToString())</tbody>
  </table>

  <footer class="note">Counts only &mdash; no individual names or accounts. The reporting structure comes from each person's listed manager in the directory, so it can lag a recent reorganisation. Accounts with no manager listed (often service accounts or top executives) are grouped together and called out separately &mdash; a large group here is worth reviewing. The table above is the printable record of record.</footer>
</div>
<script>
(function(){
  var svg = document.querySelector('svg.orgmap'); if(!svg) return;
  var nodes = Array.prototype.slice.call(document.querySelectorAll('#om-nodes > g.orgnode'));
  var edges = Array.prototype.slice.call(document.querySelectorAll('#om-edges > path.orgedge'));
  var kids = {}; var elByKey = {}; var edgeByKey = {};
  nodes.forEach(function(g){ var k=g.getAttribute('data-key'); var p=g.getAttribute('data-parent'); elByKey[k]=g; (kids[p]=kids[p]||[]).push(k); });
  edges.forEach(function(e){ edgeByKey[e.getAttribute('data-key')]=e; });
  var collapsed = {};
  function apply(){
    nodes.forEach(function(g){
      var k=g.getAttribute('data-key'); var p=g.getAttribute('data-parent'); var vis=true; var cur=p;
      while(cur){ if(collapsed[cur]){vis=false;break;} cur=(elByKey[cur]?elByKey[cur].getAttribute('data-parent'):null); }
      g.classList.toggle('hid', !vis);
      if(edgeByKey[k]) edgeByKey[k].classList.toggle('hid', !vis);
      var t=g.querySelector('text.toggle'); if(t){ t.textContent = collapsed[k] ? '+' : '-'; }
    });
  }
  function setAll(state){ Object.keys(kids).forEach(function(p){ if(p) collapsed[p]=state; }); apply(); }
  nodes.forEach(function(g){
    var k=g.getAttribute('data-key');
    g.addEventListener('click', function(ev){ ev.stopPropagation(); if((kids[k]||[]).length){ collapsed[k]=!collapsed[k]; apply(); } });
    g.addEventListener('keydown', function(ev){ if(ev.key==='Enter'||ev.key===' '){ ev.preventDefault(); if((kids[k]||[]).length){ collapsed[k]=!collapsed[k]; apply(); } } });
  });
  nodes.forEach(function(g){ if(parseInt(g.getAttribute('data-depth'),10) >= $DefaultOpenDepth && (kids[g.getAttribute('data-key')]||[]).length){ collapsed[g.getAttribute('data-key')]=true; } });
  apply();
  document.getElementById('om-expand').addEventListener('click', function(){ setAll(false); });
  document.getElementById('om-collapse').addEventListener('click', function(){ setAll(true); });
  document.getElementById('om-priv').addEventListener('click', function(){
    Object.keys(kids).forEach(function(p){ if(p) collapsed[p]=true; });
    nodes.forEach(function(g){ if(parseInt(g.getAttribute('data-priv'),10)>0){ var cur=g.getAttribute('data-key'); while(cur){ collapsed[cur]=false; cur=(elByKey[cur]?elByKey[cur].getAttribute('data-parent'):null);} } });
    apply();
  });
  var vb = svg.getAttribute('viewBox').split(' ').map(Number); var base = vb.slice();
  function setVB(){ svg.setAttribute('viewBox', vb.join(' ')); }
  var drag=false, sx=0, sy=0;
  svg.addEventListener('mousedown', function(e){ drag=true; sx=e.clientX; sy=e.clientY; svg.classList.add('grabbing'); });
  window.addEventListener('mouseup', function(){ drag=false; svg.classList.remove('grabbing'); });
  window.addEventListener('mousemove', function(e){ if(!drag) return; var r=svg.getBoundingClientRect(); var kx=vb[2]/r.width, ky=vb[3]/r.height; vb[0]-=(e.clientX-sx)*kx; vb[1]-=(e.clientY-sy)*ky; sx=e.clientX; sy=e.clientY; setVB(); });
  svg.addEventListener('wheel', function(e){ e.preventDefault(); var f=(e.deltaY<0)?0.9:1.1; var r=svg.getBoundingClientRect(); var mxr=(e.clientX-r.left)/r.width, myr=(e.clientY-r.top)/r.height; var nx=vb[0]+vb[2]*mxr*(1-f), ny=vb[1]+vb[3]*myr*(1-f); vb[2]*=f; vb[3]*=f; vb[0]=nx; vb[1]=ny; setVB(); }, {passive:false});
  document.getElementById('om-reset').addEventListener('click', function(){ vb=base.slice(); setVB(); });
  // Export the FULL chart as a PNG -- pure Canvas, no libraries. Clones the SVG, un-hides every
  // node, embeds the resolved theme CSS so the standalone SVG rasterises styled, then downloads.
  function exportPng(){
    var W = base[2], H = base[3];
    var clone = svg.cloneNode(true);
    Array.prototype.forEach.call(clone.querySelectorAll('.hid'), function(e){ e.classList.remove('hid'); });
    Array.prototype.forEach.call(clone.querySelectorAll('text.toggle'), function(t){ t.textContent='-'; });
    clone.setAttribute('viewBox','0 0 '+W+' '+H); clone.setAttribute('width', W); clone.setAttribute('height', H);
    var css='';
    for (var i=0;i<document.styleSheets.length;i++){ try { var rr=document.styleSheets[i].cssRules; for(var j=0;j<rr.length;j++){ css+=rr[j].cssText+'\n'; } } catch(e){} }
    var cs=getComputedStyle(document.documentElement);
    var names=['--bg','--surface','--surface-alt','--ink','--muted','--line','--accent','--header-bg','--row-crit-bg','--row-warn-bg','--row-low-bg','--crit','--warn','--low','--ok','--badge-crit-bg','--badge-crit-ink','--badge-warn-bg','--badge-warn-ink','--badge-low-bg','--badge-low-ink','--badge-ok-bg','--badge-ok-ink'];
    var rootvars=':root{'; for(var k=0;k<names.length;k++){ var v=cs.getPropertyValue(names[k]); if(v){ rootvars+=names[k]+':'+v.trim()+';'; } } rootvars+='}';
    var st=document.createElementNS('http://www.w3.org/2000/svg','style'); st.textContent=rootvars+css;
    clone.insertBefore(st, clone.firstChild);
    var xml=new XMLSerializer().serializeToString(clone);
    var url='data:image/svg+xml;base64,'+btoa(unescape(encodeURIComponent(xml)));
    var img=new Image();
    img.onload=function(){
      // Cap the ABSOLUTE canvas size, not just the 2x multiplier -- browsers refuse canvases past
      // ~16k px and toDataURL then returns an empty string (a PNG that won't open). Scale down so the
      // longest side fits MAX; prefer 2x for crispness when it fits.
      var MAX=16000;
      var scale=2;
      if (W*scale>MAX || H*scale>MAX){ scale=Math.min(MAX/W, MAX/H, 2); }
      if (!(scale>0)) scale=1;
      var cw=Math.max(1,Math.floor(W*scale)), ch=Math.max(1,Math.floor(H*scale));
      var c=document.createElement('canvas'); c.width=cw; c.height=ch;
      var ctx=c.getContext('2d'); ctx.scale(scale,scale);
      ctx.fillStyle=(cs.getPropertyValue('--surface')||'#ffffff').trim(); ctx.fillRect(0,0,W,H);
      ctx.drawImage(img,0,0,W,H);
      try {
        var durl=c.toDataURL('image/png');
        if(!durl || durl.length<128){ alert('PNG export failed: the chart is too large to rasterise. Use the managers-only view (large orgs collapse automatically) or scope with -Groups.'); return; }
        var a=document.createElement('a'); a.download='org-role-map.png'; a.href=durl; a.click();
      }
      catch(e){ alert('PNG export failed: '+e.message); }
    };
    img.onerror=function(){ alert('PNG export failed to rasterise the chart.'); };
    img.src=url;
  }
  var pngBtn=document.getElementById('om-png'); if(pngBtn){ pngBtn.addEventListener('click', exportPng); }
})();
</script>
$themeScript
</body>
</html>
"@

    $dir = Split-Path -Parent $OutputPath
    if ($dir -and -not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    [System.IO.File]::WriteAllText($OutputPath, $html, [System.Text.UTF8Encoding]::new($false))
    return $OutputPath
}

# =============================================================================
# AD/IO LAYER - the ONLY part that touches LDAP. Runs on FULL builds; DELTA/ADHOC
# reuse the persisted org-tree.json without a DC. The chain walk takes an injectable
# lookup scriptblock so it is unit-testable with a fake map (no DC).
# =============================================================================
function Get-OrgDomainFromDn {
    param([string]$Dn)
    if ([string]::IsNullOrWhiteSpace($Dn)) { return '' }
    $dcs = [regex]::Matches($Dn, '(?i)DC=([^,]+)') | ForEach-Object { $_.Groups[1].Value }
    return ($dcs -join '.')
}

function New-OrgAdLookup {
    <#
    .SYNOPSIS  Build the default LDAP-backed lookup scriptblock { param($Dn) -> node | $null }
               over an ADLdap connection pool. A $null result means the DN is in an unreachable /
               untrusted domain (the chain stops there - a documented limitation, not a bug).
    #>
    param([Parameter(Mandatory = $true)][hashtable]$Pool, [int]$TimeoutSeconds = 120, [string]$JoinKeyAttribute = 'employeeID')
    $joinKeyLower = $JoinKeyAttribute.ToLowerInvariant()
    # Capture the helper FUNCTIONS as scriptblock variables so GetNewClosure() snapshots them.
    # GetNewClosure captures variables, NOT functions, so referencing these by name inside the
    # returned closure fails with "X is not recognized" when it runs from Build-OrgTreeCache's scope
    # (the original reason this lookup was sidestepped). Capturing + invoking via & makes it portable.
    $fnCtxForDN  = ${function:Get-AdLdapContextForDN}
    $fnPooledCtx = ${function:Get-AdLdapPooledContext}
    $fnDomain    = ${function:Get-OrgDomainFromDn}
    $fnSearch    = ${function:Invoke-AdLdapSearch}
    return {
        param($Dn)
        $ctx = & $fnCtxForDN -Pool $Pool -DistinguishedName $Dn
        if ($null -eq $ctx) {
            # Cross-domain forest: the DN's domain isn't pooled yet -> open it on demand (DC-locator by
            # FQDN) so a manager who lives in a DIFFERENT forest domain still resolves instead of the
            # chain dead-ending at the trust boundary. An unreachable/untrusted domain stays $null.
            $dom = & $fnDomain $Dn
            if ($dom) { try { $ctx = & $fnPooledCtx -Pool $Pool -Domain $dom } catch { $ctx = $null } }
        }
        if ($null -eq $ctx) { return $null }
        $res = $null
        try {
            $res = & $fnSearch -Context $ctx -BaseDN $Dn -Scope Base -Filter '(objectClass=*)' `
                -Attributes @('manager', 'sAMAccountName', 'displayName', 'userAccountControl', $JoinKeyAttribute, 'userPrincipalName', 'mail', 'objectGUID') `
                -BinaryAttributes @('objectGUID') -TimeoutSeconds $TimeoutSeconds
        } catch { return $null }
        if (-not $res -or @($res).Count -eq 0) { return $null }
        $e = @($res)[0]
        $uac = 0; [void][int]::TryParse([string]$e['userAccountControl'], [ref]$uac)
        # objectGUID is binary -> stable GUID string; never emit raw bytes (malformed -> '').
        $objGuid = ''
        if ($e.Contains('objectguid') -and $e['objectguid']) { try { $objGuid = ([guid][byte[]]$e['objectguid']).ToString() } catch { $objGuid = '' } }
        elseif ($e.Contains('objectGUID') -and $e['objectGUID']) { try { $objGuid = ([guid][byte[]]$e['objectGUID']).ToString() } catch { $objGuid = '' } }
        $empId = if ($e.Contains($joinKeyLower)) { [string]$e[$joinKeyLower] } elseif ($e.Contains($JoinKeyAttribute)) { [string]$e[$JoinKeyAttribute] } else { '' }
        $upn = if ($e.Contains('userprincipalname')) { [string]$e['userprincipalname'] } elseif ($e.Contains('userPrincipalName')) { [string]$e['userPrincipalName'] } else { '' }
        $mail = if ($e.Contains('mail')) { [string]$e['mail'] } elseif ($e.Contains('Mail')) { [string]$e['Mail'] } else { '' }
        return @{
            Dn = [string]$e['DistinguishedName']; Sam = [string]$e['sAMAccountName']; Display = [string]$e['displayName']
            Domain = (& $fnDomain $Dn); Enabled = (-not ($uac -band 2)); ManagerDn = [string]$e['manager']; Resolved = $true
            EmployeeId = $empId; Upn = $upn; Mail = $mail; ObjectGuid = $objGuid
        }
    }.GetNewClosure()
}

function Resolve-ManagerChain {
    <#
    .SYNOPSIS  Walk a user's manager chain UPWARD, populating NodeCache. Iterative (PS5.1-safe),
               per-chain cycle break, per-run memoisation (each manager DN resolved at most once),
               depth cap, and an unreachable-domain stop.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$StartDn,
        [Parameter(Mandatory = $true)][scriptblock]$LookupFn,
        [Parameter(Mandatory = $true)][hashtable]$NodeCache,
        [Parameter(Mandatory = $true)][hashtable]$ResolvedThisRun,
        [int]$DepthCap = 20,
        [hashtable]$Stats = $null
    )
    $current = $StartDn
    $depth = 0
    $visited = New-Object 'System.Collections.Generic.HashSet[string]'
    while ($current -and $depth -lt $DepthCap) {
        $key = Get-OrgDnKey $current
        if (-not $visited.Add($key)) {
            if ($NodeCache.ContainsKey($key)) { $NodeCache[$key].ManagerDn = $null }
            if ($Stats) { $Stats.Cycles++ }
            break
        }
        if ($ResolvedThisRun.ContainsKey($key)) { break }   # already walked from here this run
        $rec = & $LookupFn $current
        if ($null -eq $rec) {
            if (-not $NodeCache.ContainsKey($key)) {
                $NodeCache[$key] = @{ Dn = $current; Sam = ''; Display = ''; Domain = (Get-OrgDomainFromDn $current); Enabled = $true; ManagerDn = $null; Resolved = $false; Synthetic = $true; EmployeeId = ''; Upn = ''; Mail = ''; ObjectGuid = '' }
            }
            $ResolvedThisRun[$key] = $true
            if ($Stats) { $Stats.Unresolved++ }
            break
        }
        $NodeCache[$key] = @{ Dn = $rec.Dn; Sam = $rec.Sam; Display = $rec.Display; Domain = $rec.Domain; Enabled = [bool]$rec.Enabled; ManagerDn = $rec.ManagerDn; Resolved = $true; Synthetic = $false; EmployeeId = [string]$rec.EmployeeId; Upn = [string]$rec.Upn; Mail = [string]$rec.Mail; ObjectGuid = [string]$rec.ObjectGuid }
        $ResolvedThisRun[$key] = $true
        $current = $rec.ManagerDn
        $depth++
    }
    if ($depth -ge $DepthCap -and $current) {
        $lastKey = Get-OrgDnKey $current
        if ($NodeCache.ContainsKey($lastKey)) { $NodeCache[$lastKey].ManagerDn = $null }
        if ($Stats) { $Stats.DepthCapped++ }
    }
}

function Build-OrgTreeCache {
    <#
    .SYNOPSIS  Seed from a snapshot's member DNs and walk every chain upward (memoised) into a flat
               DN-keyed org-tree cache @{ Metadata; Nodes }. Pure given an injected $LookupFn.
    #>
    param(
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][string[]]$MemberDns,
        [Parameter(Mandatory = $true)][scriptblock]$LookupFn,
        [int]$DepthCap = 20,
        [string]$BuiltByMode = 'Full'
    )
    $nodeCache = @{}; $resolved = @{}; $stats = @{ Cycles = 0; Unresolved = 0; DepthCapped = 0 }
    foreach ($dn in $MemberDns) {
        if ([string]::IsNullOrWhiteSpace($dn)) { continue }
        Resolve-ManagerChain -StartDn $dn -LookupFn $LookupFn -NodeCache $nodeCache -ResolvedThisRun $resolved -DepthCap $DepthCap -Stats $stats
    }
    $domainsResolved = @($nodeCache.Values | Where-Object { $_.Resolved } | ForEach-Object { $_.Domain } | Where-Object { $_ } | Sort-Object -Unique)
    $domainsUnreach  = @($nodeCache.Values | Where-Object { -not $_.Resolved } | ForEach-Object { $_.Domain } | Where-Object { $_ } | Sort-Object -Unique)
    $issues = @()
    if ($stats.Cycles -gt 0) { $issues += "cycles:$($stats.Cycles)" }
    if ($stats.DepthCapped -gt 0) { $issues += "depth-capped:$($stats.DepthCapped)" }
    if ($stats.Unresolved -gt 0) { $issues += "unreachable-managers:$($stats.Unresolved)" }
    return @{
        Metadata = @{
            Version = '1.0'; BuiltUtc = ((Get-Date).ToUniversalTime().ToString('o')); BuiltByMode = $BuiltByMode
            DepthCap = $DepthCap; NodeCount = $nodeCache.Count
            DomainsResolved = $domainsResolved; DomainsUnreachable = $domainsUnreach; Issues = $issues
        }
        Nodes = $nodeCache
    }
}

function Save-OrgTreeCache {
    param([Parameter(Mandatory = $true)][hashtable]$Cache, [Parameter(Mandatory = $true)][string]$Path)
    $dir = Split-Path -Parent $Path
    if ($dir -and -not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    $json = $Cache | ConvertTo-Json -Depth 6
    $tmp = "$Path.tmp"
    [System.IO.File]::WriteAllText($tmp, $json, [System.Text.UTF8Encoding]::new($false))
    Move-Item -LiteralPath $tmp -Destination $Path -Force
    return $Path
}

function Import-OrgTreeCache {
    # Returns a ConvertFrom-Json object; Build-OrgTree consumes PSCustomObject via Get-OrgNodeEntries.
    param([Parameter(Mandatory = $true)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { return $null }
    return ([System.IO.File]::ReadAllText($Path) | ConvertFrom-Json)
}

function Get-OrgTreeStaleness {
    <#
    .SYNOPSIS  Return @{ AgeDays; Stale; Warning } from an org-tree cache's Metadata.BuiltUtc.
    #>
    param([object]$OrgTreeCache, [int]$MaxStaleDays = 30, [datetime]$Now = [datetime]::UtcNow)
    $meta = Get-OrgProp $OrgTreeCache 'Metadata'
    $built = [string](Get-OrgProp $meta 'BuiltUtc')
    if ([string]::IsNullOrWhiteSpace($built)) { return @{ AgeDays = $null; Stale = $true; Warning = 'Org-tree cache has no build timestamp; treat placement as unverified.' } }
    $dt = [datetime]::MinValue
    if (-not [datetime]::TryParse($built, [ref]$dt)) { return @{ AgeDays = $null; Stale = $true; Warning = "Org-tree cache build time '$built' is unparseable." } }
    $age = [int][math]::Floor(($Now - $dt.ToUniversalTime()).TotalDays)
    $stale = ($age -gt $MaxStaleDays)
    $warn = if ($stale) { "Org-tree cache is $age days old (> $MaxStaleDays). Reorganisations since then place users on stale branches." } else { '' }
    return @{ AgeDays = $age; Stale = $stale; Warning = $warn }
}
