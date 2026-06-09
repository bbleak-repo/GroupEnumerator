<#
.SYNOPSIS
    Recursively resolves AD group membership to flat user lists

.DESCRIPTION
    Traverses nested AD group membership trees via LDAPS, returning a de-duplicated
    flat list of all user objects regardless of how many levels deep they are nested.

    Key behaviours:
      - Circular reference detection via visited-DN tracking
      - Configurable maximum recursion depth (NestedGroupMaxDepth config key, default 10)
      - De-duplication by DistinguishedName when the same user appears via multiple paths
      - Structured logging at DEBUG/INFO/WARN/ERROR levels using Write-GroupEnumLog
      - Uses the shared ADLdap helpers (New-AdLdapConnection / Invoke-AdLdapSearch)
        with AllowInsecure config controlling tier fallback
      - A single LdapConnection is opened per top-level call and reused throughout

.NOTES
    Requires ADLdap.ps1 and GroupEnumLogger.ps1 to be dot-sourced first
    (New-AdLdapConnection, Invoke-AdLdapSearch, Close-AdLdapConnection, and
    Write-GroupEnumLog must be loaded in the session).
    Compatible with PowerShell 5.1 and 7+. Targets Windows Active Directory only.
    Uses objectCategory (indexed) for all LDAP filters; never uses objectClass.
#>

# ---------------------------------------------------------------------------
# Private helper: open a shared LdapConnection context for this module
# Returns @{ Ctx = <context>; Error = <string> }
# ---------------------------------------------------------------------------
function script:Open-NestedResolverLdap {
    param(
        [string]$Domain,
        [PSCredential]$Credential,
        [hashtable]$Config
    )

    $allowInsecure  = if ($null -ne $Config.AllowInsecure) { $Config.AllowInsecure } else { $false }
    $timeoutSeconds = if ($Config.LdapTimeout) { $Config.LdapTimeout } else { 120 }

    Write-GroupEnumLog -Level 'DEBUG' -Operation 'LdapConnect' `
        -Message "Opening LDAP connection to '$Domain'" `
        -Context @{ domain = $Domain; allowInsecure = $allowInsecure }

    $connParams = @{
        Server         = $Domain
        TimeoutSeconds = $timeoutSeconds
    }
    if ($Credential)    { $connParams.Credential    = $Credential }
    if ($allowInsecure) { $connParams.AllowInsecure = $true }

    try {
        $ctx = New-AdLdapConnection @connParams
    } catch {
        Write-GroupEnumLog -Level 'ERROR' -Operation 'LdapConnect' `
            -Message "Could not connect to '$Domain'" `
            -Context @{ domain = $Domain; error = $_.ToString() }
        return @{ Ctx = $null; Error = "Failed to connect to domain '$Domain': $($_.ToString())" }
    }

    Write-GroupEnumLog -Level 'INFO' -Operation 'LdapConnect' `
        -Message "Connected to '$Domain' via $($ctx.Tier)" `
        -Context @{ domain = $Domain; tier = $ctx.Tier; port = $ctx.Port; baseDN = $ctx.BaseDN }

    $warn = $null
    if ($ctx.Tier -ne 'LDAPS-Verified') {
        $warn = "WARNING: Using tier '$($ctx.Tier)' (port $($ctx.Port)) for domain '$Domain'. Verified LDAPS was not available."
    }

    return @{ Ctx = $ctx; Error = $warn }
}

# ---------------------------------------------------------------------------
# Private: recursive core
# $visitedGroups  - hashtable keyed by DN (tracks already-visited groups)
# $flatUsers      - hashtable keyed by DN (de-duplicated user accumulator)
# $nestedGroups   - accumulator array (ref via [ref] inside plain hashtable trick)
# ---------------------------------------------------------------------------
function script:Resolve-GroupMembersRecursive {
    param(
        [hashtable]$Ctx,
        [string]$GroupDN,
        [string]$GroupName,
        [string]$Domain,
        [PSCredential]$Credential,
        [hashtable]$Config,
        [int]$CurrentDepth,
        [int]$MaxDepth,
        [hashtable]$VisitedGroups,       # [string DN] -> $true
        [hashtable]$FlatUsers,           # [string DN] -> user hashtable
        [System.Collections.ArrayList]$NestedGroups,
        [System.Collections.ArrayList]$ErrorList
    )

    # Guard: circular reference
    if ($VisitedGroups.ContainsKey($GroupDN)) {
        Write-GroupEnumLog -Level 'DEBUG' -Operation 'ResolveNested' `
            -Message "Skipping already-visited group DN (circular reference avoided)" `
            -Context @{ groupDn = $GroupDN; depth = $CurrentDepth }
        return
    }
    $VisitedGroups[$GroupDN] = $true

    # Guard: max depth
    if ($CurrentDepth -gt $MaxDepth) {
        Write-GroupEnumLog -Level 'WARN' -Operation 'ResolveNested' `
            -Message "Max recursion depth $MaxDepth reached at group '$GroupName'" `
            -Context @{ groupDn = $GroupDN; depth = $CurrentDepth; maxDepth = $MaxDepth }
        return
    }

    Write-GroupEnumLog -Level 'DEBUG' -Operation 'ResolveNested' `
        -Message "Resolving nested group '$GroupName' at depth $CurrentDepth" `
        -Context @{ group = $GroupName; groupDn = $GroupDN; depth = $CurrentDepth }

    $timeoutSeconds = if ($Config.LdapTimeout)  { $Config.LdapTimeout }  else { 120 }
    $pageSize       = if ($Config.LdapPageSize) { $Config.LdapPageSize } else { 1000 }

    # Read the member attribute from the group DN (Base scope -- we already have the DN)
    $rawMemberDNs = @()
    try {
        $groupHits = Invoke-AdLdapSearch -Context $Ctx -BaseDN $GroupDN `
            -Filter '(objectCategory=group)' -Scope Base `
            -Attributes @('member','cn','distinguishedName') `
            -PageSize $pageSize -TimeoutSeconds $timeoutSeconds

        if (-not $groupHits -or $groupHits.Count -eq 0) {
            Write-GroupEnumLog -Level 'WARN' -Operation 'ResolveNested' `
                -Message "Group DN '$GroupDN' returned no results with objectCategory=group" `
                -Context @{ groupDn = $GroupDN; depth = $CurrentDepth }
            return
        }

        $gr = $groupHits[0]
        if ($gr.ContainsKey('member')) {
            if ($gr.member -is [array]) { $rawMemberDNs = @($gr.member) }
            else                        { $rawMemberDNs = @([string]$gr.member) }
        }

        Write-GroupEnumLog -Level 'DEBUG' -Operation 'ResolveNested' `
            -Message "Group '$GroupName' at depth $CurrentDepth has $($rawMemberDNs.Count) direct member DN(s)" `
            -Context @{ group = $GroupName; depth = $CurrentDepth; directMemberCount = $rawMemberDNs.Count }

    } catch {
        $null = $ErrorList.Add("Failed to read members of group '$GroupName' (DN: $GroupDN) at depth $CurrentDepth`: $_")
        return
    }

    # Process each member DN
    foreach ($memberDN in $rawMemberDNs) {
        try {
            # Use a broad filter and check objectCategory in results to classify
            $memberHits = Invoke-AdLdapSearch -Context $Ctx -BaseDN $memberDN `
                -Filter '(|(objectCategory=person)(objectCategory=group))' -Scope Base `
                -Attributes @('objectCategory','sAMAccountName','displayName','mail','userAccountControl','distinguishedName','cn') `
                -TimeoutSeconds $timeoutSeconds

            if (-not $memberHits -or $memberHits.Count -eq 0) {
                Write-GroupEnumLog -Level 'DEBUG' -Operation 'ResolveNested' `
                    -Message "Member DN '$memberDN' returned no results (may be a contact or computer)" `
                    -Context @{ memberDn = $memberDN; depth = $CurrentDepth }
                continue
            }

            $mr = $memberHits[0]

            # objectCategory comes back as the full DN of the schema class,
            # e.g. "CN=Person,CN=Schema,..." or "CN=Group,CN=Schema,..."
            $objectCategoryRaw = if ($mr.ContainsKey('objectCategory')) {
                if ($mr.objectCategory -is [array]) { [string]$mr.objectCategory[0] } else { [string]$mr.objectCategory }
            } else { '' }

            $isUser  = $objectCategoryRaw -imatch '^CN=Person,'
            $isGroup = $objectCategoryRaw -imatch '^CN=Group,'

            if ($isUser) {
                # Only add if not already seen (de-duplicate by DN)
                $dn = if ($mr.ContainsKey('distinguishedName')) {
                    if ($mr.distinguishedName -is [array]) { [string]$mr.distinguishedName[0] } else { [string]$mr.distinguishedName }
                } else { $memberDN }

                if (-not $FlatUsers.ContainsKey($dn)) {
                    $sam     = if ($mr.ContainsKey('sAMAccountName')) { $mr.sAMAccountName } else { $null }
                    $display = if ($mr.ContainsKey('displayName'))    { $mr.displayName }    else { $null }
                    $mail    = if ($mr.ContainsKey('mail'))           { $mr.mail }           else { $null }
                    $uac     = if ($mr.ContainsKey('userAccountControl')) {
                        [int]$mr.userAccountControl
                    } else { 0 }
                    $enabled = ($uac -band 2) -eq 0

                    $FlatUsers[$dn] = @{
                        SamAccountName    = $sam
                        DisplayName       = $display
                        Email             = $mail
                        Enabled           = $enabled
                        DistinguishedName = $dn
                        Domain            = $Domain
                    }

                    Write-GroupEnumLog -Level 'DEBUG' -Operation 'ResolveNested' `
                        -Message "Added user '$sam' from group '$GroupName' at depth $CurrentDepth" `
                        -Context @{ sam = $sam; dn = $dn; depth = $CurrentDepth; group = $GroupName }
                }

            } elseif ($isGroup) {
                $subGroupCn = if ($mr.ContainsKey('cn')) {
                    if ($mr.cn -is [array]) { [string]$mr.cn[0] } else { [string]$mr.cn }
                } else { $memberDN }

                $subGroupDn = if ($mr.ContainsKey('distinguishedName')) {
                    if ($mr.distinguishedName -is [array]) { [string]$mr.distinguishedName[0] } else { [string]$mr.distinguishedName }
                } else { $memberDN }

                Write-GroupEnumLog -Level 'DEBUG' -Operation 'ResolveNested' `
                    -Message "Found nested group '$subGroupCn' at depth $CurrentDepth, recursing" `
                    -Context @{ subGroup = $subGroupCn; subGroupDn = $subGroupDn; depth = $CurrentDepth }

                # Record this nested group in the traversal list
                # (MemberCount placeholder filled after recursion)
                $null = $NestedGroups.Add(@{
                    Name        = $subGroupCn
                    Depth       = $CurrentDepth + 1
                    DN          = $subGroupDn
                    ParentGroup = $GroupName
                    ParentDN    = $GroupDN
                })

                # Recurse
                script:Resolve-GroupMembersRecursive `
                    -Ctx            $Ctx `
                    -GroupDN        $subGroupDn `
                    -GroupName      $subGroupCn `
                    -Domain         $Domain `
                    -Credential     $Credential `
                    -Config         $Config `
                    -CurrentDepth   ($CurrentDepth + 1) `
                    -MaxDepth       $MaxDepth `
                    -VisitedGroups  $VisitedGroups `
                    -FlatUsers      $FlatUsers `
                    -NestedGroups   $NestedGroups `
                    -ErrorList      $ErrorList

            } else {
                Write-GroupEnumLog -Level 'DEBUG' -Operation 'ResolveNested' `
                    -Message "Member DN '$memberDN' is neither a person nor group (objectCategory: $objectCategoryRaw) -- skipping" `
                    -Context @{ memberDn = $memberDN; objectCategory = $objectCategoryRaw }
            }

        } catch {
            $null = $ErrorList.Add("Failed to classify member DN '$memberDN' in group '$GroupName': $_")

            Write-GroupEnumLog -Level 'ERROR' -Operation 'ResolveNested' `
                -Message "Failed to classify member DN '$memberDN': $_" `
                -Context @{ memberDn = $memberDN; group = $GroupName; depth = $CurrentDepth; error = $_.ToString() }
        }
    }
}

# ---------------------------------------------------------------------------
# Public: Resolve-NestedGroupMembers
# ---------------------------------------------------------------------------
function Resolve-NestedGroupMembers {
    <#
    .SYNOPSIS
        Recursively resolves all members of an AD group to a flat, de-duplicated user list

    .DESCRIPTION
        Starting from the named group, traverses the full group membership tree via LDAPS.
        Users encountered through multiple nesting paths are de-duplicated by
        DistinguishedName. Circular group references are detected and skipped.

        The recursion depth limit is read from Config.NestedGroupMaxDepth (default 10).
        AllowInsecure in Config controls whether LDAP (389) with Kerberos Sealing is
        permitted when LDAPS (636) is unavailable.

        Requires ADLdap.ps1 and GroupEnumLogger.ps1 to be dot-sourced first so that
        New-AdLdapConnection, Invoke-AdLdapSearch, Close-AdLdapConnection, and
        Write-GroupEnumLog are available in the session.

    .PARAMETER Domain
        NetBIOS name or FQDN of the domain containing the group

    .PARAMETER GroupName
        CN (common name) of the root group to resolve

    .PARAMETER Credential
        Optional PSCredential for LDAP authentication. Omit for integrated Windows auth.

    .PARAMETER Config
        Configuration hashtable. Relevant keys:
          NestedGroupMaxDepth  - max recursion depth (default 10)
          LdapTimeout          - per-query timeout in seconds (default 120)
          LdapPageSize         - LDAP page size (default 1000)
          AllowInsecure        - allow LDAP (389) fallback (default $false)

    .PARAMETER MaxDepth
        Override for NestedGroupMaxDepth. If both are specified, this wins.

    .OUTPUTS
        Hashtable:
          FlatMembers     - array of user hashtables (SamAccountName, DisplayName, Email,
                            Enabled, DistinguishedName, Domain); de-duplicated
          NestedGroups    - array of group hashtables found during traversal
                            (Name, Depth, DN, ParentGroup, ParentDN)
          MaxDepthReached - $true if the depth limit was hit during traversal
          TotalUsersFound - count of unique users in FlatMembers
          Errors          - array of error strings (non-fatal issues accumulated)

    .EXAMPLE
        $result = Resolve-NestedGroupMembers -Domain 'CORP' -GroupName 'GG_AppTeam' -Config $cfg
        $result.FlatMembers | Select-Object SamAccountName, DisplayName, Enabled
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Domain,

        [Parameter(Mandatory = $true)]
        [string]$GroupName,

        [Parameter(Mandatory = $false)]
        [PSCredential]$Credential,

        [Parameter(Mandatory = $false)]
        [hashtable]$Config = @{},

        [Parameter(Mandatory = $false)]
        [hashtable]$ConnectionPool,

        [Parameter(Mandatory = $false)]
        [int]$MaxDepth = 0
    )

    $errors = @()

    if ([string]::IsNullOrWhiteSpace($Domain)) {
        return @{
            FlatMembers     = @()
            NestedGroups    = @()
            MaxDepthReached = $false
            TotalUsersFound = 0
            Errors          = @("Domain parameter is required and cannot be empty")
        }
    }

    if ([string]::IsNullOrWhiteSpace($GroupName)) {
        return @{
            FlatMembers     = @()
            NestedGroups    = @()
            MaxDepthReached = $false
            TotalUsersFound = 0
            Errors          = @("GroupName parameter is required and cannot be empty")
        }
    }

    # Resolve max depth: explicit param > config key > hard default
    $resolvedMaxDepth = if ($MaxDepth -gt 0) {
        $MaxDepth
    } elseif ($Config.NestedGroupMaxDepth -and $Config.NestedGroupMaxDepth -gt 0) {
        $Config.NestedGroupMaxDepth
    } else {
        10
    }

    $timeoutSeconds = if ($Config.LdapTimeout)  { $Config.LdapTimeout }  else { 120 }
    $pageSize       = if ($Config.LdapPageSize) { $Config.LdapPageSize } else { 1000 }

    Write-GroupEnumLog -Level 'INFO' -Operation 'ResolveNested' `
        -Message "Starting nested group resolution for '$GroupName' in domain '$Domain'" `
        -Context @{ group = $GroupName; domain = $Domain; maxDepth = $resolvedMaxDepth }

    # Step 1: Open LDAP connection and find the root group DN
    $ctx = $null
    $ownCtx = $false
    $flatMembersArray = @()
    $nestedGroups     = [System.Collections.ArrayList]::new()
    $maxDepthReached  = $false
    $totalUsers       = 0

    try {
        if ($ConnectionPool) {
            try {
                $ctx = Get-AdLdapPooledContext -Pool $ConnectionPool -Domain $Domain
            } catch {
                Write-GroupEnumLog -Level 'ERROR' -Operation 'LdapConnect' `
                    -Message "Could not obtain pooled connection to '$Domain'" `
                    -Context @{ domain = $Domain; error = $_.ToString() }
                return @{
                    FlatMembers     = @()
                    NestedGroups    = @()
                    MaxDepthReached = $false
                    TotalUsersFound = 0
                    Errors          = @("Failed to connect to domain '$Domain': $($_.ToString())")
                }
            }
            Write-GroupEnumLog -Level 'INFO' -Operation 'LdapConnect' `
                -Message "Using pooled connection to '$Domain' via $($ctx.Tier)" `
                -Context @{ domain = $Domain; tier = $ctx.Tier; port = $ctx.Port; baseDN = $ctx.BaseDN; pooled = $true }
            if ($ctx.Tier -ne 'LDAPS-Verified') {
                $errors += "WARNING: Using tier '$($ctx.Tier)' (port $($ctx.Port)) for domain '$Domain'. Verified LDAPS was not available."
            }
        } else {
            $connOpen = script:Open-NestedResolverLdap -Domain $Domain -Credential $Credential -Config $Config
            if (-not $connOpen.Ctx) {
                return @{
                    FlatMembers     = @()
                    NestedGroups    = @()
                    MaxDepthReached = $false
                    TotalUsersFound = 0
                    Errors          = @($connOpen.Error)
                }
            }
            if ($connOpen.Error) { $errors += $connOpen.Error }
            $ctx = $connOpen.Ctx
            $ownCtx = $true
        }

        $rootGroupDN = $null
        try {
            $rootHits = Invoke-AdLdapSearch -Context $ctx `
                -Filter "(&(objectCategory=group)(cn=$(Escape-AdLdapFilterValue $GroupName)))" `
                -Scope Subtree `
                -Attributes @('distinguishedName','cn') `
                -PageSize $pageSize -TimeoutSeconds $timeoutSeconds

            if (-not $rootHits -or $rootHits.Count -eq 0) {
                return @{
                    FlatMembers     = @()
                    NestedGroups    = @()
                    MaxDepthReached = $false
                    TotalUsersFound = 0
                    Errors          = $errors + @("Group '$GroupName' not found in domain '$Domain'")
                }
            }

            $rootGroupDN = $rootHits[0].DistinguishedName

        } catch {
            return @{
                FlatMembers     = @()
                NestedGroups    = @()
                MaxDepthReached = $false
                TotalUsersFound = 0
                Errors          = $errors + @("Failed to locate root group '$GroupName' in domain '$Domain': $_")
            }
        }

        if (-not $rootGroupDN) {
            return @{
                FlatMembers     = @()
                NestedGroups    = @()
                MaxDepthReached = $false
                TotalUsersFound = 0
                Errors          = $errors + @("Group '$GroupName' found but DistinguishedName attribute was empty")
            }
        }

        Write-GroupEnumLog -Level 'DEBUG' -Operation 'ResolveNested' `
            -Message "Root group '$GroupName' resolved to DN '$rootGroupDN'" `
            -Context @{ group = $GroupName; dn = $rootGroupDN }

        # Step 2: Recursive traversal
        $visitedGroups = @{}
        $flatUsers     = @{}                  # keyed by DN
        $errorList     = [System.Collections.ArrayList]::new()

        script:Resolve-GroupMembersRecursive `
            -Ctx           $ctx `
            -GroupDN       $rootGroupDN `
            -GroupName     $GroupName `
            -Domain        $Domain `
            -Credential    $Credential `
            -Config        $Config `
            -CurrentDepth  1 `
            -MaxDepth      $resolvedMaxDepth `
            -VisitedGroups $visitedGroups `
            -FlatUsers     $flatUsers `
            -NestedGroups  $nestedGroups `
            -ErrorList     $errorList

        foreach ($e in $errorList) { $errors += $e }

        $flatMembersArray = @($flatUsers.Values)
        $totalUsers       = $flatMembersArray.Count

    } finally {
        if ($ctx -and $ownCtx) { Close-AdLdapConnection $ctx }
    }

    # Determine whether max depth was reached by checking if any nested group
    # was recorded at exactly maxDepth + 1 (which triggers the depth guard in recursion)
    $maxDepthReached = $false
    foreach ($ng in $nestedGroups) {
        if ($ng.Depth -gt $resolvedMaxDepth) {
            $maxDepthReached = $true
            break
        }
    }

    if ($maxDepthReached) {
        Write-GroupEnumLog -Level 'WARN' -Operation 'ResolveNested' `
            -Message "Max depth $resolvedMaxDepth reached during resolution of '$GroupName'. Some members may be missing." `
            -Context @{ group = $GroupName; domain = $Domain; maxDepth = $resolvedMaxDepth }
    }

    Write-GroupEnumLog -Level 'INFO' -Operation 'ResolveNested' `
        -Message "Completed nested resolution for '$GroupName': $totalUsers unique user(s) found, $($nestedGroups.Count) nested group(s) traversed" `
        -Context @{
            group           = $GroupName
            domain          = $Domain
            uniqueUsers     = $totalUsers
            nestedGroupsHit = $nestedGroups.Count
            maxDepthReached = $maxDepthReached
            errorCount      = $errors.Count
        }

    return @{
        FlatMembers     = $flatMembersArray
        NestedGroups    = @($nestedGroups)
        MaxDepthReached = $maxDepthReached
        TotalUsersFound = $totalUsers
        Errors          = $errors
    }
}

# ---------------------------------------------------------------------------
# Public: Get-NestedGroupTree
# ---------------------------------------------------------------------------
function Get-NestedGroupTree {
    <#
    .SYNOPSIS
        Returns the nesting structure of an AD group as a tree for logging or display

    .DESCRIPTION
        Traverses the same group membership tree as Resolve-NestedGroupMembers but
        focuses on the group-to-group relationships rather than collecting users.
        Returns a tree node for each group encountered, including depth, parent, and
        direct member count.

        Useful for diagnosing complex nesting hierarchies before running a full
        member resolution, and for including group topology in reports.

    .PARAMETER Domain
        NetBIOS name or FQDN of the domain containing the root group

    .PARAMETER GroupName
        CN (common name) of the root group

    .PARAMETER Credential
        Optional PSCredential for LDAP authentication. Omit for integrated Windows auth.

    .PARAMETER Config
        Configuration hashtable (same keys as Resolve-NestedGroupMembers).

    .PARAMETER MaxDepth
        Override for recursion depth limit. If 0, Config.NestedGroupMaxDepth or 10 applies.

    .OUTPUTS
        Hashtable:
          RootGroup  - name and DN of the root group
          Nodes      - array of group node hashtables (Name, DN, Depth, ParentGroup,
                       ParentDN, DirectMemberCount, DirectGroupCount)
          MaxDepth   - the depth limit used
          Errors     - array of error strings

    .EXAMPLE
        $tree = Get-NestedGroupTree -Domain 'CORP' -GroupName 'GG_AppTeam' -Config $cfg
        $tree.Nodes | Sort-Object Depth | Format-Table Name, Depth, ParentGroup
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Domain,

        [Parameter(Mandatory = $true)]
        [string]$GroupName,

        [Parameter(Mandatory = $false)]
        [PSCredential]$Credential,

        [Parameter(Mandatory = $false)]
        [hashtable]$Config = @{},

        [Parameter(Mandatory = $false)]
        [hashtable]$ConnectionPool,

        [Parameter(Mandatory = $false)]
        [int]$MaxDepth = 0
    )

    $errors = @()

    $resolvedMaxDepth = if ($MaxDepth -gt 0) {
        $MaxDepth
    } elseif ($Config.NestedGroupMaxDepth -and $Config.NestedGroupMaxDepth -gt 0) {
        $Config.NestedGroupMaxDepth
    } else {
        10
    }

    $timeoutSeconds = if ($Config.LdapTimeout)  { $Config.LdapTimeout }  else { 120 }
    $pageSize       = if ($Config.LdapPageSize) { $Config.LdapPageSize } else { 1000 }

    Write-GroupEnumLog -Level 'INFO' -Operation 'GroupTree' `
        -Message "Building group nesting tree for '$GroupName' in domain '$Domain'" `
        -Context @{ group = $GroupName; domain = $Domain; maxDepth = $resolvedMaxDepth }

    # Locate root group
    $ctx = $null
    $ownCtx = $false
    $nodes      = [System.Collections.ArrayList]::new()
    $rootGroupDN = $null

    try {
        if ($ConnectionPool) {
            try {
                $ctx = Get-AdLdapPooledContext -Pool $ConnectionPool -Domain $Domain
            } catch {
                Write-GroupEnumLog -Level 'ERROR' -Operation 'LdapConnect' `
                    -Message "Could not obtain pooled connection to '$Domain'" `
                    -Context @{ domain = $Domain; error = $_.ToString() }
                return @{
                    RootGroup = @{ Name = $GroupName; DN = $null }
                    Nodes     = @()
                    MaxDepth  = $resolvedMaxDepth
                    Errors    = @("Failed to connect to domain '$Domain': $($_.ToString())")
                }
            }
            Write-GroupEnumLog -Level 'INFO' -Operation 'LdapConnect' `
                -Message "Using pooled connection to '$Domain' via $($ctx.Tier)" `
                -Context @{ domain = $Domain; tier = $ctx.Tier; port = $ctx.Port; baseDN = $ctx.BaseDN; pooled = $true }
            if ($ctx.Tier -ne 'LDAPS-Verified') {
                $errors += "WARNING: Using tier '$($ctx.Tier)' (port $($ctx.Port)) for domain '$Domain'. Verified LDAPS was not available."
            }
        } else {
            $connOpen = script:Open-NestedResolverLdap -Domain $Domain -Credential $Credential -Config $Config
            if (-not $connOpen.Ctx) {
                return @{
                    RootGroup = @{ Name = $GroupName; DN = $null }
                    Nodes     = @()
                    MaxDepth  = $resolvedMaxDepth
                    Errors    = @($connOpen.Error)
                }
            }
            if ($connOpen.Error) { $errors += $connOpen.Error }
            $ctx = $connOpen.Ctx
            $ownCtx = $true
        }

        try {
            $rootHits = Invoke-AdLdapSearch -Context $ctx `
                -Filter "(&(objectCategory=group)(cn=$(Escape-AdLdapFilterValue $GroupName)))" `
                -Scope Subtree `
                -Attributes @('distinguishedName') `
                -PageSize $pageSize -TimeoutSeconds $timeoutSeconds

            if ($rootHits -and $rootHits.Count -gt 0) {
                $rootGroupDN = $rootHits[0].DistinguishedName
            }
        } catch {
            $errors += "Failed to locate root group '$GroupName': $_"
        }

        if (-not $rootGroupDN) {
            return @{
                RootGroup = @{ Name = $GroupName; DN = $null }
                Nodes     = @()
                MaxDepth  = $resolvedMaxDepth
                Errors    = $errors + @("Group '$GroupName' not found in domain '$Domain'")
            }
        }

        # Walk the tree (breadth queue to avoid deep call stack on very flat wide trees)
        $visitedDNs   = @{}
        $queue        = [System.Collections.Queue]::new()

        $queue.Enqueue(@{ DN = $rootGroupDN; Name = $GroupName; Depth = 0; ParentGroup = $null; ParentDN = $null })

        while ($queue.Count -gt 0) {
            $current = $queue.Dequeue()

            if ($visitedDNs.ContainsKey($current.DN)) { continue }
            $visitedDNs[$current.DN] = $true

            if ($current.Depth -gt $resolvedMaxDepth) { continue }

            $directUsers  = 0
            $directGroups = 0

            try {
                $nodeHits = Invoke-AdLdapSearch -Context $ctx -BaseDN $current.DN `
                    -Filter '(objectCategory=group)' -Scope Base `
                    -Attributes @('member') `
                    -TimeoutSeconds $timeoutSeconds

                if ($nodeHits -and $nodeHits.Count -gt 0) {
                    $nr = $nodeHits[0]
                    $memberDNs = @()
                    if ($nr.ContainsKey('member')) {
                        if ($nr.member -is [array]) { $memberDNs = @($nr.member) }
                        else                         { $memberDNs = @([string]$nr.member) }
                    }

                    # Classify child members (lightweight: check CN=Person or CN=Group prefix)
                    foreach ($mDN in $memberDNs) {
                        try {
                            $mHits = Invoke-AdLdapSearch -Context $ctx -BaseDN $mDN `
                                -Filter '(|(objectCategory=person)(objectCategory=group))' -Scope Base `
                                -Attributes @('objectCategory','cn','distinguishedName') `
                                -TimeoutSeconds $timeoutSeconds

                            if ($mHits -and $mHits.Count -gt 0) {
                                $mr2  = $mHits[0]
                                $cat2 = if ($mr2.ContainsKey('objectCategory')) {
                                    if ($mr2.objectCategory -is [array]) { [string]$mr2.objectCategory[0] } else { [string]$mr2.objectCategory }
                                } else { '' }

                                if ($cat2 -imatch '^CN=Person,') {
                                    $directUsers++
                                } elseif ($cat2 -imatch '^CN=Group,') {
                                    $directGroups++
                                    $childCN = if ($mr2.ContainsKey('cn')) {
                                        if ($mr2.cn -is [array]) { [string]$mr2.cn[0] } else { [string]$mr2.cn }
                                    } else { $mDN }
                                    $childDN = if ($mr2.ContainsKey('distinguishedName')) {
                                        if ($mr2.distinguishedName -is [array]) { [string]$mr2.distinguishedName[0] } else { [string]$mr2.distinguishedName }
                                    } else { $mDN }
                                    if (-not $visitedDNs.ContainsKey($childDN) -and ($current.Depth + 1) -le $resolvedMaxDepth) {
                                        $queue.Enqueue(@{
                                            DN          = $childDN
                                            Name        = $childCN
                                            Depth       = $current.Depth + 1
                                            ParentGroup = $current.Name
                                            ParentDN    = $current.DN
                                        })
                                    }
                                }
                            }
                        } catch {
                            $errors += "Tree: failed to classify member '$mDN': $_"
                        }
                    }
                }
            } catch {
                $errors += "Tree: failed to read group '$($current.Name)': $_"
            }

            $null = $nodes.Add(@{
                Name              = $current.Name
                DN                = $current.DN
                Depth             = $current.Depth
                ParentGroup       = $current.ParentGroup
                ParentDN          = $current.ParentDN
                DirectUserCount   = $directUsers
                DirectGroupCount  = $directGroups
            })
        }

    } finally {
        if ($ctx -and $ownCtx) { Close-AdLdapConnection $ctx }
    }

    Write-GroupEnumLog -Level 'INFO' -Operation 'GroupTree' `
        -Message "Group tree complete for '$GroupName': $($nodes.Count) node(s)" `
        -Context @{ group = $GroupName; domain = $Domain; nodeCount = $nodes.Count; errorCount = $errors.Count }

    return @{
        RootGroup = @{ Name = $GroupName; DN = $rootGroupDN }
        Nodes     = @($nodes)
        MaxDepth  = $resolvedMaxDepth
        Errors    = $errors
    }
}
