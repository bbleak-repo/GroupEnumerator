<#
.SYNOPSIS
    Domain-wide user search module for migration readiness analysis

.DESCRIPTION
    Searches a target domain for users who were not found during group-member
    correlation. This distinguishes between:
      - Users who do not exist in the target domain at all (need provisioning)
      - Users who exist in the target domain but are not in the matched group

    Searches are scoped to a configurable OU (SearchBase) for performance.
    Indexed attributes are used exclusively: mail, sAMAccountName, sn.

    Connection strategy matches GroupEnumerator: LDAPS 636 first, Kerberos
    Sealing 389 fallback when AllowInsecure is set.

.NOTES
    No emoji in code.
    Depends on New-AdLdapConnection / Invoke-AdLdapSearch / Escape-AdLdapFilterValue
    from ADLdap.ps1 (dot-sourced first).
    Depends on Get-FuzzySamVariants from UserCorrelation.ps1 (dot-sourced first).
    Depends on Write-GroupEnumLog from GroupEnumLogger.ps1 (dot-sourced first).
#>

# ---------------------------------------------------------------------------
# Public: Get-CurrentUserOU
# ---------------------------------------------------------------------------
function Get-CurrentUserOU {
    <#
    .SYNOPSIS
        Detects the OU of the currently logged-in user by querying AD for their DN.

    .DESCRIPTION
        Queries the target domain for the current user's distinguishedName using
        their sAMAccountName ($env:USERNAME). Extracts the parent OU from the DN.
        Returns $null if detection fails (non-domain-joined, no access, etc.).

    .PARAMETER Domain
        Domain to query

    .PARAMETER Credential
        Optional PSCredential

    .PARAMETER Config
        Configuration hashtable (uses AllowInsecure)

    .OUTPUTS
        Hashtable: @{ UserDN = "CN=..."; ParentOU = "OU=Users,..."; Detected = $true/$false; Error = $null }
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Domain,

        [Parameter(Mandatory = $false)]
        [PSCredential]$Credential,

        [Parameter(Mandatory = $false)]
        [hashtable]$Config = @{}
    )

    $allowInsecure = if ($null -ne $Config.AllowInsecure) { [bool]$Config.AllowInsecure } else { $false }
    $timeout       = if ($Config.LdapTimeout) { [int]$Config.LdapTimeout } else { 120 }
    $currentUser   = $env:USERNAME

    if (-not $currentUser) {
        return @{ UserDN = $null; ParentOU = $null; Detected = $false; Error = 'Cannot determine current username from environment' }
    }

    $ctx = $null
    try {
        $connParams = @{ Server = $Domain; TimeoutSeconds = $timeout }
        if ($Credential)    { $connParams.Credential    = $Credential }
        if ($allowInsecure) { $connParams.AllowInsecure = $true }

        try {
            $ctx = New-AdLdapConnection @connParams
        } catch {
            return @{ UserDN = $null; ParentOU = $null; Detected = $false; Error = "Cannot connect to domain '$Domain': $_" }
        }

        $escapedUser = Escape-AdLdapFilterValue $currentUser
        $hits = Invoke-AdLdapSearch -Context $ctx `
            -Filter "(&(objectCategory=person)(sAMAccountName=$escapedUser))" `
            -Attributes @('distinguishedName') `
            -Scope Subtree -SizeLimit 1 -TimeoutSeconds $timeout

        if ($hits -and $hits.Count -gt 0) {
            $userDN = $hits[0].DistinguishedName

            # Extract parent OU: strip the first RDN (CN=username,) from the DN
            $parentOU = $null
            $commaIdx = $userDN.IndexOf(',')
            if ($commaIdx -ge 0) {
                $parentOU = $userDN.Substring($commaIdx + 1).Trim()
            }

            Write-GroupEnumLog -Level 'DEBUG' -Operation 'DetectUserOU' `
                -Message "Detected current user OU: $parentOU" `
                -Context @{ userDN = $userDN; parentOU = $parentOU; domain = $Domain }

            return @{ UserDN = $userDN; ParentOU = $parentOU; Detected = $true; Error = $null }
        } else {
            return @{ UserDN = $null; ParentOU = $null; Detected = $false; Error = "User '$currentUser' not found in domain '$Domain'" }
        }
    } catch {
        return @{ UserDN = $null; ParentOU = $null; Detected = $false; Error = "OU detection failed: $_" }
    } finally {
        if ($ctx -and $ctx.Connection) { try { $ctx.Connection.Dispose() } catch {} }
    }
}

# ---------------------------------------------------------------------------
# Public: Test-SearchBaseExists
# ---------------------------------------------------------------------------
function Test-SearchBaseExists {
    <#
    .SYNOPSIS
        Validates that an LDAP SearchBase (OU path) exists in the target domain.

    .PARAMETER Domain
        Target domain name (NetBIOS or FQDN)

    .PARAMETER SearchBase
        Distinguished Name of the OU to validate (e.g. "OU=Users,DC=partner,DC=com")

    .PARAMETER Credential
        Optional PSCredential for LDAP bind

    .PARAMETER Config
        Configuration hashtable (uses AllowInsecure)

    .OUTPUTS
        Hashtable: @{ Exists = $true/$false; DN = "..."; Error = $null/"message" }
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Domain,

        [Parameter(Mandatory = $true)]
        [string]$SearchBase,

        [Parameter(Mandatory = $false)]
        [PSCredential]$Credential,

        [Parameter(Mandatory = $false)]
        [hashtable]$Config = @{}
    )

    $allowInsecure = if ($null -ne $Config.AllowInsecure) { [bool]$Config.AllowInsecure } else { $false }
    $timeout       = if ($Config.LdapTimeout) { [int]$Config.LdapTimeout } else { 120 }
    $ctx = $null

    try {
        $connParams = @{ Server = $Domain; TimeoutSeconds = $timeout }
        if ($Credential)    { $connParams.Credential    = $Credential }
        if ($allowInsecure) { $connParams.AllowInsecure = $true }

        try {
            $ctx = New-AdLdapConnection @connParams
        } catch {
            return @{
                Exists = $false
                DN     = $SearchBase
                Error  = "Cannot connect to domain '$Domain': $_"
            }
        }

        # Base-scope read against the SearchBase DN. A non-existent base throws
        # ("No Such Object"), which the catch below turns into Exists=$false.
        $hits = Invoke-AdLdapSearch -Context $ctx -BaseDN $SearchBase `
            -Filter '(|(objectCategory=organizationalUnit)(objectCategory=container))' `
            -Attributes @('distinguishedName') `
            -Scope Base -TimeoutSeconds $timeout

        $found = ($null -ne $hits -and $hits.Count -gt 0)

        if ($found) {
            Write-GroupEnumLog -Level 'DEBUG' -Operation 'SearchBaseValidation' `
                -Message "SearchBase validated: $SearchBase" -Context @{ domain = $Domain }
        }

        return @{
            Exists = $found
            DN     = $SearchBase
            Error  = $(if (-not $found) { "SearchBase '$SearchBase' exists but is not an OU or container" } else { $null })
        }
    } catch {
        return @{
            Exists = $false
            DN     = $SearchBase
            Error  = "SearchBase validation failed for '$SearchBase': $_"
        }
    } finally {
        if ($ctx -and $ctx.Connection) { try { $ctx.Connection.Dispose() } catch {} }
    }
}

# ---------------------------------------------------------------------------
# Public: Search-DomainForUser
# ---------------------------------------------------------------------------
function Search-DomainForUser {
    <#
    .SYNOPSIS
        Searches the target domain for a user by email, surname, and SAM variants.

    .DESCRIPTION
        Performs indexed LDAP searches against the target domain to find a user
        account that might correspond to a source domain user. Searches are
        executed in priority order:
          1. Email exact match (mail attribute, indexed)
          2. Surname exact match (sn attribute, indexed)
          3. SAM exact match on fuzzy variants (sAMAccountName, indexed)
          4. SAM prefix match on surname-based patterns (sAMAccountName=LastF*, indexed)

        Stops at the first successful search tier that returns results.
        All searches use objectCategory=person for indexed filtering.

    .PARAMETER Domain
        Target domain to search

    .PARAMETER SearchBase
        Distinguished Name of the OU to scope the search (or $null for domain root)

    .PARAMETER SourceUser
        Hashtable with the source user's attributes: SamAccountName, DisplayName, Email

    .PARAMETER Credential
        Optional PSCredential for LDAP bind

    .PARAMETER Config
        Configuration hashtable (uses AllowInsecure, LdapTimeout)

    .OUTPUTS
        Hashtable:
        @{
            Found          = $true/$false
            Candidates     = @( @{ SamAccountName; DisplayName; Email; DN; MatchMethod } )
            SearchMethod   = "Email"|"Surname"|"SamVariant"|"SamPrefix"|"None"
            Errors         = @()
        }
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Domain,

        [Parameter(Mandatory = $false)]
        [string]$SearchBase,

        [Parameter(Mandatory = $true)]
        [hashtable]$SourceUser,

        [Parameter(Mandatory = $false)]
        [PSCredential]$Credential,

        [Parameter(Mandatory = $false)]
        [hashtable]$Config = @{}
    )

    $errors        = @()
    $allowInsecure = if ($null -ne $Config.AllowInsecure) { $Config.AllowInsecure } else { $false }
    $timeout       = if ($Config.LdapTimeout) { $Config.LdapTimeout } else { 120 }

    $srcSam     = if ($SourceUser.SamAccountName) { $SourceUser.SamAccountName } else { '' }
    $srcEmail   = if ($SourceUser.Email)          { $SourceUser.Email }          else { '' }
    $srcDisplay = if ($SourceUser.DisplayName)    { $SourceUser.DisplayName }    else { '' }

    # Extract surname from DisplayName (assume "FirstName LastName" or "LastName, FirstName")
    $surname = ''
    if ($srcDisplay) {
        if ($srcDisplay -match ',') {
            # "LastName, FirstName" format
            $surname = ($srcDisplay -split ',')[0].Trim()
        } elseif ($srcDisplay -match '\s') {
            # "FirstName LastName" format -- take last word
            $parts = $srcDisplay -split '\s+'
            $surname = $parts[-1].Trim()
        } else {
            $surname = $srcDisplay.Trim()
        }
    }

    # Helper: run a single LDAP search. Opens and disposes its own connection
    # so each tier search is self-contained. New-AdLdapConnection handles the
    # LDAPS -> 389 tier fallback internally based on $allowInsecure.
    $searchDomain = {
        param([string]$Filter, [string]$MethodName)

        $sCtx = $null
        try {
            $cp = @{ Server = $Domain; TimeoutSeconds = $timeout }
            if ($Credential)    { $cp.Credential    = $Credential }
            if ($allowInsecure) { $cp.AllowInsecure = $true }
            $sCtx = New-AdLdapConnection @cp

            $searchParams = @{
                Context        = $sCtx
                Filter         = $Filter
                Attributes     = @('sAMAccountName','displayName','mail','distinguishedName')
                Scope          = 'Subtree'
                PageSize       = 50
                TimeoutSeconds = $timeout
            }
            if ($SearchBase) { $searchParams.BaseDN = $SearchBase }
            $rows = Invoke-AdLdapSearch @searchParams

            $candidates = @()
            foreach ($r in $rows) {
                $candidates += @{
                    SamAccountName = [string]$(if ($r['sAMAccountName'] -is [array]) { $r['sAMAccountName'][0] } else { $r['sAMAccountName'] })
                    DisplayName    = [string]$(if ($r['displayName']    -is [array]) { $r['displayName'][0] }    else { $r['displayName'] })
                    Email          = [string]$(if ($r['mail']           -is [array]) { $r['mail'][0] }           else { $r['mail'] })
                    DN             = [string]$r.DistinguishedName
                    MatchMethod    = $MethodName
                }
            }
            return $candidates
        } finally {
            if ($sCtx -and $sCtx.Connection) { try { $sCtx.Connection.Dispose() } catch {} }
        }
    }

    # Connectivity precheck: surface a clean error if the domain is unreachable
    # before running the search tiers.
    try {
        $preCp = @{ Server = $Domain; TimeoutSeconds = $timeout }
        if ($Credential)    { $preCp.Credential    = $Credential }
        if ($allowInsecure) { $preCp.AllowInsecure = $true }
        $preCtx = New-AdLdapConnection @preCp
        if ($preCtx -and $preCtx.Connection) { try { $preCtx.Connection.Dispose() } catch {} }
    } catch {
        $errors += "Cannot connect to domain '$Domain': $_"
        return @{ Found = $false; Candidates = @(); SearchMethod = 'None'; Errors = $errors }
    }

    # --- Search Tier 1: Email exact match ---
    if ($srcEmail) {
        Write-GroupEnumLog -Level 'DEBUG' -Operation 'DomainLookup' `
            -Message "Searching domain '$Domain' for email '$srcEmail'" `
            -Context @{ sam = $srcSam; method = 'Email' }

        $escapedEmail = Escape-AdLdapFilterValue $srcEmail
        $filter = "(&(objectCategory=person)(mail=$escapedEmail))"
        try {
            $hits = & $searchDomain $filter 'Email'
            if ($hits.Count -gt 0) {
                Write-GroupEnumLog -Level 'DEBUG' -Operation 'DomainLookup' `
                    -Message "Found $($hits.Count) match(es) by email for '$srcSam'" `
                    -Context @{ method = 'Email'; matchCount = $hits.Count }
                return @{ Found = $true; Candidates = $hits; SearchMethod = 'Email'; Errors = $errors }
            }
        } catch {
            $errors += "Email search failed: $_"
        }
    }

    # --- Search Tier 2: Surname exact match ---
    if ($surname) {
        Write-GroupEnumLog -Level 'DEBUG' -Operation 'DomainLookup' `
            -Message "Searching domain '$Domain' for surname '$surname'" `
            -Context @{ sam = $srcSam; method = 'Surname' }

        $escapedSn = Escape-AdLdapFilterValue $surname
        $filter = "(&(objectCategory=person)(sn=$escapedSn))"
        try {
            $hits = & $searchDomain $filter 'Surname'
            if ($hits.Count -gt 0) {
                Write-GroupEnumLog -Level 'DEBUG' -Operation 'DomainLookup' `
                    -Message "Found $($hits.Count) match(es) by surname '$surname' for '$srcSam'" `
                    -Context @{ method = 'Surname'; matchCount = $hits.Count; surname = $surname }
                return @{ Found = $true; Candidates = $hits; SearchMethod = 'Surname'; Errors = $errors }
            }
        } catch {
            $errors += "Surname search failed: $_"
        }
    }

    # --- Search Tier 3: SAM exact match on fuzzy variants ---
    if ($srcSam) {
        $variants = Get-FuzzySamVariants -SamAccountName $srcSam
        # Build OR filter for all variants
        $variantFilters = $variants | ForEach-Object {
            $escaped = Escape-AdLdapFilterValue $_
            "(sAMAccountName=$escaped)"
        }
        if ($variantFilters.Count -gt 0) {
            $orFilter = "(|$($variantFilters -join ''))"
            $filter = "(&(objectCategory=person)$orFilter)"

            Write-GroupEnumLog -Level 'DEBUG' -Operation 'DomainLookup' `
                -Message "Searching domain '$Domain' for SAM variants of '$srcSam' ($($variants.Count) variants)" `
                -Context @{ method = 'SamVariant'; variantCount = $variants.Count }

            try {
                $hits = & $searchDomain $filter 'SamVariant'
                if ($hits.Count -gt 0) {
                    Write-GroupEnumLog -Level 'DEBUG' -Operation 'DomainLookup' `
                        -Message "Found $($hits.Count) match(es) by SAM variants for '$srcSam'" `
                        -Context @{ method = 'SamVariant'; matchCount = $hits.Count }
                    return @{ Found = $true; Candidates = $hits; SearchMethod = 'SamVariant'; Errors = $errors }
                }
            } catch {
                $errors += "SAM variant search failed: $_"
            }
        }
    }

    # --- Search Tier 4: SAM prefix from surname pattern (LastFirst*) ---
    if ($surname -and $srcDisplay) {
        # Extract first initial
        $firstInitial = ''
        if ($srcDisplay -match ',') {
            $firstPart = ($srcDisplay -split ',')[-1].Trim()
            if ($firstPart.Length -gt 0) { $firstInitial = $firstPart[0] }
        } elseif ($srcDisplay -match '\s') {
            $parts = $srcDisplay -split '\s+'
            if ($parts[0].Length -gt 0) { $firstInitial = $parts[0][0] }
        }

        if ($firstInitial) {
            # Build LastnameFirstinitial* pattern
            $prefix = "$surname$firstInitial"
            $escapedPrefix = Escape-AdLdapFilterValue $prefix
            $filter = "(&(objectCategory=person)(sAMAccountName=$escapedPrefix*))"

            Write-GroupEnumLog -Level 'DEBUG' -Operation 'DomainLookup' `
                -Message "Searching domain '$Domain' for SAM prefix '$prefix*'" `
                -Context @{ method = 'SamPrefix'; prefix = $prefix }

            try {
                $hits = & $searchDomain $filter 'SamPrefix'
                if ($hits.Count -gt 0) {
                    Write-GroupEnumLog -Level 'DEBUG' -Operation 'DomainLookup' `
                        -Message "Found $($hits.Count) match(es) by SAM prefix '$prefix*' for '$srcSam'" `
                        -Context @{ method = 'SamPrefix'; matchCount = $hits.Count; prefix = $prefix }
                    return @{ Found = $true; Candidates = $hits; SearchMethod = 'SamPrefix'; Errors = $errors }
                }
            } catch {
                $errors += "SAM prefix search failed: $_"
            }
        }
    }

    # --- No match found ---
    Write-GroupEnumLog -Level 'DEBUG' -Operation 'DomainLookup' `
        -Message "No domain match found for '$srcSam' in '$Domain'" `
        -Context @{ sam = $srcSam; email = $srcEmail; surname = $surname }

    return @{ Found = $false; Candidates = @(); SearchMethod = 'None'; Errors = $errors }
}

# ---------------------------------------------------------------------------
# Public: Resolve-DomainExistence
# ---------------------------------------------------------------------------
function Resolve-DomainExistence {
    <#
    .SYNOPSIS
        Post-processes gap analysis results to split NotProvisioned into
        NotInDomain vs ExistsNotInGroup by searching the target domain.

    .DESCRIPTION
        For each gap item with status "NotProvisioned", performs a domain-wide
        LDAP search in the target domain. If a matching user is found, the
        status is upgraded to "ExistsNotInGroup" (P2) with the candidate
        account details. If not found, status becomes "NotInDomain" (P1).

    .PARAMETER GapResults
        Array of gap analysis results from Get-MigrationGapAnalysis

    .PARAMETER TargetDomain
        The domain name to search (-MigratingTo value)

    .PARAMETER TargetSearchBase
        Optional OU DN to scope searches. $null = search entire domain.

    .PARAMETER Credential
        Optional PSCredential for LDAP bind

    .PARAMETER Config
        Configuration hashtable

    .OUTPUTS
        Modified GapResults array with NotProvisioned split into
        NotInDomain and ExistsNotInGroup. Original array is not mutated;
        a new array is returned.
    #>
    [CmdletBinding()]
    [OutputType([array])]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [array]$GapResults,

        [Parameter(Mandatory = $true)]
        [string]$TargetDomain,

        [Parameter(Mandatory = $false)]
        [string]$TargetSearchBase,

        [Parameter(Mandatory = $false)]
        [PSCredential]$Credential,

        [Parameter(Mandatory = $false)]
        [hashtable]$Config = @{}
    )

    if (-not $GapResults -or $GapResults.Count -eq 0) {
        return , @()
    }

    $totalSearched       = 0
    $foundInDomain       = 0
    $notFoundInDomain    = 0
    $searchErrors        = 0

    Write-GroupEnumLog -Level 'INFO' -Operation 'DomainExistence' `
        -Message "Resolving domain existence for NotProvisioned users in '$TargetDomain'" `
        -Context @{
            targetDomain = $TargetDomain
            searchBase   = $(if ($TargetSearchBase) { $TargetSearchBase } else { '(domain root)' })
            gapResultCount = $GapResults.Count
        }

    $updatedResults = @()

    foreach ($gapResult in $GapResults) {
        # Deep-clone the items list so we don't mutate the original
        $updatedItems = [System.Collections.Generic.List[hashtable]]::new()
        $updatedReadiness = @{}
        if ($gapResult.Readiness) {
            foreach ($k in $gapResult.Readiness.Keys) {
                $updatedReadiness[$k] = $gapResult.Readiness[$k]
            }
        }

        # Track reclassification counts for this group
        $existsNotInGroupCount = 0
        $notInDomainCount      = 0

        foreach ($item in $gapResult.Items) {
            if ($item.Status -eq 'NotProvisioned') {
                $totalSearched++
                $sourceUser = $item.SourceUser

                $lookupResult = Search-DomainForUser `
                    -Domain       $TargetDomain `
                    -SearchBase   $TargetSearchBase `
                    -SourceUser   $sourceUser `
                    -Credential   $Credential `
                    -Config       $Config

                if ($lookupResult.Found -and $lookupResult.Candidates.Count -gt 0) {
                    $foundInDomain++
                    $existsNotInGroupCount++
                    $bestCandidate = $lookupResult.Candidates[0]
                    $targetGroupName = if ($gapResult.GroupPair) { $gapResult.GroupPair.TargetGroup } else { '' }
                    $targetDomainName = if ($gapResult.GroupPair) { $gapResult.GroupPair.TargetDomain } else { $TargetDomain }

                    $updatedItems.Add(@{
                        Status                = 'ExistsNotInGroup'
                        Priority              = 'P2'
                        SourceUser            = $sourceUser
                        TargetUser            = @{
                            SamAccountName = $bestCandidate.SamAccountName
                            DisplayName    = $bestCandidate.DisplayName
                            Email          = $bestCandidate.Email
                        }
                        CorrelationConfidence = 'DomainSearch'
                        Action                = "Add $($bestCandidate.SamAccountName) to $targetDomainName\$targetGroupName"
                        Notes                 = "Found in target domain via $($lookupResult.SearchMethod) search. $(if ($lookupResult.Candidates.Count -gt 1) { "$($lookupResult.Candidates.Count) candidates found -- review recommended." } else { '' })"
                        DomainSearchResult    = $lookupResult
                    })

                    Write-GroupEnumLog -Level 'INFO' -Operation 'DomainExistence' `
                        -Message "User '$($sourceUser.SamAccountName)' found in target domain as '$($bestCandidate.SamAccountName)' via $($lookupResult.SearchMethod)" `
                        -Context @{
                            sourceSam  = $sourceUser.SamAccountName
                            targetSam  = $bestCandidate.SamAccountName
                            method     = $lookupResult.SearchMethod
                            candidates = $lookupResult.Candidates.Count
                        }
                } else {
                    $notFoundInDomain++
                    $notInDomainCount++

                    $updatedItems.Add(@{
                        Status                = 'NotInDomain'
                        Priority              = 'P1'
                        SourceUser            = $sourceUser
                        TargetUser            = $null
                        CorrelationConfidence = 'None'
                        Action                = "Provision user account in $TargetDomain domain"
                        Notes                 = "No matching account found in target domain (searched: email, surname, SAM variants)"
                        DomainSearchResult    = $lookupResult
                    })

                    Write-GroupEnumLog -Level 'WARN' -Operation 'DomainExistence' `
                        -Message "User '$($sourceUser.SamAccountName)' NOT found in target domain '$TargetDomain'" `
                        -Context @{ sourceSam = $sourceUser.SamAccountName; email = $sourceUser.Email }
                }

                if ($lookupResult.Errors.Count -gt 0) {
                    $searchErrors++
                }
            } else {
                # Not NotProvisioned -- keep as-is
                $updatedItems.Add($item)
            }
        }

        # Update readiness counts
        if ($updatedReadiness.Count -gt 0) {
            # Remove old NotProvisionedCount, add new breakdowns
            $oldNotProv = if ($updatedReadiness.NotProvisionedCount) { $updatedReadiness.NotProvisionedCount } else { 0 }
            $updatedReadiness.NotProvisionedCount  = 0
            $updatedReadiness.NotInDomainCount     = $notInDomainCount
            $updatedReadiness.ExistsNotInGroupCount = $existsNotInGroupCount
            # AddToGroup now includes ExistsNotInGroup for readiness
            $updatedReadiness.AddToGroupCount = $updatedReadiness.AddToGroupCount + $existsNotInGroupCount
        }

        $updatedResults += @{
            GroupPair = $gapResult.GroupPair
            Items     = $updatedItems.ToArray()
            Readiness = $updatedReadiness
            Errors    = $gapResult.Errors
        }
    }

    Write-GroupEnumLog -Level 'INFO' -Operation 'DomainExistence' `
        -Message "Domain existence check complete: $foundInDomain found, $notFoundInDomain not found, $searchErrors errors" `
        -Context @{
            totalSearched    = $totalSearched
            foundInDomain    = $foundInDomain
            notFoundInDomain = $notFoundInDomain
            searchErrors     = $searchErrors
        }

    return , $updatedResults
}
