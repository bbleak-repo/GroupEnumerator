<#
.SYNOPSIS
    Cross-domain user identity correlation module for cross-domain migration support

.DESCRIPTION
    Correlates users between two AD domains where accounts are distinct contractor
    identities (e.g. jsmith in CORP vs jsmith02 in PARTNER). Because no single
    reliable key exists across domains, matching is attempted through five tiers:

      Tier 1 - Email exact match    (High confidence, auto-correlate)
      Tier 2 - SAM exact match      (Medium confidence, flag review)
      Tier 3 - DisplayName normalized (Medium confidence, flag review)
               Strips SailPoint/Okta/IdM tags before comparison
      Tier 4 - SAM fuzzy match      (Low confidence, flag human review)
      Tier 5 - No match             (Report as unmatched)

    This module NEVER auto-acts on matches. All results are flagged appropriately
    for human sign-off before any migration changes are made.

    Depends on:
      - Get-SimilarityScore from FuzzyMatcher.ps1 (must be dot-sourced first)
      - Write-GroupEnumLog from GroupEnumLogger.ps1 (must be dot-sourced first)

.NOTES
    No LDAP activity in this module. Input is already-enumerated member arrays.
    Compatible with PowerShell 5.1 and PowerShell 7+.
    Dot-sourced files do NOT use Export-ModuleMember.
#>

# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

function _UCorp_NullOrEmpty {
    # Returns $true when a string is null, empty, or whitespace-only.
    param([string]$Value)
    return [string]::IsNullOrWhiteSpace($Value)
}

function _UCorp_SafeLower {
    # Returns lowercase string or empty string if null.
    param([string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value)) { return '' }
    return $Value.Trim().ToLower()
}

function _UCorp_NormalizeDisplayName {
    # Normalizes a DisplayName for cross-domain comparison by stripping
    # identity system tags commonly appended by SailPoint, Okta, etc.
    # Examples:
    #   "John Smith (SailPoint)"      -> "john smith"
    #   "SailPoint - John Smith"      -> "john smith"
    #   "John Smith [Contractor]"     -> "john smith"
    #   "John Smith - EXT"            -> "john smith"
    #   "John Smith (Okta Provisioned)" -> "john smith"
    param([string]$DisplayName)
    if ([string]::IsNullOrWhiteSpace($DisplayName)) { return '' }

    $name = $DisplayName.Trim()

    # Strip trailing parenthetical tags: "(SailPoint)", "(Contractor)", "(EXT)", etc.
    $name = $name -replace '\s*\([^)]*\)\s*$', ''

    # Strip trailing bracketed tags: "[Contractor]", "[SailPoint]", etc.
    $name = $name -replace '\s*\[[^\]]*\]\s*$', ''

    # Strip leading identity system prefixes: "SailPoint - ", "Okta - ", "SP - "
    $name = $name -replace '(?i)^(sailpoint|okta|sp|idm|iam)\s*[-:]\s*', ''

    # Strip trailing identity system suffixes: " - SailPoint", " - EXT", " - Contractor"
    $name = $name -replace '(?i)\s*[-:]\s*(sailpoint|okta|sp|ext|contractor|vendor|external|idm|iam)\s*$', ''

    # Strip trailing common suffixes without separator: " EXT", " CONTRACTOR"
    $name = $name -replace '(?i)\s+(ext|contractor|vendor|external)\s*$', ''

    # Normalize whitespace and lowercase
    $name = ($name -replace '\s+', ' ').Trim().ToLower()

    return $name
}

function _UCorp_UserKey {
    # Builds a collision-resistant key for a user hashtable.
    # Prefer DistinguishedName; fall back to Domain+SAM.
    param([hashtable]$User)
    if (-not [string]::IsNullOrWhiteSpace($User.DistinguishedName)) {
        return $User.DistinguishedName.ToLower()
    }
    $domain = _UCorp_SafeLower $User.Domain
    $sam    = _UCorp_SafeLower $User.SamAccountName
    return "$domain|$sam"
}

# ---------------------------------------------------------------------------
# Public: Get-FuzzySamVariants
# ---------------------------------------------------------------------------

function Get-FuzzySamVariants {
    <#
    .SYNOPSIS
        Generates likely SAM account name variants for cross-domain contractor accounts

    .DESCRIPTION
        Contractor accounts frequently differ between domains by trailing numeric
        suffixes (jsmith -> jsmith02), dots (jsmith -> j.smith), or domain-specific
        prefixes/suffixes (jsmith -> ext_jsmith, jsmith_ext).

        This function returns a de-duplicated array of lowercase variant strings
        that Find-UserCorrelations uses for Tier 4 fuzzy matching.

        Transformations applied:
          - The original name (lowercased)
          - Trailing-digit variants: append 1-5, 01-05
          - Strip trailing digits from the original (jsmith02 -> jsmith)
          - Add dot after first character (jsmith -> j.smith)
          - Strip common contractor prefixes: a_, c_, ext_, ext., ext-, vendor_
          - Add common contractor suffixes: _ext, .ext, -ext, _c, _vendor
          - Add common contractor prefixes: ext., ext_, ext-, c_, a_, vendor_

    .PARAMETER SamAccountName
        The source SAM account name to generate variants for

    .OUTPUTS
        Array of unique lowercase variant strings
    #>
    [CmdletBinding()]
    [OutputType([string[]])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$SamAccountName
    )

    $base = $SamAccountName.Trim().ToLower()
    $variants = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase
    )

    # Always include original
    $null = $variants.Add($base)

    # --- Strip common contractor prefixes from the original ---
    $prefixPatterns = @('a_', 'c_', 'ext_', 'ext.', 'ext-', 'vendor_', 'contractor_')
    $stripped = $base
    foreach ($p in $prefixPatterns) {
        if ($base.Length -gt $p.Length -and $base.StartsWith($p)) {
            $stripped = $base.Substring($p.Length)
            $null = $variants.Add($stripped)
            break
        }
    }

    # Work from the stripped base for further variants
    $root = $stripped

    # --- Strip trailing digits from the root (jsmith02 -> jsmith) ---
    $rootNoDigits = $root -replace '\d+$', ''
    if ($rootNoDigits -ne $root -and $rootNoDigits.Length -gt 0) {
        $null = $variants.Add($rootNoDigits)
    } else {
        $rootNoDigits = $root
    }

    # --- Trailing-digit variants on the digit-stripped root ---
    $digitSuffixes = @('1', '2', '3', '4', '5', '01', '02', '03', '04', '05')
    foreach ($suffix in $digitSuffixes) {
        $null = $variants.Add("$rootNoDigits$suffix")
    }

    # --- Dot-separated variant: j.smith (insert dot after first character) ---
    if ($rootNoDigits.Length -gt 1) {
        $dotVariant = $rootNoDigits[0] + '.' + $rootNoDigits.Substring(1)
        $null = $variants.Add($dotVariant)
    }

    # --- Common contractor suffixes appended to the digit-stripped root ---
    $suffixes = @('_ext', '.ext', '-ext', '_c', '_vendor', '_contractor')
    foreach ($s in $suffixes) {
        $null = $variants.Add("$rootNoDigits$s")
    }

    # --- Common contractor prefixes prepended to the digit-stripped root ---
    $prefixes = @('ext.', 'ext_', 'ext-', 'c_', 'a_', 'vendor_', 'contractor_')
    foreach ($p in $prefixes) {
        $null = $variants.Add("$p$rootNoDigits")
    }

    # Return as plain array, sorted for deterministic output
    return [string[]]($variants | Sort-Object)
}

# ---------------------------------------------------------------------------
# Public: Get-UserMatchScore
# ---------------------------------------------------------------------------

function Get-UserMatchScore {
    <#
    .SYNOPSIS
        Scores a potential user pair across multiple attributes

    .DESCRIPTION
        Evaluates a single source/target user pair for all matching criteria and
        returns the best tier found along with supporting details. Does not modify
        any shared state and does not claim the match -- that is handled by
        Find-UserCorrelations.

        The returned hashtable is also used internally by Find-UserCorrelations
        to decide tier assignment.

    .PARAMETER SourceUser
        User hashtable from the source domain. Expected keys:
          SamAccountName, DisplayName, Email, Enabled, Domain, DistinguishedName

    .PARAMETER TargetUser
        User hashtable from the target domain. Same structure as SourceUser.

    .PARAMETER FuzzyThreshold
        Minimum Levenshtein similarity score for a SAM fuzzy match (default 0.7).

    .OUTPUTS
        Hashtable:
          @{
            EmailMatch       = $true/$false
            SamExactMatch    = $true/$false
            SamFuzzyScore    = [double]
            DisplayNameMatch = $true/$false
            BestTier         = [int] 1-5
            Confidence       = "High"/"Medium"/"Low"/"None"
            NeedsReview      = $true/$false
            MatchDetails     = [string]
          }
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$SourceUser,

        [Parameter(Mandatory = $true)]
        [hashtable]$TargetUser,

        [Parameter(Mandatory = $false)]
        [double]$FuzzyThreshold = 0.7
    )

    $emailMatch       = $false
    $samExactMatch    = $false
    $samFuzzyScore    = 0.0
    $displayNameMatch = $false
    $bestTier         = 5
    $confidence       = 'None'
    $needsReview      = $false
    $matchDetails     = 'No match found'

    # Self-match guard: same DN is never a valid cross-domain correlation
    $srcKey = _UCorp_UserKey $SourceUser
    $tgtKey = _UCorp_UserKey $TargetUser
    if ($srcKey -eq $tgtKey) {
        return @{
            EmailMatch       = $false
            SamExactMatch    = $false
            SamFuzzyScore    = 0.0
            DisplayNameMatch = $false
            BestTier         = 5
            Confidence       = 'None'
            NeedsReview      = $false
            MatchDetails     = 'Self-match prevented (same distinguished name)'
        }
    }

    $srcSam  = _UCorp_SafeLower $SourceUser.SamAccountName
    $tgtSam  = _UCorp_SafeLower $TargetUser.SamAccountName
    $srcEmail = _UCorp_SafeLower $SourceUser.Email
    $tgtEmail = _UCorp_SafeLower $TargetUser.Email
    $srcDN   = _UCorp_NormalizeDisplayName $SourceUser.DisplayName
    $tgtDN   = _UCorp_NormalizeDisplayName $TargetUser.DisplayName

    # --- Tier 1: Email exact match ---
    if (-not (_UCorp_NullOrEmpty $srcEmail) -and -not (_UCorp_NullOrEmpty $tgtEmail)) {
        if ($srcEmail -eq $tgtEmail) {
            $emailMatch   = $true
            $bestTier     = 1
            $confidence   = 'High'
            $needsReview  = $false
            $matchDetails = "Email exact match: $srcEmail"
        }
    }

    # --- Tier 2: SAM exact match ---
    if ($bestTier -gt 2 -and -not (_UCorp_NullOrEmpty $srcSam) -and -not (_UCorp_NullOrEmpty $tgtSam)) {
        if ($srcSam -eq $tgtSam) {
            $samExactMatch = $true
            $bestTier      = 2
            $confidence    = 'Medium'
            $needsReview   = $true
            $matchDetails  = "SAM exact match: $srcSam"
        }
    }

    # --- Tier 3: DisplayName exact match ---
    if ($bestTier -gt 3 -and -not (_UCorp_NullOrEmpty $srcDN) -and -not (_UCorp_NullOrEmpty $tgtDN)) {
        if ($srcDN -eq $tgtDN) {
            $displayNameMatch = $true
            $bestTier         = 3
            $confidence       = 'Medium'
            $needsReview      = $true
            $matchDetails     = "DisplayName normalized match: '$($SourceUser.DisplayName)' ~ '$($TargetUser.DisplayName)'"
        }
    }

    # --- Tier 4: SAM fuzzy match ---
    if ($bestTier -gt 4 -and -not (_UCorp_NullOrEmpty $srcSam) -and -not (_UCorp_NullOrEmpty $tgtSam)) {
        # Check SAM variants first (cheaper than full Levenshtein against all targets)
        $variants = Get-FuzzySamVariants -SamAccountName $srcSam
        if ($variants -contains $tgtSam) {
            # Variant hit -- compute the actual score for reporting
            $score = Get-SimilarityScore -Name1 $srcSam -Name2 $tgtSam
            $samFuzzyScore = $score
            if ($score -ge $FuzzyThreshold) {
                $bestTier     = 4
                $confidence   = 'Low'
                $needsReview  = $true
                $matchDetails = "SAM variant match: $srcSam ~ $tgtSam (score $([Math]::Round($score, 4)))"
            }
        }

        # Direct Levenshtein score (catches cases the variant list misses)
        if ($bestTier -gt 4) {
            $score = Get-SimilarityScore -Name1 $srcSam -Name2 $tgtSam
            if ($score -gt $samFuzzyScore) { $samFuzzyScore = $score }
            if ($score -ge $FuzzyThreshold) {
                $bestTier     = 4
                $confidence   = 'Low'
                $needsReview  = $true
                $matchDetails = "SAM fuzzy match: $srcSam ~ $tgtSam (score $([Math]::Round($score, 4)))"
            }
        }
    }

    return @{
        EmailMatch       = $emailMatch
        SamExactMatch    = $samExactMatch
        SamFuzzyScore    = $samFuzzyScore
        DisplayNameMatch = $displayNameMatch
        BestTier         = $bestTier
        Confidence       = $confidence
        NeedsReview      = $needsReview
        MatchDetails     = $matchDetails
    }
}

# ---------------------------------------------------------------------------
# Public: Find-UserCorrelations
# ---------------------------------------------------------------------------

function Find-UserCorrelations {
    <#
    .SYNOPSIS
        Correlates users from a source domain member list against a target domain member list

    .DESCRIPTION
        Implements a five-tier correlation strategy (email -> SAM exact -> DisplayName
        -> SAM fuzzy -> unmatched) to identify likely identity pairs across two AD
        domains where contractor accounts do not share a common key.

        Each target user can only be claimed once (first-come-first-served by tier
        priority). Matches flagged NeedsReview=true must be validated by a human
        before any migration action is taken.

        Self-matches (same DistinguishedName) are always prevented.

        Requires Get-SimilarityScore (FuzzyMatcher.ps1) and Write-GroupEnumLog
        (GroupEnumLogger.ps1) to be available in the session.

    .PARAMETER SourceMembers
        Array of user hashtables from the source domain.
        Each hashtable must contain: SamAccountName, DisplayName, Email,
        Enabled, Domain, DistinguishedName

    .PARAMETER TargetMembers
        Array of user hashtables from the target domain. Same structure.

    .PARAMETER Config
        Optional configuration hashtable. Recognised keys:
          CorrelationStrategy - string, reserved for future use (default 'email-first')

    .PARAMETER FuzzyThreshold
        Minimum Levenshtein similarity score (0.0-1.0) for a SAM fuzzy match.
        Matches scoring below this threshold are not recorded.
        Default: 0.7

    .OUTPUTS
        Hashtable:
          @{
            Correlated        = @( ... )   # Matched pairs
            UnmatchedSource   = @( ... )   # Source users with no target match
            UnmatchedTarget   = @( ... )   # Target users claimed by nobody
            NeedsReview       = @( ... )   # Subset of Correlated where NeedsReview=$true
            Summary           = @{ ... }   # Counts and confidence breakdown
          }

        Each Correlated entry:
          @{
            SourceUser   = <user hashtable>
            TargetUser   = <user hashtable>
            MatchTier    = [int] 1-4
            MatchType    = [string]
            Confidence   = "High"/"Medium"/"Low"
            Score        = [double]
            NeedsReview  = [bool]
            ReviewReason = [string]
          }

    .EXAMPLE
        $result = Find-UserCorrelations -SourceMembers $corpUsers -TargetMembers $partnerUsers
        $result.Summary | Format-Table
        $result.NeedsReview | ForEach-Object { "$($_.SourceUser.SamAccountName) -> $($_.TargetUser.SamAccountName): $($_.ReviewReason)" }
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [array]$SourceMembers,

        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [array]$TargetMembers,

        [Parameter(Mandatory = $false)]
        [hashtable]$Config = @{},

        [Parameter(Mandatory = $false)]
        [double]$FuzzyThreshold = 0.7
    )

    Write-GroupEnumLog -Level 'INFO' -Operation 'UserCorrelation' `
        -Message 'Starting user correlation' `
        -Context @{
            SourceCount    = $SourceMembers.Count
            TargetCount    = $TargetMembers.Count
            FuzzyThreshold = $FuzzyThreshold
            Strategy       = $(if ($Config.CorrelationStrategy) { $Config.CorrelationStrategy } else { 'email-first' })
        }

    # ------------------------------------------------------------------
    # Build lookup indexes for target users
    # ------------------------------------------------------------------
    # Key: lowercase email -> array of target user hashtables
    $targetByEmail = @{}
    # Key: lowercase SAM -> array of target user hashtables
    $targetBySam   = @{}
    # Key: lowercase DisplayName -> array of target user hashtables
    $targetByDN    = @{}

    foreach ($tUser in $TargetMembers) {
        if (-not $tUser) { continue }

        $email = _UCorp_SafeLower $tUser.Email
        $sam   = _UCorp_SafeLower $tUser.SamAccountName
        $dn    = _UCorp_NormalizeDisplayName $tUser.DisplayName

        if (-not (_UCorp_NullOrEmpty $email)) {
            if (-not $targetByEmail.ContainsKey($email)) {
                $targetByEmail[$email] = @()
            }
            $targetByEmail[$email] += $tUser
            if ($targetByEmail[$email].Count -gt 1) {
                Write-GroupEnumLog -Level 'WARN' -Operation 'UserCorrelation' `
                    -Message "Duplicate email in target members -- only first match will be used" `
                    -Context @{ Email = $email; Count = $targetByEmail[$email].Count }
            }
        }

        if (-not (_UCorp_NullOrEmpty $sam)) {
            if (-not $targetBySam.ContainsKey($sam)) {
                $targetBySam[$sam] = @()
            }
            $targetBySam[$sam] += $tUser
        }

        if (-not (_UCorp_NullOrEmpty $dn)) {
            if (-not $targetByDN.ContainsKey($dn)) {
                $targetByDN[$dn] = @()
            }
            $targetByDN[$dn] += $tUser
        }
    }

    # ------------------------------------------------------------------
    # Tracking structures
    # ------------------------------------------------------------------
    # claimedTargetKeys: set of target user keys that have been claimed
    $claimedTargetKeys = @{}

    $correlated      = @()
    $unmatchedSource = @()
    $needsReview     = @()

    # Confidence counters
    $highCount   = 0
    $mediumCount = 0
    $lowCount    = 0

    # ------------------------------------------------------------------
    # Attempt to claim a target user (first-come-first-served)
    # Returns $true if the claim succeeded, $false if already claimed.
    # ------------------------------------------------------------------
    # (Inline logic below -- no nested function to avoid PS scope issues)

    # ------------------------------------------------------------------
    # Process each source user
    # ------------------------------------------------------------------
    foreach ($sUser in $SourceMembers) {
        if (-not $sUser) { continue }

        $srcSam   = _UCorp_SafeLower $sUser.SamAccountName
        $srcEmail = _UCorp_SafeLower $sUser.Email
        $srcDN    = _UCorp_NormalizeDisplayName $sUser.DisplayName
        $srcKey   = _UCorp_UserKey $sUser

        Write-GroupEnumLog -Level 'DEBUG' -Operation 'UserCorrelation' `
            -Message "Correlating source user: $srcSam" `
            -Context @{ SamAccountName = $srcSam; Email = $srcEmail; Domain = $sUser.Domain }

        $matched      = $false
        $matchTier    = 5
        $matchType    = 'None'
        $matchConf    = 'None'
        $matchScore   = 0.0
        $matchReview  = $false
        $reviewReason = ''
        $matchedTarget = $null

        # --------------------------------------------------------------
        # Tier 1: Email exact match
        # --------------------------------------------------------------
        if (-not $matched -and -not (_UCorp_NullOrEmpty $srcEmail) -and $targetByEmail.ContainsKey($srcEmail)) {
            $candidates = $targetByEmail[$srcEmail]
            foreach ($cand in $candidates) {
                $tKey = _UCorp_UserKey $cand
                # Self-match guard
                if ($tKey -eq $srcKey) { continue }
                # Claim check
                if ($claimedTargetKeys.ContainsKey($tKey)) { continue }

                $claimedTargetKeys[$tKey] = $true
                $matchedTarget = $cand
                $matched       = $true
                $matchTier     = 1
                $matchType     = 'Email Exact'
                $matchConf     = 'High'
                $matchScore    = 1.0
                $matchReview   = $false
                $reviewReason  = ''
                break
            }
        }

        # --------------------------------------------------------------
        # Tier 2: SAM exact match
        # --------------------------------------------------------------
        if (-not $matched -and -not (_UCorp_NullOrEmpty $srcSam) -and $targetBySam.ContainsKey($srcSam)) {
            $candidates = $targetBySam[$srcSam]
            foreach ($cand in $candidates) {
                $tKey = _UCorp_UserKey $cand
                if ($tKey -eq $srcKey) { continue }
                if ($claimedTargetKeys.ContainsKey($tKey)) { continue }

                $claimedTargetKeys[$tKey] = $true
                $matchedTarget = $cand
                $matched       = $true
                $matchTier     = 2
                $matchType     = 'SAM Exact'
                $matchConf     = 'Medium'
                $matchScore    = 1.0
                $matchReview   = $true
                $reviewReason  = "SAM exact match across domains: verify these are the same person ($srcSam)"
                break
            }
        }

        # --------------------------------------------------------------
        # Tier 3: DisplayName exact match
        # --------------------------------------------------------------
        if (-not $matched -and -not (_UCorp_NullOrEmpty $srcDN) -and $targetByDN.ContainsKey($srcDN)) {
            $candidates = $targetByDN[$srcDN]
            foreach ($cand in $candidates) {
                $tKey = _UCorp_UserKey $cand
                if ($tKey -eq $srcKey) { continue }
                if ($claimedTargetKeys.ContainsKey($tKey)) { continue }

                $claimedTargetKeys[$tKey] = $true
                $matchedTarget = $cand
                $matched       = $true
                $matchTier     = 3
                $matchType     = 'DisplayName Exact'
                $matchConf     = 'Medium'
                $matchScore    = 1.0
                $matchReview   = $true
                $reviewReason  = "DisplayName normalized match: '$($sUser.DisplayName)' ~ '$($cand.DisplayName)' -- confirm identity before migrating"
                break
            }
        }

        # --------------------------------------------------------------
        # Tier 4: SAM fuzzy match
        # --------------------------------------------------------------
        if (-not $matched -and -not (_UCorp_NullOrEmpty $srcSam)) {

            # Build the set of unclaimed target SAMs for comparison
            $bestScore    = 0.0
            $bestCandidate = $null

            # First pass: check generated SAM variants against the index
            $variants = Get-FuzzySamVariants -SamAccountName $srcSam
            foreach ($v in $variants) {
                if ($v -eq $srcSam) { continue }   # skip self
                if (-not $targetBySam.ContainsKey($v)) { continue }

                foreach ($cand in $targetBySam[$v]) {
                    $tKey = _UCorp_UserKey $cand
                    if ($tKey -eq $srcKey) { continue }
                    if ($claimedTargetKeys.ContainsKey($tKey)) { continue }

                    $score = Get-SimilarityScore -Name1 $srcSam -Name2 $v
                    if ($score -ge $FuzzyThreshold -and $score -gt $bestScore) {
                        $bestScore     = $score
                        $bestCandidate = $cand
                    }
                }
            }

            # Second pass: Levenshtein against all unclaimed target SAMs
            # (catches cases where the variant list does not generate the exact form)
            foreach ($tSam in $targetBySam.Keys) {
                if ($tSam -eq $srcSam) { continue }  # already handled in Tier 2

                foreach ($cand in $targetBySam[$tSam]) {
                    $tKey = _UCorp_UserKey $cand
                    if ($tKey -eq $srcKey) { continue }
                    if ($claimedTargetKeys.ContainsKey($tKey)) { continue }

                    $score = Get-SimilarityScore -Name1 $srcSam -Name2 $tSam
                    if ($score -ge $FuzzyThreshold -and $score -gt $bestScore) {
                        $bestScore     = $score
                        $bestCandidate = $cand
                    }
                }
            }

            if ($null -ne $bestCandidate) {
                $tKey = _UCorp_UserKey $bestCandidate
                # Claim the best candidate (score check already applied above)
                if (-not $claimedTargetKeys.ContainsKey($tKey)) {
                    $claimedTargetKeys[$tKey] = $true
                    $tSamDisplay = _UCorp_SafeLower $bestCandidate.SamAccountName
                    $matchedTarget = $bestCandidate
                    $matched       = $true
                    $matchTier     = 4
                    $matchType     = 'SAM Fuzzy'
                    $matchConf     = 'Low'
                    $matchScore    = [Math]::Round($bestScore, 4)
                    $matchReview   = $true
                    $reviewReason  = "Fuzzy SAM match: $srcSam ~ $tSamDisplay (score $matchScore) -- manual verification required"
                }
            }
        }

        # --------------------------------------------------------------
        # Record result
        # --------------------------------------------------------------
        if ($matched) {
            $entry = @{
                SourceUser   = $sUser
                TargetUser   = $matchedTarget
                MatchTier    = $matchTier
                MatchType    = $matchType
                Confidence   = $matchConf
                Score        = $matchScore
                NeedsReview  = $matchReview
                ReviewReason = $reviewReason
            }
            $correlated += $entry

            if ($matchReview) {
                $needsReview += $entry
            }

            switch ($matchConf) {
                'High'   { $highCount++ }
                'Medium' { $mediumCount++ }
                'Low'    { $lowCount++ }
            }

            Write-GroupEnumLog -Level 'DEBUG' -Operation 'UserCorrelation' `
                -Message "Correlated: $srcSam -> $(_UCorp_SafeLower $matchedTarget.SamAccountName) (Tier $matchTier, $matchConf)" `
                -Context @{
                    SourceSam  = $srcSam
                    TargetSam  = _UCorp_SafeLower $matchedTarget.SamAccountName
                    Tier       = $matchTier
                    Confidence = $matchConf
                    Score      = $matchScore
                    Review     = $matchReview
                }

            if ($matchReview) {
                Write-GroupEnumLog -Level 'WARN' -Operation 'UserCorrelation' `
                    -Message "Low-confidence match requires review: $srcSam -> $(_UCorp_SafeLower $matchedTarget.SamAccountName)" `
                    -Context @{ ReviewReason = $reviewReason; MatchTier = $matchTier }
            }
        } else {
            $unmatchedSource += @{
                User   = $sUser
                Reason = 'No matching user found in target domain'
            }
            Write-GroupEnumLog -Level 'DEBUG' -Operation 'UserCorrelation' `
                -Message "No match for source user: $srcSam" `
                -Context @{ SamAccountName = $srcSam; Domain = $sUser.Domain }
        }
    }

    # ------------------------------------------------------------------
    # Build UnmatchedTarget (orphaned target users)
    # ------------------------------------------------------------------
    $unmatchedTarget = @()
    foreach ($tUser in $TargetMembers) {
        if (-not $tUser) { continue }
        $tKey = _UCorp_UserKey $tUser
        if (-not $claimedTargetKeys.ContainsKey($tKey)) {
            $unmatchedTarget += @{
                User   = $tUser
                Reason = 'Not correlated to any source user (orphaned access?)'
            }
        }
    }

    # ------------------------------------------------------------------
    # Warn on large unmatched counts
    # ------------------------------------------------------------------
    $unmatchedSourcePct = $(if ($SourceMembers.Count -gt 0) {
        [Math]::Round(($unmatchedSource.Count / $SourceMembers.Count) * 100, 1)
    } else { 0 })

    if ($unmatchedSource.Count -gt 0) {
        Write-GroupEnumLog -Level 'WARN' -Operation 'UserCorrelation' `
            -Message "$($unmatchedSource.Count) source user(s) have no target match ($unmatchedSourcePct%)" `
            -Context @{ UnmatchedCount = $unmatchedSource.Count; Percent = $unmatchedSourcePct }
    }

    if ($unmatchedTarget.Count -gt 0) {
        Write-GroupEnumLog -Level 'WARN' -Operation 'UserCorrelation' `
            -Message "$($unmatchedTarget.Count) target user(s) are orphaned (no source correlation)" `
            -Context @{ OrphanedCount = $unmatchedTarget.Count }
    }

    $summary = @{
        TotalSource          = $SourceMembers.Count
        TotalTarget          = $TargetMembers.Count
        CorrelatedCount      = $correlated.Count
        HighConfidence       = $highCount
        MediumConfidence     = $mediumCount
        LowConfidence        = $lowCount
        UnmatchedSourceCount = $unmatchedSource.Count
        UnmatchedTargetCount = $unmatchedTarget.Count
        NeedsReviewCount     = $needsReview.Count
    }

    Write-GroupEnumLog -Level 'INFO' -Operation 'UserCorrelation' `
        -Message 'User correlation complete' `
        -Context $summary

    return @{
        Correlated      = $correlated
        UnmatchedSource = $unmatchedSource
        UnmatchedTarget = $unmatchedTarget
        NeedsReview     = $needsReview
        Summary         = $summary
    }
}

# ---------------------------------------------------------------------------
# Public: Get-CorrelationSummaryText
# ---------------------------------------------------------------------------

function Get-CorrelationSummaryText {
    <#
    .SYNOPSIS
        Generates a human-readable summary of correlation results for report embedding

    .DESCRIPTION
        Formats the output of Find-UserCorrelations into a multi-line plain-text
        summary suitable for inclusion in migration reports, change requests, or
        email bodies.

        Includes overall statistics, confidence breakdown, and a flagged-items
        section listing every match that needs human review.

    .PARAMETER CorrelationResult
        The hashtable returned by Find-UserCorrelations

    .OUTPUTS
        Multi-line string
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$CorrelationResult
    )

    $s = $CorrelationResult.Summary
    $lines = @()

    $lines += 'USER CORRELATION SUMMARY'
    $lines += '========================'
    $lines += ''

    # Overall counts
    $lines += "Source domain users:   $($s.TotalSource)"
    $lines += "Target domain users:   $($s.TotalTarget)"
    $lines += "Correlated pairs:      $($s.CorrelatedCount)"
    $lines += "Unmatched (source):    $($s.UnmatchedSourceCount)"
    $lines += "Orphaned (target):     $($s.UnmatchedTargetCount)"
    $lines += "Flagged for review:    $($s.NeedsReviewCount)"
    $lines += ''

    # Confidence breakdown
    $lines += 'CONFIDENCE BREAKDOWN'
    $lines += '--------------------'
    $lines += "  High   (Tier 1 - Email exact):       $($s.HighConfidence)"
    $lines += "  Medium (Tier 2/3 - SAM/Name exact):  $($s.MediumConfidence)"
    $lines += "  Low    (Tier 4 - SAM fuzzy):          $($s.LowConfidence)"
    $lines += ''

    # Coverage percentage
    if ($s.TotalSource -gt 0) {
        $pct = [Math]::Round(($s.CorrelatedCount / $s.TotalSource) * 100, 1)
        $lines += "Coverage: $pct% of source users have a target correlation"
        $lines += ''
    }

    # Items needing human review
    if ($CorrelationResult.NeedsReview.Count -gt 0) {
        $lines += 'MATCHES REQUIRING HUMAN REVIEW'
        $lines += '------------------------------'
        foreach ($item in $CorrelationResult.NeedsReview) {
            $srcSam = $item.SourceUser.SamAccountName
            $tgtSam = $item.TargetUser.SamAccountName
            $tier   = $item.MatchTier
            $conf   = $item.Confidence
            $reason = $item.ReviewReason
            $lines += "  [Tier $tier / $conf]  $srcSam  ->  $tgtSam"
            $lines += "    Reason: $reason"
        }
        $lines += ''
    }

    # Unmatched source users
    if ($CorrelationResult.UnmatchedSource.Count -gt 0) {
        $lines += 'UNMATCHED SOURCE USERS (not provisioned in target domain?)'
        $lines += '----------------------------------------------------------'
        foreach ($item in $CorrelationResult.UnmatchedSource) {
            $u = $item.User
            $lines += "  $($u.SamAccountName)  ($($u.DisplayName))  [$($u.Domain)]"
        }
        $lines += ''
    }

    # Orphaned target users
    if ($CorrelationResult.UnmatchedTarget.Count -gt 0) {
        $lines += 'ORPHANED TARGET USERS (access with no source equivalent)'
        $lines += '---------------------------------------------------------'
        foreach ($item in $CorrelationResult.UnmatchedTarget) {
            $u = $item.User
            $lines += "  $($u.SamAccountName)  ($($u.DisplayName))  [$($u.Domain)]"
        }
        $lines += ''
    }

    return $lines -join "`n"
}
