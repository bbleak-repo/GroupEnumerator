<#
.SYNOPSIS
    Cross-domain group name fuzzy matching module

.DESCRIPTION
    Normalises group names by stripping well-known naming prefixes (GG_, SG_, etc.)
    then performs two-pass matching across domains:
      Pass 1 - exact match on normalised names (score 1.0)
      Pass 2 - Levenshtein similarity on remaining unmatched pairs (score >= MinScore)

    All public functions return plain hashtables. No side effects.

.NOTES
    No LDAP activity in this module. Input is already-enumerated group result objects.
    Compatible with PowerShell 5.1 and PowerShell 7+.
#>

function Get-NormalizedName {
    <#
    .SYNOPSIS
        Strips known prefixes and normalises a group name for comparison

    .DESCRIPTION
        Processing steps (applied in order):
          1. Strip any prefix in the Prefixes array (case-insensitive, first match wins)
          2. Convert to lowercase
          3. Trim leading and trailing underscores

        Examples:
          "GG_IT_Admins"   --> "it_admins"   (stripped GG_ then lowercased)
          "USV_Finance"    --> "finance"
          "IT_Admins"      --> "it_admins"   (no prefix matched, just lowercased)

    .PARAMETER GroupName
        Raw group name string

    .PARAMETER Prefixes
        Array of prefix strings to strip (e.g. @('GG_', 'USV_', 'SG_', 'DL_', 'GL_'))

    .OUTPUTS
        Normalised lowercase string
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$GroupName,

        [Parameter(Mandatory = $false)]
        [string[]]$Prefixes = @()
    )

    $name = $GroupName

    # Strip the first matching prefix (case-insensitive)
    foreach ($prefix in $Prefixes) {
        if ($name.Length -ge $prefix.Length -and
            $name.Substring(0, $prefix.Length) -ieq $prefix) {
            $name = $name.Substring($prefix.Length)
            break
        }
    }

    # Lowercase
    $name = $name.ToLower()

    # Trim leading/trailing underscores
    $name = $name.Trim('_')

    # If stripping the prefix left nothing (e.g. a name that is ENTIRELY a known
    # prefix like "GG_"), fall back to the original lowercased name. Otherwise
    # every prefix-only group would normalise to "" and false-match the others at
    # score 1.0.
    if ([string]::IsNullOrEmpty($name)) {
        $name = $GroupName.ToLower()
    }

    return $name
}

function Get-SimilarityScore {
    <#
    .SYNOPSIS
        Computes Levenshtein similarity score between two strings

    .DESCRIPTION
        Calculates the Levenshtein edit distance between Name1 and Name2,
        then converts to a 0.0-1.0 similarity score:

            score = 1.0 - (distance / Max(len1, len2))

        A score of 1.0 means identical strings.
        A score of 0.0 means the strings share no characters in common
        (distance equals the length of the longer string).

        Empty strings: two empty strings score 1.0; one empty scores 0.0.

    .PARAMETER Name1
        First string

    .PARAMETER Name2
        Second string

    .OUTPUTS
        Double in range [0.0, 1.0]
    #>
    [CmdletBinding()]
    [OutputType([double])]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$Name1,

        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$Name2
    )

    # Edge cases
    if ($Name1 -ceq $Name2) { return 1.0 }
    if ($Name1.Length -eq 0 -and $Name2.Length -eq 0) { return 1.0 }
    if ($Name1.Length -eq 0 -or $Name2.Length -eq 0)  { return 0.0 }

    $len1 = $Name1.Length
    $len2 = $Name2.Length

    # Build Levenshtein distance matrix (Wagner-Fischer algorithm)
    # $d[$i][$j] = edit distance between Name1[0..$i-1] and Name2[0..$j-1]
    # Use two rolling rows to limit memory allocation
    $prev = [int[]](0..($len2))   # row i-1
    $curr = [int[]]::new($len2 + 1)

    for ($i = 1; $i -le $len1; $i++) {
        $curr[0] = $i

        for ($j = 1; $j -le $len2; $j++) {
            $cost = if ($Name1[$i - 1] -ceq $Name2[$j - 1]) { 0 } else { 1 }

            $deleteCost  = $prev[$j]     + 1
            $insertCost  = $curr[$j - 1] + 1
            $replaceCost = $prev[$j - 1] + $cost

            $minCost = $deleteCost
            if ($insertCost  -lt $minCost) { $minCost = $insertCost  }
            if ($replaceCost -lt $minCost) { $minCost = $replaceCost }

            $curr[$j] = $minCost
        }

        # Swap rows: prev = curr, allocate fresh curr
        $prev = [int[]]$curr
        $curr = [int[]]::new($len2 + 1)
    }

    $distance  = $prev[$len2]
    $maxLength = [Math]::Max($len1, $len2)
    $score     = 1.0 - ($distance / [double]$maxLength)

    return $score
}

function Group-ResultsByDomain {
    <#
    .SYNOPSIS
        Organises an array of group result objects by domain name

    .DESCRIPTION
        Takes the array returned by repeated Get-GroupMembers calls and builds a
        hashtable keyed by domain name for efficient lookup during matching.

        Input items must have a Data.Domain property (i.e. the standard module return
        shape: @{ Data = @{ Domain = "CORP"; GroupName = "..."; ... }; Errors = @() }).

    .PARAMETER GroupResults
        Array of group result hashtables from Get-GroupMembers

    .OUTPUTS
        Hashtable: @{ "CORP" = @( result1, result2, ... ); "PARTNER" = @( ... ) }
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory = $true)]
        [array]$GroupResults
    )

    $byDomain = @{}

    foreach ($result in $GroupResults) {
        if (-not $result -or -not $result.Data) { continue }

        $domain = $result.Data.Domain
        if ([string]::IsNullOrWhiteSpace($domain)) { $domain = '(unknown)' }

        if (-not $byDomain.ContainsKey($domain)) {
            $byDomain[$domain] = @()
        }

        $byDomain[$domain] += $result
    }

    return $byDomain
}

function Find-MatchingGroups {
    <#
    .SYNOPSIS
        Matches groups across domains using two-pass normalise-then-fuzzy strategy

    .DESCRIPTION
        Pass 1 - Exact match on normalised names:
            Groups whose normalised names are identical are collected into a
            Matched entry with Score 1.0.

        Pass 2 - Levenshtein similarity:
            Groups that did not exact-match are compared pairwise across domains.
            Any pair whose similarity score >= MinScore is collected into a
            Matched entry with the computed Score.
            Groups that still don't pair with anything go into Unmatched.

        A "match" always involves groups from different domains. Groups from the
        same domain are never matched against each other.

        Return shape:
          @{
            Matched = @(
              @{
                NormalizedName = "it_admins"
                Score          = 1.0
                Groups         = @(
                  @{ Domain = "CORP"; GroupName = "GG_IT_Admins"; MemberCount = 42; Data = <full result> },
                  @{ Domain = "PARTNER"; GroupName = "USV_IT_Admins"; MemberCount = 38; Data = <full result> }
                )
              }
            )
            Unmatched = @(
              @{ Domain = "CORP"; GroupName = "GG_Finance_Only"; MemberCount = 15; Data = <full result> }
            )
          }

    .PARAMETER GroupResults
        Array of group result hashtables from Get-GroupMembers

    .PARAMETER Prefixes
        Prefix strings to strip during normalisation
        (passed through to Get-NormalizedName)

    .PARAMETER MinScore
        Minimum Levenshtein similarity score for a fuzzy match (0.0-1.0).
        Groups scoring below this threshold are placed in Unmatched.

    .OUTPUTS
        Hashtable with Matched and Unmatched arrays
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [array]$GroupResults,

        [Parameter(Mandatory = $false)]
        [string[]]$Prefixes = @(),

        [Parameter(Mandatory = $false)]
        [double]$MinScore = 0.7
    )

    # Build flat working list: each element = lightweight descriptor + reference to full result
    $items = @()
    foreach ($result in $GroupResults) {
        if (-not $result -or -not $result.Data) { continue }

        $data = $result.Data

        # Skip groups that were skipped during enumeration (no meaningful members)
        if ($data.Skipped) { continue }

        $normalised = Get-NormalizedName -GroupName $data.GroupName -Prefixes $Prefixes

        $items += @{
            Domain         = $data.Domain
            GroupName      = $data.GroupName
            NormalizedName = $normalised
            MemberCount    = $data.MemberCount
            Data           = $result  # full result reference
        }
    }

    # -------------------------------------------------------------------------
    # Pass 1: Exact match on normalised name
    # -------------------------------------------------------------------------
    # Group items by normalised name
    $byNormalized = @{}
    foreach ($item in $items) {
        $key = $item.NormalizedName
        if (-not $byNormalized.ContainsKey($key)) {
            $byNormalized[$key] = @()
        }
        $byNormalized[$key] += $item
    }

    $matched   = @()
    $unmatchedItems = @()  # items that still need Pass 2 processing

    foreach ($key in $byNormalized.Keys) {
        $group = $byNormalized[$key]

        # A match requires items from at least two distinct domains
        $distinctDomains = @($group | ForEach-Object { $_.Domain } | Sort-Object -Unique)
        if ($distinctDomains.Count -ge 2) {
            $groupArr = @($group | ForEach-Object {
                @{
                    Domain      = $_.Domain
                    GroupName   = $_.GroupName
                    MemberCount = $_.MemberCount
                    Data        = $_.Data
                }
            })
            # Directional fields: source = first entry of the first distinct
            # domain, target = first entry of the second distinct domain.
            # Selecting by distinct domain (not groupArr[0]/[1]) guarantees the
            # pair spans two domains even when 3+ groups share a normalized name
            # (e.g. CORP\GG_Admins + CORP\SG_Admins + PARTNER\USV_Admins).
            $sourceEntry = $groupArr | Where-Object { $_.Domain -eq $distinctDomains[0] } | Select-Object -First 1
            $targetEntry = $groupArr | Where-Object { $_.Domain -eq $distinctDomains[1] } | Select-Object -First 1
            $matched += @{
                NormalizedName = $key
                Score          = 1.0
                Groups         = $groupArr
                SourceDomain   = $sourceEntry.Domain
                SourceGroup    = $sourceEntry.GroupName
                TargetDomain   = $targetEntry.Domain
                TargetGroup    = $targetEntry.GroupName
            }
        } else {
            # Single domain or empty -- candidate for fuzzy pass
            foreach ($item in $group) {
                $unmatchedItems += $item
            }
        }
    }

    # -------------------------------------------------------------------------
    # Pass 2: Levenshtein fuzzy matching on remaining items
    # -------------------------------------------------------------------------
    # Strategy: compare every unmatched item against every other item from
    # a different domain. Greedily pair the highest-scoring pair first,
    # then continue with what remains.
    #
    # Build scored candidate pairs
    $candidatePairs = @()

    for ($i = 0; $i -lt $unmatchedItems.Count; $i++) {
        for ($j = $i + 1; $j -lt $unmatchedItems.Count; $j++) {
            $a = $unmatchedItems[$i]
            $b = $unmatchedItems[$j]

            # Only pair across domains
            if ($a.Domain -ieq $b.Domain) { continue }

            $score = Get-SimilarityScore -Name1 $a.NormalizedName -Name2 $b.NormalizedName

            if ($score -ge $MinScore) {
                $candidatePairs += @{
                    Score = $score
                    ItemA = $a
                    ItemB = $b
                }
            }
        }
    }

    # Sort pairs descending by score (greedy best-first)
    $sortedPairs = $candidatePairs | Sort-Object -Property Score -Descending

    # Track which items have been claimed by a fuzzy match
    $claimedItems = @{}  # key = "$Domain|$GroupName"

    $fuzzyMatched = @{}  # key = pair representative name --> match entry being built

    foreach ($pair in $sortedPairs) {
        $keyA = "$($pair.ItemA.Domain)|$($pair.ItemA.GroupName)"
        $keyB = "$($pair.ItemB.Domain)|$($pair.ItemB.GroupName)"

        # Skip if either item already claimed
        if ($claimedItems.ContainsKey($keyA) -or $claimedItems.ContainsKey($keyB)) {
            continue
        }

        # Claim both items
        $claimedItems[$keyA] = $true
        $claimedItems[$keyB] = $true

        # Choose a normalised name for the match (use the longer one as canonical)
        $canonicalName = if ($pair.ItemA.NormalizedName.Length -ge $pair.ItemB.NormalizedName.Length) {
            $pair.ItemA.NormalizedName
        } else {
            $pair.ItemB.NormalizedName
        }

        $matched += @{
            NormalizedName = $canonicalName
            Score          = [Math]::Round($pair.Score, 4)
            Groups         = @(
                @{
                    Domain      = $pair.ItemA.Domain
                    GroupName   = $pair.ItemA.GroupName
                    MemberCount = $pair.ItemA.MemberCount
                    Data        = $pair.ItemA.Data
                },
                @{
                    Domain      = $pair.ItemB.Domain
                    GroupName   = $pair.ItemB.GroupName
                    MemberCount = $pair.ItemB.MemberCount
                    Data        = $pair.ItemB.Data
                }
            )
            SourceDomain = $pair.ItemA.Domain
            SourceGroup  = $pair.ItemA.GroupName
            TargetDomain = $pair.ItemB.Domain
            TargetGroup  = $pair.ItemB.GroupName
        }
    }

    # -------------------------------------------------------------------------
    # Build final Unmatched list
    # -------------------------------------------------------------------------
    $unmatched = @()
    foreach ($item in $unmatchedItems) {
        $key = "$($item.Domain)|$($item.GroupName)"
        if (-not $claimedItems.ContainsKey($key)) {
            $unmatched += @{
                Domain      = $item.Domain
                GroupName   = $item.GroupName
                MemberCount = $item.MemberCount
                Data        = $item.Data
            }
        }
    }

    return @{
        Matched   = $matched
        Unmatched = $unmatched
    }
}
