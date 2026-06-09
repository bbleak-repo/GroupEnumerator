<#
.SYNOPSIS
    Migration gap analysis module for cross-domain migration readiness tool.

.DESCRIPTION
    Compares CORP (source/EntraID) and PARTNER (target/Okta) group membership using
    correlation results to produce actionable Change Request data.

    Users have distinct contractor accounts in each domain (e.g. jsmith in CORP,
    jsmith02 in PARTNER). This module classifies each source member by their migration
    status and produces prioritised CR items.

    Status values:
      Ready           - Correlated user already in target group. No action needed.
      AddToGroup      - Correlated user exists in target domain but not in the target group.
      NotProvisioned  - Source user has no correlated account in the target domain.
      OrphanedAccess  - Target user has group access with no corresponding source user.
      Skip-Stale      - Source user is stale (last logon > threshold). Excluded from migration.
      Skip-Disabled   - Source user account is disabled. Excluded from migration.

    Priority:
      P1 - NotProvisioned  (blocks migration - account must be created)
      P2 - AddToGroup      (blocks app access - group membership needed)
      P3 - OrphanedAccess  (security review - target has access not in source)
      Info - Ready / Skip-Stale / Skip-Disabled

.NOTES
    No emoji in code.
    Uses Write-GroupEnumLog for structured logging (must be loaded before dot-sourcing).
    Module return pattern: @{ ... ; Errors = @() }
    File writes use UTF-8 without BOM via [System.IO.File]::WriteAllText.
#>

# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

function Get-StaleAndDisabledSams {
    <#
    .SYNOPSIS
        Builds lookup sets of stale and disabled SamAccountNames from a StaleResult.
    #>
    param(
        [hashtable]$StaleResult
    )

    $staleSams    = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $disabledSams = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

    if ($null -eq $StaleResult) { return @{ Stale = $staleSams; Disabled = $disabledSams }; }

    if ($StaleResult.Stale) {
        foreach ($u in $StaleResult.Stale) {
            if ($u.SamAccountName) { $null = $staleSams.Add($u.SamAccountName) }
        }
    }

    if ($StaleResult.Disabled) {
        foreach ($u in $StaleResult.Disabled) {
            if ($u.SamAccountName) { $null = $disabledSams.Add($u.SamAccountName) }
        }
    }

    return @{ Stale = $staleSams; Disabled = $disabledSams }
}

function Build-CorrelationLookup {
    <#
    .SYNOPSIS
        Builds a lookup of source SAM -> correlated target user from a CorrelationResult.
        Also builds a set of target SAMs that are correlated to some source user.
    #>
    param(
        [hashtable]$CorrelationResult
    )

    # sourceToTarget: sourceSam (lower) -> @{ TargetUser; Confidence }
    $sourceToTarget = @{}
    # correlatedTargetSams: set of target SAMs that have a source correlation
    $correlatedTargetSams = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

    if ($null -eq $CorrelationResult) {
        return @{ SourceToTarget = $sourceToTarget; CorrelatedTargetSams = $correlatedTargetSams }
    }

    if ($CorrelationResult.Correlated) {
        foreach ($pair in $CorrelationResult.Correlated) {
            $sourceSam = if ($pair.SourceUser -and $pair.SourceUser.SamAccountName) {
                $pair.SourceUser.SamAccountName
            } else { $null }

            $targetSam = if ($pair.TargetUser -and $pair.TargetUser.SamAccountName) {
                $pair.TargetUser.SamAccountName
            } else { $null }

            if ($sourceSam) {
                $confidence = if ($pair.Confidence) { $pair.Confidence } else { 'Low' }
                $sourceToTarget[$sourceSam.ToLower()] = @{
                    TargetUser  = $pair.TargetUser
                    Confidence  = $confidence
                }
            }
            if ($targetSam) {
                $null = $correlatedTargetSams.Add($targetSam)
            }
        }
    }

    return @{ SourceToTarget = $sourceToTarget; CorrelatedTargetSams = $correlatedTargetSams }
}

function Build-TargetGroupSamSet {
    <#
    .SYNOPSIS
        Builds a HashSet of target group member SAMs for fast membership testing.
    #>
    param(
        [hashtable]$TargetGroupResult
    )

    $set = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

    if ($null -eq $TargetGroupResult -or $null -eq $TargetGroupResult.Data) {
        return , $set
    }

    $members = $TargetGroupResult.Data.Members
    if ($members) {
        foreach ($m in $members) {
            if ($m.SamAccountName) { $null = $set.Add($m.SamAccountName) }
        }
    }

    return , $set
}

function Get-GapItemPriority {
    <#
    .SYNOPSIS
        Maps a gap status to its CR priority level.
    #>
    param([string]$Status)

    switch ($Status) {
        'NotProvisioned'  { return 'P1' }
        'NotInDomain'     { return 'P1' }
        'AddToGroup'      { return 'P2' }
        'ExistsNotInGroup' { return 'P2' }
        'OrphanedAccess'  { return 'P3' }
        default           { return 'Info' }
    }
}

function Get-GapItemAction {
    <#
    .SYNOPSIS
        Produces a human-readable action description for a gap item.
    #>
    param(
        [string]$Status,
        [string]$TargetSam,
        [string]$TargetGroupName,
        [string]$TargetDomain
    )

    switch ($Status) {
        'Ready'            { return 'No action needed' }
        'AddToGroup'       { return "Add $TargetSam to $TargetDomain\$TargetGroupName" }
        'ExistsNotInGroup' { return "Add $TargetSam to $TargetDomain\$TargetGroupName (found via domain search)" }
        'NotProvisioned'   { return "Provision user account in $TargetDomain domain" }
        'NotInDomain'      { return "Provision user account in $TargetDomain domain (confirmed not found)" }
        'OrphanedAccess'   { return "Review orphaned access for $TargetSam in $TargetDomain\$TargetGroupName" }
        'Skip-Stale'       { return 'User is stale - excluded from migration scope' }
        'Skip-Disabled'    { return 'User account is disabled - excluded from migration scope' }
        default            { return '' }
    }
}

function Get-PrioritySortKey {
    <#
    .SYNOPSIS
        Returns a numeric sort key for priority (P1 first).
    #>
    param([string]$Priority)
    switch ($Priority) {
        'P1'   { return 1 }
        'P2'   { return 2 }
        'P3'   { return 3 }
        'Info' { return 4 }
        default { return 5 }
    }
}

# ---------------------------------------------------------------------------
# Public: Get-MigrationGapAnalysis
# ---------------------------------------------------------------------------
function Get-MigrationGapAnalysis {
    <#
    .SYNOPSIS
        Analyse one matched group pair to identify migration gaps.

    .DESCRIPTION
        Classifies each source (CORP) group member by their migration status using
        correlation data from Find-UserCorrelations and optional stale account data.
        Also identifies target (PARTNER) group members with no source correlation
        (orphaned access).

    .PARAMETER SourceGroupResult
        Hashtable from Get-GroupMembers for the CORP source group.
        Expected: @{ Data = @{ GroupName; Domain; Members = @(...) }; Errors = @() }

    .PARAMETER TargetGroupResult
        Hashtable from Get-GroupMembers for the PARTNER target group.
        Expected: @{ Data = @{ GroupName; Domain; Members = @(...) }; Errors = @() }

    .PARAMETER CorrelationResult
        Hashtable from Find-UserCorrelations for this group pair's member population.
        Expected: @{ Correlated = @(...); UnmatchedSource = @(...); UnmatchedTarget = @(...) }

    .PARAMETER StaleResult
        Hashtable from Get-AccountStaleness, or $null to skip stale/disabled checks.
        Expected: @{ Stale = @(...); Disabled = @(...); Active = @(...) }

    .PARAMETER Config
        Configuration hashtable. Currently unused but accepted for forward compatibility.

    .OUTPUTS
        Hashtable:
        @{
            GroupPair   = @{ SourceDomain; SourceGroup; TargetDomain; TargetGroup }
            Items       = @( @{ Status; Priority; SourceUser; TargetUser; CorrelationConfidence; Action; Notes } )
            Readiness   = @{ Percent; ReadyCount; AddToGroupCount; NotProvisionedCount;
                             OrphanedCount; SkipStaleCount; SkipDisabledCount;
                             TotalSourceMembers; TotalTargetMembers }
            Errors      = @()
        }
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$SourceGroupResult,

        [Parameter(Mandatory = $true)]
        [hashtable]$TargetGroupResult,

        [Parameter(Mandatory = $true)]
        [hashtable]$CorrelationResult,

        [Parameter(Mandatory = $false)]
        [hashtable]$StaleResult = $null,

        [Parameter(Mandatory = $false)]
        [hashtable]$Config = @{}
    )

    $errors = @()

    # --- Extract group metadata ---
    $srcData  = if ($SourceGroupResult.Data) { $SourceGroupResult.Data } else { @{} }
    $tgtData  = if ($TargetGroupResult.Data) { $TargetGroupResult.Data } else { @{} }

    $sourceGroupName = if ($srcData.GroupName) { $srcData.GroupName } else { '(unknown)' }
    $sourceDomain    = if ($srcData.Domain)    { $srcData.Domain }    else { 'CORP' }
    $targetGroupName = if ($tgtData.GroupName) { $tgtData.GroupName } else { '(unknown)' }
    $targetDomain    = if ($tgtData.Domain)    { $tgtData.Domain }    else { 'PARTNER' }

    Write-GroupEnumLog -Level 'INFO' -Operation 'GapAnalysis' `
        -Message "Analysing gap for $sourceDomain\$sourceGroupName -> $targetDomain\$targetGroupName" `
        -Context @{ SourceGroup = $sourceGroupName; TargetGroup = $targetGroupName }

    # --- Build lookup structures ---
    $stalenessLookup  = Get-StaleAndDisabledSams -StaleResult $StaleResult
    $correlationLookup = Build-CorrelationLookup -CorrelationResult $CorrelationResult
    $targetGroupSams   = Build-TargetGroupSamSet -TargetGroupResult $TargetGroupResult

    $sourceToTarget       = $correlationLookup.SourceToTarget
    $correlatedTargetSams = $correlationLookup.CorrelatedTargetSams

    $staleSams    = $stalenessLookup.Stale
    $disabledSams = $stalenessLookup.Disabled

    # --- Process source members ---
    $items = [System.Collections.Generic.List[hashtable]]::new()

    $readyCount          = 0
    $addToGroupCount     = 0
    $notProvisionedCount = 0
    $skipStaleCount      = 0
    $skipDisabledCount   = 0

    $sourceMembers = [array]@()
    $targetMembers = [array]@()
    if ($srcData.Members -and $srcData.Members.Count -gt 0) {
        $sourceMembers = [array]$srcData.Members
    }
    if ($tgtData.Members -and $tgtData.Members.Count -gt 0) {
        $targetMembers = [array]$tgtData.Members
    }

    foreach ($srcMember in $sourceMembers) {
        $srcSam = if ($srcMember.SamAccountName) { $srcMember.SamAccountName } else { '' }

        $sourceUserInfo = @{
            SamAccountName = $srcSam
            DisplayName    = if ($srcMember.DisplayName) { $srcMember.DisplayName } else { '' }
            Email          = if ($srcMember.Email)       { $srcMember.Email }       else { '' }
        }

        # Priority 1: Disabled check
        if ($srcSam -and $disabledSams.Contains($srcSam)) {
            $skipDisabledCount++
            $items.Add(@{
                Status                = 'Skip-Disabled'
                Priority              = 'Info'
                SourceUser            = $sourceUserInfo
                TargetUser            = $null
                CorrelationConfidence = 'None'
                Action                = Get-GapItemAction -Status 'Skip-Disabled' -TargetSam '' -TargetGroupName $targetGroupName -TargetDomain $targetDomain
                Notes                 = 'Account disabled in source domain'
            })
            continue
        }

        # Priority 2: Stale check
        if ($srcSam -and $staleSams.Contains($srcSam)) {
            $skipStaleCount++
            $items.Add(@{
                Status                = 'Skip-Stale'
                Priority              = 'Info'
                SourceUser            = $sourceUserInfo
                TargetUser            = $null
                CorrelationConfidence = 'None'
                Action                = Get-GapItemAction -Status 'Skip-Stale' -TargetSam '' -TargetGroupName $targetGroupName -TargetDomain $targetDomain
                Notes                 = 'Account stale (no recent logon) in source domain'
            })
            continue
        }

        # Priority 3: Correlation check
        $samKey = if ($srcSam) { $srcSam.ToLower() } else { '' }
        $correlatedEntry = if ($samKey -and $sourceToTarget.ContainsKey($samKey)) {
            $sourceToTarget[$samKey]
        } else { $null }

        if ($null -ne $correlatedEntry) {
            # User is correlated - check if they are in the target group
            $targetUser = $correlatedEntry.TargetUser
            $confidence = $correlatedEntry.Confidence
            $tgtSam     = if ($targetUser -and $targetUser.SamAccountName) { $targetUser.SamAccountName } else { '' }

            $targetUserInfo = @{
                SamAccountName = $tgtSam
                DisplayName    = if ($targetUser -and $targetUser.DisplayName) { $targetUser.DisplayName } else { '' }
                Email          = if ($targetUser -and $targetUser.Email)       { $targetUser.Email }       else { '' }
            }

            if ($tgtSam -and $targetGroupSams.Contains($tgtSam)) {
                # Correlated AND in target group -> Ready
                $readyCount++
                $items.Add(@{
                    Status                = 'Ready'
                    Priority              = 'Info'
                    SourceUser            = $sourceUserInfo
                    TargetUser            = $targetUserInfo
                    CorrelationConfidence = $confidence
                    Action                = Get-GapItemAction -Status 'Ready' -TargetSam $tgtSam -TargetGroupName $targetGroupName -TargetDomain $targetDomain
                    Notes                 = ''
                })
            } else {
                # Correlated but NOT in target group -> AddToGroup
                $addToGroupCount++
                $items.Add(@{
                    Status                = 'AddToGroup'
                    Priority              = 'P2'
                    SourceUser            = $sourceUserInfo
                    TargetUser            = $targetUserInfo
                    CorrelationConfidence = $confidence
                    Action                = Get-GapItemAction -Status 'AddToGroup' -TargetSam $tgtSam -TargetGroupName $targetGroupName -TargetDomain $targetDomain
                    Notes                 = "Correlated target account $tgtSam exists but is not a member of $targetDomain\$targetGroupName"
                })
            }
        } else {
            # No correlation -> NotProvisioned
            $notProvisionedCount++
            $items.Add(@{
                Status                = 'NotProvisioned'
                Priority              = 'P1'
                SourceUser            = $sourceUserInfo
                TargetUser            = $null
                CorrelationConfidence = 'None'
                Action                = Get-GapItemAction -Status 'NotProvisioned' -TargetSam '' -TargetGroupName $targetGroupName -TargetDomain $targetDomain
                Notes                 = 'No correlated account found in target domain'
            })
        }
    }

    # --- Process orphaned target members ---
    $orphanedCount = 0

    foreach ($tgtMember in $targetMembers) {
        $tgtSam = if ($tgtMember.SamAccountName) { $tgtMember.SamAccountName } else { '' }

        if ($tgtSam -and -not $correlatedTargetSams.Contains($tgtSam)) {
            $orphanedCount++
            $targetUserInfo = @{
                SamAccountName = $tgtSam
                DisplayName    = if ($tgtMember.DisplayName) { $tgtMember.DisplayName } else { '' }
                Email          = if ($tgtMember.Email)       { $tgtMember.Email }       else { '' }
            }
            $items.Add(@{
                Status                = 'OrphanedAccess'
                Priority              = 'P3'
                SourceUser            = $null
                TargetUser            = $targetUserInfo
                CorrelationConfidence = 'None'
                Action                = Get-GapItemAction -Status 'OrphanedAccess' -TargetSam $tgtSam -TargetGroupName $targetGroupName -TargetDomain $targetDomain
                Notes                 = 'Target user has group access with no corresponding source user'
            })
        }
    }

    # --- Compute readiness percentage ---
    # Readiness is based on source members only (orphaned target members are separate).
    # Skip-Stale and Skip-Disabled are excluded from the denominator (out of scope).
    $inScopeCount = $sourceMembers.Count - $skipStaleCount - $skipDisabledCount
    $readinessPercent = if ($inScopeCount -gt 0) {
        [Math]::Round(($readyCount / $inScopeCount) * 100, 1)
    } else {
        100.0
    }

    Write-GroupEnumLog -Level 'INFO' -Operation 'GapAnalysis' `
        -Message "Gap analysis complete: $sourceGroupName -> $targetGroupName, $readinessPercent% ready" `
        -Context @{
            SourceGroup      = $sourceGroupName
            TargetGroup      = $targetGroupName
            ReadinessPercent = $readinessPercent
            ReadyCount       = $readyCount
            AddToGroupCount  = $addToGroupCount
            NotProvisioned   = $notProvisionedCount
            Orphaned         = $orphanedCount
            SkipStale        = $skipStaleCount
            SkipDisabled     = $skipDisabledCount
        }

    return @{
        GroupPair = @{
            SourceDomain = $sourceDomain
            SourceGroup  = $sourceGroupName
            TargetDomain = $targetDomain
            TargetGroup  = $targetGroupName
        }
        Items     = $items.ToArray()
        Readiness = @{
            Percent              = $readinessPercent
            ReadyCount           = $readyCount
            AddToGroupCount      = $addToGroupCount
            NotProvisionedCount  = $notProvisionedCount
            OrphanedCount        = $orphanedCount
            SkipStaleCount       = $skipStaleCount
            SkipDisabledCount    = $skipDisabledCount
            TotalSourceMembers   = $sourceMembers.Count
            TotalTargetMembers   = $targetMembers.Count
        }
        Errors    = $errors
    }
}

# ---------------------------------------------------------------------------
# Public: Get-OverallMigrationReadiness
# ---------------------------------------------------------------------------
function Get-OverallMigrationReadiness {
    <#
    .SYNOPSIS
        Aggregate readiness across all group pairs.

    .DESCRIPTION
        Rolls up per-group gap analysis results into an overall migration readiness
        summary with CR counts by type and priority.

    .PARAMETER GapResults
        Array of hashtables returned by Get-MigrationGapAnalysis.

    .PARAMETER AppReadiness
        Optional hashtable from Get-AppReadiness. Currently reserved for future use.

    .OUTPUTS
        Hashtable:
        @{
            OverallPercent   = 78.3
            GroupCount       = 12
            ReadyGroups      = 5    # 100% ready
            InProgressGroups = 5    # 50-99% ready
            BlockedGroups    = 2    # <50% ready
            TotalCRItems     = 23
            CRByType         = @{ AddToGroup; NotProvisioned; OrphanedAccess }
            CRByPriority     = @{ P1; P2; P3 }
        }
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [array]$GapResults,

        [Parameter(Mandatory = $false)]
        [hashtable]$AppReadiness = $null
    )

    if (-not $GapResults -or $GapResults.Count -eq 0) {
        Write-GroupEnumLog -Level 'WARN' -Operation 'OverallReadiness' `
            -Message 'No gap results provided to Get-OverallMigrationReadiness'
        return @{
            OverallPercent   = 0.0
            GroupCount       = 0
            ReadyGroups      = 0
            InProgressGroups = 0
            BlockedGroups    = 0
            TotalCRItems     = 0
            CRByType         = @{ AddToGroup = 0; NotProvisioned = 0; OrphanedAccess = 0 }
            CRByPriority     = @{ P1 = 0; P2 = 0; P3 = 0 }
        }
    }

    $readyGroups      = 0
    $inProgressGroups = 0
    $blockedGroups    = 0

    $addToGroupTotal     = 0
    $notProvisionedTotal = 0
    $orphanedTotal       = 0

    $readinessSum = 0.0

    foreach ($gap in $GapResults) {
        $pct = if ($gap.Readiness -and $null -ne $gap.Readiness.Percent) {
            [double]$gap.Readiness.Percent
        } else { 0.0 }

        $readinessSum += $pct

        if ($pct -ge 100.0) {
            $readyGroups++
        } elseif ($pct -ge 50.0) {
            $inProgressGroups++
        } else {
            $blockedGroups++
        }

        if ($gap.Readiness) {
            $addToGroupTotal     += [int]$(if ($gap.Readiness.AddToGroupCount)     { $gap.Readiness.AddToGroupCount }     else { 0 })
            $notProvisionedTotal += [int]$(if ($gap.Readiness.NotProvisionedCount) { $gap.Readiness.NotProvisionedCount } else { 0 })
            $orphanedTotal       += [int]$(if ($gap.Readiness.OrphanedCount)       { $gap.Readiness.OrphanedCount }       else { 0 })
        }
    }

    $overallPercent = [Math]::Round($readinessSum / $GapResults.Count, 1)
    $totalCRItems   = $addToGroupTotal + $notProvisionedTotal + $orphanedTotal

    Write-GroupEnumLog -Level 'INFO' -Operation 'OverallReadiness' `
        -Message "Overall migration readiness: $overallPercent% across $($GapResults.Count) groups" `
        -Context @{
            GroupCount       = $GapResults.Count
            OverallPercent   = $overallPercent
            TotalCRItems     = $totalCRItems
            ReadyGroups      = $readyGroups
            InProgressGroups = $inProgressGroups
            BlockedGroups    = $blockedGroups
        }

    return @{
        OverallPercent   = $overallPercent
        GroupCount       = $GapResults.Count
        ReadyGroups      = $readyGroups
        InProgressGroups = $inProgressGroups
        BlockedGroups    = $blockedGroups
        TotalCRItems     = $totalCRItems
        CRByType         = @{
            AddToGroup     = $addToGroupTotal
            NotProvisioned = $notProvisionedTotal
            OrphanedAccess = $orphanedTotal
        }
        CRByPriority     = @{
            P1 = $notProvisionedTotal
            P2 = $addToGroupTotal
            P3 = $orphanedTotal
        }
    }
}

# ---------------------------------------------------------------------------
# Public: Export-GapAnalysisCsv
# ---------------------------------------------------------------------------
function Export-GapAnalysisCsv {
    <#
    .SYNOPSIS
        Export actionable gap analysis data to CSV for Change Request documentation.

    .DESCRIPTION
        Produces a UTF-8 (no BOM) CSV with one row per gap item across all group pairs.
        Sorted by priority (P1 first), then status, then group name, then SAM.

        Columns:
          Status | Priority | SourceDomain | SourceGroup | TargetDomain | TargetGroup |
          SourceSam | SourceDisplayName | SourceEmail |
          TargetSam | TargetDisplayName | CorrelationConfidence | Action | Notes

    .PARAMETER GapResults
        Array of hashtables from Get-MigrationGapAnalysis.

    .PARAMETER OutputPath
        Full file path for the output CSV file.

    .OUTPUTS
        String path to the written CSV file.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [array]$GapResults,

        [Parameter(Mandatory = $true)]
        [string]$OutputPath
    )

    $errors = @()

    # Helper: escape a CSV field (wrap in quotes if it contains comma, quote, or newline)
    function ConvertTo-CsvField {
        param([string]$Value)
        if ($null -eq $Value) { return '' }
        if ($Value -match '[",\r\n]') {
            $escaped = $Value -replace '"', '""'
            return "`"$escaped`""
        }
        return $Value
    }

    # Discover extra attributes beyond the standard set (e.g. Manager, department)
    $standardKeys = @('SamAccountName','DisplayName','Email','Enabled','Domain','DistinguishedName')
    $extraAttrNames = @()
    foreach ($gap in $GapResults) {
        if (-not $gap.Items) { continue }
        foreach ($item in $gap.Items) {
            $srcUser = $item.SourceUser
            if ($srcUser -and $srcUser -is [hashtable]) {
                foreach ($k in $srcUser.Keys) {
                    if ($standardKeys -notcontains $k -and $extraAttrNames -notcontains $k) {
                        $extraAttrNames += $k
                    }
                }
            }
        }
        if ($extraAttrNames.Count -gt 0) { break }  # Found extras from first group
    }

    $header = 'Status,Priority,SourceDomain,SourceGroup,TargetDomain,TargetGroup,' +
              'SourceSam,SourceDisplayName,SourceEmail,' +
              'TargetSam,TargetDisplayName,CorrelationConfidence,Action,Notes'
    if ($extraAttrNames.Count -gt 0) {
        $header += ',' + (($extraAttrNames | ForEach-Object { "Source$_" }) -join ',')
    }

    $rows = [System.Collections.Generic.List[string]]::new()
    $rows.Add($header)

    # Collect all items with their group pair context, then sort
    $allItems = [System.Collections.Generic.List[hashtable]]::new()

    foreach ($gap in $GapResults) {
        $pair = if ($gap.GroupPair) { $gap.GroupPair } else { @{} }
        $srcDomain  = if ($pair.SourceDomain) { $pair.SourceDomain } else { '' }
        $srcGroup   = if ($pair.SourceGroup)  { $pair.SourceGroup }  else { '' }
        $tgtDomain  = if ($pair.TargetDomain) { $pair.TargetDomain } else { '' }
        $tgtGroup   = if ($pair.TargetGroup)  { $pair.TargetGroup }  else { '' }

        if (-not $gap.Items) { continue }

        foreach ($item in $gap.Items) {
            $allItems.Add(@{
                Item        = $item
                SourceDomain = $srcDomain
                SourceGroup  = $srcGroup
                TargetDomain = $tgtDomain
                TargetGroup  = $tgtGroup
            })
        }
    }

    # Sort: priority key, status, source group, source SAM
    $sorted = $allItems | Sort-Object -Property `
        @{ Expression = { Get-PrioritySortKey -Priority $_.Item.Priority } },
        @{ Expression = { $_.Item.Status } },
        @{ Expression = { $_.SourceGroup } },
        @{ Expression = { if ($_.Item.SourceUser -and $_.Item.SourceUser.SamAccountName) { $_.Item.SourceUser.SamAccountName } else { '' } } }

    foreach ($entry in $sorted) {
        $item       = $entry.Item
        $srcUser    = if ($item.SourceUser) { $item.SourceUser } else { @{} }
        $tgtUser    = if ($item.TargetUser) { $item.TargetUser } else { @{} }

        $row = @(
            (ConvertTo-CsvField -Value $item.Status),
            (ConvertTo-CsvField -Value $item.Priority),
            (ConvertTo-CsvField -Value $entry.SourceDomain),
            (ConvertTo-CsvField -Value $entry.SourceGroup),
            (ConvertTo-CsvField -Value $entry.TargetDomain),
            (ConvertTo-CsvField -Value $entry.TargetGroup),
            (ConvertTo-CsvField -Value $(if ($srcUser.SamAccountName) { $srcUser.SamAccountName } else { '' })),
            (ConvertTo-CsvField -Value $(if ($srcUser.DisplayName)    { $srcUser.DisplayName }    else { '' })),
            (ConvertTo-CsvField -Value $(if ($srcUser.Email)          { $srcUser.Email }          else { '' })),
            (ConvertTo-CsvField -Value $(if ($tgtUser.SamAccountName) { $tgtUser.SamAccountName } else { '' })),
            (ConvertTo-CsvField -Value $(if ($tgtUser.DisplayName)    { $tgtUser.DisplayName }    else { '' })),
            (ConvertTo-CsvField -Value $(if ($item.CorrelationConfidence) { $item.CorrelationConfidence } else { '' })),
            (ConvertTo-CsvField -Value $(if ($item.Action) { $item.Action } else { '' })),
            (ConvertTo-CsvField -Value $(if ($item.Notes)  { $item.Notes }  else { '' }))
        )

        # Append extra attribute columns
        foreach ($attrName in $extraAttrNames) {
            $attrVal = if ($srcUser -and $srcUser[$attrName]) { $srcUser[$attrName] } else { '' }
            $row += (ConvertTo-CsvField -Value $attrVal)
        }

        $rows.Add($row -join ',')
    }

    try {
        $outDir = Split-Path $OutputPath -Parent
        if ($outDir -and -not (Test-Path $outDir)) {
            $null = New-Item -ItemType Directory -Path $outDir -Force
        }

        $csvContent = $rows -join "`r`n"
        [System.IO.File]::WriteAllText($OutputPath, $csvContent, [System.Text.UTF8Encoding]::new($false))

        Write-GroupEnumLog -Level 'INFO' -Operation 'ExportCsv' `
            -Message "Gap analysis CSV written: $OutputPath" `
            -Context @{ OutputPath = $OutputPath; RowCount = ($rows.Count - 1) }

        return $OutputPath

    } catch {
        $msg = "Export-GapAnalysisCsv failed writing to '$OutputPath': $_"
        Write-GroupEnumLog -Level 'ERROR' -Operation 'ExportCsv' -Message $msg
        throw $msg
    }
}

# ---------------------------------------------------------------------------
# Public: Export-ChangeRequestSummary
# ---------------------------------------------------------------------------
function Export-ChangeRequestSummary {
    <#
    .SYNOPSIS
        Generate a plain-text summary suitable for pasting into a Change Request ticket.

    .DESCRIPTION
        Produces a structured text document with overall readiness, CR counts by priority,
        blocked group list, and per-group detail. Suitable for CR ticket description fields.

    .PARAMETER GapResults
        Array of hashtables from Get-MigrationGapAnalysis.

    .PARAMETER OverallReadiness
        Hashtable from Get-OverallMigrationReadiness.

    .OUTPUTS
        Multi-line string containing the Change Request summary document.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [array]$GapResults,

        [Parameter(Mandatory = $true)]
        [hashtable]$OverallReadiness
    )

    $dateStr = Get-Date -Format 'yyyy-MM-dd'
    $lines   = [System.Collections.Generic.List[string]]::new()

    $lines.Add("MIGRATION READINESS REPORT - $dateStr")
    $lines.Add('========================================')
    $lines.Add("Overall Readiness: $($OverallReadiness.OverallPercent)%")

    $gc = $OverallReadiness.GroupCount
    $rg = $OverallReadiness.ReadyGroups
    $ig = $OverallReadiness.InProgressGroups
    $bg = $OverallReadiness.BlockedGroups
    $lines.Add("Groups Analyzed: $gc ($rg ready, $ig in progress, $bg blocked)")
    $lines.Add('')

    $totalCR = $OverallReadiness.TotalCRItems
    $lines.Add("CHANGE REQUESTS REQUIRED: $totalCR")

    $p1Count = $OverallReadiness.CRByPriority.P1
    $p2Count = $OverallReadiness.CRByPriority.P2
    $p3Count = $OverallReadiness.CRByPriority.P3

    $lines.Add("  P1 - User Provisioning: $p1Count users need accounts in target domain")
    $lines.Add("  P2 - Group Membership:  $p2Count users need to be added to target groups")
    $lines.Add("  P3 - Access Review:     $p3Count orphaned access entries to review")
    $lines.Add('')

    # Blocked groups (< 50% ready)
    $blockedGaps = @($GapResults | Where-Object {
        $_.Readiness -and [double]$_.Readiness.Percent -lt 50.0
    } | Sort-Object { [double]$_.Readiness.Percent })

    if ($blockedGaps.Count -gt 0) {
        $lines.Add('BLOCKED GROUPS (< 50% ready):')
        foreach ($gap in $blockedGaps) {
            $pair  = $gap.GroupPair
            $pct   = $gap.Readiness.Percent
            $crCnt = $(if ($gap.Readiness) {
                [int]$gap.Readiness.AddToGroupCount + [int]$gap.Readiness.NotProvisionedCount + [int]$gap.Readiness.OrphanedCount
            } else { 0 })
            $lines.Add("  $($pair.SourceDomain)\$($pair.SourceGroup) -> $($pair.TargetDomain)\$($pair.TargetGroup) ($pct% ready, $crCnt CRs)")
        }
        $lines.Add('')
    }

    # In-progress groups (50-99%)
    $inProgressGaps = @($GapResults | Where-Object {
        $_.Readiness -and [double]$_.Readiness.Percent -ge 50.0 -and [double]$_.Readiness.Percent -lt 100.0
    } | Sort-Object { [double]$_.Readiness.Percent })

    if ($inProgressGaps.Count -gt 0) {
        $lines.Add('IN PROGRESS GROUPS (50-99% ready):')
        foreach ($gap in $inProgressGaps) {
            $pair  = $gap.GroupPair
            $pct   = $gap.Readiness.Percent
            $crCnt = $(if ($gap.Readiness) {
                [int]$gap.Readiness.AddToGroupCount + [int]$gap.Readiness.NotProvisionedCount + [int]$gap.Readiness.OrphanedCount
            } else { 0 })
            $lines.Add("  $($pair.SourceDomain)\$($pair.SourceGroup) -> $($pair.TargetDomain)\$($pair.TargetGroup) ($pct% ready, $crCnt CRs)")
        }
        $lines.Add('')
    }

    # Detail by group
    $lines.Add('DETAIL BY GROUP:')

    $sortedGaps = @($GapResults | Sort-Object { [double]$_.Readiness.Percent })

    foreach ($gap in $sortedGaps) {
        $pair = $gap.GroupPair
        $r    = $gap.Readiness
        $pct  = if ($r) { $r.Percent }            else { 0.0 }
        $tot  = if ($r) { $r.TotalSourceMembers }  else { 0 }
        $rdy  = if ($r) { $r.ReadyCount }          else { 0 }
        $atg  = if ($r) { $r.AddToGroupCount }     else { 0 }
        $np   = if ($r) { $r.NotProvisionedCount } else { 0 }
        $orp  = if ($r) { $r.OrphanedCount }       else { 0 }
        $ss   = if ($r) { $r.SkipStaleCount }      else { 0 }
        $sd   = if ($r) { $r.SkipDisabledCount }   else { 0 }

        $lines.Add('')
        $lines.Add("  $($pair.SourceDomain)\$($pair.SourceGroup) -> $($pair.TargetDomain)\$($pair.TargetGroup)")
        $lines.Add("    Readiness:      $pct% ($rdy/$tot source members ready)")
        if ($np  -gt 0) { $lines.Add("    P1 Provision:   $np users need accounts in $($pair.TargetDomain)") }
        if ($atg -gt 0) { $lines.Add("    P2 Add to group: $atg users need adding to $($pair.TargetGroup)") }
        if ($orp -gt 0) { $lines.Add("    P3 Orphaned:    $orp target users need access review") }
        if ($ss  -gt 0) { $lines.Add("    Skipped stale:  $ss accounts (excluded from scope)") }
        if ($sd  -gt 0) { $lines.Add("    Skipped disabled: $sd accounts (excluded from scope)") }
    }

    $summary = $lines -join "`n"

    Write-GroupEnumLog -Level 'INFO' -Operation 'CRSummary' `
        -Message 'Change Request summary generated' `
        -Context @{ GroupCount = $GapResults.Count; TotalCRItems = $totalCR }

    return $summary
}
