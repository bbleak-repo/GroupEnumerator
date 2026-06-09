<#
.SYNOPSIS
    Application-to-group mapping module for migration readiness tool.

.DESCRIPTION
    Provides optional application-level readiness visibility by mapping applications
    to their underlying AD group pairs. Consumes gap analysis results from GapAnalysis.ps1
    to produce per-application readiness metrics.

    CSV format for app mapping:
        AppName,SourceGroup,TargetGroup,Notes
        Salesforce,GG_Sales_Users,USV_Sales_Users,IdP initiated
        ServiceNow,GG_ITSM_Team,USV_ITSM_Team,SP initiated

    Status thresholds:
        Ready       - 100% readiness
        InProgress  - 50-99% readiness
        Blocked     - < 50% readiness
        NotAnalyzed - No matching gap result found

.NOTES
    No emoji in code.
    Uses Write-GroupEnumLog for structured logging (must be loaded before dot-sourcing).
    Module return pattern: @{ ... ; Errors = @() } where applicable.
    File writes use UTF-8 without BOM via [System.IO.File]::WriteAllText.
#>

# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

function Get-AppStatusFromPercent {
    <#
    .SYNOPSIS
        Converts a readiness percentage to a status label.
    #>
    param([double]$Percent)

    if ($Percent -ge 100.0)  { return 'Ready' }
    if ($Percent -ge 50.0)   { return 'InProgress' }
    return 'Blocked'
}

function Find-GapResultForGroups {
    <#
    .SYNOPSIS
        Finds the gap result whose source group or target group matches either supplied name.
        Matching is case-insensitive on GroupName only (domain-prefix stripped if present).
    #>
    param(
        [array]$GapResults,
        [string]$SourceGroup,
        [string]$TargetGroup
    )

    # Strip domain prefix if caller passed DOMAIN\Group
    $srcGroupName = if ($SourceGroup -match '\\') { ($SourceGroup -split '\\', 2)[1] } else { $SourceGroup }
    $tgtGroupName = if ($TargetGroup -match '\\') { ($TargetGroup -split '\\', 2)[1] } else { $TargetGroup }

    foreach ($gap in $GapResults) {
        $pair = $gap.GroupPair
        if (-not $pair) { continue }

        $gapSrc = if ($pair.SourceGroup) { $pair.SourceGroup } else { '' }
        $gapTgt = if ($pair.TargetGroup) { $pair.TargetGroup } else { '' }

        if ($srcGroupName -and $gapSrc -and $gapSrc -ieq $srcGroupName) { return $gap }
        if ($tgtGroupName -and $gapTgt -and $gapTgt -ieq $tgtGroupName) { return $gap }
    }

    return $null
}

# ---------------------------------------------------------------------------
# Public: Import-AppMapping
# ---------------------------------------------------------------------------
function Import-AppMapping {
    <#
    .SYNOPSIS
        Load an optional CSV that maps applications to AD groups.

    .DESCRIPTION
        Reads a CSV file with the columns AppName, SourceGroup, TargetGroup, Notes.
        Returns an empty array (with a warning log entry) if the file does not exist.

        Expected CSV format (header row required):
            AppName,SourceGroup,TargetGroup,Notes
            Salesforce,GG_Sales_Users,USV_Sales_Users,IdP initiated

    .PARAMETER CsvPath
        Path to the application mapping CSV file.

    .OUTPUTS
        Array of hashtables: @( @{ AppName; SourceGroup; TargetGroup; Notes } )
        Returns an empty array if the file does not exist or contains no valid rows.
    #>
    [CmdletBinding()]
    [OutputType([array])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$CsvPath
    )

    if (-not (Test-Path $CsvPath)) {
        Write-GroupEnumLog -Level 'WARN' -Operation 'ImportAppMapping' `
            -Message "App mapping CSV not found at '$CsvPath'. Skipping application readiness." `
            -Context @{ CsvPath = $CsvPath }
        return , @()
    }

    try {
        $csvRows = Import-Csv -Path $CsvPath -ErrorAction Stop
    } catch {
        Write-GroupEnumLog -Level 'ERROR' -Operation 'ImportAppMapping' `
            -Message "Failed to parse app mapping CSV '$CsvPath': $_" `
            -Context @{ CsvPath = $CsvPath }
        return @()
    }

    if (-not $csvRows -or @($csvRows).Count -eq 0) {
        Write-GroupEnumLog -Level 'WARN' -Operation 'ImportAppMapping' `
            -Message "App mapping CSV '$CsvPath' is empty." `
            -Context @{ CsvPath = $CsvPath }
        return @()
    }

    $mappings = [System.Collections.Generic.List[hashtable]]::new()
    $rowNum   = 1

    foreach ($row in $csvRows) {
        $rowNum++

        $appName     = if ($row.AppName)     { $row.AppName.Trim() }     else { '' }
        $sourceGroup = if ($row.SourceGroup) { $row.SourceGroup.Trim() } else { '' }
        $targetGroup = if ($row.TargetGroup) { $row.TargetGroup.Trim() } else { '' }
        $notes       = if ($row.Notes)       { $row.Notes.Trim() }       else { '' }

        if (-not $appName -or (-not $sourceGroup -and -not $targetGroup)) {
            Write-GroupEnumLog -Level 'WARN' -Operation 'ImportAppMapping' `
                -Message "Row $rowNum in '$CsvPath' is missing AppName or both group columns. Skipping." `
                -Context @{ Row = $rowNum; AppName = $appName }
            continue
        }

        $mappings.Add(@{
            AppName     = $appName
            SourceGroup = $sourceGroup
            TargetGroup = $targetGroup
            Notes       = $notes
        })
    }

    Write-GroupEnumLog -Level 'INFO' -Operation 'ImportAppMapping' `
        -Message "Loaded $($mappings.Count) app mappings from '$CsvPath'" `
        -Context @{ CsvPath = $CsvPath; AppCount = $mappings.Count }

    return $mappings.ToArray()
}

# ---------------------------------------------------------------------------
# Public: Get-AppReadiness
# ---------------------------------------------------------------------------
function Get-AppReadiness {
    <#
    .SYNOPSIS
        Calculate per-application migration readiness from gap analysis results.

    .DESCRIPTION
        For each app mapping, locates the corresponding gap result by matching source or
        target group name. Extracts the readiness percentage and CR counts from that result.

        Apps whose group was not analysed are given status "NotAnalyzed".

    .PARAMETER AppMappings
        Array of hashtables from Import-AppMapping.

    .PARAMETER GapResults
        Array of hashtables from Get-MigrationGapAnalysis.

    .OUTPUTS
        Hashtable:
        @{
            Apps    = @(
                @{
                    AppName          = "Salesforce"
                    SourceGroup      = "GG_Sales_Users"
                    TargetGroup      = "USV_Sales_Users"
                    ReadinessPercent = 85.0
                    GapCount         = 3
                    P1Count          = 1
                    P2Count          = 2
                    P3Count          = 0
                    Notes            = "IdP initiated"
                    Status           = "InProgress"
                }
            )
            Summary = @{
                TotalApps      = 3
                ReadyApps      = 1
                InProgressApps = 1
                BlockedApps    = 1
                NotAnalyzedApps = 0
            }
        }
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [array]$AppMappings,

        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [array]$GapResults
    )

    $apps          = [System.Collections.Generic.List[hashtable]]::new()
    $readyCount    = 0
    $inProgressCount = 0
    $blockedCount  = 0
    $notAnalyzedCount = 0

    foreach ($mapping in $AppMappings) {
        $appName     = $mapping.AppName
        $sourceGroup = $mapping.SourceGroup
        $targetGroup = $mapping.TargetGroup
        $notes       = if ($mapping.Notes) { $mapping.Notes } else { '' }

        $matchedGap = Find-GapResultForGroups -GapResults $GapResults `
            -SourceGroup $sourceGroup -TargetGroup $targetGroup

        if ($null -eq $matchedGap) {
            $notAnalyzedCount++
            Write-GroupEnumLog -Level 'WARN' -Operation 'AppReadiness' `
                -Message "No gap result found for app '$appName' (source: $sourceGroup, target: $targetGroup)" `
                -Context @{ AppName = $appName; SourceGroup = $sourceGroup; TargetGroup = $targetGroup }

            $apps.Add(@{
                AppName          = $appName
                SourceGroup      = $sourceGroup
                TargetGroup      = $targetGroup
                ReadinessPercent = 0.0
                GapCount         = 0
                P1Count          = 0
                P2Count          = 0
                P3Count          = 0
                Notes            = $notes
                Status           = 'NotAnalyzed'
            })
            continue
        }

        $r = $matchedGap.Readiness

        $pct  = if ($r -and $null -ne $r.Percent)             { [double]$r.Percent }             else { 0.0 }
        $np   = if ($r -and $null -ne $r.NotProvisionedCount) { [int]$r.NotProvisionedCount }    else { 0 }
        $atg  = if ($r -and $null -ne $r.AddToGroupCount)     { [int]$r.AddToGroupCount }        else { 0 }
        $orp  = if ($r -and $null -ne $r.OrphanedCount)       { [int]$r.OrphanedCount }          else { 0 }
        $gapCount = $np + $atg + $orp

        $status = Get-AppStatusFromPercent -Percent $pct

        switch ($status) {
            'Ready'       { $readyCount++ }
            'InProgress'  { $inProgressCount++ }
            'Blocked'     {
                $blockedCount++
                Write-GroupEnumLog -Level 'WARN' -Operation 'AppReadiness' `
                    -Message "App '$appName' is BLOCKED ($pct% ready, $gapCount gaps)" `
                    -Context @{ AppName = $appName; ReadinessPercent = $pct; GapCount = $gapCount }
            }
        }

        Write-GroupEnumLog -Level 'INFO' -Operation 'AppReadiness' `
            -Message "App '$appName': $pct% ready, $gapCount gaps, status: $status" `
            -Context @{
                AppName          = $appName
                ReadinessPercent = $pct
                GapCount         = $gapCount
                P1Count          = $np
                P2Count          = $atg
                P3Count          = $orp
                Status           = $status
            }

        $apps.Add(@{
            AppName          = $appName
            SourceGroup      = $sourceGroup
            TargetGroup      = $targetGroup
            ReadinessPercent = $pct
            GapCount         = $gapCount
            P1Count          = $np
            P2Count          = $atg
            P3Count          = $orp
            Notes            = $notes
            Status           = $status
        })
    }

    return @{
        Apps    = $apps.ToArray()
        Summary = @{
            TotalApps       = $AppMappings.Count
            ReadyApps       = $readyCount
            InProgressApps  = $inProgressCount
            BlockedApps     = $blockedCount
            NotAnalyzedApps = $notAnalyzedCount
        }
    }
}

# ---------------------------------------------------------------------------
# Public: Export-AppReadinessCsv
# ---------------------------------------------------------------------------
function Export-AppReadinessCsv {
    <#
    .SYNOPSIS
        Export per-application readiness to CSV.

    .DESCRIPTION
        Writes a UTF-8 (no BOM) CSV sorted by status (Blocked first) then app name.

        Columns:
          AppName | SourceGroup | TargetGroup | Status | ReadinessPercent |
          GapCount | P1Count | P2Count | P3Count | Notes

    .PARAMETER AppReadiness
        Hashtable from Get-AppReadiness.

    .PARAMETER OutputPath
        Full file path for the output CSV file.

    .OUTPUTS
        String path to the written CSV file.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$AppReadiness,

        [Parameter(Mandatory = $true)]
        [string]$OutputPath
    )

    # Helper: escape a CSV field
    function ConvertTo-CsvField {
        param([string]$Value)
        if ($null -eq $Value) { return '' }
        if ($Value -match '[",\r\n]') {
            $escaped = $Value -replace '"', '""'
            return "`"$escaped`""
        }
        return $Value
    }

    $statusSortKey = @{
        'Blocked'     = 1
        'InProgress'  = 2
        'Ready'       = 3
        'NotAnalyzed' = 4
    }

    $header = 'AppName,SourceGroup,TargetGroup,Status,ReadinessPercent,' +
              'GapCount,P1Count,P2Count,P3Count,Notes'

    $rows = [System.Collections.Generic.List[string]]::new()
    $rows.Add($header)

    $apps = if ($AppReadiness.Apps) { @($AppReadiness.Apps) } else { @() }

    $sorted = $apps | Sort-Object `
        @{ Expression = { $k = $_.Status; if ($statusSortKey.ContainsKey($k)) { $statusSortKey[$k] } else { 5 } } },
        @{ Expression = { $_.AppName } }

    foreach ($app in $sorted) {
        $row = (ConvertTo-CsvField -Value $app.AppName),
               (ConvertTo-CsvField -Value $app.SourceGroup),
               (ConvertTo-CsvField -Value $app.TargetGroup),
               (ConvertTo-CsvField -Value $app.Status),
               (ConvertTo-CsvField -Value ([string]$app.ReadinessPercent)),
               (ConvertTo-CsvField -Value ([string]$app.GapCount)),
               (ConvertTo-CsvField -Value ([string]$app.P1Count)),
               (ConvertTo-CsvField -Value ([string]$app.P2Count)),
               (ConvertTo-CsvField -Value ([string]$app.P3Count)),
               (ConvertTo-CsvField -Value $app.Notes)

        $rows.Add($row -join ',')
    }

    try {
        $outDir = Split-Path $OutputPath -Parent
        if ($outDir -and -not (Test-Path $outDir)) {
            $null = New-Item -ItemType Directory -Path $outDir -Force
        }

        $csvContent = $rows -join "`r`n"
        [System.IO.File]::WriteAllText($OutputPath, $csvContent, [System.Text.UTF8Encoding]::new($false))

        Write-GroupEnumLog -Level 'INFO' -Operation 'ExportAppCsv' `
            -Message "App readiness CSV written: $OutputPath" `
            -Context @{ OutputPath = $OutputPath; AppCount = $apps.Count }

        return $OutputPath

    } catch {
        $msg = "Export-AppReadinessCsv failed writing to '$OutputPath': $_"
        Write-GroupEnumLog -Level 'ERROR' -Operation 'ExportAppCsv' -Message $msg
        throw $msg
    }
}
