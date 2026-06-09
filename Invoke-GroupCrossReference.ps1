<#
.SYNOPSIS
    Cross-references AD group membership against an external CSV user list

.DESCRIPTION
    Compares users in enumerated AD groups (from cache or live) against an
    external comma-delimited CSV containing user identifiers (SAM/LAN names).
    Produces a report showing:
      - Users in the group but NOT in the external list
      - Users in the external list but NOT in the group
      - Users present in both (matched)

    Common use case: reconciling RSA token holders, VPN access lists, or
    application license assignments against AD group membership.

.PARAMETER CachePath
    Path to a Group Enumerator JSON cache file (from a previous run).
    Mutually exclusive with -CsvPath + live enumeration.

.PARAMETER GroupFilter
    Optional group name filter. If provided, only groups matching this
    pattern (supports wildcards) are cross-referenced.
    Example: "GG_IT*" or "USV_Finance_Users"

.PARAMETER ExternalCsvPath
    Path to the external CSV file containing user identifiers.
    Expected: comma-delimited with a header row containing a column
    for the SAM/LAN account name.

.PARAMETER ExternalSamColumn
    Column name in the external CSV that contains the SAM/LAN username.
    Default: "SamAccountName". Also accepts "Username", "LanID", "UserID".

.PARAMETER OutputPath
    Directory for output files. Default: .\Output

.PARAMETER Theme
    HTML report theme: "dark" (default) or "light"

.PARAMETER ConfigPath
    Path to group-enum-config.json

.EXAMPLE
    .\Invoke-GroupCrossReference.ps1 -CachePath .\Cache\groups-20260409.json `
        -ExternalCsvPath .\rsa-tokens.csv -ExternalSamColumn "LanID"

.EXAMPLE
    .\Invoke-GroupCrossReference.ps1 -CachePath .\Cache\groups-20260409.json `
        -ExternalCsvPath .\vpn-users.csv -GroupFilter "GG_VPN*"

.NOTES
    Reuses GroupEnumLogger, GroupReportGenerator, and other common modules.
    No admin rights required. Works with cached data (no LDAP needed).
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$CachePath,

    [Parameter(Mandatory = $true)]
    [string]$ExternalCsvPath,

    [Parameter(Mandatory = $false)]
    [string]$GroupFilter,

    [Parameter(Mandatory = $false)]
    [string]$ExternalSamColumn = 'SamAccountName',

    [Parameter(Mandatory = $false)]
    [string]$OutputPath,

    [Parameter(Mandatory = $false)]
    [ValidateSet('dark', 'light')]
    [string]$Theme = 'dark',

    [Parameter(Mandatory = $false)]
    [string]$ConfigPath
)

$ErrorActionPreference = 'Stop'
$scriptRoot = $PSScriptRoot

# ---------------------------------------------------------------------------
# Load modules
# ---------------------------------------------------------------------------
Write-Host 'Loading modules...' -ForegroundColor Cyan

$moduleFiles = @(
    'GroupEnumLogger.ps1',
    'GroupEnumerator.ps1',
    'FuzzyMatcher.ps1',
    'GroupReportGenerator.ps1'
)

foreach ($moduleFile in $moduleFiles) {
    $modulePath = Join-Path (Join-Path $scriptRoot 'Modules') $moduleFile
    if (Test-Path $modulePath) {
        . $modulePath
    } else {
        Write-Error "Required module not found: $modulePath"
        exit 1
    }
}

Write-Host ''

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
try {
    # Load config
    if (-not $ConfigPath) {
        $ConfigPath = Join-Path $scriptRoot (Join-Path 'Config' 'group-enum-config.json')
    }
    $config = New-GroupEnumConfig -ConfigPath $ConfigPath

    # Initialize logging
    $logState = Initialize-GroupEnumLog -Config $config -ScriptRoot $scriptRoot
    if ($logState.Enabled) {
        Write-Host "  Log: $($logState.LogFilePath)" -ForegroundColor Gray
    }

    Write-GroupEnumLog -Level 'INFO' -Operation 'CrossReference' `
        -Message 'Cross-reference session started' -Context @{
            cachePath       = $CachePath
            externalCsvPath = $ExternalCsvPath
            groupFilter     = $(if ($GroupFilter) { $GroupFilter } else { '(all)' })
            samColumn       = $ExternalSamColumn
        }

    # ---- Load group cache ----
    Write-Host "Loading group cache: $CachePath" -ForegroundColor Cyan
    if (-not (Test-Path $CachePath)) {
        Write-Error "Cache file not found: $CachePath"
        exit 1
    }
    $cacheData    = Import-GroupDataJson -JsonPath $CachePath
    $groupResults = $cacheData.Groups

    # Apply group filter if specified
    if ($GroupFilter) {
        $groupResults = @($groupResults | Where-Object {
            $_.Data.GroupName -like $GroupFilter
        })
        Write-Host "  Filtered to $($groupResults.Count) group(s) matching '$GroupFilter'" -ForegroundColor Gray
    }

    Write-Host "  Loaded $($groupResults.Count) group(s)" -ForegroundColor Gray
    Write-Host ''

    # ---- Load external CSV ----
    Write-Host "Loading external CSV: $ExternalCsvPath" -ForegroundColor Cyan
    if (-not (Test-Path $ExternalCsvPath)) {
        Write-Error "External CSV not found: $ExternalCsvPath"
        exit 1
    }

    $externalRows = Import-Csv -Path $ExternalCsvPath -ErrorAction Stop
    $headers = $externalRows[0].PSObject.Properties.Name

    # Auto-detect SAM column if default not found
    $samCol = $null
    $commonNames = @($ExternalSamColumn, 'SamAccountName', 'sAMAccountName', 'Username',
                     'UserName', 'LanID', 'LAN_ID', 'UserID', 'User_ID', 'Account',
                     'AccountName', 'Login', 'LoginName', 'SAM')
    foreach ($candidate in $commonNames) {
        if ($headers -contains $candidate) {
            $samCol = $candidate
            break
        }
    }

    if (-not $samCol) {
        Write-Error "Cannot find SAM column in external CSV. Tried: $($commonNames -join ', '). Available headers: $($headers -join ', ')"
        exit 1
    }

    $externalSams = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($row in $externalRows) {
        $val = $row.$samCol
        if ($val -and $val.Trim()) {
            $null = $externalSams.Add($val.Trim())
        }
    }

    Write-Host "  Loaded $($externalSams.Count) unique users from column '$samCol'" -ForegroundColor Gray
    Write-Host ''

    # ---- Cross-reference each group ----
    Write-Host 'Cross-referencing...' -ForegroundColor Cyan

    $crossRefResults = @()

    foreach ($groupResult in $groupResults) {
        if ($groupResult.Data.Skipped) { continue }

        $domain    = $groupResult.Data.Domain
        $groupName = $groupResult.Data.GroupName
        $members   = if ($groupResult.Data.Members -is [array]) { $groupResult.Data.Members } elseif ($groupResult.Data.Members) { @(, $groupResult.Data.Members) } else { @() }

        $groupSams = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        $memberBySam = @{}
        foreach ($m in $members) {
            if ($m.SamAccountName) {
                $null = $groupSams.Add($m.SamAccountName)
                $memberBySam[$m.SamAccountName.ToLower()] = $m
            }
        }

        # In group but NOT in external list
        $inGroupNotExternal = @()
        foreach ($sam in $groupSams) {
            if (-not $externalSams.Contains($sam)) {
                $user = $memberBySam[$sam.ToLower()]
                $inGroupNotExternal += @{
                    SamAccountName = $sam
                    DisplayName    = if ($user.DisplayName) { $user.DisplayName } else { '' }
                    Email          = if ($user.Email) { $user.Email } else { '' }
                }
            }
        }

        # In external list but NOT in group
        $inExternalNotGroup = @()
        foreach ($sam in $externalSams) {
            if (-not $groupSams.Contains($sam)) {
                $inExternalNotGroup += @{
                    SamAccountName = $sam
                    DisplayName    = ''
                    Email          = ''
                }
            }
        }

        # In both
        $inBoth = @()
        foreach ($sam in $groupSams) {
            if ($externalSams.Contains($sam)) {
                $user = $memberBySam[$sam.ToLower()]
                $inBoth += @{
                    SamAccountName = $sam
                    DisplayName    = if ($user.DisplayName) { $user.DisplayName } else { '' }
                    Email          = if ($user.Email) { $user.Email } else { '' }
                }
            }
        }

        $result = @{
            Domain             = $domain
            GroupName          = $groupName
            InGroupNotExternal = $inGroupNotExternal
            InExternalNotGroup = $inExternalNotGroup
            InBoth             = $inBoth
            Summary            = @{
                GroupMemberCount       = $groupSams.Count
                ExternalCount          = $externalSams.Count
                InGroupNotExternalCount = $inGroupNotExternal.Count
                InExternalNotGroupCount = $inExternalNotGroup.Count
                InBothCount            = $inBoth.Count
            }
        }

        $crossRefResults += $result

        Write-Host "  $domain\$groupName : In group only=$($inGroupNotExternal.Count), In external only=$($inExternalNotGroup.Count), Both=$($inBoth.Count)" -ForegroundColor Gray

        Write-GroupEnumLog -Level 'INFO' -Operation 'CrossReference' `
            -Message "Cross-ref $domain\$groupName" -Context $result.Summary
    }

    Write-Host ''

    # ---- Resolve output directory ----
    $resolvedOutputDir = if ($OutputPath) { $OutputPath } else { Join-Path $scriptRoot 'Output' }
    if (-not (Test-Path $resolvedOutputDir)) {
        $null = New-Item -ItemType Directory -Path $resolvedOutputDir -Force
    }

    $timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $externalLeaf = [System.IO.Path]::GetFileNameWithoutExtension($ExternalCsvPath)

    # ---- Export CSV ----
    $csvOutPath = Join-Path $resolvedOutputDir "crossref-${externalLeaf}-${timestamp}.csv"

    $csvRows = [System.Collections.Generic.List[string]]::new()
    $csvRows.Add('Comparison,Domain,GroupName,SamAccountName,DisplayName,Email')

    foreach ($result in $crossRefResults) {
        foreach ($user in $result.InGroupNotExternal) {
            $csvRows.Add("InGroupOnly,$($result.Domain),$($result.GroupName),$($user.SamAccountName),`"$($user.DisplayName)`",$($user.Email)")
        }
        foreach ($user in $result.InExternalNotGroup) {
            $csvRows.Add("InExternalOnly,$($result.Domain),$($result.GroupName),$($user.SamAccountName),,")
        }
        foreach ($user in $result.InBoth) {
            $csvRows.Add("InBoth,$($result.Domain),$($result.GroupName),$($user.SamAccountName),`"$($user.DisplayName)`",$($user.Email)")
        }
    }

    [System.IO.File]::WriteAllText($csvOutPath, ($csvRows -join "`r`n"), [System.Text.UTF8Encoding]::new($false))
    Write-Host "  CSV: $csvOutPath" -ForegroundColor Cyan

    # ---- Export HTML ----
    $htmlOutPath = Join-Path $resolvedOutputDir "crossref-${externalLeaf}-${timestamp}.html"

    $htmlBuilder = [System.Text.StringBuilder]::new()
    $themeClass = if ($Theme -eq 'light') { 'theme-light' } else { 'theme-dark' }

    [void]$htmlBuilder.AppendLine("<!DOCTYPE html><html lang='en' class='$themeClass'><head><meta charset='UTF-8'><meta name='viewport' content='width=device-width,initial-scale=1.0'>")
    [void]$htmlBuilder.AppendLine("<title>Cross-Reference Report</title>")
    [void]$htmlBuilder.AppendLine("<style>")
    [void]$htmlBuilder.AppendLine(".theme-dark{--bg:#1a1a2e;--card-bg:#16213e;--text:#e0e0e0;--text-muted:#94a3b8;--accent:#3498db;--border:#2d3748;--th-bg:#2c3e50;--th-text:#fff;--row-alt:rgba(44,62,80,0.25);--row-hover:#1a2332;--shadow:0 4px 6px rgba(0,0,0,0.35)}")
    [void]$htmlBuilder.AppendLine(".theme-light{--bg:#f8f9fa;--card-bg:#fff;--text:#1a1a2e;--text-muted:#64748b;--accent:#2563eb;--border:#e2e8f0;--th-bg:#334155;--th-text:#fff;--row-alt:rgba(226,232,240,0.5);--row-hover:#e0eaff;--shadow:0 4px 6px rgba(0,0,0,0.1)}")
    [void]$htmlBuilder.AppendLine("*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}")
    [void]$htmlBuilder.AppendLine("body{font-family:-apple-system,'Segoe UI',system-ui,sans-serif;background:var(--bg);color:var(--text);padding:20px;line-height:1.6}")
    [void]$htmlBuilder.AppendLine(".container{max-width:1200px;margin:0 auto}")
    [void]$htmlBuilder.AppendLine("header{background:linear-gradient(135deg,#2c3e50,#3498db);padding:30px 35px;border-radius:10px;margin-bottom:30px;box-shadow:var(--shadow)}")
    [void]$htmlBuilder.AppendLine("header h1{font-size:2em;color:#fff;margin-bottom:8px}header .meta{color:#e8f4ff;font-size:0.92em;opacity:0.92}")
    [void]$htmlBuilder.AppendLine(".section{background:var(--card-bg);border-radius:10px;margin-bottom:24px;box-shadow:var(--shadow)}")
    [void]$htmlBuilder.AppendLine(".section-header{padding:18px 25px;border-bottom:2px solid var(--accent)}.section-header h2{color:var(--accent);font-size:1.3em}")
    [void]$htmlBuilder.AppendLine(".section-body{padding:25px}")
    [void]$htmlBuilder.AppendLine(".stat-cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:16px;margin-bottom:24px}")
    [void]$htmlBuilder.AppendLine(".stat-card{background:var(--bg);border:1px solid var(--border);border-radius:8px;padding:18px;text-align:center}")
    [void]$htmlBuilder.AppendLine(".stat-value{font-size:2em;font-weight:700;color:var(--accent)}.stat-label{font-size:0.8em;color:var(--text-muted);text-transform:uppercase}")
    [void]$htmlBuilder.AppendLine("table{width:100%;border-collapse:collapse;font-size:0.9em;background:var(--bg)}")
    [void]$htmlBuilder.AppendLine("thead th{background:var(--th-bg);color:var(--th-text);padding:10px 14px;text-align:left;font-size:0.82em;text-transform:uppercase}")
    [void]$htmlBuilder.AppendLine("tbody tr{border-bottom:1px solid var(--border)}tbody tr:nth-child(even){background:var(--row-alt)}tbody tr:hover{background:var(--row-hover)}")
    [void]$htmlBuilder.AppendLine("tbody td{padding:9px 14px}")
    [void]$htmlBuilder.AppendLine(".badge{display:inline-block;padding:2px 9px;border-radius:99px;font-size:0.78em;font-weight:600}")
    [void]$htmlBuilder.AppendLine(".badge-group{background:rgba(230,57,70,0.15);color:#e63946}.badge-external{background:rgba(245,158,11,0.15);color:#f59e0b}.badge-both{background:rgba(82,183,136,0.15);color:#52b788}")
    [void]$htmlBuilder.AppendLine("details{background:var(--card-bg);border:1px solid var(--border);border-radius:8px;margin-bottom:12px}")
    [void]$htmlBuilder.AppendLine("details>summary{padding:14px 20px;cursor:pointer;list-style:none;display:flex;align-items:center;gap:10px}")
    [void]$htmlBuilder.AppendLine("details>summary::-webkit-details-marker{display:none}")
    [void]$htmlBuilder.AppendLine("details>summary::before{content:'\\25B6';font-size:0.75em;color:var(--text-muted);transition:transform 0.2s}")
    [void]$htmlBuilder.AppendLine("details[open]>summary::before{transform:rotate(90deg)}")
    [void]$htmlBuilder.AppendLine(".detail-body{padding:18px 20px;border-top:1px solid var(--border)}")
    [void]$htmlBuilder.AppendLine("footer{text-align:center;padding:24px 0;color:var(--text-muted);font-size:0.85em;border-top:1px solid var(--border);margin-top:24px}")
    [void]$htmlBuilder.AppendLine("@media print{html{--bg:#f8f9fa;--card-bg:#fff;--text:#1a1a2e;--border:#e2e8f0;--th-bg:#334155;--shadow:none}}")
    [void]$htmlBuilder.AppendLine("</style></head><body><div class='container'>")

    # Header
    $reportTimestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    [void]$htmlBuilder.AppendLine("<header><h1>Cross-Reference Report</h1><div class='meta'>")
    [void]$htmlBuilder.AppendLine("<p><strong>Generated:</strong> $reportTimestamp &nbsp;|&nbsp; <strong>External Source:</strong> $externalLeaf</p>")
    [void]$htmlBuilder.AppendLine("<p><strong>Groups:</strong> $($crossRefResults.Count) &nbsp;|&nbsp; <strong>External Users:</strong> $($externalSams.Count)</p>")
    [void]$htmlBuilder.AppendLine("</div></header>")

    # Summary per group
    foreach ($result in $crossRefResults) {
        $gn  = [System.Web.HttpUtility]::HtmlEncode("$($result.Domain)\$($result.GroupName)")
        $s   = $result.Summary

        [void]$htmlBuilder.AppendLine("<details><summary>")
        [void]$htmlBuilder.AppendLine("<strong>$gn</strong>")
        [void]$htmlBuilder.AppendLine("<span style='margin-left:auto;font-size:0.85em;color:var(--text-muted)'>")
        [void]$htmlBuilder.AppendLine("<span class='badge badge-group'>Group Only: $($s.InGroupNotExternalCount)</span> ")
        [void]$htmlBuilder.AppendLine("<span class='badge badge-external'>External Only: $($s.InExternalNotGroupCount)</span> ")
        [void]$htmlBuilder.AppendLine("<span class='badge badge-both'>Both: $($s.InBothCount)</span>")
        [void]$htmlBuilder.AppendLine("</span></summary><div class='detail-body'>")

        # In Group Only table
        if ($result.InGroupNotExternal.Count -gt 0) {
            [void]$htmlBuilder.AppendLine("<h3 style='color:#e63946;margin-bottom:8px'>In Group Only ($($result.InGroupNotExternal.Count))</h3>")
            [void]$htmlBuilder.AppendLine("<table><thead><tr><th>SAM</th><th>Display Name</th><th>Email</th></tr></thead><tbody>")
            foreach ($u in ($result.InGroupNotExternal | Sort-Object SamAccountName)) {
                $eSam = [System.Web.HttpUtility]::HtmlEncode([string]$u.SamAccountName)
                $eDn  = [System.Web.HttpUtility]::HtmlEncode([string]$u.DisplayName)
                $eMail = [System.Web.HttpUtility]::HtmlEncode([string]$u.Email)
                [void]$htmlBuilder.AppendLine("<tr><td>$eSam</td><td>$eDn</td><td>$eMail</td></tr>")
            }
            [void]$htmlBuilder.AppendLine("</tbody></table><br/>")
        }

        # In External Only table
        if ($result.InExternalNotGroup.Count -gt 0) {
            [void]$htmlBuilder.AppendLine("<h3 style='color:#f59e0b;margin-bottom:8px'>In External Only ($($result.InExternalNotGroup.Count))</h3>")
            [void]$htmlBuilder.AppendLine("<table><thead><tr><th>SAM</th></tr></thead><tbody>")
            foreach ($u in ($result.InExternalNotGroup | Sort-Object SamAccountName)) {
                $eSam = [System.Web.HttpUtility]::HtmlEncode([string]$u.SamAccountName)
                [void]$htmlBuilder.AppendLine("<tr><td>$eSam</td></tr>")
            }
            [void]$htmlBuilder.AppendLine("</tbody></table><br/>")
        }

        # In Both table
        if ($result.InBoth.Count -gt 0) {
            [void]$htmlBuilder.AppendLine("<h3 style='color:#52b788;margin-bottom:8px'>In Both ($($result.InBoth.Count))</h3>")
            [void]$htmlBuilder.AppendLine("<table><thead><tr><th>SAM</th><th>Display Name</th><th>Email</th></tr></thead><tbody>")
            foreach ($u in ($result.InBoth | Sort-Object SamAccountName)) {
                $eSam = [System.Web.HttpUtility]::HtmlEncode([string]$u.SamAccountName)
                $eDn  = [System.Web.HttpUtility]::HtmlEncode([string]$u.DisplayName)
                $eMail = [System.Web.HttpUtility]::HtmlEncode([string]$u.Email)
                [void]$htmlBuilder.AppendLine("<tr><td>$eSam</td><td>$eDn</td><td>$eMail</td></tr>")
            }
            [void]$htmlBuilder.AppendLine("</tbody></table>")
        }

        [void]$htmlBuilder.AppendLine("</div></details>")
    }

    # Footer
    [void]$htmlBuilder.AppendLine("<footer><p>Cross-Reference Report &mdash; Generated $reportTimestamp</p></footer>")
    [void]$htmlBuilder.AppendLine("</div></body></html>")

    [System.IO.File]::WriteAllText($htmlOutPath, $htmlBuilder.ToString(), [System.Text.UTF8Encoding]::new($false))
    Write-Host "  HTML: $htmlOutPath" -ForegroundColor Cyan

    # ---- Summary ----
    Write-Host ''
    Write-Host '========================================' -ForegroundColor Cyan
    Write-Host 'Cross-Reference Summary' -ForegroundColor Cyan
    Write-Host '========================================' -ForegroundColor Cyan
    Write-Host "  Groups analyzed    : $($crossRefResults.Count)" -ForegroundColor White
    Write-Host "  External users     : $($externalSams.Count)" -ForegroundColor White
    Write-Host "  CSV output         : $csvOutPath" -ForegroundColor Cyan
    Write-Host "  HTML output        : $htmlOutPath" -ForegroundColor Cyan

    $logPath = Close-GroupEnumLog -Summary @{
        groups       = $crossRefResults.Count
        externalUsers = $externalSams.Count
    }
    if ($logPath) {
        Write-Host "  Log                : $logPath" -ForegroundColor Cyan
    }

    Write-Host ''

} catch {
    Write-Host ''
    Write-Host "FATAL ERROR: $_" -ForegroundColor Red
    Write-Host $_.ScriptStackTrace -ForegroundColor DarkRed
    exit 1
}
