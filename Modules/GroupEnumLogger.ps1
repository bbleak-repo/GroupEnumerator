<#
.SYNOPSIS
    File-based JSON Lines logger for the Group Enumerator tool

.DESCRIPTION
    Structured logging to .jsonl (JSON Lines) format. Each line is a self-contained
    JSON object with timestamp, level, operation, and context fields.

    No admin rights required. No Windows Event Log dependency.
    Follows the same pattern as BreakGlass-Tool/Modules/AuditLogger.ps1.

.NOTES
    Log levels: DEBUG, INFO, WARN, ERROR
    File format: one compressed JSON object per line (.jsonl)
    Encoding: UTF-8 without BOM
    Timestamps: ISO 8601 UTC
#>

# ---------------------------------------------------------------------------
# Script-scope state
# ---------------------------------------------------------------------------
$script:GroupEnumLogState = @{
    Enabled     = $false
    LogFilePath = $null
    LogLevel    = 'INFO'
    Issues      = @()
}

$script:LogLevelRank = @{
    'DEBUG' = 0
    'INFO'  = 1
    'WARN'  = 2
    'ERROR' = 3
}

# ---------------------------------------------------------------------------
# Public: Initialize-GroupEnumLog
# ---------------------------------------------------------------------------
function Initialize-GroupEnumLog {
    <#
    .SYNOPSIS
        Sets up file-based logging for the Group Enumerator session

    .PARAMETER Config
        Configuration hashtable. Expected keys:
          LogEnabled  - $true/$false (default $true)
          LogPath     - Directory or file path for log output
          LogLevel    - Minimum level: DEBUG, INFO, WARN, ERROR (default INFO)

    .PARAMETER ScriptRoot
        Project root directory for resolving relative log paths

    .PARAMETER SessionId
        Optional session identifier for correlating log entries across a run

    .OUTPUTS
        Hashtable with Enabled, LogFilePath, Issues keys
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$Config,

        [Parameter(Mandatory = $true)]
        [string]$ScriptRoot,

        [Parameter(Mandatory = $false)]
        [string]$SessionId = ''
    )

    $issues = @()

    # Determine if logging is enabled
    $enabled = if ($null -ne $Config.LogEnabled) { $Config.LogEnabled } else { $true }

    if (-not $enabled) {
        $script:GroupEnumLogState = @{
            Enabled     = $false
            LogFilePath = $null
            LogLevel    = 'INFO'
            Issues      = @('Logging disabled by configuration')
        }
        return $script:GroupEnumLogState
    }

    # Resolve log level
    $level = if ($Config.LogLevel) { $Config.LogLevel.ToUpper() } else { 'INFO' }
    if (-not $script:LogLevelRank.ContainsKey($level)) {
        $issues += "Invalid LogLevel '$level'. Defaulting to INFO."
        $level = 'INFO'
    }

    # Resolve log file path
    $logPath = if ($Config.LogPath) { $Config.LogPath } else { 'Logs' }

    if (-not [System.IO.Path]::IsPathRooted($logPath)) {
        $logPath = Join-Path $ScriptRoot $logPath
    }

    # If path looks like a directory (no extension), build a filename
    $extension = [System.IO.Path]::GetExtension($logPath)
    if (-not $extension) {
        $timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'
        $logPath = Join-Path $logPath "group-enum-$timestamp.jsonl"
    }

    # Ensure parent directory exists
    $logDir = Split-Path $logPath -Parent
    if ($logDir -and -not (Test-Path $logDir)) {
        try {
            $null = New-Item -ItemType Directory -Path $logDir -Force
        } catch {
            $issues += "Cannot create log directory '$logDir': $_"
            $enabled = $false
        }
    }

    # Generate session ID if not provided
    if (-not $SessionId) {
        $SessionId = [guid]::NewGuid().ToString('N').Substring(0, 8)
    }

    $script:GroupEnumLogState = @{
        Enabled     = $enabled
        LogFilePath = $logPath
        LogLevel    = $level
        SessionId   = $SessionId
        Issues      = $issues
    }

    if ($enabled) {
        # Write session start entry
        Write-GroupEnumLog -Level 'INFO' -Operation 'SessionStart' `
            -Message "Group Enumerator logging initialized" `
            -Context @{
                LogFile   = $logPath
                LogLevel  = $level
                SessionId = $SessionId
                Operator  = "$env:USERDOMAIN\$env:USERNAME"
                Computer  = $env:COMPUTERNAME
            }
    }

    return $script:GroupEnumLogState
}

# ---------------------------------------------------------------------------
# Public: Write-GroupEnumLog
# ---------------------------------------------------------------------------
function Write-GroupEnumLog {
    <#
    .SYNOPSIS
        Writes a structured log entry to the JSON Lines file

    .PARAMETER Level
        Log level: DEBUG, INFO, WARN, ERROR

    .PARAMETER Operation
        What operation produced this entry (e.g. LdapConnect, EnumerateGroup, FuzzyMatch)

    .PARAMETER Message
        Human-readable description

    .PARAMETER Context
        Optional hashtable of structured data fields (domain, groupName, memberCount, etc.)
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('DEBUG', 'INFO', 'WARN', 'ERROR')]
        [string]$Level,

        [Parameter(Mandatory = $true)]
        [string]$Operation,

        [Parameter(Mandatory = $true)]
        [string]$Message,

        [Parameter(Mandatory = $false)]
        [hashtable]$Context = @{}
    )

    if (-not $script:GroupEnumLogState.Enabled) { return }

    # Check minimum log level
    $entryRank   = $script:LogLevelRank[$Level]
    $minRank     = $script:LogLevelRank[$script:GroupEnumLogState.LogLevel]
    if ($entryRank -lt $minRank) { return }

    $entry = @{
        timestamp = [DateTime]::UtcNow.ToString('o')
        level     = $Level
        sessionId = $script:GroupEnumLogState.SessionId
        operation = $Operation
        message   = $Message
    }

    # Merge context fields into the entry (flat, not nested)
    foreach ($key in $Context.Keys) {
        if (-not $entry.ContainsKey($key)) {
            $entry[$key] = $Context[$key]
        }
    }

    try {
        $jsonLine = $entry | ConvertTo-Json -Compress -Depth 3
        Add-Content -Path $script:GroupEnumLogState.LogFilePath -Value $jsonLine `
            -Encoding UTF8 -ErrorAction Stop
    } catch {
        # Avoid recursive logging failures -- just warn to console
        Write-Warning "Failed to write log entry: $_"
    }
}

# ---------------------------------------------------------------------------
# Public: Get-GroupEnumLog
# ---------------------------------------------------------------------------
function Get-GroupEnumLog {
    <#
    .SYNOPSIS
        Reads and parses entries from a Group Enumerator log file

    .PARAMETER LogFilePath
        Path to the .jsonl log file. Defaults to current session log.

    .PARAMETER Last
        Return only the last N entries. 0 = all entries (default).

    .PARAMETER Level
        Filter to entries at or above this level.

    .OUTPUTS
        Array of parsed log entry objects
    #>
    [CmdletBinding()]
    [OutputType([array])]
    param(
        [Parameter(Mandatory = $false)]
        [string]$LogFilePath,

        [Parameter(Mandatory = $false)]
        [int]$Last = 0,

        [Parameter(Mandatory = $false)]
        [ValidateSet('DEBUG', 'INFO', 'WARN', 'ERROR')]
        [string]$Level
    )

    if (-not $LogFilePath) {
        $LogFilePath = $script:GroupEnumLogState.LogFilePath
    }

    if (-not $LogFilePath -or -not (Test-Path $LogFilePath)) {
        return @()
    }

    $lines = Get-Content -Path $LogFilePath -Encoding UTF8 -ErrorAction SilentlyContinue
    if (-not $lines) { return @() }

    $entries = @()
    foreach ($line in $lines) {
        if ($line.Trim()) {
            try {
                $entries += ($line | ConvertFrom-Json)
            } catch {
                # Skip malformed lines
            }
        }
    }

    # Filter by level if specified
    if ($Level) {
        $minRank = $script:LogLevelRank[$Level]
        $entries = @($entries | Where-Object {
            $r = $script:LogLevelRank[$_.level]
            $null -ne $r -and $r -ge $minRank
        })
    }

    # Return last N if specified
    if ($Last -gt 0 -and $entries.Count -gt $Last) {
        $entries = $entries[($entries.Count - $Last)..($entries.Count - 1)]
    }

    return $entries
}

# ---------------------------------------------------------------------------
# Public: Close-GroupEnumLog
# ---------------------------------------------------------------------------
function Close-GroupEnumLog {
    <#
    .SYNOPSIS
        Writes a session-end entry and returns the log file path
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $false)]
        [hashtable]$Summary = @{}
    )

    if (-not $script:GroupEnumLogState.Enabled) { return $null }

    Write-GroupEnumLog -Level 'INFO' -Operation 'SessionEnd' `
        -Message 'Group Enumerator session complete' -Context $Summary

    $path = $script:GroupEnumLogState.LogFilePath
    $script:GroupEnumLogState.Enabled = $false
    return $path
}
