<#
.SYNOPSIS
    SQLite-backed membership state via Python state_db.py CLI wrapper.

.DESCRIPTION
    Provides the same function signatures and return shapes as MembershipState.ps1
    (Import-MembershipState, Update-MembershipState, Save-MembershipState,
    Add-ChangeLogEntries) but delegates to the Python state_db.py CLI tool which
    stores data in a SQLite database.

    Additionally provides "Auto" dispatch functions that route to either JSON
    or SQLite backends based on a -Backend parameter, and a migration helper for
    importing existing JSON state files into SQLite.

    This module also provides Get-CacheFromSqlite for the incremental gate, and
    Start-EnumerationRun / Complete-EnumerationRun for run lifecycle management.

.NOTES
    Dot-sourced .ps1 file (NOT .psm1). No Export-ModuleMember.
    PowerShell 5.1 compatible.
    No emoji in code.
    Version: 3.0.0
#>

# ---------------------------------------------------------------------------
# Script-scoped variables
# ---------------------------------------------------------------------------
$script:pythonAvailable = $null
$script:pythonCommand   = $null
$script:stateDbScript   = Join-Path (Split-Path $PSScriptRoot -Parent) 'state_db.py'

# ---------------------------------------------------------------------------
# Private: optional structured logging (no-op if logger not loaded)
# ---------------------------------------------------------------------------
function Write-StateDbLog {
    param(
        [string]$Level = 'INFO',
        [string]$Operation = 'StateDatabase',
        [string]$Message = '',
        [hashtable]$Context = @{}
    )
    if ($null -ne (Get-Command Write-GroupEnumLog -ErrorAction SilentlyContinue)) {
        Write-GroupEnumLog -Level $Level -Operation $Operation -Message $Message -Context $Context
    }
}

# ---------------------------------------------------------------------------
# Private: Convert PSCustomObject to hashtable (recursive, PS 5.1 compat)
# ---------------------------------------------------------------------------
function ConvertTo-HashtableDeep {
    <#
    .SYNOPSIS
        Recursively converts PSCustomObject (from ConvertFrom-Json) to hashtable.
    #>
    param($InputObject)

    if ($null -eq $InputObject) { return $null }

    if ($InputObject -is [System.Management.Automation.PSCustomObject]) {
        $ht = @{}
        foreach ($prop in $InputObject.PSObject.Properties) {
            $ht[$prop.Name] = ConvertTo-HashtableDeep $prop.Value
        }
        return $ht
    }

    if ($InputObject -is [System.Collections.IList]) {
        $arr = @()
        foreach ($item in $InputObject) {
            $arr += , (ConvertTo-HashtableDeep $item)
        }
        return $arr
    }

    return $InputObject
}

# ---------------------------------------------------------------------------
# Public: Test-PythonAvailable
# ---------------------------------------------------------------------------
function Test-PythonAvailable {
    <#
    .SYNOPSIS
        Checks whether python3 (or python) is available on this system.

    .OUTPUTS
        [bool] True if a usable Python interpreter was found, False otherwise.
        Caches the result in $script:pythonAvailable for subsequent calls.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param()

    if ($null -ne $script:pythonAvailable) {
        return $script:pythonAvailable
    }

    # Candidate launchers in preference order. 'py' (the Windows Python launcher)
    # is tried first because it is never shadowed by the Microsoft Store
    # "App execution alias" stub that hijacks bare 'python'/'python3' when no
    # Store Python is installed. That stub prints "Python was not found..." and
    # (depending on PATH order under -File invocation) could otherwise be
    # mis-detected as a working interpreter, then fail every state_db.py call.
    foreach ($candidate in @('py', 'python3', 'python')) {
        try {
            $verOutput = & $candidate --version 2>&1 | Out-String
            # Accept only a real interpreter: exit 0 AND a "Python X.Y" banner.
            # The Store stub exits non-zero and emits the "not found" message,
            # so this banner check rejects it on every Windows configuration.
            if ($LASTEXITCODE -eq 0 -and $verOutput -match 'Python\s+\d') {
                $script:pythonCommand   = $candidate
                $script:pythonAvailable = $true
                Write-StateDbLog -Level 'DEBUG' -Message "Python found: $candidate ($($verOutput.Trim()))"
                return $true
            }
        } catch { }
    }

    $script:pythonAvailable = $false
    Write-StateDbLog -Level 'WARN' -Message 'No Python interpreter found (tried py, python3, python)'
    return $false
}

# ---------------------------------------------------------------------------
# Public: Invoke-StateDb
# ---------------------------------------------------------------------------
function Invoke-StateDb {
    <#
    .SYNOPSIS
        Core wrapper that calls the state_db.py CLI tool with a given subcommand.

    .PARAMETER Command
        The state_db.py subcommand (e.g. import-state, update-state, etc.).

    .PARAMETER Arguments
        Additional CLI arguments to pass after the subcommand.

    .PARAMETER StdinJson
        Optional JSON string to pipe to stdin.

    .PARAMETER DbPath
        Path to the SQLite database file. If not specified, state_db.py uses its default.

    .OUTPUTS
        Parsed JSON response (as hashtable/array) or $null on error.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Command,

        [Parameter(Mandatory = $false)]
        [string[]]$Arguments = @(),

        [Parameter(Mandatory = $false)]
        [string]$StdinJson,

        [Parameter(Mandatory = $false)]
        [string]$DbPath
    )

    if (-not (Test-PythonAvailable)) {
        Write-Warning 'StateDatabase: Python is not available. SQLite backend cannot function.'
        return $null
    }

    if (-not (Test-Path $script:stateDbScript)) {
        Write-Warning "StateDatabase: state_db.py not found at $($script:stateDbScript)"
        return $null
    }

    # Build argument list. state_db.py uses subparsers so --db is per-subcommand:
    #   python3 state_db.py <subcommand> --db $DbPath [other args...]
    $argList = @($script:stateDbScript, $Command)
    if ($DbPath) {
        $argList += '--db'
        $argList += $DbPath
    }
    $argList += $Arguments

    $stdoutContent = $null
    $stderrContent = $null
    $exitCode      = 0

    # Native python stderr (even redirected to a file) can raise NativeCommandError
    # under an inherited $ErrorActionPreference='Stop' in PS 5.1, masking a
    # successful run as a silent $null. Drop to Continue locally; the exit code and
    # stderr are inspected explicitly below. The stdin branch uses ProcessStartInfo
    # and is unaffected either way.
    $ErrorActionPreference = 'Continue'

    try {
        if ($StdinJson) {
            # Pipe JSON via stdin using a process to avoid PS 5.1 quirks with
            # pipeline + native stdin.
            $psi = [System.Diagnostics.ProcessStartInfo]::new()
            $psi.FileName               = $script:pythonCommand
            $psi.Arguments              = ($argList | ForEach-Object { '"{0}"' -f ($_ -replace '"', '\"') }) -join ' '
            $psi.UseShellExecute        = $false
            $psi.RedirectStandardInput  = $true
            $psi.RedirectStandardOutput = $true
            $psi.RedirectStandardError  = $true
            $psi.CreateNoWindow         = $true

            # Ensure UTF-8 encoding on stdout/stderr
            $psi.StandardOutputEncoding = [System.Text.UTF8Encoding]::new($false)
            $psi.StandardErrorEncoding  = [System.Text.UTF8Encoding]::new($false)

            $proc = [System.Diagnostics.Process]::new()
            $proc.StartInfo = $psi
            $null = $proc.Start()

            # Read stdout/stderr ASYNCHRONOUSLY before writing stdin, so a large
            # stdin payload (big snapshot) can't deadlock against the child filling
            # its stdout/stderr pipe while we're still blocked writing input.
            $outTask = $proc.StandardOutput.ReadToEndAsync()
            $errTask = $proc.StandardError.ReadToEndAsync()

            # Write JSON to stdin as explicit UTF-8 bytes (no BOM) and close
            # immediately so the process does not hang waiting for input. We write
            # the underlying byte stream rather than relying on
            # ProcessStartInfo.StandardInputEncoding (unreliable across .NET
            # versions); the StreamWriter would otherwise encode with the console
            # code page, corrupting non-ASCII member data (accented DisplayName /
            # Email) that the Python side decodes as utf-8-sig.
            $utf8NoBom = [System.Text.UTF8Encoding]::new($false)
            $inBytes   = $utf8NoBom.GetBytes($StdinJson)
            $proc.StandardInput.BaseStream.Write($inBytes, 0, $inBytes.Length)
            $proc.StandardInput.BaseStream.Flush()
            $proc.StandardInput.Close()

            $stdoutContent = $outTask.GetAwaiter().GetResult()
            $stderrContent = $errTask.GetAwaiter().GetResult()
            $proc.WaitForExit()
            $exitCode = $proc.ExitCode
            $proc.Dispose()
        } else {
            # No stdin needed -- use standard invocation
            $tempStderr = [System.IO.Path]::GetTempFileName()
            try {
                $stdoutContent = & $script:pythonCommand $argList 2>$tempStderr
                $exitCode = $LASTEXITCODE
                if (Test-Path $tempStderr) {
                    $stderrContent = [System.IO.File]::ReadAllText($tempStderr)
                }
            } finally {
                if (Test-Path $tempStderr) {
                    Remove-Item $tempStderr -Force -ErrorAction SilentlyContinue
                }
            }
        }
    } catch {
        Write-Warning "StateDatabase: Failed to execute state_db.py $Command -- $_"
        Write-StateDbLog -Level 'ERROR' -Operation 'StateDatabase' `
            -Message "Failed to execute state_db.py $Command" -Context @{ error = $_.ToString() }
        return $null
    }

    if ($exitCode -ne 0) {
        $errMsg = if ($stderrContent) { $stderrContent.Trim() } else { "exit code $exitCode" }
        Write-Warning "StateDatabase: state_db.py $Command failed -- $errMsg"
        Write-StateDbLog -Level 'WARN' -Operation 'StateDatabase' `
            -Message "state_db.py $Command failed" -Context @{ exitCode = $exitCode; stderr = $errMsg }
        return $null
    }

    # Parse stdout JSON
    $rawJson = if ($stdoutContent -is [array]) { $stdoutContent -join '' } else { [string]$stdoutContent }
    if ([string]::IsNullOrWhiteSpace($rawJson)) {
        Write-StateDbLog -Level 'WARN' -Message "state_db.py $Command returned empty output"
        return $null
    }

    try {
        $parsed = $rawJson | ConvertFrom-Json
        return $parsed
    } catch {
        Write-Warning "StateDatabase: Failed to parse JSON from state_db.py $Command -- $_"
        Write-StateDbLog -Level 'ERROR' -Message "JSON parse error for $Command" -Context @{ raw = $rawJson.Substring(0, [Math]::Min($rawJson.Length, 200)) }
        return $null
    }
}

# ---------------------------------------------------------------------------
# Public: Import-MembershipStateSqlite
# ---------------------------------------------------------------------------
function Import-MembershipStateSqlite {
    <#
    .SYNOPSIS
        Loads the membership state from SQLite, returning the same shape as
        Import-MembershipState (JSON backend).

    .PARAMETER DbPath
        Path to the SQLite database file.

    .PARAMETER CsvName
        The CSV leaf filename used to scope the state.

    .OUTPUTS
        Hashtable:
        @{
            Metadata   = @{ Version; FirstRun; LastRun; RunCount }
            GroupsByKey = @{ "DOMAIN|GroupName" = @{ Domain; GroupName; LastSeen; Members = @() } }
            IsFirstRun = [bool]
        }
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$DbPath,

        [Parameter(Mandatory = $true)]
        [string]$CsvName
    )

    $empty = @{
        Metadata    = @{ Version = '1.0'; FirstRun = $null; LastRun = $null; RunCount = 0 }
        GroupsByKey  = @{}
        IsFirstRun  = $true
    }

    $result = Invoke-StateDb -Command 'import-state' -Arguments @('--csv-name', $CsvName) -DbPath $DbPath

    if ($null -eq $result) {
        Write-StateDbLog -Level 'WARN' -Message "import-state returned null for $CsvName; treating as first run"
        return $empty
    }

    # Convert PSCustomObject to hashtable structure
    $resultHt = ConvertTo-HashtableDeep $result

    $meta = @{
        Version  = if ($resultHt.Metadata.Version)  { $resultHt.Metadata.Version }  else { '1.0' }
        FirstRun = if ($resultHt.Metadata.FirstRun) { $resultHt.Metadata.FirstRun } else { $null }
        LastRun  = if ($resultHt.Metadata.LastRun)  { $resultHt.Metadata.LastRun }  else { $null }
        RunCount = if ($resultHt.Metadata.RunCount) { [int]$resultHt.Metadata.RunCount } else { 0 }
    }

    $groupsByKey = @{}
    if ($resultHt.GroupsByKey -and $resultHt.GroupsByKey -is [hashtable]) {
        foreach ($key in $resultHt.GroupsByKey.Keys) {
            $g = $resultHt.GroupsByKey[$key]
            $members = @()
            if ($g.Members) {
                $members = @($g.Members | ForEach-Object {
                    @{
                        SamAccountName = if ($_.SamAccountName) { $_.SamAccountName } else { '' }
                        DisplayName    = if ($_.DisplayName)    { $_.DisplayName }    else { '' }
                        Email          = if ($_.Email)          { $_.Email }          else { '' }
                    }
                })
            }
            $groupsByKey[$key] = @{
                Domain    = $g.Domain
                GroupName = $g.GroupName
                LastSeen  = $g.LastSeen
                Members   = $members
            }
        }
    }

    $isFirstRun = if ($null -ne $resultHt.IsFirstRun) { [bool]$resultHt.IsFirstRun } else { $groupsByKey.Count -eq 0 }

    Write-StateDbLog -Level 'INFO' -Message "SQLite state loaded: $($groupsByKey.Count) group(s), run #$($meta.RunCount)" `
        -Context @{ csvName = $CsvName; groups = $groupsByKey.Count; runCount = $meta.RunCount }

    return @{
        Metadata    = $meta
        GroupsByKey  = $groupsByKey
        IsFirstRun  = $isFirstRun
    }
}

# ---------------------------------------------------------------------------
# Public: Update-MembershipStateSqlite
# ---------------------------------------------------------------------------
function Update-MembershipStateSqlite {
    <#
    .SYNOPSIS
        Diffs current enumeration against SQLite-stored state, producing change
        events and summary -- same shape as Update-MembershipState (JSON backend).

    .PARAMETER DbPath
        Path to the SQLite database file.

    .PARAMETER CsvName
        The CSV leaf filename used to scope the state.

    .PARAMETER CurrentGroupResults
        Array of current group result hashtables (each @{ Data = @{...}; Errors = @() }).

    .OUTPUTS
        Hashtable:
        @{
            NewState = @{ Metadata; GroupsByKey }
            Changes  = @( @{ Timestamp; Domain; GroupName; SamAccountName; DisplayName; Email; Action } )
            Summary  = @{ TotalAdded; TotalRemoved; GroupsChanged; GroupsTracked; GroupsSeeded; IsFirstRun }
        }
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$DbPath,

        [Parameter(Mandatory = $true)]
        [string]$CsvName,

        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [array]$CurrentGroupResults
    )

    # Serialize group results to JSON for stdin.
    # Each element is @{ Data = @{...}; Errors = @() } -- the Python side handles it.
    $inputJson = $CurrentGroupResults | ConvertTo-Json -Compress -Depth 10

    # Guard: if only a single result, ConvertTo-Json won't produce an array
    if ($CurrentGroupResults.Count -eq 1) {
        $inputJson = "[$inputJson]"
    }
    if ($CurrentGroupResults.Count -eq 0) {
        $inputJson = '[]'
    }

    $result = Invoke-StateDb -Command 'update-state' `
        -Arguments @('--csv-name', $CsvName, '--stdin') `
        -StdinJson $inputJson -DbPath $DbPath

    if ($null -eq $result) {
        Write-Warning "StateDatabase: update-state returned null for $CsvName"
        # Signal FAILURE explicitly. Do NOT report IsFirstRun = $true here: a failed
        # call is not a clean first-run seed, and callers that treat it as one would
        # silently lose change tracking. Summary.Failed lets the orchestrator warn.
        return @{
            NewState = @{ Metadata = @{ Version = '1.0' }; GroupsByKey = @{} }
            Changes  = @()
            Summary  = @{ TotalAdded = 0; TotalRemoved = 0; GroupsChanged = 0; GroupsTracked = 0; GroupsSeeded = 0; IsFirstRun = $false; Failed = $true }
        }
    }

    $resultHt = ConvertTo-HashtableDeep $result

    # Build Changes array -- each element must be a hashtable
    $changes = @()
    if ($resultHt.Changes) {
        $changes = @($resultHt.Changes | ForEach-Object {
            @{
                Timestamp      = $_.Timestamp
                Domain         = $_.Domain
                GroupName      = $_.GroupName
                SamAccountName = $_.SamAccountName
                DisplayName    = if ($_.DisplayName) { $_.DisplayName } else { '' }
                Email          = if ($_.Email)       { $_.Email }       else { '' }
                Action         = $_.Action
            }
        })
    }

    # Build Summary hashtable
    $summary = @{
        TotalAdded    = if ($resultHt.Summary.TotalAdded)    { [int]$resultHt.Summary.TotalAdded }    else { 0 }
        TotalRemoved  = if ($resultHt.Summary.TotalRemoved)  { [int]$resultHt.Summary.TotalRemoved }  else { 0 }
        GroupsChanged = if ($resultHt.Summary.GroupsChanged) { [int]$resultHt.Summary.GroupsChanged } else { 0 }
        GroupsTracked = if ($resultHt.Summary.GroupsTracked) { [int]$resultHt.Summary.GroupsTracked } else { 0 }
        GroupsSeeded  = if ($resultHt.Summary.GroupsSeeded)  { [int]$resultHt.Summary.GroupsSeeded }  else { 0 }
        IsFirstRun    = if ($null -ne $resultHt.Summary.IsFirstRun) { [bool]$resultHt.Summary.IsFirstRun } else { $false }
    }

    # Build a NewState that matches the JSON backend shape. The SQLite backend
    # already persisted state internally during update-state, but the orchestrator
    # expects NewState for subsequent Save-MembershipState calls.
    # Re-import the state to get the authoritative NewState.
    $newState = Import-MembershipStateSqlite -DbPath $DbPath -CsvName $CsvName
    $newStateOut = @{
        Metadata    = $newState.Metadata
        GroupsByKey  = $newState.GroupsByKey
    }

    Write-StateDbLog -Level 'INFO' -Message "SQLite update: +$($summary.TotalAdded) added, -$($summary.TotalRemoved) removed across $($summary.GroupsChanged) group(s); $($summary.GroupsSeeded) seeded" `
        -Context @{ csvName = $CsvName; added = $summary.TotalAdded; removed = $summary.TotalRemoved; changed = $summary.GroupsChanged; seeded = $summary.GroupsSeeded }

    return @{
        NewState = $newStateOut
        Changes  = $changes
        Summary  = $summary
    }
}

# ---------------------------------------------------------------------------
# Public: Save-MembershipStateSqlite
# ---------------------------------------------------------------------------
function Save-MembershipStateSqlite {
    <#
    .SYNOPSIS
        Saves a run's cache snapshot to SQLite (for incremental gate).

    .DESCRIPTION
        The update-state command already persists the membership state. This function
        saves the full cache snapshot (including WhenChanged, IsNested, etc.) that the
        incremental gate needs for the next run.

    .PARAMETER DbPath
        Path to the SQLite database file.

    .PARAMETER RunId
        The run ID returned by Start-EnumerationRun.

    .PARAMETER GroupResults
        Array of group result hashtables to cache.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$DbPath,

        [Parameter(Mandatory = $true)]
        [int]$RunId,

        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [array]$GroupResults
    )

    if ($GroupResults.Count -eq 0) {
        Write-StateDbLog -Level 'INFO' -Message "No group results to save as snapshot for run $RunId"
        return
    }

    $inputJson = $GroupResults | ConvertTo-Json -Compress -Depth 10
    # Guard: single-element arrays
    if ($GroupResults.Count -eq 1) {
        $inputJson = "[$inputJson]"
    }

    $result = Invoke-StateDb -Command 'save-snapshot' `
        -Arguments @('--run-id', $RunId.ToString(), '--stdin') `
        -StdinJson $inputJson -DbPath $DbPath

    if ($result) {
        $saved = if ($result.SnapshotsSaved) { $result.SnapshotsSaved } else { 0 }
        Write-StateDbLog -Level 'INFO' -Message "Cache snapshot saved: $saved group(s) for run $RunId" `
            -Context @{ runId = $RunId; saved = $saved }
    }
}

# ---------------------------------------------------------------------------
# Public: Add-ChangeLogEntriesSqlite
# ---------------------------------------------------------------------------
function Add-ChangeLogEntriesSqlite {
    <#
    .SYNOPSIS
        No-op for SQLite backend -- changelog is written by update-state.

    .DESCRIPTION
        The Python update-state command writes changelog entries directly to the
        database. This function exists only for API compatibility with the JSON
        backend's Add-ChangeLogEntries.

    .PARAMETER Changes
        Array of change events (ignored for SQLite backend).

    .PARAMETER DbPath
        Path to the SQLite database (unused, present for API symmetry).

    .OUTPUTS
        [int] Count of changes passed in, for compatibility.
    #>
    [CmdletBinding()]
    [OutputType([int])]
    param(
        [Parameter(Mandatory = $false)]
        [AllowEmptyCollection()]
        [array]$Changes,

        [Parameter(Mandatory = $false)]
        [string]$DbPath
    )

    return $(if ($Changes) { $Changes.Count } else { 0 })
}

# ---------------------------------------------------------------------------
# Public: Get-CacheFromSqlite
# ---------------------------------------------------------------------------
function Get-CacheFromSqlite {
    <#
    .SYNOPSIS
        Retrieves the latest cache snapshot from SQLite for the incremental gate.

    .DESCRIPTION
        Returns a hashtable keyed by "DOMAIN|GroupName" with the same structure
        that the orchestrator builds from JSON cache files. Each entry has a .Data
        property containing WhenChanged, IsNested, MemberCount, and Members so that
        Test-GroupUnchanged and the incremental reuse path work identically.

    .PARAMETER DbPath
        Path to the SQLite database file.

    .PARAMETER CsvName
        The CSV leaf filename used to scope the cache.

    .OUTPUTS
        Hashtable keyed by "DOMAIN|GroupName":
        @{
            "DOMAIN|GroupName" = @{
                Data = @{
                    WhenChanged  = "..."
                    IsNested     = [bool] or $null
                    MemberCount  = N
                    Members      = @(...)
                }
            }
        }
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$DbPath,

        [Parameter(Mandatory = $true)]
        [string]$CsvName
    )

    $result = Invoke-StateDb -Command 'get-cache' -Arguments @('--csv-name', $CsvName) -DbPath $DbPath

    $cacheLookup = @{}

    if ($null -eq $result) {
        Write-StateDbLog -Level 'WARN' -Message "get-cache returned null for $CsvName"
        return $cacheLookup
    }

    $resultHt = ConvertTo-HashtableDeep $result

    if (-not $resultHt.GroupCache -or $resultHt.GroupCache -isnot [hashtable]) {
        return $cacheLookup
    }

    foreach ($key in $resultHt.GroupCache.Keys) {
        $entry = $resultHt.GroupCache[$key]

        # Parse MembersJson back into an array
        $members = @()
        if ($entry.MembersJson -and $entry.MembersJson -ne '') {
            try {
                $parsed = $entry.MembersJson | ConvertFrom-Json
                if ($parsed) {
                    $members = @($parsed | ForEach-Object {
                        $m = ConvertTo-HashtableDeep $_
                        $m
                    })
                }
            } catch {
                Write-StateDbLog -Level 'WARN' -Message "Failed to parse MembersJson for $key" -Context @{ error = $_.ToString() }
            }
        }

        # Map IsNested: the Python side returns true/false/null.
        # The orchestrator checks ($cached.Data.IsNested -eq $false) so we need
        # to preserve $null vs $true vs $false accurately.
        $isNested = $null
        if ($null -ne $entry.IsNested) {
            $isNested = [bool]$entry.IsNested
        }

        # Domain/GroupName come from get-cache; fall back to splitting the
        # "DOMAIN|GroupName" key so a reused group's Data always carries its
        # identity (needed to re-save its snapshot and to label it in reports).
        $cacheDomain = $entry.Domain
        $cacheGroup  = $entry.GroupName
        if ([string]::IsNullOrEmpty([string]$cacheDomain) -or [string]::IsNullOrEmpty([string]$cacheGroup)) {
            $sepIdx = ([string]$key).IndexOf('|')
            if ($sepIdx -ge 0) {
                if ([string]::IsNullOrEmpty([string]$cacheDomain)) { $cacheDomain = ([string]$key).Substring(0, $sepIdx) }
                if ([string]::IsNullOrEmpty([string]$cacheGroup))  { $cacheGroup  = ([string]$key).Substring($sepIdx + 1) }
            }
        }

        $cacheLookup[$key] = @{
            Data = @{
                Domain      = $cacheDomain
                GroupName   = $cacheGroup
                WhenChanged = $entry.WhenChanged
                IsNested    = $isNested
                MemberCount = if ($entry.MemberCount) { [int]$entry.MemberCount } else { 0 }
                Members     = $members
            }
        }
    }

    Write-StateDbLog -Level 'INFO' -Message "SQLite cache loaded: $($cacheLookup.Count) group(s) for $CsvName" `
        -Context @{ csvName = $CsvName; groups = $cacheLookup.Count }

    return $cacheLookup
}

# ---------------------------------------------------------------------------
# Public: Test-StateDbConsistency
# ---------------------------------------------------------------------------
function Test-StateDbConsistency {
    <#
    .SYNOPSIS
        Audits the SQLite state DB for integrity / consistency (read-only).
    .DESCRIPTION
        Wraps `state_db.py validate`. Returns a hashtable with Ok (bool), Errors,
        Warnings, SchemaVersion, and Checks (one per audit: Name/Severity/Count/Detail).
        Checks: SQLite integrity, foreign-key references, blank group/member identity,
        snapshot member_count vs stored members, and reuse-basis completeness (the
        incremental-decay detector).
    .PARAMETER DbPath
        Path to the SQLite database file.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$DbPath)

    $result = Invoke-StateDb -Command 'validate' -Arguments @() -DbPath $DbPath
    if ($null -eq $result) {
        Write-StateDbLog -Level 'WARN' -Message "validate returned null for $DbPath"
        return @{ Ok = $false; Errors = 1; Warnings = 0; Checks = @(); SchemaVersion = $null }
    }
    $ht = ConvertTo-HashtableDeep $result
    # Normalize Checks to an array of hashtables for easy consumption.
    if ($ht.Checks) { $ht.Checks = @($ht.Checks) } else { $ht.Checks = @() }
    return $ht
}

# ---------------------------------------------------------------------------
# Public: Start-EnumerationRun
# ---------------------------------------------------------------------------
function Start-EnumerationRun {
    <#
    .SYNOPSIS
        Begins a new enumeration run record in SQLite.

    .PARAMETER DbPath
        Path to the SQLite database file.

    .PARAMETER CsvName
        The CSV leaf filename for this run.

    .OUTPUTS
        [int] The run ID to use with Save-MembershipStateSqlite and Complete-EnumerationRun.
    #>
    [CmdletBinding()]
    [OutputType([int])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$DbPath,

        [Parameter(Mandatory = $true)]
        [string]$CsvName
    )

    $result = Invoke-StateDb -Command 'start-run' -Arguments @('--csv-name', $CsvName) -DbPath $DbPath

    if ($null -eq $result -or $null -eq $result.RunId) {
        Write-Warning "StateDatabase: start-run failed for $CsvName; returning 0"
        return 0
    }

    $runId = [int]$result.RunId

    Write-StateDbLog -Level 'INFO' -Message "Enumeration run started: run $runId for $CsvName" `
        -Context @{ csvName = $CsvName; runId = $runId }

    return $runId
}

# ---------------------------------------------------------------------------
# Public: Complete-EnumerationRun
# ---------------------------------------------------------------------------
function Complete-EnumerationRun {
    <#
    .SYNOPSIS
        Marks an enumeration run as complete with metrics.

    .PARAMETER DbPath
        Path to the SQLite database file.

    .PARAMETER RunId
        The run ID returned by Start-EnumerationRun.

    .PARAMETER Metrics
        Hashtable of run metrics (GroupsEnumerated, GroupsSkipped, GroupsReused,
        TotalMembers, ChangesDetected).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$DbPath,

        [Parameter(Mandatory = $true)]
        [int]$RunId,

        [Parameter(Mandatory = $true)]
        [hashtable]$Metrics
    )

    $metricsJson = $Metrics | ConvertTo-Json -Compress -Depth 5

    $result = Invoke-StateDb -Command 'complete-run' `
        -Arguments @('--run-id', $RunId.ToString(), '--stdin') `
        -StdinJson $metricsJson -DbPath $DbPath

    if ($result) {
        Write-StateDbLog -Level 'INFO' -Message "Enumeration run $RunId completed" `
            -Context @{ runId = $RunId; completedAt = $result.CompletedAt }
    }
}

# ---------------------------------------------------------------------------
# Public: Import-MembershipStateAuto
# ---------------------------------------------------------------------------
function Import-MembershipStateAuto {
    <#
    .SYNOPSIS
        Backend-dispatching wrapper for Import-MembershipState / Import-MembershipStateSqlite.

    .PARAMETER Path
        JSON state file path (used when Backend is 'json').

    .PARAMETER Backend
        'json' (default) or 'sqlite'.

    .PARAMETER DbPath
        SQLite database path (used when Backend is 'sqlite').

    .PARAMETER CsvLeaf
        CSV leaf filename (used when Backend is 'sqlite').

    .OUTPUTS
        Hashtable with Metadata, GroupsByKey, IsFirstRun -- identical shape regardless of backend.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory = $false)]
        [string]$Path,

        [Parameter(Mandatory = $false)]
        [string]$Backend = 'json',

        [Parameter(Mandatory = $false)]
        [string]$DbPath,

        [Parameter(Mandatory = $false)]
        [string]$CsvLeaf
    )

    if ($Backend -eq 'sqlite') {
        return Import-MembershipStateSqlite -DbPath $DbPath -CsvName $CsvLeaf
    }
    return Import-MembershipState -Path $Path
}

# ---------------------------------------------------------------------------
# Public: Update-MembershipStateAuto
# ---------------------------------------------------------------------------
function Update-MembershipStateAuto {
    <#
    .SYNOPSIS
        Backend-dispatching wrapper for Update-MembershipState / Update-MembershipStateSqlite.

    .PARAMETER State
        Prior state hashtable (used when Backend is 'json').

    .PARAMETER CurrentGroupResults
        Array of current group result hashtables.

    .PARAMETER Backend
        'json' (default) or 'sqlite'.

    .PARAMETER DbPath
        SQLite database path (used when Backend is 'sqlite').

    .PARAMETER CsvLeaf
        CSV leaf filename (used when Backend is 'sqlite').

    .OUTPUTS
        Hashtable with NewState, Changes, Summary -- identical shape regardless of backend.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory = $false)]
        [hashtable]$State,

        [Parameter(Mandatory = $false)]
        [AllowEmptyCollection()]
        [array]$CurrentGroupResults,

        [Parameter(Mandatory = $false)]
        [string]$Backend = 'json',

        [Parameter(Mandatory = $false)]
        [string]$DbPath,

        [Parameter(Mandatory = $false)]
        [string]$CsvLeaf
    )

    if ($Backend -eq 'sqlite') {
        return Update-MembershipStateSqlite -DbPath $DbPath -CsvName $CsvLeaf -CurrentGroupResults $CurrentGroupResults
    }
    return Update-MembershipState -State $State -CurrentGroupResults $CurrentGroupResults -CsvName $CsvLeaf
}

# ---------------------------------------------------------------------------
# Public: Save-MembershipStateAuto
# ---------------------------------------------------------------------------
function Save-MembershipStateAuto {
    <#
    .SYNOPSIS
        Backend-dispatching wrapper for Save-MembershipState / Save-MembershipStateSqlite.

    .PARAMETER NewState
        New state hashtable from Update (used when Backend is 'json').

    .PARAMETER Path
        JSON state file path (used when Backend is 'json').

    .PARAMETER Backend
        'json' (default) or 'sqlite'.

    .PARAMETER DbPath
        SQLite database path (used when Backend is 'sqlite').

    .PARAMETER RunId
        Run ID from Start-EnumerationRun (used when Backend is 'sqlite').

    .PARAMETER GroupResults
        Array of group result hashtables to cache (used when Backend is 'sqlite').
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        $NewState,

        [Parameter(Mandatory = $false)]
        [string]$Path,

        [Parameter(Mandatory = $false)]
        [string]$Backend = 'json',

        [Parameter(Mandatory = $false)]
        [string]$DbPath,

        [Parameter(Mandatory = $false)]
        [int]$RunId,

        [Parameter(Mandatory = $false)]
        [AllowEmptyCollection()]
        [array]$GroupResults
    )

    if ($Backend -eq 'sqlite') {
        Save-MembershipStateSqlite -DbPath $DbPath -RunId $RunId -GroupResults $GroupResults
        return
    }
    Save-MembershipState -NewState $NewState -Path $Path
}

# ---------------------------------------------------------------------------
# Public: Add-ChangeLogEntriesAuto
# ---------------------------------------------------------------------------
function Add-ChangeLogEntriesAuto {
    <#
    .SYNOPSIS
        Backend-dispatching wrapper for Add-ChangeLogEntries / Add-ChangeLogEntriesSqlite.

    .PARAMETER Changes
        Array of change event hashtables.

    .PARAMETER Path
        JSONL changelog file path (used when Backend is 'json').

    .PARAMETER Backend
        'json' (default) or 'sqlite'.

    .PARAMETER DbPath
        SQLite database path (used when Backend is 'sqlite').

    .OUTPUTS
        [int] Number of changes written.
    #>
    [CmdletBinding()]
    [OutputType([int])]
    param(
        [Parameter(Mandatory = $false)]
        [AllowEmptyCollection()]
        [array]$Changes,

        [Parameter(Mandatory = $false)]
        [string]$Path,

        [Parameter(Mandatory = $false)]
        [string]$Backend = 'json',

        [Parameter(Mandatory = $false)]
        [string]$DbPath
    )

    if ($Backend -eq 'sqlite') {
        return Add-ChangeLogEntriesSqlite -Changes $Changes -DbPath $DbPath
    }
    return Add-ChangeLogEntries -Changes $Changes -Path $Path
}

# ---------------------------------------------------------------------------
# Public: Invoke-JsonToSqliteMigration
# ---------------------------------------------------------------------------
function Invoke-JsonToSqliteMigration {
    <#
    .SYNOPSIS
        Migrates existing JSON state files to the SQLite database.

    .DESCRIPTION
        Scans the specified directory for *-membership-state.json files and imports
        each into the SQLite database via state_db.py migrate-json. If a corresponding
        *-changelog.jsonl file exists, it is included in the migration.

    .PARAMETER DbPath
        Path to the SQLite database file.

    .PARAMETER StateDir
        Directory containing JSON state files.

    .PARAMETER CsvLeaf
        Optional: migrate only the state for a specific CSV leaf. If omitted, all
        state files in the directory are migrated.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$DbPath,

        [Parameter(Mandatory = $true)]
        [string]$StateDir,

        [Parameter(Mandatory = $false)]
        [string]$CsvLeaf
    )

    if (-not (Test-Path $StateDir)) {
        Write-Warning "StateDatabase: State directory not found: $StateDir"
        return
    }

    $stateFiles = Get-ChildItem -Path $StateDir -Filter '*-membership-state.json' -File -ErrorAction SilentlyContinue
    if (-not $stateFiles -or $stateFiles.Count -eq 0) {
        Write-Host 'No JSON state files found to migrate.' -ForegroundColor Gray
        return
    }

    $migrated = 0
    $failed   = 0

    foreach ($sf in $stateFiles) {
        # Derive csvLeaf from filename: "Groups-membership-state.json" -> "Groups"
        $derivedLeaf = $sf.BaseName -replace '-membership-state$', ''

        if ($CsvLeaf -and $derivedLeaf -ne $CsvLeaf) {
            continue
        }

        Write-Host "  Migrating: $($sf.Name) (csvLeaf=$derivedLeaf)..." -NoNewline -ForegroundColor Gray

        $migrateArgs = @('--state-file', $sf.FullName, '--csv-name', $derivedLeaf)

        # Check for corresponding changelog
        $changelogPath = Join-Path $StateDir "${derivedLeaf}-changelog.jsonl"
        if (Test-Path $changelogPath) {
            $migrateArgs += '--changelog-file'
            $migrateArgs += $changelogPath
        }

        $result = Invoke-StateDb -Command 'migrate-json' -Arguments $migrateArgs -DbPath $DbPath

        if ($result) {
            $gi = if ($result.GroupsImported)             { $result.GroupsImported }             else { 0 }
            $mi = if ($result.MembersImported)            { $result.MembersImported }            else { 0 }
            $ci = if ($result.ChangelogEntriesImported)   { $result.ChangelogEntriesImported }   else { 0 }
            Write-Host " $gi group(s), $mi member(s), $ci changelog entry(ies)" -ForegroundColor Green
            Write-StateDbLog -Level 'INFO' -Operation 'Migration' `
                -Message "Migrated $($sf.Name): $gi groups, $mi members, $ci changelog" `
                -Context @{ file = $sf.FullName; groups = $gi; members = $mi; changelog = $ci }
            $migrated++
        } else {
            Write-Host ' FAILED' -ForegroundColor Red
            Write-StateDbLog -Level 'ERROR' -Operation 'Migration' `
                -Message "Failed to migrate $($sf.Name)" -Context @{ file = $sf.FullName }
            $failed++
        }
    }

    Write-Host ''
    Write-Host "Migration complete: $migrated succeeded, $failed failed." -ForegroundColor $(if ($failed -gt 0) { 'Yellow' } else { 'Green' })
}
