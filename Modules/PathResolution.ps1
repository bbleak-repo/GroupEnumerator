<#
.SYNOPSIS
    Pure path-resolution helpers for the orchestrator (Invoke-GroupEnumerator.ps1).
.DESCRIPTION
    Extracted so the (previously inline, live-validated-only) cache/DB path logic is
    directly unit-testable. No side effects, no script-scope globals -- every input is a
    parameter and the result is returned. The orchestrator still owns directory creation.

    Uses [IO.Path]::Combine (not Join-Path) so resolution is a pure string operation that
    does NOT require the drive/dir to exist yet (Join-Path validates the drive in PS 5.1).
    Every second argument here is relative, so Combine's semantics match the previous
    Join-Path behaviour for real paths.

    Behaviour preserved exactly:
      * -OutputPath / -CachePath are DIRECTORIES for writes (a filename is built under them).
      * -CachePath is a cache FILE for -FromCache (read), or an explicit *.json write target.
      * -StatePath redirects the SQLite DB unless a USER-CUSTOMIZED SqliteDbPath is set
        (the default config always sets SqliteDbPath, so it must be special-cased).
#>

function Resolve-GeSqliteDbPath {
    <#
    .SYNOPSIS Resolve the SQLite DB path. Precedence: customized SqliteDbPath > explicit
    -StatePath > config ChangeTracking.StatePath > built-in default.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [string]$ConfigSqliteDbPath,
        [string]$StatePathParam,
        [bool]$StatePathExplicit,
        [string]$ConfigCtStatePath,
        [Parameter(Mandatory)][string]$ScriptRoot
    )
    $resolveDir = {
        param($p) if ([System.IO.Path]::IsPathRooted($p)) { $p } else { [System.IO.Path]::Combine($ScriptRoot, $p) }
    }
    $defaultDbRel   = 'State/group-enumerator.db'
    $cfgDbIsDefault = $ConfigSqliteDbPath -and (($ConfigSqliteDbPath -replace '\\', '/') -ieq $defaultDbRel)

    if ($ConfigSqliteDbPath -and -not $cfgDbIsDefault) {
        if ([System.IO.Path]::IsPathRooted($ConfigSqliteDbPath)) { return $ConfigSqliteDbPath }
        return [System.IO.Path]::Combine($ScriptRoot, $ConfigSqliteDbPath)
    }
    if ($StatePathExplicit -and $StatePathParam) {
        return [System.IO.Path]::Combine((& $resolveDir $StatePathParam), 'group-enumerator.db')
    }
    if ($ConfigCtStatePath) {
        return [System.IO.Path]::Combine((& $resolveDir $ConfigCtStatePath), 'group-enumerator.db')
    }
    return [System.IO.Path]::Combine($ScriptRoot, 'State', 'group-enumerator.db')
}

function Resolve-GeCachePaths {
    <#
    .SYNOPSIS Resolve the cache directory + the resolved cache path. Returns a hashtable
    @{ CacheDir; ResolvedCachePath; IsDir }. IsDir = -CachePath was given as a write directory.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [string]$CachePathParam,
        [bool]$FromCache,
        [string]$ConfigCachePath,
        [Parameter(Mandatory)][string]$ScriptRoot,
        [string]$JsonFileName
    )
    # -CachePath is a write DIRECTORY when: provided, not -FromCache, and it is either an
    # existing container or has no file extension. (An explicit *.json is a file.)
    $isDir = [bool]($CachePathParam -and -not $FromCache -and `
        ((Test-Path -LiteralPath $CachePathParam -PathType Container) -or -not [System.IO.Path]::GetExtension($CachePathParam)))

    $cacheDir = if ($isDir) {
        $CachePathParam
    } elseif ($ConfigCachePath) {
        if ([System.IO.Path]::IsPathRooted($ConfigCachePath)) { $ConfigCachePath } else { [System.IO.Path]::Combine($ScriptRoot, $ConfigCachePath) }
    } else {
        [System.IO.Path]::Combine($ScriptRoot, 'Cache')
    }

    $resolvedCachePath = if ($CachePathParam -and -not $isDir) {
        # explicit cache FILE path (-FromCache, or an explicit *.json write target)
        $CachePathParam
    } elseif ($JsonFileName) {
        # default OR -CachePath directory: timestamped filename under the cache dir
        [System.IO.Path]::Combine($cacheDir, $JsonFileName)
    } else {
        $cacheDir
    }

    return @{ CacheDir = $cacheDir; ResolvedCachePath = $resolvedCachePath; IsDir = $isDir }
}
