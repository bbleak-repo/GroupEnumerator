#Requires -Version 5.1
<#
.SYNOPSIS
    Launches the Group Enumerator WPF GUI.
.DESCRIPTION
    Opens a graphical interface for configuring and running group enumeration.
    Automatically spawns in an isolated STA PowerShell process for WPF compatibility.

    The GUI provides:
      - Configuration editing (LDAP, fuzzy matching, stale detection, etc.)
      - CSV file selection and parameter configuration
      - One-click enumeration runs with live progress
      - Results browsing and report access

    Requirements:
      - Windows with .NET Framework 4.5 or later (WPF)
      - PowerShell 5.1 Desktop Edition (not PowerShell Core/6+)
      - Group Enumerator modules in the Modules\ subdirectory

.PARAMETER NoIsolation
    Internal sentinel flag. Do not use directly -- the script auto-relaunches
    in an isolated STA process and passes this flag to the child.
    Advanced users debugging inside PowerShell ISE may pass it to run
    in-process, but that re-introduces WPF's once-per-AppDomain
    Application-singleton trap after the first window close.

.PARAMETER ConfigPath
    Optional path to group-enum-config.json. Defaults to
    .\Config\group-enum-config.json relative to the script directory.

.EXAMPLE
    .\Show-GroupEnumeratorGui.ps1
    # Launch the GUI with default settings

.EXAMPLE
    .\Show-GroupEnumeratorGui.ps1 -ConfigPath 'C:\Tools\Config\custom-config.json'
    # Launch the GUI pointed at a specific configuration file

.NOTES
    Script:  Show-GroupEnumeratorGui.ps1
    Version: 3.0.0
    WPF requires a Single-Threaded Apartment (STA) thread. This script
    detects the current apartment state and re-launches in STA if needed.
    No emoji in code.
#>
[CmdletBinding()]
param(
    [Parameter()]
    [switch]$NoIsolation,

    [Parameter()]
    [string]$ConfigPath
)

Set-StrictMode -Version 1
$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------------------
# Process Isolation
# ---------------------------------------------------------------------------
# WPF requires STA, AND [System.Windows.Application] is a once-per-AppDomain
# singleton for the entire life of the host process: once you close the
# window in a given PowerShell session, you cannot launch it again in that
# same session (the Application instance stays registered in a shutdown state
# and cannot be recreated).
#
# The robust fix is to always run in a brand-new child powershell.exe so
# every launch starts from a clean AppDomain regardless of whether the
# caller's shell is MTA (regular powershell.exe), STA (PowerShell ISE,
# -STA-flagged terminal), or has previously launched the GUI.
#
# The -NoIsolation switch is the recursion sentinel: parent invocations
# omit it; child invocations carry it (set automatically below) and skip
# this block to do the actual work.

if (-not $NoIsolation) {
    $scriptPath = $MyInvocation.MyCommand.Path
    if (-not $scriptPath) {
        Write-Host "ERROR: Cannot determine script path for child-process launch." -ForegroundColor Red
        exit 1
    }

    Write-Host "  INFO: Launching Group Enumerator GUI in isolated STA child process..." -ForegroundColor Cyan

    $relaunchArgs = @(
        '-STA',
        '-NoProfile',
        '-ExecutionPolicy', 'Bypass',
        '-File', "`"$scriptPath`"",
        '-NoIsolation'
    )
    if ($ConfigPath) {
        $relaunchArgs += @('-ConfigPath', "`"$ConfigPath`"")
    }

    Start-Process powershell.exe -ArgumentList $relaunchArgs -Wait -NoNewWindow
    exit $LASTEXITCODE
}

# Past this point we are the isolated child (or someone bypassed isolation
# manually). WPF still requires STA; verify and fail clearly if the caller
# passed -NoIsolation from a non-STA shell.
if ([System.Threading.Thread]::CurrentThread.ApartmentState -ne 'STA') {
    Write-Host ("ERROR: WPF requires STA apartment state. " +
                "Remove the -NoIsolation switch (recommended -- the launcher " +
                "will spawn an STA child for you), or launch powershell.exe " +
                "with -STA before re-running.") -ForegroundColor Red
    exit 1
}

# ---------------------------------------------------------------------------
# Path Resolution
# ---------------------------------------------------------------------------
$appRoot = $PSScriptRoot
if (-not $appRoot) {
    $appRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
}

# ---------------------------------------------------------------------------
# Assembly Loading
# ---------------------------------------------------------------------------
Add-Type -AssemblyName PresentationFramework
Add-Type -AssemblyName PresentationCore
Add-Type -AssemblyName WindowsBase
Add-Type -AssemblyName System.Xml

# ---------------------------------------------------------------------------
# Module Loading
# ---------------------------------------------------------------------------
Write-Host 'Loading modules...' -ForegroundColor Cyan

# Dot-source the GUI controller module (provides Initialize-GroupEnumeratorGui)
$guiControllerPath = Join-Path $appRoot 'Modules\GuiController.ps1'
if (-not (Test-Path $guiControllerPath)) {
    Write-Host "ERROR: GUI controller not found: $guiControllerPath" -ForegroundColor Red
    exit 1
}
. $guiControllerPath
Write-Host "  Loaded: GuiController.ps1" -ForegroundColor Gray

# Dot-source core modules needed for config loading, state, and data operations.
# These are required by the GUI controller for enumeration and config management.
$coreModules = @(
    @{ File = 'GroupEnumLogger.ps1';  Required = $true  },  # Logging infrastructure
    @{ File = 'GroupEnumerator.ps1';  Required = $true  },  # New-GroupEnumConfig, core enumeration
    @{ File = 'ADLdap.ps1';          Required = $true  },  # LDAP connection pool
    @{ File = 'MembershipState.ps1';  Required = $false },  # State management
    @{ File = 'MembershipDrift.ps1';  Required = $false },  # Drift comparison
    @{ File = 'StateDatabase.ps1';    Required = $false },  # SQLite dispatch
    @{ File = 'FuzzyMatcher.ps1';     Required = $false },  # Cross-domain fuzzy matching
    @{ File = 'NestedGroupResolver.ps1'; Required = $false },  # Nested group resolution
    @{ File = 'UserCorrelation.ps1';  Required = $false },  # Cross-domain user correlation
    @{ File = 'GapAnalysis.ps1';      Required = $false },  # Gap analysis
    @{ File = 'StaleAccountDetector.ps1'; Required = $false },  # Stale/disabled detection
    @{ File = 'AppMapping.ps1';       Required = $false },  # Application mapping
    @{ File = 'GroupReportGenerator.ps1'; Required = $false },  # V1 HTML report
    @{ File = 'MigrationReportGenerator.ps1'; Required = $false },  # V2 migration report
    @{ File = 'EmailSummary.ps1';     Required = $false },  # SMTP delivery
    @{ File = 'DomainUserLookup.ps1'; Required = $false },  # Domain user lookup
    @{ File = 'IncrementalGate.ps1';  Required = $false },  # Incremental enumeration
    @{ File = 'GovernanceReportGenerator.ps1'; Required = $false },  # V3 governance report
    @{ File = 'ComplianceReportGenerator.ps1'; Required = $false }   # V3 compliance report
)

foreach ($moduleDef in $coreModules) {
    $modPath = Join-Path $appRoot "Modules\$($moduleDef.File)"
    if (Test-Path $modPath) {
        . $modPath
        Write-Host "  Loaded: $($moduleDef.File)" -ForegroundColor Gray
    }
    elseif ($moduleDef.Required) {
        Write-Host "ERROR: Required module not found: $modPath" -ForegroundColor Red
        exit 1
    }
    else {
        Write-Host "  Skipped (not found): $($moduleDef.File)" -ForegroundColor DarkYellow
    }
}

# Baseline governance report generators (additive; one self-contained module each)
$baselineDir = Join-Path $appRoot 'Modules\BaselineReports'
if (Test-Path $baselineDir) {
    foreach ($bm in (Get-ChildItem $baselineDir -Filter '*.ps1' -File -ErrorAction SilentlyContinue | Sort-Object Name)) {
        . $bm.FullName
        Write-Host "  Loaded: BaselineReports\$($bm.Name)" -ForegroundColor DarkGray
    }
}

Write-Host ''

# ---------------------------------------------------------------------------
# Config Loading
# ---------------------------------------------------------------------------
$defaultConfigPath = Join-Path $appRoot 'Config\group-enum-config.json'
$effectiveConfigPath = if ($ConfigPath) { $ConfigPath } else { $defaultConfigPath }

$config = $null
if (Test-Path $effectiveConfigPath) {
    Write-Host "Loading configuration from: $effectiveConfigPath" -ForegroundColor Cyan
    $config = New-GroupEnumConfig -ConfigPath $effectiveConfigPath
}
else {
    Write-Host "WARNING: Config not found at $effectiveConfigPath, using defaults" -ForegroundColor Yellow
    $config = New-GroupEnumConfig
}

# ---------------------------------------------------------------------------
# XAML Loading
# ---------------------------------------------------------------------------
$guiDir = Join-Path $appRoot 'Gui'

# Validate Styles.xaml exists
$stylesPath = Join-Path $guiDir 'Styles.xaml'
if (-not (Test-Path $stylesPath)) {
    Write-Host "ERROR: Styles.xaml not found: $stylesPath" -ForegroundColor Red
    exit 1
}

# Validate and load MainWindow.xaml
$mainWindowPath = Join-Path $guiDir 'MainWindow.xaml'
if (-not (Test-Path $mainWindowPath)) {
    Write-Host "ERROR: MainWindow.xaml not found: $mainWindowPath" -ForegroundColor Red
    exit 1
}

Write-Host "Loading GUI from: $mainWindowPath" -ForegroundColor Cyan

try {
    # Parse MainWindow XAML
    [xml]$xaml = [System.IO.File]::ReadAllText($mainWindowPath)

    # Remove x:Class attribute if present (not needed without code-behind
    # compilation; XamlReader.Load throws if it encounters an x:Class it
    # cannot resolve to a compiled type).
    $classNode = $xaml.DocumentElement.GetAttributeNode(
        'Class',
        'http://schemas.microsoft.com/winfx/2006/xaml'
    )
    if ($classNode) {
        $xaml.DocumentElement.RemoveAttributeNode($classNode) | Out-Null
    }

    # Fix relative ResourceDictionary Source paths: XamlReader.Load() cannot
    # resolve relative URIs from a string/stream context. Replace "Styles.xaml"
    # with an absolute file URI so the resource dictionary loads correctly
    # regardless of the process working directory.
    $nsMgr = [System.Xml.XmlNamespaceManager]::new($xaml.NameTable)
    $nsMgr.AddNamespace('x', 'http://schemas.microsoft.com/winfx/2006/xaml')
    $nsMgr.AddNamespace('d', 'http://schemas.microsoft.com/winfx/2006/xaml/presentation')
    $rdNodes = $xaml.SelectNodes('//d:ResourceDictionary[@Source]', $nsMgr)
    foreach ($rdNode in $rdNodes) {
        $src = $rdNode.GetAttribute('Source')
        if ($src -and -not [System.Uri]::IsWellFormedUriString($src, [System.UriKind]::Absolute)) {
            $absolutePath = Join-Path $guiDir $src
            if (Test-Path $absolutePath) {
                $fileUri = ([System.Uri]::new($absolutePath)).AbsoluteUri
                $rdNode.SetAttribute('Source', $fileUri)
            }
        }
    }

    $reader = [System.Xml.XmlNodeReader]::new($xaml)
    $window = [System.Windows.Markup.XamlReader]::Load($reader)
}
catch {
    Write-Host "ERROR: Failed to load MainWindow XAML: $($_.Exception.Message)" -ForegroundColor Red
    if ($_.ScriptStackTrace) {
        Write-Host $_.ScriptStackTrace -ForegroundColor DarkGray
    }
    exit 1
}
finally {
    if ($reader) { $reader.Dispose() }
}

# ---------------------------------------------------------------------------
# Initialize GUI
# ---------------------------------------------------------------------------
# Initialize-GroupEnumeratorGui is provided by GuiController.ps1. It wires up
# all event handlers, populates controls from config, and prepares the window
# for display.
try {
    Initialize-GroupEnumeratorGui `
        -Window $window `
        -Config $config `
        -ConfigPath $effectiveConfigPath `
        -ScriptRoot $appRoot
}
catch {
    Write-Host "ERROR: Failed to initialize GUI: $($_.Exception.Message)" -ForegroundColor Red
    if ($_.ScriptStackTrace) {
        Write-Host $_.ScriptStackTrace -ForegroundColor DarkGray
    }
    exit 1
}

# ---------------------------------------------------------------------------
# Show Window
# ---------------------------------------------------------------------------
# Application.Run() is the proper WPF lifecycle entry point. It sets up the
# message pump and blocks until the window closes. If an Application singleton
# already exists in this AppDomain (should not happen with process isolation,
# but guard against it), fall back to ShowDialog().
try {
    # WPF allows only ONE Application per process. If the GUI was already launched in this
    # same PowerShell session, an Application already exists and Application.Run() cannot be
    # called again -- show the fresh (hidden) window modally instead. Checking Current FIRST
    # avoids the "more than one Application" throw and the "ShowDialog on a non-hidden window"
    # error that the old try/new()/catch pattern produced on a second in-session launch.
    $existingApp = [System.Windows.Application]::Current
    if ($null -eq $existingApp) {
        $app = [System.Windows.Application]::new()
        $app.Run($window) | Out-Null
    }
    elseif (-not $window.IsVisible) {
        $window.ShowDialog() | Out-Null
    }
}
catch {
    Write-Host "ERROR launching the GUI window: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "Tip: the WPF GUI can only start once per PowerShell session. If you launched it" -ForegroundColor Yellow
    Write-Host "     before in THIS window, open a NEW PowerShell window and run it again." -ForegroundColor Yellow
    exit 1
}

exit 0
