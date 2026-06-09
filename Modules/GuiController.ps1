<#
.SYNOPSIS
    WPF GUI controller for Group Enumerator v3.0.
.DESCRIPTION
    Provides Initialize-GroupEnumeratorGui and all event handling logic for the
    WPF dashboard. Dot-sourced by Show-GroupEnumeratorGui.ps1.

    This module is split into two logical sections:
    1. Foundation + Run Tab (command building, presets, execution engine)
    2. Config/Settings + Results + Enumeration/Reports tabs (added by Agent 4)
.NOTES
    Dot-sourced .ps1 file. No Export-ModuleMember.
    PowerShell 5.1 Desktop Edition required.
    No emoji in code.
    Version: 3.0.0
#>

# ---------------------------------------------------------------------------
# Script-scoped state
# ---------------------------------------------------------------------------
$script:MainWindow      = $null
$script:Config          = $null
$script:ConfigPath      = ''
$script:ScriptRoot      = ''
$script:IsRunning       = $false
$script:RunspaceInstance = $null
$script:PowerShellInstance = $null
$script:PollTimer       = $null
$script:SyncHash        = $null
$script:SuppressReportSync = $false

# ---------------------------------------------------------------------------
# Foundation Helpers
# ---------------------------------------------------------------------------

function Find-GuiControl {
    <#
    .SYNOPSIS
        Finds a named WPF control within the main window.
    .PARAMETER Name
        The x:Name of the control to find.
    .PARAMETER Window
        Optional window override. Defaults to $script:MainWindow.
    #>
    param(
        [Parameter(Mandatory)]
        [string]$Name,

        [System.Windows.Window]$Window = $script:MainWindow
    )

    if ($null -eq $Window) { return $null }
    return $Window.FindName($Name)
}

function Invoke-OnDispatcher {
    <#
    .SYNOPSIS
        Marshals an action to the WPF dispatcher for thread-safe UI updates.
    .PARAMETER Action
        ScriptBlock to invoke on the UI thread.
    #>
    param(
        [Parameter(Mandatory)]
        [scriptblock]$Action
    )

    if ($null -ne $script:MainWindow) {
        $script:MainWindow.Dispatcher.Invoke(
            [System.Action]$Action,
            [System.Windows.Threading.DispatcherPriority]::Normal
        )
    }
    else {
        & $Action
    }
}

function Set-StatusMessage {
    <#
    .SYNOPSIS
        Updates the status bar at the bottom of the main window.
    .PARAMETER Message
        Text to display.
    .PARAMETER IsError
        Display in error color (red/salmon).
    .PARAMETER IsWarning
        Display in warning color (yellow/orange).
    #>
    param(
        [Parameter(Mandatory)]
        [string]$Message,

        [switch]$IsError,
        [switch]$IsWarning
    )

    try {
        $statusBar = Find-GuiControl 'TxtStatusBar'
        if ($null -eq $statusBar) { return }

        $statusBar.Text = $Message
        if ($IsError) {
            $statusBar.Foreground = [System.Windows.Media.Brushes]::Salmon
        }
        elseif ($IsWarning) {
            $statusBar.Foreground = [System.Windows.Media.Brushes]::Orange
        }
        else {
            # Reset to theme-appropriate muted color
            $brush = $script:MainWindow.TryFindResource('BrushTextMuted')
            if ($null -ne $brush) {
                $statusBar.Foreground = $brush
            }
            else {
                $statusBar.Foreground = [System.Windows.Media.Brushes]::LightGray
            }
        }
    }
    catch {
        # Swallow -- never let status bar updates crash the GUI
    }
}

function Append-LogMessage {
    <#
    .SYNOPSIS
        Appends a timestamped message to the Output Log panel on the Run tab.
    .PARAMETER Message
        The text to append.
    .PARAMETER Color
        Reserved for future use (RichTextBox upgrade). Currently ignored.
    #>
    param(
        [Parameter(Mandatory)]
        [string]$Message,

        [string]$Color = ''
    )

    $action = {
        try {
            $txtLog = Find-GuiControl 'TxtLog'
            if ($null -eq $txtLog) { return }

            $timestamp = (Get-Date).ToString('HH:mm:ss')
            $line = "[$timestamp] $Message"

            if ($txtLog.Text.Length -gt 0) {
                $txtLog.AppendText("`r`n$line")
            }
            else {
                $txtLog.AppendText($line)
            }

            # Auto-scroll to bottom
            $txtLog.ScrollToEnd()
        }
        catch {
            # Swallow -- log display must never crash the GUI
        }
    }

    # If called from a background thread, marshal to the UI dispatcher
    if ($null -ne $script:MainWindow -and
        -not $script:MainWindow.Dispatcher.CheckAccess()) {
        Invoke-OnDispatcher -Action $action
    }
    else {
        & $action
    }
}

function Set-TabsEnabled {
    <#
    .SYNOPSIS
        Enables or disables all tabs except the Run tab (first tab).
        Used during execution to prevent config changes mid-run.
    .PARAMETER Enabled
        $true to enable tabs, $false to disable them.
    #>
    param([bool]$Enabled)

    try {
        $tabCtrl = Find-GuiControl 'MainTabControl'
        if ($null -eq $tabCtrl) { return }

        for ($i = 1; $i -lt $tabCtrl.Items.Count; $i++) {
            $tab = $tabCtrl.Items[$i]
            if ($null -ne $tab) {
                $tab.IsEnabled = $Enabled
            }
        }
    }
    catch {
        # Non-critical -- tab state is UX only
    }
}

# ---------------------------------------------------------------------------
# Command Preview + Preset Management
# ---------------------------------------------------------------------------

function Get-ComboSelectedText {
    <#
    .SYNOPSIS
        Extracts the string content from a ComboBox selection.
    .PARAMETER ControlName
        The x:Name of the ComboBox.
    #>
    param([string]$ControlName)

    $ctrl = Find-GuiControl $ControlName
    if ($null -eq $ctrl -or $null -eq $ctrl.SelectedItem) { return '' }

    $selected = $ctrl.SelectedItem
    if ($selected -is [System.Windows.Controls.ComboBoxItem]) {
        return [string]$selected.Content
    }
    return [string]$selected
}

function Format-PreviewQuoted {
    # Escape a value for display inside a double-quoted PowerShell string in the
    # command preview, so free-text (e.g. a report title) with " ` or $ stays
    # copy-paste-correct. Backtick first so we don't double-escape what we add.
    param([string]$Value)
    if ([string]::IsNullOrEmpty($Value)) { return $Value }
    return ($Value -replace '`', '``' -replace '"', '`"' -replace '\$', '`$')
}

function Update-CommandPreview {
    <#
    .SYNOPSIS
        Reads all GUI controls and builds the equivalent PowerShell command.
        Updates the TxtCommandPreview control.
    #>

    try {
        $parts = [System.Collections.Generic.List[string]]::new()
        $parts.Add('.\Invoke-GroupEnumerator.ps1')

        # CSV Path
        $csvPath = (Find-GuiControl 'TxtCsvPath').Text
        if (-not [string]::IsNullOrWhiteSpace($csvPath)) {
            $parts.Add("-CsvPath `"$(Format-PreviewQuoted $csvPath)`"")
        }

        # Switch-type checkboxes
        $switchMap = [ordered]@{
            'ChkFuzzyMatch'       = '-FuzzyMatch'
            'ChkResolveNested'    = '-ResolveNested'
            'ChkDetectStale'      = '-DetectStale'
            'ChkAnalyzeGaps'      = '-AnalyzeGaps'
            'ChkIncremental'      = '-Incremental'
            'ChkAllowInsecure'    = '-AllowInsecure'
            'ChkTrackChanges'     = '-TrackChanges'
            'ChkExportMembersCsv' = '-ExportMembersCsv'
            'ChkJsonOnly'         = '-JsonOnly'
            'ChkNoCache'          = '-NoCache'
            'ChkSendEmail'        = '-SendEmail'
            'ChkLegacy'           = '-Legacy'
            'ChkFromCache'        = '-FromCache'
        }

        foreach ($entry in $switchMap.GetEnumerator()) {
            $ctrl = Find-GuiControl $entry.Key
            if ($null -ne $ctrl -and $ctrl.IsChecked -eq $true) {
                $parts.Add($entry.Value)
            }
        }

        # Report switches
        $reportSwitches = [ordered]@{
            'ChkAllReports'         = '-AllReports'
            'ChkGovernanceReport'   = '-GovernanceReport'
            'ChkComplianceReport'   = '-ComplianceReport'
            'ChkExecutiveDashboard' = '-ExecutiveDashboard'
            'ChkLeadershipSummary'  = '-LeadershipSummary'
        }

        $allReportsCtrl = Find-GuiControl 'ChkAllReports'
        $allReportsOn   = ($null -ne $allReportsCtrl -and $allReportsCtrl.IsChecked -eq $true)

        if ($allReportsOn) {
            $parts.Add('-AllReports')
        }
        else {
            foreach ($entry in $reportSwitches.GetEnumerator()) {
                if ($entry.Key -eq 'ChkAllReports') { continue }
                $ctrl = Find-GuiControl $entry.Key
                if ($null -ne $ctrl -and $ctrl.IsChecked -eq $true) {
                    $parts.Add($entry.Value)
                }
            }
        }

        # Baseline governance reports -- master = all 10, or individual selections
        $blMap = [ordered]@{ 'ChkBlRoster' = 'roster'; 'ChkBlAccessCert' = 'access-cert'; 'ChkBlPrivileged' = 'privileged'; 'ChkBlSod' = 'sod'; 'ChkBlOrphaned' = 'orphaned'; 'ChkBlInventory' = 'inventory'; 'ChkBlEmptyStale' = 'empty-stale'; 'ChkBlNestedAudit' = 'nested-audit'; 'ChkBlExecSummary' = 'exec-summary'; 'ChkBlChangeAttest' = 'change-attestation' }
        $blMaster = Find-GuiControl 'ChkBaselineReports'
        if ($null -ne $blMaster -and $blMaster.IsChecked -eq $true) {
            $parts.Add('-BaselineReports')
        } else {
            $blKeys = @()
            foreach ($bk in $blMap.Keys) { $bc = Find-GuiControl $bk; if ($null -ne $bc -and $bc.IsChecked -eq $true) { $blKeys += $blMap[$bk] } }
            if ($blKeys.Count -gt 0) { $parts.Add("-BaselineReport $($blKeys -join ',')") }
        }

        # Composable report components -- collect checked, honour the half-width toggles
        $rcMap = [ordered]@{ 'ChkRcKpiCards' = 'kpi-cards'; 'ChkRcHeatmap' = 'heatmap'; 'ChkRcTopN' = 'top-n'; 'ChkRcTree' = 'tree'; 'ChkRcDiff' = 'diff'; 'ChkRcGroupTable' = 'group-table'; 'ChkRcRiskFlags' = 'risk-flags'; 'ChkRcPrivRisk' = 'privileged-risk' }
        $rcList = @()
        foreach ($rk in $rcMap.Keys) {
            $rc = Find-GuiControl $rk
            if ($null -ne $rc -and $rc.IsChecked -eq $true) {
                $key = $rcMap[$rk]
                $half = Find-GuiControl ($rk + 'Half')
                if ($null -ne $half -and $half.IsChecked -eq $true) { $key = "${key}:half" }
                $rcList += $key
            }
        }
        if ($rcList.Count -gt 0) {
            $parts.Add("-ReportComponents $($rcList -join ',')")
            $rcTitle = Find-GuiControl 'TxtComponentTitle'
            if ($null -ne $rcTitle -and -not [string]::IsNullOrWhiteSpace($rcTitle.Text) -and $rcTitle.Text -ne 'Composable Group Report') { $parts.Add("-ComponentReportTitle `"$(Format-PreviewQuoted $rcTitle.Text)`"") }
            $rcDark = Find-GuiControl 'ChkComponentDark'
            if ($null -ne $rcDark -and $rcDark.IsChecked -eq $true) { $parts.Add('-ComponentReportTheme dark') }
        }

        # Theme (only if non-default)
        $theme = Get-ComboSelectedText 'CmbTheme'
        if ($theme -and $theme -ne 'dark') {
            $parts.Add("-Theme `"$theme`"")
        }

        # ChangeType (only if TrackChanges is on and non-default)
        $trackCtrl = Find-GuiControl 'ChkTrackChanges'
        if ($null -ne $trackCtrl -and $trackCtrl.IsChecked -eq $true) {
            $changeType = Get-ComboSelectedText 'CmbChangeType'
            if ($changeType -and $changeType -ne 'Both') {
                $parts.Add("-ChangeType `"$changeType`"")
            }

            $cw = Get-GuiChangeWindowArg
            switch ($cw.Kind) {
                'since'  { $parts.Add("-ChangeSince `"$($cw.Value.ToString('yyyy-MM-dd'))`"") }
                'days'   { $parts.Add("-ChangeDays $($cw.Value)") }
                'period' { $parts.Add("-ChangePeriod `"$($cw.Value)`"") }
            }
        }

        # State backend (only if non-default)
        $rdoSqlite = Find-GuiControl 'RdoBackendSqlite'
        if ($null -ne $rdoSqlite -and $rdoSqlite.IsChecked -eq $true) {
            $parts.Add('-StateBackend "sqlite"')
        }

        # State path (mirror the splat builder so the preview is copy-paste accurate)
        $txtStatePathPreview = Find-GuiControl 'TxtStatePath'
        if ($null -ne $txtStatePathPreview -and -not [string]::IsNullOrWhiteSpace($txtStatePathPreview.Text)) {
            $parts.Add("-StatePath `"$(Format-PreviewQuoted $txtStatePathPreview.Text.Trim())`"")
        }

        # Config path (the splat passes $script:ConfigPath when a config was loaded)
        if (-not [string]::IsNullOrWhiteSpace($script:ConfigPath)) {
            $parts.Add("-ConfigPath `"$(Format-PreviewQuoted $script:ConfigPath)`"")
        }

        # Output path (only if non-default)
        $txtOutDir = Find-GuiControl 'TxtOutputDirectory'
        if ($null -ne $txtOutDir -and -not [string]::IsNullOrWhiteSpace($txtOutDir.Text)) {
            $outDirVal = $txtOutDir.Text.Trim()
            if ($outDirVal -ne 'Output') {
                $parts.Add("-OutputPath `"$(Format-PreviewQuoted $outDirVal)`"")
            }
        }

        # StaleDays (only if DetectStale is on and non-default 90)
        $chkStale = Find-GuiControl 'ChkDetectStale'
        if ($null -ne $chkStale -and $chkStale.IsChecked -eq $true) {
            $txtStaleDaysPreview = Find-GuiControl 'TxtStaleAccountDays'
            if ($null -ne $txtStaleDaysPreview -and -not [string]::IsNullOrWhiteSpace($txtStaleDaysPreview.Text)) {
                $sdVal = 0
                if ([int]::TryParse($txtStaleDaysPreview.Text.Trim(), [ref]$sdVal) -and $sdVal -gt 0 -and $sdVal -ne 90) {
                    $parts.Add("-StaleDays $sdVal")
                }
            }
        }

        # IncludeAttributes (manager/dept/title) -- enriches reports + lets the Org Role Map build
        # its tree from the cache (single-hop / Adhoc DC-free path).
        $chkInclAttrPrev = Find-GuiControl 'ChkIncludeManager'
        if ($null -ne $chkInclAttrPrev -and $chkInclAttrPrev.IsChecked -eq $true) {
            $parts.Add('-IncludeAttributes manager,department,title')
        }

        # CachePath: in From Cache (previous-run) mode this is the picked cache FILE; otherwise
        # it is the write directory (emitted only when non-default).
        $chkFcPrev = Find-GuiControl 'ChkFromCache'
        if ($null -ne $chkFcPrev -and $chkFcPrev.IsChecked -eq $true) {
            $prevPrev = Find-GuiControl 'TxtPrevRunCache'
            if ($null -ne $prevPrev -and -not [string]::IsNullOrWhiteSpace($prevPrev.Text)) {
                $parts.Add("-CachePath `"$(Format-PreviewQuoted $prevPrev.Text.Trim())`"")
            }
        } else {
            $txtCachePreview = Find-GuiControl 'TxtCachePath'
            if ($null -ne $txtCachePreview -and -not [string]::IsNullOrWhiteSpace($txtCachePreview.Text)) {
                $cacheVal = $txtCachePreview.Text.Trim()
                if ($cacheVal -ne 'Cache') {
                    $parts.Add("-CachePath `"$(Format-PreviewQuoted $cacheVal)`"")
                }
            }
        }

        # MigratingTo (Advanced)
        $txtMigTo = Find-GuiControl 'TxtMigratingTo'
        if ($null -ne $txtMigTo -and -not [string]::IsNullOrWhiteSpace($txtMigTo.Text)) {
            $parts.Add("-MigratingTo `"$(Format-PreviewQuoted $txtMigTo.Text.Trim())`"")
        }

        # BaselinePath (Advanced)
        $txtBasePrev = Find-GuiControl 'TxtBaselinePath'
        if ($null -ne $txtBasePrev -and -not [string]::IsNullOrWhiteSpace($txtBasePrev.Text)) {
            $parts.Add("-BaselinePath `"$(Format-PreviewQuoted $txtBasePrev.Text.Trim())`"")
        }

        # PreviousRunPath (Advanced)
        $txtPrevRunPrev = Find-GuiControl 'TxtPreviousRunPath'
        if ($null -ne $txtPrevRunPrev -and -not [string]::IsNullOrWhiteSpace($txtPrevRunPrev.Text)) {
            $parts.Add("-PreviousRunPath `"$(Format-PreviewQuoted $txtPrevRunPrev.Text.Trim())`"")
        }

        # AppMappingCsv (Advanced)
        $txtAppMapPrev = Find-GuiControl 'TxtAppMappingCsv'
        if ($null -ne $txtAppMapPrev -and -not [string]::IsNullOrWhiteSpace($txtAppMapPrev.Text)) {
            $parts.Add("-AppMappingCsv `"$(Format-PreviewQuoted $txtAppMapPrev.Text.Trim())`"")
        }

        # Credential hint (we never write the actual password to the preview)
        $txtUser = Find-GuiControl 'TxtUsername'
        if ($null -ne $txtUser -and -not [string]::IsNullOrWhiteSpace($txtUser.Text)) {
            $parts.Add('-Credential (Get-Credential)')
        }

        $preview = Find-GuiControl 'TxtCommandPreview'
        if ($null -ne $preview) {
            $preview.Text = ($parts -join ' ')
        }
    }
    catch {
        # Swallow -- preview is informational only
        $preview = Find-GuiControl 'TxtCommandPreview'
        if ($null -ne $preview) {
            $preview.Text = "# Error building command preview: $($_.Exception.Message)"
        }
    }
}

function Set-Preset {
    <#
    .SYNOPSIS
        Applies a preset configuration by toggling checkboxes.
    .PARAMETER PresetName
        One of: Basic Inventory, Nested+Stale, Cross-Domain Migration,
        Compliance Audit, Full Analysis, Custom.
    #>
    param(
        [Parameter(Mandatory)]
        [string]$PresetName
    )

    # Custom means the user has manually configured -- don't change anything
    if ($PresetName -eq 'Custom') { return }

    # Define which controls are ON for each preset
    $presetDefs = @{
        'Basic Inventory' = @{
            'ChkFuzzyMatch'         = $false
            'ChkResolveNested'      = $false
            'ChkDetectStale'        = $false
            'ChkAnalyzeGaps'        = $false
            'ChkIncremental'        = $false
            'ChkAllowInsecure'      = $false
            'ChkTrackChanges'       = $false
            'ChkGovernanceReport'   = $false
            'ChkComplianceReport'   = $false
            'ChkExecutiveDashboard' = $false
            'ChkLeadershipSummary'  = $false
            'ChkAllReports'         = $false
            'ChkExportMembersCsv'   = $false
            'ChkJsonOnly'           = $false
            'ChkNoCache'            = $false
            'ChkSendEmail'          = $false
            'ChkLegacy'             = $false
            'ChkFromCache'          = $false
        }
        'Nested+Stale' = @{
            'ChkFuzzyMatch'         = $false
            'ChkResolveNested'      = $true
            'ChkDetectStale'        = $true
            'ChkAnalyzeGaps'        = $false
            'ChkIncremental'        = $false
            'ChkAllowInsecure'      = $false
            'ChkTrackChanges'       = $false
            'ChkGovernanceReport'   = $false
            'ChkComplianceReport'   = $false
            'ChkExecutiveDashboard' = $false
            'ChkLeadershipSummary'  = $false
            'ChkAllReports'         = $false
            'ChkExportMembersCsv'   = $false
            'ChkJsonOnly'           = $false
            'ChkNoCache'            = $false
            'ChkSendEmail'          = $false
            'ChkLegacy'             = $false
            'ChkFromCache'          = $false
        }
        'Cross-Domain Migration' = @{
            'ChkFuzzyMatch'         = $true
            'ChkResolveNested'      = $true
            'ChkDetectStale'        = $true
            'ChkAnalyzeGaps'        = $true
            'ChkIncremental'        = $false
            'ChkAllowInsecure'      = $false
            'ChkTrackChanges'       = $false
            'ChkGovernanceReport'   = $false
            'ChkComplianceReport'   = $false
            'ChkExecutiveDashboard' = $false
            'ChkLeadershipSummary'  = $false
            'ChkAllReports'         = $false
            'ChkExportMembersCsv'   = $true
            'ChkJsonOnly'           = $false
            'ChkNoCache'            = $false
            'ChkSendEmail'          = $false
            'ChkLegacy'             = $false
            'ChkFromCache'          = $false
        }
        'Compliance Audit' = @{
            'ChkFuzzyMatch'         = $false
            'ChkResolveNested'      = $true
            'ChkDetectStale'        = $true
            'ChkAnalyzeGaps'        = $false
            'ChkIncremental'        = $false
            'ChkAllowInsecure'      = $false
            'ChkTrackChanges'       = $true
            'ChkGovernanceReport'   = $true
            'ChkComplianceReport'   = $true
            'ChkExecutiveDashboard' = $true
            'ChkLeadershipSummary'  = $false
            'ChkAllReports'         = $false
            'ChkExportMembersCsv'   = $false
            'ChkJsonOnly'           = $false
            'ChkNoCache'            = $false
            'ChkSendEmail'          = $false
            'ChkLegacy'             = $false
            'ChkFromCache'          = $false
        }
        'Full Analysis' = @{
            'ChkFuzzyMatch'         = $true
            'ChkResolveNested'      = $true
            'ChkDetectStale'        = $true
            'ChkAnalyzeGaps'        = $true
            'ChkIncremental'        = $false
            'ChkAllowInsecure'      = $false
            'ChkTrackChanges'       = $true
            'ChkGovernanceReport'   = $true
            'ChkComplianceReport'   = $true
            'ChkExecutiveDashboard' = $true
            'ChkLeadershipSummary'  = $true
            'ChkAllReports'         = $true
            'ChkExportMembersCsv'   = $true
            'ChkJsonOnly'           = $false
            'ChkNoCache'            = $false
            'ChkSendEmail'          = $false
            'ChkLegacy'             = $false
            'ChkFromCache'          = $false
        }
    }

    $def = $presetDefs[$PresetName]
    if ($null -eq $def) { return }

    foreach ($entry in $def.GetEnumerator()) {
        $ctrl = Find-GuiControl $entry.Key
        if ($null -ne $ctrl) {
            $ctrl.IsChecked = $entry.Value
        }
    }
}

# ---------------------------------------------------------------------------
# Run Dialog (confirmation before execution)
# ---------------------------------------------------------------------------

function Show-RunConfirmDialog {
    <#
    .SYNOPSIS
        Shows the RunDialog.xaml confirmation modal before starting enumeration.
    .PARAMETER CommandText
        The built command string to display.
    .OUTPUTS
        $true if the user confirmed, $false if cancelled.
    #>
    param(
        [Parameter(Mandatory)]
        [string]$CommandText
    )

    $xamlPath = Join-Path $script:ScriptRoot 'Gui\RunDialog.xaml'
    if (-not (Test-Path $xamlPath)) {
        # If dialog XAML is missing, proceed without confirmation
        return $true
    }

    try {
        [xml]$xaml = [System.IO.File]::ReadAllText($xamlPath)

        # Remove x:Class if present
        $classNode = $xaml.DocumentElement.GetAttributeNode(
            'Class',
            'http://schemas.microsoft.com/winfx/2006/xaml'
        )
        if ($classNode) {
            $xaml.DocumentElement.RemoveAttributeNode($classNode) | Out-Null
        }

        # Fix relative ResourceDictionary Source paths for XamlReader.Load()
        $guiDir = Join-Path $script:ScriptRoot 'Gui'
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
        $dialog = [System.Windows.Markup.XamlReader]::Load($reader)
        $reader.Dispose()

        # Set owner for centering
        if ($null -ne $script:MainWindow) {
            $dialog.Owner = $script:MainWindow
        }

        # Populate summary
        $csvPath = (Find-GuiControl 'TxtCsvPath').Text
        $csvDisplay = if ([string]::IsNullOrWhiteSpace($csvPath)) { '(none selected)' } else { $csvPath }

        # Count enabled options
        $optionNames = @(
            'ChkFuzzyMatch', 'ChkResolveNested', 'ChkDetectStale', 'ChkAnalyzeGaps', 'ChkIncludeManager',
            'ChkIncremental', 'ChkAllowInsecure', 'ChkTrackChanges',
            'ChkExportMembersCsv', 'ChkJsonOnly', 'ChkNoCache', 'ChkSendEmail', 'ChkLegacy'
        )
        $enabledCount = 0
        foreach ($name in $optionNames) {
            $ctrl = Find-GuiControl $name
            if ($null -ne $ctrl -and $ctrl.IsChecked -eq $true) { $enabledCount++ }
        }

        # Count selected reports
        $reportNames = @('ChkGovernanceReport', 'ChkComplianceReport', 'ChkExecutiveDashboard', 'ChkLeadershipSummary')
        $reportCount = 0
        foreach ($name in $reportNames) {
            $ctrl = Find-GuiControl $name
            if ($null -ne $ctrl -and $ctrl.IsChecked -eq $true) { $reportCount++ }
        }

        $summaryText = "CSV: $csvDisplay`nOptions: $enabledCount enabled`nReports: $reportCount selected"

        $txtSummary = $dialog.FindName('TxtRunSummary')
        if ($null -ne $txtSummary) {
            $txtSummary.Text = $summaryText
        }

        $txtCmd = $dialog.FindName('TxtCommandSummary')
        if ($null -ne $txtCmd) {
            $txtCmd.Text = $CommandText
        }

        # Wire buttons
        $btnConfirm = $dialog.FindName('BtnRunConfirm')
        if ($null -ne $btnConfirm) {
            $btnConfirm.Add_Click({
                $dialog.DialogResult = $true
            }.GetNewClosure())
        }

        $btnCancel = $dialog.FindName('BtnRunCancel')
        if ($null -ne $btnCancel) {
            $btnCancel.Add_Click({
                $dialog.Close()
            }.GetNewClosure())
        }

        $result = $dialog.ShowDialog()
        return ($result -eq $true)
    }
    catch {
        # On error, let the user proceed anyway
        Append-LogMessage "Warning: Could not show confirmation dialog: $($_.Exception.Message)"
        return $true
    }
}

# ---------------------------------------------------------------------------
# Execution Engine (Runspace + DispatcherTimer polling)
# ---------------------------------------------------------------------------

function Build-ParameterHash {
    <#
    .SYNOPSIS
        Reads all GUI controls and builds a parameter hashtable suitable
        for splatting to Invoke-GroupEnumerator.ps1.
    #>

    $params = @{}

    # CSV Path (mandatory)
    $csvPath = (Find-GuiControl 'TxtCsvPath').Text
    if (-not [string]::IsNullOrWhiteSpace($csvPath)) {
        $params['CsvPath'] = $csvPath
    }

    # Config path
    if (-not [string]::IsNullOrWhiteSpace($script:ConfigPath)) {
        $params['ConfigPath'] = $script:ConfigPath
    }

    # Switch parameters
    $switchMap = @{
        'ChkFuzzyMatch'       = 'FuzzyMatch'
        'ChkResolveNested'    = 'ResolveNested'
        'ChkDetectStale'      = 'DetectStale'
        'ChkAnalyzeGaps'      = 'AnalyzeGaps'
        'ChkIncremental'      = 'Incremental'
        'ChkAllowInsecure'    = 'AllowInsecure'
        'ChkTrackChanges'     = 'TrackChanges'
        'ChkExportMembersCsv' = 'ExportMembersCsv'
        'ChkJsonOnly'         = 'JsonOnly'
        'ChkNoCache'          = 'NoCache'
        'ChkSendEmail'        = 'SendEmail'
        'ChkLegacy'           = 'Legacy'
    }

    foreach ($entry in $switchMap.GetEnumerator()) {
        $ctrl = Find-GuiControl $entry.Key
        if ($null -ne $ctrl -and $ctrl.IsChecked -eq $true) {
            $params[$entry.Value] = $true
        }
    }

    # Report switches
    $allReportsCtrl = Find-GuiControl 'ChkAllReports'
    if ($null -ne $allReportsCtrl -and $allReportsCtrl.IsChecked -eq $true) {
        $params['AllReports'] = $true
    }
    else {
        $reportMap = @{
            'ChkGovernanceReport'   = 'GovernanceReport'
            'ChkComplianceReport'   = 'ComplianceReport'
            'ChkExecutiveDashboard' = 'ExecutiveDashboard'
            'ChkLeadershipSummary'  = 'LeadershipSummary'
        }
        foreach ($entry in $reportMap.GetEnumerator()) {
            $ctrl = Find-GuiControl $entry.Key
            if ($null -ne $ctrl -and $ctrl.IsChecked -eq $true) {
                $params[$entry.Value] = $true
            }
        }
    }

    # Baseline governance reports -- master = all 10, or individual selections
    $blMapP = [ordered]@{ 'ChkBlRoster' = 'roster'; 'ChkBlAccessCert' = 'access-cert'; 'ChkBlPrivileged' = 'privileged'; 'ChkBlSod' = 'sod'; 'ChkBlOrphaned' = 'orphaned'; 'ChkBlInventory' = 'inventory'; 'ChkBlEmptyStale' = 'empty-stale'; 'ChkBlNestedAudit' = 'nested-audit'; 'ChkBlExecSummary' = 'exec-summary'; 'ChkBlChangeAttest' = 'change-attestation' }
    $blMasterP = Find-GuiControl 'ChkBaselineReports'
    if ($null -ne $blMasterP -and $blMasterP.IsChecked -eq $true) {
        $params['BaselineReports'] = $true
    } else {
        $blKeysP = @()
        foreach ($bk in $blMapP.Keys) { $bc = Find-GuiControl $bk; if ($null -ne $bc -and $bc.IsChecked -eq $true) { $blKeysP += $blMapP[$bk] } }
        if ($blKeysP.Count -gt 0) { $params['BaselineReport'] = $blKeysP }
    }

    # Composable report components -- mirror the preview builder (splat is what actually runs)
    $rcMapP = [ordered]@{ 'ChkRcKpiCards' = 'kpi-cards'; 'ChkRcHeatmap' = 'heatmap'; 'ChkRcTopN' = 'top-n'; 'ChkRcTree' = 'tree'; 'ChkRcDiff' = 'diff'; 'ChkRcGroupTable' = 'group-table'; 'ChkRcRiskFlags' = 'risk-flags'; 'ChkRcPrivRisk' = 'privileged-risk' }
    $rcListP = @()
    foreach ($rk in $rcMapP.Keys) {
        $rc = Find-GuiControl $rk
        if ($null -ne $rc -and $rc.IsChecked -eq $true) {
            $key = $rcMapP[$rk]
            $half = Find-GuiControl ($rk + 'Half')
            if ($null -ne $half -and $half.IsChecked -eq $true) { $key = "${key}:half" }
            $rcListP += $key
        }
    }
    if ($rcListP.Count -gt 0) {
        $params['ReportComponents'] = $rcListP
        $rcTitleP = Find-GuiControl 'TxtComponentTitle'
        # Skip the default title so the splat matches the command preview (omitting
        # it == using the default 'Composable Group Report').
        if ($null -ne $rcTitleP -and -not [string]::IsNullOrWhiteSpace($rcTitleP.Text) -and $rcTitleP.Text -ne 'Composable Group Report') { $params['ComponentReportTitle'] = $rcTitleP.Text }
        $rcDarkP = Find-GuiControl 'ChkComponentDark'
        if ($null -ne $rcDarkP -and $rcDarkP.IsChecked -eq $true) { $params['ComponentReportTheme'] = 'dark' }
    }

    # Theme -- skip the default ('dark') so the splat matches the preview, which
    # only shows -Theme when non-default.
    $theme = Get-ComboSelectedText 'CmbTheme'
    if ($theme -and $theme -ne 'dark') {
        $params['Theme'] = $theme
    }

    # Change tracking options (only if TrackChanges is on)
    if ($params.ContainsKey('TrackChanges')) {
        $changeType = Get-ComboSelectedText 'CmbChangeType'
        if ($changeType -and $changeType -ne 'Both') {
            $params['ChangeType'] = $changeType
        }

        $cw = Get-GuiChangeWindowArg
        switch ($cw.Kind) {
            'since'  { $params['ChangeSince'] = $cw.Value }
            'days'   { $params['ChangeDays'] = $cw.Value }
            'period' { $params['ChangePeriod'] = $cw.Value }
        }
    }

    # State backend
    $rdoSqlite = Find-GuiControl 'RdoBackendSqlite'
    if ($null -ne $rdoSqlite -and $rdoSqlite.IsChecked -eq $true) {
        $params['StateBackend'] = 'sqlite'
    }

    # Output path (from Configuration tab)
    $txtOutDir = Find-GuiControl 'TxtOutputDirectory'
    if ($null -ne $txtOutDir -and -not [string]::IsNullOrWhiteSpace($txtOutDir.Text)) {
        $outDir = $txtOutDir.Text.Trim()
        if ($outDir -ne 'Output') {
            $params['OutputPath'] = $outDir
        }
    }

    # State path (from Configuration tab)
    $txtStatePath = Find-GuiControl 'TxtStatePath'
    if ($null -ne $txtStatePath -and -not [string]::IsNullOrWhiteSpace($txtStatePath.Text)) {
        $stPath = $txtStatePath.Text.Trim()
        if ($stPath -ne 'State') {
            $params['StatePath'] = $stPath
        }
    }

    # Stale days (from Configuration tab -- only if DetectStale is on and non-default)
    if ($params.ContainsKey('DetectStale')) {
        $txtStaleDays = Find-GuiControl 'TxtStaleAccountDays'
        if ($null -ne $txtStaleDays -and -not [string]::IsNullOrWhiteSpace($txtStaleDays.Text)) {
            $staleDaysVal = 0
            # Skip the default (90) so the splat matches the preview (which also
            # omits the default) -- omitting it yields identical behaviour.
            if ([int]::TryParse($txtStaleDays.Text.Trim(), [ref]$staleDaysVal) -and $staleDaysVal -gt 0 -and $staleDaysVal -ne 90) {
                $params['StaleDays'] = $staleDaysVal
            }
        }
    }

    # IncludeAttributes (manager/dept/title) -- array param; enriches reports + feeds the Org Role Map.
    $chkInclAttr = Find-GuiControl 'ChkIncludeManager'
    if ($null -ne $chkInclAttr -and $chkInclAttr.IsChecked -eq $true) {
        $params['IncludeAttributes'] = @('manager', 'department', 'title')
    }

    # FromCache (Data Source = Previous run)
    $chkFromCache = Find-GuiControl 'ChkFromCache'
    $isFc = ($null -ne $chkFromCache -and $chkFromCache.IsChecked -eq $true)
    if ($isFc) { $params['FromCache'] = $true }

    # Cache path: the picked previous-run cache FILE in From Cache mode; otherwise the write
    # directory (from the Configuration tab, only if non-default).
    if ($isFc) {
        $prevCtl = Find-GuiControl 'TxtPrevRunCache'
        if ($null -ne $prevCtl -and -not [string]::IsNullOrWhiteSpace($prevCtl.Text)) {
            $params['CachePath'] = $prevCtl.Text.Trim()
        }
    } else {
        $txtCacheDir = Find-GuiControl 'TxtCachePath'
        if ($null -ne $txtCacheDir -and -not [string]::IsNullOrWhiteSpace($txtCacheDir.Text)) {
            $cpVal = $txtCacheDir.Text.Trim()
            if ($cpVal -ne 'Cache') { $params['CachePath'] = $cpVal }
        }
    }

    # MigratingTo (Advanced section)
    $txtMigratingTo = Find-GuiControl 'TxtMigratingTo'
    if ($null -ne $txtMigratingTo -and -not [string]::IsNullOrWhiteSpace($txtMigratingTo.Text)) {
        $params['MigratingTo'] = $txtMigratingTo.Text.Trim()
    }

    # BaselinePath (Advanced section)
    $txtBaseline = Find-GuiControl 'TxtBaselinePath'
    if ($null -ne $txtBaseline -and -not [string]::IsNullOrWhiteSpace($txtBaseline.Text)) {
        $params['BaselinePath'] = $txtBaseline.Text.Trim()
    }

    # PreviousRunPath (Advanced section)
    $txtPrevRun = Find-GuiControl 'TxtPreviousRunPath'
    if ($null -ne $txtPrevRun -and -not [string]::IsNullOrWhiteSpace($txtPrevRun.Text)) {
        $params['PreviousRunPath'] = $txtPrevRun.Text.Trim()
    }

    # AppMappingCsv (Advanced section)
    $txtAppMapping = Find-GuiControl 'TxtAppMappingCsv'
    if ($null -ne $txtAppMapping -and -not [string]::IsNullOrWhiteSpace($txtAppMapping.Text)) {
        $params['AppMappingCsv'] = $txtAppMapping.Text.Trim()
    }

    # Credential
    $txtUser = Find-GuiControl 'TxtUsername'
    $pwdBox  = Find-GuiControl 'PwdPassword'
    if ($null -ne $txtUser -and
        -not [string]::IsNullOrWhiteSpace($txtUser.Text) -and
        $null -ne $pwdBox) {
        try {
            $securePass = $pwdBox.SecurePassword
            if ($null -ne $securePass -and $securePass.Length -gt 0) {
                $cred = [System.Management.Automation.PSCredential]::new(
                    $txtUser.Text,
                    $securePass
                )
                $params['Credential'] = $cred
            }
        }
        catch {
            Append-LogMessage "Warning: Could not build credential object: $($_.Exception.Message)"
        }
    }

    return $params
}

function Start-GuiEnumeration {
    <#
    .SYNOPSIS
        Validates inputs, shows the confirmation dialog, and launches
        Invoke-GroupEnumerator.ps1 in a background runspace.
    #>

    # Guard: already running
    if ($script:IsRunning) {
        Set-StatusMessage -Message 'An enumeration is already in progress.' -IsWarning
        return
    }

    # Validate inputs based on mode
    $chkFromCacheVal = Find-GuiControl 'ChkFromCache'
    $isFromCacheMode = ($null -ne $chkFromCacheVal -and $chkFromCacheVal.IsChecked -eq $true)

    $csvPath = (Find-GuiControl 'TxtCsvPath').Text

    if ($isFromCacheMode) {
        # Previous-run mode reports from a picked cache FILE (Data Source -> Previous run), not a CSV.
        $txtPrevForValidation = Find-GuiControl 'TxtPrevRunCache'
        $prevPathVal = if ($null -ne $txtPrevForValidation) { $txtPrevForValidation.Text } else { '' }
        if ([string]::IsNullOrWhiteSpace($prevPathVal)) {
            Set-StatusMessage -Message 'Select a previous run first (Data Source -> Previous run).' -IsError
            Append-LogMessage 'ERROR: Previous-run mode needs a saved cache file selected (Data Source -> Previous run -> pick a run or Browse).'
            return
        }
        if (-not (Test-Path -LiteralPath $prevPathVal)) {
            Set-StatusMessage -Message 'The selected previous-run cache file no longer exists.' -IsError
            Append-LogMessage "ERROR: previous-run cache not found: $prevPathVal"
            return
        }
    }
    else {
        # Normal mode requires CSV path
        if ([string]::IsNullOrWhiteSpace($csvPath)) {
            Set-StatusMessage -Message 'Please select a CSV file before running.' -IsError
            Append-LogMessage 'ERROR: No CSV file selected.'
            return
        }

        if (-not (Test-Path $csvPath)) {
            Set-StatusMessage -Message "CSV file not found: $csvPath" -IsError
            Append-LogMessage "ERROR: CSV file not found: $csvPath"
            return
        }
    }

    # Get command preview for the confirmation dialog
    $previewCtrl = Find-GuiControl 'TxtCommandPreview'
    $commandText = if ($null -ne $previewCtrl) { $previewCtrl.Text } else { '(unknown)' }

    # Show confirmation dialog
    $confirmed = Show-RunConfirmDialog -CommandText $commandText
    if (-not $confirmed) {
        Append-LogMessage 'Run cancelled by user.'
        return
    }

    # Build parameters
    $paramHash = Build-ParameterHash

    # Save last-run configuration for restore on next launch
    Save-LastRunState

    # Clear log
    $txtLog = Find-GuiControl 'TxtLog'
    if ($null -ne $txtLog) { $txtLog.Text = '' }

    Append-LogMessage 'Starting enumeration...'
    Append-LogMessage "CSV: $csvPath"
    Set-StatusMessage -Message 'Enumeration in progress...'

    # Update UI state
    $script:IsRunning = $true
    $btnRun    = Find-GuiControl 'BtnRun'
    $btnCancel = Find-GuiControl 'BtnCancel'
    $prgBar    = Find-GuiControl 'PrgProgress'
    $txtPct    = Find-GuiControl 'TxtProgressPercent'

    if ($null -ne $btnRun)    { $btnRun.IsEnabled = $false }
    if ($null -ne $btnCancel) { $btnCancel.Visibility = [System.Windows.Visibility]::Visible }
    if ($null -ne $prgBar) {
        $prgBar.Value = 0
        $prgBar.Visibility = [System.Windows.Visibility]::Visible
    }
    if ($null -ne $txtPct)    { $txtPct.Text = '0%' }

    # Disable non-Run tabs during execution to prevent config changes mid-run
    Set-TabsEnabled -Enabled $false

    # ---------------------------------------------------------------------------
    # Create synchronized hashtable for inter-thread communication
    # ---------------------------------------------------------------------------
    $syncHash = [hashtable]::Synchronized(@{
        Completed     = $false
        Error         = $null
        Messages      = [System.Collections.Generic.List[string]]::new()
        MessageIndex  = 0
        Progress      = 0
        StatusMessage = 'Starting...'
        OutputFiles   = @()
    })
    $script:SyncHash = $syncHash

    # ---------------------------------------------------------------------------
    # Create and launch the background runspace
    # ---------------------------------------------------------------------------
    $rs = [System.Management.Automation.Runspaces.RunspaceFactory]::CreateRunspace()
    $rs.ApartmentState = 'MTA'
    $rs.Open()

    $rs.SessionStateProxy.SetVariable('syncHash',   $syncHash)
    $rs.SessionStateProxy.SetVariable('scriptRoot', $script:ScriptRoot)
    $rs.SessionStateProxy.SetVariable('params',     $paramHash)

    $ps = [System.Management.Automation.PowerShell]::Create()
    $ps.Runspace = $rs

    $scriptBlock = {
        try {
            $syncHash.Messages.Add('Initializing modules...')

            # Dot-source all modules from the Modules directory
            $modulesDir = Join-Path $scriptRoot 'Modules'
            $moduleFiles = @(
                'GroupEnumLogger.ps1',
                'GroupEnumerator.ps1',
                'ADLdap.ps1',
                'MembershipState.ps1',
                'MembershipDrift.ps1',
                'StateDatabase.ps1',
                'FuzzyMatcher.ps1',
                'NestedGroupResolver.ps1',
                'UserCorrelation.ps1',
                'GapAnalysis.ps1',
                'StaleAccountDetector.ps1',
                'AppMapping.ps1',
                'GroupReportGenerator.ps1',
                'MigrationReportGenerator.ps1',
                'EmailSummary.ps1',
                'DomainUserLookup.ps1',
                'IncrementalGate.ps1',
                'GovernanceReportGenerator.ps1',
                'ComplianceReportGenerator.ps1'
            )

            foreach ($modFile in $moduleFiles) {
                $modPath = Join-Path $modulesDir $modFile
                if (Test-Path $modPath) {
                    . $modPath
                    $syncHash.Messages.Add("  Loaded: $modFile")
                }
            }

            $syncHash.Messages.Add('Modules loaded. Starting enumeration...')
            $syncHash.Progress = 5

            # Execute the main orchestrator script
            $mainScript = Join-Path $scriptRoot 'Invoke-GroupEnumerator.ps1'
            if (-not (Test-Path $mainScript)) {
                throw "Invoke-GroupEnumerator.ps1 not found at: $mainScript"
            }

            # Run the script using dot-sourcing with splatted parameters
            . $mainScript @params

            $syncHash.Progress = 100
            $syncHash.Messages.Add('Enumeration completed successfully.')

            # Collect output files from the output directory
            $outputDir = $null
            if ($params.ContainsKey('OutputPath')) {
                $outputDir = $params['OutputPath']
            }
            else {
                $outputDir = Join-Path $scriptRoot 'Output'
            }

            if (Test-Path $outputDir) {
                $recentFiles = Get-ChildItem -Path $outputDir -File |
                    Where-Object { $_.LastWriteTime -gt (Get-Date).AddMinutes(-5) } |
                    Sort-Object LastWriteTime -Descending |
                    Select-Object -First 20

                $fileList = @()
                foreach ($f in $recentFiles) {
                    $sizeStr = if ($f.Length -ge 1MB) {
                        '{0:N1} MB' -f ($f.Length / 1MB)
                    }
                    elseif ($f.Length -ge 1KB) {
                        '{0:N1} KB' -f ($f.Length / 1KB)
                    }
                    else {
                        "$($f.Length) B"
                    }

                    $fileType = switch -Wildcard ($f.Extension) {
                        '.html' { 'HTML Report' }
                        '.json' { 'JSON Cache'  }
                        '.csv'  { 'CSV Export'   }
                        '.jsonl' { 'Change Log'  }
                        default { 'File' }
                    }

                    $fileList += @{
                        FileName  = $f.Name
                        Type      = $fileType
                        Size      = $sizeStr
                        Generated = $f.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss')
                        FullPath  = $f.FullName
                    }
                }
                $syncHash.OutputFiles = $fileList
            }
        }
        catch {
            $syncHash.Error = $_.Exception.Message
            $syncHash.Messages.Add("ERROR: $($_.Exception.Message)")
            if ($_.ScriptStackTrace) {
                $syncHash.Messages.Add("Stack trace: $($_.ScriptStackTrace)")
            }
        }
        finally {
            $syncHash.Completed = $true
        }
    }

    $ps.AddScript($scriptBlock) | Out-Null

    $script:RunspaceInstance    = $rs
    $script:PowerShellInstance  = $ps

    $asyncResult = $ps.BeginInvoke()

    # ---------------------------------------------------------------------------
    # DispatcherTimer for polling the background runspace
    # ---------------------------------------------------------------------------
    $timer = [System.Windows.Threading.DispatcherTimer]::new()
    $timer.Interval = [System.TimeSpan]::FromMilliseconds(500)

    # 60-minute ceiling to prevent permanent lockout
    $maxWaitSeconds   = 3600
    $capturedTimer    = $timer
    $capturedPs       = $ps
    $capturedRs       = $rs
    $capturedAsync    = $asyncResult
    $capturedSync     = $syncHash
    $capturedStart    = Get-Date
    $capturedMaxWait  = $maxWaitSeconds

    $timer.Add_Tick({
        try {
            $elapsed = ((Get-Date) - $capturedStart).TotalSeconds
            $done    = $capturedPs.InvocationStateInfo.State -in @('Completed', 'Failed', 'Stopped')
            $timeout = (-not $done) -and ($elapsed -gt $capturedMaxWait)

            # Drain new messages from the sync hash
            $msgCount = $capturedSync.Messages.Count
            while ($capturedSync.MessageIndex -lt $msgCount) {
                $msg = $capturedSync.Messages[$capturedSync.MessageIndex]
                $capturedSync.MessageIndex++
                Append-LogMessage $msg
            }

            # Update progress bar and elapsed time
            $prgBar = Find-GuiControl 'PrgProgress'
            $txtPct = Find-GuiControl 'TxtProgressPercent'
            if ($null -ne $prgBar) {
                $prgBar.Value = $capturedSync.Progress
            }
            if ($null -ne $txtPct) {
                $elapsedSpan = (Get-Date) - $capturedStart
                $elapsedStr = ''
                if ($elapsedSpan.TotalMinutes -ge 1) {
                    $elapsedStr = '{0}m {1}s' -f [int][System.Math]::Floor($elapsedSpan.TotalMinutes), $elapsedSpan.Seconds
                }
                else {
                    $elapsedStr = '{0}s' -f [int][System.Math]::Floor($elapsedSpan.TotalSeconds)
                }
                $txtPct.Text = "$($capturedSync.Progress)% ($elapsedStr)"
            }

            if (-not ($done -or $timeout)) { return }

            # --- Run is finished or timed out ---
            $capturedTimer.Stop()

            try {
                if ($timeout) {
                    # Request the abort WITHOUT the synchronous Stop(), which would
                    # block the UI dispatcher until the pipeline winds down. BeginStop
                    # returns immediately; the guarded EndInvoke in cleanup below reaps
                    # the stopped pipeline. Fall back to Stop() if BeginStop is unavailable.
                    try { $capturedPs.BeginStop($null, $null) | Out-Null } catch { try { $capturedPs.Stop() } catch { } }
                    Append-LogMessage "ERROR: Enumeration aborted -- exceeded $capturedMaxWait second ceiling."
                    Set-StatusMessage -Message 'Enumeration aborted (timeout).' -IsError
                }
                elseif ($capturedSync.Error) {
                    Append-LogMessage "ERROR: $($capturedSync.Error)"
                    Set-StatusMessage -Message "Enumeration failed: $($capturedSync.Error)" -IsError
                }
                elseif ($capturedPs.HadErrors) {
                    $errMsg = ($capturedPs.Streams.Error | Select-Object -First 1).Exception.Message
                    Append-LogMessage "ERROR: $errMsg"
                    Set-StatusMessage -Message "Enumeration completed with errors." -IsWarning
                }
                else {
                    # Build completion summary with duration and file count
                    $durationSpan = (Get-Date) - $capturedStart
                    $durationStr = ''
                    if ($durationSpan.TotalMinutes -ge 1) {
                        $durationStr = '{0:N1} minutes' -f $durationSpan.TotalMinutes
                    }
                    else {
                        $durationStr = '{0} seconds' -f [int][System.Math]::Floor($durationSpan.TotalSeconds)
                    }
                    $fileCount = 0
                    if ($null -ne $capturedSync.OutputFiles) {
                        $fileCount = @($capturedSync.OutputFiles).Count
                    }
                    $summaryMsg = "Completed in $durationStr. Generated $fileCount file(s)."
                    Set-StatusMessage -Message $summaryMsg
                    Append-LogMessage $summaryMsg
                }

                # Drain any remaining messages
                $finalCount = $capturedSync.Messages.Count
                while ($capturedSync.MessageIndex -lt $finalCount) {
                    $msg = $capturedSync.Messages[$capturedSync.MessageIndex]
                    $capturedSync.MessageIndex++
                    Append-LogMessage $msg
                }

                # Update progress to 100%
                $prgBarFinal = Find-GuiControl 'PrgProgress'
                $txtPctFinal = Find-GuiControl 'TxtProgressPercent'
                if ($null -ne $prgBarFinal) { $prgBarFinal.Value = 100 }
                if ($null -ne $txtPctFinal) { $txtPctFinal.Text = '100%' }

                # Notify results tab and auto-switch to it
                if (Get-Command Update-ResultsGrid -ErrorAction SilentlyContinue) {
                    try { Update-ResultsGrid -OutputFiles $capturedSync.OutputFiles } catch { }
                }
                # Auto-switch to Results tab on successful completion
                if (-not $timeout -and -not $capturedSync.Error) {
                    try {
                        $tabCtrl = Find-GuiControl 'MainTabControl'
                        if ($null -ne $tabCtrl) {
                            # Find the Results tab (index 4, zero-based)
                            foreach ($tab in $tabCtrl.Items) {
                                if ($tab.Header -eq 'Results') {
                                    $tabCtrl.SelectedItem = $tab
                                    break
                                }
                            }
                        }
                    }
                    catch { }
                }

                # Cleanup runspace. Always EndInvoke the async result before Dispose
                # -- including the timeout path, where the pipeline was stopped and
                # EndInvoke throws PipelineStoppedException (swallowed). Disposing
                # without ending the invocation can leak the async wait handle.
                try {
                    try { $capturedPs.EndInvoke($capturedAsync) | Out-Null } catch { }
                    $capturedPs.Dispose()
                    $capturedRs.Close()
                    $capturedRs.Dispose()   # Close() alone leaks the runspace thread/handles
                }
                catch { }
            }
            finally {
                $script:IsRunning          = $false
                $script:RunspaceInstance    = $null
                $script:PowerShellInstance  = $null
                $script:PollTimer          = $null
                $script:SyncHash           = $null

                # Restore UI state
                $btnRun    = Find-GuiControl 'BtnRun'
                $btnCancel = Find-GuiControl 'BtnCancel'
                if ($null -ne $btnRun)    { $btnRun.IsEnabled = $true }
                if ($null -ne $btnCancel) { $btnCancel.Visibility = [System.Windows.Visibility]::Collapsed }

                # Re-enable tabs
                Set-TabsEnabled -Enabled $true
            }
        }
        catch {
            # Last-resort error handler for the timer tick
            try {
                $capturedTimer.Stop()
                Set-StatusMessage -Message "Internal error in progress monitor: $($_.Exception.Message)" -IsError
                Append-LogMessage "INTERNAL ERROR: $($_.Exception.Message)"
            } catch { }

            $script:IsRunning          = $false
            $script:RunspaceInstance    = $null
            $script:PowerShellInstance  = $null
            $script:PollTimer          = $null

            $btnRun    = Find-GuiControl 'BtnRun'
            $btnCancel = Find-GuiControl 'BtnCancel'
            if ($null -ne $btnRun)    { $btnRun.IsEnabled = $true }
            if ($null -ne $btnCancel) { $btnCancel.Visibility = [System.Windows.Visibility]::Collapsed }
            Set-TabsEnabled -Enabled $true
        }
    }.GetNewClosure())

    $script:PollTimer = $timer
    $timer.Start()
}

function Stop-GuiEnumeration {
    <#
    .SYNOPSIS
        Cancels a running enumeration by stopping the background runspace.
    #>

    if (-not $script:IsRunning) {
        Set-StatusMessage -Message 'No enumeration is currently running.' -IsWarning
        return
    }

    Append-LogMessage 'Cancellation requested by user...'
    Set-StatusMessage -Message 'Cancelling enumeration...'

    try {
        # Stop the poll timer first
        if ($null -ne $script:PollTimer) {
            $script:PollTimer.Stop()
        }

        # Stop the PowerShell instance (interrupts the running script)
        if ($null -ne $script:PowerShellInstance) {
            try { $script:PowerShellInstance.Stop() } catch { }
        }

        # Cleanup runspace
        if ($null -ne $script:PowerShellInstance) {
            try { $script:PowerShellInstance.Dispose() } catch { }
        }
        if ($null -ne $script:RunspaceInstance) {
            try { $script:RunspaceInstance.Close(); $script:RunspaceInstance.Dispose() } catch { }
        }
    }
    catch {
        Append-LogMessage "Warning: Error during cancellation cleanup: $($_.Exception.Message)"
    }
    finally {
        $script:IsRunning          = $false
        $script:RunspaceInstance    = $null
        $script:PowerShellInstance  = $null
        $script:PollTimer          = $null
        $script:SyncHash           = $null

        # Restore UI state
        $btnRun    = Find-GuiControl 'BtnRun'
        $btnCancel = Find-GuiControl 'BtnCancel'
        $prgBar    = Find-GuiControl 'PrgProgress'
        $txtPct    = Find-GuiControl 'TxtProgressPercent'

        if ($null -ne $btnRun)    { $btnRun.IsEnabled = $true }
        if ($null -ne $btnCancel) { $btnCancel.Visibility = [System.Windows.Visibility]::Collapsed }
        if ($null -ne $prgBar)    { $prgBar.Visibility = [System.Windows.Visibility]::Collapsed }
        if ($null -ne $txtPct)    { $txtPct.Text = '' }

        # Re-enable tabs
        Set-TabsEnabled -Enabled $true

        Set-StatusMessage -Message 'Enumeration cancelled.'
        Append-LogMessage 'Enumeration cancelled.'
    }
}

# ---------------------------------------------------------------------------
# Config-to-GUI population
# ---------------------------------------------------------------------------

function Initialize-FromConfig {
    <#
    .SYNOPSIS
        Populates GUI controls from the loaded $script:Config hashtable.
        Called once during Initialize-GroupEnumeratorGui.
    #>

    if ($null -eq $script:Config) { return }

    try {
        $cfg = $script:Config

        # --- Theme ---
        $cmbTheme = Find-GuiControl 'CmbTheme'
        if ($null -ne $cmbTheme -and $cfg.ContainsKey('DefaultTheme')) {
            Select-ComboItemByContent -ComboBox $cmbTheme -Content $cfg.DefaultTheme
        }

        # --- LDAP Connection ---
        Set-TextFromConfig 'TxtLdapPageSize'         'LdapPageSize'
        Set-TextFromConfig 'TxtLdapTimeout'          'LdapTimeout'
        Set-TextFromConfig 'TxtMaxMemberCount'       'MaxMemberCount'
        Set-TextFromConfig 'TxtLargeGroupThreshold'  'LargeGroupThreshold'

        # --- Skip Groups ---
        if ($cfg.ContainsKey('SkipGroups') -and $null -ne $cfg.SkipGroups) {
            $txtSkip = Find-GuiControl 'TxtSkipGroups'
            if ($null -ne $txtSkip) {
                $txtSkip.Text = ($cfg.SkipGroups -join ', ')
            }
        }

        # --- Fuzzy ---
        if ($cfg.ContainsKey('FuzzyPrefixes') -and $null -ne $cfg.FuzzyPrefixes) {
            $txtPrefixes = Find-GuiControl 'TxtFuzzyPrefixes'
            if ($null -ne $txtPrefixes) {
                $txtPrefixes.Text = ($cfg.FuzzyPrefixes -join ', ')
            }
        }
        Set-TextFromConfig 'TxtFuzzyMinScore' 'FuzzyMinScore'

        # --- Stale ---
        Set-TextFromConfig 'TxtStaleAccountDays' 'StaleAccountDays'

        # --- Correlation ---
        $cmbCorr = Find-GuiControl 'CmbCorrelationStrategy'
        if ($null -ne $cmbCorr -and $cfg.ContainsKey('CorrelationStrategy')) {
            Select-ComboItemByContent -ComboBox $cmbCorr -Content $cfg.CorrelationStrategy
        }

        # --- Logging ---
        if ($cfg.ContainsKey('LogEnabled')) {
            $chkLog = Find-GuiControl 'ChkLogEnabled'
            if ($null -ne $chkLog) { $chkLog.IsChecked = [bool]$cfg.LogEnabled }
        }

        $cmbLogLevel = Find-GuiControl 'CmbLogLevel'
        if ($null -ne $cmbLogLevel -and $cfg.ContainsKey('LogLevel')) {
            Select-ComboItemByContent -ComboBox $cmbLogLevel -Content $cfg.LogLevel
        }

        Set-TextFromConfig 'TxtLogPath' 'LogPath'

        # --- State Backend ---
        if ($cfg.ContainsKey('StateBackend')) {
            $backend = $cfg.StateBackend
            $rdoJson   = Find-GuiControl 'RdoBackendJson'
            $rdoSqlite = Find-GuiControl 'RdoBackendSqlite'
            if ($backend -eq 'sqlite') {
                if ($null -ne $rdoSqlite) { $rdoSqlite.IsChecked = $true }
            }
            else {
                if ($null -ne $rdoJson) { $rdoJson.IsChecked = $true }
            }
        }

        Set-TextFromConfig 'TxtSqliteDbPath' 'SqliteDbPath'

        # --- Change Tracking ---
        if ($cfg.ContainsKey('ChangeTracking')) {
            $ct = $cfg.ChangeTracking

            if ($ct.ContainsKey('UnifiedState')) {
                $chkUnified = Find-GuiControl 'ChkUnifiedState'
                if ($null -ne $chkUnified) { $chkUnified.IsChecked = [bool]$ct.UnifiedState }
            }

            if ($ct.ContainsKey('DefaultChangeType')) {
                $cmbChange = Find-GuiControl 'CmbChangeType'
                if ($null -ne $cmbChange) {
                    Select-ComboItemByContent -ComboBox $cmbChange -Content $ct.DefaultChangeType
                }
            }

            Set-TextFromConfigNested 'TxtMaxChangeLogSizeMB' $ct 'MaxChangeLogSizeMB'
            Set-TextFromConfigNested 'TxtRetentionDays'       $ct 'RetentionDays'

            if ($ct.ContainsKey('StatePath')) {
                $txtState = Find-GuiControl 'TxtStatePath'
                if ($null -ne $txtState) { $txtState.Text = [string]$ct.StatePath }
            }
        }

        # --- Incremental ---
        if ($cfg.ContainsKey('Enumeration')) {
            $enumCfg = $cfg.Enumeration
            if ($enumCfg.ContainsKey('Incremental') -and $enumCfg.Incremental) {
                $chkInc = Find-GuiControl 'ChkIncremental'
                if ($null -ne $chkInc) { $chkInc.IsChecked = $true }
            }
        }

        # --- Nested Groups ---
        Set-TextFromConfig 'TxtNestedGroupMaxDepth' 'NestedGroupMaxDepth'

        # --- Paths ---
        Set-TextFromConfig 'TxtOutputDirectory' 'OutputDirectory'
        Set-TextFromConfig 'TxtCachePath'        'CachePath'

        # --- App Mapping ---
        Set-TextFromConfig 'TxtAppMappingCsv' 'AppMappingCsvPath'

        # --- Email ---
        if ($cfg.ContainsKey('Email')) {
            $em = $cfg.Email
            # Defensive: convert PSCustomObject to hashtable if needed
            if ($em -is [System.Management.Automation.PSCustomObject]) {
                $em = ConvertTo-Hashtable -InputObject $em
            }

            # Map Email.Enabled -> ChkSendEmail
            if ($em.ContainsKey('Enabled')) {
                $chkSend = Find-GuiControl 'ChkSendEmail'
                if ($null -ne $chkSend) { $chkSend.IsChecked = [bool]$em.Enabled }
            }

            Set-TextFromConfigNested 'TxtSmtpServer'        $em 'SmtpServer'
            Set-TextFromConfigNested 'TxtSmtpPort'          $em 'SmtpPort'
            Set-TextFromConfigNested 'TxtSmtpFrom'          $em 'From'

            if ($em.ContainsKey('To') -and $null -ne $em.To) {
                $txtTo = Find-GuiControl 'TxtSmtpTo'
                if ($null -ne $txtTo) {
                    $txtTo.Text = if ($em.To -is [array]) { $em.To -join ', ' } else { [string]$em.To }
                }
            }
            if ($em.ContainsKey('Cc') -and $null -ne $em.Cc) {
                $txtCc = Find-GuiControl 'TxtSmtpCc'
                if ($null -ne $txtCc) {
                    $txtCc.Text = if ($em.Cc -is [array]) { $em.Cc -join ', ' } else { [string]$em.Cc }
                }
            }

            Set-TextFromConfigNested 'TxtSmtpSubjectPrefix' $em 'SubjectPrefix'

            if ($em.ContainsKey('UseSsl')) {
                $chkSsl = Find-GuiControl 'ChkSmtpUseSsl'
                if ($null -ne $chkSsl) { $chkSsl.IsChecked = [bool]$em.UseSsl }
            }
            if ($em.ContainsKey('AttachReport')) {
                $chkAttach = Find-GuiControl 'ChkSmtpAttachReport'
                if ($null -ne $chkAttach) { $chkAttach.IsChecked = [bool]$em.AttachReport }
            }
        }

        # --- Reporting ---
        if ($cfg.ContainsKey('Reporting')) {
            $rpt = $cfg.Reporting
            $reportCheckboxMap = @{
                'GovernanceReport'   = 'ChkGovernanceReport'
                'ComplianceReport'   = 'ChkComplianceReport'
                'ExecutiveDashboard' = 'ChkExecutiveDashboard'
                'LeadershipSummary'  = 'ChkLeadershipSummary'
            }
            foreach ($entry in $reportCheckboxMap.GetEnumerator()) {
                if ($rpt.ContainsKey($entry.Key)) {
                    $ctrl = Find-GuiControl $entry.Value
                    if ($null -ne $ctrl) { $ctrl.IsChecked = [bool]$rpt[$entry.Key] }
                }
            }
        }
    }
    catch {
        Append-LogMessage "Warning: Could not fully populate GUI from config: $($_.Exception.Message)"
    }
}

function Set-TextFromConfig {
    <#
    .SYNOPSIS
        Sets a TextBox value from a top-level config key.
    #>
    param([string]$ControlName, [string]$ConfigKey)

    if ($null -eq $script:Config) { return }
    if (-not $script:Config.ContainsKey($ConfigKey)) { return }

    $ctrl = Find-GuiControl $ControlName
    if ($null -ne $ctrl) {
        $val = $script:Config[$ConfigKey]
        $ctrl.Text = if ($null -ne $val) { [string]$val } else { '' }
    }
}

function Set-TextFromConfigNested {
    <#
    .SYNOPSIS
        Sets a TextBox value from a nested config hashtable key.
    #>
    param([string]$ControlName, [hashtable]$Nested, [string]$Key)

    if ($null -eq $Nested) { return }
    if (-not $Nested.ContainsKey($Key)) { return }

    $ctrl = Find-GuiControl $ControlName
    if ($null -ne $ctrl) {
        $val = $Nested[$Key]
        $ctrl.Text = if ($null -ne $val) { [string]$val } else { '' }
    }
}

function Select-ComboItemByContent {
    <#
    .SYNOPSIS
        Selects a ComboBox item by matching its Content property.
    #>
    param(
        [System.Windows.Controls.ComboBox]$ComboBox,
        [string]$Content
    )

    if ($null -eq $ComboBox -or [string]::IsNullOrWhiteSpace($Content)) { return }

    foreach ($item in $ComboBox.Items) {
        $itemContent = if ($item -is [System.Windows.Controls.ComboBoxItem]) {
            [string]$item.Content
        }
        else {
            [string]$item
        }

        if ($itemContent -eq $Content) {
            $ComboBox.SelectedItem = $item
            return
        }
    }
}

# ---------------------------------------------------------------------------
# Data Source (Live AD vs Previous run) helpers
# ---------------------------------------------------------------------------

function Get-GuiCacheDir {
    # Resolve the cache DIRECTORY to list previous runs from: the Configuration cache path if
    # it is a directory, else the default Cache folder under the script root.
    $dir = $null
    $ctl = Find-GuiControl 'TxtCachePath'
    if ($null -ne $ctl -and -not [string]::IsNullOrWhiteSpace($ctl.Text)) {
        $v = $ctl.Text.Trim()
        if ($v -and $v -ne 'Cache' -and -not [System.IO.Path]::GetExtension($v)) {
            $dir = if ([System.IO.Path]::IsPathRooted($v)) { $v } else { Join-Path $script:ScriptRoot $v }
        }
    }
    if (-not $dir) { $dir = Join-Path $script:ScriptRoot 'Cache' }
    return $dir
}

function Update-PrevRunCombo {
    # Populate the previous-run picker from the cache directory (newest first). Keeps a
    # filename -> full-path map so the (short) combo labels resolve to real files.
    $cmb = Find-GuiControl 'CmbPrevRun'
    if ($null -eq $cmb) { return }
    $cmb.Items.Clear()
    $script:PrevRunMap = @{}
    $dir = Get-GuiCacheDir
    if (Test-Path -LiteralPath $dir) {
        $files = @(Get-ChildItem -LiteralPath $dir -Filter '*.json' -File -ErrorAction SilentlyContinue |
            Sort-Object LastWriteTime -Descending)
        foreach ($f in $files) {
            $label = ('{0}   ({1})' -f $f.Name, $f.LastWriteTime.ToString('yyyy-MM-dd HH:mm'))
            $script:PrevRunMap[$label] = $f.FullName
            [void]$cmb.Items.Add($label)
        }
    }
    if ($cmb.Items.Count -gt 0) { $cmb.SelectedIndex = 0 } # newest
}

function Set-PrevRunFromCombo {
    # Reflect the combo selection into TxtPrevRunCache (the value the command builder reads).
    $cmb = Find-GuiControl 'CmbPrevRun'
    $txt = Find-GuiControl 'TxtPrevRunCache'
    if ($null -eq $cmb -or $null -eq $txt) { return }
    $sel = [string]$cmb.SelectedItem
    if ($sel -and $script:PrevRunMap -and $script:PrevRunMap.ContainsKey($sel)) {
        $txt.Text = $script:PrevRunMap[$sel]
    }
}

function Set-DataSourceMode {
    # Toggle between Live AD and Previous run. Drives the existing ChkFromCache flag (which the
    # command builder + validation already honour) and enables/populates the run picker.
    $rdoCache = Find-GuiControl 'RdoSrcCache'
    $isCache  = ($null -ne $rdoCache -and $rdoCache.IsChecked -eq $true)
    $chkFc = Find-GuiControl 'ChkFromCache'
    if ($null -ne $chkFc) { $chkFc.IsChecked = $isCache }
    $grd = Find-GuiControl 'GrdPrevRun'
    if ($null -ne $grd) { $grd.IsEnabled = $isCache }
    if ($isCache) {
        Update-PrevRunCombo
        Set-PrevRunFromCombo
    } else {
        $txt = Find-GuiControl 'TxtPrevRunCache'
        if ($null -ne $txt) { $txt.Text = '' }
    }
    Update-CommandPreview
}

function Get-GuiChangeWindowArg {
    # Resolve the change-history window selection into one of:
    #   @{ Kind='period'; Value=<preset> } | @{ Kind='days'; Value=<int> } |
    #   @{ Kind='since'; Value=<datetime> } | @{ Kind='none' }
    # 'Custom' in the period combo activates the days field / Since date picker
    # (explicit date wins over days). Shared by the command preview + Build-ParameterHash.
    $period = Get-ComboSelectedText 'CmbChangePeriod'
    if ($period -eq 'Custom') {
        $dp = Find-GuiControl 'DpChangeSince'
        if ($null -ne $dp -and $null -ne $dp.SelectedDate) {
            return @{ Kind = 'since'; Value = [datetime]$dp.SelectedDate }
        }
        $daysCtl = Find-GuiControl 'TxtChangeDays'
        $n = 0
        if ($null -ne $daysCtl) { [void][int]::TryParse([string]$daysCtl.Text, [ref]$n) }
        if ($n -gt 0) { return @{ Kind = 'days'; Value = $n } }
        return @{ Kind = 'none'; Value = $null }
    }
    if ($period -and $period -ne '(none)') { return @{ Kind = 'period'; Value = $period } }
    return @{ Kind = 'none'; Value = $null }
}

function Update-ChangeCustomEnabled {
    # Enable the custom days / date-picker row only when the period combo = Custom.
    $isCustom = ((Get-ComboSelectedText 'CmbChangePeriod') -eq 'Custom')
    $grd = Find-GuiControl 'GrdChangeCustom'
    if ($null -ne $grd) { $grd.IsEnabled = $isCustom }
}

function Invoke-ReportsFromSavedData {
    # One-click (Reports tab): switch to saved-data mode (latest cache) and run the selected
    # reports offline -- equivalent to Run tab -> Data Source = Use saved data -> Run.
    $rdoCache = Find-GuiControl 'RdoSrcCache'
    if ($null -ne $rdoCache) { $rdoCache.IsChecked = $true }
    Set-DataSourceMode   # FromCache on + newest run auto-selected
    $prev = Find-GuiControl 'TxtPrevRunCache'
    if ($null -eq $prev -or [string]::IsNullOrWhiteSpace($prev.Text)) {
        Set-StatusMessage -Message 'No saved run found. Run an enumeration first (it writes a cache), then try again.' -IsWarning
        Append-LogMessage 'INFO: "Generate Reports from Saved Data" found no cache in the cache folder.'
        return
    }
    Start-GuiEnumeration
}

# ---------------------------------------------------------------------------
# Main Entry Point
# ---------------------------------------------------------------------------

function Initialize-GroupEnumeratorGui {
    <#
    .SYNOPSIS
        Main entry point called by Show-GroupEnumeratorGui.ps1.
        Stores references, wires all Run tab events, populates controls
        from config, and prepares the window for display.
    .PARAMETER Window
        The loaded WPF Window object.
    .PARAMETER Config
        The parsed configuration hashtable from New-GroupEnumConfig.
    .PARAMETER ConfigPath
        The file path to group-enum-config.json.
    .PARAMETER ScriptRoot
        The root directory of the Group Enumerator tool.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [System.Windows.Window]$Window,

        [Parameter(Mandatory)]
        [hashtable]$Config,

        [Parameter(Mandatory)]
        [string]$ConfigPath,

        [Parameter(Mandatory)]
        [string]$ScriptRoot
    )

    # Store references in script scope
    $script:MainWindow = $Window
    $script:Config     = $Config
    $script:ConfigPath = $ConfigPath
    $script:ScriptRoot = $ScriptRoot

    # ---- Wire Tab Switch (auto-refresh Results when switching to that tab) ----
    $tabCtrl = Find-GuiControl 'MainTabControl'
    if ($null -ne $tabCtrl) {
        $tabCtrl.Add_SelectionChanged({
            param($sender, $e)
            try {
                $tc = Find-GuiControl 'MainTabControl'
                if ($null -eq $tc) { return }
                $selectedTab = $tc.SelectedItem
                if ($null -ne $selectedTab -and $selectedTab.Header -eq 'Results') {
                    if (Get-Command Refresh-ResultsGrid -ErrorAction SilentlyContinue) {
                        Refresh-ResultsGrid
                    }
                }
            }
            catch { }
        }.GetNewClosure())
    }

    # ---- Wire Close Button ----
    $btnClose = Find-GuiControl 'BtnCloseApp'
    if ($null -ne $btnClose) {
        $btnClose.Add_Click({
            if ($script:IsRunning) {
                $result = [System.Windows.MessageBox]::Show(
                    'An enumeration is currently running. Are you sure you want to close?',
                    'Confirm Close',
                    [System.Windows.MessageBoxButton]::YesNo,
                    [System.Windows.MessageBoxImage]::Warning
                )
                if ($result -ne [System.Windows.MessageBoxResult]::Yes) { return }
                Stop-GuiEnumeration
            }
            $script:MainWindow.Close()
        }.GetNewClosure())
    }

    # ---- Wire Window Closing (OS titlebar X, Alt+F4) ----
    # Ensures background runspace is cleaned up even if user bypasses BtnCloseApp
    $Window.Add_Closing({
        param($sender, $e)
        if ($script:IsRunning) {
            $result = [System.Windows.MessageBox]::Show(
                'An enumeration is currently running. Are you sure you want to close?',
                'Confirm Close',
                [System.Windows.MessageBoxButton]::YesNo,
                [System.Windows.MessageBoxImage]::Warning
            )
            if ($result -ne [System.Windows.MessageBoxResult]::Yes) {
                $e.Cancel = $true
                return
            }
            Stop-GuiEnumeration
        }
    }.GetNewClosure())

    # ---- Wire Run Tab Events ----

    # Browse button -> file dialog
    $btnBrowse = Find-GuiControl 'BtnBrowseCsv'
    if ($null -ne $btnBrowse) {
        $btnBrowse.Add_Click({
            try {
                $dialog = New-Object Microsoft.Win32.OpenFileDialog
                $dialog.Filter = 'CSV Files (*.csv)|*.csv|All Files (*.*)|*.*'
                $dialog.Title  = 'Select Group CSV File'
                $dialog.InitialDirectory = $script:ScriptRoot
                if ($dialog.ShowDialog() -eq $true) {
                    (Find-GuiControl 'TxtCsvPath').Text = $dialog.FileName
                    Update-CommandPreview
                }
            }
            catch {
                Set-StatusMessage -Message "Error opening file dialog: $($_.Exception.Message)" -IsError
            }
        }.GetNewClosure())
    }

    # Data Source (Live AD vs Previous run) + previous-run picker
    $rdoLive  = Find-GuiControl 'RdoSrcLive'
    $rdoCache = Find-GuiControl 'RdoSrcCache'
    if ($null -ne $rdoLive)  { $rdoLive.Add_Checked({ Set-DataSourceMode }.GetNewClosure()) }
    if ($null -ne $rdoCache) { $rdoCache.Add_Checked({ Set-DataSourceMode }.GetNewClosure()) }
    $cmbPrev = Find-GuiControl 'CmbPrevRun'
    if ($null -ne $cmbPrev) {
        $cmbPrev.Add_SelectionChanged({ Set-PrevRunFromCombo; Update-CommandPreview }.GetNewClosure())
    }
    $btnBrowsePrev = Find-GuiControl 'BtnBrowsePrevRun'
    if ($null -ne $btnBrowsePrev) {
        $btnBrowsePrev.Add_Click({
            try {
                $dialog = New-Object Microsoft.Win32.OpenFileDialog
                $dialog.Filter = 'JSON cache (*.json)|*.json|All Files (*.*)|*.*'
                $dialog.Title  = 'Select a previous-run JSON cache'
                $dialog.InitialDirectory = Get-GuiCacheDir
                if ($dialog.ShowDialog() -eq $true) {
                    $txtPrev = Find-GuiControl 'TxtPrevRunCache'
                    if ($null -ne $txtPrev) { $txtPrev.Text = $dialog.FileName }
                    Update-CommandPreview
                }
            }
            catch {
                Set-StatusMessage -Message "Error opening file dialog: $($_.Exception.Message)" -IsError
            }
        }.GetNewClosure())
    }

    # One-click "Generate Reports from Saved Data" (Reports tab)
    $btnReportSaved = Find-GuiControl 'BtnReportFromSaved'
    if ($null -ne $btnReportSaved) {
        $btnReportSaved.Add_Click({ Invoke-ReportsFromSavedData }.GetNewClosure())
    }

    # Preset selector
    $cmbPreset = Find-GuiControl 'CmbPreset'
    if ($null -ne $cmbPreset) {
        $cmbPreset.Add_SelectionChanged({
            try {
                $selected = (Find-GuiControl 'CmbPreset').SelectedItem
                if ($null -ne $selected) {
                    $presetName = if ($selected -is [System.Windows.Controls.ComboBoxItem]) {
                        [string]$selected.Content
                    }
                    else {
                        [string]$selected
                    }
                    Set-Preset -PresetName $presetName
                    Update-CommandPreview
                }
            }
            catch {
                Set-StatusMessage -Message "Error applying preset: $($_.Exception.Message)" -IsError
            }
        }.GetNewClosure())
    }

    # Run button
    $btnRun = Find-GuiControl 'BtnRun'
    if ($null -ne $btnRun) {
        $btnRun.Add_Click({
            Start-GuiEnumeration
        }.GetNewClosure())
    }

    # Cancel button
    $btnCancel = Find-GuiControl 'BtnCancel'
    if ($null -ne $btnCancel) {
        $btnCancel.Add_Click({
            Stop-GuiEnumeration
        }.GetNewClosure())
    }

    # ---- Wire Copy Command Button ----
    $btnCopyCmd = Find-GuiControl 'BtnCopyCommand'
    if ($null -ne $btnCopyCmd) {
        $btnCopyCmd.Add_Click({
            try {
                $previewCtrl = Find-GuiControl 'TxtCommandPreview'
                if ($null -ne $previewCtrl -and -not [string]::IsNullOrWhiteSpace($previewCtrl.Text)) {
                    [System.Windows.Clipboard]::SetText($previewCtrl.Text)
                    Set-StatusMessage -Message 'Command copied to clipboard.'
                }
                else {
                    Set-StatusMessage -Message 'No command to copy.' -IsWarning
                }
            }
            catch {
                Set-StatusMessage -Message "Could not copy to clipboard: $($_.Exception.Message)" -IsError
            }
        }.GetNewClosure())
    }

    # ---- Wire Change-Detection Events (for command preview updates) ----
    # Every checkbox that affects the command should trigger Update-CommandPreview

    $checkboxNames = @(
        'ChkFuzzyMatch', 'ChkResolveNested', 'ChkDetectStale', 'ChkAnalyzeGaps',
        'ChkIncremental', 'ChkAllowInsecure', 'ChkTrackChanges',
        'ChkGovernanceReport', 'ChkComplianceReport', 'ChkExecutiveDashboard', 'ChkLeadershipSummary',
        'ChkAllReports', 'ChkExportMembersCsv', 'ChkJsonOnly', 'ChkNoCache', 'ChkSendEmail',
        'ChkUnifiedState', 'ChkLegacy', 'ChkFromCache',
        'ChkBaselineReports',
        'ChkBlRoster', 'ChkBlAccessCert', 'ChkBlPrivileged', 'ChkBlSod', 'ChkBlOrphaned',
        'ChkBlInventory', 'ChkBlEmptyStale', 'ChkBlNestedAudit', 'ChkBlExecSummary', 'ChkBlChangeAttest',
        'ChkRcKpiCards', 'ChkRcHeatmap', 'ChkRcTopN', 'ChkRcTree', 'ChkRcDiff', 'ChkRcGroupTable', 'ChkRcRiskFlags', 'ChkRcPrivRisk',
        'ChkRcKpiCardsHalf', 'ChkRcHeatmapHalf', 'ChkRcTopNHalf', 'ChkRcTreeHalf', 'ChkRcDiffHalf', 'ChkRcGroupTableHalf', 'ChkRcRiskFlagsHalf', 'ChkRcPrivRiskHalf',
        'ChkComponentDark'
    )
    foreach ($name in $checkboxNames) {
        $ctrl = Find-GuiControl $name
        if ($null -ne $ctrl) {
            $ctrl.Add_Checked({ Update-CommandPreview }.GetNewClosure())
            $ctrl.Add_Unchecked({ Update-CommandPreview }.GetNewClosure())
        }
    }

    # Advanced text fields that affect the command preview
    $advancedTextNames = @('TxtMigratingTo', 'TxtBaselinePath', 'TxtPreviousRunPath', 'TxtAppMappingCsv', 'TxtComponentTitle')
    foreach ($name in $advancedTextNames) {
        $ctrl = Find-GuiControl $name
        if ($null -ne $ctrl) {
            $ctrl.Add_TextChanged({ Update-CommandPreview }.GetNewClosure())
        }
    }

    # ComboBoxes that affect the command
    $comboNames = @('CmbTheme', 'CmbChangeType', 'CmbChangePeriod')
    foreach ($name in $comboNames) {
        $ctrl = Find-GuiControl $name
        if ($null -ne $ctrl) {
            $ctrl.Add_SelectionChanged({ Update-CommandPreview }.GetNewClosure())
        }
    }

    # Radio buttons for state backend
    $rdoJson = Find-GuiControl 'RdoBackendJson'
    $rdoSqlite = Find-GuiControl 'RdoBackendSqlite'
    if ($null -ne $rdoJson)   { $rdoJson.Add_Checked({ Update-CommandPreview }.GetNewClosure()) }
    if ($null -ne $rdoSqlite) { $rdoSqlite.Add_Checked({ Update-CommandPreview }.GetNewClosure()) }

    # CSV path text changed
    $txtCsv = Find-GuiControl 'TxtCsvPath'
    if ($null -ne $txtCsv) {
        $txtCsv.Add_TextChanged({ Update-CommandPreview }.GetNewClosure())
    }

    # AllReports master checkbox -- toggles individual report checkboxes
    $chkAll = Find-GuiControl 'ChkAllReports'
    if ($null -ne $chkAll) {
        $chkAll.Add_Checked({
            if ($script:SuppressReportSync) { return }
            $script:SuppressReportSync = $true
            try {
                foreach ($n in @('ChkGovernanceReport','ChkComplianceReport','ChkExecutiveDashboard','ChkLeadershipSummary')) {
                    $c = Find-GuiControl $n
                    if ($null -ne $c) { $c.IsChecked = $true }
                }
            }
            catch { }
            finally { $script:SuppressReportSync = $false }
        }.GetNewClosure())

        $chkAll.Add_Unchecked({
            if ($script:SuppressReportSync) { return }
            $script:SuppressReportSync = $true
            try {
                foreach ($n in @('ChkGovernanceReport','ChkComplianceReport','ChkExecutiveDashboard','ChkLeadershipSummary')) {
                    $c = Find-GuiControl $n
                    if ($null -ne $c) { $c.IsChecked = $false }
                }
            }
            catch { }
            finally { $script:SuppressReportSync = $false }
        }.GetNewClosure())
    }

    # Individual report checkboxes -> auto-sync AllReports state
    foreach ($rptName in @('ChkGovernanceReport','ChkComplianceReport','ChkExecutiveDashboard','ChkLeadershipSummary')) {
        $ctrl = Find-GuiControl $rptName
        if ($null -ne $ctrl) {
            $syncAction = {
                if ($script:SuppressReportSync) { return }
                $script:SuppressReportSync = $true
                try {
                    $allOn = $true
                    foreach ($n in @('ChkGovernanceReport','ChkComplianceReport','ChkExecutiveDashboard','ChkLeadershipSummary')) {
                        $c = Find-GuiControl $n
                        if ($null -eq $c -or $c.IsChecked -ne $true) { $allOn = $false; break }
                    }
                    $chkAllCtrl = Find-GuiControl 'ChkAllReports'
                    if ($null -ne $chkAllCtrl) {
                        $chkAllCtrl.IsChecked = $allOn
                    }
                }
                catch { }
                finally { $script:SuppressReportSync = $false }
            }.GetNewClosure()
            $ctrl.Add_Checked($syncAction)
            $ctrl.Add_Unchecked($syncAction)
        }
    }

    # AnalyzeGaps requires FuzzyMatch -- auto-enable FuzzyMatch when AnalyzeGaps is checked
    $chkGaps = Find-GuiControl 'ChkAnalyzeGaps'
    if ($null -ne $chkGaps) {
        $chkGaps.Add_Checked({
            $chkFuzzy = Find-GuiControl 'ChkFuzzyMatch'
            if ($null -ne $chkFuzzy -and $chkFuzzy.IsChecked -ne $true) {
                $chkFuzzy.IsChecked = $true
            }
        }.GetNewClosure())
    }

    # ---- Wire Config/Settings/Results Events ----
    # Agent 4 will add Initialize-ConfigTab, Initialize-ResultsTab, etc.
    # Call them here if they have been defined (allows independent loading order):
    if (Get-Command Initialize-ConfigTab -ErrorAction SilentlyContinue) {
        Initialize-ConfigTab
    }
    if (Get-Command Initialize-ResultsTab -ErrorAction SilentlyContinue) {
        Initialize-ResultsTab
    }
    if (Get-Command Initialize-EnumerationTab -ErrorAction SilentlyContinue) {
        Initialize-EnumerationTab
    }
    if (Get-Command Initialize-ReportsTab -ErrorAction SilentlyContinue) {
        Initialize-ReportsTab
    }
    if (Get-Command Initialize-ChangeTrackingTab -ErrorAction SilentlyContinue) {
        Initialize-ChangeTrackingTab
    }

    # ---- Keyboard Shortcuts ----
    # F5 = Run, Escape = Cancel (when running), Ctrl+S = Save Config, Ctrl+O = Open Output
    $Window.Add_PreviewKeyDown({
        param($sender, $e)
        try {
            $ctrlHeld = [System.Windows.Input.Keyboard]::Modifiers -band [System.Windows.Input.ModifierKeys]::Control

            if ($e.Key -eq [System.Windows.Input.Key]::F5) {
                $e.Handled = $true
                Start-GuiEnumeration
            }
            elseif ($e.Key -eq [System.Windows.Input.Key]::Escape -and $script:IsRunning) {
                $e.Handled = $true
                Stop-GuiEnumeration
            }
            elseif ($e.Key -eq [System.Windows.Input.Key]::S -and $ctrlHeld) {
                $e.Handled = $true
                Save-GuiConfig
            }
            elseif ($e.Key -eq [System.Windows.Input.Key]::O -and $ctrlHeld) {
                $e.Handled = $true
                Open-GuiOutputDirectory
            }
        }
        catch { }
    }.GetNewClosure())

    # ---- Initial State ----
    Initialize-FromConfig

    # Offer to restore last-run configuration if available
    $restored = Restore-LastRunState

    Update-CommandPreview

    if (-not $restored) {
        Set-StatusMessage -Message 'Ready. Select a CSV file and configure options to begin. (F5=Run, Ctrl+S=Save)'
    }
}

# --- END OF RUN TAB + EXECUTION ENGINE ---

# ============================================================================
# Configuration Tab (Save / Reset / Load / Browse)
# ============================================================================

function Initialize-ConfigTab {
    <#
    .SYNOPSIS
        Wires event handlers for the Configuration tab controls:
        Save, Reset, Load, and Browse buttons.
    #>

    # --- BtnSaveConfig ---
    $btnSave = Find-GuiControl 'BtnSaveConfig'
    if ($null -ne $btnSave) {
        $btnSave.Add_Click({
            Save-GuiConfig
        }.GetNewClosure())
    }

    # --- BtnResetConfig ---
    $btnReset = Find-GuiControl 'BtnResetConfig'
    if ($null -ne $btnReset) {
        $btnReset.Add_Click({
            Reset-GuiConfig
        }.GetNewClosure())
    }

    # --- BtnLoadConfig ---
    $btnLoad = Find-GuiControl 'BtnLoadConfig'
    if ($null -ne $btnLoad) {
        $btnLoad.Add_Click({
            Load-GuiConfigFile
        }.GetNewClosure())
    }

    # --- BtnBrowseLogPath ---
    $btnBrowseLog = Find-GuiControl 'BtnBrowseLogPath'
    if ($null -ne $btnBrowseLog) {
        $btnBrowseLog.Add_Click({
            try {
                Add-Type -AssemblyName System.Windows.Forms -ErrorAction SilentlyContinue
                $dialog = New-Object System.Windows.Forms.FolderBrowserDialog
                $dialog.Description = 'Select Log Directory'
                $dialog.ShowNewFolderButton = $true
                if ($dialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
                    $ctrl = Find-GuiControl 'TxtLogPath'
                    if ($null -ne $ctrl) { $ctrl.Text = $dialog.SelectedPath }
                }
            }
            catch {
                Set-StatusMessage -Message "Error opening folder dialog: $($_.Exception.Message)" -IsError
            }
        }.GetNewClosure())
    }

    # --- BtnBrowseOutputDir ---
    $btnBrowseOut = Find-GuiControl 'BtnBrowseOutputDir'
    if ($null -ne $btnBrowseOut) {
        $btnBrowseOut.Add_Click({
            try {
                Add-Type -AssemblyName System.Windows.Forms -ErrorAction SilentlyContinue
                $dialog = New-Object System.Windows.Forms.FolderBrowserDialog
                $dialog.Description = 'Select Output Directory'
                $dialog.ShowNewFolderButton = $true
                if ($dialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
                    $ctrl = Find-GuiControl 'TxtOutputDirectory'
                    if ($null -ne $ctrl) { $ctrl.Text = $dialog.SelectedPath }
                }
            }
            catch {
                Set-StatusMessage -Message "Error opening folder dialog: $($_.Exception.Message)" -IsError
            }
        }.GetNewClosure())
    }
}

function Test-ConfigValidation {
    <#
    .SYNOPSIS
        Validates all config fields before saving. Returns an array of
        error messages (empty array means all valid).
    #>

    $errors = [System.Collections.Generic.List[string]]::new()

    # --- Numeric fields must be positive integers ---
    $numericFields = @(
        @{ Name = 'TxtLdapPageSize';         Label = 'LDAP Page Size';       Min = 1;   Max = 10000 }
        @{ Name = 'TxtLdapTimeout';          Label = 'LDAP Timeout';         Min = 1;   Max = 3600  }
        @{ Name = 'TxtMaxMemberCount';       Label = 'Max Member Count';     Min = 1;   Max = 100000 }
        @{ Name = 'TxtLargeGroupThreshold';  Label = 'Large Group Threshold'; Min = 1;  Max = 100000 }
        @{ Name = 'TxtStaleAccountDays';     Label = 'Stale Account Days';   Min = 1;   Max = 3650  }
        @{ Name = 'TxtSmtpPort';             Label = 'SMTP Port';            Min = 1;   Max = 65535 }
        @{ Name = 'TxtMaxChangeLogSizeMB';   Label = 'Max Changelog Size MB'; Min = 1;  Max = 10000 }
        @{ Name = 'TxtRetentionDays';        Label = 'Retention Days';       Min = 0;   Max = 36500 }
        @{ Name = 'TxtNestedGroupMaxDepth';  Label = 'Max Nesting Depth';    Min = 1;   Max = 100   }
    )

    foreach ($field in $numericFields) {
        $ctrl = Find-GuiControl $field.Name
        if ($null -ne $ctrl -and -not [string]::IsNullOrWhiteSpace($ctrl.Text)) {
            $val = 0
            if (-not [int]::TryParse($ctrl.Text.Trim(), [ref]$val)) {
                $errors.Add("$($field.Label): '$($ctrl.Text.Trim())' is not a valid number.")
            }
            elseif ($val -lt $field.Min -or $val -gt $field.Max) {
                $errors.Add("$($field.Label): $val is out of range ($($field.Min)-$($field.Max)).")
            }
        }
    }

    # --- FuzzyMinScore must be 0.0-1.0 ---
    $txtMinScore = Find-GuiControl 'TxtFuzzyMinScore'
    if ($null -ne $txtMinScore -and -not [string]::IsNullOrWhiteSpace($txtMinScore.Text)) {
        $scoreVal = 0.0
        if (-not [double]::TryParse($txtMinScore.Text.Trim(), [ref]$scoreVal)) {
            $errors.Add("Fuzzy Min Score: '$($txtMinScore.Text.Trim())' is not a valid number.")
        }
        elseif ($scoreVal -lt 0.0 -or $scoreVal -gt 1.0) {
            $errors.Add("Fuzzy Min Score: $scoreVal is out of range (0.0-1.0).")
        }
    }

    # --- Email addresses must contain @ if non-empty ---
    $emailFields = @(
        @{ Name = 'TxtSmtpFrom'; Label = 'SMTP From' }
        @{ Name = 'TxtSmtpTo';   Label = 'SMTP To' }
        @{ Name = 'TxtSmtpCc';   Label = 'SMTP Cc' }
    )
    foreach ($field in $emailFields) {
        $ctrl = Find-GuiControl $field.Name
        if ($null -ne $ctrl -and -not [string]::IsNullOrWhiteSpace($ctrl.Text)) {
            $addresses = @($ctrl.Text -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' })
            foreach ($addr in $addresses) {
                if ($addr -notmatch '@') {
                    $errors.Add("$($field.Label): '$addr' does not appear to be a valid email address.")
                    break
                }
            }
        }
    }

    # --- Paths must not contain invalid characters ---
    $pathFields = @(
        @{ Name = 'TxtOutputDirectory'; Label = 'Output Directory' }
        @{ Name = 'TxtCachePath';       Label = 'Cache Path' }
        @{ Name = 'TxtStatePath';       Label = 'State Path' }
        @{ Name = 'TxtLogPath';         Label = 'Log Path' }
        @{ Name = 'TxtSqliteDbPath';    Label = 'SQLite DB Path' }
    )
    $invalidChars = [System.IO.Path]::GetInvalidPathChars()
    foreach ($field in $pathFields) {
        $ctrl = Find-GuiControl $field.Name
        if ($null -ne $ctrl -and -not [string]::IsNullOrWhiteSpace($ctrl.Text)) {
            $pathVal = $ctrl.Text.Trim()
            foreach ($c in $invalidChars) {
                if ($pathVal.Contains($c)) {
                    $errors.Add("$($field.Label): contains invalid path character.")
                    break
                }
            }
        }
    }

    # Use unary comma to prevent pipeline unrolling of single-element arrays
    return , @($errors)
}

function Save-GuiConfig {
    <#
    .SYNOPSIS
        Validates config fields, reads all Configuration tab controls,
        builds a config hashtable, and writes it to disk as JSON.
        Updates $script:Config in memory.
    #>

    try {
        # Validate before saving
        $validationErrors = Test-ConfigValidation
        if ($validationErrors.Count -gt 0) {
            $errMsg = "Validation errors:`n" + ($validationErrors -join "`n")
            Set-StatusMessage -Message "Config not saved: $($validationErrors.Count) validation error(s). Check log." -IsError
            Append-LogMessage "CONFIG VALIDATION FAILED:"
            foreach ($err in $validationErrors) {
                Append-LogMessage "  - $err"
            }
            return
        }
        # Helper: read TextBox as string, return empty string for null/blank
        function Get-CfgText {
            param([string]$Name)
            $ctrl = Find-GuiControl $Name
            if ($null -ne $ctrl -and -not [string]::IsNullOrWhiteSpace($ctrl.Text)) {
                return $ctrl.Text.Trim()
            }
            return ''
        }

        # Helper: read TextBox as integer, return default for invalid
        function Get-CfgInt {
            param([string]$Name, [int]$Default)
            $text = Get-CfgText $Name
            $val = 0
            if ([int]::TryParse($text, [ref]$val)) { return $val }
            return $Default
        }

        # Helper: read TextBox as double, return default for invalid
        function Get-CfgDouble {
            param([string]$Name, [double]$Default)
            $text = Get-CfgText $Name
            $val = 0.0
            if ([double]::TryParse($text, [ref]$val)) { return $val }
            return $Default
        }

        # Helper: read CheckBox as bool
        function Get-CfgBool {
            param([string]$Name)
            $ctrl = Find-GuiControl $Name
            if ($null -ne $ctrl) { return ($ctrl.IsChecked -eq $true) }
            return $false
        }

        # --- Build config hashtable ---
        $config = [ordered]@{
            LdapPageSize          = Get-CfgInt 'TxtLdapPageSize' 1000
            LdapTimeout           = Get-CfgInt 'TxtLdapTimeout' 120
            MaxMemberCount        = Get-CfgInt 'TxtMaxMemberCount' 5000
            SkipLargeGroups       = $true
            LargeGroupThreshold   = Get-CfgInt 'TxtLargeGroupThreshold' 5000
        }

        # SkipGroups (comma-separated to array)
        $skipText = Get-CfgText 'TxtSkipGroups'
        if (-not [string]::IsNullOrWhiteSpace($skipText)) {
            $config['SkipGroups'] = @($skipText -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' })
        }
        else {
            $config['SkipGroups'] = @()
        }

        # FuzzyPrefixes (comma-separated to array)
        $prefixText = Get-CfgText 'TxtFuzzyPrefixes'
        if (-not [string]::IsNullOrWhiteSpace($prefixText)) {
            $config['FuzzyPrefixes'] = @($prefixText -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' })
        }
        else {
            $config['FuzzyPrefixes'] = @()
        }

        $config['FuzzyMinScore']        = Get-CfgDouble 'TxtFuzzyMinScore' 0.7
        $config['OutputDirectory']      = Get-CfgText 'TxtOutputDirectory'
        if ([string]::IsNullOrWhiteSpace($config['OutputDirectory'])) {
            $config['OutputDirectory'] = 'Output'
        }

        $config['DefaultTheme']         = Get-ComboSelectedText 'CmbTheme'
        if ([string]::IsNullOrWhiteSpace($config['DefaultTheme'])) {
            $config['DefaultTheme'] = 'dark'
        }

        $config['CachePath']            = Get-CfgText 'TxtCachePath'
        if ([string]::IsNullOrWhiteSpace($config['CachePath'])) {
            $config['CachePath'] = 'Cache'
        }

        $config['CacheEnabled']         = $true
        $config['AllowInsecure']        = Get-CfgBool 'ChkAllowInsecure'
        $config['LogEnabled']           = Get-CfgBool 'ChkLogEnabled'
        $config['LogPath']              = Get-CfgText 'TxtLogPath'
        if ([string]::IsNullOrWhiteSpace($config['LogPath'])) {
            $config['LogPath'] = 'Logs'
        }

        $config['LogLevel']             = Get-ComboSelectedText 'CmbLogLevel'
        if ([string]::IsNullOrWhiteSpace($config['LogLevel'])) {
            $config['LogLevel'] = 'INFO'
        }

        $config['NestedGroupMaxDepth']  = Get-CfgInt 'TxtNestedGroupMaxDepth' 10
        $config['StaleAccountDays']     = Get-CfgInt 'TxtStaleAccountDays' 90
        $config['CorrelationStrategy']  = Get-ComboSelectedText 'CmbCorrelationStrategy'
        if ([string]::IsNullOrWhiteSpace($config['CorrelationStrategy'])) {
            $config['CorrelationStrategy'] = 'email-first'
        }

        $appMapVal = Get-CfgText 'TxtAppMappingCsv'
        $config['AppMappingCsvPath']    = if ([string]::IsNullOrWhiteSpace($appMapVal)) { $null } else { $appMapVal }

        # --- ChangeTracking nested section ---
        $statePath = Get-CfgText 'TxtStatePath'
        if ([string]::IsNullOrWhiteSpace($statePath)) { $statePath = 'State' }

        $changeType = Get-ComboSelectedText 'CmbChangeType'
        if ([string]::IsNullOrWhiteSpace($changeType)) { $changeType = 'Both' }

        $config['ChangeTracking'] = [ordered]@{
            Enabled           = Get-CfgBool 'ChkTrackChanges'
            UnifiedState      = Get-CfgBool 'ChkUnifiedState'
            StatePath         = $statePath
            StateFile         = 'membership-state.json'
            ChangeLogFile     = 'changelog.jsonl'
            DefaultChangeType = $changeType
            MaxChangeLogSizeMB = Get-CfgInt 'TxtMaxChangeLogSizeMB' 50
            RetentionDays     = Get-CfgInt 'TxtRetentionDays' 0
        }

        # --- Enumeration nested section ---
        $config['Enumeration'] = [ordered]@{
            Incremental = Get-CfgBool 'ChkIncremental'
        }

        # --- StateBackend ---
        $rdoSqlite = Find-GuiControl 'RdoBackendSqlite'
        if ($null -ne $rdoSqlite -and $rdoSqlite.IsChecked -eq $true) {
            $config['StateBackend'] = 'sqlite'
        }
        else {
            $config['StateBackend'] = 'json'
        }

        $config['SqliteDbPath'] = Get-CfgText 'TxtSqliteDbPath'
        if ([string]::IsNullOrWhiteSpace($config['SqliteDbPath'])) {
            $config['SqliteDbPath'] = 'State/group-enumerator.db'
        }

        $config['GarbageCollectDays'] = 90

        # --- Reporting nested section ---
        $config['Reporting'] = [ordered]@{
            GovernanceReport        = Get-CfgBool 'ChkGovernanceReport'
            ComplianceReport        = Get-CfgBool 'ChkComplianceReport'
            ExecutiveDashboard      = Get-CfgBool 'ChkExecutiveDashboard'
            LeadershipSummary       = Get-CfgBool 'ChkLeadershipSummary'
            IdentityDetailThreshold = 3
        }

        # --- Email nested section ---
        $smtpTo = Get-CfgText 'TxtSmtpTo'
        $toArray = @()
        if (-not [string]::IsNullOrWhiteSpace($smtpTo)) {
            $toArray = @($smtpTo -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' })
        }

        $smtpCc = Get-CfgText 'TxtSmtpCc'
        $ccArray = @()
        if (-not [string]::IsNullOrWhiteSpace($smtpCc)) {
            $ccArray = @($smtpCc -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' })
        }

        $config['Email'] = [ordered]@{
            Enabled       = Get-CfgBool 'ChkSendEmail'
            SmtpServer    = Get-CfgText 'TxtSmtpServer'
            SmtpPort      = Get-CfgInt 'TxtSmtpPort' 587
            UseSsl        = Get-CfgBool 'ChkSmtpUseSsl'
            From          = Get-CfgText 'TxtSmtpFrom'
            To            = $toArray
            Cc            = $ccArray
            SubjectPrefix = Get-CfgText 'TxtSmtpSubjectPrefix'
            AttachReport  = Get-CfgBool 'ChkSmtpAttachReport'
        }

        if ([string]::IsNullOrWhiteSpace($config['Email'].SubjectPrefix)) {
            $config['Email'].SubjectPrefix = '[Migration Readiness]'
        }

        # --- Write to disk ---
        $targetPath = $script:ConfigPath
        if ([string]::IsNullOrWhiteSpace($targetPath)) {
            $targetPath = Join-Path $script:ScriptRoot 'Config\group-enum-config.json'
        }

        # Ensure the directory exists
        $configDir = Split-Path $targetPath -Parent
        if (-not (Test-Path $configDir)) {
            New-Item -Path $configDir -ItemType Directory -Force | Out-Null
        }

        $config | ConvertTo-Json -Depth 4 | Set-Content -Path $targetPath -Encoding UTF8

        # Update in-memory config
        $script:Config     = $config
        $script:ConfigPath = $targetPath

        Set-StatusMessage -Message "Configuration saved to: $targetPath"
        Append-LogMessage "Configuration saved to: $targetPath"
    }
    catch {
        Set-StatusMessage -Message "Error saving configuration: $($_.Exception.Message)" -IsError
        Append-LogMessage "ERROR: Failed to save config: $($_.Exception.Message)"
    }
}

function Reset-GuiConfig {
    <#
    .SYNOPSIS
        Resets all Configuration tab controls to their default values.
        Prompts the user for confirmation first.
    #>

    $result = [System.Windows.MessageBox]::Show(
        'Reset all configuration values to defaults? This will not save to disk until you click Save.',
        'Reset Configuration',
        [System.Windows.MessageBoxButton]::YesNo,
        [System.Windows.MessageBoxImage]::Question
    )

    if ($result -ne [System.Windows.MessageBoxResult]::Yes) { return }

    try {
        $defaults = @{
            LdapPageSize          = 1000
            LdapTimeout           = 120
            MaxMemberCount        = 5000
            SkipLargeGroups       = $true
            LargeGroupThreshold   = 5000
            SkipGroups            = @('Domain Users', 'Domain Computers', 'Authenticated Users')
            FuzzyPrefixes         = @('GG_', 'USV_', 'SG_', 'DL_', 'GL_')
            FuzzyMinScore         = 0.7
            OutputDirectory       = 'Output'
            DefaultTheme          = 'dark'
            CachePath             = 'Cache'
            CacheEnabled          = $true
            AllowInsecure         = $false
            LogEnabled            = $true
            LogPath               = 'Logs'
            LogLevel              = 'INFO'
            NestedGroupMaxDepth   = 10
            StaleAccountDays      = 90
            CorrelationStrategy   = 'email-first'
            AppMappingCsvPath     = $null
            ChangeTracking        = @{
                Enabled           = $false
                UnifiedState      = $true
                StatePath         = 'State'
                StateFile         = 'membership-state.json'
                ChangeLogFile     = 'changelog.jsonl'
                DefaultChangeType = 'Both'
                MaxChangeLogSizeMB = 50
                RetentionDays     = 0
            }
            Enumeration           = @{ Incremental = $false }
            StateBackend          = 'json'
            SqliteDbPath          = 'State/group-enumerator.db'
            GarbageCollectDays    = 90
            Reporting             = @{
                GovernanceReport        = $false
                ComplianceReport        = $false
                ExecutiveDashboard      = $false
                LeadershipSummary       = $false
                IdentityDetailThreshold = 3
            }
            Email                 = @{
                Enabled       = $false
                SmtpServer    = ''
                SmtpPort      = 25
                UseSsl        = $false
                From          = ''
                To            = @()
                Cc            = @()
                SubjectPrefix = '[Migration Readiness]'
                AttachReport  = $true
            }
        }

        Populate-ConfigControls -Config $defaults
        Set-StatusMessage -Message 'Configuration reset to defaults. Click Save to persist.'
        Append-LogMessage 'Configuration reset to defaults.'
    }
    catch {
        Set-StatusMessage -Message "Error resetting configuration: $($_.Exception.Message)" -IsError
    }
}

function Load-GuiConfigFile {
    <#
    .SYNOPSIS
        Opens a file dialog to select a JSON config file, loads it,
        and populates all GUI controls from the loaded config.
    #>

    try {
        $dialog = New-Object Microsoft.Win32.OpenFileDialog
        $dialog.Filter = 'JSON Files (*.json)|*.json|All Files (*.*)|*.*'
        $dialog.Title  = 'Load Configuration File'
        if (-not [string]::IsNullOrWhiteSpace($script:ConfigPath)) {
            $dialog.InitialDirectory = Split-Path $script:ConfigPath -Parent
        }
        else {
            $dialog.InitialDirectory = $script:ScriptRoot
        }

        if ($dialog.ShowDialog() -ne $true) { return }

        $filePath = $dialog.FileName
        if (-not (Test-Path $filePath)) {
            Set-StatusMessage -Message "File not found: $filePath" -IsError
            return
        }

        $rawJson = Get-Content -Path $filePath -Raw -ErrorAction Stop
        $loaded  = $rawJson | ConvertFrom-Json

        # ConvertFrom-Json produces PSCustomObject, convert to hashtable
        $config = ConvertTo-Hashtable -InputObject $loaded

        # Update in-memory state
        $script:Config     = $config
        $script:ConfigPath = $filePath

        # Populate GUI controls
        Populate-ConfigControls -Config $config

        # Also re-run the main Initialize-FromConfig to sync Enumeration/Reports tabs
        Initialize-FromConfig
        Update-CommandPreview

        Set-StatusMessage -Message "Configuration loaded from: $filePath"
        Append-LogMessage "Configuration loaded from: $filePath"
    }
    catch {
        Set-StatusMessage -Message "Error loading config: $($_.Exception.Message)" -IsError
        Append-LogMessage "ERROR: Failed to load config: $($_.Exception.Message)"
    }
}

function ConvertTo-Hashtable {
    <#
    .SYNOPSIS
        Recursively converts a PSCustomObject (from ConvertFrom-Json) into
        an ordered hashtable. Arrays are preserved. Null values are handled
        without throwing.
    #>
    param(
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [AllowEmptyString()]
        $InputObject = $null
    )

    if ($null -eq $InputObject) {
        return $null
    }

    if ($InputObject -is [System.Management.Automation.PSCustomObject]) {
        $hash = [ordered]@{}
        foreach ($prop in $InputObject.PSObject.Properties) {
            $val = $prop.Value
            if ($null -eq $val) {
                $hash[$prop.Name] = $null
            }
            else {
                $hash[$prop.Name] = ConvertTo-Hashtable -InputObject $val
            }
        }
        return $hash
    }
    elseif ($InputObject -is [System.Collections.IEnumerable] -and $InputObject -isnot [string]) {
        $arr = @()
        foreach ($item in $InputObject) {
            $arr += ConvertTo-Hashtable -InputObject $item
        }
        return $arr
    }
    else {
        return $InputObject
    }
}

function Populate-ConfigControls {
    <#
    .SYNOPSIS
        Maps config values to all Configuration tab GUI controls.
        Handles top-level keys, nested sections, arrays, and booleans.
    .PARAMETER Config
        The config hashtable to populate from.
    #>
    param(
        [Parameter(Mandatory)]
        [hashtable]$Config
    )

    try {
        $cfg = $Config

        # --- LDAP Connection ---
        $txtPageSize = Find-GuiControl 'TxtLdapPageSize'
        if ($null -ne $txtPageSize -and $cfg.ContainsKey('LdapPageSize')) {
            $txtPageSize.Text = [string]$cfg.LdapPageSize
        }

        $txtTimeout = Find-GuiControl 'TxtLdapTimeout'
        if ($null -ne $txtTimeout -and $cfg.ContainsKey('LdapTimeout')) {
            $txtTimeout.Text = [string]$cfg.LdapTimeout
        }

        $txtMaxMember = Find-GuiControl 'TxtMaxMemberCount'
        if ($null -ne $txtMaxMember -and $cfg.ContainsKey('MaxMemberCount')) {
            $txtMaxMember.Text = [string]$cfg.MaxMemberCount
        }

        # --- Large Group Threshold ---
        $txtLargeThreshold = Find-GuiControl 'TxtLargeGroupThreshold'
        if ($null -ne $txtLargeThreshold -and $cfg.ContainsKey('LargeGroupThreshold')) {
            $txtLargeThreshold.Text = [string]$cfg.LargeGroupThreshold
        }

        # --- Skip Groups (array -> comma-joined) ---
        if ($cfg.ContainsKey('SkipGroups') -and $null -ne $cfg.SkipGroups) {
            $txtSkip = Find-GuiControl 'TxtSkipGroups'
            if ($null -ne $txtSkip) {
                $txtSkip.Text = if ($cfg.SkipGroups -is [array]) { $cfg.SkipGroups -join ', ' } else { [string]$cfg.SkipGroups }
            }
        }

        # --- Fuzzy Matching ---
        if ($cfg.ContainsKey('FuzzyPrefixes') -and $null -ne $cfg.FuzzyPrefixes) {
            $txtPrefixes = Find-GuiControl 'TxtFuzzyPrefixes'
            if ($null -ne $txtPrefixes) {
                $txtPrefixes.Text = if ($cfg.FuzzyPrefixes -is [array]) { $cfg.FuzzyPrefixes -join ', ' } else { [string]$cfg.FuzzyPrefixes }
            }
        }

        $txtMinScore = Find-GuiControl 'TxtFuzzyMinScore'
        if ($null -ne $txtMinScore -and $cfg.ContainsKey('FuzzyMinScore')) {
            $txtMinScore.Text = [string]$cfg.FuzzyMinScore
        }

        # --- Stale Detection ---
        $txtStaleDays = Find-GuiControl 'TxtStaleAccountDays'
        if ($null -ne $txtStaleDays -and $cfg.ContainsKey('StaleAccountDays')) {
            $txtStaleDays.Text = [string]$cfg.StaleAccountDays
        }

        # --- Correlation ---
        if ($cfg.ContainsKey('CorrelationStrategy')) {
            $cmbCorr = Find-GuiControl 'CmbCorrelationStrategy'
            if ($null -ne $cmbCorr) {
                Select-ComboItemByContent -ComboBox $cmbCorr -Content $cfg.CorrelationStrategy
            }
        }

        # --- Logging ---
        if ($cfg.ContainsKey('LogEnabled')) {
            $chkLog = Find-GuiControl 'ChkLogEnabled'
            if ($null -ne $chkLog) { $chkLog.IsChecked = [bool]$cfg.LogEnabled }
        }

        if ($cfg.ContainsKey('LogLevel')) {
            $cmbLogLevel = Find-GuiControl 'CmbLogLevel'
            if ($null -ne $cmbLogLevel) {
                Select-ComboItemByContent -ComboBox $cmbLogLevel -Content $cfg.LogLevel
            }
        }

        $txtLogPath = Find-GuiControl 'TxtLogPath'
        if ($null -ne $txtLogPath -and $cfg.ContainsKey('LogPath')) {
            $txtLogPath.Text = [string]$cfg.LogPath
        }

        # --- Email Delivery ---
        if ($cfg.ContainsKey('Email') -and $null -ne $cfg.Email) {
            $em = $cfg.Email
            # Defensive: convert PSCustomObject to hashtable if needed
            if ($em -is [System.Management.Automation.PSCustomObject]) {
                $em = ConvertTo-Hashtable -InputObject $em
            }

            # Map Email.Enabled -> ChkSendEmail on Enumeration/Reports tab
            if ($em.ContainsKey('Enabled')) {
                $chkSendEmail = Find-GuiControl 'ChkSendEmail'
                if ($null -ne $chkSendEmail) { $chkSendEmail.IsChecked = [bool]$em.Enabled }
            }

            $txtSmtp = Find-GuiControl 'TxtSmtpServer'
            if ($null -ne $txtSmtp -and $em.ContainsKey('SmtpServer')) {
                $txtSmtp.Text = [string]$em.SmtpServer
            }

            $txtPort = Find-GuiControl 'TxtSmtpPort'
            if ($null -ne $txtPort -and $em.ContainsKey('SmtpPort')) {
                $txtPort.Text = [string]$em.SmtpPort
            }

            if ($em.ContainsKey('UseSsl')) {
                $chkSsl = Find-GuiControl 'ChkSmtpUseSsl'
                if ($null -ne $chkSsl) { $chkSsl.IsChecked = [bool]$em.UseSsl }
            }

            $txtFrom = Find-GuiControl 'TxtSmtpFrom'
            if ($null -ne $txtFrom -and $em.ContainsKey('From')) {
                $txtFrom.Text = [string]$em.From
            }

            if ($em.ContainsKey('To') -and $null -ne $em.To) {
                $txtTo = Find-GuiControl 'TxtSmtpTo'
                if ($null -ne $txtTo) {
                    $txtTo.Text = if ($em.To -is [array]) { $em.To -join ', ' } else { [string]$em.To }
                }
            }

            if ($em.ContainsKey('Cc') -and $null -ne $em.Cc) {
                $txtCc = Find-GuiControl 'TxtSmtpCc'
                if ($null -ne $txtCc) {
                    $txtCc.Text = if ($em.Cc -is [array]) { $em.Cc -join ', ' } else { [string]$em.Cc }
                }
            }

            $txtSubject = Find-GuiControl 'TxtSmtpSubjectPrefix'
            if ($null -ne $txtSubject -and $em.ContainsKey('SubjectPrefix')) {
                $txtSubject.Text = [string]$em.SubjectPrefix
            }

            if ($em.ContainsKey('AttachReport')) {
                $chkAttach = Find-GuiControl 'ChkSmtpAttachReport'
                if ($null -ne $chkAttach) { $chkAttach.IsChecked = [bool]$em.AttachReport }
            }
        }

        # --- Changelog ---
        if ($cfg.ContainsKey('ChangeTracking') -and $null -ne $cfg.ChangeTracking) {
            $ct = $cfg.ChangeTracking

            $txtMaxLog = Find-GuiControl 'TxtMaxChangeLogSizeMB'
            if ($null -ne $txtMaxLog -and $ct.ContainsKey('MaxChangeLogSizeMB')) {
                $txtMaxLog.Text = [string]$ct.MaxChangeLogSizeMB
            }

            $txtRetention = Find-GuiControl 'TxtRetentionDays'
            if ($null -ne $txtRetention -and $ct.ContainsKey('RetentionDays')) {
                $txtRetention.Text = [string]$ct.RetentionDays
            }
        }

        # --- Paths ---
        $txtOutDir = Find-GuiControl 'TxtOutputDirectory'
        if ($null -ne $txtOutDir -and $cfg.ContainsKey('OutputDirectory')) {
            $txtOutDir.Text = [string]$cfg.OutputDirectory
        }

        $txtCache = Find-GuiControl 'TxtCachePath'
        if ($null -ne $txtCache -and $cfg.ContainsKey('CachePath')) {
            $txtCache.Text = [string]$cfg.CachePath
        }

        if ($cfg.ContainsKey('ChangeTracking') -and $null -ne $cfg.ChangeTracking -and $cfg.ChangeTracking.ContainsKey('StatePath')) {
            $txtState = Find-GuiControl 'TxtStatePath'
            if ($null -ne $txtState) { $txtState.Text = [string]$cfg.ChangeTracking.StatePath }
        }

        # --- Nested Groups ---
        if ($cfg.ContainsKey('NestedGroupMaxDepth')) {
            $txtNestDepth = Find-GuiControl 'TxtNestedGroupMaxDepth'
            if ($null -ne $txtNestDepth) { $txtNestDepth.Text = [string]$cfg.NestedGroupMaxDepth }
        }

        # --- App Mapping ---
        if ($cfg.ContainsKey('AppMappingCsvPath') -and $null -ne $cfg.AppMappingCsvPath) {
            $txtAppMap = Find-GuiControl 'TxtAppMappingCsv'
            if ($null -ne $txtAppMap) { $txtAppMap.Text = [string]$cfg.AppMappingCsvPath }
        }

        $txtSqlite = Find-GuiControl 'TxtSqliteDbPath'
        if ($null -ne $txtSqlite -and $cfg.ContainsKey('SqliteDbPath')) {
            $txtSqlite.Text = [string]$cfg.SqliteDbPath
        }

        # --- Theme ---
        if ($cfg.ContainsKey('DefaultTheme')) {
            $cmbTheme = Find-GuiControl 'CmbTheme'
            if ($null -ne $cmbTheme) {
                Select-ComboItemByContent -ComboBox $cmbTheme -Content $cfg.DefaultTheme
            }
        }

        # --- State Backend ---
        if ($cfg.ContainsKey('StateBackend')) {
            $rdoJson   = Find-GuiControl 'RdoBackendJson'
            $rdoSqlite = Find-GuiControl 'RdoBackendSqlite'
            if ($cfg.StateBackend -eq 'sqlite') {
                if ($null -ne $rdoSqlite) { $rdoSqlite.IsChecked = $true }
            }
            else {
                if ($null -ne $rdoJson) { $rdoJson.IsChecked = $true }
            }
        }

        # --- Change Tracking controls on Enumeration tab ---
        if ($cfg.ContainsKey('ChangeTracking') -and $null -ne $cfg.ChangeTracking) {
            $ct = $cfg.ChangeTracking

            if ($ct.ContainsKey('Enabled')) {
                $chkTrack = Find-GuiControl 'ChkTrackChanges'
                if ($null -ne $chkTrack) { $chkTrack.IsChecked = [bool]$ct.Enabled }
            }

            if ($ct.ContainsKey('UnifiedState')) {
                $chkUnified = Find-GuiControl 'ChkUnifiedState'
                if ($null -ne $chkUnified) { $chkUnified.IsChecked = [bool]$ct.UnifiedState }
            }

            if ($ct.ContainsKey('DefaultChangeType')) {
                $cmbChange = Find-GuiControl 'CmbChangeType'
                if ($null -ne $cmbChange) {
                    Select-ComboItemByContent -ComboBox $cmbChange -Content $ct.DefaultChangeType
                }
            }
        }

        # --- Incremental ---
        if ($cfg.ContainsKey('Enumeration') -and $null -ne $cfg.Enumeration) {
            if ($cfg.Enumeration.ContainsKey('Incremental')) {
                $chkInc = Find-GuiControl 'ChkIncremental'
                if ($null -ne $chkInc) { $chkInc.IsChecked = [bool]$cfg.Enumeration.Incremental }
            }
        }

        # --- AllowInsecure ---
        if ($cfg.ContainsKey('AllowInsecure')) {
            $chkInsecure = Find-GuiControl 'ChkAllowInsecure'
            if ($null -ne $chkInsecure) { $chkInsecure.IsChecked = [bool]$cfg.AllowInsecure }
        }

        # --- Reporting ---
        if ($cfg.ContainsKey('Reporting') -and $null -ne $cfg.Reporting) {
            $rpt = $cfg.Reporting
            $rptMap = @{
                'GovernanceReport'   = 'ChkGovernanceReport'
                'ComplianceReport'   = 'ChkComplianceReport'
                'ExecutiveDashboard' = 'ChkExecutiveDashboard'
                'LeadershipSummary'  = 'ChkLeadershipSummary'
            }
            foreach ($entry in $rptMap.GetEnumerator()) {
                if ($rpt.ContainsKey($entry.Key)) {
                    $ctrl = Find-GuiControl $entry.Value
                    if ($null -ne $ctrl) { $ctrl.IsChecked = [bool]$rpt[$entry.Key] }
                }
            }
        }
    }
    catch {
        Set-StatusMessage -Message "Error populating config controls: $($_.Exception.Message)" -IsError
    }
}

# ============================================================================
# Results Tab (Output Files DataGrid)
# ============================================================================

function Open-GuiOutputDirectory {
    # Open the resolved Output directory in Explorer. Null/empty-safe root resolution:
    # $script:ScriptRoot can be unset/null in some launch contexts -> fall back to the app
    # root (parent of this module's Modules\ folder), then the current location. Creates the
    # directory if it doesn't exist yet (so it never fails before the first run).
    try {
        $root = $script:ScriptRoot
        if ([string]::IsNullOrWhiteSpace($root)) { $root = Split-Path -Parent $PSScriptRoot }
        if ([string]::IsNullOrWhiteSpace($root)) { $root = (Get-Location).Path }

        $outputDir = ''
        $txtOut = Find-GuiControl 'TxtOutputDirectory'
        if ($null -ne $txtOut -and -not [string]::IsNullOrWhiteSpace($txtOut.Text)) { $outputDir = $txtOut.Text.Trim() }
        if ([string]::IsNullOrWhiteSpace($outputDir)) { $outputDir = 'Output' }
        if (-not [System.IO.Path]::IsPathRooted($outputDir)) { $outputDir = Join-Path $root $outputDir }

        if (-not (Test-Path -LiteralPath $outputDir)) {
            New-Item -ItemType Directory -Path $outputDir -Force | Out-Null
        }
        Start-Process -FilePath 'explorer.exe' -ArgumentList $outputDir
        Set-StatusMessage -Message "Opened output directory: $outputDir"
    }
    catch {
        Set-StatusMessage -Message "Error opening output directory: $($_.Exception.Message)" -IsError
    }
}

function Initialize-ResultsTab {
    <#
    .SYNOPSIS
        Wires event handlers for the Results tab:
        Open Output Directory, Refresh, and DataGrid double-click.
    #>

    # --- BtnOpenOutputDir ---
    $btnOpen = Find-GuiControl 'BtnOpenOutputDir'
    if ($null -ne $btnOpen) {
        $btnOpen.Add_Click({ Open-GuiOutputDirectory }.GetNewClosure())
    }

    # --- BtnRefreshResults ---
    $btnRefresh = Find-GuiControl 'BtnRefreshResults'
    if ($null -ne $btnRefresh) {
        $btnRefresh.Add_Click({
            Refresh-ResultsGrid
        }.GetNewClosure())
    }

    # --- DgOutputFiles double-click -> open file ---
    $dgFiles = Find-GuiControl 'DgOutputFiles'
    if ($null -ne $dgFiles) {
        $dgFiles.Add_MouseDoubleClick({
            param($sender, $e)
            try {
                $dg = Find-GuiControl 'DgOutputFiles'
                if ($null -eq $dg -or $null -eq $dg.SelectedItem) { return }

                $selected = $dg.SelectedItem
                $fullPath = $selected.FullPath

                if (-not [string]::IsNullOrWhiteSpace($fullPath) -and (Test-Path $fullPath)) {
                    Open-OutputFile -FilePath $fullPath
                }
                else {
                    Set-StatusMessage -Message "File not found: $fullPath" -IsWarning
                }
            }
            catch {
                Set-StatusMessage -Message "Error opening file: $($_.Exception.Message)" -IsError
            }
        }.GetNewClosure())
    }

    # --- Context Menu (Copy Path, Open File, Open Containing Folder) ---
    $dgCtxMenu = Find-GuiControl 'DgOutputFiles'
    if ($null -ne $dgCtxMenu) {
        $ctxMenu = $dgCtxMenu.ContextMenu
        if ($null -ne $ctxMenu) {
            # Wire Copy Path
            $mnuCopy = $ctxMenu.Items | Where-Object { $_.Name -eq 'MnuCopyPath' } | Select-Object -First 1
            if ($null -ne $mnuCopy) {
                $mnuCopy.Add_Click({
                    try {
                        $dg = Find-GuiControl 'DgOutputFiles'
                        if ($null -ne $dg -and $null -ne $dg.SelectedItem) {
                            $fullPath = $dg.SelectedItem.FullPath
                            if (-not [string]::IsNullOrWhiteSpace($fullPath)) {
                                [System.Windows.Clipboard]::SetText($fullPath)
                                Set-StatusMessage -Message "Copied: $fullPath"
                            }
                        }
                    }
                    catch { }
                }.GetNewClosure())
            }

            # Wire Open File
            $mnuOpen = $ctxMenu.Items | Where-Object { $_.Name -eq 'MnuOpenFile' } | Select-Object -First 1
            if ($null -ne $mnuOpen) {
                $mnuOpen.Add_Click({
                    try {
                        $dg = Find-GuiControl 'DgOutputFiles'
                        if ($null -ne $dg -and $null -ne $dg.SelectedItem) {
                            $fullPath = $dg.SelectedItem.FullPath
                            if (-not [string]::IsNullOrWhiteSpace($fullPath) -and (Test-Path $fullPath)) {
                                Start-Process -FilePath $fullPath
                            }
                        }
                    }
                    catch { }
                }.GetNewClosure())
            }

            # Wire Open Containing Folder
            $mnuFolder = $ctxMenu.Items | Where-Object { $_.Name -eq 'MnuOpenFolder' } | Select-Object -First 1
            if ($null -ne $mnuFolder) {
                $mnuFolder.Add_Click({
                    try {
                        $dg = Find-GuiControl 'DgOutputFiles'
                        if ($null -ne $dg -and $null -ne $dg.SelectedItem) {
                            $fullPath = $dg.SelectedItem.FullPath
                            if (-not [string]::IsNullOrWhiteSpace($fullPath)) {
                                $folder = Split-Path $fullPath -Parent
                                if (Test-Path $folder) {
                                    Start-Process -FilePath 'explorer.exe' -ArgumentList "/select,`"$fullPath`""
                                }
                            }
                        }
                    }
                    catch { }
                }.GetNewClosure())
            }
        }
    }

    # Initialize the DataGrid with an empty collection
    try {
        $collection = [System.Collections.ObjectModel.ObservableCollection[PSObject]]::new()
        $dg = Find-GuiControl 'DgOutputFiles'
        if ($null -ne $dg) {
            $dg.ItemsSource = $collection
        }
    }
    catch {
        # Swallow -- DataGrid init is not critical
    }
}

function Refresh-ResultsGrid {
    <#
    .SYNOPSIS
        Scans the output directory for generated files and populates
        the DgOutputFiles DataGrid. Also accepts pre-collected output
        files from the execution engine via -OutputFiles parameter.
    .PARAMETER OutputFiles
        Optional array of hashtables from the execution engine sync hash.
        If not provided, scans the output directory on disk.
    #>
    param(
        [array]$OutputFiles = $null
    )

    try {
        $dgFiles = Find-GuiControl 'DgOutputFiles'
        if ($null -eq $dgFiles) { return }

        $collection = [System.Collections.ObjectModel.ObservableCollection[PSObject]]::new()

        if ($null -ne $OutputFiles -and $OutputFiles.Count -gt 0) {
            # Use pre-collected files from the execution engine
            foreach ($f in $OutputFiles) {
                $item = [PSCustomObject]@{
                    FileName  = $f.FileName
                    Type      = $f.Type
                    Size      = $f.Size
                    Generated = $f.Generated
                    FullPath  = $f.FullPath
                }
                $collection.Add($item)
            }
        }
        else {
            # Scan the output directory
            $outputDir = $null

            $txtOut = Find-GuiControl 'TxtOutputDirectory'
            if ($null -ne $txtOut -and -not [string]::IsNullOrWhiteSpace($txtOut.Text)) {
                $outputDir = $txtOut.Text
            }

            # Resolve relative paths
            if ($null -ne $outputDir -and -not [System.IO.Path]::IsPathRooted($outputDir)) {
                $outputDir = Join-Path $script:ScriptRoot $outputDir
            }

            if ([string]::IsNullOrWhiteSpace($outputDir)) {
                $outputDir = Join-Path $script:ScriptRoot 'Output'
            }

            if (-not (Test-Path $outputDir)) {
                Set-StatusMessage -Message "Output directory not found: $outputDir" -IsWarning
                $dgFiles.ItemsSource = $collection
                return
            }

            $files = Get-ChildItem -Path $outputDir -File -ErrorAction SilentlyContinue |
                Sort-Object LastWriteTime -Descending |
                Select-Object -First 50

            foreach ($f in $files) {
                $sizeStr = if ($f.Length -ge 1MB) {
                    '{0:N1} MB' -f ($f.Length / 1MB)
                }
                elseif ($f.Length -ge 1KB) {
                    '{0:N1} KB' -f ($f.Length / 1KB)
                }
                else {
                    "$($f.Length) B"
                }

                $fileType = switch -Wildcard ($f.Extension) {
                    '.html' { 'HTML Report' }
                    '.json' { 'JSON Cache'  }
                    '.csv'  { 'CSV Export'   }
                    '.jsonl' { 'Change Log'  }
                    '.txt'  { 'Text File'    }
                    '.log'  { 'Log File'     }
                    default  { 'File'         }
                }

                $item = [PSCustomObject]@{
                    FileName  = $f.Name
                    Type      = $fileType
                    Size      = $sizeStr
                    Generated = $f.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss')
                    FullPath  = $f.FullName
                }
                $collection.Add($item)
            }
        }

        $dgFiles.ItemsSource = $collection

        $count = $collection.Count
        if ($count -gt 0) {
            # Calculate combined size from raw bytes if available, else from display strings
            $totalBytes = 0
            if ($null -eq $OutputFiles -or $OutputFiles.Count -eq 0) {
                # Scanned from disk -- re-read sizes
                $outputDir2 = $null
                $txtOut2 = Find-GuiControl 'TxtOutputDirectory'
                if ($null -ne $txtOut2 -and -not [string]::IsNullOrWhiteSpace($txtOut2.Text)) {
                    $outputDir2 = $txtOut2.Text
                }
                if ($null -ne $outputDir2 -and -not [System.IO.Path]::IsPathRooted($outputDir2)) {
                    $outputDir2 = Join-Path $script:ScriptRoot $outputDir2
                }
                if ([string]::IsNullOrWhiteSpace($outputDir2)) {
                    $outputDir2 = Join-Path $script:ScriptRoot 'Output'
                }
                if (Test-Path $outputDir2) {
                    $totalBytes = (Get-ChildItem -Path $outputDir2 -File -ErrorAction SilentlyContinue |
                        Sort-Object LastWriteTime -Descending |
                        Select-Object -First 50 |
                        Measure-Object -Property Length -Sum).Sum
                }
            }
            $sizeDisplay = ''
            if ($totalBytes -ge 1MB) {
                $sizeDisplay = ', {0:N1} MB total' -f ($totalBytes / 1MB)
            }
            elseif ($totalBytes -ge 1KB) {
                $sizeDisplay = ', {0:N1} KB total' -f ($totalBytes / 1KB)
            }
            elseif ($totalBytes -gt 0) {
                $sizeDisplay = ", $totalBytes B total"
            }
            Set-StatusMessage -Message "Results: $count file(s) found in output directory$sizeDisplay."
        }
        else {
            Set-StatusMessage -Message 'Results: No output files found. Run an enumeration first.'
        }
    }
    catch {
        Set-StatusMessage -Message "Error refreshing results: $($_.Exception.Message)" -IsError
    }
}

function Update-ResultsGrid {
    <#
    .SYNOPSIS
        Called by the execution engine timer to push output files
        to the Results tab DataGrid after a run completes.
    .PARAMETER OutputFiles
        Array of hashtables with FileName, Type, Size, Generated, FullPath.
    #>
    param([array]$OutputFiles = $null)

    Refresh-ResultsGrid -OutputFiles $OutputFiles
}

# ============================================================================
# Enumeration Tab (inter-control dependencies)
# ============================================================================

function Initialize-EnumerationTab {
    <#
    .SYNOPSIS
        Wires additional event handlers for the Enumeration tab:
        - AnalyzeGaps requires FuzzyMatch
        - AllowInsecure shows a security warning
        - TrackChanges enables/disables ChangeType and ChangePeriod combos
    #>

    # --- FuzzyMatch unchecked -> disable and uncheck AnalyzeGaps ---
    $chkFuzzy = Find-GuiControl 'ChkFuzzyMatch'
    if ($null -ne $chkFuzzy) {
        $chkFuzzy.Add_Unchecked({
            $chkGaps = Find-GuiControl 'ChkAnalyzeGaps'
            if ($null -ne $chkGaps) {
                $chkGaps.IsChecked = $false
                $chkGaps.IsEnabled = $false
            }
        }.GetNewClosure())

        $chkFuzzy.Add_Checked({
            $chkGaps = Find-GuiControl 'ChkAnalyzeGaps'
            if ($null -ne $chkGaps) {
                $chkGaps.IsEnabled = $true
            }
        }.GetNewClosure())

        # Set initial state
        if ($chkFuzzy.IsChecked -ne $true) {
            $chkGaps = Find-GuiControl 'ChkAnalyzeGaps'
            if ($null -ne $chkGaps) {
                $chkGaps.IsEnabled = $false
            }
        }
    }

    # --- AllowInsecure -> show security warning ---
    $chkInsecure = Find-GuiControl 'ChkAllowInsecure'
    if ($null -ne $chkInsecure) {
        $chkInsecure.Add_Checked({
            $result = [System.Windows.MessageBox]::Show(
                ("AllowInsecure enables LDAP 389 fallback which may transmit" +
                 " data without encryption. Only use when LDAPS certificates" +
                 " are unavailable.`n`nContinue?"),
                'Security Warning',
                [System.Windows.MessageBoxButton]::YesNo,
                [System.Windows.MessageBoxImage]::Warning
            )

            if ($result -ne [System.Windows.MessageBoxResult]::Yes) {
                $ctrl = Find-GuiControl 'ChkAllowInsecure'
                if ($null -ne $ctrl) { $ctrl.IsChecked = $false }
            }
        }.GetNewClosure())
    }

    # --- TrackChanges -> enable/disable ChangeType and ChangePeriod combos ---
    $chkTrack = Find-GuiControl 'ChkTrackChanges'
    if ($null -ne $chkTrack) {
        $chkTrack.Add_Checked({
            $cmbType   = Find-GuiControl 'CmbChangeType'
            $cmbPeriod = Find-GuiControl 'CmbChangePeriod'
            if ($null -ne $cmbType)   { $cmbType.IsEnabled = $true }
            if ($null -ne $cmbPeriod) { $cmbPeriod.IsEnabled = $true }
        }.GetNewClosure())

        $chkTrack.Add_Unchecked({
            $cmbType   = Find-GuiControl 'CmbChangeType'
            $cmbPeriod = Find-GuiControl 'CmbChangePeriod'
            if ($null -ne $cmbType)   { $cmbType.IsEnabled = $false }
            if ($null -ne $cmbPeriod) { $cmbPeriod.IsEnabled = $false }
        }.GetNewClosure())

        # Set initial state
        if ($chkTrack.IsChecked -ne $true) {
            $cmbType   = Find-GuiControl 'CmbChangeType'
            $cmbPeriod = Find-GuiControl 'CmbChangePeriod'
            if ($null -ne $cmbType)   { $cmbType.IsEnabled = $false }
            if ($null -ne $cmbPeriod) { $cmbPeriod.IsEnabled = $false }
        }
    }

    # --- Custom change-window controls (active when Change Period = Custom) ---
    $cmbPeriodCustom = Find-GuiControl 'CmbChangePeriod'
    if ($null -ne $cmbPeriodCustom) {
        $cmbPeriodCustom.Add_SelectionChanged({ Update-ChangeCustomEnabled; Update-CommandPreview }.GetNewClosure())
    }
    $txtChangeDays = Find-GuiControl 'TxtChangeDays'
    if ($null -ne $txtChangeDays) {
        $txtChangeDays.Add_TextChanged({ Update-CommandPreview }.GetNewClosure())
    }
    $dpSince = Find-GuiControl 'DpChangeSince'
    if ($null -ne $dpSince) {
        $dpSince.Add_SelectedDateChanged({ Update-CommandPreview }.GetNewClosure())
    }
    Update-ChangeCustomEnabled

    # --- SQLite backend -> check Python availability ---
    $rdoSqlite = Find-GuiControl 'RdoBackendSqlite'
    if ($null -ne $rdoSqlite) {
        $rdoSqlite.Add_Checked({
            try {
                $pythonAvailable = $null -ne (Get-Command 'python' -ErrorAction SilentlyContinue) -or
                                   $null -ne (Get-Command 'python3' -ErrorAction SilentlyContinue)
                if (-not $pythonAvailable) {
                    [System.Windows.MessageBox]::Show(
                        'SQLite backend requires Python to be installed and available in PATH. Python was not detected on this system.',
                        'Python Not Found',
                        [System.Windows.MessageBoxButton]::OK,
                        [System.Windows.MessageBoxImage]::Warning
                    )
                }
            }
            catch { }
        }.GetNewClosure())
    }

    # --- DetectStale -> suggest enabling ResolveNested (status bar hint, not forced) ---
    $chkStale = Find-GuiControl 'ChkDetectStale'
    if ($null -ne $chkStale) {
        $chkStale.Add_Checked({
            $chkNested = Find-GuiControl 'ChkResolveNested'
            if ($null -ne $chkNested -and $chkNested.IsChecked -ne $true) {
                Set-StatusMessage -Message 'Tip: Enable Resolve Nested Groups for more complete stale account detection across nested memberships.'
            }
        }.GetNewClosure())
    }

    # --- FromCache -> status bar hint about CachePath requirement ---
    $chkFromCache = Find-GuiControl 'ChkFromCache'
    if ($null -ne $chkFromCache) {
        $chkFromCache.Add_Checked({
            Set-StatusMessage -Message 'FromCache mode: Set a specific Cache Path in the Configuration tab pointing to a JSON cache file. CSV is not required.'
        }.GetNewClosure())
        $chkFromCache.Add_Unchecked({
            Set-StatusMessage -Message 'FromCache disabled. Normal LDAP enumeration mode. CSV file is required.'
        }.GetNewClosure())
    }
}

# ============================================================================
# Reports Tab (report selection + output preview)
# ============================================================================

function Initialize-ReportsTab {
    <#
    .SYNOPSIS
        Wires event handlers for the Reports tab:
        - Update output preview when report checkboxes change
        - Initial output preview population
    #>

    # Wire all report-related checkboxes to update the output preview
    # Includes ChkTrackChanges because it affects output file list (changelog, state)
    $reportCheckboxes = @(
        'ChkAllReports', 'ChkGovernanceReport', 'ChkComplianceReport',
        'ChkExecutiveDashboard', 'ChkLeadershipSummary',
        'ChkExportMembersCsv', 'ChkJsonOnly', 'ChkNoCache', 'ChkSendEmail',
        'ChkTrackChanges'
    )

    foreach ($name in $reportCheckboxes) {
        $ctrl = Find-GuiControl $name
        if ($null -ne $ctrl) {
            $ctrl.Add_Checked({ Update-OutputPreview }.GetNewClosure())
            $ctrl.Add_Unchecked({ Update-OutputPreview }.GetNewClosure())
        }
    }

    # Theme changes also affect preview
    $cmbTheme = Find-GuiControl 'CmbTheme'
    if ($null -ne $cmbTheme) {
        $cmbTheme.Add_SelectionChanged({ Update-OutputPreview }.GetNewClosure())
    }

    # CSV path changes affect output file name prefix
    $txtCsvForPreview = Find-GuiControl 'TxtCsvPath'
    if ($null -ne $txtCsvForPreview) {
        $txtCsvForPreview.Add_TextChanged({ Update-OutputPreview }.GetNewClosure())
    }

    # Initial preview
    Update-OutputPreview
}

function Update-OutputPreview {
    <#
    .SYNOPSIS
        Based on current GUI selections, builds a preview of which output
        files will be generated and displays it in TxtOutputPreview.
    #>

    try {
        $preview = Find-GuiControl 'TxtOutputPreview'
        if ($null -eq $preview) { return }

        $timestamp = (Get-Date).ToString('yyyyMMdd-HHmmss')
        $lines = [System.Collections.Generic.List[string]]::new()

        # Derive output filename prefix from CSV path (matches orchestrator behavior)
        $csvLeaf = 'groups'
        $txtCsvPreview = Find-GuiControl 'TxtCsvPath'
        if ($null -ne $txtCsvPreview -and -not [string]::IsNullOrWhiteSpace($txtCsvPreview.Text)) {
            $csvLeaf = [System.IO.Path]::GetFileNameWithoutExtension($txtCsvPreview.Text)
        }

        # Check if JSON-only mode
        $chkJsonOnly = Find-GuiControl 'ChkJsonOnly'
        $jsonOnly = ($null -ne $chkJsonOnly -and $chkJsonOnly.IsChecked -eq $true)

        # Check if cache is disabled
        $chkNoCache = Find-GuiControl 'ChkNoCache'
        $noCache = ($null -ne $chkNoCache -and $chkNoCache.IsChecked -eq $true)

        # Operational HTML report (always generated unless JSON-only)
        if (-not $jsonOnly) {
            $lines.Add("$csvLeaf-$timestamp.html  (Operational Report)")
        }

        # JSON cache (unless NoCache)
        if (-not $noCache) {
            $lines.Add("$csvLeaf-$timestamp.json  (JSON Cache)")
        }

        # If JSON-only and NoCache, that's a no-op
        if ($jsonOnly -and $noCache) {
            $lines.Clear()
            $lines.Add('(No output files -- both JsonOnly and NoCache are enabled)')
            $preview.Text = ($lines -join "`n")
            return
        }

        # Governance Report
        $chkGov = Find-GuiControl 'ChkGovernanceReport'
        if ($null -ne $chkGov -and $chkGov.IsChecked -eq $true -and -not $jsonOnly) {
            $lines.Add("$csvLeaf-governance-$timestamp.html  (Governance Report)")
        }

        # Compliance Report
        $chkComp = Find-GuiControl 'ChkComplianceReport'
        if ($null -ne $chkComp -and $chkComp.IsChecked -eq $true -and -not $jsonOnly) {
            $lines.Add("$csvLeaf-compliance-$timestamp.html  (Compliance Report)")
        }

        # Executive Dashboard
        $chkExec = Find-GuiControl 'ChkExecutiveDashboard'
        if ($null -ne $chkExec -and $chkExec.IsChecked -eq $true -and -not $jsonOnly) {
            $lines.Add("$csvLeaf-executive-$timestamp.html  (Executive Dashboard)")
        }

        # Leadership Summary
        $chkLead = Find-GuiControl 'ChkLeadershipSummary'
        if ($null -ne $chkLead -and $chkLead.IsChecked -eq $true -and -not $jsonOnly) {
            $lines.Add("$csvLeaf-leadership-$timestamp.html  (Leadership Summary)")
        }

        # Members CSV export
        $chkCsv = Find-GuiControl 'ChkExportMembersCsv'
        if ($null -ne $chkCsv -and $chkCsv.IsChecked -eq $true) {
            $lines.Add("$csvLeaf-members-$timestamp.csv  (Members CSV Export)")
        }

        # Change tracking log
        $chkTrack = Find-GuiControl 'ChkTrackChanges'
        if ($null -ne $chkTrack -and $chkTrack.IsChecked -eq $true) {
            $lines.Add("changelog.jsonl  (Change Log - append)")
            $lines.Add("membership-state.json  (State Snapshot - overwrite)")
        }

        # Email notification
        $chkEmail = Find-GuiControl 'ChkSendEmail'
        if ($null -ne $chkEmail -and $chkEmail.IsChecked -eq $true) {
            $lines.Add("[Email notification will be sent after report generation]")
        }

        if ($lines.Count -eq 0) {
            $preview.Text = 'No output files configured.'
        }
        else {
            $preview.Text = ($lines -join "`n")
        }
    }
    catch {
        # Swallow -- preview is informational
        try {
            $preview = Find-GuiControl 'TxtOutputPreview'
            if ($null -ne $preview) {
                $preview.Text = '(Error generating preview)'
            }
        }
        catch { }
    }
}

# ============================================================================
# File Operations
# ============================================================================

function Open-OutputFile {
    <#
    .SYNOPSIS
        Opens a file with its default application using Start-Process.
    .PARAMETER FilePath
        The full path to the file to open.
    #>
    param(
        [Parameter(Mandatory)]
        [string]$FilePath
    )

    try {
        if (-not (Test-Path $FilePath)) {
            Set-StatusMessage -Message "File not found: $FilePath" -IsWarning
            return
        }

        Start-Process -FilePath $FilePath
        Set-StatusMessage -Message "Opened: $(Split-Path $FilePath -Leaf)"
    }
    catch {
        Set-StatusMessage -Message "Error opening file: $($_.Exception.Message)" -IsError
    }
}

# ============================================================================
# Last-Run State (auto-save / restore)
# ============================================================================

function Save-LastRunState {
    <#
    .SYNOPSIS
        Captures the current GUI state (checkboxes, combos, text fields) and
        writes it to last-run.json in the Config directory. Called automatically
        when the user starts an enumeration.
    #>

    try {
        $state = [ordered]@{}

        # CSV path
        $txtCsv = Find-GuiControl 'TxtCsvPath'
        if ($null -ne $txtCsv) { $state['CsvPath'] = $txtCsv.Text }

        # Checkboxes
        $checkboxNames = @(
            'ChkFuzzyMatch', 'ChkResolveNested', 'ChkDetectStale', 'ChkAnalyzeGaps', 'ChkIncludeManager',
            'ChkIncremental', 'ChkAllowInsecure', 'ChkTrackChanges',
            'ChkGovernanceReport', 'ChkComplianceReport', 'ChkExecutiveDashboard', 'ChkLeadershipSummary',
            'ChkAllReports', 'ChkExportMembersCsv', 'ChkJsonOnly', 'ChkNoCache', 'ChkSendEmail',
            'ChkUnifiedState', 'ChkLegacy', 'ChkFromCache',
            'ChkBaselineReports',
            'ChkBlRoster', 'ChkBlAccessCert', 'ChkBlPrivileged', 'ChkBlSod', 'ChkBlOrphaned',
            'ChkBlInventory', 'ChkBlEmptyStale', 'ChkBlNestedAudit', 'ChkBlExecSummary', 'ChkBlChangeAttest',
            'ChkRcKpiCards', 'ChkRcHeatmap', 'ChkRcTopN', 'ChkRcTree', 'ChkRcDiff', 'ChkRcGroupTable', 'ChkRcRiskFlags', 'ChkRcPrivRisk',
            'ChkRcKpiCardsHalf', 'ChkRcHeatmapHalf', 'ChkRcTopNHalf', 'ChkRcTreeHalf', 'ChkRcDiffHalf', 'ChkRcGroupTableHalf', 'ChkRcRiskFlagsHalf', 'ChkRcPrivRiskHalf',
            'ChkComponentDark'
        )
        foreach ($name in $checkboxNames) {
            $ctrl = Find-GuiControl $name
            if ($null -ne $ctrl) {
                $state[$name] = ($ctrl.IsChecked -eq $true)
            }
        }

        # Advanced text fields
        $advancedTextFields = @('TxtMigratingTo', 'TxtBaselinePath', 'TxtPreviousRunPath', 'TxtAppMappingCsv', 'TxtComponentTitle')
        foreach ($name in $advancedTextFields) {
            $ctrl = Find-GuiControl $name
            if ($null -ne $ctrl -and -not [string]::IsNullOrWhiteSpace($ctrl.Text)) {
                $state[$name] = $ctrl.Text
            }
        }

        # ComboBoxes
        $comboNames = @('CmbPreset', 'CmbTheme', 'CmbChangeType', 'CmbChangePeriod')
        foreach ($name in $comboNames) {
            $val = Get-ComboSelectedText $name
            if ($val) { $state[$name] = $val }
        }

        # Radio buttons
        $rdoSqlite = Find-GuiControl 'RdoBackendSqlite'
        if ($null -ne $rdoSqlite) {
            $state['BackendSqlite'] = ($rdoSqlite.IsChecked -eq $true)
        }

        # Timestamp
        $state['SavedAt'] = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')

        # Write to disk
        $configDir = Join-Path $script:ScriptRoot 'Config'
        if (-not (Test-Path $configDir)) {
            New-Item -Path $configDir -ItemType Directory -Force | Out-Null
        }
        $lastRunPath = Join-Path $configDir 'last-run.json'
        $state | ConvertTo-Json -Depth 2 | Set-Content -Path $lastRunPath -Encoding UTF8
    }
    catch {
        # Non-critical -- never let this fail the run
    }
}

function Restore-LastRunState {
    <#
    .SYNOPSIS
        If last-run.json exists, offers to restore the previous run's GUI state.
        Called during Initialize-GroupEnumeratorGui.
    .OUTPUTS
        $true if state was restored, $false otherwise.
    #>

    try {
        $lastRunPath = Join-Path $script:ScriptRoot 'Config\last-run.json'
        if (-not (Test-Path $lastRunPath)) { return $false }

        $rawJson = Get-Content -Path $lastRunPath -Raw -ErrorAction Stop
        $loaded  = $rawJson | ConvertFrom-Json

        # Show saved timestamp if available
        $savedAt = ''
        if ($null -ne $loaded.SavedAt) { $savedAt = " (saved $($loaded.SavedAt))" }

        $result = [System.Windows.MessageBox]::Show(
            "A previous run configuration was found$savedAt.`n`nRestore the previous settings?",
            'Restore Last Run',
            [System.Windows.MessageBoxButton]::YesNo,
            [System.Windows.MessageBoxImage]::Question
        )

        if ($result -ne [System.Windows.MessageBoxResult]::Yes) { return $false }

        # Restore CSV path
        if ($null -ne $loaded.CsvPath -and -not [string]::IsNullOrWhiteSpace($loaded.CsvPath)) {
            $txtCsv = Find-GuiControl 'TxtCsvPath'
            if ($null -ne $txtCsv) { $txtCsv.Text = [string]$loaded.CsvPath }
        }

        # Restore checkboxes
        $checkboxNames = @(
            'ChkFuzzyMatch', 'ChkResolveNested', 'ChkDetectStale', 'ChkAnalyzeGaps', 'ChkIncludeManager',
            'ChkIncremental', 'ChkAllowInsecure', 'ChkTrackChanges',
            'ChkGovernanceReport', 'ChkComplianceReport', 'ChkExecutiveDashboard', 'ChkLeadershipSummary',
            'ChkAllReports', 'ChkExportMembersCsv', 'ChkJsonOnly', 'ChkNoCache', 'ChkSendEmail',
            'ChkUnifiedState', 'ChkLegacy', 'ChkFromCache',
            'ChkBaselineReports',
            'ChkBlRoster', 'ChkBlAccessCert', 'ChkBlPrivileged', 'ChkBlSod', 'ChkBlOrphaned',
            'ChkBlInventory', 'ChkBlEmptyStale', 'ChkBlNestedAudit', 'ChkBlExecSummary', 'ChkBlChangeAttest',
            'ChkRcKpiCards', 'ChkRcHeatmap', 'ChkRcTopN', 'ChkRcTree', 'ChkRcDiff', 'ChkRcGroupTable', 'ChkRcRiskFlags', 'ChkRcPrivRisk',
            'ChkRcKpiCardsHalf', 'ChkRcHeatmapHalf', 'ChkRcTopNHalf', 'ChkRcTreeHalf', 'ChkRcDiffHalf', 'ChkRcGroupTableHalf', 'ChkRcRiskFlagsHalf', 'ChkRcPrivRiskHalf',
            'ChkComponentDark'
        )
        foreach ($name in $checkboxNames) {
            $prop = $loaded.PSObject.Properties[$name]
            if ($null -ne $prop) {
                $ctrl = Find-GuiControl $name
                if ($null -ne $ctrl) {
                    $ctrl.IsChecked = [bool]$prop.Value
                }
            }
        }

        # Restore advanced text fields
        $advancedTextFields = @('TxtMigratingTo', 'TxtBaselinePath', 'TxtPreviousRunPath', 'TxtAppMappingCsv', 'TxtComponentTitle')
        foreach ($name in $advancedTextFields) {
            $prop = $loaded.PSObject.Properties[$name]
            if ($null -ne $prop -and $null -ne $prop.Value) {
                $ctrl = Find-GuiControl $name
                if ($null -ne $ctrl) {
                    $ctrl.Text = [string]$prop.Value
                }
            }
        }

        # Restore combos
        $comboNames = @('CmbPreset', 'CmbTheme', 'CmbChangeType', 'CmbChangePeriod')
        foreach ($name in $comboNames) {
            $prop = $loaded.PSObject.Properties[$name]
            if ($null -ne $prop -and $null -ne $prop.Value) {
                $ctrl = Find-GuiControl $name
                if ($null -ne $ctrl) {
                    Select-ComboItemByContent -ComboBox $ctrl -Content ([string]$prop.Value)
                }
            }
        }

        # Restore backend radio
        $propSqlite = $loaded.PSObject.Properties['BackendSqlite']
        if ($null -ne $propSqlite) {
            $rdoSqlite = Find-GuiControl 'RdoBackendSqlite'
            $rdoJson   = Find-GuiControl 'RdoBackendJson'
            if ($propSqlite.Value -eq $true) {
                if ($null -ne $rdoSqlite) { $rdoSqlite.IsChecked = $true }
            }
            else {
                if ($null -ne $rdoJson) { $rdoJson.IsChecked = $true }
            }
        }

        Set-StatusMessage -Message "Restored previous run settings$savedAt."
        return $true
    }
    catch {
        # Non-critical
        return $false
    }
}

# ============================================================================
# Change Tracking tab: state DB stats + change explorer
# ============================================================================

function Get-ChangeTrackingDb {
    # Resolve the SQLite state DB path the tool would use (TxtStatePath override,
    # else config/default 'State' under the app root), + the canonical db file.
    $stateDir = $null
    $txtState = Find-GuiControl 'TxtStatePath'
    if ($null -ne $txtState -and -not [string]::IsNullOrWhiteSpace($txtState.Text)) { $stateDir = $txtState.Text.Trim() }
    if ([string]::IsNullOrWhiteSpace($stateDir)) { $stateDir = 'State' }
    if (-not [System.IO.Path]::IsPathRooted($stateDir)) { $stateDir = Join-Path $script:ScriptRoot $stateDir }
    return (Join-Path $stateDir 'group-enumerator.db')
}

function Invoke-ChangeTrackingPy {
    # Run state_db.py <args> and return parsed JSON (or $null). Self-contained so it
    # works in the controller scope without StateDatabase.ps1 being dot-sourced here.
    param([string[]]$PyArgs)
    $py = Get-Command python -ErrorAction SilentlyContinue
    if (-not $py) { $py = Get-Command python3 -ErrorAction SilentlyContinue }
    $script = Join-Path $script:ScriptRoot 'state_db.py'
    if (-not $py -or -not (Test-Path $script)) { return $null }
    try {
        $raw = & $py.Source $script @PyArgs 2>$null
        if (-not $raw) { return $null }
        return ($raw | Out-String | ConvertFrom-Json)
    } catch { return $null }
}

function Get-ChangeTrackingBackend {
    $rdo = Find-GuiControl 'RdoBackendSqlite'
    if ($null -ne $rdo -and $rdo.IsChecked -eq $true) { return 'sqlite' }
    return 'json'
}

function Update-ChangeTrackingStats {
    $set = { param($n, $v) $c = Find-GuiControl $n; if ($null -ne $c) { $c.Text = [string]$v } }
    $backend = Get-ChangeTrackingBackend
    $db = Get-ChangeTrackingDb
    & $set 'TxtCtBackend' $backend
    & $set 'TxtCtDbPath' $db
    if ($backend -ne 'sqlite') {
        foreach ($n in 'TxtCtGroups', 'TxtCtMembers', 'TxtCtDistinct', 'TxtCtChanges', 'TxtCtRuns') { & $set $n 'n/a (JSON backend)' }
        $note = Find-GuiControl 'TxtCtStatsNote'
        if ($null -ne $note) { $note.Text = 'DB stats require the SQLite backend (Configuration tab). The JSON backend stores per-CSV state files instead.' }
        return
    }
    if (-not (Test-Path $db)) {
        foreach ($n in 'TxtCtGroups', 'TxtCtMembers', 'TxtCtDistinct', 'TxtCtRuns') { & $set $n '0' }
        & $set 'TxtCtChanges' 'no DB yet -- run with -TrackChanges'
        return
    }
    $st = Invoke-ChangeTrackingPy -PyArgs @('stats', '--db', $db)
    if ($null -eq $st) { Set-StatusMessage -Message 'Could not read state DB stats (is Python available?).' -IsWarning; return }
    & $set 'TxtCtGroups' $st.Groups
    & $set 'TxtCtMembers' $st.Members
    & $set 'TxtCtDistinct' $st.DistinctMembers
    & $set 'TxtCtChanges' ('+{0} / -{1}' -f $st.ChangelogAdded, $st.ChangelogRemoved)
    & $set 'TxtCtRuns' ('{0} runs / {1} CSV source(s)' -f $st.Runs, $st.CsvSources)
    Set-StatusMessage -Message 'State DB stats refreshed.'
}

function Update-ChangeTrackingExplorer {
    if ((Get-ChangeTrackingBackend) -ne 'sqlite') { Set-StatusMessage -Message 'Change Explorer requires the SQLite backend.' -IsWarning; return }
    $db = Get-ChangeTrackingDb
    if (-not (Test-Path $db)) { Set-StatusMessage -Message 'No state DB yet -- run with -TrackChanges first.' -IsWarning; return }
    $pyArgs = @('query-changes', '--db', $db)
    $csv = Find-GuiControl 'TxtCtCsvFilter'
    if ($null -ne $csv -and -not [string]::IsNullOrWhiteSpace($csv.Text)) { $pyArgs += @('--csv', $csv.Text.Trim()) }
    $rows = @(Invoke-ChangeTrackingPy -PyArgs $pyArgs)

    # Period filter is applied client-side (parsed dates) to avoid string/timezone
    # fragility in a server-side --since comparison.
    $period = Get-ComboSelectedText 'CboCtPeriod'
    $days = switch ($period) { 'Day' { 1 } 'Week' { 7 } 'Month' { 30 } 'Quarter' { 90 } default { 0 } }
    $cutoff = if ($days -gt 0) { (Get-Date).AddDays(-$days) } else { $null }

    $list = New-Object System.Collections.ObjectModel.ObservableCollection[object]
    foreach ($r in $rows) {
        if (-not $r) { continue }
        if ($null -ne $cutoff) {
            $ts = [datetime]::MinValue
            if ([datetime]::TryParse([string]$r.Timestamp, [ref]$ts)) { if ($ts -lt $cutoff) { continue } } else { continue }
        }
        $list.Add([pscustomobject]@{ Timestamp = $r.Timestamp; Action = $r.Action; Domain = $r.Domain; GroupName = $r.GroupName; SamAccountName = $r.SamAccountName; DisplayName = $r.DisplayName })
    }
    $grid = Find-GuiControl 'DgCtChanges'
    if ($null -ne $grid) { $grid.ItemsSource = $list }
    Set-StatusMessage -Message ('Change Explorer: {0} change(s).' -f $list.Count)
}

function Update-ChangeTrackingConsistency {
    # Run the read-only state-DB consistency audit (state_db.py validate) and render the
    # RAG-style verdict into TxtCtConsistency.
    $txt = Find-GuiControl 'TxtCtConsistency'
    if ($null -eq $txt) { return }
    if ((Get-ChangeTrackingBackend) -ne 'sqlite') {
        $txt.Text = 'Consistency audit requires the SQLite backend (set it on the Configuration tab).'
        return
    }
    $db = Get-ChangeTrackingDb
    if (-not (Test-Path $db)) { $txt.Text = 'No state DB yet -- run with -TrackChanges first.'; return }
    $v = Invoke-ChangeTrackingPy -PyArgs @('validate', '--db', $db)
    if ($null -eq $v) {
        $txt.Text = 'Could not run the consistency audit (is Python available?).'
        Set-StatusMessage -Message 'Consistency audit failed to run.' -IsWarning
        return
    }
    $verdict = if ([bool]$v.Ok) { 'PASS' } else { 'FAIL' }
    $lines = New-Object System.Collections.Generic.List[string]
    $lines.Add(('Result: {0}   {1} error(s), {2} warning(s)   schema v{3}' -f $verdict, [int]$v.Errors, [int]$v.Warnings, $v.SchemaVersion))
    foreach ($c in @($v.Checks)) {
        $tag = switch ([string]$c.Severity) { 'ok' { '[ OK ]' } 'warn' { '[WARN]' } 'error' { '[FAIL]' } default { '[????]' } }
        $lines.Add(('{0} {1}  {2}' -f $tag, ([string]$c.Name), $c.Detail))
    }
    $txt.Text = ($lines -join "`r`n")
    $msg = ('State consistency: {0} ({1} error(s), {2} warning(s))' -f $verdict, [int]$v.Errors, [int]$v.Warnings)
    if ([int]$v.Errors -gt 0) { Set-StatusMessage -Message $msg -IsError }
    elseif ([int]$v.Warnings -gt 0) { Set-StatusMessage -Message $msg -IsWarning }
    else { Set-StatusMessage -Message $msg }
}

function Update-PrivilegedRiskGuiCheck {
    # Run the scriptable privileged-access gate against the latest cache and render its
    # RAG output into TxtCtPrivRisk. Read-only; shells to Invoke-PrivilegedRiskCheck.ps1
    # (the GUI is a frontend and does not load the RC modules in-process).
    $txt = Find-GuiControl 'TxtCtPrivRisk'
    if ($null -eq $txt) { return }
    $gate = Join-Path $script:ScriptRoot 'Invoke-PrivilegedRiskCheck.ps1'
    if (-not (Test-Path $gate)) { $txt.Text = 'Invoke-PrivilegedRiskCheck.ps1 not found.'; return }

    # Cache path: the Configuration Cache field if set, else the default Cache dir.
    $cache = Join-Path $script:ScriptRoot 'Cache'
    $cacheCtl = Find-GuiControl 'TxtCachePath'
    if ($null -ne $cacheCtl -and -not [string]::IsNullOrWhiteSpace($cacheCtl.Text)) {
        $v = $cacheCtl.Text.Trim()
        $cache = if ([System.IO.Path]::IsPathRooted($v)) { $v } else { Join-Path $script:ScriptRoot $v }
    }
    if (-not (Test-Path $cache)) { $txt.Text = "No cache found at: $cache  (run an enumeration first)."; return }

    $out = & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $gate -CachePath $cache 2>&1 | Out-String
    $code = $LASTEXITCODE
    $txt.Text = $out.Trim()
    $msg = switch ($code) {
        0 { 'Privileged-access gate: PASS (no at-risk accounts).' }
        2 { 'Privileged-access gate: at-risk accounts found.' }
        default { 'Privileged-access gate: could not run.' }
    }
    if ($code -eq 2) { Set-StatusMessage -Message $msg -IsWarning }
    elseif ($code -eq 0) { Set-StatusMessage -Message $msg }
    else { Set-StatusMessage -Message $msg -IsError }
}

function Update-ChurnReport {
    # Run the membership-churn / re-grant report over the change ledger and render the verdict
    # into TxtCtChurn. Read-only; shells to Invoke-MembershipChurn.ps1 + writes an HTML report.
    $txt = Find-GuiControl 'TxtCtChurn'
    if ($null -eq $txt) { return }
    $churnScript = Join-Path $script:ScriptRoot 'Invoke-MembershipChurn.ps1'
    if (-not (Test-Path $churnScript)) { $txt.Text = 'Invoke-MembershipChurn.ps1 not found.'; return }

    $days = 30
    $dCtl = Find-GuiControl 'TxtCtChurnDays'
    if ($null -ne $dCtl) { $t1 = 0; if ([int]::TryParse([string]$dCtl.Text, [ref]$t1) -and $t1 -ge 1) { $days = $t1 } }
    $min = 1
    $mCtl = Find-GuiControl 'TxtCtChurnMin'
    if ($null -ne $mCtl) { $t2 = 0; if ([int]::TryParse([string]$mCtl.Text, [ref]$t2) -and $t2 -ge 1) { $min = $t2 } }
    $privOnly = $false
    $pCtl = Find-GuiControl 'ChkCtChurnPriv'
    if ($null -ne $pCtl -and $pCtl.IsChecked -eq $true) { $privOnly = $true }

    $db = Get-ChangeTrackingDb
    $stateDir = Split-Path -Parent $db
    $backend = Get-ChangeTrackingBackend

    $outDir = $null
    $oCtl = Find-GuiControl 'TxtOutputDirectory'
    if ($null -ne $oCtl -and -not [string]::IsNullOrWhiteSpace($oCtl.Text)) { $outDir = $oCtl.Text.Trim() }
    if ([string]::IsNullOrWhiteSpace($outDir)) { $outDir = 'Output' }
    if (-not [System.IO.Path]::IsPathRooted($outDir)) { $outDir = Join-Path $script:ScriptRoot $outDir }
    if (-not (Test-Path $outDir)) { New-Item -ItemType Directory -Path $outDir -Force | Out-Null }
    $html = Join-Path $outDir ("membership-churn-{0}.html" -f (Get-Date -Format 'yyyyMMdd-HHmmss'))

    $a = @('-Days', $days, '-MinReGrants', $min, '-OutputHtml', $html)
    if ($privOnly) { $a += '-PrivilegedOnly' }
    if ($backend -eq 'sqlite') { $a += @('-Backend', 'Sqlite', '-DbPath', $db) }
    else { $a += @('-Backend', 'Json', '-StatePath', $stateDir) }

    $out = & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $churnScript @a 2>&1 | Out-String
    $code = $LASTEXITCODE
    $txt.Text = $out.Trim()
    if (Test-Path $html) { try { Start-Process $html } catch { } }
    $msg = switch ($code) {
        0 { 'Churn report: no re-grants in the window.' }
        2 { 'Churn report: re-grant / flapping accounts found.' }
        default { 'Churn report: could not run (see panel).' }
    }
    if ($code -eq 2) { Set-StatusMessage -Message $msg -IsWarning }
    elseif ($code -eq 0) { Set-StatusMessage -Message $msg }
    else { Set-StatusMessage -Message $msg -IsError }
}

function Update-OrgRoleMapReport {
    # Run the Org Role Map (manager->group->count) and render the verdict into TxtOrmResult.
    # Read-only; shells to Invoke-OrgRoleMap.ps1 and opens the HTML. Mode from CmbOrmMode.
    $txt = Find-GuiControl 'TxtOrmResult'
    if ($null -eq $txt) { return }
    $ormScript = Join-Path $script:ScriptRoot 'Invoke-OrgRoleMap.ps1'
    if (-not (Test-Path $ormScript)) { $txt.Text = 'Invoke-OrgRoleMap.ps1 not found.'; return }

    $mode = 'Adhoc'
    $mCtl = Find-GuiControl 'CmbOrmMode'
    if ($null -ne $mCtl -and $null -ne $mCtl.SelectedItem -and $mCtl.SelectedItem.Content) { $mode = [string]$mCtl.SelectedItem.Content }
    $privOnly = $false
    $pCtl = Find-GuiControl 'ChkOrmPriv'
    if ($null -ne $pCtl -and $pCtl.IsChecked -eq $true) { $privOnly = $true }
    $deep = $false
    $dCtl = Find-GuiControl 'ChkOrmDeep'
    if ($null -ne $dCtl -and $dCtl.IsChecked -eq $true) { $deep = $true }

    # Cache: explicit field, else newest *.json under Cache\
    $cache = ''
    $cCtl = Find-GuiControl 'TxtOrmCache'
    if ($null -ne $cCtl -and -not [string]::IsNullOrWhiteSpace($cCtl.Text)) { $cache = $cCtl.Text.Trim() }
    if (-not $cache) {
        $cacheDir = Join-Path $script:ScriptRoot 'Cache'
        if (Test-Path $cacheDir) {
            $latest = Get-ChildItem $cacheDir -Filter '*.json' -File -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 1
            if ($latest) { $cache = $latest.FullName }
        }
    }

    $db = Get-ChangeTrackingDb
    $stateDir = Split-Path -Parent $db
    $orgTree = Join-Path $stateDir 'org-tree.json'

    $outDir = $null
    $oCtl = Find-GuiControl 'TxtOutputDirectory'
    if ($null -ne $oCtl -and -not [string]::IsNullOrWhiteSpace($oCtl.Text)) { $outDir = $oCtl.Text.Trim() }
    if ([string]::IsNullOrWhiteSpace($outDir)) { $outDir = 'Output' }
    if (-not [System.IO.Path]::IsPathRooted($outDir)) { $outDir = Join-Path $script:ScriptRoot $outDir }
    if (-not (Test-Path $outDir)) { New-Item -ItemType Directory -Path $outDir -Force | Out-Null }
    $html = Join-Path $outDir ("org-role-map-{0}-{1}.html" -f $mode.ToLower(), (Get-Date -Format 'yyyyMMdd-HHmmss'))

    $a = @('-Mode', $mode, '-OutputHtml', $html, '-OrgTreePath', $orgTree)
    if ($privOnly) { $a += '-PrivilegedOnly' }
    if ($mode -eq 'Delta') {
        $backend = Get-ChangeTrackingBackend
        if ($backend -eq 'sqlite') { $a += @('-Backend', 'Sqlite', '-DbPath', $db) } else { $a += @('-Backend', 'Json', '-StatePath', $stateDir) }
        if ($cache) { $a += @('-CachePath', $cache) }
    } else {
        if (-not $cache) {
            $txt.Text = 'No snapshot cache found. Run an enumeration with -IncludeAttributes manager (or set a cache path), then retry.'
            Set-StatusMessage -Message 'Org role map: no cache available.' -IsError
            return
        }
        $a += @('-CachePath', $cache)
        # Full + "build full org tree (live)": deep manager-chain walk via LDAP. The CLI derives the
        # DC from the snapshot domain; reuse the GUI's AllowInsecure setting for lab/self-signed DCs.
        if ($mode -eq 'Full' -and $deep) {
            $a += '-BuildOrgTree'
            $ins = Find-GuiControl 'ChkAllowInsecure'
            if ($null -ne $ins -and $ins.IsChecked -eq $true) { $a += '-AllowInsecure' }
        }
    }

    # --- Full-parity optional args ---
    if ($mode -eq 'Delta') {
        $dCtl2 = Find-GuiControl 'TxtOrmDays'
        if ($null -ne $dCtl2 -and -not [string]::IsNullOrWhiteSpace($dCtl2.Text)) { $dv = 0; if ([int]::TryParse($dCtl2.Text.Trim(), [ref]$dv) -and $dv -ge 1) { $a += @('-Days', $dv) } }
    }
    $gCtl = Find-GuiControl 'TxtOrmGroups'
    if ($null -ne $gCtl -and -not [string]::IsNullOrWhiteSpace($gCtl.Text)) {
        $glist = @($gCtl.Text -split '[,;]' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
        if ($glist.Count -gt 0) { $a += '-Groups'; $a += $glist }
    }
    $msCtl = Find-GuiControl 'TxtOrmStale'
    if ($null -ne $msCtl -and -not [string]::IsNullOrWhiteSpace($msCtl.Text)) { $mv = 0; if ([int]::TryParse($msCtl.Text.Trim(), [ref]$mv) -and $mv -ge 0) { $a += @('-MaxStaleDays', $mv) } }
    $dcCtl = Find-GuiControl 'TxtOrmDepth'
    if ($null -ne $dcCtl -and -not [string]::IsNullOrWhiteSpace($dcCtl.Text)) { $cv = 0; if ([int]::TryParse($dcCtl.Text.Trim(), [ref]$cv) -and $cv -ge 1) { $a += @('-DepthCap', $cv) } }
    $odCtl = Find-GuiControl 'TxtOrmOpenDepth'
    if ($null -ne $odCtl -and -not [string]::IsNullOrWhiteSpace($odCtl.Text)) { $ov = 0; if ([int]::TryParse($odCtl.Text.Trim(), [ref]$ov) -and $ov -ge 0) { $a += @('-DefaultOpenDepth', $ov) } }
    $svCtl = Find-GuiControl 'TxtOrmServer'
    if ($null -ne $svCtl -and -not [string]::IsNullOrWhiteSpace($svCtl.Text)) { $a += @('-Server', $svCtl.Text.Trim()) }
    $csvCtl = Find-GuiControl 'ChkOrmCsv'
    if ($null -ne $csvCtl -and $csvCtl.IsChecked -eq $true) { $a += @('-ExportCsv', (Join-Path $outDir ("org-role-map-{0}-{1}.csv" -f $mode.ToLower(), (Get-Date -Format 'yyyyMMdd-HHmmss')))) }
    $failOn = @()
    $f1 = Find-GuiControl 'ChkOrmFailStale';     if ($null -ne $f1 -and $f1.IsChecked -eq $true) { $failOn += 'StaleCache' }
    $f2 = Find-GuiControl 'ChkOrmFailUnmanaged'; if ($null -ne $f2 -and $f2.IsChecked -eq $true) { $failOn += 'UnmanagedBucket' }
    $f3 = Find-GuiControl 'ChkOrmFailPriv';      if ($null -ne $f3 -and $f3.IsChecked -eq $true) { $failOn += 'PrivConcentration' }
    if ($failOn.Count -gt 0) { $a += '-FailOn'; $a += $failOn }
    # Privileged definition: All-groups-privileged + custom regex patterns
    $apCtl = Find-GuiControl 'ChkOrmAllPriv'
    if ($null -ne $apCtl -and $apCtl.IsChecked -eq $true) { $a += '-AllPrivileged' }
    $ppCtl = Find-GuiControl 'TxtOrmPrivPattern'
    if ($null -ne $ppCtl -and -not [string]::IsNullOrWhiteSpace($ppCtl.Text)) {
        $plist = @($ppCtl.Text -split '[,;]' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
        if ($plist.Count -gt 0) { $a += '-PrivilegedPattern'; $a += $plist }
    }

    $out = & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $ormScript @a 2>&1 | Out-String
    $code = $LASTEXITCODE
    $txt.Text = $out.Trim()
    if (Test-Path $html) { try { Start-Process $html } catch { } }
    $msg = switch ($code) {
        0 { "Org role map generated ($mode)." }
        2 { 'Org role map: a -FailOn threshold tripped (see panel).' }
        default { 'Org role map: could not run (see panel).' }
    }
    if ($code -eq 2) { Set-StatusMessage -Message $msg -IsWarning }
    elseif ($code -eq 0) { Set-StatusMessage -Message $msg }
    else { Set-StatusMessage -Message $msg -IsError }
}

function Initialize-ChangeTrackingTab {
    <#
    .SYNOPSIS
        Wires the Change Tracking tab: Refresh Stats + Check Consistency + Privileged Risk +
        Churn / Re-grant + Org Role Map + Query Changes.
    #>
    $btnR = Find-GuiControl 'BtnCtRefresh'
    if ($null -ne $btnR) { $btnR.Add_Click({ Update-ChangeTrackingStats }.GetNewClosure()) }
    $btnV = Find-GuiControl 'BtnCtValidate'
    if ($null -ne $btnV) { $btnV.Add_Click({ Update-ChangeTrackingConsistency }.GetNewClosure()) }
    $btnP = Find-GuiControl 'BtnCtPrivRisk'
    if ($null -ne $btnP) { $btnP.Add_Click({ Update-PrivilegedRiskGuiCheck }.GetNewClosure()) }
    $btnCh = Find-GuiControl 'BtnCtChurn'
    if ($null -ne $btnCh) { $btnCh.Add_Click({ Update-ChurnReport }.GetNewClosure()) }
    $btnOrm = Find-GuiControl 'BtnOrmRun'
    if ($null -ne $btnOrm) { $btnOrm.Add_Click({ Update-OrgRoleMapReport }.GetNewClosure()) }
    $btnQ = Find-GuiControl 'BtnCtQuery'
    if ($null -ne $btnQ) { $btnQ.Add_Click({ Update-ChangeTrackingExplorer }.GetNewClosure()) }
}

# --- END OF GUI CONTROLLER ---
