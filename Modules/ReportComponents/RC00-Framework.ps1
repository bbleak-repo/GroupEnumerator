<#
.SYNOPSIS
    RC00 - Report Components framework (composable reporting engine).

.DESCRIPTION
    Foundation for dynamic / composable reporting. Instead of fixed report
    types, a report is a COMPOSITION of independent components (KPI cards,
    heatmap, drill-down tree, change diff, top-N bars, group table, ...).
    Each component is a self-contained function that takes a uniform Context
    plus per-component Options and returns an HTML *fragment* (a <section>).
    The composer (New-ComposableReport) assembles selected fragments, in the
    requested order and width, inside one shared themed shell.

    Design goals:
      * Reusable  - components are project-agnostic; the library can be lifted
                    into other tools wholesale.
      * Additive  - this engine sits ALONGSIDE the existing fixed reports;
                    nothing is removed or changed. Existing reports remain.
      * Cohesive  - every component draws from one shared CSS token set so a
                    mixed composition reads as a single report.
      * Graceful  - a component whose data prerequisite is unmet renders a
                    small notice instead of failing the whole report.

    Readable / auditable by design (no encoded or hidden PowerShell).
    Self-contained: dot-sources nothing; no hardcoded input/output paths.

.NOTES
    Component contract:
        function New-RC<Name>Component {
            param([hashtable]$Context, [hashtable]$Options = @{}, [hashtable]$Palette)
            ... return '<section class="rc-section"> ... </section>'
        }
        Register-RCComponent -Key '<key>' -DisplayName '...' -Description '...' `
            -FunctionName 'New-RC<Name>Component' -Requires @('GroupResults')
#>

# ---------------------------------------------------------------------------
# Registry (initialised at dot-source; components self-register after).
# ---------------------------------------------------------------------------
$script:RCComponentRegistry = [ordered]@{}

function Register-RCComponent {
    <#
    .SYNOPSIS
        Registers (or overwrites) a report component in the shared registry.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Key,
        [Parameter(Mandatory = $true)][string]$DisplayName,
        [Parameter()][string]$Description = '',
        [Parameter(Mandatory = $true)][string]$FunctionName,
        [Parameter()][string[]]$Requires = @('GroupResults'),
        [Parameter()][hashtable]$DefaultOptions = @{}
    )
    if ($null -eq $script:RCComponentRegistry) { $script:RCComponentRegistry = [ordered]@{} }
    $script:RCComponentRegistry[$Key] = [pscustomobject]@{
        Key            = $Key
        DisplayName    = $DisplayName
        Description    = $Description
        FunctionName   = $FunctionName
        Requires       = @($Requires)
        DefaultOptions = $DefaultOptions
    }
}

function Get-RCComponentRegistry {
    <#
    .SYNOPSIS
        Returns the ordered registry of registered components.
    #>
    [CmdletBinding()]
    param()
    if ($null -eq $script:RCComponentRegistry) { return [ordered]@{} }
    return $script:RCComponentRegistry
}

function Get-RCComponentKeys {
    <#
    .SYNOPSIS
        Returns just the registered component keys (registration order).
    #>
    [CmdletBinding()]
    param()
    return @((Get-RCComponentRegistry).Keys)
}

function Expand-RCComponentList {
    <#
    .SYNOPSIS
        Normalizes a -ReportComponents value into a flat list of component specs.
    .DESCRIPTION
        Accepts BOTH a real array (e.g. PowerShell parsing 'a,b,c' as 3 elements)
        AND a single comma-joined string ('a,b,c', which binds as one element when
        quoted). Splits every element on commas, trims, and drops blanks so the
        quoted / copy-pasted form behaves the same as the unquoted array form.
        Per-element ':half'/':full' width suffixes are preserved.
    #>
    [CmdletBinding()]
    [OutputType([string[]])]
    param([Parameter()][AllowNull()][object[]]$Components)
    if ($null -eq $Components) { return @() }
    return @($Components | ForEach-Object { ([string]$_) -split ',' } | ForEach-Object { $_.Trim() } | Where-Object { $_ })
}

# ---------------------------------------------------------------------------
# Shared helpers (namespaced RC* so they never collide with report modules).
# ---------------------------------------------------------------------------
function ConvertTo-RCHtmlText {
    param([object]$Value)
    if ($null -eq $Value) { return '' }
    $s = [string]$Value
    $s = $s.Replace('&', '&amp;')
    $s = $s.Replace('<', '&lt;')
    $s = $s.Replace('>', '&gt;')
    $s = $s.Replace('"', '&quot;')
    $s = $s.Replace("'", '&#39;')
    return $s
}

function Get-RCProp {
    # Safe property accessor that tolerates missing members under StrictMode AND
    # works for BOTH hashtables/dictionaries (the -FromCache shape) and
    # PSCustomObjects (the live-enumeration shape).
    param([object]$Object, [string]$Name)
    if ($null -eq $Object) { return $null }
    if ($Object -is [System.Collections.IDictionary]) {
        if ($Object.Contains($Name)) { return $Object[$Name] }
        return $null
    }
    $p = $Object.PSObject.Properties[$Name]
    if ($null -eq $p) { return $null }
    return $p.Value
}

function Get-RCDirectCount {
    # Direct *user* member count for a group result: prefer MemberCount, fall back
    # to the Members array length so a composition stays accurate either way.
    #
    # The AD 'member' attribute (and therefore MemberCount / the Members array)
    # includes nested GROUP members alongside users. B09's nested audit reports
    # direct *user* members only (it moves group-type members into the nesting
    # graph). To keep estate totals consistent across the report family, subtract
    # the count of direct nested-group members (NestedGroupDNs) when it is known.
    # For a flat directory NestedGroupDNs is empty/null, so the count is unchanged.
    param([object]$Data)
    if ($null -eq $Data) { return 0 }
    $count = $null
    $mc = Get-RCProp $Data 'MemberCount'
    if ($null -ne $mc) { try { $count = [int]$mc } catch { } }
    if ($null -eq $count) {
        $m = Get-RCProp $Data 'Members'
        if ($null -ne $m) { $count = @($m).Count } else { return 0 }
    }
    $nested = Get-RCProp $Data 'NestedGroupDNs'
    if ($null -ne $nested) {
        $nc = @($nested).Count
        if ($nc -gt 0) { $count = $count - $nc }
    }
    if ($count -lt 0) { $count = 0 }
    return $count
}

# ---------------------------------------------------------------------------
# Theme -> palette. Two themes (light default, dark). Palette is a flat token
# bag so components never hardcode colours; the shell injects them as CSS.
# ---------------------------------------------------------------------------
function Get-RCTheme {
    [CmdletBinding()]
    param([ValidateSet('light', 'dark')][string]$Name = 'light')

    if ($Name -eq 'dark') {
        return @{
            Name       = 'dark'
            PageBg     = '#11161d'
            HeaderBg   = '#0b0f14'
            HeaderText = '#eef2f7'
            HeaderSub  = '#9aa7b4'
            SectionBg  = '#1a212b'
            Text       = '#e6ebf1'
            Muted      = '#93a0ad'
            Border     = '#2b3543'
            Accent     = '#4ea1ff'
            Ok         = '#3fb56b'
            Warn       = '#d8a23a'
            Danger     = '#e0604f'
            TableHead  = '#232c38'
            TableStripe= '#1d2530'
            HeatLow    = '#1b3a2b'
            HeatHigh   = '#46d089'
            BarTrack   = '#232c38'
            BarFill    = '#4ea1ff'
            AddBg      = '#15351f'; AddText = '#5fd388'
            RemBg      = '#3a1b18'; RemText = '#f0897a'
            CardBg     = '#212a36'
        }
    }

    # light (default)
    return @{
        Name       = 'light'
        PageBg     = '#f5f6f8'
        HeaderBg   = '#1f2933'
        HeaderText = '#ffffff'
        HeaderSub  = '#c8d0d8'
        SectionBg  = '#ffffff'
        Text       = '#1f2430'
        Muted      = '#5b6671'
        Border     = '#d9dee3'
        Accent     = '#2563c4'
        Ok         = '#1e6b2c'
        Warn       = '#9a6a00'
        Danger     = '#9b1c0c'
        TableHead  = '#eef1f4'
        TableStripe= '#fafbfc'
        HeatLow    = '#e6f2ea'
        HeatHigh   = '#1e6b2c'
        BarTrack   = '#eef1f4'
        BarFill    = '#2563c4'
        AddBg      = '#e3efe3'; AddText = '#1e6b2c'
        RemBg      = '#fde2dd'; RemText = '#9b1c0c'
        CardBg     = '#f7f9fb'
    }
}

# ---------------------------------------------------------------------------
# Shared CSS. Every component references these classes so a mixed composition
# is visually cohesive. Palette tokens are interpolated in.
# ---------------------------------------------------------------------------
function Get-RCSharedCss {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][hashtable]$Palette)
    $p = $Palette
    return @"
* { box-sizing: border-box; }
body { font-family: Segoe UI, Tahoma, Arial, sans-serif; margin: 0; padding: 24px;
       background: $($p.PageBg); color: $($p.Text); font-size: 14px; }
a { color: $($p.Accent); }
.rc-report-header { background: $($p.HeaderBg); color: $($p.HeaderText);
       padding: 18px 22px; border-radius: 8px; margin-bottom: 18px; }
.rc-report-header h1 { margin: 0 0 4px 0; font-size: 21px; }
.rc-report-header .rc-sub { color: $($p.HeaderSub); font-size: 13px; margin: 0; }
.rc-meta { display: flex; flex-wrap: wrap; gap: 6px 26px; font-size: 12.5px;
       color: $($p.HeaderSub); margin-top: 10px; }
.rc-meta span.k { color: $($p.HeaderSub); opacity: .8; }
.rc-row { display: flex; flex-wrap: wrap; gap: 18px; margin-bottom: 18px; align-items: stretch; }
.rc-col-full { flex: 1 1 100%; }
.rc-col-half { flex: 1 1 360px; min-width: 320px; }
.rc-section { background: $($p.SectionBg); border: 1px solid $($p.Border);
       border-radius: 8px; padding: 16px 18px; height: 100%; }
.rc-section-h { margin: 0 0 4px 0; font-size: 15px; color: $($p.Text); }
.rc-section-d { margin: 0 0 14px 0; font-size: 12px; color: $($p.Muted); }
.rc-note { background: $($p.TableStripe); border: 1px dashed $($p.Border);
       border-radius: 6px; padding: 10px 14px; color: $($p.Muted); font-size: 12.5px; }
.rc-cards { display: flex; flex-wrap: wrap; gap: 12px; }
.rc-card { flex: 1 1 130px; background: $($p.CardBg); border: 1px solid $($p.Border);
       border-radius: 8px; padding: 12px 14px; text-align: center; }
.rc-card .n { font-size: 24px; font-weight: 700; color: $($p.Text);
       font-variant-numeric: tabular-nums; }
.rc-card .l { font-size: 11.5px; color: $($p.Muted); text-transform: uppercase;
       letter-spacing: .03em; margin-top: 3px; }
.rc-card.accent .n { color: $($p.Accent); }
.rc-card.warn .n { color: $($p.Warn); }
.rc-card.danger .n { color: $($p.Danger); }
.rc-card.ok .n { color: $($p.Ok); }
table.rc-table { border-collapse: collapse; width: 100%; font-size: 13px; }
table.rc-table thead th { background: $($p.TableHead); text-align: left;
       padding: 8px 11px; font-size: 11.5px; text-transform: uppercase;
       letter-spacing: .03em; color: $($p.Muted); border-bottom: 2px solid $($p.Border);
       white-space: nowrap; }
table.rc-table tbody td { padding: 7px 11px; border-bottom: 1px solid $($p.Border); }
table.rc-table tbody tr:nth-child(even) { background: $($p.TableStripe); }
table.rc-table .num { text-align: right; font-variant-numeric: tabular-nums; }
.rc-badge { display: inline-block; padding: 1px 8px; border-radius: 10px;
       font-size: 11px; font-weight: 600; }
.rc-badge.ok { background: $($p.AddBg); color: $($p.AddText); }
.rc-badge.warn { background: $($p.TableHead); color: $($p.Warn); }
.rc-badge.danger { background: $($p.RemBg); color: $($p.RemText); }
.rc-badge.neutral { background: $($p.TableHead); color: $($p.Muted); }
.rc-heatmap { display: flex; flex-wrap: wrap; gap: 4px; }
.rc-cell { width: 46px; height: 46px; border-radius: 5px; display: flex;
       align-items: center; justify-content: center; font-size: 12px; font-weight: 700;
       color: #fff; border: 1px solid rgba(0,0,0,.12); overflow: hidden; }
.rc-heat-legend { display: flex; align-items: center; gap: 8px; margin-top: 12px;
       font-size: 11.5px; color: $($p.Muted); }
.rc-heat-bar { width: 140px; height: 12px; border-radius: 6px;
       background: linear-gradient(90deg, $($p.HeatLow), $($p.HeatHigh)); }
.rc-tree { font-size: 13px; }
.rc-tree details { margin: 0 0 4px 0; }
.rc-tree summary { cursor: pointer; padding: 5px 8px; border-radius: 6px;
       background: $($p.TableStripe); border: 1px solid $($p.Border);
       list-style: none; }
.rc-tree summary::-webkit-details-marker { display: none; }
.rc-tree summary .tw { color: $($p.Muted); font-weight: 600; }
.rc-tree .rc-leaf { padding: 4px 8px 4px 26px; border-bottom: 1px solid $($p.Border);
       color: $($p.Text); }
.rc-tree .rc-leaf .c { color: $($p.Muted); font-size: 11.5px; }
.rc-bars { display: flex; flex-direction: column; gap: 7px; }
.rc-bar-row { display: flex; align-items: center; gap: 10px; }
.rc-bar-label { flex: 0 0 200px; font-size: 12.5px; color: $($p.Text);
       white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.rc-bar-track { flex: 1 1 auto; height: 16px; background: $($p.BarTrack);
       border-radius: 8px; overflow: hidden; }
.rc-bar-fill { height: 100%; background: $($p.BarFill); border-radius: 8px; }
.rc-bar-val { flex: 0 0 56px; text-align: right; font-size: 12.5px;
       font-variant-numeric: tabular-nums; color: $($p.Muted); }
.rc-diff { display: flex; flex-direction: column; gap: 6px; }
.rc-diff-row { display: flex; align-items: center; gap: 10px; font-size: 13px;
       padding: 6px 8px; border-bottom: 1px solid $($p.Border); }
.rc-diff-name { flex: 1 1 auto; color: $($p.Text); }
.rc-diff-add { color: $($p.AddText); font-weight: 700; font-variant-numeric: tabular-nums; }
.rc-diff-rem { color: $($p.RemText); font-weight: 700; font-variant-numeric: tabular-nums; }
.rc-footer { margin-top: 20px; padding-top: 12px; border-top: 1px solid $($p.Border);
       font-size: 12px; color: $($p.Muted); }
"@
}

# ---------------------------------------------------------------------------
# Context builder. Uniform data bag passed to every component. Components read
# only what they need; everything is optional except GroupResults.
# ---------------------------------------------------------------------------
function New-RCContext {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][array]$GroupResults,
        [Parameter()][hashtable]$StaleResults = $null,
        [Parameter()][string]$ChangeLogPath = $null,
        [Parameter()][array]$Changes = $null,
        [Parameter()][hashtable]$Metadata = @{},
        [Parameter()][ValidateSet('light', 'dark')][string]$Theme = 'light'
    )

    # Derive the enumerated set once so components agree on member-count totals.
    $enumerated = @($GroupResults | Where-Object {
        $d = Get-RCProp $_ 'Data'
        ($null -ne $d) -and ((Get-RCProp $d 'Skipped') -ne $true)
    })
    # Domains span the whole ESTATE -- include skipped groups' domains so a domain
    # whose groups are all skipped is still represented (otherwise RC06/RC01 and
    # the Summary KPI would under-count domains vs the baseline reports).
    $domains = @($GroupResults | ForEach-Object {
        Get-RCProp (Get-RCProp $_ 'Data') 'Domain'
    } | Where-Object { $_ } | Sort-Object -Unique)

    return @{
        GroupResults  = @($GroupResults)
        Enumerated    = $enumerated
        StaleResults  = $StaleResults
        ChangeLogPath = $ChangeLogPath
        Changes       = $Changes
        Domains       = $domains
        IsCrossDomain = ($domains.Count -ge 2)
        Theme         = $Theme
        Metadata      = $Metadata
    }
}

# ---------------------------------------------------------------------------
# Requirement check: is a component's data prerequisite satisfied by Context?
# ---------------------------------------------------------------------------
function Test-RCRequirement {
    param([hashtable]$Context, [string]$Requirement)
    # Use Get-RCProp for StrictMode-safe access in case a caller hand-builds a
    # Context missing some keys (New-RCContext always populates them).
    switch ($Requirement) {
        'GroupResults' { return ($null -ne (Get-RCProp $Context 'GroupResults')) }
        'StaleResults' { return ($null -ne (Get-RCProp $Context 'StaleResults')) }
        'ChangeLog' {
            $rcChanges = Get-RCProp $Context 'Changes'
            if ($rcChanges -and @($rcChanges).Count -gt 0) { return $true }
            $rcClp = Get-RCProp $Context 'ChangeLogPath'
            return ($rcClp -and (Test-Path -LiteralPath $rcClp))
        }
        default { return $true }
    }
}

# ---------------------------------------------------------------------------
# Component spec parser. Accepts a plain key ('heatmap'), a key:width string
# ('heatmap:half'), or a hashtable @{ Key; Options; Width }.
# ---------------------------------------------------------------------------
function ConvertTo-RCComponentSpec {
    param([object]$Item)

    if ($Item -is [hashtable]) {
        $key = [string]$Item['Key']
        $width = if ($Item.ContainsKey('Width')) { [string]$Item['Width'] } else { 'full' }
        $opts = if ($Item.ContainsKey('Options') -and $Item['Options'] -is [hashtable]) { $Item['Options'] } else { @{} }
    } else {
        $raw = [string]$Item
        $key = $raw; $width = 'full'
        if ($raw -match '^\s*([^:]+):(half|full)\s*$') {
            $key = $Matches[1].Trim(); $width = $Matches[2].ToLower()
        } else {
            $key = $raw.Trim()
        }
        $opts = @{}
    }
    if ($width -ne 'half') { $width = 'full' }
    return [pscustomobject]@{ Key = $key; Width = $width; Options = $opts }
}

# ---------------------------------------------------------------------------
# Composer. Assembles selected components, in order and width, into one shell.
# ---------------------------------------------------------------------------
function New-ComposableReport {
    <#
    .SYNOPSIS
        Renders a composable HTML report from an ordered list of components.

    .PARAMETER Components
        Ordered list. Each item is a key ('heatmap'), a 'key:half'/'key:full'
        string, or @{ Key='heatmap'; Width='half'; Options=@{...} }. Order is
        top-to-bottom; consecutive half-width components pair side-by-side.

    .PARAMETER Context
        Uniform data bag from New-RCContext.

    .PARAMETER Title
        Report title (header).

    .PARAMETER Theme
        'light' (default) or 'dark'.

    .PARAMETER OutputPath
        Destination .html file path.

    .OUTPUTS
        The output path (string).
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)][array]$Components,
        [Parameter(Mandatory = $true)][hashtable]$Context,
        [Parameter()][string]$Title = 'Composable Group Report',
        [Parameter()][ValidateSet('light', 'dark')][string]$Theme = 'light',
        [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string]$OutputPath
    )

    Set-StrictMode -Version 2.0

    $palette  = Get-RCTheme -Name $Theme
    $registry = Get-RCComponentRegistry

    # ---- Render each requested component to a fragment ----
    $fragments = New-Object System.Collections.Generic.List[object]
    foreach ($item in $Components) {
        $spec = ConvertTo-RCComponentSpec -Item $item
        if ([string]::IsNullOrWhiteSpace($spec.Key)) { continue }

        $entry = if ($registry.Contains($spec.Key)) { $registry[$spec.Key] } else { $null }

        if ($null -eq $entry) {
            $fragments.Add([pscustomobject]@{
                Width = $spec.Width
                Html  = '<section class="rc-section"><div class="rc-note">Unknown component: <strong>' + (ConvertTo-RCHtmlText $spec.Key) + '</strong> (not registered).</div></section>'
            })
            continue
        }

        # Requirement gate -> graceful notice rather than a hard failure.
        $missing = @($entry.Requires | Where-Object { -not (Test-RCRequirement -Context $Context -Requirement $_) })
        if ($missing.Count -gt 0) {
            $fragments.Add([pscustomobject]@{
                Width = $spec.Width
                Html  = '<section class="rc-section"><h2 class="rc-section-h">' + (ConvertTo-RCHtmlText $entry.DisplayName) + '</h2><div class="rc-note">Not rendered &mdash; requires ' + (ConvertTo-RCHtmlText ($missing -join ', ')) + '. (e.g. run with -DetectStale or after change tracking has data.)</div></section>'
            })
            continue
        }

        $opts = @{}
        if ($entry.DefaultOptions -is [hashtable]) { foreach ($k in $entry.DefaultOptions.Keys) { $opts[$k] = $entry.DefaultOptions[$k] } }
        if ($spec.Options -is [hashtable]) { foreach ($k in $spec.Options.Keys) { $opts[$k] = $spec.Options[$k] } }

        try {
            $html = & $entry.FunctionName -Context $Context -Options $opts -Palette $palette
        } catch {
            $html = '<section class="rc-section"><h2 class="rc-section-h">' + (ConvertTo-RCHtmlText $entry.DisplayName) + '</h2><div class="rc-note">Component error: ' + (ConvertTo-RCHtmlText ([string]$_)) + '</div></section>'
        }
        $fragments.Add([pscustomobject]@{ Width = $spec.Width; Html = [string]$html })
    }

    # ---- Lay out fragments: pack consecutive half-width into 2-col rows ----
    $body = New-Object System.Text.StringBuilder
    $i = 0
    while ($i -lt $fragments.Count) {
        $f = $fragments[$i]
        if ($f.Width -eq 'half' -and ($i + 1) -lt $fragments.Count -and $fragments[$i + 1].Width -eq 'half') {
            $g = $fragments[$i + 1]
            [void]$body.AppendLine('<div class="rc-row">')
            [void]$body.AppendLine('<div class="rc-col-half">' + $f.Html + '</div>')
            [void]$body.AppendLine('<div class="rc-col-half">' + $g.Html + '</div>')
            [void]$body.AppendLine('</div>')
            $i += 2
        } else {
            $cls = if ($f.Width -eq 'half') { 'rc-col-half' } else { 'rc-col-full' }
            [void]$body.AppendLine('<div class="rc-row"><div class="' + $cls + '">' + $f.Html + '</div></div>')
            $i += 1
        }
    }

    # ---- Shell ----
    $asOf      = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss zzz')
    $tEsc      = ConvertTo-RCHtmlText $Title
    $compCount = $fragments.Count
    $grpCount  = @($Context.GroupResults).Count
    $domCount  = @($Context.Domains).Count

    $sb = New-Object System.Text.StringBuilder
    [void]$sb.AppendLine('<!DOCTYPE html>')
    [void]$sb.AppendLine('<html lang="en">')
    [void]$sb.AppendLine('<head>')
    [void]$sb.AppendLine('<meta charset="utf-8">')
    [void]$sb.AppendLine('<meta name="viewport" content="width=device-width, initial-scale=1">')
    [void]$sb.AppendLine(('<title>{0}</title>' -f $tEsc))
    [void]$sb.AppendLine('<style>')
    [void]$sb.AppendLine((Get-RCSharedCss -Palette $palette))
    [void]$sb.AppendLine('</style>')
    [void]$sb.AppendLine('</head>')
    [void]$sb.AppendLine('<body>')
    [void]$sb.AppendLine('<div class="rc-report-header">')
    [void]$sb.AppendLine(('<h1>{0}</h1>' -f $tEsc))
    [void]$sb.AppendLine('<p class="rc-sub">Composable group report &mdash; assembled from selected components.</p>')
    [void]$sb.AppendLine('<div class="rc-meta">')
    [void]$sb.AppendLine(('<div><span class="k">As of:</span> {0}</div>' -f (ConvertTo-RCHtmlText $asOf)))
    [void]$sb.AppendLine(('<div><span class="k">Groups:</span> {0}</div>' -f $grpCount))
    [void]$sb.AppendLine(('<div><span class="k">Domains:</span> {0}</div>' -f $domCount))
    [void]$sb.AppendLine(('<div><span class="k">Components:</span> {0}</div>' -f $compCount))
    [void]$sb.AppendLine('</div>')
    [void]$sb.AppendLine('</div>')
    [void]$sb.Append($body.ToString())
    [void]$sb.AppendLine('<div class="rc-footer">Numbers-only by default: individual account identities appear only where a component is explicitly expanded. Generated by Group Enumerator composable reporting.</div>')
    [void]$sb.AppendLine('</body>')
    [void]$sb.AppendLine('</html>')

    # ---- Write (UTF-8, no BOM) ----
    $outDir = Split-Path -Parent $OutputPath
    if ($outDir -and -not (Test-Path -LiteralPath $outDir)) {
        New-Item -ItemType Directory -Path $outDir -Force | Out-Null
    }
    $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($OutputPath, $sb.ToString(), $utf8NoBom)

    return $OutputPath
}
