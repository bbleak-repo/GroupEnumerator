<#
.SYNOPSIS
    Shared, accessible theming for the baseline (B0x) HTML reports.
.DESCRIPTION
    One place that defines the report colour system as CSS custom properties, with a LIGHT and
    a DARK palette, every pair verified to meet WCAG 2.1 AA contrast (Tests/Test-ReportTheme.ps1
    computes the ratios). Theme selection:
      * default LIGHT;
      * follows the viewer's OS via @media (prefers-color-scheme: dark) UNLESS the user has
        manually chosen a theme;
      * a toggle button sets :root[data-theme="light|dark"] and persists the choice in
        localStorage (key 'ge-report-theme');
      * @media print FORCES light so PDFs / printed evidence are always print-correct.

    Reports include Get-GEReportThemeCss in their <style>, reference the var(--...) tokens for
    every colour, drop Get-GEReportThemeToggleHtml at the top of <body>, and append
    Get-GEReportThemeScript before </body>. Badges are SOLID (own background + light/dark ink)
    so they are self-contained and AA in both themes without per-theme overrides.
#>

function Get-GEReportThemePalette {
    # Returns @{ Light=@{token=hex}; Dark=@{token=hex} }. Single source of truth so the tests
    # can verify contrast directly from the same data the CSS is built from.
    [OutputType([hashtable])]
    param()
    return @{
        Light = [ordered]@{
            'bg'              = '#eceef1'   # page background (dimmed for less glare + clearer card lift)
            'surface'         = '#fbfbfa'   # cards / table -- off-white "paper" (not pure #fff; text still AAA)
            'surface-alt'     = '#eef1f5'   # subtle header row / code
            'ink'             = '#1b1f24'   # primary text on surface/bg
            'muted'           = '#5b6270'   # secondary text (AA on surface AND bg)
            'line'            = '#d7dbe2'   # borders (decorative divider)
            'accent'          = '#1f4e79'   # links / section accents
            'header-bg'       = '#1f4e79'   # report header band (white ink)
            'row-crit-bg'     = '#fbe4e1'   # critical row tint (deepened to stay visible on off-white)
            'row-warn-bg'     = '#fdeecb'   # warning row tint (deepened to stay visible on off-white)
            'row-low-bg'      = '#eef2e3'   # low-severity row tint (pale olive)
            'crit'            = '#94403b'   # critical accent -- muted brick (desaturated, not signal-red)
            'warn'            = '#8a5200'   # warning accent
            'low'             = '#4d6b34'   # low-severity accent -- muddy olive (distinct hue, not signal-green)
            'ok'              = '#1a7f37'   # ok accent
        }
        Dark = [ordered]@{
            'bg'              = '#15191f'   # lifted off near-black (less halation, better elevation)
            'surface'         = '#1c222b'   # lighter surface tint = elevation by tint, not shadow
            'surface-alt'     = '#232c38'
            'ink'             = '#dfe6ee'   # softened from pure-ish white to ease glare on dark
            'muted'           = '#aab1c0'
            'line'            = '#30363d'
            'accent'          = '#7fb3e6'   # desaturated a step so the blue stops vibrating on dark
            'header-bg'       = '#26405a'   # marginally lighter band to match lifted surfaces
            'row-crit-bg'     = '#321a1c'   # dark critical tint (tracks lighter surface; light ink on top)
            'row-warn-bg'     = '#2e2614'   # dark warning tint (tracks lighter surface; light ink on top)
            'row-low-bg'      = '#23291a'   # dark low-severity tint (dark olive)
            'crit'            = '#d98a82'   # muted salmon (calmer than a hot red on dark)
            'warn'            = '#d9a544'   # calmer amber
            'low'             = '#9ab57f'   # low-severity accent -- sage (muted, distinct from ok-green)
            'ok'              = '#5cbf6f'   # slightly desaturated green
        }
    }
}

function ConvertTo-GEThemeVarBlock {
    param([System.Collections.IDictionary]$Map, [string]$Indent = '  ')
    $sb = New-Object System.Text.StringBuilder
    foreach ($k in $Map.Keys) { [void]$sb.AppendLine("${Indent}--${k}: $($Map[$k]);") }
    return $sb.ToString().TrimEnd()
}

function Get-GEReportThemeBadgeCss {
    <#
    .SYNOPSIS  The solid, theme-independent status badge tokens (AA on their own bg in any theme).
               Emitted once inside :root; reports reference var(--badge-*-bg/ink). Reusable so every
               report shares ONE badge vocabulary regardless of its local palette names.
    #>
    [OutputType([string])]
    param([string]$Indent = '  ')
    return @"
${Indent}/* Solid, self-contained status badges (AA in any context, both themes) */
${Indent}--badge-crit-bg: #94403b; --badge-crit-ink: #ffffff;   /* 6.87:1 -- muted brick */
${Indent}--badge-warn-bg: #8a5200; --badge-warn-ink: #ffffff;   /* 6.4:1 */
${Indent}--badge-low-bg:  #4d6b34; --badge-low-ink:  #ffffff;   /* 6.05:1 -- muddy olive */
${Indent}--badge-ok-bg:   #1a7f37; --badge-ok-ink:   #ffffff;   /* 5.08:1 */
"@
}

function Get-GEThemedRootCss {
    <#
    .SYNOPSIS
        Emit the full runtime-theming machinery for ANY report's own light/dark token maps:
        light defaults in :root, dark via BOTH :root[data-theme="dark"] and
        @media (prefers-color-scheme: dark) (so it follows the OS unless the viewer overrides),
        @media print forcing the LIGHT palette, plus the floating toggle-button style.

        The reusable core: a report defines two hashtables (token->hex) and calls this rather than
        hand-rolling the prefers/data-theme/print plumbing. The canonical accessible palette
        (Get-GEReportThemePalette) is just one caller; bespoke reports pass their own maps.
    .PARAMETER Light / Dark
        Ordered hashtables of CSS custom-property name (without leading --) to hex.
    .PARAMETER ExtraRootCss
        Extra lines injected into :root only (e.g. the shared solid badge tokens) -- things that
        are theme-independent and so need no dark/print override.
    #>
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)][System.Collections.IDictionary]$Light,
        [Parameter(Mandatory = $true)][System.Collections.IDictionary]$Dark,
        [string]$ExtraRootCss = ''
    )
    $l = ConvertTo-GEThemeVarBlock -Map $Light
    $d = ConvertTo-GEThemeVarBlock -Map $Dark
    $extra = if ($ExtraRootCss) { "`n" + $ExtraRootCss } else { '' }
    return @"
/* ===== Shared accessible theme (B00) ===== */
:root {
$l$extra
}
:root[data-theme="dark"] {
$d
}
@media (prefers-color-scheme: dark) {
  :root:not([data-theme="light"]) {
$d
  }
}
@media print {
  /* Evidence/PDF is always print-correct: force the light palette regardless of screen theme */
  :root, :root[data-theme="dark"] {
$l
  }
  .theme-toggle, .no-print { display: none !important; }
}
/* Floating theme toggle (screen only). Fallbacks so it styles even when a report names its
   surface --card/--panel rather than --surface. */
.theme-toggle {
  position: fixed; top: 12px; right: 14px; z-index: 1000;
  font: 600 12px/1 -apple-system, Segoe UI, Roboto, Arial, sans-serif;
  padding: 7px 12px; border-radius: 6px; cursor: pointer;
  background: var(--surface, var(--card, var(--panel, #ffffff)));
  color: var(--ink, #1b1f24);
  border: 1px solid var(--line, #d7dbe2);
  box-shadow: 0 1px 4px rgba(0,0,0,.18);
}
.theme-toggle:hover { border-color: var(--accent, #1f4e79); }
"@
}

function Get-GEReportThemeCss {
    <#
    .SYNOPSIS  The canonical accessible theme layer (palette + badges + toggle + print).
               Thin caller of Get-GEThemedRootCss with the audited palette + shared badges.
    #>
    [OutputType([string])]
    param()
    $p = Get-GEReportThemePalette
    return Get-GEThemedRootCss -Light $p.Light -Dark $p.Dark -ExtraRootCss (Get-GEReportThemeBadgeCss)
}

function Get-GEReportThemeToggleHtml {
    [OutputType([string])]
    param()
    return '<button id="theme-toggle" class="theme-toggle no-print" type="button" aria-label="Toggle dark or light theme">&#9728; Theme</button>'
}

function Get-GEReportThemeScript {
    [OutputType([string])]
    param()
    return @'
<script>
(function(){
  var root = document.documentElement;
  try { var s = localStorage.getItem('ge-report-theme'); if (s === 'dark' || s === 'light') root.setAttribute('data-theme', s); } catch (e) {}
  function current(){
    var a = root.getAttribute('data-theme');
    if (a === 'dark' || a === 'light') return a;
    return (window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches) ? 'dark' : 'light';
  }
  var btn = document.getElementById('theme-toggle');
  function label(){ if (btn) btn.innerHTML = (current() === 'dark') ? '&#9728; Light' : '&#9789; Dark'; }
  if (btn) btn.addEventListener('click', function(){
    var next = (current() === 'dark') ? 'light' : 'dark';
    root.setAttribute('data-theme', next);
    try { localStorage.setItem('ge-report-theme', next); } catch (e) {}
    label();
  });
  label();
})();
</script>
'@
}
