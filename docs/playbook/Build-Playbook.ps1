#Requires -Version 5.1
<#
.SYNOPSIS
    Build self-contained HTML guides from the playbook Markdown (the source of truth).

.DESCRIPTION
    Dependency-free Markdown -> HTML converter (no pandoc, no CDN, no external CSS/JS).
    Emits, into .\html\:
      cli-guide.html  = 00-foundations.md + cli-playbook.md
      gui-guide.html  = 00-foundations.md + gui-playbook.md
      index.html      = landing page linking both
    Each guide is ONE self-contained file (embedded CSS + a sticky TOC sidebar), matching
    the tool's own audit-tier "no external references" report ethos.

    Defensive by design:
      * Source .md is read as UTF-8 (BOM-aware) -- NOT PowerShell 5.1's ANSI default,
        which would double-encode curly quotes / dashes / dots into mojibake.
      * Output is ASCII-safe: every non-ASCII character becomes a numeric HTML entity,
        so the file renders identically regardless of how it is served or opened.
      * '&' is escaped entity-safely (existing &entity; are not double-escaped).
      * A post-build self-check warns on mojibake signatures or stray non-ASCII.

    The .md files remain authoritative; re-run this after editing them.

.EXAMPLE
    powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Build-Playbook.ps1
#>
[CmdletBinding()]
param([Parameter()][string]$OutDir)

$ErrorActionPreference = 'Stop'
$here = $PSScriptRoot
if (-not $OutDir) { $OutDir = Join-Path $here 'html' }
if (-not (Test-Path $OutDir)) { New-Item -ItemType Directory -Path $OutDir -Force | Out-Null }

# ---------------------------------------------------------------------------
# Escapers
# ---------------------------------------------------------------------------
function Escape-Html { param([string]$s, [switch]$Code)
    # In prose, leave valid &entity; intact; in code, escape every '&' literally.
    if ($Code) { $s = $s -replace '&', '&amp;' }
    else       { $s = [regex]::Replace($s, '&(?![#A-Za-z0-9]+;)', '&amp;') }
    return ($s -replace '<', '&lt;' -replace '>', '&gt;')
}
function ConvertTo-AsciiSafe { param([string]$s)
    # Replace any char outside printable-ASCII (keep tab/newline/CR) with a numeric
    # HTML entity. Guarantees a pure-ASCII file that renders correctly everywhere.
    return [regex]::Replace($s, '[^\x09\x0A\x0D\x20-\x7E]', { param($m) '&#' + ([int][char]$m.Value[0]) + ';' })
}

# ---------------------------------------------------------------------------
# Inline formatting: code spans, bold, links. HTML-escapes everything else.
# ---------------------------------------------------------------------------
function Convert-Inline {
    param([string]$s)
    $codes = New-Object System.Collections.Generic.List[string]
    $nul = [char]0
    $s = [regex]::Replace($s, '`([^`]+)`', { param($m) $codes.Add($m.Groups[1].Value); "$nul$($codes.Count-1)$nul" })
    $s = Escape-Html $s
    $s = [regex]::Replace($s, '\*\*([^*]+)\*\*', '<strong>$1</strong>')
    $s = [regex]::Replace($s, '\[([^\]]+)\]\(([^)]+)\)', '<a href="$2">$1</a>')
    $s = [regex]::Replace($s, "$nul(\d+)$nul", { param($m) '<code>' + (Escape-Html ($codes[[int]$m.Groups[1].Value]) -Code) + '</code>' })
    return $s
}

function Get-Slug { param([string]$t)
    $s = ($t -replace '<[^>]+>', '').ToLowerInvariant() -replace '[^a-z0-9]+', '-'
    return $s.Trim('-')
}
function Convert-Cells { param([string]$row)
    $r = $row.Trim(); if ($r.StartsWith('|')) { $r = $r.Substring(1) }; if ($r.EndsWith('|')) { $r = $r.Substring(0, $r.Length - 1) }
    return ($r -split '\|') | ForEach-Object { $_.Trim() }
}

# ---------------------------------------------------------------------------
# Block converter (line state-machine). Returns @{ Html; Toc }
# ---------------------------------------------------------------------------
function Convert-Markdown {
    param([string]$md)
    $lines = $md -replace "`r", "" -split "`n"
    $out = New-Object System.Text.StringBuilder
    $toc = New-Object System.Collections.Generic.List[object]
    $para = New-Object System.Collections.Generic.List[string]
    function Flush-Para { if ($para.Count) { [void]$out.AppendLine('<p>' + (Convert-Inline ($para -join ' ')) + '</p>'); $para.Clear() } }

    $i = 0
    while ($i -lt $lines.Count) {
        $line = $lines[$i]

        if ($line -match '^\s*```') {
            Flush-Para; $i++
            $code = New-Object System.Collections.Generic.List[string]
            while ($i -lt $lines.Count -and $lines[$i] -notmatch '^\s*```') { $code.Add($lines[$i]); $i++ }
            if ($i -lt $lines.Count) { $i++ }   # closing fence (guard EOF)
            [void]$out.AppendLine('<pre><code>' + (Escape-Html ($code -join "`n") -Code) + '</code></pre>')
            continue
        }
        if ($line -match '^(#{1,6})\s+(.*)$') {
            Flush-Para
            $lvl = $Matches[1].Length; $txt = $Matches[2].TrimEnd('#', ' ')
            $slug = Get-Slug $txt
            if ($lvl -le 3) { $toc.Add([pscustomobject]@{ Level = $lvl; Text = (Convert-Inline $txt); Slug = $slug }) }
            [void]$out.AppendLine("<h$lvl id=`"$slug`">$(Convert-Inline $txt)</h$lvl>")
            $i++; continue
        }
        if ($line -match '^\s*---+\s*$') { Flush-Para; [void]$out.AppendLine('<hr>'); $i++; continue }
        if ($line -match '\|' -and $i + 1 -lt $lines.Count -and $lines[$i + 1] -match '^\s*\|?[\s:|-]*-[\s:|-]*\|?\s*$' -and $lines[$i + 1] -match '-') {
            Flush-Para
            $head = Convert-Cells $line; $i += 2
            [void]$out.AppendLine('<table><thead><tr>')
            foreach ($h in $head) { [void]$out.Append("<th>$(Convert-Inline $h)</th>") }
            [void]$out.AppendLine('</tr></thead><tbody>')
            while ($i -lt $lines.Count -and $lines[$i] -match '\|' -and $lines[$i].Trim() -ne '') {
                $cells = Convert-Cells $lines[$i]
                [void]$out.Append('<tr>')
                foreach ($c in $cells) { [void]$out.Append("<td>$(Convert-Inline $c)</td>") }
                [void]$out.AppendLine('</tr>'); $i++
            }
            [void]$out.AppendLine('</tbody></table>')
            continue
        }
        if ($line -match '^\s*>\s?(.*)$') {
            Flush-Para
            $q = New-Object System.Collections.Generic.List[string]
            while ($i -lt $lines.Count -and $lines[$i] -match '^\s*>\s?(.*)$') { $q.Add($Matches[1]); $i++ }
            [void]$out.AppendLine('<blockquote>' + (Convert-Inline ($q -join ' ')) + '</blockquote>')
            continue
        }
        if ($line -match '^\s*([-*]|\d+\.)\s+(.*)$') {
            Flush-Para
            $tag = if ($Matches[1] -match '\d') { 'ol' } else { 'ul' }
            [void]$out.AppendLine("<$tag>")
            while ($i -lt $lines.Count -and $lines[$i] -match '^\s*([-*]|\d+\.)\s+(.*)$') {
                [void]$out.AppendLine('<li>' + (Convert-Inline $Matches[2]) + '</li>'); $i++
            }
            [void]$out.AppendLine("</$tag>")
            continue
        }
        if ($line.Trim() -eq '') { Flush-Para; $i++; continue }
        $para.Add($line.Trim()); $i++
    }
    Flush-Para
    return @{ Html = $out.ToString(); Toc = $toc }
}

# ---------------------------------------------------------------------------
# Self-contained page shell (embedded CSS + tiny scroll-spy JS).
# ---------------------------------------------------------------------------
$css = @'
*{box-sizing:border-box}
:root{--bg:#fff;--ink:#1f2430;--muted:#5b6671;--accent:#2563c4;--line:#dfe3e8;--codebg:#f3f4f6;--side:#f7f9fb;--head:#eef1f5}
body{margin:0;font:15px/1.6 -apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;color:var(--ink);background:var(--bg)}
a{color:var(--accent);text-decoration:none}a:hover{text-decoration:underline}
.topbar{background:#1f2933;color:#fff;padding:14px 24px}
.topbar h1{margin:0;font-size:18px}.topbar .sub{color:#c8d0d8;font-size:12.5px;margin-top:3px}
.topbar .gen{color:#9aa7b4;font-size:11.5px;margin-top:2px}
.wrap{display:flex;align-items:flex-start}
.nav{width:280px;flex:0 0 280px;position:sticky;top:0;height:100vh;overflow:auto;background:var(--side);border-right:1px solid var(--line);padding:18px 14px;font-size:13px}
.nav .t{font-weight:700;text-transform:uppercase;letter-spacing:.04em;color:var(--muted);font-size:11px;margin:0 0 8px}
.nav a{display:block;color:var(--ink);padding:4px 8px;border-radius:6px;border-left:2px solid transparent}
.nav a.lvl3{padding-left:20px;color:var(--muted);font-size:12.5px}
.nav a:hover{background:#eef1f5;text-decoration:none}
.nav a.active{color:var(--accent);border-left-color:var(--accent);background:#eaf0fb;font-weight:600}
.content{flex:1 1 auto;min-width:0;max-width:940px;padding:28px 38px}
h1,h2,h3,h4{line-height:1.3;scroll-margin-top:16px}
h1{font-size:26px;margin:.2em 0 .6em}
h2{font-size:20px;margin:1.7em 0 .5em;padding-bottom:6px;border-bottom:1px solid var(--line)}
h3{font-size:16px;margin:1.3em 0 .4em}h4{font-size:14px;margin:1.1em 0 .3em}
p{margin:.6em 0}
code{font-family:Consolas,Menlo,monospace;background:var(--codebg);padding:1.5px 5px;border-radius:4px;font-size:90%}
pre{background:var(--codebg);border:1px solid var(--line);border-radius:8px;padding:12px 14px;overflow-x:auto}
pre code{background:none;padding:0;font-size:13px;line-height:1.5}
table{border-collapse:collapse;width:100%;margin:1em 0;font-size:13.5px;display:block;overflow-x:auto}
th,td{border:1px solid var(--line);padding:7px 10px;text-align:left;vertical-align:top}
th{background:var(--head);font-size:12px;text-transform:uppercase;letter-spacing:.02em;color:var(--muted);white-space:nowrap}
tbody tr:nth-child(even){background:#fafbfc}
blockquote{margin:1em 0;padding:10px 16px;border-left:4px solid var(--accent);background:#f5f8fd;color:var(--ink);border-radius:0 6px 6px 0}
blockquote p{margin:.3em 0}
hr{border:0;border-top:1px solid var(--line);margin:1.6em 0}
ul,ol{margin:.6em 0;padding-left:1.4em}li{margin:.25em 0}
.foot{margin-top:36px;padding-top:14px;border-top:1px solid var(--line);color:var(--muted);font-size:12.5px}
@media(max-width:820px){.wrap{display:block}.nav{width:auto;flex:none;position:static;height:auto;border-right:0;border-bottom:1px solid var(--line)}.content{padding:18px}}
@media print{.nav,.topbar .gen{display:none}.wrap{display:block}.content{max-width:none;padding:0}a{color:inherit}pre,table,blockquote{break-inside:avoid}}
'@

$spy = @'
<script>
(function(){var links={};document.querySelectorAll('.nav a').forEach(function(a){links[a.getAttribute('href').slice(1)]=a;});
function set(id){for(var k in links)links[k].classList.remove('active');if(links[id])links[id].classList.add('active');}
var hs=[].slice.call(document.querySelectorAll('h2[id],h3[id]'));
if('IntersectionObserver'in window){var o=new IntersectionObserver(function(es){es.forEach(function(e){if(e.isIntersecting)set(e.target.id);});},{rootMargin:'0px 0px -75% 0px'});hs.forEach(function(h){o.observe(h);});}
})();
</script>
'@

function Test-Output { param([string]$Path)
    $t = [System.IO.File]::ReadAllText($Path)
    if ($t -match '&#19[46];|&#226;|&#160;&#8364;') { Write-Warning "$([System.IO.Path]::GetFileName($Path)): mojibake signature found (source not read as UTF-8?)" }
    $nonAscii = ([regex]::Matches($t, '[^\x09\x0A\x0D\x20-\x7E]')).Count
    if ($nonAscii -gt 0) { Write-Warning "$([System.IO.Path]::GetFileName($Path)): $nonAscii non-ASCII char(s) survived the ASCII-safe pass" }
}

# ===========================================================================
# Alternate renderer: a single combined "USER-GUIDE.html" in the SailPoint style
# (navy grouped sidebar section-switcher, dark header band, report-section cards,
# callouts). Reuses the same converter so the two styles never drift.
# ===========================================================================
function Split-Sections {
    # Split a markdown doc into sections at level-2 (##) headings. Content before
    # the first ## becomes an "Overview" section. The H1 is dropped (the page has
    # its own header band).
    param([string]$md)
    $lines = $md -replace "`r", "" -split "`n"
    $out = New-Object System.Collections.Generic.List[object]
    $title = 'Overview'; $body = New-Object System.Collections.Generic.List[string]
    foreach ($l in $lines) {
        if ($l -match '^#\s+') { continue }
        if ($l -match '^##\s+(.*)$') {
            $out.Add([pscustomobject]@{ Title = $title; Slug = (Get-Slug $title); Body = ($body -join "`n") })
            $title = $Matches[1].Trim(); $body.Clear(); continue
        }
        $body.Add($l)
    }
    $out.Add([pscustomobject]@{ Title = $title; Slug = (Get-Slug $title); Body = ($body -join "`n") })
    return ($out | Where-Object { $_.Body.Trim() -ne '' -or $_.Title -ne 'Overview' })
}

$spCss = @'
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
:root{--primary:#336699;--primary-dark:#264d73;--success:#339933;--success-bg:#edf6ef;--danger:#CC3333;--danger-bg:#fdf0ef;--warning:#FF8800;--warning-bg:#fff8ec;--sidebar-bg:#1e2a3a;--sidebar-hover:rgba(255,255,255,.05);--sidebar-active-bg:rgba(91,155,213,.10);--header-bg:#2c3e50;--accent:#5B9BD5;--text:#2c3e50;--text-muted:#555e70;--bg:#f7f8fa;--surface:#fff;--border:#e0e4ea;--border-light:#eaecf0;--code-bg:#f5f6f8;--table-header:#34495e;--table-alt:#f9f9f9;--sidebar-w:240px}
html{font-size:15px}
body{font-family:-apple-system,'Segoe UI',system-ui,sans-serif;color:var(--text);background:var(--bg);line-height:1.65;-webkit-font-smoothing:antialiased}
#report-header{position:sticky;top:0;z-index:1000;background:var(--header-bg);color:#fff;padding:14px 24px;border-bottom:3px solid var(--accent);display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:8px}
.report-title{font-size:1.05rem;font-weight:700;color:var(--accent);letter-spacing:.01em}
.report-sub{font-size:.72rem;color:rgba(255,255,255,.65);margin-top:2px}
.meta-items{display:flex;gap:20px;flex-wrap:wrap}
.meta-item{font-size:.68rem;color:rgba(255,255,255,.60);line-height:1.4}
.meta-item strong{display:block;color:rgba(255,255,255,.85);font-size:.65rem;text-transform:uppercase;letter-spacing:.08em}
#app-layout{display:flex;min-height:calc(100vh - 56px)}
#sidebar{width:var(--sidebar-w);flex-shrink:0;background:var(--sidebar-bg);position:sticky;top:0;height:100vh;overflow-y:auto;align-self:flex-start;scrollbar-width:thin;scrollbar-color:rgba(255,255,255,.15) transparent}
#sidebar-inner{padding:18px 0}
.sidebar-group-label{font-size:.60rem;font-weight:800;letter-spacing:.15em;text-transform:uppercase;color:rgba(255,255,255,.35);padding:14px 16px 8px;border-bottom:1px solid rgba(255,255,255,.08);margin-bottom:6px}
#sidebar a{display:flex;align-items:center;gap:10px;padding:9px 16px;font-size:.80rem;font-weight:500;color:#8892a8;text-decoration:none;border-left:3px solid transparent;transition:color .15s,border-color .15s,background .15s;line-height:1.3}
#sidebar a:hover{color:#c8d0e0;background:var(--sidebar-hover)}
#sidebar a.active{color:var(--accent);border-left-color:var(--accent);background:var(--sidebar-active-bg);font-weight:600}
.sidebar-num{width:20px;height:20px;border-radius:50%;background:rgba(255,255,255,.10);font-size:.60rem;font-weight:700;display:flex;align-items:center;justify-content:center;flex-shrink:0;color:rgba(255,255,255,.50)}
#sidebar a.active .sidebar-num{background:var(--accent);color:var(--sidebar-bg)}
#content-area{flex:1;min-width:0}
.report-section{display:none;padding:28px 36px 52px;max-width:980px}
.report-section.is-active{display:block}
.report-section h1{font-size:1.5rem;color:var(--primary);margin-bottom:14px}
.report-section h2{font-size:1.35rem;font-weight:700;color:var(--primary);margin:0 0 16px;padding-bottom:10px;border-bottom:2px solid var(--accent)}
.report-section h3{font-size:1.05rem;font-weight:700;color:var(--header-bg);margin:26px 0 10px}
.report-section h4{font-size:.92rem;font-weight:700;color:var(--text);margin:18px 0 8px}
.report-section p{font-size:.875rem;margin-bottom:12px;line-height:1.65}
.report-section ul,.report-section ol{padding-left:22px;margin:8px 0 14px}
.report-section li{font-size:.875rem;padding:3px 0;line-height:1.55}
.report-section table{width:100%;border-collapse:collapse;font-size:.84rem;margin:14px 0 18px;border:1px solid var(--border);border-radius:6px;overflow:hidden}
.report-section thead tr{background:var(--table-header);color:#fff}
.report-section thead th{padding:9px 14px;text-align:left;font-size:.70rem;font-weight:700;letter-spacing:.09em;text-transform:uppercase}
.report-section thead th:first-child{color:var(--accent)}
.report-section tbody tr:nth-child(even){background:var(--table-alt)}
.report-section tbody tr:hover{background:#eef3fb}
.report-section td{padding:8px 14px;border-bottom:1px solid var(--border-light);vertical-align:top;line-height:1.45}
.report-section td:first-child{font-weight:600;color:var(--primary-dark)}
.report-section pre{background:var(--code-bg);border:1px solid var(--border);border-radius:6px;padding:14px 18px;overflow-x:auto;margin:12px 0 16px;font-size:.82rem;line-height:1.55}
.report-section code{font-family:'Cascadia Code','Consolas',monospace;font-size:.84em}
.report-section p code,.report-section li code,.report-section td code{background:var(--code-bg);border:1px solid var(--border);border-radius:3px;padding:1px 5px;color:var(--danger)}
.report-section pre code{background:none;border:none;padding:0;color:var(--text);font-size:1em}
.report-section hr{border:0;border-top:1px solid var(--border);margin:1.4em 0}
.callout{border-radius:6px;padding:13px 16px;margin:14px 0;font-size:.84rem;background:#eef3fb;border:1px solid #b8d0ee;border-left:4px solid var(--primary)}
.callout-label{font-size:.65rem;font-weight:800;text-transform:uppercase;letter-spacing:.10em;margin-bottom:6px;color:var(--primary)}
.callout p{font-size:.84rem;margin-bottom:0}
@media(max-width:820px){#app-layout{display:block}#sidebar{width:auto;position:static;height:auto}.report-section{padding:18px}}
@media print{#sidebar,.report-header .meta-items{display:none}.report-section{display:block!important;max-width:none;page-break-after:always}}
'@

$spJs = @'
<script>
function showSection(id){
 var s=document.querySelectorAll('.report-section');for(var i=0;i<s.length;i++)s[i].classList.remove('is-active');
 var el=document.getElementById('section-'+id);if(el)el.classList.add('is-active');
 var a=document.querySelectorAll('#sidebar a');for(var j=0;j<a.length;j++)a[j].classList.remove('active');
 var act=document.querySelectorAll('[data-sec="'+id+'"]');for(var k=0;k<act.length;k++)act[k].classList.add('active');
 if(history.replaceState){history.replaceState(null,'','#'+id);}else{location.hash=id;}
 window.scrollTo(0,0);
}
(function(){var h=(location.hash||'').replace('#','');var f=document.querySelector('#sidebar a[data-sec]');var id=h||(f?f.getAttribute('data-sec'):null);if(id)showSection(id);})();
</script>
'@

function Build-CombinedGuide {
    param([object[]]$Groups, [string]$OutFile, [string]$Stamp)
    $secs = New-Object System.Text.StringBuilder
    $nav = New-Object System.Text.StringBuilder
    $first = $null; $n = 0
    foreach ($g in $Groups) {
        [void]$nav.AppendLine("<div class=`"sidebar-group-label`">$($g.Label)</div>")
        $md = [System.IO.File]::ReadAllText($g.File)
        foreach ($s in (Split-Sections $md)) {
            $n++; $id = "$($g.Prefix)-$($s.Slug)"; if (-not $first) { $first = $id }
            $conv = Convert-Markdown ("## " + $s.Title + "`n`n" + $s.Body)
            $h = $conv.Html
            $h = [regex]::Replace($h, '<blockquote>(.*?)</blockquote>', '<div class="callout"><div class="callout-label">Note</div><p>$1</p></div>', [System.Text.RegularExpressions.RegexOptions]::Singleline)
            $h = [regex]::Replace($h, 'id="([^"]+)"', ('id="' + $g.Prefix + '-$1"'))
            $cls = if ($null -eq $script:cgFirstDone) { $script:cgFirstDone = $true; 'report-section is-active' } else { 'report-section' }
            [void]$secs.AppendLine("<div id=`"section-$id`" class=`"$cls`">$h</div>")
            [void]$nav.AppendLine("<a href=`"#$id`" data-sec=`"$id`" onclick=`"showSection('$id');return false;`"><span class=`"sidebar-num`">$n</span><span>$(Convert-Inline $s.Title)</span></a>")
        }
    }
    $script:cgFirstDone = $null
    $html = @"
<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Group Enumerator - User Guide</title><style>$spCss</style></head><body>
<div id="report-header"><div class="title-block"><div class="report-title">Group Enumerator - User Guide</div><div class="report-sub">CLI + GUI reference, generated from the playbook Markdown</div></div>
<div class="meta-items"><div class="meta-item"><strong>Version</strong>v3.1.x</div><div class="meta-item"><strong>Date</strong>$Stamp</div><div class="meta-item"><strong>Platform</strong>PowerShell 5.1 &middot; WPF GUI</div></div></div>
<div id="app-layout"><nav id="sidebar"><div id="sidebar-inner">$($nav.ToString())</div></nav>
<div id="content-area">$($secs.ToString())</div></div>
$spJs
</body></html>
"@
    $html = ConvertTo-AsciiSafe $html
    [System.IO.File]::WriteAllText($OutFile, $html, (New-Object System.Text.UTF8Encoding($false)))
    Test-Output $OutFile
    Write-Host ("  {0,-16} {1,5} KB  ({2} sections)" -f (Split-Path $OutFile -Leaf), [int]((Get-Item $OutFile).Length / 1KB), $n) -ForegroundColor Green
}

function Build-Guide {
    param([string[]]$MdFiles, [string]$Title, [string]$Sub, [string]$OutFile, [string]$Stamp)
    # UTF-8, BOM-aware read -- NOT Get-Content (ANSI default in PS 5.1 -> mojibake).
    $md = ($MdFiles | ForEach-Object { [System.IO.File]::ReadAllText($_) }) -join "`n`n"
    $r = Convert-Markdown $md
    $nav = New-Object System.Text.StringBuilder
    [void]$nav.AppendLine('<div class="t">On this page</div>')
    foreach ($h in $r.Toc) { $cls = if ($h.Level -eq 3) { ' class="lvl3"' } else { '' }; [void]$nav.AppendLine("<a href=`"#$($h.Slug)`"$cls>$($h.Text)</a>") }
    $html = @"
<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>$(ConvertTo-AsciiSafe $Title)</title>
<style>$css</style></head><body>
<div class="topbar"><h1>$(ConvertTo-AsciiSafe $Title)</h1><div class="sub">$(ConvertTo-AsciiSafe $Sub)</div><div class="gen">Generated $Stamp from the playbook Markdown &mdash; do not edit this file; edit the .md and re-run Build-Playbook.ps1.</div></div>
<div class="wrap"><nav class="nav">$($nav.ToString())</nav><main class="content">$($r.Html)
<footer class="foot">Source of truth: <code>docs/playbook/*.md</code> &middot; regenerate with <code>Build-Playbook.ps1</code> &middot; <a href="index.html">All guides</a></footer>
</main></div>
$spy
</body></html>
"@
    # Final defensive pass: pure-ASCII output (typography -> numeric entities).
    $html = ConvertTo-AsciiSafe $html
    [System.IO.File]::WriteAllText($OutFile, $html, (New-Object System.Text.UTF8Encoding($false)))
    Test-Output $OutFile
    Write-Host ("  {0,-16} {1,5} KB  ({2} TOC entries)" -f (Split-Path $OutFile -Leaf), [int]((Get-Item $OutFile).Length / 1KB), $r.Toc.Count) -ForegroundColor Green
}

$stamp = (Get-Date).ToString('yyyy-MM-dd')
$foundations = Join-Path $here '00-foundations.md'
Write-Host "Building playbook HTML -> $OutDir" -ForegroundColor Cyan
Build-Guide -MdFiles @($foundations, (Join-Path $here 'cli-playbook.md')) -Title 'Group Enumerator - CLI Guide' -Sub 'Operators / automation' -OutFile (Join-Path $OutDir 'cli-guide.html') -Stamp $stamp
Build-Guide -MdFiles @($foundations, (Join-Path $here 'gui-playbook.md')) -Title 'Group Enumerator - GUI Guide' -Sub 'Analysts / reviewers' -OutFile (Join-Path $OutDir 'gui-guide.html') -Stamp $stamp

# Alternate single-file "USER-GUIDE.html" in the SailPoint style (combined CLI+GUI).
Build-CombinedGuide -Groups @(
    [pscustomobject]@{ Label = 'Foundations';   Prefix = 'found'; File = $foundations },
    [pscustomobject]@{ Label = 'CLI Reference'; Prefix = 'cli';   File = (Join-Path $here 'cli-playbook.md') },
    [pscustomobject]@{ Label = 'GUI Reference'; Prefix = 'gui';   File = (Join-Path $here 'gui-playbook.md') }
) -OutFile (Join-Path $OutDir 'USER-GUIDE.html') -Stamp $stamp

$index = ConvertTo-AsciiSafe @"
<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Group Enumerator - Playbook</title><style>$css .card{display:block;border:1px solid var(--line);border-radius:10px;padding:18px 20px;margin:14px 0;background:var(--side)}.card:hover{border-color:var(--accent);text-decoration:none}.card h3{margin:0 0 4px}.card p{margin:0;color:var(--muted)}</style></head><body>
<div class="topbar"><h1>Group Enumerator - Playbook</h1><div class="sub">Pick your guide</div><div class="gen">Generated $stamp from Markdown.</div></div>
<main class="content" style="max-width:760px;margin:0 auto">
<a class="card" href="USER-GUIDE.html"><h3>User Guide (combined) &rarr;</h3><p>Single-file CLI + GUI reference with a grouped navigation sidebar (SailPoint-style). Foundations, CLI, and GUI in one document.</p></a>
<a class="card" href="cli-guide.html"><h3>CLI Guide &rarr;</h3><p>Operators / automation: every entry script and parameter, reports catalog, recipes, troubleshooting (+ shared foundations).</p></a>
<a class="card" href="gui-guide.html"><h3>GUI Guide &rarr;</h3><p>Analysts / reviewers: every tab and control, presets, task recipes (+ shared foundations).</p></a>
<p style="color:var(--muted);font-size:13px;margin-top:24px">Both guides share the same Foundations section (install, auth, config, safety, glossary). Source of truth is the Markdown in <code>docs/playbook/</code>.</p>
</main></body></html>
"@
[System.IO.File]::WriteAllText((Join-Path $OutDir 'index.html'), $index, (New-Object System.Text.UTF8Encoding($false)))
Test-Output (Join-Path $OutDir 'index.html')
Write-Host "  index.html written" -ForegroundColor Green
Write-Host "Done." -ForegroundColor Cyan
