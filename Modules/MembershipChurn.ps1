<#
.SYNOPSIS
    Membership churn / re-grant ("access flapping") analysis over the change ledger.
.DESCRIPTION
    Pure analysis: given a flat list of changelog events (Added/Removed, timestamped, per
    domain|group|account), reconstruct each account's per-group timeline and flag RE-GRANTS --
    an account that was Removed and later Added again. Repeated re-grants ("was there, removed,
    re-added, removed, re-added") are a classic governance red flag (ticket thrash, automation
    loops, or deliberate evasion), especially in privileged groups.

    Backend-agnostic + side-effect-free: the caller supplies the events (from the SQLite
    `query-changes` command or the JSON Read-ChangeLog), so this is fully unit-testable. The
    privileged classification is injected as a predicate to avoid coupling to RC08.

    NOTE on fidelity: this detects oscillation that crosses enumeration runs. An add+remove that
    happens entirely between two runs is not in the ledger (snapshot sampling). Run cadence
    therefore bounds resolution -- frequent (e.g. business-hours) runs catch more.
#>

function ConvertTo-ChurnDateTime {
    param([object]$Value)
    if ($null -eq $Value) { return $null }
    if ($Value -is [datetime]) { return $Value }
    $s = [string]$Value
    if ([string]::IsNullOrWhiteSpace($s)) { return $null }
    $dt = [datetime]::MinValue
    # RoundtripKind honours a trailing 'Z'/offset (UTC); all changelog timestamps are ISO-8601 UTC.
    $styles = [System.Globalization.DateTimeStyles]::RoundtripKind
    if ([datetime]::TryParse($s, [System.Globalization.CultureInfo]::InvariantCulture, $styles, [ref]$dt)) { return $dt }
    return $null
}

function Get-ChurnProp {
    param([object]$Obj, [string]$Name)
    if ($null -eq $Obj) { return $null }
    if ($Obj -is [System.Collections.IDictionary]) { if ($Obj.Contains($Name)) { return $Obj[$Name] } return $null }
    $p = $Obj.PSObject.Properties[$Name]
    if ($p) { return $p.Value }
    return $null
}

function Get-MembershipChurn {
    <#
    .SYNOPSIS
        Analyse changelog events for re-grant / flapping patterns.
    .OUTPUTS
        @{ Records = @(@{ Domain; Group; Sam; DisplayName; Events; Adds; Removes; ReGrants;
                          FirstSeen; LastSeen; LastAction; CurrentlyIn; MinReAddGapHours; Privileged });
           Summary = @{ AccountsFlagged; TotalReGrants; PrivilegedReGrants; GroupsAffected; EventsAnalyzed } }
        Records contain only accounts with ReGrants >= MinReGrants (privileged first, then most re-grants).
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [object[]]$Events,
        [int]$MinReGrants = 1,
        [scriptblock]$PrivilegedNamePredicate = $null,
        [switch]$PrivilegedOnly
    )

    $byKey = @{}
    $analyzed = 0
    foreach ($e in @($Events)) {
        if ($null -eq $e) { continue }
        $grp = [string](Get-ChurnProp $e 'GroupName')
        $sam = [string](Get-ChurnProp $e 'SamAccountName')
        $act = [string](Get-ChurnProp $e 'Action')
        if ([string]::IsNullOrWhiteSpace($grp) -or [string]::IsNullOrWhiteSpace($sam)) { continue }
        $dom = [string](Get-ChurnProp $e 'Domain')
        $key = ('{0}|{1}|{2}' -f $dom, $grp, $sam).ToLowerInvariant()
        if (-not $byKey.ContainsKey($key)) { $byKey[$key] = New-Object System.Collections.Generic.List[object] }
        $byKey[$key].Add([pscustomobject]@{
            Domain = $dom; Group = $grp; Sam = $sam
            Display = [string](Get-ChurnProp $e 'DisplayName'); Action = $act
            Ts = (ConvertTo-ChurnDateTime (Get-ChurnProp $e 'Timestamp'))
        })
        $analyzed++
    }

    $records = New-Object System.Collections.Generic.List[object]
    foreach ($key in $byKey.Keys) {
        $evs = @($byKey[$key] | Sort-Object Ts)
        $adds = 0; $removes = 0; $reGrants = 0; $lastAction = $null; $lastRemoveTs = $null; $minGap = $null
        foreach ($ev in $evs) {
            if ($ev.Action -eq 'Added') {
                $adds++
                if ($lastAction -eq 'Removed') {
                    $reGrants++
                    if ($lastRemoveTs -and $ev.Ts) {
                        $gap = [math]::Round((($ev.Ts) - $lastRemoveTs).TotalHours, 1)
                        if ($null -eq $minGap -or $gap -lt $minGap) { $minGap = $gap }
                    }
                }
                $lastAction = 'Added'
            } elseif ($ev.Action -eq 'Removed') {
                $removes++; $lastRemoveTs = $ev.Ts; $lastAction = 'Removed'
            }
        }
        if ($reGrants -lt $MinReGrants) { continue }
        $first = $evs[0]; $last = $evs[$evs.Count - 1]
        $priv = $false
        if ($PrivilegedNamePredicate) { try { $priv = [bool](& $PrivilegedNamePredicate $first.Group) } catch { $priv = $false } }
        if ($PrivilegedOnly -and -not $priv) { continue }
        $records.Add([pscustomobject]@{
            Domain = $first.Domain; Group = $first.Group; Sam = $first.Sam; DisplayName = $first.Display
            Events = $evs.Count; Adds = $adds; Removes = $removes; ReGrants = $reGrants
            FirstSeen = $first.Ts; LastSeen = $last.Ts; LastAction = $last.Action
            CurrentlyIn = ($last.Action -eq 'Added'); MinReAddGapHours = $minGap; Privileged = $priv
        })
    }

    $recArr = @($records | Sort-Object @{ Expression = { $_.Privileged }; Descending = $true }, @{ Expression = { $_.ReGrants }; Descending = $true }, Group, Sam)
    return @{
        Records = $recArr
        Summary = @{
            AccountsFlagged    = $recArr.Count
            TotalReGrants      = [int]((@($recArr) | Measure-Object -Property ReGrants -Sum).Sum)
            PrivilegedReGrants = [int]((@($recArr | Where-Object { $_.Privileged }) | Measure-Object -Property ReGrants -Sum).Sum)
            GroupsAffected     = @($recArr | ForEach-Object { '{0}|{1}' -f $_.Domain, $_.Group } | Sort-Object -Unique).Count
            EventsAnalyzed     = $analyzed
        }
    }
}

function New-ChurnHtmlReport {
    <# .SYNOPSIS  Write a self-contained churn report (numbers + at-risk table) to OutputPath. #>
    [CmdletBinding()]
    param([hashtable]$Churn, [string]$Title = 'Membership Churn / Re-grant Report', [string]$WindowLabel = '', [Parameter(Mandatory)][string]$OutputPath)

    function _enc { param([string]$s) if ($null -eq $s) { return '' } ($s -replace '&', '&amp;' -replace '<', '&lt;' -replace '>', '&gt;') }
    $sum = $Churn.Summary
    $rows = New-Object System.Text.StringBuilder
    foreach ($r in @($Churn.Records)) {
        $cls = if ($r.Privileged) { ' class="priv"' } else { '' }
        $gap = if ($null -ne $r.MinReAddGapHours) { "{0}h" -f $r.MinReAddGapHours } else { '-' }
        $cur = if ($r.CurrentlyIn) { 'In group' } else { 'Removed' }
        [void]$rows.AppendLine(('<tr{0}><td>{1}</td><td>{2}</td><td>{3}</td><td class="n">{4}</td><td class="n">{5}</td><td class="n">{6}</td><td>{7}</td><td>{8}</td></tr>' -f `
            $cls, (_enc $r.Group), (_enc $r.Sam), (_enc $r.DisplayName), $r.ReGrants, $r.Adds, $r.Removes, $gap, $cur))
    }
    $body = if (@($Churn.Records).Count -gt 0) {
        "<table><thead><tr><th>Group</th><th>Account</th><th>Name</th><th>Re-grants</th><th>Adds</th><th>Removes</th><th>Fastest re-add</th><th>Now</th></tr></thead><tbody>$($rows.ToString())</tbody></table>"
    } else { '<p class="ok">No re-grant / flapping accounts found in the window.</p>' }
    $win = if ($WindowLabel) { " &mdash; $(_enc $WindowLabel)" } else { '' }
    $html = @"
<!DOCTYPE html><html><head><meta charset="utf-8"><title>$(_enc $Title)</title>
<style>body{font-family:Segoe UI,Arial,sans-serif;margin:24px;color:#1f2937;}h1{font-size:20px;}
.cards{display:flex;gap:14px;margin:14px 0;flex-wrap:wrap;}.card{border:1px solid #e5e7eb;border-radius:8px;padding:12px 16px;min-width:130px;}
.card .n{font-size:24px;font-weight:700;}.card .l{font-size:12px;color:#6b7280;}.danger .n{color:#b91c1c;}.warn .n{color:#b45309;}
table{border-collapse:collapse;width:100%;margin-top:12px;font-size:13px;}th,td{border:1px solid #e5e7eb;padding:6px 10px;text-align:left;}
th{background:#f9fafb;}td.n{text-align:right;}tr.priv{background:#fef2f2;}.ok{color:#15803d;}.muted{color:#6b7280;font-size:12px;}</style></head>
<body><h1>$(_enc $Title)$win</h1>
<div class="cards">
<div class="card $(if($sum.AccountsFlagged -gt 0){'danger'})"><div class="n">$($sum.AccountsFlagged)</div><div class="l">Accounts Flagged</div></div>
<div class="card $(if($sum.TotalReGrants -gt 0){'warn'})"><div class="n">$($sum.TotalReGrants)</div><div class="l">Total Re-grants</div></div>
<div class="card $(if($sum.PrivilegedReGrants -gt 0){'danger'})"><div class="n">$($sum.PrivilegedReGrants)</div><div class="l">Privileged Re-grants</div></div>
<div class="card"><div class="n">$($sum.GroupsAffected)</div><div class="l">Groups Affected</div></div>
</div>
$body
<p class="muted">A re-grant = an account Removed then Added again. Detected across enumeration runs; an add+remove entirely between two runs is not captured (run cadence bounds resolution). Privileged groups highlighted.</p>
</body></html>
"@
    [System.IO.File]::WriteAllText($OutputPath, $html, [System.Text.UTF8Encoding]::new($false))
    return $OutputPath
}
