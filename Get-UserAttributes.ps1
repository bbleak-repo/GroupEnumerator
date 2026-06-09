<#
.SYNOPSIS
    Lists the LDAP attributes present on an AD account, to discover what is
    available to pass to Invoke-GroupEnumerator.ps1 -IncludeAttributes.

.DESCRIPTION
    Connects to a domain controller using the same LDAP stack as the main tool
    (Modules\ADLdap.ps1: LDAPS first, with -AllowInsecure enabling cert-bypass and
    LDAP 389 sign+seal fallback), looks up a single account by sAMAccountName or
    userPrincipalName, and reports its populated attributes.

    The attribute NAMES it prints are the exact LDAP names you pass to
    Invoke-GroupEnumerator.ps1 -ExportMembersCsv -IncludeAttributes <names>.
    ('manager' is special-cased by the enumerator into Manager + ManagerDN columns.)

.PARAMETER Identity
    sAMAccountName or userPrincipalName of the account to inspect.

.PARAMETER Server
    DC hostname or domain FQDN to query (e.g. dc01.corp.com or corp.com).

.PARAMETER Credential
    Optional PSCredential. Defaults to the current Windows identity (Kerberos).

.PARAMETER AllowInsecure
    Allow LDAPS cert-verification bypass and LDAP 389 sign+seal fallback. Needed
    for lab/self-signed DCs (same semantics as the main tool's -AllowInsecure).

.PARAMETER NamesOnly
    Output just the attribute names (handy to copy straight into -IncludeAttributes).

.PARAMETER Properties
    Attribute names to request. Defaults to '*' (all populated, non-operational
    attributes). Pass specific names to check just those.

.EXAMPLE
    .\Get-UserAttributes.ps1 -Identity jsmith -Server corp.example.com -AllowInsecure
    Lists every populated attribute (name + value) on jsmith.

.EXAMPLE
    .\Get-UserAttributes.ps1 -Identity jsmith -Server corp.com -NamesOnly
    Prints just the attribute names.

.EXAMPLE
    .\Get-UserAttributes.ps1 -Identity jsmith -Server corp.com -AllowInsecure |
        Where-Object Value | Format-Table -Auto
    Show only attributes that have a value.

.NOTES
    Author: EntraID Team
    Requires: PowerShell 5.1 or 7+. Uses only Modules\ADLdap.ps1 (no RSAT).
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$Identity,

    [Parameter(Mandatory = $true)]
    [string]$Server,

    [Parameter(Mandatory = $false)]
    [PSCredential]$Credential,

    [Parameter(Mandatory = $false)]
    [switch]$AllowInsecure,

    [Parameter(Mandatory = $false)]
    [switch]$NamesOnly,

    [Parameter(Mandatory = $false)]
    [string[]]$Properties = @('*')
)

$ErrorActionPreference = 'Stop'
$scriptRoot = $PSScriptRoot

# Optional structured-logger stub so ADLdap log calls (if any) are no-ops when
# this helper runs standalone, without pulling in the full logging setup.
if (-not (Get-Command Write-GroupEnumLog -ErrorAction SilentlyContinue)) {
    function Write-GroupEnumLog { param($Level, $Operation, $Message, $Context) }
}

$adLdapPath = Join-Path $scriptRoot 'Modules\ADLdap.ps1'
if (-not (Test-Path $adLdapPath)) {
    Write-Error "Required module not found: $adLdapPath"
    exit 1
}
. $adLdapPath

Write-Host "Connecting to $Server ..." -ForegroundColor Cyan
$connParams = @{ Server = $Server }
if ($AllowInsecure) { $connParams.AllowInsecure = $true }
if ($Credential)    { $connParams.Credential    = $Credential }

$ctx = $null
try {
    $ctx = New-AdLdapConnection @connParams
    Write-Host ("  Connected via tier '{0}' (port {1}); base {2}" -f $ctx.Tier, $ctx.Port, $ctx.BaseDN) -ForegroundColor Gray
    if ($ctx.Tier -ne 'LDAPS-Verified') {
        Write-Host "  (tier downgrade -- data is still retrieved; see -AllowInsecure notes)" -ForegroundColor DarkGray
    }

    $idEsc  = Escape-AdLdapFilterValue $Identity
    $filter = "(&(objectClass=user)(|(sAMAccountName=$idEsc)(userPrincipalName=$idEsc)))"
    # Invoke-AdLdapSearch returns its hashtable[] via ',$array', so assign the
    # result directly. Wrapping the call in @(...) nests the array (one element
    # that IS the array), which then breaks per-attribute [key] lookups.
    $entries = Invoke-AdLdapSearch -Context $ctx -Filter $filter -Attributes $Properties -Scope 'Subtree'
    $matched = @($entries)

    if ($matched.Count -eq 0) {
        Write-Warning "No account found matching '$Identity' under $($ctx.BaseDN)."
        return
    }
    if ($matched.Count -gt 1) {
        Write-Warning "$($matched.Count) accounts matched '$Identity'; showing the first: $($matched[0].DistinguishedName)"
    }

    $entry = $matched[0]
    $names = @($entry.Keys) | Sort-Object

    Write-Host ''
    Write-Host ("{0} attribute(s) on {1}:" -f $names.Count, $entry.DistinguishedName) -ForegroundColor Green
    Write-Host ''

    if ($NamesOnly) {
        $names
    } else {
        foreach ($k in $names) {
            $v = $entry[$k]
            $val = if ($v -is [array]) { ($v -join '; ') } else { [string]$v }
            [pscustomobject]@{ Attribute = $k; Value = $val }
        }
    }
}
finally {
    Close-AdLdapConnection -Context $ctx
}
