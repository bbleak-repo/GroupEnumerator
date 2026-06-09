<#
.SYNOPSIS
    Modern Active Directory LDAP helper built on System.DirectoryServices.Protocols

.DESCRIPTION
    Self-contained LDAP connection and search helpers for Active Directory tools.
    Uses System.DirectoryServices.Protocols.LdapConnection (not legacy ADSI
    DirectoryEntry) so it works against DCs that enforce LDAP Channel Binding
    (CBT) and LDAP Signing -- the modern hardened default.

    Connection tiers (tried in order, highest security first):
      Tier 1: LDAPS 636, cert verification strict      (always attempted)
      Tier 2: LDAPS 636, cert verification bypassed    (requires -AllowInsecure)
      Tier 3: LDAP  389, SASL sign + seal (Kerberos)   (requires -AllowInsecure)
      Tier 4: LDAP  389, no signing/sealing            (requires -AllowInsecureUnsigned)

    Authentication: AuthType.Negotiate (Kerberos preferred, NTLM fallback).
    Credentials: optional PSCredential; when omitted the current Windows identity
    is used via SSPI.

.NOTES
    CANONICAL COPY: Group-Enumerator/Modules/ADLdap.ps1
    This file is intentionally self-contained. It has no dependencies on any
    other module in the repo so it can be dropped into any AD tool's Modules/
    directory and dot-sourced. When fixing bugs, update this canonical copy and
    sync any vendored copies in sibling tools (AD-Discovery, etc.).

    Compatible with PowerShell 5.1 and 7+. Windows only (requires the
    System.DirectoryServices.Protocols assembly).
#>

# Ensure the Protocols assembly is loaded (no-op if already loaded).
Add-Type -AssemblyName System.DirectoryServices.Protocols -ErrorAction SilentlyContinue

# ---------------------------------------------------------------------------
# Public: Escape-AdLdapFilterValue
# ---------------------------------------------------------------------------
function Escape-AdLdapFilterValue {
    <#
    .SYNOPSIS
        Escapes a value for safe interpolation into an LDAP search filter
        (RFC 4515 section 3). Prevents filter injection and broken queries
        when a value contains ( ) * \ or NUL -- all legal characters in AD
        names that are CSV-supplied to this toolkit.

    .DESCRIPTION
        Uses hexadecimal escaping (\28, \29, \2a, \5c, \00) which is the
        canonical, unambiguous RFC 4515 form and avoids the double-backslash
        trap of `-replace '([\\*()])','\\$1'` in PowerShell.
    #>
    param([string]$Value)
    if ($null -eq $Value) { return '' }
    return [regex]::Replace($Value, '[\\*()\x00]', {
        param($m) '\{0:x2}' -f [int][char]$m.Value
    })
}

# ---------------------------------------------------------------------------
# Public: New-AdLdapConnection
# ---------------------------------------------------------------------------
function New-AdLdapConnection {
    <#
    .SYNOPSIS
        Opens an authenticated LdapConnection to an AD domain, trying tiers in
        order of decreasing security.

    .PARAMETER Server
        Target server. May be a DC hostname, a domain FQDN, or an IP address.
        When a domain FQDN is supplied, Windows will locate a DC via DC Locator
        (serverless binding) -- this is usually what you want for portability.

    .PARAMETER Credential
        Optional PSCredential. When omitted the current Windows identity is used.

    .PARAMETER AllowInsecure
        Enables fallback tiers: LDAPS with cert verification bypassed, and LDAP
        389 with SASL sign+seal (Kerberos-encrypted session). Defaults to $false.

    .PARAMETER AllowInsecureUnsigned
        Enables the lowest fallback: LDAP 389 with no signing or sealing. Only
        use when talking to legacy DCs that refuse modern auth. Off by default
        and ignored unless -AllowInsecure is also set.

    .PARAMETER TimeoutSeconds
        Bind + search timeout in seconds. Defaults to 120.

    .OUTPUTS
        Hashtable @{
            Connection = [System.DirectoryServices.Protocols.LdapConnection]
            BaseDN     = '<defaultNamingContext>'
            Tier       = 'LDAPS-Verified' | 'LDAPS-Unverified' | 'LDAP-SignSeal' | 'LDAP-Plain'
            Port       = 636 | 389
            Secure     = $true | $false
            Server     = '<server you passed in>'
            Errors     = @() # non-fatal warnings from skipped tiers
        }

    .NOTES
        Caller is responsible for disposing the returned Connection, either
        directly (.Dispose()) or via Close-AdLdapConnection.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Server,

        [Parameter(Mandatory = $false)]
        [PSCredential]$Credential,

        [Parameter(Mandatory = $false)]
        [switch]$AllowInsecure,

        [Parameter(Mandatory = $false)]
        [switch]$AllowInsecureUnsigned,

        [Parameter(Mandatory = $false)]
        [int]$TimeoutSeconds = 120
    )

    $tierErrors = @()

    # Build the list of tiers to try in descending security order.
    $tiers = New-Object System.Collections.Generic.List[hashtable]
    $tiers.Add(@{ Name = 'LDAPS-Verified';   Port = 636; Ssl = $true;  VerifyCert = $true;  SignSeal = $false }) | Out-Null
    if ($AllowInsecure) {
        $tiers.Add(@{ Name = 'LDAPS-Unverified'; Port = 636; Ssl = $true;  VerifyCert = $false; SignSeal = $false }) | Out-Null
        $tiers.Add(@{ Name = 'LDAP-SignSeal';    Port = 389; Ssl = $false; VerifyCert = $false; SignSeal = $true  }) | Out-Null
        if ($AllowInsecureUnsigned) {
            $tiers.Add(@{ Name = 'LDAP-Plain';   Port = 389; Ssl = $false; VerifyCert = $false; SignSeal = $false }) | Out-Null
        }
    }

    foreach ($tier in $tiers) {
        $conn = $null
        try {
            Write-Verbose "New-AdLdapConnection: trying tier '$($tier.Name)' on $Server`:$($tier.Port)"

            $id   = New-Object System.DirectoryServices.Protocols.LdapDirectoryIdentifier(
                        $Server, [int]$tier.Port, <# fullyQualifiedDnsHostName #> $false, <# connectionless #> $false)
            $conn = New-Object System.DirectoryServices.Protocols.LdapConnection($id)
            $conn.AuthType    = [System.DirectoryServices.Protocols.AuthType]::Negotiate
            $conn.Timeout     = [TimeSpan]::FromSeconds($TimeoutSeconds)
            $conn.SessionOptions.ProtocolVersion = 3
            $conn.SessionOptions.ReferralChasing = [System.DirectoryServices.Protocols.ReferralChasingOptions]::None

            if ($tier.Ssl) {
                $conn.SessionOptions.SecureSocketLayer = $true
                if (-not $tier.VerifyCert) {
                    # Accept any server cert. Channel is still encrypted; we're
                    # just trusting the server identity on faith.
                    $conn.SessionOptions.VerifyServerCertificate = {
                        param($connection, $certificate) $true
                    }
                }
            } elseif ($tier.SignSeal) {
                # SASL sign + seal (Kerberos-encrypted session over 389)
                $conn.SessionOptions.Signing = $true
                $conn.SessionOptions.Sealing = $true
            }

            if ($Credential) {
                $netCred = New-Object System.Net.NetworkCredential(
                    $Credential.UserName,
                    $Credential.GetNetworkCredential().Password,
                    $Credential.GetNetworkCredential().Domain)
                $conn.Bind($netCred)
            } else {
                $conn.Bind()  # current Windows identity via SSPI
            }

            # Discover the base DN from the RootDSE
            $rootReq = New-Object System.DirectoryServices.Protocols.SearchRequest(
                '', '(objectClass=*)',
                [System.DirectoryServices.Protocols.SearchScope]::Base,
                @('defaultNamingContext'))
            $rootResp = $conn.SendRequest($rootReq)
            if ($rootResp.Entries.Count -eq 0 -or -not $rootResp.Entries[0].Attributes['defaultNamingContext']) {
                throw "Connected but RootDSE did not return defaultNamingContext"
            }
            $baseDN = [string]$rootResp.Entries[0].Attributes['defaultNamingContext'][0]

            Write-Verbose "New-AdLdapConnection: tier '$($tier.Name)' succeeded, baseDN=$baseDN"

            # If higher-security tiers were attempted and failed before this one
            # succeeded, surface the downgrade at warning level (the per-tier
            # detail is in the returned Errors and under -Verbose). A silent
            # downgrade hides that, e.g., LDAPS-Verified failed and we fell back
            # to a cert-bypassed or 389 sign+seal channel.
            if ($tierErrors.Count -gt 0) {
                Write-Warning ("New-AdLdapConnection: connected to '$Server' on a downgraded tier '$($tier.Name)' after $($tierErrors.Count) higher-tier attempt(s) failed. Run with -Verbose for per-tier detail.")
            }

            return @{
                Connection = $conn
                BaseDN     = $baseDN
                Tier       = $tier.Name
                Port       = [int]$tier.Port
                Secure     = [bool]$tier.Ssl
                Server     = $Server
                Errors     = $tierErrors
            }

        } catch {
            $msg = "Tier '$($tier.Name)' on $Server`:$($tier.Port) failed: $($_.Exception.Message.Trim())"
            Write-Verbose "New-AdLdapConnection: $msg"
            $tierErrors += $msg
            if ($conn) { try { $conn.Dispose() } catch {} }
            # fall through to next tier
        }
    }

    # All tiers exhausted
    $summary = "Unable to establish an LDAP connection to '$Server'. Attempts:`n  - " + ($tierErrors -join "`n  - ")
    if (-not $AllowInsecure) {
        $summary += "`nNote: only LDAPS-Verified was tried. Pass -AllowInsecure to enable fallback tiers (LDAPS cert bypass, 389 sign+seal)."
    }
    throw $summary
}

# ---------------------------------------------------------------------------
# Ranged-attribute helpers (AD returns large multi-valued attributes in blocks
# named 'attr;range=lo-hi'). Factored out so the parse + follow loop is unit-
# testable without a live directory.
# ---------------------------------------------------------------------------
function ConvertFrom-AdLdapRangedName {
    <#
    .SYNOPSIS
        Parses an AD ranged attribute name ('member;range=0-1499') into parts.
    .OUTPUTS
        @{ Base; Low; High; Terminal } for a ranged name, or $null otherwise.
        Terminal is $true for the final block ('...;range=3000-*').
    #>
    [CmdletBinding()]
    param([string]$Name)
    if ($Name -match '^(?<base>[^;]+);range=(?<lo>\d+)-(?<hi>\d+|\*)$') {
        $terminal = ($Matches['hi'] -eq '*')
        return @{
            Base     = $Matches['base']
            Low      = [int]$Matches['lo']
            High     = $(if ($terminal) { $null } else { [int]$Matches['hi'] })
            Terminal = $terminal
        }
    }
    return $null
}

function Get-AdLdapRangedAttributeValues {
    <#
    .SYNOPSIS
        Follows an AD ranged attribute to completion for a single entry and
        returns the full value set for the base attribute (string values).
    .DESCRIPTION
        Mirrors the live-proven block-follow loop used by Get-GroupRangedMemberDNs.
        The block fetcher is injectable so the continuation logic is unit-testable
        without a live directory.
    #>
    [CmdletBinding()]
    param(
        [hashtable]$Context,
        [string]$EntryDn,
        [string]$BaseAttr,
        [int]$NextStart,
        [object[]]$FirstBlock = @(),
        [int]$TimeoutSeconds = 120,
        [scriptblock]$Fetcher
    )
    $all = New-Object System.Collections.Generic.List[string]
    foreach ($v in @($FirstBlock)) { if ($null -ne $v) { $all.Add([string]$v) } }

    if (-not $Fetcher) {
        $Fetcher = {
            param($Ctx, $Dn, $Attr, $Start, $Timeout)
            $conn = $Ctx.Connection
            $req = New-Object System.DirectoryServices.Protocols.SearchRequest(
                $Dn, '(objectClass=*)',
                [System.DirectoryServices.Protocols.SearchScope]::Base,
                @("$Attr;range=$Start-*"))
            $req.TimeLimit = [TimeSpan]::FromSeconds($Timeout)
            $resp = $conn.SendRequest($req)
            if ($resp.Entries.Count -eq 0) { return $null }
            $entry = $resp.Entries[0]
            $rk = @($entry.Attributes.AttributeNames | Where-Object { $_ -match ('^' + [regex]::Escape($Attr) + ';range=') })[0]
            if (-not $rk) { return [pscustomobject]@{ Values = @(); Terminal = $true; NextStart = $null } }
            $vals    = $entry.Attributes[$rk].GetValues([string])
            $parsed  = ConvertFrom-AdLdapRangedName $rk
            $terminal = $true; $next = $null
            if ($parsed) { $terminal = $parsed.Terminal; if (-not $terminal) { $next = $parsed.High + 1 } }
            return [pscustomobject]@{ Values = @($vals); Terminal = $terminal; NextStart = $next }
        }
    }

    $start = $NextStart; $guard = 0
    while ($null -ne $start) {
        if (++$guard -gt 10000) { break }                  # never loop forever
        $blk = & $Fetcher $Context $EntryDn $BaseAttr $start $TimeoutSeconds
        if ($null -eq $blk) { break }
        foreach ($v in @($blk.Values)) { if ($null -ne $v) { $all.Add([string]$v) } }
        if ($blk.Terminal) { break }
        if ($null -eq $blk.NextStart) { break }
        $start = [int]$blk.NextStart
    }
    return $all.ToArray()
}

# ---------------------------------------------------------------------------
# Public: Invoke-AdLdapSearch
# ---------------------------------------------------------------------------
function Invoke-AdLdapSearch {
    <#
    .SYNOPSIS
        Runs a paged LDAP search and returns entries as plain hashtables.

    .PARAMETER Context
        A connection context hashtable returned by New-AdLdapConnection.

    .PARAMETER BaseDN
        Base DN for the search. Defaults to $Context.BaseDN.

    .PARAMETER Filter
        LDAP filter string. Must be a valid LDAP filter (e.g.
        '(&(objectCategory=group)(cn=Domain Admins))').

    .PARAMETER Attributes
        Array of attribute names to load. Pass an empty array to return DN only.

    .PARAMETER Scope
        Subtree (default), OneLevel, or Base.

    .PARAMETER PageSize
        Paging page size. Defaults to 1000. Server-side paging handles large
        result sets without hitting the default 1000-row LDAP cap.

    .PARAMETER SizeLimit
        Soft maximum number of entries to return across all pages. 0 (default)
        means no cap.

    .PARAMETER TimeoutSeconds
        Per-request timeout. Defaults to 120.

    .OUTPUTS
        Array of hashtables. Each entry looks like:
            @{
                DistinguishedName = 'CN=...,DC=...'
                <attr1>           = <string or string[]>
                <attr2>           = <string or string[]>
                ...
            }
        Multi-valued attributes come back as string arrays; single-valued as
        scalar strings; missing attributes are absent from the hashtable.
    #>
    [CmdletBinding()]
    [OutputType([hashtable[]])]
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$Context,

        [Parameter(Mandatory = $false)]
        [string]$BaseDN,

        [Parameter(Mandatory = $true)]
        [string]$Filter,

        [Parameter(Mandatory = $false)]
        [string[]]$Attributes = @(),

        [Parameter(Mandatory = $false)]
        [string[]]$BinaryAttributes = @(),

        [Parameter(Mandatory = $false)]
        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [string]$Scope = 'Subtree',

        [Parameter(Mandatory = $false)]
        [int]$PageSize = 1000,

        [Parameter(Mandatory = $false)]
        [int]$SizeLimit = 0,

        [Parameter(Mandatory = $false)]
        [int]$TimeoutSeconds = 120
    )

    if (-not $Context -or -not $Context.Connection) {
        throw "Invoke-AdLdapSearch: Context is null or missing a Connection"
    }

    $conn = $Context.Connection
    # Distinguish "caller omitted -BaseDN" (use the context default) from
    # "caller passed -BaseDN '' explicitly" (address the RootDSE). PowerShell
    # treats an empty string as falsy, so $BaseDN truthiness can't tell them
    # apart -- use PSBoundParameters instead.
    $effBase = if ($PSBoundParameters.ContainsKey('BaseDN')) { $BaseDN } else { $Context.BaseDN }

    $scopeEnum = switch ($Scope) {
        'Base'     { [System.DirectoryServices.Protocols.SearchScope]::Base }
        'OneLevel' { [System.DirectoryServices.Protocols.SearchScope]::OneLevel }
        default    { [System.DirectoryServices.Protocols.SearchScope]::Subtree }
    }

    $results = New-Object System.Collections.Generic.List[hashtable]
    $pagingControl = $null

    # Base-scope single-entry fetches don't need paging.
    $usePaging = ($scopeEnum -ne [System.DirectoryServices.Protocols.SearchScope]::Base)

    if ($usePaging) {
        $pagingControl = New-Object System.DirectoryServices.Protocols.PageResultRequestControl($PageSize)
        $pagingControl.IsCritical = $false
    }

    do {
        $req = New-Object System.DirectoryServices.Protocols.SearchRequest(
            $effBase, $Filter, $scopeEnum, $Attributes)
        $req.TimeLimit = [TimeSpan]::FromSeconds($TimeoutSeconds)
        if ($usePaging) { $null = $req.Controls.Add($pagingControl) }

        $resp = $conn.SendRequest($req)

        foreach ($entry in $resp.Entries) {
            # Note: SearchResultEntry.DistinguishedName may be an empty string
            # (legitimately, for RootDSE). Referrals land in $resp.References,
            # not $resp.Entries, so we do NOT skip on empty DN here.
            $h = @{ DistinguishedName = [string]$entry.DistinguishedName }
            # Case-insensitive set for binary attr lookup
            $binarySet = @{}
            foreach ($b in $BinaryAttributes) { $binarySet[$b.ToLowerInvariant()] = $true }

            foreach ($attrName in $entry.Attributes.AttributeNames) {
                $attr = $entry.Attributes[$attrName]
                if ($attr.Count -eq 0) { continue }

                # AD returns large multi-valued attributes in ranged blocks named
                # 'attr;range=lo-hi'. Normalize the key to the base attribute name
                # and follow the range to completion, so a caller that asked for
                # 'member' gets the full value set under 'member' rather than a
                # partial block stranded under a 'member;range=0-1499' key.
                $ranged    = ConvertFrom-AdLdapRangedName ([string]$attrName)
                $storeName = if ($ranged) { $ranged.Base } else { [string]$attrName }
                $isBinary  = $binarySet.ContainsKey(([string]$storeName).ToLowerInvariant())

                if ($ranged) {
                    if ($isBinary) {
                        # Ranged binary is vanishingly rare; take the first block.
                        $rangedVals = @($attr.GetValues([byte[]]))
                    } elseif ($ranged.Terminal) {
                        $rangedVals = @($attr.GetValues([string]))
                    } else {
                        $rangedVals = Get-AdLdapRangedAttributeValues -Context $Context `
                            -EntryDn ([string]$entry.DistinguishedName) -BaseAttr $ranged.Base `
                            -NextStart ($ranged.High + 1) -FirstBlock @($attr.GetValues([string])) `
                            -TimeoutSeconds $TimeoutSeconds
                    }
                    if ($h.ContainsKey($storeName)) {
                        $merged = New-Object System.Collections.Generic.List[object]
                        foreach ($x in @($h[$storeName]))  { $merged.Add($x) }
                        foreach ($x in @($rangedVals))     { $merged.Add($x) }
                        $h[$storeName] = $merged.ToArray()
                    } else {
                        $h[$storeName] = @($rangedVals)
                    }
                    continue
                }

                if ($isBinary) {
                    # Return byte[] (single) or byte[][] (multi)
                    $byteValues = $attr.GetValues([byte[]])
                    if ($byteValues.Count -eq 1) {
                        $h[$storeName] = [byte[]]$byteValues[0]
                    } else {
                        $h[$storeName] = $byteValues
                    }
                } elseif ($attr.Count -eq 1) {
                    # Use GetValues([string]) (like the multi-value branch) so a
                    # single value marshals to its string form rather than the
                    # raw indexer object (which can stringify to 'System.Byte[]').
                    $h[$storeName] = [string]($attr.GetValues([string])[0])
                } else {
                    $vals = New-Object System.Collections.Generic.List[string]
                    foreach ($v in $attr.GetValues([string])) { $vals.Add([string]$v) }
                    $h[$storeName] = $vals.ToArray()
                }
            }
            $results.Add($h) | Out-Null

            if ($SizeLimit -gt 0 -and $results.Count -ge $SizeLimit) { break }
        }

        if ($SizeLimit -gt 0 -and $results.Count -ge $SizeLimit) { break }

        # Paging continuation
        if ($usePaging) {
            $cookie = $null
            foreach ($c in $resp.Controls) {
                if ($c -is [System.DirectoryServices.Protocols.PageResultResponseControl]) {
                    $cookie = $c.Cookie
                    break
                }
            }
            if ($null -eq $cookie -or $cookie.Length -eq 0) { break }
            $pagingControl.Cookie = $cookie
        } else {
            break
        }
    } while ($true)

    return ,$results.ToArray()
}

# ---------------------------------------------------------------------------
# Public: Get-AdLdapRootDse
# ---------------------------------------------------------------------------
function Get-AdLdapRootDse {
    <#
    .SYNOPSIS
        Returns the RootDSE as a hashtable. Useful for discovering naming
        contexts, supported controls, and forest-wide metadata.

    .PARAMETER Context
        Connection context from New-AdLdapConnection.

    .PARAMETER Attributes
        Attributes to load. Defaults to the common set.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$Context,

        [Parameter(Mandatory = $false)]
        [string[]]$Attributes = @(
            'defaultNamingContext',
            'configurationNamingContext',
            'schemaNamingContext',
            'rootDomainNamingContext',
            'dnsHostName',
            'serverName',
            'supportedLDAPVersion',
            'supportedControl'
        )
    )

    $entries = Invoke-AdLdapSearch -Context $Context -BaseDN '' `
        -Filter '(objectClass=*)' -Scope Base -Attributes $Attributes
    if ($entries.Count -eq 0) { return @{} }
    return $entries[0]
}

# ---------------------------------------------------------------------------
# Public: Close-AdLdapConnection
# ---------------------------------------------------------------------------
function Close-AdLdapConnection {
    <#
    .SYNOPSIS
        Disposes an LdapConnection context. Safe to call with $null.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false, ValueFromPipeline = $true)]
        [hashtable]$Context
    )
    if ($Context -and $Context.Connection) {
        try { $Context.Connection.Dispose() } catch { }
        # Null the handle and flag the context so a second Close is a no-op and a
        # reuse-after-close is detectable rather than dereferencing a disposed
        # LdapConnection.
        $Context.Connection = $null
        $Context.Disposed   = $true
    }
}

# ---------------------------------------------------------------------------
# Public: New-AdLdapConnectionPool
# ---------------------------------------------------------------------------
function New-AdLdapConnectionPool {
    <#
    .SYNOPSIS
        Creates an empty connection pool for reuse across multiple queries.

    .DESCRIPTION
        A pool is an ordered hashtable keyed by domain name. Entries are added
        lazily by Get-AdLdapPooledContext when first requested, and disposed
        collectively by Close-AdLdapConnectionPool. A pool also tracks the
        credential and insecure-fallback flags to apply when opening new
        contexts on demand.

    .PARAMETER Credential
        Optional PSCredential to use for all contexts opened through this pool.

    .PARAMETER AllowInsecure
        Enables LDAPS cert-bypass and LDAP 389 sign+seal fallback tiers for
        all contexts opened through this pool.

    .PARAMETER TimeoutSeconds
        Default timeout for bind + search on pooled contexts.

    .OUTPUTS
        Hashtable with Domains (ordered dict), Credential, AllowInsecure,
        TimeoutSeconds, and DomainSidCache fields.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory = $false)]
        [PSCredential]$Credential,

        [Parameter(Mandatory = $false)]
        [switch]$AllowInsecure,

        [Parameter(Mandatory = $false)]
        [int]$TimeoutSeconds = 120
    )
    return @{
        Domains         = [ordered]@{}     # key = domain (lowercase) → context hashtable
        Credential      = $Credential
        AllowInsecure   = [bool]$AllowInsecure
        TimeoutSeconds  = $TimeoutSeconds
        DomainSidCache  = @{}              # key = domain → domain SID string (lazy)
    }
}

# ---------------------------------------------------------------------------
# Public: Get-AdLdapPooledContext
# ---------------------------------------------------------------------------
function Get-AdLdapPooledContext {
    <#
    .SYNOPSIS
        Returns the pooled LdapConnection context for a given domain, opening
        a new connection on first access.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$Pool,

        [Parameter(Mandatory = $true)]
        [string]$Domain
    )
    $key = $Domain.ToLowerInvariant()
    if ($Pool.Domains.Contains($key)) {
        $cached = $Pool.Domains[$key]
        # A previously-cached lazy-open failure: fail fast rather than silently
        # re-attempting every connection tier on every member lookup for a domain
        # we already know we can't reach this run.
        if ($cached -is [System.Collections.IDictionary] -and $cached['Failed']) {
            throw $cached['Error']
        }
        if ($cached -is [System.Collections.IDictionary] -and $cached['Disposed']) {
            throw "Pooled context for domain '$Domain' has been disposed (pool closed); reopen the pool before reuse."
        }
        return $cached
    }

    $connParams = @{
        Server         = $Domain
        TimeoutSeconds = $Pool.TimeoutSeconds
    }
    if ($Pool.Credential)    { $connParams.Credential    = $Pool.Credential }
    if ($Pool.AllowInsecure) { $connParams.AllowInsecure = $true }

    try {
        $ctx = New-AdLdapConnection @connParams
    } catch {
        # Cache the failure so subsequent lookups for this domain fail fast
        # instead of re-running the full tier ladder on every call.
        $Pool.Domains[$key] = @{ Failed = $true; Error = [string]$_ }
        throw
    }
    $Pool.Domains[$key] = $ctx
    return $ctx
}

# ---------------------------------------------------------------------------
# Public: Close-AdLdapConnectionPool
# ---------------------------------------------------------------------------
function Close-AdLdapConnectionPool {
    <#
    .SYNOPSIS
        Disposes every LdapConnection in a pool. Safe on $null.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false, ValueFromPipeline = $true)]
        [hashtable]$Pool
    )
    if (-not $Pool) { return }
    foreach ($ctx in $Pool.Domains.Values) {
        Close-AdLdapConnection $ctx
    }
    $Pool.Domains.Clear()
}

# ---------------------------------------------------------------------------
# Public: Get-AdLdapContextForDN
# ---------------------------------------------------------------------------
function Get-AdLdapContextForDN {
    <#
    .SYNOPSIS
        Returns the pooled context whose BaseDN is the parent of the given
        distinguished name, or $null if no pooled domain owns it.

    .DESCRIPTION
        Cross-forest / cross-domain queries need to route a member DN to the
        right connection. This walks every pooled context and picks the one
        whose BaseDN is a suffix of $DistinguishedName. The longest matching
        suffix wins so a child domain wins over its parent.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$Pool,

        [Parameter(Mandatory = $true)]
        [string]$DistinguishedName
    )
    $dnLower = $DistinguishedName.ToLowerInvariant()
    $best = $null
    $bestLen = -1
    foreach ($ctx in $Pool.Domains.Values) {
        if (-not $ctx.BaseDN) { continue }
        $base = $ctx.BaseDN.ToLowerInvariant()
        if ($dnLower.EndsWith(',' + $base) -or $dnLower -eq $base) {
            if ($base.Length -gt $bestLen) {
                $best = $ctx
                $bestLen = $base.Length
            }
        }
    }
    return $best
}

# ---------------------------------------------------------------------------
# Public: ConvertTo-AdLdapSidString
# ---------------------------------------------------------------------------
function ConvertTo-AdLdapSidString {
    <#
    .SYNOPSIS
        Converts a binary SID (byte[]) to its string form ('S-1-5-...').
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [byte[]]$SidBytes
    )
    return (New-Object System.Security.Principal.SecurityIdentifier($SidBytes, 0)).Value
}

# ---------------------------------------------------------------------------
# Public: ConvertTo-AdLdapSidFilter
# ---------------------------------------------------------------------------
function ConvertTo-AdLdapSidFilter {
    <#
    .SYNOPSIS
        Converts a binary SID to an LDAP-escaped byte filter value, e.g.
        '\01\05\00\00\00\00\00\05...'. Use this to build '(objectSid=<val>)'
        filters since AD matches SIDs byte-wise, not by string.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [byte[]]$SidBytes
    )
    $sb = New-Object System.Text.StringBuilder
    foreach ($b in $SidBytes) { [void]$sb.Append(('\{0:x2}' -f $b)) }
    return $sb.ToString()
}

# ---------------------------------------------------------------------------
# Public: Get-AdLdapDomainSid
# ---------------------------------------------------------------------------
function Get-AdLdapDomainSid {
    <#
    .SYNOPSIS
        Returns the domain SID (as a string, e.g. 'S-1-5-21-aaa-bbb-ccc') for
        a pooled context, reading objectSid from the domain's defaultNamingContext.
        Cached on the pool.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$Pool,

        [Parameter(Mandatory = $true)]
        [hashtable]$Context
    )
    $key = $Context.BaseDN.ToLowerInvariant()
    if ($Pool.DomainSidCache.ContainsKey($key)) {
        return $Pool.DomainSidCache[$key]
    }
    $hits = Invoke-AdLdapSearch -Context $Context -BaseDN $Context.BaseDN -Scope Base `
        -Filter '(objectClass=*)' `
        -Attributes @('objectSid') -BinaryAttributes @('objectSid')
    if ($hits.Count -eq 0 -or -not $hits[0].ContainsKey('objectSid')) {
        $Pool.DomainSidCache[$key] = $null
        return $null
    }
    $sidString = ConvertTo-AdLdapSidString -SidBytes ([byte[]]$hits[0].objectSid)
    $Pool.DomainSidCache[$key] = $sidString
    return $sidString
}
