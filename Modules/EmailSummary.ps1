<#
.SYNOPSIS
    Optional SMTP email delivery of migration readiness HTML reports

.DESCRIPTION
    Sends the migration readiness HTML report via SMTP. This module is fully
    optional -- the tool completes successfully whether or not email is
    configured. Email failures are logged as warnings and never abort the run.

    Supports both anonymous SMTP (port 25 internal relay) and authenticated
    SMTP with TLS (port 587). Credentials are accepted via PSCredential
    parameter only -- never stored in config files.

    Uses .NET SmtpClient directly, following the same pattern as
    BreakGlass-Tool/Modules/EmailDelivery.ps1.

.NOTES
    Dot-sourced module -- do NOT use Export-ModuleMember.
    Requires GroupEnumLogger.ps1 to be dot-sourced before this file.
#>

# ---------------------------------------------------------------------------
# Public: Test-EmailConfig
# ---------------------------------------------------------------------------
function Test-EmailConfig {
    <#
    .SYNOPSIS
        Validates email configuration before attempting to send

    .DESCRIPTION
        Checks that all required SMTP fields are present and within valid
        ranges. Returns a result hashtable rather than throwing so callers
        can decide how to handle invalid config.

    .PARAMETER Config
        Top-level tool configuration hashtable. Reads the Email sub-key.

    .OUTPUTS
        Hashtable:
          Valid  - [bool] $true if config is usable
          Issues - [string[]] list of validation error messages (empty when Valid)

    .EXAMPLE
        $check = Test-EmailConfig -Config $config
        if (-not $check.Valid) { $check.Issues | ForEach-Object { Write-Warning $_ } }
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$Config
    )

    $issues = [System.Collections.Generic.List[string]]::new()

    # Email sub-key must exist
    if (-not $Config.ContainsKey('Email') -or $null -eq $Config.Email) {
        $issues.Add('Config.Email section is missing')
        return @{ Valid = $false; Issues = $issues.ToArray() }
    }

    $email = $Config.Email

    Write-GroupEnumLog -Level 'DEBUG' -Operation 'EmailConfigValidate' `
        -Message 'Validating email configuration' `
        -Context @{
            SmtpServer = $(if ($email.SmtpServer) { $email.SmtpServer } else { '' })
            SmtpPort   = $(if ($email.SmtpPort)   { $email.SmtpPort }   else { 0  })
            From       = $(if ($email.From)        { $email.From }       else { '' })
            ToCount    = $(if ($email.To)          { @($email.To).Count } else { 0 })
        }

    # Enabled flag
    if ($email.ContainsKey('Enabled') -and $email.Enabled -ne $true) {
        $issues.Add('Email.Enabled is not $true -- email is disabled by configuration')
    }

    # Required string fields
    if ([string]::IsNullOrWhiteSpace($email.SmtpServer)) {
        $issues.Add('Email.SmtpServer is required')
    }

    if ([string]::IsNullOrWhiteSpace($email.From)) {
        $issues.Add('Email.From is required')
    }

    # To must have at least one entry
    $toList = @($email.To | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    if ($toList.Count -eq 0) {
        $issues.Add('Email.To must contain at least one recipient address')
    }

    # Port range check
    $port = if ($email.SmtpPort) { [int]$email.SmtpPort } else { 25 }
    if ($port -lt 1 -or $port -gt 65535) {
        $issues.Add("Email.SmtpPort value '$port' is not in the valid range 1-65535")
    }

    $valid = ($issues.Count -eq 0)

    Write-GroupEnumLog -Level 'DEBUG' -Operation 'EmailConfigValidate' `
        -Message $(if ($valid) { 'Email configuration valid' } else { 'Email configuration invalid' }) `
        -Context @{ IssueCount = $issues.Count; Issues = ($issues -join '; ') }

    return @{
        Valid  = $valid
        Issues = $issues.ToArray()
    }
}

# ---------------------------------------------------------------------------
# Public: Build-EmailBodyText
# ---------------------------------------------------------------------------
function Build-EmailBodyText {
    <#
    .SYNOPSIS
        Builds the plain text email body with readiness summary statistics

    .DESCRIPTION
        Produces a human-readable plain text summary suitable for the email
        body when the HTML report is sent as an attachment. When the HTML
        report is inlined instead, this text is not used.

    .PARAMETER OverallReadiness
        Hashtable produced by Get-MigrationReadiness (GapAnalysis.ps1).
        Expected keys used: OverallPercent, GroupCount, ReadyCount,
        InProgressCount, BlockedCount, TotalCRItems, P1Count, P2Count, P3Count.
        Missing keys are treated as zero / unknown -- the function is
        intentionally tolerant of partial data.

    .PARAMETER CRSummaryText
        Pre-formatted plain text Change Request summary. Inserted verbatim
        after the stats block. Pass empty string if unavailable.

    .OUTPUTS
        [string] Plain text email body

    .EXAMPLE
        $body = Build-EmailBodyText -OverallReadiness $readiness -CRSummaryText $crText
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$OverallReadiness,

        [Parameter(Mandatory = $false)]
        [string]$CRSummaryText = ''
    )

    $date    = Get-Date -Format 'yyyy-MM-dd'
    $percent = $(if ($null -ne $OverallReadiness.OverallPercent) {
        '{0:N1}' -f [double]$OverallReadiness.OverallPercent
    } else { 'N/A' })

    $groupCount   = $(if ($null -ne $OverallReadiness.GroupCount)      { $OverallReadiness.GroupCount }      else { 0 })
    $readyCount   = $(if ($null -ne $OverallReadiness.ReadyCount)      { $OverallReadiness.ReadyCount }      else { 0 })
    $inProgCount  = $(if ($null -ne $OverallReadiness.InProgressCount) { $OverallReadiness.InProgressCount } else { 0 })
    $blockedCount = $(if ($null -ne $OverallReadiness.BlockedCount)    { $OverallReadiness.BlockedCount }    else { 0 })
    $totalCR      = $(if ($null -ne $OverallReadiness.TotalCRItems)    { $OverallReadiness.TotalCRItems }    else { 0 })
    $p1Count      = $(if ($null -ne $OverallReadiness.P1Count)         { $OverallReadiness.P1Count }         else { 0 })
    $p2Count      = $(if ($null -ne $OverallReadiness.P2Count)         { $OverallReadiness.P2Count }         else { 0 })
    $p3Count      = $(if ($null -ne $OverallReadiness.P3Count)         { $OverallReadiness.P3Count }         else { 0 })

    $sb = [System.Text.StringBuilder]::new()
    $null = $sb.AppendLine("Migration Readiness Report - $date")
    $null = $sb.AppendLine('========================================')
    $null = $sb.AppendLine("Overall Readiness: $percent%")
    $null = $sb.AppendLine("Groups: $groupCount analyzed ($readyCount ready, $inProgCount in progress, $blockedCount blocked)")
    $null = $sb.AppendLine("Change Requests: $totalCR total ($p1Count P1, $p2Count P2, $p3Count P3)")
    $null = $sb.AppendLine('')
    $null = $sb.AppendLine('See attached HTML report for full details.')

    if (-not [string]::IsNullOrWhiteSpace($CRSummaryText)) {
        $null = $sb.AppendLine('')
        $null = $sb.AppendLine('--- CR SUMMARY ---')
        $null = $sb.AppendLine($CRSummaryText.Trim())
    }

    return $sb.ToString()
}

# ---------------------------------------------------------------------------
# Private helper: Build-EmailSubject
# ---------------------------------------------------------------------------
function Build-EmailSubject {
    <#
    .SYNOPSIS
        Constructs the email subject line from readiness data and config

    .PARAMETER EmailConfig
        The Email sub-section of the tool config hashtable

    .PARAMETER OverallReadiness
        Readiness hashtable (same as Build-EmailBodyText)
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$EmailConfig,

        [Parameter(Mandatory = $true)]
        [hashtable]$OverallReadiness
    )

    # If caller already provided a full subject, use it verbatim
    if (-not [string]::IsNullOrWhiteSpace($EmailConfig.Subject)) {
        return $EmailConfig.Subject
    }

    $prefix  = $(if (-not [string]::IsNullOrWhiteSpace($EmailConfig.SubjectPrefix)) {
        $EmailConfig.SubjectPrefix.Trim()
    } else {
        '[Migration Readiness]'
    })

    $percent = $(if ($null -ne $OverallReadiness.OverallPercent) {
        '{0:N1}' -f [double]$OverallReadiness.OverallPercent
    } else { 'N/A' })

    $totalCR = $(if ($null -ne $OverallReadiness.TotalCRItems) {
        [int]$OverallReadiness.TotalCRItems
    } else { 0 })

    $date = Get-Date -Format 'yyyy-MM-dd'

    return "$prefix $percent% Ready - $totalCR CRs - $date"
}

# ---------------------------------------------------------------------------
# Public: Send-MigrationSummaryEmail
# ---------------------------------------------------------------------------
function Send-MigrationSummaryEmail {
    <#
    .SYNOPSIS
        Sends the migration readiness HTML report via SMTP email

    .DESCRIPTION
        Delivers the generated HTML report to the configured recipients.
        Supports two delivery modes:
          - AttachReport = $true  : plain text body + HTML file as attachment
          - AttachReport = $false : full HTML content inlined as the email body

        Supports anonymous SMTP (port 25 internal relay) and authenticated
        SMTP with TLS (port 587). SmtpClient and MailMessage are always
        disposed in a finally block regardless of send outcome.

        Email sending is intentionally non-fatal. Any failure is logged as a
        warning. The HTML report file has already been written to disk before
        this function is called -- no report data is lost on email failure.

    .PARAMETER HtmlReportPath
        Full path to the generated HTML report file.

    .PARAMETER Config
        Top-level tool configuration hashtable containing an Email sub-key.
        Required Email keys: SmtpServer, From, To.
        Optional Email keys: SmtpPort (default 25), UseSsl (default $false),
          Cc, Subject, SubjectPrefix, AttachReport (default $true).

    .PARAMETER OverallReadiness
        Readiness hashtable produced by Get-MigrationReadiness. Used for
        building the subject line and plain text body summary.

    .PARAMETER CRSummaryText
        Optional plain text Change Request summary. Appended to the email
        body when AttachReport is $true.

    .PARAMETER Credential
        Optional PSCredential for authenticated SMTP. Pass $null (default)
        for anonymous relay. Never embed credentials in Config.

    .OUTPUTS
        Hashtable:
          Sent       - [bool]     $true if SmtpClient.Send() completed without error
          Recipients - [string[]] list of To addresses that were targeted
          Subject    - [string]   the subject line used
          Error      - [string]   error message string, or $null on success

    .EXAMPLE
        $result = Send-MigrationSummaryEmail `
            -HtmlReportPath 'C:\Reports\migration.html' `
            -Config $config `
            -OverallReadiness $readiness `
            -CRSummaryText $crText

        if (-not $result.Sent) {
            Write-Warning "Email failed: $($result.Error)"
        }

    .EXAMPLE
        # Authenticated SMTP with TLS (port 587)
        $cred = Get-Credential
        $result = Send-MigrationSummaryEmail `
            -HtmlReportPath $reportPath `
            -Config $config `
            -OverallReadiness $readiness `
            -Credential $cred
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$HtmlReportPath,

        [Parameter(Mandatory = $true)]
        [hashtable]$Config,

        [Parameter(Mandatory = $true)]
        [hashtable]$OverallReadiness,

        [Parameter(Mandatory = $false)]
        [string]$CRSummaryText = '',

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]$Credential = $null
    )

    # Default return value -- updated throughout
    $result = @{
        Sent       = $false
        Recipients = @()
        Subject    = ''
        Error      = $null
    }

    # -------------------------------------------------------------------------
    # 1. Validate config before attempting anything
    # -------------------------------------------------------------------------
    $check = Test-EmailConfig -Config $Config
    if (-not $check.Valid) {
        $issueText = $check.Issues -join '; '
        Write-GroupEnumLog -Level 'WARN' -Operation 'EmailSend' `
            -Message 'Email configuration invalid -- skipping send' `
            -Context @{ Issues = $issueText }
        Write-Warning "EmailSummary: Cannot send email -- $issueText"
        $result.Error = "Config invalid: $issueText"
        return $result
    }

    $emailCfg = $Config.Email

    # -------------------------------------------------------------------------
    # 2. Validate report file exists
    # -------------------------------------------------------------------------
    if (-not (Test-Path -LiteralPath $HtmlReportPath -PathType Leaf)) {
        $msg = "HTML report file not found: $HtmlReportPath"
        Write-GroupEnumLog -Level 'WARN' -Operation 'EmailSend' `
            -Message $msg -Context @{ HtmlReportPath = $HtmlReportPath }
        Write-Warning "EmailSummary: $msg"
        $result.Error = $msg
        return $result
    }

    # -------------------------------------------------------------------------
    # 3. Resolve config values with defaults
    # -------------------------------------------------------------------------
    $smtpServer  = $emailCfg.SmtpServer.Trim()
    $smtpPort    = $(if ($emailCfg.SmtpPort -and [int]$emailCfg.SmtpPort -gt 0) {
        [int]$emailCfg.SmtpPort
    } else { 25 })
    $useSsl      = $(if ($emailCfg.ContainsKey('UseSsl')) { [bool]$emailCfg.UseSsl } else { $false })
    $fromAddr    = $emailCfg.From.Trim()
    $toList      = @($emailCfg.To | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    $ccList      = $(if ($emailCfg.Cc) {
        @($emailCfg.Cc | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    } else { @() })
    $attachReport = $(if ($emailCfg.ContainsKey('AttachReport')) {
        [bool]$emailCfg.AttachReport
    } else { $true })

    $subject = Build-EmailSubject -EmailConfig $emailCfg -OverallReadiness $OverallReadiness
    $result.Recipients = $toList
    $result.Subject    = $subject

    Write-GroupEnumLog -Level 'DEBUG' -Operation 'EmailSend' `
        -Message 'Preparing to send migration summary email' `
        -Context @{
            SmtpServer    = $smtpServer
            SmtpPort      = $smtpPort
            UseSsl        = $useSsl
            From          = $fromAddr
            ToCount       = $toList.Count
            CcCount       = $ccList.Count
            Subject       = $subject
            AttachReport  = $attachReport
            HtmlReportPath = $HtmlReportPath
            HasCredential = ($null -ne $Credential)
        }

    # -------------------------------------------------------------------------
    # 4. Build email content
    # -------------------------------------------------------------------------
    if ($attachReport) {
        $bodyText   = Build-EmailBodyText -OverallReadiness $OverallReadiness `
                          -CRSummaryText $CRSummaryText
        $isBodyHtml = $false
    } else {
        # Inline HTML body -- read the report file
        try {
            $bodyText = [System.IO.File]::ReadAllText(
                $HtmlReportPath,
                [System.Text.Encoding]::UTF8
            )
        } catch {
            $msg = "Failed to read HTML report for inline body: $_"
            Write-GroupEnumLog -Level 'WARN' -Operation 'EmailSend' `
                -Message $msg -Context @{ HtmlReportPath = $HtmlReportPath }
            Write-Warning "EmailSummary: $msg"
            $result.Error = $msg
            return $result
        }
        $isBodyHtml = $true
    }

    # -------------------------------------------------------------------------
    # 5. Send via .NET SmtpClient
    # -------------------------------------------------------------------------
    $smtpClient  = $null
    $mailMessage = $null

    try {
        # Build SmtpClient
        $smtpClient            = [System.Net.Mail.SmtpClient]::new($smtpServer, $smtpPort)
        $smtpClient.EnableSsl  = $useSsl
        $smtpClient.DeliveryMethod = [System.Net.Mail.SmtpDeliveryMethod]::Network

        if ($null -ne $Credential) {
            $smtpClient.Credentials = $Credential.GetNetworkCredential()
        } else {
            $smtpClient.UseDefaultCredentials = $false
        }

        # Build MailMessage
        $mailMessage             = [System.Net.Mail.MailMessage]::new()
        $mailMessage.From        = [System.Net.Mail.MailAddress]::new($fromAddr)
        $mailMessage.Subject     = $subject
        $mailMessage.Body        = $bodyText
        $mailMessage.IsBodyHtml  = $isBodyHtml

        foreach ($addr in $toList) {
            $mailMessage.To.Add($addr.Trim())
        }
        foreach ($addr in $ccList) {
            $mailMessage.CC.Add($addr.Trim())
        }

        # Attach the HTML report if requested
        if ($attachReport) {
            $attachment = [System.Net.Mail.Attachment]::new(
                $HtmlReportPath,
                'text/html'
            )
            $fileName = [System.IO.Path]::GetFileName($HtmlReportPath)
            $attachment.ContentDisposition.FileName = $fileName
            $mailMessage.Attachments.Add($attachment)
        }

        # Send
        $smtpClient.Send($mailMessage)

        $result.Sent  = $true
        $result.Error = $null

        Write-GroupEnumLog -Level 'INFO' -Operation 'EmailSend' `
            -Message 'Migration summary email sent successfully' `
            -Context @{
                SmtpServer = $smtpServer
                SmtpPort   = $smtpPort
                Subject    = $subject
                To         = ($toList -join ', ')
                Cc         = $(if ($ccList.Count -gt 0) { $ccList -join ', ' } else { '' })
                Attached   = $attachReport
            }

    } catch {
        $errorMsg = $_.Exception.Message
        $result.Sent  = $false
        $result.Error = $errorMsg

        Write-GroupEnumLog -Level 'WARN' -Operation 'EmailSend' `
            -Message "Email send failed: $errorMsg" `
            -Context @{
                SmtpServer = $smtpServer
                SmtpPort   = $smtpPort
                Subject    = $subject
                To         = ($toList -join ', ')
                ErrorType  = $_.Exception.GetType().Name
            }
        Write-Warning "EmailSummary: Email send failed -- $errorMsg"

    } finally {
        # Always dispose, even if attachment add or Send threw
        if ($null -ne $mailMessage) {
            # Disposing MailMessage also disposes its Attachments collection
            $mailMessage.Dispose()
        }
        if ($null -ne $smtpClient) {
            $smtpClient.Dispose()
        }
    }

    return $result
}
