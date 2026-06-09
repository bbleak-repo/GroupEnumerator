# Quick Start Guide

## Prerequisites

- PowerShell 5.1 (Windows) or PowerShell 7+ (any platform)
- Network connectivity to target domain controllers on port 636 (LDAPS); 389 is only used by fallback tiers
- A user account with read access to AD group membership (no admin needed)
- Works against DCs enforcing LDAP Channel Binding and LDAP Signing -- no workaround required

## Getting help

Run the script with no arguments or with `-Help` to see a usage summary with examples:

```powershell
.\Invoke-GroupEnumerator.ps1
.\Invoke-GroupEnumerator.ps1 -Help
```

For full parameter documentation:

```powershell
Get-Help .\Invoke-GroupEnumerator.ps1 -Detailed
```

## Step 1: Prepare Your CSV

Create a CSV file listing the groups to enumerate. Use either format.
Header names must match **exactly** (case-insensitive) -- `Groups` (plural)
or other variants will be rejected with an error that lists the supported formats.

**Option A -- Two columns (`Domain,GroupName`):**
```csv
Domain,GroupName
CONTOSO,GG_IT_Admins
CONTOSO,GG_Finance_Users
FABRIKAM,USV_IT_Admins
FABRIKAM,USV_Finance_Users
```

**Option B -- Single column (`Group`, values in `DOMAIN\GroupName`):**
```csv
Group
CONTOSO\GG_IT_Admins
CONTOSO\GG_Finance_Users
FABRIKAM\USV_IT_Admins
FABRIKAM\USV_Finance_Users
```

Ready-to-copy sample files live in [`../Templates/`](../Templates/):
- `groups-example-standard.csv`
- `groups-example-backslash.csv`

## Step 2: Basic Single-Domain Inventory (V1)

For a simple "show me who's in these groups" report against one domain, no switches are needed:

```powershell
.\Invoke-GroupEnumerator.ps1 -CsvPath .\groups.csv
```

This will:
1. Enumerate all groups via verified LDAPS (Tier 1) with integrated Kerberos auth
2. Generate a V1 HTML report in `Output/` (search, sort, copy-as-TSV)
3. Save a JSON cache in `Cache/`
4. Write a structured log in `Logs/`

Add `-ResolveNested -DetectStale` for a deeper inventory view that flattens nested memberships and flags inactive accounts:

```powershell
.\Invoke-GroupEnumerator.ps1 -CsvPath .\groups.csv -ResolveNested -DetectStale
```

## Step 3: Cross-Domain Matching (V1 + FuzzyMatch)

When your CSV includes groups from two or more domains, add `-FuzzyMatch` to pair them by normalized name (e.g. `GG_IT_Admins` ~ `USV_IT_Admins`):

```powershell
.\Invoke-GroupEnumerator.ps1 -CsvPath .\groups.csv -FuzzyMatch
```

## Step 4: Cross-Forest Without CA Trust (Fallback Tiers)

If your workstation can't validate the remote DC's TLS certificate (common in cross-forest or lab scenarios), enable the fallback tiers with `-AllowInsecure`:

```powershell
.\Invoke-GroupEnumerator.ps1 -CsvPath .\groups.csv -FuzzyMatch -AllowInsecure
```

Tier order is:
1. LDAPS 636 with strict cert verification (always tried first)
2. LDAPS 636 with cert verification bypassed -- channel still TLS-encrypted, you're just trusting the server identity on faith
3. LDAP 389 with SASL sign+seal -- Kerberos-wrapped session over unencrypted 389

Whichever tier actually connects is logged as a structured `LdapConnect` event and surfaced in the HTML report when it's anything other than Tier 1.

## Step 5: With Explicit Credentials

```powershell
$cred = Get-Credential -Message "Enter credentials for LDAP queries"
.\Invoke-GroupEnumerator.ps1 -CsvPath .\groups.csv -FuzzyMatch -AllowInsecure -Credential $cred
```

## Step 6: Migration Readiness Analysis (V2)

```powershell
.\Invoke-GroupEnumerator.ps1 -CsvPath .\groups.csv -FuzzyMatch -AllowInsecure `
    -AnalyzeGaps `          # Run gap analysis with user correlation
    -DetectStale `          # Flag disabled/stale accounts
    -ResolveNested `        # Flatten nested group memberships
    -StaleDays 90           # Accounts inactive > 90 days = stale
```

This produces:
- **Migration dashboard HTML** -- readiness percentages, progress bars, executive summary
- **Gap analysis CSV** -- actionable items for Change Requests (P1/P2/P3)
- **CR summary text** -- plain-text summary ready for ticket systems

## Step 7: Add Application Mapping (Optional)

Create an app mapping CSV:
```csv
AppName,SourceGroup,TargetGroup,Notes
CRM Application,GG_Sales_Users,USV_Sales_Users,IdP initiated
Helpdesk Portal,GG_ITSM_Team,USV_ITSM_Team,SP initiated
```

Then:
```powershell
.\Invoke-GroupEnumerator.ps1 -CsvPath .\groups.csv -FuzzyMatch -AllowInsecure `
    -AnalyzeGaps -DetectStale -AppMappingCsv .\app-mapping.csv
```

## Step 8: Daily Change Tracking (V3)

Enable persistent membership change tracking to detect adds/removals between runs:

```powershell
# First run seeds the baseline (no false-positive "add" events)
.\Invoke-GroupEnumerator.ps1 -CsvPath .\groups.csv -TrackChanges

# Subsequent runs detect membership changes and write to changelog
.\Invoke-GroupEnumerator.ps1 -CsvPath .\groups.csv -TrackChanges
```

State is saved in `State/membership-state.json` and changes are appended to `State/changelog.jsonl`.

### Step 8b: Choosing a state backend (JSON vs SQLite)

Change tracking has two backends. The default **JSON** backend keeps a per-CSV view
("what changed in *this* CSV since *this* CSV last ran"). The opt-in **SQLite**
backend uses **group-as-PK**: one global baseline per `(domain, group)`, so a change
is detected once globally regardless of which CSV references the group -- ideal for an
authoritative, deduplicated history and accurate distinct-user counts.

```powershell
# Use the SQLite backend (group-as-PK); state lives in State\group-enumerator.db
.\Invoke-GroupEnumerator.ps1 -CsvPath .\groups.csv -TrackChanges -StateBackend sqlite
```

Even with the global model, SQLite remembers **which CSVs each group appeared in**
(`csv_group_map`), so you can still pull a **per-CSV change view** when needed:

```powershell
# Per-CSV view of the global changelog (no duplicate baselines):
python state_db.py query-changes --db State\group-enumerator.db --csv groups

# True distinct users vs raw membership rows (e.g. 25,000 memberships -> 500 users):
python state_db.py stats --db State\group-enumerator.db   # Members vs DistinctMembers
```

> The two backends behave **identically** unless a group is referenced by more than
> one CSV. See the README "State & Change-Tracking Model" section for the full picture.

## Step 9: Governance & Compliance Reports (V3)

Generate governance-tier reports alongside change tracking:

```powershell
.\Invoke-GroupEnumerator.ps1 -CsvPath .\groups.csv -TrackChanges `
    -GovernanceReport `       # Identity-centric access certification (Word-compatible)
    -ComplianceReport `       # Audit evidence with drift analysis and sign-off
    -ExecutiveDashboard `     # KPI dashboard with SVG charts
    -LeadershipSummary `      # 1-page director-level rollup
    -DetectStale              # Include stale/disabled account risk flags
```

Use `-ChangePeriod` to scope change data to a specific time window:

```powershell
# Show only changes from the past week in reports
.\Invoke-GroupEnumerator.ps1 -CsvPath .\groups.csv -TrackChanges `
    -ChangePeriod Week -GovernanceReport -ComplianceReport
```

Valid periods: `Day`, `Week`, `Month`, `Quarter`.

## Step 10: Regenerate Reports from Cache

```powershell
# Regenerate HTML from cached JSON (no LDAP needed)
.\Invoke-GroupEnumerator.ps1 -CsvPath .\groups.csv -FromCache `
    -CachePath .\Cache\groups-20260409-143000.json

# Change theme
.\Invoke-GroupEnumerator.ps1 -CsvPath .\groups.csv -FromCache `
    -CachePath .\Cache\groups-20260409-143000.json -Theme light
```

## Step 11: Email the Report (Optional)

Configure email in `Config/group-enum-config.json`:
```json
{
    "Email": {
        "Enabled": true,
        "SmtpServer": "smtp.company.com",
        "SmtpPort": 25,
        "From": "migration-tool@company.com",
        "To": ["team@company.com"],
        "SubjectPrefix": "[Migration Readiness]",
        "AttachReport": true
    }
}
```

Then add `-SendEmail`:
```powershell
.\Invoke-GroupEnumerator.ps1 -CsvPath .\groups.csv -FuzzyMatch -AllowInsecure `
    -AnalyzeGaps -DetectStale -SendEmail
```

## Configuration

All settings are in `Config/group-enum-config.json`. Key options:

| Setting | Default | Description |
|---------|---------|-------------|
| `FuzzyPrefixes` | GG_, USV_, SG_, DL_, GL_ | Prefixes stripped before fuzzy matching |
| `FuzzyMinScore` | 0.7 | Minimum Levenshtein similarity (0.0-1.0) |
| `SkipGroups` | Domain Users, etc. | Groups to skip automatically |
| `LargeGroupThreshold` | 5000 | Skip groups with more members than this |
| `AllowInsecure` | false | Enable LDAP 389 fallback (overridden by -AllowInsecure switch) |
| `LogLevel` | INFO | DEBUG for verbose, WARN for errors only |
| `StaleAccountDays` | 90 | Days since last logon to consider stale |
| `NestedGroupMaxDepth` | 10 | Max recursion depth for nested groups |
| `ChangeTracking.Enabled` | false | Enable change tracking by default |
| `ChangeTracking.MaxChangeLogSizeMB` | 50 | Archive changelog when it exceeds this size |
| `ChangeTracking.RetentionDays` | 0 | Trim changelog entries older than N days (0=disabled) |
| `StateBackend` | json | State backend: `json` or `sqlite` |
| `Reporting.GovernanceReport` | false | Generate governance report by default |
| `Reporting.ComplianceReport` | false | Generate compliance report by default |

## Troubleshooting

**LDAPS (Tier 1) connection fails with cert errors:**
- Ensure port 636 is reachable to the target DC
- Use `-AllowInsecure` to enable Tier 2 (cert bypass) and Tier 3 (389 sign+seal)
- Check `Logs/*.jsonl` for `LdapConnect` events showing the actual tier used

**All tiers fail with "The user name or password is incorrect":**
- This is LDAP error 49; common causes are Channel Binding / Signing mismatches or a logon session that isn't actually authenticated to the target domain
- `LdapConnection` (the modern stack this tool uses) handles Channel Binding correctly, so this usually points at a credential issue
- Try `-Credential (Get-Credential)` to bind explicitly instead of relying on integrated auth

**Large groups causing timeouts:**
- Increase `LdapTimeout` in config (default 120 seconds)
- Add large groups to `SkipGroups` list
- Lower `LargeGroupThreshold` to skip them automatically

**Debug logging:**
- Set `"LogLevel": "DEBUG"` in config to see every LDAP connection attempt and member query
- Each `LdapConnect` log entry includes `tier`, `port`, `baseDN`, and `pooled` fields
