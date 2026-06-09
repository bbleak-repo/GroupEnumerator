# Cross-Domain Group Enumerator

A production-ready PowerShell tool for enumerating Active Directory group memberships across trusted forests, with cross-domain fuzzy matching, migration readiness analysis, and professional HTML reporting.

## Features

### V1 -- Group Enumeration & Comparison
- **CSV-driven input** -- `Domain,GroupName` or `DOMAIN\GroupName` backslash format (auto-detected); group values may be plain names or full distinguished names
- **Modern LDAP stack** -- Built on `System.DirectoryServices.Protocols.LdapConnection` (works against DCs enforcing LDAP Channel Binding / Signing, the modern hardened default)
- **Tiered connectivity** -- LDAPS-Verified (636) by default; with `-AllowInsecure` falls through LDAPS cert-bypass then LDAP 389 with Kerberos sign+seal; tier in use is surfaced in the report and logs
- **Per-domain connection pooling** -- One `LdapConnection` per domain, reused across every group, nested-resolve, and stale-check call in a single invocation
- **Fuzzy group matching** -- Levenshtein-based name matching strips configurable prefixes (GG\_, USV\_, SG\_, DL\_, GL\_) to pair groups across domains
- **Dark/light HTML reports** -- Theme toggle persisted to localStorage, sortable columns, per-table search, copy-as-TSV for Excel
- **Side-by-side member diff** -- Color-coded highlighting showing members unique to each domain
- **JSON cache** -- Save/reload enumerated data with `-FromCache` for offline report regeneration
- **Structured logging** -- JSON Lines (.jsonl) with DEBUG/INFO/WARN/ERROR levels, per-tier LdapConnect events

### V2 -- Migration Readiness Analysis
- **Nested group resolution** -- Recursive flattening with cycle detection and configurable depth limit
- **5-tier user correlation** -- Matches users across domains where accounts differ:
  - Tier 1: Email exact match (High confidence)
  - Tier 2: SAM exact match (Medium, flagged for review)
  - Tier 3: DisplayName normalized match (Medium, strips identity system tags)
  - Tier 4: SAM fuzzy match (Low, requires human review)
  - Tier 5: No match (reported as unmatched)
- **Gap analysis** -- Per-group migration readiness scoring with Change Request generation:
  - P1: User not provisioned in target domain
  - P2: User exists but missing from target group
  - P3: Orphaned access in target (security review)
- **Stale account detection** -- Flags disabled and inactive accounts (configurable threshold)
- **Cross-forest member resolution** -- When multiple domains are pooled, member DNs that live in another pooled domain are routed to the correct connection, and ForeignSecurityPrincipal entries are resolved by SID against the foreign pool (two-way trust scenarios)
- **Application mapping** -- Optional CSV mapping apps to groups for app-level readiness view
- **Migration dashboard** -- Progress bars, executive summary, CR summary with copy button
- **Email delivery** -- Optional SMTP summary (supports anonymous relay and authenticated TLS)

### V3 -- Change Tracking, Governance & Compliance Reporting
- **Persistent change tracking** -- JSON state ledger (`state.json`) + append-only changelog (`changelog.jsonl`) detect adds/removals between consecutive runs
- **Unified v2 state** -- Multiple CSV sources merge into a single state file with `CsvSources` tracking
- **Change period reports** -- `-ChangePeriod Day|Week|Month|Quarter` surfaces historical changes in reports
- **Changelog rotation** -- Size-based archiving (`MaxChangeLogSizeMB`) and retention-based trimming (`RetentionDays`)
- **Legacy state migration** -- `Merge-LegacyState` consolidates per-CSV v1 state files into unified v2 format
- **4 new report types:**
  - **Access Governance Report** (Audit Tier) -- Identity-centric SailPoint-style access certification, inline CSS, Word-compatible
  - **Executive Dashboard** (Executive Tier) -- SVG donut charts, KPI cards, change velocity bars, embedded CSS
  - **Compliance Audit Report** (Audit Tier) -- Point-in-time audit evidence, drift analysis, reviewer sign-off, Word-compatible
  - **Leadership Summary** (Leadership Tier) -- 1-page print/PDF optimized director-level rollup
- **Change report HTML** -- Self-contained dark/light themed change report with per-group add/remove tables
- **Change feed CSV** -- SailPoint-ready CSV keyed on sAMAccountName, RFC 4180 escaped
- **Membership drift** -- Snapshot-vs-snapshot comparison (baseline and previous run)
- **SQLite backend** -- Optional `state_db.py` + `schema.sql` for high-volume state management
- **Incremental gate** -- Skip unchanged groups based on `whenChanged` attribute

## Requirements

- PowerShell 5.1 or PowerShell 7+
- `System.DirectoryServices.Protocols` (ships with .NET on Windows; available via .NET on other platforms)
- Network access to target domain controllers on port 636 (LDAPS) or 389 (LDAP) if using fallback tiers
- No RSAT modules required
- No admin rights required (read-only LDAP queries)
- Works against DCs enforcing LDAP Channel Binding and LDAP Signing (the hardened modern default)

## Quick Start

```powershell
# Show usage summary (also printed when invoked with no arguments)
.\Invoke-GroupEnumerator.ps1 -Help

# Simplest single-domain inventory (V1 report)
.\Invoke-GroupEnumerator.ps1 -CsvPath .\groups.csv

# Single-domain inventory with nested group flattening and stale flagging
.\Invoke-GroupEnumerator.ps1 -CsvPath .\groups.csv -ResolveNested -DetectStale

# Cross-domain fuzzy match (verified LDAPS only)
.\Invoke-GroupEnumerator.ps1 -CsvPath .\groups.csv -FuzzyMatch

# Full two-forest migration readiness with fallback tiers enabled
.\Invoke-GroupEnumerator.ps1 -CsvPath .\groups.csv -FuzzyMatch `
    -AnalyzeGaps -DetectStale -ResolveNested -AllowInsecure

# Offline re-render from a saved cache (no AD access)
.\Invoke-GroupEnumerator.ps1 -CsvPath .\groups.csv -FromCache `
    -CachePath .\Cache\groups-20260415-103821.json

# With application mapping
.\Invoke-GroupEnumerator.ps1 -CsvPath .\groups.csv -FuzzyMatch -AllowInsecure `
    -AnalyzeGaps -DetectStale -AppMappingCsv .\app-mapping.csv

# V3: Daily change tracking (seeds on first run, detects changes on subsequent runs)
.\Invoke-GroupEnumerator.ps1 -CsvPath .\groups.csv -TrackChanges

# V3: Change tracking + all 4 governance/compliance reports
.\Invoke-GroupEnumerator.ps1 -CsvPath .\groups.csv -TrackChanges `
    -GovernanceReport -ComplianceReport -ExecutiveDashboard -LeadershipSummary

# V3: Weekly change period (report shows last 7 days of changes)
.\Invoke-GroupEnumerator.ps1 -CsvPath .\groups.csv -TrackChanges `
    -ChangePeriod Week -GovernanceReport -ComplianceReport
```

See [QUICKSTART.md](docs/QUICKSTART.md) for detailed setup instructions, or run
`Get-Help .\Invoke-GroupEnumerator.ps1 -Detailed` for full parameter docs.

## CSV Input Format

Two formats are supported; the header row is auto-detected (case-insensitive).
Header names must match **exactly** -- `Groups` (plural) or other variants will be
rejected with an error that lists the supported formats.

**Format 1 -- two-column (`Domain,GroupName`):**
```csv
Domain,GroupName
CONTOSO,GG_IT_Admins
FABRIKAM,USV_IT_Admins
```

**Format 2 -- single-column (`Group`, values in `DOMAIN\GroupName`):**
```csv
Group
CONTOSO\GG_IT_Admins
FABRIKAM\USV_IT_Admins
```

**Group value may be a full distinguished name.** In either format, a group value may be a
plain name (resolved by CN) **or** a full DN, auto-detected per row. A DN is the unambiguous
identifier -- it disambiguates duplicate names across OUs and is bound directly (Base scope).
The domain is derived from the DN's `DC=` components, so the `Domain` column is optional on DN
rows; the report shows the resolved short name:
```csv
Domain,GroupName
CONTOSO,GG_IT_Admins
,"CN=GG_IT_Admins,OU=Groups,OU=Corp,DC=corp,DC=com"
,"CN=CyberArk-Vault Admins,OU=PAM,DC=corp,DC=com"
```

Ready-to-copy sample files live in [`Templates/`](Templates/):
- `groups-example-standard.csv`
- `groups-example-backslash.csv`
- `groups-example-dn.csv` (full-DN group values)

**Application mapping (optional):**
```csv
AppName,SourceGroup,TargetGroup,Notes
CRM App,GG_Sales_Users,USV_Sales_Users,IdP initiated
Helpdesk,GG_ITSM_Team,USV_ITSM_Team,SP initiated
```

## Output Files

| File | Description |
|------|-------------|
| `Output/<csv>-<timestamp>.html` | HTML report (v1 or v2 migration dashboard) |
| `Cache/<csv>-<timestamp>.json` | JSON cache for offline regeneration |
| `Output/<csv>-<timestamp>-gaps.csv` | Gap analysis CSV (v2, when `-AnalyzeGaps`) |
| `Output/<csv>-<timestamp>-cr-summary.txt` | Change Request summary (v2) |
| `Logs/group-enum-<timestamp>.jsonl` | Structured log file |
| `Output/<csv>-governance-<timestamp>.html` | Access Governance Report (v3) |
| `Output/<csv>-executive-<timestamp>.html` | Executive Dashboard (v3) |
| `Output/<csv>-compliance-<timestamp>.html` | Compliance Audit Report (v3) |
| `Output/<csv>-leadership-<timestamp>.html` | Leadership Summary (v3) |
| `State/membership-state.json` | Persistent change tracking state (v3) |
| `State/changelog.jsonl` | Append-only change log (v3) |
| `Output/<csv>-changes-<timestamp>.html` | Change report HTML (v3) |
| `Output/<csv>-change-feed-<timestamp>.csv` | SailPoint-ready change feed CSV (v3) |

## Configuration

Edit `Config/group-enum-config.json` to customize:

```json
{
    "LdapPageSize": 1000,
    "LdapTimeout": 120,
    "MaxMemberCount": 5000,
    "SkipLargeGroups": true,
    "LargeGroupThreshold": 5000,
    "SkipGroups": ["Domain Users", "Domain Computers", "Authenticated Users"],
    "FuzzyPrefixes": ["GG_", "USV_", "SG_", "DL_", "GL_"],
    "FuzzyMinScore": 0.7,
    "AllowInsecure": false,
    "LogLevel": "INFO",
    "StaleAccountDays": 90,
    "ChangeTracking": {
        "Enabled": false,
        "UnifiedState": true,
        "StatePath": "State",
        "MaxChangeLogSizeMB": 50,
        "RetentionDays": 0
    },
    "StateBackend": "json",
    "Reporting": {
        "GovernanceReport": false,
        "ComplianceReport": false,
        "ExecutiveDashboard": false,
        "LeadershipSummary": false
    }
}
```

## State & Change-Tracking Model (JSON vs SQLite)

`-TrackChanges` records membership adds/removes between runs in a persistent state
store plus an append-only changelog. Two backends are available, selected by
`StateBackend` in config or the `-StateBackend` switch:

### JSON backend (default) -- per-CSV view
- Each CSV source keeps its own baseline. The unified v2 state file holds a global
  `GroupsByKey` plus a `CsvSources` map (which groups each CSV contributed).
- "Changes" mean *what changed in this CSV's view since this CSV last ran*.
- Best for operational, per-list ownership -- "show me what changed in **my** groups."

### SQLite backend (opt-in) -- group-as-PK (global)
- Set `StateBackend: "sqlite"` (or `-StateBackend sqlite`); uses `state_db.py` + `schema.sql`.
- **The group is the primary key** (`domain` + `group_name`): one GLOBAL membership
  baseline per group, independent of CSV filenames (which change over time).
- A change is detected **once, globally** -- a group already in the database is diffed
  against its baseline no matter which CSV references it; only a brand-new group is
  seeded silently. The changelog stays symmetric (an add is logged when first seen,
  the matching remove when the member later leaves).
- Best for an authoritative, deduplicated per-group history (governance, compliance,
  high volume) and for accurate distinct-user counts.

### Both views from one store: CSV provenance
Even under the global group-as-PK model, the SQLite backend records **which CSVs each
group appeared in** (`csv_group_map` -- a many-to-many mapping maintained every run).
That powers a **per-CSV view on demand** without keeping duplicate baselines:

```powershell
# Changes for just one CSV's groups (filtered through provenance):
python state_db.py query-changes --db State\group-enumerator.db --csv east-groups
```

So the **global group-as-PK view is the default** (used in almost all cases), and you
can still **report per-CSV when needed**. The same provenance exists on the JSON side
via `CsvSources`.

> **When do the two models differ?** Only for a group referenced by *more than one*
> CSV. For groups that live in a single CSV (the common case), JSON and SQLite behave
> identically.

### Distinct users vs memberships
A user in 10 groups is 10 *memberships* but 1 *identity*. The SQLite `stats` command
reports both, so a tenant with 25,000 memberships across 500 people reads as 500:

```powershell
python state_db.py stats --db State\group-enumerator.db
# Members         -> membership rows
# DistinctMembers -> unique identities by (domain, sAMAccountName)
```

Compliance posture and the leadership "Total Identities" metric likewise count
**distinct accounts**, not summed memberships.

## Architecture

```
Group-Enumerator/
  Invoke-GroupEnumerator.ps1       # Main orchestrator (pool owner, flow control)
  Config/
    group-enum-config.json         # All settings
  Modules/
    ADLdap.ps1                     # Shared LDAP helper (LdapConnection, pool, tiers)
    GroupEnumLogger.ps1            # JSON Lines structured logging
    GroupEnumerator.ps1            # Group enumeration + cross-forest member resolution
    FuzzyMatcher.ps1               # Levenshtein fuzzy group matching
    GroupReportGenerator.ps1       # V1 HTML report generation
    NestedGroupResolver.ps1        # Recursive group flattening
    UserCorrelation.ps1            # 5-tier cross-domain user matching
    GapAnalysis.ps1                # Migration gap analysis + CR generation
    StaleAccountDetector.ps1       # Disabled/stale account detection
    AppMapping.ps1                 # App-to-group readiness mapping
    MigrationReportGenerator.ps1   # V2 migration dashboard HTML
    EmailSummary.ps1               # Optional SMTP delivery
    MembershipState.ps1            # V3 persistent change tracking (JSON state + changelog)
    MembershipDrift.ps1            # V3 membership drift detection
    IncrementalGate.ps1            # V3 incremental enumeration optimization
    DomainUserLookup.ps1           # V3 cross-domain user resolution
    StateDatabase.ps1              # V3 SQLite backend + auto-dispatch
    GovernanceReportGenerator.ps1  # V3 governance + executive dashboard
    ComplianceReportGenerator.ps1  # V3 compliance + leadership summary
  Templates/
    group-report-template.html     # V1 HTML template
    migration-report-template.html # V2 migration dashboard template
    governance-report-template.html    # V3 audit tier (Word-compatible)
    executive-dashboard-template.html  # V3 executive tier (CSS + SVG)
    compliance-report-template.html    # V3 audit tier (Word-compatible)
    leadership-summary-template.html   # V3 leadership tier (1-page)
  Tests/
    Test-GroupEnumerator.ps1       # 141 tests (v1 features)
    Test-MigrationReadiness.ps1    # 150 tests (v2 features)
    Test-MembershipState.ps1       # 89 tests (v3 change tracking)
    Test-StateDatabase.ps1         # 56 tests (v3 SQLite backend)
    Test-GovernanceReport.ps1      # 38 tests (v3 governance reports)
    Test-ComplianceReport.ps1      # 44 tests (v3 compliance reports)
    Test-Integration.ps1           # 109 tests (end-to-end pipeline)
    fixtures/
      test-groups.csv              # Example CSV for smoke testing
      test-groups-ip.csv           # Example CSV targeting a DC by IP
      Build-SyntheticTwoForest.ps1 # Builds a synthetic two-forest cache from a real one
  docs/
    QUICKSTART.md
    DEV-GUIDE.md
  state_db.py                      # V3 Python SQLite CLI
  schema.sql                       # V3 SQLite schema
```

`ADLdap.ps1` is a self-contained, vendored helper with no dependencies on
anything else in this repo. It can be dropped into any sibling AD tool's
`Modules/` directory and dot-sourced; the file header marks it as the canonical
copy so future vendored copies can be diff-synced.

## Testing

```powershell
# Run v1 tests (141 tests, no AD required)
pwsh -File Tests/Test-GroupEnumerator.ps1

# Run v2 migration tests (150 tests, no AD required)
pwsh -File Tests/Test-MigrationReadiness.ps1

# Run v3 change tracking tests (89 tests, no AD required)
pwsh -File Tests/Test-MembershipState.ps1

# Run v3 governance report tests (38 tests, no AD required)
pwsh -File Tests/Test-GovernanceReport.ps1

# Run v3 compliance report tests (44 tests, no AD required)
pwsh -File Tests/Test-ComplianceReport.ps1

# Run v3 end-to-end integration tests (109 tests, no AD required)
pwsh -File Tests/Test-Integration.ps1
```

All tests use synthetic data and run on any platform (Windows, macOS, Linux).
Total test count: ~627 across 7 test files.

## LDAP Connection Strategy

Connections are built on `System.DirectoryServices.Protocols.LdapConnection`
with `AuthType.Negotiate` (Kerberos preferred, NTLM fallback). Tiers are tried
in order of decreasing security and the tier in use is logged as a structured
`LdapConnect` event and surfaced in the report when any fallback is active.

| Tier | Port | Encryption | Cert verification | When used |
|------|------|------------|-------------------|-----------|
| 1 | 636 | TLS (LDAPS) | strict | **Default. Always attempted.** |
| 2 | 636 | TLS (LDAPS) | bypassed | `-AllowInsecure` when client cannot validate the DC cert |
| 3 | 389 | SASL sign + seal (Kerberos-wrapped) | n/a | `-AllowInsecure` when 636 is unreachable on the target DC |
| 4 | 389 | none | n/a | Not reachable via switches; reserved for explicit opt-in only |

On every successful bind the tool reads the domain's RootDSE for the
`defaultNamingContext` and caches the connection in the per-run pool, so
subsequent group/member/nested/stale queries for that domain reuse the same
authenticated session.

## License

MIT
