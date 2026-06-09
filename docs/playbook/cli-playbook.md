# Group Enumerator — CLI Playbook

> Audience: operators / automation. Read `00-foundations.md` first (install, auth,
> config, safety, file locations, glossary). This playbook documents every entry script
> and every parameter. Each parameter notes its **GUI equivalent**; for GUI workflows
> see `gui-playbook.md`.

There are four entry scripts. `Invoke-GroupEnumerator.ps1` is the workhorse; the others
are focused utilities.

---

## Script: `Invoke-GroupEnumerator.ps1`

**Purpose.** Enumerate the members of the groups in a CSV (or a saved cache) and produce
reports.
**When to use.** Any inventory, access review, governance/compliance, migration-readiness,
or change-tracking run — interactively or scheduled.
**Synopsis.** `.\Invoke-GroupEnumerator.ps1 -CsvPath <csv> [analysis] [reports] [output] [-AllowInsecure]`
**Output & location.** Timestamped HTML + JSON in `Output/` (`-OutputPath`); a JSON cache
in `Cache/` unless `-NoCache`; logs in `Logs/`; state in `State/`.
**Safety / What-If.** Read-only against AD. `-FromCache` = true dry run (no DC).
`-JsonOnly` skips HTML. Large groups are skipped (counted) per config.
**Scheduling.** Safe to schedule (Task Scheduler). Use `-Incremental` for cheap recurring
runs, `-TrackChanges` to accumulate a change ledger, `-FromCache` for report-only refreshes.
**Related GUI.** The whole GUI (`Show-GroupEnumeratorGui.ps1`) — the **Run** tab's command
preview is exactly this invocation.

### Parameters

**Input & scope**
| Name | Type | Req | Default | What it does · GUI |
|---|---|---|---|---|
| `CsvPath` | string | yes* | — | CSV of groups (`Domain,GroupName` or `Group` = `DOMAIN\Group`); group values may be plain names **or** full DNs. *Not required with `-FromCache`. · Run tab “CSV Path” |
| `Credential` | PSCredential | no | current identity | Bind as a specific user (`(Get-Credential)`). · Run “Username/Password” |
| `AllowInsecure` | switch | no | off | Enable cert-bypass / 389 fallback tiers (needed for self-signed lab DCs). · Enumeration “Allow Insecure LDAP” |
| `IncludeAttributes` | string[] | no | core set | Extra LDAP attributes to pull per member. · Advanced |

> **Full-DN group values.** A group value in the CSV may be a plain name (resolved by CN) **or** a
> full distinguished name, e.g. `CN=GG_IT_Admins,OU=Groups,DC=corp,DC=com`, auto-detected per row.
> A DN disambiguates duplicate names across OUs and is bound Base-scope directly; its domain is
> derived from the `DC=` components, so the `Domain` column is optional on DN rows. The report shows
> the resolved short name. Sample: `Templates\groups-example-dn.csv`.

**Caching & run modes**
| Name | Type | Req | Default | What it does · GUI |
|---|---|---|---|---|
| `FromCache` | switch | no | off | Rebuild reports from a saved cache; no DC contact. · Enumeration “From Cache (skip LDAP)” |
| `CachePath` | string | no | `Cache/` | Cache file (with `-FromCache`) or output dir (otherwise). · Configuration “Cache path” |
| `NoCache` | switch | no | off | Don’t write a cache this run. · Reports “No Cache” |
| `Incremental` | switch | no | off | Reuse cached membership for groups whose `whenChanged` is unchanged (nested groups always re-enumerated). · Enumeration “Incremental Mode” |
| `Legacy` | switch | no | off | Use legacy per-CSV state instead of unified state. · Enumeration “Legacy Mode” |

**Analysis**
| Name | Type | Req | Default | What it does · GUI |
|---|---|---|---|---|
| `FuzzyMatch` | switch | no | off | Fuzzy-correlate group names across forests (prefix-aware). · Enumeration “Fuzzy match” |
| `ResolveNested` | switch | no | off | Expand nested groups to effective members (depth per config). · Enumeration “Resolve nested” |
| `AnalyzeGaps` | switch | no | off | Cross-forest gap analysis (who’s missing where). · Enumeration “Analyze gaps” |
| `DetectStale` | switch | no | off | Flag disabled/stale accounts (inactivity). · Enumeration “Detect Stale Accounts” |
| `StaleDays` | int | no | 0→90 | Inactivity window for `-DetectStale`. · Configuration “Stale account days” |
| `AppMappingCsv` | string | no | — | Group→application mapping for app-centric reports. · Enumeration “App mapping CSV” |
| `MigratingTo` | string | no | — | Target forest/domain label for migration-readiness. · Enumeration “Migrating to” |
| `TargetSearchBase` | string | no | — | Target search base for migration correlation. · (CLI only) |
| `BaselinePath` | string | no | — | A prior baseline to diff against. · Enumeration “Baseline path” |
| `PreviousRunPath` | string | no | — | A prior run to compare for drift. · Enumeration “Previous run path” |

**Reports**
| Name | Type | Req | Default | What it does · GUI |
|---|---|---|---|---|
| `GovernanceReport` | switch | no | off | Access-governance report (posture, RAG). · Reports |
| `ComplianceReport` | switch | no | off | Compliance posture (SOC2/SOX/PCI framing). · Reports |
| `ExecutiveDashboard` | switch | no | off | One-page executive KPI dashboard. · Reports |
| `LeadershipSummary` | switch | no | off | Leadership summary (distinct identities, risk). · Reports |
| `AllReports` | switch | no | off | All v3 reports above. · Reports “All reports” |
| `BaselineReports` | switch | no | off | All 10 baseline governance reports (B01–B10). · Reports “Baseline governance” |
| `BaselineReport` | string[] | no | — | A subset of baselines, e.g. `roster,privileged,sod`. · Reports (individual checkboxes) |
| `ReportComponents` | string[] | no | — | Composable report blocks, e.g. `kpi-cards,heatmap,group-table:half,diff:half`. Accepts a quoted comma-string too. · Reports “Composable” |
| `ComponentReportTitle` | string | no | Composable Group Report | Title for the composable report. · Reports |
| `ComponentReportTheme` | string | no | light | `light`/`dark` for the composable report. · Reports |
| `Theme` | string | no | dark | Theme for standard/v3 reports. · Reports “Theme” |
| `JsonOnly` | switch | no | off | Skip HTML; cache/JSON only. · Reports “JSON Only” |
| `ExportMembersCsv` | switch | no | off | Also write a flat member roster CSV. · Reports “Export Members CSV” |

**Change tracking & state**
| Name | Type | Req | Default | What it does · GUI |
|---|---|---|---|---|
| `TrackChanges` | switch | no | off | Diff against the persistent ledger; record Added/Removed. · Enumeration “Track Changes” (the **Change Tracking** tab is the read-only viewer) |
| `ChangeType` | string | no | Both | `Added`, `Removed`, or `Both`. · Enumeration “Change type” |
| `ChangePeriod` | string | no | — | Rolling window for the change report (e.g. last N days). · Enumeration “Change period” |
| `StatePath` | string | no | `State/` | State/ledger directory. With the `sqlite` backend the DB also lives here (unless a custom `SqliteDbPath` is configured), so a distinct `-StatePath` fully isolates a run. · Configuration “State path” |
| `StateBackend` | string | no | json | `json` or `sqlite` (sqlite needs Python). · Enumeration “Backend: JSON/SQLite” |

**Output, email, misc**
| Name | Type | Req | Default | What it does · GUI |
|---|---|---|---|---|
| `OutputPath` | string | no | `Output/` | Report output directory. · Configuration “Output” |
| `ConfigPath` | string | no | `Config/…json` | Use a specific config file. · Configuration “Load config” |
| `SendEmail` | switch | no | off | Email the summary (SMTP set on Configuration). · Reports “Send Email Report” |
| `PassThru` | switch | no | off | Return the result object to the pipeline. · — |
| `Help` | switch | no | — | Show built-in help. · Help tab |

---

## Script: `Show-GroupEnumeratorGui.ps1`
**Purpose.** Launch the WPF GUI. **When.** Interactive analysts/reviewers.
**Synopsis.** `powershell.exe -STA -File .\Show-GroupEnumeratorGui.ps1 [-ConfigPath <f>]`
(needs STA). **Related.** See `gui-playbook.md` for every tab and control.

## Script: `Invoke-GroupCrossReference.ps1`
**Purpose.** Cross-reference group memberships across inputs (who is in which groups,
overlaps). **When.** Comparing membership sets / building cross-group views.
**Synopsis.** `.\Invoke-GroupCrossReference.ps1 -CsvPath <csv> [-AllowInsecure]`.
**Output.** HTML/JSON cross-reference in `Output/`.

## Script: `Get-UserAttributes.ps1`
**Purpose.** Pull selected attributes for specific users (ad-hoc lookup). **When.** Quick
per-user attribute checks outside a full enumeration. **Synopsis.**
`.\Get-UserAttributes.ps1 -Identity <sam|dn> [-Attributes a,b]`.

## Script: `Invoke-StateValidation.ps1`
**Purpose.** Read-only integrity/consistency audit of the SQLite state database (SQLite
backend). Reports a RAG-style verdict over: SQLite integrity, foreign-key references,
group/member identity, snapshot member-count agreement, and **reuse-basis completeness**
(the incremental-reuse decay detector). **When.** Ad-hoc trust check of the change ledger,
or scheduled (e.g. nightly) as a data-consistency gate. **Synopsis.**
`.\Invoke-StateValidation.ps1 [-DbPath <db>] [-ConfigPath <cfg>]`. **Exit codes:** `0` clean
(or warnings only), `1` errors found / could not run, `2` no DB yet. No AD/network needed.

## Script: `Invoke-PrivilegedRiskCheck.ps1`
**Purpose.** Scriptable privileged-access governance gate: flags accounts that still hold
**privileged-group** membership while **disabled** (and never-logged-in/stale if the cache
carries stale data). Reuses the RC08 classifier, so it agrees with the `privileged-risk`
report. **When.** Schedule it (nightly/CI) over the newest cache to fail a job when a
disabled account retains admin rights. **Synopsis.**
`.\Invoke-PrivilegedRiskCheck.ps1 [-CachePath <file|dir>] [-Quiet] [-MaxList <n>] [-ExportCsv <path>] [-AllPrivileged] [-PrivilegedPattern <regex…>] [-ReplacePrivilegedBuiltins]`
(`-ExportCsv` writes the at-risk Group/Domain/Sam/Status rows for remediation tracking).
**Exit codes:** `0` clean, `2` at-risk accounts found, `1` cache not found/unreadable. Reads
a JSON cache — **no AD/network needed**. (For never-logged-in/stale, generate the cache with
a `-DetectStale` run.)

## Script: `Invoke-MembershipChurn.ps1`
**Purpose.** Membership **churn / re-grant ("access flapping")** report over the change ledger:
flags accounts that were **Removed then Added again** within a window — repeated cycles ("was
there, removed, re-added, removed…") are a governance red flag, weighted for privileged groups.
**When.** Schedule it (e.g. weekly over 30 days) to catch oscillation that crosses runs. Reads
**SQLite or JSON** backend; reuses the RC08 privileged classifier. **Synopsis.**
`.\Invoke-MembershipChurn.ps1 [-Days <n>|-Since <date>|-Period Day|Week|Month|Quarter] [-MinReGrants <n>] [-PrivilegedOnly] [-AllPrivileged] [-PrivilegedPattern <regex…>] [-ReplacePrivilegedBuiltins] [-CsvName <x>] [-ExportCsv <path>] [-OutputHtml <path>] [-Quiet] [-Backend Auto|Sqlite|Json] [-DbPath <db>] [-StatePath <dir>]`.
**Exit codes:** `0` no re-grants, `2` re-grants found, `1` error. Default window 30 days.
**Fidelity:** detects oscillation across runs — an add+remove entirely between two runs isn't
in the ledger (run cadence bounds resolution; frequent/business-hours runs catch more).

## Script: `Invoke-OrgRoleMap.ps1`
**Purpose.** The **Org Role Map** — manager → group → user as **COUNTS** (no user names) over an
org tree derived from AD's `manager` attribute, so you can see **where in the business** privileged
(or otherwise tracked) group roles concentrate. Output is one self-contained HTML: an inline-SVG
**spatial map** (pan/zoom, click to expand/collapse; **zero external libraries**) plus a static,
accessible, printable **placement table** (the canonical evidence artifact). Shared accessible
light/dark theme + toggle; `@media print` forces light. Privileged scope reuses the RC08 classifier.
**Prerequisite.** Build the snapshot with manager data:
`.\Invoke-GroupEnumerator.ps1 -CsvPath groups.csv -IncludeAttributes manager` (writes a cache whose
member records carry `ManagerDN`). The org tree is derived from those edges.
**Three modes.**
- **Full** — `-Mode Full -CachePath <snapshot.json>`: build/refresh the org-tree cache
  (`State\org-tree.json`) from the snapshot's manager edges and render. `-BuildOrgTree` requests the
  deep upward chain walk (managers' managers… to the top), which needs a reachable DC.
- **Delta** — `-Mode Delta [-Days <n>|-Since <date>|-Period …]`: reuse the cached org tree (no DC)
  and overlay changelog Added/Removed over the window (+/- per branch). A loud **staleness banner**
  appears when the cached tree is older than `-MaxStaleDays` (default 30).
- **Adhoc** — `-Mode Adhoc -CachePath <snapshot.json>`: render from a snapshot only; **no state
  writes** (auditor "what did this snapshot look like" mode).
**Synopsis.**
`.\Invoke-OrgRoleMap.ps1 -Mode Full|Delta|Adhoc [-CachePath <json>] [-OrgTreePath <json>] [-Groups <name…>] [-PrivilegedOnly] [-Days <n>|-Since <date>|-Period …] [-Backend Auto|Sqlite|Json] [-DbPath <db>] [-StatePath <dir>] [-DepthCap <n>] [-BuildOrgTree] [-MaxStaleDays <n>] [-FailOn StaleCache,UnmanagedBucket,PrivConcentration] [-AllPrivileged] [-PrivilegedPattern <regex…>] [-ReplacePrivilegedBuiltins] [-DefaultOpenDepth <n>] [-ExportCsv <path>] [-OutputHtml <path>] [-Quiet]`.
**Exit codes:** `0` ok/informational, `1` error, `2` a `-FailOn` threshold tripped (stale org-tree
cache; an oversized **Unmanaged** bucket — service accounts / accounts with no manager, itself a
finding; or one branch holding too high a share of privileged refs).
**Leadership-facing report.** Plain-English (no jargon), counts-only/no-names; a top summary leads
with **distinct people** (people with tracked/privileged access, managers vs individuals) so totals
aren't misread as headcount. `-DefaultOpenDepth <n>` sets how many levels the chart starts expanded;
the in-report **Save as image** button exports a PNG for slides.
**Fidelity/limits:** counts only (numbers-only, scale-safe + privacy); the org tree is only as
fresh as AD's `manager` attribute (reorganisations lag) and the cached build; cross-forest chains
stop at an unreachable trust boundary (documented, not a bug).

> **Privileged scope (configurable).** Privileged classification is the RC08 name predicate, tunable
> for estates where privileged roles don't contain "admin" (CyberArk, IAM, AWS, PAM, Vault…):
> `-AllPrivileged` treats every tracked group as privileged; `-PrivilegedPattern <regex…>` adds
> custom patterns; `-ReplacePrivilegedBuiltins` uses **only** those patterns. The **same three flags**
> work on `Invoke-MembershipChurn.ps1` and `Invoke-PrivilegedRiskCheck.ps1`. Defaults come from config
> (`AllGroupsPrivileged`, `PrivilegedPatterns`, `ReplacePrivilegedBuiltins`).

---

## Reports catalog (what each report is · when to use)

**Baseline governance (B01–B10)** — `-BaselineReports` or `-BaselineReport <keys>`:
| Key | Report | Use when |
|---|---|---|
| `roster` | Membership snapshot roster | a clean point-in-time member list |
| `access-cert` | Access certification / attestation | reviewers must sign off on access |
| `privileged` | Privileged group review | scrutinize admin/privileged groups |
| `sod` | SoD toxic co-membership | find users in conflicting group pairs |
| `orphaned` | Orphaned / disabled members | disabled accounts still in groups |
| `inventory` | Group inventory catalog | catalog of all groups + sizes |
| `empty-stale` | Empty & stale groups | groups to clean up |
| `nested-audit` | Nested / effective-access audit | certify *effective* (transitive) access |
| `exec-summary` | Governance executive summary | one-page governance KPIs (distinct members) |
| `change-attestation` | Membership change attestation | sign-off on Added/Removed over a window |

**Composable components** — `-ReportComponents <keys>` (each optional `:half`/`:full`):
`kpi-cards` (headline counts incl. distinct members), `heatmap` (member-count density),
`tree` (drill-down by group), `diff` (per-group Added/Removed/Other from the changelog),
`top-n` (largest groups), `group-table` (condensed roster), `risk-flags` (governance risk
snapshot: disabled members, empty groups, oversized/skipped, nested), `privileged-risk`
(disabled accounts still in privileged groups — a critical access-governance finding). Mix
into one cohesive report. *(all eight are selectable in both the CLI and the GUI Reports tab.)*

**v3 reports** — `-GovernanceReport`, `-ComplianceReport`, `-ExecutiveDashboard`,
`-LeadershipSummary`, or `-AllReports`. Governance/compliance compute **posture** (RAG =
**Red/Amber/Green** threshold ratings — deterministic, computed locally; no AI/LLM)
over **distinct accounts**; leadership/exec are summary KPIs. Migration-readiness engages
when `-MigratingTo`/`-TargetSearchBase` (+ `-FuzzyMatch`/`-AnalyzeGaps`) are set.

---

## Recipes

```powershell
# 1. Simplest inventory (live), HTML + cache
.\Invoke-GroupEnumerator.ps1 -CsvPath .\groups.csv -AllowInsecure

# 2. Full governance pass: baselines + composable + governance/compliance
.\Invoke-GroupEnumerator.ps1 -CsvPath .\groups.csv -AllowInsecure `
    -BaselineReports -ReportComponents 'kpi-cards,heatmap,group-table' -GovernanceReport -ComplianceReport

# 3. Recurring cheap run with change tracking (SQLite) + incremental reuse
.\Invoke-GroupEnumerator.ps1 -CsvPath .\groups.csv -AllowInsecure `
    -StateBackend sqlite -TrackChanges -Incremental

# 4. Rebuild reports from a saved cache — no DC needed
.\Invoke-GroupEnumerator.ps1 -CsvPath .\groups.csv -FromCache `
    -CachePath .\Cache\groups-20260601-181204.json -BaselineReports

# 5. Migration readiness (source vs target forest)
.\Invoke-GroupEnumerator.ps1 -CsvPath .\groups.csv -AllowInsecure `
    -FuzzyMatch -AnalyzeGaps -MigratingTo 'TARGET.forest' -TargetSearchBase 'DC=target,DC=forest'
```

## Troubleshooting

| Symptom | Cause / fix |
|---|---|
| “domain unreachable” for all groups | DC down / DNS / VPN. Pre-flight failed fast — fix connectivity (`00-foundations §3`). |
| “tier downgrade” warning | self-signed DC cert; expected with `-AllowInsecure`. Not an error. |
| Composable report skipped: “unknown component(s)” | a bad component key — valid: kpi-cards, heatmap, tree, diff, top-n, group-table, risk-flags, privileged-risk. (Quoted comma-strings are accepted.) |
| Group shows 0 / “at least N” members | skipped large group (≥ `LargeGroupThreshold`) — count may be truncated; lower the threshold or raise `MaxMemberCount` to expand. |
| Incremental reused nothing / re-enumerates all | first run is always a full baseline; nested groups always re-enumerate. |
| SQLite backend errors | Python 3 not on PATH; or use `-StateBackend json`. |
