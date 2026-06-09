# Group Enumerator — Foundations

> **Shared foundation for both the CLI and GUI playbooks.** The HTML build emits two
> guides — *CLI guide* = this file + `cli-playbook.md`, *GUI guide* = this file +
> `gui-playbook.md` — so install/auth/config/safety are written **once** here and never
> duplicated. This `.md` set is the source of truth; HTML is generated from it.

## 1. What Group Enumerator is

A read-only Active Directory / Entra **group-membership enumeration and governance
reporting** tool. You give it a list of groups (a CSV); it resolves their members over
LDAP(S), then produces HTML/JSON reports — from a simple inventory up to access
certification, privileged-access review, SoD, nested/effective-access audits,
governance & compliance posture, and migration-readiness. It also tracks membership
**changes** over time and supports **incremental** re-runs. Two front ends: the CLI
(`Invoke-GroupEnumerator.ps1`) and the WPF GUI (`Show-GroupEnumeratorGui.ps1`); the GUI
builds and runs the exact same CLI invocation.

## 2. Prerequisites & install

| Need | Why |
|---|---|
| **Windows PowerShell 5.1** | the tool targets 5.1 (`pwsh`/PS7 not required). Run from the `Group-Enumerator/` folder. |
| Network line of sight to a DC | LDAPS 636 (preferred) or LDAP 389. |
| **Python 3** (optional) | only for the SQLite change-tracking backend (`-StateBackend sqlite`). The JSON backend needs nothing extra. |
| RSAT / FlaUI | not needed to *run*. FlaUI is only for the GUI test kit (dev). |

Install = unzip the distribution (`AD-Group-Enumerator-vX.Y.Z.zip`) and run from the
extracted `Group-Enumerator/` folder. No system install.

## 3. Authentication & the connection-tier model

- **Default = current Windows identity (Kerberos)** — just run it on a domain-joined box.
- **Explicit credential:** `-Credential (Get-Credential)` (CLI) or the Username field
  (GUI). The password is never written to logs or the command preview.
- The tool tries connections in descending security order and uses the first that works:

  | Tier | Port | Security | Requires |
  |---|---|---|---|
  | LDAPS-Verified | 636 | TLS + cert validated | trusted DC cert (default) |
  | LDAPS-Unverified | 636 | TLS, cert **not** validated | `-AllowInsecure` |
  | LDAP-SignSeal | 389 | Kerberos sign+seal | `-AllowInsecure` |
  | LDAP-Plain | 389 | none | `-AllowInsecure` + `-AllowInsecureUnsigned` |

  A **tier downgrade** (e.g. self-signed lab cert → LDAPS-Unverified) logs a WARNING but
  still enumerates; it is expected in labs and is **not** an error.

## 4. Environments: live vs cache vs mock

| Mode | How | Use when |
|---|---|---|
| **Live** | normal run against a DC | producing real reports |
| **From cache** | `-FromCache -CachePath <file>` | regenerate/iterate reports with **no DC** — every cache file is preserved, so old runs stay reproducible |
| **Mock / synthetic** | seeders & cache builders in `Tests/fixtures/` | demos, two-forest migration tests without two real domains |

## 5. Safety / "What-If" model (read this before a real run)

- **Enumeration is strictly read-only.** The tool binds LDAP read-only and never writes
  to AD. There is no destructive operation in the enumeration path.
- **`-FromCache` is the true dry run** — it touches no directory at all and just rebuilds
  reports from a saved cache.
- **Large-group guard:** groups at/over `LargeGroupThreshold` (default 5000) are *skipped*
  (counted, not member-expanded) when `SkipLargeGroups` is on — protects against
  multi-thousand-member blowups. Skipped groups are flagged, never silently dropped.
- **Caches/outputs are additive** — runs write new timestamped files; they don't
  overwrite prior caches/reports. Safe to re-run.
- **Clean failure:** if a domain is unreachable, a pre-flight probe marks its groups as
  errors *without* LDAP retries and still emits a report — it fails fast, never hangs.
- **No AI / no cloud:** every report is generated locally with deterministic PowerShell
  (the RAG ratings are threshold rules — see glossary). There is **no LLM, no external
  service, and no internet call** in any report. The only outbound traffic the tool makes
  is LDAP to your DC (live enumeration) and SMTP (only with `-SendEmail`); `-FromCache`
  regenerates every report with no network at all (air-gap-friendly).

## 6. Output & file locations (relative to the run folder, overridable)

| Path | Holds | Override |
|---|---|---|
| `Output/` | HTML + JSON reports (timestamped) | `-OutputPath` |
| `Cache/` | per-run JSON caches (for `-FromCache`/incremental) | `-CachePath` |
| `Logs/` | structured JSONL run logs | config `LogPath` |
| `State/` | change-tracking ledger + SQLite DB (`group-enumerator.db`) | `-StatePath` / config `SqliteDbPath` |

## 7. Configuration reference (`Config/group-enum-config.json`)

Every key. CLI flags and GUI controls override the matching config value at runtime.

| Key | Default | Meaning |
|---|---|---|
| `LdapPageSize` | 1000 | LDAP paged-search page size |
| `LdapTimeout` | 120 | per-request timeout (seconds) |
| `MaxMemberCount` | 5000 | cap on members resolved per group (truncates beyond) |
| `SkipLargeGroups` | true | skip (count-only) groups ≥ threshold |
| `LargeGroupThreshold` | 5000 | the skip threshold |
| `SkipGroups` | Domain Users, Domain Computers, Authenticated Users | groups never enumerated |
| `FuzzyPrefixes` | GG_, USV_, SG_, DL_, GL_ | prefixes stripped when fuzzy-matching names |
| `FuzzyMinScore` | 0.7 | min similarity (0–1) for a fuzzy match |
| `OutputDirectory` | Output | default report folder |
| `DefaultTheme` | dark | report theme (`dark`/`light`) |
| `CachePath` | Cache | default cache folder |
| `CacheEnabled` | true | write a cache each run |
| `AllowInsecure` | false | enable cert-bypass / 389 fallback tiers |
| `LogEnabled` / `LogPath` / `LogLevel` | true / Logs / INFO | structured logging |
| `NestedGroupMaxDepth` | 10 | max recursion depth for `-ResolveNested` |
| `StaleAccountDays` | 90 | inactivity window for `-DetectStale` |
| `CorrelationStrategy` | email-first | cross-forest identity matching strategy |
| `AppMappingCsvPath` | null | optional group→application mapping CSV |
| `ChangeTracking.*` | Enabled false; UnifiedState true; StatePath State; DefaultChangeType Both; MaxChangeLogSizeMB 50; RetentionDays 0 | change-ledger settings |
| `Enumeration.Incremental` | false | reuse unchanged groups from cache |
| `StateBackend` | json | `json` or `sqlite` |
| `SqliteDbPath` | State/group-enumerator.db | SQLite DB location |
| `GarbageCollectDays` | 90 | prune state older than N days |
| `Reporting.*` | all false; IdentityDetailThreshold 3 | default report toggles + when to show identities |
| `Email.*` | disabled | SMTP settings for `-SendEmail` |

## 8. Glossary

- **DN / distinguishedName** — a directory object's full path. **whenChanged** — AD's
  last-modified stamp; the incremental gate diffs it to decide reuse.
- **Ranged retrieval** — AD returns very large `member` attributes in blocks
  (`member;range=0-1499`, …); the tool follows them to completion.
- **Nested / effective membership** — members inherited via groups-within-groups; B09
  reveals effective (transitive) access vs direct.
- **FSP** — Foreign Security Principal; a member from a trusted external domain.
- **Incremental gate** — skips re-enumerating groups whose `whenChanged` hasn't moved,
  reusing cached membership. Nested groups are always re-enumerated.
- **Change tracking** — a persistent ledger of Added/Removed membership events across runs.
- **Baseline reports** — the 10 fixed governance reports (B01–B10).
- **Composable components** — pick-and-mix report blocks (`kpi-cards`, `heatmap`, `tree`,
  `diff`, `top-n`, `group-table`) assembled into one report.
- **RAG** — **Red / Amber / Green** traffic-light rating (a GRC convention). *Not*
  Retrieval-Augmented Generation — no AI is involved.
- **Posture (governance/compliance)** — RAG (Red/Amber/Green)-rated coverage metrics over
  distinct accounts, computed by deterministic threshold rules.
