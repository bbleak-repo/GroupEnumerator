# Group Enumerator — GUI Playbook

> Audience: analysts / reviewers. Read `00-foundations.md` first (install, auth, config,
> safety, file locations, glossary). This playbook walks every tab and control; for the
> *meaning* of each option it links to `cli-playbook.md` (single source of truth — the
> GUI builds and runs that exact CLI command).

**Launch:** `powershell.exe -STA -NoProfile -ExecutionPolicy Bypass -File .\Show-GroupEnumeratorGui.ps1`
(STA is required for WPF). Window title: *Group Enumerator vX.Y*.

**Core idea:** every control maps to a CLI flag. The **Run** tab shows a live **command
preview** that is byte-for-byte what will execute — so the GUI is also a teaching tool for
the CLI. Settings persist between sessions (last-run state is saved/restored).

There are **7 tabs**: Run · Enumeration · Reports · Configuration · Change Tracking ·
Results · Help. *(Tab/control placement below is verified against `Gui/MainWindow.xaml`.)*

---

## Tab: Run
**Purpose.** Pick the input + credentials, optionally apply a preset, review the command
preview, and execute.
**When.** Every run starts and ends here.
**Controls**
| Control | What it does | CLI |
|---|---|---|
| CSV Path (+ Browse) | the group list to enumerate | `-CsvPath` |
| Data Source (Live AD / Use saved data) | enumerate live from AD, or **report on data already pulled in a previous run** (no new AD query) | `-FromCache` |
| Saved run (picker + Browse) | *optional* — pick a specific older run; the **latest is used by default**. Browse for any `*.json` cache | `-CachePath <file>` |
| Username / Password | bind as a specific user (blank = current Windows identity) | `-Credential` |
| Preset (dropdown) | apply a one-click configuration bundle (see Presets below) | (toggles many flags) |
| Command preview + Copy Command | live, copy-paste-accurate CLI equivalent | (mirrors all flags) |
| Run / Cancel | start / abort the background run | — |
| Log | live status stream | — |
**Workflow.** Set CSV → (optional) credentials → (optional) pick a Preset → glance at the
preview → **Run** → watch the log → it auto-switches to **Results** on success.
**How to read results.** The log streams status; a completion line reports duration + file
count; Results fills in.
**Safety prompts.** The preview shows the exact command before running; the password never
appears in it or the logs. Cancel is non-blocking (UI stays responsive). Read-only against
AD (`00-foundations §5`).
**Related CLI.** `Invoke-GroupEnumerator.ps1` — the preview *is* the command.

## Tab: Enumeration
**Purpose.** Control **how** the run executes — analysis passes, run modes, change
capture, state backend, and scope.
**When.** Whenever you want more than a default live roster, or to change run behavior.
**Controls**
| Control | What it does | CLI |
|---|---|---|
| Fuzzy Match | cross-forest name correlation | `-FuzzyMatch` |
| Resolve Nested Groups | expand to effective members | `-ResolveNested` |
| Detect Stale Accounts | flag inactive/disabled (window = Config “Stale account days”) | `-DetectStale` |
| Analyze Migration Gaps | cross-forest gap analysis | `-AnalyzeGaps` |
| Incremental Mode | reuse unchanged groups from cache | `-Incremental` |
| From Cache (skip LDAP) | rebuild from a saved cache, no DC | `-FromCache` |
| Allow Insecure LDAP | cert-bypass / 389 fallback (lab DCs) | `-AllowInsecure` |
| Track Changes | record Added/Removed vs the ledger | `-TrackChanges` |
| Change type / Change period | filter the change report; **Period = Custom** reveals a **days-back** field + a **Since date picker** (calendar) | `-ChangeType` / `-ChangePeriod` / `-ChangeDays` / `-ChangeSince` |
| Backend: JSON / SQLite | change-tracking store (SQLite needs Python) | `-StateBackend` |
| Unified State / Legacy Mode | unified vs per-CSV legacy state | `-Legacy` |
| Large group threshold / Skip groups | scope tuning (override config) | config keys |
| Migrating to / Baseline path / Previous run path / App mapping CSV | migration-readiness inputs | `-MigratingTo` / `-BaselinePath` / `-PreviousRunPath` / `-AppMappingCsv` |
**Workflow.** Tick the analyses/modes you need (they compose) and pick a backend if
tracking changes. (Incremental auto-disables with Detect Stale, which needs fresh per-user
data.) **How to read results.** Each pass adds sections/columns (effective vs direct
members, gap priority, stale/disabled flags). **Related CLI.** “Analysis”, “Caching & run
modes”, and “Change tracking & state” parameters in `cli-playbook.md`.

## Tab: Reports
**Purpose.** Choose deliverables, theme, and output options.
**When.** Any run where you want HTML/CSV out (most runs).
**Controls**
| Control group | What it does | CLI |
|---|---|---|
| **Generate Reports from Saved Data** (button, top) | one-click: run the ticked reports from the **latest saved run** — no AD. (For an older run or a live run, use the Run tab.) | `-FromCache -CachePath <latest>` |
| Generate All Reports | every v3 report | `-AllReports` |
| Access Governance / Compliance Audit / Executive Dashboard / Leadership Summary | individual v3 reports | `-GovernanceReport` etc. |
| Baseline Governance Reports — All (10) | all baselines | `-BaselineReports` |
| 10 individual baseline ☑ (Roster, Access Certification, Privileged, SoD, Orphaned, Inventory, Empty/Stale, Nested Audit, Exec Summary, Change Attestation) | a subset | `-BaselineReport roster,…` |
| 8 composable ☑ (KPI Cards, Heatmap, Top-N, Tree, Diff, Group Table, Governance Risk Flags, Privileged-Access Risk) + “½ width” each | assemble a custom report | `-ReportComponents kpi-cards,…[:half]` |
| Component title / Dark theme | composable report title + theme | `-ComponentReportTitle` / `-ComponentReportTheme` |
| Theme (dropdown) | theme for standard/v3 reports | `-Theme` |
| Export Members CSV | also write a flat roster CSV | `-ExportMembersCsv` |
| JSON Only (skip HTML) | cache/JSON only | `-JsonOnly` |
| No Cache | don’t write a cache this run | `-NoCache` |
| Send Email Report | email the summary (SMTP in Config) | `-SendEmail` |
**Workflow.** Pick baselines and/or compose components, set a title/theme; the preview
updates live. **How to read results.** Each selection produces a timestamped HTML in
Results; the reports catalog in `cli-playbook.md` says what each is and when to use it.
**Related CLI.** “Reports” parameters + the reports catalog in `cli-playbook.md`.

## Tab: Configuration
**Purpose.** Tuning, logging, email/SMTP, file paths, and config save/load. (Connection
*credentials* are on the **Run** tab; *Allow Insecure* and *backend* are on **Enumeration**.)
**When.** First-time setup, environment changes, or tuning.
**Controls**
| Control group | What it does | CLI / config |
|---|---|---|
| LDAP page size / timeout, Max member count | connection + size tuning | config keys (`00-foundations §7`) |
| Fuzzy prefixes / min score, Stale account days, Nested group max depth, Correlation strategy | analysis tuning | config keys |
| Logging: enabled / level / path | structured logging | config keys |
| SMTP: server/port/from/to/cc/subject/SSL/attach | email delivery for Send Email | config `Email.*` |
| Change-log size / Retention days | ledger limits | config `ChangeTracking.*` |
| Output / Cache / State / SQLite DB paths | where files go | `-OutputPath` / `-CachePath` / `-StatePath` / config `SqliteDbPath` |
| Save / Reset / Load Config | persist, reset, or load a config file | `-ConfigPath` (load) |
**Workflow.** Set tuning + paths + (if emailing) SMTP, then **Save Configuration** to reuse.
**Safety prompts.** Reset to Defaults restores built-in config. **Related CLI.**
Foundations §3 (auth/tiers) and §7 (config keys).

## Tab: Change Tracking
**Purpose.** A read-only **view** of the change ledger + estate stats. (Enabling capture is
**Track Changes on the Enumeration tab**; this tab reads what was recorded.)
**When.** After recurring tracked runs, to inspect deltas and trends.
**Controls**
| Control | What it does |
|---|---|
| Refresh Stats | load the stats panel: backend, DB path, groups / members / distinct members / changes / runs |
| Check Consistency | read-only integrity/consistency audit of the state DB (RAG verdict per check) — same engine as `Invoke-StateValidation.ps1` |
| Churn / Re-grant Report (+ days / min re-grants / Privileged only) | find accounts **removed then re-added** ("access flapping") over the window; writes + opens an HTML report — same engine as `Invoke-MembershipChurn.ps1` |
| Org Role Map (+ mode Adhoc/Delta/Full / Privileged only / cache path) | manager → group → user **counts** over an org tree (where privileged roles concentrate); opens a self-contained HTML with an SVG map + printable table — same engine as `Invoke-OrgRoleMap.ps1`. Full/Adhoc use the cache-path field (or newest `Cache\*.json`); Delta uses the ledger + `State\org-tree.json`. Needs a snapshot enumerated with `-IncludeAttributes manager` |
| CSV filter + Period + Query Changes | filter the changelog and populate the results grid |
**Workflow.** Refresh Stats for the estate snapshot → set a CSV filter/period → Query
Changes. **How to read results.** Stats show the estate at a glance (distinct accounts ≠
membership rows); the grid lists individual Added/Removed events. **Related CLI.** “Change
tracking & state” parameters in `cli-playbook.md`; state model in `00-foundations §6`.

## Tab: Results
**Purpose.** See and open what the last run produced.
**When.** After every run (auto-selected on success).
**Controls.** A grid of generated files; **Open Output Directory**; **Refresh**.
**Workflow.** Click a report to open it; or Open Output Directory to browse/share. Files are
timestamped in `Output/`.

## Tab: Help
**Purpose.** In-app guidance and version.

---

## Presets & persistence
- **Preset dropdown (Run tab):** Basic Inventory · Nested+Stale · Cross-Domain Migration ·
  Compliance Audit · Full Analysis · Custom. Each toggles a sensible set of
  Enumeration/Reports options — a fast on-ramp; tweak afterward.
- **Persistence:** the GUI saves your last-run selections (input, switches, report and
  component choices, title, paths) and restores them next launch.

## Task recipes (GUI)
1. **Quick inventory:** Run → set CSV → (lab) Enumeration → Allow Insecure → Run.
2. **Access review pack:** Reports → Baseline Governance (All) + Access Governance +
   Compliance Audit → Run → Results → open the access-cert / privileged / SoD reports.
3. **Custom dashboard:** Reports → tick KPI Cards + Heatmap + Group Table, set a title → Run.
4. **Track changes over time:** Enumeration → Track Changes + Backend = SQLite → Run a few
   times; then read the **Change Tracking** tab (Refresh Stats / Query Changes).
5. **Report-only refresh (no DC):** Enumeration → From Cache → Run → choose reports → Run.

> Every action above has a CLI equivalent shown in the Run tab’s command preview — copy it
> to schedule the same thing headlessly (see `cli-playbook.md` recipes).
