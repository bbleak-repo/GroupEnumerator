-- Group Enumerator v3.0 - SQLite Schema
-- Replaces JSON-based state management with SQLite.
-- Primary key is GROUP (domain + group_name), not CSV filename.

PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;

-- Schema version tracking
CREATE TABLE IF NOT EXISTS schema_version (
    version INTEGER PRIMARY KEY,
    applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

INSERT OR IGNORE INTO schema_version (version) VALUES (1);

-- Groups: unique by (domain, group_name)
CREATE TABLE IF NOT EXISTS groups (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    domain TEXT NOT NULL,
    group_name TEXT NOT NULL,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    when_changed TEXT,
    is_nested INTEGER,
    UNIQUE(domain, group_name)
);

-- Members: unique per group by sam_account_name
CREATE TABLE IF NOT EXISTS members (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    group_id INTEGER NOT NULL,
    sam_account_name TEXT NOT NULL,
    display_name TEXT,
    email TEXT,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    UNIQUE(group_id, sam_account_name),
    FOREIGN KEY (group_id) REFERENCES groups(id)
);

-- CSV sources: each input CSV file tracked by leaf name
CREATE TABLE IF NOT EXISTS csv_sources (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    csv_name TEXT NOT NULL UNIQUE
);

-- Runs: one record per invocation, tied to a CSV source
CREATE TABLE IF NOT EXISTS runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    csv_id INTEGER NOT NULL,
    started_at TEXT NOT NULL,
    completed_at TEXT,
    groups_enumerated INTEGER DEFAULT 0,
    groups_skipped INTEGER DEFAULT 0,
    groups_reused INTEGER DEFAULT 0,
    total_members INTEGER DEFAULT 0,
    changes_detected INTEGER DEFAULT 0,
    FOREIGN KEY (csv_id) REFERENCES csv_sources(id)
);

-- Changelog: append-only record of membership adds/removes
CREATE TABLE IF NOT EXISTS changelog (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    group_id INTEGER NOT NULL,
    sam_account_name TEXT NOT NULL,
    display_name TEXT,
    email TEXT,
    action TEXT NOT NULL CHECK(action IN ('Added', 'Removed')),
    run_id INTEGER,
    FOREIGN KEY (group_id) REFERENCES groups(id),
    FOREIGN KEY (run_id) REFERENCES runs(id)
);

-- CSV-to-group mapping: which groups came from which CSV
CREATE TABLE IF NOT EXISTS csv_group_map (
    csv_id INTEGER NOT NULL,
    group_id INTEGER NOT NULL,
    first_mapped TEXT NOT NULL,
    last_mapped TEXT NOT NULL,
    PRIMARY KEY(csv_id, group_id),
    FOREIGN KEY (csv_id) REFERENCES csv_sources(id),
    FOREIGN KEY (group_id) REFERENCES groups(id)
);

-- Cache snapshots: per-run snapshot of each group's state for incremental gate
CREATE TABLE IF NOT EXISTS cache_snapshots (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id INTEGER NOT NULL,
    group_id INTEGER NOT NULL,
    member_count INTEGER,
    when_changed TEXT,
    is_nested INTEGER,
    reused_from_cache INTEGER DEFAULT 0,
    members_json TEXT,
    UNIQUE(run_id, group_id),
    FOREIGN KEY (run_id) REFERENCES runs(id),
    FOREIGN KEY (group_id) REFERENCES groups(id)
);

-- Indexes for query performance
CREATE INDEX IF NOT EXISTS idx_groups_domain_name ON groups(domain, group_name);
CREATE INDEX IF NOT EXISTS idx_members_group_id ON members(group_id);
CREATE INDEX IF NOT EXISTS idx_changelog_timestamp ON changelog(timestamp);
CREATE INDEX IF NOT EXISTS idx_changelog_group_id ON changelog(group_id);
CREATE INDEX IF NOT EXISTS idx_runs_csv_id ON runs(csv_id);
CREATE INDEX IF NOT EXISTS idx_cache_run_group ON cache_snapshots(run_id, group_id);
