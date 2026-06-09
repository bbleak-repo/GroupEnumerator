#!/usr/bin/env python3
"""Group Enumerator v3.0 - SQLite State Manager.

Replaces JSON-based membership state tracking with a SQLite database.
Groups are keyed by (domain, group_name) rather than by CSV filename.

Designed to be called from PowerShell via:
    python3 state_db.py <subcommand> [args]

All output is compact JSON to stdout. Errors go to stderr.
Exit code 0 on success, 1 on error.

Subcommands:
    import-state    Load current membership state for a CSV set
    update-state    Diff current results against stored state, return changes
    save-snapshot   Save a run's cache snapshot
    get-cache       Get latest cache for incremental gate
    start-run       Begin a new run record
    complete-run    Mark run as complete with metrics
    query-changes   Query changelog with filters
    migrate-json    Import existing JSON state files into the database
    gc              Garbage collect orphaned groups
    stats           Database statistics
"""

import argparse
import json
import os
import sqlite3
import sys
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path


SCHEMA_PATH = Path(__file__).parent / "schema.sql"
DEFAULT_DB = Path(__file__).parent / "group-enumerator.db"


# ---------------------------------------------------------------------------
# Database connection and initialization
# ---------------------------------------------------------------------------

@contextmanager
def get_connection(db_path):
    """Context manager for SQLite connections with auto-commit/rollback.

    Sets WAL journal mode, enables foreign keys, and uses Row factory
    for dict-like access. On success the transaction is committed; on
    exception it is rolled back.

    Args:
        db_path: Path to the SQLite database file.

    Yields:
        sqlite3.Connection with row_factory = sqlite3.Row.
    """
    conn = sqlite3.connect(str(db_path))
    # Connection setup (PRAGMAs) must be inside the try so that a failure here --
    # e.g. "file is not a database" raised by PRAGMA on a corrupt file -- still
    # runs finally: conn.close(). Otherwise the open handle leaks and, on Windows,
    # blocks the corrupt-file rename in handle_corruption (WinError 32).
    try:
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute("PRAGMA journal_mode=WAL")
        yield conn
        conn.commit()
    except Exception:
        try:
            conn.rollback()
        except sqlite3.Error:
            pass
        raise
    finally:
        conn.close()


def init_database(db_path):
    """Initialize the database from the external schema.sql file.

    Loads and executes the DDL from schema.sql. If the database file
    already exists and has been initialized, the IF NOT EXISTS guards
    in the schema prevent duplicate creation.

    Args:
        db_path: Path to the SQLite database file.
    """
    schema_file = SCHEMA_PATH
    if not schema_file.exists():
        error_exit("Schema file not found: {}".format(schema_file))
    schema = schema_file.read_text()
    with get_connection(db_path) as conn:
        conn.executescript(schema)


def handle_corruption(db_path):
    """Handle database corruption by renaming the corrupt file and creating fresh.

    Attempts PRAGMA integrity_check first. If that fails, renames the
    corrupt file with a .corrupt.<timestamp> suffix and creates a new
    database from schema.sql.

    Args:
        db_path: Path to the SQLite database file.

    Returns:
        True if recovery was performed, False if database is healthy.
    """
    db_path = Path(db_path)
    if not db_path.exists():
        return False

    try:
        conn = sqlite3.connect(str(db_path))
        try:
            result = conn.execute("PRAGMA integrity_check").fetchone()
        finally:
            # Always close, even when integrity_check raises on a corrupt file.
            # On Windows an open handle blocks the os.rename below (WinError 32);
            # POSIX allows renaming an open file, so this only bit on Windows.
            conn.close()
        if result and result[0] == "ok":
            return False
    except sqlite3.DatabaseError:
        pass

    # Database is corrupt -- rename and recreate
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    corrupt_name = str(db_path) + ".corrupt.{}".format(timestamp)
    print_err("Database corruption detected. Renaming to: {}".format(corrupt_name))
    try:
        os.rename(str(db_path), corrupt_name)
    except OSError as e:
        print_err("Failed to rename corrupt database: {}".format(e))

    init_database(db_path)
    return True


def ensure_db(db_path):
    """Ensure the database exists and is initialized.

    Creates the database from schema if it does not exist, and checks
    for corruption on existing databases.

    Args:
        db_path: Path to the SQLite database file.
    """
    db_path = Path(db_path)
    if not db_path.exists():
        init_database(db_path)
        return

    try:
        with get_connection(db_path) as conn:
            conn.execute("SELECT version FROM schema_version LIMIT 1")
    except sqlite3.DatabaseError:
        if not handle_corruption(db_path):
            init_database(db_path)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def print_err(msg):
    """Print a message to stderr.

    Args:
        msg: The error message string.
    """
    print(msg, file=sys.stderr)


def error_exit(msg, code=1):
    """Print an error message to stderr and exit with the given code.

    Args:
        msg: The error message string.
        code: Exit code (default 1).
    """
    print_err("ERROR: {}".format(msg))
    sys.exit(code)


def json_out(obj):
    """Print a Python object as compact JSON to stdout.

    Uses separators=(',', ':') for minimal whitespace, which is
    compatible with PowerShell's ConvertFrom-Json.

    Args:
        obj: The Python object to serialize.
    """
    print(json.dumps(obj, separators=(",", ":")))


def now_iso():
    """Return the current UTC time as an ISO 8601 string.

    Returns:
        String in ISO 8601 format.
    """
    # timezone-aware UTC: datetime.utcnow() is deprecated in 3.12+ and emits a
    # DeprecationWarning to stderr, which trips PowerShell's native-stderr error
    # handling. The output string is identical (literal trailing 'Z').
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def make_group_key(domain, group_name):
    """Build the canonical group key used in JSON I/O.

    Args:
        domain: The AD domain name.
        group_name: The group's common name.

    Returns:
        String in the form 'DOMAIN|GroupName'.
    """
    return "{}|{}".format(domain, group_name)


def get_or_create_csv(conn, csv_name):
    """Get or create a csv_sources record, returning its id.

    Args:
        conn: Active sqlite3 connection.
        csv_name: The CSV leaf filename.

    Returns:
        Integer csv_id.
    """
    row = conn.execute(
        "SELECT id FROM csv_sources WHERE csv_name = ?", (csv_name,)
    ).fetchone()
    if row:
        return row["id"]
    cursor = conn.execute(
        "INSERT INTO csv_sources (csv_name) VALUES (?)", (csv_name,)
    )
    return cursor.lastrowid


def get_or_create_group(conn, domain, group_name, timestamp):
    """Get or create a groups record, returning its id.

    If the group already exists, updates last_seen. If it does not
    exist, creates it with first_seen and last_seen set to timestamp.

    Args:
        conn: Active sqlite3 connection.
        domain: The AD domain name.
        group_name: The group's common name.
        timestamp: ISO 8601 timestamp string.

    Returns:
        Tuple of (group_id, is_new) where is_new is True if the group
        was just created.
    """
    row = conn.execute(
        "SELECT id FROM groups WHERE domain = ? AND group_name = ?",
        (domain, group_name),
    ).fetchone()
    if row:
        conn.execute(
            "UPDATE groups SET last_seen = ? WHERE id = ?",
            (timestamp, row["id"]),
        )
        return row["id"], False
    cursor = conn.execute(
        "INSERT INTO groups (domain, group_name, first_seen, last_seen) VALUES (?, ?, ?, ?)",
        (domain, group_name, timestamp, timestamp),
    )
    return cursor.lastrowid, True


def get_current_members(conn, group_id):
    """Get the current members of a group from the members table.

    Args:
        conn: Active sqlite3 connection.
        group_id: Integer group id.

    Returns:
        Dict mapping lowercase sam_account_name to dict with keys
        SamAccountName, DisplayName, Email.
    """
    rows = conn.execute(
        "SELECT sam_account_name, display_name, email FROM members WHERE group_id = ?",
        (group_id,),
    ).fetchall()
    result = {}
    for r in rows:
        result[r["sam_account_name"].lower()] = {
            "SamAccountName": r["sam_account_name"],
            "DisplayName": r["display_name"] or "",
            "Email": r["email"] or "",
        }
    return result


def sync_members(conn, group_id, current_members, timestamp):
    """Synchronize the members table to reflect the current membership.

    Inserts new members and updates last_seen for existing members.
    Removes members no longer present.

    Args:
        conn: Active sqlite3 connection.
        group_id: Integer group id.
        current_members: List of dicts with SamAccountName, DisplayName, Email.
        timestamp: ISO 8601 timestamp string.
    """
    # Build set of current SAMs (lowercase for matching)
    current_sams = set()
    for m in current_members:
        sam = m.get("SamAccountName", "")
        if not sam:
            continue
        current_sams.add(sam.lower())

        # Upsert member
        existing = conn.execute(
            "SELECT id FROM members WHERE group_id = ? AND sam_account_name = ?",
            (group_id, sam),
        ).fetchone()
        if existing:
            conn.execute(
                "UPDATE members SET display_name = ?, email = ?, last_seen = ? WHERE id = ?",
                (m.get("DisplayName", ""), m.get("Email", ""), timestamp, existing["id"]),
            )
        else:
            conn.execute(
                "INSERT INTO members (group_id, sam_account_name, display_name, email, first_seen, last_seen) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (group_id, sam, m.get("DisplayName", ""), m.get("Email", ""), timestamp, timestamp),
            )

    # Remove members no longer in the group
    existing_rows = conn.execute(
        "SELECT id, sam_account_name FROM members WHERE group_id = ?",
        (group_id,),
    ).fetchall()
    for row in existing_rows:
        if row["sam_account_name"].lower() not in current_sams:
            conn.execute("DELETE FROM members WHERE id = ?", (row["id"],))


def update_csv_group_map(conn, csv_id, group_id, timestamp):
    """Update or create the csv_group_map entry linking a CSV to a group.

    Args:
        conn: Active sqlite3 connection.
        csv_id: Integer csv_sources id.
        group_id: Integer groups id.
        timestamp: ISO 8601 timestamp string.
    """
    existing = conn.execute(
        "SELECT csv_id FROM csv_group_map WHERE csv_id = ? AND group_id = ?",
        (csv_id, group_id),
    ).fetchone()
    if existing:
        conn.execute(
            "UPDATE csv_group_map SET last_mapped = ? WHERE csv_id = ? AND group_id = ?",
            (timestamp, csv_id, group_id),
        )
    else:
        conn.execute(
            "INSERT INTO csv_group_map (csv_id, group_id, first_mapped, last_mapped) VALUES (?, ?, ?, ?)",
            (csv_id, group_id, timestamp, timestamp),
        )


# ---------------------------------------------------------------------------
# Subcommand: import-state
# ---------------------------------------------------------------------------

def cmd_import_state(args):
    """Load current membership state for a CSV set.

    Returns JSON matching the shape of Import-MembershipState in
    MembershipState.ps1: Metadata, GroupsByKey, IsFirstRun.

    Args:
        args: Parsed argparse namespace with csv_name and db.
    """
    db_path = args.db or DEFAULT_DB
    ensure_db(db_path)

    csv_name = args.csv_name

    with get_connection(db_path) as conn:
        # Check if CSV exists
        csv_row = conn.execute(
            "SELECT id FROM csv_sources WHERE csv_name = ?", (csv_name,)
        ).fetchone()

        if not csv_row:
            # First run -- no prior state
            json_out({
                "Metadata": {
                    "Version": "1.0",
                    "FirstRun": None,
                    "LastRun": None,
                    "RunCount": 0,
                },
                "GroupsByKey": {},
                "IsFirstRun": True,
            })
            return

        csv_id = csv_row["id"]

        # Get run metadata
        runs = conn.execute(
            "SELECT COUNT(*) as cnt, MIN(started_at) as first_run, MAX(started_at) as last_run "
            "FROM runs WHERE csv_id = ?",
            (csv_id,),
        ).fetchone()

        # Get all groups mapped to this CSV
        group_rows = conn.execute(
            "SELECT g.id, g.domain, g.group_name, g.last_seen "
            "FROM groups g "
            "JOIN csv_group_map cgm ON cgm.group_id = g.id "
            "WHERE cgm.csv_id = ?",
            (csv_id,),
        ).fetchall()

        groups_by_key = {}
        for g in group_rows:
            key = make_group_key(g["domain"], g["group_name"])
            members = conn.execute(
                "SELECT sam_account_name, display_name, email "
                "FROM members WHERE group_id = ?",
                (g["id"],),
            ).fetchall()

            member_list = []
            for m in members:
                member_list.append({
                    "SamAccountName": m["sam_account_name"],
                    "DisplayName": m["display_name"] or "",
                    "Email": m["email"] or "",
                })

            groups_by_key[key] = {
                "Domain": g["domain"],
                "GroupName": g["group_name"],
                "LastSeen": g["last_seen"],
                "Members": member_list,
            }

        is_first_run = len(groups_by_key) == 0

        json_out({
            "Metadata": {
                "Version": "1.0",
                "FirstRun": runs["first_run"],
                "LastRun": runs["last_run"],
                "RunCount": runs["cnt"],
            },
            "GroupsByKey": groups_by_key,
            "IsFirstRun": is_first_run,
        })


# ---------------------------------------------------------------------------
# Subcommand: update-state
# ---------------------------------------------------------------------------

def cmd_update_state(args):
    """Diff current results against stored state, return changes.

    Change detection is GLOBAL per group (group-as-PK, see schema.sql): a group
    already present in the DB is diffed against its baseline regardless of which
    CSV references it; only a globally-new group is seeded silently.
    - Globally-known groups: compute added/removed members.
    - Globally-new groups (first appearance in the DB): seed silently.
    - Skipped groups: ignored entirely.
    csv_group_map records which CSVs each group appeared in (provenance), enabling
    per-CSV filtered views (query-changes --csv) without maintaining per-CSV
    baselines.

    Reads a JSON array of group results from stdin.

    Args:
        args: Parsed argparse namespace with csv_name, db, stdin flag.
    """
    db_path = args.db or DEFAULT_DB
    ensure_db(db_path)

    csv_name = args.csv_name
    timestamp = now_iso()

    # Read group results from stdin
    try:
        # Read raw bytes and decode as utf-8-sig: PowerShell prepends a UTF-8 BOM
        # to piped stdin, and text-mode sys.stdin (locale codepage on Windows)
        # would mis-decode it, breaking json.loads. utf-8-sig strips any BOM.
        raw = sys.stdin.buffer.read().decode("utf-8-sig")
        group_results = json.loads(raw)
    except (json.JSONDecodeError, ValueError) as e:
        error_exit("Failed to parse input JSON: {}".format(e))

    if not isinstance(group_results, list):
        error_exit("Input must be a JSON array of group results")

    changes = []
    total_added = 0
    total_removed = 0
    groups_changed = 0
    groups_seeded = 0

    with get_connection(db_path) as conn:
        csv_id = get_or_create_csv(conn, csv_name)

        # IsFirstRun = the GLOBAL state was empty before this run (consistent with the
        # JSON backend). A NEW CSV that references already-tracked groups is NOT a first
        # run: those groups are diffed (changes detected and reported), not silently
        # "seeded". Keying this per-CSV (csv_group_map) mislabelled such a run as
        # "baseline seeded for N group(s)" and could suppress the console change report
        # for a shared group that changed before that CSV's first run.
        total_groups_before = conn.execute(
            "SELECT COUNT(*) as cnt FROM groups"
        ).fetchone()["cnt"]
        is_first_run = total_groups_before == 0

        # Get the latest run_id for this CSV (to attach changelog entries)
        latest_run = conn.execute(
            "SELECT id FROM runs WHERE csv_id = ? ORDER BY id DESC LIMIT 1",
            (csv_id,),
        ).fetchone()
        run_id = latest_run["id"] if latest_run else None

        for gr in group_results:
            data = gr.get("Data") or gr.get("data")
            if not data:
                continue
            if data.get("Skipped") or data.get("skipped"):
                continue

            domain = data.get("Domain") or data.get("domain") or ""
            group_name = data.get("GroupName") or data.get("groupName") or ""
            if not domain or not group_name:
                continue

            current_members_raw = data.get("Members") or data.get("members") or []
            when_changed = data.get("WhenChanged") or data.get("whenChanged")
            is_nested_val = data.get("IsNested")
            if is_nested_val is None:
                is_nested_val = data.get("isNested")
            is_nested = None
            if is_nested_val is not None:
                is_nested = 1 if is_nested_val else 0

            # Normalize member list
            current_members = []
            for m in current_members_raw:
                current_members.append({
                    "SamAccountName": m.get("SamAccountName") or m.get("samAccountName") or "",
                    "DisplayName": m.get("DisplayName") or m.get("displayName") or "",
                    "Email": m.get("Email") or m.get("email") or "",
                })

            # Check if group already exists in the DB
            existing_group = conn.execute(
                "SELECT id FROM groups WHERE domain = ? AND group_name = ?",
                (domain, group_name),
            ).fetchone()

            # Group-as-PK (see schema.sql): the membership baseline is GLOBAL per
            # group, so the change gate must be global too. A group already present
            # in the DB is diffed against its baseline regardless of which CSV
            # references it; only a GLOBALLY-new group is seeded silently.
            #
            # Gating on csv_group_map (per-CSV) instead caused a globally-known
            # group that was merely new to THIS CSV to seed silently -- suppressing
            # real adds/removes AND clobbering the shared baseline, which then made
            # the owning CSV emit phantom changes on its next run. With a global
            # gate the changelog stays symmetric (the add is logged when first seen,
            # the remove when it later leaves) no matter which CSV observes it.
            was_known = existing_group is not None

            # Get or create the group
            group_id, is_new_group = get_or_create_group(conn, domain, group_name, timestamp)

            # Update group metadata
            conn.execute(
                "UPDATE groups SET when_changed = ?, is_nested = ? WHERE id = ?",
                (when_changed, is_nested, group_id),
            )

            if was_known:
                # Known group -- compute delta
                baseline = get_current_members(conn, group_id)
                current_sams = {}
                for m in current_members:
                    sam = m["SamAccountName"]
                    if sam:
                        current_sams[sam.lower()] = m

                # Find added members
                added_count = 0
                for sam_lower, m in current_sams.items():
                    if sam_lower not in baseline:
                        changes.append({
                            "Timestamp": timestamp,
                            "Domain": domain,
                            "GroupName": group_name,
                            "SamAccountName": m["SamAccountName"],
                            "DisplayName": m["DisplayName"],
                            "Email": m["Email"],
                            "Action": "Added",
                        })
                        added_count += 1

                # Find removed members
                removed_count = 0
                for sam_lower, m in baseline.items():
                    if sam_lower not in current_sams:
                        changes.append({
                            "Timestamp": timestamp,
                            "Domain": domain,
                            "GroupName": group_name,
                            "SamAccountName": m["SamAccountName"],
                            "DisplayName": m["DisplayName"],
                            "Email": m["Email"],
                            "Action": "Removed",
                        })
                        removed_count += 1

                total_added += added_count
                total_removed += removed_count
                if added_count > 0 or removed_count > 0:
                    groups_changed += 1
            else:
                # New group (first run or newly tracked) -- seed silently
                groups_seeded += 1

            # Sync members table to current state
            sync_members(conn, group_id, current_members, timestamp)

            # Update CSV-group mapping
            update_csv_group_map(conn, csv_id, group_id, timestamp)

        # Write changelog entries to the database
        for change in changes:
            # Look up group_id for this change
            g_row = conn.execute(
                "SELECT id FROM groups WHERE domain = ? AND group_name = ?",
                (change["Domain"], change["GroupName"]),
            ).fetchone()
            if g_row:
                conn.execute(
                    "INSERT INTO changelog (timestamp, group_id, sam_account_name, "
                    "display_name, email, action, run_id) VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (
                        change["Timestamp"],
                        g_row["id"],
                        change["SamAccountName"],
                        change["DisplayName"],
                        change["Email"],
                        change["Action"],
                        run_id,
                    ),
                )

        groups_tracked = conn.execute(
            "SELECT COUNT(*) as cnt FROM csv_group_map WHERE csv_id = ?",
            (csv_id,),
        ).fetchone()["cnt"]

    json_out({
        "Changes": changes,
        "Summary": {
            "TotalAdded": total_added,
            "TotalRemoved": total_removed,
            "GroupsChanged": groups_changed,
            "GroupsTracked": groups_tracked,
            "GroupsSeeded": groups_seeded,
            "IsFirstRun": is_first_run,
        },
    })


# ---------------------------------------------------------------------------
# Subcommand: save-snapshot
# ---------------------------------------------------------------------------

def cmd_save_snapshot(args):
    """Save a run's cache snapshot.

    Reads a JSON array of group results from stdin and stores each
    group's data into cache_snapshots with members_json.

    Args:
        args: Parsed argparse namespace with run_id, db, stdin flag.
    """
    db_path = args.db or DEFAULT_DB
    ensure_db(db_path)

    run_id = args.run_id

    # Read group results from stdin
    try:
        # Read raw bytes and decode as utf-8-sig: PowerShell prepends a UTF-8 BOM
        # to piped stdin, and text-mode sys.stdin (locale codepage on Windows)
        # would mis-decode it, breaking json.loads. utf-8-sig strips any BOM.
        raw = sys.stdin.buffer.read().decode("utf-8-sig")
        group_results = json.loads(raw)
    except (json.JSONDecodeError, ValueError) as e:
        error_exit("Failed to parse input JSON: {}".format(e))

    if not isinstance(group_results, list):
        error_exit("Input must be a JSON array of group results")

    saved = 0
    with get_connection(db_path) as conn:
        # Verify run exists
        run_row = conn.execute("SELECT id FROM runs WHERE id = ?", (run_id,)).fetchone()
        if not run_row:
            error_exit("Run {} not found".format(run_id))

        for gr in group_results:
            data = gr.get("Data") or gr.get("data")
            if not data:
                continue

            domain = data.get("Domain") or data.get("domain") or ""
            group_name = data.get("GroupName") or data.get("groupName") or ""
            if not domain or not group_name:
                continue

            # Find group id
            g_row = conn.execute(
                "SELECT id FROM groups WHERE domain = ? AND group_name = ?",
                (domain, group_name),
            ).fetchone()
            if not g_row:
                continue

            members = data.get("Members") or data.get("members") or []
            when_changed = data.get("WhenChanged") or data.get("whenChanged")
            is_nested_val = data.get("IsNested")
            if is_nested_val is None:
                is_nested_val = data.get("isNested")
            is_nested = None
            if is_nested_val is not None:
                is_nested = 1 if is_nested_val else 0

            skipped = data.get("Skipped") or data.get("skipped") or False
            reused = 1 if skipped else 0

            members_json = json.dumps(members, separators=(",", ":"))

            conn.execute(
                "INSERT OR REPLACE INTO cache_snapshots "
                "(run_id, group_id, member_count, when_changed, is_nested, "
                "reused_from_cache, members_json) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    run_id,
                    g_row["id"],
                    len(members),
                    when_changed,
                    is_nested,
                    reused,
                    members_json,
                ),
            )
            saved += 1

    json_out({"SnapshotsSaved": saved})


# ---------------------------------------------------------------------------
# Subcommand: get-cache
# ---------------------------------------------------------------------------

def cmd_get_cache(args):
    """Get latest cache for incremental gate.

    Returns the most recent cache snapshot for each group associated
    with the given CSV source.

    Args:
        args: Parsed argparse namespace with csv_name and db.
    """
    db_path = args.db or DEFAULT_DB
    ensure_db(db_path)

    csv_name = args.csv_name

    with get_connection(db_path) as conn:
        csv_row = conn.execute(
            "SELECT id FROM csv_sources WHERE csv_name = ?", (csv_name,)
        ).fetchone()

        if not csv_row:
            json_out({"GroupCache": {}})
            return

        csv_id = csv_row["id"]

        # Latest run for this CSV that actually HAS cache snapshots. The orchestrator
        # calls Start-EnumerationRun (creating an empty run row) BEFORE reading the
        # cache, so "latest run" would be the just-started empty run -> no reuse.
        # Selecting the newest run_id present in cache_snapshots returns the prior
        # populated run (and skips any earlier run that failed before saving).
        latest_run = conn.execute(
            "SELECT cs.run_id AS id FROM cache_snapshots cs "
            "JOIN runs r ON r.id = cs.run_id "
            "WHERE r.csv_id = ? ORDER BY cs.run_id DESC LIMIT 1",
            (csv_id,),
        ).fetchone()

        if not latest_run:
            json_out({"GroupCache": {}})
            return

        # Get all cache snapshots for that run
        snapshots = conn.execute(
            "SELECT cs.when_changed, cs.is_nested, cs.member_count, cs.members_json, "
            "g.domain, g.group_name "
            "FROM cache_snapshots cs "
            "JOIN groups g ON g.id = cs.group_id "
            "WHERE cs.run_id = ?",
            (latest_run["id"],),
        ).fetchall()

        cache = {}
        for s in snapshots:
            key = make_group_key(s["domain"], s["group_name"])
            cache[key] = {
                # Domain/GroupName MUST be returned: the orchestrator's reuse path
                # re-saves the reused group's Data into the next run's snapshot, and
                # save-snapshot keys on Domain+GroupName. Omitting them made reused
                # groups un-saveable, so incremental reuse decayed to nothing after
                # one cycle (and reused groups rendered with blank names in reports).
                "Domain": s["domain"],
                "GroupName": s["group_name"],
                "WhenChanged": s["when_changed"],
                "IsNested": bool(s["is_nested"]) if s["is_nested"] is not None else None,
                "MemberCount": s["member_count"],
                "MembersJson": s["members_json"],
            }

    json_out({"GroupCache": cache})


# ---------------------------------------------------------------------------
# Subcommand: start-run
# ---------------------------------------------------------------------------

def cmd_start_run(args):
    """Begin a new run record.

    Creates a csv_sources record if needed, then inserts a new runs
    record with started_at set to now.

    Args:
        args: Parsed argparse namespace with csv_name and db.
    """
    db_path = args.db or DEFAULT_DB
    ensure_db(db_path)

    csv_name = args.csv_name
    timestamp = now_iso()

    with get_connection(db_path) as conn:
        csv_id = get_or_create_csv(conn, csv_name)
        cursor = conn.execute(
            "INSERT INTO runs (csv_id, started_at) VALUES (?, ?)",
            (csv_id, timestamp),
        )
        run_id = cursor.lastrowid

    json_out({"RunId": run_id})


# ---------------------------------------------------------------------------
# Subcommand: complete-run
# ---------------------------------------------------------------------------

def cmd_complete_run(args):
    """Mark a run as complete with metrics.

    Reads a JSON object of metrics from stdin and updates the run
    record.

    Args:
        args: Parsed argparse namespace with run_id, db, stdin flag.
    """
    db_path = args.db or DEFAULT_DB
    ensure_db(db_path)

    run_id = args.run_id
    timestamp = now_iso()

    # Read metrics from stdin
    try:
        # Read raw bytes and decode as utf-8-sig: PowerShell prepends a UTF-8 BOM
        # to piped stdin, and text-mode sys.stdin (locale codepage on Windows)
        # would mis-decode it, breaking json.loads. utf-8-sig strips any BOM.
        raw = sys.stdin.buffer.read().decode("utf-8-sig")
        metrics = json.loads(raw)
    except (json.JSONDecodeError, ValueError) as e:
        error_exit("Failed to parse metrics JSON: {}".format(e))

    with get_connection(db_path) as conn:
        run_row = conn.execute("SELECT id FROM runs WHERE id = ?", (run_id,)).fetchone()
        if not run_row:
            error_exit("Run {} not found".format(run_id))

        conn.execute(
            "UPDATE runs SET completed_at = ?, groups_enumerated = ?, "
            "groups_skipped = ?, groups_reused = ?, total_members = ?, "
            "changes_detected = ? WHERE id = ?",
            (
                timestamp,
                metrics.get("GroupsEnumerated", 0),
                metrics.get("GroupsSkipped", 0),
                metrics.get("GroupsReused", 0),
                metrics.get("TotalMembers", 0),
                metrics.get("ChangesDetected", 0),
                run_id,
            ),
        )

    json_out({"RunId": run_id, "CompletedAt": timestamp})


# ---------------------------------------------------------------------------
# Subcommand: query-changes
# ---------------------------------------------------------------------------

def cmd_query_changes(args):
    """Query changelog with filters.

    Returns a JSON array of change events, optionally filtered by
    CSV source, change type, and/or date.

    Args:
        args: Parsed argparse namespace with csv_name, change_type,
              since, and db.
    """
    db_path = args.db or DEFAULT_DB
    ensure_db(db_path)

    with get_connection(db_path) as conn:
        query = (
            "SELECT cl.timestamp, g.domain, g.group_name, cl.sam_account_name, "
            "cl.display_name, cl.email, cl.action "
            "FROM changelog cl "
            "JOIN groups g ON g.id = cl.group_id"
        )
        params = []
        conditions = []

        # Filter by CSV source
        if args.csv_name:
            conditions.append(
                "cl.group_id IN ("
                "  SELECT group_id FROM csv_group_map "
                "  WHERE csv_id = (SELECT id FROM csv_sources WHERE csv_name = ?)"
                ")"
            )
            params.append(args.csv_name)

        # Filter by change type
        if args.change_type and args.change_type != "Both":
            conditions.append("cl.action = ?")
            params.append(args.change_type)

        # Filter by date
        if args.since:
            conditions.append("cl.timestamp >= ?")
            params.append(args.since)

        if conditions:
            query += " WHERE " + " AND ".join(conditions)

        query += " ORDER BY cl.timestamp DESC"

        rows = conn.execute(query, params).fetchall()

        result = []
        for r in rows:
            result.append({
                "Timestamp": r["timestamp"],
                "Domain": r["domain"],
                "GroupName": r["group_name"],
                "SamAccountName": r["sam_account_name"],
                "DisplayName": r["display_name"] or "",
                "Email": r["email"] or "",
                "Action": r["action"],
            })

    json_out(result)


# ---------------------------------------------------------------------------
# Subcommand: migrate-json
# ---------------------------------------------------------------------------

def cmd_migrate_json(args):
    """Import existing JSON state files into the database.

    Reads the JSON state file format used by MembershipState.ps1 and
    imports all groups and members. Optionally imports changelog entries
    from the JSONL changelog file.

    Args:
        args: Parsed argparse namespace with state_file, changelog_file,
              csv_name, and db.
    """
    db_path = args.db or DEFAULT_DB
    ensure_db(db_path)

    state_file = Path(args.state_file)
    if not state_file.exists():
        error_exit("State file not found: {}".format(state_file))

    # Read state file
    try:
        state_data = json.loads(state_file.read_text(encoding="utf-8-sig"))
    except (json.JSONDecodeError, ValueError) as e:
        error_exit("Failed to parse state file: {}".format(e))

    csv_name = args.csv_name
    groups_imported = 0
    members_imported = 0
    changelog_imported = 0

    with get_connection(db_path) as conn:
        csv_id = get_or_create_csv(conn, csv_name)
        timestamp = now_iso()

        # Create a migration run
        cursor = conn.execute(
            "INSERT INTO runs (csv_id, started_at, completed_at) VALUES (?, ?, ?)",
            (csv_id, timestamp, timestamp),
        )
        run_id = cursor.lastrowid

        # Import groups from the state file
        groups = state_data.get("Groups", [])
        if not isinstance(groups, list):
            groups = []

        for g in groups:
            domain = g.get("Domain", "")
            group_name = g.get("GroupName", "")
            if not domain or not group_name:
                continue

            last_seen = g.get("LastSeen", timestamp)
            group_id, _ = get_or_create_group(conn, domain, group_name, last_seen)

            # Update group metadata
            conn.execute(
                "UPDATE groups SET first_seen = ?, last_seen = ? WHERE id = ?",
                (last_seen, last_seen, group_id),
            )

            # Import members
            members = g.get("Members", [])
            if not isinstance(members, list):
                members = []

            for m in members:
                sam = m.get("SamAccountName", "")
                if not sam:
                    continue
                display_name = m.get("DisplayName", "")
                email = m.get("Email", "")

                existing = conn.execute(
                    "SELECT id FROM members WHERE group_id = ? AND sam_account_name = ?",
                    (group_id, sam),
                ).fetchone()
                if not existing:
                    conn.execute(
                        "INSERT INTO members (group_id, sam_account_name, display_name, "
                        "email, first_seen, last_seen) VALUES (?, ?, ?, ?, ?, ?)",
                        (group_id, sam, display_name, email, last_seen, last_seen),
                    )
                    members_imported += 1

            # Map CSV to group
            update_csv_group_map(conn, csv_id, group_id, last_seen)
            groups_imported += 1

        # Import changelog if provided
        if args.changelog_file:
            changelog_path = Path(args.changelog_file)
            if changelog_path.exists():
                for line in changelog_path.read_text(encoding="utf-8-sig").splitlines():
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        entry = json.loads(line)
                    except (json.JSONDecodeError, ValueError):
                        continue

                    domain = entry.get("Domain", "")
                    group_name = entry.get("GroupName", "")
                    if not domain or not group_name:
                        continue

                    g_row = conn.execute(
                        "SELECT id FROM groups WHERE domain = ? AND group_name = ?",
                        (domain, group_name),
                    ).fetchone()
                    if not g_row:
                        # Create the group if referenced in changelog but not in state
                        g_id, _ = get_or_create_group(
                            conn, domain, group_name,
                            entry.get("Timestamp", timestamp),
                        )
                    else:
                        g_id = g_row["id"]

                    conn.execute(
                        "INSERT INTO changelog (timestamp, group_id, sam_account_name, "
                        "display_name, email, action, run_id) VALUES (?, ?, ?, ?, ?, ?, ?)",
                        (
                            entry.get("Timestamp", timestamp),
                            g_id,
                            entry.get("SamAccountName", ""),
                            entry.get("DisplayName", ""),
                            entry.get("Email", ""),
                            entry.get("Action", "Added"),
                            run_id,
                        ),
                    )
                    changelog_imported += 1

        # Update run metrics
        conn.execute(
            "UPDATE runs SET groups_enumerated = ?, total_members = ?, "
            "changes_detected = ? WHERE id = ?",
            (groups_imported, members_imported, changelog_imported, run_id),
        )

    json_out({
        "GroupsImported": groups_imported,
        "MembersImported": members_imported,
        "ChangelogEntriesImported": changelog_imported,
    })


# ---------------------------------------------------------------------------
# Subcommand: gc
# ---------------------------------------------------------------------------

def cmd_gc(args):
    """Garbage collect orphaned groups not seen in more than N days.

    Groups whose last_seen timestamp is older than the threshold are
    removed along with their members and changelog entries. In dry-run
    mode, no changes are made.

    Args:
        args: Parsed argparse namespace with days, db, dry_run.
    """
    db_path = args.db or DEFAULT_DB
    ensure_db(db_path)

    threshold_days = args.days
    cutoff = (datetime.now(timezone.utc) - timedelta(days=threshold_days)).strftime(
        "%Y-%m-%dT%H:%M:%S.%fZ"
    )

    with get_connection(db_path) as conn:
        stale_groups = conn.execute(
            "SELECT id, domain, group_name, last_seen FROM groups WHERE last_seen < ?",
            (cutoff,),
        ).fetchall()

        group_names = []
        group_ids = []
        for g in stale_groups:
            group_names.append(make_group_key(g["domain"], g["group_name"]))
            group_ids.append(g["id"])

        if args.dry_run:
            json_out({
                "GroupsArchived": len(group_ids),
                "GroupNames": group_names,
                "DryRun": True,
            })
            return

        for gid in group_ids:
            # Delete in order: cache_snapshots, changelog, csv_group_map, members, then group
            conn.execute("DELETE FROM cache_snapshots WHERE group_id = ?", (gid,))
            conn.execute("DELETE FROM changelog WHERE group_id = ?", (gid,))
            conn.execute("DELETE FROM csv_group_map WHERE group_id = ?", (gid,))
            conn.execute("DELETE FROM members WHERE group_id = ?", (gid,))
            conn.execute("DELETE FROM groups WHERE id = ?", (gid,))

    json_out({
        "GroupsArchived": len(group_ids),
        "GroupNames": group_names,
    })


# ---------------------------------------------------------------------------
# Subcommand: stats
# ---------------------------------------------------------------------------

def cmd_stats(args):
    """Return database statistics as JSON.

    Counts of groups, members, changelog entries, runs, CSV sources,
    and cache snapshots.

    Args:
        args: Parsed argparse namespace with db.
    """
    db_path = args.db or DEFAULT_DB
    ensure_db(db_path)

    with get_connection(db_path) as conn:
        groups = conn.execute("SELECT COUNT(*) as c FROM groups").fetchone()["c"]
        # Members = membership rows (a user in N groups counts N times).
        members = conn.execute("SELECT COUNT(*) as c FROM members").fetchone()["c"]
        # DistinctMembers = true distinct identities by (domain, sam): a user in 10
        # groups counts ONCE. (e.g. 5000 memberships across 500 users -> 500.)
        distinct_members = conn.execute(
            "SELECT COUNT(*) as c FROM ("
            "  SELECT DISTINCT g.domain, m.sam_account_name "
            "  FROM members m JOIN groups g ON g.id = m.group_id"
            ")"
        ).fetchone()["c"]
        changelog = conn.execute("SELECT COUNT(*) as c FROM changelog").fetchone()["c"]
        runs = conn.execute("SELECT COUNT(*) as c FROM runs").fetchone()["c"]
        csv_sources = conn.execute("SELECT COUNT(*) as c FROM csv_sources").fetchone()["c"]
        cache_snapshots = conn.execute(
            "SELECT COUNT(*) as c FROM cache_snapshots"
        ).fetchone()["c"]

        # Get latest run info
        latest_run = conn.execute(
            "SELECT r.started_at, r.completed_at, cs.csv_name "
            "FROM runs r JOIN csv_sources cs ON cs.id = r.csv_id "
            "ORDER BY r.id DESC LIMIT 1"
        ).fetchone()

        # Get changelog summary
        added = conn.execute(
            "SELECT COUNT(*) as c FROM changelog WHERE action = 'Added'"
        ).fetchone()["c"]
        removed = conn.execute(
            "SELECT COUNT(*) as c FROM changelog WHERE action = 'Removed'"
        ).fetchone()["c"]

        # Database file size
        db_file = Path(db_path)
        db_size_kb = round(db_file.stat().st_size / 1024, 1) if db_file.exists() else 0

    result = {
        "Groups": groups,
        "Members": members,
        "DistinctMembers": distinct_members,
        "ChangelogEntries": changelog,
        "ChangelogAdded": added,
        "ChangelogRemoved": removed,
        "Runs": runs,
        "CsvSources": csv_sources,
        "CacheSnapshots": cache_snapshots,
        "DatabaseSizeKB": db_size_kb,
    }

    if latest_run:
        result["LatestRun"] = {
            "StartedAt": latest_run["started_at"],
            "CompletedAt": latest_run["completed_at"],
            "CsvName": latest_run["csv_name"],
        }

    json_out(result)


def cmd_validate(args):
    """Audit the state DB for integrity / consistency (read-only).

    Runs a battery of structural + logical checks and returns a structured
    verdict. Designed to catch the classes of bug we have actually hit (e.g.
    incremental-reuse snapshot decay, blank-identity reused groups) plus generic
    corruption / referential-integrity problems.

    Args:
        args: Parsed argparse namespace with db.
    """
    db_path = args.db or DEFAULT_DB
    ensure_db(db_path)
    checks = []

    def add(name, severity, count, detail):
        checks.append({"Name": name, "Severity": severity, "Count": count, "Detail": detail})

    with get_connection(db_path) as conn:
        # 1. SQLite physical integrity.
        ic = conn.execute("PRAGMA integrity_check").fetchall()
        ic_ok = (len(ic) == 1 and ic[0][0] == "ok")
        add("sqlite_integrity", "ok" if ic_ok else "error", 0 if ic_ok else len(ic),
            "ok" if ic_ok else "; ".join(str(r[0]) for r in ic[:5]))

        # 2. Referential integrity across all foreign keys.
        fk = conn.execute("PRAGMA foreign_key_check").fetchall()
        add("foreign_keys", "ok" if not fk else "error", len(fk),
            "all references valid" if not fk else "{} orphaned reference(s)".format(len(fk)))

        # 3. Group identity (blank domain/name -> reused groups would render nameless).
        blank_g = conn.execute(
            "SELECT COUNT(*) c FROM groups WHERE domain IS NULL OR domain='' "
            "OR group_name IS NULL OR group_name=''").fetchone()["c"]
        add("group_identity", "ok" if not blank_g else "warn", blank_g,
            "all groups have domain+name" if not blank_g else
            "{} group(s) with blank domain/name".format(blank_g))

        # 4. Member identity.
        blank_m = conn.execute(
            "SELECT COUNT(*) c FROM members WHERE sam_account_name IS NULL "
            "OR sam_account_name=''").fetchone()["c"]
        add("member_identity", "ok" if not blank_m else "warn", blank_m,
            "all members have a sam_account_name" if not blank_m else
            "{} member(s) with blank sam".format(blank_m))

        # 5. Snapshot internal consistency: member_count == len(members_json).
        bad_snap = 0
        for row in conn.execute("SELECT member_count, members_json FROM cache_snapshots"):
            try:
                n = len(json.loads(row["members_json"])) if row["members_json"] else 0
            except (ValueError, TypeError):
                n = -1
            if row["member_count"] is not None and n >= 0 and row["member_count"] != n:
                bad_snap += 1
        add("snapshot_member_counts", "ok" if not bad_snap else "error", bad_snap,
            "member_count matches stored members" if not bad_snap else
            "{} snapshot(s) where member_count != stored members".format(bad_snap))

        # 6. Reuse-basis completeness (incremental-decay detector): for each CSV, the
        #    latest run WITH snapshots is the next run's reuse basis and must cover every
        #    group mapped to that CSV -- else reuse silently re-enumerates / loses groups.
        decay = 0
        for csv in conn.execute("SELECT id, csv_name FROM csv_sources"):
            latest = conn.execute(
                "SELECT cs.run_id AS rid FROM cache_snapshots cs JOIN runs r ON r.id=cs.run_id "
                "WHERE r.csv_id=? ORDER BY cs.run_id DESC LIMIT 1", (csv["id"],)).fetchone()
            if not latest:
                continue
            mapped = set(r["group_id"] for r in conn.execute(
                "SELECT group_id FROM csv_group_map WHERE csv_id=?", (csv["id"],)))
            snapped = set(r["group_id"] for r in conn.execute(
                "SELECT group_id FROM cache_snapshots WHERE run_id=?", (latest["rid"],)))
            decay += len(mapped - snapped)
        add("reuse_basis_completeness", "ok" if not decay else "warn", decay,
            "each CSV's latest snapshot covers all its mapped groups" if not decay else
            "{} mapped group(s) missing from a CSV's latest snapshot (reuse decay?)".format(decay))

        sv = conn.execute("SELECT MAX(version) v FROM schema_version").fetchone()
        version = sv["v"] if sv and sv["v"] is not None else None

    errors = sum(1 for c in checks if c["Severity"] == "error")
    warnings = sum(1 for c in checks if c["Severity"] == "warn")
    json_out({"Ok": errors == 0, "Errors": errors, "Warnings": warnings,
              "SchemaVersion": version, "Checks": checks})


# ---------------------------------------------------------------------------
# CLI argument parsing
# ---------------------------------------------------------------------------

def build_parser():
    """Build the argparse parser with all subcommands.

    Returns:
        argparse.ArgumentParser with subcommands configured.
    """
    parser = argparse.ArgumentParser(
        description="Group Enumerator v3.0 - SQLite State Manager"
    )
    sub = parser.add_subparsers(dest="command", help="Commands")

    # import-state
    p_import = sub.add_parser(
        "import-state",
        help="Load current membership state for a CSV set",
    )
    p_import.add_argument("--csv-name", required=True, help="CSV leaf filename")
    p_import.add_argument("--db", help="Path to SQLite database")

    # update-state
    p_update = sub.add_parser(
        "update-state",
        help="Diff current results against stored state, return changes",
    )
    p_update.add_argument("--csv-name", required=True, help="CSV leaf filename")
    p_update.add_argument("--db", help="Path to SQLite database")
    p_update.add_argument(
        "--stdin", action="store_true",
        help="Read JSON array of group results from stdin",
    )

    # save-snapshot
    p_snap = sub.add_parser(
        "save-snapshot",
        help="Save a run's cache snapshot",
    )
    p_snap.add_argument("--run-id", type=int, required=True, help="Run ID")
    p_snap.add_argument("--db", help="Path to SQLite database")
    p_snap.add_argument(
        "--stdin", action="store_true",
        help="Read JSON array of group results from stdin",
    )

    # get-cache
    p_cache = sub.add_parser(
        "get-cache",
        help="Get latest cache for incremental gate",
    )
    p_cache.add_argument("--csv-name", required=True, help="CSV leaf filename")
    p_cache.add_argument("--db", help="Path to SQLite database")

    # start-run
    p_start = sub.add_parser(
        "start-run",
        help="Begin a new run record",
    )
    p_start.add_argument("--csv-name", required=True, help="CSV leaf filename")
    p_start.add_argument("--db", help="Path to SQLite database")

    # complete-run
    p_complete = sub.add_parser(
        "complete-run",
        help="Mark run as complete with metrics",
    )
    p_complete.add_argument("--run-id", type=int, required=True, help="Run ID")
    p_complete.add_argument("--db", help="Path to SQLite database")
    p_complete.add_argument(
        "--stdin", action="store_true",
        help="Read JSON metrics from stdin",
    )

    # query-changes
    p_query = sub.add_parser(
        "query-changes",
        help="Query changelog with filters",
    )
    p_query.add_argument("--csv-name", help="Filter by CSV source (optional)")
    p_query.add_argument(
        "--change-type", default="Both",
        choices=["Added", "Removed", "Both"],
        help="Filter by change type",
    )
    p_query.add_argument("--since", help="Only changes at or after this ISO 8601 date")
    p_query.add_argument("--db", help="Path to SQLite database")

    # migrate-json
    p_migrate = sub.add_parser(
        "migrate-json",
        help="Import existing JSON state files into the database",
    )
    p_migrate.add_argument("--state-file", required=True, help="Path to state.json")
    p_migrate.add_argument("--changelog-file", help="Path to changelog.jsonl (optional)")
    p_migrate.add_argument("--csv-name", required=True, help="CSV leaf filename to associate")
    p_migrate.add_argument("--db", help="Path to SQLite database")

    # gc
    p_gc = sub.add_parser(
        "gc",
        help="Garbage collect orphaned groups",
    )
    p_gc.add_argument("--days", type=int, required=True, help="Threshold in days")
    p_gc.add_argument("--db", help="Path to SQLite database")
    p_gc.add_argument("--dry-run", action="store_true", help="Preview without deleting")

    # stats
    p_stats = sub.add_parser(
        "stats",
        help="Database statistics",
    )
    p_stats.add_argument("--db", help="Path to SQLite database")

    p_validate = sub.add_parser(
        "validate",
        help="Audit the database for integrity / consistency (read-only)",
    )
    p_validate.add_argument("--db", help="Path to SQLite database")

    return parser


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def main():
    """Main entry point for the CLI."""
    parser = build_parser()
    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    commands = {
        "import-state": cmd_import_state,
        "update-state": cmd_update_state,
        "save-snapshot": cmd_save_snapshot,
        "get-cache": cmd_get_cache,
        "start-run": cmd_start_run,
        "complete-run": cmd_complete_run,
        "query-changes": cmd_query_changes,
        "migrate-json": cmd_migrate_json,
        "gc": cmd_gc,
        "stats": cmd_stats,
        "validate": cmd_validate,
    }

    func = commands.get(args.command)
    if func:
        try:
            func(args)
        except sqlite3.DatabaseError as e:
            db_path = getattr(args, "db", None) or DEFAULT_DB
            print_err("Database error: {}".format(e))
            if handle_corruption(db_path):
                print_err("Database was corrupt and has been recreated. Please retry.")
            sys.exit(1)
        except Exception as e:
            print_err("Unexpected error: {}".format(e))
            sys.exit(1)
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
