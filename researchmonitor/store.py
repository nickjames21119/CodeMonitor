"""Durable local state in SQLite (WAL). Shared by the CLI, per-run supervisors, the agent and the dashboard.

Every process opens its own connection; writes are short `BEGIN IMMEDIATE` transactions, so several
supervisors can finalize runs concurrently without corrupting each other.
"""
from __future__ import annotations

import contextlib
import os
import sqlite3
import time

from . import util
from .config import db_path

SCHEMA_VERSION = 2

TERMINAL = {"SUCCEEDED", "SUCCEEDED_UNVERIFIED", "FAILED", "UNKNOWN", "CANCELED", "TIMED_OUT", "LOST"}
ACTIVE = {"CREATED", "STARTING", "RUNNING", "FINALIZING"}

# Authority of the evidence behind a status. A terminal status can only be replaced by stronger evidence.
AUTH_INFERRED = 1     # recovery / watchdog inference
AUTH_OBSERVED = 2     # attached observer saw the process vanish
AUTH_SUPERVISOR = 3   # parent supervisor holding the real exit code

SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT);
CREATE TABLE IF NOT EXISTS kv (key TEXT PRIMARY KEY, value TEXT, updated_at REAL);
CREATE TABLE IF NOT EXISTS runs (
    run_id TEXT PRIMARY KEY,
    name TEXT, project TEXT, mode TEXT, priority TEXT, tags TEXT,
    command TEXT, cwd TEXT, host_id TEXT, boot_id TEXT,
    status TEXT NOT NULL, status_authority INTEGER DEFAULT 0, health TEXT DEFAULT 'OK',
    version INTEGER NOT NULL DEFAULT 0,
    created_at REAL, started_at REAL, ended_at REAL,
    supervisor_pid INTEGER, supervisor_token TEXT, supervisor_seen_at REAL,
    pid INTEGER, pid_token TEXT,
    exit_code INTEGER, exit_desc TEXT,
    failure_code TEXT, failure_summary TEXT, evidence TEXT,
    validation TEXT, metrics TEXT, resources TEXT,
    last_progress TEXT, last_progress_at REAL, progress_count INTEGER DEFAULT 0,
    run_dir TEXT, log_path TEXT, progress_path TEXT,
    spec TEXT, cancel_requested INTEGER DEFAULT 0, incident_id TEXT,
    profile TEXT, detect TEXT
);
CREATE INDEX IF NOT EXISTS runs_status ON runs(status);
CREATE INDEX IF NOT EXISTS runs_created ON runs(created_at);
CREATE TABLE IF NOT EXISTS events (
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id TEXT UNIQUE NOT NULL,
    run_id TEXT, incident_id TEXT, ts REAL NOT NULL, source TEXT, type TEXT NOT NULL, payload TEXT
);
CREATE INDEX IF NOT EXISTS events_run ON events(run_id);
CREATE TABLE IF NOT EXISTS samples (
    run_id TEXT NOT NULL, ts REAL NOT NULL, cpu REAL, rss INTEGER, nproc INTEGER, threads INTEGER,
    sys_mem REAL, gpu_util REAL, gpu_mem INTEGER, disk_free INTEGER
);
CREATE INDEX IF NOT EXISTS samples_run ON samples(run_id, ts);
CREATE TABLE IF NOT EXISTS incidents (
    incident_id TEXT PRIMARY KEY, fingerprint TEXT, category TEXT, title TEXT,
    severity TEXT, status TEXT NOT NULL, kind TEXT,
    created_at REAL, updated_at REAL, acked_at REAL, acked_by TEXT, resolved_at REAL,
    snoozed_until REAL, next_step INTEGER DEFAULT 1, next_step_at REAL, escalation_stopped INTEGER DEFAULT 0,
    runs TEXT, version INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS incidents_fp ON incidents(fingerprint, status);
CREATE TABLE IF NOT EXISTS incident_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT, incident_id TEXT NOT NULL, ts REAL, actor TEXT, action TEXT, detail TEXT
);
CREATE TABLE IF NOT EXISTS notifications (
    notification_id TEXT PRIMARY KEY, group_key TEXT, kind TEXT, run_id TEXT, incident_id TEXT, severity TEXT,
    channel TEXT NOT NULL, subject TEXT, body_text TEXT, body_html TEXT, push_title TEXT, push_body TEXT,
    attachments TEXT, status TEXT NOT NULL, attempts INTEGER DEFAULT 0,
    next_attempt_at REAL, lease_until REAL, created_at REAL, sent_at REAL, last_error TEXT
);
CREATE INDEX IF NOT EXISTS notif_due ON notifications(status, next_attempt_at);
CREATE TABLE IF NOT EXISTS rules (
    id INTEGER PRIMARY KEY AUTOINCREMENT, action TEXT NOT NULL, pattern TEXT NOT NULL, note TEXT, created_at REAL
);
CREATE TABLE IF NOT EXISTS notification_attempts (
    id INTEGER PRIMARY KEY AUTOINCREMENT, notification_id TEXT, ts REAL, ok INTEGER, error TEXT, duration REAL
);
"""


def connect(path: str | None = None) -> sqlite3.Connection:
    path = path or db_path()
    conn = sqlite3.connect(path, timeout=60, isolation_level=None, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA busy_timeout=60000")
    try:
        conn.execute("PRAGMA journal_mode=WAL")
    except sqlite3.OperationalError:
        pass
    conn.execute("PRAGMA synchronous=NORMAL")  # WAL+NORMAL: crash-safe, far fewer fsyncs (lightweight)
    _ensure_schema(conn)
    return conn


def _ensure_schema(conn: sqlite3.Connection) -> None:
    row = None
    try:
        row = conn.execute("SELECT value FROM meta WHERE key='schema_version'").fetchone()
    except sqlite3.OperationalError:
        pass
    if row and int(row[0]) >= SCHEMA_VERSION:
        return
    with tx(conn):
        for stmt in [s for s in SCHEMA.split(";") if s.strip()]:
            conn.execute(stmt)
        cols = {r[1] for r in conn.execute("PRAGMA table_info(runs)")}
        for col in ("profile", "detect"):  # v1 -> v2
            if col not in cols:
                conn.execute(f"ALTER TABLE runs ADD COLUMN {col} TEXT")
        conn.execute("INSERT OR REPLACE INTO meta(key,value) VALUES('schema_version',?)", (str(SCHEMA_VERSION),))


@contextlib.contextmanager
def tx(conn: sqlite3.Connection):
    """Exclusive-for-writes transaction with retry on SQLITE_BUSY at BEGIN. Nested use becomes a savepoint."""
    if conn.in_transaction:
        name = "sp_" + util.new_id()
        conn.execute(f"SAVEPOINT {name}")
        try:
            yield conn
        except BaseException:
            conn.execute(f"ROLLBACK TO {name}")
            conn.execute(f"RELEASE {name}")
            raise
        else:
            conn.execute(f"RELEASE {name}")
        return
    for attempt in range(20):
        try:
            conn.execute("BEGIN IMMEDIATE")
            break
        except sqlite3.OperationalError as e:
            if "locked" not in str(e) and "busy" not in str(e):
                raise
            time.sleep(0.2 * (attempt + 1))
    else:
        conn.execute("BEGIN IMMEDIATE")
    try:
        yield conn
    except BaseException:
        conn.execute("ROLLBACK")
        raise
    else:
        conn.execute("COMMIT")


# --------------------------------------------------------------------------- kv / meta

def kv_get(conn, key: str, default=None):
    row = conn.execute("SELECT value FROM kv WHERE key=?", (key,)).fetchone()
    return row[0] if row else default


def kv_set(conn, key: str, value) -> None:
    conn.execute("INSERT INTO kv(key,value,updated_at) VALUES(?,?,?) "
                 "ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at",
                 (key, None if value is None else str(value), util.now()))


def kv_claim_interval(conn, key: str, interval: float) -> bool:
    """Atomically claim a periodic job. True if this caller should do it now."""
    t = util.now()
    with tx(conn):
        row = conn.execute("SELECT value FROM kv WHERE key=?", (key,)).fetchone()
        last = float(row[0]) if row and row[0] else 0.0
        if t - last < interval:
            return False
        kv_set(conn, key, t)
        return True


# --------------------------------------------------------------------------- events

def add_event(conn, type_: str, run_id: str | None = None, incident_id: str | None = None,
              source: str = "agent", payload: dict | None = None, ts: float | None = None) -> str:
    eid = util.new_id("ev-")
    conn.execute("INSERT OR IGNORE INTO events(event_id,run_id,incident_id,ts,source,type,payload) "
                 "VALUES(?,?,?,?,?,?,?)",
                 (eid, run_id, incident_id, ts or util.now(), source, type_, util.json_dumps(payload or {})))
    return eid


def run_events(conn, run_id: str) -> list:
    return conn.execute("SELECT * FROM events WHERE run_id=? ORDER BY seq", (run_id,)).fetchall()


# --------------------------------------------------------------------------- runs

def get_run(conn, run_id: str):
    return conn.execute("SELECT * FROM runs WHERE run_id=?", (run_id,)).fetchone()


def resolve_run_id(conn, ref: str | None) -> str | None:
    """Accept a full id, a unique prefix/substring, or nothing (= latest run)."""
    if not ref or ref in ("last", "@last"):
        row = conn.execute("SELECT run_id FROM runs ORDER BY created_at DESC LIMIT 1").fetchone()
        return row[0] if row else None
    row = conn.execute("SELECT run_id FROM runs WHERE run_id=?", (ref,)).fetchone()
    if row:
        return row[0]
    rows = conn.execute("SELECT run_id FROM runs WHERE run_id LIKE ? ORDER BY created_at DESC",
                        (f"%{ref}%",)).fetchall()
    if len(rows) == 1:
        return rows[0][0]
    if len(rows) > 1:
        raise LookupError(f"'{ref}' matches {len(rows)} runs; be more specific")
    return None


def insert_run(conn, **fields) -> None:
    cols = ",".join(fields)
    qs = ",".join("?" for _ in fields)
    conn.execute(f"INSERT INTO runs({cols}) VALUES({qs})", tuple(fields.values()))


def update_run(conn, run_id: str, **fields) -> None:
    if not fields:
        return
    sets = ",".join(f"{k}=?" for k in fields)
    conn.execute(f"UPDATE runs SET {sets}, version=version+1 WHERE run_id=?", (*fields.values(), run_id))


def transition(conn, run_id: str, new_status: str, authority: int, **fields) -> bool:
    """Apply a run status change if the state machine allows it. Call inside tx().

    - non-terminal -> anything: allowed
    - terminal -> terminal: only with strictly stronger evidence (e.g. a supervisor's real exit code
      overrides a watchdog's LOST inference); never terminal -> non-terminal (no stale regression).
    """
    row = conn.execute("SELECT status, status_authority, version FROM runs WHERE run_id=?", (run_id,)).fetchone()
    if row is None:
        return False
    cur, cur_auth = row["status"], row["status_authority"] or 0
    if cur in TERMINAL:
        if new_status not in TERMINAL or authority <= cur_auth:
            add_event(conn, "STALE_TRANSITION_IGNORED", run_id, payload={"from": cur, "to": new_status,
                                                                         "authority": authority})
            return False
    fields = dict(fields)
    fields["status"] = new_status
    fields["status_authority"] = max(authority, cur_auth) if cur in TERMINAL else authority
    sets = ",".join(f"{k}=?" for k in fields)
    cur2 = conn.execute(f"UPDATE runs SET {sets}, version=version+1 WHERE run_id=? AND version=?",
                        (*fields.values(), run_id, row["version"]))
    if cur2.rowcount != 1:
        return False
    add_event(conn, "STATUS_" + new_status, run_id, source="state", payload={"from": cur, "authority": authority})
    return True


def active_runs(conn) -> list:
    qs = ",".join("?" for _ in ACTIVE)
    return conn.execute(f"SELECT * FROM runs WHERE status IN ({qs}) ORDER BY created_at", tuple(ACTIVE)).fetchall()


def add_sample(conn, run_id: str, s: dict) -> None:
    conn.execute("INSERT INTO samples(run_id,ts,cpu,rss,nproc,threads,sys_mem,gpu_util,gpu_mem,disk_free) "
                 "VALUES(?,?,?,?,?,?,?,?,?,?)",
                 (run_id, s.get("ts"), s.get("cpu"), s.get("rss"), s.get("nproc"), s.get("threads"),
                  s.get("sys_mem"), s.get("gpu_util"), s.get("gpu_mem"), s.get("disk_free")))


def samples_for(conn, run_id: str, limit: int = 2000) -> list:
    rows = conn.execute("SELECT * FROM samples WHERE run_id=? ORDER BY ts", (run_id,)).fetchall()
    if len(rows) > limit:  # thin out evenly for display
        step = len(rows) / limit
        rows = [rows[int(i * step)] for i in range(limit)]
    return rows


def file_mode_private(path: str) -> None:
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
