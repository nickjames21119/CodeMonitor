"""Incident lifecycle (OPEN -> ACKNOWLEDGED -> INVESTIGATING -> MITIGATED -> RESOLVED), correlation and escalation.

Incident state is deliberately separate from run state: a FAILED run can have an ACKNOWLEDGED incident.
"""
from __future__ import annotations

from . import store, util

STATES = ["OPEN", "ACKNOWLEDGED", "INVESTIGATING", "MITIGATED", "RESOLVED"]
OPEN_STATES = ("OPEN", "ACKNOWLEDGED", "INVESTIGATING", "MITIGATED")
SEV_ORDER = {"P0": 0, "P1": 1, "P2": 2, "P3": 3}


def sev_max(a: str, b: str) -> str:
    return a if SEV_ORDER.get(a, 9) <= SEV_ORDER.get(b, 9) else b


def reminder_offsets(cfg, severity: str) -> list[float]:
    """Minutes-after-open at which un-acknowledged incidents are re-notified."""
    raw = cfg.get(f"incidents.{severity.lower()}_reminders", "") or ""
    out = []
    for part in str(raw).split(","):
        part = part.strip()
        if part:
            out.append(util.parse_duration(part))
    return sorted(x for x in out if x and x > 0)


def _event(conn, incident_id: str, actor: str, action: str, detail=None) -> None:
    conn.execute("INSERT INTO incident_events(incident_id,ts,actor,action,detail) VALUES(?,?,?,?,?)",
                 (incident_id, util.now(), actor, action, util.json_dumps(detail) if detail is not None else None))


def _next_id(conn) -> str:
    n = int(store.kv_get(conn, "incident_seq", "0")) + 1
    store.kv_set(conn, "incident_seq", n)
    return f"INC-{n:06d}"


def get(conn, incident_id: str):
    return conn.execute("SELECT * FROM incidents WHERE incident_id=?", (incident_id,)).fetchone()


def resolve_ref(conn, ref: str | None) -> str | None:
    if not ref:
        row = conn.execute("SELECT incident_id FROM incidents WHERE status!='RESOLVED' "
                           "ORDER BY created_at DESC LIMIT 1").fetchone()
        return row[0] if row else None
    ref = ref.upper()
    if ref.isdigit():
        ref = f"INC-{int(ref):06d}"
    row = conn.execute("SELECT incident_id FROM incidents WHERE incident_id=?", (ref,)).fetchone()
    return row[0] if row else None


def open_or_join(conn, cfg, *, fingerprint: str, category: str, severity: str, title: str,
                 run_id: str | None, kind: str, escalate: bool = True, host_level: bool = False) -> tuple:
    """Correlate into a recent open incident with the same fingerprint, or open a new one. Call inside tx().

    Returns (incident_row, created: bool). Joining never discards evidence: the run is linked and the
    timeline records it.
    """
    t = util.now()
    window = util.parse_duration(cfg.get("incidents.correlation_window", "10m")) or 600
    row = conn.execute(
        f"SELECT * FROM incidents WHERE fingerprint=? AND status IN ({','.join('?' * len(OPEN_STATES))}) "
        "AND updated_at >= ? ORDER BY created_at DESC LIMIT 1",
        (fingerprint, *OPEN_STATES, t - window)).fetchone()
    if row is not None:
        runs = util.json_loads(row["runs"], []) or []
        if run_id and run_id not in runs:
            runs.append(run_id)
        new_sev = sev_max(row["severity"], severity)
        if kind == "failure" and host_level and len(runs) >= 3:
            new_sev = "P0"  # widespread failure on this host (not merely the same bug re-run)
        next_at = row["next_step_at"]
        if new_sev != row["severity"] and row["status"] == "OPEN" and not row["escalation_stopped"]:
            offs = reminder_offsets(cfg, new_sev)  # follow the stricter policy from the current step on
            k = (row["next_step"] or 1) - 1
            next_at = (row["created_at"] + offs[k]) if k < len(offs) else None
        conn.execute("UPDATE incidents SET runs=?, severity=?, updated_at=?, next_step_at=?, version=version+1 "
                     "WHERE incident_id=?", (util.json_dumps(runs), new_sev, t, next_at, row["incident_id"]))
        _event(conn, row["incident_id"], "system", "RUN_CORRELATED", {"run_id": run_id, "severity": new_sev})
        if run_id:
            conn.execute("UPDATE runs SET incident_id=? WHERE run_id=?", (row["incident_id"], run_id))
        return get(conn, row["incident_id"]), False

    iid = _next_id(conn)
    offs = reminder_offsets(cfg, severity) if escalate else []
    conn.execute(
        "INSERT INTO incidents(incident_id,fingerprint,category,title,severity,status,kind,created_at,updated_at,"
        "next_step,next_step_at,escalation_stopped,runs) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (iid, fingerprint, category, title, severity, "OPEN", kind, t, t, 1,
         (t + offs[0]) if offs else None, 0 if escalate else 1, util.json_dumps([run_id] if run_id else [])))
    _event(conn, iid, "system", "OPENED", {"severity": severity, "category": category, "run_id": run_id})
    if run_id:
        conn.execute("UPDATE runs SET incident_id=? WHERE run_id=?", (iid, run_id))
    return get(conn, iid), True


def transition(conn, incident_id: str, new_state: str, actor: str, note: str | None = None) -> tuple:
    """Move an incident forward. Returns (ok, message). Uses a version check against concurrent updates."""
    new_state = new_state.upper()
    if new_state not in STATES:
        return False, f"unknown state {new_state}"
    with store.tx(conn):
        row = get(conn, incident_id)
        if row is None:
            return False, f"{incident_id} not found"
        cur = row["status"]
        if cur == "RESOLVED":
            return False, f"{incident_id} is already resolved"
        if STATES.index(new_state) <= STATES.index(cur):
            return False, f"{incident_id} is already {cur}"
        t = util.now()
        fields = {"status": new_state, "updated_at": t}
        executed = row["next_step"] - 1 if row["next_step"] else 0
        if cur == "OPEN":  # first human response stops escalation
            fields.update(acked_at=t, acked_by=actor, escalation_stopped=1, next_step_at=None)
        if new_state == "RESOLVED":
            fields.update(resolved_at=t, escalation_stopped=1, next_step_at=None)
        sets = ",".join(f"{k}=?" for k in fields)
        c = conn.execute(f"UPDATE incidents SET {sets}, version=version+1 WHERE incident_id=? AND version=?",
                         (*fields.values(), incident_id, row["version"]))
        if c.rowcount != 1:
            return False, "concurrent update, try again"
        detail = {"from": cur, "note": note}
        if cur == "OPEN":
            detail.update(reminders_already_sent=max(0, executed), escalation_stopped=True)
        _event(conn, incident_id, actor, new_state, detail)
        # pending (not yet sent) reminders for this incident are no longer needed
        if new_state in ("ACKNOWLEDGED", "RESOLVED") or cur == "OPEN":
            conn.execute("UPDATE notifications SET status='cancelled', last_error='incident acknowledged' "
                         "WHERE incident_id=? AND kind='reminder' AND status='pending'", (incident_id,))
    return True, f"{incident_id}: {cur} -> {new_state}"


def snooze(conn, incident_id: str, seconds: float, actor: str) -> tuple:
    with store.tx(conn):
        row = get(conn, incident_id)
        if row is None:
            return False, f"{incident_id} not found"
        until = util.now() + seconds
        conn.execute("UPDATE incidents SET snoozed_until=?, version=version+1 WHERE incident_id=?",
                     (until, incident_id))
        _event(conn, incident_id, actor, "SNOOZED", {"until": util.iso_utc(until)})
    return True, f"{incident_id} reminders snoozed until {util.local_str(until)}"


def due_reminders(conn) -> list:
    t = util.now()
    return conn.execute(
        "SELECT * FROM incidents WHERE status='OPEN' AND escalation_stopped=0 AND next_step_at IS NOT NULL "
        "AND next_step_at <= ? AND (snoozed_until IS NULL OR snoozed_until <= ?)", (t, t)).fetchall()


def advance_step(conn, row, cfg) -> int | None:
    """Claim the next escalation step (inside tx). Returns the step number claimed, or None."""
    offs = reminder_offsets(cfg, row["severity"])
    step = row["next_step"]
    nxt = (row["created_at"] + offs[step]) if step < len(offs) else None
    c = conn.execute("UPDATE incidents SET next_step=?, next_step_at=?, version=version+1 "
                     "WHERE incident_id=? AND version=?", (step + 1, nxt, row["incident_id"], row["version"]))
    if c.rowcount != 1:
        return None
    _event(conn, row["incident_id"], "system", "ESCALATION_STEP", {"step": step, "of": len(offs)})
    return step


def timeline(conn, incident_id: str) -> list:
    return conn.execute("SELECT * FROM incident_events WHERE incident_id=? ORDER BY id", (incident_id,)).fetchall()


def open_with_pending_steps(conn) -> int:
    return conn.execute("SELECT COUNT(*) FROM incidents WHERE status='OPEN' AND escalation_stopped=0 "
                        "AND next_step_at IS NOT NULL").fetchone()[0]
