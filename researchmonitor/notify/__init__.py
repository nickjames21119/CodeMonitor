"""Durable notification outbox: at-least-once delivery with bounded exponential back-off.

A notification row is written in the same transaction as the state change that caused it. Any rmon
process (agent, a finishing supervisor) may drain the outbox; rows are claimed with a lease so two
processes never send the same row concurrently. A crash between "provider accepted" and "marked sent"
can still cause one duplicate e-mail — exactly-once is not achievable over SMTP (design §6.7).
"""
from __future__ import annotations

import random
import time

from .. import store, util
from .channels import NotifyError, send

SEV_RANK = {"P0": 0, "P1": 1, "P2": 2, "P3": 3}
LEASE_S = 180


def channels_for(cfg, severity: str) -> list[str]:
    chans = []
    if (cfg.get("notify.email_backend") or "none") != "none" and cfg.email_to:
        chans.append("email")
    if (cfg.get("notify.push_backend") or "none") != "none":
        if SEV_RANK.get(severity, 3) <= SEV_RANK.get(cfg.get("notify.push_min_severity") or "P1", 1):
            chans.append("push")
    return chans


def enqueue(conn, cfg, *, group_key: str, kind: str, severity: str, content: dict, run_id=None,
            incident_id=None, channels=None, delay: float = 0.0) -> list[str]:
    """Insert one row per channel (idempotent on group_key). Call inside tx()."""
    t = util.now()
    ids = []
    for ch in channels if channels is not None else channels_for(cfg, severity):
        nid = f"{group_key}:{ch}"
        conn.execute(
            "INSERT OR IGNORE INTO notifications(notification_id,group_key,kind,run_id,incident_id,severity,channel,"
            "subject,body_text,body_html,push_title,push_body,attachments,status,attempts,next_attempt_at,created_at)"
            " VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,'pending',0,?,?)",
            (nid, group_key, kind, run_id, incident_id, severity, ch, content.get("subject"), content.get("text"),
             content.get("html"), content.get("push_title"), content.get("push_body"),
             util.json_dumps(content.get("attachments") or []), t + delay, t))
        ids.append(nid)
    return ids


def update_pending(conn, group_key: str, content: dict, severity: str) -> int:
    """Refresh the content of a not-yet-claimed notification (used to coalesce incident updates)."""
    c = conn.execute(
        "UPDATE notifications SET subject=?, body_text=?, body_html=?, push_title=?, push_body=?, severity=? "
        "WHERE group_key=? AND status='pending' AND attempts=0",
        (content.get("subject"), content.get("text"), content.get("html"), content.get("push_title"),
         content.get("push_body"), severity, group_key))
    return c.rowcount


def _backoff(attempts: int) -> float:
    base = min(30 * (2 ** max(0, attempts - 1)), 1800)
    return base * (0.8 + 0.4 * random.random())


def _claim(conn, nid: str, owner: str) -> bool:
    t = util.now()
    with store.tx(conn):
        c = conn.execute(
            "UPDATE notifications SET status='sending', lease_until=? WHERE notification_id=? AND "
            "((status='pending' AND next_attempt_at<=?) OR (status='sending' AND lease_until<?))",
            (t + LEASE_S, nid, t, t))
        return c.rowcount == 1


def dispatch_due(conn, cfg, max_items: int = 20, time_budget: float = 90.0, owner: str = "") -> dict:
    stats = {"sent": 0, "failed": 0, "retry": 0}
    start = time.monotonic()
    t = util.now()
    rows = conn.execute(
        "SELECT notification_id FROM notifications WHERE (status='pending' AND next_attempt_at<=?) "
        "OR (status='sending' AND lease_until<?) ORDER BY created_at LIMIT ?", (t, t, max_items)).fetchall()
    max_attempts = int(cfg.get("notify.max_attempts") or 30)
    for (nid,) in rows:
        if time.monotonic() - start > time_budget:
            break
        if not _claim(conn, nid, owner):
            continue
        row = conn.execute("SELECT * FROM notifications WHERE notification_id=?", (nid,)).fetchone()
        t0 = time.monotonic()
        ok, err, permanent = True, None, False
        try:
            info = send(cfg, row)
        except NotifyError as e:
            ok, err, permanent = False, str(e), e.permanent
        except Exception as e:  # unexpected bug in a channel must not kill the dispatcher
            ok, err = False, f"{type(e).__name__}: {e}"
        dur = time.monotonic() - t0
        attempts = (row["attempts"] or 0) + 1
        with store.tx(conn):
            conn.execute("INSERT INTO notification_attempts(notification_id,ts,ok,error,duration) VALUES(?,?,?,?,?)",
                         (nid, util.now(), 1 if ok else 0, None if ok else err, dur))
            if ok:
                conn.execute("UPDATE notifications SET status='sent', attempts=?, sent_at=?, last_error=NULL, "
                             "lease_until=NULL WHERE notification_id=?", (attempts, util.now(), nid))
                store.add_event(conn, "NOTIFICATION_SENT", row["run_id"], row["incident_id"], "notifier",
                                {"notification_id": nid, "channel": row["channel"], "info": info[:200]})
                stats["sent"] += 1
            elif permanent or attempts >= max_attempts:
                conn.execute("UPDATE notifications SET status='failed', attempts=?, last_error=?, lease_until=NULL "
                             "WHERE notification_id=?", (attempts, err, nid))
                store.add_event(conn, "NOTIFICATION_FAILED", row["run_id"], row["incident_id"], "notifier",
                                {"notification_id": nid, "error": err, "permanent": permanent})
                store.kv_set(conn, "last_notify_error", f"{util.local_str(util.now())} {row['channel']}: {err}")
                stats["failed"] += 1
            else:
                conn.execute("UPDATE notifications SET status='pending', attempts=?, last_error=?, lease_until=NULL,"
                             " next_attempt_at=? WHERE notification_id=?",
                             (attempts, err, util.now() + _backoff(attempts), nid))
                stats["retry"] += 1
    return stats


def pending_count(conn) -> int:
    return conn.execute("SELECT COUNT(*) FROM notifications WHERE status IN ('pending','sending')").fetchone()[0]


def retry_failed(conn, ids=None) -> int:
    with store.tx(conn):
        if ids:
            q = ",".join("?" for _ in ids)
            c = conn.execute(f"UPDATE notifications SET status='pending', attempts=0, next_attempt_at=? "
                             f"WHERE status='failed' AND notification_id IN ({q})", (util.now(), *ids))
        else:
            c = conn.execute("UPDATE notifications SET status='pending', attempts=0, next_attempt_at=? "
                             "WHERE status='failed'", (util.now(),))
        return c.rowcount
