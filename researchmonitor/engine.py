"""Policy and orchestration: run finalization, severity, warnings, escalation, recovery, periodic tick."""
from __future__ import annotations

import os

import psutil

from . import heartbeat, identity, incidents, notify, render, store, util
from .classify import title as failure_title

FAILURE_STATES = {"FAILED", "TIMED_OUT", "UNKNOWN", "LOST"}
# Causes that are about the machine, not the code: correlated across all runs on the host, may escalate to P0,
# and a burst produces one digest instead of one e-mail per run.
HOST_LEVEL = {"CUDA_OOM", "SYSTEM_OOM", "GPU_ERROR", "PROCESS_TERMINATED", "HOST_REBOOTED", "AGENT_FAILURE",
              "RESOURCE_DISK", "RESOURCE_MEMORY", "RESOURCE_GPU_TEMP"}


def fingerprint(run, code: str) -> str:
    if code in HOST_LEVEL:
        return f"{run['host_id']}|{code}"
    return f"{run['host_id']}|{code}|{run['project'] or run['name'] or run['run_id']}"
SUCCESS_STATES = {"SUCCEEDED", "SUCCEEDED_UNVERIFIED"}


# --------------------------------------------------------------------------- severity policy

def severity_for(cfg, run) -> str:
    """Severity reflects impact (lost compute, user priority), not just the error message (design §7.2)."""
    status = run["status"]
    if status in SUCCESS_STATES or status == "CANCELED":
        return "P3"
    prio = (run["priority"] or "normal").lower()
    if prio == "low":
        return "P2"
    dur = 0.0
    if run["started_at"]:
        dur = (run["ended_at"] or util.now()) - run["started_at"]
    p1_min = util.parse_duration(cfg.get("monitor.p1_min_runtime", "2h")) or 7200
    if prio == "high" or dur >= p1_min:
        return "P1"
    return "P2"


# --------------------------------------------------------------------------- finalization

def finalize_run(conn, cfg, run_id: str, o: dict, notify_now: bool = True) -> bool:
    """Atomically: terminal status + evidence + incident + notification rows (outbox pattern)."""
    with store.tx(conn):
        run = store.get_run(conn, run_id)
        if run is None:
            return False
        spec = util.json_loads(run["spec"], {}) or {}
        if o.get("attachments") is not None:
            spec["_attachments"] = o["attachments"]
        fields = {
            "ended_at": o.get("ended_at") or util.now(),
            "exit_code": o.get("exit_code"), "exit_desc": o.get("exit_desc"),
            "failure_code": o.get("failure_code"), "failure_summary": o.get("failure_summary"),
            "evidence": util.json_dumps(o.get("evidence") or {}),
            "validation": util.json_dumps(o["validation"]) if o.get("validation") is not None else run["validation"],
            "metrics": util.json_dumps(o.get("metrics") or {}) if o.get("metrics") is not None else run["metrics"],
            "spec": util.json_dumps(spec),
        }
        if o.get("health"):
            fields["health"] = o["health"]
        prev_status, prev_incident = run["status"], run["incident_id"]
        if not store.transition(conn, run_id, o["status"], o["authority"], **fields):
            return False
        if prev_status in store.TERMINAL and prev_incident:
            # e.g. recovery inferred LOST, then the real supervisor reported the true outcome
            conn.execute("UPDATE runs SET incident_id=NULL WHERE run_id=?", (run_id,))
            inc = incidents.get(conn, prev_incident)
            if inc is not None and inc["status"] != "RESOLVED":
                incidents.transition(conn, prev_incident, "RESOLVED", "system",
                                     f"superseded: run {run_id} later reported {o['status']}")
        run = store.get_run(conn, run_id)
        store.add_event(conn, "RUN_FINALIZED", run_id, source=o.get("source", "supervisor"),
                        payload={"status": run["status"], "failure_code": run["failure_code"],
                                 "exit_code": run["exit_code"]})
        if notify_now:
            _notify_terminal(conn, cfg, run)
    return True


def _notify_pref(cfg, run) -> str:
    spec = util.json_loads(run["spec"], {}) or {}
    pref = spec.get("notify")
    if pref in ("all", "failure", "none"):
        return pref
    return "all" if cfg.get("notify.notify_success", True) else "failure"


def _notify_terminal(conn, cfg, run) -> None:
    status = run["status"]
    pref = _notify_pref(cfg, run)
    sev = severity_for(cfg, run)
    if status in FAILURE_STATES:
        code = run["failure_code"] or ("ENDED_UNKNOWN" if status == "UNKNOWN" else status)
        lang = cfg.get("general.language") or "zh"
        inc, created = incidents.open_or_join(
            conn, cfg, fingerprint=fingerprint(run, code), category=code, severity=sev,
            title=f"{run['name'] or run['run_id']}: {failure_title(code, lang) or code}", run_id=run["run_id"],
            kind="failure", escalate=pref != "none", host_level=code in HOST_LEVEL)
        if pref == "none":
            return
        if created or code not in HOST_LEVEL:
            # code-level failures always get their own full report (traceback, output, attachments)
            notify.enqueue(conn, cfg, group_key=f"run:{run['run_id']}:final:{status}", kind="final", severity=sev,
                           content=render.run_report(conn, cfg, store.get_run(conn, run["run_id"]), sev, inc),
                           run_id=run["run_id"], incident_id=inc["incident_id"])
        else:
            _coalesced_update(conn, cfg, inc)
        return
    if status == "CANCELED" and not cfg.get("notify.notify_cancel", False):
        return
    if pref != "all":
        return
    notify.enqueue(conn, cfg, group_key=f"run:{run['run_id']}:final:{status}", kind="final", severity=sev,
                   content=render.run_report(conn, cfg, run, sev, None), run_id=run["run_id"])


def _coalesced_update(conn, cfg, inc) -> None:
    """Correlated failures produce one digest e-mail per burst instead of one e-mail per run."""
    content = render.incident_update(conn, cfg, inc)
    rows = conn.execute("SELECT DISTINCT group_key FROM notifications WHERE incident_id=? AND kind='update' "
                        "AND status='pending' AND attempts=0", (inc["incident_id"],)).fetchall()
    for (gk,) in rows:
        if notify.update_pending(conn, gk, content, inc["severity"]):
            return
    n = conn.execute("SELECT COUNT(DISTINCT group_key) FROM notifications WHERE incident_id=? AND kind='update'",
                     (inc["incident_id"],)).fetchone()[0]
    notify.enqueue(conn, cfg, group_key=f"inc:{inc['incident_id']}:update:{n + 1}", kind="update",
                   severity=inc["severity"], content=content, incident_id=inc["incident_id"], delay=120)


# --------------------------------------------------------------------------- automatically detected jobs

def finalize_auto(conn, cfg, run_id: str, o: dict) -> bool:
    """Terminal state + ONE comprehensive report for a job found by discovery (outbox pattern)."""
    with store.tx(conn):
        run = store.get_run(conn, run_id)
        if run is None:
            return False
        fields = {"ended_at": o.get("ended_at") or util.now(), "exit_code": o.get("exit_code"),
                  "exit_desc": o.get("exit_desc"), "failure_code": o.get("failure_code"),
                  "failure_summary": o.get("failure_summary"), "evidence": util.json_dumps(o.get("evidence") or {}),
                  "metrics": util.json_dumps(o.get("metrics") or {}), "profile": util.json_dumps(o.get("profile") or {}),
                  "health": "OK"}
        if not store.transition(conn, run_id, o["status"], o["authority"], **fields):
            return False
        run = store.get_run(conn, run_id)
        store.add_event(conn, "RUN_FINALIZED", run_id, source="tracker",
                        payload={"status": run["status"], "failure_code": run["failure_code"],
                                 "exit_code": run["exit_code"], "confidence": (o.get("evidence") or {}).get("confidence")})
        status = run["status"]
        if o.get("episode") or status in SUCCESS_STATES or status == "CANCELED":
            sev = "P3"
        elif status == "UNKNOWN":
            sev = "P2"
        else:
            sev = severity_for(cfg, run)
        inc = None
        code = run["failure_code"]
        if not o.get("episode") and (status in ("FAILED", "LOST") or (status == "UNKNOWN" and code and
                                                                       code != "ENDED_UNKNOWN")):
            code = code or status
            lang = cfg.get("general.language") or "zh"
            inc, _ = incidents.open_or_join(
                conn, cfg, fingerprint=fingerprint(run, code), category=code, severity=sev,
                title=f"{run['name'] or run_id}: {failure_title(code, lang) or code}", run_id=run_id,
                kind="failure", host_level=code in HOST_LEVEL)
        if sev == "P3" and not cfg.get("notify.notify_success", True) and status != "CANCELED":
            return True
        notify.enqueue(conn, cfg, group_key=f"run:{run_id}:final:{status}", kind="final", severity=sev,
                       content=render.job_report(conn, cfg, run, sev, inc, o.get("profile") or {}),
                       run_id=run_id, incident_id=inc["incident_id"] if inc is not None else None)
    return True


# --------------------------------------------------------------------------- warnings during a run

def raise_warning(conn, cfg, run_id: str, code: str, detail: str, per_run: bool = False,
                  severity: str = "P2") -> str | None:
    with store.tx(conn):
        run = store.get_run(conn, run_id)
        if run is None:
            return None
        fp = f"{run['host_id']}|{code}" + (f"|{run_id}" if per_run else "")
        lang = cfg.get("general.language") or "zh"
        inc, created = incidents.open_or_join(
            conn, cfg, fingerprint=fp, category=code, severity=severity,
            title=f"{run['name'] or run_id}: {failure_title(code, lang) or code}", run_id=run_id, kind="warning",
            escalate=_notify_pref(cfg, run) != "none")
        store.add_event(conn, "WARNING_" + code, run_id, inc["incident_id"], "supervisor", {"detail": detail})
        alert_kind = {"SUSPECTED_STALL": "stall", "NAN_LOSS": "nan"}.get(code, "resource")
        allowed = alert_kind in (cfg.get("notify.mid_run_alerts") or [])  # otherwise: only in the final report
        if created and allowed and _notify_pref(cfg, run) != "none":
            notify.enqueue(conn, cfg, group_key=f"run:{run_id}:warn:{code}:{int(util.now())}", kind="warning",
                           severity=severity, content=render.warning(conn, cfg, run, code, detail, severity, inc),
                           run_id=run_id, incident_id=inc["incident_id"])
        if code == "SUSPECTED_STALL":
            conn.execute("UPDATE runs SET health='SUSPECTED_STALL' WHERE run_id=?", (run_id,))
        return inc["incident_id"]


def clear_warning(conn, cfg, run_id: str, code: str, incident_id: str | None, note: str) -> None:
    with store.tx(conn):
        store.add_event(conn, "WARNING_CLEARED_" + code, run_id, incident_id, "supervisor", {"note": note})
        if code == "SUSPECTED_STALL":
            conn.execute("UPDATE runs SET health='OK' WHERE run_id=?", (run_id,))
        notified = conn.execute("SELECT COUNT(*) FROM notifications WHERE run_id=? AND kind='warning' "
                                "AND group_key LIKE ?", (run_id, f"run:{run_id}:warn:{code}:%")).fetchone()[0]
        run = store.get_run(conn, run_id)
        if notified and run is not None:
            notify.enqueue(conn, cfg, group_key=f"run:{run_id}:cleared:{code}:{int(util.now())}", kind="cleared",
                           severity="P3", content=render.warning_cleared(conn, cfg, run, code, note),
                           run_id=run_id, incident_id=incident_id, channels=notify.channels_for(cfg, "P3")
                           if cfg.get("notify.notify_success", True) else [])
    if incident_id:
        inc = incidents.get(conn, incident_id)
        if inc is not None and inc["status"] != "RESOLVED":
            incidents.transition(conn, incident_id, "RESOLVED", "system", note)


# --------------------------------------------------------------------------- escalation

def process_escalations(conn, cfg) -> int:
    n = 0
    for inc in incidents.due_reminders(conn):
        offs = incidents.reminder_offsets(cfg, inc["severity"])
        with store.tx(conn):
            row = incidents.get(conn, inc["incident_id"])
            if row is None or row["status"] != "OPEN" or row["escalation_stopped"] or not row["next_step_at"] \
                    or row["next_step_at"] > util.now():
                continue
            step = incidents.advance_step(conn, row, cfg)
            if step is None:
                continue
            notify.enqueue(conn, cfg, group_key=f"inc:{row['incident_id']}:reminder:{step}", kind="reminder",
                           severity=row["severity"],
                           content=render.reminder(conn, cfg, row, step, len(offs)),
                           incident_id=row["incident_id"])
            n += 1
    return n


# --------------------------------------------------------------------------- agent liveness

def agent_alive(conn) -> bool:
    info = util.json_loads(store.kv_get(conn, "agent"), None)
    if not info:
        return False
    if util.now() - float(info.get("seen_at", 0)) > 90:
        return False
    return identity.is_alive(info.get("pid"), info.get("token"))


def has_pending_work(conn) -> bool:
    return notify.pending_count(conn) > 0 or incidents.open_with_pending_steps(conn) > 0


def tick(conn, cfg, *, do_heartbeat: bool = True) -> dict:
    out = {}
    out["escalations"] = process_escalations(conn, cfg)
    out["dispatch"] = notify.dispatch_due(conn, cfg, owner=str(os.getpid()))
    if do_heartbeat:
        out["heartbeat"] = heartbeat.tick(conn, cfg)
    return out


# --------------------------------------------------------------------------- recovery manager

def recover(conn, cfg, *, spawn_adopters: bool = True) -> dict:
    """Reconcile runs whose supervisor is gone (crash, kill, reboot). Never infers failure from silence alone:
    a live job keeps running and is re-observed; only when both supervisor and job are gone is it LOST."""
    from . import supervisor  # local import: supervisor imports engine
    t = util.now()
    cur_boot = identity.boot_id()
    try:
        boot_time = psutil.boot_time()
    except Exception:
        boot_time = None
    stats = {"adopted": 0, "lost": 0, "rebooted": 0}
    rebooted_runs = []
    for run in store.active_runs(conn):
        if run["mode"] in ("auto", "interactive"):
            continue  # owned by the agent's tracker (it re-attaches or finalizes them on start)
        if not identity.same_boot(run["boot_id"], cur_boot):
            rebooted_runs.append((run, "boot id changed"))
            continue
        if identity.is_alive(run["supervisor_pid"], run["supervisor_token"]):
            continue
        if run["status"] == "CREATED" and t - (run["created_at"] or t) < 120:
            continue  # supervisor still starting
        if run["health"] == "ADOPTING" and t - (run["supervisor_seen_at"] or 0) < 120:
            continue  # an adopter was just spawned and has not registered yet
        child_alive = bool(run["pid"]) and identity.is_alive(run["pid"], run["pid_token"])
        if child_alive and spawn_adopters:
            tries = conn.execute("SELECT COUNT(*) FROM events WHERE run_id=? AND type='SUPERVISOR_LOST'",
                                 (run["run_id"],)).fetchone()[0]
            if tries >= 3:  # adopters keep dying: stop respawning; LOST is decided once the job ends
                continue
            with store.tx(conn):
                c = conn.execute("UPDATE runs SET health='ADOPTING', supervisor_pid=NULL, supervisor_seen_at=?, "
                                 "version=version+1 WHERE run_id=? AND version=?", (t, run["run_id"], run["version"]))
                if c.rowcount != 1:
                    continue
                store.add_event(conn, "SUPERVISOR_LOST", run["run_id"], source="recovery",
                                payload={"old_supervisor_pid": run["supervisor_pid"], "action": "adopt"})
            supervisor.spawn_adopter(run["run_id"])
            stats["adopted"] += 1
            continue
        if child_alive:
            continue
        last_seen = run["supervisor_seen_at"] or run["started_at"] or run["created_at"] or t
        # Both monitor and job are gone. A boot after the last sign of life, or a long silence (the monitor
        # writes every few seconds), means the computer was restarted / shut down / asleep — including
        # Windows "Fast Startup" shutdowns, which do not change the boot id.
        seen = run["supervisor_seen_at"] is not None  # a monitor that never registered = failed to start
        if seen and boot_time and boot_time > last_seen + 5:
            rebooted_runs.append((run, "system booted after the monitor was last seen"))
            continue
        if seen and t - last_seen > 300:
            rebooted_runs.append((run, f"no sign of life for {util.fmt_duration(t - last_seen)} (computer off, "
                                       "asleep or restarted)"))
            continue
        ok = finalize_run(conn, cfg, run["run_id"], {
            "status": "LOST", "authority": store.AUTH_INFERRED, "source": "recovery",
            "failure_code": "AGENT_FAILURE",
            "failure_summary": "The monitoring process exited unexpectedly and the job is no longer running; "
                               "its real exit status is unknown.",
            "exit_desc": "unknown (monitor lost)",
            "ended_at": last_seen or t,
            "evidence": {"supervisor_last_seen": util.iso_utc(last_seen), "detected_at": util.iso_utc(t),
                         "notes": [f"Supervisor last seen {util.local_str(last_seen)}; see supervisor.log in the run "
                                   "directory."]},
        })
        stats["lost"] += 1 if ok else 0
    if rebooted_runs:
        stats["rebooted"] = _handle_reboot(conn, cfg, rebooted_runs, cur_boot, boot_time)
    return stats


def _handle_reboot(conn, cfg, runs, cur_boot: str, boot_time) -> int:
    done = []
    with store.tx(conn):
        sev = "P2"
        for run, reason in runs:
            last_seen = run["supervisor_seen_at"] or run["started_at"] or run["created_at"]
            fields = {
                "ended_at": last_seen, "exit_desc": "unknown (host restarted)", "failure_code": "HOST_REBOOTED",
                "failure_summary": (f"Job and monitor vanished: monitor last seen {util.local_str(last_seen)}; "
                                    f"system boot time {util.local_str(boot_time)}; evidence: {reason}."),
                "evidence": util.json_dumps({"old_boot_id": run["boot_id"], "new_boot_id": cur_boot, "reason": reason,
                                             "last_seen": util.iso_utc(last_seen), "boot_time": util.iso_utc(boot_time)}),
            }
            if store.transition(conn, run["run_id"], "LOST", store.AUTH_INFERRED, **fields):
                done.append(run["run_id"])
                sev = incidents.sev_max(sev, severity_for(cfg, store.get_run(conn, run["run_id"])))
        if not done:
            return 0
        inc = None
        for rid in done:
            inc, _ = incidents.open_or_join(conn, cfg, fingerprint=f"{runs[0][0]['host_id']}|HOST_REBOOTED|{cur_boot}",
                                            category="HOST_REBOOTED", severity=sev,
                                            title=f"{cfg.host_name}: host restarted during {len(done)} run(s)",
                                            run_id=rid, kind="failure", host_level=True)
        inc = incidents.get(conn, inc["incident_id"])
        notify.enqueue(conn, cfg, group_key=f"inc:{inc['incident_id']}:hostlost", kind="final",
                       severity=inc["severity"], content=render.host_lost(conn, cfg, inc, done, "HOST_REBOOTED"),
                       incident_id=inc["incident_id"])
    return len(done)
