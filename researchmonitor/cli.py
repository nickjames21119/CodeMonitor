"""`rmon` command line."""
from __future__ import annotations

import argparse
import codecs
import getpass
import json
import os
import shlex
import sys
import time

from . import __version__, engine, identity, incidents, notify, render, store, supervisor, util, validators
from .config import (SECRET_NAMES, Config, config_path, get_secret, home_dir, load_config, load_toml_file,
                     runs_dir, save_config, set_secret)

DEFAULT_RECIPIENT = ""


def _out(msg: str = "") -> None:
    print(msg, flush=True)


def _err(msg: str) -> None:
    print(msg, file=sys.stderr, flush=True)


def _open():
    cfg = load_config()
    conn = store.connect()
    return cfg, conn


def _quick_recover(cfg, conn) -> None:
    try:
        stats = engine.recover(conn, cfg)
        if stats.get("rebooted") or stats.get("lost"):
            _err(f"[rmon] recovered {stats['rebooted']} run(s) interrupted by a restart and "
                 f"{stats['lost']} run(s) whose monitor died; notifications queued.")
            if not engine.agent_alive(conn):
                engine.tick(conn, cfg, do_heartbeat=False)
    except Exception as e:  # recovery must never block normal commands
        _err(f"[rmon] recovery check failed: {e}")


# --------------------------------------------------------------------------- run

def _load_project_file(path: str | None, cwd: str) -> dict:
    cand = path or next((os.path.join(cwd, n) for n in ("rmon.toml", ".rmon.toml")
                         if os.path.exists(os.path.join(cwd, n))), None)
    if not cand:
        return {}
    data = load_toml_file(cand)
    data["_file"] = cand
    return data


def _merge_run_options(args, proj: dict) -> dict:
    def lst(name):
        v = proj.get(name) or []
        v = [v] if isinstance(v, str) else list(v)
        return v + list(getattr(args, name, None) or [])

    def scalar(name, default=None):
        v = getattr(args, name, None)
        return v if v is not None else proj.get(name, default)

    return {
        "name": scalar("name"), "project": scalar("project"), "priority": scalar("priority", "normal"),
        "tags": lst("tag") + list(proj.get("tags") or []), "expect": lst("expect"),
        "expect_json": lst("expect_json"), "expect_glob": lst("expect_glob"), "attach": lst("attach"),
        "progress": scalar("progress"), "stall_after": scalar("stall_after"), "timeout": scalar("timeout"),
        "notify": scalar("notify"), "allow_sleep": bool(scalar("allow_sleep", False)),
        "no_unbuffered": bool(scalar("no_unbuffered", False)),
    }


def _new_run_record(conn, cfg, *, opts: dict, mode: str, command, cwd: str, name: str,
                    pid=None, pid_token=None, started_at=None, log_path=None) -> dict:
    run_id = util.new_run_id(name)
    run_dir = os.path.join(runs_dir(), run_id)
    os.makedirs(run_dir, exist_ok=True)
    if opts.get("progress"):
        p = os.path.expanduser(opts["progress"])
        progress_path = p if os.path.isabs(p) else os.path.join(cwd, p)
    else:
        progress_path = os.path.join(run_dir, "progress.jsonl")
    stall = opts.get("stall_after")
    timeout = opts.get("timeout")
    spec = {
        "expectations": validators.build_expectations(opts["expect"], opts["expect_json"], opts["expect_glob"]),
        "attach": opts["attach"], "notify": opts.get("notify"),
        "stall_after_s": util.parse_duration(stall) if stall is not None else None,
        "timeout_s": util.parse_duration(timeout, "h") if timeout else None,
        "allow_sleep": opts.get("allow_sleep"), "no_unbuffered": opts.get("no_unbuffered"),
        "project_file": opts.get("_file"),
    }
    hid, bid = identity.host_id(conn), identity.boot_id()
    with store.tx(conn):
        store.insert_run(conn, run_id=run_id, name=name, project=opts.get("project") or name, mode=mode,
                         priority=(opts.get("priority") or "normal").lower(), tags=util.json_dumps(opts["tags"]),
                         command=util.json_dumps(command) if isinstance(command, list) else command, cwd=cwd,
                         host_id=hid, boot_id=bid, status="CREATED",
                         created_at=util.now(), started_at=started_at, run_dir=run_dir,
                         log_path=log_path or os.path.join(run_dir, "output.log"), progress_path=progress_path,
                         spec=util.json_dumps(spec), pid=pid, pid_token=pid_token)
        store.add_event(conn, "RUN_CREATED", run_id, source="cli", payload={"mode": mode})
    return {"run_id": run_id, "run_dir": run_dir}


def cmd_run(args) -> int:
    cfg, conn = _open()
    command = list(args.command or [])
    if command and command[0] == "--":
        command = command[1:]
    if not command:
        _err("usage: rmon run [options] -- <command> [args...]")
        return 2
    cwd = os.getcwd()
    try:
        proj = _load_project_file(args.project_file, cwd)
    except Exception as e:
        _err(f"rmon: cannot read project settings file: {e}")
        return 2
    opts = _merge_run_options(args, proj)
    opts["_file"] = proj.get("_file")
    if args.shell:
        if len(command) == 1:
            cmd_for_record = command[0]
        elif util.IS_WINDOWS:
            import subprocess
            cmd_for_record = subprocess.list2cmdline(command)
        else:
            cmd_for_record = " ".join(shlex.quote(c) for c in command)
        default_name = os.path.basename(shlex.split(cmd_for_record, posix=not util.IS_WINDOWS)[0]) \
            if cmd_for_record.strip() else "job"
    else:
        cmd_for_record = command
        default_name = _guess_name(command)
    name = opts["name"] or default_name
    try:
        if opts.get("stall_after") is not None:
            util.parse_duration(opts["stall_after"])
        if opts.get("timeout"):
            util.parse_duration(opts["timeout"], "h")
    except ValueError as e:
        _err(f"rmon: {e}")
        return 2
    _quick_recover(cfg, conn)
    if not cfg.configured:
        _err("[rmon] note: no config yet — run `rmon init` to set up e-mail. Monitoring still works locally.")
    rec = _new_run_record(conn, cfg, opts=opts, mode="managed", command=cmd_for_record, cwd=cwd, name=name)
    spec = {"run_id": rec["run_id"], "mode": "managed", "env": supervisor.job_env(dict(os.environ))}
    if args.shell:
        spec["shell"] = cmd_for_record
    else:
        spec["argv"] = command
    spec_path = supervisor.write_spec(rec["run_dir"], spec)
    sup_pid = supervisor.spawn_supervisor(spec_path, rec["run_dir"])
    _out(f"[rmon] run {rec['run_id']} started (monitor pid {sup_pid}).")
    if proj.get("_file"):
        _out(f"[rmon] using project settings from {proj['_file']}")
    if args.detach:
        _out(f"[rmon] detached. Follow with: rmon logs {rec['run_id']} -f   ·   stop with: rmon stop {rec['run_id']}")
        return 0
    _out("[rmon] streaming output; Ctrl+C detaches (the job keeps running).")
    return _follow(conn, rec["run_id"], sup_pid=sup_pid, print_summary=True)


def _guess_name(argv: list[str]) -> str:
    base = os.path.basename(argv[0])
    if base.lower().startswith("python") and len(argv) > 1:
        it = iter(argv[1:])
        for a in it:
            if a == "-m":
                return next(it, "python")
            if a == "-c":
                return "python-c"
            if not a.startswith("-"):
                return os.path.splitext(os.path.basename(a))[0]
    return os.path.splitext(base)[0] or "job"


def _follow(conn, run_id: str, sup_pid=None, print_summary=False, from_start=True, initial_lines=None) -> int:
    run = store.get_run(conn, run_id)
    path = run["log_path"]
    pos = 0
    if not from_start and path and os.path.exists(path):
        size = os.path.getsize(path)
        if initial_lines:
            text = util.decode_output(util.read_tail_bytes(path, 64 * 1024))
            sys.stdout.write("\n".join(util.tail_lines(text, initial_lines)) + "\n")
        pos = size
    dec = codecs.getincrementaldecoder("utf-8")(errors="replace")
    t0 = time.monotonic()
    try:
        while True:
            if path and os.path.exists(path):
                with open(path, "rb") as f:
                    f.seek(pos)
                    data = f.read()
                if data:
                    pos += len(data)
                    sys.stdout.write(dec.decode(data))
                    sys.stdout.flush()
            run = store.get_run(conn, run_id)
            if run["status"] in store.TERMINAL:
                break
            if run["status"] == "CREATED" and time.monotonic() - t0 > 20 and sup_pid and \
                    not identity.is_alive(sup_pid, None):
                _err(f"\n[rmon] the monitor process exited before starting the job; see "
                     f"{os.path.join(run['run_dir'], 'supervisor.log')}")
                return 1
            time.sleep(0.5)
    except KeyboardInterrupt:
        _out(f"\n[rmon] detached; the job keeps running. Re-attach: rmon logs {run_id} -f · stop: rmon stop {run_id}")
        return 0
    if print_summary:
        _print_summary(run)
    rc = run["exit_code"]
    if run["status"] in ("SUCCEEDED", "SUCCEEDED_UNVERIFIED"):
        return 0
    return rc if isinstance(rc, int) and 0 < rc < 256 else 1


def _print_summary(run) -> None:
    dur = (run["ended_at"] - run["started_at"]) if run["ended_at"] and run["started_at"] else None
    line = f"\n[rmon] {run['status']} after {util.fmt_duration(dur)} · exit {run['exit_desc'] or '-'}"
    if run["failure_code"]:
        line += f" · {run['failure_code']}: {(run['failure_summary'] or '')[:200]}"
    _out(line)
    if run["incident_id"]:
        _out(f"[rmon] incident {run['incident_id']} opened — acknowledge with: rmon ack {run['incident_id']}")


def cmd_attach(args) -> int:
    import psutil
    cfg, conn = _open()
    pid = args.pid
    token = identity.proc_token(pid)
    if token is None:
        _err(f"rmon: no process with PID {pid}")
        return 2
    info = identity.describe_process(pid)
    cwd = info.get("cwd") or os.getcwd()
    proj = {}
    opts = _merge_run_options(args, proj)
    name = opts["name"] or (_guess_name(info.get("cmdline") or [info.get("name") or f"pid{pid}"]))
    log_path = os.path.abspath(args.log) if args.log else None
    try:
        started = psutil.Process(pid).create_time()
    except psutil.Error:
        started = util.now()
    rec = _new_run_record(conn, cfg, opts=opts, mode="attached", command=info.get("cmdline") or [str(pid)],
                          cwd=cwd, name=name, pid=pid, pid_token=token, started_at=started, log_path=log_path)
    spec_path = supervisor.write_spec(rec["run_dir"], {"run_id": rec["run_id"], "mode": "attach"})
    sup_pid = supervisor.spawn_supervisor(spec_path, rec["run_dir"])
    _out(f"[rmon] attached to PID {pid} ({' '.join(info.get('cmdline') or [])[:120]}) as run {rec['run_id']} "
         f"(monitor pid {sup_pid}).")
    _out("[rmon] note: the exit code of a process rmon did not start cannot be observed; its end will be reported "
         "as UNKNOWN unless logs/validators give stronger evidence. Prefer `rmon run` for new jobs.")
    return 0


# --------------------------------------------------------------------------- inspection

def _short(run_id: str) -> str:
    return run_id


def cmd_ls(args) -> int:
    cfg, conn = _open()
    _quick_recover(cfg, conn)
    q = "SELECT * FROM runs"
    if not args.all:
        q += " WHERE status IN ('CREATED','STARTING','RUNNING','FINALIZING') OR created_at > ?"
        rows = conn.execute(q + " ORDER BY created_at DESC LIMIT ?", (util.now() - 7 * 86400, args.n)).fetchall()
    else:
        rows = conn.execute(q + " ORDER BY created_at DESC LIMIT ?", (args.n,)).fetchall()
    if not rows:
        _out("no runs yet. Start one with: rmon run -- python train.py")
        return 0
    _out(f"{'RUN ID':40} {'STATUS':21} {'STARTED':19} {'DURATION':>9}  DETAIL")
    for r in rows:
        dur = None
        if r["started_at"]:
            dur = (r["ended_at"] or util.now()) - r["started_at"]
        status = r["status"] + ("*" if r["health"] not in (None, "OK") else "")
        detail = r["failure_code"] or ""
        if r["health"] not in (None, "OK"):
            detail = (detail + " " + r["health"]).strip()
        if r["status"] == "RUNNING" and r["last_progress"]:
            p = util.json_loads(r["last_progress"], {}) or {}
            detail = (detail + " " + " ".join(f"{k}={v}" for k, v in list(p.items()) if not k.startswith("_"))[:60]).strip()
        _out(f"{r['run_id']:40} {status:21} {util.local_str(r['started_at'] or r['created_at']):19} "
             f"{util.fmt_duration(dur):>9}  {detail}")
    return 0


def cmd_status(args) -> int:
    cfg, conn = _open()
    _quick_recover(cfg, conn)
    try:
        rid = store.resolve_run_id(conn, args.run)
    except LookupError as e:
        _err(str(e))
        return 2
    if not rid:
        _err("run not found")
        return 2
    r = store.get_run(conn, rid)
    if args.json:
        _out(json.dumps({k: r[k] for k in r.keys()}, ensure_ascii=False, indent=2, default=str))
        return 0
    dur = ((r["ended_at"] or util.now()) - r["started_at"]) if r["started_at"] else None
    rows = [("run", r["run_id"]), ("name", r["name"]), ("mode", r["mode"]), ("status", r["status"]),
            ("health", r["health"]), ("priority", r["priority"]), ("command", render._command_str(r)),
            ("cwd", r["cwd"]), ("pid", r["pid"]), ("started", util.local_str(r["started_at"])),
            ("ended", util.local_str(r["ended_at"])), ("duration", util.fmt_duration(dur)),
            ("exit", r["exit_desc"]), ("failure", r["failure_code"]), ("summary", r["failure_summary"]),
            ("incident", r["incident_id"]), ("log", r["log_path"]), ("run dir", r["run_dir"])]
    for k, v in rows:
        if v not in (None, ""):
            _out(f"{k:>10}: {v}")
    prog = util.json_loads(r["last_progress"], None)
    if prog:
        _out(f"{'progress':>10}: " + ", ".join(f"{k}={v}" for k, v in prog.items() if not k.startswith("_"))
             + f"  (@ {util.local_str(r['last_progress_at'])}, {r['progress_count']} records)")
    from .resources import human_resources
    for k, v in human_resources(util.json_loads(r["resources"], {})):
        _out(f"{k:>10}: {v}")
    val = util.json_loads(r["validation"], None)
    if val and val.get("configured"):
        for v in val["results"]:
            _out(f"{'check':>10}: {'OK ' if v['ok'] else 'BAD'} {v['target']}: {v['detail']}")
    ev = util.json_loads(r["evidence"], {}) or {}
    if ev.get("final_exception"):
        _out(f"{'exception':>10}: {ev['final_exception']}")
    _out("\nevents:")
    for e in store.run_events(conn, rid)[-15:]:
        _out(f"  {util.local_str(e['ts'])}  {e['type']}")
    notes = conn.execute("SELECT notification_id, channel, status, attempts, last_error FROM notifications "
                         "WHERE run_id=? ORDER BY created_at", (rid,)).fetchall()
    if notes:
        _out("\nnotifications:")
        for n in notes:
            _out(f"  {n['status']:9} {n['channel']:5} {n['notification_id']}"
                 + (f"  (attempts {n['attempts']}; {n['last_error']})" if n["last_error"] else ""))
    return 0


def cmd_logs(args) -> int:
    cfg, conn = _open()
    try:
        rid = store.resolve_run_id(conn, args.run)
    except LookupError as e:
        _err(str(e))
        return 2
    if not rid:
        _err("run not found")
        return 2
    r = store.get_run(conn, rid)
    if args.follow and r["status"] not in store.TERMINAL and r["log_path"]:
        return _follow(conn, rid, from_start=False, initial_lines=args.n)
    if not r["log_path"] or not os.path.exists(r["log_path"]):
        _err("no log file for this run (attach mode without --log?)")
        return 1
    text = util.decode_output(util.read_tail_bytes(r["log_path"], 4 << 20))
    _out("\n".join(util.tail_lines(text, args.n)))
    return 0


def cmd_stop(args) -> int:
    cfg, conn = _open()
    try:
        rid = store.resolve_run_id(conn, args.run)
    except LookupError as e:
        _err(str(e))
        return 2
    r = store.get_run(conn, rid) if rid else None
    if r is None:
        _err("run not found")
        return 2
    if r["status"] in store.TERMINAL:
        _out(f"{rid} already {r['status']}")
        return 0
    with store.tx(conn):
        store.update_run(conn, rid, cancel_requested=1)
        store.add_event(conn, "CANCEL_REQUESTED", rid, source="cli")
    if identity.is_alive(r["supervisor_pid"], r["supervisor_token"]):
        how = ("asks it via researchmonitor.should_stop() if the program uses it, otherwise terminates the process tree"
               if util.IS_WINDOWS else "should_stop() if used, then SIGINT → SIGTERM → kill")
        _out(f"[rmon] stop requested; the monitor {how}, and records CANCELED.")
        for _ in range(60):
            time.sleep(1)
            if store.get_run(conn, rid)["status"] in store.TERMINAL:
                _out(f"[rmon] {rid}: {store.get_run(conn, rid)['status']}")
                return 0
        _out("[rmon] still stopping; check `rmon status`.")
        return 0
    if r["pid"] and identity.is_alive(r["pid"], r["pid_token"]):
        how = supervisor.terminate_tree(r["pid"])
        engine.finalize_run(conn, cfg, rid, {"status": "CANCELED", "authority": store.AUTH_OBSERVED,
                                             "failure_summary": f"terminated by user ({how}); monitor was not running",
                                             "exit_desc": "terminated by rmon"})
        _out(f"[rmon] {rid}: terminated ({how}).")
        return 0
    _quick_recover(cfg, conn)
    _out(f"[rmon] {rid}: process not running; state reconciled.")
    return 0


# --------------------------------------------------------------------------- incidents

def cmd_incidents(args) -> int:
    cfg, conn = _open()
    q = "SELECT * FROM incidents" + ("" if args.all else " WHERE status!='RESOLVED'") + \
        " ORDER BY created_at DESC LIMIT 50"
    rows = conn.execute(q).fetchall()
    if not rows:
        _out("no open incidents" if not args.all else "no incidents")
        return 0
    for i in rows:
        runs = util.json_loads(i["runs"], []) or []
        nxt = f" next reminder {util.local_str(i['next_step_at'])}" if i["next_step_at"] and i["status"] == "OPEN" else ""
        _out(f"{i['incident_id']}  {i['severity']}  {i['status']:13} {util.local_str(i['created_at'])}  "
             f"{i['title']}  ({len(runs)} run(s)){nxt}")
    return 0


def _incident_action(args, state: str) -> int:
    cfg, conn = _open()
    iid = incidents.resolve_ref(conn, args.incident)
    if not iid:
        _err("incident not found")
        return 2
    ok, msg = incidents.transition(conn, iid, state, f"cli:{identity.current_user()}", getattr(args, "note", None))
    (_out if ok else _err)(msg)
    return 0 if ok else 1


def cmd_ack(args) -> int:
    return _incident_action(args, "ACKNOWLEDGED")


def cmd_resolve(args) -> int:
    return _incident_action(args, "RESOLVED")


def cmd_incident_set(args) -> int:
    return _incident_action(args, args.state)


def cmd_snooze(args) -> int:
    cfg, conn = _open()
    iid = incidents.resolve_ref(conn, args.incident)
    if not iid:
        _err("incident not found")
        return 2
    ok, msg = incidents.snooze(conn, iid, util.parse_duration(args.duration, "m"), f"cli:{identity.current_user()}")
    _out(msg)
    return 0 if ok else 1


# --------------------------------------------------------------------------- notifications

def cmd_notifications(args) -> int:
    cfg, conn = _open()
    q = "SELECT * FROM notifications" + (" WHERE status='failed'" if args.failed else "") + \
        " ORDER BY created_at DESC LIMIT ?"
    for n in conn.execute(q, (args.n,)).fetchall():
        _out(f"{util.local_str(n['created_at'])}  {n['status']:9} {n['channel']:5} {n['severity'] or '':3} "
             f"{(n['subject'] or '')[:70]}" + (f"\n{'':22}last error: {n['last_error']}" if n["last_error"] else ""))
    last = store.kv_get(conn, "last_notify_error")
    if last:
        _out(f"\nlast delivery error: {last}")
    return 0


def cmd_retry(args) -> int:
    cfg, conn = _open()
    n = notify.retry_failed(conn)
    _out(f"re-queued {n} failed notification(s)")
    stats = notify.dispatch_due(conn, cfg)
    _out(f"dispatch: {stats}")
    return 0


def send_test(cfg, conn) -> tuple[bool, str]:
    chans = notify.channels_for(cfg, "P1")
    if not chans:
        return False, "no delivery channel configured (run `rmon init`)"
    content = render.test_message(cfg)
    gk = f"test:{int(util.now() * 1000)}"
    with store.tx(conn):
        notify.enqueue(conn, cfg, group_key=gk, kind="test", severity="P1", content=content, channels=chans)
    notify.dispatch_due(conn, cfg)
    rows = conn.execute("SELECT channel, status, last_error FROM notifications WHERE group_key=?", (gk,)).fetchall()
    ok = all(r["status"] == "sent" for r in rows)
    detail = "; ".join(f"{r['channel']}: {r['status']}" + (f" ({r['last_error']})" if r["last_error"] else "")
                       for r in rows)
    if not ok:  # do not keep retrying a test message in the background
        with store.tx(conn):
            conn.execute("UPDATE notifications SET status='cancelled' WHERE group_key=? AND status='pending'", (gk,))
    return ok, detail


def cmd_test_email(args) -> int:
    cfg, conn = _open()
    ok, detail = send_test(cfg, conn)
    _out(("OK — " if ok else "FAILED — ") + detail)
    if ok and "email" in detail:
        _out(f"check the inbox of {', '.join(cfg.email_to)} (and the Junk folder the first time).")
    return 0 if ok else 1


# --------------------------------------------------------------------------- secrets / config

def cmd_secret(args) -> int:
    cfg = load_config()
    if args.action == "list":
        for name, desc in SECRET_NAMES.items():
            _out(f"{name:22} {'set' if get_secret(name, cfg) else '-':4} {desc}")
        return 0
    if args.name not in SECRET_NAMES:
        _err(f"unknown secret {args.name}; one of: {', '.join(SECRET_NAMES)}")
        return 2
    value = args.value if args.value is not None else getpass.getpass(f"{SECRET_NAMES[args.name]}: ")
    if not value:
        _err("empty value; nothing stored")
        return 1
    _out(f"stored in {set_secret(args.name, value.strip(), cfg)}")
    return 0


def _parse_value(v: str):
    lv = v.lower()
    if lv in ("true", "false"):
        return lv == "true"
    try:
        return int(v)
    except ValueError:
        pass
    try:
        return float(v)
    except ValueError:
        return v


def cmd_config(args) -> int:
    cfg = load_config()
    if args.action == "path":
        _out(config_path())
    elif args.action == "show":
        from .config import dumps_toml
        _out(f"# {config_path()}\n" + dumps_toml(cfg.data))
    elif args.action == "set":
        val = _parse_value(args.value)
        if args.key == "notify.email_to":
            val = [x.strip() for x in str(args.value).split(",") if x.strip()]
        cfg.set(args.key, val)
        save_config(cfg)
        _out(f"{args.key} = {val!r}")
    return 0


# --------------------------------------------------------------------------- init wizard

def _ask(prompt: str, default: str = "") -> str:
    v = input(f"{prompt}" + (f" [{default}]" if default else "") + ": ").strip()
    return v or default


def _yes(prompt: str, default: bool = True) -> bool:
    v = input(f"{prompt} [{'Y/n' if default else 'y/N'}]: ").strip().lower()
    return default if not v else v.startswith("y")


SMTP_PRESETS = {
    "qq": ("smtp.qq.com", 465, "ssl"), "163": ("smtp.163.com", 465, "ssl"),
    "126": ("smtp.126.com", 465, "ssl"), "gmail": ("smtp.gmail.com", 465, "ssl"),
}


def cmd_init(args) -> int:
    cfg = load_config()
    if args.non_interactive:
        return _init_noninteractive(args, cfg)
    _out("ResearchMonitor setup. Press Enter to accept [defaults].\n")
    to = _ask("Notification e-mail (recipient)", ", ".join(cfg.email_to) or DEFAULT_RECIPIENT)
    cfg.set("notify.email_to", [x.strip() for x in to.split(",") if x.strip()])
    _out("\nHow should rmon SEND e-mail? (Outlook.com no longer allows password-based SMTP, so the sender is a\n"
         "separate service; your Outlook address only receives.)\n"
         "  1) Resend — sign up at resend.com with the recipient address above, create an API key (recommended)\n"
         "  2) QQ Mail SMTP — needs an SMTP authorization code (授权码) from QQ Mail settings\n"
         "  3) 163 Mail SMTP — needs an authorization code\n"
         "  4) Gmail SMTP — needs an app password (2-step verification on)\n"
         "  5) Other SMTP server\n"
         "  6) No e-mail for now (write messages to files only)")
    choice = _ask("Choose 1-6", "1")
    if choice == "1":
        cfg.set("notify.email_backend", "resend")
        key = getpass.getpass("Resend API key (re_...): ").strip()
        if key:
            _out("  stored in " + set_secret("resend_api_key", key, cfg))
    elif choice in ("2", "3", "4", "5"):
        preset = {"2": "qq", "3": "163", "4": "gmail"}.get(choice)
        host, port, sec = SMTP_PRESETS.get(preset, ("", 587, "starttls"))
        if choice == "5":
            host = _ask("SMTP host")
            port = int(_ask("SMTP port", "587"))
            sec = _ask("Security (ssl/starttls/none)", "starttls")
        user = _ask("Sender address / SMTP username")
        cfg.set("notify.email_backend", "smtp")
        cfg.set("smtp.host", host)
        cfg.set("smtp.port", port)
        cfg.set("smtp.security", sec)
        cfg.set("smtp.username", user)
        cfg.set("smtp.from", f"ResearchMonitor <{user}>")
        pw = getpass.getpass("SMTP authorization code / app password: ").strip()
        if pw:
            _out("  stored in " + set_secret("smtp_password", pw, cfg))
    else:
        cfg.set("notify.email_backend", "file")
    cfg.set("general.host_name", _ask("Name of this computer in reports", cfg.host_name))
    cfg.set("general.language", _ask("Report language (zh/en)", cfg.get("general.language") or "zh"))
    _out("\nRemote watchdog (alerts you if this computer dies while jobs run): create a free check at\n"
         "healthchecks.io (Period 5 min, Grace 5 min) and paste its ping URL. Leave empty to skip.")
    url = _ask("healthchecks ping URL", cfg.get("heartbeat.ping_url") or "")
    cfg.set("heartbeat.ping_url", url)
    if url:
        key = getpass.getpass("healthchecks project API key (read-write; lets rmon pause the check when idle; "
                              "Enter to skip): ").strip()
        if key:
            set_secret("healthchecks_api_key", key, cfg)
    path = save_config(cfg)
    _out(f"\nsaved {path}")
    if cfg.get("notify.email_backend") not in ("none",) and _yes("Send a test message now?"):
        conn = store.connect()
        ok, detail = send_test(cfg, conn)
        _out(("OK — " if ok else "FAILED — ") + detail)
    if _yes("Start the background agent automatically at login (recommended)?"):
        from . import service
        _out(service.install())
    _out("\nDone. Try:  rmon selftest   then   rmon run --name demo -- python your_script.py")
    return 0


def _init_noninteractive(args, cfg: Config) -> int:
    if args.email_to:
        cfg.set("notify.email_to", [x.strip() for x in args.email_to.split(",") if x.strip()])
    if args.backend:
        cfg.set("notify.email_backend", args.backend)
    if args.smtp_preset:
        host, port, sec = SMTP_PRESETS[args.smtp_preset]
        cfg.set("smtp.host", host)
        cfg.set("smtp.port", port)
        cfg.set("smtp.security", sec)
    if args.smtp_user:
        cfg.set("smtp.username", args.smtp_user)
        cfg.set("smtp.from", f"ResearchMonitor <{args.smtp_user}>")
    if args.ping_url is not None:
        cfg.set("heartbeat.ping_url", args.ping_url)
    if args.host_name:
        cfg.set("general.host_name", args.host_name)
    if args.language:
        cfg.set("general.language", args.language)
    _out(f"saved {save_config(cfg)}")
    return 0


# --------------------------------------------------------------------------- agent / service / dashboard

def cmd_agent(args) -> int:
    from .agent import run_agent
    return run_agent(dashboard=not args.no_dashboard, quiet=args.quiet)


def cmd_start(args) -> int:
    """Double-click entry point: make sure the background agent runs, then open the dashboard."""
    import webbrowser
    from . import dashboard, service
    conn = store.connect()
    if not engine.agent_alive(conn):
        service.start_now()
    info = {}
    for _ in range(80):
        info = util.json_loads(store.kv_get(conn, "agent"), {}) or {}
        if engine.agent_alive(conn) and info.get("port"):
            break
        time.sleep(0.25)
    port = info.get("port")
    if not port:
        _err("[rmon] the background agent did not start; see " + os.path.join(home_dir(), "agent.log"))
        return 1
    cfg = load_config()
    url = dashboard.login_url(port, "/" if dashboard._email_ready(cfg) else "/setup")
    _out(f"ResearchMonitor is running in the background. Dashboard: {url}")
    if not args.no_browser:
        webbrowser.open(url)
    return 0


def cmd_stop_agent(args) -> int:
    conn = store.connect()
    if not engine.agent_alive(conn):
        _out("agent is not running")
        return 0
    store.kv_set(conn, "agent_stop", util.now())
    for _ in range(40):
        time.sleep(0.25)
        if not engine.agent_alive(conn):
            _out("agent stopped (jobs keep running; start again to resume monitoring)")
            return 0
    _out("stop requested; the agent will exit within a few seconds")
    return 0


def cmd_jobs(args) -> int:
    import urllib.request
    from . import dashboard
    cfg, conn = _open()
    info = util.json_loads(store.kv_get(conn, "agent"), {}) or {}
    if not engine.agent_alive(conn):
        _out("background agent is not running — start it with `rmon start`")
    for r in store.active_runs(conn):
        _out(f"[{r['mode']}] {r['name']:24} {r['health'] or '':8} {util.fmt_duration(util.now() - (r['started_at'] or util.now())):>8}"
             f"  pid {r['pid']}  {render._command_str(r)[:80]}")
    if info.get("port") and engine.agent_alive(conn):
        try:
            req = urllib.request.Request(f"http://127.0.0.1:{info['port']}/api/state.json",
                                         headers={"Cookie": f"rmon_session={dashboard._token()}"})
            with urllib.request.urlopen(req, timeout=5) as resp:
                data = json.loads(resp.read().decode())
            cands = [c for c in data.get("candidates", []) if not c.get("tracked")]
            if cands:
                _out("\ncandidates (not tracked):")
                for c in cands[:20]:
                    why = c.get("excluded") or "; ".join(c.get("reasons") or [])
                    _out(f"  pid {c['pid']:>6} score {c['score']:>2}  {c['cmd'][:70]}  — {why[:80]}")
        except Exception as ex:
            _err(f"could not read candidates: {ex}")
    return 0


def cmd_rule(args) -> int:
    conn = store.connect()
    with store.tx(conn):
        conn.execute("INSERT INTO rules(action,pattern,note,created_at) VALUES(?,?,?,?)",
                     (args.action, args.pattern, "cli", util.now()))
    _out(f"{'will always monitor' if args.action == 'watch' else 'will ignore'} programs whose command line or "
         f"folder contains: {args.pattern}")
    return 0


def cmd_service(args) -> int:
    from . import service
    fn = {"install": service.install, "uninstall": service.uninstall, "status": service.status}[args.action]
    _out(fn())
    return 0


def cmd_dashboard(args) -> int:
    from . import dashboard
    return dashboard.open_or_serve(no_browser=args.no_browser, port=args.port)


def cmd_doctor(args) -> int:
    from .doctor import run_doctor
    return run_doctor(send=args.send_test)


def cmd_selftest(args) -> int:
    from .selftest import run_selftest
    return run_selftest(keep=args.keep)


# --------------------------------------------------------------------------- parser

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="rmon", description="ResearchMonitor: watch long-running research jobs and "
                                                         "get notified when they finish, fail, stall or are lost.")
    p.add_argument("--version", action="version", version=f"ResearchMonitor {__version__}")
    sub = p.add_subparsers(dest="cmd")

    def run_opts(sp, attach=False):
        sp.add_argument("--name", help="display name (default: script name)")
        sp.add_argument("--project", help="project name for grouping")
        sp.add_argument("--priority", choices=["high", "normal", "low"], help="high → failures are P1 (urgent)")
        sp.add_argument("--tag", action="append", help="free-form tag (repeatable)")
        sp.add_argument("--expect", action="append", help="result file that must be written by this run (repeatable)")
        sp.add_argument("--expect-json", action="append", dest="expect_json",
                        help="JSON result that must be valid, e.g. results/m.json#acc,loss (keys must be finite)")
        sp.add_argument("--expect-glob", action="append", dest="expect_glob",
                        help="glob that must match ≥1 file written by this run, e.g. 'ckpt/*.pt'")
        sp.add_argument("--attach", action="append", dest="attach",
                        help="small result file to attach to the report e-mail (repeatable)")
        sp.add_argument("--progress", help="JSONL progress file written by the program (default: provided via "
                                           "$RMON_PROGRESS_FILE)")
        sp.add_argument("--stall-after", dest="stall_after", help="warn after this long without progress, e.g. 45m "
                                                                  "(0 = off; default 30m)")
        sp.add_argument("--notify", choices=["all", "failure", "none"], help="which outcomes to e-mail")
        if not attach:
            sp.add_argument("--timeout", help="wall-time limit, e.g. 48h (job is terminated → TIMED_OUT)")
            sp.add_argument("--allow-sleep", action="store_true", dest="allow_sleep",
                            help="do not keep Windows awake while the job runs")
            sp.add_argument("--no-unbuffered", action="store_true", dest="no_unbuffered",
                            help="do not set PYTHONUNBUFFERED=1 for the job")

    sp = sub.add_parser("run", help="start a command under monitoring")
    run_opts(sp)
    sp.add_argument("--shell", action="store_true", help="run the command through the system shell")
    sp.add_argument("-d", "--detach", action="store_true", help="return immediately instead of streaming output")
    sp.add_argument("--project-file", dest="project_file", help="settings file (default: ./rmon.toml if present)")
    sp.add_argument("command", nargs=argparse.REMAINDER, help="-- command [args...]")
    sp.set_defaults(func=cmd_run)

    sp = sub.add_parser("attach", help="monitor an already-running process by PID")
    sp.add_argument("--pid", type=int, required=True)
    sp.add_argument("--log", help="log file the process writes (used for activity + error classification)")
    run_opts(sp, attach=True)
    sp.set_defaults(func=cmd_attach)

    sp = sub.add_parser("ls", help="list runs")
    sp.add_argument("-a", "--all", action="store_true")
    sp.add_argument("-n", type=int, default=30)
    sp.set_defaults(func=cmd_ls)

    sp = sub.add_parser("status", aliases=["show"], help="details of a run (default: latest)")
    sp.add_argument("run", nargs="?")
    sp.add_argument("--json", action="store_true")
    sp.set_defaults(func=cmd_status)

    sp = sub.add_parser("logs", help="show a run's output")
    sp.add_argument("run", nargs="?")
    sp.add_argument("-f", "--follow", action="store_true")
    sp.add_argument("-n", type=int, default=100)
    sp.set_defaults(func=cmd_logs)

    sp = sub.add_parser("stop", help="cancel a run (terminates the job)")
    sp.add_argument("run")
    sp.set_defaults(func=cmd_stop)

    sp = sub.add_parser("incidents", help="list incidents")
    sp.add_argument("-a", "--all", action="store_true")
    sp.set_defaults(func=cmd_incidents)
    for name, fn, hlp in (("ack", cmd_ack, "acknowledge an incident (stops reminders)"),
                          ("resolve", cmd_resolve, "resolve an incident")):
        sp = sub.add_parser(name, help=hlp)
        sp.add_argument("incident", nargs="?", help="INC-000123 or 123 (default: latest open)")
        sp.add_argument("--note")
        sp.set_defaults(func=fn)
    sp = sub.add_parser("incident", help="move an incident to INVESTIGATING / MITIGATED / …")
    sp.add_argument("incident")
    sp.add_argument("state", choices=["acknowledged", "investigating", "mitigated", "resolved"])
    sp.add_argument("--note")
    sp.set_defaults(func=cmd_incident_set)
    sp = sub.add_parser("snooze", help="pause reminders for an incident")
    sp.add_argument("incident")
    sp.add_argument("duration", help="e.g. 2h")
    sp.set_defaults(func=cmd_snooze)

    sp = sub.add_parser("notifications", help="delivery history")
    sp.add_argument("--failed", action="store_true")
    sp.add_argument("-n", type=int, default=20)
    sp.set_defaults(func=cmd_notifications)
    sp = sub.add_parser("retry", help="re-queue failed notifications")
    sp.set_defaults(func=cmd_retry)
    sp = sub.add_parser("test-email", help="send a test message on all configured channels")
    sp.set_defaults(func=cmd_test_email)

    sp = sub.add_parser("init", help="interactive setup (e-mail, watchdog, autostart)")
    sp.add_argument("--non-interactive", action="store_true")
    sp.add_argument("--email-to")
    sp.add_argument("--backend", choices=["resend", "smtp", "file", "none"])
    sp.add_argument("--smtp-preset", choices=list(SMTP_PRESETS))
    sp.add_argument("--smtp-user")
    sp.add_argument("--ping-url")
    sp.add_argument("--host-name")
    sp.add_argument("--language", choices=["zh", "en"])
    sp.set_defaults(func=cmd_init)

    sp = sub.add_parser("secret", help="store credentials outside the config file")
    sp.add_argument("action", choices=["set", "list"])
    sp.add_argument("name", nargs="?")
    sp.add_argument("--value", help="(avoid: visible in shell history) value; prompts if omitted")
    sp.set_defaults(func=cmd_secret)

    sp = sub.add_parser("config", help="show / change configuration")
    sp.add_argument("action", choices=["show", "path", "set"])
    sp.add_argument("key", nargs="?")
    sp.add_argument("value", nargs="?")
    sp.set_defaults(func=cmd_config)

    sp = sub.add_parser("agent", help="run the background agent in the foreground")
    sp.add_argument("--no-dashboard", action="store_true")
    sp.add_argument("--quiet", action="store_true")
    sp.set_defaults(func=cmd_agent)
    sp = sub.add_parser("start", help="start background monitoring and open the dashboard (double-click entry)")
    sp.add_argument("--no-browser", action="store_true")
    sp.set_defaults(func=cmd_start)
    sp = sub.add_parser("stop-agent", aliases=["quit"], help="stop the background agent (jobs keep running)")
    sp.set_defaults(func=cmd_stop_agent)
    sp = sub.add_parser("jobs", help="programs being monitored automatically, and candidates")
    sp.set_defaults(func=cmd_jobs)
    for name, hlp in (("watch", "always monitor programs whose command/folder contains PATTERN"),
                      ("ignore", "never monitor programs whose command/folder contains PATTERN")):
        sp = sub.add_parser(name, help=hlp)
        sp.add_argument("pattern")
        sp.set_defaults(func=cmd_rule, action=name)
    sp = sub.add_parser("service", help="install/uninstall agent autostart")
    sp.add_argument("action", choices=["install", "uninstall", "status"])
    sp.set_defaults(func=cmd_service)
    sp = sub.add_parser("dashboard", help="open the local web dashboard")
    sp.add_argument("--no-browser", action="store_true")
    sp.add_argument("--port", type=int)
    sp.set_defaults(func=cmd_dashboard)
    sp = sub.add_parser("doctor", help="check configuration and environment")
    sp.add_argument("--send-test", action="store_true")
    sp.set_defaults(func=cmd_doctor)
    sp = sub.add_parser("selftest", help="end-to-end self test on this computer (no e-mails sent)")
    sp.add_argument("--keep", action="store_true", help="keep the temporary data directory")
    sp.set_defaults(func=cmd_selftest)
    sp = sub.add_parser("version")
    sp.set_defaults(func=lambda a: (_out(f"ResearchMonitor {__version__} · data dir {home_dir()}"), 0)[1])
    return p


def main(argv=None) -> int:
    for stream in (sys.stdout, sys.stderr):
        try:
            if stream is not None and (stream.encoding or "").lower() not in ("utf-8", "utf8"):
                stream.reconfigure(errors="replace")
        except (AttributeError, ValueError):
            pass
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "func", None):
        parser.print_help()
        return 0
    try:
        return int(args.func(args) or 0)
    except KeyboardInterrupt:
        return 130
