"""`rmon doctor`: explain what is configured, what works, and what to fix."""
from __future__ import annotations

import os
import platform
import shutil
import socket
import subprocess
import sys

import psutil

from . import __version__, engine, heartbeat, notify, store, util
from .config import config_path, get_secret, home_dir, load_config


def _line(level: str, msg: str) -> None:
    print(f"[{level:4}] {msg}", flush=True)


def run_doctor(send: bool = False) -> int:
    problems = 0
    _line("INFO", f"ResearchMonitor {__version__} · Python {platform.python_version()} · {platform.platform()}")
    _line("INFO", f"psutil {psutil.__version__} · data dir {home_dir()}")
    cfg = load_config()
    if not os.path.exists(config_path()):
        _line("WARN", "no config file yet — run `rmon init`")
        problems += 1
    conn = store.connect()

    # e-mail
    backend = cfg.get("notify.email_backend") or "none"
    if not cfg.email_to:
        _line("WARN", "no recipient (notify.email_to)")
        problems += 1
    else:
        _line("OK", f"recipient: {', '.join(cfg.email_to)}")
    if backend == "resend":
        if get_secret("resend_api_key", cfg):
            _line("OK", f"e-mail via Resend from {cfg.get('resend.from')}")
            if "resend.dev" in (cfg.get("resend.from") or ""):
                _line("INFO", "onboarding@resend.dev can only deliver to the address you signed up with at Resend")
        else:
            _line("FAIL", "Resend API key missing: rmon secret set resend_api_key")
            problems += 1
    elif backend == "smtp":
        host = cfg.get("smtp.host") or ""
        if any(x in host.lower() for x in ("outlook", "office365", "hotmail", "live.com")):
            _line("FAIL", "Outlook/Office365 SMTP no longer accepts passwords (OAuth only) — use Resend or "
                          "another mailbox (QQ/163/Gmail) as the sender")
            problems += 1
        try:
            socket.getaddrinfo(host, cfg.get("smtp.port"))
            _line("OK", f"SMTP {host}:{cfg.get('smtp.port')} ({cfg.get('smtp.security')}) resolves")
        except OSError as e:
            _line("FAIL", f"SMTP host {host!r} does not resolve: {e}")
            problems += 1
        if not get_secret("smtp_password", cfg):
            _line("FAIL", "SMTP password/authorization code missing: rmon secret set smtp_password")
            problems += 1
    elif backend == "file":
        _line("WARN", f"e-mail backend 'file': messages are only written to {os.path.join(home_dir(), 'mail_outbox')}")
    else:
        _line("WARN", "e-mail disabled (notify.email_backend = none)")
    pb = cfg.get("notify.push_backend") or "none"
    if pb != "none":
        _line("OK", f"push via {pb} for {cfg.get('notify.push_min_severity')} and above")

    # heartbeat
    if cfg.get("heartbeat.ping_url"):
        mode = heartbeat.effective_mode(cfg)
        _line("OK", f"remote heartbeat → {cfg.get('heartbeat.ping_url')} (mode {mode})")
        if mode == "always":
            _line("INFO", "mode 'always': the check alerts whenever this computer is off, even if idle. "
                          "Add a healthchecks API key (rmon secret set healthchecks_api_key) to pause it when idle.")
        last = store.kv_get(conn, "hb_last_result")
        if last:
            _line("INFO", f"last heartbeat: {last}")
    else:
        _line("WARN", "no remote heartbeat: if this computer dies, nobody can tell you (set heartbeat.ping_url)")

    # agent / autostart
    from . import service
    st = service.status()
    alive = engine.agent_alive(conn)
    _line("OK" if alive else "WARN", st.replace("\n", " · "))
    if not alive:
        problems += 1

    # gpu
    from .resources import GpuSampler
    g = GpuSampler()
    _line("OK" if g.backend != "none" else "INFO", f"GPU monitoring backend: {g.backend}")
    if g.backend == "nvidia-smi":
        _line("INFO", "tip: `pip install nvidia-ml-py` gives cheaper GPU sampling via NVML")

    # platform specifics
    if sys.platform.startswith("linux"):
        try:
            with open("/etc/systemd/logind.conf") as f:
                txt = f.read()
            if any(ln.strip().lower() == "killuserprocesses=yes" for ln in txt.splitlines()):
                _line("WARN", "logind KillUserProcesses=yes: jobs may be killed when you log out; use "
                              "`loginctl enable-linger $USER` or run jobs from a systemd service")
        except OSError:
            pass
        if shutil.which("loginctl"):
            r = subprocess.run(["loginctl", "show-user", os.environ.get("USER", ""), "-p", "Linger"],
                               capture_output=True, text=True)
            if "Linger=no" in r.stdout:
                _line("INFO", "linger is off: the agent stops when you log out (loginctl enable-linger $USER)")

    # outbox
    pend = notify.pending_count(conn)
    failed = conn.execute("SELECT COUNT(*) FROM notifications WHERE status='failed'").fetchone()[0]
    _line("OK" if not failed else "WARN", f"outbox: {pend} pending, {failed} failed")
    last_err = store.kv_get(conn, "last_notify_error")
    if last_err:
        _line("INFO", f"last delivery error: {last_err}")
    du = shutil.disk_usage(home_dir())
    _line("OK" if du.free > 2e9 else "WARN", f"free disk at data dir: {util.fmt_bytes(du.free)}")

    if send:
        from .cli import send_test
        ok, detail = send_test(cfg, conn)
        _line("OK" if ok else "FAIL", f"test message: {detail}")
        problems += 0 if ok else 1
    print()
    print("No problems found." if not problems else f"{problems} item(s) need attention.")
    return 0 if not problems else 1
