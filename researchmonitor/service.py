"""Autostart for the agent without admin rights.

Windows: a .cmd in the user's Startup folder launching pythonw (no console window).
Linux:   a systemd --user unit (falls back to an @reboot crontab entry).
"""
from __future__ import annotations

import os
import shutil
import subprocess
import sys

from . import engine, store

UNIT = "researchmonitor-agent.service"
DETACHED_PROCESS = 0x00000008
CREATE_NEW_PROCESS_GROUP = 0x00000200
CREATE_BREAKAWAY_FROM_JOB = 0x01000000


def _pythonw() -> str:
    exe = sys.executable
    if sys.platform == "win32":
        cand = os.path.join(os.path.dirname(exe), "pythonw.exe")
        if os.path.exists(cand):
            return cand
    return exe


def _startup_file() -> str:
    appdata = os.environ.get("APPDATA") or os.path.expanduser(r"~\AppData\Roaming")
    return os.path.join(appdata, "Microsoft", "Windows", "Start Menu", "Programs", "Startup",
                        "ResearchMonitorAgent.cmd")


def _env_lines_win() -> str:
    lines = []
    if os.environ.get("RMON_HOME"):
        lines.append(f'set "RMON_HOME={os.environ["RMON_HOME"]}"')
    return "\r\n".join(lines) + ("\r\n" if lines else "")


def start_now() -> str:
    conn = store.connect()
    if engine.agent_alive(conn):
        return "agent already running"
    cmd = [_pythonw(), "-m", "researchmonitor", "agent", "--quiet"]
    kw = dict(stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, close_fds=True)
    if sys.platform == "win32":
        try:
            subprocess.Popen(cmd, creationflags=DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP | CREATE_BREAKAWAY_FROM_JOB,
                             **kw)
        except OSError:
            subprocess.Popen(cmd, creationflags=DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP, **kw)
    else:
        subprocess.Popen(cmd, start_new_session=True, **kw)
    return "agent started"


def install(start: bool = True) -> str:
    if sys.platform == "win32":
        path = _startup_file()
        os.makedirs(os.path.dirname(path), exist_ok=True)
        # UTF-8 + chcp 65001 so paths with non-ASCII user names (e.g. C:\Users\张三) survive
        with open(path, "w", encoding="utf-8", newline="") as f:
            f.write("@echo off\r\nchcp 65001 >nul\r\n" + _env_lines_win() +
                    f'start "" "{_pythonw()}" -m researchmonitor agent --quiet\r\n')
        return f"autostart installed: {path}" + (f"\n{start_now()}" if start else "")
    if shutil.which("systemctl"):
        unit_dir = os.path.expanduser("~/.config/systemd/user")
        os.makedirs(unit_dir, exist_ok=True)
        env = f"Environment=RMON_HOME={os.environ['RMON_HOME']}\n" if os.environ.get("RMON_HOME") else ""
        with open(os.path.join(unit_dir, UNIT), "w") as f:
            f.write("[Unit]\nDescription=ResearchMonitor agent\nAfter=network-online.target\n\n"
                    f"[Service]\nExecStart={sys.executable} -m researchmonitor agent --quiet\n{env}"
                    "Restart=always\nRestartSec=10\nKillMode=process\n\n[Install]\nWantedBy=default.target\n")
        r1 = subprocess.run(["systemctl", "--user", "daemon-reload"], capture_output=True, text=True)
        r2 = subprocess.run(["systemctl", "--user", "enable"] + (["--now"] if start else []) + [UNIT],
                            capture_output=True, text=True)
        if r1.returncode == 0 and r2.returncode == 0:
            return (f"systemd user service enabled ({UNIT}).\n"
                    "Tip: run `loginctl enable-linger $USER` so it also runs when you are not logged in.")
        msg = (r1.stderr + r2.stderr).strip()
        subprocess.run(["systemctl", "--user", "disable", UNIT], capture_output=True)
        try:
            os.remove(os.path.join(unit_dir, UNIT))
        except OSError:
            pass
        return _cron_install() + f"\n(systemd --user unavailable: {msg[:200]})"
    return _cron_install()


def _cron_install() -> str:
    if not shutil.which("crontab"):
        return start_now() + "\nno systemd/crontab found: start the agent manually after reboot (`rmon agent`)."
    line = f"@reboot {sys.executable} -m researchmonitor agent --quiet >/dev/null 2>&1 # researchmonitor"
    cur = subprocess.run(["crontab", "-l"], capture_output=True, text=True).stdout
    if "# researchmonitor" not in cur:
        new = (cur.rstrip("\n") + "\n" if cur.strip() else "") + line + "\n"
        subprocess.run(["crontab", "-"], input=new, text=True, check=False)
    return "crontab @reboot entry installed\n" + start_now()


def uninstall(stop_agent: bool = True) -> str:
    msgs = []
    if sys.platform == "win32":
        p = _startup_file()
        if os.path.exists(p):
            os.remove(p)
            msgs.append(f"removed {p}")
    else:
        if shutil.which("systemctl"):
            subprocess.run(["systemctl", "--user", "disable"] + (["--now"] if stop_agent else []) + [UNIT],
                           capture_output=True)
            p = os.path.expanduser(f"~/.config/systemd/user/{UNIT}")
            if os.path.exists(p):
                os.remove(p)
                msgs.append(f"removed {p}")
        if shutil.which("crontab"):
            cur = subprocess.run(["crontab", "-l"], capture_output=True, text=True).stdout
            if "# researchmonitor" in cur:
                new = "\n".join(ln for ln in cur.splitlines() if "# researchmonitor" not in ln) + "\n"
                subprocess.run(["crontab", "-"], input=new, text=True)
                msgs.append("removed crontab entry")
    conn = store.connect()
    from . import util
    info = util.json_loads(store.kv_get(conn, "agent"), None)
    if stop_agent and info and engine.agent_alive(conn):
        try:
            import psutil
            psutil.Process(info["pid"]).terminate()
            msgs.append(f"stopped agent pid {info['pid']}")
        except Exception as e:
            msgs.append(f"could not stop agent: {e}")
    return "\n".join(msgs) or "nothing to remove"


def status() -> str:
    conn = store.connect()
    from . import util
    info = util.json_loads(store.kv_get(conn, "agent"), None) or {}
    alive = engine.agent_alive(conn)
    lines = [f"agent: {'running pid ' + str(info.get('pid')) if alive else 'not running'}"]
    if alive and info.get("port"):
        lines.append(f"dashboard: http://127.0.0.1:{info['port']}  (open with `rmon dashboard`)")
    if sys.platform == "win32":
        p = _startup_file()
        lines.append(f"autostart: {'installed ' + p if os.path.exists(p) else 'not installed'}")
    else:
        p = os.path.expanduser(f"~/.config/systemd/user/{UNIT}")
        cron = ""
        if shutil.which("crontab"):
            cron = subprocess.run(["crontab", "-l"], capture_output=True, text=True).stdout
        lines.append("autostart: " + ("systemd user unit" if os.path.exists(p) else
                                      "crontab @reboot" if "# researchmonitor" in cron else "not installed"))
    return "\n".join(lines)
