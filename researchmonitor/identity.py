"""Host, boot-session and process identity.

A PID alone is not an identity (PIDs are reused), so every process is recorded as (pid, start token):
- Linux: start time in clock ticks since boot from /proc/<pid>/stat (immune to wall-clock changes)
- Windows/macOS: process creation time from psutil (absolute; fixed at creation)
"""
from __future__ import annotations

import os
import sys
import uuid

import psutil

from . import store


def host_id(conn) -> str:
    hid = store.kv_get(conn, "host_id")
    if not hid:
        hid = "host-" + uuid.uuid4().hex[:12]
        with store.tx(conn):
            if not store.kv_get(conn, "host_id"):
                store.kv_set(conn, "host_id", hid)
            hid = store.kv_get(conn, "host_id")
    return hid


def boot_id() -> str:
    if sys.platform.startswith("linux"):
        try:
            with open("/proc/sys/kernel/random/boot_id") as f:
                return "linux:" + f.read().strip()
        except OSError:
            pass
    if sys.platform == "win32":
        try:
            import winreg
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                                 r"SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management"
                                 r"\PrefetchParameters")
            val, _ = winreg.QueryValueEx(key, "BootId")
            return f"winreg:{int(val)}"
        except Exception:
            pass
    return f"bt:{int(psutil.boot_time())}"


def same_boot(a: str | None, b: str | None) -> bool:
    """True unless we can positively tell the two boot ids are different boot sessions."""
    if not a or not b:
        return True
    ka, _, va = a.partition(":")
    kb, _, vb = b.partition(":")
    if ka != kb:
        return True  # incomparable; rely on process liveness instead
    if ka == "bt":  # derived from wall clock; tolerate clock adjustments
        try:
            return abs(float(va) - float(vb)) < 300
        except ValueError:
            return True
    return va == vb


def proc_token(pid: int) -> str | None:
    """Stable start token for a live process, or None if it does not exist."""
    if sys.platform.startswith("linux"):
        try:
            with open(f"/proc/{pid}/stat", "rb") as f:
                data = f.read().decode("ascii", "replace")
            fields = data[data.rindex(")") + 2:].split()
            return "ticks:" + fields[19]  # field 22 overall = starttime
        except (OSError, ValueError, IndexError):
            return None
    try:
        return "ctime:%.2f" % psutil.Process(pid).create_time()
    except (psutil.Error, OSError):
        return None


def is_alive(pid: int | None, token: str | None) -> bool:
    """Is the *same* process (not a reused PID) still running?"""
    if not pid:
        return False
    cur = proc_token(int(pid))
    if cur is None:
        return False
    if token is None:
        return True
    if cur == token:
        try:
            return psutil.Process(int(pid)).status() != psutil.STATUS_ZOMBIE
        except psutil.Error:
            return False
    if cur.startswith("ctime:") and token.startswith("ctime:"):
        try:
            return abs(float(cur[6:]) - float(token[6:])) < 0.05
        except ValueError:
            return False
    return False


def describe_process(pid: int) -> dict:
    info = {"pid": pid}
    try:
        p = psutil.Process(pid)
        with p.oneshot():
            info["name"] = p.name()
            try:
                info["cmdline"] = p.cmdline()
            except psutil.Error:
                info["cmdline"] = []
            try:
                info["cwd"] = p.cwd()
            except psutil.Error:
                info["cwd"] = None
            info["create_time"] = p.create_time()
            try:
                info["username"] = p.username()
            except psutil.Error:
                info["username"] = None
    except psutil.Error as e:
        info["error"] = str(e)
    return info


def current_user() -> str:
    try:
        return psutil.Process(os.getpid()).username()
    except psutil.Error:
        return os.environ.get("USERNAME") or os.environ.get("USER") or "?"
