"""Remote dead-man's switch via healthchecks.io (or a self-hosted Healthchecks instance).

While runs are active, some rmon process pings the check every `interval_s`. If the computer powers
off, crashes or loses network, the pings stop and healthchecks.io alerts you from outside the failure
domain of this host (design principle 2). When nothing is running the check is paused through the
management API, so switching the computer off while idle does not alert.
"""
from __future__ import annotations

import re
import socket
import urllib.error
import urllib.request

from . import store, util
from .config import get_secret

UA = "ResearchMonitor/0.1"
_UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", re.I)


def effective_mode(cfg) -> str:
    mode = (cfg.get("heartbeat.mode") or "auto").lower()
    if mode == "auto":
        return "while_running" if get_secret("healthchecks_api_key", cfg) else "always"
    return mode


def check_uuid(cfg) -> str | None:
    explicit = cfg.get("heartbeat.check_uuid")
    if explicit:
        return explicit
    m = _UUID.search(cfg.get("heartbeat.ping_url") or "")
    return m.group(0) if m else None


def _post(url: str, data: bytes, headers: dict, timeout: float = 15) -> tuple[bool, str]:
    req = urllib.request.Request(url, data=data, method="POST", headers={"User-Agent": UA, **headers})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return 200 <= resp.status < 300, f"HTTP {resp.status}"
    except urllib.error.HTTPError as e:
        return False, f"HTTP {e.code}"
    except (urllib.error.URLError, OSError, socket.timeout) as e:
        return False, f"network error: {getattr(e, 'reason', e)}"


def ping(cfg, body: str) -> tuple[bool, str]:
    return _post(cfg.get("heartbeat.ping_url"), body.encode("utf-8")[:10000], {"Content-Type": "text/plain"})


def pause(cfg) -> tuple[bool, str]:
    key = get_secret("healthchecks_api_key", cfg)
    uid = check_uuid(cfg)
    if not key or not uid:
        return False, "pause needs heartbeat API key and a check UUID"
    base = (cfg.get("heartbeat.api_base") or "https://healthchecks.io/api/v3").rstrip("/")
    return _post(f"{base}/checks/{uid}/pause", b"", {"X-Api-Key": key})


def tick(conn, cfg, force: bool = False) -> str | None:
    """Ping while runs are active; pause when idle. Safe to call from many processes."""
    if not cfg.get("heartbeat.ping_url"):
        return None
    interval = float(cfg.get("heartbeat.interval_s") or 60)
    runs = store.active_runs(conn)
    mode = effective_mode(cfg)
    if runs or mode == "always":
        if force:
            store.kv_set(conn, "hb_last_ping", util.now())
        elif not store.kv_claim_interval(conn, "hb_last_ping", interval - 2):
            return None
        names = ", ".join((r["name"] or r["run_id"]) for r in runs[:10])
        body = f"host={cfg.host_name} active_runs={len(runs)} {names}"
        ok, info = ping(cfg, body)
        store.kv_set(conn, "hb_last_result", f"{util.local_str(util.now())} ping {'ok' if ok else 'FAILED'} {info}")
        if ok:
            store.kv_set(conn, "hb_paused", "0")
            store.kv_set(conn, "hb_last_ok", util.now())
        return "ping-ok" if ok else "ping-failed"
    # idle and mode == while_running
    if store.kv_get(conn, "hb_paused") == "1" or store.kv_get(conn, "hb_last_ok") is None:
        return None  # already paused, or never pinged (healthchecks does not alert on a fresh check)
    if not force and not store.kv_claim_interval(conn, "hb_pause_attempt", 60):
        return None
    ok, info = pause(cfg)
    store.kv_set(conn, "hb_last_result", f"{util.local_str(util.now())} pause {'ok' if ok else 'FAILED'} {info}")
    if ok:
        store.kv_set(conn, "hb_paused", "1")
    return "pause-ok" if ok else "pause-failed"
