"""Configuration file (~/.researchmonitor/config.toml) and secret storage."""
from __future__ import annotations

import copy
import json
import os
import socket
import stat
import sys

try:  # Python 3.11+
    import tomllib as _toml
except ImportError:  # pragma: no cover - exercised on 3.9/3.10
    try:
        import tomli as _toml  # type: ignore
    except ImportError:
        _toml = None

DEFAULT_EMAIL = ""

DEFAULTS: dict = {
    "general": {"host_name": "", "language": "zh"},
    "notify": {
        "email_to": [],
        "email_backend": "none",        # resend | smtp | file | none
        "push_backend": "none",         # ntfy | serverchan | webhook | none
        "push_min_severity": "P1",      # push is used for this severity and above
        "notify_success": True,
        "notify_cancel": False,
        "attach_max_kb": 512,
        "max_attempts": 30,             # ~12h of exponential back-off before giving up
        "linger_max_h": 24,             # how long a finished run's supervisor keeps retrying when no agent runs
        "linger_tick_s": 10,
        "intermediate": "2h",           # intermediate-result e-mails: off | each | 30m | 1h | 2h | 6h ...
        "intermediate_first_after": "15m",
        "mid_run_alerts": ["stall", "nan"],   # sent once each; everything else goes into the final report
    },
    "smtp": {"host": "", "port": 465, "security": "ssl", "username": "", "from": "", "timeout_s": 30},
    "resend": {"from": "ResearchMonitor <onboarding@resend.dev>", "api_url": "https://api.resend.com/emails"},
    "ntfy": {"url": ""},
    "webhook": {"url": ""},
    "heartbeat": {
        "ping_url": "",                 # e.g. https://hc-ping.com/<uuid>
        "mode": "auto",                 # auto | while_running | always
        "interval_s": 60,
        "api_base": "https://healthchecks.io/api/v3",
    },
    "monitor": {
        "sample_interval_s": 15,
        "gpu_interval_s": 30,
        "stall_after": "30m",
        "prevent_sleep": True,
        "p1_min_runtime": "2h",
        "disk_free_warn_gb": 5.0,
        "mem_warn_percent": 95,
        "gpu_temp_warn_c": 90,
        "stop_grace_s": 60,             # wait for a should_stop()-aware job to exit by itself
    },
    "incidents": {
        "correlation_window": "10m",
        "p0_reminders": "",
        "p1_reminders": "",             # one e-mail per job by default; e.g. "30m" re-sends unacknowledged P1
        "p2_reminders": "",
    },
    "discovery": {
        "enabled": True,
        "scan_interval_s": 20,          # cheap whole-system process scan
        "min_age_s": 120,               # ignore programs that finish within 2 minutes
        "min_score": 5,
        "watch": [],                    # substrings (script, folder, keyword) that mark a process as yours
        "ignore": [],                   # substrings that are never monitored
        "only": [],                     # if set, ONLY processes matching one of these are tracked
        "track_notebooks": True,        # Jupyter kernels: one report per long computation burst
        "notebook_min_episode": "10m",
        "console_capture": True,        # Windows: read the job's terminal text; Linux: tmux panes
    },
    "dashboard": {"port": 8765},
    "secrets": {"backend": "auto"},     # auto | keyring | file
}

SECRET_NAMES = {
    "smtp_password": "SMTP password / authorization code",
    "resend_api_key": "Resend API key",
    "healthchecks_api_key": "healthchecks.io project API key (read-write)",
    "serverchan_sendkey": "ServerChan SendKey",
    "ntfy_token": "ntfy access token (optional)",
}


def home_dir() -> str:
    d = os.environ.get("RMON_HOME") or os.path.join(os.path.expanduser("~"), ".researchmonitor")
    os.makedirs(d, exist_ok=True)
    return d


def config_path() -> str:
    return os.path.join(home_dir(), "config.toml")


def db_path() -> str:
    return os.path.join(home_dir(), "rmon.db")


def runs_dir() -> str:
    d = os.path.join(home_dir(), "runs")
    os.makedirs(d, exist_ok=True)
    return d


class Config:
    def __init__(self, data: dict | None = None, path: str | None = None):
        self.data = _merge(copy.deepcopy(DEFAULTS), data or {})
        self.path = path
        self.load_error = None

    def get(self, dotted: str, default=None):
        cur = self.data
        for part in dotted.split("."):
            if not isinstance(cur, dict) or part not in cur:
                return default
            cur = cur[part]
        return cur

    def set(self, dotted: str, value) -> None:
        parts = dotted.split(".")
        cur = self.data
        for part in parts[:-1]:
            cur = cur.setdefault(part, {})
        cur[parts[-1]] = value

    @property
    def host_name(self) -> str:
        return self.get("general.host_name") or socket.gethostname()

    @property
    def email_to(self) -> list:
        v = self.get("notify.email_to") or []
        return [v] if isinstance(v, str) else list(v)

    @property
    def configured(self) -> bool:
        return bool(self.path and os.path.exists(self.path))


def _merge(base: dict, over: dict) -> dict:
    for k, v in (over or {}).items():
        if isinstance(v, dict) and isinstance(base.get(k), dict):
            _merge(base[k], v)
        else:
            base[k] = v
    return base


_warned: set = set()


def load_toml_file(path: str) -> dict:
    """Parse TOML tolerating a UTF-8 BOM (Windows Notepad) or a GBK-encoded file."""
    if _toml is None:
        raise RuntimeError("Reading TOML needs Python 3.11+ or `pip install tomli`.")
    from .util import read_text_any
    return _toml.loads(read_text_any(path))


def load_config(path: str | None = None) -> Config:
    path = path or config_path()
    data = {}
    error = None
    if os.path.exists(path):
        try:
            data = load_toml_file(path)
        except Exception as e:  # a broken config must not stop monitoring altogether
            error = f"{path}: {e}"
            if path not in _warned and sys.stderr is not None:
                _warned.add(path)
                print(f"[rmon] WARNING: cannot parse {path} ({e}); using defaults "
                      f"(e-mail disabled until fixed). Check with `rmon doctor`.", file=sys.stderr, flush=True)
    cfg = Config(data, path)
    cfg.load_error = error
    return cfg


def _toml_value(v) -> str:
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, (int, float)):
        return repr(v)
    if isinstance(v, (list, tuple)):
        return "[" + ", ".join(_toml_value(x) for x in v) + "]"
    return json.dumps(str(v), ensure_ascii=False)


def dumps_toml(data: dict) -> str:
    out = ["# ResearchMonitor configuration. Secrets are NOT stored here (see `rmon secret`).", ""]
    for section, values in data.items():
        if not isinstance(values, dict):
            continue
        out.append(f"[{section}]")
        for k, v in values.items():
            if isinstance(v, dict):
                continue
            key = k if k.replace("_", "").isalnum() else json.dumps(k)
            out.append(f"{key} = {_toml_value(v)}")
        out.append("")
    return "\n".join(out)


def save_config(cfg: Config, path: str | None = None) -> str:
    path = path or cfg.path or config_path()
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(dumps_toml(cfg.data))
    _replace_retry(tmp, path)
    cfg.path = path
    return path


def _replace_retry(src: str, dst: str) -> None:
    import time
    for i in range(20):
        try:
            os.replace(src, dst)
            return
        except PermissionError:
            if i == 19:
                raise
            time.sleep(0.1 * (i + 1))


# --------------------------------------------------------------------------- secrets

_KEYRING_SERVICE = "researchmonitor"


def _secrets_file() -> str:
    return os.path.join(home_dir(), "secrets.json")


def _secret_backend(cfg: Config | None) -> str:
    env = os.environ.get("RMON_SECRETS_BACKEND")
    if env:
        return env
    b = (cfg.get("secrets.backend") if cfg else None) or "auto"
    if b != "auto":
        return b
    # Windows Credential Manager is reliable; on Linux a keyring may block on a GUI unlock prompt.
    if sys.platform == "win32":
        try:
            import keyring  # noqa: F401
            return "keyring"
        except Exception:
            return "file"
    return "file"


def get_secret(name: str, cfg: Config | None = None) -> str | None:
    env = os.environ.get("RMON_SECRET_" + name.upper())
    if env:
        return env
    if _secret_backend(cfg) == "keyring":
        try:
            import keyring
            v = keyring.get_password(_KEYRING_SERVICE, name)
            if v:
                return v
        except Exception:
            pass
    try:
        with open(_secrets_file(), "r", encoding="utf-8") as f:
            return json.load(f).get(name) or None
    except (OSError, ValueError):
        return None


def set_secret(name: str, value: str, cfg: Config | None = None) -> str:
    """Store a secret. Returns where it was stored."""
    if _secret_backend(cfg) == "keyring":
        try:
            import keyring
            keyring.set_password(_KEYRING_SERVICE, name, value)
            _file_secret_delete(name)
            return "keyring (OS credential manager)"
        except Exception:
            pass
    path = _secrets_file()
    data = {}
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, ValueError):
        pass
    data[name] = value
    fd = os.open(path + ".tmp", os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(data, f)
    _replace_retry(path + ".tmp", path)
    try:
        os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
    except OSError:
        pass
    return f"file {path} (owner-only permissions)"


def _file_secret_delete(name: str) -> None:
    path = _secrets_file()
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        if name in data:
            del data[name]
            with open(path, "w", encoding="utf-8") as f:
                json.dump(data, f)
    except (OSError, ValueError):
        pass


def delete_secret(name: str, cfg: Config | None = None) -> None:
    if _secret_backend(cfg) == "keyring":
        try:
            import keyring
            keyring.delete_password(_KEYRING_SERVICE, name)
        except Exception:
            pass
    _file_secret_delete(name)
