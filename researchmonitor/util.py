"""Small shared helpers (stdlib only)."""
from __future__ import annotations

import datetime as _dt
import hashlib
import json
import locale
import math
import os
import re
import secrets
import time

IS_WINDOWS = os.name == "nt"


def now() -> float:
    return time.time()


def iso_utc(ts: float | None) -> str | None:
    if ts is None:
        return None
    return _dt.datetime.fromtimestamp(ts, _dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def local_str(ts: float | None) -> str:
    if not ts:
        return "-"
    return _dt.datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")


def parse_duration(text, default_unit: str = "m") -> float | None:
    """'90s' / '45m' / '2h' / '1.5d' / 30 -> seconds. '0', 'off', 'none' -> 0."""
    if text is None:
        return None
    if isinstance(text, (int, float)):
        return float(text) * {"s": 1, "m": 60, "h": 3600, "d": 86400}[default_unit]
    t = str(text).strip().lower()
    if t in ("", "off", "none", "no", "false"):
        return 0.0
    total = 0.0
    parts = re.findall(r"(\d+(?:\.\d+)?)\s*([smhd]?)", t)
    if not parts or re.sub(r"[\d.\ssmhd]", "", t):
        raise ValueError(f"invalid duration: {text!r} (examples: 90s, 45m, 2h, 1d, 1h30m)")
    for num, unit in parts:
        unit = unit or default_unit
        total += float(num) * {"s": 1, "m": 60, "h": 3600, "d": 86400}[unit]
    return total


def fmt_duration(seconds: float | None) -> str:
    if seconds is None:
        return "-"
    s = int(max(0, seconds))
    d, s = divmod(s, 86400)
    h, s = divmod(s, 3600)
    m, s = divmod(s, 60)
    if d:
        return f"{d}d{h}h{m:02d}m"
    if h:
        return f"{h}h{m:02d}m"
    if m:
        return f"{m}m{s:02d}s"
    return f"{s}s"


def fmt_bytes(n) -> str:
    if n is None:
        return "-"
    n = float(n)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(n) < 1024 or unit == "TB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"


def slug(text: str, maxlen: int = 24) -> str:
    s = re.sub(r"[^A-Za-z0-9]+", "-", text or "").strip("-").lower()
    return (s or "run")[:maxlen].strip("-") or "run"


def new_run_id(name: str) -> str:
    stamp = _dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    return f"{stamp}-{slug(name)}-{secrets.token_hex(2)}"


def new_id(prefix: str = "") -> str:
    return f"{prefix}{secrets.token_hex(8)}"


def json_dumps(obj) -> str:
    """Strict JSON (NaN/Inf become strings) so the database never holds non-standard JSON."""
    return json.dumps(_sanitize(obj), ensure_ascii=False, default=str, separators=(",", ":"))


def _sanitize(obj):
    if isinstance(obj, float) and (math.isnan(obj) or math.isinf(obj)):
        return str(obj)
    if isinstance(obj, dict):
        return {k: _sanitize(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_sanitize(v) for v in obj]
    return obj


def json_loads(text, default=None):
    if text is None or text == "":
        return default
    try:
        return json.loads(text)
    except (TypeError, ValueError):
        return default


def read_tail_bytes(path: str, max_bytes: int = 256 * 1024) -> bytes:
    try:
        with open(path, "rb") as f:
            f.seek(0, os.SEEK_END)
            size = f.tell()
            f.seek(max(0, size - max_bytes))
            return f.read()
    except OSError:
        return b""


def decode_output(data: bytes) -> str:
    """Decode child output. UTF-8 first; fall back to the locale code page (e.g. GBK on Chinese Windows)."""
    if not data:
        return ""
    text = data.decode("utf-8", errors="replace")
    bad = text.count("�")
    if bad > 4 and bad > len(text) / 200:
        enc = locale.getpreferredencoding(False) or "utf-8"
        for candidate in (enc, "gbk"):
            try:
                alt = data.decode(candidate, errors="replace")
            except LookupError:
                continue
            if alt.count("�") < bad:
                return alt
    return text


def read_text_any(path: str) -> str:
    """Read a small text file written by any Windows/Linux tool: UTF-8 (with or without BOM),
    UTF-16 (BOM), or the locale code page (e.g. GBK)."""
    with open(path, "rb") as f:
        data = f.read()
    if data.startswith((b"\xff\xfe", b"\xfe\xff")):
        return data.decode("utf-16")
    try:
        return data.decode("utf-8-sig")
    except UnicodeDecodeError:
        pass
    for enc in (locale.getpreferredencoding(False), "gbk"):
        try:
            return data.decode(enc)
        except (UnicodeDecodeError, LookupError):
            continue
    return data.decode("utf-8", errors="replace")


def tail_lines(text: str, n: int) -> list[str]:
    # tqdm-style carriage-return updates: keep only the last segment of each line
    lines = [ln.rsplit("\r", 1)[-1] for ln in text.splitlines()]
    return lines[-n:]


def sha256_file(path: str, limit_bytes: int = 1 << 30) -> str | None:
    try:
        if os.path.getsize(path) > limit_bytes:
            return None
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(1 << 20), b""):
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return None


def is_finite_number(v) -> bool:
    return isinstance(v, (int, float)) and not isinstance(v, bool) and math.isfinite(v)
