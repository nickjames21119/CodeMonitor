"""Optional in-program progress reporting. Safe no-op when not running under `rmon run`.

    import researchmonitor as rm
    rm.report(epoch=3, step=1200, loss=0.31)      # progress (used for stall detection & e-mails)
    rm.checkpoint("ckpt/epoch3.pt")               # latest checkpoint path
    rm.result(acc=0.912, mrr=0.55)                # final metrics shown in the report
    if rm.should_stop(): save(); break            # graceful `rmon stop` / --timeout (works on Windows too)

Records are appended as JSON lines to $RMON_PROGRESS_FILE. Uses only the standard library.
"""
from __future__ import annotations

import json
import math
import os
import time

_ENV = "RMON_PROGRESS_FILE"


def _clean(v):
    if isinstance(v, float) and (math.isnan(v) or math.isinf(v)):
        return str(v)  # keep "nan"/"inf" visible without producing invalid JSON
    if isinstance(v, (str, int, float, bool)) or v is None:
        return v
    try:  # numpy / torch scalars
        return _clean(v.item())
    except Exception:
        return str(v)


def _write(kind: str, fields: dict) -> bool:
    path = os.environ.get(_ENV)
    if not path:
        return False
    rec = {"_type": kind, "_ts": time.time()}
    rec.update({str(k): _clean(v) for k, v in fields.items()})
    try:
        with open(path, "a", encoding="utf-8") as f:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
        return True
    except OSError:
        return False


def report(**fields) -> bool:
    return _write("progress", fields)


def checkpoint(path: str, **fields) -> bool:
    return _write("checkpoint", dict(fields, checkpoint=str(path)))


def result(**metrics) -> bool:
    return _write("result", metrics)


def message(text: str) -> bool:
    return _write("message", {"text": str(text)[:2000]})


_stop_announced = False


def should_stop() -> bool:
    """True once `rmon stop` or `--timeout` asked this job to stop. Calling it tells the monitor that the
    program can stop cleanly, so it waits (default 60 s) before terminating the process."""
    global _stop_announced
    path = os.environ.get("RMON_STOP_FILE")
    if not path:
        return False
    if not _stop_announced:
        _stop_announced = _write("stop_aware", {})
    return os.path.exists(path)
