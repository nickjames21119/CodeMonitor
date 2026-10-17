"""Result validators: exit code 0 is not proof of a valid experiment.

Expectation forms (CLI flags or rmon.toml):
  expect       = ["results/metrics.json"]            file exists, non-empty, written during this run
  expect_json  = ["results/metrics.json#acc,mrr"]    valid JSON; listed keys (dotted) exist and are finite numbers
  expect_glob  = ["checkpoints/*.pt"]                at least one fresh match
"""
from __future__ import annotations

import glob
import json
import math
import os

from . import util

FRESH_SLACK_S = 2.0


def build_expectations(expect=(), expect_json=(), expect_glob=()) -> list[dict]:
    out = []
    for p in expect or ():
        out.append({"type": "file", "path": p})
    for spec in expect_json or ():
        path, _, keys = str(spec).partition("#")
        out.append({"type": "json", "path": path, "keys": [k.strip() for k in keys.split(",") if k.strip()]})
    for pat in expect_glob or ():
        out.append({"type": "glob", "pattern": pat})
    return out


def _abs(cwd: str, p: str) -> str:
    p = os.path.expanduser(p)
    return p if os.path.isabs(p) else os.path.join(cwd, p)


def _get_dotted(obj, dotted: str):
    cur = obj
    for part in dotted.split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        elif isinstance(cur, list) and part.isdigit() and int(part) < len(cur):
            cur = cur[int(part)]
        else:
            raise KeyError(dotted)
    return cur


def _check_file(path: str, started_at: float | None) -> tuple[str | None, str]:
    """Return (failure_code or None, detail)."""
    if not os.path.exists(path):
        return "RESULT_MISSING", "file not found"
    try:
        st = os.stat(path)
    except OSError as e:
        return "RESULT_MISSING", f"cannot stat: {e}"
    if st.st_size <= 0:
        return "RESULT_INVALID", "file is empty"
    if started_at and st.st_mtime < started_at - FRESH_SLACK_S:
        return "RESULT_MISSING", (f"stale: last modified {util.local_str(st.st_mtime)}, before this run started "
                                  f"({util.local_str(started_at)})")
    return None, f"ok ({util.fmt_bytes(st.st_size)})"


def evaluate(expectations: list[dict], cwd: str, started_at: float | None) -> dict:
    results = []
    for exp in expectations:
        t = exp.get("type")
        r = {"type": t, "target": exp.get("path") or exp.get("pattern"), "ok": False, "code": None, "detail": ""}
        if t in ("file", "json"):
            path = _abs(cwd, exp["path"])
            code, detail = _check_file(path, started_at)
            r["file"] = path
            if code is None and t == "json":
                try:
                    data = json.loads(util.read_text_any(path))
                    problems = []
                    for k in exp.get("keys") or []:
                        try:
                            v = _get_dotted(data, k)
                        except KeyError:
                            problems.append(f"missing key '{k}'")
                            continue
                        if isinstance(v, bool) or not isinstance(v, (int, float)):
                            problems.append(f"'{k}' is not a number ({v!r})"[:200])
                        elif not math.isfinite(v):
                            problems.append(f"'{k}' is {v}")
                    if problems:
                        code, detail = "RESULT_INVALID", "; ".join(problems)
                    else:
                        detail = detail + ", valid JSON" + (f", keys {', '.join(exp['keys'])} finite"
                                                            if exp.get("keys") else "")
                except ValueError as e:
                    code, detail = "RESULT_INVALID", f"invalid JSON: {e}"[:300]
                except OSError as e:
                    code, detail = "RESULT_MISSING", f"cannot read: {e}"
            r.update(ok=code is None, code=code, detail=detail)
        elif t == "glob":
            pattern = _abs(cwd, exp["pattern"])
            matches = sorted(glob.glob(pattern, recursive=True))
            fresh = [m for m in matches if os.path.isfile(m) and os.path.getsize(m) > 0 and
                     (not started_at or os.path.getmtime(m) >= started_at - FRESH_SLACK_S)]
            if fresh:
                newest = max(fresh, key=os.path.getmtime)
                r.update(ok=True, detail=f"{len(fresh)} fresh match(es); newest {os.path.basename(newest)}",
                         file=newest)
            elif matches:
                r.update(code="RESULT_MISSING", detail=f"{len(matches)} match(es) but none written during this run")
            else:
                r.update(code="RESULT_MISSING", detail="no matching files")
        else:
            r.update(code="RESULT_INVALID", detail=f"unknown expectation type {t!r}")
        results.append(r)
    failed = [r for r in results if not r["ok"]]
    code = None
    if failed:
        code = "RESULT_MISSING" if any(r["code"] == "RESULT_MISSING" for r in failed) else "RESULT_INVALID"
    return {"configured": bool(expectations), "passed": not failed, "failure_code": code, "results": results}


def extract_metrics(validation: dict, limit: int = 30) -> dict:
    """Pull scalar metrics out of validated JSON result files for the report."""
    metrics = {}
    for r in validation.get("results", []):
        if r.get("type") != "json" or not r.get("file"):
            continue
        try:
            data = json.loads(util.read_text_any(r["file"]))
        except (OSError, ValueError):
            continue
        if not isinstance(data, dict):
            continue
        for k, v in data.items():
            if isinstance(v, (int, float)) and not isinstance(v, bool):
                metrics[k] = v
            elif isinstance(v, dict):
                for k2, v2 in v.items():
                    if isinstance(v2, (int, float)) and not isinstance(v2, bool):
                        metrics[f"{k}.{k2}"] = v2
            if len(metrics) >= limit:
                return metrics
    return metrics


def collect_attachments(paths, cwd: str, dest_dir: str, max_kb: int) -> list[dict]:
    """Snapshot small requested files into the run directory; large ones become references."""
    import shutil
    out = []
    os.makedirs(dest_dir, exist_ok=True)
    for p in paths or ():
        full = _abs(cwd, p)
        for f in (sorted(glob.glob(full)) or [full]):
            item = {"name": os.path.basename(f), "source": f}
            if not os.path.isfile(f):
                item["missing"] = True
                out.append(item)
                continue
            size = os.path.getsize(f)
            item["size"] = size
            if size <= max_kb * 1024:
                dst = os.path.join(dest_dir, item["name"])
                try:
                    shutil.copy2(f, dst)
                    item["attached"] = dst
                except OSError as e:
                    item["error"] = str(e)
            else:
                item["sha256"] = util.sha256_file(f)
                item["reference_only"] = True
            out.append(item)
    return out
