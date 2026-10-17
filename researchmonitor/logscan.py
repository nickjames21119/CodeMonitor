"""Find where a job writes its output, read it incrementally, and extract progress / metrics / signals.

No changes to the user's code are needed: we look at the job's redirected stdout (Linux), files it has
open, recently written log-like files in its working directory, and (Windows) its terminal window text.
"""
from __future__ import annotations

import math
import os
import re
import stat
import sys
from collections import deque

from . import util

LOG_EXTS = {".log", ".txt", ".out", ".err", ".csv", ".jsonl"}
LOG_DIRS = {"logs", "log", "output", "outputs", "runs", "results", "lightning_logs", "wandb", "checkpoints", "exp",
            "experiments", "save", "saved"}
SKIP_DIRS = {".git", "__pycache__", "node_modules", ".venv", "venv", "env", "envs", "site-packages", ".idea",
             ".vscode", ".ipynb_checkpoints", ".mypy_cache", ".pytest_cache", "dist", "build",
             "appdata", "application data", "library", "programdata", "program files", "program files (x86)",
             "windows", "$recycle.bin", "system volume information", "onedrive", "miniconda3", "anaconda3",
             "miniforge3", "mambaforge", ".conda", ".cache", ".local", "snap", "proc", "sys", "usr", "var"}

_ANSI = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]|\x1b\][^\x07]*\x07")
_NUM = r"[-+]?(?:\d+\.\d*|\.\d+|\d+)(?:[eE][-+]?\d+)?|nan|NaN|inf|Inf|-inf"
KV = re.compile(r"(?P<k>[A-Za-z][\w./@\-]{0,40})['\"]?\s*[:=]\s*['\"]?(?P<v>" + _NUM + r")(?![\w.])")
EPOCH_OF = re.compile(r"(?i)\bepoch\b[\s:=\[#]*(\d+)\s*(?:/|of)\s*(\d+)")
EPOCH = re.compile(r"(?i)['\"]?\bepoch\b['\"]?[\s:=\[#]*(\d+(?:\.\d+)?)")
TQDM = re.compile(r"(\d+)/(\d+)\s*\[(\d+(?::\d+){1,2})<(\d+(?::\d+){1,2})")
PCT = re.compile(r"(\d{1,3})%\|")
EVAL_CTX = re.compile(r"(?i)(\b(val|valid|validation|eval|evaluation|test|testing|dev|best|result|results|metrics?)\b"
                      r"|\b(val|eval|test|valid)_|验证|测试|评估|结果)")
METRIC_KEY = re.compile(r"(?i)(loss|acc|accuracy|f1|auc|roc|mrr|ndcg|hit|recall|precision|map\b|bleu|rouge|meteor|"
                        r"mae|rmse|mse|ppl|perplexity|top-?1|top-?5|iou|psnr|ssim|r2|score|reward|return|wer|cer|"
                        r"error|err\b|kl\b|elbo)")
NOT_METRIC = re.compile(r"(?i)^(lr|learning_rate|step|steps|global_step|it|iter|iteration|batch|bs|epoch|time|"
                        r"eta|seed|gpu|mem|memory|grad_norm|samples|tokens|num_\w+|n_\w+|id|pid|rank|world_size)$")
LOWER_IS_BETTER = re.compile(r"(?i)(loss|mae|rmse|mse|ppl|perplexity|wer|cer|error|err\b|kl\b)")
CKPT = re.compile(r"(?i)\b(saving|saved|save|wrote|writing|保存)\b[^\n]{0,40}\b(checkpoint|ckpt|model|weights|state_dict)")
MODEL_FILE = re.compile(r"(?i)[\w./\\:~-]*[\w-]\.(?:pt|pth|ckpt|bin|safetensors|h5|keras|pkl|npz|joblib|onnx)\b")
COMPLETE = re.compile(r"(?i)\b(training (is )?(complete|completed|finished|done)|finished training|all done|"
                      r"done\.?$|finished\.?$|completed\.?$|job (is )?(done|finished|complete)|test results?|"
                      r"final (result|results|metrics|score)s?|exiting normally|saved (final|best) model)\b|"
                      r"训练完成|运行完成|全部完成|已完成|结束$")
ERRORISH = re.compile(r"(?i)(traceback \(most recent call last\)|\berror\b|exception|out of memory|killed|"
                      r"segmentation fault|core dumped|aborted)")


def clean_line(line: str) -> str:
    line = _ANSI.sub("", line)
    if "\r" in line:
        line = line.rstrip("\r").rsplit("\r", 1)[-1]
    return line.rstrip()


def _to_float(v: str):
    try:
        return float(v)
    except ValueError:
        return None


def _hms(s: str) -> float:
    parts = [int(p) for p in s.split(":")]
    sec = 0
    for p in parts:
        sec = sec * 60 + p
    return float(sec)


class OutputAnalyzer:
    """Incremental parser over the job's output lines."""

    def __init__(self, max_tail: int = 400):
        self.tail: deque = deque(maxlen=max_tail)
        self.last_change: float | None = None
        self.train: dict = {}
        self.train_at: float | None = None
        self.evals: list = []                 # [(ts, epoch, {k: v})]
        self.best: dict = {}                  # k -> (value, ts, epoch)
        self.epoch: float | None = None
        self.epoch_total: int | None = None
        self.epoch_times: list = []           # (ts, epoch) when epoch value changes
        self.tqdm: dict | None = None         # {"done", "total", "elapsed", "remaining", "ts"}
        self.checkpoint: str | None = None
        self.checkpoint_at: float | None = None
        self.completion: list = []            # [(ts, line)]
        self._eval_keys: set = set()
        self.nan: tuple | None = None         # (ts, key, value, line)
        self.lines_seen = 0
        self.csv_header: dict = {}            # path -> header list

    # ------------------------------------------------------------------ feeding
    def feed(self, lines, ts: float, source: str = "") -> int:
        n = 0
        for raw in lines:
            line = clean_line(raw)
            if not line.strip():
                continue
            self.tail.append(line)
            self.lines_seen += 1
            self._parse(line, ts)
            n += 1
        if n:
            self.last_change = ts
        return n

    def feed_csv(self, path: str, lines, ts: float) -> None:
        """Lightning CSVLogger / custom metrics.csv: header + rows → metric records."""
        for raw in lines:
            line = raw.strip()
            if not line:
                continue
            cells = [c.strip() for c in line.split(",")]
            if not any(_to_float(c) is not None for c in cells if c):  # header row
                self.csv_header[path] = cells
                continue
            header = self.csv_header.get(path)
            if not header or len(header) != len(cells):
                continue
            rec = {h: _to_float(c) for h, c in zip(header, cells) if c and _to_float(c) is not None}
            self.last_change = ts
            ep = rec.get("epoch")
            if ep is not None:
                self._set_epoch(ep, ts)
            metrics = {k: v for k, v in rec.items() if METRIC_KEY.search(k) and not NOT_METRIC.match(k)}
            if any(EVAL_CTX.search(k) for k in metrics):
                self._add_eval(ts, metrics)
            elif metrics:
                self.train, self.train_at = metrics, ts

    def _set_epoch(self, ep: float, ts: float) -> None:
        if self.epoch is None or ep != self.epoch:
            self.epoch = ep
            self.epoch_times.append((ts, ep))
            self.epoch_times = self.epoch_times[-200:]

    def _parse(self, line: str, ts: float) -> None:
        m = EPOCH_OF.search(line)
        if m:
            ep, tot = int(m.group(1)), int(m.group(2))
            if 0 < tot < 100000 and ep <= tot + 1:
                self.epoch_total = tot
                self._set_epoch(float(ep), ts)
        else:
            m = EPOCH.search(line)
            if m:
                self._set_epoch(float(m.group(1)), ts)
        m = None
        for m in TQDM.finditer(line):
            pass
        if m:
            done, total = int(m.group(1)), int(m.group(2))
            if total > 0:
                self.tqdm = {"done": done, "total": total, "elapsed": _hms(m.group(3)),
                             "remaining": _hms(m.group(4)), "ts": ts}
        if CKPT.search(line):
            files = MODEL_FILE.findall(line)
            self.checkpoint = files[-1] if files else line.strip()[:200]
            self.checkpoint_at = ts
        if COMPLETE.search(line) and not any(c[1] == line[:300] for c in self.completion):
            self.completion.append((ts, line[:300]))
            self.completion = self.completion[-20:]
        kvs = {}
        for km in KV.finditer(line):
            k, v = km.group("k").strip("'\""), _to_float(km.group("v"))
            if v is None or NOT_METRIC.match(k) or not METRIC_KEY.search(k):
                continue
            kvs[k] = v
            if "loss" in k.lower() and not math.isfinite(v) and self.nan is None:
                self.nan = (ts, k, v, line[:300])
        if not kvs:
            return
        if EVAL_CTX.search(line):
            self._add_eval(ts, kvs)
        else:
            self.train, self.train_at = kvs, ts

    def _add_eval(self, ts: float, kvs: dict) -> None:
        rec = (ts, self.epoch, kvs)
        key = (self.epoch, frozenset(kvs.items()))
        if key in self._eval_keys:
            return  # the same record seen again (overlapping reads)
        self._eval_keys.add(key)
        if len(self._eval_keys) > 2000:
            self._eval_keys = set(list(self._eval_keys)[-1000:])
        self.evals.append(rec)
        self.evals = self.evals[-300:]
        for k, v in kvs.items():
            if not math.isfinite(v):
                continue
            lower = bool(LOWER_IS_BETTER.search(k))
            cur = self.best.get(k)
            if cur is None or (v < cur[0] if lower else v > cur[0]):
                self.best[k] = (v, ts, self.epoch)

    # ------------------------------------------------------------------ summaries
    def progress(self, now: float, started_at: float | None) -> dict:
        out = {}
        if self.epoch is not None:
            out["epoch"] = self.epoch
            if self.epoch_total:
                out["epoch_total"] = self.epoch_total
                out["fraction"] = min(1.0, self.epoch / self.epoch_total)
                # ETA from the pace of epoch changes
                if len(self.epoch_times) >= 2:
                    (t0, e0), (t1, e1) = self.epoch_times[0], self.epoch_times[-1]
                    if e1 > e0 and t1 > t0:
                        per = (t1 - t0) / (e1 - e0)
                        out["eta_s"] = max(0.0, (self.epoch_total - e1) * per - (now - t1))
                        out["epoch_s"] = per
        if self.tqdm and now - self.tqdm["ts"] < 600:
            out["bar"] = f"{self.tqdm['done']}/{self.tqdm['total']}"
            out.setdefault("eta_s", self.tqdm["remaining"])
            if "fraction" not in out:
                out["fraction"] = self.tqdm["done"] / self.tqdm["total"]
        return out

    def snapshot(self) -> dict:
        """JSON-serialisable state (persisted so a restarted agent can still write a good report)."""
        return {"train": self.train, "train_at": self.train_at, "evals": self.evals[-50:],
                "best": {k: list(v) for k, v in self.best.items()}, "epoch": self.epoch,
                "epoch_total": self.epoch_total, "checkpoint": self.checkpoint, "checkpoint_at": self.checkpoint_at,
                "completion": self.completion[-5:], "nan": list(self.nan) if self.nan else None,
                "last_change": self.last_change, "lines_seen": self.lines_seen}

    def restore(self, d: dict) -> None:
        if not d:
            return
        self.train = d.get("train") or {}
        self.train_at = d.get("train_at")
        self.evals = [tuple(x) for x in d.get("evals") or []]
        self._eval_keys = {(e[1], frozenset((e[2] or {}).items())) for e in self.evals}
        self.best = {k: tuple(v) for k, v in (d.get("best") or {}).items()}
        self.epoch, self.epoch_total = d.get("epoch"), d.get("epoch_total")
        self.checkpoint, self.checkpoint_at = d.get("checkpoint"), d.get("checkpoint_at")
        self.completion = [tuple(x) for x in d.get("completion") or []]
        self.nan = tuple(d["nan"]) if d.get("nan") else None
        self.last_change = d.get("last_change")
        self.lines_seen = d.get("lines_seen") or 0


# ---------------------------------------------------------------------------- sources

class FileTail:
    """Reads only newly appended bytes of a file."""

    def __init__(self, path: str, from_end: bool = True, backlog: int = 64 * 1024):
        self.path = path
        self.offset = 0
        self.buf = b""
        self.is_csv = path.lower().endswith(".csv")
        try:
            size = os.path.getsize(path)
            self.offset = max(0, size - backlog) if from_end else 0
            if self.is_csv:
                self.offset = 0 if size < 4 << 20 else size - backlog
        except OSError:
            pass

    def read_new(self, limit: int = 2 << 20) -> list[str]:
        try:
            size = os.path.getsize(self.path)
        except OSError:
            return []
        if size < self.offset:  # truncated / rotated
            self.offset, self.buf = 0, b""
        if size == self.offset:
            return []
        try:
            with open(self.path, "rb") as f:
                f.seek(max(self.offset, size - limit))
                data = f.read(limit)
        except OSError:
            return []
        self.offset = size
        self.buf += data
        *lines, self.buf = self.buf.split(b"\n")
        if len(self.buf) > 256 * 1024:  # very long progress-bar line without newline
            lines.append(self.buf)
            self.buf = b""
        text = util.decode_output(b"\n".join(lines))
        return text.split("\n") if text else []


def _is_regular(path: str) -> bool:
    try:
        return stat.S_ISREG(os.stat(path).st_mode)
    except OSError:
        return False


def _logish(path: str) -> bool:
    low = path.lower()
    if os.path.splitext(low)[1] not in LOG_EXTS:
        return False
    bad = ("\\windows\\", "/proc/", "/sys/", "\\appdata\\local\\temp\\", "/tmp/pip-", "site-packages",
           "\\programdata\\", "/usr/", "/var/lib/")
    return not any(b in low for b in bad)


def stdout_files(pid: int) -> list[str]:
    """Linux: the job's stdout/stderr when redirected to a file (`python x.py > log.txt`, nohup.out)."""
    out = []
    if sys.platform.startswith("linux"):
        for fd in (1, 2):
            try:
                target = os.readlink(f"/proc/{pid}/fd/{fd}")
            except OSError:
                continue
            if target.startswith("/") and _is_regular(target) and target not in out:
                out.append(target)
    return out


def open_log_files(proc) -> list[str]:
    """Log-like files the process currently has open (works on Windows and Linux)."""
    try:
        files = proc.open_files()
    except Exception:
        return []
    out = []
    for f in files:
        p = getattr(f, "path", None)
        if p and _logish(p) and p not in out:
            out.append(p)
    return out[:8]


def recent_files_in(cwd: str, since: float, max_entries: int = 1500, max_depth: int = 3,
                    exts=None, limit: int = 10) -> list[tuple]:
    """Files under cwd modified at/after `since` (bounded scan). Returns [(path, mtime, size)] newest first."""
    if not cwd or not os.path.isdir(cwd):
        return []
    found = []
    seen = 0
    stack = [(cwd, 0)]
    while stack and seen < max_entries:
        d, depth = stack.pop()
        try:
            with os.scandir(d) as it:
                for e in it:
                    seen += 1
                    if seen >= max_entries:
                        break
                    try:
                        if e.is_dir(follow_symlinks=False):
                            if (depth < max_depth and e.name.lower() not in SKIP_DIRS and not e.name.startswith(".")
                                    and not e.name.startswith("$")):
                                stack.append((e.path, depth + 1))
                            continue
                        if exts and os.path.splitext(e.name)[1].lower() not in exts:
                            continue
                        st = e.stat(follow_symlinks=False)
                        if st.st_mtime >= since:
                            found.append((e.path, st.st_mtime, st.st_size))
                    except OSError:
                        continue
        except OSError:
            continue
    found.sort(key=lambda x: -x[1])
    return found[:limit]


def work_dir(cwd: str | None, cmdline: list) -> str | None:
    """Folder to look in for the job's logs and outputs. Terminals often start in the home folder or a drive
    root (`python D:\\proj\\train.py` run from C:\\Users\\me); scanning those would pick up unrelated files,
    so use the script's folder instead."""
    from .discovery import SCRIPT_EXT
    home = os.path.normcase(os.path.abspath(os.path.expanduser("~")))
    c = os.path.normcase(os.path.abspath(cwd)) if cwd else None
    broad = c is None or c == home or os.path.dirname(c) == c or len(c.rstrip("\\/")) <= 3
    if not broad:
        return cwd
    for a in (cmdline or [])[1:]:
        if SCRIPT_EXT.search(a):
            p = a if os.path.isabs(a) else os.path.join(cwd or "", a)
            d = os.path.dirname(os.path.abspath(p))
            dn = os.path.normcase(d)
            if os.path.isdir(d) and dn != home and os.path.dirname(dn) != dn:
                return d
    return None  # nothing safe to scan


def candidate_logs(proc, cwd: str, started_at: float, now: float) -> list[str]:
    """Best guesses for the job's log files, most specific first."""
    paths = []
    for p in stdout_files(proc.pid) + open_log_files(proc):
        if p not in paths:
            paths.append(p)
    for p, mtime, size in recent_files_in(cwd, max(started_at - 60, now - 900), exts=LOG_EXTS, limit=6):
        if size > 0 and p not in paths and _logish(p):
            paths.append(p)
    return paths[:6]
