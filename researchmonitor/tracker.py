"""Follow one automatically detected program until it ends, then write its single report.

Per sampling tick (default 15 s) the job is put into one run-state from CPU / GPU / disk I/O and output
activity; consecutive identical states form a timeline. Output (log files, terminal text) is parsed for
progress and metrics. At the end, every piece of evidence goes to infer.infer_end().
"""
from __future__ import annotations

import os
import sys
import time
from collections import deque

import psutil

from . import classify, engine, identity, infer, logscan, notify, render, store, util, winconsole
from .resources import Peaks, TreeSampler, attribute_gpu, disk_free, uses_cuda

IS_WIN = sys.platform == "win32"



# --------------------------------------------------------------------------- Windows exit code of a non-child

class ExitWatcher:
    """Holds a handle to the job's process on Windows. The process object (and its exit code) stays
    readable after the process ends as long as we hold the handle; it also pins the PID (no reuse)."""

    SYNCHRONIZE = 0x00100000
    QUERY_LIMITED = 0x1000

    def __init__(self, pid: int, create_time: float | None):
        self.h = None
        if not IS_WIN:
            return
        try:
            import ctypes
            from ctypes import wintypes as W
            k = ctypes.WinDLL("kernel32", use_last_error=True)
            k.OpenProcess.restype = W.HANDLE
            k.OpenProcess.argtypes = [W.DWORD, W.BOOL, W.DWORD]
            k.GetExitCodeProcess.argtypes = [W.HANDLE, ctypes.POINTER(W.DWORD)]
            k.WaitForSingleObject.argtypes = [W.HANDLE, W.DWORD]
            k.WaitForSingleObject.restype = W.DWORD
            k.CloseHandle.argtypes = [W.HANDLE]
            k.GetProcessTimes.argtypes = [W.HANDLE] + [ctypes.POINTER(W.FILETIME)] * 4
            self._k, self._W, self._ct = k, W, ctypes
            h = k.OpenProcess(self.SYNCHRONIZE | self.QUERY_LIMITED, False, pid)
            if not h:
                return
            # make sure the handle is for the process we saw (not a PID reused in between)
            c, e, kk, u = W.FILETIME(), W.FILETIME(), W.FILETIME(), W.FILETIME()
            if k.GetProcessTimes(h, ctypes.byref(c), ctypes.byref(e), ctypes.byref(kk), ctypes.byref(u)):
                ft = (c.dwHighDateTime << 32) | c.dwLowDateTime
                started = ft / 1e7 - 11644473600.0
                if create_time and abs(started - create_time) > 2:
                    k.CloseHandle(h)
                    return
            self.h = h
        except Exception:
            self.h = None

    def exited(self) -> bool | None:
        if not self.h:
            return None
        return self._k.WaitForSingleObject(self.h, 0) == 0  # WAIT_OBJECT_0

    def exit_code(self) -> int | None:
        if not self.h:
            return None
        code = self._W.DWORD(0)
        if self._k.GetExitCodeProcess(self.h, self._ct.byref(code)) and code.value != 259:  # STILL_ACTIVE
            return int(code.value)  # unsigned, e.g. 0xC000013A for Ctrl+C; classify.describe_exit decodes it
        return None

    def close(self) -> None:
        if self.h:
            try:
                self._k.CloseHandle(self.h)
            except Exception:
                pass
            self.h = None


# --------------------------------------------------------------------------- tracker

class JobTracker:
    def __init__(self, agent, *, pid: int, token: str | None, info: dict, mode: str = "auto",
                 run_row=None, detect: dict | None = None):
        self.agent = agent
        self.cfg = agent.cfg
        self.lang = self.cfg.get("general.language") or "zh"
        self.pid = pid
        self.token = token
        self.mode = mode                         # auto | interactive
        self.info = info                         # cmdline, cwd, exe, name, create_time, parents
        self.cwd = info.get("cwd")
        self.wdir = logscan.work_dir(self.cwd, info.get("cmdline") or [])  # where to look for logs / outputs
        self.sampler = TreeSampler(pid)
        self.analyzer = logscan.OutputAnalyzer()
        self.tails: dict = {}
        self.console_pids = [pid] + list(info.get("parent_pids") or [])[:2]
        self.console_ok = None if (IS_WIN and self.cfg.get("discovery.console_capture", True)) else False
        self.console_prev: list = []
        self.console_fail = 0
        self.tmux = None
        self.samples: deque = deque(maxlen=240)
        self.timeline: list = []
        self.anomalies: list = []
        self.peaks = Peaks()
        self.state = "START"
        self.has_computed = False
        self.idle_since = None
        self.stall_alerted = False
        self.last_io = None
        self.last_out_change = None
        self.inter_sent_at = None
        self.inter_sent_evals = 0
        self.nan_alerted = False
        self.t_sample = self.t_out = self.t_console = self.t_persist = self.t_logdisc = 0.0
        self.ended = False
        self.started_at = info.get("create_time") or util.now()
        self.exitw = ExitWatcher(pid, info.get("create_time"))
        self.episode_start = None
        self.observed_from = None
        self.cuda_loaded = False
        self.cuda_checked_at = 0.0
        self.detect = detect or {}
        if run_row is not None:
            self.run_id = run_row["run_id"]
            self._restore(run_row)
        else:
            self.run_id = self._create_run()
        if not IS_WIN and self.cfg.get("discovery.console_capture", True):
            try:
                self.tmux = winconsole.tmux_target(psutil.Process(pid))
            except psutil.Error:
                self.tmux = None

    # ------------------------------------------------------------------ records
    def _create_run(self) -> str:
        conn = self.agent.conn
        cmd = self.info.get("cmdline") or [self.info.get("name") or str(self.pid)]
        name = self.info.get("display") or _display_name(cmd, self.mode)
        run_id = util.new_run_id(name)
        run_dir = os.path.join(self.agent.runs_dir, run_id)
        os.makedirs(run_dir, exist_ok=True)
        hid, bid = identity.host_id(conn), identity.boot_id()
        with store.tx(conn):
            store.insert_run(conn, run_id=run_id, name=name, project=name, mode=self.mode, priority="normal",
                             tags="[]", command=util.json_dumps(cmd), cwd=self.cwd, host_id=hid, boot_id=bid,
                             status="RUNNING", status_authority=store.AUTH_OBSERVED, created_at=util.now(),
                             started_at=self.started_at, run_dir=run_dir, pid=self.pid, pid_token=self.token,
                             supervisor_pid=os.getpid(), supervisor_token=identity.proc_token(os.getpid()),
                             supervisor_seen_at=util.now(), spec="{}", detect=util.json_dumps(self.detect))
            store.add_event(conn, "AUTO_DETECTED", run_id, source="discovery",
                            payload={"pid": self.pid, "score": self.detect.get("score"),
                                     "reasons": self.detect.get("reasons")})
        self.run_dir = run_dir
        return run_id

    def _restore(self, row) -> None:
        self.run_dir = row["run_dir"]
        prof = util.json_loads(row["profile"], {}) or {}
        self.timeline = prof.get("timeline") or []
        self.anomalies = prof.get("anomalies") or []
        self.analyzer.restore(prof.get("output") or {})
        for ln in prof.get("tail") or []:
            self.analyzer.tail.append(ln)
        self.peaks.d.update(util.json_loads(row["resources"], {}) or {})
        self.has_computed = bool(prof.get("has_computed"))
        self.inter_sent_at = prof.get("inter_sent_at")
        self.inter_sent_evals = prof.get("inter_sent_evals") or 0
        self.stall_alerted = bool(prof.get("stall_alerted"))
        self.nan_alerted = bool(prof.get("nan_alerted"))
        self.detect = util.json_loads(row["detect"], {}) or {}
        self.episode_start = prof.get("episode_start")
        self.observed_from = prof.get("observed_from")

    def tree_pids(self) -> set:
        pids = set(self.sampler.pids())
        pids.add(self.pid)
        return pids

    # ------------------------------------------------------------------ liveness
    def alive(self) -> bool:
        ex = self.exitw.exited()
        if ex is not None:
            return not ex
        return identity.is_alive(self.pid, self.token)

    # ------------------------------------------------------------------ sampling
    def sample(self, now: float, snap: dict | None) -> None:
        s = self.sampler.sample(io=True)
        pids = self.tree_pids()
        g = attribute_gpu(snap, pids)
        if snap and snap.get("gpus") and not g.get("on_gpu") and now - self.cuda_checked_at >= 600:
            # driver did not attribute a GPU process to us (common on Windows/WDDM): look at loaded libraries
            self.cuda_checked_at = now
            self.cuda_loaded = any(uses_cuda(p) for p in list(pids)[:8])
        if not g.get("on_gpu") and self.cuda_loaded:
            g = attribute_gpu(snap, pids, assume_on_gpu=True)
        io_rate = 0.0
        if self.last_io is not None and now > self.last_io[1]:
            io_rate = max(0.0, (s["io_bytes"] - self.last_io[0]) / (now - self.last_io[1]))
        self.last_io = (s["io_bytes"], now)
        out_changed = self.last_out_change is not None and now - self.last_out_change < 60
        gpu_util = g.get("gpu_util") or 0
        first = not self.samples and not self.timeline  # psutil's first CPU reading is a 0 % baseline
        if first:
            state = "START"
        elif s.get("root_status") == psutil.STATUS_STOPPED:
            state = "PAUSED"
        elif g.get("on_gpu") and gpu_util >= (10 if g.get("gpu_util_scope") == "process" else 20):
            state = "GPU"
        elif s["cpu"] >= 50:
            state = "CPU"
        elif io_rate >= 5e6:
            state = "IO"
        elif s["cpu"] >= 5 or out_changed:
            state = "LIGHT"
        else:
            state = "IDLE"
        if state in ("GPU", "CPU"):
            self.has_computed = True
        rec = {"ts": now, "cpu": s["cpu"], "rss": s["rss"], "sys_mem": s["sys_mem"], "state": state,
               "gpu_util": g.get("gpu_util"), "gpu_mem": g.get("gpu_mem"), "gpu_mem_total": g.get("gpu_mem_total"),
               "io": io_rate, "nproc": s["nproc"]}
        self.samples.append(rec)
        if first:
            self.timeline.append(["START", self.started_at, now, 0, 0.0, 0.0])
            self.observed_from = now
            return
        self._timeline_add(state, now, rec)
        self.state = state
        self.peaks.update(peak_rss=s["rss"], peak_cpu=s["cpu"], peak_sys_mem=s["sys_mem"],
                          peak_gpu_mem=g.get("gpu_mem"), peak_gpu_util=g.get("gpu_util"),
                          peak_gpu_temp=g.get("gpu_temp"), gpu_mem_scope=g.get("gpu_mem_scope"),
                          gpu_mem_total=g.get("gpu_mem_total"), gpu_names=g.get("gpu_names") or None,
                          sys_mem_total=s.get("sys_mem_total"), last_state=state, nproc=s["nproc"],
                          peak_io=io_rate, gpu_backend=(snap or {}).get("backend"))
        self._anomalies(now, s, g)
        self._stall(now, state)
        with store.tx(self.agent.conn):
            store.add_sample(self.agent.conn, self.run_id, {"ts": now, "cpu": s["cpu"], "rss": s["rss"],
                                                            "nproc": s["nproc"], "threads": s["threads"],
                                                            "sys_mem": s["sys_mem"], "gpu_util": g.get("gpu_util"),
                                                            "gpu_mem": g.get("gpu_mem"),
                                                            "disk_free": None})
            store.update_run(self.agent.conn, self.run_id, resources=util.json_dumps(self.peaks.to_dict()),
                             supervisor_seen_at=now, health=state)

    def _timeline_add(self, state: str, now: float, rec: dict) -> None:
        tl = self.timeline
        if tl and tl[-1][0] == state:
            seg = tl[-1]
            seg[2] = now
            seg[3] += 1
            seg[4] += rec["cpu"] or 0
            seg[5] += rec.get("gpu_util") or 0
        else:
            start = tl[-1][2] if tl else (self.samples[0]["ts"] if self.samples else now)
            tl.append([state, start, now, 1, rec["cpu"] or 0, rec.get("gpu_util") or 0])
        if len(tl) > 400:  # merge the shortest neighbouring segments to stay bounded
            del tl[1]

    def _note(self, now: float, kind: str, text: str) -> None:
        self.anomalies.append([now, kind, text])
        del self.anomalies[:-40]

    def _anomalies(self, now: float, s: dict, g: dict) -> None:
        def note(kind, text):
            if not any(a[1] == kind and now - a[0] < 1800 for a in self.anomalies):
                self._note(now, kind, text)
        if s["sys_mem"] >= 95:
            note("RESOURCE_MEMORY", f"system memory {s['sys_mem']:.0f}%")
        pct = (100.0 * g["gpu_mem"] / g["gpu_mem_total"]) if g.get("gpu_mem") and g.get("gpu_mem_total") else None
        if pct is not None and pct >= 98:
            note("GPU_MEM_FULL", f"GPU memory {pct:.0f}% used")
        if (g.get("gpu_temp") or 0) >= float(self.cfg.get("monitor.gpu_temp_warn_c", 90) or 999):
            note("RESOURCE_GPU_TEMP", f"GPU {g.get('gpu_temp'):.0f}°C")
        free = disk_free(self.cwd) if self.cwd else None
        if free is not None and free < float(self.cfg.get("monitor.disk_free_warn_gb", 5) or 0) * 1e9:
            note("RESOURCE_DISK", f"only {util.fmt_bytes(free)} disk free")

    def _stall(self, now: float, state: str) -> None:
        if self.mode != "auto":
            return
        if state == "IDLE":
            self.idle_since = self.idle_since or now
        else:
            if self.stall_alerted:
                self._note(now, "STALL_CLEARED", "activity resumed")
            self.idle_since = None
            self.stall_alerted = False
            return
        after = util.parse_duration(self.cfg.get("monitor.stall_after", "30m")) or 0
        if after and self.has_computed and not self.stall_alerted and now - self.idle_since >= after:
            self.stall_alerted = True
            text = (f"no CPU/GPU activity and no new output for {util.fmt_duration(now - self.idle_since)} "
                    f"(was computing before); the program is still running and was NOT stopped")
            self._note(now, "SUSPECTED_STALL", text)
            if "stall" in (self.cfg.get("notify.mid_run_alerts") or []):
                self._send_intermediate(now, alert=("SUSPECTED_STALL", text))

    # ------------------------------------------------------------------ outputs
    def read_outputs(self, now: float) -> None:
        if now - self.t_logdisc >= 300 or not self.tails:
            self.t_logdisc = now
            try:
                proc = psutil.Process(self.pid)
                for p in logscan.candidate_logs(proc, self.wdir, self.started_at, now):
                    if p not in self.tails and len(self.tails) < 4:
                        self.tails[p] = logscan.FileTail(p)
            except psutil.Error:
                pass
        for path, tail in list(self.tails.items()):
            lines = tail.read_new()
            if not lines:
                continue
            if tail.is_csv:
                self.analyzer.feed_csv(path, lines, now)
            else:
                self.analyzer.feed(lines, now, path)
            self.last_out_change = now
        self._check_nan(now)

    def read_console(self, now: float, final: bool = False) -> bool:
        rows = None
        if self.console_ok is not False and IS_WIN:
            pids = self.console_pids[1:] if final else self.console_pids
            rows = winconsole.read_windows_console(pids or self.console_pids)
            if rows is None:
                self.console_fail += 1
                if self.console_fail >= 3 and not self.console_ok:
                    self.console_ok = False  # no console (pythonw, service, IDE without a console)
            else:
                self.console_ok = True
        elif self.tmux:
            rows = winconsole.read_tmux(self.tmux)
        if not rows:
            return False
        fresh = winconsole.new_lines(self.console_prev, rows)
        self.console_prev = rows
        if fresh:
            self.analyzer.feed(fresh, now, "console")
            self.last_out_change = now
        self._check_nan(now)
        return True

    def _check_nan(self, now: float) -> None:
        if self.analyzer.nan and not self.nan_alerted:
            self.nan_alerted = True
            ts, k, v, line = self.analyzer.nan
            text = f"{k} = {v}: {line}"
            self._note(now, "NAN_LOSS", text)
            if "nan" in (self.cfg.get("notify.mid_run_alerts") or []):
                self._send_intermediate(now, alert=("NAN_LOSS", text))

    @property
    def output_readable(self) -> bool:
        return bool(self.tails) or bool(self.console_ok) or bool(self.tmux)

    # ------------------------------------------------------------------ intermediate results
    def maybe_intermediate(self, now: float) -> None:
        if self.mode != "auto":
            return
        spec = str(self.cfg.get("notify.intermediate", "2h") or "off").strip().lower()
        if spec in ("off", "0", "none", "false", ""):
            return
        n = len(self.analyzer.evals)
        if n <= self.inter_sent_evals:
            return
        interval = 300.0 if spec == "each" else (util.parse_duration(spec) or 7200)
        first_after = util.parse_duration(self.cfg.get("notify.intermediate_first_after", "15m"))
        if self.inter_sent_at is None:
            if now - self.started_at < min(first_after if first_after is not None else 900, interval):
                return
        elif now - self.inter_sent_at < interval:
            return
        self._send_intermediate(now)

    def _send_intermediate(self, now: float, alert=None) -> None:
        conn = self.agent.conn
        run = store.get_run(conn, self.run_id)
        if run is None:
            return
        content = render.intermediate_report(self.cfg, run, self.view(now), alert=alert)
        kind = "alert" if alert else "intermediate"
        with store.tx(conn):
            notify.enqueue(conn, self.cfg, group_key=f"run:{self.run_id}:{kind}:{int(now)}", kind="intermediate",
                           severity="P2" if alert else "P3", content=content, run_id=self.run_id,
                           channels=notify.channels_for(self.cfg, "P2" if alert else "P3"))
            store.add_event(conn, "ALERT_" + alert[0] if alert else "INTERMEDIATE_SENT", self.run_id,
                            source="tracker", payload={"evals": len(self.analyzer.evals)})
        if not alert:
            self.inter_sent_at = now
            self.inter_sent_evals = len(self.analyzer.evals)

    # ------------------------------------------------------------------ views / persistence
    def view(self, now: float) -> dict:
        """Everything the reports and dashboard need, in one dict."""
        return {"timeline": self.timeline, "anomalies": self.anomalies, "state": self.state,
                "samples": list(self.samples)[-40:], "output": self.analyzer.snapshot(),
                "progress": self.analyzer.progress(now, self.started_at),
                "tail": list(self.analyzer.tail)[-60:], "detect": self.detect, "info": self.info,
                "output_readable": self.output_readable,
                "sources": list(self.tails) + (["terminal window"] if self.console_ok else []) +
                           (["tmux pane"] if self.tmux else []),
                "has_computed": self.has_computed, "episode_start": self.episode_start,
                "observed_from": self.observed_from}

    def persist(self, now: float) -> None:
        prof = self.view(now)
        prof.pop("samples", None)
        prof.update(inter_sent_at=self.inter_sent_at, inter_sent_evals=self.inter_sent_evals,
                    stall_alerted=self.stall_alerted, nan_alerted=self.nan_alerted)
        prog = prof["progress"]
        last_prog = dict(self.analyzer.train or {})
        if prog.get("epoch") is not None:
            last_prog["epoch"] = prog["epoch"] if not prog.get("epoch_total") else \
                f"{prog['epoch']:g}/{prog['epoch_total']}"
        if prog.get("eta_s") is not None:
            last_prog["ETA"] = util.fmt_duration(prog["eta_s"])
        with store.tx(self.agent.conn):
            store.update_run(self.agent.conn, self.run_id, profile=util.json_dumps(prof),
                             last_progress=util.json_dumps(last_prog) if last_prog else None,
                             last_progress_at=self.analyzer.last_change)

    # ------------------------------------------------------------------ the end
    def finish(self, now: float, *, rebooted: bool = False, reboot_reason: str | None = None,
               agent_gap: bool = False, episode_end: bool = False) -> None:
        if self.ended:
            return
        self.ended = True
        exit_code = None if episode_end else self.exitw.exit_code()
        if not rebooted and not agent_gap:
            try:
                self.read_outputs(now)
            except Exception:
                pass
            if IS_WIN or self.tmux:
                try:
                    self.read_console(now, final=not episode_end)
                except Exception:
                    pass
        self.exitw.close()
        files = []
        if self.wdir and not rebooted:
            try:
                files = logscan.recent_files_in(self.wdir, self.started_at, max_entries=3000, limit=12)
            except Exception:
                files = []
        end_ts = now if not (rebooted or agent_gap) else (self.samples[-1]["ts"] if self.samples else now)
        prog = self.analyzer.progress(end_ts, self.started_at)
        lines = list(self.analyzer.tail)
        conn = self.agent.conn
        stored = store.samples_for(conn, self.run_id, 400)
        samples = list(self.samples) or [{"ts": r["ts"], "cpu": r["cpu"], "rss": r["rss"], "sys_mem": r["sys_mem"],
                                          "gpu_util": r["gpu_util"], "gpu_mem": r["gpu_mem"], "state": None}
                                         for r in stored[-20:]]
        if episode_end:
            dur = (self.timeline[-1][2] - (self.episode_start or self.started_at)) if self.timeline else 0
            verdict = {"status": "SUCCEEDED_UNVERIFIED", "code": None, "confidence": "high",
                       "verdict": ("计算段结束（进程仍在运行），用时 " if self.lang == "zh" else
                                   "Computation burst finished (session still open) after ") + util.fmt_duration(dur),
                       "evidence": [("CPU/GPU 回到空闲已超过 2 分钟" if self.lang == "zh" else
                                     "CPU/GPU idle for more than 2 minutes")], "summary": "episode finished"}
        else:
            verdict = infer.infer_end({
                "exit_code": exit_code, "exit_known": exit_code is not None, "lines": lines, "samples": samples,
                "end_ts": end_ts, "started_ts": self.started_at, "rebooted": rebooted, "reboot_reason": reboot_reason,
                "completion": self.analyzer.completion, "files": [(_rel(p, self.wdir), m, s) for p, m, s in files],
                "progress": prog, "output_readable": self.output_readable,
                "stalled_before_end": self.stall_alerted and self.state == "IDLE",
            }, self.lang)
            if agent_gap:
                verdict["evidence"].insert(0, ("监控程序当时没有运行，结束时间按最后一次观测计" if self.lang == "zh" else
                                               "the monitor was not running when the job ended; end time = last observation"))
                if verdict["confidence"] == "high" and not rebooted:
                    verdict["confidence"] = "medium"
        tail_text = "\n".join(lines[-400:])
        try:
            with open(os.path.join(self.run_dir, "output_tail.txt"), "w", encoding="utf-8") as f:
                from .redact import redact
                f.write(redact(tail_text))
        except OSError:
            pass
        final_exc, tb = classify.extract_traceback(lines)
        profile = self.view(end_ts)
        profile["files"] = [(_rel(p, self.wdir), m, s) for p, m, s in files]
        profile["verdict"] = verdict
        profile.pop("samples", None)
        metrics = {k: v[0] for k, v in self.analyzer.best.items()}
        status = verdict["status"]
        engine.finalize_auto(conn, self.cfg, self.run_id, {
            "status": status, "authority": store.AUTH_SUPERVISOR if exit_code is not None else store.AUTH_OBSERVED,
            "exit_code": exit_code,
            "exit_desc": classify.describe_exit(exit_code) if exit_code is not None else "unknown",
            "failure_code": verdict.get("code"), "failure_summary": verdict.get("summary"),
            "evidence": {"verdict": verdict["verdict"], "confidence": verdict["confidence"],
                         "evidence": verdict["evidence"], "final_exception": final_exc, "traceback": tb[-40:]},
            "metrics": metrics, "ended_at": end_ts, "profile": profile, "episode": episode_end,
        })


def _rel(p: str, base: str | None) -> str:
    try:
        return os.path.relpath(p, base) if base else p
    except ValueError:  # different drive on Windows
        return p


def _display_name(cmd: list, mode: str) -> str:
    from .discovery import SCRIPT_EXT
    if mode == "interactive":
        return "notebook"
    for i, a in enumerate(cmd[1:], 1):
        if a == "-m" and i + 1 < len(cmd):
            return cmd[i + 1].split(".")[-1] if cmd[i + 1] not in ("torch.distributed.run",) else \
                next((os.path.splitext(os.path.basename(x))[0] for x in cmd[i + 2:] if SCRIPT_EXT.search(x)), "torchrun")
        if SCRIPT_EXT.search(a):
            return os.path.splitext(os.path.basename(a))[0]
    return os.path.splitext(os.path.basename(cmd[0]))[0] if cmd else "job"
