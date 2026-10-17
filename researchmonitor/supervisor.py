"""Per-run supervisor process.

One small detached process per run. It launches the job (managed mode) or observes an existing process
(attach / adopt mode), samples resources, watches progress, raises warnings, and on termination records
the authoritative outcome and queues notifications. It is detached from the terminal so closing the
terminal or GUI never kills the job or its monitor.

The job's stdout/stderr go straight to a log file (no pipes): nothing can deadlock on a full pipe, and
the job keeps running even if this supervisor dies.
"""
from __future__ import annotations

import json
import math
import os
import shutil
import signal
import statistics
import subprocess
import sys
import threading
import time
import traceback
from collections import deque

import psutil

from . import classify, engine, heartbeat, identity, store, util, validators
from .config import load_config, runs_dir
from .resources import GpuSampler, Peaks, TreeSampler, disk_free, summarize_gpu

IS_WIN = sys.platform == "win32"
DETACHED_PROCESS = 0x00000008
CREATE_NEW_PROCESS_GROUP = 0x00000200
CREATE_BREAKAWAY_FROM_JOB = 0x01000000
CREATE_NO_WINDOW = 0x08000000


# --------------------------------------------------------------------------- spawning

def spawn_supervisor(spec_path: str, run_dir: str) -> int:
    """Start a detached supervisor; returns its PID.

    On Windows it runs as python.exe with DETACHED_PROCESS (no console window); every process it starts
    itself uses CREATE_NO_WINDOW so no console windows pop up either.
    """
    cmd = [sys.executable, "-m", "researchmonitor.supervisor", spec_path]
    log = open(os.path.join(run_dir, "supervisor.log"), "ab")
    env = dict(os.environ)
    # make sure the package that launched us is importable even when run from a source checkout
    pkg_parent = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    env["PYTHONPATH"] = pkg_parent + (os.pathsep + env["PYTHONPATH"] if env.get("PYTHONPATH") else "")
    kwargs = dict(stdin=subprocess.DEVNULL, stdout=log, stderr=log, close_fds=True, cwd=run_dir, env=env)
    try:
        if IS_WIN:
            flags = DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP
            try:  # escape terminals that kill their whole job object on close
                p = subprocess.Popen(cmd, creationflags=flags | CREATE_BREAKAWAY_FROM_JOB, **kwargs)
            except OSError:
                p = subprocess.Popen(cmd, creationflags=flags, **kwargs)
        else:
            p = subprocess.Popen(cmd, start_new_session=True, **kwargs)
    finally:
        log.close()
    return p.pid


def resolve_program(prog: str, cwd: str, env: dict) -> str:
    """Find the program the way the user's shell would, relative to the *job's* directory.

    The supervisor itself runs in the run directory, and on Windows CreateProcess resolves relative
    names against the parent's directory rather than Popen's cwd= — so resolve explicitly.
    """
    path_env = env.get("PATH") or env.get("Path") or os.environ.get("PATH", "")
    has_sep = os.sep in prog or (os.altsep and os.altsep in prog)
    if has_sep and not os.path.isabs(prog):
        cand = os.path.join(cwd, prog)
        found = shutil.which(cand) if IS_WIN else (cand if os.path.exists(cand) else None)
        return found or cand
    if has_sep:
        return prog
    search = (cwd + os.pathsep + path_env) if IS_WIN else path_env  # Windows also searches the current dir
    return shutil.which(prog, path=search) or prog


def job_env(env: dict) -> dict:
    """Environment for the job: never pass rmon's own credentials on to user code."""
    return {k: v for k, v in env.items() if not k.upper().startswith("RMON_SECRET")}


def write_spec(run_dir: str, spec: dict) -> str:
    path = os.path.join(run_dir, "spec.json")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)  # may contain environment variables
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(spec, f, ensure_ascii=False)
    return path


def spawn_adopter(run_id: str) -> int:
    run_dir = os.path.join(runs_dir(), run_id)
    os.makedirs(run_dir, exist_ok=True)
    path = write_spec(run_dir, {"run_id": run_id, "mode": "adopt"})
    return spawn_supervisor(path, run_dir)


# --------------------------------------------------------------------------- sleep prevention (Windows)

def _set_exec_state(keep_awake: bool) -> None:
    if not IS_WIN:
        return
    try:
        import ctypes
        ES_CONTINUOUS, ES_SYSTEM_REQUIRED = 0x80000000, 0x00000001
        ctypes.windll.kernel32.SetThreadExecutionState(ES_CONTINUOUS | (ES_SYSTEM_REQUIRED if keep_awake else 0))
    except Exception:
        pass


# --------------------------------------------------------------------------- process-tree termination

def terminate_tree(pid: int, grace: float = 10.0) -> str:
    try:
        root = psutil.Process(pid)
        procs = [root] + root.children(recursive=True)
    except psutil.Error:
        return "already gone"
    if not IS_WIN:
        try:  # polite first: SIGINT to the job's process group lets Python save/cleanup
            os.killpg(pid, signal.SIGINT)
            _, alive = psutil.wait_procs(procs, timeout=grace)
            if not alive:
                return "SIGINT"
            procs = alive
        except (OSError, psutil.Error):
            pass
    for p in reversed(procs):
        try:
            p.terminate()
        except psutil.Error:
            pass
    _, alive = psutil.wait_procs(procs, timeout=grace)
    for p in alive:
        try:
            p.kill()
        except psutil.Error:
            pass
    psutil.wait_procs(alive, timeout=5)
    return "terminate" if not alive else "kill"


# --------------------------------------------------------------------------- progress tail

class ProgressTail:
    def __init__(self, path: str | None):
        self.path = path
        self.offset = 0
        self.buf = b""
        self.count = 0
        self.last = None
        self.last_at = None
        self.arrivals: deque = deque(maxlen=50)
        self.results: dict = {}
        self.checkpoint = None
        self.nan_seen = None
        self.stop_aware = False

    def poll(self) -> int:
        if not self.path or not os.path.exists(self.path):
            return 0
        try:
            size = os.path.getsize(self.path)
            if size < self.offset:
                self.offset, self.buf = 0, b""
            if size == self.offset:
                return 0
            with open(self.path, "rb") as f:
                f.seek(self.offset)
                data = f.read(min(size - self.offset, 4 << 20))
            self.offset += len(data)
        except OSError:
            return 0
        self.buf += data
        *lines, self.buf = self.buf.split(b"\n")
        n = 0
        t = util.now()
        for raw in lines:
            raw = raw.strip()
            if not raw:
                continue
            try:
                rec = json.loads(raw.decode("utf-8", "replace"))
            except ValueError:
                continue
            if not isinstance(rec, dict):
                continue
            kind = rec.get("_type", "progress")
            if kind == "stop_aware":
                self.stop_aware = True
                continue
            if kind == "result":
                self.results.update({k: v for k, v in rec.items() if not k.startswith("_")})
                continue
            if kind == "message":
                continue
            if rec.get("checkpoint"):
                self.checkpoint = rec["checkpoint"]
            if kind == "checkpoint":
                rec = dict(self.last or {}, checkpoint=rec["checkpoint"], _ts=rec.get("_ts"))
            self.last = rec
            self.last_at = t
            self.count += 1
            self.arrivals.append(t)
            n += 1
            for k, v in rec.items():
                if "loss" in str(k).lower() and _is_nan_like(v):
                    self.nan_seen = (k, v)
        return n

    def median_interval(self) -> float | None:
        a = list(self.arrivals)
        if len(a) < 4:
            return None
        gaps = [b - x for x, b in zip(a, a[1:]) if b - x > 0.5]
        return statistics.median(gaps) if len(gaps) >= 3 else None


def _is_nan_like(v) -> bool:
    if isinstance(v, float):
        return math.isnan(v) or math.isinf(v)
    if isinstance(v, str):
        return v.strip().lower() in ("nan", "inf", "-inf", "infinity", "-infinity")
    return False


# --------------------------------------------------------------------------- supervisor

class Supervisor:
    def __init__(self, spec: dict, spec_path: str):
        self.spec = spec
        self.spec_path = spec_path
        self.cfg = load_config()
        self.conn = store.connect()
        self.run_id = spec["run_id"]
        run = store.get_run(self.conn, self.run_id)
        if run is None:
            raise SystemExit(f"run {self.run_id} not found")
        self.run = run
        self.rspec = util.json_loads(run["spec"], {}) or {}
        self.mode = spec.get("mode", "managed")
        self.run_dir = run["run_dir"]
        self.log_path = run["log_path"]
        self.progress = ProgressTail(run["progress_path"])
        self.cwd = run["cwd"]
        mon = lambda k, d: self.cfg.get(f"monitor.{k}", d)  # noqa: E731
        self.sample_every = float(mon("sample_interval_s", 15))
        self.gpu_every = float(mon("gpu_interval_s", 30))
        st = self.rspec.get("stall_after_s")
        self.stall_explicit = st is not None
        self.stall_after = float(st) if st is not None else (util.parse_duration(mon("stall_after", "30m")) or 0)
        self.timeout_s = self.rspec.get("timeout_s") or 0
        self.peaks = Peaks()
        self.gpu = None
        self.gpu_last = {}
        self.last_activity = util.now()
        self.last_log_size = self._log_size()
        self.stall_incident = None
        self.stalled = False
        self.warned = set()
        self.mem_high_count = 0
        self.cancel_reason = None
        self.sampler = None
        self.child = None
        self._bg = None
        self.stop_file = os.path.join(self.run_dir, "STOP") if self.run_dir else None
        self.stop_grace = float(self.cfg.get("monitor.stop_grace_s", 60) or 0)
        self.last_sample_cpu = 0.0
        self.started_at = run["started_at"]

    # ---------------------------------------------------------------- helpers
    def log(self, msg: str) -> None:
        print(f"[{util.local_str(util.now())}] {msg}", flush=True)

    def _log_size(self) -> int:
        try:
            return os.path.getsize(self.log_path) if self.log_path else 0
        except OSError:
            return 0

    def register(self) -> None:
        me = os.getpid()
        with store.tx(self.conn):
            store.update_run(self.conn, self.run_id, supervisor_pid=me, supervisor_token=identity.proc_token(me),
                             supervisor_seen_at=util.now())
            store.add_event(self.conn, "SUPERVISOR_STARTED", self.run_id, source="supervisor",
                            payload={"pid": me, "mode": self.mode})

    def _scrub_spec_env(self) -> None:
        try:
            spec = dict(self.spec)
            spec.pop("env", None)
            write_spec(os.path.dirname(self.spec_path), spec)
        except OSError:
            pass

    # ---------------------------------------------------------------- main
    def main(self) -> int:
        self.register()
        if self.cfg.get("monitor.prevent_sleep", True) and not self.rspec.get("allow_sleep"):
            _set_exec_state(True)
        try:
            if self.mode == "managed":
                self.run_managed()
            else:
                self.run_watch()
        except Exception:
            self.log("supervisor error:\n" + traceback.format_exc())
            raise
        finally:
            _set_exec_state(False)
        self.after_finish()
        return 0

    def run_managed(self) -> None:
        spec = self.spec
        with store.tx(self.conn):
            store.transition(self.conn, self.run_id, "STARTING", store.AUTH_SUPERVISOR)
        env = job_env(dict(spec.get("env") or os.environ))
        if not self.rspec.get("no_unbuffered"):
            env.setdefault("PYTHONUNBUFFERED", "1")
            env.setdefault("PYTHONIOENCODING", "utf-8")
        env["RMON_RUN_ID"] = self.run_id
        if self.progress.path:
            env["RMON_PROGRESS_FILE"] = self.progress.path
        if self.stop_file:
            env["RMON_STOP_FILE"] = self.stop_file
        argv = spec.get("argv")
        shell_cmd = spec.get("shell")
        kwargs = dict(cwd=self.cwd, env=env, stdin=subprocess.DEVNULL, stderr=subprocess.STDOUT)
        if IS_WIN:
            kwargs["creationflags"] = CREATE_NO_WINDOW | CREATE_NEW_PROCESS_GROUP
        else:
            kwargs["start_new_session"] = True
        log = open(self.log_path, "ab")
        try:
            if shell_cmd:
                self.child = subprocess.Popen(shell_cmd, shell=True, stdout=log, **kwargs)
            else:
                self.child = subprocess.Popen([resolve_program(argv[0], self.cwd, env)] + list(argv[1:]),
                                              stdout=log, **kwargs)
        except (OSError, ValueError) as e:
            log.close()
            self._scrub_spec_env()
            self.log(f"spawn failed: {e}")
            engine.finalize_run(self.conn, self.cfg, self.run_id, {
                "status": "FAILED", "authority": store.AUTH_SUPERVISOR, "failure_code": "SPAWN_ERROR",
                "failure_summary": f"{type(e).__name__}: {e}", "exit_desc": "not started",
                "evidence": {"final_exception": f"{type(e).__name__}: {e}"}, "validation": None})
            return
        log.close()
        self._scrub_spec_env()
        pid = self.child.pid
        self.started_at = util.now()
        with store.tx(self.conn):
            store.transition(self.conn, self.run_id, "RUNNING", store.AUTH_SUPERVISOR, pid=pid,
                             pid_token=identity.proc_token(pid), started_at=self.started_at)
            store.add_event(self.conn, "RUN_STARTED", self.run_id, source="supervisor", payload={"pid": pid})
        self.log(f"started pid {pid}")
        self.sampler = TreeSampler(pid)
        self.monitor_loop(lambda: self.child.poll() is None, pid)
        rc = self.child.wait()
        self.finish_managed(rc)

    def run_watch(self) -> None:
        """attach (user-requested) or adopt (recovery after supervisor loss): observe a non-child process."""
        run = store.get_run(self.conn, self.run_id)
        pid, token = run["pid"], run["pid_token"]
        if self.mode == "attach":
            with store.tx(self.conn):
                store.transition(self.conn, self.run_id, "RUNNING", store.AUTH_OBSERVED,
                                 started_at=run["started_at"] or util.now())
        else:
            with store.tx(self.conn):
                store.update_run(self.conn, self.run_id, health="ADOPTED")
                store.add_event(self.conn, "ADOPTED", self.run_id, source="supervisor", payload={"pid": pid})
        self.started_at = run["started_at"] or util.now()
        self._scrub_spec_env()
        self.sampler = TreeSampler(pid)
        self.monitor_loop(lambda: identity.is_alive(pid, token), pid)
        self.finish_watch()

    # ---------------------------------------------------------------- loop
    def monitor_loop(self, alive, pid: int) -> None:
        t_sample = t_prog = t_cancel = t_disp = 0.0
        canceled = False
        while alive():
            t = time.monotonic()
            try:
                if t - t_cancel >= 2:
                    t_cancel = t
                    if not canceled:
                        canceled = self._check_cancel(pid)
                if t - t_prog >= 2:
                    t_prog = t
                    self._poll_progress()
                if t - t_sample >= self.sample_every:
                    t_sample = t
                    self._sample()
                if t - t_disp >= 10:
                    t_disp = t
                    self._background_tick()
            except Exception:
                self.log("monitor iteration error:\n" + traceback.format_exc())
            time.sleep(1.0 if self.mode == "managed" else 2.0)
        try:
            self._poll_progress()
        except Exception:
            pass

    def _background_tick(self) -> None:
        """Heartbeat + (when no agent runs) mail delivery/escalation, off the monitoring thread: an SMTP or
        HTTP timeout must not freeze sampling, stall detection or `rmon stop`."""
        if self._bg is not None and self._bg.is_alive():
            return

        def work():
            conn = None
            try:
                conn = store.connect()
                heartbeat.tick(conn, self.cfg)
                if not engine.agent_alive(conn):
                    engine.tick(conn, self.cfg, do_heartbeat=False)
            except Exception:
                self.log("background tick error:\n" + traceback.format_exc())
            finally:
                if conn is not None:
                    conn.close()
        self._bg = threading.Thread(target=work, daemon=True)
        self._bg.start()

    def _check_cancel(self, pid: int) -> bool:
        row = self.conn.execute("SELECT cancel_requested FROM runs WHERE run_id=?", (self.run_id,)).fetchone()
        if row and row[0]:
            self.cancel_reason = "user"
        elif self.timeout_s and self.started_at and util.now() - self.started_at > self.timeout_s:
            self.cancel_reason = "timeout"
        else:
            return False
        with store.tx(self.conn):
            store.add_event(self.conn, "TERMINATION_REQUESTED", self.run_id, source="supervisor",
                            payload={"reason": self.cancel_reason})
        if self.progress.stop_aware and self.stop_file and self.stop_grace > 0:
            # the program polls researchmonitor.should_stop(): let it save a checkpoint and exit by itself
            try:
                with open(self.stop_file, "w") as f:
                    f.write(self.cancel_reason or "stop")
                self.log(f"stop requested via should_stop(); waiting up to {self.stop_grace:.0f}s")
                deadline = time.monotonic() + self.stop_grace
                while time.monotonic() < deadline and identity.proc_token(pid) is not None and \
                        identity.is_alive(pid, None):
                    if self.child is not None and self.child.poll() is not None:
                        break
                    time.sleep(0.5)
            except OSError:
                pass
        if self.child is not None and self.child.poll() is not None:
            self.log(f"job exited by itself after stop request ({self.cancel_reason})")
            return True
        how = terminate_tree(pid)
        self.log(f"terminated job ({self.cancel_reason}) via {how}")
        return True

    def _poll_progress(self) -> None:
        n = self.progress.poll()
        if not n:
            return
        self.last_activity = util.now()
        with store.tx(self.conn):
            store.update_run(self.conn, self.run_id, last_progress=util.json_dumps(self.progress.last),
                             last_progress_at=self.progress.last_at, progress_count=self.progress.count)
        if self.progress.nan_seen and "NAN_LOSS" not in self.warned:
            self.warned.add("NAN_LOSS")
            k, v = self.progress.nan_seen
            engine.raise_warning(self.conn, self.cfg, self.run_id, "NAN_LOSS",
                                 f"progress field '{k}' = {v}", per_run=True)

    def _sample(self) -> None:
        s = self.sampler.sample()
        t = util.now()
        g = {}
        if self.gpu is None:
            self.gpu = GpuSampler()
        if self.gpu.backend != "none" and (not self.gpu_last or t - self.gpu_last.get("_t", 0) >= self.gpu_every):
            g = summarize_gpu(self.gpu.sample(self.sampler.pids() or [self.sampler.root_pid]))
            g["_t"] = t
            self.gpu_last = g
        else:
            g = self.gpu_last
        disk = disk_free(self.cwd or ".")
        self.peaks.update(peak_rss=s["rss"], peak_cpu=s["cpu"], peak_sys_mem=s["sys_mem"],
                          peak_gpu_mem=g.get("gpu_mem"), peak_gpu_util=g.get("gpu_util"),
                          peak_gpu_temp=g.get("gpu_temp_max"), min_disk_free=disk,
                          gpu_mem_scope=g.get("gpu_mem_scope"), gpu_mem_total=g.get("gpu_mem_total"),
                          gpu_names=g.get("gpu_names") or None, sys_mem_total=s.get("sys_mem_total"),
                          last_rss=s["rss"], last_cpu=s["cpu"], last_sys_mem=s["sys_mem"], nproc=s["nproc"],
                          gpu_backend=self.gpu.backend if self.gpu else None)
        with store.tx(self.conn):
            store.add_sample(self.conn, self.run_id, {"ts": t, "cpu": s["cpu"], "rss": s["rss"], "nproc": s["nproc"],
                                                      "threads": s["threads"], "sys_mem": s["sys_mem"],
                                                      "gpu_util": g.get("gpu_util"), "gpu_mem": g.get("gpu_mem"),
                                                      "disk_free": disk})
            store.update_run(self.conn, self.run_id, resources=util.json_dumps(self.peaks.to_dict()),
                             supervisor_seen_at=t)
        # activity: new output, CPU work, GPU work by this run, or new progress records
        size = self._log_size()
        gpu_busy = bool(g.get("run_on_gpu")) and (g.get("gpu_util") or 0) >= 10
        if size != self.last_log_size or s["cpu"] >= 3.0 or gpu_busy:
            self.last_activity = t
        self.last_log_size = size
        self._check_stall(paused=(s.get("root_status") == psutil.STATUS_STOPPED))
        self._check_resources(s, g, disk)

    def _check_stall(self, paused: bool) -> None:
        if not self.stall_after or self.stall_after <= 0:
            return
        t = util.now()
        if self.progress.count >= 1:
            med = self.progress.median_interval()
            threshold = self.stall_after
            if not self.stall_explicit and med:
                threshold = min(max(self.stall_after, 10 * med), 6 * 3600)
            idle = t - (self.progress.last_at or t)
            basis = "no new progress record"
        else:
            threshold = self.stall_after
            idle = t - self.last_activity
            basis = "no output, CPU or GPU activity"
        if paused:
            return
        if not self.stalled and idle >= threshold:
            self.stalled = True
            detail = f"{basis} for {util.fmt_duration(idle)} (threshold {util.fmt_duration(threshold)}); job NOT killed"
            with store.tx(self.conn):
                store.add_event(self.conn, "SUSPECTED_STALL", self.run_id, source="supervisor", payload={"detail": detail})
            self.stall_incident = engine.raise_warning(self.conn, self.cfg, self.run_id, "SUSPECTED_STALL", detail,
                                                       per_run=True)
            self.log("suspected stall: " + detail)
        elif self.stalled and idle < threshold:
            self.stalled = False
            engine.clear_warning(self.conn, self.cfg, self.run_id, "SUSPECTED_STALL", self.stall_incident,
                                 "activity resumed")
            self.stall_incident = None
            self.log("stall cleared")

    def _check_resources(self, s: dict, g: dict, disk) -> None:
        cfg = self.cfg
        warn_gb = float(cfg.get("monitor.disk_free_warn_gb", 5) or 0)
        if disk is not None and warn_gb and disk < warn_gb * 1e9 and "RESOURCE_DISK" not in self.warned:
            self.warned.add("RESOURCE_DISK")
            engine.raise_warning(self.conn, cfg, self.run_id, "RESOURCE_DISK",
                                 f"only {util.fmt_bytes(disk)} free on the volume of {self.cwd}")
        mem_warn = float(cfg.get("monitor.mem_warn_percent", 95) or 0)
        self.mem_high_count = self.mem_high_count + 1 if (mem_warn and s["sys_mem"] >= mem_warn) else 0
        if self.mem_high_count >= 2 and "RESOURCE_MEMORY" not in self.warned:
            self.warned.add("RESOURCE_MEMORY")
            engine.raise_warning(self.conn, cfg, self.run_id, "RESOURCE_MEMORY",
                                 f"system memory at {s['sys_mem']:.0f}% (job tree RSS {util.fmt_bytes(s['rss'])})")
        temp_warn = float(cfg.get("monitor.gpu_temp_warn_c", 90) or 0)
        if temp_warn and (g.get("gpu_temp_max") or 0) >= temp_warn and "RESOURCE_GPU_TEMP" not in self.warned:
            self.warned.add("RESOURCE_GPU_TEMP")
            engine.raise_warning(self.conn, cfg, self.run_id, "RESOURCE_GPU_TEMP",
                                 f"GPU temperature {g.get('gpu_temp_max'):.0f}°C")

    # ---------------------------------------------------------------- finalization
    def _output_lines(self, path: str | None) -> list[str]:
        if not path:
            return []
        return util.decode_output(util.read_tail_bytes(path, 256 * 1024)).splitlines()

    def _mem_pressure(self) -> bool:
        p = self.peaks.d
        return (p.get("last_sys_mem") or 0) >= 90 or (p.get("peak_sys_mem") or 0) >= 97

    def _validate(self) -> dict:
        exps = self.rspec.get("expectations") or []
        if not exps:
            return {"configured": False, "passed": True, "failure_code": None, "results": []}
        return validators.evaluate(exps, self.cwd, self.started_at)

    def _common_outcome(self) -> dict:
        try:
            with store.tx(self.conn):
                store.transition(self.conn, self.run_id, "FINALIZING", store.AUTH_SUPERVISOR
                                 if self.mode == "managed" else store.AUTH_OBSERVED)
        except Exception:
            pass
        att = validators.collect_attachments(self.rspec.get("attach") or [], self.cwd,
                                             os.path.join(self.run_dir, "attachments"),
                                             int(self.cfg.get("notify.attach_max_kb", 512)))
        return {"attachments": att, "ended_at": util.now()}

    def finish_managed(self, rc: int) -> None:
        o = self._common_outcome()
        o.update(authority=store.AUTH_SUPERVISOR, exit_code=rc, exit_desc=classify.describe_exit(rc))
        lines = self._output_lines(self.log_path)
        notes = []
        validation = None
        if self.cancel_reason == "user":
            o.update(status="CANCELED", failure_code=None, failure_summary="canceled by user (rmon stop)")
        elif self.cancel_reason == "timeout":
            o.update(status="TIMED_OUT", failure_code="TIMED_OUT",
                     failure_summary=f"exceeded --timeout {util.fmt_duration(self.timeout_s)}")
        else:
            c = classify.classify(rc, lines, mem_pressure=self._mem_pressure())
            validation = self._validate()
            if rc == 0:
                if c["evidence"].get("final_exception"):
                    notes.append("Exit code was 0 but a Python traceback appears in the output: "
                                 + c["evidence"]["final_exception"])
                if validation["configured"] and not validation["passed"]:
                    bad = [f"{r['target']}: {r['detail']}" for r in validation["results"] if not r["ok"]]
                    o.update(status="FAILED", failure_code=validation["failure_code"], failure_summary="; ".join(bad))
                else:
                    o.update(status="SUCCEEDED" if validation["configured"] else "SUCCEEDED_UNVERIFIED",
                             failure_code=None, failure_summary=None)
            else:
                o.update(status="FAILED", failure_code=c["failure_code"], failure_summary=c["summary"])
            o["evidence"] = dict(c["evidence"])
        ev = o.setdefault("evidence", {})
        if notes:
            ev["notes"] = notes
        if self.progress.checkpoint:
            ev["checkpoint"] = self.progress.checkpoint
        o["validation"] = validation
        metrics = dict(self.progress.results)
        if validation:
            metrics.update({k: v for k, v in validators.extract_metrics(validation).items() if k not in metrics})
        o["metrics"] = metrics
        engine.finalize_run(self.conn, self.cfg, self.run_id, o)
        self.log(f"finished: rc={rc} status={o['status']} failure={o.get('failure_code')}")

    def finish_watch(self) -> None:
        o = self._common_outcome()
        o.update(authority=store.AUTH_OBSERVED, exit_code=None)
        if self.cancel_reason == "user":
            o.update(status="CANCELED", failure_summary="terminated by user (rmon stop)",
                     exit_desc="terminated by rmon")
        elif self.cancel_reason == "timeout":
            o.update(status="TIMED_OUT", failure_code="TIMED_OUT", exit_desc="terminated by rmon",
                     failure_summary=f"exceeded --timeout {util.fmt_duration(self.timeout_s)}")
        else:
            lines = self._output_lines(self.log_path)
            c = classify.classify(None, lines, mem_pressure=self._mem_pressure(), authoritative=False)
            validation = self._validate()
            ev = dict(c["evidence"])
            notes = ["Exit status of a process ResearchMonitor did not start cannot be observed; "
                     "status is UNKNOWN unless stronger evidence exists."]
            if self.mode == "adopt":
                notes.insert(0, "The original monitor process was lost; the job was re-observed until it ended.")
            if validation["configured"]:
                notes.append("Result validators " + ("PASSED" if validation["passed"] else "FAILED") + ".")
            ev["notes"] = notes
            if self.progress.checkpoint:
                ev["checkpoint"] = self.progress.checkpoint
            code = c["failure_code"] or (validation["failure_code"] if validation["configured"] else None)
            o.update(status="UNKNOWN", exit_desc="unknown (not a child of the monitor)",
                     failure_code=code or "ENDED_UNKNOWN",
                     failure_summary=c["summary"] if c["failure_code"] else
                     ("validators passed; process probably completed" if validation["configured"] and
                      validation["passed"] else "process ended; exit status unknown"),
                     evidence=ev, validation=validation)
            o["metrics"] = dict(self.progress.results, **validators.extract_metrics(validation))
        engine.finalize_run(self.conn, self.cfg, self.run_id, o)
        self.log(f"observed process ended: status={o['status']} failure={o.get('failure_code')}")

    def after_finish(self) -> None:
        try:
            heartbeat.tick(self.conn, self.cfg, force=True)
        except Exception:
            self.log("heartbeat error:\n" + traceback.format_exc())
        deadline = time.monotonic() + float(self.cfg.get("notify.linger_max_h", 24)) * 3600
        while time.monotonic() < deadline:
            try:
                if engine.agent_alive(self.conn):
                    self.log("agent is running; leaving remaining deliveries to it")
                    break
                engine.tick(self.conn, self.cfg)
                if not engine.has_pending_work(self.conn):
                    break
            except Exception:
                self.log("linger error:\n" + traceback.format_exc())
            time.sleep(float(self.cfg.get("notify.linger_tick_s", 10) or 10))


def main(argv=None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    spec_path = argv[0]
    if sys.stdout is None or sys.stderr is None:  # pythonw: make sure diagnostics land somewhere
        f = open(os.path.join(os.path.dirname(os.path.abspath(spec_path)), "supervisor.log"), "a",
                 encoding="utf-8", buffering=1)
        sys.stdout = sys.stdout or f
        sys.stderr = sys.stderr or f
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass
    with open(spec_path, "r", encoding="utf-8") as f:
        spec = json.load(f)
    return Supervisor(spec, spec_path).main()


if __name__ == "__main__":
    raise SystemExit(main())
