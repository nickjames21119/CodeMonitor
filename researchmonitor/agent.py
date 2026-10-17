"""The background agent — the only long-running ResearchMonitor process.

Responsibilities: discover research programs, follow them until they end, send the reports, deliver /
retry e-mails, ping the remote heartbeat, recover after restarts, serve the local dashboard.

Lightweight by construction:
- runs at below-normal CPU and I/O priority, so it never competes with your experiments;
- one scheduler thread that sleeps until the next due task (no busy polling);
- whole-system process scan every 20 s using cheap fields only; expensive details once per process;
- per-job sampling every 15 s, output reading every 30 s, terminal capture every 60 s;
- when nothing is being tracked, only the 20 s scan and a 10 s outbox check remain.
"""
from __future__ import annotations

import logging
import logging.handlers
import os
import signal
import sys
import threading
import time

import psutil

from . import discovery as disc
from . import engine, identity, store, util
from .config import home_dir, load_config, runs_dir

log = logging.getLogger("rmon.agent")
IS_WIN = sys.platform == "win32"


def _setup_logging(quiet: bool) -> None:
    path = os.path.join(home_dir(), "agent.log")
    root = logging.getLogger("rmon")
    if root.handlers:
        return
    h = logging.handlers.RotatingFileHandler(path, maxBytes=1_000_000, backupCount=2, encoding="utf-8")
    h.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
    root.setLevel(logging.INFO)
    root.addHandler(h)
    if not quiet and sys.stderr is not None:
        root.addHandler(logging.StreamHandler())


def _lower_priority() -> None:
    p = psutil.Process()
    try:
        p.nice(psutil.BELOW_NORMAL_PRIORITY_CLASS if IS_WIN else 10)
    except Exception:
        pass
    try:
        if IS_WIN:
            p.ionice(psutil.IOPRIO_LOW)
        elif hasattr(psutil, "IOPRIO_CLASS_IDLE"):
            p.ionice(psutil.IOPRIO_CLASS_IDLE)
    except Exception:
        pass


class Agent:
    def __init__(self, dashboard: bool = True):
        self.cfg = load_config()
        self.conn = store.connect()
        self.runs_dir = runs_dir()
        self.lock = threading.RLock()
        self.trackers: dict = {}          # root pid -> JobTracker
        self.disc = None
        self.gpu = None
        self.snap = None
        self.snap_at = 0.0
        self.stop = threading.Event()
        self.want_dashboard = dashboard
        self.port = None
        self.server = None
        self.me = psutil.Process()
        self.self_stats = {}
        self.started = util.now()
        self.rules_sig = None
        self.cfg_sig = None
        self.last_scan_cost = 0.0

    # ------------------------------------------------------------------ setup
    def _rules(self) -> list:
        return [(r["action"], r["pattern"]) for r in self.conn.execute("SELECT action, pattern FROM rules")]

    def _reload(self, force: bool = False) -> None:
        cfg = load_config()
        rules = self._rules()
        sig = (repr(cfg.get("discovery")), repr(cfg.get("monitor")), repr(cfg.get("notify")))
        if force or sig != self.cfg_sig or rules != self.rules_sig or self.disc is None:
            self.cfg = cfg
            for t in self.trackers.values():
                t.cfg = cfg
            old = self.disc
            self.disc = disc.Discovery(cfg, rules, own_pids={os.getpid()})
            if old is not None:
                self.disc.cpu_prev = old.cpu_prev  # keep CPU baselines; re-describe candidates with new rules
            self.cfg_sig, self.rules_sig = sig, rules
        else:
            self.cfg = cfg

    def gpu_snapshot(self, max_age: float = 5.0) -> dict | None:
        now = time.monotonic()
        if self.snap is not None and now - self.snap_at < max_age:
            return self.snap
        if self.gpu is None:
            from .resources import GpuSnapshot
            self.gpu = GpuSnapshot()
        self.snap = self.gpu.take() if self.gpu.backend != "none" else None
        self.snap_at = now
        return self.snap

    # ------------------------------------------------------------------ pids to leave alone
    def _skip_pids(self) -> set:
        skip = {os.getpid()}
        try:
            skip.update(c.pid for c in self.me.children(recursive=True))
        except psutil.Error:
            pass
        for t in self.trackers.values():
            skip.update(t.tree_pids())
        for r in self.conn.execute("SELECT pid, supervisor_pid FROM runs WHERE status IN "
                                   "('CREATED','STARTING','RUNNING','FINALIZING') AND mode IN ('managed','attached')"):
            for pid in (r[0], r[1]):
                if pid:
                    skip.add(pid)
                    try:
                        skip.update(c.pid for c in psutil.Process(pid).children(recursive=True))
                    except psutil.Error:
                        pass
        return skip

    # ------------------------------------------------------------------ tasks
    def task_scan(self, now: float) -> None:
        with self.lock:
            self._task_scan(now)

    def _task_scan(self, now: float) -> None:
        if not self.cfg.get("discovery.enabled", True):
            return
        t0 = time.process_time()
        snap = self.gpu_snapshot()
        ready = self.disc.scan(now, snap, self._skip_pids())
        for c in ready:
            try:
                self._start_tracking(c, now)
            except Exception:
                log.exception("could not start tracking pid %s", c.pid)
        self.last_scan_cost = time.process_time() - t0

    def _start_tracking(self, c, now: float) -> None:
        from .tracker import JobTracker
        root = disc.job_root(c.pid, disc.same_program) if c.category != "interactive" else c.pid
        with self.lock:
            if root in self.trackers or any(root in t.tree_pids() or c.pid in t.tree_pids()
                                            for t in self.trackers.values()):
                c.tracked = True
                return
        try:
            p = psutil.Process(root)
            with p.oneshot():
                info = {"cmdline": p.cmdline(), "name": p.name(), "create_time": p.create_time()}
                try:
                    info["cwd"] = p.cwd()
                except psutil.Error:
                    info["cwd"] = c.cwd
                try:
                    info["exe"] = p.exe()
                except psutil.Error:
                    info["exe"] = c.exe
            parents = []
            par = p
            for _ in range(2):
                par = par.parent()
                if par is None:
                    break
                parents.append(par.pid)
            info["parent_pids"] = parents
        except psutil.Error:
            return
        detect = {"score": c.score, "reasons": c.reasons + c.dyn_reasons, "category": c.category,
                  "pid": c.pid, "root": root}
        mode = "interactive" if c.category == "interactive" else "auto"
        t = JobTracker(self, pid=root, token=identity.proc_token(root), info=info, mode=mode, detect=detect)
        if mode == "interactive":
            t.episode_start = now
        with self.lock:
            self.trackers[root] = t
        c.tracked = True
        log.info("tracking pid %s (%s) as %s; score %s: %s", root, " ".join(info["cmdline"])[:160], t.run_id,
                 c.score, "; ".join(detect["reasons"]))
        try:
            t.sample(now, self.gpu_snapshot())
            t.read_outputs(now)
            if t.console_ok is not False:
                t.read_console(now)
        except Exception:
            log.exception("initial sample failed for %s", t.run_id)

    def task_live(self, now: float) -> None:
        for pid, t in list(self.trackers.items()):
            if t.alive():
                continue
            self._finish(pid, t, now)

    def _finish(self, pid, t, now: float, **kw) -> None:
        try:
            t.finish(now, **kw)
            log.info("finished %s (%s)", t.run_id, (kw or "ended"))
        except Exception:
            log.exception("finalizing %s failed", t.run_id)
        with self.lock:
            self.trackers.pop(pid, None)
        if self.disc and pid in self.disc.cands:
            self.disc.cands[pid].tracked = False
        try:  # deliver the report now rather than at the next outbox tick (bounded: slow SMTP must not stall us)
            from . import notify
            notify.dispatch_due(self.conn, self.cfg, max_items=3, time_budget=20)
        except Exception:
            log.exception("immediate delivery failed")

    def task_sample(self, now: float) -> None:
        with self.lock:
            self._task_sample(now)

    def _task_sample(self, now: float) -> None:
        if not self.trackers:
            return
        snap = self.gpu_snapshot(max_age=2.0)
        min_ep = util.parse_duration(self.cfg.get("discovery.notebook_min_episode", "10m")) or 600
        for pid, t in list(self.trackers.items()):
            try:
                t.sample(now, snap)
            except Exception:
                log.exception("sample %s", t.run_id)
                continue
            if t.mode == "interactive":
                idle = [s for s in list(t.samples)[-9:] if now - s["ts"] <= 125]
                if len(idle) >= 3 and all(s["state"] in ("IDLE", "LIGHT") and (s["cpu"] or 0) < 5 for s in idle):
                    episode = now - (t.episode_start or now)
                    if episode >= min_ep:
                        self._finish(pid, t, now, episode_end=True)
                    else:
                        self._discard(pid, t)
                    if self.disc and pid in self.disc.cands:
                        self.disc.cands[pid].cpu_hist.clear()

    def _discard(self, pid, t) -> None:
        """A short burst in an interactive session: not worth a report."""
        with store.tx(self.conn):
            for tbl in ("samples", "events"):
                self.conn.execute(f"DELETE FROM {tbl} WHERE run_id=?", (t.run_id,))
            self.conn.execute("DELETE FROM runs WHERE run_id=?", (t.run_id,))
        t.exitw.close()
        import shutil
        if t.run_dir and os.path.basename(t.run_dir) == t.run_id:
            shutil.rmtree(t.run_dir, ignore_errors=True)
        with self.lock:
            self.trackers.pop(pid, None)
        if self.disc and pid in self.disc.cands:
            c = self.disc.cands[pid]
            c.tracked = False
            c.cooldown_until = util.now() + 600  # do not re-track the same idle session right away

    def task_outputs(self, now: float) -> None:
        with self.lock:
            self._task_outputs(now)

    def _task_outputs(self, now: float) -> None:
        for t in list(self.trackers.values()):
            try:
                t.read_outputs(now)
                t.maybe_intermediate(now)
            except Exception:
                log.exception("outputs %s", t.run_id)

    def task_console(self, now: float) -> None:
        with self.lock:
            self._task_console(now)

    def _task_console(self, now: float) -> None:
        for t in list(self.trackers.values()):
            if t.console_ok is False and not t.tmux:
                continue
            try:
                t.read_console(now)
                t.maybe_intermediate(now)
            except Exception:
                log.exception("console %s", t.run_id)

    def task_persist(self, now: float) -> None:
        with self.lock:
            self._task_persist(now)

    def _task_persist(self, now: float) -> None:
        for t in list(self.trackers.values()):
            try:
                t.persist(now)
            except Exception:
                log.exception("persist %s", t.run_id)

    def task_notify(self, now: float) -> None:
        out = engine.tick(self.conn, self.cfg)
        d = out.get("dispatch") or {}
        if d.get("sent") or d.get("failed") or d.get("retry"):
            log.info("notifications: %s", d)

    def task_recover(self, now: float) -> None:
        stats = engine.recover(self.conn, self.cfg)
        if any(stats.values()):
            log.info("recovery: %s", stats)

    def task_beat(self, now: float) -> None:
        try:
            with self.me.oneshot():
                cpu = self.me.cpu_times()
                rss = self.me.memory_info().rss
            prev = self.self_stats.get("_cpu")
            if prev:
                d_cpu = (cpu.user + cpu.system) - prev[0]
                d_t = now - prev[1]
                self.self_stats["cpu_pct"] = 100.0 * d_cpu / d_t if d_t > 0 else None
            self.self_stats["_cpu"] = (cpu.user + cpu.system, now)
            self.self_stats["rss"] = rss
            self.self_stats["cpu_total_s"] = cpu.user + cpu.system
        except psutil.Error:
            pass
        store.kv_set(self.conn, "agent", util.json_dumps({
            "pid": os.getpid(), "token": identity.proc_token(os.getpid()), "seen_at": now, "port": self.port,
            "started_at": self.started, "tracking": len(self.trackers),
            "cpu_pct": self.self_stats.get("cpu_pct"), "rss": self.self_stats.get("rss")}))

    def task_config(self, now: float) -> None:
        self._reload()

    def task_control(self, now: float) -> None:
        flag = store.kv_get(self.conn, "agent_stop")
        if flag and float(flag) >= self.started:
            store.kv_set(self.conn, "agent_stop", None)
            log.info("stop requested")
            self.stop.set()

    # ------------------------------------------------------------------ resume after (re)start
    def resume(self, now: float) -> None:
        cur_boot = identity.boot_id()
        try:
            boot_time = psutil.boot_time()
        except Exception:
            boot_time = None
        rows = self.conn.execute("SELECT * FROM runs WHERE mode IN ('auto','interactive') AND status IN "
                                 "('CREATED','STARTING','RUNNING','FINALIZING')").fetchall()
        for row in rows:
            try:
                self._resume_one(row, now, cur_boot, boot_time)
            except Exception:
                log.exception("resume of %s failed; closing it as UNKNOWN", row["run_id"])
                try:
                    engine.finalize_auto(self.conn, self.cfg, row["run_id"], {
                        "status": "UNKNOWN", "authority": store.AUTH_INFERRED, "failure_code": "ENDED_UNKNOWN",
                        "failure_summary": "could not resume monitoring after a restart",
                        "evidence": {"verdict": "监控重启后无法继续跟踪该任务", "confidence": "low",
                                     "evidence": ["see agent.log"]}, "ended_at": row["supervisor_seen_at"] or now,
                        "profile": util.json_loads(row["profile"], {}) or {}})
                except Exception:
                    log.exception("could not close %s", row["run_id"])

    def _resume_one(self, row, now: float, cur_boot: str, boot_time) -> None:
        from .tracker import JobTracker
        prof = util.json_loads(row["profile"], {}) or {}
        info = prof.get("info") or {"cmdline": util.json_loads(row["command"], []), "cwd": row["cwd"],
                                    "create_time": row["started_at"]}
        last_seen = row["supervisor_seen_at"] or row["started_at"] or now
        rebooted = not identity.same_boot(row["boot_id"], cur_boot) or bool(boot_time and boot_time > last_seen + 5)
        alive = not rebooted and identity.is_alive(row["pid"], row["pid_token"])
        t = JobTracker(self, pid=row["pid"], token=row["pid_token"], info=info, mode=row["mode"], run_row=row)
        if alive:
            with self.lock:
                self.trackers[row["pid"]] = t
            log.info("resumed tracking %s (pid %s)", row["run_id"], row["pid"])
            return
        reason = None
        if rebooted:
            reason = (f"电脑在任务运行期间重启或关机：最后一次看到任务是 {util.local_str(last_seen)}，"
                      f"系统开机时间 {util.local_str(boot_time)}") if (self.cfg.get("general.language") or "zh") \
                == "zh" else f"host restarted: last seen {util.local_str(last_seen)}, booted {util.local_str(boot_time)}"
        t.finish(now, rebooted=rebooted, reboot_reason=reason, agent_gap=not rebooted)
        log.info("finalized %s after restart (rebooted=%s)", row["run_id"], rebooted)

    # ------------------------------------------------------------------ main loop
    def tasks(self):
        c = self.cfg
        busy = bool(self.trackers)
        return [
            ("beat", 30, self.task_beat),
            ("control", 3, self.task_control),
            ("config", 60, self.task_config),
            ("scan", float(c.get("discovery.scan_interval_s", 20) or 20), self.task_scan),
            ("live", 3, self.task_live),
            ("sample", float(c.get("monitor.sample_interval_s", 15) or 15), self.task_sample),
            ("outputs", 30, self.task_outputs),
            ("console", 60, self.task_console),
            ("persist", 60, self.task_persist),
            ("notify", 10, self.task_notify),
            ("recover", 60, self.task_recover),
        ]

    def run(self) -> int:
        _lower_priority()
        self._reload(force=True)
        if self.want_dashboard:
            try:
                from .dashboard import start_server
                self.server, self.port = start_server(int(self.cfg.get("dashboard.port") or 8765), agent=self)
                log.info("dashboard on http://127.0.0.1:%s", self.port)
            except Exception as e:
                log.warning("dashboard not started: %s", e)
        now = util.now()
        self.task_beat(now)
        try:
            self.resume(now)
        except Exception:
            log.exception("resume failed")
        log.info("agent started pid=%s data_dir=%s", os.getpid(), home_dir())
        due: dict = {}
        while not self.stop.is_set():
            mono = time.monotonic()
            for name, interval, fn in self.tasks():
                if mono >= due.get(name, 0):
                    due[name] = mono + interval
                    try:
                        fn(util.now())
                    except Exception:
                        log.exception("task %s failed", name)
            nxt = min(due.values()) - time.monotonic()
            self.stop.wait(max(0.5, min(nxt, 10.0)))
        self.shutdown()
        return 0

    def shutdown(self) -> None:
        now = util.now()
        for t in list(self.trackers.values()):
            try:
                t.persist(now)
                t.exitw.close()
            except Exception:
                pass
        try:  # last chance to deliver queued mail (bounded); the rest is retried on next start
            from . import notify
            notify.dispatch_due(self.conn, self.cfg, max_items=10, time_budget=15)
        except Exception:
            pass
        try:
            store.kv_set(self.conn, "agent", None)
            if self.server:
                self.server.shutdown()
        except Exception:
            pass
        log.info("agent stopped")

    # ------------------------------------------------------------------ dashboard helpers
    def candidates(self) -> list:
        with self.lock:
            return self.disc.listing(util.now()) if self.disc else []

    def live_views(self) -> dict:
        now = util.now()
        with self.lock:
            return {t.run_id: t.view(now) for t in self.trackers.values()}


def run_agent(dashboard: bool = True, quiet: bool = False) -> int:
    _setup_logging(quiet)
    conn = store.connect()
    if engine.agent_alive(conn):
        info = util.json_loads(store.kv_get(conn, "agent"), {})
        log.info("agent already running (pid %s); exiting", info.get("pid"))
        if not quiet:
            print(f"agent already running (pid {info.get('pid')})")
        return 0
    conn.close()
    agent = Agent(dashboard=dashboard)

    def _sig(*_):
        agent.stop.set()
    for s in (signal.SIGINT, signal.SIGTERM, getattr(signal, "SIGBREAK", None)):
        if s is not None:
            try:
                signal.signal(s, _sig)
            except (ValueError, OSError):
                pass
    return agent.run()
