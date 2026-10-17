"""Find the user's research programs among everything running on the computer — no wrapper needed.

Cost model (design goal: well under 1 % of one CPU core):
- one whole-system scan every `scan_interval_s` (default 20 s) reading only cheap fields
  (name, parent, start time, CPU time) for every process;
- expensive fields (command line, working dir, exe, user, parents) are read ONCE per new process
  whose name looks interesting (interpreter, CUDA compute user, or a long CPU hog);
- browsers, chat apps, IDEs, desktop/system services, package managers, notebook servers,
  language servers, etc. are dropped by name or command line before anything expensive happens.

Each surviving process gets a score from features; a process is tracked when it scores high enough,
shows real activity and has been alive for `min_age_s`. Every decision keeps its reasons, which the
dashboard and the final e-mail show ("why was this detected").
"""
from __future__ import annotations

import os
import re
import sys

import psutil

from . import identity, util

IS_WIN = sys.platform == "win32"

INTERPRETERS = {"python", "pythonw", "python3", "pypy", "pypy3", "julia", "r", "rscript", "rterm", "rsession",
                "matlab", "octave", "octave-cli", "octave-gui", "mathematica", "wolframkernel", "stata", "sas"}

# Never ours: desktop, browsers, chat, office, IDE shells, system, drivers, sync clients, media.
DENY_NAMES = {
    "system", "registry", "idle", "smss", "csrss", "wininit", "winlogon", "services", "lsass", "svchost", "dwm",
    "explorer", "sihost", "taskhostw", "runtimebroker", "searchhost", "searchindexer", "searchapp", "startmenuexperiencehost",
    "shellexperiencehost", "textinputhost", "ctfmon", "fontdrvhost", "audiodg", "spoolsv", "msmpeng", "nissrv",
    "securityhealthservice", "wudfhost", "dllhost", "conhost", "openconsole", "windowsterminal", "wmiprvse",
    "taskmgr", "applicationframehost", "systemsettings", "lockapp", "smartscreen", "widgets", "phoneexperiencehost",
    "chrome", "msedge", "msedgewebview2", "firefox", "brave", "opera", "vivaldi", "iexplore", "360se", "360chrome",
    "qqbrowser", "sogouexplorer", "2345explorer", "liebao", "safari",
    "wechat", "weixin", "wechatappex", "qq", "tim", "dingtalk", "feishu", "lark", "teams", "ms-teams", "zoom",
    "slack", "discord", "telegram", "skype", "wemeetapp", "tencentmeeting",
    "code", "code - insiders", "cursor", "devenv", "pycharm64", "pycharm", "idea64", "clion64", "datagrip64",
    "rider64", "webstorm64", "sublime_text", "notepad++", "notepad", "typora", "obsidian", "notion", "zotero",
    "winword", "excel", "powerpnt", "outlook", "onenote", "wps", "wpp", "et", "acrord32", "acrobat",
    "onedrive", "dropbox", "baidunetdisk", "baidunetdiskhost", "thunder", "xmp", "googledrivefs",
    "spotify", "cloudmusic", "qqmusic", "potplayermini64", "vlc", "obs64", "steam", "steamwebhelper",
    "epicgameslauncher", "wegame", "photoshop", "illustrator",
    "nvcontainer", "nvdisplay.container", "nvidia share", "nvidia web helper", "nvsphelper64", "nvidia-smi",
    "docker desktop", "com.docker.backend", "vmmem", "vmmemwsl", "vmcompute", "wslhost", "wslservice",
    "systemd", "init", "kthreadd", "dbus-daemon", "dbus-broker", "xorg", "xwayland", "gnome-shell", "plasmashell",
    "kwin_x11", "kwin_wayland", "pulseaudio", "pipewire", "wireplumber", "sshd", "ssh-agent", "gnome-terminal-server",
    "tmux", "tmux: server", "screen", "bash", "zsh", "fish", "sh", "dash", "cmd", "powershell", "pwsh",
    "nautilus", "tracker-miner-fs", "snapd", "containerd", "dockerd", "packagekitd", "networkmanager",
}

# Interpreter processes that are tools / servers, not experiments. Names must appear as a command token
# (so a folder called "black" or "tensorboard_logs" in a script path does not exclude a training job).
_TOK_END = r"(?:\.exe|-script\.py|\.py)?(?=[\s\"']|$)"
TOOL_CMD = re.compile(
    r"(?i)(?:^|[\s/\\\"'])(?:"
    r"(?:pip3?|conda|mamba|micromamba|jupyter-lab|jupyter-notebook|jupyter-server|tensorboard|mlflow|"
    r"pylsp|pyls|jedi-language-server|pyright|pyright-langserver|basedpyright|ruff|ruff-lsp|black|isort|mypy|"
    r"pylint|flake8|pytest|py\.test|tox|nox|pre-commit|poetry|pdm|pipx|virtualenv|sphinx-build|mkdocs|"
    r"streamlit|gradio|uvicorn|gunicorn|flask|celery|airflow|supervisord|spyder|anaconda-navigator|"
    r"researchmonitor|rmon|code-server|voila|dask-scheduler|dask-worker|ray)" + _TOK_END + "|"
    r"jupyter[\s-](?:lab|notebook|server|console|qtconsole)\b|aim\s+up\b|mlflow\s+(?:ui|server)\b|"
    r"-m\s+(?:pip|conda|notebook|jupyter|jupyterlab|jupyter_server|tensorboard|pytest|venv|http\.server|"
    r"debugpy\.adapter|researchmonitor|black|isort|mypy|pylint|flake8|mkdocs|sphinx|uvicorn|gunicorn|flask|"
    r"streamlit|celery|idlelib|pydoc|ensurepip|py_compile|compileall)\b|"
    r"lsp_server\.py|vscode-pylance|[/\\]debugpy[/\\]adapter|ms-python\.|idlelib|jupyter_server|"
    r"jupyterlab[/\\]|notebook[/\\]notebookapp"
    r")")
# Long-lived interactive sessions: watched for compute bursts ("episodes"), not for exit.
KERNEL_CMD = re.compile(r"(?i)ipykernel_launcher|-m\s+ipykernel\b|spyder_kernels|kernel-[\w-]+\.json|"
                        r"(?:^|[\s/\\])ipython(?:\.exe|-script\.py)?(?=\s|$)|-m\s+IPython\b")
ML_WORDS = re.compile(
    r"(?i)(?<![a-z])(train(?:ing)?|eval(?:uate|uation)?|infer(?:ence)?|predict|finetune|fine[_-]tune|pretrain|"
    r"sft|dpo|rlhf|ppo|grpo|experiment|exp\d+|sweep|benchmark|simulat\w*|epochs?|lr|learning[_-]rate|"
    r"batch[_-]size|torchrun|torch\.distributed\.\w+|accelerate|deepspeed|lightning|hydra|wandb|"
    r"papermill|--execute)(?![a-z])|训练|实验|推理|评估|微调")
SCRIPT_EXT = re.compile(r"(?i)\.(py|pyw|r|jl|m|ipynb|sh|bat|cmd)$")
TERMINAL_PARENTS = {"cmd", "powershell", "pwsh", "windowsterminal", "openconsole", "conhost", "bash", "zsh", "fish",
                    "sh", "dash", "tmux", "tmux: server", "screen", "sshd", "nohup", "code", "cursor", "pycharm64",
                    "pycharm", "idea64", "spyder", "jupyter", "slurmstepd", "sbatch", "srun", "cron", "crond",
                    "gnome-terminal-server", "konsole", "xterm", "alacritty", "wezterm-gui", "mintty", "git-bash",
                    "wsl", "python", "pythonw", "conda", "rmon"}
ENV_HINT = re.compile(r"(?i)[/\\](envs|venv|\.venv|virtualenvs|miniconda\d?|anaconda\d?|mambaforge|miniforge\d?|"
                      r"pyenv|conda)[/\\]")


def norm_name(name: str | None) -> str:
    n = (name or "").lower()
    if n.endswith(".exe"):
        n = n[:-4]
    n = re.sub(r"(?<=[a-z])[\d.]+$", "", n)  # python3.11 -> python, pythonw3 -> pythonw
    return n


def _match_any(patterns, text: str) -> str | None:
    low = text.lower()
    for p in patterns or ():
        p = str(p).strip()
        if p and p.lower() in low:
            return p
    return None


class Candidate:
    __slots__ = ("pid", "token", "name", "ppid", "create_time", "cmdline", "cwd", "exe", "user", "parents",
                 "static_score", "reasons", "category", "excluded", "cpu_hist", "rss", "first_seen", "described",
                 "score", "dyn_reasons", "tracked", "hint", "cuda", "cuda_checked", "gpu_busy", "cooldown_until")

    def __init__(self, pid, token, name, ppid, create_time, now):
        self.pid, self.token, self.name, self.ppid, self.create_time = pid, token, name, ppid, create_time
        self.cmdline, self.cwd, self.exe, self.user, self.parents = [], None, None, None, []
        self.static_score, self.reasons, self.category, self.excluded = 0, [], "unknown", None
        self.cpu_hist = []
        self.rss = 0
        self.first_seen = now
        self.described = False
        self.score, self.dyn_reasons, self.tracked, self.hint = 0, [], False, None
        self.cuda, self.cuda_checked = False, 0.0
        self.gpu_busy, self.cooldown_until = False, 0.0

    def cmd_str(self) -> str:
        return " ".join(self.cmdline) if self.cmdline else (self.name or "")

    def to_dict(self) -> dict:
        return {"pid": self.pid, "token": self.token, "name": self.name, "cmd": self.cmd_str()[:300],
                "cwd": self.cwd, "exe": self.exe, "score": self.score, "category": self.category,
                "reasons": self.reasons + self.dyn_reasons, "excluded": self.excluded,
                "age_s": None, "create_time": self.create_time, "tracked": self.tracked,
                "cpu": self.cpu_hist[-1] if self.cpu_hist else None, "rss": self.rss}


class Discovery:
    def __init__(self, cfg, rules=(), own_pids=()):
        self.cfg = cfg
        self.rules = list(rules)            # [(action, pattern)]
        self.own_pids = set(own_pids)
        self.cands: dict = {}               # pid -> Candidate
        self.cpu_prev: dict = {}            # pid -> (cpu_seconds, wall)
        self.user = identity.current_user()
        self.min_score = int(cfg.get("discovery.min_score", 5) or 5)
        self.min_age = float(cfg.get("discovery.min_age_s", 120) or 0)
        self.watch = list(cfg.get("discovery.watch") or [])
        self.ignore = list(cfg.get("discovery.ignore") or [])
        self.only = list(cfg.get("discovery.only") or [])
        self.notebooks = bool(cfg.get("discovery.track_notebooks", True))
        self.ncpu = psutil.cpu_count() or 1

    # ------------------------------------------------------------------ scanning
    def scan(self, now: float, gpu_snap: dict | None, skip_pids=()) -> list:
        """One cheap pass. Returns candidates that should start being tracked now."""
        skip = set(skip_pids) | self.own_pids
        compute = (gpu_snap or {}).get("compute", {})
        graphics = (gpu_snap or {}).get("graphics", set())
        alive = set()
        ready = []
        for p in psutil.process_iter(["pid", "name", "ppid", "create_time", "cpu_times"]):
            info = p.info
            pid = info["pid"]
            if pid in (0, 4) or pid in skip:
                continue
            name = norm_name(info.get("name"))
            ct = info.get("create_time") or 0
            alive.add(pid)
            cpu_t = info.get("cpu_times")
            cpu_pct = None
            if cpu_t is not None:
                tot = (cpu_t.user or 0) + (cpu_t.system or 0)
                prev = self.cpu_prev.get(pid)
                if prev and prev[2] == ct and now > prev[1]:
                    cpu_pct = max(0.0, (tot - prev[0]) / (now - prev[1]) * 100.0)
                self.cpu_prev[pid] = (tot, now, ct)
            c = self.cands.get(pid)
            if c is not None and c.create_time != ct:  # PID reused
                c = None
                del self.cands[pid]
            if c is None:
                interesting = (name in INTERPRETERS or pid in compute or
                               (cpu_pct is not None and cpu_pct >= 80 and name not in DENY_NAMES))
                if not interesting or name in DENY_NAMES:
                    continue
                c = Candidate(pid, identity.proc_token(pid), info.get("name"), info.get("ppid"), ct, now)
                self.cands[pid] = c
            if c.excluded:
                continue
            if cpu_pct is not None:
                c.cpu_hist.append(round(cpu_pct, 1))
                c.cpu_hist = c.cpu_hist[-10:]
            if not c.described:
                self._describe(c, p)
                if c.excluded:
                    continue
            self._score(c, now, pid in compute, pid in graphics)
            c.gpu_busy = _gpu_busy(gpu_snap, pid)
            if not c.tracked and self._qualifies(c, now):
                ready.append(c)
        for pid in list(self.cands):
            if pid not in alive:
                del self.cands[pid]
        for pid in list(self.cpu_prev):
            if pid not in alive:
                del self.cpu_prev[pid]
        return ready

    # ------------------------------------------------------------------ features
    def _describe(self, c: Candidate, p) -> None:
        """Expensive, once per process."""
        c.described = True
        try:
            with p.oneshot():
                try:
                    c.cmdline = p.cmdline() or []
                except psutil.Error:
                    c.cmdline = []
                try:
                    c.exe = p.exe()
                except psutil.Error:
                    c.exe = None
                try:
                    c.cwd = p.cwd()
                except psutil.Error:
                    c.cwd = None
                try:
                    c.user = p.username()
                except psutil.Error:
                    c.user = None
                try:
                    c.rss = p.memory_info().rss
                except psutil.Error:
                    pass
            par = p
            for _ in range(4):
                try:
                    par = par.parent()
                except psutil.Error:
                    par = None
                if par is None:
                    break
                try:
                    c.parents.append(norm_name(par.name()))
                except psutil.Error:
                    break
        except psutil.Error:
            c.excluded = "vanished"
            return
        text = c.cmd_str() + " " + (c.cwd or "")
        if c.user and self.user and c.user.split("\\")[-1].lower() != self.user.split("\\")[-1].lower():
            c.excluded = f"other user ({c.user})"
            return
        if "rmon_selftest" in text and not self.only:
            c.excluded = "ResearchMonitor self-test"
            return
        ig = _match_any(self.ignore, text) or self._rule("ignore", text)
        if ig:
            c.excluded = f"ignored by rule '{ig}'"
            return
        if self.only and not _match_any(self.only, text):
            c.excluded = "not in 'only' list"
            return
        c.hint = _match_any(self.watch, text) or self._rule("watch", text)
        if not c.hint and TOOL_CMD.search(" " + c.cmd_str()):
            c.excluded = "tool / server process"
            return
        r, s = [], 0
        name = norm_name(c.name)
        if KERNEL_CMD.search(c.cmd_str()) or (len(c.cmdline) <= 1 and name in INTERPRETERS):
            c.category = "interactive"
            r.append("interactive session (Jupyter kernel / IPython / REPL)")
        elif name in INTERPRETERS:
            c.category = "job"
        else:
            c.category = "native"
        if name in INTERPRETERS:
            s += 2
            r.append(f"interpreter {name}")
        script = next((a for a in c.cmdline[1:] if SCRIPT_EXT.search(a)), None)
        if "-m" in c.cmdline:
            i = c.cmdline.index("-m")
            if i + 1 < len(c.cmdline):
                script = script or ("-m " + c.cmdline[i + 1])
        if script and c.category != "interactive":
            s += 1
            r.append(f"script {os.path.basename(script)}")
        words = set(m.group(0).lower().lstrip("-") for m in ML_WORDS.finditer(" ".join(c.cmdline[1:])))
        if words:
            s += min(2, len(words))
            r.append("keywords " + ",".join(sorted(words)[:4]))
        if any(par in TERMINAL_PARENTS for par in c.parents[:3]):
            s += 1
            r.append("started from " + next(par for par in c.parents[:3] if par in TERMINAL_PARENTS))
        if c.exe and ENV_HINT.search(c.exe):
            s += 1
            r.append("conda/venv interpreter")
        if c.hint:
            s += 10
            r.append(f"matches your watch rule '{c.hint}'")
        c.static_score, c.reasons = s, r

    def _rule(self, action: str, text: str) -> str | None:
        return _match_any([p for a, p in self.rules if a == action], text)

    def _score(self, c: Candidate, now: float, on_compute: bool, on_graphics: bool) -> None:
        s, r = c.static_score, []
        name = norm_name(c.name)
        if (not on_compute and not c.cuda and name in INTERPRETERS and c.static_score >= 3
                and now - c.cuda_checked >= 120 and now - (c.create_time or now) >= 20):
            # Windows (WDDM) often hides CUDA processes from NVML: check loaded libraries, at most every 2 min
            from .resources import uses_cuda
            c.cuda_checked = now
            c.cuda = uses_cuda(c.pid)
        if (on_compute and (name in INTERPRETERS or not on_graphics)) or c.cuda:
            s += 3
            r.append("uses GPU (CUDA compute)" if on_compute else "CUDA libraries loaded")
        hist = c.cpu_hist[-3:]
        if len(hist) >= 2 and min(hist) >= 150:
            s += 2
            r.append(f"sustained CPU {min(hist):.0f}%")
        elif len(hist) >= 2 and min(hist) >= 50:
            s += 1
            r.append(f"sustained CPU {min(hist):.0f}%")
        if c.rss >= 1 << 30:
            s += 1
            r.append(f"memory {util.fmt_bytes(c.rss)}")
        c.score, c.dyn_reasons = s, r

    @staticmethod
    def busy(c: Candidate) -> bool:
        """Real computation right now (holding a CUDA context alone does not count)."""
        return any(x >= 30 for x in c.cpu_hist[-2:]) or c.gpu_busy

    def active(self, c: Candidate) -> bool:
        if any(x >= 30 for x in c.cpu_hist[-3:]) or any("GPU" in x for x in c.dyn_reasons) or c.hint:
            return True
        # long-running, clearly experiment-like scripts that mostly wait (e.g. LLM API evaluation, downloads)
        age = util.now() - (c.create_time or util.now())
        return age >= 600 and c.static_score >= self.min_score

    def _qualifies(self, c: Candidate, now: float) -> bool:
        if c.excluded or (c.category == "interactive" and not self.notebooks):
            return False
        age = now - (c.create_time or now)
        if c.category == "interactive":
            # sessions live for days; a sustained burst of computation is what gets reported
            if now < c.cooldown_until:
                return False
            return (len(c.cpu_hist) >= 2 and min(c.cpu_hist[-2:]) >= 30) or c.gpu_busy
        if c.hint:
            return age >= min(self.min_age, 30)
        if age < self.min_age:
            return False
        if c.category == "native":
            # native programs need strong evidence: pure CUDA compute or long heavy CPU and a work-like command
            return c.score >= self.min_score + 1 and self.active(c)
        return c.score >= self.min_score and self.active(c)

    def refresh_rss(self, pids) -> None:
        for pid in pids:
            c = self.cands.get(pid)
            if c is None:
                continue
            try:
                c.rss = psutil.Process(pid).memory_info().rss
            except psutil.Error:
                pass

    def listing(self, now: float) -> list[dict]:
        out = []
        for c in self.cands.values():
            if not c.described:
                continue
            d = c.to_dict()
            d["age_s"] = now - (c.create_time or now)
            out.append(d)
        out.sort(key=lambda d: (-int(d["tracked"]), d["excluded"] is not None, -d["score"]))
        return out[:60]


def _gpu_busy(snap, pid: int) -> bool:
    if not snap:
        return False
    if pid in snap.get("proc_util", {}):
        return snap["proc_util"][pid] >= 10
    if pid in snap.get("compute", {}):
        return any((g.get("util") or 0) >= 30 for g in snap.get("gpus", []) if pid in g.get("pids", []))
    return False


def job_root(pid: int, is_candidate) -> int:
    """Walk up the parent chain while the parent is part of the same program (venv launcher, torchrun,
    multiprocessing parent); the topmost such process represents the job."""
    root = pid
    try:
        p = psutil.Process(pid)
        for _ in range(6):
            par = p.parent()
            if par is None or not is_candidate(par):
                break
            root, p = par.pid, par
    except psutil.Error:
        pass
    return root


def same_program(par) -> bool:
    try:
        name = norm_name(par.name())
        if name not in INTERPRETERS:
            return False
        cmd = " ".join(par.cmdline())
        return not TOOL_CMD.search(" " + cmd) and not KERNEL_CMD.search(cmd)
    except psutil.Error:
        return False
