"""Low-overhead resource sampling for a process tree, system memory, disk and NVIDIA GPUs."""
from __future__ import annotations

import os
import shutil
import subprocess
import sys

import psutil

from . import util

_NO_WINDOW = 0x08000000 if sys.platform == "win32" else 0  # CREATE_NO_WINDOW: no console flash from a detached monitor


class TreeSampler:
    """CPU/RSS of a root process plus all descendants. Keeps Process objects so cpu_percent has a baseline."""

    def __init__(self, root_pid: int):
        self.root_pid = root_pid
        self._procs: dict[int, psutil.Process] = {}

    def pids(self) -> list[int]:
        return list(self._procs)

    def sample(self, io: bool = False) -> dict:
        try:
            root = psutil.Process(self.root_pid)
            members = [root] + root.children(recursive=True)
        except psutil.Error:
            members = []
        alive = {}
        cpu = 0.0
        rss = 0
        threads = 0
        io_bytes = 0
        status = None
        for p in members:
            proc = self._procs.get(p.pid, p)
            try:
                with proc.oneshot():
                    c = proc.cpu_percent(None)  # first call returns 0.0 (baseline)
                    mi = proc.memory_info()
                    threads += proc.num_threads()
                    if p.pid == self.root_pid:
                        status = proc.status()
                    if io:
                        try:
                            ioc = proc.io_counters()
                            io_bytes += (ioc.read_bytes or 0) + (ioc.write_bytes or 0)
                        except (psutil.Error, AttributeError, NotImplementedError):
                            pass
                cpu += c
                rss += getattr(mi, "rss", 0)
                alive[p.pid] = proc
            except psutil.Error:
                continue
        self._procs = alive
        vm = psutil.virtual_memory()
        return {"cpu": round(cpu, 1), "rss": rss, "nproc": len(alive), "threads": threads, "io_bytes": io_bytes,
                "sys_mem": vm.percent, "sys_mem_total": vm.total, "root_status": status}


def disk_free(path: str) -> int | None:
    try:
        return shutil.disk_usage(path).free
    except OSError:
        return None


class GpuSampler:
    """NVML via nvidia-ml-py when installed, else `nvidia-smi`, else disabled."""

    def __init__(self):
        self.backend = "none"
        self._nvml = None
        self._smi = None
        try:
            import pynvml  # provided by the nvidia-ml-py package
            pynvml.nvmlInit()
            self._nvml = pynvml
            self.backend = "nvml"
            return
        except Exception:
            pass
        smi = shutil.which("nvidia-smi")
        if not smi and sys.platform == "win32":
            cand = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "nvidia-smi.exe")
            smi = cand if os.path.exists(cand) else None
        if smi:
            self._smi = smi
            self.backend = "nvidia-smi"

    def sample(self, pids=()) -> dict | None:
        try:
            if self.backend == "nvml":
                return self._sample_nvml(set(pids))
            if self.backend == "nvidia-smi":
                return self._sample_smi(set(pids))
        except Exception as e:  # never let GPU probing break monitoring
            return {"error": str(e)[:200], "gpus": []}
        return None

    def _sample_nvml(self, pids: set) -> dict:
        nv = self._nvml
        gpus, proc_mem, proc_known = [], 0, False
        for i in range(nv.nvmlDeviceGetCount()):
            h = nv.nvmlDeviceGetHandleByIndex(i)
            g = {"index": i}
            try:
                name = nv.nvmlDeviceGetName(h)
                g["name"] = name.decode() if isinstance(name, bytes) else name
            except Exception:
                pass
            try:
                g["util"] = nv.nvmlDeviceGetUtilizationRates(h).gpu
            except Exception:
                pass
            try:
                m = nv.nvmlDeviceGetMemoryInfo(h)
                g["mem_used"], g["mem_total"] = int(m.used), int(m.total)
            except Exception:
                pass
            try:
                g["temp"] = nv.nvmlDeviceGetTemperature(h, 0)
            except Exception:
                pass
            mine = False
            try:
                for pr in nv.nvmlDeviceGetComputeRunningProcesses(h):
                    if pr.pid in pids:
                        mine = True
                        if pr.usedGpuMemory is not None:
                            proc_mem += int(pr.usedGpuMemory)
                            proc_known = True
            except Exception:
                pass
            g["used_by_run"] = mine
            gpus.append(g)
        return {"gpus": gpus, "proc_mem": proc_mem if proc_known else None}

    def _run(self, args) -> str:
        return subprocess.run([self._smi] + args, capture_output=True, text=True, timeout=10,
                              creationflags=_NO_WINDOW).stdout

    def _sample_smi(self, pids: set) -> dict:
        out = self._run(["--query-gpu=index,name,utilization.gpu,memory.used,memory.total,temperature.gpu,uuid",
                         "--format=csv,noheader,nounits"])
        gpus, uuid_idx = [], {}
        for line in out.strip().splitlines():
            parts = [x.strip() for x in line.split(",")]
            if len(parts) < 7:
                continue
            num = lambda s: float(s) if s.replace(".", "", 1).isdigit() else None  # noqa: E731
            g = {"index": int(parts[0]), "name": parts[1], "util": num(parts[2]),
                 "mem_used": int(num(parts[3]) * 2**20) if num(parts[3]) is not None else None,
                 "mem_total": int(num(parts[4]) * 2**20) if num(parts[4]) is not None else None,
                 "temp": num(parts[5]), "used_by_run": False}
            uuid_idx[parts[6]] = len(gpus)
            gpus.append(g)
        proc_mem, known = 0, False
        if pids:
            out2 = self._run(["--query-compute-apps=pid,used_memory,gpu_uuid", "--format=csv,noheader,nounits"])
            for line in out2.strip().splitlines():
                parts = [x.strip() for x in line.split(",")]
                if len(parts) < 3 or not parts[0].isdigit() or int(parts[0]) not in pids:
                    continue
                if parts[2] in uuid_idx:
                    gpus[uuid_idx[parts[2]]]["used_by_run"] = True
                if parts[1].isdigit():  # "[N/A]" on Windows WDDM
                    proc_mem += int(parts[1]) * 2**20
                    known = True
        return {"gpus": gpus, "proc_mem": proc_mem if known else None}


class GpuSnapshot:
    """One system-wide GPU view per sampling tick, shared by discovery and every tracked job.

    compute:  {pid: used_bytes or None}   processes holding a CUDA (compute) context
    graphics: set(pid)                     processes using the GPU for graphics (browsers, desktop, games)
    proc_util: {pid: sm_util_percent}      per-process utilisation when the driver supports it
    """

    def __init__(self):
        self.backend = "none"
        self._nv = None
        self._handles = []
        self._smi = None
        self._util_ok = True
        self._util_ts = {}
        try:
            import pynvml
            pynvml.nvmlInit()
            self._nv = pynvml
            self._handles = [pynvml.nvmlDeviceGetHandleByIndex(i) for i in range(pynvml.nvmlDeviceGetCount())]
            self.backend = "nvml"
        except Exception:
            g = GpuSampler()
            if g.backend == "nvidia-smi":
                self._smi = g
                self.backend = "nvidia-smi"

    def take(self) -> dict:
        snap = {"gpus": [], "compute": {}, "graphics": set(), "proc_util": {}, "backend": self.backend}
        try:
            if self._nv is not None:
                self._take_nvml(snap)
            elif self._smi is not None:
                g = self._smi._sample_smi(set())
                snap["gpus"] = g.get("gpus", [])
                out = self._smi._run(["--query-compute-apps=pid,used_memory", "--format=csv,noheader,nounits"])
                for line in out.strip().splitlines():
                    parts = [x.strip() for x in line.split(",")]
                    if parts and parts[0].isdigit():
                        snap["compute"][int(parts[0])] = int(parts[1]) * 2**20 if len(parts) > 1 and \
                            parts[1].isdigit() else None
        except Exception as e:
            snap["error"] = str(e)[:200]
        return snap

    def _take_nvml(self, snap: dict) -> None:
        nv = self._nv
        for i, h in enumerate(self._handles):
            g = {"index": i}
            for key, fn in (("util", lambda: nv.nvmlDeviceGetUtilizationRates(h).gpu),
                            ("temp", lambda: nv.nvmlDeviceGetTemperature(h, 0))):
                try:
                    g[key] = fn()
                except Exception:
                    pass
            try:
                m = nv.nvmlDeviceGetMemoryInfo(h)
                g["mem_used"], g["mem_total"] = int(m.used), int(m.total)
            except Exception:
                pass
            try:
                name = nv.nvmlDeviceGetName(h)
                g["name"] = name.decode() if isinstance(name, bytes) else name
            except Exception:
                pass
            pids_here = []
            try:
                try:
                    procs = nv.nvmlDeviceGetComputeRunningProcesses(h)
                except Exception:  # older drivers do not know the v3 struct of newer nvidia-ml-py
                    fn = getattr(nv, "nvmlDeviceGetComputeRunningProcesses_v2", None)
                    procs = fn(h) if fn else []
                for p in procs:
                    snap["compute"][p.pid] = (snap["compute"].get(p.pid) or 0) + int(p.usedGpuMemory) \
                        if p.usedGpuMemory is not None else snap["compute"].get(p.pid)
                    pids_here.append(p.pid)
            except Exception:
                pass
            try:
                for p in nv.nvmlDeviceGetGraphicsRunningProcesses(h):
                    snap["graphics"].add(p.pid)
            except Exception:
                pass
            g["pids"] = pids_here
            if self._util_ok:
                try:
                    samples = nv.nvmlDeviceGetProcessUtilization(h, self._util_ts.get(i, 0))
                    for s in samples:
                        snap["proc_util"][s.pid] = max(snap["proc_util"].get(s.pid, 0), s.smUtil)
                        self._util_ts[i] = max(self._util_ts.get(i, 0), s.timeStamp)
                except Exception as e:
                    if "NotSupported" in type(e).__name__ or "Not Supported" in str(e):
                        self._util_ok = False
            snap["gpus"].append(g)


_CUDA_LIBS = ("nvcuda", "cudart", "torch_cuda", "cublas", "cudnn", "libcuda.so", "cupy_backends", "xla_extension",
              "tensorflow_framework", "c10_cuda", "nccl")


def uses_cuda(pid: int) -> bool:
    """Has the process loaded CUDA libraries? Needed on Windows (WDDM), where the driver often does not
    report which process owns a CUDA context. Moderately expensive: call rarely."""
    try:
        if os.path.exists(f"/proc/{pid}/maps"):
            with open(f"/proc/{pid}/maps", "r", errors="replace") as f:
                text = f.read().lower()
            return any(lib in text for lib in _CUDA_LIBS)
        for m in psutil.Process(pid).memory_maps(grouped=True):
            path = (getattr(m, "path", "") or "").lower()
            if any(lib in path for lib in _CUDA_LIBS):
                return True
    except (psutil.Error, OSError):
        pass
    return False


def attribute_gpu(snap: dict | None, pids, assume_on_gpu: bool = False) -> dict:
    """GPU usage attributable to a process tree, from a shared snapshot. `assume_on_gpu`: the process has CUDA
    libraries loaded but the driver did not list it (Windows WDDM) → attribute device-level figures."""
    if not snap or not snap.get("gpus"):
        return {}
    pids = set(pids)
    mine = [p for p in pids if p in snap.get("compute", {})]
    res = {"on_gpu": bool(mine) or assume_on_gpu}
    mem_known = [snap["compute"][p] for p in mine if snap["compute"][p] is not None]
    gpus = snap["gpus"]
    used_gpus = [g for g in gpus if set(g.get("pids", [])) & pids] or (gpus if (mine or assume_on_gpu) else [])
    if mem_known:
        res["gpu_mem"], res["gpu_mem_scope"] = sum(mem_known), "process"
    elif used_gpus:
        res["gpu_mem"] = sum(g.get("mem_used") or 0 for g in used_gpus) or None
        res["gpu_mem_scope"] = "device"
    if used_gpus:
        res["gpu_mem_total"] = sum(g.get("mem_total") or 0 for g in used_gpus) or None
        res["gpu_names"] = sorted({g.get("name") for g in used_gpus if g.get("name")})
        temps = [g["temp"] for g in used_gpus if g.get("temp") is not None]
        res["gpu_temp"] = max(temps) if temps else None
    pu = [snap["proc_util"][p] for p in pids if p in snap.get("proc_util", {})]
    if pu:
        res["gpu_util"], res["gpu_util_scope"] = float(max(pu)), "process"
    elif used_gpus:
        vals = [g["util"] for g in used_gpus if g.get("util") is not None]
        res["gpu_util"] = float(max(vals)) if vals else None
        res["gpu_util_scope"] = "device"
    return res


def summarize_gpu(g: dict | None) -> dict:
    """Reduce a GPU sample to (util, memory) attributed to the run as well as possible."""
    if not g or not g.get("gpus"):
        return {}
    gpus = g["gpus"]
    mine = [x for x in gpus if x.get("used_by_run")] or gpus
    util_vals = [x["util"] for x in mine if x.get("util") is not None]
    temps = [x["temp"] for x in gpus if x.get("temp") is not None]
    res = {"gpu_util": max(util_vals) if util_vals else None, "gpu_temp_max": max(temps) if temps else None,
           "gpu_mem_total": sum(x.get("mem_total") or 0 for x in mine) or None}
    if g.get("proc_mem") is not None:
        res["gpu_mem"], res["gpu_mem_scope"] = g["proc_mem"], "process"
    else:
        used = [x.get("mem_used") for x in mine if x.get("mem_used") is not None]
        res["gpu_mem"], res["gpu_mem_scope"] = (sum(used) if used else None), "device"
    res["gpu_names"] = sorted({x.get("name") for x in mine if x.get("name")})
    res["run_on_gpu"] = any(x.get("used_by_run") for x in gpus)
    return res


class Peaks:
    """Running peaks/minima for the final report."""

    def __init__(self):
        self.d: dict = {}

    def update(self, **vals):
        for k, v in vals.items():
            if v is None:
                continue
            if k.startswith("min_"):
                cur = self.d.get(k)
                self.d[k] = v if cur is None else min(cur, v)
            elif k.startswith("peak_"):
                cur = self.d.get(k)
                self.d[k] = v if cur is None else max(cur, v)
            else:
                self.d[k] = v

    def to_dict(self) -> dict:
        return dict(self.d)


def human_resources(r: dict | None) -> list[tuple[str, str]]:
    """Display rows for a resources summary."""
    r = r or {}
    rows = []
    if r.get("peak_rss") is not None:
        rows.append(("peak_rss", util.fmt_bytes(r["peak_rss"])))
    if r.get("peak_cpu") is not None:
        rows.append(("peak_cpu", f"{r['peak_cpu']:.0f}% (100% = 1 core)"))
    if r.get("peak_sys_mem") is not None:
        rows.append(("peak_sys_mem", f"{r['peak_sys_mem']:.0f}%"))
    if r.get("peak_gpu_mem") is not None:
        scope = r.get("gpu_mem_scope")
        total = r.get("gpu_mem_total")
        txt = util.fmt_bytes(r["peak_gpu_mem"]) + (f" / {util.fmt_bytes(total)}" if total else "")
        if scope == "device":
            txt += " (device total, not per-process)"
        rows.append(("peak_gpu_mem", txt))
    if r.get("peak_gpu_util") is not None:
        rows.append(("peak_gpu_util", f"{r['peak_gpu_util']:.0f}%"))
    if r.get("peak_gpu_temp") is not None:
        rows.append(("peak_gpu_temp", f"{r['peak_gpu_temp']:.0f}°C"))
    if r.get("gpu_names"):
        rows.append(("gpu", ", ".join(r["gpu_names"])))
    if r.get("min_disk_free") is not None:
        rows.append(("min_disk_free", util.fmt_bytes(r["min_disk_free"])))
    return rows
