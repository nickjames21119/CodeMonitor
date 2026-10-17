"""Failure classification from authoritative exit status + log evidence, and runbooks."""
from __future__ import annotations

import re
import signal
import sys

_POSIX = sys.platform != "win32"  # 128+N exit codes mean "killed by signal N" only for POSIX shells

CUDA_OOM = [
    r"CUDA out of memory", r"torch\.(?:cuda\.)?OutOfMemoryError", r"CUBLAS_STATUS_ALLOC_FAILED",
    r"cudaErrorMemoryAllocation", r"CUDA error: out of memory", r"RESOURCE_EXHAUSTED.*(?:OOM|out of memory)",
    r"failed to allocate .* (?:on device|GPU)", r"HIP out of memory", r"MPS backend out of memory",
]
GPU_ERROR = [
    r"CUDA error", r"device-side assert", r"NCCL (?:error|WARN.*failed)", r"ncclInternalError", r"cuDNN error",
    r"CUDNN_STATUS_", r"CUBLAS_STATUS_(?!ALLOC)", r"illegal memory access", r"no CUDA-capable device",
    r"CUDA driver version is insufficient", r"NVML_ERROR", r"GPU is lost", r"Xid \d+",
]
SYSTEM_OOM = [
    r"^MemoryError", r"\bMemoryError\b", r"_ArrayMemoryError", r"Unable to allocate [\d.]+ [KMGT]?i?B",
    r"std::bad_alloc", r"Cannot allocate memory", r"killed by signal: Killed",
]
_C = lambda pats: [re.compile(p, re.I) for p in pats]  # noqa: E731
_CUDA_OOM, _GPU, _SYSOOM = _C(CUDA_OOM), _C(GPU_ERROR), _C(SYSTEM_OOM)

NTSTATUS = {
    0xC0000005: "STATUS_ACCESS_VIOLATION (native crash)",
    0xC00000FD: "STATUS_STACK_OVERFLOW (native crash)",
    0xC0000409: "STATUS_STACK_BUFFER_OVERRUN / fast-fail abort (native crash)",
    0xC000001D: "STATUS_ILLEGAL_INSTRUCTION (native crash)",
    0xC0000017: "STATUS_NO_MEMORY",
    0xC000013A: "STATUS_CONTROL_C_EXIT (interrupted)",
    0xC0000142: "STATUS_DLL_INIT_FAILED",
    0xC0000135: "STATUS_DLL_NOT_FOUND",
}


def describe_exit(code) -> str:
    if code is None:
        return "unknown (no authoritative exit status)"
    code = int(code)
    if code == 0:
        return "0 (success)"
    if code < 0:
        try:
            return f"{code} (killed by signal {signal.Signals(-code).name})"
        except (ValueError, AttributeError):
            return f"{code} (killed by signal {-code})"
    u = code & 0xFFFFFFFF
    if u in NTSTATUS:
        return f"0x{u:08X} ({NTSTATUS[u]})"
    if _POSIX and 128 < code < 160:
        try:
            return f"{code} (shell: killed by signal {signal.Signals(code - 128).name})"
        except (ValueError, AttributeError):
            pass
    return str(code)


def _signal_of(code) -> int | None:
    if code is None:
        return None
    if code < 0:
        return -code
    if _POSIX and 128 < code < 160:
        return code - 128
    return None


def extract_traceback(lines: list[str]) -> tuple[str | None, list[str]]:
    """Return (final exception line, traceback excerpt) of the last Python traceback in `lines`."""
    idx = None
    for i in range(len(lines) - 1, -1, -1):
        if lines[i].lstrip().startswith("Traceback (most recent call last)"):
            idx = i
            break
    if idx is None:
        return None, []
    # include earlier chained tracebacks if close by
    start = idx
    for j in range(idx - 1, max(-1, idx - 120), -1):
        if lines[j].lstrip().startswith("Traceback (most recent call last)"):
            start = j
    final = None
    end = len(lines)
    for k in range(idx + 1, len(lines)):
        ln = lines[k]
        if ln.strip() and not ln.startswith((" ", "\t")):
            final = ln.strip()
            end = min(len(lines), k + 3)
            break
    excerpt = lines[start:end]
    if len(excerpt) > 60:
        excerpt = excerpt[:10] + ["    ..."] + excerpt[-49:]
    return final, excerpt


def _first_match(pats, lines):
    for ln in reversed(lines):
        for p in pats:
            if p.search(ln):
                return ln.strip()
    return None


def classify(exit_code, output_lines: list[str], *, mem_pressure: bool = False,
             authoritative: bool = True) -> dict:
    """Classify a terminated process. Evidence is retained with the decision.

    `authoritative=False` (attach mode) means exit_code is unknown and the result is an inference.
    """
    final_exc, tb = extract_traceback(output_lines)
    tail = output_lines[-120:]
    ev = {"final_exception": final_exc, "traceback": tb, "matched_line": None,
          "exit_desc": describe_exit(exit_code), "confidence": "high" if authoritative else "inferred"}
    sig = _signal_of(exit_code) if authoritative else None
    code_u = (int(exit_code) & 0xFFFFFFFF) if (authoritative and exit_code is not None) else None

    def out(code, summary):
        r = {"failure_code": code, "summary": summary, "evidence": ev}
        return r

    if authoritative and exit_code == 0:
        return out(None, "exit code 0")

    if final_exc:
        if any(p.search(final_exc) for p in _CUDA_OOM):
            ev["matched_line"] = final_exc
            return out("CUDA_OOM", final_exc)
        if any(p.search(final_exc) for p in _GPU):
            ev["matched_line"] = final_exc
            return out("GPU_ERROR", final_exc)
        if any(p.search(final_exc) for p in _SYSOOM):
            ev["matched_line"] = final_exc
            return out("SYSTEM_OOM", final_exc)
        if final_exc.startswith("KeyboardInterrupt"):
            return out("PROCESS_TERMINATED", "KeyboardInterrupt (interrupted)")
        # an OOM message just above a generic re-raise still means OOM
        m = _first_match(_CUDA_OOM, tb[-15:])
        if m:
            ev["matched_line"] = m
            return out("CUDA_OOM", final_exc)
        return out("PYTHON_EXCEPTION", final_exc)

    m = _first_match(_CUDA_OOM, tail)
    if m:
        ev["matched_line"] = m
        return out("CUDA_OOM", m)
    m = _first_match(_GPU, tail)
    if m:
        ev["matched_line"] = m
        return out("GPU_ERROR", m)

    if sig is not None:
        name = describe_exit(exit_code)
        if sig == 9:
            if mem_pressure:
                return out("SYSTEM_OOM", f"{name}; memory was nearly exhausted (likely the OS out-of-memory killer)")
            return out("PROCESS_TERMINATED", f"{name} (forcibly killed)")
        return out("PROCESS_TERMINATED", name)

    m = _first_match(_SYSOOM, tail)
    if m:
        ev["matched_line"] = m
        return out("SYSTEM_OOM", m)
    if code_u == 0xC0000017:
        return out("SYSTEM_OOM", describe_exit(exit_code))
    if code_u in NTSTATUS:
        return out("PROCESS_TERMINATED", describe_exit(exit_code))
    if any(ln.strip() == "Killed" for ln in tail[-5:]):
        ev["matched_line"] = "Killed"
        return out("SYSTEM_OOM" if mem_pressure else "PROCESS_TERMINATED", "Killed (SIGKILL reported by shell)")

    if not authoritative:
        return out(None, "process ended; exit status not observable in attach mode")
    return out("NONZERO_EXIT", f"exited with {describe_exit(exit_code)} without a recognizable error message")


FAILURE_TITLES = {
    "zh": {
        "CUDA_OOM": "CUDA 显存不足", "SYSTEM_OOM": "系统内存耗尽", "PYTHON_EXCEPTION": "Python 未捕获异常",
        "GPU_ERROR": "GPU / CUDA 运行时错误", "PROCESS_TERMINATED": "进程被终止", "NONZERO_EXIT": "非零退出码",
        "SPAWN_ERROR": "程序无法启动", "RESULT_MISSING": "缺少预期结果文件", "RESULT_INVALID": "结果文件校验失败",
        "SUSPECTED_STALL": "疑似卡死（长时间无进展）", "HOST_REBOOTED": "电脑重启/断电，任务中断",
        "AGENT_FAILURE": "监控进程意外退出", "TIMED_OUT": "超过运行时限", "NAN_LOSS": "loss 出现 NaN/Inf",
        "RESOURCE_DISK": "磁盘空间不足", "RESOURCE_MEMORY": "系统内存接近耗尽", "RESOURCE_GPU_TEMP": "GPU 温度过高",
        "ENDED_UNKNOWN": "进程已结束，退出状态未知",
    },
    "en": {
        "CUDA_OOM": "CUDA out of memory", "SYSTEM_OOM": "System memory exhausted",
        "PYTHON_EXCEPTION": "Unhandled Python exception", "GPU_ERROR": "GPU / CUDA runtime error",
        "PROCESS_TERMINATED": "Process terminated", "NONZERO_EXIT": "Non-zero exit code",
        "SPAWN_ERROR": "Program failed to start", "RESULT_MISSING": "Expected result missing",
        "RESULT_INVALID": "Result failed validation", "SUSPECTED_STALL": "Suspected stall (no progress)",
        "HOST_REBOOTED": "Host restarted or lost power during run", "AGENT_FAILURE": "Monitor process died",
        "TIMED_OUT": "Wall-time limit exceeded", "NAN_LOSS": "Loss became NaN/Inf",
        "RESOURCE_DISK": "Low disk space", "RESOURCE_MEMORY": "System memory nearly exhausted",
        "RESOURCE_GPU_TEMP": "GPU temperature high", "ENDED_UNKNOWN": "Process ended, exit status unknown",
    },
}

RUNBOOKS = {
    "zh": {
        "CUDA_OOM": ["核对下方报错原文，确认是前向、反向还是评估阶段 OOM。",
                     "对比「GPU 峰值显存」与显卡总显存；检查是否有其它进程占用同一张卡。",
                     "记下失败时的 epoch / step，从最近的 checkpoint 续训。",
                     "可考虑：减小 batch size 或序列长度、梯度累积、混合精度 (AMP)、gradient checkpointing。",
                     "本系统不会自动修改你的实验配置或重启任务。"],
        "SYSTEM_OOM": ["对比「进程峰值内存」与系统总内存。",
                       "DataLoader 的 num_workers / prefetch 会复制内存，可先调小。",
                       "检查是否一次性把整个数据集读进内存；考虑分块或 memmap。",
                       "Linux 可用 `dmesg | grep -i kill` 确认是否为 OOM killer。"],
        "PYTHON_EXCEPTION": ["先看最后一行异常类型与信息，再看 traceback 指向的代码行。",
                             "用失败时的 epoch/step 和输入复现；修复后从 checkpoint 续跑。",
                             "完整输出见附件 output_tail.txt 或 `rmon logs <run>`。"],
        "GPU_ERROR": ["运行 nvidia-smi 检查驱动与显卡状态、温度。",
                      "device-side assert 常见于标签越界：用 CUDA_LAUNCH_BLOCKING=1 重跑定位。",
                      "多卡 NCCL 错误：检查各卡是否可见、端口与网络设置。"],
        "PROCESS_TERMINATED": ["确认是否有人/程序结束了进程（任务管理器、kill、系统关机、OOM killer）。",
                               "查看输出末尾最后的日志时间点。"],
        "NONZERO_EXIT": ["程序以非零退出码结束但没有可识别的错误信息；查看输出末尾。",
                         "检查脚本中是否有 sys.exit(非0) 或子进程失败。"],
        "SPAWN_ERROR": ["命令无法启动：检查命令拼写、是否在正确的 conda/venv 环境中运行 rmon。",
                        "Windows 上 .bat/.cmd 脚本请加 --shell。"],
        "RESULT_MISSING": ["程序退出码为 0，但预期的结果文件不存在或不是本次运行生成的。",
                           "检查输出路径、工作目录，以及程序是否提前 return 跳过了保存。"],
        "RESULT_INVALID": ["结果文件存在但校验失败（JSON 损坏、指标缺失或为 NaN）。",
                           "查看「结果校验」一节的具体原因。"],
        "SUSPECTED_STALL": ["这只是警告：系统不会结束任务。",
                            "用 `rmon logs <run> -f` 看是否还有输出；检查 CPU/GPU 是否空转。",
                            "DataLoader 死锁可用 num_workers=0 验证；可用 py-spy dump --pid <PID> 查看卡在哪里。"],
        "HOST_REBOOTED": ["电脑在任务运行期间重启或断电（Windows 自动更新、断电、蓝屏、手动重启）。",
                          "Windows：设置 → Windows 更新 → 暂停更新 / 设置使用时段，避免训练中被自动重启。",
                          "事件查看器 → Windows 日志 → 系统，可查看重启原因 (事件 ID 41/1074/6008)。",
                          "从最近的 checkpoint 续跑。"],
        "AGENT_FAILURE": ["负责监控该任务的 rmon 进程意外退出，任务的真实结果未知。",
                          "查看运行目录下的 supervisor.log；若任务仍在运行，rmon 会以附着模式继续观察。"],
        "TIMED_OUT": ["任务超过了 --timeout 设定的时限，已被 rmon 结束。",
                      "从 checkpoint 续跑或调大时限。"],
        "NAN_LOSS": ["loss 变成 NaN/Inf：检查学习率、梯度裁剪、混合精度下的溢出、数据中的异常值。"],
        "RESOURCE_DISK": ["磁盘剩余空间不足，checkpoint/日志写入可能失败；请清理空间。"],
        "RESOURCE_MEMORY": ["系统内存接近耗尽，可能触发 OOM；考虑关闭其它程序或降低内存占用。"],
        "RESOURCE_GPU_TEMP": ["GPU 温度过高，检查散热与风扇；长期高温会降频或导致错误。"],
        "ENDED_UNKNOWN": ["附着模式无法读取一个非子进程的退出码，因此结果标记为 UNKNOWN。",
                          "请结合日志、结果校验判断；以后建议用 `rmon run` 直接启动任务。"],
    },
    "en": {
        "CUDA_OOM": ["Read the exact error below; note the phase (forward/backward/eval).",
                     "Compare peak GPU memory with device capacity; check for other processes on the GPU.",
                     "Note the failing epoch/step and resume from the latest checkpoint.",
                     "Consider smaller batch/sequence length, gradient accumulation, AMP, gradient checkpointing.",
                     "ResearchMonitor never edits your configuration or restarts jobs automatically."],
        "PYTHON_EXCEPTION": ["Read the final exception line and the frame it points to.",
                             "Reproduce at the failing step; fix; resume from checkpoint."],
        "HOST_REBOOTED": ["The computer restarted or lost power during the run.",
                          "On Windows, pause updates / set active hours to avoid automatic restarts.",
                          "Resume from the latest checkpoint."],
    },
}


def title(code: str | None, lang: str = "zh") -> str:
    if not code:
        return ""
    return FAILURE_TITLES.get(lang, FAILURE_TITLES["en"]).get(code) or FAILURE_TITLES["en"].get(code, code)


def runbook(code: str | None, lang: str = "zh") -> list[str]:
    if not code:
        return []
    return RUNBOOKS.get(lang, {}).get(code) or RUNBOOKS["en"].get(code) or RUNBOOKS["zh"].get(code, [])
