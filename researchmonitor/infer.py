"""Why did the program end? Combine every piece of evidence into one verdict with a confidence level.

Evidence, strongest first:
1. the host restarted (boot time / boot id changed)            → certain
2. the authoritative exit code (Windows: kept process handle;
   `rmon run`: parent supervisor)                               → strong
3. the program's own last words (traceback / "Killed" / "done") from its terminal or log
4. what the machine looked like just before the end (memory / GPU memory exhaustion, compute → idle)
5. what it left behind (result files written in the last minutes, progress reaching 100 %)
"""
from __future__ import annotations

from . import classify, util

STATUS_OK, STATUS_LIKELY_OK = "SUCCEEDED", "SUCCEEDED_UNVERIFIED"
CTRL_C_CODES = {0xC000013A, 3221225786, -1073741510, 130, -2}

LABELS = {
    "zh": {"high": "高", "medium": "中", "low": "低"},
    "en": {"high": "high", "medium": "medium", "low": "low"},
}


def _pct(a, b):
    try:
        return 100.0 * a / b if a is not None and b else None
    except ZeroDivisionError:
        return None


def resource_story(samples: list, end_ts: float) -> dict:
    """What the last minutes looked like. samples: dicts with ts, cpu, rss, sys_mem, gpu_mem, gpu_mem_total,
    gpu_util, state (oldest first)."""
    last = [s for s in samples if s.get("ts") and end_ts - s["ts"] <= 300]
    out = {"n": len(last)}
    if not last:
        return out
    tail = last[-1]
    out["last"] = tail
    out["sys_mem_max"] = max((s.get("sys_mem") or 0) for s in last)
    gm = [_pct(s.get("gpu_mem"), s.get("gpu_mem_total")) for s in last]
    gm = [x for x in gm if x is not None]
    out["gpu_mem_pct_max"] = max(gm) if gm else None
    out["was_computing"] = tail.get("state") in ("GPU", "CPU")
    states = [s.get("state") for s in last]
    out["idle_tail"] = len(states) >= 2 and all(st in ("IDLE",) for st in states[-4:])
    rss = [s.get("rss") or 0 for s in last]
    out["rss_growing"] = len(rss) >= 3 and rss[-1] > rss[0] * 1.3 and rss[-1] > 1 << 30
    return out


def infer_end(ctx: dict, lang: str = "zh") -> dict:
    """ctx keys: exit_code, exit_known, lines (last output lines), samples, end_ts, started_ts, rebooted,
    reboot_reason, completion (list of (ts, line)), files (list of (path, mtime, size)), progress (dict),
    output_readable (bool), stalled_before_end (bool), last_output_ts.

    Returns {status, code, confidence, verdict, evidence[], summary}.
    """
    zh = lang == "zh"
    ev = []
    end = ctx.get("end_ts") or util.now()
    lines = ctx.get("lines") or []
    story = resource_story(ctx.get("samples") or [], end)
    code_known = bool(ctx.get("exit_known"))
    code = ctx.get("exit_code")

    def out(status, fcode, conf, verdict, summary=None):
        return {"status": status, "code": fcode, "confidence": conf, "verdict": verdict, "evidence": ev,
                "summary": summary or verdict, "story": story}

    # helpful context lines, used by several branches
    last_line = next((ln for ln in reversed(lines) if ln.strip()), None)
    final_line = classify.extract_traceback(lines)[0]
    if last_line and (not final_line or last_line.strip() != final_line.strip()):
        ev.append(("最后一行输出：" if zh else "last output line: ") + last_line.strip()[:200])
    if story.get("sys_mem_max", 0) >= 95:
        ev.append((f"结束前 5 分钟内系统内存最高 {story['sys_mem_max']:.0f}%") if zh else
                  f"system memory peaked at {story['sys_mem_max']:.0f}% in the last 5 minutes")
    if (story.get("gpu_mem_pct_max") or 0) >= 95:
        ev.append((f"结束前 GPU 显存占用最高 {story['gpu_mem_pct_max']:.0f}%") if zh else
                  f"GPU memory peaked at {story['gpu_mem_pct_max']:.0f}% before the end")
    recent_files = [f for f in ctx.get("files") or [] if end - f[1] <= 600]
    if recent_files:
        names = ", ".join(f"{f[0]}" for f in recent_files[:3])
        ev.append((f"结束前 10 分钟内写出 {len(recent_files)} 个文件：{names}") if zh else
                  f"{len(recent_files)} file(s) written in the last 10 minutes: {names}")
    prog = ctx.get("progress") or {}
    finished_progress = prog.get("fraction") is not None and prog["fraction"] >= 0.999
    if prog.get("epoch") is not None and prog.get("epoch_total"):
        ev.append((f"进度：epoch {prog['epoch']:g}/{prog['epoch_total']}") if zh else
                  f"progress: epoch {prog['epoch']:g}/{prog['epoch_total']}")
    completion = [c for c in ctx.get("completion") or [] if end - c[0] <= 900]
    if completion:
        ev.append(("输出中有完成信号：" if zh else "completion message: ") + completion[-1][1][:160])

    # 1. host restart / power loss
    if ctx.get("rebooted"):
        ev.insert(0, ctx.get("reboot_reason") or ("电脑在任务运行期间重启或断电" if zh else "host restarted"))
        return out("LOST", "HOST_REBOOTED", "high",
                   "电脑重启 / 关机 / 断电，任务被中断" if zh else "Host restarted or lost power")

    mem_pressure = story.get("sys_mem_max", 0) >= 95
    c = classify.classify(code if code_known else None, lines, mem_pressure=mem_pressure, authoritative=code_known)
    final_exc = c["evidence"].get("final_exception")
    tb_at_end = bool(final_exc) and any(final_exc.strip() == ln.strip() for ln in lines[-40:])

    if code_known:
        ev.insert(0, ("退出码 " if zh else "exit code ") + classify.describe_exit(code))
        cu = (int(code) & 0xFFFFFFFF) if code is not None else None
        if code == 0:
            if tb_at_end:
                ev.append(("注意：退出码为 0，但输出末尾有 traceback：" if zh else "note: exit 0 but a traceback is at the end: ")
                          + final_exc)
            return out(STATUS_OK, None, "high", "正常完成" if zh else "Completed normally")
        if cu in {c_ & 0xFFFFFFFF for c_ in CTRL_C_CODES} or (final_exc or "").startswith("KeyboardInterrupt"):
            return out("CANCELED", "PROCESS_TERMINATED", "high",
                       "被中断：按了 Ctrl+C 或关闭了终端窗口" if zh else "Interrupted (Ctrl+C or terminal closed)")
        if final_exc and c["failure_code"]:
            ev.insert(1, ("报错：" if zh else "error: ") + final_exc)
            return out("FAILED", c["failure_code"], "high", _fail_title(c["failure_code"], zh), final_exc)
        if c["failure_code"] and c["failure_code"] not in ("NONZERO_EXIT",) and c["evidence"].get("matched_line"):
            ev.insert(1, ("匹配到错误：" if zh else "matched: ") + c["evidence"]["matched_line"])
            return out("FAILED", c["failure_code"], "high", _fail_title(c["failure_code"], zh), c["summary"])
        if cu in classify.NTSTATUS:
            return out("FAILED", "PROCESS_TERMINATED", "high",
                       ("程序崩溃（原生错误 " if zh else "Native crash (") + classify.NTSTATUS[cu] + ")")
        if code == 1 and not ctx.get("output_readable"):
            return out("FAILED", "NONZERO_EXIT", "medium",
                       "错误退出（退出码 1）：可能是未捕获的异常或被任务管理器结束；未能读取程序输出" if zh else
                       "Exited with code 1: an uncaught exception or killed via Task Manager; output not readable")
        if code == 1 and story.get("was_computing") and not lines[-5:]:
            return out("FAILED", "PROCESS_TERMINATED", "medium",
                       "计算中被强制结束（退出码 1，无错误输出）" if zh else "Killed while computing (exit 1, no error)")
        if mem_pressure:
            return out("FAILED", "SYSTEM_OOM", "medium", "系统内存耗尽后退出" if zh else "Exited under memory exhaustion")
        return out("FAILED", "NONZERO_EXIT", "medium",
                   (f"错误退出（{classify.describe_exit(code)}），没有可识别的错误信息" if zh else
                    f"Exited with {classify.describe_exit(code)} without a recognisable error"))

    # ---- no exit code (Linux, process not started by rmon): reason from the evidence
    ev.insert(0, "无法获取退出码（该进程不是由本软件启动的；Linux 不允许读取其他进程的退出码）" if zh else
              "exit code not observable (process not started by rmon)")
    if final_exc and tb_at_end:
        ev.insert(1, ("输出末尾的报错：" if zh else "error at end of output: ") + final_exc)
        if final_exc.startswith("KeyboardInterrupt"):
            return out("CANCELED", "PROCESS_TERMINATED", "high", "被中断（Ctrl+C）" if zh else "Interrupted (Ctrl+C)")
        return out("FAILED", c["failure_code"] or "PYTHON_EXCEPTION", "high", _fail_title(c["failure_code"], zh),
                   final_exc)
    if c["failure_code"] and c["evidence"].get("matched_line"):
        ev.insert(1, ("输出中的错误：" if zh else "error in output: ") + c["evidence"]["matched_line"])
        conf = "high" if c["failure_code"] in ("CUDA_OOM", "GPU_ERROR") else "medium"
        return out("FAILED", c["failure_code"], conf, _fail_title(c["failure_code"], zh), c["summary"])
    if mem_pressure and (story.get("was_computing") or story.get("rss_growing")):
        return out("FAILED", "SYSTEM_OOM", "medium",
                   "很可能因系统内存耗尽被系统结束（OOM）" if zh else "Most likely killed by the system for running out of memory")
    if (completion or finished_progress) and not final_exc:
        conf = "high" if (completion and (recent_files or finished_progress)) else "medium"
        return out(STATUS_LIKELY_OK, None, conf, "很可能正常完成" if zh else "Most likely completed normally")
    if recent_files and not story.get("was_computing") and not final_exc:
        return out(STATUS_LIKELY_OK, None, "medium",
                   "可能正常完成（结束前写出了结果文件并停止计算）" if zh else
                   "Probably completed (wrote files and stopped computing before exiting)")
    if (story.get("gpu_mem_pct_max") or 0) >= 97 and story.get("was_computing"):
        return out("UNKNOWN", "CUDA_OOM", "low",
                   "计算中突然结束，结束前显存已接近占满：可能是显存不足" if zh else
                   "Ended abruptly with GPU memory nearly full: possibly CUDA OOM")
    if ctx.get("stalled_before_end"):
        return out("UNKNOWN", "SUSPECTED_STALL", "low",
                   "长时间无进展后结束（可能卡住后被手动结束）" if zh else "Ended after a long stall (probably stopped manually)")
    if story.get("was_computing"):
        why = "" if ctx.get("output_readable") else ("；未能读取程序输出" if zh else "; output not readable")
        return out("UNKNOWN", "PROCESS_TERMINATED", "low",
                   ("计算中突然结束，没有错误输出：可能被手动结束、被系统结束或崩溃" + why) if zh else
                   ("Ended abruptly while computing, without error output" + why))
    return out("UNKNOWN", "ENDED_UNKNOWN", "low", "已结束，原因无法确定" if zh else "Ended; reason undetermined")


def _fail_title(code, zh: bool) -> str:
    t = classify.title(code, "zh" if zh else "en") or (code or "")
    return ("异常退出：" if zh else "Failed: ") + t
