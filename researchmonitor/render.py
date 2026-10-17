"""E-mail / push content. All log-derived text is redacted before it leaves the machine."""
from __future__ import annotations

import html
import os
import re

from . import classify, resources, util
from .redact import redact

L = {
    "zh": {
        "project": "项目", "run": "运行 ID", "host": "主机", "command": "命令", "cwd": "工作目录", "status": "状态",
        "severity": "严重级别", "start": "开始时间", "end": "结束时间", "duration": "用时", "exit": "退出码",
        "failure": "失败类型", "summary": "摘要", "incident": "事件单", "mode": "监控模式",
        "sec_facts": "关键信息", "sec_evidence": "错误证据", "sec_progress": "最近进度", "sec_metrics": "结果指标",
        "sec_validation": "结果校验", "sec_resources": "资源使用", "sec_output": "输出末尾",
        "sec_files": "附件与结果文件", "sec_runbook": "处理建议", "sec_ack": "如何确认（停止提醒）",
        "sec_runs": "受影响的运行", "sec_notes": "备注",
        "peak_rss": "进程峰值内存", "peak_cpu": "进程峰值 CPU", "peak_sys_mem": "系统内存峰值占用",
        "peak_gpu_mem": "GPU 峰值显存", "peak_gpu_util": "GPU 峰值利用率", "peak_gpu_temp": "GPU 最高温度",
        "gpu": "GPU", "min_disk_free": "磁盘最低剩余",
        "final_exception": "最终异常", "matched_line": "匹配到的错误行", "traceback": "Traceback 摘录",
        "checkpoint": "最近 checkpoint", "no_validators": "未配置结果校验（可用 --expect 指定预期结果文件）",
        "ack_text": "在这台电脑上运行 `rmon ack {iid}`，或运行 `rmon dashboard` 打开本地面板点击「确认」。确认后不再发送提醒。",
        "footer": "ResearchMonitor 自动发送 · 主机 {host} · {time}",
        "attached": "已附在邮件中", "reference": "文件较大，未附带",
        "head": {
            "SUCCEEDED": "✅ 运行成功（结果已校验）", "SUCCEEDED_UNVERIFIED": "☑️ 运行结束，退出码 0（未配置结果校验）",
            "FAILED": "❌ 运行失败：{f}", "TIMED_OUT": "⏱ 超过运行时限，已被终止", "CANCELED": "⏹ 已手动取消",
            "UNKNOWN": "❔ 进程已结束，退出状态未知{f}", "LOST": "⚠️ 任务已中断：{f}",
        },
        "likely": "（推测：{f}）",
        "update_head": "事件 {iid} 更新：共 {n} 个运行受影响（{f}）",
        "reminder_head": "提醒 {k}/{n}：事件 {iid} 仍未确认",
        "warn_head": "⚠️ 运行中警告：{f}", "cleared_head": "✅ 警告解除：{f}",
        "lost_head": "⚠️ 电脑重启或监控中断：{n} 个任务受影响",
        "test_head": "✅ ResearchMonitor 测试邮件",
        "test_body": "如果你收到了这封邮件，说明发信配置正确。\n建议把发件人加入 Outlook 的「安全发件人」，避免以后被归入垃圾邮件。",
    },
    "en": {
        "project": "Project", "run": "Run ID", "host": "Host", "command": "Command", "cwd": "Working dir",
        "status": "Status", "severity": "Severity", "start": "Started", "end": "Ended", "duration": "Duration",
        "exit": "Exit code", "failure": "Failure", "summary": "Summary", "incident": "Incident", "mode": "Mode",
        "sec_facts": "Key facts", "sec_evidence": "Evidence", "sec_progress": "Last progress", "sec_metrics": "Metrics",
        "sec_validation": "Result validation", "sec_resources": "Resources", "sec_output": "Output tail",
        "sec_files": "Attachments & result files", "sec_runbook": "Runbook", "sec_ack": "Acknowledge (stops reminders)",
        "sec_runs": "Affected runs", "sec_notes": "Notes",
        "peak_rss": "Peak process memory", "peak_cpu": "Peak process CPU", "peak_sys_mem": "Peak system memory",
        "peak_gpu_mem": "Peak GPU memory", "peak_gpu_util": "Peak GPU utilization", "peak_gpu_temp": "Max GPU temp",
        "gpu": "GPU", "min_disk_free": "Lowest free disk",
        "final_exception": "Final exception", "matched_line": "Matched error line", "traceback": "Traceback excerpt",
        "checkpoint": "Latest checkpoint", "no_validators": "No result validators configured (use --expect)",
        "ack_text": "Run `rmon ack {iid}` on this computer, or `rmon dashboard` and click Acknowledge.",
        "footer": "Sent by ResearchMonitor · host {host} · {time}",
        "attached": "attached", "reference": "too large, not attached",
        "head": {
            "SUCCEEDED": "✅ Succeeded (results validated)", "SUCCEEDED_UNVERIFIED": "☑️ Exited 0 (no validators)",
            "FAILED": "❌ Failed: {f}", "TIMED_OUT": "⏱ Wall-time limit exceeded", "CANCELED": "⏹ Canceled",
            "UNKNOWN": "❔ Ended, exit status unknown{f}", "LOST": "⚠️ Interrupted: {f}",
        },
        "likely": " (likely: {f})",
        "update_head": "Incident {iid} update: {n} runs affected ({f})",
        "reminder_head": "Reminder {k}/{n}: incident {iid} not acknowledged",
        "warn_head": "⚠️ Warning: {f}", "cleared_head": "✅ Warning cleared: {f}",
        "lost_head": "⚠️ Host restarted or monitoring lost: {n} run(s) affected",
        "test_head": "✅ ResearchMonitor test e-mail",
        "test_body": "If you can read this, e-mail delivery works.\nAdd the sender to Safe Senders to avoid the junk folder.",
    },
}

_CARETS = re.compile(r"^\s*[\^~]+\s*$")  # Python 3.11+ traceback position markers

COLORS = {"P0": "#b42318", "P1": "#c4320a", "P2": "#b54708", "P3": "#067647"}
STATUS_COLORS = {"SUCCEEDED": "#067647", "SUCCEEDED_UNVERIFIED": "#2e7d32", "CANCELED": "#475467"}


def _lang(cfg) -> str:
    lang = cfg.get("general.language") or "zh"
    return lang if lang in L else "en"


def _e(s) -> str:
    return html.escape("" if s is None else str(s))


class _Doc:
    """Builds matching HTML and plain-text bodies."""

    def __init__(self, headline: str, color: str):
        self.headline, self.color = headline, color
        self.h: list[str] = []
        self.t: list[str] = [headline, "=" * 40]

    def table(self, title: str, rows):
        rows = [(k, v) for k, v in rows if v not in (None, "", [])]
        if not rows:
            return
        self.t.append(f"\n## {title}")
        cells = []
        for k, v in rows:
            self.t.append(f"{k}: {v}")
            cells.append(f"<tr><td style='padding:4px 12px 4px 0;color:#667085;white-space:nowrap;"
                         f"vertical-align:top'>{_e(k)}</td><td style='padding:4px 0;word-break:break-all'>{_e(v)}</td></tr>")
        self.h.append(f"<h3 style='margin:20px 0 6px;font-size:15px'>{_e(title)}</h3>"
                      f"<table style='border-collapse:collapse;font-size:14px'>{''.join(cells)}</table>")

    def pre(self, title: str, text: str):
        if not text:
            return
        self.t.append(f"\n## {title}\n{text}")
        self.h.append(f"<h3 style='margin:20px 0 6px;font-size:15px'>{_e(title)}</h3>"
                      f"<pre style='background:#f6f7f9;border:1px solid #e4e7ec;border-radius:6px;padding:10px;"
                      f"font-size:12px;line-height:1.45;white-space:pre-wrap;word-break:break-all'>{_e(text)}</pre>")

    def items(self, title: str, items, ordered=False):
        items = [i for i in items if i]
        if not items:
            return
        if title:
            self.t.append(f"\n## {title}")
        for n, i in enumerate(items, 1):
            self.t.append(f"{n}. {i}" if ordered else f"- {i}")
        tag = "ol" if ordered else "ul"
        lis = "".join(f"<li style='margin:3px 0'>{_e(i)}</li>" for i in items)
        h3 = f"<h3 style='margin:20px 0 6px;font-size:15px'>{_e(title)}</h3>" if title else ""
        self.h.append(f"{h3}<{tag} style='margin:4px 0 0;padding-left:22px;font-size:14px'>{lis}</{tag}>")

    def para(self, text: str):
        self.t.append("\n" + text)
        self.h.append(f"<p style='font-size:14px;margin:12px 0'>{_e(text)}</p>")

    def render(self, footer: str) -> tuple[str, str]:
        self.t.append("\n--\n" + footer)
        body = (f"<div style='font-family:-apple-system,Segoe UI,Microsoft YaHei,Helvetica,Arial,sans-serif;"
                f"color:#101828;max-width:760px'>"
                f"<div style='border-left:6px solid {self.color};padding:8px 14px;background:#fafafa'>"
                f"<div style='font-size:18px;font-weight:600'>{_e(self.headline)}</div></div>"
                + "".join(self.h) +
                f"<p style='color:#98a2b3;font-size:12px;margin-top:28px'>{_e(footer)}</p></div>")
        return "\n".join(self.t), body


def _command_str(run) -> str:
    cmd = util.json_loads(run["command"], run["command"])
    if isinstance(cmd, list):
        from .redact import redact_argv
        import shlex
        return " ".join(shlex.quote(c) for c in redact_argv([str(c) for c in cmd]))
    return redact(str(cmd or ""))


def _duration(run) -> float | None:
    if run["started_at"] and run["ended_at"]:
        return run["ended_at"] - run["started_at"]
    if run["started_at"]:
        return util.now() - run["started_at"]
    return None


def _output_tail(run, n: int) -> str:
    if not run["log_path"]:
        return ""
    text = util.decode_output(util.read_tail_bytes(run["log_path"], 128 * 1024))
    lines = [ln for ln in util.tail_lines(text, n * 2) if not _CARETS.match(ln)][-n:]
    return redact("\n".join(lines))


def _footer(cfg, lang) -> str:
    return L[lang]["footer"].format(host=cfg.host_name, time=util.local_str(util.now()))


def run_failure_title(run, lang) -> str:
    code = run["failure_code"]
    return classify.title(code, lang) or (run["failure_summary"] or "")


def run_report(conn, cfg, run, severity: str, incident=None) -> dict:
    lang = _lang(cfg)
    T = L[lang]
    status = run["status"]
    ftitle = run_failure_title(run, lang)
    head_tpl = T["head"].get(status, status)
    if status == "UNKNOWN":
        head = head_tpl.format(f=T["likely"].format(f=ftitle) if run["failure_code"] and
                               run["failure_code"] != "ENDED_UNKNOWN" else "")
    else:
        head = head_tpl.format(f=ftitle or status)
    color = STATUS_COLORS.get(status, COLORS.get(severity, "#b42318"))
    name = run["name"] or run["run_id"]
    short = ftitle if status not in ("SUCCEEDED", "SUCCEEDED_UNVERIFIED") else \
        ("运行成功" if lang == "zh" else "succeeded")
    dur = _duration(run)
    subject = f"[{status}][{severity}] {name} — {short}" + (f" · {util.fmt_duration(dur)}" if dur else "")
    doc = _Doc(f"{head} · {name}", color)
    evidence = util.json_loads(run["evidence"], {}) or {}
    doc.table(T["sec_facts"], [
        (T["project"], run["project"] or name), (T["run"], run["run_id"]), (T["host"], cfg.host_name),
        (T["mode"], run["mode"]), (T["command"], _command_str(run)), (T["cwd"], run["cwd"]),
        (T["status"], status), (T["severity"], severity),
        (T["start"], util.local_str(run["started_at"])), (T["end"], util.local_str(run["ended_at"])),
        (T["duration"], util.fmt_duration(dur)), (T["exit"], run["exit_desc"]),
        (T["failure"], f"{ftitle} ({run['failure_code']})" if run["failure_code"] else None),
        (T["summary"], redact(run["failure_summary"] or "") if run["failure_code"] else None),
        (T["incident"], incident["incident_id"] if incident is not None else None),
    ])
    notes = evidence.get("notes") or []
    doc.items(T["sec_notes"], [redact(n) for n in notes])
    if run["failure_code"]:
        ev_rows = [(T["final_exception"], redact(evidence.get("final_exception") or "")),
                   (T["matched_line"], redact(evidence.get("matched_line") or "")
                    if evidence.get("matched_line") != evidence.get("final_exception") else None)]
        doc.table(T["sec_evidence"], ev_rows)
        tb = [ln for ln in (evidence.get("traceback") or []) if not _CARETS.match(ln)]
        if tb:
            doc.pre(T["traceback"], redact("\n".join(tb[-40:])))
    prog = util.json_loads(run["last_progress"], None)
    if prog:
        rows = [(k, v) for k, v in prog.items() if not str(k).startswith("_")][:15]
        if run["last_progress_at"]:
            rows.append(("@", util.local_str(run["last_progress_at"])))
        doc.table(T["sec_progress"], rows)
    metrics = util.json_loads(run["metrics"], {}) or {}
    if metrics:
        doc.table(T["sec_metrics"], [(k, v) for k, v in list(metrics.items())[:30]])
    val = util.json_loads(run["validation"], None)
    if val is not None:
        if val.get("configured"):
            doc.items(T["sec_validation"], [("✓ " if r["ok"] else "✗ ") + f"{r['target']}: {r['detail']}"
                                            for r in val.get("results", [])])
        elif status in ("SUCCEEDED_UNVERIFIED",):
            doc.items(T["sec_validation"], [T["no_validators"]])
    res = util.json_loads(run["resources"], {}) or {}
    doc.table(T["sec_resources"], [(T.get(k, k), v) for k, v in resources.human_resources(res)])
    files = []
    for a in util.json_loads(run["spec"], {}).get("_attachments", []) if run["spec"] else []:
        if a.get("attached"):
            files.append(f"{a['name']} — {util.fmt_bytes(a.get('size'))} ({T['attached']})")
        elif a.get("reference_only"):
            files.append(f"{a['source']} — {util.fmt_bytes(a.get('size'))}, sha256={a.get('sha256') or '-'} "
                         f"({T['reference']})")
        elif a.get("missing"):
            files.append(f"{a['source']} — missing")
    ckpt = (prog or {}).get("checkpoint") or evidence.get("checkpoint")
    if ckpt:
        files.insert(0, f"{T['checkpoint']}: {ckpt}")
    doc.items(T["sec_files"], files)
    failing = status in ("FAILED", "TIMED_OUT", "UNKNOWN", "LOST")
    code = run["failure_code"] or ("ENDED_UNKNOWN" if status == "UNKNOWN" else None)
    doc.items(T["sec_runbook"], classify.runbook(code, lang), ordered=True)
    # the traceback is already shown above; keep the body short and attach the full tail instead
    n_tail = 12 if evidence.get("traceback") else (40 if failing else 15)
    doc.pre(T["sec_output"], _output_tail(run, n_tail))
    if incident is not None and severity in ("P0", "P1", "P2"):
        doc.para(T["ack_text"].format(iid=incident["incident_id"]))
    text, body = doc.render(_footer(cfg, lang))
    attachments = []
    for a in util.json_loads(run["spec"], {}).get("_attachments", []) if run["spec"] else []:
        if a.get("attached"):
            attachments.append({"path": a["attached"], "name": a["name"]})
    if failing and run["run_dir"]:
        tail_path = os.path.join(run["run_dir"], "output_tail.txt")
        try:
            with open(tail_path, "w", encoding="utf-8") as f:
                f.write(_output_tail(run, 400))
            attachments.append({"path": tail_path, "name": "output_tail.txt"})
        except OSError:
            pass
    push_line = redact(evidence.get("final_exception") or run["failure_summary"] or "") if failing else \
        util.fmt_duration(dur)
    return {"subject": subject, "text": text, "html": body, "attachments": attachments,
            "push_title": f"[{status}] {name}"[:80],
            "push_body": f"{head}\n{push_line}\n{cfg.host_name} · {util.fmt_duration(dur)}"
                         + (f" · {incident['incident_id']}" if incident is not None else "")}


def _runs_rows(conn, run_ids, lang) -> list[str]:
    out = []
    for rid in run_ids:
        r = conn.execute("SELECT * FROM runs WHERE run_id=?", (rid,)).fetchone()
        if r is None:
            continue
        ev = util.json_loads(r["evidence"], {}) or {}
        line = f"{r['name'] or rid} [{r['status']}] {rid}"
        detail = ev.get("final_exception") or r["failure_summary"]
        if detail:
            line += f" — {redact(detail)[:200]}"
        if r["started_at"]:
            line += f" ({util.fmt_duration(_duration(r))})"
        out.append(line)
    return out


def incident_update(conn, cfg, incident) -> dict:
    lang = _lang(cfg)
    T = L[lang]
    runs = util.json_loads(incident["runs"], []) or []
    ftitle = classify.title(incident["category"], lang) or incident["category"]
    head = T["update_head"].format(iid=incident["incident_id"], n=len(runs), f=ftitle)
    doc = _Doc(head, COLORS.get(incident["severity"], "#b42318"))
    doc.items(T["sec_runs"], _runs_rows(conn, runs, lang))
    doc.items(T["sec_runbook"], classify.runbook(incident["category"], lang), ordered=True)
    doc.para(T["ack_text"].format(iid=incident["incident_id"]))
    text, body = doc.render(_footer(cfg, lang))
    return {"subject": f"[INCIDENT][{incident['severity']}] {incident['incident_id']} — {ftitle} ×{len(runs)}",
            "text": text, "html": body, "push_title": f"{incident['incident_id']} ×{len(runs)}",
            "push_body": head}


def reminder(conn, cfg, incident, step: int, total: int) -> dict:
    lang = _lang(cfg)
    T = L[lang]
    runs = util.json_loads(incident["runs"], []) or []
    head = T["reminder_head"].format(k=step, n=total, iid=incident["incident_id"])
    doc = _Doc(head, COLORS.get(incident["severity"], "#b42318"))
    doc.table(T["sec_facts"], [(T["incident"], incident["incident_id"]), (T["summary"], incident["title"]),
                               (T["severity"], incident["severity"]),
                               (T["start"], util.local_str(incident["created_at"]))])
    doc.items(T["sec_runs"], _runs_rows(conn, runs, lang))
    doc.para(T["ack_text"].format(iid=incident["incident_id"]))
    text, body = doc.render(_footer(cfg, lang))
    return {"subject": f"[REMINDER {step}/{total}][{incident['severity']}] {incident['title']}",
            "text": text, "html": body, "push_title": head[:80], "push_body": incident["title"]}


def warning(conn, cfg, run, code: str, detail: str, severity: str, incident) -> dict:
    lang = _lang(cfg)
    T = L[lang]
    ftitle = classify.title(code, lang) or code
    name = run["name"] or run["run_id"]
    head = T["warn_head"].format(f=ftitle)
    doc = _Doc(f"{head} · {name}", COLORS.get(severity, "#b54708"))
    doc.table(T["sec_facts"], [(T["run"], run["run_id"]), (T["host"], cfg.host_name),
                               (T["command"], _command_str(run)), (T["status"], run["status"]),
                               (T["duration"], util.fmt_duration(_duration(run))), (T["summary"], redact(detail)),
                               (T["incident"], incident["incident_id"] if incident is not None else None)])
    prog = util.json_loads(run["last_progress"], None)
    if prog:
        doc.table(T["sec_progress"], [(k, v) for k, v in prog.items() if not str(k).startswith("_")][:12]
                  + [("@", util.local_str(run["last_progress_at"]))])
    res = util.json_loads(run["resources"], {}) or {}
    doc.table(T["sec_resources"], [(T.get(k, k), v) for k, v in resources.human_resources(res)])
    doc.pre(T["sec_output"], _output_tail(run, 20))
    doc.items(T["sec_runbook"], classify.runbook(code, lang), ordered=True)
    if incident is not None:
        doc.para(T["ack_text"].format(iid=incident["incident_id"]))
    text, body = doc.render(_footer(cfg, lang))
    return {"subject": f"[WARNING][{severity}] {name} — {ftitle}", "text": text, "html": body,
            "push_title": f"[WARNING] {name}"[:80], "push_body": f"{ftitle}: {redact(detail)}"[:500]}


def warning_cleared(conn, cfg, run, code: str, note: str) -> dict:
    lang = _lang(cfg)
    T = L[lang]
    ftitle = classify.title(code, lang) or code
    name = run["name"] or run["run_id"]
    head = T["cleared_head"].format(f=ftitle)
    doc = _Doc(f"{head} · {name}", "#067647")
    doc.table(T["sec_facts"], [(T["run"], run["run_id"]), (T["summary"], note),
                               (T["duration"], util.fmt_duration(_duration(run)))])
    text, body = doc.render(_footer(cfg, lang))
    return {"subject": f"[RECOVERED][P3] {name} — {ftitle}", "text": text, "html": body,
            "push_title": f"[RECOVERED] {name}"[:80], "push_body": note}


def host_lost(conn, cfg, incident, run_ids, reason_code: str) -> dict:
    lang = _lang(cfg)
    T = L[lang]
    head = T["lost_head"].format(n=len(run_ids))
    doc = _Doc(head, COLORS.get(incident["severity"], "#c4320a"))
    doc.table(T["sec_facts"], [(T["host"], cfg.host_name), (T["incident"], incident["incident_id"]),
                               (T["failure"], f"{classify.title(reason_code, lang)} ({reason_code})"),
                               (T["severity"], incident["severity"])])
    doc.items(T["sec_runs"], _runs_rows(conn, run_ids, lang))
    doc.items(T["sec_runbook"], classify.runbook(reason_code, lang), ordered=True)
    doc.para(T["ack_text"].format(iid=incident["incident_id"]))
    text, body = doc.render(_footer(cfg, lang))
    return {"subject": f"[LOST][{incident['severity']}] {cfg.host_name} — {classify.title(reason_code, lang)}"
                       f" ×{len(run_ids)}", "text": text, "html": body,
            "push_title": head[:80], "push_body": "\n".join(_runs_rows(conn, run_ids, lang))[:500]}


def test_message(cfg) -> dict:
    lang = _lang(cfg)
    T = L[lang]
    doc = _Doc(T["test_head"], "#067647")
    doc.para(T["test_body"])
    doc.table(T["sec_facts"], [(T["host"], cfg.host_name), ("email_backend", cfg.get("notify.email_backend")),
                               ("to", ", ".join(cfg.email_to))])
    text, body = doc.render(_footer(cfg, lang))
    return {"subject": f"[TEST] ResearchMonitor @ {cfg.host_name}", "text": text, "html": body,
            "push_title": "ResearchMonitor test", "push_body": T["test_body"].splitlines()[0]}


# =========================================================================== automatic detection reports

STATE_LABEL = {
    "zh": {"GPU": "GPU 计算", "CPU": "CPU 计算", "IO": "数据读写", "LIGHT": "轻负载/等待", "IDLE": "空闲",
           "PAUSED": "已暂停", "START": "启动"},
    "en": {"GPU": "GPU compute", "CPU": "CPU compute", "IO": "disk I/O", "LIGHT": "light load", "IDLE": "idle",
           "PAUSED": "paused", "START": "starting"},
}
STATE_COLOR = {"GPU": "#2f6fdb", "CPU": "#7a5af8", "IO": "#0e9384", "LIGHT": "#98a2b3", "IDLE": "#f04438",
               "PAUSED": "#475467", "START": "#d0d5dd"}

A = {
    "zh": {"sec_verdict": "结论依据", "sec_timeline": "运行过程", "sec_anom": "运行中发现的情况",
           "sec_progress": "进度与中间结果", "sec_evals": "评估记录（最近）", "sec_best": "最好结果",
           "sec_train": "最近训练指标", "sec_files": "本次运行写出的文件", "sec_out": "程序最后的输出",
           "sec_out_before": "报错前的输出",
           "detected": "识别方式", "auto": "自动识别", "interp": "解释器", "score": "评分",
           "sources": "输出来源", "no_output": "未能读取程序输出（终端输出无法从外部读取）。想在邮件里看到报错：把输出重定向到文件，"
                                              "或在 tmux 中运行；Windows 上普通终端窗口可以自动读取。",
           "share": "时间占比", "avg_cpu": "平均 CPU", "avg_gpu": "平均 GPU 利用率", "conf": "置信度",
           "elapsed": "已运行", "eta": "预计剩余", "state_now": "当前状态", "latest": "最新评估",
           "inter_head": "📈 中间结果", "alert_head": "⚠️ 运行中提醒", "still": "程序仍在运行，本邮件不代表结束。"},
    "en": {"sec_verdict": "Why we think so", "sec_timeline": "What it did", "sec_anom": "Observed during the run",
           "sec_progress": "Progress & intermediate results", "sec_evals": "Recent evaluations", "sec_best": "Best values",
           "sec_train": "Latest training metrics", "sec_files": "Files written by this run", "sec_out": "Last output",
           "sec_out_before": "Output before the error",
           "detected": "Detection", "auto": "automatic", "interp": "Interpreter", "score": "score",
           "sources": "Output read from", "no_output": "Program output was not readable (terminal output cannot be read "
                                                     "from outside). Redirect to a file or run inside tmux.",
           "share": "Time share", "avg_cpu": "Average CPU", "avg_gpu": "Average GPU util", "conf": "confidence",
           "elapsed": "Elapsed", "eta": "ETA", "state_now": "Current state", "latest": "Latest evaluation",
           "inter_head": "📈 Intermediate results", "alert_head": "⚠️ Mid-run alert",
           "still": "The program is still running; this is not the final report."},
}
ICON = {"SUCCEEDED": "✅", "SUCCEEDED_UNVERIFIED": "✅", "FAILED": "❌", "LOST": "⚠️", "UNKNOWN": "❔",
        "CANCELED": "⏹", "TIMED_OUT": "⏱"}


def _state_shares(timeline) -> list:
    tot = {}
    for seg in timeline or []:
        st, a, b = seg[0], seg[1], seg[2]
        tot[st] = tot.get(st, 0.0) + max(0.0, (b or 0) - (a or 0))
    whole = sum(d for st, d in tot.items() if st != "START") or 1.0
    return sorted(((st, d, d / whole) for st, d in tot.items() if st != "START"), key=lambda x: -x[1])


def _bar_html(timeline, lang) -> str:
    shares = _state_shares(timeline)
    if not shares:
        return ""
    cells = "".join(f"<td style='background:{STATE_COLOR.get(st, '#999')};height:12px;padding:0' "
                    f"width='{max(1, round(p * 100))}%'></td>" for st, d, p in shares if p >= 0.005)
    legend = " · ".join(f"<span style='color:{STATE_COLOR.get(st, '#999')}'>■</span> "
                        f"{_e(STATE_LABEL[lang].get(st, st))} {p * 100:.0f}% ({util.fmt_duration(d)})"
                        for st, d, p in shares if p >= 0.005)
    return (f"<table width='100%' cellpadding='0' cellspacing='0' style='border-collapse:collapse;"
            f"border-radius:4px;overflow:hidden;margin:4px 0'><tr>{cells}</tr></table>"
            f"<div style='font-size:13px;color:#475467'>{legend}</div>")


def _segments_text(timeline, lang, limit=12) -> list[str]:
    segs = [s for s in timeline or [] if s[0] != "START"]
    total = sum(max(0, s[2] - s[1]) for s in segs) or 1
    keep = [s for s in segs if (s[2] - s[1]) / total >= 0.02 or s is segs[-1]]
    if len(keep) > limit:
        keep = keep[:limit // 2] + keep[-(limit - limit // 2):]
    out = []
    for st, a, b, n, cpu_sum, gpu_sum in keep:
        avg = f"CPU {cpu_sum / max(n, 1):.0f}%"
        if gpu_sum:
            avg += f", GPU {gpu_sum / max(n, 1):.0f}%"
        out.append(f"{util.local_str(a)[11:16]}–{util.local_str(b)[11:16]}  {STATE_LABEL[lang].get(st, st)}"
                   f"  {util.fmt_duration(b - a)}  ({avg})")
    return out


def _eval_rows(output: dict, limit=8) -> list[str]:
    rows = []
    for ts, ep, kvs in (output.get("evals") or [])[-limit:]:
        kv = ", ".join(f"{k}={v:.4g}" if isinstance(v, (int, float)) else f"{k}={v}" for k, v in list(kvs.items())[:8])
        rows.append(f"{util.local_str(ts)[5:16]}" + (f"  epoch {ep:g}" if isinstance(ep, (int, float)) else "") + f"  {kv}")
    return rows


def _avg_from_timeline(timeline) -> tuple:
    n = sum(s[3] for s in timeline or [])
    if not n:
        return None, None
    return sum(s[4] for s in timeline) / n, sum(s[5] for s in timeline) / n


def job_report(conn, cfg, run, severity: str, incident, prof: dict) -> dict:
    lang = _lang(cfg)
    T, X = L[lang], A[lang]
    ev = util.json_loads(run["evidence"], {}) or {}
    status = run["status"]
    verdict = ev.get("verdict") or status
    conf = ev.get("confidence")
    conf_txt = {"zh": {"high": "高", "medium": "中", "low": "低"}}.get(lang, {}).get(conf, conf) if conf else ""
    name = run["name"] or run["run_id"]
    dur = _duration(run)
    color = STATUS_COLORS.get(status, COLORS.get(severity, "#b42318"))
    head = f"{ICON.get(status, '•')} {verdict}" + (f"（{X['conf']}：{conf_txt}）" if conf_txt and lang == "zh" else
                                                   (f" ({X['conf']}: {conf_txt})" if conf_txt else ""))
    subject = f"[{status}][{severity}] {name} — {verdict[:60]}" + (f" · {util.fmt_duration(dur)}" if dur else "")
    doc = _Doc(f"{head} · {name}", color)
    doc.items(X["sec_verdict"], [redact(str(x)) for x in ev.get("evidence") or []])
    info = prof.get("info") or {}
    det = prof.get("detect") or util.json_loads(run["detect"], {}) or {}
    detect_txt = None
    if run["mode"] in ("auto", "interactive"):
        detect_txt = f"{X['auto']} ({X['score']} {det.get('score', '?')}): " + "; ".join(det.get("reasons") or [])[:300]
    doc.table(T["sec_facts"], [
        (T["command"], _command_str(run)), (T["cwd"], run["cwd"]), (X["interp"], info.get("exe")),
        ("PID", run["pid"]), (T["host"], cfg.host_name), (X["detected"], detect_txt),
        (T["start"], util.local_str(run["started_at"])), (T["end"], util.local_str(run["ended_at"])),
        (T["duration"], util.fmt_duration(dur)), (T["exit"], run["exit_desc"]),
        (T["severity"], severity), (T["incident"], incident["incident_id"] if incident is not None else None),
    ])
    tl = prof.get("timeline") or []
    if tl:
        doc.t.append(f"\n## {X['sec_timeline']}")
        shares = _state_shares(tl)
        doc.t.append(X["share"] + ": " + " · ".join(f"{STATE_LABEL[lang].get(st, st)} {p * 100:.0f}%"
                                                     for st, d, p in shares if p >= 0.005))
        obs = prof.get("observed_from")
        if obs and run["started_at"] and obs - run["started_at"] > 60:
            note = (f"（程序 {util.local_str(run['started_at'])[11:16]} 启动，{util.local_str(obs)[11:16]} 起被识别并开始观测）"
                    if lang == "zh" else f"(observed from {util.local_str(obs)[11:16]}; started "
                                         f"{util.local_str(run['started_at'])[11:16]})")
            doc.t.append(note)
            doc.h.append(f"<div style='font-size:12px;color:#667085'>{_e(note)}</div>")
        doc.h.append(f"<h3 style='margin:20px 0 6px;font-size:15px'>{_e(X['sec_timeline'])}</h3>" + _bar_html(tl, lang))
        doc.items("", _segments_text(tl, lang))
    anoms = prof.get("anomalies") or []
    doc.items(X["sec_anom"], [f"{util.local_str(a[0])[5:16]}  {a[1]}: {redact(str(a[2]))}" for a in anoms[-12:]])
    res = util.json_loads(run["resources"], {}) or {}
    rows = [(T.get(k, k), v) for k, v in resources.human_resources(res)]
    avg_cpu, avg_gpu = _avg_from_timeline(tl)
    if avg_cpu is not None:
        rows.insert(0, (X["avg_cpu"], f"{avg_cpu:.0f}% (100% = 1 core)"))
    if avg_gpu:
        rows.insert(1, (X["avg_gpu"], f"{avg_gpu:.0f}%"))
    doc.table(T["sec_resources"], rows)
    out = prof.get("output") or {}
    prog = prof.get("progress") or {}
    prow = []
    if prog.get("epoch") is not None:
        prow.append(("epoch", f"{prog['epoch']:g}" + (f" / {prog['epoch_total']}" if prog.get("epoch_total") else "")))
    if prog.get("bar"):
        prow.append(("progress bar", prog["bar"]))
    if out.get("checkpoint"):
        prow.append((T["checkpoint"], out["checkpoint"]))
    for k, v in list((out.get("train") or {}).items())[:6]:
        prow.append((k, f"{v:.5g}" if isinstance(v, (int, float)) else v))
    doc.table(X["sec_progress"], prow)
    doc.items(X["sec_best"], [f"{k} = {v[0]:.5g}" + (f"  (epoch {v[2]:g})" if isinstance(v[2], (int, float)) else "")
                              for k, v in list((out.get("best") or {}).items())[:10]])
    doc.items(X["sec_evals"], _eval_rows(out))
    files = prof.get("files") or []
    doc.items(X["sec_files"], [f"{p}  {util.fmt_bytes(s)}  {util.local_str(m)[11:19]}" for p, m, s in files[:12]])
    if ev.get("traceback"):
        tb = [ln for ln in ev["traceback"] if not _CARETS.match(ln)]
        doc.pre(T["traceback"], redact("\n".join(tb[-40:])))
    tail = [ln for ln in (prof.get("tail") or []) if not _CARETS.match(ln)]
    if tail and ev.get("traceback"):
        # the traceback is shown above; show what the program printed just before it
        start = max((i for i, ln in enumerate(tail) if ln.lstrip().startswith("Traceback (most recent call last)")),
                    default=len(tail))
        before = tail[max(0, start - 12):start]
        if before:
            doc.pre(X["sec_out_before"], redact("\n".join(before)))
    elif tail:
        doc.pre(X["sec_out"], redact("\n".join(tail[-30:])))
    srcs = prof.get("sources") or []
    if run["mode"] in ("auto", "interactive"):
        doc.para((X["sources"] + ": " + ", ".join(srcs)) if srcs else X["no_output"])
    code = run["failure_code"]
    doc.items(T["sec_runbook"], classify.runbook(code, lang) if status not in SUCCESS_LIKE else [], ordered=True)
    if incident is not None and severity in ("P0", "P1", "P2"):
        doc.para(T["ack_text"].format(iid=incident["incident_id"]))
    text, body = doc.render(_footer(cfg, lang))
    atts = []
    if status not in SUCCESS_LIKE and run["run_dir"]:
        p = os.path.join(run["run_dir"], "output_tail.txt")
        if os.path.exists(p) and os.path.getsize(p) > 0:
            atts.append({"path": p, "name": "output_tail.txt"})
    return {"subject": subject, "text": text, "html": body, "attachments": atts,
            "push_title": f"[{status}] {name}"[:80],
            "push_body": f"{verdict}\n{cfg.host_name} · {util.fmt_duration(dur)}"[:500]}


SUCCESS_LIKE = {"SUCCEEDED", "SUCCEEDED_UNVERIFIED", "CANCELED"}


def intermediate_report(cfg, run, view: dict, alert=None) -> dict:
    lang = _lang(cfg)
    T, X = L[lang], A[lang]
    name = run["name"] or run["run_id"]
    prog = view.get("progress") or {}
    out = view.get("output") or {}
    elapsed = util.now() - (run["started_at"] or util.now())
    if alert:
        code, text = alert
        title = classify.title(code, lang) or code
        head = f"{X['alert_head']}：{title}" if lang == "zh" else f"{X['alert_head']}: {title}"
        color = "#b54708"
        subject = f"[ALERT][P2] {name} — {title}"
    else:
        ep = f" · epoch {prog['epoch']:g}/{prog['epoch_total']}" if prog.get("epoch_total") else ""
        head = f"{X['inter_head']} · {name}{ep}"
        color = "#2f6fdb"
        subject = f"[PROGRESS] {name}{ep}"
    doc = _Doc(head, color)
    if alert:
        doc.para(redact(alert[1]))
    doc.para(X["still"])
    rows = [(X["state_now"], STATE_LABEL[lang].get(view.get("state"), view.get("state"))),
            (X["elapsed"], util.fmt_duration(elapsed))]
    if prog.get("epoch") is not None:
        rows.append(("epoch", f"{prog['epoch']:g}" + (f" / {prog['epoch_total']}" if prog.get("epoch_total") else "")))
    if prog.get("eta_s") is not None:
        rows.append((X["eta"], util.fmt_duration(prog["eta_s"])))
    evals = out.get("evals") or []
    if evals:
        ts, ep, kvs = evals[-1]
        rows.append((X["latest"], ", ".join(f"{k}={v:.4g}" for k, v in list(kvs.items())[:8])))
    doc.table(T["sec_facts"], rows + [(T["command"], _command_str(run)), (T["host"], cfg.host_name)])
    doc.items(X["sec_best"], [f"{k} = {v[0]:.5g}" for k, v in list((out.get("best") or {}).items())[:10]])
    doc.items(X["sec_evals"], _eval_rows(out, 10))
    doc.table(X["sec_train"], [(k, f"{v:.5g}") for k, v in list((out.get("train") or {}).items())[:8]
                               if isinstance(v, (int, float))])
    tl = view.get("timeline") or []
    if tl:
        doc.h.append(f"<h3 style='margin:20px 0 6px;font-size:15px'>{_e(X['sec_timeline'])}</h3>" + _bar_html(tl, lang))
        doc.t.append(f"\n## {X['sec_timeline']}\n" + " · ".join(
            f"{STATE_LABEL[lang].get(st, st)} {p * 100:.0f}%" for st, d, p in _state_shares(tl)))
    tail = [ln for ln in (view.get("tail") or []) if not _CARETS.match(ln)]
    doc.pre(X["sec_out"], redact("\n".join(tail[-12:])))
    text, body = doc.render(_footer(cfg, lang))
    return {"subject": subject, "text": text, "html": body, "push_title": subject[:80],
            "push_body": head + ("\n" + redact(alert[1]) if alert else "")}
