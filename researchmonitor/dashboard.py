"""Local web dashboard and setup page (http://127.0.0.1:<port>), standard library only.

Security: binds to 127.0.0.1 only; requires a session cookie obtained from a secret login link
(`rmon start` / `rmon dashboard` opens it); rejects foreign Host headers (DNS rebinding); every state change
is a POST with a CSRF token — never a GET (mail scanners and prefetchers follow GET links).
"""
from __future__ import annotations

import hmac
import html
import json
import os
import secrets
import sys
import threading
import urllib.parse
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from . import engine, identity, incidents, notify, store, util
from .classify import runbook, title as ftitle
from .config import SECRET_NAMES, get_secret, home_dir, load_config, save_config, set_secret
from .resources import human_resources

COOKIE = "rmon_session"


def _token() -> str:
    path = os.path.join(home_dir(), "dashboard_token")
    try:
        with open(path, "r") as f:
            t = f.read().strip()
            if len(t) >= 32:
                return t
    except OSError:
        pass
    t = secrets.token_urlsafe(32)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(t)
    return t


def _csrf(token: str) -> str:
    return hmac.new(token.encode(), b"csrf", "sha256").hexdigest()[:32]


e = lambda s: html.escape("" if s is None else str(s))  # noqa: E731

CSS = """
:root{--bg:#f6f6f4;--card:#fff;--fg:#1c1d1f;--mut:#6b6f76;--line:#e6e6e3;--acc:#2f5bd3;
--ok:#1a7f45;--bad:#c0362c;--warn:#b26a00;--unk:#6a5acd;--chip:#f0f0ed}
@media (prefers-color-scheme:dark){:root{--bg:#141517;--card:#1c1d20;--fg:#e8e8e6;--mut:#9a9da3;--line:#2c2e33;
--acc:#7aa2ff;--ok:#4cc38a;--bad:#ff6b5e;--warn:#f0b34a;--unk:#a99cff;--chip:#26282c}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);
font:14px/1.55 -apple-system,"Segoe UI","Microsoft YaHei",system-ui,sans-serif}
header{display:flex;gap:18px;align-items:center;padding:12px 20px;border-bottom:1px solid var(--line);
background:var(--card);position:sticky;top:0;flex-wrap:wrap;z-index:2}
header b{font-size:15px}header a{color:var(--mut);text-decoration:none}
header a.on,header a:hover{color:var(--fg)}main{max-width:1180px;margin:0 auto;padding:18px 16px 60px}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:12px;margin-bottom:16px}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:14px 16px}
.k{color:var(--mut);font-size:12px;letter-spacing:.3px}.v{font-size:22px;font-weight:600}
table{width:100%;border-collapse:collapse}th,td{text-align:left;padding:7px 8px;border-bottom:1px solid var(--line);
vertical-align:top}th{color:var(--mut);font-weight:500;font-size:12px}td a{color:var(--acc);text-decoration:none}
.pill{display:inline-block;padding:1px 8px;border-radius:999px;font-size:12px;font-weight:600;background:var(--chip)}
.s-SUCCEEDED,.s-SUCCEEDED_UNVERIFIED,.s-sent,.s-RESOLVED{color:var(--ok)}
.s-FAILED,.s-LOST,.s-TIMED_OUT,.s-failed,.s-OPEN,.s-P0,.s-P1,.s-IDLE{color:var(--bad)}
.s-RUNNING,.s-STARTING,.s-FINALIZING,.s-pending,.s-sending,.s-GPU,.s-CPU{color:var(--acc)}
.s-UNKNOWN{color:var(--unk)}.s-SUSPECTED_STALL,.s-P2,.s-ACKNOWLEDGED,.s-INVESTIGATING,.s-MITIGATED,.s-IO{color:var(--warn)}
h2{font-size:16px;margin:22px 0 10px}pre{background:var(--chip);border-radius:8px;padding:10px;overflow:auto;
font-size:12px;line-height:1.45;max-height:520px;white-space:pre-wrap;word-break:break-all}
.mut{color:var(--mut)}.row{display:flex;gap:10px;flex-wrap:wrap;align-items:center}
button{font:inherit;padding:5px 12px;border-radius:7px;border:1px solid var(--line);background:var(--card);
color:var(--fg);cursor:pointer}button.primary{background:var(--acc);color:#fff;border-color:var(--acc)}
dl{display:grid;grid-template-columns:max-content 1fr;gap:4px 14px;margin:0}dt{color:var(--mut)}dd{margin:0;
word-break:break-all}svg{display:block;width:100%;height:auto}.tl{font-size:12px}
.banner{background:#fff4e5;border:1px solid #f5c37a;color:#7a4b00;border-radius:10px;padding:12px 16px;margin-bottom:16px}
@media (prefers-color-scheme:dark){.banner{background:#3a2a10;border-color:#7a5a20;color:#f5d9a8}}
label{display:block;margin:10px 0 4px;color:var(--mut);font-size:13px}
input[type=text],input[type=password],input[type=email],select,textarea{font:inherit;width:100%;max-width:520px;
padding:7px 9px;border:1px solid var(--line);border-radius:7px;background:var(--card);color:var(--fg)}
textarea{min-height:64px}.hint{font-size:12px;color:var(--mut);margin-top:3px}
fieldset{border:1px solid var(--line);border-radius:10px;padding:8px 16px 16px;margin:0 0 14px;background:var(--card)}
legend{padding:0 6px;font-weight:600}.bar{display:flex;height:10px;border-radius:5px;overflow:hidden;margin:6px 0}
@media (max-width:640px){.hide-s{display:none}}
"""

STATE_ZH = {"GPU": "GPU 计算", "CPU": "CPU 计算", "IO": "数据读写", "LIGHT": "轻负载", "IDLE": "空闲",
            "PAUSED": "暂停", "START": "启动", "OK": ""}
STATE_COLOR = {"GPU": "#2f6fdb", "CPU": "#7a5af8", "IO": "#0e9384", "LIGHT": "#98a2b3", "IDLE": "#f04438",
               "PAUSED": "#475467", "START": "#d0d5dd"}


def _pill(s, label=None) -> str:
    return f"<span class='pill s-{e(s)}'>{e(label or s)}</span>" if s else ""


def _page(title: str, body: str, active: str = "", refresh: int = 0) -> bytes:
    nav = "".join(f"<a href='{h}' class='{'on' if active == k else ''}'>{t}</a>"
                  for k, h, t in (("runs", "/", "任务"), ("inc", "/incidents", "事件单"),
                                  ("notif", "/notifications", "邮件"), ("rules", "/rules", "识别规则"),
                                  ("setup", "/setup", "设置")))
    meta = f"<meta http-equiv='refresh' content='{refresh}'>" if refresh else ""
    cfg = load_config()
    return (f"<!doctype html><html lang='zh'><head><meta charset='utf-8'><meta name='viewport' "
            f"content='width=device-width,initial-scale=1'>{meta}<title>{e(title)} · ResearchMonitor</title>"
            f"<style>{CSS}</style></head><body><header><b>ResearchMonitor</b>{nav}"
            f"<span class='mut' style='margin-left:auto'>{e(cfg.host_name)}</span></header>"
            f"<main>{body}</main></body></html>").encode("utf-8")


def _spark(values, color="var(--acc)", h=60, fmt=lambda v: f"{v:.0f}") -> str:
    vals = [v for v in values if v is not None]
    if len(vals) < 2:
        return "<div class='mut'>样本不足</div>"
    w = 600
    lo, hi = min(vals), max(vals)
    span = (hi - lo) or 1
    pts = []
    n = len(values)
    for i, v in enumerate(values):
        if v is None:
            continue
        x = i * (w - 2) / max(1, n - 1) + 1
        y = h - 4 - (v - lo) / span * (h - 8)
        pts.append(f"{x:.1f},{y:.1f}")
    return (f"<svg viewBox='0 0 {w} {h}' preserveAspectRatio='none'><polyline fill='none' stroke='{color}' "
            f"stroke-width='1.6' points='{' '.join(pts)}'/></svg>"
            f"<div class='mut tl'>最低 {fmt(lo)} · 最高 {fmt(hi)} · 最近 {fmt(vals[-1])}</div>")


def _bar(timeline) -> str:
    tot = {}
    for seg in timeline or []:
        tot[seg[0]] = tot.get(seg[0], 0) + max(0, seg[2] - seg[1])
    whole = sum(v for k, v in tot.items() if k != "START") or 0
    if not whole:
        return ""
    parts = "".join(f"<div title='{e(STATE_ZH.get(k, k))} {v / whole * 100:.0f}%' style='background:"
                    f"{STATE_COLOR.get(k, '#999')};width:{v / whole * 100:.2f}%'></div>"
                    for k, v in sorted(tot.items(), key=lambda x: -x[1]) if k != "START")
    legend = " · ".join(f"<span style='color:{STATE_COLOR.get(k, '#999')}'>■</span> {e(STATE_ZH.get(k, k))} "
                        f"{v / whole * 100:.0f}%" for k, v in sorted(tot.items(), key=lambda x: -x[1]) if k != "START")
    return f"<div class='bar'>{parts}</div><div class='mut tl'>{legend}</div>"


def _dur(r):
    if not r["started_at"]:
        return None
    return (r["ended_at"] or util.now()) - r["started_at"]


def _email_ready(cfg) -> bool:
    b = cfg.get("notify.email_backend") or "none"
    if not cfg.email_to or b == "none":
        return False
    if b == "resend":
        return bool(get_secret("resend_api_key", cfg))
    if b == "smtp":
        return bool(cfg.get("smtp.host")) and bool(get_secret("smtp_password", cfg))
    return True


SMTP_PRESETS = {"qq": ("smtp.qq.com", 465, "ssl"), "163": ("smtp.163.com", 465, "ssl"),
                "126": ("smtp.126.com", 465, "ssl"), "gmail": ("smtp.gmail.com", 465, "ssl")}


class Handler(BaseHTTPRequestHandler):
    server_version = "ResearchMonitor"
    token = ""
    port = 0
    agent = None

    def log_message(self, *a):
        pass

    # ------------------------------------------------------------ plumbing
    def _host_ok(self) -> bool:
        host = (self.headers.get("Host") or "").lower()
        return host in (f"127.0.0.1:{self.port}", f"localhost:{self.port}")

    def _authed(self) -> bool:
        raw = self.headers.get("Cookie") or ""
        for part in raw.split(";"):
            k, _, v = part.strip().partition("=")
            if k == COOKIE and hmac.compare_digest(v, self.token):
                return True
        return False

    def _send(self, code: int, body: bytes, ctype="text/html; charset=utf-8", headers=None):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "same-origin")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; "
                                                    "img-src data:; form-action 'self'; frame-ancestors 'none'")
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _redirect(self, loc: str, headers=None):
        self._send(303, b"", headers=dict(headers or {}, Location=loc))

    def _form(self, action: str, label: str, primary=False, fields=None) -> str:
        hidden = "".join(f"<input type='hidden' name='{e(k)}' value='{e(v)}'>" for k, v in (fields or {}).items())
        return (f"<form method='post' action='{e(action)}' style='display:inline'>"
                f"<input type='hidden' name='csrf' value='{_csrf(self.token)}'>{hidden}"
                f"<button class='{'primary' if primary else ''}'>{e(label)}</button></form>")

    def do_GET(self):
        if not self._host_ok():
            return self._send(400, b"bad host")
        u = urllib.parse.urlparse(self.path)
        if u.path == "/login":
            tok = urllib.parse.parse_qs(u.query).get("token", [""])[0]
            nxt = urllib.parse.parse_qs(u.query).get("next", ["/"])[0]
            if not nxt.startswith("/") or nxt.startswith("//"):
                nxt = "/"
            if hmac.compare_digest(tok, self.token):
                return self._redirect(nxt, {"Set-Cookie": f"{COOKIE}={self.token}; HttpOnly; SameSite=Strict; "
                                                          f"Path=/; Max-Age=2592000"})
            return self._send(403, "登录链接无效，请重新运行「启动 ResearchMonitor」或 `rmon dashboard`".encode("utf-8"))
        if not self._authed():
            return self._send(401, _page("请登录", "<div class='card'>请在这台电脑上双击「启动 ResearchMonitor」"
                                         "或运行 <code>rmon dashboard</code> 打开面板。</div>"))
        conn = store.connect()
        try:
            parts = [urllib.parse.unquote(p) for p in u.path.split("/") if p]
            if not parts:
                body = self.page_overview(conn)
            elif parts[0] == "runs" and len(parts) == 2:
                body = self.page_run(conn, parts[1])
            elif parts[0] == "incidents" and len(parts) == 1:
                body = self.page_incidents(conn)
            elif parts[0] == "incidents" and len(parts) == 2:
                body = self.page_incident(conn, parts[1])
            elif parts == ["notifications"]:
                body = self.page_notifications(conn)
            elif parts == ["setup"]:
                q = urllib.parse.parse_qs(u.query)
                body = self.page_setup(q.get("msg", [""])[0])
            elif parts == ["rules"]:
                body = self.page_rules(conn)
            elif parts[0] == "api" and parts[-1] == "state.json":
                runs = [dict(r) for r in conn.execute("SELECT run_id,name,status,health,failure_code,started_at,"
                                                      "ended_at,mode FROM runs ORDER BY created_at DESC LIMIT 100")]
                data = {"runs": runs, "candidates": self.agent.candidates() if self.agent else []}
                return self._send(200, json.dumps(data, default=str).encode(), "application/json")
            else:
                return self._send(404, _page("未找到", "<div class='card'>页面不存在</div>"))
            self._send(200, body)
        finally:
            conn.close()

    def do_POST(self):
        if not self._host_ok() or not self._authed():
            return self._send(403, b"forbidden")
        origin = (self.headers.get("Origin") or "").lower()
        # "null" is what browsers send when an older page still carries a no-referrer policy or a privacy
        # extension strips the origin; the SameSite=Strict session cookie and the CSRF token still apply.
        if origin and origin != "null" and origin not in (f"http://127.0.0.1:{self.port}", f"http://localhost:{self.port}"):
            return self._send(403, "请求来源不对。请重新双击「Start ResearchMonitor.vbs」打开面板后再试。".encode("utf-8"))
        n = min(int(self.headers.get("Content-Length") or 0), 100000)
        form = {k: v[0] for k, v in urllib.parse.parse_qs(self.rfile.read(n).decode("utf-8", "replace"),
                                                          keep_blank_values=True).items()}
        if not hmac.compare_digest(form.get("csrf", ""), _csrf(self.token)):
            return self._send(403, b"bad csrf token")
        parts = [urllib.parse.unquote(p) for p in urllib.parse.urlparse(self.path).path.split("/") if p]
        conn = store.connect()
        try:
            actor = f"dashboard:{identity.current_user()}"
            if len(parts) == 3 and parts[0] == "incidents":
                iid, action = parts[1], parts[2]
                if action == "snooze":
                    incidents.snooze(conn, iid, 3600, actor)
                elif action in ("acknowledged", "investigating", "mitigated", "resolved"):
                    incidents.transition(conn, iid, action.upper(), actor, form.get("note"))
                return self._redirect(f"/incidents/{iid}")
            if parts == ["notifications", "retry"]:
                notify.retry_failed(conn)
                return self._redirect("/notifications")
            if len(parts) == 3 and parts[0] == "runs" and parts[2] == "stop":
                with store.tx(conn):
                    store.update_run(conn, parts[1], cancel_requested=1)
                    store.add_event(conn, "CANCEL_REQUESTED", parts[1], source="dashboard")
                return self._redirect(f"/runs/{urllib.parse.quote(parts[1])}")
            if parts == ["setup"]:
                msg = self.save_setup(form, conn)
                return self._redirect("/setup?msg=" + urllib.parse.quote(msg))
            if parts == ["rules", "add"]:
                pat = (form.get("pattern") or "").strip()
                if pat and form.get("action") in ("watch", "ignore"):
                    with store.tx(conn):
                        conn.execute("INSERT INTO rules(action,pattern,note,created_at) VALUES(?,?,?,?)",
                                     (form["action"], pat[:300], form.get("note", "")[:200], util.now()))
                return self._redirect(form.get("back") or "/rules")
            if len(parts) == 3 and parts[0] == "rules" and parts[2] == "delete":
                with store.tx(conn):
                    conn.execute("DELETE FROM rules WHERE id=?", (int(parts[1]),))
                return self._redirect("/rules")
            if parts == ["agent", "stop"] and self.agent is not None:
                self.agent.stop.set()
                return self._send(200, _page("已退出", "<div class='card'>后台监控已退出。再次双击「启动 ResearchMonitor」即可重新开始。</div>"))
            return self._send(404, b"not found")
        finally:
            conn.close()

    # ------------------------------------------------------------ setup
    def page_setup(self, msg: str = "") -> bytes:
        cfg = load_config()
        b = cfg.get("notify.email_backend") or "none"
        host = cfg.get("smtp.host") or ""
        preset = next((k for k, v in SMTP_PRESETS.items() if v[0] == host), "smtp" if host else "qq")
        method = "resend" if b == "resend" else (preset if b == "smtp" else ("file" if b in ("file", "none") else b))
        if b == "none" and not cfg.email_to:
            method = "resend"
        has = lambda name: "已设置（留空表示不修改）" if get_secret(name, cfg) else ""  # noqa: E731
        opts = [("resend", "Resend（推荐：用收件邮箱注册 resend.com，拿 API Key）"), ("qq", "QQ 邮箱（授权码）"),
                ("163", "163 邮箱（授权码）"), ("gmail", "Gmail（应用专用密码）"), ("smtp", "其他 SMTP 服务器"),
                ("file", "暂不发邮件（只写到本地文件）")]
        radios = "".join(f"<label style='color:inherit'><input type='radio' name='method' value='{k}' "
                         f"{'checked' if k == method else ''}> {e(t)}</label>" for k, t in opts)
        inter = str(cfg.get("notify.intermediate", "2h"))
        choices = [("off", "不发"), ("each", "每次出现新评估结果（最多 5 分钟一封）"), ("1h", "最多每 1 小时一封"),
                   ("2h", "最多每 2 小时一封"), ("6h", "最多每 6 小时一封")]
        if inter not in [v for v, _ in choices]:
            choices.insert(1, (inter, f"最多每 {inter} 一封（当前配置）"))
        inter_opts = "".join(f"<option value='{e(v)}' {'selected' if v == inter else ''}>{e(t)}</option>"
                             for v, t in choices)
        from . import service
        auto = "installed" in service.status() and "not installed" not in service.status()
        lines = lambda key: "\n".join(cfg.get(key) or [])  # noqa: E731
        banner = f"<div class='banner'>{e(msg)}</div>" if msg else ""
        body = f"""{banner}<h2 style='margin-top:0'>设置</h2>
<form method='post' action='/setup'><input type='hidden' name='csrf' value='{_csrf(self.token)}'>
<fieldset><legend>收件人</legend>
<label>通知发到哪个邮箱</label><input type='email' name='email_to' value='{e(", ".join(cfg.email_to))}'
 placeholder='you@outlook.com'>
<div class='hint'>Outlook 邮箱只能收信（微软已关闭 SMTP 密码登录），发信请在下面选一种方式。</div></fieldset>
<fieldset><legend>发信方式</legend>{radios}
<label>Resend API Key（re_ 开头）</label><input type='password' name='resend_key' placeholder='{e(has("resend_api_key"))}'>
<div class='hint'>在 resend.com 用上面的收件邮箱注册 → API Keys → Create。测试发件人只能发给注册邮箱本人。</div>
<label>发件邮箱（QQ / 163 / Gmail / 其他 SMTP）</label><input type='text' name='smtp_user' value='{e(cfg.get("smtp.username"))}'>
<label>授权码 / 应用专用密码</label><input type='password' name='smtp_pass' placeholder='{e(has("smtp_password"))}'>
<div class='hint'>QQ 邮箱：设置 → 账号 → 开启 SMTP 服务 → 生成授权码（不是 QQ 密码）。</div>
<label>其他 SMTP：服务器 / 端口 / 加密（ssl、starttls）</label>
<div class='row'><input type='text' name='smtp_host' value='{e(host if preset == "smtp" else "")}' style='max-width:240px' placeholder='smtp.example.com'>
<input type='text' name='smtp_port' value='{e(cfg.get("smtp.port"))}' style='max-width:90px'>
<input type='text' name='smtp_sec' value='{e(cfg.get("smtp.security"))}' style='max-width:110px'></div></fieldset>
<fieldset><legend>什么时候发邮件</legend>
<label><input type='checkbox' name='notify_success' {'checked' if cfg.get('notify.notify_success', True) else ''}> 成功结束也发报告（失败、中断一定会发）</label>
<label>中间结果邮件（从日志 / 终端识别到 val、eval、test 等评估结果时）</label><select name='intermediate'>{inter_opts}</select>
<label>多久没有任何计算和输出算「疑似卡死」</label><input type='text' name='stall_after' value='{e(cfg.get("monitor.stall_after"))}' style='max-width:120px'>
<div class='hint'>例如 30m、1h。只提醒一次，不会结束程序。</div></fieldset>
<fieldset><legend>识别哪些程序</legend>
<label>只监控运行超过</label><input type='text' name='min_age' value='{e(util.fmt_duration(float(cfg.get("discovery.min_age_s") or 0)))}' style='max-width:120px'>
<div class='hint'>更短的程序不会产生邮件。例如 2m、5m。</div>
<label>一定要监控的关键词（每行一个：脚本名、项目文件夹、命令里的词）</label><textarea name='watch'>{e(lines("discovery.watch"))}</textarea>
<label>不要监控的关键词（每行一个）</label><textarea name='ignore'>{e(lines("discovery.ignore"))}</textarea></fieldset>
<fieldset><legend>电脑断电 / 死机提醒（可选，推荐）</legend>
<label>healthchecks.io Ping URL</label><input type='text' name='ping_url' value='{e(cfg.get("heartbeat.ping_url"))}' placeholder='https://hc-ping.com/...'>
<label>healthchecks.io API Key（让空闲时自动暂停检查，避免关机误报）</label><input type='password' name='hc_key' placeholder='{e(has("healthchecks_api_key"))}'></fieldset>
<fieldset><legend>其他</legend>
<label>报告里这台电脑的名字</label><input type='text' name='host_name' value='{e(cfg.host_name)}'>
<label><input type='checkbox' name='autostart' {'checked' if auto else ''}> 开机（登录）后自动开始监控</label></fieldset>
<div class='row'><button class='primary' name='do' value='save'>保存</button>
<button name='do' value='test'>保存并发送测试邮件</button></div></form>"""
        return _page("设置", body, "setup")

    def save_setup(self, f: dict, conn) -> str:
        cfg = load_config()
        to = [x.strip() for x in (f.get("email_to") or "").replace(";", ",").split(",") if x.strip()]
        cfg.set("notify.email_to", to)
        m = f.get("method") or "resend"
        if m == "resend":
            cfg.set("notify.email_backend", "resend")
            if f.get("resend_key", "").strip():
                set_secret("resend_api_key", f["resend_key"].strip(), cfg)
        elif m in SMTP_PRESETS or m == "smtp":
            cfg.set("notify.email_backend", "smtp")
            if m in SMTP_PRESETS:
                h, p, s = SMTP_PRESETS[m]
            else:
                h = (f.get("smtp_host") or "").strip()
                try:
                    p = int(f.get("smtp_port") or 587)
                except ValueError:
                    return "保存失败：SMTP 端口必须是数字"
                s = (f.get("smtp_sec") or "starttls").strip()
            user = (f.get("smtp_user") or "").strip()
            cfg.set("smtp.host", h)
            cfg.set("smtp.port", p)
            cfg.set("smtp.security", s)
            cfg.set("smtp.username", user)
            cfg.set("smtp.from", f"ResearchMonitor <{user}>" if user else "")
            if f.get("smtp_pass", "").strip():
                set_secret("smtp_password", f["smtp_pass"].strip(), cfg)
        else:
            cfg.set("notify.email_backend", "file")
        cfg.set("notify.notify_success", f.get("notify_success") == "on")
        cfg.set("notify.intermediate", f.get("intermediate") or "2h")
        try:
            util.parse_duration(f.get("stall_after") or "30m")
            cfg.set("monitor.stall_after", f.get("stall_after") or "30m")
            cfg.set("discovery.min_age_s", int(util.parse_duration(f.get("min_age") or "2m", "m") or 0))
        except ValueError as ex:
            return f"保存失败：{ex}"
        split = lambda s: [x.strip() for x in (s or "").splitlines() if x.strip()]  # noqa: E731
        cfg.set("discovery.watch", split(f.get("watch")))
        cfg.set("discovery.ignore", split(f.get("ignore")))
        cfg.set("heartbeat.ping_url", (f.get("ping_url") or "").strip())
        if f.get("hc_key", "").strip():
            set_secret("healthchecks_api_key", f["hc_key"].strip(), cfg)
        if f.get("host_name", "").strip():
            cfg.set("general.host_name", f["host_name"].strip())
        save_config(cfg)
        from . import service
        try:
            st = service.status()
            installed = "installed" in st and "not installed" not in st
            if f.get("autostart") == "on" and not installed:
                service.install(start=False)
            elif f.get("autostart") != "on" and installed:
                service.uninstall(stop_agent=False)
        except Exception as ex:
            return f"已保存，但开机自启设置失败：{ex}"
        if f.get("do") == "test":
            from .cli import send_test
            ok, detail = send_test(cfg, conn)
            return ("已保存。测试邮件已发出，请查收（第一次请看看垃圾邮件文件夹）：" if ok else "已保存，但测试邮件发送失败：") + detail
        return "已保存。"

    # ------------------------------------------------------------ overview
    def page_overview(self, conn) -> bytes:
        cfg = load_config()
        info = util.json_loads(store.kv_get(conn, "agent"), {}) or {}
        live = self.agent.live_views() if self.agent else {}
        cands = [c for c in (self.agent.candidates() if self.agent else []) if not c["tracked"]]
        failed24 = conn.execute("SELECT COUNT(*) FROM runs WHERE status IN ('FAILED','LOST','TIMED_OUT','UNKNOWN') "
                                "AND ended_at>?", (util.now() - 86400,)).fetchone()[0]
        ok24 = conn.execute("SELECT COUNT(*) FROM runs WHERE status IN ('SUCCEEDED','SUCCEEDED_UNVERIFIED') "
                            "AND ended_at>?", (util.now() - 86400,)).fetchone()[0]
        active = store.active_runs(conn)
        body = ""
        if not _email_ready(cfg):
            body += "<div class='banner'>还没有配置发信方式，任务结束时无法发邮件。请先到 <a href='/setup'>设置</a> 填写。</div>"
        cpu = info.get("cpu_pct")
        self_txt = (f"{cpu:.2f}% CPU · {util.fmt_bytes(info.get('rss'))}" if cpu is not None
                    else util.fmt_bytes(info.get("rss")) if info.get("rss") else "—")
        cards = [("正在监控", len(active)), ("24 小时内成功", ok24), ("24 小时内失败/异常", failed24),
                 ("待发送邮件", notify.pending_count(conn)), ("本软件占用", self_txt)]
        body += "<div class='grid'>" + "".join(f"<div class='card'><div class='k'>{k}</div><div class='v'>{v}</div></div>"
                                              for k, v in cards) + "</div>"
        hb = store.kv_get(conn, "hb_last_result") or ("未配置" if not cfg.get("heartbeat.ping_url") else "—")
        body += (f"<div class='card mut tl'>后台监控：{'运行中' if engine.agent_alive(conn) else '未运行'} · "
                 f"远程心跳：{e(hb)} · 邮件：{e(cfg.get('notify.email_backend'))} → {e(', '.join(cfg.email_to) or '-')}"
                 + (" · " + self._form("/agent/stop", "退出后台监控") if self.agent else "") + "</div>")
        if active:
            body += "<h2>正在运行</h2><div class='card'><table><tr><th>程序</th><th>状态</th><th>进度</th>" \
                    "<th class='hide-s'>已运行</th><th>最新指标</th></tr>"
            for r in active:
                v = live.get(r["run_id"], {})
                prog = v.get("progress") or {}
                ptxt = ""
                if prog.get("epoch") is not None:
                    ptxt = f"epoch {prog['epoch']:g}" + (f"/{prog['epoch_total']}" if prog.get("epoch_total") else "")
                if prog.get("eta_s") is not None:
                    ptxt += f" · 剩余 {util.fmt_duration(prog['eta_s'])}"
                out = v.get("output") or {}
                ev = (out.get("evals") or [])[-1:] or []
                met = ", ".join(f"{k}={val:.4g}" for k, val in list(ev[0][2].items())[:4]) if ev else \
                    ", ".join(f"{k}={val:.4g}" for k, val in list((out.get("train") or {}).items())[:3])
                st = v.get("state") or r["health"]
                body += (f"<tr><td><a href='/runs/{urllib.parse.quote(r['run_id'])}'>{e(r['name'])}</a>"
                         f"<div class='mut tl'>{e(render_cmd(r)[:90])}</div></td>"
                         f"<td>{_pill(st, STATE_ZH.get(st, st))}</td><td>{e(ptxt)}</td>"
                         f"<td class='hide-s'>{util.fmt_duration(_dur(r))}</td><td class='tl'>{e(met)}</td></tr>")
            body += "</table></div>"
        if cands:
            body += ("<h2>识别到但未监控的程序</h2><div class='mut tl' style='margin-bottom:6px'>得分不够或运行时间太短。"
                     "觉得是你的实验，就点「监控它」；以后同名脚本也会自动监控。</div><div class='card'><table>"
                     "<tr><th>程序</th><th>得分</th><th class='hide-s'>依据</th><th></th></tr>")
            for c in cands[:15]:
                pat = _pattern_for(c)
                acts = "" if c.get("excluded") else (
                    self._form("/rules/add", "监控它", True, {"action": "watch", "pattern": pat, "back": "/"}) + " ")
                acts += self._form("/rules/add", "忽略", False, {"action": "ignore", "pattern": pat, "back": "/"})
                why = c.get("excluded") or "; ".join(c.get("reasons") or [])
                body += (f"<tr><td>{e(c['cmd'][:110])}<div class='mut tl'>PID {c['pid']} · 已运行 "
                         f"{util.fmt_duration(c.get('age_s'))}</div></td><td>{c['score']}</td>"
                         f"<td class='hide-s tl'>{e(why[:200])}</td><td style='white-space:nowrap'>{acts}</td></tr>")
            body += "</table></div>"
        open_inc = conn.execute("SELECT * FROM incidents WHERE status!='RESOLVED' ORDER BY created_at DESC "
                                "LIMIT 20").fetchall()
        if open_inc:
            body += "<h2>未处理的事件单</h2><div class='card'><table>"
            for i in open_inc:
                body += (f"<tr><td><a href='/incidents/{e(i['incident_id'])}'>{e(i['incident_id'])}</a></td>"
                         f"<td>{_pill(i['severity'])}</td><td>{_pill(i['status'])}</td><td>{e(i['title'])}</td>"
                         f"<td class='hide-s'>{util.local_str(i['created_at'])}</td></tr>")
            body += "</table></div>"
        rows = conn.execute("SELECT * FROM runs WHERE status NOT IN ('CREATED','STARTING','RUNNING','FINALIZING') "
                            "ORDER BY created_at DESC LIMIT 60").fetchall()
        body += "<h2>已结束</h2><div class='card'><table><tr><th>程序</th><th>结果</th><th class='hide-s'>开始</th>" \
                "<th>用时</th><th>结论</th></tr>"
        for r in rows:
            ev = util.json_loads(r["evidence"], {}) or {}
            concl = ev.get("verdict") or r["failure_code"] or ""
            body += (f"<tr><td><a href='/runs/{urllib.parse.quote(r['run_id'])}'>{e(r['name'])}</a>"
                     f"<div class='mut tl'>{e(r['run_id'])}</div></td><td>{_pill(r['status'])}</td>"
                     f"<td class='hide-s'>{util.local_str(r['started_at'] or r['created_at'])}</td>"
                     f"<td>{util.fmt_duration(_dur(r))}</td><td class='tl'>{e(concl)}</td></tr>")
        body += "</table></div>" if rows else "<tr><td colspan=5 class='mut'>还没有结束的任务。</td></tr></table></div>"
        return _page("任务", body, "runs", refresh=15)

    def page_run(self, conn, run_id: str) -> bytes:
        r = store.get_run(conn, run_id)
        if r is None:
            return _page("未找到", "<div class='card'>任务不存在</div>")
        lang = load_config().get("general.language") or "zh"
        live = (self.agent.live_views() if self.agent else {}).get(run_id)
        prof = live or util.json_loads(r["profile"], {}) or {}
        ev = util.json_loads(r["evidence"], {}) or {}
        body = f"<div class='row'><h2 style='margin:0'>{e(r['name'])}</h2>{_pill(r['status'])}"
        if r["mode"] in ("managed",) and r["status"] not in store.TERMINAL:
            body += self._form(f"/runs/{urllib.parse.quote(run_id)}/stop", "停止任务")
        body += "</div>"
        if ev.get("verdict"):
            conf = {"high": "高", "medium": "中", "low": "低"}.get(ev.get("confidence"), ev.get("confidence") or "")
            body += (f"<div class='card' style='margin-top:12px'><b>{e(ev['verdict'])}</b>"
                     + (f" <span class='mut'>（置信度：{e(conf)}）</span>" if conf else "") +
                     "<ul>" + "".join(f"<li>{e(x)}</li>" for x in ev.get("evidence") or []) + "</ul></div>")
        det = util.json_loads(r["detect"], {}) or {}
        facts = [("运行 ID", r["run_id"]), ("方式", {"auto": "自动识别", "interactive": "交互式会话（Jupyter/IPython）",
                                                 "managed": "rmon run 启动", "attached": "rmon attach"}.get(r["mode"], r["mode"])),
                 ("命令", render_cmd(r)), ("目录", r["cwd"]), ("PID", r["pid"]),
                 ("识别依据", (f"得分 {det.get('score')}：" + "; ".join(det.get("reasons") or [])) if det else None),
                 ("开始", util.local_str(r["started_at"])), ("结束", util.local_str(r["ended_at"])),
                 ("用时", util.fmt_duration(_dur(r))), ("退出码", r["exit_desc"]),
                 ("失败类型", f"{ftitle(r['failure_code'], lang)} ({r['failure_code']})" if r["failure_code"] else None),
                 ("事件单", r["incident_id"]), ("输出来源", ", ".join(prof.get("sources") or []) or None)]
        body += "<div class='card' style='margin-top:12px'><dl>" + "".join(
            f"<dt>{k}</dt><dd>{e(v)}</dd>" for k, v in facts if v not in (None, "")) + "</dl></div>"
        tl = prof.get("timeline") or []
        if tl:
            body += "<h2>运行过程</h2><div class='card'>" + _bar(tl) + "</div>"
        anoms = prof.get("anomalies") or []
        if anoms:
            body += "<h2>运行中发现的情况</h2><div class='card'><ul>" + "".join(
                f"<li>{util.local_str(a[0])} {e(a[1])}: {e(a[2])}</li>" for a in anoms[-15:]) + "</ul></div>"
        out = prof.get("output") or {}
        prog = prof.get("progress") or {}
        if out.get("evals") or out.get("train") or prog:
            body += "<h2>进度与中间结果</h2><div class='card'>"
            if prog.get("epoch") is not None:
                body += f"<div>epoch {prog['epoch']:g}" + (f" / {prog['epoch_total']}" if prog.get("epoch_total") else "")
                body += (f" · 预计剩余 {util.fmt_duration(prog['eta_s'])}" if prog.get("eta_s") is not None else "") + "</div>"
            if out.get("best"):
                body += "<div class='tl'>最好：" + e(", ".join(f"{k}={v[0]:.4g}" for k, v in out["best"].items())) + "</div>"
            if out.get("evals"):
                body += "<table class='tl'>" + "".join(
                    f"<tr><td>{util.local_str(ts)[5:16]}</td><td>{'' if ep is None else 'epoch %g' % ep}</td>"
                    f"<td>{e(', '.join(f'{k}={v:.4g}' for k, v in kv.items()))}</td></tr>"
                    for ts, ep, kv in out["evals"][-15:]) + "</table>"
            body += "</div>"
        rb = runbook(r["failure_code"], lang) if r["status"] not in ("SUCCEEDED", "SUCCEEDED_UNVERIFIED") else []
        if rb:
            body += "<h2>处理建议</h2><div class='card'><ol>" + "".join(f"<li>{e(x)}</li>" for x in rb) + "</ol></div>"
        res = human_resources(util.json_loads(r["resources"], {}))
        samples = store.samples_for(conn, run_id, 400)
        if res or samples:
            from .render import L as _labels
            body += "<h2>资源</h2><div class='grid'>" + "".join(
                f"<div class='card'><div class='k'>{e(_labels['zh'].get(k, k))}</div><div>{e(v)}</div></div>"
                for k, v in res) + "</div>"
            if samples:
                body += "<div class='grid' style='grid-template-columns:repeat(auto-fit,minmax(280px,1fr))'>"
                body += f"<div class='card'><div class='k'>CPU %（含子进程）</div>{_spark([s['cpu'] for s in samples])}</div>"
                body += (f"<div class='card'><div class='k'>内存</div>"
                         f"{_spark([s['rss'] for s in samples], fmt=util.fmt_bytes)}</div>")
                if any(s["gpu_util"] for s in samples):
                    body += f"<div class='card'><div class='k'>GPU 利用率</div>{_spark([s['gpu_util'] for s in samples])}</div>"
                if any(s["gpu_mem"] for s in samples):
                    body += (f"<div class='card'><div class='k'>GPU 显存</div>"
                             f"{_spark([s['gpu_mem'] for s in samples], fmt=util.fmt_bytes)}</div>")
                body += "</div>"
        tail = prof.get("tail") or []
        if not tail and r["log_path"] and os.path.exists(r["log_path"]):
            tail = util.tail_lines(util.decode_output(util.read_tail_bytes(r["log_path"], 96 * 1024)), 200)
        body += "<h2>最后的输出</h2>" + (f"<pre>{e(chr(10).join(tail[-200:]))}</pre>" if tail else
                                        "<div class='card mut'>（没有读到输出）</div>")
        files = prof.get("files") or []
        if files:
            body += "<h2>写出的文件</h2><div class='card'><table class='tl'>" + "".join(
                f"<tr><td>{e(p)}</td><td>{util.fmt_bytes(s)}</td><td>{util.local_str(m)}</td></tr>"
                for p, m, s in files) + "</table></div>"
        body += "<h2>事件</h2><div class='card'><table class='tl'>" + "".join(
            f"<tr><td>{util.local_str(x['ts'])}</td><td>{e(x['type'])}</td><td class='mut'>{e(x['source'])}</td></tr>"
            for x in store.run_events(conn, run_id)) + "</table></div>"
        notes = conn.execute("SELECT * FROM notifications WHERE run_id=? ORDER BY created_at", (run_id,)).fetchall()
        if notes:
            body += "<h2>邮件</h2><div class='card'><table class='tl'>" + "".join(
                f"<tr><td>{_pill(n['status'])}</td><td>{e(n['channel'])}</td><td>{e(n['subject'])}</td>"
                f"<td class='mut'>{e(n['last_error'] or '')}</td></tr>" for n in notes) + "</table></div>"
        return _page(r["name"] or run_id, body, "runs", refresh=0 if r["status"] in store.TERMINAL else 15)

    def page_rules(self, conn) -> bytes:
        cfg = load_config()
        rows = conn.execute("SELECT * FROM rules ORDER BY id DESC").fetchall()
        body = ("<h2 style='margin-top:0'>识别规则</h2><div class='mut' style='margin-bottom:8px'>命令行或工作目录里包含这些文字的"
                "程序会被一定监控 / 一定忽略。也可以在 <a href='/setup'>设置</a> 里按行填写。</div><div class='card'><table>"
                "<tr><th>动作</th><th>匹配</th><th>添加时间</th><th></th></tr>")
        for r in rows:
            act = "监控" if r["action"] == "watch" else "忽略"
            delete = self._form("/rules/%d/delete" % r["id"], "删除")
            body += (f"<tr><td>{act}</td><td>{e(r['pattern'])}</td>"
                     f"<td>{util.local_str(r['created_at'])}</td><td>{delete}</td></tr>")
        for p in cfg.get("discovery.watch") or []:
            body += f"<tr><td>监控</td><td>{e(p)}</td><td class='mut'>设置页</td><td></td></tr>"
        for p in cfg.get("discovery.ignore") or []:
            body += f"<tr><td>忽略</td><td>{e(p)}</td><td class='mut'>设置页</td><td></td></tr>"
        body += "</table></div>"
        body += (f"<h2>添加规则</h2><form method='post' action='/rules/add' class='card'>"
                 f"<input type='hidden' name='csrf' value='{_csrf(self.token)}'>"
                 f"<div class='row'><select name='action' style='max-width:120px'><option value='watch'>监控</option>"
                 f"<option value='ignore'>忽略</option></select><input type='text' name='pattern' "
                 f"placeholder='例如 train.py、D:\\projects\\CityMemory、finetune' style='max-width:420px'>"
                 f"<button class='primary'>添加</button></div></form>")
        return _page("识别规则", body, "rules")

    def page_incidents(self, conn) -> bytes:
        rows = conn.execute("SELECT * FROM incidents ORDER BY created_at DESC LIMIT 200").fetchall()
        body = "<h2>事件单</h2><div class='card'><table><tr><th>ID</th><th>级别</th><th>状态</th><th>标题</th>" \
               "<th class='hide-s'>时间</th><th class='hide-s'>任务数</th></tr>"
        for i in rows:
            body += (f"<tr><td><a href='/incidents/{e(i['incident_id'])}'>{e(i['incident_id'])}</a></td>"
                     f"<td>{_pill(i['severity'])}</td><td>{_pill(i['status'])}</td><td>{e(i['title'])}</td>"
                     f"<td class='hide-s'>{util.local_str(i['created_at'])}</td>"
                     f"<td class='hide-s'>{len(util.json_loads(i['runs'], []) or [])}</td></tr>")
        body += "</table></div>" if rows else "<tr><td colspan=6 class='mut'>没有事件单。</td></tr></table></div>"
        return _page("事件单", body, "inc")

    def page_incident(self, conn, iid: str) -> bytes:
        i = incidents.get(conn, iid)
        if i is None:
            return _page("未找到", "<div class='card'>事件单不存在</div>")
        body = f"<div class='row'><h2 style='margin:0'>{e(iid)}</h2>{_pill(i['severity'])}{_pill(i['status'])}</div>"
        body += f"<p>{e(i['title'])}</p>"
        if i["status"] != "RESOLVED":
            body += "<div class='row'>"
            if i["status"] == "OPEN":
                body += self._form(f"/incidents/{iid}/acknowledged", "确认", primary=True)
                body += self._form(f"/incidents/{iid}/snooze", "1 小时内不提醒")
            for st, label in (("investigating", "调查中"), ("mitigated", "已缓解"), ("resolved", "已解决")):
                body += self._form(f"/incidents/{iid}/{st}", label)
            body += "</div>"
        body += (f"<div class='card' style='margin-top:12px'><dl><dt>创建</dt><dd>{util.local_str(i['created_at'])}</dd>"
                 f"<dt>确认</dt><dd>{util.local_str(i['acked_at'])} {e(i['acked_by'] or '')}</dd>"
                 f"<dt>解决</dt><dd>{util.local_str(i['resolved_at'])}</dd></dl></div>")
        runs = util.json_loads(i["runs"], []) or []
        if runs:
            body += "<h2>相关任务</h2><div class='card'><table>"
            for rid in runs:
                r = store.get_run(conn, rid)
                if r is not None:
                    body += (f"<tr><td><a href='/runs/{urllib.parse.quote(rid)}'>{e(r['name'])}</a></td>"
                             f"<td>{_pill(r['status'])}</td><td>{e((r['failure_summary'] or '')[:200])}</td></tr>")
            body += "</table></div>"
        body += "<h2>时间线</h2><div class='card'><table class='tl'>" + "".join(
            f"<tr><td>{util.local_str(x['ts'])}</td><td>{e(x['action'])}</td><td>{e(x['actor'])}</td>"
            f"<td class='mut'>{e(x['detail'] or '')}</td></tr>" for x in incidents.timeline(conn, iid)) + "</table></div>"
        return _page(iid, body, "inc")

    def page_notifications(self, conn) -> bytes:
        rows = conn.execute("SELECT * FROM notifications ORDER BY created_at DESC LIMIT 200").fetchall()
        failed = sum(1 for n in rows if n["status"] == "failed")
        body = "<div class='row'><h2 style='margin:0'>邮件</h2>"
        if failed:
            body += self._form("/notifications/retry", f"重试 {failed} 封失败的邮件")
        body += "</div><div class='card' style='margin-top:12px'><table><tr><th>时间</th><th>状态</th><th>渠道</th>" \
                "<th>级别</th><th>主题</th><th class='hide-s'>尝试</th></tr>"
        for n in rows:
            body += (f"<tr><td>{util.local_str(n['created_at'])}</td><td>{_pill(n['status'])}</td>"
                     f"<td>{e(n['channel'])}</td><td>{e(n['severity'])}</td><td>{e(n['subject'])}"
                     + (f"<div class='mut tl'>{e(n['last_error'])}</div>" if n["last_error"] else "")
                     + f"</td><td class='hide-s'>{n['attempts']}</td></tr>")
        body += "</table></div>"
        return _page("邮件", body, "notif", refresh=20)


def render_cmd(r) -> str:
    from .render import _command_str
    return _command_str(r)


def _pattern_for(c: dict) -> str:
    from .discovery import SCRIPT_EXT
    parts = (c.get("cmd") or "").split()
    for p in parts[1:]:
        if SCRIPT_EXT.search(p):
            return os.path.basename(p)
    return os.path.basename(parts[0]) if parts else str(c.get("pid"))


class _Server(ThreadingHTTPServer):
    allow_reuse_address = sys.platform != "win32"
    daemon_threads = True


def start_server(port: int, agent=None) -> tuple:
    token = _token()
    last_err = None
    for p in [port] + list(range(port + 1, port + 10)):
        handler = type("H", (Handler,), {"token": token, "port": p, "agent": agent})
        try:
            srv = _Server(("127.0.0.1", p), handler)
        except OSError as ex:
            last_err = ex
            continue
        handler.port = srv.server_address[1]
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        return srv, srv.server_address[1]
    raise OSError(f"no free port near {port}: {last_err}")


def login_url(port: int, nxt: str = "/") -> str:
    return f"http://127.0.0.1:{port}/login?token={_token()}" + (f"&next={urllib.parse.quote(nxt)}" if nxt != "/" else "")


def open_or_serve(no_browser: bool = False, port: int | None = None) -> int:
    conn = store.connect()
    info = util.json_loads(store.kv_get(conn, "agent"), None) or {}
    if engine.agent_alive(conn) and info.get("port") and not port:
        url = login_url(info["port"])
        print(f"dashboard (served by the agent): {url}")
        if not no_browser:
            webbrowser.open(url)
        return 0
    cfg = load_config()
    srv, p = start_server(port or int(cfg.get("dashboard.port") or 8765))
    url = login_url(p)
    print(f"dashboard: {url}\n(agent not running, serving from this terminal; Ctrl+C to stop)")
    if not no_browser:
        webbrowser.open(url)
    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        srv.shutdown()
    return 0
