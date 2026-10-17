"""Delivery channels. Each `send_*` raises NotifyError(permanent=...) on failure."""
from __future__ import annotations

import base64
import email.utils
import json
import mimetypes
import os
import smtplib
import socket
import ssl
import urllib.error
import urllib.request
from email.message import EmailMessage

from .. import util
from ..config import get_secret, home_dir

USER_AGENT = "ResearchMonitor/0.1 (+local agent)"


class NotifyError(Exception):
    def __init__(self, msg: str, permanent: bool = False):
        super().__init__(msg)
        self.permanent = permanent


def _attachments(row) -> list[dict]:
    items = util.json_loads(row["attachments"], []) or []
    out = []
    for a in items:
        p = a.get("path")
        if p and os.path.isfile(p):
            out.append({"path": p, "name": a.get("name") or os.path.basename(p)})
    return out


def build_email(cfg, row, sender: str) -> EmailMessage:
    msg = EmailMessage()
    msg["Subject"] = row["subject"]
    msg["From"] = sender
    msg["To"] = ", ".join(cfg.email_to)
    msg["Date"] = email.utils.formatdate(localtime=True)
    domain = sender.rsplit("@", 1)[-1].strip("> ") or "researchmonitor.local"
    # stable id per logical notification so retries are recognisable as the same message
    msg["Message-ID"] = f"<{row['notification_id'].replace(':', '.')}@{domain}>"
    msg["X-RMon-Notification-ID"] = row["notification_id"]
    msg.set_content(row["body_text"] or "")
    if row["body_html"]:
        msg.add_alternative(row["body_html"], subtype="html")
    for a in _attachments(row):
        ctype, _ = mimetypes.guess_type(a["name"])
        maintype, subtype = (ctype or "application/octet-stream").split("/", 1)
        with open(a["path"], "rb") as f:
            msg.add_attachment(f.read(), maintype=maintype, subtype=subtype, filename=a["name"])
    return msg


# --------------------------------------------------------------------------- email backends

def send_smtp(cfg, row) -> str:
    host = cfg.get("smtp.host")
    port = int(cfg.get("smtp.port") or 465)
    security = (cfg.get("smtp.security") or "ssl").lower()
    user = cfg.get("smtp.username") or ""
    password = get_secret("smtp_password", cfg)
    sender = cfg.get("smtp.from") or user
    if not host or not cfg.email_to:
        raise NotifyError("SMTP host or recipient not configured", permanent=True)
    if user and not password:
        raise NotifyError("SMTP password not set (run `rmon secret set smtp_password`)", permanent=True)
    msg = build_email(cfg, row, sender)
    ctx = ssl.create_default_context()
    timeout = float(cfg.get("smtp.timeout_s") or 30)
    s = None
    try:
        if security == "ssl":
            s = smtplib.SMTP_SSL(host, port, timeout=timeout, context=ctx)
        else:
            s = smtplib.SMTP(host, port, timeout=timeout)
        s.ehlo()
        if security == "starttls":
            s.starttls(context=ctx)
            s.ehlo()
        if user:
            s.login(user, password)
        refused = s.send_message(msg)
        # The message is accepted at this point. Do NOT use `with smtplib.SMTP(...)`: some servers
        # (notably smtp.qq.com) answer QUIT with a malformed reply, and __exit__ would raise — the
        # message would then be "retried" and delivered again and again.
        try:
            s.quit()
        except Exception:
            pass
        if refused:
            return f"accepted by SMTP server; some recipients refused: {refused}"
        return "accepted by SMTP server"
    except smtplib.SMTPAuthenticationError as e:
        raise NotifyError(f"SMTP authentication failed ({e.smtp_code}): check username / authorization code. "
                          "Note: Outlook.com no longer accepts passwords over SMTP.", permanent=True)
    except smtplib.SMTPRecipientsRefused as e:
        raise NotifyError(f"recipient refused: {e.recipients}", permanent=True)
    except smtplib.SMTPResponseException as e:
        # 5xx = the server rejected the message for good; 4xx = try again later
        raise NotifyError(f"SMTP error {e.smtp_code}: {e.smtp_error!r}"[:300], permanent=500 <= e.smtp_code < 600)
    except (smtplib.SMTPException, OSError, socket.timeout, ssl.SSLError) as e:
        raise NotifyError(f"SMTP connection problem: {e}"[:300])
    finally:
        if s is not None:
            try:
                s.close()
            except Exception:
                pass


def _http_json(url: str, payload: dict, headers: dict, timeout: float = 30) -> tuple[int, str]:
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=data, method="POST",
                                 headers={"Content-Type": "application/json", "User-Agent": USER_AGENT, **headers})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, resp.read(2000).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read(2000).decode("utf-8", "replace")
    except (urllib.error.URLError, OSError, socket.timeout) as e:
        raise NotifyError(f"network error: {getattr(e, 'reason', e)}"[:300])


def send_resend(cfg, row) -> str:
    key = get_secret("resend_api_key", cfg)
    if not key:
        raise NotifyError("Resend API key not set (run `rmon secret set resend_api_key`)", permanent=True)
    if not cfg.email_to:
        raise NotifyError("no recipient configured", permanent=True)
    payload = {"from": cfg.get("resend.from"), "to": cfg.email_to, "subject": row["subject"],
               "text": row["body_text"] or "", "headers": {"X-RMon-Notification-ID": row["notification_id"]}}
    if row["body_html"]:
        payload["html"] = row["body_html"]
    atts = []
    for a in _attachments(row):
        with open(a["path"], "rb") as f:
            atts.append({"filename": a["name"], "content": base64.b64encode(f.read()).decode()})
    if atts:
        payload["attachments"] = atts
    # A stable Idempotency-Key lets the provider drop a retried request whose first response was lost
    # (ignored harmlessly where unsupported).
    status, body = _http_json(cfg.get("resend.api_url"), payload,
                              {"Authorization": f"Bearer {key}", "Idempotency-Key": row["notification_id"][:256]})
    if 200 <= status < 300:
        return f"accepted by Resend: {body[:120]}"
    permanent = status in (400, 401, 403, 404, 422)
    hint = ""
    if status == 403:
        hint = (" (with onboarding@resend.dev you can only send to the address you registered at Resend; "
                "make sure email_to is exactly that address)")
    raise NotifyError(f"Resend HTTP {status}: {body[:300]}{hint}", permanent=permanent)


def send_file(cfg, row) -> str:
    d = os.path.join(home_dir(), "mail_outbox")
    os.makedirs(d, exist_ok=True)
    sender = "ResearchMonitor <rmon@localhost>"
    msg = build_email(cfg, row, sender)
    path = os.path.join(d, row["notification_id"].replace(":", "_") + ".eml")
    with open(path, "wb") as f:
        f.write(bytes(msg))
    return f"written to {path}"


# --------------------------------------------------------------------------- push backends

def send_ntfy(cfg, row) -> str:
    url = cfg.get("ntfy.url")
    if not url:
        raise NotifyError("ntfy.url not configured", permanent=True)
    prio = {"P0": "5", "P1": "5", "P2": "3", "P3": "2"}.get(row["severity"], "3")
    headers = {"Title": _ascii_header(row["push_title"] or row["subject"] or ""), "Priority": prio,
               "Tags": "rotating_light" if row["severity"] in ("P0", "P1") else "bell", "User-Agent": USER_AGENT}
    token = get_secret("ntfy_token", cfg)
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(url, data=(row["push_body"] or "").encode("utf-8"), method="POST", headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            return f"ntfy HTTP {resp.status}"
    except urllib.error.HTTPError as e:
        raise NotifyError(f"ntfy HTTP {e.code}", permanent=e.code in (400, 401, 403, 404))
    except (urllib.error.URLError, OSError) as e:
        raise NotifyError(f"ntfy network error: {getattr(e, 'reason', e)}")


def _ascii_header(text: str) -> str:
    # HTTP headers must be latin-1; use RFC 2047 encoding for non-ASCII titles (ntfy supports it)
    try:
        text.encode("latin-1")
        return text
    except UnicodeEncodeError:
        return "=?UTF-8?B?" + base64.b64encode(text.encode("utf-8")).decode() + "?="


def send_serverchan(cfg, row) -> str:
    key = get_secret("serverchan_sendkey", cfg)
    if not key:
        raise NotifyError("ServerChan SendKey not set", permanent=True)
    url = f"https://sctapi.ftqq.com/{key}.send"
    status, body = _http_json(url, {"title": (row["push_title"] or row["subject"] or "")[:32],
                                    "desp": row["push_body"] or ""}, {})
    if 200 <= status < 300 and '"code":0' in body.replace(" ", ""):
        return "accepted by ServerChan"
    raise NotifyError(f"ServerChan HTTP {status}: {body[:200]}", permanent=status in (400, 401, 403))


def send_webhook(cfg, row) -> str:
    url = cfg.get("webhook.url")
    if not url:
        raise NotifyError("webhook.url not configured", permanent=True)
    status, body = _http_json(url, {"title": row["push_title"] or row["subject"], "body": row["push_body"],
                                    "severity": row["severity"], "kind": row["kind"], "run_id": row["run_id"],
                                    "incident_id": row["incident_id"], "id": row["notification_id"]}, {})
    if 200 <= status < 300:
        return f"webhook HTTP {status}"
    raise NotifyError(f"webhook HTTP {status}: {body[:200]}", permanent=400 <= status < 500 and status != 429)


EMAIL_BACKENDS = {"smtp": send_smtp, "resend": send_resend, "file": send_file}
PUSH_BACKENDS = {"ntfy": send_ntfy, "serverchan": send_serverchan, "webhook": send_webhook}


def send(cfg, row) -> str:
    ch = row["channel"]
    if ch == "email":
        fn = EMAIL_BACKENDS.get(cfg.get("notify.email_backend"))
    elif ch == "push":
        fn = PUSH_BACKENDS.get(cfg.get("notify.push_backend"))
    else:
        fn = None
    if fn is None:
        raise NotifyError(f"channel '{ch}' has no configured backend", permanent=True)
    return fn(cfg, row)
