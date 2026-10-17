"""In-process tests of the incident engine, outbox, channels and state machine."""
import json
import os
import socket
import subprocess
import sys
import threading
import time

import pytest

from researchmonitor import classify, engine, identity, incidents, notify, redact, store, util, validators
from researchmonitor.config import set_secret


def _mk_run(conn, rid, status="RUNNING", priority="normal", started_ago=60.0, name=None, host="host-x",
            project=None, spec="{}"):
    with store.tx(conn):
        store.insert_run(conn, run_id=rid, name=name or rid, project=project, mode="managed", priority=priority,
                         status=status,
                         host_id=host, boot_id=identity.boot_id(), created_at=time.time() - started_ago,
                         started_at=time.time() - started_ago, spec=spec, cwd="/tmp", command='["python","x.py"]')


def _fail(conn, cfg, rid, code="CUDA_OOM", authority=store.AUTH_SUPERVISOR, status="FAILED"):
    return engine.finalize_run(conn, cfg, rid, {"status": status, "authority": authority, "exit_code": 1,
                                                "exit_desc": "1", "failure_code": code,
                                                "failure_summary": f"{code} happened",
                                                "evidence": {"final_exception": "RuntimeError: x"}})


class Clock:
    def __init__(self, monkeypatch):
        self.t = time.time()
        monkeypatch.setattr(util, "now", lambda: self.t)

    def advance(self, s):
        self.t += s


# --------------------------------------------------------------------------- T08 / T09: idempotency & ordering

def test_T08_duplicate_notifications_are_not_stored_twice(home):
    conn, cfg = home.conn(), home.cfg()
    for _ in range(3):
        with store.tx(conn):
            notify.enqueue(conn, cfg, group_key="run:x:final", kind="final", severity="P2",
                           content={"subject": "s", "text": "t"})
    assert conn.execute("SELECT COUNT(*) FROM notifications").fetchone()[0] == 1


def test_T08_outbox_claim_is_exclusive(home):
    conn, cfg = home.conn(), home.cfg()
    with store.tx(conn):
        notify.enqueue(conn, cfg, group_key="g", kind="final", severity="P2", content={"subject": "s", "text": "t"})
    c2 = home.conn()
    assert notify._claim(conn, "g:email", "a") is True
    assert notify._claim(c2, "g:email", "b") is False


def test_T09_stale_or_weaker_transitions_never_regress_state(home):
    conn, cfg = home.conn(), home.cfg()
    _mk_run(conn, "r1")
    with store.tx(conn):
        assert store.transition(conn, "r1", "FAILED", store.AUTH_SUPERVISOR)
        assert not store.transition(conn, "r1", "RUNNING", store.AUTH_SUPERVISOR)       # terminal -> active
        assert not store.transition(conn, "r1", "LOST", store.AUTH_INFERRED)            # weaker evidence
    assert store.get_run(conn, "r1")["status"] == "FAILED"
    _mk_run(conn, "r2")
    with store.tx(conn):
        assert store.transition(conn, "r2", "LOST", store.AUTH_INFERRED)
        assert store.transition(conn, "r2", "SUCCEEDED", store.AUTH_SUPERVISOR)        # stronger evidence wins
    assert store.get_run(conn, "r2")["status"] == "SUCCEEDED"
    types = [e["type"] for e in store.run_events(conn, "r1")]
    assert types.count("STALE_TRANSITION_IGNORED") == 2


# --------------------------------------------------------------------------- correlation / severity

def test_host_level_failures_one_incident_one_digest_p0(home):
    conn, cfg = home.conn(), home.cfg()
    for i in range(4):
        _mk_run(conn, f"c{i}", project=f"proj{i}")
        _fail(conn, cfg, f"c{i}", code="CUDA_OOM")
    incs = conn.execute("SELECT * FROM incidents").fetchall()
    assert len(incs) == 1
    assert len(json.loads(incs[0]["runs"])) == 4
    assert incs[0]["severity"] == "P0"  # ≥3 runs on one host hit by the same machine-level cause
    kinds = [n["kind"] for n in conn.execute("SELECT kind FROM notifications")]
    assert kinds.count("final") == 1 and kinds.count("update") == 1  # coalesced
    upd = conn.execute("SELECT subject FROM notifications WHERE kind='update'").fetchone()[0]
    assert "×4" in upd


def test_code_level_failures_scoped_by_project_and_fully_reported(home):
    conn, cfg = home.conn(), home.cfg()
    for i in range(3):  # the same buggy script re-run three times
        _mk_run(conn, f"b{i}", project="CityMemory")
        _fail(conn, cfg, f"b{i}", code="PYTHON_EXCEPTION")
    _mk_run(conn, "other", project="Other")
    _fail(conn, cfg, "other", code="PYTHON_EXCEPTION")
    incs = conn.execute("SELECT * FROM incidents ORDER BY created_at").fetchall()
    assert len(incs) == 2                                   # different projects are not merged
    assert incs[0]["severity"] == "P2"                      # re-running a bug is not a P0 outage
    finals = conn.execute("SELECT COUNT(*) FROM notifications WHERE kind='final'").fetchone()[0]
    assert finals == 4                                      # each run keeps its own full report


def test_severity_rise_reschedules_escalation(home, monkeypatch):
    home.configure(incidents__p2_reminders="", incidents__p0_reminders="5m")
    conn, cfg = home.conn(), home.cfg()
    clock = Clock(monkeypatch)
    for i in range(3):
        _mk_run(conn, f"g{i}", project=f"p{i}")
        _fail(conn, cfg, f"g{i}", code="GPU_ERROR")
    inc = conn.execute("SELECT * FROM incidents").fetchone()
    assert inc["severity"] == "P0" and inc["next_step_at"] is not None
    clock.advance(301)
    assert engine.process_escalations(conn, cfg) == 1


def test_notify_none_never_escalates(home, monkeypatch):
    home.configure(incidents__p1_reminders="5m")
    conn, cfg = home.conn(), home.cfg()
    clock = Clock(monkeypatch)
    _mk_run(conn, "quiet", priority="high", spec='{"notify":"none"}')
    _fail(conn, cfg, "quiet")
    clock.advance(3600)
    assert engine.process_escalations(conn, cfg) == 0
    assert conn.execute("SELECT COUNT(*) FROM notifications").fetchone()[0] == 0


def test_lost_then_real_outcome_is_reported_and_old_incident_resolved(home, monkeypatch):
    home.configure(incidents__p1_reminders="5m")
    conn, cfg = home.conn(), home.cfg()
    _mk_run(conn, "late", priority="high")
    _fail(conn, cfg, "late", code="AGENT_FAILURE", authority=store.AUTH_INFERRED, status="LOST")
    old_iid = store.get_run(conn, "late")["incident_id"]
    assert engine.finalize_run(conn, cfg, "late", {"status": "SUCCEEDED", "authority": store.AUTH_SUPERVISOR,
                                                   "exit_code": 0, "exit_desc": "0"})
    assert store.get_run(conn, "late")["status"] == "SUCCEEDED"
    assert incidents.get(conn, old_iid)["status"] == "RESOLVED"
    subjects = [r[0] for r in conn.execute("SELECT subject FROM notifications WHERE run_id='late' "
                                           "ORDER BY created_at")]
    assert subjects[0].startswith("[LOST]") and subjects[1].startswith("[SUCCEEDED]")


def test_different_failures_open_separate_incidents(home):
    conn, cfg = home.conn(), home.cfg()
    _mk_run(conn, "a")
    _mk_run(conn, "b")
    _fail(conn, cfg, "a", code="CUDA_OOM")
    _fail(conn, cfg, "b", code="PYTHON_EXCEPTION")
    assert conn.execute("SELECT COUNT(*) FROM incidents").fetchone()[0] == 2


def test_severity_policy(home):
    conn, cfg = home.conn(), home.cfg()
    _mk_run(conn, "short", started_ago=60)
    _mk_run(conn, "long", started_ago=3 * 3600)
    _mk_run(conn, "hi", priority="high", started_ago=10)
    _mk_run(conn, "lo", priority="low", started_ago=5 * 3600)
    for rid in ("short", "long", "hi", "lo"):
        with store.tx(conn):
            store.transition(conn, rid, "FAILED", 3, ended_at=util.now())
    sev = {rid: engine.severity_for(cfg, store.get_run(conn, rid)) for rid in ("short", "long", "hi", "lo")}
    assert sev == {"short": "P2", "long": "P1", "hi": "P1", "lo": "P2"}


# --------------------------------------------------------------------------- T11 / T12: escalation & ACK

def test_T11_unacknowledged_p1_escalates_on_schedule(home, monkeypatch):
    home.configure(incidents__p1_reminders="5m,15m")
    conn, cfg = home.conn(), home.cfg()
    clock = Clock(monkeypatch)
    _mk_run(conn, "e1", priority="high")
    _fail(conn, cfg, "e1")
    assert engine.process_escalations(conn, cfg) == 0
    clock.advance(301)
    assert engine.process_escalations(conn, cfg) == 1
    assert engine.process_escalations(conn, cfg) == 0  # not twice
    clock.advance(600)
    assert engine.process_escalations(conn, cfg) == 1
    clock.advance(3600)
    assert engine.process_escalations(conn, cfg) == 0  # policy exhausted
    rem = conn.execute("SELECT subject FROM notifications WHERE kind='reminder' ORDER BY created_at").fetchall()
    assert [r[0].split("]")[0] for r in rem] == ["[REMINDER 1/2", "[REMINDER 2/2"]


def test_T12_ack_stops_pending_escalation(home, monkeypatch):
    home.configure(incidents__p1_reminders="5m,15m")
    conn, cfg = home.conn(), home.cfg()
    clock = Clock(monkeypatch)
    _mk_run(conn, "e2", priority="high")
    _fail(conn, cfg, "e2")
    iid = store.get_run(conn, "e2")["incident_id"]
    clock.advance(301)
    engine.process_escalations(conn, cfg)  # reminder 1 queued (not yet sent)
    ok, _ = incidents.transition(conn, iid, "ACKNOWLEDGED", "tester")
    assert ok
    clock.advance(3600)
    assert engine.process_escalations(conn, cfg) == 0
    inc = incidents.get(conn, iid)
    assert inc["acked_by"] == "tester" and inc["escalation_stopped"] == 1
    st = conn.execute("SELECT status FROM notifications WHERE kind='reminder'").fetchone()[0]
    assert st == "cancelled"
    ack_ev = [json.loads(e["detail"]) for e in incidents.timeline(conn, iid) if e["action"] == "ACKNOWLEDGED"][0]
    assert ack_ev["reminders_already_sent"] == 1 and ack_ev["escalation_stopped"] is True
    # job status is unaffected by incident state
    assert store.get_run(conn, "e2")["status"] == "FAILED"
    assert not incidents.transition(conn, iid, "OPEN", "x")[0]


def test_snooze_defers_reminders(home, monkeypatch):
    home.configure(incidents__p1_reminders="5m")
    conn, cfg = home.conn(), home.cfg()
    clock = Clock(monkeypatch)
    _mk_run(conn, "s1", priority="high")
    _fail(conn, cfg, "s1")
    iid = store.get_run(conn, "s1")["incident_id"]
    incidents.snooze(conn, iid, 3600, "me")
    clock.advance(400)
    assert engine.process_escalations(conn, cfg) == 0
    clock.advance(3600)
    assert engine.process_escalations(conn, cfg) == 1


# --------------------------------------------------------------------------- T06 / T10: delivery failures

def test_T06_T10_smtp_outage_retried_then_delivered(home, fake_smtp, monkeypatch):
    home.configure(notify__email_backend="smtp", smtp__host="127.0.0.1", smtp__port=fake_smtp.port,
                   smtp__security="none", smtp__username="", smtp__from="rm@test.local", smtp__timeout_s=3)
    conn, cfg = home.conn(), home.cfg()
    fake_smtp.stop()  # provider unreachable
    _mk_run(conn, "n1")
    _fail(conn, cfg, "n1")
    st = notify.dispatch_due(conn, cfg)
    assert st["retry"] == 1
    row = conn.execute("SELECT * FROM notifications").fetchone()
    assert row["status"] == "pending" and row["attempts"] == 1 and row["next_attempt_at"] > util.now()
    fake_smtp.start()
    conn.execute("UPDATE notifications SET next_attempt_at=0")
    st = notify.dispatch_due(conn, cfg)
    assert st["sent"] == 1
    assert len(fake_smtp.messages) == 1
    env = fake_smtp.messages[0]
    assert env.rcpt_tos == ["me@example.com"]
    body = env.content.decode("utf-8", "replace")
    assert "X-RMon-Notification-ID: run:n1:final:FAILED:email" in body
    attempts = conn.execute("SELECT ok FROM notification_attempts ORDER BY id").fetchall()
    assert [a[0] for a in attempts] == [0, 1]


def test_T10_hanging_provider_bounded_retries(home):
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(5)  # accepts, never speaks SMTP
    port = srv.getsockname()[1]
    home.configure(notify__email_backend="smtp", smtp__host="127.0.0.1", smtp__port=port, smtp__security="none",
                   smtp__timeout_s=1, notify__max_attempts=3)
    conn, cfg = home.conn(), home.cfg()
    _mk_run(conn, "h1")
    _fail(conn, cfg, "h1")
    for _ in range(3):
        conn.execute("UPDATE notifications SET next_attempt_at=0 WHERE status='pending'")
        notify.dispatch_due(conn, cfg)
    row = conn.execute("SELECT * FROM notifications").fetchone()
    assert row["status"] == "failed" and row["attempts"] == 3
    assert store.kv_get(conn, "last_notify_error")
    srv.close()


def test_smtp_bad_quit_reply_still_counts_as_sent(home, fake_smtp, monkeypatch):
    """smtp.qq.com answers QUIT with a malformed reply; that must not trigger re-sending."""
    import smtplib

    def bad_quit(self):
        raise smtplib.SMTPResponseException(-1, b"\x00\x00\x00")
    monkeypatch.setattr(smtplib.SMTP, "quit", bad_quit)
    home.configure(notify__email_backend="smtp", smtp__host="127.0.0.1", smtp__port=fake_smtp.port,
                   smtp__security="none", smtp__username="", smtp__from="rm@test.local", smtp__timeout_s=3)
    conn, cfg = home.conn(), home.cfg()
    _mk_run(conn, "qq")
    _fail(conn, cfg, "qq")
    assert notify.dispatch_due(conn, cfg)["sent"] == 1
    conn.execute("UPDATE notifications SET next_attempt_at=0")
    assert notify.dispatch_due(conn, cfg) == {"sent": 0, "failed": 0, "retry": 0}
    assert len(fake_smtp.messages) == 1


def test_config_and_results_written_by_windows_tools(home, tmp_path):
    from researchmonitor import config as rconfig
    p = tmp_path / "bom.toml"
    p.write_bytes(b"\xef\xbb\xbf" + '[general]\nhost_name = "实验机"\n'.encode("utf-8"))  # Notepad UTF-8 BOM
    assert rconfig.load_config(str(p)).host_name == "实验机"
    g = tmp_path / "gbk.toml"
    g.write_bytes('[general]\nhost_name = "实验机"\n'.encode("gbk"))
    assert rconfig.load_config(str(g)).host_name == "实验机"
    bad = tmp_path / "bad.toml"
    bad.write_text("this is = = not toml")
    cfg = rconfig.load_config(str(bad))  # never crashes every rmon process
    assert cfg.load_error and cfg.get("notify.email_backend") == "none"
    (tmp_path / "m.json").write_bytes(b"\xef\xbb\xbf" + json.dumps({"acc": 0.9}).encode())
    (tmp_path / "z.json").write_bytes(json.dumps({"名称": "测试", "acc": 0.5}, ensure_ascii=False).encode("gbk"))
    exps = validators.build_expectations(expect_json=["m.json#acc", "z.json#acc"])
    r = validators.evaluate(exps, str(tmp_path), None)
    assert r["passed"], r


def test_program_resolution_relative_to_job_dir(tmp_path):
    from researchmonitor.supervisor import resolve_program, job_env
    script = tmp_path / "tools" / "run.sh"
    script.parent.mkdir()
    script.write_text("#!/bin/sh\necho hi\n")
    script.chmod(0o755)
    assert resolve_program("tools/run.sh", str(tmp_path), {"PATH": "/usr/bin"}) == str(script)
    assert resolve_program(sys.executable, str(tmp_path), {}) == sys.executable
    assert resolve_program("sh", str(tmp_path), dict(os.environ)).endswith("sh")
    assert "RMON_SECRET_SMTP_PASSWORD" not in job_env({"RMON_SECRET_SMTP_PASSWORD": "x", "PATH": "/bin"})


def test_adopter_not_spawned_twice(home, monkeypatch):
    from researchmonitor import supervisor as sup
    spawned = []
    monkeypatch.setattr(sup, "spawn_adopter", lambda rid: spawned.append(rid) or 0)
    conn, cfg = home.conn(), home.cfg()
    child = subprocess.Popen([sys.executable, "-c", "import time;time.sleep(10)"])
    try:
        with store.tx(conn):
            store.insert_run(conn, run_id="adopt-me", name="a", mode="managed", status="RUNNING",
                             host_id="h", boot_id=identity.boot_id(), created_at=time.time(), started_at=time.time(),
                             supervisor_pid=999999, supervisor_token="ticks:1", supervisor_seen_at=time.time(),
                             pid=child.pid, pid_token=identity.proc_token(child.pid), spec="{}")
        engine.recover(conn, cfg)
        engine.recover(conn, cfg)
        engine.recover(home.conn(), cfg)
        assert spawned == ["adopt-me"]
    finally:
        child.kill()
        child.wait()


def test_smtp_auth_failure_is_permanent_with_outlook_hint(home):
    from researchmonitor.notify.channels import NotifyError, send_smtp
    import smtplib

    class Boom:
        def __init__(self, *a, **k):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def ehlo(self):
            pass

        def login(self, u, p):
            raise smtplib.SMTPAuthenticationError(535, b"5.7.3 Authentication unsuccessful")

    import researchmonitor.notify.channels as ch
    orig = ch.smtplib.SMTP_SSL
    ch.smtplib.SMTP_SSL = Boom
    try:
        home.configure(notify__email_backend="smtp", smtp__host="x", smtp__username="u@outlook.com")
        set_secret("smtp_password", "pw")
        with pytest.raises(NotifyError) as ei:
            send_smtp(home.cfg(), {"subject": "s", "body_text": "t", "body_html": None, "attachments": "[]",
                                   "notification_id": "n:1"})
        assert ei.value.permanent and "Outlook" in str(ei.value)
    finally:
        ch.smtplib.SMTP_SSL = orig


def test_resend_backend_payload_and_errors(home, fake_http):
    home.configure(notify__email_backend="resend", resend__api_url=f"{fake_http.url}/emails")
    set_secret("resend_api_key", "re_test_123456789012345")
    conn, cfg = home.conn(), home.cfg()
    _mk_run(conn, "rs")
    _fail(conn, cfg, "rs")
    assert notify.dispatch_due(conn, cfg)["sent"] == 1
    req = fake_http.requests[0]
    assert req["headers"]["Authorization"] == "Bearer re_test_123456789012345"
    payload = json.loads(req["body"])
    assert payload["to"] == ["me@example.com"] and payload["from"].endswith("<onboarding@resend.dev>")
    assert payload["subject"].startswith("[FAILED]") and "html" in payload
    # 403 (sending to an address other than the account owner) is permanent with a clear hint
    fake_http.status = 403
    fake_http.body = b'{"message":"You can only send testing emails to your own email address"}'
    _mk_run(conn, "rs2")
    _fail(conn, cfg, "rs2", code="PYTHON_EXCEPTION")
    st = notify.dispatch_due(conn, cfg)
    assert st["failed"] == 1
    err = conn.execute("SELECT last_error FROM notifications WHERE run_id='rs2'").fetchone()[0]
    assert "only send to the address you registered" in err


def test_push_channels_routing(home, fake_http):
    home.configure(notify__push_backend="webhook", webhook__url=f"{fake_http.url}/hook", notify__push_min_severity="P1")
    conn, cfg = home.conn(), home.cfg()
    assert notify.channels_for(cfg, "P1") == ["email", "push"]
    assert notify.channels_for(cfg, "P2") == ["email"]
    _mk_run(conn, "p1", priority="high")
    _fail(conn, cfg, "p1")
    notify.dispatch_due(conn, cfg)
    assert any(r["path"] == "/hook" for r in fake_http.requests)


# --------------------------------------------------------------------------- T14 / T19 / units

def test_T14_secrets_redacted():
    s = ("token=abc123 password: hunter2 Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sig12345 "
         "https://user:pa55@host/x sk-proj-ABCDEFGHIJKLMNOPQRSTUV hf_abcdefghijklmnopqrstuvwx AKIAABCDEFGHIJKLMNOP "
         "--api-key SECRETVALUE WANDB_API_KEY=0123456789abcdef")
    out = redact.redact(s)
    for secret in ("abc123", "hunter2", "eyJhbGciOiJIUzI1NiJ9", "pa55", "sk-proj-ABCDEFG", "hf_abcdefgh",
                   "AKIAABCDEFGHIJKLMNOP", "SECRETVALUE", "0123456789abcdef"):
        assert secret not in out, (secret, out)
    assert redact.redact_argv(["python", "t.py", "--token", "XYZ", "--lr", "0.1"]) == \
        ["python", "t.py", "--token", "[REDACTED]", "--lr", "0.1"]


def test_T14_secret_in_traceback_not_emailed(home):
    conn, cfg = home.conn(), home.cfg()
    _mk_run(conn, "sec")
    engine.finalize_run(conn, cfg, "sec", {"status": "FAILED", "authority": 3, "failure_code": "PYTHON_EXCEPTION",
                                           "failure_summary": "ValueError: bad key sk-ant-ABCDEFGHIJKLMNOPQRSTUV",
                                           "evidence": {"final_exception": "ValueError: password=hunter2"}})
    row = conn.execute("SELECT body_text, body_html, subject FROM notifications").fetchone()
    blob = "".join(row)
    assert "hunter2" not in blob and "sk-ant-ABCDEFG" not in blob


def test_T19_pid_reuse_not_confused():
    p = subprocess.Popen([sys.executable, "-c", "import time;time.sleep(5)"])
    tok = identity.proc_token(p.pid)
    assert identity.is_alive(p.pid, tok)
    assert not identity.is_alive(p.pid, "ticks:1" if tok.startswith("ticks:") else "ctime:1.00")
    p.kill()
    p.wait()
    assert not identity.is_alive(p.pid, tok)


@pytest.mark.parametrize("lines,rc,code", [
    (["Traceback (most recent call last):", '  File "a.py", line 1', "torch.OutOfMemoryError: CUDA out of memory."],
     1, "CUDA_OOM"),
    (["Traceback (most recent call last):", '  File "a.py", line 1',
      "RuntimeError: CUDA error: device-side assert triggered"], 1, "GPU_ERROR"),
    (["Traceback (most recent call last):", '  File "a.py", line 1', "MemoryError"], 1, "SYSTEM_OOM"),
    (["Traceback (most recent call last):", '  File "a.py", line 1', "ValueError: nope"], 1, "PYTHON_EXCEPTION"),
    (["Traceback (most recent call last):", '  File "a.py", line 1', "KeyboardInterrupt"], 1, "PROCESS_TERMINATED"),
    (["working..."], -9, "PROCESS_TERMINATED"),
    (["working..."], -15, "PROCESS_TERMINATED"),
    (["working..."], 0xC0000005, "PROCESS_TERMINATED"),
    (["working..."], 2, "NONZERO_EXIT"),
    (["numpy.core._exceptions._ArrayMemoryError: Unable to allocate 32.0 GiB for an array"], 1, "SYSTEM_OOM"),
])
def test_classification(lines, rc, code):
    assert classify.classify(rc, lines)["failure_code"] == code


def test_sigkill_under_memory_pressure_is_system_oom():
    assert classify.classify(-9, ["x"], mem_pressure=True)["failure_code"] == "SYSTEM_OOM"


def test_chained_traceback_uses_final_exception():
    lines = ["Traceback (most recent call last):", '  File "a"', "KeyError: 'x'", "",
             "During handling of the above exception, another exception occurred:", "",
             "Traceback (most recent call last):", '  File "b"', "    ^^^^", "ValueError: final one"]
    final, tb = classify.extract_traceback(lines)
    assert final == "ValueError: final one" and tb[0].startswith("Traceback")


def test_durations():
    assert util.parse_duration("90s") == 90
    assert util.parse_duration("45m") == 2700
    assert util.parse_duration("1h30m") == 5400
    assert util.parse_duration("2", "h") == 7200
    assert util.parse_duration("off") == 0
    with pytest.raises(ValueError):
        util.parse_duration("ten minutes")
    assert util.fmt_duration(5 * 3600 + 23 * 60) == "5h23m"


def test_validators_glob_freshness(tmp_path):
    old = tmp_path / "ck" / "old.pt"
    old.parent.mkdir()
    old.write_bytes(b"x")
    os.utime(old, (time.time() - 999, time.time() - 999))
    exps = validators.build_expectations(expect_glob=["ck/*.pt"])
    r = validators.evaluate(exps, str(tmp_path), time.time() - 10)
    assert not r["passed"] and r["failure_code"] == "RESULT_MISSING"
    (tmp_path / "ck" / "new.pt").write_bytes(b"y")
    assert validators.evaluate(exps, str(tmp_path), time.time() - 10)["passed"]


def test_gbk_output_decoding():
    text = "训练失败：显存不足".encode("gbk")
    assert "显存不足" in util.decode_output(text * 10)  # GBK (Chinese Windows code page) fallback
