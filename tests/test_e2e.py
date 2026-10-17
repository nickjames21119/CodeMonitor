"""End-to-end tests that drive the real CLI and detached supervisors (design §18.1 test cases)."""
import email
import json
import os
import signal
import subprocess
import sys
import time

import psutil
import pytest

from researchmonitor import engine, identity, store, util

PY = sys.executable


def _eml(home, run_id=None):
    d = os.path.join(home.path, "mail_outbox")
    out = []
    for f in sorted(os.listdir(d)) if os.path.isdir(d) else []:
        if run_id is None or run_id in f:
            out.append(email.message_from_bytes(open(os.path.join(d, f), "rb").read()))
    return out


def _text(msg):
    for part in msg.walk():
        if part.get_content_type() == "text/plain" and not part.get_filename():
            return part.get_payload(decode=True).decode("utf-8")
    return ""


def test_T01_normal_exit_reports_completion(home):
    rid = home.start("--name", "t01", "--", PY, "-c", "print('hello')")
    row = home.wait(rid)
    assert row["status"] == "SUCCEEDED_UNVERIFIED"
    assert row["exit_code"] == 0
    home.wait_notifications()
    msgs = _eml(home, rid)
    assert len(msgs) == 1
    assert "[SUCCEEDED_UNVERIFIED][P3]" in msgs[0]["Subject"]
    assert "hello" in _text(msgs[0])


def test_T01_foreground_run_streams_output_and_returns_exit_code(home):
    r = home.rmon("run", "--name", "fg", "--", PY, "-c", "import sys;print('visible-line');sys.exit(3)")
    assert "visible-line" in r.stdout
    assert r.returncode == 3


def test_T02_python_exception_classified_with_traceback(home):
    rid = home.start("--name", "t02", "--", PY, "-c",
                     "def f():\n    raise KeyError('missing_column')\nf()")
    row = home.wait(rid)
    assert row["status"] == "FAILED"
    assert row["failure_code"] == "PYTHON_EXCEPTION"
    ev = json.loads(row["evidence"])
    assert ev["final_exception"].startswith("KeyError")
    assert any("Traceback" in ln for ln in ev["traceback"])
    home.wait_notifications()
    msg = _eml(home, rid)[0]
    assert "[FAILED][P2]" in msg["Subject"]
    names = [p.get_filename() for p in msg.walk() if p.get_filename()]
    assert "output_tail.txt" in names
    assert row["incident_id"]


def test_T03_exit_zero_but_missing_or_invalid_results(home):
    work = home.work
    # stale file from an earlier run must not count as this run's output
    stale = os.path.join(work, "old.json")
    with open(stale, "w") as f:
        json.dump({"acc": 1}, f)
    os.utime(stale, (time.time() - 3600, time.time() - 3600))
    r1 = home.start("--expect", "never.txt", "--", PY, "-c", "pass")
    r2 = home.start("--expect-json", "old.json#acc", "--", PY, "-c", "pass")
    r3 = home.start("--expect-json", "m.json#acc", "--", PY, "-c",
                    "import json;json.dump({'acc': float('nan')}, open('m.json','w'))")
    r4 = home.start("--expect-json", "ok.json#acc,f1", "--expect-glob", "ck/*.pt", "--", PY, "-c",
                    "import json,os;os.makedirs('ck',exist_ok=True);open('ck/a.pt','wb').write(b'x'*10);"
                    "json.dump({'acc':0.8,'f1':0.7},open('ok.json','w'))")
    assert home.wait(r1)["failure_code"] == "RESULT_MISSING"
    row2 = home.wait(r2)
    assert row2["failure_code"] == "RESULT_MISSING" and "stale" in row2["failure_summary"]
    row3 = home.wait(r3)
    assert row3["status"] == "FAILED" and row3["failure_code"] == "RESULT_INVALID"
    row4 = home.wait(r4)
    assert row4["status"] == "SUCCEEDED"
    assert json.loads(row4["metrics"]) == {"acc": 0.8, "f1": 0.7}


def test_T04_attached_process_disappearing_is_unknown(home):
    p = subprocess.Popen([PY, "-c", "import time;time.sleep(3)"])
    r = home.rmon("attach", "--pid", str(p.pid), "--name", "att", check=True)
    assert "UNKNOWN" in r.stdout
    conn = home.conn()
    rid = conn.execute("SELECT run_id FROM runs WHERE mode='attached'").fetchone()[0]
    p.wait()
    row = home.wait(rid)
    assert row["status"] == "UNKNOWN"
    assert row["exit_code"] is None
    home.wait_notifications()
    assert "[UNKNOWN]" in _eml(home, rid)[0]["Subject"]


def test_T04b_attach_with_log_infers_likely_failure_but_stays_unknown(home):
    log = os.path.join(home.work, "job.log")
    p = subprocess.Popen([PY, "-c", "import time,sys;time.sleep(2);"
                          "sys.stderr.write('Traceback (most recent call last):\\n  File \"x\", line 1\\n"
                          "torch.OutOfMemoryError: CUDA out of memory.\\n')"], stderr=open(log, "w"))
    home.rmon("attach", "--pid", str(p.pid), "--log", log, check=True)
    p.wait()
    rid = home.conn().execute("SELECT run_id FROM runs WHERE mode='attached'").fetchone()[0]
    row = home.wait(rid)
    assert row["status"] == "UNKNOWN" and row["failure_code"] == "CUDA_OOM"
    assert json.loads(row["evidence"])["confidence"] == "inferred"


def test_T05_supervisor_killed_job_alive_is_adopted(home):
    rid = home.start("--name", "t05", "--", PY, "-c", "import time;time.sleep(6)")
    row = home.wait(rid, statuses={"RUNNING"})
    time.sleep(1)
    row = store.get_run(home.conn(), rid)
    os.kill(row["supervisor_pid"], signal.SIGKILL)
    time.sleep(1)
    assert identity.is_alive(row["pid"], row["pid_token"])  # job survives its monitor
    stats = engine.recover(home.conn(), home.cfg())
    assert stats["adopted"] == 1
    final = home.wait(rid, timeout=30)
    assert final["status"] == "UNKNOWN"
    assert "monitor process was lost" in final["evidence"]
    evs = [e["type"] for e in store.run_events(home.conn(), rid)]
    assert "SUPERVISOR_LOST" in evs and "ADOPTED" in evs


def test_T05b_supervisor_and_job_both_dead_is_lost(home):
    rid = home.start("--name", "t05b", "--", PY, "-c", "import time;time.sleep(30)")
    row = home.wait(rid, statuses={"RUNNING"})
    time.sleep(0.5)
    row = store.get_run(home.conn(), rid)
    os.kill(row["supervisor_pid"], signal.SIGKILL)
    os.killpg(row["pid"], signal.SIGKILL)
    time.sleep(1)
    engine.recover(home.conn(), home.cfg())
    final = store.get_run(home.conn(), rid)
    assert final["status"] == "LOST" and final["failure_code"] == "AGENT_FAILURE"


def test_T07_reboot_detected_and_reported_once(home):
    conn = home.conn()
    rids = []
    for i in range(2):
        rid = f"20260101-000000-rebooted{i}-abcd"
        with store.tx(conn):
            store.insert_run(conn, run_id=rid, name=f"rb{i}", mode="managed", priority="normal", status="RUNNING",
                             host_id=identity.host_id(conn), boot_id="linux:old-boot", created_at=time.time() - 9000,
                             started_at=time.time() - 9000, supervisor_pid=999999, supervisor_token="ticks:1",
                             supervisor_seen_at=time.time() - 600, spec="{}")
        rids.append(rid)
    stats = engine.recover(conn, home.cfg())
    assert stats["rebooted"] == 2
    for rid in rids:
        r = store.get_run(conn, rid)
        assert r["status"] == "LOST" and r["failure_code"] == "HOST_REBOOTED"
    incs = conn.execute("SELECT * FROM incidents").fetchall()
    assert len(incs) == 1 and incs[0]["severity"] == "P1"  # 2.5h of compute lost
    notes = conn.execute("SELECT * FROM notifications").fetchall()
    assert len(notes) == 1 and "[LOST]" in notes[0]["subject"]
    # running recovery again must not duplicate anything
    engine.recover(conn, home.cfg())
    assert conn.execute("SELECT COUNT(*) FROM notifications").fetchone()[0] == 1


def test_T07_heartbeat_pings_while_running_and_pauses_when_idle(home, fake_http):
    uid = "0d1f3a4b-1111-2222-3333-444455556666"
    home.configure(heartbeat__ping_url=f"{fake_http.url}/ping/{uid}", heartbeat__api_base=f"{fake_http.url}/api/v3",
                   heartbeat__interval_s=1)
    from researchmonitor.config import set_secret
    set_secret("healthchecks_api_key", "hc-test-key")
    rid = home.start("--", PY, "-c", "import time;time.sleep(4)")
    home.wait(rid)
    deadline = time.time() + 15
    while time.time() < deadline and not any(r["path"].endswith("/pause") for r in fake_http.requests):
        time.sleep(0.3)
    pings = [r for r in fake_http.requests if r["path"] == f"/ping/{uid}"]
    pauses = [r for r in fake_http.requests if r["path"] == f"/api/v3/checks/{uid}/pause"]
    assert pings, fake_http.requests
    assert pauses and pauses[0]["headers"].get("X-Api-Key") == "hc-test-key"


def test_T15_stall_warns_without_killing_then_clears(home):
    home.configure(monitor__stall_after="3s")
    rid = home.start("--name", "stall", "--", PY, "-c",
                     "import time,researchmonitor as rm\nrm.report(step=1)\ntime.sleep(7)\nrm.report(step=2)\n"
                     "time.sleep(5)")
    row = home.wait(rid, timeout=40)
    assert row["status"] == "SUCCEEDED_UNVERIFIED"  # never killed
    types = [e["type"] for e in store.run_events(home.conn(), rid)]
    assert "SUSPECTED_STALL" in types and "WARNING_CLEARED_SUSPECTED_STALL" in types
    home.wait_notifications()
    subjects = [n["subject"] for n in home.notifications(run_id=rid)]
    assert any("[WARNING]" in s for s in subjects) and any("[RECOVERED]" in s for s in subjects)
    inc = home.conn().execute("SELECT status FROM incidents WHERE category='SUSPECTED_STALL'").fetchone()
    assert inc["status"] == "RESOLVED"


def test_nan_loss_warning(home):
    rid = home.start("--", PY, "-c", "import researchmonitor as rm,time;rm.report(loss=float('nan'));time.sleep(7)")
    home.wait(rid)
    assert "WARNING_NAN_LOSS" in [e["type"] for e in store.run_events(home.conn(), rid)]


def test_stop_cancels_job_tree(home):
    rid = home.start("--name", "stopme", "--shell", "--",
                     f"{PY} -c \"import time;time.sleep(60)\" & {PY} -c \"import time;time.sleep(60)\"; wait")
    row = home.wait(rid, statuses={"RUNNING"})
    time.sleep(2)
    pid = store.get_run(home.conn(), rid)["pid"]
    kids = [p.pid for p in psutil.Process(pid).children(recursive=True)]
    assert kids
    home.rmon("stop", rid, check=True)
    row = home.wait(rid)
    assert row["status"] == "CANCELED"
    time.sleep(0.5)
    assert not any(psutil.pid_exists(k) and psutil.Process(k).status() != psutil.STATUS_ZOMBIE for k in kids)
    assert not home.notifications(run_id=rid)  # cancel is not e-mailed by default


def test_graceful_stop_via_should_stop(home):
    code = ("import time,researchmonitor as rm\n"
            "while not rm.should_stop():\n    time.sleep(0.2)\n"
            "open('saved.txt','w').write('checkpoint saved')\nprint('clean exit')")
    rid = home.start("--name", "graceful", "--", PY, "-c", code)
    home.wait(rid, statuses={"RUNNING"})
    time.sleep(3)
    home.rmon("stop", rid, check=True)
    row = home.wait(rid)
    assert row["status"] == "CANCELED"
    assert os.path.exists(os.path.join(home.work, "saved.txt"))
    assert row["exit_code"] == 0  # exited by itself, not killed


def test_shell_mode_keeps_quoted_arguments(home):
    rid = home.start("--shell", "--", PY, "-c", "import sys;print('ARGS', sys.argv[1:])", "a b", "c")
    row = home.wait(rid)
    out = open(row["log_path"], encoding="utf-8").read()
    assert "ARGS ['a b', 'c']" in out, out


def test_timeout_marks_timed_out(home):
    rid = home.start("--timeout", "3s", "--", PY, "-c", "import time;time.sleep(60)")
    row = home.wait(rid, timeout=40)
    assert row["status"] == "TIMED_OUT" and row["failure_code"] == "TIMED_OUT"


def test_spawn_error(home):
    rid = home.start("--", "definitely-not-a-command-xyz")
    row = home.wait(rid)
    assert row["status"] == "FAILED" and row["failure_code"] == "SPAWN_ERROR"


def test_terminal_close_does_not_kill_job(home):
    """Killing the foreground `rmon run` (as a closed terminal would) leaves job and monitor running."""
    p = subprocess.Popen([PY, "-m", "researchmonitor", "run", "--name", "survivor", "--", PY, "-c",
                          "import time;time.sleep(4);print('done')"], env=home.env, cwd=home.work,
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(2)
    p.send_signal(signal.SIGHUP)
    p.wait()
    rid = home.conn().execute("SELECT run_id FROM runs").fetchone()[0]
    assert home.wait(rid)["status"] == "SUCCEEDED_UNVERIFIED"


def test_project_file_and_long_job_failure_is_p1(home):
    with open(os.path.join(home.work, "rmon.toml"), "w") as f:
        f.write('name = "CityMemory"\npriority = "high"\nexpect = ["result.txt"]\n')
    rid = home.start("--", PY, "-c", "import sys;sys.exit(2)")
    row = home.wait(rid)
    assert row["name"] == "CityMemory" and row["priority"] == "high"
    assert row["failure_code"] == "NONZERO_EXIT"
    home.wait_notifications()
    assert "[FAILED][P1]" in home.notifications(run_id=rid)[0]["subject"]


def test_T20_large_artifact_is_referenced_not_attached(home):
    home.configure(notify__attach_max_kb=1)
    rid = home.start("--attach", "big.bin", "--attach", "small.json", "--", PY, "-c",
                     "open('big.bin','wb').write(b'0'*50000);open('small.json','w').write('{\"a\":1}')")
    home.wait(rid)
    home.wait_notifications()
    msg = _eml(home, rid)[0]
    names = [p.get_filename() for p in msg.walk() if p.get_filename()]
    assert "small.json" in names and "big.bin" not in names
    assert "sha256=" in _text(msg)
