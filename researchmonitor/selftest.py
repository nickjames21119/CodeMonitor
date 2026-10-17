"""`rmon selftest`: exercise the real launch/observe/finalize/notify path on this computer.

Uses a throw-away data directory and the 'file' e-mail backend, so nothing is sent and the user's
real history is untouched.
"""
from __future__ import annotations

import glob
import os
import shutil
import subprocess
import sys
import tempfile
import time

PY = sys.executable


def _rmon(env, *args, timeout=60):
    return subprocess.run([PY, "-m", "researchmonitor", *args], env=env, capture_output=True, text=True,
                          timeout=timeout, encoding="utf-8", errors="replace")


AUTO_OK = """import time, json
def burn(s):
    t = time.time()
    while time.time() - t < s:
        sum(i * i for i in range(20000))
for ep in range(1, 4):
    burn(2.5)
    print(f"Epoch {ep}/3 train_loss={1/ep:.3f}", flush=True)
    print(f"[eval] epoch {ep} val_acc={0.7 + 0.05 * ep:.3f}", flush=True)
json.dump({"acc": 0.85}, open("rmon_selftest_result.json", "w"))
print("Training complete", flush=True)
"""
AUTO_ERR = """import time
def burn(s):
    t = time.time()
    while time.time() - t < s:
        sum(i * i for i in range(20000))
burn(7)
print("Epoch 1/5 loss=0.9", flush=True)
raise ValueError("rmon selftest boom")
"""


def _auto_checks(env, home, work, results) -> None:
    """Start a private agent, run two small programs normally (no wrapper), check the reports."""
    import json as _json
    is_win = sys.platform == "win32"
    flags = 0x08000000 if is_win else 0  # CREATE_NO_WINDOW
    agent = subprocess.Popen([PY, "-m", "researchmonitor", "agent", "--no-dashboard", "--quiet"], env=env,
                             stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                             creationflags=flags)
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from researchmonitor import store, util
    db = os.path.join(home, "rmon.db")
    conn = None
    for _ in range(100):
        if os.path.exists(db):
            conn = store.connect(db)
            info = util.json_loads(store.kv_get(conn, "agent"), None)
            if info and info.get("pid") == agent.pid:
                break
        time.sleep(0.2)
    ok_path = os.path.join(work, "rmon_selftest_ok.py")
    err_path = os.path.join(work, "rmon_selftest_err.py")
    with open(ok_path, "w", encoding="utf-8") as f:
        f.write(AUTO_OK)
    with open(err_path, "w", encoding="utf-8") as f:
        f.write(AUTO_ERR)
    job_env = {k: v for k, v in os.environ.items() if k != "RMON_HOME"}
    ok_job = subprocess.Popen([PY, ok_path, "--epochs", "3"], cwd=work, env=job_env, stdin=subprocess.DEVNULL,
                              stdout=open(os.path.join(work, "ok.log"), "w"), stderr=subprocess.STDOUT,
                              creationflags=flags)
    shell = None
    if is_win:
        # like a user typing `python train.py` in a terminal window: the traceback is only on screen
        si = subprocess.STARTUPINFO()
        si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        si.wShowWindow = 7  # SW_SHOWMINNOACTIVE
        shell = subprocess.Popen(["cmd.exe", "/k", PY, err_path, "--epochs", "5"], cwd=work, env=job_env, startupinfo=si,
                                 creationflags=0x00000010)  # CREATE_NEW_CONSOLE
    else:
        shell = subprocess.Popen([PY, err_path, "--epochs", "5"], cwd=work, env=job_env, stdin=subprocess.DEVNULL,
                                 stdout=open(os.path.join(work, "err.log"), "w"), stderr=subprocess.STDOUT)
    ok_job.wait(timeout=120)
    rows = []
    deadline = time.time() + 120
    while time.time() < deadline:
        rows = conn.execute("SELECT * FROM runs WHERE mode='auto'").fetchall() if conn else []
        if len([r for r in rows if r["status"] in store.TERMINAL]) >= 2:
            break
        time.sleep(1)
    def find(word):
        return next((r for r in rows if word in (r["command"] or "")), None)
    ok, err = find("rmon_selftest_ok"), find("rmon_selftest_err")
    if ok is None:
        results.append(("auto: program detected", "FAIL", "the test program was not detected (see agent.log)"))
    else:
        det = _json.loads(ok["detect"] or "{}")
        results.append(("auto: program detected", "PASS", f"score {det.get('score')}: "
                        + "; ".join(det.get("reasons") or [])[:120]))
        good = ok["status"] in ("SUCCEEDED", "SUCCEEDED_UNVERIFIED")
        results.append(("auto: normal end recognised", "PASS" if good else "FAIL",
                        f"{ok['status']} exit={ok['exit_desc']}"))
    if err is None:
        results.append(("auto: failure explained", "FAIL", "the failing test program was not detected"))
    else:
        ev = _json.loads(err["evidence"] or "{}")
        good = err["status"] == "FAILED" and err["failure_code"] == "PYTHON_EXCEPTION"
        detail = f"{err['status']} {err['failure_code']} ({ev.get('confidence')}) exit={err['exit_desc']}"
        if is_win:
            got_text = "rmon selftest boom" in (ev.get("final_exception") or "")
            results.append(("auto: Windows exit code read", "PASS" if err["exit_code"] == 1 else "FAIL",
                            str(err["exit_desc"])))
            results.append(("auto: terminal window text read", "PASS" if got_text else "WARN",
                            (ev.get("final_exception") or "traceback not captured from the console window")[:120]))
            good = good or (err["exit_code"] == 1)
        results.append(("auto: failure explained", "PASS" if good else "FAIL", detail))
    try:
        store.kv_set(conn, "agent_stop", time.time())
        agent.wait(timeout=20)
    except Exception:
        agent.kill()
    if shell is not None and shell.poll() is None:
        shell.kill()
    finals = [r for r in (conn.execute("SELECT run_id FROM notifications WHERE kind='final' AND run_id IN "
                                       "(SELECT run_id FROM runs WHERE mode='auto')").fetchall() if conn else [])]
    results.append(("auto: exactly one report per program", "PASS" if len(finals) == len(rows) and rows else "FAIL",
                    f"{len(finals)} report(s) for {len(rows)} program(s)"))
    if conn:
        conn.close()


def run_selftest(keep: bool = False) -> int:
    tmp = tempfile.mkdtemp(prefix="rmon-selftest-")
    home = os.path.join(tmp, "home")
    work = os.path.join(tmp, "work")
    os.makedirs(home)
    os.makedirs(work)
    env = dict(os.environ, RMON_HOME=home, RMON_SECRETS_BACKEND="file")
    pkg_parent = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    env["PYTHONPATH"] = pkg_parent + (os.pathsep + env["PYTHONPATH"] if env.get("PYTHONPATH") else "")
    with open(os.path.join(home, "config.toml"), "w", encoding="utf-8") as f:
        f.write('[general]\nhost_name = "selftest"\n[notify]\nemail_to = ["selftest@example.invalid"]\n'
                'email_backend = "file"\nintermediate = "off"\nlinger_tick_s = 1\n'
                '[monitor]\nsample_interval_s = 1\nstall_after = "0"\n'
                '[discovery]\nscan_interval_s = 1\nmin_age_s = 2\nonly = ["rmon_selftest"]\n')
    print(f"self-test data dir: {home}")
    print("part 1/2: automatic detection (a temporary background agent watches two small test programs) ...")
    results = []
    _auto_checks(env, home, work, results)
    print("part 2/2: `rmon run` / `rmon attach` ...")
    cases = {
        "success+validated": (["--expect-json", "out.json#acc"],
                              [PY, "-c", "import json,time;time.sleep(1);json.dump({'acc':0.9},open('out.json','w'))"],
                              "SUCCEEDED", None),
        "python exception": ([], [PY, "-c", "import time;time.sleep(1);raise ValueError('selftest boom')"],
                             "FAILED", "PYTHON_EXCEPTION"),
        "exit 0, result missing": (["--expect", "never_written.txt"], [PY, "-c", "print('done')"],
                                   "FAILED", "RESULT_MISSING"),
        "CUDA OOM message": ([], [PY, "-c", "import sys;sys.stderr.write('torch.OutOfMemoryError: CUDA out of "
                                            "memory. Tried to allocate 2.00 GiB\\n');sys.exit(1)"],
                             "FAILED", "CUDA_OOM"),
        "progress API": ([], [PY, "-c", "import researchmonitor as rm;rm.report(step=1,loss=0.5);"
                                        "rm.result(acc=0.93)"], "SUCCEEDED_UNVERIFIED", None),
        "command not found": ([], ["rmon-selftest-no-such-command"], "FAILED", "SPAWN_ERROR"),
    }
    ids = {}
    for name, (opts, cmd, _, _) in cases.items():
        r = subprocess.run([PY, "-m", "researchmonitor", "run", "-d", "--name", name.replace(" ", "-").replace(",", ""),
                            *opts, "--", *cmd], env=env, cwd=work, capture_output=True, text=True, timeout=60,
                           encoding="utf-8", errors="replace")
        rid = None
        for tok in (r.stdout or "").split():
            if tok.count("-") >= 3 and tok[:8].isdigit():
                rid = tok
                break
        ids[name] = rid
        if not rid:
            results.append((name, "FAIL", f"could not start: {r.stdout} {r.stderr}"[:300]))
    # stop / cancel
    r = subprocess.run([PY, "-m", "researchmonitor", "run", "-d", "--name", "cancel-me", "--",
                        PY, "-c", "import time;time.sleep(300)"], env=env, cwd=work, capture_output=True, text=True,
                       timeout=60, encoding="utf-8", errors="replace")
    cancel_id = next((t for t in r.stdout.split() if t.count("-") >= 3 and t[:8].isdigit()), None)
    # attach to a process rmon did not start
    flags = 0x08000000 if sys.platform == "win32" else 0
    sleeper = subprocess.Popen([PY, "-c", "import time;time.sleep(6)"], creationflags=flags)
    ra = _rmon(env, "attach", "--pid", str(sleeper.pid), "--name", "attached")
    attach_ok = ra.returncode == 0
    time.sleep(4)
    if cancel_id:
        _rmon(env, "stop", cancel_id, timeout=90)

    sys.path.insert(0, pkg_parent)
    os.environ["RMON_HOME"] = home
    from researchmonitor import store
    conn = store.connect(os.path.join(home, "rmon.db"))
    deadline = time.time() + 90
    while time.time() < deadline:
        rows = conn.execute("SELECT status FROM runs").fetchall()
        if rows and all(row[0] in store.TERMINAL for row in rows):
            break
        time.sleep(1)
    sleeper.wait(timeout=30)
    for name, (_, _, want_status, want_code) in cases.items():
        rid = ids.get(name)
        if not rid:
            continue
        row = conn.execute("SELECT * FROM runs WHERE run_id=?", (rid,)).fetchone()
        got = (row["status"], row["failure_code"]) if row else ("missing", None)
        ok = got[0] == want_status and (want_code is None or got[1] == want_code)
        extra = ""
        if name == "progress API" and row is not None:
            ok = ok and "0.93" in (row["metrics"] or "")
            extra = f" metrics={row['metrics']}"
        results.append((name, "PASS" if ok else "FAIL", f"{got[0]} {got[1] or ''}{extra}"))
    if cancel_id:
        row = conn.execute("SELECT status FROM runs WHERE run_id=?", (cancel_id,)).fetchone()
        results.append(("rmon stop → CANCELED", "PASS" if row and row[0] == "CANCELED" else "FAIL",
                        row[0] if row else "missing"))
    row = conn.execute("SELECT status, failure_code FROM runs WHERE mode='attached'").fetchone()
    results.append(("attach → UNKNOWN", "PASS" if attach_ok and row and row[0] == "UNKNOWN" else "FAIL",
                    f"{row[0]} {row[1]}" if row else (ra.stderr or ra.stdout)[:200]))
    # notifications written by the 'file' backend
    deadline = time.time() + 30
    while time.time() < deadline and conn.execute(
            "SELECT COUNT(*) FROM notifications WHERE status IN ('pending','sending')").fetchone()[0]:
        time.sleep(1)
    emls = glob.glob(os.path.join(home, "mail_outbox", "*.eml"))
    expected = len([c for c in cases]) + 1 + 2  # cases + attached run + 2 auto jobs (cancel is not e-mailed)
    results.append(("report e-mails rendered", "PASS" if len(emls) >= expected else "FAIL",
                    f"{len(emls)} .eml files (expected ≥ {expected})"))
    width = max(len(r[0]) for r in results)
    print()
    for name, verdict, detail in results:
        print(f"  {verdict}  {name:{width}}  {detail}")
    failed = [r for r in results if r[1] == "FAIL"]
    print()
    if failed:
        print(f"{len(failed)} check(s) failed. Data kept for inspection: {home}")
    else:
        print("All checks passed. No real e-mail was sent (file backend).")
        if not keep:
            conn.close()
            shutil.rmtree(tmp, ignore_errors=True)
    return 1 if failed else 0
