"""Zero-config mode: discovery, run-state, output parsing, end-reason inference, single report."""
import email
import email.policy
import json
import os
import signal
import subprocess
import sys
import textwrap
import time

import psutil
import pytest

from researchmonitor import config as rconfig, discovery, identity, infer, logscan, store, util, winconsole

PY = sys.executable
MARK = "rmon_autotest"


# --------------------------------------------------------------------------- output parsing

def test_parse_common_training_logs():
    a = logscan.OutputAnalyzer()
    lines = [
        "\x1b[32mEpoch 3/10\x1b[0m",
        "{'loss': 0.4123, 'learning_rate': 5e-05, 'epoch': 0.5}",                      # HF Trainer
        "{'eval_loss': 0.3011, 'eval_accuracy': 0.871, 'epoch': 1.0}",
        "100/100 [==============================] - 12s 120ms/step - loss: 0.2 - accuracy: 0.9 - val_loss: 0.31 "
        "- val_accuracy: 0.88",                                                          # Keras
        " 45%|████▌     | 450/1000 [02:13<02:43,  3.37it/s]",                            # tqdm
        "Saving model checkpoint to outputs/checkpoint-500/model.safetensors",
        "测试集结果 mrr=0.512 hit@10=0.734",
        "step 900 loss nan",
        "train_loss=nan",
        "Training complete.",
    ]
    a.feed(lines, 1000.0)
    assert a.epoch_total == 10
    assert a.evals and any("eval_accuracy" in e[2] for e in a.evals)
    assert any("val_accuracy" in e[2] for e in a.evals)
    assert any("mrr" in e[2] for e in a.evals)
    assert a.best["eval_loss"][0] == pytest.approx(0.3011)
    assert a.tqdm["done"] == 450 and a.tqdm["remaining"] == 163
    assert a.checkpoint.endswith("model.safetensors")
    assert a.nan and a.nan[1] == "train_loss"
    assert a.completion
    assert "lr" not in a.train and "learning_rate" not in a.train
    prog = a.progress(1001.0, 900.0)
    assert prog["epoch"] == 1.0 and prog["eta_s"] == 163  # last epoch seen (HF fractional epoch)


def test_parse_lightning_metrics_csv(tmp_path):
    p = tmp_path / "metrics.csv"
    p.write_text("epoch,step,train_loss,val_loss,val_acc\n0,99,0.9,,\n0,100,,0.7,0.61\n1,200,,0.5,0.72\n")
    a = logscan.OutputAnalyzer()
    t = logscan.FileTail(str(p))
    a.feed_csv(str(p), t.read_new(), 10.0)
    assert a.best["val_acc"][0] == 0.72 and a.epoch == 1


def test_console_snapshot_diff():
    prev = ["Epoch 1", "loss=0.5", "Epoch 2", "loss=0.4"]
    cur = ["Epoch 2", "loss=0.4", "Epoch 3", "loss=0.3"]
    assert winconsole.new_lines(prev, cur) == ["Epoch 3", "loss=0.3"]
    assert winconsole.new_lines([], cur) == cur


def test_file_tail_reads_only_new_bytes(tmp_path):
    p = tmp_path / "x.log"
    p.write_text("old line\n")
    t = logscan.FileTail(str(p), from_end=False)
    assert t.read_new() == ["old line"]
    with open(p, "a") as f:
        f.write("new 1\nnew 2 partial")
    assert t.read_new() == ["new 1"]
    with open(p, "a") as f:
        f.write(" done\n")
    assert t.read_new() == ["new 2 partial done"]


# --------------------------------------------------------------------------- inference

def _ctx(**kw):
    base = {"exit_code": None, "exit_known": False, "lines": [], "samples": [], "end_ts": 1000.0, "started_ts": 0.0,
            "rebooted": False, "completion": [], "files": [], "progress": {}, "output_readable": True}
    base.update(kw)
    return base


def _samples(state="GPU", sys_mem=40, gpu_mem=10, gpu_total=24):
    return [{"ts": 1000.0 - 15 * i, "cpu": 100, "rss": 2 << 30, "sys_mem": sys_mem, "state": state,
             "gpu_mem": gpu_mem << 30, "gpu_mem_total": gpu_total << 30, "gpu_util": 90} for i in range(5, -1, -1)]


@pytest.mark.parametrize("ctx,status,code,conf", [
    (_ctx(exit_code=0, exit_known=True), "SUCCEEDED", None, "high"),
    (_ctx(exit_code=0xC000013A, exit_known=True), "CANCELED", "PROCESS_TERMINATED", "high"),
    (_ctx(exit_code=1, exit_known=True, lines=["Traceback (most recent call last):", '  File "t.py"',
                                                "torch.OutOfMemoryError: CUDA out of memory."]), "FAILED", "CUDA_OOM", "high"),
    (_ctx(exit_code=1, exit_known=True, output_readable=False), "FAILED", "NONZERO_EXIT", "medium"),
    (_ctx(exit_code=0xC0000005, exit_known=True), "FAILED", "PROCESS_TERMINATED", "high"),
    (_ctx(lines=["Traceback (most recent call last):", '  File "t.py"', "ValueError: bad shape"]),
     "FAILED", "PYTHON_EXCEPTION", "high"),
    (_ctx(lines=["epoch 3", "Killed"], samples=_samples(sys_mem=99)), "FAILED", "SYSTEM_OOM", "medium"),
    (_ctx(lines=["Training complete"], completion=[(990.0, "Training complete")],
          files=[("results.json", 995.0, 10)]), "SUCCEEDED_UNVERIFIED", None, "high"),
    (_ctx(lines=["step 10"], samples=_samples(gpu_mem=24, gpu_total=24)), "UNKNOWN", "CUDA_OOM", "low"),
    (_ctx(lines=["step 10"], samples=_samples()), "UNKNOWN", "PROCESS_TERMINATED", "low"),
    (_ctx(rebooted=True), "LOST", "HOST_REBOOTED", "high"),
])
def test_end_reason_inference(ctx, status, code, conf):
    v = infer.infer_end(ctx, "zh")
    assert (v["status"], v["code"], v["confidence"]) == (status, code, conf), v
    assert v["verdict"] and v["evidence"]


# --------------------------------------------------------------------------- discovery

def _spawn(code: str, *args, cwd=None):
    return subprocess.Popen([PY, "-c", code, *args], cwd=cwd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def test_discovery_scores_and_excludes(tmp_path, monkeypatch):
    monkeypatch.setenv("RMON_HOME", str(tmp_path / "h"))
    script = tmp_path / f"{MARK}_train.py"
    script.write_text("import time\nt=time.time()\nwhile time.time()-t<20: sum(i*i for i in range(30000))\n")
    idle = tmp_path / f"{MARK}_idle.py"
    idle.write_text("import time\ntime.sleep(20)\n")
    procs = [subprocess.Popen([PY, str(script), "--epochs", "3"]), subprocess.Popen([PY, str(idle)]),
             subprocess.Popen([PY, "-m", "http.server", "0", "--bind", "127.0.0.1", MARK],
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)]
    try:
        cfg = rconfig.Config({"discovery": {"min_age_s": 0, "only": [MARK]}})
        d = discovery.Discovery(cfg)
        ready = []
        for _ in range(4):
            ready += d.scan(time.time(), None)
            time.sleep(1.0)
        by_pid = {c.pid: c for c in d.cands.values()}
        train = by_pid[procs[0].pid]
        assert train in ready and train.score >= 5
        assert any("sustained CPU" in r for r in train.dyn_reasons)
        assert any("keywords" in r for r in train.reasons)
        assert procs[1].pid not in [c.pid for c in ready]            # idle script: not active
        assert by_pid[procs[2].pid].excluded == "tool / server process"
        # user watch rule makes the idle script count
        d2 = discovery.Discovery(cfg, rules=[("watch", f"{MARK}_idle")])
        for _ in range(2):
            got = d2.scan(time.time(), None)
            time.sleep(0.5)
        assert any(c.pid == procs[1].pid for c in d2.cands.values() if c.hint)
    finally:
        for p in procs:
            p.kill()
            p.wait()


# --------------------------------------------------------------------------- end to end with a real agent

class AgentHome:
    def __init__(self, home):
        self.home = home
        self.env = dict(home.env)
        self.proc = None

    def configure(self, **extra):
        data = {"general": {"host_name": "auto-test", "language": "zh"},
                "notify": {"email_to": ["me@example.com"], "email_backend": "file", "intermediate": "off",
                           "intermediate_first_after": "0s", "linger_tick_s": 1},
                "discovery": {"scan_interval_s": 1, "min_age_s": 2, "only": [MARK]},
                "monitor": {"sample_interval_s": 1, "stall_after": "0"},
                "incidents": {"p1_reminders": ""}}
        for dotted, v in extra.items():
            sec, key = dotted.split("__", 1)
            data.setdefault(sec, {})[key] = v
        rconfig.save_config(rconfig.Config(data), os.path.join(self.home.path, "config.toml"))

    def start(self):
        self.proc = subprocess.Popen([PY, "-m", "researchmonitor", "agent", "--no-dashboard", "--quiet"],
                                     env=self.env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        conn = self.home.conn()
        for _ in range(60):
            info = util.json_loads(store.kv_get(conn, "agent"), None)
            if info and info.get("pid") == self.proc.pid:
                return
            time.sleep(0.2)
        raise AssertionError("agent did not start")

    def stop(self):
        if self.proc and self.proc.poll() is None:
            store.kv_set(self.home.conn(), "agent_stop", time.time())
            try:
                self.proc.wait(timeout=15)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait()

    def wait_runs(self, n=1, timeout=60, terminal=True):
        conn = self.home.conn()
        deadline = time.time() + timeout
        while time.time() < deadline:
            rows = conn.execute("SELECT * FROM runs WHERE mode IN ('auto','interactive')").fetchall()
            done = [r for r in rows if (r["status"] in store.TERMINAL) == terminal]
            if len(done) >= n:
                return done
            time.sleep(0.3)
        raise AssertionError(f"runs: {[dict(r) for r in conn.execute('SELECT run_id,status FROM runs')]}")

    def mails(self):
        d = os.path.join(self.home.path, "mail_outbox")
        out = []
        for f in sorted(os.listdir(d)) if os.path.isdir(d) else []:
            m = email.message_from_bytes(open(os.path.join(d, f), "rb").read(), policy=email.policy.default)
            body = next((p.get_payload(decode=True).decode() for p in m.walk()
                         if p.get_content_type() == "text/plain" and not p.get_filename()), "")
            out.append((f, str(m["Subject"]), body))
        return out


@pytest.fixture
def agent(home):
    a = AgentHome(home)
    a.configure()
    yield a
    a.stop()


def _job(home, name, body, redirect=True):
    path = os.path.join(home.work, f"{MARK}_{name}.py")
    with open(path, "w") as f:
        f.write(textwrap.dedent(body))
    out = open(os.path.join(home.work, f"{name}.log"), "w") if redirect else subprocess.DEVNULL
    # like a real launch: `python train_x.py --epochs 3`
    return subprocess.Popen([PY, path, "--epochs", "3"], cwd=home.work, stdout=out, stderr=subprocess.STDOUT)


BURN = "import time\ndef burn(s):\n    t=time.time()\n    while time.time()-t<s: sum(i*i for i in range(20000))\n"


def test_auto_success_single_report(agent, home):
    agent.start()
    p = _job(home, "ok", BURN + """
for ep in range(1, 4):
    burn(1.5)
    print(f"Epoch {ep}/3 train_loss={1/ep:.3f}", flush=True)
    print(f"eval epoch {ep} val_acc={0.7+0.05*ep:.3f}", flush=True)
open('result.json','w').write('{"acc": 0.85}')
print("Training complete", flush=True)
""")
    p.wait()
    run = agent.wait_runs()[0]
    assert run["status"] == "SUCCEEDED_UNVERIFIED"
    det = json.loads(run["detect"])
    assert det["score"] >= 5
    home.wait_notifications()
    mails = agent.mails()
    assert len(mails) == 1                                  # exactly one e-mail per job
    f, subj, body = mails[0]
    assert "很可能正常完成" in subj
    for must in ("结论依据", "运行过程", "CPU 计算", "val_acc", "epoch 3/3", "result.json", "Training complete"):
        assert must in body, must


def test_auto_exception_traceback_from_log(agent, home):
    agent.start()
    p = _job(home, "boom", BURN + """
burn(3)
print("Epoch 1/5 loss=0.9", flush=True)
import torch_fake_module_does_not_exist
""")
    p.wait()
    run = agent.wait_runs()[0]
    assert run["status"] == "FAILED" and run["failure_code"] == "PYTHON_EXCEPTION"
    ev = json.loads(run["evidence"])
    assert ev["confidence"] == "high" and "ModuleNotFoundError" in ev["final_exception"]
    home.wait_notifications()
    subj = agent.mails()[0][1]
    assert subj.startswith("[FAILED]")


def test_auto_stall_alert_then_one_final_report(agent, home):
    agent.configure(monitor__stall_after="3s")
    agent.start()
    p = _job(home, "stall", BURN + """
burn(3)
print("Epoch 1/2 loss=0.5", flush=True)
time.sleep(9)
burn(2)
print("Training complete", flush=True)
""")
    p.wait()
    agent.wait_runs()
    home.wait_notifications()
    subjects = [m[1] for m in agent.mails()]
    assert sum(1 for s in subjects if s.startswith("[ALERT]")) == 1
    assert sum(1 for s in subjects if not s.startswith("[ALERT]")) == 1


def test_auto_intermediate_results(agent, home):
    agent.configure(notify__intermediate="1s")
    agent.start()
    p = _job(home, "inter", BURN + """
for ep in range(1, 4):
    burn(2)
    print(f"[eval] epoch {ep}/3 val_mrr={0.3+0.1*ep:.2f}", flush=True)
    time.sleep(31 if ep == 1 else 0)
""")
    p.wait()
    agent.wait_runs(timeout=90)
    home.wait_notifications()
    subjects = [m[1] for m in agent.mails()]
    assert any(s.startswith("[PROGRESS]") for s in subjects), subjects


def test_auto_job_ending_while_agent_down_is_reported_on_restart(agent, home):
    agent.start()
    p = _job(home, "gap", BURN + "burn(30)\n")
    agent.wait_runs(terminal=False)
    agent.stop()
    p.kill()
    p.wait()
    agent.start()
    run = agent.wait_runs()[0]
    ev = json.loads(run["evidence"])
    assert any("监控程序当时没有运行" in x for x in ev["evidence"])


def test_auto_reboot_detected(agent, home):
    agent.start()
    p = _job(home, "reboot", BURN + "burn(30)\n")
    run = agent.wait_runs(terminal=False)[0]
    agent.stop()
    p.kill()
    p.wait()
    conn = home.conn()
    with store.tx(conn):
        conn.execute("UPDATE runs SET boot_id='linux:previous-boot' WHERE run_id=?", (run["run_id"],))
    agent.start()
    run = agent.wait_runs()[0]
    assert run["status"] == "LOST" and run["failure_code"] == "HOST_REBOOTED"


def test_auto_ignores_tools_and_other_users_jobs(agent, home):
    agent.configure(discovery__only=[])  # look at everything, like a real user
    agent.start()
    srv = subprocess.Popen([PY, "-m", "http.server", "0", "--bind", "127.0.0.1"], stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL, cwd=home.work)
    try:
        time.sleep(6)
        conn = home.conn()
        cmds = [r["command"] for r in conn.execute("SELECT command FROM runs")]
        assert not any("http.server" in (c or "") for c in cmds)
        assert not any("pytest" in (c or "") for c in cmds)
    finally:
        srv.kill()
        srv.wait()


def test_setup_page_saves_config(home):
    from researchmonitor import dashboard
    import http.client
    import urllib.parse
    srv, port = dashboard.start_server(18900)
    tok = dashboard._token()
    try:
        c = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        hdr = {"Host": f"127.0.0.1:{port}", "Cookie": f"rmon_session={tok}"}
        c.request("GET", "/setup", headers=hdr)
        r = c.getresponse()
        assert r.status == 200 and "发信方式" in r.read().decode()
        form = {"csrf": dashboard._csrf(tok), "email_to": "you@outlook.com", "method": "qq",
                "smtp_user": "12345@qq.com", "smtp_pass": "auth-code", "intermediate": "1h", "stall_after": "45m",
                "min_age": "5m", "watch": "train.py\nCityMemory", "ignore": "", "host_name": "lab-pc",
                "notify_success": "on", "do": "save"}
        c.request("POST", "/setup", body=urllib.parse.urlencode(form),
                  headers=dict(hdr, **{"Content-Type": "application/x-www-form-urlencoded"}))
        r = c.getresponse()
        r.read()
        assert r.status == 303
        cfg = home.cfg()
        assert cfg.email_to == ["you@outlook.com"]
        assert cfg.get("smtp.host") == "smtp.qq.com" and cfg.get("notify.email_backend") == "smtp"
        assert cfg.get("discovery.watch") == ["train.py", "CityMemory"]
        assert cfg.get("discovery.min_age_s") == 300
        assert rconfig.get_secret("smtp_password", cfg) == "auth-code"
    finally:
        srv.shutdown()


# --------------------------------------------------------------------------- regressions from the v0.2 review

def test_console_diff_ignores_redrawn_progress_bars():
    prev = ["[eval] epoch 1 val_acc=0.7", "Epoch 2/5", " 30%|███       | 30/100 [00:10<00:23,  3.1it/s]"]
    cur = ["[eval] epoch 1 val_acc=0.7", "Epoch 2/5", "[eval] epoch 2 val_acc=0.75",
           " 80%|████████  | 80/100 [00:26<00:06,  3.1it/s]"]
    assert winconsole.new_lines(prev, cur)[0] == "[eval] epoch 2 val_acc=0.75"
    assert winconsole.new_lines(["a", "b"], ["x", "y"]) == []  # no anchor: re-read nothing
    a = logscan.OutputAnalyzer()
    for _ in range(3):  # overlapping reads must not duplicate results or refresh completion times
        a.feed(["[eval] epoch 1 val_acc=0.7", "saved best model"], 10.0 + _)
    assert len(a.evals) == 1 and len(a.completion) == 1 and a.completion[0][0] == 10.0


def test_keywords_only_from_arguments():
    words = lambda cmd: {m.group(0).lower().lstrip("-") for m in discovery.ML_WORDS.finditer(cmd)}  # noqa: E731
    assert words(r"D:\proj\train.py --epochs 3 --lr 0.1") == {"train", "epochs", "lr"}
    assert words(r"C:\Users\me\AppData\Local\Programs\Python\python.exe") == set()
    assert words("download_data.py --url x --process 4") == set()


def test_work_dir_avoids_home_folder(tmp_path):
    home = os.path.expanduser("~")
    script_dir = tmp_path / "proj"
    script_dir.mkdir()
    assert logscan.work_dir(home, ["python", str(script_dir / "train.py")]) == str(script_dir)
    assert logscan.work_dir(home, ["python", "-c", "x"]) is None
    assert logscan.work_dir(str(script_dir), ["python", "train.py"]) == str(script_dir)


def test_idle_notebook_kernel_with_cuda_context_is_not_tracked():
    cfg = rconfig.Config({"discovery": {"min_age_s": 0}})
    d = discovery.Discovery(cfg)
    c = discovery.Candidate(1, "t", "python", 0, time.time() - 3600, time.time())
    c.category, c.described, c.cpu_hist = "interactive", True, [0.0, 0.5, 0.0]
    c.dyn_reasons = ["uses GPU (CUDA compute)"]
    assert not d._qualifies(c, time.time())
    c.cpu_hist = [95.0, 97.0]
    assert d._qualifies(c, time.time())
    c.cooldown_until = time.time() + 600
    assert not d._qualifies(c, time.time())


def test_resume_continues_after_a_bad_row(home, monkeypatch):
    from researchmonitor import agent as agent_mod, tracker as tracker_mod
    conn = home.conn()
    for rid in ("bad-row", "good-row"):
        with store.tx(conn):
            store.insert_run(conn, run_id=rid, name=rid, mode="auto", status="RUNNING", host_id="h",
                             boot_id=identity.boot_id(), created_at=time.time() - 100, started_at=time.time() - 100,
                             pid=999999, pid_token="ticks:1", supervisor_seen_at=time.time() - 5, spec="{}",
                             run_dir=os.path.join(home.path, "runs", rid), profile="{}", command='["python","x.py"]')
    real = tracker_mod.JobTracker.__init__

    def flaky(self, agent, **kw):
        if kw.get("run_row") is not None and kw["run_row"]["run_id"] == "bad-row":
            raise RuntimeError("corrupt profile")
        real(self, agent, **kw)
    monkeypatch.setattr(tracker_mod.JobTracker, "__init__", flaky)
    a = agent_mod.Agent(dashboard=False)
    a.resume(time.time())
    st = {r["run_id"]: r["status"] for r in home.conn().execute("SELECT run_id, status FROM runs")}
    assert st["good-row"] in store.TERMINAL and st["bad-row"] == "UNKNOWN"


def test_setup_page_rejects_bad_port_without_crashing(home):
    from researchmonitor import dashboard
    import http.client
    import urllib.parse
    srv, port = dashboard.start_server(18950)
    tok = dashboard._token()
    try:
        c = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        form = {"csrf": dashboard._csrf(tok), "email_to": "a@b.c", "method": "smtp", "smtp_host": "x",
                "smtp_port": "abc", "stall_after": "30m", "min_age": "2m", "intermediate": "2h", "do": "save"}
        c.request("POST", "/setup", body=urllib.parse.urlencode(form),
                  headers={"Host": f"127.0.0.1:{port}", "Cookie": f"rmon_session={tok}",
                           "Content-Type": "application/x-www-form-urlencoded"})
        r = c.getresponse()
        r.read()
        assert r.status == 303 and "%E7%AB%AF%E5%8F%A3" in r.getheader("Location")  # "端口" message
    finally:
        srv.shutdown()
