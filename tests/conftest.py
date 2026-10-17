import os
import socket
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import psutil
import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from researchmonitor import config as rconfig, store  # noqa: E402

PY = sys.executable


def free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


class Home:
    """An isolated RMON_HOME plus helpers to drive the real CLI/supervisors."""

    def __init__(self, path, work, monkeypatch):
        self.path = str(path)
        self.work = str(work)
        self.env = dict(os.environ, RMON_HOME=self.path, RMON_SECRETS_BACKEND="file",
                        PYTHONPATH=ROOT + os.pathsep + os.environ.get("PYTHONPATH", ""))
        monkeypatch.setenv("RMON_HOME", self.path)
        monkeypatch.setenv("RMON_SECRETS_BACKEND", "file")
        self.configure()

    def configure(self, **overrides):
        data = {
            "general": {"host_name": "testhost", "language": "zh"},
            "notify": {"email_to": ["me@example.com"], "email_backend": "file", "linger_tick_s": 1,
                       "max_attempts": 3},
            "monitor": {"sample_interval_s": 1, "gpu_interval_s": 1, "stall_after": "0"},
            "incidents": {"p1_reminders": "", "p0_reminders": "", "correlation_window": "10m"},
        }
        for dotted, v in overrides.items():
            sec, key = dotted.split("__", 1)
            data.setdefault(sec, {})[key] = v
        rconfig.save_config(rconfig.Config(data), os.path.join(self.path, "config.toml"))

    def cfg(self):
        return rconfig.load_config(os.path.join(self.path, "config.toml"))

    def conn(self):
        return store.connect(os.path.join(self.path, "rmon.db"))

    def rmon(self, *args, cwd=None, timeout=90, check=False):
        r = subprocess.run([PY, "-m", "researchmonitor", *args], env=self.env, cwd=cwd or self.work,
                           capture_output=True, text=True, timeout=timeout, encoding="utf-8", errors="replace")
        if check and r.returncode != 0:
            raise AssertionError(f"rmon {args} failed: {r.stdout}\n{r.stderr}")
        return r

    def start(self, *opts_and_cmd, cwd=None) -> str:
        r = self.rmon("run", "-d", *opts_and_cmd, cwd=cwd, check=True)
        for tok in r.stdout.split():
            if tok.count("-") >= 3 and tok[:8].isdigit():
                return tok
        raise AssertionError(r.stdout + r.stderr)

    def wait(self, run_id, timeout=60, statuses=None):
        statuses = statuses or store.TERMINAL
        conn = self.conn()
        deadline = time.time() + timeout
        while time.time() < deadline:
            row = store.get_run(conn, run_id)
            if row is not None and row["status"] in statuses:
                return row
            time.sleep(0.3)
        raise AssertionError(f"run {run_id} did not reach {statuses}: {dict(store.get_run(conn, run_id))}")

    def wait_notifications(self, timeout=30):
        conn = self.conn()
        deadline = time.time() + timeout
        while time.time() < deadline:
            n = conn.execute("SELECT COUNT(*) FROM notifications WHERE status IN ('pending','sending')").fetchone()[0]
            if n == 0:
                return
            time.sleep(0.3)
        raise AssertionError("notifications still pending")

    def notifications(self, **where):
        conn = self.conn()
        q = "SELECT * FROM notifications"
        if where:
            q += " WHERE " + " AND ".join(f"{k}=?" for k in where)
        return conn.execute(q + " ORDER BY created_at", tuple(where.values())).fetchall()

    def kill_leftovers(self):
        for p in psutil.process_iter(["cmdline"]):
            try:
                cl = " ".join(p.info["cmdline"] or [])
            except psutil.Error:
                continue
            if self.path in cl and p.pid != os.getpid():
                try:
                    p.kill()
                except psutil.Error:
                    pass


@pytest.fixture
def home(tmp_path, monkeypatch):
    h = Home(tmp_path / "home", tmp_path / "work", monkeypatch)
    os.makedirs(h.work, exist_ok=True)
    yield h
    h.kill_leftovers()


class FakeHTTP:
    """Records requests; responds with a configurable status."""

    def __init__(self):
        self.requests = []
        self.status = 200
        self.body = b'{"id":"fake"}'
        outer = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _handle(self):
                n = int(self.headers.get("Content-Length") or 0)
                outer.requests.append({"method": self.command, "path": self.path, "headers": dict(self.headers),
                                       "body": self.rfile.read(n) if n else b""})
                self.send_response(outer.status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(outer.body)))
                self.end_headers()
                self.wfile.write(outer.body)

            do_POST = do_GET = _handle

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.port = self.server.server_address[1]
        self.url = f"http://127.0.0.1:{self.port}"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def close(self):
        self.server.shutdown()


@pytest.fixture
def fake_http():
    f = FakeHTTP()
    yield f
    f.close()


class FakeSMTP:
    def __init__(self):
        from aiosmtpd.controller import Controller
        self.messages = []
        outer = self

        class Handler:
            async def handle_DATA(self, server, session, envelope):
                outer.messages.append(envelope)
                return "250 OK"

        self.port = free_port()
        self._make = lambda: Controller(Handler(), hostname="127.0.0.1", port=self.port)

    def start(self):
        self.controller = self._make()  # a stopped aiosmtpd controller cannot be restarted
        self.controller.start()

    def stop(self):
        self.controller.stop()


@pytest.fixture
def fake_smtp():
    s = FakeSMTP()
    s.start()
    yield s
    try:
        s.stop()
    except Exception:
        pass
