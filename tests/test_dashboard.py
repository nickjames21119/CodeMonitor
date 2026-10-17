"""T13: the dashboard rejects unauthenticated / forged state changes; pages render."""
import http.client
import time
import urllib.parse

import pytest

from researchmonitor import dashboard, engine, identity, incidents, store


@pytest.fixture
def dash(home):
    conn, cfg = home.conn(), home.cfg()
    with store.tx(conn):
        store.insert_run(conn, run_id="r-dash", name="dash<script>", mode="managed", priority="high",
                         status="RUNNING", host_id="h", boot_id=identity.boot_id(), created_at=time.time() - 50,
                         started_at=time.time() - 50, spec="{}", cwd="/tmp", command='["python","x.py"]')
    engine.finalize_run(conn, cfg, "r-dash", {"status": "FAILED", "authority": 3, "failure_code": "CUDA_OOM",
                                              "failure_summary": "oom", "evidence": {"final_exception": "OOM"}})
    srv, port = dashboard.start_server(0 or 18765)
    token = dashboard._token()
    yield {"port": port, "token": token, "conn": conn, "iid": store.get_run(conn, "r-dash")["incident_id"]}
    srv.shutdown()


def _req(port, method, path, body=None, cookie=None, host=None, origin=None):
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    headers = {"Host": host or f"127.0.0.1:{port}"}
    if cookie:
        headers["Cookie"] = cookie
    if origin:
        headers["Origin"] = origin
    if body is not None:
        body = urllib.parse.urlencode(body)
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    c.request(method, path, body=body, headers=headers)
    r = c.getresponse()
    return r.status, r.read().decode("utf-8", "replace"), dict(r.getheaders())


def test_T13_login_and_pages(dash):
    p, tok = dash["port"], dash["token"]
    assert _req(p, "GET", "/")[0] == 401
    assert _req(p, "GET", "/login?token=wrong")[0] == 403
    st, _, hdr = _req(p, "GET", f"/login?token={tok}")
    assert st == 303 and "HttpOnly" in hdr["Set-Cookie"] and "SameSite=Strict" in hdr["Set-Cookie"]
    cookie = f"rmon_session={tok}"
    for path in ("/", "/runs/r-dash", "/incidents", f"/incidents/{dash['iid']}", "/notifications", "/api/state.json"):
        st, body, _ = _req(p, "GET", path, cookie=cookie)
        assert st == 200, path
    st, body, _ = _req(p, "GET", "/", cookie=cookie)
    assert "dash&lt;script&gt;" in body and "dash<script>" not in body  # escaped


def test_T13_unauthorized_or_forged_ack_rejected(dash):
    p, tok, iid, conn = dash["port"], dash["token"], dash["iid"], dash["conn"]
    cookie = f"rmon_session={tok}"
    csrf = dashboard._csrf(tok)
    path = f"/incidents/{iid}/acknowledged"
    assert _req(p, "POST", path, body={"csrf": csrf})[0] == 403                          # no session
    assert _req(p, "POST", path, body={"csrf": "x" * 32}, cookie=cookie)[0] == 403       # bad CSRF
    assert _req(p, "POST", path, body={"csrf": csrf}, cookie=cookie, host="evil.com")[0] in (400, 403)  # rebinding
    assert _req(p, "POST", path, body={"csrf": csrf}, cookie=cookie, origin="http://evil.com")[0] == 403
    assert _req(p, "GET", path, cookie=cookie)[0] in (404,)                              # GET never mutates
    assert incidents.get(conn, iid)["status"] == "OPEN"
    st, _, _ = _req(p, "POST", path, body={"csrf": csrf}, cookie=cookie, origin=f"http://127.0.0.1:{p}")
    assert st == 303
    inc = incidents.get(conn, iid)
    assert inc["status"] == "ACKNOWLEDGED" and inc["acked_by"].startswith("dashboard:")


def test_setup_form_in_a_real_browser(home):
    """Real browsers send `Origin: null` on POSTs from a page with Referrer-Policy: no-referrer — only a browser
    test catches that. Skipped where Playwright/Chromium is not installed."""
    sync_api = pytest.importorskip("playwright.sync_api")
    from researchmonitor import config
    srv, port = dashboard.start_server(18780)
    try:
        with sync_api.sync_playwright() as pw:
            import os
            try:
                b = pw.chromium.launch()
            except Exception as ex:  # browser revision missing: try a preinstalled Chromium
                exe = os.environ.get("RMON_TEST_CHROMIUM") or "/opt/pw-browsers/chromium"
                if not os.path.exists(exe):
                    pytest.skip(f"chromium not available: {ex}")
                b = pw.chromium.launch(executable_path=os.path.realpath(exe) if os.path.isfile(exe) else exe)
            pg = b.new_page()
            pg.goto(dashboard.login_url(port, "/setup"))
            pg.fill("input[name=email_to]", "you@outlook.com")
            pg.check("input[name=method][value=resend]")
            pg.fill("input[name=resend_key]", "re_browser_test_123456")
            pg.click("button[value=save]")
            pg.wait_for_load_state()
            assert "已保存" in pg.inner_text("body")
            pg.goto(f"http://127.0.0.1:{port}/rules")
            pg.fill("input[name=pattern]", "train.py")
            pg.click("form[action='/rules/add'] button")
            pg.wait_for_load_state()
            assert "train.py" in pg.inner_text("body")
            b.close()
        cfg = home.cfg()
        assert cfg.email_to == ["you@outlook.com"] and cfg.get("notify.email_backend") == "resend"
        assert config.get_secret("resend_api_key", cfg) == "re_browser_test_123456"
    finally:
        srv.shutdown()
