"""
Frontend test in headless Chromium (Playwright): runs the recorded happy-path
demo end to end, verifies the certificate in the page, tries four different
tampering attacks against the in-page verifier, checks the security tab, and
checks that hostile text is never interpreted as HTML.

    python3 tests/test_frontend.py

Skipped with a clear message (exit code 0 and "SKIPPED") only when Playwright
or Chromium is not installed; CI installs both.
"""
import http.server
import json
import os
import socketserver
import sys
import threading

from harness import ROOT
from runner import Suite, main

suite = Suite("test_frontend")
test = suite.test
FRONT = os.path.join(ROOT, "frontend")

try:
    from playwright.sync_api import sync_playwright
except Exception:  # pragma: no cover
    sync_playwright = None


class Quiet(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *a, **k):
        super().__init__(*a, directory=FRONT, **k)

    def log_message(self, *a):
        pass


def serve():
    srv = socketserver.TCPServer(("127.0.0.1", 0), Quiet)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def with_page(fn, use_http=True):
    srv = serve() if use_http else None
    url = f"http://127.0.0.1:{srv.server_address[1]}/index.html" if use_http else "file://" + os.path.join(FRONT, "index.html")
    errors = []
    with sync_playwright() as p:
        exe = os.environ.get("VF_CHROMIUM")
        browser = p.chromium.launch(**({"executable_path": exe} if exe else {}), args=["--no-sandbox"])
        page = browser.new_page(viewport={"width": 390, "height": 900})
        page.on("pageerror", lambda e: errors.append(str(e)))
        page.on("console", lambda m: errors.append(m.text) if m.type == "error" and not m.text.startswith("Failed to load resource") else None)
        page.goto(url)
        try:
            fn(page)
        finally:
            browser.close()
            if srv:
                srv.shutdown()
    assert not errors, f"browser errors: {errors}"


def tab(page, name):
    page.click(f'#nav button[data-tab="{name}"]')


def run_all_steps(page):
    n = len(json.load(open(os.path.join(FRONT, "assets", "demo_run.json")))["scenarios"][0]["steps"])
    for _ in range(n):
        page.click("#next")
    return n


if sync_playwright is None:
    print("test_frontend: SKIPPED (playwright is not installed)")
    sys.exit(0)


@test("demo: the recorded happy path runs step by step to an INSECURE result with a counterexample")
def _():
    def go(page):
        n = run_all_steps(page)
        text = page.inner_text("#view")
        assert "Recorded protocol run" in text and "Frozen evidence" in text and "Threat requirements" in text
        assert "COUNTEREXAMPLE" in text and "CE-T3" in text and "withdrawTo" in text and "Final result" in text
        assert page.locator(".badge.final.v-INSECURE").count() == 1
        assert "Challenge C1" in text and "CONFIRMED" in text
        assert page.locator("#toverify").count() == 1
        assert page.locator(".step.done").count() == n
    with_page(go)


@test("demo: stepping is gradual (nothing from a later stage is visible early) and Back works")
def _():
    def go(page):
        page.click("#next")
        assert "Frozen evidence" not in page.inner_text("#view")
        page.click("#next")
        assert "Frozen evidence" in page.inner_text("#view") and "Attack hypotheses" not in page.inner_text("#view")
        page.click("#prev")
        assert "Frozen evidence" not in page.inner_text("#view")
    with_page(go)


@test("demo: the fixed PR ends SECURE and its certificate verifies")
def _():
    def go(page):
        page.select_option("#scenario", "1")
        page.click("#all")
        assert page.locator(".badge.final.v-SECURE").count() == 1
        page.click("#toverify")
        page.wait_for_selector("#vout h2")
        assert page.inner_text("#vout h2") == "CERTIFICATE VALID"
    with_page(go)


@test("verify: the in-page verifier accepts the demo certificate and shows no failing row")
def _():
    def go(page):
        run_all_steps(page)
        page.click("#toverify")
        page.wait_for_selector("#vout h2")
        assert page.inner_text("#vout h2") == "CERTIFICATE VALID"
        assert page.locator("#vout .badge.FAIL").count() == 0 and page.locator("#vout .badge.SKIP").count() == 0
        assert page.locator("#vout .badge.OK").count() > 30
    with_page(go)


@test("verify: four different tampering attacks are all detected in the page")
def _():
    def go(page):
        tab(page, "verify")
        for button, expect_fail in (("t-flip", "certificate hash"), ("t-claim", "certificate hash"), ("t-rehash", "final result"),
                                    ("t-bundle", "evidence content hashes")):
            page.click("#loadv")
            page.click(f"#{button}")
            page.wait_for_selector("#vout h2")
            assert page.inner_text("#vout h2") == "CERTIFICATE INVALID", button
            failing = page.locator("#vout tr:has(.badge.FAIL) td:nth-child(2)").all_inner_texts()
            assert any(expect_fail in f or "result" in f for f in failing), (button, failing)
        page.click("#loadv")
        page.click("#verifybtn")
        assert page.inner_text("#vout h2") == "CERTIFICATE VALID"
    with_page(go)


@test("verify: without a bundle or on-chain hash the page reports SKIP rows, and garbage input is a FAIL")
def _():
    def go(page):
        tab(page, "verify")
        page.click("#loadv")
        page.fill("#bundle", "")
        page.fill("#onchain", "")
        page.click("#verifybtn")
        assert page.locator("#vout .badge.SKIP").count() == 2
        page.fill("#cert", "not json")
        page.click("#verifybtn")
        assert "not valid JSON" in page.inner_text("#vout")
        page.fill("#cert", "{}")
        page.click("#verifybtn")
        assert page.inner_text("#vout h2") == "CERTIFICATE INVALID"
        page.fill("#cert", "[1,2,3]")
        page.click("#verifybtn")
        assert page.inner_text("#vout h2") == "CERTIFICATE INVALID"
    with_page(go)


@test("verify: a wrong on-chain hash is detected")
def _():
    def go(page):
        tab(page, "verify")
        page.click("#loadv")
        page.fill("#onchain", "0" * 64)
        page.click("#verifybtn")
        assert page.inner_text("#vout h2") == "CERTIFICATE INVALID"
    with_page(go)


@test("security: all nine attacks are listed as blocked")
def _():
    def go(page):
        tab(page, "security")
        text = page.inner_text("#view")
        assert page.locator(".badge.blocked").count() == 9 and "SUCCEEDED" not in text
    with_page(go)


@test("hostile text is rendered as text: no script or HTML from a certificate or evidence executes")
def _():
    def go(page):
        tab(page, "verify")
        page.click("#loadv")
        cert = json.loads(page.input_value("#cert"))
        cert["security_claim"] = '<img src=x onerror="window.__pwn=1"><script>window.__pwn=2</script>'
        cert["final_result"] = '<b id="injected">x</b>'
        page.fill("#cert", json.dumps(cert))
        page.click("#verifybtn")
        page.wait_for_selector("#vout h2")
        assert page.evaluate("window.__pwn") is None
        assert page.locator("#injected").count() == 0 and page.locator("#vout img").count() == 0
    with_page(go)
    src = open(os.path.join(FRONT, "assets", "app.js"), encoding="utf-8").read()
    assert "innerHTML" not in src and "outerHTML" not in src and "insertAdjacentHTML" not in src and "document.write" not in src


@test("the page also works when opened from disk (file://) and on a phone-width viewport without horizontal scroll")
def _():
    def go(page):
        run_all_steps(page)
        assert page.locator(".badge.final.v-INSECURE").count() == 1
        assert page.evaluate("document.documentElement.scrollWidth <= window.innerWidth + 1")
    with_page(go, use_http=False)


@test("verify tab accepts the live Studio certificate and rejects a tampered one")
def _():
    def go(page):
        tab(page, "verify")
        page.click("#loadlive")
        page.click("#verifybtn")
        assert "CERTIFICATE VALID" in page.inner_text("#vout")
        page.click("#t-flip")
        assert "CERTIFICATE INVALID" in page.inner_text("#vout")
    with_page(go, use_http=False)


@test("live mode renders without a wallet and refuses invalid addresses (no network needed)")
def _():
    def go(page):
        tab(page, "live")
        assert "run end to end on GenLayer Studio" in page.inner_text("#view")
        page.fill("#addr", "0x123")
        page.click("#loadlist")
        assert "valid contract address" in page.inner_text("#livelog")
        page.click("#connect")
        assert "No injected wallet" in page.inner_text("#livelog")
    with_page(go)


@test("the shared verifier is the same file the page loads (no divergent copy)")
def _():
    html = open(os.path.join(FRONT, "index.html"), encoding="utf-8").read()
    assert 'src="assets/verify.js"' in html
    assert not [f for f in os.listdir(os.path.join(FRONT, "assets")) if f.startswith("verify") and f != "verify.js"]


if __name__ == "__main__":
    main(suite)
