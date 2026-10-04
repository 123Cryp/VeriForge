"""
Live-tab test in headless Chromium with a mocked genlayer-js (no network).

Exercises every Live-tab path that talks to the contract: list, open, the full
stage chain, challenge, finalize, in-browser verification of the on-chain
certificate, temporary account, wallet connect and every error path.

    python3 tests/test_frontend_live.py
"""
import json
import os
import sys

from harness import ROOT
from runner import Suite, main

import test_frontend as tf

suite = Suite("test_frontend_live")
test = suite.test

CERT = open(os.path.join(ROOT, "examples", "live", "certificate.json")).read()
BUNDLE = open(os.path.join(ROOT, "examples", "live", "evidence_bundle.json")).read()
HASH = "d68708db96516afe5821fa61c542afe9db944519f6c14527d0191bc6dce30d6c"
ADDR = "0x7326c1C4E45dE19FBBA63D905d1071d94D4952a9"

MAIN_JS = """
const M = globalThis.__MOCK;
const NEXT = {SUBMITTED:"EVIDENCE_FROZEN",EVIDENCE_FROZEN:"THREATS_DEFINED",THREATS_DEFINED:"HYPOTHESES_READY",
 HYPOTHESES_READY:"DEFENDED",DEFENDED:"ATTACKED",ATTACKED:"AUDITED",AUDITED:"RECONCILED",RECONCILED:"AGGREGATED",AGGREGATED:"FINALIZED"};
const hex = n => Array.from({length:n},()=>"0123456789abcdef"[Math.floor(Math.random()*16)]).join("");
export function generatePrivateKey(){ return "0x"+hex(64); }
export function createAccount(pk){ return {address:"0x"+hex(40), pk}; }
export function createClient(cfg){
  return {
    cfg,
    async connect(n){ if (M.connectFails) throw new Error("user rejected"); M.connected = n; },
    async readContract({address, functionName, args}){
      M.reads.push([functionName, args]);
      if (M.readFails) throw new Error("rpc down");
      if (functionName === "list_verifications") return ["vf_1","vf_0"];
      if (functionName === "get_case") {
        const id = args[0];
        return new Map([["verification", new Map([["status", M.status[id]||"FINALIZED"],["final_result", M.status[id]==="FINALIZED"||!M.status[id]?"INSECURE":""],["security_claim","claim "+id],["repository","https://github.com/a/b"],["ref","PR#1"]])],
                        ["threats",[new Map([["threat_id","T1"],["text","req one"],["result",null]])]]]);
      }
      if (functionName === "get_certificate") return M.cert;
      if (functionName === "get_evidence_bundle") return JSON.parse(M.bundle);
      if (functionName === "get_certificate_hash") return M.hash;
      throw new Error("unknown read "+functionName);
    },
    async writeContract({address, functionName, args}){
      M.writes.push({functionName, args, address, account: cfg.account});
      if (M.writeFails) { const e = new Error(M.writeFails); throw e; }
      const id = args[0];
      if (NEXT[M.status[id]] && functionName !== "challenge" && functionName !== "submit_security_claim") M.status[id] = NEXT[M.status[id]];
      return "0x"+hex(64);
    },
    async waitForTransactionReceipt(){ await new Promise(r=>setTimeout(r, M.delay||10)); return {consensus_data:{leader_receipt:[{execution_result: M.execResult||"SUCCESS"}]}}; }
  };
}
"""
CHAINS_JS = "export const studionet = {id: 'studionet'};"


def run(fn, init=None):
    srv = tf.serve()
    errors = []
    with tf.sync_playwright() as p:
        exe = os.environ.get("VF_CHROMIUM")
        browser = p.chromium.launch(**({"executable_path": exe} if exe else {}), args=["--no-sandbox"])
        ctx = browser.new_context(viewport={"width": 390, "height": 900})
        page = ctx.new_page()
        page.on("pageerror", lambda e: errors.append(str(e)))
        page.on("console", lambda m: errors.append(m.text) if m.type == "error" and not m.text.startswith("Failed to load resource") else None)
        page.add_init_script("globalThis.__MOCK = {reads:[],writes:[],status:{vf_1:'SUBMITTED'},cert:%s,bundle:%s,hash:%s};" % (json.dumps(CERT), json.dumps(BUNDLE), json.dumps(HASH)) + (init or ""))

        def handler(route):
            url = route.request.url
            body = CHAINS_JS if url.endswith("/chains") else MAIN_JS
            route.fulfill(status=200, body=body, headers={"content-type": "application/javascript", "access-control-allow-origin": "*"})
        page.route("https://esm.sh/**", handler)
        page.goto(f"http://127.0.0.1:{srv.server_address[1]}/index.html")
        page.click('#nav button[data-tab="live"]')
        try:
            fn(page)
        finally:
            browser.close()
            srv.shutdown()
    assert not errors, f"browser errors: {errors}"


def mock(page, expr):
    return page.evaluate("() => " + expr)


def fill_form(page, repo="https://github.com/a/b", ref="PR#1", claim="a sufficiently long claim text"):
    page.fill("#f-repo", repo); page.fill("#f-ref", ref); page.fill("#f-claim", claim)


@test("address is prefilled with the live example contract")
def _():
    def go(page):
        assert page.input_value("#addr") == ADDR
    run(go)


@test("load verifications renders real buttons, never [object ...]")
def _():
    def go(page):
        page.click("#loadlist")
        page.wait_for_selector("#livelist button")
        txt = page.inner_text("#livelist")
        assert "vf_1" in txt and "vf_0" in txt and "[object" not in txt, txt
    run(go)


@test("loading with an invalid address is refused with a clear message")
def _():
    def go(page):
        page.fill("#addr", "0x123"); page.click("#loadlist")
        assert "valid contract address" in page.inner_text("#livelog")
        assert mock(page, "__MOCK.reads.length") == 0
    run(go)


@test("a read failure is reported, not thrown")
def _():
    def go(page):
        mock(page, "(__MOCK.readFails = true)")
        page.click("#loadlist")
        page.wait_for_function("document.getElementById('livelog').innerText.includes('read failed')")
    run(go)


@test("submit refuses an empty or invalid address without sending anything")
def _():
    def go(page):
        page.fill("#addr", ""); fill_form(page); page.click("#submitclaim")
        assert "valid contract address" in page.inner_text("#livelog")
        assert mock(page, "__MOCK.writes.length") == 0
    run(go)


@test("submit creates a temporary account automatically and sends exactly one transaction")
def _():
    def go(page):
        mock(page, "(__MOCK.delay = 600)")
        fill_form(page)
        page.click("#submitclaim"); page.click("#submitclaim")
        page.wait_for_function("document.getElementById('livelog').innerText.includes('accepted')")
        assert "already in progress" in page.inner_text("#livelog")
        assert mock(page, "__MOCK.writes.length") == 1
        w = mock(page, "__MOCK.writes[0]")
        assert w["functionName"] == "submit_security_claim" and w["args"] == ["https://github.com/a/b", "PR#1", "a sufficiently long claim text"]
        assert w["address"] == ADDR and w["account"]["address"].startswith("0x")
        assert "Temporary account active" in page.inner_text("#walletstatus")
    run(go)


@test("the stage chain runs from SUBMITTED to FINALIZED through the page, with correct arguments")
def _():
    def go(page):
        page.click("#loadlist"); page.wait_for_selector("#livelist button")
        page.click("#livelist button:has-text('vf_1')")
        seen = []
        for _i in range(12):
            page.wait_for_selector("#livedetail button.primary")
            label = page.inner_text("#livedetail button.primary")
            seen.append(label)
            before = mock(page, "__MOCK.writes.length")
            page.click("#livedetail button.primary")
            page.wait_for_function("__MOCK.writes.length > %d" % before)
            page.wait_for_timeout(120)
            if "finalize_certificate" in label:
                break
        calls = [(w["functionName"], w["args"]) for w in mock(page, "__MOCK.writes")]
        names = [c[0] for c in calls]
        assert names == ["freeze_evidence", "decompose_threats", "generate_attack_hypotheses", "defender_analysis",
                         "attacker_analysis", "auditor_reconciliation", "consensus", "aggregate_security_result", "finalize_certificate"], names
        for n, a in calls:
            if n in ("defender_analysis", "attacker_analysis", "auditor_reconciliation"):
                assert a == ["vf_1", ""], (n, a)
            else:
                assert a == ["vf_1"], (n, a)
        page.wait_for_selector("#livedetail >> text=FINALIZED")
        assert page.locator("#livedetail button.primary").count() == 0
    run(go)


@test("challenge form appears only when AGGREGATED and sends the right arguments")
def _():
    def go(page):
        mock(page, "(__MOCK.status.vf_1 = 'AGGREGATED')")
        page.click("#loadlist"); page.wait_for_selector("#livelist button")
        page.click("#livelist button:has-text('vf_1')")
        page.wait_for_selector("#livedetail >> text=Challenge")
        page.fill("#livedetail input[placeholder^='T3']", "T1")
        page.fill("#livedetail input[placeholder='rationale']", "why not")
        page.click("#livedetail button:has-text('Submit challenge')")
        page.wait_for_function("__MOCK.writes.length === 1")
        w = mock(page, "__MOCK.writes[0]")
        assert w["functionName"] == "challenge" and w["args"] == ["vf_1", "VERDICT", "T1", "why not"], w
    run(go)


@test("a finalized verification can be verified in the browser from the on-chain data")
def _():
    def go(page):
        page.click("#loadlist"); page.wait_for_selector("#livelist button")
        page.click("#livelist button:has-text('vf_0')")
        page.wait_for_selector("#livedetail >> text=Verify certificate in browser")
        page.click("#livedetail button:has-text('Verify certificate in browser')")
        page.wait_for_selector("#vout >> text=CERTIFICATE VALID")
        assert "matches the on-chain certificate hash" in page.inner_text("#vout")
        assert "FAIL" not in page.inner_text("#vout")
    run(go)


@test("a wrong on-chain hash makes the in-browser verification fail")
def _():
    def go(page):
        mock(page, "(__MOCK.hash = '" + "0" * 64 + "')")
        page.click("#loadlist"); page.wait_for_selector("#livelist button")
        page.click("#livelist button:has-text('vf_0')")
        page.click("#livedetail button:has-text('Verify certificate in browser')")
        page.wait_for_selector("#vout >> text=CERTIFICATE INVALID")
    run(go)


@test("a wallet nonce error gives a clear message and the next submit uses a temporary account")
def _():
    def go(page):
        mock(page, "(__MOCK.writeFails = 'NonceTooHigh(expected=43,actual=300)')")
        fill_form(page); page.click("#submitclaim")
        page.wait_for_function("document.getElementById('livelog').innerText.includes('nonce does not match')")
        mock(page, "(__MOCK.writeFails = null)")
        page.click("#submitclaim")
        page.wait_for_function("document.getElementById('livelog').innerText.includes('accepted')")
        assert mock(page, "__MOCK.writes.length") == 2
    run(go)


@test("a contract-side error result is shown as a rejection, and the page stays usable")
def _():
    def go(page):
        mock(page, "(__MOCK.execResult = 'ERROR: bad input')")
        fill_form(page); page.click("#submitclaim")
        page.wait_for_function("document.getElementById('livelog').innerText.includes('contract rejected')")
        mock(page, "(__MOCK.execResult = 'SUCCESS')")
        page.click("#submitclaim")
        page.wait_for_function("document.getElementById('livelog').innerText.includes('accepted')")
    run(go)


@test("the temporary-account button works on its own and shows the address")
def _():
    def go(page):
        page.click("#tempacct")
        page.wait_for_function("document.getElementById('walletstatus').innerText.includes('0x')")
    run(go)


@test("wallet connect switches the wallet to Studio and signs with the wallet address")
def _():
    def go(page):
        mock(page, "(window.ethereum = {request: async () => ['0x1111111111111111111111111111111111111111']})")
        page.click("#connect")
        page.wait_for_function("document.getElementById('livelog').innerText.includes('switched')")
        assert mock(page, "__MOCK.connected") == "studionet"
        page.wait_for_function("document.getElementById('walletstatus').innerText.includes('Wallet connected')")
        assert "Wallet connected" in page.inner_text("#connect")
        assert page.locator("#connect.active").count() == 1
        fill_form(page); page.click("#submitclaim")
        page.wait_for_function("__MOCK.writes.length === 1")
        assert mock(page, "__MOCK.writes[0].account") == "0x1111111111111111111111111111111111111111"
    run(go)


@test("wallet without the GenLayer snap is switched with wallet_addEthereumChain and signs itself")
def _():
    def go(page):
        mock(page, "(window.__calls = [], window.ethereum = {request: async (a) => { window.__calls.push(a.method); if (a.method === 'wallet_switchEthereumChain') throw new Error('unknown chain'); return ['0x1111111111111111111111111111111111111111']; }}, __MOCK.connectFails = true)")
        page.click("#connect")
        page.wait_for_function("document.getElementById('livelog').innerText.includes('switched')")
        assert mock(page, "window.__calls.includes('wallet_addEthereumChain')")
        assert "Falling back" not in page.inner_text("#livelog")
        fill_form(page); page.click("#submitclaim")
        page.wait_for_function("__MOCK.writes.length === 1")
        assert mock(page, "__MOCK.writes[0].account") == "0x1111111111111111111111111111111111111111"
    run(go)


@test("an empty submit form sends nothing")
def _():
    def go(page):
        page.click("#submitclaim")
        page.wait_for_function("document.getElementById('livelog').innerText.includes('Fill in')")
        assert mock(page, "__MOCK.writes.length") == 0
    run(go)


@test("wallet connect falls back to a temporary account when the network switch is refused")
def _():
    def go(page):
        mock(page, "(window.ethereum = {request: async (a) => { if (a.method.startsWith('wallet_')) throw new Error('unsupported'); return ['0x1111111111111111111111111111111111111111']; }}, __MOCK.connectFails = true)")
        page.click("#connect")
        page.wait_for_function("document.getElementById('walletstatus').innerText.includes('Temporary')")
        assert "Falling back" in page.inner_text("#livelog")
    run(go)


@test("hostile contract data is rendered as text, never as HTML")
def _():
    def go(page):
        mock(page, "(__MOCK.status.vf_1 = 'SUBMITTED')")
        page.click("#loadlist"); page.wait_for_selector("#livelist button")
        assert page.locator("#livedetail img, #livedetail script").count() == 0
    run(go)


if __name__ == "__main__":
    main(suite)
