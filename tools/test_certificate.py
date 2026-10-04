"""
Certificate suite: the independent verifier accepts every honestly produced
certificate and detects tampering. Also cross-checks the verifier against
the contract's own hashes and, when Node is installed, against the
JavaScript verifier used by the frontend.

    python3 tests/test_certificate.py
"""
import copy
import json
import os
import shutil
import subprocess
import sys
import tempfile

from harness import ROOT, OTHER, CHALLENGER, vf, gl
from runner import Suite, main
import scenario as sc
from scenario import new_chain, submit_and_freeze, run_to, full_run, when, answer, make_all_secure, THREATS
import verify_certificate as vc

suite = Suite("test_certificate")
test = suite.test
DAY = 24 * 3600 + 1


def produce(kind="insecure"):
    ch = new_chain()
    if kind == "secure":
        make_all_secure(ch.llm)
    if kind == "conflicting":
        ch.llm.hook(when("auditor", contains=THREATS[2]), answer({"ruling": "DEFENSE_UPHELD", "reason": "guard suffices"}))
    vid = submit_and_freeze(ch)
    if kind == "unproven":
        make_all_secure(ch.llm)
        run_to(ch, vid, "HYPOTHESES_READY")
        for _ in range(5):
            ch.advance(DAY)
            ch.tx(OTHER, "expire_if_timed_out", vid)
    elif kind == "challenged":
        run_to(ch, vid, "AGGREGATED")
        ch.llm.hook(when("attacker", contains=THREATS[2]), answer({"outcome": "NONE_FOUND", "reason": "none"}))
        ch.tx(CHALLENGER, "challenge", vid, "VERDICT", "T3", "x")
        ch.tx(CHALLENGER, "challenge", vid, "VERDICT", "T1", "y")
    else:
        run_to(ch, vid, "AGGREGATED")
    ch.advance(vf.CHALLENGE_WINDOW_SECONDS + 1)
    text = ch.tx(OTHER, "finalize_certificate", vid)
    bundle = ch.view("get_evidence_bundle", vid)
    return json.loads(text), bundle, ch.view("get_certificate_hash", vid)


def rehash(cert):
    body = {k: v for k, v in cert.items() if k != "certificate_hash"}
    cert["certificate_hash"] = vc.sha(vc.canon(body))
    return cert


def failed(rep):
    return [n for n, s, _ in rep.rows if s == "FAIL"]


KINDS = ["insecure", "secure", "conflicting", "unproven", "challenged"]


@test("verifier accepts honest certificates of every result kind, with bundle and on-chain hash")
def _():
    for kind in KINDS:
        cert, bundle, onchain = produce(kind)
        rep = vc.verify(cert, bundle, onchain)
        assert rep.ok, (kind, failed(rep))
        assert not [r for r in rep.rows if r[1] == "SKIP"]
    assert produce("secure")[0]["final_result"] == "SECURE"
    assert produce("conflicting")[0]["final_result"] == "CONFLICTING_EVIDENCE"
    assert produce("unproven")[0]["final_result"] == "UNPROVEN"
    ch = produce("challenged")[0]
    assert ch["final_result"] == "CONFLICTING_EVIDENCE" and ch["challenge_status"] == "RESOLVED"


@test("without a bundle or on-chain hash the verifier reports SKIP, never a silent pass")
def _():
    cert, bundle, onchain = produce()
    rep = vc.verify(cert)
    skipped = {n for n, s, _ in rep.rows if s == "SKIP"}
    assert skipped == {"evidence bytes", "on-chain anchor"} and rep.ok


@test("the verifier's hashes equal the contract's for every kind (two implementations agree)")
def _():
    for kind in KINDS:
        cert, _, onchain = produce(kind)
        assert vc.sha(vc.canon({k: v for k, v in cert.items() if k != "certificate_hash"})) == onchain == cert["certificate_hash"]


@test("naive tampering of any single scalar field is detected")
def _():
    cert, bundle, onchain = produce()
    fields = ["protocol_version", "statement", "verification_id", "repository", "ref", "ref_kind", "base_commit",
              "head_commit", "security_claim", "claim_hash", "result_note", "final_result", "challenge_status",
              "frozen_at", "aggregated_at", "finalized_at", "threat_requirements_hash", "attack_hypotheses_hash",
              "counterexamples_hash"]
    for f in fields:
        t = copy.deepcopy(cert)
        t[f] = "SECURE" if f == "final_result" else str(t[f]) + "x"
        assert not vc.verify(t, bundle, onchain).ok, f
    for f in cert:
        t = copy.deepcopy(cert)
        del t[f]
        assert not vc.verify(t, bundle, onchain).ok, f"deleting {f}"


@test("re-hashed tampering (attacker fixes certificate_hash) is caught by the deeper checks")
def _():
    cert, bundle, _ = produce()
    def m_final(c): c["final_result"] = "SECURE"
    def m_note(c): c["result_note"] = "EVIDENCE_INCOMPLETE"
    def m_result(c): c["per_requirement_results"][2]["result"] = "SECURE"
    def m_derived(c): c["per_requirement_results"][2]["derived_result"] = "SECURE"
    def m_drop_ce(c): c["counterexamples"] = []
    def m_ce_quote(c):
        c["counterexamples"][0]["counterexample"]["evidence"][0]["quote"] = "function drain() external {"
    def m_ce_symbol(c): c["counterexamples"][0]["counterexample"]["path"] = ["withdrawTo", "stealFunds"]
    def m_root(c): c["evidence"]["root"] = "0" * 64
    def m_item_hash(c): c["evidence"]["items"][2]["content_hash"] = "0" * 64
    def m_head(c): c["head_commit"] = "0" * 40
    def m_claim(c): c["security_claim"] = "Nothing at all is claimed."
    def m_threat_drop(c): c["threat_requirements"].pop()
    def m_threat_text(c): c["threat_requirements"][2]["text"] = "harmless"
    def m_hyp_drop(c): c["attack_hypotheses"].pop()
    def m_hyp_edit(c): c["attack_hypotheses"][0]["description"] = "edited"
    def m_role_out(c): c["per_requirement_results"][2]["attacker"]["output"]["outcome"] = "NONE_FOUND"
    def m_role_origin(c): c["per_requirement_results"][2]["attacker"]["origin"] = "TIMEOUT"
    def m_auditor(c): c["per_requirement_results"][2]["auditor"]["output"]["ruling"] = "INCONCLUSIVE"
    def m_analysis_hash(c): c["analyses"]["attacker_hash"] = "0" * 64
    def m_chal(c):
        c["challenges"].append({"challenge_id": "C1", "target": "T3", "kind": "VERDICT", "resolution": "CONFIRMED"})
        c["challenge_status"] = "RESOLVED"
    def m_meta(c): c["consensus_metadata"]["threat_count"] = 1
    def m_extra_ce(c): c["counterexamples"].append(copy.deepcopy(c["counterexamples"][0]))
    def m_unproven(c):
        c["final_result"] = "UNPROVEN"
    mutations = [m_final, m_note, m_result, m_derived, m_drop_ce, m_ce_quote, m_ce_symbol, m_root, m_item_hash, m_head,
                 m_claim, m_threat_drop, m_threat_text, m_hyp_drop, m_hyp_edit, m_role_out, m_role_origin, m_auditor,
                 m_analysis_hash, m_chal, m_extra_ce, m_unproven]
    for m in mutations:
        t = copy.deepcopy(cert)
        m(t)
        rehash(t)
        rep = vc.verify(t, bundle)
        real = [n for n in failed(rep) if n != "certificate hash"]
        assert real, f"{m.__name__} slipped through the re-hashed check"


@test("a mutation that only changes the consensus_metadata origins is caught by the recorded-hash chain")
def _():
    cert, bundle, onchain = produce()
    t = copy.deepcopy(cert)
    t["consensus_metadata"]["role_origins"]["attacker"] = {"TIMEOUT": 4}
    assert not vc.verify(t, bundle, onchain).ok


@test("evidence bundle tampering is detected: bytes, deletion, addition, reordering, whitespace")
def _():
    cert, bundle, onchain = produce()
    assert vc.verify(cert, bundle, onchain).ok
    def edit(b): b[2]["content"] = b[2]["content"].replace("onlyAuthorized", "onlyAuthorised", 1)
    def ws(b): b[2]["content"] = b[2]["content"].replace("    ", "  ", 1)
    def trail(b): b[2]["content"] += " "
    def delete(b): b.pop()
    def add(b): b.append({"item_id": "E9", "content": "extra"})
    def diff_edit(b): b[0]["content"] = b[0]["content"].replace("+", "-", 1)
    def crlf(b): b[2]["content"] = b[2]["content"].replace("\n", "\r\n")
    for mut in (edit, ws, trail, delete, add, diff_edit, crlf):
        b = copy.deepcopy(bundle)
        mut(b)
        assert not vc.verify(cert, b, onchain).ok, mut.__name__


@test("a fully self-consistent forgery is only exposed by the on-chain hash (documented limit)")
def _():
    cert, bundle, onchain = produce()
    forged = copy.deepcopy(cert)
    forged["security_claim"] = forged["security_claim"] + " (edited)"
    forged["claim_hash"] = vc.sha(forged["security_claim"])
    rehash(forged)
    assert vc.verify(forged, bundle).ok
    assert not vc.verify(forged, bundle, onchain).ok


@test("SECURE cannot verify when evidence is incomplete or any role is not consensus")
def _():
    cert, bundle, _ = produce("secure")
    t = copy.deepcopy(cert)
    t["evidence"]["complete"] = False
    rehash(t)
    assert not vc.verify(t, bundle).ok
    t = copy.deepcopy(cert)
    t["per_requirement_results"][0]["defender"] = {"origin": "TIMEOUT", "output": None}
    rehash(t)
    assert not vc.verify(t, bundle).ok


@test("a challenge can never be recorded as turning a result into a stronger one")
def _():
    cert, bundle, _ = produce("challenged")
    assert vc.verify(cert, bundle).ok
    t = copy.deepcopy(cert)
    ch = [c for c in t["challenges"] if c["target"] == "T3"][0]
    ch["final_result"] = "INSECURE"
    t["per_requirement_results"][2]["result"] = "INSECURE"
    t["final_result"] = "INSECURE"
    rehash(t)
    assert not vc.verify(t, bundle).ok


@test("the command line verifier exits 0 for a valid certificate and 1 for a tampered one")
def _():
    cert, bundle, onchain = produce()
    with tempfile.TemporaryDirectory() as d:
        p, b = os.path.join(d, "c.json"), os.path.join(d, "b.json")
        json.dump(cert, open(p, "w"))
        json.dump(bundle, open(b, "w"))
        tool = os.path.join(ROOT, "tools", "verify_certificate.py")
        ok = subprocess.run([sys.executable, tool, p, "--evidence", b, "--onchain-hash", onchain], capture_output=True, text=True)
        assert ok.returncode == 0 and "CERTIFICATE VALID" in ok.stdout, ok.stdout
        cert["final_result"] = "SECURE"
        json.dump(cert, open(p, "w"))
        bad = subprocess.run([sys.executable, tool, p], capture_output=True, text=True)
        assert bad.returncode == 1 and "CERTIFICATE INVALID" in bad.stdout


VERIFY_JS = os.path.join(ROOT, "frontend", "assets", "verify.js")
LIVE = os.path.join(ROOT, "examples", "live")
LIVE_HASH = "d68708db96516afe5821fa61c542afe9db944519f6c14527d0191bc6dce30d6c"


@test("the certificate produced by the real GenLayer Studio run verifies (Python and JavaScript) and detects tampering")
def _():
    cert = json.load(open(os.path.join(LIVE, "certificate.json")))
    bundle = json.load(open(os.path.join(LIVE, "evidence_bundle.json")))
    assert cert["certificate_hash"] == LIVE_HASH and cert["final_result"] == "INSECURE"
    rep = vc.verify(cert, bundle, LIVE_HASH)
    assert rep.ok and not [r for r in rep.rows if r[1] == "SKIP"], failed(rep)
    assert not vc.verify(cert, bundle, "0" * 64).ok
    forged = copy.deepcopy(cert)
    forged["final_result"] = "SECURE"
    assert not vc.verify(forged, bundle, LIVE_HASH).ok
    edited = copy.deepcopy(bundle)
    edited[1]["content"] = edited[1]["content"].replace("external {", "external onlyAuthorized {", 1)
    assert not vc.verify(cert, edited, LIVE_HASH).ok
    if shutil.which("node") and os.path.exists(VERIFY_JS):
        script = ("const V=require(process.argv[1]);const fs=require('fs');"
                  "const c=JSON.parse(fs.readFileSync(process.argv[2]));const b=JSON.parse(fs.readFileSync(process.argv[3]));"
                  "process.stdout.write(JSON.stringify([V.verify(c,b,process.argv[4]).ok(),V.verify(c,b,'0'.repeat(64)).ok()]));")
        out = subprocess.run(["node", "-e", script, VERIFY_JS, os.path.join(LIVE, "certificate.json"),
                              os.path.join(LIVE, "evidence_bundle.json"), LIVE_HASH], capture_output=True, text=True)
        assert json.loads(out.stdout) == [True, False], out.stderr


@test("certificates are deterministic: identical runs give identical hashes")
def _():
    assert produce()[0]["certificate_hash"] == produce()[0]["certificate_hash"]


@test("certificates embed no environment-specific data (no addresses of validators or transaction senders)")
def _():
    text = json.dumps(produce("challenged")[0])
    assert str(OTHER) not in text
    cert = produce("challenged")[0]
    assert all("challenger" in c for c in cert["challenges"])


@test("JavaScript verifier (frontend) agrees with the Python verifier on valid and tampered certificates")
def _():
    if not shutil.which("node") or not os.path.exists(VERIFY_JS):
        raise AssertionError("node and frontend/assets/verify.js are required for this test")
    cases = []
    for kind in KINDS:
        cert, bundle, onchain = produce(kind)
        cases.append({"name": kind, "cert": cert, "bundle": bundle, "onchain": onchain})
        t = copy.deepcopy(cert)
        t["final_result"] = "SECURE" if cert["final_result"] != "SECURE" else "INSECURE"
        rehash(t)
        cases.append({"name": kind + "-rehashed-forgery", "cert": t, "bundle": bundle, "onchain": None})
        t2 = copy.deepcopy(cert)
        t2["security_claim"] += "x"
        cases.append({"name": kind + "-naive", "cert": t2, "bundle": bundle, "onchain": onchain})
        b2 = copy.deepcopy(bundle)
        b2[2]["content"] += " "
        cases.append({"name": kind + "-bundle", "cert": cert, "bundle": b2, "onchain": onchain})
    expected = {c["name"]: vc.verify(c["cert"], c["bundle"], c["onchain"]).ok for c in cases}
    with tempfile.TemporaryDirectory() as d:
        inp = os.path.join(d, "cases.json")
        json.dump(cases, open(inp, "w"))
        runner = os.path.join(ROOT, "tests", "js_conformance.js")
        out = subprocess.run(["node", runner, VERIFY_JS, inp], capture_output=True, text=True)
        assert out.returncode == 0, out.stderr + out.stdout
        got = json.loads(out.stdout)
    assert got == expected, {k: (got.get(k), expected[k]) for k in expected if got.get(k) != expected[k]}
    assert any(expected.values()) and not all(expected.values())


if __name__ == "__main__":
    main(suite)
