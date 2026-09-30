"""
Records a real, complete protocol run against the local GenLayer stub and
writes it to frontend/assets/demo_run.json, which the frontend replays.

    python3 tools/run_demo.py            # (re)generate the recording
    python3 tools/run_demo.py --check    # fail if the committed recording is stale

Two scenarios run through the real contract code (contracts/veriforge.py):
the vulnerable pull request (withdrawTo() left unguarded) and the fixed one.
The models are scripted (tests/scenario.py); the verdicts are derived by the
contract from their answers after checking every quote against the frozen
evidence. This is a recording of local execution, not a live GenLayer run.
"""
import json
import os
import sys

import _bootstrap  # noqa: F401
from harness import ROOT, SUBMITTER, OTHER, CHALLENGER, vf, gl
import scenario as sc
import verify_certificate as vc

OUT = os.path.join(ROOT, "frontend", "assets", "demo_run.json")
OUT_JS = os.path.join(ROOT, "frontend", "assets", "demo_run.js")
NAMES = {str(SUBMITTER): "submitter", str(OTHER): "anyone", str(CHALLENGER): "challenger"}
LABELS = {
    "submit_security_claim": "Submit the security claim",
    "freeze_evidence": "Freeze evidence (diff and head files, byte-exact)",
    "decompose_threats": "Decompose the claim into threat requirements",
    "generate_attack_hypotheses": "Generate evidence-grounded attack hypotheses",
    "defender_analysis": "Defender argues each requirement holds",
    "attacker_analysis": "Attacker searches for a counterexample",
    "auditor_reconciliation": "Auditor reconciles defender and attacker",
    "consensus": "Derive per-requirement results",
    "aggregate_security_result": "Aggregate the final result",
    "challenge": "Challenge a result",
    "finalize_certificate": "Finalize the certificate",
}


def record(variant, challenge):
    ch = sc.new_chain()
    sc.register_web(gl.nondet.web, variant=variant)
    steps = []

    def do(sender, method, *args, note=""):
        before = ch.view("get_verification", vid)["status"] if steps else "(new)"
        result = ch.tx(sender, method, *args)
        after_vid = result if method == "submit_security_claim" else args[0]
        after = ch.view("get_verification", after_vid)
        steps.append({"n": len(steps) + 1, "method": method, "label": LABELS[method], "caller": NAMES[str(sender)],
                      "args": [a for a in args if not (isinstance(a, str) and len(a) > 200)], "status_before": before,
                      "status_after": after["status"], "clock": ch.now.isoformat(), "note": note,
                      "returned": result if isinstance(result, str) and len(result) < 200 else "(certificate)"})
        return result

    vid = "vf_0"
    vid = do(SUBMITTER, "submit_security_claim", sc.REPO_URL, f"PR#{sc.PR_NUMBER}", sc.CLAIM)
    do(SUBMITTER, "freeze_evidence", vid)
    for method in ("decompose_threats", "generate_attack_hypotheses", "defender_analysis", "attacker_analysis",
                   "auditor_reconciliation", "consensus", "aggregate_security_result"):
        do(OTHER, method, *((vid, "") if method.endswith(("_analysis", "_reconciliation")) else (vid,)))
    if challenge:
        do(CHALLENGER, "challenge", vid, "VERDICT", "T3", "withdrawTo() is exposed without onlyAuthorized; please re-run the analysis.",
           note="Reproduced: the challenge confirms the result. A challenge can only confirm or downgrade, never flip.")
    ch.advance(vf.CHALLENGE_WINDOW_SECONDS + 1)
    text = do(OTHER, "finalize_certificate", vid, note="Called after the 48h challenge window closed.")
    case = ch.view("get_case", vid)
    bundle = ch.view("get_evidence_bundle", vid)
    onchain = ch.view("get_certificate_hash", vid)
    cert = json.loads(text)
    rep = vc.verify(cert, bundle, onchain)
    assert rep.ok, [r for r in rep.rows if r[1] == "FAIL"]
    return {
        "id": variant, "repository": sc.REPO_URL, "ref": f"PR#{sc.PR_NUMBER}", "claim": sc.CLAIM,
        "title": "Vulnerable PR: withdrawTo() left unguarded" if variant == "vulnerable" else "Fixed PR: both entry points guarded",
        "steps": steps, "case": case, "evidence_bundle": bundle, "certificate_text": text,
        "certificate_hash": onchain, "python_verifier": [list(r) for r in rep.rows],
    }


def build():
    return {
        "recording": "Local execution of contracts/veriforge.py against tests/genlayer_stub.py with scripted models; "
                     "not a live GenLayer run.",
        "protocol": vf.PROTOCOL, "protocol_version": vf.PROTOCOL_VERSION,
        "scenarios": [record("vulnerable", True), record("fixed", False)],
    }


def main():
    text = json.dumps(build(), indent=1, sort_keys=True, ensure_ascii=True) + "\n"
    js = "window.VF_DEMO = " + text.rstrip("\n") + ";\n"
    if "--check" in sys.argv:
        current = open(OUT, encoding="utf-8").read() if os.path.exists(OUT) else ""
        current_js = open(OUT_JS, encoding="utf-8").read() if os.path.exists(OUT_JS) else ""
        if current != text or current_js != js:
            raise SystemExit("frontend/assets/demo_run.json/.js is stale; run python3 tools/run_demo.py")
        print(f"ok: demo_run.json and demo_run.js are current ({len(text)} bytes)")
        return
    with open(OUT, "w", encoding="utf-8") as f:
        f.write(text)
    with open(OUT_JS, "w", encoding="utf-8") as f:
        f.write(js)
    for s in json.loads(text)["scenarios"]:
        print(f"{s['id']:11s} {len(s['steps'])} steps -> {json.loads(s['certificate_text'])['final_result']}")
    print(f"wrote {OUT} ({len(text)} bytes)")


if __name__ == "__main__":
    main()
