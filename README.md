# VeriForge

Adversarial, consensus-backed security verification for GitHub code changes on GenLayer.

VeriForge asks one narrow question: **does a specific security claim about a specific immutable code change survive adversarial analysis?** A Defender, an Attacker and an Auditor argue against frozen evidence; GenLayer validators check each role; the contract, not the model, derives the result; the outcome is a hashed certificate anyone can re-verify.

> A SECURE result means that the defined security claim survived the protocol's evidence and adversarial verification process. It does not prove that the software contains no vulnerabilities.

**Status:** complete, tested against a local GenLayer stub, and **run end to end on GenLayer Studio**: a real public PR went from submission to a finalized certificate that the Python and JavaScript verifiers accept (`examples/live/`). The live run used a 10-minute challenge window; the production build uses 48 h. Live findings and open limits are in `docs/FINAL_SECURITY_REVIEW.md` and `docs/GENVM_LESSONS.md`.

## How it works

1. `submit_security_claim(repository, ref, claim)` with a public GitHub repo and a PR number or full commit sha.
2. `freeze_evidence` pins base/head shas and stores the diff and up to five head files byte-exactly, with an `evidence_root` hash. Nothing later re-reads the network.
3. The claim is decomposed into threat requirements; attack hypotheses are proposed and dropped unless grounded in the evidence.
4. Per requirement: Defender (must quote evidence verbatim to establish anything), Attacker (a counterexample counts only if its quotes and symbols exist in the frozen bytes), Auditor.
5. Results are derived deterministically: **SECURE**, **INSECURE**, **CONFLICTING_EVIDENCE**, or **UNPROVEN** (never treated as SECURE).
6. A 48 h challenge window; a challenge can confirm or downgrade, never flip.
7. `finalize_certificate` stores canonical JSON plus its hash. `tools/verify_certificate.py` and the browser Verify tab re-derive everything.

## Repository layout

```
contracts/   veriforge.py (source), veriforge_deploy.py (generated)
frontend/    index.html, assets/ (app.js, verify.js, style.css, recorded demo data)
tests/       test_veriforge, test_adversarial, test_certificate, test_frontend, test_fuzz,
             mutation_test, genlayer_stub, harness, scenario, attacks, fixtures/
tools/       build_deploy.py, build_short_window.py, verify_certificate.py, run_demo.py,
             security_demo.py, make_fixtures.py, run_all.py
examples/    live/ (certificate, evidence bundle and README of the Studio run)
docs/        REUSE_AUDIT, ARCHITECTURE, THREAT_MODEL, SECURITY_MODEL, CERTIFICATE_FORMAT,
             GENVM_LESSONS, DEMO, DEPLOYMENT, FINAL_SECURITY_REVIEW
.github/workflows/tests.yml
```

## Commands

Requirements: Python 3.11+, Node 22 (JS verifier tests), `pip install playwright && playwright install chromium` (frontend test).

```
python3 tools/run_all.py                      # everything, as CI does
python3 tools/run_all.py --quick              # without mutation testing

python3 tools/build_deploy.py                 # build contracts/veriforge_deploy.py
python3 tools/build_deploy.py --check
python3 tools/build_short_window.py 600       # test-only build with a 10-minute challenge window
python3 tests/test_veriforge.py               # unit
python3 tests/test_adversarial.py
python3 tests/test_certificate.py
python3 tests/test_frontend.py
FUZZ_SEED=7 FUZZ_RUNS=2000 python3 tests/test_fuzz.py
python3 tests/mutation_test.py
VF_MODULE=veriforge_deploy python3 tests/test_veriforge.py     # any suite against the artifact

python3 tools/run_demo.py                     # regenerate the recorded demo
python3 tools/security_demo.py                # nine attacks
python3 tools/verify_certificate.py cert.json --evidence bundle.json --onchain-hash <hash>
python3 -m http.server -d frontend 8000       # then open http://localhost:8000/
```

## Honest limits

The recorded demo uses scripted models and the local stub is not GenLayer; the run in `examples/live/` used real models and validators, but it is one pull request. Live models often propose irrelevant attack hypotheses, so INSECURE (driven by a checkable counterexample) is reliable while SECURE is hard to reach; no live run has produced SECURE yet. Guarantees are graded by enforcement level in `docs/SECURITY_MODEL.md`. A SECURE result reflects the process, and a model that misses a real vulnerability can still let a claim pass. Reused primitives come from SpecProof (`docs/REUSE_AUDIT.md`).

License: see `LICENSE`.
