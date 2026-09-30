# Deployment

The repository was built without network access. Live results from GenLayer Studio (2026-09-29) are recorded in the checklist below and in `docs/FINAL_SECURITY_REVIEW.md`.

## Build

```
python3 tools/build_deploy.py            # writes contracts/veriforge_deploy.py
python3 tools/build_deploy.py --check    # CI: fails if the file is stale or not equivalent
```

The build removes comments, docstrings and blank lines with Python's tokenizer, keeps the two header lines, and refuses to write unless (a) the AST of the result equals the AST of the source with docstrings removed, (b) the file is ASCII, (c) exactly two comment lines remain. The full test suites run against the artifact too: `VF_MODULE=veriforge_deploy python3 tests/test_veriforge.py`.

## Deploy to GenLayer Studio

1. Open GenLayer Studio, create a new contract, paste `contracts/veriforge_deploy.py` (or upload it).
2. Deploy with no constructor arguments.
3. Copy the contract address into the Live tab of `frontend/index.html` (or open the page and type it).

## Live validation checklist

Run these on Studio and record results in `docs/FINAL_SECURITY_REVIEW.md`:

1. Deploy succeeds; `get_protocol_info()` returns. **Done (2026-09-29).**
2. `submit_security_claim` with a real public PR; `freeze_evidence` succeeds. **Done (2026-09-29).** Confirms `web.get` on `github.com/.../compare/<base>...<head>.diff`, `api.github.com/.../pulls/N`, `raw.githubusercontent.com` and that validators receive identical bytes. **Done (2026-09-29): 5/5 validators, byte-identical.**
3. `decompose_threats`, `generate_attack_hypotheses` reach consensus with live models (propose-and-review). **In progress.** 1.0.x ended Undetermined because reviewers rejected correct proposals without a stated defect; 1.1.0 counts only grounded rejections. Undetermined leaves the state unchanged, so retry before the stage deadline.
4. `defender_analysis`, `attacker_analysis`, `auditor_reconciliation` with `threat_id` per threat (single-threat transactions), then with an empty `threat_id`. **Per-threat calls done (2026-09-29/30), 3 threats x 3 roles, all reached consensus.** The all-threats form (empty `threat_id`) is not exercised live; prompts were about 5 KB.
5. Categorical disagreement behaviour: do role stages agree with real models? The verdict must still match exactly (as stated or after grounding). If agreement is rare, prefer per-threat calls and retries after Undetermined; do not drop the grounding or the canonical check.
6. `consensus`, `aggregate_security_result`, wait out (or, on a test network, shorten) the 48 h window, `finalize_certificate`. **Done with the short-window build (10 minutes).** The 48 h value itself is only tested locally; a production instance (`0x916c...623C`) holds an aggregated case whose window ends 2026-10-01T20:31Z.
7. Download the certificate and evidence bundle and run `python3 tools/verify_certificate.py cert.json --evidence bundle.json --onchain-hash <get_certificate_hash()>`. **Done: CERTIFICATE VALID, see `examples/live/`.** Studio shows read results with the commas between object fields removed; restore them (or copy through *Export JSON*) before parsing the evidence bundle. `get_certificate` returns a JSON string and parses as is.
8. Same in the browser Verify tab. The frontend verifier (`frontend/assets/verify.js`) was run on the live certificate under Node: 46 checks passed, and it rejects an edited `final_result` and a wrong on-chain hash.

If a step fails because of a GenLayer limit, record the exact error and redesign that component without weakening the guarantees (for example smaller stages), documenting it in `docs/GENVM_LESSONS.md`.

## Short-window test build

To test the challenge window on Studio without waiting 48 h, run `python3 tools/build_short_window.py 600`. It writes `build/veriforge_short_window.py`, identical to `contracts/veriforge_deploy.py` except for the `CHALLENGE_WINDOW_SECONDS` line (the script checks this). Deploy that copy for testing only, never as the real contract. Stage deadlines stay at 24 h. The repository tests assume the 48 h value and will not pass against such a copy.
