# GenVM lessons applied in VeriForge

Inherited from SpecProof's live testing (see `docs/REUSE_AUDIT.md` section 6) and how VeriForge applies each one.

| Lesson | Application |
|---|---|
| `# v0.2.16` header first, then the `Depends` line | Lines 1-2 of the source; `tools/build_deploy.py` refuses output with any other comment; a unit test asserts it. |
| `from dataclasses import dataclass` after `from genlayer import *` | Same order. |
| Never assign `TreeMap`/`DynArray` in `__init__`; assign plain lists to DynArray fields | `__init__` only sets `verification_counter` (lint test). |
| Mutate objects from `TreeMap.get` by attribute | All updates are attribute writes on the fetched object. |
| Exceptions inside nondet closures abort the transaction | Every closure catches and returns `{"ok": false, "error": ...}`. |
| `run_nondet_unsafe(leader, validator)` positional only; leader value at `.calldata` | AST lint test enforces two positional arguments; validators read `.calldata`. |
| Closures must not capture `self`/storage | AST lint test on all module-level functions; closures capture plain values. |
| `exec_prompt(..., response_format="json")` returns a parsed object | Every consumer accepts only a dict and normalises. |
| `web.get` is byte-exact, `web.render` collapses whitespace | Diffs and raw files use `get`; the PR API JSON is parsed after `get`. |
| `strict_eq` only for immutable content | Fetches are pinned to full shas (the PR-to-sha lookup is the one mutable read and is repeated under `strict_eq`, so validators must see the same shas). |
| ASCII-only source, no heavy comments | Deploy build asserts ASCII and two comment lines. |
| Public views must not call each other | Private `_verification_dict`, `_item_dict` helpers. |
| No `datetime.min` placeholders | Empty strings for unset timestamps. |
| Report accepted-but-raised transactions as failures | Live mode checks `execution_result` for errors. |
| Wallet browsers: `createClient({chain, account})` only | Same pattern in `frontend/assets/app.js`. |

## New API surface used by VeriForge

Only APIs already used in SpecProof: `gl.Contract`, `gl.public.write/view`, `gl.message.sender_address`, `gl.nondet.exec_prompt`, `gl.nondet.web.get/render`, `gl.eq_principle.strict_eq`, `gl.vm.run_nondet_unsafe`. A lint test fails if any other `gl.*` attribute appears.

## Learned on live GenLayer Studio (VeriForge)

* **Freezing works as designed.** `web.get` on raw GitHub files and the compare diff, and `web.render` on the PR API, return byte-identical content on 5 validators under `strict_eq`.
* **Undetermined is safe to retry.** A transaction that ends Undetermined after its rotations writes no state, so the same call can be sent again before the stage deadline.
* **"Is this acceptable?" reviews do not converge.** Several live models asked to approve a proposal split roughly 2 to 3 even on a correct, two-item decomposition. Leader outputs were fine; approval was the problem. A reviewer must return a *checkable* defect (a quote from the claim, an index, a symbol present in the evidence). Only such a defect vetoes, and code verifies it.
* **Do not show evidence to a model as a JSON string.** Models quote what they see, so `\n`, `\"` and `\uXXXX` escapes appear in their quotes and verbatim-substring checks fail. Present raw text between fences whose marker contains a content-derived nonce.
* **The whole pipeline works per threat.** Each of decompose, hypotheses, defender, attacker, auditor, consensus, aggregate, challenge and finalize reached consensus on five validators with prompts of about 5 KB; no rotation was needed after 1.1.0 except one attacker round.
* **Call stages in order and for every threat.** A stage advances only when all threats have finished the previous role; calling the next role early is rejected with `invalid state` and no side effects. The number of threats can change between runs, so read `threat_ids` from `get_case` first.
* **Type inputs with an English keyboard.** A trailing Persian comma in a threat id (`T2` followed by U+060C) is a different string and was rejected.
* **Read results lose commas in Studio.** See `docs/DEPLOYMENT.md` step 7.
* **A PR must contain code.** A README-only PR has no entry point, so hypothesis generation fails by design and the verification terminates.
* **Keep inputs clean in Studio.** A left-over value in an input box (for example `vf_0` in the claim field) is sent as is. The contract rejected it, which is correct, but check every field before sending.
* **Diagnose with `stdout`.** A temporary `print` in a validator function appears in the transaction's `genvm_result`. Remove it before a release.

## Designed around, not verified

* **Transaction size and cost.** One role transaction per stage covers all threats in one call; a stage with several threats runs several consensus rounds inside one transaction. Whether Studio accepts this in one transaction is unverified. The API allows a single threat per call (`threat_id`) to keep transactions small.
* **Contract size.** The deploy artifact is about 74 KB; artifacts of 69 KB were accepted live.
* **Prompt size.** Evidence is capped at 50,000 diff characters plus 5 head files of 20,000, so prompts may reach roughly 150 KB; model context limits on live validators are unverified.
* **Clock**: `datetime.now(timezone.utc)` in a write method is used for deadlines; nodes must agree on it. Windows are hours long so small skew cannot matter.
