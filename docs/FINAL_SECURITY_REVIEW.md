# Final security review

Scope: `contracts/veriforge.py` (1771 lines, release 1.1.0) and its mechanically derived `contracts/veriforge_deploy.py` (73,990 bytes), the two certificate verifiers, and the frontend. Reviewed after all suites passed; a passing test is treated as evidence about the tested behaviour, not as proof of security.

## Enforcement levels used throughout

| Tag | Meaning |
|---|---|
| **D** | Enforced by deterministic contract logic (independent of any model or validator). |
| **C** | Enforced by GenLayer consensus (leader/validator agreement). |
| **L** | Depends on validator and LLM behaviour. |
| **T** | Tested locally against `tests/genlayer_stub.py`. |
| **V** | Verified on live GenLayer Studio. See *Live results*. Every stage from submission to a finalized, independently verified certificate has been run live once (with a 10-minute challenge window). |

## Test evidence (this run)

| Suite | Result |
|---|---|
| Unit `test_veriforge.py` | 89 passed, 0 failed (source and deploy artifact) |
| Adversarial `test_adversarial.py` (includes the 9 security-demo attacks) | 26 passed, 0 failed (source and artifact) |
| Certificate `test_certificate.py` (tamper matrix, Python vs JavaScript verifier, the live Studio certificate) | 15 passed, 0 failed (source and artifact) |
| Frontend `test_frontend.py` (headless Chromium) | 12 passed, 0 failed |
| Fuzz `test_fuzz.py`, seed 20260929 | 1000 sessions, 37,573 transactions (12,167 accepted, 25,406 rejected), ~1.29 M invariant checks, 2,968 finalized certificates independently verified |
| Fuzz, seeds 1, 2, 3 | 1,500 sessions each, ~57 k transactions each, no violation (run during development; not part of the default command) |
| Fuzz on deploy artifact | 300 sessions, 11,386 transactions, no violation |
| Mutation `mutation_test.py` | 50 mutants, 50 killed, 0 survived (one further mutant was removed as provably equivalent) |
| Build `build_deploy.py --check` | artifact current; syntax tree identical to source without docstrings; ASCII; two comment lines |

Defects the testing itself found and that were fixed: model text kept control characters (fuzz/adversarial); five mutants initially survived because tests did not pin short quotes, identifier boundaries, non-canonical leader failures, aggregate re-derivation; public views calling each other were refactored; an empty head file was treated as unavailable.

Limits of this evidence: the stub models GenLayer's documented primitives (independent validators, majority rule, `strict_eq`, rollback), not real validators, real models, real GitHub, or real gas/size limits. Scripted models cannot show that live LLMs find real vulnerabilities.

## Live results (GenLayer Studio, 2026-09-29)

| Step | Result |
|---|---|
| Deploy (1.0.0 at `0xB9D2...Ff82`, 1.0.2 at `0x6432...eb80`) | Accepted |
| `get_protocol_info`, `verification_count` | Correct values |
| `submit_security_claim` with an invalid claim (too short) | Rejected with the documented error; nothing stored |
| `submit_security_claim` for a real public PR | Accepted, returns `vf_0` |
| `freeze_evidence` | Accepted by 5 validators under `strict_eq`; PR API, diff and head file fetched byte-identically; `evidence_root` stored |
| `generate_attack_hypotheses` on a README-only PR | Leader: "no grounded attack hypothesis"; validators agreed on the failure; verification TERMINATED as designed (no code entry point exists) |
| `decompose_threats` (1.0.0, 1.0.2) | Undetermined after 3 rotations. With 1.0.2 the leader proposed two correct requirements (one per withdrawal entry point) but reviewers voted 2 agree / 3 disagree. State was unchanged, as expected. Led to the grounded-rejection rule in 1.1.0 |
| Full run on 1.1.0 (two contracts) | Reached `AGGREGATED` twice: 2 threats (T1, T2) and 3 threats (T1-T3), different decompositions each time. Both gave final `INSECURE` |
| `generate_attack_hypotheses` on the code PR | Accepted, 3 and 8 hypotheses. Some are irrelevant to the claim (key theft, storage corruption, flash loans) |
| Per-threat `defender_analysis`, `attacker_analysis`, `auditor_reconciliation` | All reached consensus (5 validators), no Undetermined. Two earlier ERRORs were operator mistakes (stages called before the previous stage was complete), rejected by the state machine with no state change |
| `consensus`, `aggregate_security_result` | Accepted; `INSECURE` because `withdrawTo` has no `onlyAuthorized` |
| `challenge` VERDICT on T2 | Accepted, re-analysis by consensus, `CONFIRMED`. A mistyped target (`T2,`) was rejected with no state change |
| `finalize_certificate` inside the window | Reverted with `challenge window is still open` (correct) |
| `finalize_certificate` after the window (10-minute build) | Accepted; certificate hash `d68708db...0d6c` |
| Independent verification of the live certificate | Python verifier: CERTIFICATE VALID, 47 checks, including every quote found in the frozen bytes and a match with the on-chain hash. JavaScript verifier: 46 checks passed. Both reject an edited `final_result` and a wrong on-chain hash. Files: `examples/live/` |

## Reviews

### Architecture review
Small trusted core: everything that decides a result is one pure function (`_derive_threat_result`) and one aggregation rule, re-implemented in two independent verifiers. Models only propose. The design reuses SpecProof's live-tested primitives and adds no unverified GenLayer API (an AST lint test fails otherwise). Weakness: `veriforge.py` is large (1651 lines, ~68 KB deployed) and its acceptance by Studio is unverified.

### State-machine review
`ALLOWED_EDGES` is checked in the single `_enter` function; all eleven states are reachable and every non-terminal state has an exit (unit test). Every stage method requires its state; stage work is refused after its deadline; roles are write-once per threat; only `freeze_evidence` is caller-restricted (submitter). Fuzz I1, I5, I12, I15 hold across ~37 k transactions. Note: stage methods are deliberately permissionless; a caller controls only timing and ordering, never content.

### Evidence-integrity review
Evidence is fetched once, under `strict_eq`, at pinned shas, byte-exact via `web.get`; stored; hashed per item and as `evidence_root`. No writer exists after freeze (D); fuzz I2/I3 and attack A5 (post-freeze force-push) confirm. Diff splitting uses `\n` only (unicode separator attack A9); over-limit input is rejected, not truncated; missing, binary, omitted or unsafe-path files make evidence incomplete and cap the result at UNPROVEN. Residual: the PR-to-sha lookup and GitHub availability at freeze time are trusted; an unlabeled deleted-file chunk is accepted as complete (its content is fully in the diff).

### Consensus review
Role outputs are normalised deterministically against the frozen evidence before comparison. Validators require the leader value to be exactly canonical and the categorical verdict to match their own independent run (defender `position`, attacker `outcome`, auditor `ruling`), taken either as stated or after grounding. Propose-and-review stages accept a canonical proposal unless a reviewer returns a grounded defect (1.1.0). Free-text reasons are not compared (so honest wording differences do not cause disagreement) and cannot change results. Malicious leaders (forged counterexample, suppressed counterexample, non-canonical values, forged failures) are rejected in the stub even when a validator colludes (A1, A2, adversarial suite). Residual (**C**/**L**): live agreement rates for the role stages are not yet measured. Live runs of 1.0.x showed the strict LLM review producing Undetermined for a correct decomposition, which led to the grounded-rejection rule.

### Adversarial-analysis review
Grounding rules: quotes must be verbatim substrings (6-400 chars); symbols match identifier boundaries; a counterexample needs a hypothesis id of its own threat, a quoted entry point, path symbols in the cited evidence, and only valid citations; otherwise it degrades to UNSUBSTANTIATED which cannot yield INSECURE. Defender SATISFIED needs verbatim rebuttals for every hypothesis. The auditor is coerced to INCONCLUSIVE when its ruling is unsupported. Residual (**L**): the attacker only tests hypotheses that consensus accepted; a missed vulnerability produces a false SECURE that no deterministic rule can prevent.

### Challenge review
One challenge per threat, decisive results only, inside a window fixed at aggregation. Resolution is CONFIRMED (same re-derived result) or DOWNGRADED to CONFLICTING_EVIDENCE; SECURE<->INSECURE flips are impossible by construction (fuzz I14, attack A8, mutants `challenge-flips` and `challenge-always-confirms` killed). A re-analysis that errors reverts without consuming the challenge. Economics is off and isolated. Trade-off, kept deliberately: an unreproduced challenge also downgrades INSECURE to CONFLICTING_EVIDENCE. The re-analysis is itself a consensus result, so disagreement between two consensus runs is reported honestly rather than hidden. CONFLICTING_EVIDENCE is never a pass, and the certificate keeps the original result and the full re-analysis. Without a stake, anyone can trigger this once per threat (see known limitations).

### Certificate review
Canonical JSON and hashes are specified in `docs/CERTIFICATE_FORMAT.md`. The Python and JavaScript verifiers are independent re-implementations and agree on valid and tampered cases (cross-language test). Tampering with any single field, re-hashed tampering, bundle byte edits, and missing fields are detected. Fuzz I9 verifies every finalized certificate. Limit: a fully self-consistent forgery verifies internally; only comparison with `get_certificate_hash()` exposes it, and the UI/CLI mark that check SKIP when the hash is not supplied.

### Replay and timeout review
Replays of every transition are rejected (A6, unit tests). Deadlines are enforced in `_need_open`; `expire_if_timed_out` is callable by anyone, terminates early stages as UNPROVEN, fills missing roles with TIMEOUT in analysis stages and runs the deterministic consensus/aggregation steps. Timeouts can produce UNPROVEN, INSECURE or CONFLICTING (from roles that did complete) but never SECURE (fuzz I7, A7). Deadlines rely on node clocks agreeing to within hours (unverified live).

### GenVM compatibility review
Uses only SpecProof-verified APIs and patterns (`docs/GENVM_LESSONS.md`); AST lint tests enforce the API allowlist, positional two-argument `run_nondet_unsafe`, no `self` in module-level closures, no TreeMap/DynArray assignment in `__init__`, ASCII source, and the header. Verified live: the whole pipeline including per-threat consensus rounds; contract size (~69-74 KB) is accepted; `web.get` on raw GitHub and the diff, and `web.render` on the PR API, give byte-identical results across 5 validators under `strict_eq`; `json.dumps` keyword arguments work. Unverified live: all-threats (multi-round) transactions, the largest prompt sizes, and the 48 h window itself.

### Test-coverage review
Every security invariant in `docs/SECURITY_MODEL.md` maps to at least one named test, fuzz invariant or killed mutant. Gaps: no test exercises real LLM disagreement; the stub cannot reproduce GenVM storage-encoding or gas failures; frontend live mode is only tested for its no-wallet paths.

## The 20 self-audit questions

1. **Can a malicious leader forge a verdict?** No result is taken from a leader. Role values must equal `normalize(value)` and match validator verdicts (**C**+**D**, **T**: A1, A2, adversarial suite). Results are derived by the contract afterwards (**D**). Depends on an honest validator majority for the categorical verdict.
2. **Can a malicious leader invent evidence?** Not in role outputs: quotes not present in the frozen bytes do not survive normalisation (**D**, **T**). Evidence freezing itself is under `strict_eq`, so a leader-only fabricated fetch fails unless a majority sees identical bytes (**C**, stub-tested only).
3. **Can an attacker reference an unknown evidence ID?** No. Hypotheses citing unknown ids are dropped; counterexample/defender citations with unknown ids are discarded (**D**, **T**: unit, fuzz).
4. **Can frozen evidence change?** No method writes evidence after `freeze_evidence`; fuzz I2/I3 and A5 confirm (**D**, **T**). If GitHub content changes later, the frozen record does not.
5. **Can a certificate be modified without detection?** Any edit breaks `certificate_hash`; a re-hashed edit breaks derivation or hash-chain checks (tamper matrix). A wholly self-consistent forgery is detected only against the on-chain hash (**T**, documented limit).
6. **Can SECURE be produced when evidence is insufficient?** No: incomplete evidence gives UNPROVEN/`EVIDENCE_INCOMPLETE` regardless of role output (**D**, **T**: unit, fuzz I8, killed mutants `aggregate-incomplete-evidence`, `freeze-complete-always`). "Sufficient" means complete within the size limits, not that the analysis was adequate.
7. **Can attacker analysis rely on nonexistent code?** It can try, but the counterexample is then UNSUBSTANTIATED and never INSECURE (**D**, **T**: A3, fuzz normaliser cases).
8. **Can a challenge be replayed?** No: one per threat, state and window checked, failed re-analysis reverts without consuming it (**D**, **T**).
9. **Can a stage be skipped?** No: `_need` and `_enter` (**D**, **T**: unit, A6, fuzz I1).
10. **Can a deadline be bypassed?** Stage methods are refused after the deadline and the challenge window is fixed at aggregation; only `expire_if_timed_out` acts afterwards (**D**, **T**). Relies on node clock agreement (**unverified live**).
11. **Can an unauthorized account mutate a verification?** Only the submitter can freeze. Any account can drive later stages by design, but cannot influence content, only timing/order; challenges are open to all by design (**D**, **T**).
12. **Can malformed validator output corrupt state?** No: malformed values fail validation, transactions revert atomically, malformed role outputs become ERROR origin (**D**, **T**: adversarial suite, fuzz with hostile models and forced leader results, rollback checks I12).
13. **Can a frontend user forge a certificate?** They can create a JSON that the in-page verifier accepts if it is fully self-consistent and no on-chain hash is supplied; the UI reports the on-chain check as SKIP and never as passed. Nothing a user does in the frontend changes chain state except by submitting transactions (**T**).
14. **Can the protocol get permanently stuck?** Every non-terminal state has a permissionless exit via `expire_if_timed_out` or the next stage; AGGREGATED can always be finalized after the window (**D**, **T**: fuzz I15 over ~37 k transactions). Live: a transaction that always exceeds real gas/size limits could make a stage un-runnable, though timeouts still advance it.
15. **Are all important claims backed by tests?** Yes for local behaviour (see coverage review and mutation results); not for live behaviour.
16. **Does the deploy artifact exactly correspond to the source?** Yes, mechanically: AST equality with docstrings removed is checked at build, in CI, and by a unit test; all suites also run against the artifact (**T**).
17. **Which guarantees are actually enforced by the contract?** **D**: evidence immutability, state machine, deadlines, write-once roles, grounding rules, derivation, aggregation, challenge direction, certificate construction (see `docs/SECURITY_MODEL.md`).
18. **Which guarantees depend on LLM behaviour?** Faithful decomposition, hypothesis coverage, whether real vulnerabilities are found, whether models agree often enough for liveness of consensus. These are **L** and are not guaranteed.
19. **Which guarantees depend on GenLayer consensus?** That a leader cannot install a non-canonical or unagreed role verdict, that no decomposition or hypothesis set is accepted over a majority of grounded objections (the review fails open on vague objections, by design since 1.1.0), and that all validators see the same frozen bytes (**C**). The frozen-bytes guarantee is verified live (**V**); the rest has only been tested against the stub.
20. **What remains unproven?** Live agreement rates over many runs (one PR, two runs so far), a SECURE outcome on a genuinely fixed change (no live run has produced SECURE), all-threats transactions, the largest prompts, the 48 h window on the production build; and, in principle, that any SECURE claim corresponds to secure code.

## Known limitations and unresolved risks

1. Live validation is partial; see *Live results* and the checklist in `docs/DEPLOYMENT.md`.
2. Shared model blindness can yield SECURE for vulnerable code (inherent).
3. LLM-dependent stages can end Undetermined on live networks. Undetermined leaves state unchanged, so a stage can be retried before its deadline. Use per-threat calls (`threat_id`): an all-threats call multiplies the chance of non-agreement.
4. Contract size (~68 KB) and prompt sizes (up to ~150 KB) may exceed live limits.
5. Only public GitHub repositories, at most 20 diff files, 50,000 diff characters and 5 head files; larger changes are rejected or marked incomplete.
6. Certificates are self-consistent proofs of process, not proofs that validators agreed; anchor with the on-chain hash.
7. Frontend live mode is unverified against a live deployment.
8. The demo uses scripted models and a local stub.
9. Without economics, a challenge costs nothing, so any address can use the single challenge per threat to turn an INSECURE result into CONFLICTING_EVIDENCE when re-analysis does not reproduce it (never into SECURE).
10. When leader and validators agree that a stage failed (for example a transient model outage on every node), the verification terminates as UNPROVEN rather than reverting. This fails closed; a new submission is required.
11. Propose-and-review fails open: a leader that weakens a decomposition or picks weak hypotheses passes when reviewers do not return a grounded defect. SECURE still needs all role stages on every requirement.
12. A threat can be blocked from SECURE by a weak attacker. If the attacker returns a counterexample whose quotes are valid but which does not concern the requirement (live: T1 got a counterexample about `withdrawTo`), the auditor rules INCONCLUSIVE or DEFENSE_UPHELD and the threat becomes CONFLICTING_EVIDENCE. This is the conservative direction and was left unchanged.
13. Model-proposed hypotheses include irrelevant ones (key theft, flash loans). The defender then cannot rebut every hypothesis with a code quote, so a correct requirement ends as NOT_ESTABLISHED. In practice this means SECURE is hard to reach on live models; INSECURE, driven by a checkable counterexample, is reliable.
14. The decomposition differs between runs of the same claim (two or three requirements). Each requirement is analyzed independently, so this changes the certificate but not the verdict in the run above.
