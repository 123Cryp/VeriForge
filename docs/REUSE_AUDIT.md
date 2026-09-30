# VeriForge - SpecProof reuse audit

Phase 1 deliverable. Written after reading every file in the SpecProof v1.6
archive (`contracts/specproof.py`, `contracts/specproof_deploy.py`,
`tests/test_specproof.py`, `tests/test_fuzz.py`, `tests/mutation_test.py`,
`tests/genlayer_stub.py`, `tests/fixtures/*`, `tools/build_deploy.py`,
`tools/probe_fetch.py`, `frontend/index.html`, `SECURITY.md`,
`ARCHITECTURE.md`, `CHANGELOG.md`, `docs/GENVM_LESSONS.md`, the GitHub
workflow). Nothing in VeriForge was written before this file.

Evidence levels used below:

- **LIVE** - the SpecProof repository or its lessons record this behaviour on a
  real GenLayer Studio deployment (v1.0 to v1.6, StudioNet).
- **STUB** - only exercised against `tests/genlayer_stub.py`. That stub is a
  hand-written imitation of the SDK, not GenVM. It proves the contract's own
  logic, not how GenVM, GitHub or an LLM behave.
- **DOC** - taken from the SDK documentation only.

## 1. What is safe to reuse

| Component | Evidence | Decision |
|---|---|---|
| Two-line runner header (`# v0.2.16` then `# { "Depends": ... }`), explicit `from dataclasses import dataclass` after `from genlayer import *` | LIVE (omitting the version line fell back to runtime v0.1.0 and crashed with `NameError: dataclass`) | Reused verbatim |
| `TreeMap` / `DynArray` fields declared at class level and never assigned in `__init__`; lists assigned to `DynArray` fields; only `u256` counters set in `__init__` | LIVE (`AssertionError: TreeMap <- dict`) | Reused |
| `@allow_storage @dataclass` records with `str`/`u256`/`Address`/`DynArray[str]` fields, mutated by attribute assignment on the object returned from `TreeMap.get` | LIVE | Reused. VeriForge stores role outputs as canonical JSON strings instead of nested storage types, to stay inside what was live-tested |
| `gl.vm.run_nondet_unsafe(leader_fn, validator_fn)`, positional, module-level closures that capture only plain values, leader value read as `getattr(leaders_res, "calldata")` | LIVE (SpecProof v1.2 to v1.6; earlier ModAppeal) | Reused. This is the only exact-consensus primitive VeriForge uses for LLM steps |
| `gl.eq_principle.strict_eq(fn)` for fetches, with the exception caught **inside** the closure and turned into a marker string, re-raised only after consensus | LIVE (an exception inside the closure otherwise aborts the whole transaction with `Equivalence Principle Outputs: 0`) | Reused (`_run_strict_eq`) |
| `gl.nondet.exec_prompt(prompt, response_format="json")` returns an already-parsed object, top-level must be an object | LIVE | Reused: every prompt asks for a JSON object |
| `gl.nondet.web.get(url)` with `.status` and `.body` (bytes) for byte-exact retrieval; `render()` collapses whitespace | LIVE (on-chain probe, `tools/probe_fetch.py`) | Reused for diffs and (new, see 3) for file contents |
| `gl.nondet.web.render(url)` for the GitHub PR API JSON, only `base.sha`/`head.sha` cross the consensus boundary | LIVE (v1.5 first PR run, v1.6 PR #100) | Reused for PR resolution |
| `gl.message.sender_address`; time via `datetime.datetime.now(timezone.utc)`; no `datetime.min` placeholders | LIVE (ModAppeal lessons) | Reused |
| Strict repository parser (https, github.com only, exactly `owner/repo`), strict ref parser (full 40-hex sha or `PR#n`) | LIVE input paths, STUB adversarial coverage | Reused |
| Diff splitting on `"\n"` only (never `splitlines()`), file label taken from `+++`/`---`/`rename to` header lines | STUB (attacks A5, A7 found by review, not live) | Reused (`_split_diff`, `_diff_file_info`) |
| Propose-and-review consensus (leader canonicalizes, validator re-checks canonical form, then a validator LLM must answer `{"acceptable": true}`) | LIVE (decomposition and mapping in v1.2+) | Reused for threat decomposition and attack hypotheses; from VeriForge 1.1.0 a rejection must be grounded (checkable defect) after live runs showed unspecific rejections blocking correct proposals |
| Exact-verdict consensus (validator re-runs the task independently and must reproduce the categorical verdict; leader output must equal its own canonical form; failure claims must be in canonical failure form) | LIVE | Reused and generalized (`_role_consensus`) |
| Untrusted-evidence fencing in prompts | LIVE, effect on prompt injection unmeasured | Reused, documented as a mitigation not a guarantee |
| Only the submitter can freeze evidence (a PR head moves) | STUB | Reused |
| Pagination for list views (`MAX_PAGE_SIZE`) | STUB | Reused |
| `tools/build_deploy.py` (tokenize + ast, docstring and comment stripping, syntax-tree equivalence proof, ASCII check, `--check` mode) | LIVE artifact (`specproof_deploy.py` deployed) | Reused, renamed and extended (header check, deploy-file must have no comment lines, source/deploy byte counts) |
| Test architecture: dependency-free runner, invariant fuzzer with ghost state and reproducible seeds, mutation runner that applies one-line edits to a copy of the tree | STUB | Reused as architecture; all tests rewritten for VeriForge APIs |
| Frontend wallet pattern: `createClient({ chain: studionet, account })` only; no `provider`, no `connect()`, no `initializeConsensusSmartContract()`; `studionet` from `genlayer-js/chains`; pinned `genlayer-js@1.1.8`; reverted transactions reported as failures; `textContent` only for untrusted data | LIVE (Rabby in Mises) | Reused |

## 2. What must be redesigned

| SpecProof behaviour | Problem for a security protocol | VeriForge design |
|---|---|---|
| One LLM judge returns PASS/FAIL/INSUFFICIENT per requirement; validators agree on the string | A PASS is only an LLM opinion | Three roles. A per-threat SECURE needs a defender position with a quoted rebuttal for **every** attack hypothesis, an attacker that found nothing, and an auditor that upholds the defence. Every quote is checked byte-exactly against frozen evidence by contract code |
| FAIL is whatever the judge says | Same problem in the other direction | INSECURE needs a structured counterexample whose quotes are exact substrings of frozen evidence and whose entry point and path symbols occur in the cited evidence, upheld by the auditor. Otherwise the attacker outcome is `UNSUBSTANTIATED`, which can never produce INSECURE |
| Three outcomes (VERIFIED/FAILED/INSUFFICIENT_EVIDENCE) | No way to say "attack and defence disagree" | Four: SECURE, INSECURE, UNPROVEN, CONFLICTING_EVIDENCE |
| Evidence = unified diff only | The diff shows changed lines, not the other public entry points of the same file. "Alternative withdrawal path" cannot be found in three lines of context | Evidence = diff per file **plus** the exact head-commit content of changed files (`raw.githubusercontent.com/<owner>/<repo>/<head_sha>/<path>`). Completeness is recorded; SECURE is impossible when evidence is incomplete |
| Long excerpts are truncated for the judge; a PASS on truncated evidence is withheld | Truncation is a patch on a design that lets the judge see partial evidence | Oversized evidence is rejected at freeze time, so no verdict is ever produced from a partial view |
| Evidence mapping stage | Not needed: the defender must cite evidence for each hypothesis and the attacker must cite evidence for a counterexample, both mechanically checked | Removed |
| Challenge: any requirement, re-judged, reproduce-or-downgrade to INSUFFICIENT_EVIDENCE, `late_judged` special case | Complex, and a downgrade to "insufficient" hides that two analyses disagreed | Challenge targets a disputed threat verdict or one counterexample; a decisive result (SECURE/INSECURE) survives only if independently reproduced, otherwise it becomes CONFLICTING_EVIDENCE. It can never flip SECURE to INSECURE or the reverse, one challenge per threat |
| Timeouts fill missing verdicts with INSUFFICIENT_EVIDENCE | Same idea is right; needs one deadline per stage | Every stage has a deadline; expiry before the analysis stages terminates as UNPROVEN, expiry inside the analysis stages marks the missing role output `TIMEOUT` and moves on |
| Plain `sha256(diff)` as evidence root, `json.dumps(sorted(...))` as other hashes | Not domain-separated, not specified for other languages | One canonical JSON (`sort_keys`, compact separators, `ensure_ascii`) for every structured hash, specified in `docs/CERTIFICATE_FORMAT.md` and reimplemented independently in Python (`tools/verify_certificate.py`) and JavaScript (`frontend/assets/verify.js`) |
| Attestation is a JSON string; hashes inside it cannot be checked without re-fetching | "Self-contained" only in name | Certificate embeds every role output, counterexample and evidence descriptor and carries `certificate_hash`; the verifier re-derives every hash **and** every result from the embedded data |
| Stub `strict_eq` runs the fetch once; validators replay the leader's LLM answers by default | Honest validators trivially agree, so nothing exercises disagreement | New stub: `strict_eq` re-executes the function for every validator and compares; validators call the LLM independently; several validators with majority rule; a hook to force a malicious leader result |
| `judge_requirements` judges every requirement in one transaction | Up to 12 nondet rounds in one transaction is untested live | Every role stage takes an optional `threat_id`, so one threat is one transaction |
| Source file begins with a long comment block | Studio can fail with `invalid_contract` on comment volume (JudgeChain, SpecProof lessons) | `contracts/veriforge.py` starts with the two header lines and then code; the deploy file is mechanically stripped of every comment and docstring |

## 3. SpecProof security invariants that must stay intact

| SpecProof invariant | Carried into VeriForge as |
|---|---|
| I3 canonical repository/ref, full 40-hex sha, PR resolved to base and head | Same parsers; both SHAs recorded and hashed into the evidence root |
| I5/I9 frozen evidence immutable, partitions the frozen diff exactly, `evidence_root` derived from exact bytes | Evidence written once from `SUBMITTED`; per-file diff items re-assemble to the diff; content hash per item; root over `(id, type, path, content_hash)` plus repository and both commits |
| I4 status changes only along declared edges | `_transition` refuses any edge not in `ALLOWED_EDGES`; fuzzer checks it after every transaction |
| I6 finalized never changes; attestation immutable | Certificate written once at `FINALIZED` |
| I8 challenge never flips a consensus verdict | Strengthened: SECURE/INSECURE survive only if reproduced, otherwise CONFLICTING_EVIDENCE |
| I14 one challenge per requirement | One challenge per threat, no special cases |
| I15 aggregation is strict and total | Aggregation is a pure function re-derived by the verifier |
| I18 only the submitter freezes | Same |
| I19 honest validators never accept a non-canonical leader result | Same, for every role output |
| I20 evidence only from HTTP 200, valid UTF-8 | Same, for the diff and every file |
| A2 validator requires the leader's exact canonical output | `normalize(value) == value` for every stage |
| A4 propose-and-review so one bad leader cannot kill a verification | Same for decomposition and hypotheses |
| v1.1 no re-aggregation, no re-opened windows | Challenge window is fixed at aggregation, never extended |

## 4. SpecProof assumptions that must NOT be copied blindly

1. **A specification is a set of independent requirements.** A security claim
   is a statement about *all* paths. Threats can overlap and one uncovered
   path invalidates the rest, hence the asymmetric aggregation
   (INSECURE > CONFLICTING_EVIDENCE > UNPROVEN > SECURE).
2. **PASS/VERIFIED is a success state.** In SpecProof insufficient evidence
   and a failed judgment both aggregate below VERIFIED, which is right, but
   nothing structural made VERIFIED hard to reach. In VeriForge SECURE has a
   list of deterministic gates (section 3 of `docs/SECURITY_MODEL.md`).
3. **Reason text does not matter.** In SpecProof only the verdict is bound.
   For a counterexample the *content* is the deliverable, so it is verified
   deterministically instead of being trusted.
4. **Decomposition is the specification's own list.** Here the decomposition
   is an interpretation of a free-text claim; a weak claim yields a weak
   threat model. The claim and the threats are both in the certificate.
5. **One diff is enough evidence.** See section 2.
6. **`SECURITY.md` is current.** It still says the PR path "has not been
   live-verified", while `CHANGELOG.md` (v1.5, v1.6) records live PR runs.
   The changelog and the live addresses are treated as the newer record.
7. **The fuzzer proves behaviour.** It proves the contract logic against the
   stub only (SpecProof says so itself). VeriForge keeps that statement.
8. **Challenge windows can be waited out in live testing.** SpecProof waited
   48 hours. VeriForge keeps `CHALLENGE_WINDOW_SECONDS` a single constant, but
   the deploy artifact is not allowed to differ from the tested source, so a
   short-window live test needs a rebuild and is a separate artifact
   (documented in `docs/DEPLOYMENT.md`).

## 5. GenLayer SDK patterns already live-tested (and used)

`gl.Contract`, `gl.public.write`, `gl.public.view`, `gl.message.sender_address`,
`gl.nondet.exec_prompt(..., response_format="json")`,
`gl.nondet.web.get` / `.render`, `gl.eq_principle.strict_eq`,
`gl.vm.run_nondet_unsafe(leader_fn, validator_fn)`, `TreeMap`, `DynArray`,
`u256`, `Address`, `allow_storage`, `datetime.datetime.now(timezone.utc)`,
`hashlib.sha256`, `json`, `re`, `urllib.parse.urlsplit`.

**No other GenLayer API is used.** In particular VeriForge does not use
`prompt_comparative`, `prompt_non_comparative`, native token transfer, or
cross-contract calls.

Requires live validation because SpecProof never exercised it:

- `gl.nondet.web.get` against `raw.githubusercontent.com` (SpecProof only used
  `github.com/.../*.diff`). Same API, different host.
- Several role-consensus calls inside one transaction when `threat_id` is
  omitted (SpecProof had `judge_requirements` but its live runs used one or
  two requirements).
- Prompts with up to about 140,000 characters of evidence.
- `json.dumps(..., separators=..., ensure_ascii=True)` inside GenVM (standard
  library, but only `sort_keys` was used live).

## 6. GenVM and deployment pitfalls already discovered

1. Missing `# v0.2.16` line silently selects runtime v0.1.0.
2. `@dataclass` needs an explicit stdlib import.
3. Never assign `{}`/`[]`-typed values to `TreeMap` fields in `__init__`.
4. An exception inside a nondet closure aborts the whole transaction; catch inside.
5. `response_format="json"` returns objects, and needs a top-level object.
6. `run_nondet_unsafe` takes two positional functions; keyword use fails.
7. The leader value in `validator_fn` is `.calldata`; any other attribute
   makes the validator raise, which counts as disagreement and shows up as a
   stuck `Undetermined` result with no error message.
8. A closure that references `self` drags the storage class into the
   pickled closure and gives inconsistent consensus; keep closures at plain
   values.
9. Byte-exact hashing of independently fetched pages is too strict when the
   page is volatile (ModAppeal). Diffs at a pinned sha and raw files at a
   pinned sha are immutable, so byte-exact is right here. Volatile sources
   are not used.
10. Studio can reject files with heavy comments or non-ASCII content.
11. A transaction can be accepted while the contract raised; the frontend
    must report it as failure.
12. `datetime.min` placeholder crashes storage encoding.
13. A wallet browser needs `createClient({ chain, account })` alone.

## 7. What in SpecProof is only a test stub

- `tests/genlayer_stub.py` in full: `run_nondet_unsafe` runs one validator
  that replays the leader's answers; `strict_eq` runs once; `exec_prompt`
  pops canned answers; there is no storage rollback on exceptions (the
  fuzzer adds its own); TreeMap and DynArray are `dict` and `list`.
- The "validator disagreement" it models is a canned answer, not the
  behaviour of independent LLMs.
- The mutation and fuzz results therefore say "the contract logic enforces
  these properties when the primitives behave as documented".
- All 95 SpecProof unit tests and 19 invariants run against that stub.

VeriForge's stub fixes the weakest points (independent validators, majority
rule, `strict_eq` re-execution, transactional rollback in the harness) but is
still a stub. `docs/FINAL_SECURITY_REVIEW.md` keeps "tested locally" and
"verified on live GenLayer" as separate columns.

## 8. Findings about SpecProof itself, noted while reading

- `SECURITY.md` says the PR path is not live-verified; the changelog says it
  was. Treated as stale documentation.
- `contracts/specproof.py` starts with a long comment block, which the
  project's own lessons say Studio can choke on; only the stripped deploy
  build is safe. VeriForge's source has no header comment block.
- `specproof.py` defines `_COMMIT_SHA_RE` and `_FULL_SHA_RE` as the same regex.
  Harmless; VeriForge keeps one.
- `mutation_test.py` requires each mutation target to occur exactly once,
  which is a useful guard against silent no-op mutants and is kept.
- The judge cannot answer "is there another public function that ..." from a
  three-line-context diff. This is the motivating gap for the head-file
  evidence in VeriForge.
