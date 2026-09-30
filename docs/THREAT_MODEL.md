# VeriForge threat model

## Assets

* The integrity of a verification record: claim, frozen evidence, role outputs, result, certificate.
* The meaning of the words SECURE and INSECURE.

## Actors and assumptions

| Actor | Capability assumed |
|---|---|
| Submitter | Chooses repository, ref, claim; may be malicious (wants SECURE for bad code). |
| Any caller | Can call any stage method, any number of times, in any order, with any arguments. |
| Repository author | Controls diff and file content, including hostile text aimed at the models. |
| Leader | May return arbitrary values instead of running the role. |
| Minority of validators | May collude with the leader or answer arbitrarily. |
| Language models | May hallucinate, be prompt-injected, or disagree. **Never trusted for a verdict.** |
| GitHub | Assumed to serve the same bytes to all validators at freeze time (`strict_eq` detects violations). |

Out of scope: a Byzantine validator majority, compromise of GenLayer itself, private or unavailable repositories, and the actual correctness of the code under review beyond what the evidence shows.

## Attacks considered and the mechanism that answers each

| # | Attack | Answer | Layer |
|---|---|---|---|
| 1 | Leader forges a counterexample with invented code | Validators recompute `normalize(value)`; quotes not in evidence do not normalise to themselves | consensus + deterministic |
| 2 | Leader hides the real counterexample | Validator's independent run gives a different `outcome`; no majority | consensus |
| 3 | Every model hallucinates the same exploit | Quote/symbol grounding turns it into UNSUBSTANTIATED (never INSECURE) | deterministic |
| 4 | Prompt injection in claim or diff | Untrusted-data notice, JSON-encoded claim and requirements, evidence in raw items fenced by a 64-bit content-derived nonce, and the rule that a role output has no authority without verbatim citations | deterministic |
| 5 | Evidence changes after freezing (force-push) | Head sha pinned; bytes and hashes stored; later stages never re-fetch | deterministic |
| 6 | Replay, skipping, repeating, wrong caller | `ALLOWED_EDGES`, write-once role slots, submitter-only freeze, single challenge | deterministic |
| 7 | Stalling to avoid a bad result | Anyone can call `expire_if_timed_out`; missing roles become TIMEOUT; result becomes UNPROVEN, never SECURE | deterministic |
| 8 | Challenge used to flip a result | Challenge resolution is CONFIRMED or DOWNGRADED-to-CONFLICTING only | deterministic |
| 9 | Diff text imitating another file header | Diff split on `\n` only; label taken from the file's own header; unlabeled or unsafe paths make the evidence incomplete | deterministic |
| 10 | SECURE with partial evidence | Binary, omitted, unavailable or over-limit files mark evidence incomplete; aggregate gives UNPROVEN | deterministic |
| 11 | Oversized or truncated input | Rejected, never truncated | deterministic |
| 12 | Certificate edited after the fact | Hash chain plus independent verifier re-derives all results; on-chain hash anchors it | deterministic + external |

## Residual risks (not eliminated)

* **Shared model blindness.** If all validators' models miss a real vulnerability, the result can be SECURE while the claim is false. Grounding prevents *invented* evidence, not *missed* evidence. SECURE is a statement about the process, not the code.
* **Hypothesis space.** The attacker is limited to hypotheses proposed and reviewed by consensus; an attack outside that set is not examined.
* **Decomposition and hypothesis quality (fail-open review).** Since 1.1.0 a canonical proposal passes unless a majority of reviewers return a grounded defect. Each defect is checked deterministically: a quote that occurs in the claim or in the named requirement or hypothesis, or a function definition in a head file. A leader that quietly weakens coverage passes when reviewers answer vaguely. The trade was made for liveness, because strict approval was Undetermined on correct proposals live. SECURE still requires the defender, attacker and auditor stages on every requirement. A stronger alternative, not implemented, is to always add the verbatim claim as a final catch-all requirement.
* **Challenge laundering.** Without economics, anyone (including the submitter) can challenge an INSECURE result once. If the re-analysis does not reproduce it, the result becomes CONFLICTING_EVIDENCE. That is still a non-passing result, and the certificate keeps `original_result`, the challenge and its re-analysis. Consumers must treat anything other than SECURE as a failure and should inspect challenges.
* **Live GenLayer behaviour** of the multi-round transactions, GitHub raw-file fetching and contract size is not verified by this repository's tests (see `docs/DEPLOYMENT.md`).
* **Fully self-consistent forged certificates** verify internally; only comparison with `get_certificate_hash()` on-chain exposes them.
