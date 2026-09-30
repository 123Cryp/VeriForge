# Changelog

## 1.1.0

First release verified end to end on GenLayer Studio: see `examples/live/` and `docs/FINAL_SECURITY_REVIEW.md`.

Changes from an independent review and from live GenLayer Studio runs. The certificate format is unchanged (`protocol_version` stays "1.0").

* **Evidence reaches the model as raw text.** Evidence was embedded as a JSON string, so models saw `\n`, `\"` and `\uXXXX` escapes. Quotes copied from what they saw failed the verbatim-substring check, which silently downgraded defences and counterexamples and caused validators to diverge. Evidence items are now raw blocks fenced by `<<<ITEM nonce ...>>>` / `<<<END_ITEM nonce>>>`. The 64-bit nonce is derived from the content hash, so forging or closing a fence is computationally infeasible.
* **Reviews veto only with a grounded defect.** In propose-and-review, a validator now rejects the leader's proposal only when its reviewer returns a defect that deterministic code can check:
  * decomposition: `UNCOVERED` with a quote that occurs in the claim, or `BAD_REQUIREMENT` with a valid index and a quote from that requirement;
  * hypotheses: `BAD_HYPOTHESIS` with a valid index and a quote from that hypothesis, or `MISSED_ENTRY_POINT` naming a function defined in a head file and used by no hypothesis.

  Quotes are matched in raw or JSON-escaped form, so claims with quotes, newlines or non-ASCII text work. The review now fails open, and this is documented as a residual in `THREAT_MODEL.md`.

  Unspecific or unparseable rejections no longer veto. The canonical-form check is unchanged. Found live: reviewers rejected a correct two-requirement decomposition 3-2 with no stated reason, which gave Undetermined in every rotation.
* **The decomposition review is claim-level.** It carries the claim and requirements but no evidence, which makes it much smaller.
* **Role agreement uses the validator's raw verdict as well.** A validator agrees when its own categorical verdict (before or after grounding) equals the leader's grounded verdict. The leader's value must still be exactly canonical and grounded, and a different verdict still disagrees.
* Deterministic `fetch failed` code for optional-file fetch errors, so node-specific exception text cannot split `strict_eq`.
* Challenge rationale is sanitised (control characters removed).
* Decomposition prompt: "use as few requirements as needed", with no preferred count.
* Removed the temporary diagnostic `print` of 1.0.3.
* Tests: 89 unit tests (seven new); 50 mutants (eight new), all killed.

## 1.0.3

* Temporary diagnostic build: the reviewing validator printed its review verdict to stdout. Removed in 1.1.0.

## 1.0.2

* Review prompts (decomposition and hypotheses) now reject only for a concrete defect instead of requiring every quality criterion. Found on the live test: three validators voted disagree in every rotation and two were idle, so the strict review never agreed.

## 1.0.1

* Decomposition prompt now requires positive obligations derived from the claim, no invented obligations, at most 3-5 requirements. Found on the first live test: the model proposed seven requirements including code observations and invented features, and validators did not agree (Undetermined).

## 1.0.0

Initial release.

* Contract with eleven-state machine, byte-exact evidence freezing, propose-and-review decomposition and hypotheses, exact-verdict role consensus (defender, attacker, auditor), deterministic derivation and aggregation, single-use challenges that can only confirm or downgrade, timeouts that never yield SECURE, canonical hashed certificates.
* Mechanically derived deploy artifact.
* Independent certificate verifiers (Python, JavaScript) with cross-language conformance test.
* Frontend: recorded demo replay, in-browser verifier, security demo, optional live mode.
* Test suites: unit (82), adversarial (26), certificate (14), frontend (12), fuzz (seeded), mutation (42 mutants).
* Not yet done: deployment and validation on live GenLayer.
