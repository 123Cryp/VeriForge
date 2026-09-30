# VeriForge architecture

VeriForge verifies one narrow question: **does a specific security claim about a specific immutable code change survive adversarial analysis against frozen evidence?** It never claims that software is bug-free.

> A SECURE result means that the defined security claim survived the protocol's evidence and adversarial verification process. It does not prove that the software contains no vulnerabilities.

## Components

| Component | File | Role |
|---|---|---|
| Contract | `contracts/veriforge.py` | State machine, evidence freezing, role consensus, deterministic derivation, challenge, certificate. |
| Deploy artifact | `contracts/veriforge_deploy.py` | Mechanically derived from the contract by `tools/build_deploy.py` (comments and docstrings stripped, syntax tree proven identical). |
| Certificate verifier | `tools/verify_certificate.py`, `frontend/assets/verify.js` | Two independent re-implementations of hashing and derivation. Import nothing from the contract. |
| Frontend | `frontend/` | Replay of a recorded local run, in-browser verifier, security demo, optional live mode. |
| Local GenLayer stub | `tests/genlayer_stub.py` | Models only the GenLayer APIs the contract uses, including leader/validator agreement. |

## Pipeline and state machine

```
SUBMITTED -> EVIDENCE_FROZEN -> THREATS_DEFINED -> HYPOTHESES_READY -> DEFENDED -> ATTACKED
          -> AUDITED -> RECONCILED -> AGGREGATED -> FINALIZED           (any early stage -> TERMINATED)
```

| Method | Precondition | Who | Effect |
|---|---|---|---|
| `submit_security_claim` | none | anyone | Validates repository, ref (PR number or 40-hex commit), claim; stores them canonically. |
| `freeze_evidence` | SUBMITTED, before deadline | **submitter only** | Fetches PR base/head shas, the diff and up to 5 head files under `strict_eq`; stores exact bytes, per-item hashes and `evidence_root`. |
| `decompose_threats` | EVIDENCE_FROZEN | anyone | LLM proposes threat requirements; validators check canonical form and review faithfulness. |
| `generate_attack_hypotheses` | THREATS_DEFINED | anyone | LLM proposes attack hypotheses; the contract drops any that cite unknown evidence or name an entry point absent from the cited evidence. |
| `defender_analysis` / `attacker_analysis` / `auditor_reconciliation` | matching stage | anyone | One role per threat. The categorical verdict must match exactly (as stated or after grounding). |
| `consensus` | AUDITED | anyone | Deterministically derives each threat's result from the three role outputs. |
| `aggregate_security_result` | RECONCILED | anyone | Re-derives every result, aggregates, opens the 48 h challenge window. |
| `challenge` | AGGREGATED, window open | anyone | Re-runs analysis for one decisive result; can confirm or downgrade only. |
| `finalize_certificate` | AGGREGATED, window closed | anyone | Builds and stores the certificate and its hash. |
| `expire_if_timed_out` | deadline passed | anyone | Advances a stalled verification without inventing a favourable outcome. |

Every transition goes through `_enter`, which checks the declared `ALLOWED_EDGES`. Stage work is refused after its 24 h deadline (`_need_open`). Nothing after `freeze_evidence` reads the network: later stages consume only stored, hashed data.

## Roles and why they cannot decide alone

* **Defender** argues each threat requirement holds. It can only reach `SATISFIED` if it supplies, for *every* hypothesis of that threat, at least one citation whose quote is a verbatim substring of the cited evidence item. Otherwise the contract downgrades it to `NOT_ESTABLISHED`.
* **Attacker** searches for a counterexample. To count it must name a hypothesis of its own threat, an entry point that occurs inside one of its quoted lines, path symbols that occur in the cited evidence, and only strictly valid quotes. Anything else becomes `UNSUBSTANTIATED`, which can never produce INSECURE.
* **Auditor** rules `ATTACK_UPHELD`, `DEFENSE_UPHELD` or `INCONCLUSIVE`. The contract coerces a ruling to `INCONCLUSIVE` when it is not backed by the attacker/defender output it refers to. If both inputs are missing no LLM call is made.

### Per-threat derivation (`_derive_threat_result`)

| Attacker | Auditor | Defender | Result |
|---|---|---|---|
| COUNTEREXAMPLE | ATTACK_UPHELD | any | INSECURE |
| COUNTEREXAMPLE | otherwise | any | CONFLICTING_EVIDENCE |
| NONE_FOUND | DEFENSE_UPHELD | SATISFIED | SECURE |
| anything else | | | UNPROVEN (with a reason code) |

### Aggregation

`INSECURE > CONFLICTING_EVIDENCE > UNPROVEN > SECURE`. All threats SECURE but evidence incomplete gives UNPROVEN with note `EVIDENCE_INCOMPLETE`.

## Consensus scheme (why exact, not fuzzy)

Every LLM output is normalised by deterministic code against the frozen evidence before it is compared. For a role, the leader returns `{"ok": true, "value": normalize(raw)}`. A validator accepts only if

1. the value is exactly canonical (`normalize(value) == value`, so a leader cannot smuggle un-normalised or un-grounded content);
2. the validator's own independent run yields the **same categorical result** (defender `position`, attacker `outcome`, auditor `ruling`), either as the model stated it or after grounding. A validator whose own quotes fail grounding but whose verdict matches the leader's grounded verdict agrees; a different verdict disagrees.

Free-text `reason` fields are stored from the leader and are deliberately not compared. A reported failure must have the exact canonical failure form and the validator must fail too. Decomposition and hypothesis generation use *propose-and-review*. Validators require the leader's proposal to be exactly canonical, then ask a reviewer model for defects. A rejection counts only if it is **grounded**, meaning deterministic code can check it:

* decomposition: an `UNCOVERED` quote that occurs in the claim, or a `BAD_REQUIREMENT` index plus a quote from that requirement;
* hypotheses: a `BAD_HYPOTHESIS` index plus a quote from that hypothesis, or a `MISSED_ENTRY_POINT` that is defined (`function`/`def`/`fn`/`func` NAME`(`) in a head file and used by no hypothesis.

Quotes are compared case-insensitively with whitespace collapsed, in either raw or JSON-escaped form. The review therefore *fails open*: an ungrounded or unparseable answer does not block a canonical proposal. This is a deliberate liveness trade-off (see `THREAT_MODEL.md`).

An unspecific "no" cannot block a canonical proposal. The decomposition review is claim-level and carries no evidence.

Evidence is shown to models as raw text in fenced items (`<<<ITEM nonce {metadata}>>>` ... `<<<END_ITEM nonce>>>`), not as a JSON string. Quotes can therefore be copied exactly as they appear in the bytes. The nonce is the first 16 hex characters (64 bits) of the hash of the evidence list, so content containing its own fence is computationally infeasible.

## Challenge

A challenge targets a decisive result (SECURE or INSECURE), once per threat, inside the 48 h window. `VERDICT` re-runs all three roles; `COUNTEREXAMPLE` re-runs only the auditor. If the re-derived result equals the original the challenge is `CONFIRMED`; otherwise the result is `DOWNGRADED` to `CONFLICTING_EVIDENCE`. **A challenge can never flip SECURE to INSECURE or the reverse.** If re-analysis cannot complete the transaction reverts and the challenge is not consumed. Economics (`ECONOMICS_ENABLED = False`) is an isolated hook that only appends an audit record.

## Certificate

`finalize_certificate` stores canonical JSON containing repository, commits, claim, evidence items with hashes, threats, hypotheses, every role output, counterexamples, per-requirement results, challenges, consensus metadata and `certificate_hash = sha256(canonical JSON without the hash)`. See `docs/CERTIFICATE_FORMAT.md`.

## Reused versus new

Reused from SpecProof: GenLayer API usage, header, storage patterns, byte-exact `web.get`, `strict_eq` with in-closure exception handling, `run_nondet_unsafe`, canonical JSON, build-time stripping, stub/harness/mutation style. Everything above the primitives (roles, derivation, counterexamples, challenge, certificate) is new. See `docs/REUSE_AUDIT.md`.
