# VeriForge security model

This document separates **what enforces each property** so that no claim is stronger than its enforcement.

| Layer | Meaning |
|---|---|
| D | Deterministic contract logic: same on every node, independent of any model. |
| C | GenLayer consensus: leader/validator agreement on a non-deterministic block. |
| L | Depends on validator and LLM behaviour. |
| T | Tested locally against the stub. |
| V | Verified on live GenLayer. **Nothing in this repository is at level V.** |

## Invariants

| ID | Invariant | Enforced by | Tested |
|---|---|---|---|
| S1 | Evidence is immutable after `freeze_evidence` and re-hashable from stored bytes | D (no writer; state machine) | T (unit, fuzz I2/I3, attack A5) |
| S2 | Only the submitter freezes | D | T |
| S3 | State transitions follow `ALLOWED_EDGES`; stage work is refused after its deadline | D | T (fuzz I1) |
| S4 | Each role output is recorded once per threat and never rewritten | D | T (fuzz I5) |
| S5 | SECURE never comes from an LLM alone: needs CONSENSUS origin for all three roles, NONE_FOUND, SATISFIED with full verbatim rebuttal coverage, DEFENSE_UPHELD, complete evidence | D | T (fuzz I7/I8, mutants) |
| S6 | INSECURE needs a structured counterexample whose quotes and symbols exist in frozen evidence plus ATTACK_UPHELD | D | T (fuzz I7, attack A3) |
| S7 | UNPROVEN is distinct from SECURE; timeouts and errors yield UNPROVEN | D | T (fuzz I15) |
| S8 | A challenge cannot flip SECURE/INSECURE | D | T (fuzz I14, attack A8) |
| S9 | A leader cannot install a non-canonical or ungrounded role output | C + D | T (attacks A1, A2) |
| S10 | Validators agree on the categorical role verdict | C | T (stub only) |
| S11 | Threat decomposition and hypotheses are faithful and complete | C + L | T only for form; faithfulness is L |
| S12 | The correct verdict for real code | L | not claimed |
| S13 | Certificate is internally consistent and re-derivable | D + external verifier | T (tamper matrix, JS parity, fuzz I9) |
| S14 | Certificate matches the chain record | anchor via `get_certificate_hash()` | T |

## Trust boundaries

* The model is a proposer. Every field it returns passes through deterministic normalisers that drop anything not grounded in the frozen bytes.
* Validators re-run the same normalisers; agreement is on categorical results only.
* In propose-and-review, a reviewer model can block a canonical proposal only with a defect that deterministic code verifies against the claim or the evidence.
* Evidence is presented as raw fenced text with a 64-bit content-derived nonce. Forging or closing a fence would require content that contains a prefix of its own hash, which is computationally infeasible.
* Residual: propose-and-review fails open. An ungrounded or unparseable review does not block a canonical proposal (see `THREAT_MODEL.md`, "Decomposition and hypothesis quality").
* The certificate verifier does not import the contract.

## What is deliberately not done

Fuzzy or semantic consensus over free text (`reason`); truncating oversized inputs; treating a challenge as a second vote; letting the auditor override a missing counterexample or missing rebuttals.
