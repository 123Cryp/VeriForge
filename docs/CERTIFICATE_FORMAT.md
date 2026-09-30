# Certificate format (protocol version 1.0)

The certificate is the JSON text returned by `get_certificate(verification_id)` once the verification is FINALIZED. Two independent implementations verify it: `tools/verify_certificate.py` and `frontend/assets/verify.js`. Both are written from this document, not from the contract.

## Canonical JSON and hashes

```
canon(x)  = json.dumps(x, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
sha(text) = lowercase hex SHA-256 of text encoded as UTF-8
```

Keys are sorted by Unicode code point. Non-ASCII is escaped as `\uXXXX` (UTF-16 surrogate pairs above U+FFFF). Numbers are integers only.

| Field | Definition |
|---|---|
| `certificate_hash` | `sha(canon(certificate without the certificate_hash key))` |
| `claim_hash` | `sha(security_claim)` |
| `threat_requirements[i].hash` | `sha(text)` |
| `threat_requirements_hash` | `sha(canon([{"id","text"}, ...]))` |
| `attack_hypotheses[i].hash` | `sha(canon(hypothesis without "hash"))` |
| `attack_hypotheses_hash` | `sha(canon([hypothesis without "hash", ...]))` |
| evidence item `content_hash` | `sha(item content)` |
| `evidence.root` | `sha(canon({"repository","base_commit","head_commit","items": [[item_id, source_type, file_path, content_hash], ...]}))` |
| `evidence.diff_hash` | `sha("\n".join(contents of diff_file items) + ("\n" if diff_ends_with_newline else ""))` |
| `analyses.<role>_hash` | `sha(canon([{"threat_id","role": <role record>}, ...]))` |
| counterexample `hash` | `sha(canon(counterexample))` |
| `counterexamples_hash` | `sha(canon([{"id","hash"}, ...]))` |
| challenge `reanalysis_hash` | `sha(canon(reanalysis))` |

A *role record* is `{"origin": "CONSENSUS"|"ERROR"|"TIMEOUT"|"NO_INPUT", "output": <object or null>}`. Only `CONSENSUS` records carry an output that counts.

## Top-level fields

`protocol` ("VeriForge"), `protocol_version` ("1.0"), `statement`, `verification_id`, `repository`, `ref`, `ref_kind` (`pr`|`commit`), `base_commit` (empty for a commit ref), `head_commit` (40 hex), `security_claim`, `claim_hash`, `evidence` (`root`, `diff_hash`, `diff_ends_with_newline`, `complete`, `notes`, `items[]` with `item_id`, `source_type` (`diff_file`|`head_file`), `file_path`, `content_hash`, `length`), `threat_requirements[]`, `threat_requirements_hash`, `attack_hypotheses[]`, `attack_hypotheses_hash`, `analyses`, `per_requirement_results[]`, `counterexamples[]`, `counterexamples_hash`, `consensus_metadata` (`role_origins` counts per role, `threat_count`, `rule`), `challenges[]`, `challenge_status` (`NONE`|`RESOLVED`), `final_result`, `result_note`, `frozen_at`, `aggregated_at`, `finalized_at`, `certificate_hash`.

## Derivation rules the verifier re-applies

Let `D`, `A`, `U` be the role outputs of a threat (null unless origin is CONSENSUS).

```
ce = A != null and A.outcome == COUNTEREXAMPLE
if ce and U.ruling == ATTACK_UPHELD          -> INSECURE
if ce                                        -> CONFLICTING_EVIDENCE
if A == null                                 -> UNPROVEN
if A.outcome != NONE_FOUND                   -> UNPROVEN
if D == null or D.position != SATISFIED      -> UNPROVEN
if U == null or U.ruling != DEFENSE_UPHELD   -> UNPROVEN
otherwise                                    -> SECURE
```

Challenge (at most one per threat): the original result must be SECURE or INSECURE. `VERDICT` re-derives from the re-run `defender`, `attacker`, `auditor`; `COUNTEREXAMPLE` from the recorded defender and attacker plus the re-run auditor. Equal result -> `CONFIRMED` (result unchanged); otherwise `DOWNGRADED` and the result becomes CONFLICTING_EVIDENCE.

Aggregation: no threats -> UNPROVEN/`NO_THREATS`; any INSECURE -> INSECURE; else any CONFLICTING_EVIDENCE -> CONFLICTING_EVIDENCE; else any non-SECURE -> UNPROVEN; else evidence incomplete -> UNPROVEN with note `EVIDENCE_INCOMPLETE`; else SECURE.

## What the verifier checks

Required fields; protocol; every hash above; evidence ids unique; hypotheses reference known threats and evidence; every threat has a hypothesis; counterexample ids/hashes/evidence hashes/hypothesis binding; per-threat derivation; SECURE defence covers every hypothesis; challenge re-derivation and hash; role-origin counts; `challenge_status`; final result and note; SECURE gates. With the evidence bundle it also checks every content hash and length, diff reassembly, and that every defender quote, counterexample quote, entry point and path symbol exists in the frozen bytes. With `--onchain-hash` it compares `certificate_hash` with the contract's record. Checks that lack data are reported `SKIP`, never as passed.

## Limits of verification

A certificate that is fully self-consistent but was never produced by the contract still verifies internally. Anchor it with `get_certificate_hash()`. The verifier proves consistency and evidence-grounding; it cannot prove that validators genuinely agreed.
