# Live run on GenLayer Studio

A complete protocol run against a real public pull request, executed on GenLayer Studio on 2026-09-29/30 (Asia/Tehran time 2026-09-30).

| Item | Value |
|---|---|
| Contract | `0x7326c1C4E45dE19FBBA63D905d1071d94D4952a9` (short-window build, see `docs/DEPLOYMENT.md`) |
| Repository / ref | `https://github.com/123Cryp/vault-test`, `PR#1` |
| Claim | This PR fixes unauthorized withdrawal: only authorized users can withdraw funds from the Vault. |
| Head commit | `ac8491a126cbc782f348d8fe101a38ede9d7766d` |
| Evidence root | `ca74dd06a59b29fe17ab04d2aed7becf1599cb753e66bd4ff8a07d1bc603fdad` |
| Certificate hash (from `get_certificate_hash`) | `d68708db96516afe5821fa61c542afe9db944519f6c14527d0191bc6dce30d6c` |
| Final result | `INSECURE` |

The PR guards `withdraw()` with `onlyAuthorized` but leaves `withdrawTo()` unguarded, so the claim does not hold.

| Requirement | Result |
|---|---|
| T1 `withdraw` | `CONFLICTING_EVIDENCE` (`COUNTEREXAMPLE_NOT_UPHELD`): the attacker attacked `withdrawTo`, outside this requirement, and the auditor ruled INCONCLUSIVE |
| T2 `withdrawTo` | `INSECURE` (`ATTACK_UPHELD`), challenged once, `CONFIRMED` |
| T3 every withdrawal entry point | `INSECURE` (`ATTACK_UPHELD`) |

## Verify it yourself

```
python3 tools/verify_certificate.py examples/live/certificate.json \
  --evidence examples/live/evidence_bundle.json \
  --onchain-hash d68708db96516afe5821fa61c542afe9db944519f6c14527d0191bc6dce30d6c
```

Expected: `CERTIFICATE VALID` (47 checks). The browser verifier (`frontend/index.html`, Verify tab) gives the same result with the same three inputs, and both reject a certificate whose `final_result` was edited or an on-chain hash that does not match.

`certificate.json` is the exact text returned by `get_certificate("vf_0")`. `evidence_bundle.json` is `get_evidence_bundle("vf_0")`; its content hashes match the certificate. Note that this run used a contract with a 10-minute challenge window so the whole flow could be executed in one session; the production build uses 48 hours.
