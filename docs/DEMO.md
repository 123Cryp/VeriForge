# Demo

## What the demo is

A pull request against a small `Vault` contract adds an `onlyAuthorized` modifier to `withdraw()` but leaves `withdrawTo()` unguarded. The claim: *"This PR fixes unauthorized withdrawal: only authorized users can withdraw funds from the Vault."* Fixtures live in `tests/fixtures/vault_pr/`; the exact diffs are `pr_vulnerable.diff` and `pr_fixed.diff`.

The protocol decomposes the claim into four requirements (T1 `withdraw()` restricted, T2 balance bound, T3 **no other entry point lets an unauthorized caller withdraw**, T4 regression test exists). The attacker's counterexample for T3 names `withdrawTo()`, cites the unguarded signature and the `_send(to, amount);` call in the frozen head file, and the contract checks both quotes against the bytes. Result: **INSECURE**, with certificate. On the fixed PR every requirement is SECURE.

## Honest scope

The models are scripted (`tests/scenario.py`), and the scripted answers read the frozen evidence: the same script gives INSECURE on the vulnerable evidence and SECURE on the fixed evidence. The verdicts are derived by the real contract code after it checks every quote. This is a local recording, **not** a live GenLayer run and not a demonstration that live LLMs find the bug.

## Run it

```
python3 tools/run_demo.py            # regenerates frontend/assets/demo_run.json/.js
python3 tools/security_demo.py       # runs the nine attacks
python3 -m http.server -d frontend 8000     # then open http://localhost:8000/
```

`frontend/index.html` also works from `file://`.

Tabs: **Demo run** (step through the eleven transactions), **Verify certificate** (in-browser verifier with tamper buttons), **Security demo** (nine attacks), **Live (GenLayer)** (needs a deployed address), **About**.

## The nine attacks

A1 forged counterexample from a malicious leader; A2 leader hides the real counterexample; A3 all nodes hallucinate the same exploit; A4 prompt injection with obedient models; A5 evidence swapped after freeze; A6 replay, skipping and wrong caller; A7 stalling; A8 challenge used to flip SECURE; A9 diff header spoofing. Each reports the layer that stopped it.
