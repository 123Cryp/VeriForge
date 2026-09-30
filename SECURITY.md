# Security policy

> A SECURE result means that the defined security claim survived the protocol's evidence and adversarial verification process. It does not prove that the software contains no vulnerabilities.

## Scope

VeriForge decides whether one stated claim about one immutable change survives adversarial analysis of frozen evidence. It is not a scanner, an audit, or a proof of correctness.

## Status

The contract has been tested only against a local GenLayer stub, by unit, adversarial, fuzz and mutation tests, and its deploy artifact has been built and tested. It has **not** been deployed or exercised on live GenLayer. Do not rely on a SECURE result for anything of value until the checklist in `docs/DEPLOYMENT.md` has been completed and recorded.

## Reporting

Report vulnerabilities in the contract, verifier or frontend privately to the maintainers of this repository (open a private security advisory on the hosting platform). Include a reproduction against `tests/genlayer_stub.py` if possible.

## Where the guarantees are documented

`docs/THREAT_MODEL.md`, `docs/SECURITY_MODEL.md`, `docs/FINAL_SECURITY_REVIEW.md` (which distinguishes deterministic, consensus, LLM-dependent, locally tested and live-verified properties).
