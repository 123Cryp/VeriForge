"""
Mutation testing: each mutant is the real contract with ONE security-relevant
line broken. The deterministic suites must fail on every mutant ("killed").
A surviving mutant means a security rule is not actually pinned by a test.

    python3 tests/mutation_test.py            # all mutants
    python3 tests/mutation_test.py -k derive  # only mutants whose id contains "derive"

The suites run in subprocesses against a mutated copy placed in a temporary
directory (VF_CONTRACT_DIR); the repository files are never modified.
"""
import os
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
SRC = os.path.join(ROOT, "contracts", "veriforge.py")
SUITES = ["test_veriforge.py", "test_adversarial.py", "test_certificate.py", "test_fuzz.py"]

# One mutant was removed as an equivalent mutant: dropping the `auditor is None`
# guard in _derive_threat_result changes nothing observable, because the next
# statement (`ruling != RULE_DEFENSE`, with ruling None) returns the same
# UNPROVEN result.
# (id, description, old text (must occur exactly once), new text)
MUTANTS = [
    ("derive-insecure-without-auditor", "INSECURE without the auditor upholding the attack",
     "    if ce and ruling == RULE_ATTACK:\n", "    if ce:\n"),
    ("derive-secure-without-auditor", "SECURE without the auditor upholding the defence",
     "    if ruling != RULE_DEFENSE:\n", "    if False:\n"),
    ("derive-secure-without-defender", "SECURE although the defender did not establish the defence",
     '    if defender.get("position") != POS_SATISFIED:\n', "    if False:\n"),
    ("derive-secure-unsubstantiated", "SECURE although the attack was only unsubstantiated",
     '    if attacker.get("outcome") != OUT_NONE:\n', "    if False:\n"),
    ("derive-secure-missing-defender", "SECURE with no defender output",
     "    if defender is None:\n", "    if False:\n"),
    ("aggregate-insecure-ignored", "INSECURE threat ignored in the aggregate",
     "    if any(r == R_INSECURE for r in results):\n", "    if False:\n"),
    ("aggregate-incomplete-evidence", "SECURE allowed with incomplete evidence",
     "    if not evidence_complete:\n", "    if False:\n"),
    ("aggregate-final-ignores-flag", "final result ignores the evidence-complete flag",
     "_aggregate_results(results, int(v.evidence_complete) == 1)", "_aggregate_results(results, True)"),
    ("freeze-complete-always", "evidence always marked complete",
     'complete = (plan["binary"] == 0 and not plan["omitted"] and not unavailable)', "complete = True"),
    ("citation-quote-not-checked", "quotes need not occur in the evidence",
     "and MIN_QUOTE_CHARS <= len(q) <= MAX_QUOTE_CHARS and q in ev[eid]):",
     "and MIN_QUOTE_CHARS <= len(q) <= MAX_QUOTE_CHARS):"),
    ("citation-min-length", "one-character quotes accepted",
     "MIN_QUOTE_CHARS = 6", "MIN_QUOTE_CHARS = 0"),
    ("defender-coverage", "SATISFIED without covering every hypothesis",
     "    if position == POS_SATISFIED and len(rebuttals) != len(hyp_ids):\n", "    if False:\n"),
    ("auditor-attack-coercion", "auditor may uphold an attack that does not exist",
     '    if ruling == RULE_ATTACK and not (attacker is not None and attacker.get("outcome") == OUT_CE):\n',
     "    if False:\n"),
    ("auditor-defense-coercion", "auditor may uphold a defence that was not established",
     '    if ruling == RULE_DEFENSE and not (defender is not None and defender.get("position") == POS_SATISFIED):\n',
     "    if False:\n"),
    ("ce-entry-point-not-quoted", "counterexample entry point need not be quoted",
     '    if not any(_has_symbol(c["quote"], entry) for c in cites):\n        return None\n', ""),
    ("ce-path-not-in-evidence", "counterexample path symbols need not be in the evidence",
     "        if not any(_has_symbol(t, s) for t in cited_text):\n            return None\n", "        pass\n"),
    ("ce-hypothesis-unbound", "counterexample need not cite a hypothesis of its threat",
     '    if not isinstance(hid, str) or hid not in hyp_ids:\n        return None\n', ""),
    ("ce-id-from-model", "counterexample id taken from the model",
     'return {\n        "id": f"CE-{threat_id}",', 'return {\n        "id": str(raw.get("id", "x")),'),
    ("hypothesis-entry-point-unchecked", "hypotheses may name entry points absent from the evidence",
     "        if not any(_has_symbol(ev[r], entry) for r in refs):\n", "        if False:\n"),
    ("symbol-boundary", "symbol match without identifier boundaries",
     'return re.search(r"(?<![A-Za-z0-9_$])" + re.escape(sym) + r"(?![A-Za-z0-9_$])", text) is not None',
     "return sym in text"),
    ("control-chars-kept", "control characters kept in model text",
     "if (ord(c) < 32 or ord(c) == 127)", "if False"),
    ("consensus-leader-not-canonical", "validators accept a leader value that is not canonical",
     "            if normalize(value) != value:\n                return False\n", ""),
    ("consensus-agree-key", "validators accept any categorical result",
     "            return verdict == mine_norm or (bool(mine_raw) and verdict == mine_raw)", "            return True"),
    ("consensus-review", "decomposition review always accepts",
     "            return not rejection_grounded(review, value)", "            return True"),
    ("review-ungrounded-veto", "any rejection vetoes, grounded or not",
     "    if defect == \"UNCOVERED\":\n        return _quoted_in", "    return True\n    if defect == \"UNCOVERED\":\n        return _quoted_in"),
    ("review-quote-not-in-claim", "a review quote need not occur in the quoted text",
     "        if len(q) >= MIN_QUOTE_CHARS and q in target:", "        if len(q) >= MIN_QUOTE_CHARS:"),
    ("review-bad-index-unquoted", "BAD_REQUIREMENT vetoes without quoting the requirement",
     "        return _quoted_in(review.get(\"requirement_quote\"), threats[int(str(index).strip()) - 1])", "        return True"),
    ("review-missed-entry-used", "a missed entry point that is already used still vetoes",
     "        if entry is None or entry in [h.get(\"entry_point\") for h in hyps]:", "        if entry is None:"),
    ("review-missed-entry-absent", "a missed entry point need not exist in the evidence",
     "        return any(re.search(pattern, t) is not None for t in head_texts)", "        return True"),
    ("review-missed-entry-any-call", "a missed entry point need only be called, not defined",
     "(?:function|def|fn|func)\\s+\" + re.escape(entry)", "\" + re.escape(entry)"),
    ("role-raw-any", "any raw verdict agrees",
     "            return verdict == mine_norm or (bool(mine_raw) and verdict == mine_raw)", "            return verdict == mine_norm or bool(mine_raw)"),
    ("evidence-nonce-fixed", "evidence fences use a fixed marker",
     "    nonce = _sha(_canon(ev_list))[:16]", "    nonce = \"0000000000000000\""),
    ("consensus-failure-form", "any leader failure accepted",
     'and len(leader["error"]) <= MAX_REASON_CHARS)', "and True)"),
    ("state-edges", "state transitions not checked",
     "        if new_status not in ALLOWED_EDGES.get(v.status, set()):\n", "        if False:\n"),
    ("deadline-not-enforced", "stage work allowed after the deadline",
     "        if v.stage_deadline and _is_past(v.stage_deadline):\n", "        if False:\n"),
    ("freeze-any-caller", "anyone can freeze evidence",
     "        if str(gl.message.sender_address).lower() != str(v.submitter).lower():\n", "        if False:\n"),
    ("threat-ownership", "threat_id need not belong to the verification",
     "            if threat_id not in tids:\n", "            if False:\n"),
    ("role-rewrite", "a role output can be recorded twice",
     "            if getattr(self.threats[self._tk(v.verification_id, threat_id)], field):\n", "            if False:\n"),
    ("timeout-no-terminate", "early timeouts do not terminate",
     '            self._terminate(v, "TIMEOUT_" + s)', "            pass"),
    ("finalize-window", "certificate can be finalized inside the challenge window",
     "        if not _is_past(v.challenge_deadline):\n            raise Exception(\"challenge window is still open\")\n", ""),
    ("challenge-window", "challenges accepted after the window",
     "        if _is_past(v.challenge_deadline):\n", "        if False:\n"),
    ("challenge-once", "unlimited challenges per threat",
     "        if int(th.challenge_count) >= 1:\n", "        if False:\n"),
    ("challenge-always-confirms", "a non-reproduced challenge still confirms",
     "        if new_result == original:\n", "        if True:\n"),
    ("challenge-flips", "a challenge can flip the result to the re-analysis",
     "resolution, final = CH_DOWNGRADED, R_CONFLICTING", "resolution, final = CH_DOWNGRADED, new_result"),
    ("challenge-undecisive", "undecisive results can be challenged",
     "        if original not in (R_SECURE, R_INSECURE):\n", "        if False:\n"),
    ("aggregate-recheck", "stored results not re-derived before aggregation",
     "            if derived != str(th.result):\n", "            if False:\n"),
    ("canon-unsorted", "canonical JSON without sorted keys",
     "sort_keys=True, separators=(\",\", \":\"), ensure_ascii=True)\n\n\ndef _sha", "sort_keys=False, separators=(\",\", \":\"), ensure_ascii=True)\n\n\ndef _sha"),
    ("evidence-root-no-head", "evidence root omits the head commit",
     '"head_commit": head, "items": metas', '"items": metas'),
    ("diff-split-unicode", "diff split on unicode line boundaries",
     '    lines = diff_text.split("\\n")\n    ends_newline = False', "    lines = diff_text.splitlines()\n    ends_newline = False"),
    ("economics-on", "economic hooks enabled by default",
     "ECONOMICS_ENABLED = False", "ECONOMICS_ENABLED = True"),
]


def run_suite(suite, env, timeout=900):
    return subprocess.run([sys.executable, os.path.join(HERE, suite)], env=env, capture_output=True, text=True, timeout=timeout)


def main():
    only = sys.argv[sys.argv.index("-k") + 1] if "-k" in sys.argv else None
    src = open(SRC, encoding="utf-8").read()
    # sanity: the unmutated copy must pass, otherwise "killed" would be meaningless
    results = []
    started = time.time()
    with tempfile.TemporaryDirectory() as tmp:
        env = dict(os.environ, VF_CONTRACT_DIR=tmp, VF_MODULE="veriforge", FUZZ_RUNS=os.environ.get("MUTATION_FUZZ_RUNS", "60"))
        open(os.path.join(tmp, "veriforge.py"), "w", encoding="utf-8").write(src)
        for suite in SUITES:
            base = run_suite(suite, env)
            if base.returncode != 0:
                print(f"BASELINE FAILED in {suite}:\n{base.stdout[-1500:]}{base.stderr[-500:]}")
                sys.exit(2)
        print(f"baseline: all {len(SUITES)} suites pass on the unmutated copy")
        for mid, desc, old, new in MUTANTS:
            if only and only not in mid:
                continue
            count = src.count(old)
            if count != 1:
                print(f"INVALID MUTANT {mid}: pattern occurs {count} times")
                sys.exit(2)
            open(os.path.join(tmp, "veriforge.py"), "w", encoding="utf-8").write(src.replace(old, new, 1))
            killed_by = None
            for suite in SUITES:
                try:
                    out = run_suite(suite, env)
                    dead = out.returncode != 0
                except subprocess.TimeoutExpired:
                    dead = True
                if dead:
                    killed_by = suite
                    break
            results.append((mid, desc, killed_by))
            print(f"{'KILLED  ' if killed_by else 'SURVIVED'} {mid:38s} {('by ' + killed_by) if killed_by else desc}", flush=True)
    killed = sum(1 for r in results if r[2])
    print(f"\nmutants: {len(results)}  killed: {killed}  survived: {len(results) - killed}  ({time.time() - started:.0f}s)")
    survivors = [r for r in results if not r[2]]
    for mid, desc, _ in survivors:
        print(f"SURVIVOR {mid}: {desc}")
    sys.exit(1 if survivors else 0)


if __name__ == "__main__":
    main()
