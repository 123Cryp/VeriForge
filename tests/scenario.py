"""
The demo scenario used by the tests, the fuzzer, the security demo and the
recorded frontend replay: a pull request against `example/vault` that adds an
`onlyAuthorized` guard to withdraw() but leaves withdrawTo() unguarded.

The repository content is real (tests/fixtures/vault_pr). The LLM is a
scripted stand-in (`ScenarioLLM`): it plays the four prompt types with
fixed, recorded-style answers, and nothing about the final verdict is stored
anywhere. The verdict is whatever the contract derives from those answers
after checking every quote against the frozen evidence.
"""
import difflib
import hashlib
import json
import os
import re

from harness import ROOT, SUBMITTER, OTHER, CHALLENGER, vf, gl, Chain  # noqa: F401

FIX = os.path.join(ROOT, "tests", "fixtures", "vault_pr")
REPO_URL = "https://github.com/example/vault"
BASE_SHA = "9f1c3a5e7b2d4c6a8e0f1a3b5c7d9e1f2a4b6c8d"
HEAD_SHA = "c4a8e2f6b0d3971a5e8c2f6b0d4a7913e5c8b2f1"
PR_NUMBER = 7
CLAIM = "This PR fixes unauthorized withdrawal: only authorized users can withdraw funds from the Vault."

THREATS = [
    "Every successful withdrawal through withdraw() is restricted to callers that the vault has authorized.",
    "A withdrawal can never transfer more than the caller's recorded balance.",
    "No other public or external entry point lets a caller without authorization withdraw funds.",
    "The change includes a regression test that fails if an unauthorized caller can call withdraw().",
]


def read(rel):
    with open(os.path.join(FIX, rel), encoding="utf-8") as f:
        return f.read()


def _blob(text):
    data = text.encode("utf-8")
    return hashlib.sha1(b"blob %d\0" % len(data) + data).hexdigest()[:7]


def _head_dir(variant):
    return {"vulnerable": "head", "fixed": "head_fixed"}[variant]


def build_diff(variant="vulnerable"):
    files = [("contracts/Vault.sol", read("base/contracts/Vault.sol"), read(_head_dir(variant) + "/contracts/Vault.sol")),
             ("test/Vault.t.sol", None, read("head/test/Vault.t.sol"))]
    out = []
    for path, old, new in files:
        out.append(f"diff --git a/{path} b/{path}")
        if old is None:
            out.append("new file mode 100644")
            out.append(f"index 0000000..{_blob(new)}")
            frm, to = "/dev/null", f"b/{path}"
            old_lines = []
        else:
            out.append(f"index {_blob(old)}..{_blob(new)} 100644")
            frm, to = f"a/{path}", f"b/{path}"
            old_lines = old.split("\n")[:-1]
        out.append(f"--- {frm}")
        out.append(f"+++ {to}")
        body = list(difflib.unified_diff(old_lines, new.split("\n")[:-1], lineterm="", n=3))
        out.extend(body[2:])
    return "\n".join(out) + "\n"


def register_web(web, head_sha=HEAD_SHA, base_sha=BASE_SHA, diff=None, files=None, variant="vulnerable"):
    diff = build_diff(variant) if diff is None else diff
    web.pages[f"https://api.github.com/repos/example/vault/pulls/{PR_NUMBER}"] = json.dumps(
        {"number": PR_NUMBER, "base": {"sha": base_sha}, "head": {"sha": head_sha}}
    )
    web.pages[f"https://github.com/example/vault/compare/{base_sha}...{head_sha}.diff"] = diff
    web.pages[f"https://github.com/example/vault/commit/{head_sha}.diff"] = diff
    for path, rel in (files or {"contracts/Vault.sol": _head_dir(variant) + "/contracts/Vault.sol",
                                "test/Vault.t.sol": "head/test/Vault.t.sol"}).items():
        web.pages[f"https://raw.githubusercontent.com/example/vault/{head_sha}/{path}"] = read(rel)


def _between(text, start, end):
    i = text.index(start) + len(start)
    return text[i:text.index(end, i)]


_ITEM_RE = re.compile(r"<<<ITEM ([0-9a-f]{16}) (\{\"evidence_id\".*?\})>>>\n(.*?)\n<<<END_ITEM \1>>>", re.S)


def _evidence_of(prompt):
    block = prompt[prompt.index("<<<EVIDENCE_START>>>"):]
    out = []
    for m in _ITEM_RE.finditer(block):
        meta = json.loads(m.group(2))
        meta["content"] = m.group(3)
        out.append(meta)
    return out


def _ids(ev_list, path):
    return [e["evidence_id"] for e in ev_list if e["file_path"] == path]


def _find(ev_list, path, needle):
    for e in ev_list:
        if e["file_path"] == path and e["source_type"] == "head_file" and needle in e["content"]:
            return {"evidence_id": e["evidence_id"], "quote": needle}
    raise AssertionError(f"scenario quote not present in evidence: {needle!r}")


VAULT = "contracts/Vault.sol"
FIXED_SIGNATURE = "function withdrawTo(address payable to, uint256 amount) external onlyAuthorized {"
TEST = "test/Vault.t.sol"

HYPOTHESES = {
    0: [("withdraw", "an account that is not authorized", "Call withdraw() directly without being authorized", VAULT),
        ("authorize", "an account that is not the owner", "Grant itself authorization through authorize()", VAULT)],
    1: [("withdraw", "an authorized account with a small balance", "Withdraw more than the recorded balance through withdraw()", VAULT),
        ("_send", "any account with a balance", "Underflow the balance inside the shared _send helper", VAULT)],
    2: [("withdrawTo", "an account that is not authorized", "Reach the transfer through the separate withdrawTo() entry point", VAULT),
        ("_send", "an account that is not authorized", "Reach _send from another public function", VAULT)],
    3: [("testWithdrawRejectsUnauthorizedCaller", "a maintainer who removes the guard", "The test never reaches the unauthorized path", TEST),
        ("withdraw", "a maintainer who removes the guard", "Remove the guard without any test failing", TEST)],
}

REBUTTALS = {
    0: [(VAULT, "function withdraw(uint256 amount) external onlyAuthorized {"),
        (VAULT, 'require(msg.sender == owner, "not owner");')],
    1: [(VAULT, 'require(balances[msg.sender] >= amount, "insufficient balance");'),
        (VAULT, "balances[msg.sender] -= amount;")],
    2: [(VAULT, "function withdraw(uint256 amount) external onlyAuthorized {"),
        (VAULT, 'require(balances[msg.sender] >= amount, "insufficient balance");')],
    3: [(TEST, 'vm.expectRevert("unauthorized");'),
        (TEST, "vault.withdraw(1 ether);")],
}


class ScenarioLLM:
    """Scripted stand-in for the model. `hooks` are (predicate, responder)
    pairs checked newest first, so a test can override one stage for one
    role (leader or validator) and leave the rest honest."""

    def __init__(self):
        self.hooks = []
        self.calls = []

    def hook(self, predicate, responder):
        self.hooks.append((predicate, responder))

    def clear_hooks(self):
        self.hooks.clear()

    def __call__(self, prompt, mode, index):
        self.calls.append((self.stage(prompt), mode, index))
        for predicate, responder in reversed(self.hooks):
            if predicate(prompt, mode, index):
                return responder(prompt, mode, index)
        return self.default(prompt, mode, index)

    @staticmethod
    def stage(prompt):
        if "Decompose the security claim" in prompt:
            return "decompose"
        if "reviewing a proposed decomposition" in prompt:
            return "decompose_review"
        if "propose up to" in prompt:
            return "hypotheses"
        if "reviewing proposed attack hypotheses" in prompt:
            return "hypotheses_review"
        for role in ("DEFENDER", "ATTACKER", "AUDITOR"):
            if f"ROLE: {role}." in prompt:
                return role.lower()
        return "unknown"

    def default(self, prompt, mode, index):
        stage = self.stage(prompt)
        if stage == "decompose":
            return {"threats": list(THREATS)}
        if stage in ("decompose_review", "hypotheses_review"):
            return {"acceptable": True}
        ev_list = _evidence_of(prompt)
        if stage == "hypotheses":
            threats = json.loads(_between(prompt, "Threat requirements: ", "\n\n<<<EVIDENCE_START>>>"))
            out = []
            for i, t in enumerate(threats):
                for entry, cap, desc, path in HYPOTHESES[i]:
                    out.append({"threat_id": t["id"], "entry_point": entry, "capability": cap,
                                "description": desc, "evidence_refs": _ids(ev_list, path)})
            return {"hypotheses": out}
        if stage in ("defender", "attacker"):
            body = _between(prompt, "<<<REQUIREMENT_START>>>\n", "\n<<<REQUIREMENT_END>>>")
            hyps = json.loads(_between(prompt, "Attack hypotheses: ", "\n\n<<<EVIDENCE_START>>>"))
            text = json.loads(body)
            text = text["text"] if isinstance(text, dict) else text
            idx = THREATS.index(text)
            fixed = any(FIXED_SIGNATURE in e["content"] for e in ev_list)
            if stage == "defender":
                quotes = [list(q) for q in REBUTTALS[idx]]
                if idx == 2 and fixed:
                    quotes[0] = [VAULT, FIXED_SIGNATURE]
                return {"position": "SATISFIED", "reason": "each listed attack fails on the quoted code",
                        "rebuttals": [{"hypothesis_id": h["id"], "citations": [_find(ev_list, *quotes[k])]}
                                      for k, h in enumerate(hyps)]}
            if idx == 2 and not fixed:
                return {"outcome": "COUNTEREXAMPLE",
                        "reason": "withdrawTo() reaches _send() with no authorization check",
                        "counterexample": {
                            "hypothesis_id": hyps[0]["id"], "entry_point": "withdrawTo()",
                            "capability": "an account that is not authorized, holding a deposited balance",
                            "path": ["withdrawTo()", "_send()"],
                            "missing_protection": "authorization check (onlyAuthorized) on withdrawTo()",
                            "evidence": [
                                _find(ev_list, VAULT, "function withdrawTo(address payable to, uint256 amount) external {"),
                                _find(ev_list, VAULT, "_send(to, amount);")]}}
            return {"outcome": "NONE_FOUND", "reason": "no valid counterexample exists in the evidence"}
        if stage == "auditor":
            defender = json.loads(_between(prompt, "Defender analysis: ", "\nAttacker analysis: "))
            attacker = json.loads(_between(prompt, "\nAttacker analysis: ", "\n\n<<<EVIDENCE_START>>>"))
            if attacker and attacker.get("outcome") == "COUNTEREXAMPLE":
                return {"ruling": "ATTACK_UPHELD", "reason": "the quoted code has no authorization on withdrawTo()"}
            if defender and defender.get("position") == "SATISFIED":
                return {"ruling": "DEFENSE_UPHELD", "reason": "the defence is supported by the quoted code"}
            return {"ruling": "INCONCLUSIVE", "reason": "neither side is established"}
        raise AssertionError(f"scenario received an unknown prompt: {prompt[:80]!r}")


def new_chain(validators=1):
    ch = Chain()
    register_web(gl.nondet.web)
    llm = ScenarioLLM()
    gl.nondet.llm = llm
    gl.vm.validators = validators
    ch.llm = llm
    return ch


def submit_and_freeze(ch, ref=f"PR#{PR_NUMBER}", claim=CLAIM):
    vid = ch.tx(SUBMITTER, "submit_security_claim", REPO_URL, ref, claim)
    ch.tx(SUBMITTER, "freeze_evidence", vid)
    return vid


def run_to(ch, vid, target):
    """Drives the real contract methods up to (and including) `target`."""
    steps = [
        ("decompose_threats", (vid,), "THREATS_DEFINED"),
        ("generate_attack_hypotheses", (vid,), "HYPOTHESES_READY"),
        ("defender_analysis", (vid, ""), "DEFENDED"),
        ("attacker_analysis", (vid, ""), "ATTACKED"),
        ("auditor_reconciliation", (vid, ""), "AUDITED"),
        ("consensus", (vid,), "RECONCILED"),
        ("aggregate_security_result", (vid,), "AGGREGATED"),
    ]
    order = ["SUBMITTED", "EVIDENCE_FROZEN"] + [st for _, _, st in steps]
    for method, args, status in steps:
        cur = ch.view("get_verification", vid)["status"]
        if cur == target or cur == "TERMINATED":
            return
        if order.index(cur) >= order.index(status):
            continue
        ch.tx(OTHER, method, *args)
    assert ch.view("get_verification", vid)["status"] == target, target


def full_run(ch, finalize=True):
    vid = submit_and_freeze(ch)
    run_to(ch, vid, "AGGREGATED")
    if finalize:
        ch.advance(vf.CHALLENGE_WINDOW_SECONDS + 1)
        ch.tx(OTHER, "finalize_certificate", vid)
    return vid


def when(stage=None, mode=None, index=None, contains=None):
    def predicate(prompt, m, i):
        return ((stage is None or ScenarioLLM.stage(prompt) == stage)
                and (mode is None or m == mode)
                and (index is None or i == index)
                and (contains is None or contains in prompt))
    return predicate


def answer(value):
    return lambda prompt, mode, index: value


def make_all_secure(llm):
    """An attacker that misses the withdrawTo() path: every threat comes out
    SECURE. Used to test the gates that must hold even when the LLMs are
    wrong (evidence completeness, timeouts, challenge direction)."""
    llm.hook(when("attacker"), answer({"outcome": "NONE_FOUND", "reason": "no valid counterexample found"}))


def stage_by_stage(ch, vid, fn):
    """Calls fn(method, args) for each analysis stage in order (helper for
    tests that need to intervene between stages)."""
    for method, args in (("decompose_threats", (vid,)), ("generate_attack_hypotheses", (vid,)),
                         ("defender_analysis", (vid, "")), ("attacker_analysis", (vid, "")),
                         ("auditor_reconciliation", (vid, "")), ("consensus", (vid,)),
                         ("aggregate_security_result", (vid,))):
        fn(method, args)
