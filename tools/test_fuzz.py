"""
Seeded, reproducible fuzzing of the whole protocol.

  * normalizers: random and structure-aware garbage through every LLM-output
    normaliser (idempotence, evidence grounding, no unexpected exception type)
  * diff parsing and freezing: hostile diffs through freeze_evidence
  * sessions: random interleavings of every public method with random
    callers, random clock jumps, malicious leaders, failing consensus and
    hostile model output, with global invariants I1..I17 checked after every
    transaction

    python3 tests/test_fuzz.py                       # default seed, 1000 sessions
    FUZZ_SEED=7 FUZZ_RUNS=2000 python3 tests/test_fuzz.py
"""
import copy
import json
import os
import random
import sys
import time

from harness import SUBMITTER, OTHER, CHALLENGER, vf, gl, NondetConsensusError
from runner import Suite, main
import scenario as sc
from scenario import new_chain, THREATS
import verify_certificate as vc

SEED = int(os.environ.get("FUZZ_SEED", "20260929"))
RUNS = int(os.environ.get("FUZZ_RUNS", "1000"))
suite = Suite("test_fuzz")
test = suite.test
STATS = {"txs": 0, "ok_txs": 0, "rejected_txs": 0, "sessions": 0, "checks": 0, "finalized": 0, "certificates_verified": 0,
         "results": {}, "normalizer_cases": 0, "diff_cases": 0}
CRASH = (TypeError, KeyError, AttributeError, IndexError, ZeroDivisionError, UnicodeError, RecursionError, AssertionError)
CALLERS = [SUBMITTER, OTHER, CHALLENGER]


class Violation(AssertionError):
    pass


def require(cond, what):
    STATS["checks"] += 1
    if not cond:
        raise Violation(what)


# --------------------------------------------------------------------------- random JSON

def rand_scalar(rng):
    return rng.choice([None, True, False, 0, -1, 7, 1.5, "", " ", "SECURE", "COUNTEREXAMPLE", "SATISFIED", "E3", "A1", "T3",
                       "x" * rng.choice([1, 50, 500, 5000]), "\x00\x1b", "‮ ", "withdrawTo()", "1; drop"])


def rand_json(rng, depth=0):
    r = rng.random()
    if depth > 3 or r < 0.4:
        return rand_scalar(rng)
    if r < 0.7:
        return [rand_json(rng, depth + 1) for _ in range(rng.randint(0, 4))]
    keys = ["position", "outcome", "ruling", "reason", "rebuttals", "citations", "counterexample", "hypothesis_id",
            "entry_point", "capability", "path", "missing_protection", "evidence", "evidence_id", "quote", "threats",
            "hypotheses", "threat_id", "evidence_refs", "description", "acceptable", "final_result"]
    return {rng.choice(keys): rand_json(rng, depth + 1) for _ in range(rng.randint(0, 6))}


def mutate(rng, value, depth=0):
    """Structure-aware corruption of an honest output."""
    if isinstance(value, dict) and value:
        out = dict(value)
        k = rng.choice(list(out))
        r = rng.random()
        if r < 0.15:
            del out[k]
        elif r < 0.35:
            out[k] = rand_json(rng, 2)
        elif r < 0.5:
            out[rng.choice(["final_result", "override", "extra"])] = rand_scalar(rng)
        else:
            out[k] = mutate(rng, out[k], depth + 1)
        return out
    if isinstance(value, list) and value:
        out = list(value)
        r = rng.random()
        i = rng.randrange(len(out))
        if r < 0.2:
            del out[i]
        elif r < 0.4:
            out.append(rand_json(rng, 2))
        elif r < 0.5:
            out.append(copy.deepcopy(out[i]))
        else:
            out[i] = mutate(rng, out[i], depth + 1)
        return out
    if isinstance(value, str) and value:
        r = rng.random()
        if r < 0.3:
            i = rng.randrange(len(value))
            return value[:i] + rng.choice("xX 1\né") + value[i + 1:]
        if r < 0.5:
            return value[: rng.randrange(len(value) + 1)]
        if r < 0.6:
            return value + " " + value
        return rand_scalar(rng)
    return rand_scalar(rng)


# --------------------------------------------------------------------------- normalizers

def evidence_map():
    ch = new_chain()
    vid = sc.submit_and_freeze(ch)
    return {i["item_id"]: i["content"] for i in ch.view("get_evidence_bundle", vid)}


def honest_outputs():
    ev = evidence_map()
    hyp_ids = ["A1", "A2"]
    llm = sc.ScenarioLLM()
    return ev, hyp_ids


def _norm_case(rng, ev):
    hyp_ids = ["A1", "A2", "A3"]
    real_quote = rng.choice([c for c in ev.values()])
    start = rng.randrange(max(1, len(real_quote) - 40))
    quote = real_quote[start:start + rng.randint(3, 60)]
    eid = rng.choice(list(ev))
    cite = {"evidence_id": eid, "quote": ev[eid][start:start + 30]}
    ce = {"hypothesis_id": rng.choice(hyp_ids), "entry_point": rng.choice(["withdrawTo()", "withdraw", "x y", "_send"]),
          "capability": "anyone", "path": rng.choice([["withdrawTo"], ["a", "b"], [], "no"]),
          "missing_protection": rng.choice(["auth", "", " "]), "evidence": [cite, {"evidence_id": eid, "quote": quote}]}
    defender = {"position": "SATISFIED", "reason": "r", "rebuttals": [{"hypothesis_id": h, "citations": [cite]} for h in hyp_ids]}
    attacker = {"outcome": "COUNTEREXAMPLE", "reason": "r", "counterexample": ce}
    auditor = {"ruling": rng.choice(["ATTACK_UPHELD", "DEFENSE_UPHELD", "INCONCLUSIVE"]), "reason": "r"}
    base = rng.choice([defender, attacker, auditor])
    return hyp_ids, (mutate(rng, base) if rng.random() < 0.85 else rand_json(rng))


@test("fuzz: LLM-output normalisers are total, idempotent and evidence-grounded")
def _():
    rng = random.Random(SEED)
    ev = evidence_map()
    n = max(2000, RUNS * 20)
    for _ in range(n):
        hyp_ids, raw = _norm_case(rng, ev)
        for name, fn in (("defender", lambda r: vf._norm_defender(r, ev, hyp_ids)),
                         ("attacker", lambda r: vf._norm_attacker(r, ev, hyp_ids, "T3"))):
            try:
                out = fn(raw)
            except CRASH as e:
                raise Violation(f"{name} normaliser crashed with {type(e).__name__}: {e} on {raw!r}")
            except RuntimeError:
                continue
            STATS["normalizer_cases"] += 1
            require(fn(out) == out, f"{name} normaliser is not idempotent on {raw!r}")
            require(set(out) <= {"position", "outcome", "reason", "rebuttals", "counterexample"}, "unknown output field")
            require(len(out["reason"]) <= vf.MAX_REASON_CHARS and "\x00" not in out["reason"], "reason not cleaned")
            for reb in out.get("rebuttals", []):
                require(reb["hypothesis_id"] in hyp_ids and reb["citations"], "rebuttal not grounded")
                for c in reb["citations"]:
                    require(c["evidence_id"] in ev and c["quote"] in ev[c["evidence_id"]], "defender quote not in evidence")
            if name == "defender":
                require(out["position"] != "SATISFIED" or len(out["rebuttals"]) == len(hyp_ids), "SATISFIED without full coverage")
            else:
                ce = out["counterexample"]
                require((out["outcome"] == "COUNTEREXAMPLE") == (ce is not None), "outcome and counterexample disagree")
                if ce:
                    require(ce["id"] == "CE-T3" and ce["threat_id"] == "T3", "counterexample identity not forced")
                    for c in ce["evidence"]:
                        require(c["quote"] in ev[c["evidence_id"]], "counterexample quote not in evidence")
                    cited = [ev[e] for e in {c["evidence_id"] for c in ce["evidence"]}]
                    require(any(vc.has_symbol(c["quote"], ce["entry_point"]) for c in ce["evidence"]), "entry point not quoted")
                    require(all(any(vc.has_symbol(t, s) for t in cited) for s in ce["path"]), "path symbol not in evidence")
        d = {"ruling": rng.choice(["ATTACK_UPHELD", "DEFENSE_UPHELD", "INCONCLUSIVE", "x", 3, None]), "reason": rand_scalar(rng)}
        att = rng.choice([None, {"outcome": "COUNTEREXAMPLE"}, {"outcome": "NONE_FOUND"}])
        dfd = rng.choice([None, {"position": "SATISFIED"}, {"position": "NOT_ESTABLISHED"}])
        try:
            a = vf._norm_auditor(d, dfd, att)
        except RuntimeError:
            continue
        require(a["ruling"] != "ATTACK_UPHELD" or (att and att["outcome"] == "COUNTEREXAMPLE"), "auditor upheld a missing attack")
        require(a["ruling"] != "DEFENSE_UPHELD" or (dfd and dfd["position"] == "SATISFIED"), "auditor upheld a missing defence")


@test("fuzz: threat and hypothesis canonicalisers are total and idempotent")
def _():
    rng = random.Random(SEED + 1)
    ev = evidence_map()
    order = sorted(ev)
    for _ in range(max(1500, RUNS * 10)):
        raw = rand_json(rng) if rng.random() < 0.5 else {"threats": [rng.choice(["  a  ", "a", "", 3, "b" * rng.choice([5, 300])]) for _ in range(rng.randint(0, 12))]}
        try:
            out = vf._canon_threats(raw)
        except RuntimeError:
            out = None
        except CRASH as e:
            raise Violation(f"_canon_threats crashed: {e!r} on {raw!r}")
        if out is not None:
            require(vf._canon_threats(out) == out, "threat canonicalisation not idempotent")
            require(len(out) == len(set(out)) and 0 < len(out) <= vf.MAX_THREATS, "threat list invariant")
        raw_h = rand_json(rng) if rng.random() < 0.4 else {"hypotheses": [
            {"threat_id": rng.choice(["T1", "T2", "T9", 5]), "entry_point": rng.choice(["withdraw", "withdrawTo", "nope", "", 3]),
             "capability": rng.choice(["c", "", None]), "description": "d", "evidence_refs": rng.choice([["E3"], ["E1", "E9"], [], "E3"])}
            for _ in range(rng.randint(0, 10))]}
        try:
            hs = vf._canon_hypotheses(raw_h, ["T1", "T2"], order, ev)
        except RuntimeError:
            continue
        except CRASH as e:
            raise Violation(f"_canon_hypotheses crashed: {e!r} on {raw_h!r}")
        for h in hs:
            require(h["threat_id"] in ("T1", "T2") and h["evidence_refs"] and set(h["evidence_refs"]) <= set(ev), "hypothesis not grounded")
            require(any(vc.has_symbol(ev[e], h["entry_point"]) for e in h["evidence_refs"]), "entry point absent from cited evidence")
        per = {}
        for h in hs:
            per[h["threat_id"]] = per.get(h["threat_id"], 0) + 1
        require(all(c <= vf.MAX_ATTACKS_PER_THREAT for c in per.values()), "too many hypotheses per threat")


# --------------------------------------------------------------------------- diffs

def rand_diff(rng):
    parts = []
    for _ in range(rng.randint(0, 6)):
        path = rng.choice(["a.py", "dir/b.sol", "a b/c.txt", "../etc/passwd", "x y.py", "é.py", "", "/abs", "a//b", "-", "a\\b"])
        kind = rng.random()
        header = f"diff --git a/{path} b/{path}\n"
        if kind < 0.1:
            parts.append(header + "Binary files a/x and b/x differ\n")
        elif kind < 0.2:
            parts.append(header + f"deleted file mode 100644\n--- a/{path}\n+++ /dev/null\n@@ -1 +0,0 @@\n-x\n")
        elif kind < 0.3:
            parts.append(header + f"rename from {path}\nrename to {path}2\n")
        else:
            body = "".join(rng.choice(["+", "-", " ", "@@ ", "\\ No newline", "diff --git ", "\x0c", "\x85", "\r"]) + rng.choice(["a", "b\t", "", " ", "c" * 40]) + "\n"
                           for _ in range(rng.randint(0, 6)))
            parts.append(header + f"--- a/{path}\n+++ b/{path}\n@@ -1 +1 @@\n" + body)
    text = "".join(parts)
    if rng.random() < 0.15:
        text = rng.choice(["", "<html>", "\n\n", "diff", "diff --git "]) + text
    if rng.random() < 0.05:
        text = text[: rng.randrange(len(text) + 1)]
    return text


@test("fuzz: hostile diffs either freeze into a verifiable evidence set or are rejected cleanly")
def _():
    rng = random.Random(SEED + 2)
    for _ in range(max(400, RUNS)):
        diff = rand_diff(rng)
        ch = new_chain(validators=rng.choice([1, 3]))
        sc.register_web(gl.nondet.web, diff=diff, files={})
        vid = ch.tx(SUBMITTER, "submit_security_claim", sc.REPO_URL, "PR#7", sc.CLAIM)
        try:
            ch.tx(SUBMITTER, "freeze_evidence", vid)
        except CRASH as e:
            raise Violation(f"freeze crashed with {type(e).__name__}: {e} for diff {diff[:200]!r}")
        except Exception:
            require(ch.view("get_verification", vid)["status"] == "SUBMITTED", "failed freeze changed state")
            continue
        STATS["diff_cases"] += 1
        v = ch.view("get_verification", vid)
        items = ch.view("get_evidence_bundle", vid)
        metas = [[i["item_id"], i["source_type"], i["file_path"], i["content_hash"]] for i in items]
        require(vf._sha(vf._canon({"repository": v["repository"], "base_commit": v["base_commit"], "head_commit": v["head_commit"], "items": metas})) == v["evidence_root"], "root")
        require(all(vf._sha(i["content"]) == i["content_hash"] for i in items), "item hash")
        diff_items = [i["content"] for i in items if i["source_type"] == "diff_file"]
        joined = "\n".join(diff_items) + ("\n" if diff.endswith("\n") else "")
        require(vf._sha(joined) == v["diff_hash"], "diff does not reassemble")
        require(joined == diff, "diff bytes changed by freezing")
        if any(i["source_type"] == "diff_file" and not i["file_path"] and "\n+++ /dev/null" not in i["content"] for i in items):
            require(v["evidence_complete"] is False, "an unlabeled file left evidence marked complete")


# --------------------------------------------------------------------------- sessions

class Model:
    """What the fuzzer remembers between transactions (write-once facts)."""

    def __init__(self):
        self.prev_status = {}
        self.evidence = {}
        self.threats_hash = {}
        self.hyps_hash = {}
        self.roles = {}
        self.cert = {}
        self.results_before_challenge = {}


def all_vids(ch):
    return [f"vf_{i}" for i in range(ch.c.verification_count())]


def check_invariants(ch, model):
    for vid in all_vids(ch):
        case = ch.c.get_case(vid)
        v = case["verification"]
        status = v["status"]
        # I1: only declared edges, checked against the previous observation
        prev = model.prev_status.get(vid)
        if prev is not None and prev != status:
            require(status in vf.ALLOWED_EDGES[prev], f"I1 illegal transition {prev}->{status}")
        model.prev_status[vid] = status
        require(status in vf.ALLOWED_EDGES, "I1 unknown status")
        bundle = ch.c.get_evidence_bundle(vid)
        if status not in ("SUBMITTED",) and v["evidence_root"]:
            # I2 evidence immutable, I3 root recomputes
            snap = (v["evidence_root"], v["diff_hash"], v["head_commit"], v["base_commit"], json.dumps(bundle, sort_keys=True))
            require(model.evidence.setdefault(vid, snap) == snap, "I2 frozen evidence changed")
            metas = [[i["item_id"], i["source_type"], i["file_path"], i["content_hash"]] for i in bundle]
            require(vf._sha(vf._canon({"repository": v["repository"], "base_commit": v["base_commit"], "head_commit": v["head_commit"], "items": metas})) == v["evidence_root"], "I3 root")
            require(all(vf._sha(i["content"]) == i["content_hash"] for i in bundle), "I3 content hash")
        else:
            require(not bundle, "evidence stored before freeze")
        # I4 threat and hypothesis sets immutable and hash-bound
        if v["threats_hash"]:
            require(model.threats_hash.setdefault(vid, v["threats_hash"]) == v["threats_hash"], "I4 threats changed")
            require(vf._sha(vf._canon([{"id": t["threat_id"], "text": t["text"]} for t in case["threats"]])) == v["threats_hash"], "I4 threats hash")
        if v["hypotheses_hash"]:
            require(model.hyps_hash.setdefault(vid, v["hypotheses_hash"]) == v["hypotheses_hash"], "I4 hypotheses changed")
            hashed = [{"id": h["id"], "threat_id": h["threat_id"], "entry_point": h["entry_point"], "capability": h["capability"],
                       "description": h["description"], "evidence_refs": list(h["evidence_refs"])} for h in case["hypotheses"]]
            require(vf._sha(vf._canon(hashed)) == v["hypotheses_hash"], "I4 hypotheses hash")
        items = {i["item_id"]: i["content"] for i in bundle}
        per_threat = []
        for t in case["threats"]:
            roles = {}
            for name in ("defender", "attacker", "auditor"):
                raw = t[name]
                key = (vid, t["threat_id"], name)
                if raw:
                    # I5 role outputs are write-once
                    require(model.roles.setdefault(key, raw) == raw, f"I5 {name} output rewritten")
                    roles[name] = json.loads(raw)
                else:
                    roles[name] = None
            per_threat.append((t, roles))
            res = t["result"]
            if not res:
                continue
            outs = {n: (roles[n]["output"] if roles[n] and roles[n]["origin"] == "CONSENSUS" else None) for n in roles}
            derived, _ = vc.derive(outs["defender"], outs["attacker"], outs["auditor"])
            challenged = [c for c in case["challenges"] if c["target"] == t["threat_id"] or c["target"] == "CE-" + t["threat_id"]]
            if not challenged:
                require(res == derived, f"I6 {t['threat_id']} result {res} != derived {derived}")
            else:
                c = challenged[0]
                require(c["original_result"] == derived, "I14 challenge original differs from derivation")
                require(res in (derived, "CONFLICTING_EVIDENCE"), "I14 challenge produced a new result")
                require(not (derived == "SECURE" and res == "INSECURE") and not (derived == "INSECURE" and res == "SECURE"), "I14 flipped")
                require(derived in ("SECURE", "INSECURE"), "I14 challenged an undecisive result")
            # I7 gates for decisive results
            if res == "SECURE":
                require(all(roles[n] and roles[n]["origin"] == "CONSENSUS" for n in roles), "I7 SECURE without three consensus roles")
                require(outs["attacker"]["outcome"] == "NONE_FOUND" and outs["defender"]["position"] == "SATISFIED"
                        and outs["auditor"]["ruling"] == "DEFENSE_UPHELD", "I7 SECURE role outputs")
                hyp_ids = {h["id"] for h in case["hypotheses"] if h["threat_id"] == t["threat_id"]}
                require({r["hypothesis_id"] for r in outs["defender"]["rebuttals"]} == hyp_ids and hyp_ids, "I7 defence coverage")
                for r in outs["defender"]["rebuttals"]:
                    for c in r["citations"]:
                        require(c["quote"] in items[c["evidence_id"]], "I7 defence quote absent")
            if res == "INSECURE":
                ce = outs["attacker"]["counterexample"]
                require(ce and outs["auditor"]["ruling"] == "ATTACK_UPHELD", "I7 INSECURE without upheld counterexample")
                require(ce["id"] == "CE-" + t["threat_id"] and ce["hypothesis_id"] in {h["id"] for h in case["hypotheses"] if h["threat_id"] == t["threat_id"]}, "I7 counterexample identity")
                for c in ce["evidence"]:
                    require(c["quote"] in items[c["evidence_id"]], "I7 counterexample quote absent")
                cited = [items[e] for e in {c["evidence_id"] for c in ce["evidence"]}]
                require(all(any(vc.has_symbol(x, s) for x in cited) for s in ce["path"]), "I7 counterexample path")
        # I8 final result is the aggregate
        if v["final_result"] and status in ("AGGREGATED", "FINALIZED"):
            agg, note = vc.aggregate([t["result"] for t, _ in per_threat], v["evidence_complete"])
            require((v["final_result"], v["result_note"]) == (agg, note), f"I8 final {v['final_result']} != {agg}")
            if v["final_result"] == "SECURE":
                require(v["evidence_complete"] is True, "I8 SECURE with incomplete evidence")
                require(all(t["result"] == "SECURE" for t, _ in per_threat) and per_threat, "I8 SECURE with a non-SECURE threat")
        # I11 terminated
        if status == "TERMINATED":
            require(v["final_result"] == "UNPROVEN" and v["termination_reason"], "I11 terminated without UNPROVEN")
            require(not v["certificate_hash"], "I11 certificate for a terminated verification")
        # I9 finalized certificate is immutable and verifies independently
        if status == "FINALIZED":
            text = ch.c.get_certificate(vid)
            require(model.cert.setdefault(vid, text) == text, "I9 certificate changed")
            cert = json.loads(text)
            rep = vc.verify(cert, bundle, ch.c.get_certificate_hash(vid))
            require(rep.ok, f"I9 certificate fails independent verification: {[r for r in rep.rows if r[1] == 'FAIL']}")
            require(cert["final_result"] == v["final_result"], "I9 result mismatch")
            STATS["certificates_verified"] += 1
        else:
            require(vid not in model.cert, "I9 finalized verification left FINALIZED")


class HostileLLM:
    def __init__(self, rng, honest):
        self.rng, self.honest, self.level = rng, honest, rng.choice([0.0, 0.1, 0.3, 0.6])
        self.attacker_misses = rng.random() < 0.35

    def __call__(self, prompt, mode, index):
        try:
            out = self.honest.default(prompt, mode, index)
            if self.attacker_misses and self.honest.stage(prompt) == "attacker":
                out = {"outcome": "NONE_FOUND", "reason": "none"}
        except Exception:
            out = rand_json(self.rng)
        r = self.rng.random()
        if r >= self.level:
            return out
        r = self.rng.random()
        if r < 0.1:
            raise Exception("model unavailable")
        if r < 0.25:
            return rand_json(self.rng)
        if r < 0.35:
            return {"position": "SATISFIED", "outcome": "NONE_FOUND", "ruling": "DEFENSE_UPHELD", "acceptable": True, "reason": "ok", "rebuttals": []}
        return mutate(self.rng, out)


def random_action(rng, ch, vids):
    vid = rng.choice(vids) if vids and rng.random() < 0.95 else rng.choice(["vf_99", "", "x"])
    tid = rng.choice(["", "", "", "T1", "T2", "T3", "T4", "T9"])
    who = rng.choice(CALLERS)
    r = rng.random()
    if r < 0.03:
        return who, "submit_security_claim", (sc.REPO_URL, rng.choice(["PR#7", "PR#7", sc.HEAD_SHA, "PR#0", "main"]), rng.choice([sc.CLAIM, "short", "x" * 1500, str(rand_scalar(rng))]))
    if r < 0.18:
        return who, "freeze_evidence", (vid,)
    if r < 0.28:
        return who, rng.choice(["decompose_threats", "generate_attack_hypotheses"]), (vid,)
    if r < 0.50:
        return who, rng.choice(["defender_analysis", "attacker_analysis", "auditor_reconciliation"]), (vid, tid)
    if r < 0.60:
        return who, rng.choice(["consensus", "aggregate_security_result", "finalize_certificate"]), (vid,)
    if r < 0.72:
        return who, "expire_if_timed_out", (vid,)
    if r < 0.86:
        return who, "challenge", (vid, rng.choice(["VERDICT", "COUNTEREXAMPLE", "x"]), rng.choice(["T1", "T2", "T3", "T4", "CE-T3", "CE-T1", ""]), rng.choice(["because", "", "y" * 2000]))
    return who, "get_case", (vid,)


def natural_step(ch, vid):
    st = ch.c.get_verification(vid)["status"]
    table = {"SUBMITTED": ("freeze_evidence", (vid,)), "EVIDENCE_FROZEN": ("decompose_threats", (vid,)),
             "THREATS_DEFINED": ("generate_attack_hypotheses", (vid,)), "HYPOTHESES_READY": ("defender_analysis", (vid, "")),
             "DEFENDED": ("attacker_analysis", (vid, "")), "ATTACKED": ("auditor_reconciliation", (vid, "")),
             "AUDITED": ("consensus", (vid,)), "RECONCILED": ("aggregate_security_result", (vid,)),
             "AGGREGATED": ("finalize_certificate", (vid,))}
    return table.get(st)


def run_session(seed):
    rng = random.Random(seed)
    ch = new_chain(validators=rng.choice([1, 1, 3, 5]))
    sc.register_web(gl.nondet.web)
    llm = HostileLLM(rng, ch.llm)
    gl.nondet.llm = llm
    model = Model()
    vids = []
    for _ in range(rng.randint(1, 3)):
        vids.append(ch.tx(SUBMITTER, "submit_security_claim", sc.REPO_URL, rng.choice(["PR#7", sc.HEAD_SHA]), sc.CLAIM))
    for _ in range(rng.randint(15, 70)):
        r = rng.random()
        if r < 0.45 and vids:
            vid = rng.choice(vids)
            step = natural_step(ch, vid)
            who, method, args = (rng.choice(CALLERS), *step) if step else random_action(rng, ch, vids)
            if method == "freeze_evidence":
                who = SUBMITTER
        elif r < 0.55:
            ch.advance(rng.choice([1, 60, 3600, 24 * 3600 + 1, 49 * 3600]))
            continue
        else:
            who, method, args = random_action(rng, ch, vids)
        if rng.random() < 0.06:
            gl.vm.force_leader_result(rng.choice([{"ok": True, "value": rand_json(rng)}, rand_json(rng), {"ok": False, "error": "x"}, None]))
        if rng.random() < 0.03:
            gl.eq_principle.force_fail_next()
        before = json.dumps([ch.c.get_case(v) for v in all_vids(ch)], sort_keys=True, default=str)
        STATS["txs"] += 1
        try:
            result = ch.tx(who, method, *args)
            STATS["ok_txs"] += 1
            if method == "submit_security_claim":
                vids.append(result)
        except CRASH as e:
            raise Violation(f"I13 {method}{args!r} crashed with {type(e).__name__}: {e}")
        except Exception:
            STATS["rejected_txs"] += 1
            after = json.dumps([ch.c.get_case(v) for v in all_vids(ch)], sort_keys=True, default=str)
            require(after == before, f"I12 rejected {method} changed state")
        gl.vm._forced = None
        gl.eq_principle._force_fail_once = False
        check_invariants(ch, model)
    # I15 liveness: with the clock running every verification reaches AGGREGATED, FINALIZED or TERMINATED
    gl.nondet.llm = HostileLLM(rng, ch.llm)
    for _ in range(8):
        ch.advance(24 * 3600 + 1)
        for vid in vids:
            try:
                ch.tx(OTHER, "expire_if_timed_out", vid)
            except CRASH as e:
                raise Violation(f"I13 expire crashed: {e!r}")
            except Exception:
                pass
        check_invariants(ch, model)
    ch.advance(vf.CHALLENGE_WINDOW_SECONDS + 1)
    for vid in vids:
        st = ch.c.get_verification(vid)["status"]
        require(st in ("AGGREGATED", "FINALIZED", "TERMINATED"), f"I15 {vid} stuck in {st}")
        if st == "AGGREGATED":
            ch.tx(OTHER, "finalize_certificate", vid)
            STATS["finalized"] += 1
    check_invariants(ch, model)
    for vid in vids:
        fr = ch.c.get_verification(vid)["final_result"]
        STATS["results"][fr] = STATS["results"].get(fr, 0) + 1
        require(fr in ("SECURE", "INSECURE", "UNPROVEN", "CONFLICTING_EVIDENCE"), "I16 every verification ends with a result")
    STATS["sessions"] += 1


@test("fuzz: random interleavings satisfy invariants I1-I17 after every transaction")
def _():
    started = time.time()
    for i in range(RUNS):
        try:
            run_session(SEED * 100003 + i)
        except Violation as e:
            raise Violation(f"{e} (reproduce: FUZZ_SEED={SEED} session {i}, session seed {SEED * 100003 + i})")
    require(STATS["ok_txs"] > 0 and STATS["rejected_txs"] > 0, "fuzzer must exercise both accepted and rejected transactions")
    require(STATS["certificates_verified"] > 0, "fuzzer must reach finalized certificates")
    STATS["seconds"] = round(time.time() - started, 1)


@test("fuzz: the fuzzer can find bugs (a deliberately broken derivation is detected)")
def _():
    original = vf._derive_threat_result
    vf._derive_threat_result = lambda d, a, u: ("SECURE", "BROKEN")
    try:
        for k in range(40):
            try:
                run_session(SEED + 900 + k)
            except Violation:
                return
        raise Violation("fuzzer failed to notice a contract that always answers SECURE")
    finally:
        vf._derive_threat_result = original


if __name__ == "__main__":
    code = suite.run()
    print(f"fuzz seed={SEED} sessions={STATS['sessions']} transactions={STATS['txs']} accepted={STATS['ok_txs']} "
          f"rejected={STATS['rejected_txs']} invariant_checks={STATS['checks']} certificates_verified={STATS['certificates_verified']} "
          f"normalizer_cases={STATS['normalizer_cases']} diff_cases={STATS['diff_cases']} results={STATS['results']}")
    sys.exit(code)
