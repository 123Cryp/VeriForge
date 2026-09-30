"""
Independent VeriForge certificate verifier. It imports nothing from the
contract: every hash and every derivation rule is implemented again from
docs/CERTIFICATE_FORMAT.md, so a bug or a lie in the contract cannot hide
behind shared code.

    python3 tools/verify_certificate.py certificate.json
    python3 tools/verify_certificate.py certificate.json --evidence bundle.json
    python3 tools/verify_certificate.py certificate.json --onchain-hash <sha256>

Exit status 0 means every check that could run passed, 1 means at least one
failed. Checks that need data that was not supplied are reported as SKIP and
never count as passed.

What this proves: the certificate is internally consistent - every hash is
recomputed, every per-requirement result and the final result are re-derived
from the embedded role outputs by the published rules, and (with the evidence
bundle) every quote and counterexample symbol is re-checked against the
frozen bytes. What it cannot prove: that the roles' outputs were what
validators really agreed on. Compare `certificate_hash` with the value the
contract returns from get_certificate_hash(), or pass --onchain-hash.
"""
import hashlib
import json
import re
import sys

SYMBOL_RE = re.compile(r"^([A-Za-z_$][A-Za-z0-9_$.]{0,79})\s*(\([^)]*\))?$")


def canon(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def sha(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def has_symbol(text, sym):
    return re.search(r"(?<![A-Za-z0-9_$])" + re.escape(sym) + r"(?![A-Za-z0-9_$])", text) is not None


def role_output(role):
    if isinstance(role, dict) and role.get("origin") == "CONSENSUS":
        return role.get("output")
    return None


def derive(defender, attacker, auditor):
    ce = attacker is not None and attacker.get("outcome") == "COUNTEREXAMPLE"
    ruling = auditor.get("ruling") if auditor is not None else None
    if ce and ruling == "ATTACK_UPHELD":
        return "INSECURE", "ATTACK_UPHELD"
    if ce:
        return "CONFLICTING_EVIDENCE", "COUNTEREXAMPLE_NOT_UPHELD"
    if attacker is None:
        return "UNPROVEN", "ATTACKER_UNRESOLVED"
    if attacker.get("outcome") != "NONE_FOUND":
        return "UNPROVEN", "ATTACK_UNSUBSTANTIATED"
    if defender is None:
        return "UNPROVEN", "DEFENDER_UNRESOLVED"
    if defender.get("position") != "SATISFIED":
        return "UNPROVEN", "DEFENSE_NOT_ESTABLISHED"
    if auditor is None:
        return "UNPROVEN", "AUDITOR_UNRESOLVED"
    if ruling != "DEFENSE_UPHELD":
        return "UNPROVEN", "AUDITOR_DID_NOT_UPHOLD_DEFENSE"
    return "SECURE", "DEFENSE_UPHELD"


def aggregate(results, complete):
    if not results:
        return "UNPROVEN", "NO_THREATS"
    if any(r == "INSECURE" for r in results):
        return "INSECURE", ""
    if any(r == "CONFLICTING_EVIDENCE" for r in results):
        return "CONFLICTING_EVIDENCE", ""
    if any(r != "SECURE" for r in results):
        return "UNPROVEN", ""
    if not complete:
        return "UNPROVEN", "EVIDENCE_INCOMPLETE"
    return "SECURE", ""


class Report:
    def __init__(self):
        self.rows = []

    def add(self, name, status, detail=""):
        self.rows.append((name, status, detail))

    def check(self, name, condition, detail=""):
        self.add(name, "OK" if condition else "FAIL", "" if condition else detail)

    @property
    def ok(self):
        return all(s != "FAIL" for _, s, _ in self.rows)


REQUIRED = [
    "protocol", "protocol_version", "statement", "verification_id", "repository", "ref", "ref_kind",
    "base_commit", "head_commit", "security_claim", "claim_hash", "evidence", "threat_requirements",
    "threat_requirements_hash", "attack_hypotheses", "attack_hypotheses_hash", "analyses",
    "per_requirement_results", "counterexamples", "counterexamples_hash", "consensus_metadata",
    "challenges", "challenge_status", "final_result", "result_note", "frozen_at", "aggregated_at",
    "finalized_at", "certificate_hash",
]


def _verify(cert, bundle=None, onchain_hash=None):
    r = Report()
    if not isinstance(cert, dict):
        r.check("certificate is a JSON object", False)
        return r
    missing = [k for k in REQUIRED if k not in cert]
    r.check("required fields present", not missing, f"missing: {missing}")
    if missing:
        return r
    r.check("protocol", cert["protocol"] == "VeriForge" and cert["protocol_version"] == "1.0",
            f"{cert['protocol']} {cert['protocol_version']}")
    body = {k: v for k, v in cert.items() if k != "certificate_hash"}
    r.check("certificate hash", sha(canon(body)) == cert["certificate_hash"], "certificate_hash does not match its content")
    r.check("claim hash", sha(cert["security_claim"]) == cert["claim_hash"], "claim_hash mismatch")

    threats = cert["threat_requirements"]
    tids = [t["id"] for t in threats]
    r.check("threat ids unique", len(set(tids)) == len(tids))
    r.check("threat hashes", all(sha(t["text"]) == t["hash"] for t in threats), "a threat hash differs from its text")
    r.check("threat requirements hash",
            sha(canon([{"id": t["id"], "text": t["text"]} for t in threats])) == cert["threat_requirements_hash"])

    ev = cert["evidence"]
    items = ev["items"]
    iids = [i["item_id"] for i in items]
    r.check("evidence ids unique", len(set(iids)) == len(iids))
    metas = [[i["item_id"], i["source_type"], i["file_path"], i["content_hash"]] for i in items]
    root = sha(canon({"repository": cert["repository"], "base_commit": cert["base_commit"],
                      "head_commit": cert["head_commit"], "items": metas}))
    r.check("evidence root", root == ev["root"], "evidence root does not match the item list and commits")
    r.check("commits are full shas", all(re.fullmatch(r"[0-9a-f]{40}", c) for c in [cert["head_commit"]])
            and (cert["base_commit"] == "" or re.fullmatch(r"[0-9a-f]{40}", cert["base_commit"]) is not None))

    hyps = cert["attack_hypotheses"]
    plain = [{k: v for k, v in h.items() if k != "hash"} for h in hyps]
    r.check("hypothesis hashes", all(sha(canon(p)) == h["hash"] for p, h in zip(plain, hyps)))
    r.check("attack hypotheses hash", sha(canon(plain)) == cert["attack_hypotheses_hash"])
    r.check("hypotheses reference known threats and evidence",
            all(h["threat_id"] in tids and h["evidence_refs"] and set(h["evidence_refs"]) <= set(iids) for h in hyps),
            "a hypothesis references an unknown threat or evidence id")
    r.check("every threat has a hypothesis", all(any(h["threat_id"] == t for h in hyps) for t in tids))

    per = cert["per_requirement_results"]
    r.check("one result per threat, in order", [p["threat_id"] for p in per] == tids)
    roles = {n: [{"threat_id": p["threat_id"], "role": p[n]} for p in per] for n in ("defender", "attacker", "auditor")}
    for n in ("defender", "attacker", "auditor"):
        r.check(f"{n} analysis hash", sha(canon(roles[n])) == cert["analyses"][f"{n}_hash"])

    ces = cert["counterexamples"]
    r.check("counterexample hashes", all(sha(canon(c["counterexample"])) == c["hash"] for c in ces))
    r.check("counterexamples hash", sha(canon([{"id": c["id"], "hash": c["hash"]} for c in ces])) == cert["counterexamples_hash"])
    expected_ces = []
    for p in per:
        a = role_output(p["attacker"])
        if a is not None and a.get("outcome") == "COUNTEREXAMPLE":
            expected_ces.append((p["threat_id"], a["counterexample"]))
            r.check(f"counterexample id {p['threat_id']}", p["counterexample_id"] == a["counterexample"]["id"] == f"CE-{p['threat_id']}")
    r.check("counterexample list matches attacker outputs",
            [(c["threat_id"], c["counterexample"]) for c in ces] == expected_ces)
    hash_by_id = {i["item_id"]: i["content_hash"] for i in items}
    r.check("counterexample evidence hashes match the evidence",
            all(e["content_hash"] == hash_by_id.get(e["evidence_id"]) for c in ces for e in c["evidence_hashes"]))
    hyp_ids_by_threat = {t: {h["id"] for h in hyps if h["threat_id"] == t} for t in tids}
    r.check("counterexamples cite a hypothesis of their threat",
            all(c["counterexample"]["hypothesis_id"] in hyp_ids_by_threat[c["threat_id"]] for c in ces))

    derived_all = []
    for p in per:
        d, a, u = role_output(p["defender"]), role_output(p["attacker"]), role_output(p["auditor"])
        result, reason = derive(d, a, u)
        r.check(f"{p['threat_id']} derived result", p["derived_result"] == result,
                f"recorded {p['derived_result']}, rules give {result}")
        if d is not None and d["position"] == "SATISFIED":
            covered = {x["hypothesis_id"] for x in d["rebuttals"]}
            r.check(f"{p['threat_id']} defence covers every hypothesis", covered == hyp_ids_by_threat[p["threat_id"]])
        chs = [c for c in cert["challenges"] if c["threat_id"] == p["threat_id"]]
        r.check(f"{p['threat_id']} at most one challenge", len(chs) <= 1)
        final = result
        if chs:
            c = chs[0]
            re_a = c["reanalysis"]
            if c["kind"] == "VERDICT":
                new, _ = derive(role_output(re_a.get("defender")), role_output(re_a.get("attacker")), role_output(re_a.get("auditor")))
            else:
                new, _ = derive(d, a, role_output(re_a.get("auditor")))
            resolution = "CONFIRMED" if new == result else "DOWNGRADED"
            final = result if resolution == "CONFIRMED" else "CONFLICTING_EVIDENCE"
            r.check(f"{p['threat_id']} challenge re-derived",
                    c["original_result"] == result and c["original_result"] in ("SECURE", "INSECURE")
                    and c["reanalysis_result"] == new and c["resolution"] == resolution
                    and c["final_result"] == final)
            r.check(f"{p['threat_id']} challenge hash", sha(canon(c["reanalysis"])) == c["reanalysis_hash"])
        r.check(f"{p['threat_id']} result", p["result"] == final, f"recorded {p['result']}, rules give {final}")
        derived_all.append(final)
    origins = {}
    for p in per:
        for n in ("defender", "attacker", "auditor"):
            o = p[n].get("origin") if isinstance(p[n], dict) else None
            origins.setdefault(n, {})
            origins[n][o] = origins[n].get(o, 0) + 1
    meta = cert["consensus_metadata"]
    r.check("consensus metadata", meta.get("role_origins") == origins and meta.get("threat_count") == len(tids),
            "consensus_metadata does not match the embedded role records")
    r.check("challenge_status", cert["challenge_status"] == ("RESOLVED" if cert["challenges"] else "NONE"))
    final, note = aggregate(derived_all, bool(ev["complete"]))
    r.check("final result", cert["final_result"] == final and cert["result_note"] == note,
            f"recorded {cert['final_result']}/{cert['result_note']}, rules give {final}/{note}")
    if cert["final_result"] == "SECURE":
        r.check("SECURE gates", bool(ev["complete"]) and all(
            role_output(p[n]) is not None for p in per for n in ("defender", "attacker", "auditor")))

    if bundle is None:
        r.add("evidence bytes", "SKIP", "no evidence bundle supplied; content hashes not re-computed")
    else:
        content = {b["item_id"]: b["content"] for b in bundle}
        r.check("bundle covers the certificate's items", set(content) == set(iids))
        r.check("evidence content hashes", all(sha(content.get(i["item_id"], "\x00")) == i["content_hash"] for i in items),
                "an evidence item's bytes do not match its content_hash")
        r.check("evidence lengths", all(len(content.get(i["item_id"], "")) == i["length"] for i in items))
        diff_items = [content[i["item_id"]] for i in items if i["source_type"] == "diff_file" and i["item_id"] in content]
        diff = "\n".join(diff_items) + ("\n" if ev["diff_ends_with_newline"] else "")
        r.check("diff hash", sha(diff) == ev["diff_hash"], "the diff items do not re-assemble to diff_hash")
        ok_quotes = True
        for p in per:
            for name in ("defender",):
                out = role_output(p[name])
                for reb in (out or {}).get("rebuttals", []):
                    for c in reb["citations"]:
                        ok_quotes &= c["quote"] in content.get(c["evidence_id"], "\x00")
            att = role_output(p["attacker"])
            if att and att["outcome"] == "COUNTEREXAMPLE":
                ce = att["counterexample"]
                for c in ce["evidence"]:
                    ok_quotes &= c["quote"] in content.get(c["evidence_id"], "\x00")
                cited = [content.get(e, "") for e in sorted({c["evidence_id"] for c in ce["evidence"]})]
                ok_quotes &= any(has_symbol(c["quote"], ce["entry_point"]) for c in ce["evidence"])
                for s in ce["path"]:
                    ok_quotes &= any(has_symbol(t, s) for t in cited)
                    ok_quotes &= SYMBOL_RE.match(s) is not None
        r.check("every quote and counterexample symbol exists in the frozen bytes", ok_quotes,
                "a citation or symbol is not present in the evidence")

    if onchain_hash is None:
        r.add("on-chain anchor", "SKIP", "no --onchain-hash supplied; the certificate is not tied to a chain record")
    else:
        r.check("matches the on-chain certificate hash", onchain_hash.strip().lower() == cert["certificate_hash"],
                "certificate_hash differs from the value stored by the contract")
    return r


def verify(cert, bundle=None, onchain_hash=None):
    """Never raises: a structurally broken certificate is reported as FAIL."""
    try:
        return _verify(cert, bundle, onchain_hash)
    except Exception as e:
        r = Report()
        r.check("certificate structure", False, f"malformed certificate ({type(e).__name__}: {e})")
        return r


def main(argv):
    if len(argv) < 2 or argv[1] in ("-h", "--help"):
        print(__doc__)
        return 2
    cert = json.load(open(argv[1], encoding="utf-8"))
    bundle = onchain = None
    if "--evidence" in argv:
        bundle = json.load(open(argv[argv.index("--evidence") + 1], encoding="utf-8"))
    if "--onchain-hash" in argv:
        onchain = argv[argv.index("--onchain-hash") + 1]
    rep = verify(cert, bundle, onchain)
    for name, status, detail in rep.rows:
        print(f"[{status:>4}] {name}" + (f" - {detail}" if detail else ""))
    print("CERTIFICATE VALID" if rep.ok else "CERTIFICATE INVALID")
    return 0 if rep.ok else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
