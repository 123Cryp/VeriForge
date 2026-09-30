/*
 * VeriForge certificate verifier (browser and Node). Independent of the
 * contract: it re-implements canonical JSON, sha256, the per-requirement
 * derivation and the aggregation rule from docs/CERTIFICATE_FORMAT.md, and
 * mirrors tools/verify_certificate.py check for check.
 */
(function (root) {
  "use strict";

  var K = new Uint32Array([
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2]);

  function utf8(str) {
    if (typeof TextEncoder !== "undefined") return new TextEncoder().encode(str);
    var out = [], i, c;
    for (i = 0; i < str.length; i++) {
      c = str.codePointAt(i);
      if (c > 0xffff) i++;
      if (c < 0x80) out.push(c);
      else if (c < 0x800) out.push(0xc0 | (c >> 6), 0x80 | (c & 63));
      else if (c < 0x10000) out.push(0xe0 | (c >> 12), 0x80 | ((c >> 6) & 63), 0x80 | (c & 63));
      else out.push(0xf0 | (c >> 18), 0x80 | ((c >> 12) & 63), 0x80 | ((c >> 6) & 63), 0x80 | (c & 63));
    }
    return Uint8Array.from(out);
  }

  function sha256(text) {
    var bytes = utf8(text), l = bytes.length, total = ((l + 9 + 63) >> 6) << 6;
    var buf = new Uint8Array(total);
    buf.set(bytes);
    buf[l] = 0x80;
    var bits = l * 8, dv = new DataView(buf.buffer);
    dv.setUint32(total - 8, Math.floor(bits / 4294967296));
    dv.setUint32(total - 4, bits >>> 0);
    var h = new Uint32Array([0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19]);
    var w = new Uint32Array(64), o, i, a, b, c, d, e, f, g, hh, s0, s1, t1, t2;
    for (o = 0; o < total; o += 64) {
      for (i = 0; i < 16; i++) w[i] = dv.getUint32(o + i * 4);
      for (i = 16; i < 64; i++) {
        s0 = ((w[i - 15] >>> 7) | (w[i - 15] << 25)) ^ ((w[i - 15] >>> 18) | (w[i - 15] << 14)) ^ (w[i - 15] >>> 3);
        s1 = ((w[i - 2] >>> 17) | (w[i - 2] << 15)) ^ ((w[i - 2] >>> 19) | (w[i - 2] << 13)) ^ (w[i - 2] >>> 10);
        w[i] = (w[i - 16] + s0 + w[i - 7] + s1) >>> 0;
      }
      a = h[0]; b = h[1]; c = h[2]; d = h[3]; e = h[4]; f = h[5]; g = h[6]; hh = h[7];
      for (i = 0; i < 64; i++) {
        s1 = ((e >>> 6) | (e << 26)) ^ ((e >>> 11) | (e << 21)) ^ ((e >>> 25) | (e << 7));
        t1 = (hh + s1 + ((e & f) ^ (~e & g)) + K[i] + w[i]) >>> 0;
        s0 = ((a >>> 2) | (a << 30)) ^ ((a >>> 13) | (a << 19)) ^ ((a >>> 22) | (a << 10));
        t2 = (s0 + ((a & b) ^ (a & c) ^ (b & c))) >>> 0;
        hh = g; g = f; f = e; e = (d + t1) >>> 0; d = c; c = b; b = a; a = (t1 + t2) >>> 0;
      }
      h[0] += a; h[1] += b; h[2] += c; h[3] += d; h[4] += e; h[5] += f; h[6] += g; h[7] += hh;
    }
    var hex = "";
    for (i = 0; i < 8; i++) hex += ("00000000" + h[i].toString(16)).slice(-8);
    return hex;
  }

  function cmpCodepoints(x, y) {
    var a = Array.from(x), b = Array.from(y), n = Math.min(a.length, b.length), i;
    for (i = 0; i < n; i++) {
      var p = a[i].codePointAt(0), q = b[i].codePointAt(0);
      if (p !== q) return p < q ? -1 : 1;
    }
    return a.length === b.length ? 0 : (a.length < b.length ? -1 : 1);
  }

  function jsonString(s) {
    var out = '"', i, c;
    for (i = 0; i < s.length; i++) {
      c = s.charCodeAt(i);
      if (c === 0x22) out += '\\"';
      else if (c === 0x5c) out += "\\\\";
      else if (c === 10) out += "\\n";
      else if (c === 13) out += "\\r";
      else if (c === 9) out += "\\t";
      else if (c === 8) out += "\\b";
      else if (c === 12) out += "\\f";
      else if (c < 0x20 || c > 0x7e && c !== 0x7f) out += "\\u" + ("0000" + c.toString(16)).slice(-4);
      else out += s[i];
    }
    return out + '"';
  }

  /* Same bytes as Python json.dumps(sort_keys=True, separators=(",", ":"), ensure_ascii=True). */
  function canon(v) {
    if (v === null || v === undefined) return "null";
    if (v === true) return "true";
    if (v === false) return "false";
    if (typeof v === "number") {
      if (!isFinite(v) || Math.floor(v) !== v) throw new Error("non-integer number in canonical JSON");
      return String(v);
    }
    if (typeof v === "string") return jsonString(v);
    if (Array.isArray(v)) return "[" + v.map(canon).join(",") + "]";
    var keys = Object.keys(v).sort(cmpCodepoints);
    return "{" + keys.map(function (k) { return jsonString(k) + ":" + canon(v[k]); }).join(",") + "}";
  }

  function eq(a, b) { return canon(a) === canon(b); }
  function isObj(x) { return x !== null && typeof x === "object" && !Array.isArray(x); }
  function has(text, sym) {
    var esc = sym.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    return new RegExp("(?<![A-Za-z0-9_$])" + esc + "(?![A-Za-z0-9_$])").test(text);
  }
  function roleOutput(role) { return isObj(role) && role.origin === "CONSENSUS" ? role.output : null; }
  function cpLen(s) { return Array.from(s).length; }
  var SYMBOL_RE = /^[A-Za-z_$][A-Za-z0-9_$.]{0,79}\s*(\([^)]*\))?$/;
  var SHA40 = /^[0-9a-f]{40}$/;

  function derive(d, a, u) {
    var ce = a !== null && a !== undefined && a.outcome === "COUNTEREXAMPLE";
    var ruling = u ? u.ruling : null;
    if (ce && ruling === "ATTACK_UPHELD") return ["INSECURE", "ATTACK_UPHELD"];
    if (ce) return ["CONFLICTING_EVIDENCE", "COUNTEREXAMPLE_NOT_UPHELD"];
    if (!a) return ["UNPROVEN", "ATTACKER_UNRESOLVED"];
    if (a.outcome !== "NONE_FOUND") return ["UNPROVEN", "ATTACK_UNSUBSTANTIATED"];
    if (!d) return ["UNPROVEN", "DEFENDER_UNRESOLVED"];
    if (d.position !== "SATISFIED") return ["UNPROVEN", "DEFENSE_NOT_ESTABLISHED"];
    if (!u) return ["UNPROVEN", "AUDITOR_UNRESOLVED"];
    if (ruling !== "DEFENSE_UPHELD") return ["UNPROVEN", "AUDITOR_DID_NOT_UPHOLD_DEFENSE"];
    return ["SECURE", "DEFENSE_UPHELD"];
  }

  function aggregate(results, complete) {
    if (!results.length) return ["UNPROVEN", "NO_THREATS"];
    if (results.some(function (r) { return r === "INSECURE"; })) return ["INSECURE", ""];
    if (results.some(function (r) { return r === "CONFLICTING_EVIDENCE"; })) return ["CONFLICTING_EVIDENCE", ""];
    if (results.some(function (r) { return r !== "SECURE"; })) return ["UNPROVEN", ""];
    if (!complete) return ["UNPROVEN", "EVIDENCE_INCOMPLETE"];
    return ["SECURE", ""];
  }

  var REQUIRED = ["protocol", "protocol_version", "statement", "verification_id", "repository", "ref", "ref_kind",
    "base_commit", "head_commit", "security_claim", "claim_hash", "evidence", "threat_requirements",
    "threat_requirements_hash", "attack_hypotheses", "attack_hypotheses_hash", "analyses",
    "per_requirement_results", "counterexamples", "counterexamples_hash", "consensus_metadata",
    "challenges", "challenge_status", "final_result", "result_note", "frozen_at", "aggregated_at",
    "finalized_at", "certificate_hash"];

  function Report() { this.rows = []; }
  Report.prototype.add = function (name, status, detail) { this.rows.push([name, status, detail || ""]); };
  Report.prototype.check = function (name, cond, detail) { this.add(name, cond ? "OK" : "FAIL", cond ? "" : (detail || "")); };
  Report.prototype.ok = function () { return this.rows.every(function (r) { return r[1] !== "FAIL"; }); };

  function unique(arr) { return new Set(arr).size === arr.length; }
  function subset(a, b) { var s = new Set(b); return a.every(function (x) { return s.has(x); }); }
  function sameSet(a, b) { return a.size === b.size && Array.from(a).every(function (x) { return b.has(x); }); }

  function verifyInner(cert, bundle, onchain) {
    var r = new Report(), i, p, n;
    if (!isObj(cert)) { r.check("certificate is a JSON object", false); return r; }
    var missing = REQUIRED.filter(function (k) { return !(k in cert); });
    r.check("required fields present", missing.length === 0, "missing: " + missing.join(","));
    if (missing.length) return r;
    r.check("protocol", cert.protocol === "VeriForge" && cert.protocol_version === "1.0", cert.protocol + " " + cert.protocol_version);
    var body = {};
    Object.keys(cert).forEach(function (k) { if (k !== "certificate_hash") body[k] = cert[k]; });
    r.check("certificate hash", sha256(canon(body)) === cert.certificate_hash, "certificate_hash does not match its content");
    r.check("claim hash", sha256(cert.security_claim) === cert.claim_hash, "claim_hash mismatch");

    var threats = cert.threat_requirements, tids = threats.map(function (t) { return t.id; });
    r.check("threat ids unique", unique(tids));
    r.check("threat hashes", threats.every(function (t) { return sha256(t.text) === t.hash; }), "a threat hash differs from its text");
    r.check("threat requirements hash", sha256(canon(threats.map(function (t) { return { id: t.id, text: t.text }; }))) === cert.threat_requirements_hash);

    var ev = cert.evidence, items = ev.items, iids = items.map(function (x) { return x.item_id; });
    r.check("evidence ids unique", unique(iids));
    var metas = items.map(function (x) { return [x.item_id, x.source_type, x.file_path, x.content_hash]; });
    var root = sha256(canon({ repository: cert.repository, base_commit: cert.base_commit, head_commit: cert.head_commit, items: metas }));
    r.check("evidence root", root === ev.root, "evidence root does not match the item list and commits");
    r.check("commits are full shas", SHA40.test(cert.head_commit) && (cert.base_commit === "" || SHA40.test(cert.base_commit)));

    var hyps = cert.attack_hypotheses;
    var plain = hyps.map(function (h) { var o = {}; Object.keys(h).forEach(function (k) { if (k !== "hash") o[k] = h[k]; }); return o; });
    r.check("hypothesis hashes", plain.every(function (q, k) { return sha256(canon(q)) === hyps[k].hash; }));
    r.check("attack hypotheses hash", sha256(canon(plain)) === cert.attack_hypotheses_hash);
    r.check("hypotheses reference known threats and evidence", hyps.every(function (h) {
      return tids.indexOf(h.threat_id) >= 0 && h.evidence_refs.length > 0 && subset(h.evidence_refs, iids);
    }), "a hypothesis references an unknown threat or evidence id");
    r.check("every threat has a hypothesis", tids.every(function (t) { return hyps.some(function (h) { return h.threat_id === t; }); }));

    var per = cert.per_requirement_results;
    r.check("one result per threat, in order", eq(per.map(function (x) { return x.threat_id; }), tids));
    ["defender", "attacker", "auditor"].forEach(function (name) {
      var list = per.map(function (x) { return { threat_id: x.threat_id, role: x[name] }; });
      r.check(name + " analysis hash", sha256(canon(list)) === cert.analyses[name + "_hash"]);
    });

    var ces = cert.counterexamples;
    r.check("counterexample hashes", ces.every(function (c) { return sha256(canon(c.counterexample)) === c.hash; }));
    r.check("counterexamples hash", sha256(canon(ces.map(function (c) { return { id: c.id, hash: c.hash }; }))) === cert.counterexamples_hash);
    var expectedCes = [];
    per.forEach(function (x) {
      var a = roleOutput(x.attacker);
      if (a && a.outcome === "COUNTEREXAMPLE") {
        expectedCes.push([x.threat_id, a.counterexample]);
        r.check("counterexample id " + x.threat_id, x.counterexample_id === a.counterexample.id && a.counterexample.id === "CE-" + x.threat_id);
      }
    });
    r.check("counterexample list matches attacker outputs",
      eq(ces.map(function (c) { return [c.threat_id, c.counterexample]; }), expectedCes));
    var hashById = {};
    items.forEach(function (x) { hashById[x.item_id] = x.content_hash; });
    r.check("counterexample evidence hashes match the evidence", ces.every(function (c) {
      return c.evidence_hashes.every(function (e) { return e.content_hash === hashById[e.evidence_id]; });
    }));
    var hypIdsByThreat = {};
    tids.forEach(function (t) { hypIdsByThreat[t] = new Set(hyps.filter(function (h) { return h.threat_id === t; }).map(function (h) { return h.id; })); });
    r.check("counterexamples cite a hypothesis of their threat", ces.every(function (c) {
      return hypIdsByThreat[c.threat_id] && hypIdsByThreat[c.threat_id].has(c.counterexample.hypothesis_id);
    }));

    var finals = [];
    per.forEach(function (x) {
      var d = roleOutput(x.defender), a = roleOutput(x.attacker), u = roleOutput(x.auditor);
      var res = derive(d, a, u)[0];
      r.check(x.threat_id + " derived result", x.derived_result === res, "recorded " + x.derived_result + ", rules give " + res);
      if (d && d.position === "SATISFIED") {
        r.check(x.threat_id + " defence covers every hypothesis", sameSet(new Set(d.rebuttals.map(function (q) { return q.hypothesis_id; })), hypIdsByThreat[x.threat_id]));
      }
      var chs = cert.challenges.filter(function (c) { return c.threat_id === x.threat_id; });
      r.check(x.threat_id + " at most one challenge", chs.length <= 1);
      var fin = res;
      if (chs.length) {
        var c = chs[0], ra = c.reanalysis, nw;
        if (c.kind === "VERDICT") nw = derive(roleOutput(ra.defender), roleOutput(ra.attacker), roleOutput(ra.auditor))[0];
        else nw = derive(d, a, roleOutput(ra.auditor))[0];
        var resolution = nw === res ? "CONFIRMED" : "DOWNGRADED";
        fin = resolution === "CONFIRMED" ? res : "CONFLICTING_EVIDENCE";
        r.check(x.threat_id + " challenge re-derived", c.original_result === res && (c.original_result === "SECURE" || c.original_result === "INSECURE")
          && c.reanalysis_result === nw && c.resolution === resolution && c.final_result === fin);
        r.check(x.threat_id + " challenge hash", sha256(canon(c.reanalysis)) === c.reanalysis_hash);
      }
      r.check(x.threat_id + " result", x.result === fin, "recorded " + x.result + ", rules give " + fin);
      finals.push(fin);
    });
    var origins = {};
    per.forEach(function (x) {
      ["defender", "attacker", "auditor"].forEach(function (nm) {
        var o = isObj(x[nm]) ? x[nm].origin : null;
        origins[nm] = origins[nm] || {};
        origins[nm][o] = (origins[nm][o] || 0) + 1;
      });
    });
    var meta = cert.consensus_metadata;
    r.check("consensus metadata", eq(meta.role_origins, origins) && meta.threat_count === tids.length,
      "consensus_metadata does not match the embedded role records");
    r.check("challenge_status", cert.challenge_status === (cert.challenges.length ? "RESOLVED" : "NONE"));
    var agg = aggregate(finals, !!ev.complete);
    r.check("final result", cert.final_result === agg[0] && cert.result_note === agg[1],
      "recorded " + cert.final_result + "/" + cert.result_note + ", rules give " + agg[0] + "/" + agg[1]);
    if (cert.final_result === "SECURE") {
      r.check("SECURE gates", !!ev.complete && per.every(function (x) {
        return ["defender", "attacker", "auditor"].every(function (nm) { return roleOutput(x[nm]) !== null && roleOutput(x[nm]) !== undefined; });
      }));
    }

    if (bundle === null || bundle === undefined) {
      r.add("evidence bytes", "SKIP", "no evidence bundle supplied; content hashes not re-computed");
    } else {
      var content = {};
      bundle.forEach(function (b) { content[b.item_id] = b.content; });
      var cids = Object.keys(content);
      r.check("bundle covers the certificate's items", sameSet(new Set(cids), new Set(iids)));
      r.check("evidence content hashes", items.every(function (x) {
        return sha256(x.item_id in content ? content[x.item_id] : "\u0000") === x.content_hash;
      }), "an evidence item's bytes do not match its content_hash");
      r.check("evidence lengths", items.every(function (x) { return cpLen(x.item_id in content ? content[x.item_id] : "") === x.length; }));
      var diffItems = items.filter(function (x) { return x.source_type === "diff_file" && x.item_id in content; }).map(function (x) { return content[x.item_id]; });
      var diff = diffItems.join("\n") + (ev.diff_ends_with_newline ? "\n" : "");
      r.check("diff hash", sha256(diff) === ev.diff_hash, "the diff items do not re-assemble to diff_hash");
      var okQuotes = true;
      var text = function (id) { return id in content ? content[id] : "\u0000"; };
      per.forEach(function (x) {
        var dout = roleOutput(x.defender);
        ((dout && dout.rebuttals) || []).forEach(function (reb) {
          reb.citations.forEach(function (c) { okQuotes = okQuotes && text(c.evidence_id).indexOf(c.quote) >= 0; });
        });
        var att = roleOutput(x.attacker);
        if (att && att.outcome === "COUNTEREXAMPLE") {
          var ce = att.counterexample;
          ce.evidence.forEach(function (c) { okQuotes = okQuotes && text(c.evidence_id).indexOf(c.quote) >= 0; });
          var ids = Array.from(new Set(ce.evidence.map(function (c) { return c.evidence_id; }))).sort();
          var cited = ids.map(function (e) { return e in content ? content[e] : ""; });
          okQuotes = okQuotes && ce.evidence.some(function (c) { return has(c.quote, ce.entry_point); });
          ce.path.forEach(function (s) {
            okQuotes = okQuotes && cited.some(function (t) { return has(t, s); }) && SYMBOL_RE.test(s);
          });
        }
      });
      r.check("every quote and counterexample symbol exists in the frozen bytes", okQuotes, "a citation or symbol is not present in the evidence");
    }

    if (onchain === null || onchain === undefined) {
      r.add("on-chain anchor", "SKIP", "no --onchain-hash supplied; the certificate is not tied to a chain record");
    } else {
      r.check("matches the on-chain certificate hash", String(onchain).trim().toLowerCase() === cert.certificate_hash,
        "certificate_hash differs from the value stored by the contract");
    }
    return r;
  }

  function verify(cert, bundle, onchain) {
    try {
      return verifyInner(cert, bundle, onchain);
    } catch (e) {
      var r = new Report();
      r.check("certificate structure", false, "malformed certificate (" + (e && e.name) + ": " + (e && e.message) + ")");
      return r;
    }
  }

  var api = { sha256: sha256, canon: canon, derive: derive, aggregate: aggregate, verify: verify };
  if (typeof module !== "undefined" && module.exports) module.exports = api;
  else root.VFVerify = api;
})(typeof self !== "undefined" ? self : this);
