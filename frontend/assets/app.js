/*
 * VeriForge frontend. Everything untrusted (claims, evidence, model text,
 * counterexamples) is rendered as text nodes only (never parsed as markup).
 * Tabs: recorded demo replay, in-browser certificate verifier, security demo,
 * live GenLayer mode (genlayer-js loaded on demand).
 */
(function () {
  "use strict";
  var V = window.VFVerify, DEMO = window.VF_DEMO, SEC = window.VF_SECURITY;
  var main = document.getElementById("main");
  var state = { tab: "demo", scenario: 0, step: 0, verify: { cert: "", bundle: "", onchain: "" }, timer: null };
  var LIVE = { address: "", client: null, write: null, account: null, busy: false };
  var EXPLORER = "https://explorer-studio.genlayer.com";

  function el(tag, attrs) {
    var n = document.createElement(tag), i, c, k;
    attrs = attrs || {};
    for (k in attrs) {
      if (!Object.prototype.hasOwnProperty.call(attrs, k) || attrs[k] === undefined || attrs[k] === null || attrs[k] === false) continue;
      if (k === "class") n.className = attrs[k];
      else if (k === "onclick") n.addEventListener("click", attrs[k]);
      else if (k === "oninput") n.addEventListener("input", attrs[k]);
      else if (k === "onchange") n.addEventListener("change", attrs[k]);
      else if (k === "value") n.value = attrs[k];
      else n.setAttribute(k, attrs[k]);
    }
    function add(x) {
      if (x === undefined || x === null || x === false) return;
      if (Array.isArray(x)) { x.forEach(add); return; }
      n.appendChild(typeof x === "object" ? x : document.createTextNode(String(x)));
    }
    for (i = 2; i < arguments.length; i++) add(arguments[i]);
    return n;
  }
  function badge(v, cls) { return el("span", { class: "badge " + (cls || ("v-" + v)) }, v || "PENDING"); }
  function panel() { return el("div", { class: "panel" }, Array.prototype.slice.call(arguments)); }
  function short(h) { return h ? h.slice(0, 12) + "…" : ""; }
  function parse(s) { try { return JSON.parse(s); } catch (e) { return null; } }
  function pretty(o) { return JSON.stringify(o, null, 2); }

  /* ------------------------------------------------------------ tabs */
  function setTab(t) {
    state.tab = t;
    stopPlay();
    Array.prototype.forEach.call(document.querySelectorAll("#nav button"), function (b) { b.classList.toggle("active", b.dataset.tab === t); });
    render();
  }
  Array.prototype.forEach.call(document.querySelectorAll("#nav button"), function (b) { b.addEventListener("click", function () { setTab(b.dataset.tab); }); });
  function render() {
    var view = el("div", { id: "view" });
    main.replaceChildren(view);
    ({ demo: renderDemo, verify: renderVerify, security: renderSecurity, live: renderLive, about: renderAbout })[state.tab](view);
  }

  /* ------------------------------------------------------------ demo replay */
  function stopPlay() { if (state.timer) { clearInterval(state.timer); state.timer = null; } }

  function roleSummary(role, kind) {
    if (!role) return null;
    if (role.origin !== "CONSENSUS") return { label: role.origin, out: null };
    var o = role.output;
    return { label: kind === "defender" ? o.position : kind === "attacker" ? o.outcome : o.ruling, out: o };
  }

  function renderQuotes(cites) {
    return (cites || []).map(function (c) { return el("div", { class: "quote" }, "[" + c.evidence_id + "] " + c.quote); });
  }

  function renderDemo(view) {
    if (!DEMO) { view.appendChild(panel(el("p", {}, "demo_run.js did not load."))); return; }
    var sc = DEMO.scenarios[state.scenario], steps = sc.steps, idx = state.step, done = {};
    steps.slice(0, idx).forEach(function (s) { done[s.method] = true; });
    var c = sc.case, threats = c.threats, hyps = c.hypotheses;

    var select = el("select", { id: "scenario", onchange: function (e) { state.scenario = +e.target.value; state.step = 0; render(); } },
      DEMO.scenarios.map(function (s, i) { var o = el("option", { value: String(i) }, s.title); if (i === state.scenario) o.selected = true; return o; }));
    var ctrl = el("div", { class: "row" }, select,
      el("button", { class: "btn", id: "prev", onclick: function () { if (state.step > 0) { state.step--; render(); } } }, "◀ Back"),
      el("button", { class: "btn primary", id: "next", onclick: function () { if (state.step < steps.length) { state.step++; render(); } } }, "Next step ▶"),
      el("button", { class: "btn", id: "play", onclick: function () {
        if (state.timer) { stopPlay(); return; }
        if (state.step >= steps.length) state.step = 0;
        state.timer = setInterval(function () { if (state.step >= steps.length) { stopPlay(); render(); return; } state.step++; render(); }, 900);
        render();
      } }, state.timer ? "Pause" : "Play"),
      el("button", { class: "btn", id: "all", onclick: function () { state.step = steps.length; render(); } }, "Show everything"));
    view.appendChild(panel(el("h2", {}, "Recorded protocol run"),
      el("p", { class: "muted" }, DEMO.recording),
      ctrl,
      el("div", { class: "steps", id: "steps" }, steps.map(function (s, i) {
        return el("div", { class: "step" + (i < idx ? " done" : "") + (i === idx - 1 ? " current" : "") },
          el("span", { class: "mono" }, String(s.n).padStart(2, "0")), el("span", {}, s.label),
          el("span", { class: "muted" }, "— " + s.caller + " → " + s.status_after));
      }))));
    if (idx === 0) { view.appendChild(panel(el("p", { class: "muted" }, "Press “Next step” to run the protocol one transaction at a time."))); return; }

    view.appendChild(panel(el("h3", {}, "Claim"), el("p", {}, sc.claim),
      el("p", { class: "muted" }, sc.repository + " @ " + sc.ref)));

    if (done.freeze_evidence) {
      var v = c.verification, ev = sc.evidence_bundle;
      var sel = el("pre", { id: "evbody" }, "Select an item to view the exact frozen bytes.");
      view.appendChild(panel(el("h3", {}, "Frozen evidence"),
        el("p", { class: "muted" }, "base " + short(v.base_commit) + " → head " + short(v.head_commit) + " · complete: " + (v.evidence_complete ? "yes" : "no")),
        el("p", { class: "mono" }, "evidence_root " + v.evidence_root),
        el("table", {}, el("tr", {}, ["Item", "Type", "Path", "SHA-256"].map(function (h) { return el("th", {}, h); })),
          ev.map(function (i) {
            return el("tr", { style: "cursor:pointer", onclick: function () { sel.textContent = i.content; } },
              el("td", { class: "mono" }, i.item_id), el("td", {}, i.source_type), el("td", { class: "wrap" }, i.file_path), el("td", { class: "mono" }, short(i.content_hash)));
          })), sel));
    }
    if (done.decompose_threats) {
      view.appendChild(panel(el("h3", {}, "Threat requirements (each must hold for the claim to hold)"),
        el("table", {}, threats.map(function (t) { return el("tr", {}, el("td", { class: "mono" }, t.threat_id), el("td", { class: "wrap" }, t.text)); }))));
    }
    if (done.generate_attack_hypotheses) {
      view.appendChild(panel(el("h3", {}, "Attack hypotheses (grounded in cited evidence)"),
        el("table", {}, el("tr", {}, ["Id", "Threat", "Entry point", "Capability"].map(function (h) { return el("th", {}, h); })),
          hyps.map(function (h) { return el("tr", {}, el("td", { class: "mono" }, h.id), el("td", { class: "mono" }, h.threat_id), el("td", { class: "mono" }, h.entry_point), el("td", { class: "wrap" }, h.capability)); }))));
    }
    if (done.defender_analysis || done.attacker_analysis || done.auditor_reconciliation) {
      threats.forEach(function (t) {
        var d = parse(t.defender), a = parse(t.attacker), u = parse(t.auditor), body = [];
        if (done.defender_analysis && d) {
          var ds = roleSummary(d, "defender");
          body.push(el("div", {}, el("strong", {}, "Defender "), badge(ds.label, "v-" + (ds.label === "SATISFIED" ? "SECURE" : "UNPROVEN")), el("span", { class: "muted" }, " " + (ds.out ? ds.out.reason : ""))));
          if (ds.out) ds.out.rebuttals.forEach(function (r) { body.push(el("div", { class: "muted" }, "Rebuts " + r.hypothesis_id + ":"), renderQuotes(r.citations)); });
        }
        if (done.attacker_analysis && a) {
          var as = roleSummary(a, "attacker");
          body.push(el("div", { style: "margin-top:8px" }, el("strong", {}, "Attacker "), badge(as.label, "v-" + (as.label === "COUNTEREXAMPLE" ? "INSECURE" : as.label === "NONE_FOUND" ? "SECURE" : "UNPROVEN")), el("span", { class: "muted" }, " " + (as.out ? as.out.reason : ""))));
          if (as.out && as.out.counterexample) {
            var ce = as.out.counterexample;
            body.push(el("div", { class: "ce" },
              el("strong", {}, ce.id + " · entry point " + ce.entry_point + "()"),
              el("div", {}, "Capability: " + ce.capability),
              el("div", {}, "Path: " + ce.path.join(" → ")),
              el("div", {}, "Missing protection: " + ce.missing_protection),
              renderQuotes(ce.evidence)));
          }
        }
        if (done.auditor_reconciliation && u) {
          var us = roleSummary(u, "auditor");
          body.push(el("div", { style: "margin-top:8px" }, el("strong", {}, "Auditor "), badge(us.label, "v-UNPROVEN"), el("span", { class: "muted" }, " " + (us.out ? us.out.reason : ""))));
        }
        if (done.consensus) body.push(el("div", { style: "margin-top:8px" }, el("strong", {}, "Result "), badge(t.result), el("span", { class: "muted" }, " " + t.result_reason)));
        view.appendChild(panel(el("h3", {}, t.threat_id + " — " + t.text), body));
      });
    }
    if (done.challenge) {
      c.challenges.forEach(function (ch) {
        view.appendChild(panel(el("h3", {}, "Challenge " + ch.challenge_id + " (" + ch.kind + " on " + ch.target + ")"),
          el("p", {}, ch.rationale), el("p", {}, "Original ", badge(ch.original_result), " · re-analysis ", badge(ch.reanalysis_result), " · resolution ", badge(ch.resolution, "v-UNPROVEN"), " · final ", badge(ch.final_result)),
          el("p", { class: "muted" }, "A challenge can only confirm or downgrade a result. It can never turn SECURE into INSECURE or the reverse.")));
      });
    }
    if (done.aggregate_security_result) {
      var cv = c.verification;
      view.appendChild(panel(el("h3", {}, "Final result"), el("div", {}, badge(cv.final_result, "v-" + cv.final_result + " final"), cv.result_note ? el("span", { class: "muted" }, "  " + cv.result_note) : null),
        el("p", { class: "muted" }, "Derived by the contract from the three role outputs of every requirement, worst result first: INSECURE > CONFLICTING_EVIDENCE > UNPROVEN > SECURE.")));
    }
    if (done.finalize_certificate) {
      view.appendChild(panel(el("h3", {}, "Certificate"), el("p", { class: "mono" }, "certificate_hash " + sc.certificate_hash),
        el("div", { class: "row" },
          el("button", { class: "btn primary", id: "toverify", onclick: function () {
            state.verify = { cert: sc.certificate_text, bundle: JSON.stringify(sc.evidence_bundle), onchain: sc.certificate_hash }; setTab("verify"); state.autorun = true; render();
          } }, "Verify this certificate in the browser"))));
    }
  }

  /* ------------------------------------------------------------ verify */
  function renderVerify(view) {
    var certBox = el("textarea", { id: "cert", placeholder: "Paste certificate JSON (from get_certificate)", value: state.verify.cert });
    var bundleBox = el("textarea", { id: "bundle", placeholder: "Optional: evidence bundle JSON (from get_evidence_bundle)", value: state.verify.bundle });
    var hashBox = el("input", { id: "onchain", placeholder: "Optional: on-chain certificate hash (from get_certificate_hash)", value: state.verify.onchain });
    var out = el("div", { id: "vout" });
    function sync() { state.verify = { cert: certBox.value, bundle: bundleBox.value, onchain: hashBox.value }; }
    function run() {
      sync();
      var cert = parse(state.verify.cert), bundle = state.verify.bundle.trim() ? parse(state.verify.bundle) : null;
      if (cert === null) { out.replaceChildren(panel(el("span", { class: "badge FAIL" }, "FAIL"), " The certificate is not valid JSON.")); return; }
      if (state.verify.bundle.trim() && bundle === null) { out.replaceChildren(panel(el("span", { class: "badge FAIL" }, "FAIL"), " The evidence bundle is not valid JSON.")); return; }
      var rep = V.verify(cert, bundle, state.verify.onchain.trim() || null);
      out.replaceChildren(panel(
        el("h2", {}, rep.ok() ? "CERTIFICATE VALID" : "CERTIFICATE INVALID"),
        el("p", { class: "muted" }, rep.ok() ? "Every check that could run passed. SKIP rows are checks that need data you did not supply; they do not count as passed." : "At least one check failed."),
        el("table", {}, rep.rows.map(function (r) { return el("tr", {}, el("td", {}, el("span", { class: "badge " + r[1] }, r[1])), el("td", {}, r[0]), el("td", { class: "wrap muted" }, r[2])); }))));
    }
    function load(i) {
      var s = DEMO.scenarios[i];
      certBox.value = s.certificate_text; bundleBox.value = JSON.stringify(s.evidence_bundle); hashBox.value = s.certificate_hash; sync(); out.replaceChildren();
    }
    function loadLive() {
      var L = window.VF_LIVE_EXAMPLE;
      if (!L) return;
      certBox.value = L.certificate_text; bundleBox.value = JSON.stringify(L.evidence_bundle); hashBox.value = L.certificate_hash; sync(); out.replaceChildren();
    }
    function tamper(kind) {
      var cert = parse(certBox.value);
      if (!cert) return;
      if (kind === "flip") cert.final_result = cert.final_result === "SECURE" ? "INSECURE" : "SECURE";
      if (kind === "claim") cert.security_claim += " (edited)";
      if (kind === "rehash") {
        cert.final_result = cert.final_result === "SECURE" ? "INSECURE" : "SECURE";
        var body = {}; Object.keys(cert).forEach(function (k) { if (k !== "certificate_hash") body[k] = cert[k]; });
        cert.certificate_hash = V.sha256(V.canon(body));
      }
      certBox.value = JSON.stringify(cert); hashBox.value = kind === "rehash" ? hashBox.value : hashBox.value; run();
    }
    function tamperBundle() {
      var b = parse(bundleBox.value);
      if (!b || !b.length) return;
      var i = b.length > 2 ? 2 : 0;
      b[i].content = b[i].content.replace("onlyAuthorized", "onlyAuthorised");
      if (b[i].content === b[i].content.replace("onlyAuthorised", "")) b[i].content += " ";
      bundleBox.value = JSON.stringify(b); run();
    }
    view.appendChild(panel(el("h2", {}, "Verify a certificate"),
      el("p", { class: "muted" }, "Runs entirely in this page (a second implementation of the hashing and derivation rules, independent of the contract). It recomputes every hash, re-derives every per-requirement result and the final result from the embedded role outputs, and — with the evidence bundle — re-checks every quote against the frozen bytes."),
      el("div", { class: "row" },
        el("button", { class: "btn", id: "loadv", onclick: function () { load(0); } }, "Load demo: vulnerable PR"),
        el("button", { class: "btn", id: "loadf", onclick: function () { load(1); } }, "Load demo: fixed PR"),
        el("button", { class: "btn", id: "loadlive", onclick: loadLive }, "Load live Studio certificate")),
      el("p", {}), certBox, el("p", {}), bundleBox, el("p", {}), hashBox, el("p", {}),
      el("div", { class: "row" }, el("button", { class: "btn primary", id: "verifybtn", onclick: run }, "Verify"),
        el("span", { class: "muted" }, "Try to break it:"),
        el("button", { class: "btn", id: "t-flip", onclick: function () { tamper("flip"); } }, "Flip the result"),
        el("button", { class: "btn", id: "t-claim", onclick: function () { tamper("claim"); } }, "Edit the claim"),
        el("button", { class: "btn", id: "t-rehash", onclick: function () { tamper("rehash"); } }, "Flip + recompute hash"),
        el("button", { class: "btn", id: "t-bundle", onclick: tamperBundle }, "Edit one evidence byte"))));
    view.appendChild(out);
    if (state.autorun) { state.autorun = false; run(); }
  }

  /* ------------------------------------------------------------ security demo */
  function renderSecurity(view) {
    view.appendChild(panel(el("h2", {}, "Nine attacks, run against the real contract code"),
      el("p", { class: "muted" }, "Each attack is executed by tools/security_demo.py against contracts/veriforge.py on a local GenLayer stub (malicious leaders, hostile models, replay, timeouts). “Stopped by” names the layer that blocked it; nothing here was run on a live network.")));
    SEC.attacks.forEach(function (a) {
      view.appendChild(panel(el("div", { class: "row" }, el("strong", {}, a.id + " · " + a.name), badge(a.blocked ? "BLOCKED" : "SUCCEEDED", a.blocked ? "blocked" : "FAIL")),
        el("p", {}, a.attack), el("p", { class: "muted" }, "Stopped by: " + a.stopped_by), el("pre", {}, pretty(a.observed))));
    });
  }

  /* ------------------------------------------------------------ live */
  function toPlain(x) {
    if (x instanceof Map) { var o = {}; x.forEach(function (v, k) { o[k] = toPlain(v); }); return o; }
    if (Array.isArray(x)) return x.map(toPlain);
    if (typeof x === "bigint") return Number(x);
    return x;
  }
  async function liveClient() {
    if (LIVE.client) return LIVE.client;
    var mod = await import("https://esm.sh/genlayer-js@1.1.8");
    var chains = await import("https://esm.sh/genlayer-js@1.1.8/chains");
    LIVE.mod = mod; LIVE.chains = chains;
    LIVE.client = mod.createClient({ chain: chains.studionet });
    return LIVE.client;
  }
  async function liveRead(method, args) {
    var c = await liveClient();
    return toPlain(await c.readContract({ address: LIVE.address, functionName: method, args: args || [] }));
  }
  async function liveWrite(method, args, log) {
    if (!LIVE.write) throw new Error("connect a wallet first");
    if (LIVE.busy) throw new Error("a transaction is already in progress");
    LIVE.busy = true;
    try {
      log("→ " + method + "(" + JSON.stringify(args) + ")");
      var hash = await LIVE.write.writeContract({ address: LIVE.address, functionName: method, args: args });
      log("  tx " + hash + " — waiting for consensus (LLM stages can take minutes)…");
      var receipt = toPlain(await LIVE.write.waitForTransactionReceipt({ hash: hash, status: "ACCEPTED", interval: 5000, retries: 120 }));
      var res = receipt && receipt.consensus_data && receipt.consensus_data.leader_receipt && receipt.consensus_data.leader_receipt[0] && receipt.consensus_data.leader_receipt[0].execution_result;
      log("  " + EXPLORER + "/tx/" + hash);
      if (typeof res === "string" && /error/i.test(res)) throw new Error("the contract rejected " + method + " (" + res + ")");
      log("  accepted");
      return receipt;
    } finally { LIVE.busy = false; }
  }
  var NEXT = { SUBMITTED: ["freeze_evidence", 0], EVIDENCE_FROZEN: ["decompose_threats", 0], THREATS_DEFINED: ["generate_attack_hypotheses", 0],
    HYPOTHESES_READY: ["defender_analysis", 1], DEFENDED: ["attacker_analysis", 1], ATTACKED: ["auditor_reconciliation", 1],
    AUDITED: ["consensus", 0], RECONCILED: ["aggregate_security_result", 0], AGGREGATED: ["finalize_certificate", 0] };

  function renderLive(view) {
    var logBox = el("pre", { id: "livelog" }, "");
    function log(s) { logBox.textContent += s + "\n"; logBox.scrollTop = logBox.scrollHeight; }
    var addr = el("input", { id: "addr", placeholder: "Deployed VeriForge contract address (0x…)", value: LIVE.address });
    var list = el("div", { id: "livelist" }), detail = el("div", { id: "livedetail" });
    var wallet = el("span", { class: "muted", id: "walletstatus" }, LIVE.account ? LIVE.account : "no wallet connected");
    view.appendChild(panel(el("h2", {}, "Live mode (GenLayer Studio)"),
      el("p", { class: "notice muted" }, "This mode talks to a deployed contract through genlayer-js (loaded on demand). The contract itself was run end to end on GenLayer Studio (see examples/live/ and docs/FINAL_SECURITY_REVIEW.md), but this page’s Live tab is only tested without a network. The recorded demo and the verifier work without it."),
      addr, el("p", {}),
      el("div", { class: "row" },
        el("button", { class: "btn primary", id: "loadlist", onclick: async function () {
          LIVE.address = addr.value.trim();
          if (!/^0x[0-9a-fA-F]{40}$/.test(LIVE.address)) { log("Enter a valid contract address."); return; }
          try {
            var ids = await liveRead("list_verifications", [0, 20]);
            list.replaceChildren(el("h3", {}, "Verifications (" + ids.length + " newest)"), ids.map(function (id) {
              return el("button", { class: "btn", style: "margin:3px", onclick: function () { open(id); } }, id);
            }));
          } catch (e) { log("read failed: " + (e.message || e)); }
        } }, "Load verifications"),
        el("button", { class: "btn", id: "connect", onclick: async function () {
          if (!window.ethereum) { log("No injected wallet found."); return; }
          try {
            var accounts = await window.ethereum.request({ method: "eth_requestAccounts" });
            await liveClient();
            LIVE.account = accounts[0];
            LIVE.write = LIVE.mod.createClient({ chain: LIVE.chains.studionet, account: LIVE.account });
            wallet.textContent = LIVE.account;
          } catch (e) { log("wallet connection failed: " + (e.message || e)); }
        } }, "Connect wallet"), wallet)));
    var form = {
      repo: el("input", { id: "f-repo", placeholder: "https://github.com/owner/repo" }),
      ref: el("input", { id: "f-ref", placeholder: "PR#7 or a full 40-hex commit sha" }),
      claim: el("textarea", { id: "f-claim", placeholder: "The security claim, e.g. “This PR fixes unauthorized withdrawal: only authorized users can withdraw funds.”" })
    };
    view.appendChild(panel(el("h3", {}, "Submit a security claim"), form.repo, el("p", {}), form.ref, el("p", {}), form.claim, el("p", {}),
      el("button", { class: "btn primary", id: "submitclaim", onclick: async function () {
        try { await liveWrite("submit_security_claim", [form.repo.value.trim(), form.ref.value.trim(), form.claim.value.trim()], log); log("Reload the list to see the new verification."); }
        catch (e) { log("failed: " + (e.message || e)); }
      } }, "Submit")));
    view.appendChild(panel(list)); view.appendChild(detail);
    view.appendChild(panel(el("h3", {}, "Activity"), logBox));

    async function open(id) {
      try {
        var c = await liveRead("get_case", [id]), v = c.verification;
        var actions = el("div", { class: "row" });
        var nx = NEXT[v.status];
        if (nx) actions.appendChild(el("button", { class: "btn primary", onclick: async function () {
          try { await liveWrite(nx[0], nx[1] ? [id, ""] : [id], log); open(id); } catch (e) { log("failed: " + (e.message || e)); }
        } }, "Run next stage: " + nx[0]));
        var kind = el("select", {}, el("option", { value: "VERDICT" }, "VERDICT"), el("option", { value: "COUNTEREXAMPLE" }, "COUNTEREXAMPLE"));
        var target = el("input", { placeholder: "T3 (verdict) or CE-T3 (counterexample)" }), why = el("input", { placeholder: "rationale" });
        var chal = v.status === "AGGREGATED" ? el("div", {}, el("h3", {}, "Challenge"), kind, target, why, el("button", { class: "btn", onclick: async function () {
          try { await liveWrite("challenge", [id, kind.value, target.value.trim(), why.value.trim()], log); open(id); } catch (e) { log("failed: " + (e.message || e)); }
        } }, "Submit challenge")) : null;
        var verifyBtn = v.status === "FINALIZED" ? el("button", { class: "btn", onclick: async function () {
          try {
            var cert = await liveRead("get_certificate", [id]), bundle = await liveRead("get_evidence_bundle", [id]), h = await liveRead("get_certificate_hash", [id]);
            state.verify = { cert: cert, bundle: JSON.stringify(bundle), onchain: h }; state.autorun = true; setTab("verify");
          } catch (e) { log("failed: " + (e.message || e)); }
        } }, "Verify certificate in browser") : null;
        detail.replaceChildren(panel(el("h2", {}, id + " "), badge(v.status, "v-UNPROVEN"), v.final_result ? badge(v.final_result) : null,
          el("p", {}, v.security_claim), el("p", { class: "muted" }, v.repository + " @ " + v.ref),
          el("table", {}, c.threats.map(function (t) { return el("tr", {}, el("td", { class: "mono" }, t.threat_id), el("td", { class: "wrap" }, t.text), el("td", {}, t.result ? badge(t.result) : "—")); })),
          el("p", {}), actions, chal, verifyBtn));
      } catch (e) { log("read failed: " + (e.message || e)); }
    }
  }

  /* ------------------------------------------------------------ about */
  function renderAbout(view) {
    view.appendChild(panel(el("h2", {}, "What a result means"),
      el("p", {}, "A SECURE result means that the defined security claim survived the protocol’s evidence and adversarial verification process. It does not prove that the software contains no vulnerabilities."),
      el("table", {},
        [["SECURE", "Every requirement: defender established it with verbatim citations, the attacker found no evidence-backed counterexample, the auditor upheld the defence, and the evidence was complete."],
         ["INSECURE", "A requirement has a structured counterexample whose every quote and symbol exists in the frozen evidence, and the auditor upheld it."],
         ["CONFLICTING_EVIDENCE", "A counterexample exists but was not upheld, or a challenge could not be reproduced."],
         ["UNPROVEN", "Anything else: timeouts, missing or unsubstantiated roles, weak defence, incomplete evidence. Never treated as SECURE."]]
          .map(function (r) { return el("tr", {}, el("td", {}, badge(r[0])), el("td", { class: "wrap" }, r[1])); })),
      el("p", { class: "muted" }, "The language model never decides a result. It proposes; validators re-check every quote against frozen bytes; the contract derives the result by fixed rules that the certificate verifier re-implements.")));
  }

  document.getElementById("nav").addEventListener("keydown", function () {});
  render();
})();
