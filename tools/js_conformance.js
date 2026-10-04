// Runs the frontend verifier on the cases written by test_certificate.py and
// prints {case name: ok}. Usage: node js_conformance.js <verify.js> <cases.json>
const fs = require("fs");
const V = require(require("path").resolve(process.argv[2]));
const cases = JSON.parse(fs.readFileSync(process.argv[3], "utf8"));
const out = {};
for (const c of cases) out[c.name] = V.verify(c.cert, c.bundle, c.onchain).ok();
process.stdout.write(JSON.stringify(out));
