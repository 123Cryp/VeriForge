"""
Runs the nine recorded attacks (tests/attacks.py) against the real contract
and prints what happened. Writes frontend/assets/security_demo.json.

    python3 tools/security_demo.py
    python3 tools/security_demo.py --check     # fail if the committed file is stale or an attack succeeds
"""
import json
import os
import sys

import _bootstrap  # noqa: F401
from harness import ROOT
import attacks

OUT = os.path.join(ROOT, "frontend", "assets", "security_demo.json")
OUT_JS = os.path.join(ROOT, "frontend", "assets", "security_demo.js")


def main():
    results = attacks.run_all()
    text = json.dumps({"attacks": results}, indent=1, sort_keys=True, ensure_ascii=True) + "\n"
    for r in results:
        print(f"[{'BLOCKED' if r['blocked'] else 'SUCCEEDED'}] {r['id']} {r['name']} (stopped by: {r['stopped_by']})")
    failed = [r["id"] for r in results if not r["blocked"]]
    js = "window.VF_SECURITY = " + text.rstrip("\n") + ";\n"
    if "--check" in sys.argv:
        current = open(OUT, encoding="utf-8").read() if os.path.exists(OUT) else ""
        current_js = open(OUT_JS, encoding="utf-8").read() if os.path.exists(OUT_JS) else ""
        if failed or current != text or current_js != js:
            raise SystemExit(f"security demo check failed (succeeded attacks: {failed}, stale file: {current != text})")
        print("ok: security_demo.json is current and every attack is blocked")
        return
    open(OUT, "w", encoding="utf-8").write(text)
    open(OUT_JS, "w", encoding="utf-8").write(js)
    print(f"{len(results) - len(failed)}/{len(results)} attacks blocked; wrote {OUT}")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
