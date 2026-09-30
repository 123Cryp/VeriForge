"""
Builds a test-only copy of the deploy artifact with a short challenge window.

    python3 tools/build_short_window.py [seconds] [output]

Default: 600 seconds, written to build/veriforge_short_window.py. The only
difference from contracts/veriforge_deploy.py is the CHALLENGE_WINDOW_SECONDS
line; the script verifies that. Never deploy the result as the real contract.
"""
import difflib
import os
import sys

from _bootstrap import ROOT  # noqa: F401
import build_deploy


def main():
    seconds = int(sys.argv[1]) if len(sys.argv) > 1 else 600
    out_path = sys.argv[2] if len(sys.argv) > 2 else os.path.join(ROOT, "build", "veriforge_short_window.py")
    if seconds < 60:
        raise SystemExit("seconds must be at least 60")
    src = open(build_deploy.SRC, encoding="utf-8").read()
    old = "CHALLENGE_WINDOW_SECONDS = 48 * 3600"
    if src.count(old) != 1:
        raise SystemExit("could not find the challenge window constant")
    built = build_deploy.build(src.replace(old, f"CHALLENGE_WINDOW_SECONDS = {seconds}"))
    built = built[0] if isinstance(built, tuple) else built
    base = open(build_deploy.OUT, encoding="utf-8").read()
    changed = [l for l in difflib.unified_diff(base.splitlines(), built.splitlines(), lineterm="", n=0)
               if l[:1] in "+-" and l[:3] not in ("+++", "---")]
    if changed != ["-" + old, f"+CHALLENGE_WINDOW_SECONDS = {seconds}"]:
        raise SystemExit(f"unexpected difference from the deploy artifact: {changed}")
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    open(out_path, "w", encoding="utf-8").write(built)
    print(f"wrote {out_path} ({len(built)} bytes); challenge window {seconds} s; only that line differs")


if __name__ == "__main__":
    main()
