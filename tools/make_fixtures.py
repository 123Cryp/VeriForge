"""
Writes the deterministic demo pull-request diffs next to their sources so the
exact bytes the protocol freezes are visible and reviewable.

    python3 tools/make_fixtures.py           # write tests/fixtures/vault_pr/pr_vulnerable.diff and pr_fixed.diff
    python3 tools/make_fixtures.py --check
"""
import os
import sys

import _bootstrap  # noqa: F401
from harness import ROOT
import scenario as sc

DIR = os.path.join(ROOT, "tests", "fixtures", "vault_pr")


def main():
    ok = True
    for variant in ("vulnerable", "fixed"):
        path = os.path.join(DIR, f"pr_{variant}.diff")
        text = sc.build_diff(variant)
        if "--check" in sys.argv:
            ok &= os.path.exists(path) and open(path, encoding="utf-8").read() == text
        else:
            open(path, "w", encoding="utf-8").write(text)
            print(f"wrote {path} ({len(text)} bytes)")
    if "--check" in sys.argv:
        if not ok:
            raise SystemExit("fixture diffs are stale; run python3 tools/make_fixtures.py")
        print("ok: fixture diffs are current")


if __name__ == "__main__":
    main()
