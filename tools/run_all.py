"""
Runs every check in the order CI runs them and prints a summary.

    python3 tools/run_all.py            # everything (mutation testing included)
    python3 tools/run_all.py --quick    # skip mutation testing
"""
import os
import subprocess
import sys
import time

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
PY = sys.executable
STEPS = [
    ("build check", [PY, "tools/build_deploy.py", "--check"], {}),
    ("fixtures current", [PY, "tools/make_fixtures.py", "--check"], {}),
    ("demo recording current", [PY, "tools/run_demo.py", "--check"], {}),
    ("security demo (9 attacks)", [PY, "tools/security_demo.py", "--check"], {}),
    ("unit", [PY, "tests/test_veriforge.py"], {}),
    ("adversarial", [PY, "tests/test_adversarial.py"], {}),
    ("certificate (python + js)", [PY, "tests/test_certificate.py"], {}),
    ("frontend (chromium)", [PY, "tests/test_frontend.py"], {}),
    ("fuzz", [PY, "tests/test_fuzz.py"], {}),
    ("unit on deploy artifact", [PY, "tests/test_veriforge.py"], {"VF_MODULE": "veriforge_deploy"}),
    ("adversarial on deploy artifact", [PY, "tests/test_adversarial.py"], {"VF_MODULE": "veriforge_deploy"}),
    ("certificate on deploy artifact", [PY, "tests/test_certificate.py"], {"VF_MODULE": "veriforge_deploy"}),
    ("fuzz on deploy artifact", [PY, "tests/test_fuzz.py"], {"VF_MODULE": "veriforge_deploy", "FUZZ_RUNS": "300"}),
    ("mutation", [PY, "tests/mutation_test.py"], {}),
]


def main():
    quick = "--quick" in sys.argv
    failed = []
    for name, cmd, env in STEPS:
        if quick and name == "mutation":
            continue
        t = time.time()
        r = subprocess.run(cmd, cwd=ROOT, env=dict(os.environ, **env), capture_output=True, text=True)
        last = [l for l in r.stdout.strip().splitlines() if l][-1:] or [""]
        print(f"{'PASS' if r.returncode == 0 else 'FAIL'}  {name:34s} {time.time() - t:5.0f}s  {last[0][:150]}", flush=True)
        if r.returncode != 0:
            failed.append(name)
            print(r.stdout[-2000:], r.stderr[-1000:])
    print("\nALL CHECKS PASSED" if not failed else f"\nFAILED: {failed}")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
