"""Dependency-free test runner (no pytest needed), same style as SpecProof."""
import sys
import traceback


class Suite:
    def __init__(self, title):
        self.title = title
        self.tests = []

    def test(self, name):
        def decorator(fn):
            self.tests.append((name, fn))
            return fn
        return decorator

    def run(self, quiet=True):
        failed = []
        for name, fn in self.tests:
            try:
                fn()
            except AssertionError as e:
                failed.append((name, f"assertion failed: {e}"))
            except Exception as e:
                failed.append((name, f"{type(e).__name__}: {e}\n{traceback.format_exc()}"))
        passed = len(self.tests) - len(failed)
        print(f"{self.title}: {passed} passed, {len(failed)} failed (of {len(self.tests)})")
        for name, msg in failed:
            print(f"\n--- FAILED: {name} ---\n{msg}")
        return 1 if failed else 0


def main(suite):
    sys.exit(suite.run())
