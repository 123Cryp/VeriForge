"""
Test harness shared by every suite: loads the contract (source or deploy
build) against the stub SDK, and models a chain with a controllable clock and
transactional rollback (a transaction that raises leaves no state change,
exactly as on GenVM).

    VF_MODULE=veriforge_deploy python3 tests/test_veriforge.py

runs a suite against the mechanically derived deploy artifact instead.
"""
import copy
import datetime
import importlib
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)
sys.path.insert(0, os.environ.get("VF_CONTRACT_DIR") or os.path.join(ROOT, "contracts"))
sys.path.insert(0, os.path.join(ROOT, "tools"))

import genlayer_stub  # noqa: E402

genlayer_stub.install()
MODULE_NAME = os.environ.get("VF_MODULE", "veriforge")
vf = importlib.import_module(MODULE_NAME)
gl = genlayer_stub.gl

SUBMITTER = genlayer_stub.Address("0x00000000000000000000000000000000000000A1")
OTHER = genlayer_stub.Address("0x00000000000000000000000000000000000000B2")
CHALLENGER = genlayer_stub.Address("0x00000000000000000000000000000000000000C3")
START = datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc)

NondetConsensusError = genlayer_stub.NondetConsensusError


class Chain:
    def __init__(self):
        genlayer_stub.reset()
        self.c = vf.VeriForge()
        self.now = START
        self.txs = 0
        vf._now_iso = lambda: self.now.isoformat()

    def advance(self, seconds):
        self.now = self.now + datetime.timedelta(seconds=seconds)

    def snapshot(self):
        return copy.deepcopy(self.c.__dict__)

    def tx(self, sender, method, *args):
        """Runs a write method as `sender`. Any exception rolls back all state."""
        vf._now_iso = lambda: self.now.isoformat()
        before = self.snapshot()
        gl.message.sender_address = sender
        try:
            result = getattr(self.c, method)(*args)
        except BaseException:
            self.c.__dict__.clear()
            self.c.__dict__.update(before)
            raise
        self.txs += 1
        return result

    def view(self, method, *args):
        vf._now_iso = lambda: self.now.isoformat()
        before = self.snapshot()
        result = getattr(self.c, method)(*args)
        assert self.c.__dict__.keys() == before.keys()
        assert self.snapshot() == before, f"view {method} mutated state"
        return result


def expect_raises(fn, fragment=None, exc=Exception):
    try:
        fn()
    except exc as e:
        if fragment is not None and fragment not in str(e):
            raise AssertionError(f"raised {type(e).__name__}: {e!s} (expected to contain {fragment!r})")
        return e
    raise AssertionError(f"expected an exception containing {fragment!r}, none raised")
