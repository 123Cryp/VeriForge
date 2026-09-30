"""
Offline stub of the GenLayer SDK surface that contracts/veriforge.py uses.
It is NOT GenVM. It does not run real LLMs or a real network. What it does
model, on purpose, and more strictly than the SpecProof stub:

  - run_nondet_unsafe runs the leader once and then EVERY validator, each
    with its own independent LLM call, and applies a strict-majority rule
  - strict_eq re-executes the function for every validator and requires an
    identical value (so a page that changes between fetches breaks consensus)
  - an exception raised by a validator counts as disagreement
  - the leader value reaches validator_fn as an object with `.calldata`
  - a hook to replace the leader's result by a forged one (malicious leader)
  - TreeMap / DynArray fields are zero-initialised before __init__

Transactional rollback on exceptions is implemented by tests/harness.py.
"""
import sys
import types
import dataclasses


class Address(str):
    pass


class u256(int):
    pass


class TreeMap(dict):
    def __class_getitem__(cls, item):
        return cls


class DynArray(list):
    def __class_getitem__(cls, item):
        return cls


def allow_storage(cls):
    return cls


dataclass = dataclasses.dataclass


class Contract:
    def __new__(cls, *args, **kwargs):
        instance = super().__new__(cls)
        for klass in reversed(cls.__mro__):
            for name, annotation in getattr(klass, "__annotations__", {}).items():
                if annotation is TreeMap:
                    object.__setattr__(instance, name, TreeMap())
                elif annotation is DynArray:
                    object.__setattr__(instance, name, DynArray())
        return instance


class _Message:
    def __init__(self):
        self.sender_address = Address("0x00000000000000000000000000000000000000A1")


class NondetConsensusError(Exception):
    pass


class _Return:
    def __init__(self, calldata):
        self.calldata = calldata


class _VM:
    NondetConsensusError = NondetConsensusError
    Return = _Return

    def __init__(self):
        self.validators = 1
        self.validator_runs = 0
        self.rounds = 0
        self._forced = None

    def force_leader_result(self, value):
        """One-shot: the next run_nondet_unsafe uses `value` as the leader's
        result instead of running leader_fn (a malicious leader)."""
        self._forced = (value,)

    def run_nondet(self, leader_fn, validator_fn):
        return self.run_nondet_unsafe(leader_fn, validator_fn)

    def run_nondet_unsafe(self, leader_fn, validator_fn):
        nd = gl.nondet
        self.rounds += 1
        nd._enter("leader", 0)
        try:
            if self._forced is not None:
                leader_result = self._forced[0]
                self._forced = None
            else:
                leader_result = leader_fn()
        finally:
            nd._exit()
        agree = 0
        for i in range(self.validators):
            nd._enter("validator", i)
            try:
                ok = validator_fn(_Return(leader_result))
            except Exception:
                ok = False
            finally:
                nd._exit()
            self.validator_runs += 1
            if ok is True:
                agree += 1
        if agree * 2 <= self.validators:
            raise NondetConsensusError(f"validators rejected the leader result ({agree}/{self.validators} agreed)")
        return leader_result


class _EqPrinciple:
    def __init__(self):
        self._force_fail_once = False

    def force_fail_next(self):
        self._force_fail_once = True

    def strict_eq(self, fn):
        if self._force_fail_once:
            self._force_fail_once = False
            raise NondetConsensusError("forced disagreement (test)")
        nd = gl.nondet
        nd._enter("leader", 0)
        try:
            leader_value = fn()
        finally:
            nd._exit()
        agree = 0
        for i in range(gl.vm.validators):
            nd._enter("validator", i)
            try:
                same = fn() == leader_value
            except Exception:
                same = False
            finally:
                nd._exit()
            if same:
                agree += 1
        if agree * 2 <= gl.vm.validators:
            raise NondetConsensusError("strict_eq: validators saw a different value")
        return leader_value


class _Response:
    def __init__(self, status, body):
        self.status = status
        self.body = body


class Sequence:
    """A page whose body changes on every fetch (a source that moves)."""

    def __init__(self, *bodies):
        self.bodies = list(bodies)
        self.calls = 0

    def next(self):
        body = self.bodies[min(self.calls, len(self.bodies) - 1)]
        self.calls += 1
        return body


class _Web:
    def __init__(self):
        self.pages = {}
        self.statuses = {}
        self.raw = {}
        self.calls = []

    def _body(self, url):
        page = self.pages[url]
        return page.next() if isinstance(page, Sequence) else page

    def render(self, url, mode="text"):
        self.calls.append(("render", url))
        if url not in self.pages:
            raise Exception(f"[stub] no page registered for url: {url}")
        text = self._body(url)
        if mode != "text":
            return text
        out = []
        for line in text.split("\n"):
            while "  " in line:
                line = line.replace("  ", " ")
            out.append(line.rstrip(" "))
        return "\n".join(out)

    def get(self, url, headers=None):
        self.calls.append(("get", url))
        if url not in self.pages and url not in self.raw:
            raise Exception(f"[stub] no page registered for url: {url}")
        body = self.raw[url] if url in self.raw else self._body(url).encode("utf-8")
        return _Response(self.statuses.get(url, 200), body)


class _Nondet:
    def __init__(self):
        self.web = _Web()
        self.llm = None  # callable(prompt, mode, index) -> parsed JSON object
        self.prompts = []
        self.mode = None
        self.index = 0
        self._stack = []

    def _enter(self, mode, index):
        self._stack.append((self.mode, self.index))
        self.mode, self.index = mode, index

    def _exit(self):
        self.mode, self.index = self._stack.pop()

    def exec_prompt(self, prompt, response_format=None, images=None):
        self.prompts.append(prompt)
        if self.llm is None:
            raise Exception("[stub] exec_prompt called but no LLM handler is installed")
        return self.llm(prompt, self.mode, self.index)


def _write(fn):
    fn._gl_kind = "write"
    return fn


def _view(fn):
    fn._gl_kind = "view"
    return fn


class _Public:
    write = staticmethod(_write)
    view = staticmethod(_view)


class _GL:
    def __init__(self):
        self.Contract = Contract
        self.message = _Message()
        self.vm = _VM()
        self.eq_principle = _EqPrinciple()
        self.nondet = _Nondet()
        self.public = _Public()


gl = _GL()


def install():
    module = types.ModuleType("genlayer")
    module.gl = gl
    module.Address = Address
    module.u256 = u256
    module.TreeMap = TreeMap
    module.DynArray = DynArray
    module.allow_storage = allow_storage
    module.dataclass = dataclass
    module.Contract = Contract
    module.__all__ = ["gl", "Address", "u256", "TreeMap", "DynArray", "allow_storage", "dataclass", "Contract"]
    sys.modules["genlayer"] = module
    return module


def reset():
    gl.message.sender_address = Address("0x00000000000000000000000000000000000000A1")
    gl.eq_principle._force_fail_once = False
    gl.nondet.web.pages.clear()
    gl.nondet.web.statuses.clear()
    gl.nondet.web.raw.clear()
    gl.nondet.web.calls.clear()
    gl.nondet.llm = None
    gl.nondet.prompts.clear()
    gl.nondet.mode = None
    gl.nondet.index = 0
    gl.nondet._stack.clear()
    gl.vm.validators = 1
    gl.vm.validator_runs = 0
    gl.vm.rounds = 0
    gl.vm._forced = None
