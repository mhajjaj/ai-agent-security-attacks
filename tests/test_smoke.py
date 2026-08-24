"""Smoke test for attack.py against the local MOCK SDK.

Runs the full AttackAlgorithm end-to-end and asserts the plumbing holds:
imports resolve, all four phases execute without crashing, dedup keeps
candidates unique, and every returned object is a replayable AttackCandidate.

It does NOT prove real attack efficacy — the mock agent is permissive by
construction (see local_test/mock_env.py). A green run means the code works,
not that the attacks will fire on Kaggle.

Runnable two ways:
    python -m pytest tests/test_smoke.py     # if pytest is installed
    python3 tests/test_smoke.py              # zero-dependency fallback
"""

import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_REPO = os.path.dirname(_HERE)
_LOCAL_TEST = os.path.join(_REPO, "local_test")

# Resolve `import aicomp_sdk` / `import mock_env` -> the local mock, and
# `import attack` -> the repo-root submission entrypoint.
for _p in (_LOCAL_TEST, _REPO):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from mock_env import MockEnv                      # noqa: E402
from aicomp_sdk.attacks import AttackRunConfig     # noqa: E402
import attack                                       # noqa: E402


def _run():
    """Run the algorithm against the mock env with an effectively unbounded
    budget (mock interact() is instant, so every pool drains)."""
    algo = attack.AttackAlgorithm()
    env = MockEnv()
    config = AttackRunConfig(time_budget_s=100_000)
    return algo.run(env, config)


def test_returns_list_of_candidates():
    findings = _run()
    assert isinstance(findings, list), "run() must return a list"
    assert all(hasattr(f, "user_messages") for f in findings), \
        "every finding must be an AttackCandidate with user_messages"


def test_candidates_are_deduped():
    findings = _run()
    sigs = {tuple(f.user_messages) for f in findings}
    assert len(sigs) == len(findings), "duplicate candidates leaked through"


def test_finds_something():
    """The mock is permissive, so the exfil/destructive phases must fire."""
    findings = _run()
    assert len(findings) > 0, "expected at least one firing candidate on the mock"


def test_respects_finding_cap():
    findings = _run()
    assert len(findings) <= attack.MAX_FINDINGS, "exceeded MAX_FINDINGS cap"


if __name__ == "__main__":
    # Zero-dependency fallback: run every test_* function in this module.
    _tests = [v for k, v in sorted(globals().items())
              if k.startswith("test_") and callable(v)]
    _failed = 0
    for _t in _tests:
        try:
            _t()
            print(f"  PASS  {_t.__name__}")
        except AssertionError as _e:
            _failed += 1
            print(f"  FAIL  {_t.__name__}: {_e}")
    n = len(_tests)
    print(f"\n{n - _failed}/{n} passed")
    sys.exit(1 if _failed else 0)
