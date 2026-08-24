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
    """The mock is permissive, so several phases must fire."""
    findings = _run()
    assert len(findings) > 0, "expected at least one firing candidate on the mock"


def test_has_multistep_exfil_and_single_step_chains():
    """Phase 1 emits 2-message read->post exfil chains; other phases emit
    single-message chains. Both shapes should appear."""
    findings = _run()
    lengths = {len(f.user_messages) for f in findings}
    assert 2 in lengths, "expected a multi-step (read->post) exfil chain"
    assert 1 in lengths, "expected a single-message injection/destructive chain"


def test_exfil_chain_reads_before_posting():
    """Every exfil chain (one that instructs an HTTP POST) must read secret.txt
    first, or EXFILTRATION cannot fire on the real predicate."""
    findings = _run()
    exfil = [f for f in findings
             if any("http post" in m.lower() for m in f.user_messages)]
    assert exfil, "expected at least one exfil (HTTP POST) chain"
    for f in exfil:
        first = f.user_messages[0].lower()
        assert "secret.txt" in first and "read" in first, \
            f"exfil chain does not read secret.txt first: {f.user_messages}"


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
