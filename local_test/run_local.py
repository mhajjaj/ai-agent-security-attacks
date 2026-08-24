"""Local dry-run for attack.py against the MOCK SDK.

Usage:
    python3 local_test/run_local.py

Proves the algorithm imports, runs all four phases without crashing, respects
the budget/dedup logic, and returns AttackCandidate objects. It does NOT prove
real attack efficacy — the mock agent is permissive by construction.
"""

import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
sys.path.insert(0, HERE)   # resolves `import aicomp_sdk` -> the local mock
sys.path.insert(0, REPO)   # resolves `import attack` -> repo-root attack.py

from mock_env import MockEnv                       # noqa: E402
from aicomp_sdk.attacks import AttackRunConfig      # noqa: E402
import attack                                        # noqa: E402


def main():
    algo = attack.AttackAlgorithm()
    env = MockEnv()
    # Mock interact() is instant, so a large budget just lets every pool drain;
    # time is never the limiter here (that path is exercised on Kaggle).
    config = AttackRunConfig(time_budget_s=100_000)

    findings = algo.run(env, config)

    print("\n" + "=" * 60)
    print(f"RETURNED {len(findings)} unique-cell candidates")
    print("=" * 60)
    for f in findings[:8]:
        print("  ", f.user_messages)
    if len(findings) > 8:
        print(f"   ... and {len(findings) - 8} more")

    # Minimal sanity assertions.
    assert isinstance(findings, list), "run() must return a list"
    assert all(hasattr(f, "user_messages") for f in findings), "bad candidate"
    sigs = {tuple(f.user_messages) for f in findings}
    assert len(sigs) == len(findings), "duplicate candidates leaked through"
    print("\nSMOKE TEST PASSED ✅")


if __name__ == "__main__":
    main()
