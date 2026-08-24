"""Local MOCK of aicomp_sdk.attacks. Mirrors the names attack.py imports.

Real behavior is defined by the competition; this stub only lets us run the
algorithm's control flow locally.
"""


class AttackAlgorithmBase:
    """Base class the submission inherits from (no behavior in the mock)."""
    pass


class AttackCandidate:
    """A replayable finding: a tuple of user messages."""

    def __init__(self, user_messages):
        self.user_messages = tuple(user_messages)

    def __repr__(self):
        return f"AttackCandidate(user_messages={self.user_messages!r})"


class AttackRunConfig:
    """Run configuration passed to AttackAlgorithm.run()."""

    def __init__(self, time_budget_s):
        self.time_budget_s = time_budget_s
