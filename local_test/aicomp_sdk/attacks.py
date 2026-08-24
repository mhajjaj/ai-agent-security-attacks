"""Local MOCK of aicomp_sdk.attacks. Mirrors the names attack.py imports and the
real dataclass fields (aicomp_sdk 3.1.2 attacks/contracts.py).

Real behavior is defined by the competition; this stub only lets us run the
algorithm's control flow locally.
"""


class AttackAlgorithmBase:
    """Base class the submission inherits from (config kwarg, no behavior)."""

    def __init__(self, config=None):
        self.config = dict(config or {})


class AttackCandidate:
    """A replayable finding: a tuple of user messages."""

    def __init__(self, user_messages):
        self.user_messages = tuple(user_messages)

    @classmethod
    def from_messages(cls, user_messages):
        return cls(user_messages=tuple(user_messages))

    def __repr__(self):
        return f"AttackCandidate(user_messages={self.user_messages!r})"


class AttackRunConfig:
    """Run configuration passed to AttackAlgorithm.run() (real default fields)."""

    def __init__(self, time_budget_s=30.0, max_steps=10 ** 9, max_tool_hops=8):
        self.time_budget_s = time_budget_s
        self.max_steps = max_steps
        self.max_tool_hops = max_tool_hops
