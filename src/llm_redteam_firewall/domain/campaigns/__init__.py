"""domain.campaigns: the planning layer between Campaign and ExecutionEngine.

``Campaign`` says *what* to probe. ``AttackCampaign``/``AttackBatch``
say *how the resulting attacks are grouped and intended to run*,
sitting immediately before ``ExecutionEngine`` in the pipeline:

    Campaign -> AttackGenerator -> list[Attack]
             -> AttackCampaign (batches of AttackBatch)
             -> ExecutionEngine

Both types are pure planning data — no scheduler, retry loop, or
concurrency limiter reads their fields yet. See ``.attack_campaign``
and ``.attack_batch`` module docstrings for the rationale.
"""

from .attack_batch import AttackBatch, ExecutionStrategy, RetryPolicy
from .attack_campaign import AttackCampaign

__all__ = [
    "AttackBatch",
    "AttackCampaign",
    "ExecutionStrategy",
    "RetryPolicy",
]
