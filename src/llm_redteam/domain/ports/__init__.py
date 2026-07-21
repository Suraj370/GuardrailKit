"""Ports: the interfaces the application layer depends on.

The five core campaign-flow interfaces — ``AttackGenerator``,
``Target``, ``Evaluator``, ``Policy``, ``Reporter`` — are ``abc.ABC``
subclasses: each declares exactly one abstract responsibility (generate
attacks, execute one attack, grade one result, enforce a safety rule,
render a report) and adapters implement a port by explicit subclassing,
not by structural shape. This makes "does this class satisfy the
interface" checkable both at class-definition time (missing an
``@abstractmethod`` override raises ``TypeError`` on instantiation) and
via ``isinstance``.

``FindingsStorage`` remains a ``typing.Protocol`` — it is a supporting
persistence concern rather than a step in the Campaign -> Vulnerability
-> AttackGenerator -> Target -> Evaluator / Policy -> Reporter flow, and
structural typing is a reasonable fit for a two-method storage-backend
contract.

This package is the hexagon's boundary: ``application`` imports these
interfaces and nothing else; ``adapters`` implement them and depend
inward on ``domain``, never on ``application``.
"""

from .attack_generator import AttackGenerator
from .evaluator import Evaluator
from .policy import Policy
from .reporter import Reporter
from .storage import FindingsStorage
from .target import Target

__all__ = [
    "AttackGenerator",
    "Evaluator",
    "Policy",
    "Reporter",
    "FindingsStorage",
    "Target",
]
