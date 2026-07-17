"""Ports: the interfaces the application layer depends on.

Every port here is a ``typing.Protocol`` — structural typing, not
inheritance. Adapters satisfy a port by shape, not by subclassing,
which keeps ``adapters/`` free to depend on third-party SDKs without
those dependencies leaking into ``domain`` or ``application``.

This package is the hexagon's boundary: ``application`` imports these
protocols and nothing else; ``adapters`` implement them and depend
inward on ``domain``, never on ``application``.
"""

from .attack_generator import AttackGenerator
from .evaluator import Evaluator
from .reporter import Reporter
from .storage import FindingsStorage
from .target import Target

__all__ = [
    "AttackGenerator",
    "Evaluator",
    "Reporter",
    "FindingsStorage",
    "Target",
]
