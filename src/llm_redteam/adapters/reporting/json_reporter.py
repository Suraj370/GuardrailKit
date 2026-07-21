"""JSONReporter: serializes a campaign result to a JSON file.

Pure serialization, same spirit as :mod:`.console_reporter` — no
grading or business logic. Useful as machine-readable output for CI
pipelines or downstream tooling.
"""

from __future__ import annotations

import dataclasses
import json
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any

from llm_redteam.domain.models import Report
from llm_redteam.domain.ports import Reporter
from llm_redteam.plugins import REPORTERS


def _json_default(value: Any) -> Any:
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        return dataclasses.asdict(value)
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, datetime):
        return value.isoformat()
    raise TypeError(f"object of type {type(value).__name__} is not JSON serializable")


@REPORTERS.register("json")
class JSONReporter(Reporter):
    """Writes the campaign report to ``output_path`` as JSON."""

    name = "json"

    def __init__(self, output_path: str) -> None:
        self._output_path = Path(output_path)

    def report(self, report: Report) -> None:
        self._output_path.parent.mkdir(parents=True, exist_ok=True)
        with self._output_path.open("w", encoding="utf-8") as fh:
            json.dump(dataclasses.asdict(report), fh, default=_json_default, indent=2)
