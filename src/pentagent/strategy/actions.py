"""Action = a ranked proposal for the next tool invocation."""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any


class ActionPriority(IntEnum):
    low = 1
    normal = 5
    high = 8
    critical = 10


@dataclass
class Action:
    tool: str
    params: dict[str, Any] = field(default_factory=dict)
    reason: str = ""
    expected_signal: str = ""
    priority: int = ActionPriority.normal
    # Parser context — passed through to parse_for() so parsers can know
    # which webapp/endpoint this tool run belongs to.
    parser_context: dict[str, Any] = field(default_factory=dict)

    def dedup_key(self) -> str:
        import hashlib
        import json
        blob = json.dumps({"tool": self.tool, "params": self.params}, sort_keys=True, default=str)
        return hashlib.sha256(blob.encode("utf-8")).hexdigest()
