"""Core action types shared by every layer of the platform."""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import IntEnum
from typing import Any


class RiskTier(IntEnum):
    """How much harm an action can do if it is wrong."""

    READ = 0  # read-only lookups, no side effects
    LOW = 1  # internal, easily reversible side effects
    MEDIUM = 2  # customer-visible or bounded financial impact
    HIGH = 3  # irreversible, regulated, or large financial impact


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class ActionRequest:
    """An agent's request to invoke a tool with parameters."""

    agent_id: str
    tool: str
    params: dict[str, Any]
    justification: str = ""
    request_id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    created_at: str = field(default_factory=_now)

    def to_dict(self) -> dict[str, Any]:
        return {
            "request_id": self.request_id,
            "agent_id": self.agent_id,
            "tool": self.tool,
            "params": self.params,
            "justification": self.justification,
            "created_at": self.created_at,
        }


@dataclass
class ActionResult:
    """Outcome of a request: executed, denied, pending_approval, rejected or failed."""

    request_id: str
    status: str
    output: Any = None
    reason: str = ""

    @property
    def ok(self) -> bool:
        return self.status == "executed"
