"""Human-in-the-loop approval queue."""

from __future__ import annotations

from dataclasses import dataclass

from .actions import ActionRequest
from .policy import PolicyDecision


@dataclass
class PendingApproval:
    request: ActionRequest
    decision: PolicyDecision


class ApprovalQueue:
    def __init__(self) -> None:
        self._pending: dict[str, PendingApproval] = {}

    def submit(self, request: ActionRequest, decision: PolicyDecision) -> None:
        self._pending[request.request_id] = PendingApproval(request, decision)

    def pending(self) -> list[PendingApproval]:
        return list(self._pending.values())

    def get(self, request_id: str) -> PendingApproval:
        if request_id not in self._pending:
            raise KeyError(f"no pending approval for request {request_id}")
        return self._pending[request_id]

    def remove(self, request_id: str) -> PendingApproval:
        item = self.get(request_id)
        del self._pending[request_id]
        return item

    def __len__(self) -> int:
        return len(self._pending)
