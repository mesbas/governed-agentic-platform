"""Governed runtime: the control plane every agent action passes through.

Order of checks for each request:
  1. kill switch      -> deny everything while engaged
  2. tool registry    -> unknown tools are denied
  3. action budget    -> per-agent cap on executed side-effecting actions
  4. policy engine    -> allow / require_approval / deny
  5. approval queue   -> a different principal must approve (separation of duties)
  6. execution        -> result or failure recorded
Every step is written to the audit log.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from typing import Any, Callable

from .actions import ActionRequest, ActionResult, RiskTier
from .approvals import ApprovalQueue
from .audit import AuditLog
from .policy import PolicyEngine, Verdict


@dataclass
class Tool:
    name: str
    fn: Callable[..., Any]
    risk: RiskTier
    description: str = ""


class GovernedRuntime:
    def __init__(
        self,
        policy: PolicyEngine,
        audit: AuditLog | None = None,
        approvals: ApprovalQueue | None = None,
        budget_per_agent: int | None = None,
        separation_of_duties: bool = True,
    ):
        self.policy = policy
        self.audit = audit or AuditLog()
        self.approvals = approvals or ApprovalQueue()
        self.budget_per_agent = budget_per_agent
        self.separation_of_duties = separation_of_duties
        self.tools: dict[str, Tool] = {}
        self._executed: Counter[str] = Counter()
        self._kill_switch: dict[str, str] | None = None

    # ------------------------------------------------------------------ setup
    def register(self, name: str, fn: Callable[..., Any], risk: RiskTier, description: str = "") -> None:
        self.tools[name] = Tool(name, fn, risk, description)
        self.audit.append("tool_registered", {"tool": name, "risk": risk.name})

    def tool(self, risk: RiskTier, name: str | None = None, description: str = ""):
        """Decorator form of `register`."""

        def wrap(fn: Callable[..., Any]) -> Callable[..., Any]:
            self.register(name or fn.__name__, fn, risk, description or (fn.__doc__ or "").strip())
            return fn

        return wrap

    # ------------------------------------------------------------ kill switch
    @property
    def kill_switch_engaged(self) -> bool:
        return self._kill_switch is not None

    def engage_kill_switch(self, by: str, reason: str) -> None:
        self._kill_switch = {"by": by, "reason": reason}
        self.audit.append("kill_switch_engaged", {"by": by, "reason": reason})

    def release_kill_switch(self, by: str) -> None:
        self._kill_switch = None
        self.audit.append("kill_switch_released", {"by": by})

    # --------------------------------------------------------------- requests
    def submit(self, request: ActionRequest) -> ActionResult:
        rid = request.request_id
        self.audit.append("requested", request.to_dict())

        if self.kill_switch_engaged:
            return self._deny(rid, "kill switch engaged")

        tool = self.tools.get(request.tool)
        if tool is None:
            return self._deny(rid, f"unknown tool '{request.tool}'")

        if (
            self.budget_per_agent is not None
            and tool.risk > RiskTier.READ
            and self._executed[request.agent_id] >= self.budget_per_agent
        ):
            return self._deny(rid, f"action budget of {self.budget_per_agent} exhausted for {request.agent_id}")

        decision = self.policy.evaluate(request, tool.risk)
        self.audit.append(
            "policy_decision",
            {"request_id": rid, "verdict": decision.verdict.value, "rule": decision.rule, "reason": decision.reason},
        )

        if decision.verdict == Verdict.DENY:
            return self._deny(rid, decision.reason)
        if decision.verdict == Verdict.REQUIRE_APPROVAL:
            self.approvals.submit(request, decision)
            self.audit.append("approval_requested", {"request_id": rid, "rule": decision.rule})
            return ActionResult(rid, "pending_approval", reason=decision.reason)
        return self._execute(request, tool)

    def approve(self, request_id: str, approver: str, note: str = "") -> ActionResult:
        pending = self.approvals.get(request_id)
        if self.separation_of_duties and approver == pending.request.agent_id:
            self.audit.append("approval_refused", {"request_id": request_id, "approver": approver, "reason": "self-approval"})
            raise PermissionError("separation of duties: requester cannot approve its own action")
        self.approvals.remove(request_id)
        self.audit.append("approved", {"request_id": request_id, "approver": approver, "note": note})
        if self.kill_switch_engaged:
            return self._deny(request_id, "kill switch engaged")
        tool = self.tools[pending.request.tool]
        return self._execute(pending.request, tool)

    def reject(self, request_id: str, approver: str, reason: str) -> ActionResult:
        self.approvals.remove(request_id)
        self.audit.append("rejected", {"request_id": request_id, "approver": approver, "reason": reason})
        return ActionResult(request_id, "rejected", reason=reason)

    # ---------------------------------------------------------------- helpers
    def _deny(self, request_id: str, reason: str) -> ActionResult:
        self.audit.append("denied", {"request_id": request_id, "reason": reason})
        return ActionResult(request_id, "denied", reason=reason)

    def _execute(self, request: ActionRequest, tool: Tool) -> ActionResult:
        rid = request.request_id
        try:
            output = tool.fn(**request.params)
        except Exception as exc:  # recorded, never swallowed silently
            self.audit.append("failed", {"request_id": rid, "error": f"{type(exc).__name__}: {exc}"})
            return ActionResult(rid, "failed", reason=str(exc))
        if tool.risk > RiskTier.READ:
            self._executed[request.agent_id] += 1
        self.audit.append("executed", {"request_id": rid, "tool": tool.name, "output": output})
        return ActionResult(rid, "executed", output=output)
