"""Demo: a customer-support agent that can look up orders, email and refund.

Run with:  python -m gap.demo
"""

from __future__ import annotations

from .actions import ActionRequest, RiskTier
from .policy import PolicyEngine, PolicyRule, Verdict
from .runtime import GovernedRuntime

ORDERS = {"A100": {"customer": "c-17", "total": 42.0}, "A200": {"customer": "c-22", "total": 640.0}}


def build_runtime() -> GovernedRuntime:
    policy = PolicyEngine(
        [
            PolicyRule("reads-allowed", Verdict.ALLOW, tools={"lookup_order"}),
            PolicyRule("emails-allowed", Verdict.ALLOW, tools={"send_email"}),
            PolicyRule(
                "small-refunds",
                Verdict.ALLOW,
                tools={"issue_refund"},
                condition=lambda r: r.params.get("amount", 0) <= 100,
                description="refunds up to $100 are pre-approved",
            ),
            PolicyRule(
                "large-refunds-need-approval",
                Verdict.REQUIRE_APPROVAL,
                tools={"issue_refund"},
                condition=lambda r: r.params.get("amount", 0) > 100,
                description="refunds over $100 need a human approver",
            ),
            PolicyRule(
                "no-irreversible-actions",
                Verdict.DENY,
                min_risk=RiskTier.HIGH,
                description="agents may not take HIGH-risk actions",
            ),
        ]
    )
    rt = GovernedRuntime(policy, budget_per_agent=10)

    @rt.tool(RiskTier.READ)
    def lookup_order(order_id: str) -> dict:
        """Look up an order."""
        return ORDERS[order_id]

    @rt.tool(RiskTier.LOW)
    def send_email(to: str, body: str) -> str:
        """Send an email to a customer."""
        return f"email queued to {to}"

    @rt.tool(RiskTier.MEDIUM)
    def issue_refund(order_id: str, amount: float) -> str:
        """Refund part or all of an order."""
        if amount > ORDERS[order_id]["total"]:
            raise ValueError("refund exceeds order total")
        return f"refunded ${amount:.2f} on {order_id}"

    @rt.tool(RiskTier.HIGH)
    def delete_customer(customer_id: str) -> str:
        """Permanently delete a customer record."""
        return f"deleted {customer_id}"

    return rt


def main() -> None:
    rt = build_runtime()
    agent = "support-agent-1"

    def show(label: str, result) -> None:
        print(f"{label:<42} -> {result.status:<17} {result.output or result.reason}")

    show("lookup order A100", rt.submit(ActionRequest(agent, "lookup_order", {"order_id": "A100"})))
    show("refund $25 on A100", rt.submit(ActionRequest(agent, "issue_refund", {"order_id": "A100", "amount": 25})))
    big = rt.submit(ActionRequest(agent, "issue_refund", {"order_id": "A200", "amount": 300}, "damaged item"))
    show("refund $300 on A200", big)
    show("  ...approved by supervisor", rt.approve(big.request_id, approver="supervisor-maria"))
    show("refund $99 on A100 (exceeds $42 total)",rt.submit(ActionRequest(agent, "issue_refund", {"order_id": "A100", "amount": 99})))
    show("delete customer c-17", rt.submit(ActionRequest(agent, "delete_customer", {"customer_id": "c-17"})))

    rt.engage_kill_switch(by="oncall-sre", reason="anomalous refund volume")
    show("email while kill switch engaged", rt.submit(ActionRequest(agent, "send_email", {"to": "c-17", "body": "hi"})))

    print(f"\naudit entries: {len(rt.audit.entries)}, chain valid: {rt.audit.verify()}")


if __name__ == "__main__":
    main()
