"""Attribute-Based Access Control: a small policy engine.

ABAC evaluates rules over four attribute bags:

    subject     who is asking      (roles, department, clearance, mfa)
    resource    what they want     (owner, classification, amount)
    action      what they'd do     (read, approve, delete)
    environment context            (time, source IP, device posture)

The combining algorithm matters more than the rules. We use
**deny-overrides**, the same choice XACML calls `deny-overrides` and that AWS
IAM uses: any applicable DENY wins, no matter how many ALLOWs there are, and
the default with no applicable policy is DENY (default-deny).

Both halves are load-bearing:

* Default-deny means a resource nobody wrote a policy for is closed, not
  open. Default-allow systems fail open on every gap, and the gaps are
  invisible until someone finds one.
* Deny-overrides means a targeted exception ("contractors may never read
  salary data") cannot be undone by a broad grant somewhere else. Under
  allow-overrides you can never write a reliable prohibition.

The known cost of ABAC is that "why was this denied?" gets hard, so every
decision here carries the list of policies that fired.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable


class Effect(Enum):
    ALLOW = "allow"
    DENY = "deny"


@dataclass
class Request:
    """One access request, fully described."""

    subject: dict[str, Any] = field(default_factory=dict)
    resource: dict[str, Any] = field(default_factory=dict)
    action: str = ""
    environment: dict[str, Any] = field(default_factory=dict)


Condition = Callable[[Request], bool]


@dataclass
class Policy:
    """One rule. `target` decides applicability; `condition` decides the rest."""

    name: str
    effect: Effect
    actions: list[str] = field(default_factory=lambda: ["*"])
    resource_types: list[str] = field(default_factory=lambda: ["*"])
    condition: Condition | None = None
    description: str = ""

    def applies_to(self, request: Request) -> bool:
        action_ok = "*" in self.actions or request.action in self.actions
        resource_type = request.resource.get("type", "")
        type_ok = "*" in self.resource_types or resource_type in self.resource_types
        return action_ok and type_ok

    def evaluate(self, request: Request) -> bool:
        """True if this policy fires. A condition that raises counts as
        not-applicable rather than allow -- an attribute-lookup error must
        never become a grant."""
        if self.condition is None:
            return True
        try:
            return bool(self.condition(request))
        except Exception:  # noqa: BLE001
            return False


@dataclass
class PolicyDecision:
    effect: Effect
    reason: str
    matched: list[str] = field(default_factory=list)

    @property
    def allowed(self) -> bool:
        return self.effect is Effect.ALLOW

    def __bool__(self) -> bool:
        return self.allowed


class ABAC:
    """Deny-overrides, default-deny policy engine."""

    def __init__(self, policies: list[Policy] | None = None) -> None:
        self.policies = list(policies or [])

    def add(self, policy: Policy) -> "ABAC":
        self.policies.append(policy)
        return self

    def evaluate(self, request: Request) -> PolicyDecision:
        allows: list[str] = []
        denies: list[str] = []

        for policy in self.policies:
            if not policy.applies_to(request):
                continue
            if not policy.evaluate(request):
                continue
            (denies if policy.effect is Effect.DENY else allows).append(policy.name)

        if denies:
            # Deny wins regardless of how many allows matched.
            return PolicyDecision(
                Effect.DENY, f"explicit deny from {denies}", matched=denies + allows
            )
        if allows:
            return PolicyDecision(Effect.ALLOW, f"allowed by {allows}", matched=allows)
        return PolicyDecision(Effect.DENY, "default deny: no policy matched", matched=[])

    def can(self, request: Request) -> bool:
        return self.evaluate(request).allowed


# --- condition combinators --------------------------------------------------
# Small, composable, and testable in isolation. A policy language you cannot
# unit test is a policy language you cannot trust.


def all_of(*conditions: Condition) -> Condition:
    return lambda request: all(c(request) for c in conditions)


def any_of(*conditions: Condition) -> Condition:
    return lambda request: any(c(request) for c in conditions)


def negate(condition: Condition) -> Condition:
    return lambda request: not condition(request)


def _bag(request: Request, name: str) -> dict[str, Any]:
    return {
        "subject": request.subject,
        "resource": request.resource,
        "environment": request.environment,
    }[name]


def attr_equals(bag: str, key: str, value: Any) -> Condition:
    return lambda request: _bag(request, bag).get(key) == value


def attr_in(bag: str, key: str, values: list[Any]) -> Condition:
    return lambda request: _bag(request, bag).get(key) in values


def attr_contains(bag: str, key: str, value: Any) -> Condition:
    return lambda request: value in (_bag(request, bag).get(key) or [])


def attr_lte(bag: str, key: str, limit: float) -> Condition:
    def check(request: Request) -> bool:
        actual = _bag(request, bag).get(key)
        return isinstance(actual, (int, float)) and actual <= limit

    return check


def subject_matches_resource_owner(
    subject_key: str = "sub", resource_key: str = "owner"
) -> Condition:
    """The "their own" condition RBAC cannot express.

    This single combinator is the difference between `orders:read` meaning
    "read orders" and meaning "read your orders".
    """

    def check(request: Request) -> bool:
        from ..util.ct import constant_time_equals

        subject = request.subject.get(subject_key)
        owner = request.resource.get(resource_key)
        return bool(subject) and bool(owner) and constant_time_equals(str(subject), str(owner))

    return check


def time_between(start_hour: int, end_hour: int, key: str = "hour") -> Condition:
    """Business-hours condition. Note that the caller supplies the hour --
    the engine must not read the clock itself, or the policy becomes
    untestable and timezone-dependent in ways nobody notices until an
    overnight batch job starts failing."""

    def check(request: Request) -> bool:
        hour = request.environment.get(key)
        return isinstance(hour, int) and start_hour <= hour < end_hour

    return check


def ip_in_cidr(cidr: str, key: str = "ip") -> Condition:
    """Source-network condition.

    A caution worth writing down: IP is a weak signal. It is spoofable at the
    edge, shared behind NAT, and trivially forged in an `X-Forwarded-For`
    header if your proxy chain is misconfigured. Use it to narrow, never as
    the only control.
    """
    import ipaddress

    network = ipaddress.ip_network(cidr)

    def check(request: Request) -> bool:
        raw = request.environment.get(key)
        if not raw:
            return False
        try:
            return ipaddress.ip_address(raw) in network
        except ValueError:
            return False

    return check
