"""RBAC, deny-overrides ABAC, and relationship-based authorization."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable


@dataclass
class RBAC:
    roles: dict[str, set[str]] = field(default_factory=dict)
    parents: dict[str, set[str]] = field(default_factory=dict)
    assignments: dict[str, set[str]] = field(default_factory=dict)

    def add_role(
        self,
        role: str,
        permissions: set[str],
        *,
        parents: set[str] | None = None,
    ) -> None:
        self.roles[role] = set(permissions)
        self.parents[role] = set() if parents is None else set(parents)

    def assign(self, user: str, role: str) -> None:
        if role not in self.roles:
            raise KeyError(f"unknown role: {role}")
        self.assignments.setdefault(user, set()).add(role)

    def _permissions(self, role: str, seen: set[str]) -> set[str]:
        if role in seen:
            return set()
        seen.add(role)
        result = set(self.roles.get(role, set()))
        for parent in self.parents.get(role, set()):
            result |= self._permissions(parent, seen)
        return result

    def allowed(self, user: str, permission: str) -> bool:
        return any(
            permission in self._permissions(role, set())
            for role in self.assignments.get(user, set())
        )


Condition = Callable[[dict[str, Any], dict[str, Any], dict[str, Any]], bool]


@dataclass(frozen=True)
class Policy:
    effect: str
    action: str
    condition: Condition
    name: str = "unnamed"


@dataclass
class ABAC:
    policies: list[Policy] = field(default_factory=list)

    def decide(
        self,
        *,
        subject: dict[str, Any],
        resource: dict[str, Any],
        context: dict[str, Any],
        action: str,
    ) -> tuple[bool, list[str]]:
        matched = [
            policy
            for policy in self.policies
            if policy.action in {action, "*"}
            and policy.condition(subject, resource, context)
        ]
        reasons = [f"{policy.effect}:{policy.name}" for policy in matched]
        if any(policy.effect == "deny" for policy in matched):
            return False, reasons
        return any(policy.effect == "allow" for policy in matched), reasons


@dataclass(frozen=True)
class Tuple:
    resource: str
    relation: str
    subject: str


@dataclass
class ReBAC:
    tuples: set[Tuple] = field(default_factory=set)

    def add(self, resource: str, relation: str, subject: str) -> None:
        self.tuples.add(Tuple(resource, relation, subject))

    def check(
        self,
        user: str,
        resource: str,
        relation: str,
        *,
        depth: int = 12,
        seen: set[tuple[str, str, str]] | None = None,
    ) -> bool:
        if depth <= 0:
            return False
        visited = set() if seen is None else seen
        key = (user, resource, relation)
        if key in visited:
            return False
        visited.add(key)
        for item in self.tuples:
            if item.resource != resource or item.relation != relation:
                continue
            if item.subject == f"user:{user}":
                return True
            if "#" in item.subject:
                parent_resource, parent_relation = item.subject.split("#", 1)
                if self.check(
                    user,
                    parent_resource,
                    parent_relation,
                    depth=depth - 1,
                    seen=visited,
                ):
                    return True
        return False

    def list_objects(self, user: str, relation: str) -> list[str]:
        resources = {item.resource for item in self.tuples if item.relation == relation}
        return sorted(
            resource for resource in resources if self.check(user, resource, relation)
        )

    def expand(self, resource: str, relation: str) -> list[str]:
        return sorted(
            item.subject
            for item in self.tuples
            if item.resource == resource and item.relation == relation
        )

