"""Executable parity lab for RBAC, ABAC, ReBAC, Cedar, and Rego.

The Cedar and Rego classes are semantic adapters, not parsers or embedded
policy runtimes.  Their policy source is kept next to the adapter so learners
can compare the real language shape with the small, inspectable evaluator.
Production interoperability belongs in an optional profile, not the
dependency-free core.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
import hashlib
import hmac
import time
from typing import Protocol

from .abac import ABAC, Effect, Policy, Request
from .rbac import RBAC
from .rebac import ReBAC, Userset

MAX_RELATIONSHIP_DEPTH = 25


CEDAR_POLICY = """
forbid (
    principal,
    action,
    resource
) when {
    principal.tenant != resource.tenant
};

forbid (
    principal,
    action,
    resource
) when {
    resource.locked
};

permit (
    principal,
    action in [Action::"read", Action::"write"],
    resource
) when {
    principal.tenantAdmin && principal.tenant == resource.tenant
};

permit (
    principal,
    action in [Action::"read", Action::"write"],
    resource
) when {
    principal == resource.owner
};

permit (
    principal in resource.readerGroup,
    action == Action::"read",
    resource
);
""".strip()


REGO_POLICY = """
package authlab.document

import rego.v1

default allow := false

deny if input.subject.tenant != input.resource.tenant
deny if input.resource.locked

effective_groups := graph.reachable(
    data.group_parents,
    input.subject.direct_groups,
)

permit if {
    input.action in {"read", "write"}
    input.subject.tenant_admin
    input.subject.tenant == input.resource.tenant
}

permit if {
    input.action in {"read", "write"}
    input.subject.id == input.resource.owner
}

permit if {
    input.action == "read"
    input.resource.reader_group in effective_groups
}

allow if {
    permit
    not deny
}
""".strip()


@dataclass(frozen=True)
class Subject:
    id: str
    tenant: str
    direct_groups: frozenset[str] = frozenset()
    tenant_admin: bool = False


@dataclass(frozen=True)
class Resource:
    id: str
    tenant: str
    owner: str
    reader_group: str | None = None
    locked: bool = False


@dataclass(frozen=True)
class AccessRequest:
    subject_id: str
    action: str
    resource_id: str


@dataclass(frozen=True)
class ComparisonDecision:
    model: str
    allowed: bool
    reason_code: str
    determining_policies: tuple[str, ...] = ()


@dataclass(frozen=True)
class RelationshipResolution:
    matched: bool
    visited: tuple[str, ...]
    cycle_detected: bool
    depth_limited: bool


@dataclass
class PolicyDataset:
    subjects: dict[str, Subject]
    resources: dict[str, Resource]
    # An edge child -> parent means every member of child is also a member of
    # parent.  For example, platform -> eng implements a nested group.
    group_parents: dict[str, frozenset[str]] = field(default_factory=dict)
    max_relationship_depth: int = MAX_RELATIONSHIP_DEPTH

    def resolve_group(self, subject_id: str, target_group: str) -> RelationshipResolution:
        """Resolve nested membership with explicit cycle and depth bounds."""
        subject = self.subjects.get(subject_id)
        if subject is None:
            return RelationshipResolution(False, (), False, False)

        pending = [(group, 0, frozenset()) for group in sorted(subject.direct_groups)]
        visited: set[str] = set()
        cycle_detected = False
        depth_limited = False

        while pending:
            group, depth, path = pending.pop()
            if group in path:
                cycle_detected = True
                continue
            if depth > self.max_relationship_depth:
                depth_limited = True
                continue

            visited.add(group)
            if group == target_group:
                return RelationshipResolution(
                    True, tuple(sorted(visited)), cycle_detected, depth_limited
                )

            next_path = path | {group}
            for parent in sorted(self.group_parents.get(group, frozenset()), reverse=True):
                pending.append((parent, depth + 1, next_path))

        return RelationshipResolution(
            False, tuple(sorted(visited)), cycle_detected, depth_limited
        )


class PolicyAdapter(Protocol):
    name: str
    list_strategy: str
    consistency: str

    def decide(self, request: AccessRequest) -> ComparisonDecision: ...


class _Adapter:
    name = ""
    list_strategy = "candidate scan: O(resources × check)"
    consistency = "one immutable in-memory snapshot; no distributed consistency token"

    def __init__(self, dataset: PolicyDataset) -> None:
        self.dataset = dataset

    def _entities(
        self, request: AccessRequest
    ) -> tuple[Subject | None, Resource | None]:
        return (
            self.dataset.subjects.get(request.subject_id),
            self.dataset.resources.get(request.resource_id),
        )

    def _deny(self, code: str, *policies: str) -> ComparisonDecision:
        return ComparisonDecision(self.name, False, code, tuple(policies))

    def _allow(self, code: str, *policies: str) -> ComparisonDecision:
        return ComparisonDecision(self.name, True, code, tuple(policies))


class RBACAdapter(_Adapter):
    """RBAC plus mandatory guards and materialized resource-scoped roles."""

    name = "RBAC"
    list_strategy = "materialized roles, then candidate scan: O(resources × roles)"

    def __init__(self, dataset: PolicyDataset) -> None:
        super().__init__(dataset)
        self.engine = RBAC()
        for resource in dataset.resources.values():
            owner_role = f"owner:{resource.id}"
            reader_role = f"reader:{resource.id}"
            admin_role = f"tenant-admin:{resource.tenant}"
            if owner_role not in self.engine.roles:
                self.engine.define_role(
                    owner_role, [f"{resource.id}:read", f"{resource.id}:write"]
                )
            if reader_role not in self.engine.roles:
                self.engine.define_role(reader_role, [f"{resource.id}:read"])
            if admin_role not in self.engine.roles:
                permissions = [
                    f"{item.id}:{action}"
                    for item in dataset.resources.values()
                    if item.tenant == resource.tenant
                    for action in ("read", "write")
                ]
                self.engine.define_role(admin_role, permissions)

        for subject in dataset.subjects.values():
            assigned: list[str] = []
            if subject.tenant_admin:
                assigned.append(f"tenant-admin:{subject.tenant}")
            for resource in dataset.resources.values():
                if subject.id == resource.owner:
                    assigned.append(f"owner:{resource.id}")
                if (
                    resource.reader_group
                    and dataset.resolve_group(subject.id, resource.reader_group).matched
                ):
                    assigned.append(f"reader:{resource.id}")
            if assigned:
                self.engine.assign(subject.id, *assigned)

    def decide(self, request: AccessRequest) -> ComparisonDecision:
        subject, resource = self._entities(request)
        if subject is None or resource is None:
            return self._deny("unknown-entity")
        if subject.tenant != resource.tenant:
            return self._deny("tenant-boundary", "application-tenant-guard")
        if resource.locked:
            return self._deny("explicit-deny", "application-locked-guard")
        if request.action not in {"read", "write"}:
            return self._deny("default-deny")

        permission = f"{resource.id}:{request.action}"
        if self.engine.can(subject.id, permission):
            roles = sorted(self.engine.effective_roles(subject.id))
            return self._allow("materialized-role", *roles)
        return self._deny("default-deny")


class ABACAdapter(_Adapter):
    """ABAC with deny-overrides and a precomputed group-closure attribute."""

    name = "ABAC"
    list_strategy = "attribute policy evaluation per candidate: O(resources × policies)"

    def __init__(self, dataset: PolicyDataset) -> None:
        super().__init__(dataset)
        self.engine = ABAC(
            [
                Policy(
                    "deny-cross-tenant",
                    Effect.DENY,
                    condition=lambda req: req.subject.get("tenant")
                    != req.resource.get("tenant"),
                ),
                Policy(
                    "deny-locked",
                    Effect.DENY,
                    condition=lambda req: bool(req.resource.get("locked")),
                ),
                Policy(
                    "allow-tenant-admin",
                    Effect.ALLOW,
                    actions=["read", "write"],
                    condition=lambda req: bool(req.subject.get("tenant_admin"))
                    and req.subject.get("tenant") == req.resource.get("tenant"),
                ),
                Policy(
                    "allow-owner",
                    Effect.ALLOW,
                    actions=["read", "write"],
                    condition=lambda req: req.subject.get("id")
                    == req.resource.get("owner"),
                ),
                Policy(
                    "allow-reader-group",
                    Effect.ALLOW,
                    actions=["read"],
                    condition=lambda req: req.resource.get("reader_group")
                    in req.subject.get("effective_groups", ()),
                ),
            ]
        )

    def decide(self, request: AccessRequest) -> ComparisonDecision:
        subject, resource = self._entities(request)
        if subject is None or resource is None:
            return self._deny("unknown-entity")
        known_groups = set(self.dataset.group_parents)
        for parents in self.dataset.group_parents.values():
            known_groups.update(parents)
        effective_groups = {
            group
            for group in known_groups
            if self.dataset.resolve_group(subject.id, group).matched
        } | set(subject.direct_groups)
        decision = self.engine.evaluate(
            Request(
                subject={
                    "id": subject.id,
                    "tenant": subject.tenant,
                    "tenant_admin": subject.tenant_admin,
                    "effective_groups": effective_groups,
                },
                resource={
                    "id": resource.id,
                    "tenant": resource.tenant,
                    "owner": resource.owner,
                    "reader_group": resource.reader_group,
                    "locked": resource.locked,
                },
                action=request.action,
            )
        )
        if decision.allowed:
            return self._allow("attribute-policy", *decision.matched)
        if "deny-cross-tenant" in decision.matched:
            return self._deny("tenant-boundary", *decision.matched)
        if "deny-locked" in decision.matched:
            return self._deny("explicit-deny", *decision.matched)
        return self._deny("default-deny", *decision.matched)


class ReBACAdapter(_Adapter):
    """ReBAC tuples for grants, with tenant and explicit-deny guards."""

    name = "ReBAC"
    list_strategy = "tuple candidate scan: O(resources × graph check); production needs reverse indexes"
    consistency = "one tuple snapshot; no Zanzibar zookie/new-enemy guarantee"

    def __init__(self, dataset: PolicyDataset) -> None:
        super().__init__(dataset)
        self.engine = ReBAC(max_depth=dataset.max_relationship_depth)
        self.engine.namespace("group").relation("member")
        self.engine.namespace("tenant").relation("admin")
        self.engine.namespace("document") \
            .relation("owner") \
            .relation(
                "editor",
                Userset.union(Userset.this(), Userset.computed("owner")),
            ) \
            .relation("reader") \
            .relation(
                "viewer",
                Userset.union(
                    Userset.this(),
                    Userset.computed("editor"),
                    Userset.computed("reader"),
                ),
            )

        for subject in dataset.subjects.values():
            for group in subject.direct_groups:
                self.engine.write(f"group:{group}#member@user:{subject.id}")
            if subject.tenant_admin:
                self.engine.write(f"tenant:{subject.tenant}#admin@user:{subject.id}")
        for child, parents in dataset.group_parents.items():
            for parent in parents:
                self.engine.write(f"group:{parent}#member@group:{child}#member")
        for resource in dataset.resources.values():
            self.engine.write(
                f"document:{resource.id}#owner@user:{resource.owner}"
            )
            if resource.reader_group:
                self.engine.write(
                    f"document:{resource.id}#reader@group:{resource.reader_group}#member"
                )

    def decide(self, request: AccessRequest) -> ComparisonDecision:
        subject, resource = self._entities(request)
        if subject is None or resource is None:
            return self._deny("unknown-entity")
        if subject.tenant != resource.tenant:
            return self._deny("tenant-boundary", "application-tenant-guard")
        if resource.locked:
            return self._deny("explicit-deny", "application-locked-guard")
        if request.action not in {"read", "write"}:
            return self._deny("default-deny")

        user = f"user:{subject.id}"
        if self.engine.check(f"tenant:{subject.tenant}", "admin", user):
            return self._allow("relationship-path", "tenant-admin")
        relation = "viewer" if request.action == "read" else "editor"
        if self.engine.check(f"document:{resource.id}", relation, user):
            return self._allow("relationship-path", relation)
        return self._deny("default-deny")


class CedarAdapter(_Adapter):
    """Executable equivalent of :data:`CEDAR_POLICY`."""

    name = "Cedar"
    list_strategy = "policy evaluation per candidate: O(resources × policies)"

    def decide(self, request: AccessRequest) -> ComparisonDecision:
        subject, resource = self._entities(request)
        if subject is None or resource is None:
            return self._deny("unknown-entity")

        # Cedar's forbid-overrides-permit combination is intentionally visible.
        forbids: list[str] = []
        if subject.tenant != resource.tenant:
            forbids.append("forbid-cross-tenant")
        if resource.locked:
            forbids.append("forbid-locked")
        if forbids:
            code = "tenant-boundary" if "forbid-cross-tenant" in forbids else "explicit-deny"
            return self._deny(code, *forbids)

        permits: list[str] = []
        if request.action in {"read", "write"}:
            if subject.tenant_admin:
                permits.append("permit-tenant-admin")
            if subject.id == resource.owner:
                permits.append("permit-owner")
        if (
            request.action == "read"
            and resource.reader_group
            and self.dataset.resolve_group(subject.id, resource.reader_group).matched
        ):
            permits.append("permit-reader-group")
        if permits:
            return self._allow("cedar-permit", *permits)
        return self._deny("default-deny")


class RegoAdapter(_Adapter):
    """Executable equivalent of :data:`REGO_POLICY`."""

    name = "Rego"
    list_strategy = "rule evaluation per candidate: O(resources × rules)"

    def decide(self, request: AccessRequest) -> ComparisonDecision:
        subject, resource = self._entities(request)
        if subject is None or resource is None:
            return self._deny("unknown-entity")

        deny = subject.tenant != resource.tenant or resource.locked
        permits: list[str] = []
        if request.action in {"read", "write"} and subject.tenant_admin:
            permits.append("permit_tenant_admin")
        if request.action in {"read", "write"} and subject.id == resource.owner:
            permits.append("permit_owner")
        if (
            request.action == "read"
            and resource.reader_group
            and self.dataset.resolve_group(subject.id, resource.reader_group).matched
        ):
            permits.append("permit_reader_group")

        if deny:
            code = "tenant-boundary" if subject.tenant != resource.tenant else "explicit-deny"
            return self._deny(code, "deny")
        if permits:
            return self._allow("rego-permit", *permits)
        return self._deny("default-deny")


@dataclass(frozen=True)
class ListObjectsResult:
    model: str
    object_ids: tuple[str, ...]
    candidate_checks: int
    elapsed_ns: int
    strategy: str
    consistency: str


class PolicyComparison:
    """Run the same request through all five policy-model adapters."""

    def __init__(self, dataset: PolicyDataset) -> None:
        self.dataset = dataset
        self.adapters: tuple[PolicyAdapter, ...] = (
            RBACAdapter(dataset),
            ABACAdapter(dataset),
            ReBACAdapter(dataset),
            CedarAdapter(dataset),
            RegoAdapter(dataset),
        )

    def decide_all(self, request: AccessRequest) -> dict[str, ComparisonDecision]:
        return {adapter.name: adapter.decide(request) for adapter in self.adapters}

    def require_parity(self, request: AccessRequest) -> bool:
        decisions = self.decide_all(request)
        effects = {decision.allowed for decision in decisions.values()}
        if len(effects) != 1:
            detail = ", ".join(
                f"{name}={'allow' if decision.allowed else 'deny'}"
                for name, decision in decisions.items()
            )
            raise AssertionError(f"policy decision mismatch: {detail}")
        return next(iter(effects))

    def list_objects_all(
        self, subject_id: str, action: str
    ) -> dict[str, ListObjectsResult]:
        results: dict[str, ListObjectsResult] = {}
        for adapter in self.adapters:
            started = time.perf_counter_ns()
            object_ids = tuple(
                sorted(
                    resource_id
                    for resource_id in self.dataset.resources
                    if adapter.decide(
                        AccessRequest(subject_id, action, resource_id)
                    ).allowed
                )
            )
            elapsed = time.perf_counter_ns() - started
            results[adapter.name] = ListObjectsResult(
                model=adapter.name,
                object_ids=object_ids,
                candidate_checks=len(self.dataset.resources),
                elapsed_ns=elapsed,
                strategy=adapter.list_strategy,
                consistency=adapter.consistency,
            )
        return results


@dataclass(frozen=True)
class DecisionLogEntry:
    occurred_at: int
    expires_at: int
    model: str
    effect: str
    subject_ref: str
    resource_ref: str
    action: str
    reason_code: str
    policy_ids: tuple[str, ...]
    request_ref: str | None = None
    risk_bucket: str | None = None

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


class PrivacyPreservingDecisionLog:
    """Minimized, pseudonymized decision logs with bounded retention.

    Raw policy input, email addresses, IP addresses, tokens, and arbitrary
    context are deliberately not accepted into the stored entry.
    """

    def __init__(self, secret: bytes, retention_seconds: int = 7 * 24 * 60 * 60) -> None:
        if len(secret) < 16:
            raise ValueError("decision-log secret must be at least 16 bytes")
        if retention_seconds <= 0:
            raise ValueError("retention_seconds must be positive")
        self._secret = secret
        self.retention_seconds = retention_seconds
        self.entries: list[DecisionLogEntry] = []

    def _reference(self, namespace: str, value: str) -> str:
        digest = hmac.new(
            self._secret,
            f"{namespace}:{value}".encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        return f"hmac-sha256:{digest[:24]}"

    def record(
        self,
        decision: ComparisonDecision,
        request: AccessRequest,
        *,
        occurred_at: int,
        context: dict[str, object] | None = None,
    ) -> DecisionLogEntry:
        allowed_context = context or {}
        request_id = allowed_context.get("request_id")
        risk_bucket = allowed_context.get("risk_bucket")
        entry = DecisionLogEntry(
            occurred_at=occurred_at,
            expires_at=occurred_at + self.retention_seconds,
            model=decision.model,
            effect="allow" if decision.allowed else "deny",
            subject_ref=self._reference("subject", request.subject_id),
            resource_ref=self._reference("resource", request.resource_id),
            action=request.action,
            reason_code=decision.reason_code,
            policy_ids=tuple(
                self._reference("policy", policy_id)
                for policy_id in decision.determining_policies
            ),
            request_ref=(
                self._reference("request", str(request_id))
                if request_id is not None
                else None
            ),
            risk_bucket=(
                str(risk_bucket)
                if risk_bucket in {"low", "medium", "high"}
                else None
            ),
        )
        self.entries.append(entry)
        return entry

    def purge(self, now: int) -> int:
        before = len(self.entries)
        self.entries = [entry for entry in self.entries if entry.expires_at > now]
        return before - len(self.entries)


def canonical_dataset(
    *,
    group_parents: dict[str, frozenset[str]] | None = None,
    max_relationship_depth: int = MAX_RELATIONSHIP_DEPTH,
) -> PolicyDataset:
    """A small matrix containing every policy edge the comparison needs."""
    return PolicyDataset(
        subjects={
            "alice": Subject("alice", "blue", frozenset({"platform"})),
            "bob": Subject("bob", "blue"),
            "root": Subject("root", "blue", tenant_admin=True),
            "carol": Subject("carol", "red"),
            "mallory": Subject("mallory", "blue"),
        },
        resources={
            "budget": Resource("budget", "blue", "bob", reader_group="eng"),
            "locked": Resource(
                "locked", "blue", "bob", reader_group="eng", locked=True
            ),
            "red-plan": Resource("red-plan", "red", "carol", reader_group="eng"),
        },
        group_parents=(
            {"platform": frozenset({"eng"})}
            if group_parents is None
            else group_parents
        ),
        max_relationship_depth=max_relationship_depth,
    )


CANONICAL_CASES: dict[str, tuple[AccessRequest, bool]] = {
    "nested-group-read": (AccessRequest("alice", "read", "budget"), True),
    "group-cannot-write": (AccessRequest("alice", "write", "budget"), False),
    "owner-write": (AccessRequest("bob", "write", "budget"), True),
    "explicit-deny-owner": (AccessRequest("bob", "read", "locked"), False),
    "tenant-admin": (AccessRequest("root", "write", "budget"), True),
    "tenant-boundary": (AccessRequest("root", "read", "red-plan"), False),
    "default-deny": (AccessRequest("mallory", "read", "budget"), False),
    "other-tenant-owner": (AccessRequest("carol", "write", "red-plan"), True),
}
