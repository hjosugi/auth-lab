"""Role-Based Access Control, with role hierarchy.

RBAC is the model almost everyone starts with, and it earns its place: it is
easy to audit ("show me everyone who can delete an invoice") and easy to
explain to a compliance auditor.

The two things to get right:

* Hierarchy. `admin` inherits `editor` inherits `viewer`. Without inheritance
  you end up copy-pasting permission lists and they drift apart. With it, you
  must detect cycles or resolution loops forever.

* Permission naming. `resource:action` scales; a flat `can_edit_invoice`
  namespace does not. Wildcards (`invoice:*`, `*:read`) are convenient and
  are also how an over-broad grant hides in plain sight, so we support them
  but make them visible in `explain()`.

What RBAC fundamentally cannot say: "their own". `orders:read` is a statement
about a class of objects, never about a specific one. The moment a
requirement contains the word "own" or "their", you need ABAC or ReBAC on
top -- and if you skip that step you have shipped BOLA.
"""

from __future__ import annotations

from dataclasses import dataclass, field

Permission = str


@dataclass
class Role:
    name: str
    permissions: set[Permission] = field(default_factory=set)
    # Roles this one inherits all permissions from.
    inherits: set[str] = field(default_factory=set)
    description: str = ""


class RBAC:
    """A role store with hierarchy resolution and assignment."""

    def __init__(self) -> None:
        self.roles: dict[str, Role] = {}
        self.assignments: dict[str, set[str]] = {}

    # ---- definition -------------------------------------------------

    def define_role(
        self, name: str, permissions: list[Permission] | None = None,
        inherits: list[str] | None = None, description: str = "",
    ) -> Role:
        role = Role(
            name=name,
            permissions=set(permissions or []),
            inherits=set(inherits or []),
            description=description,
        )
        self.roles[name] = role
        self._assert_acyclic(name)
        return role

    def _assert_acyclic(self, start: str) -> None:
        """Depth-first cycle check. A cycle would make resolution never finish."""
        seen: set[str] = set()
        stack = [start]
        path: list[str] = []
        while stack:
            current = stack.pop()
            if current in path:
                raise ValueError(f"role hierarchy cycle: {' -> '.join(path + [current])}")
            role = self.roles.get(current)
            if role is None:
                continue
            if current in seen:
                continue
            seen.add(current)
            path.append(current)
            stack.extend(role.inherits)

    def assign(self, subject: str, *role_names: str) -> None:
        for name in role_names:
            if name not in self.roles:
                raise KeyError(f"unknown role: {name!r}")
        self.assignments.setdefault(subject, set()).update(role_names)

    def unassign(self, subject: str, *role_names: str) -> None:
        held = self.assignments.get(subject)
        if held:
            held.difference_update(role_names)

    # ---- resolution -------------------------------------------------

    def effective_roles(self, subject: str) -> set[str]:
        """All roles held, directly or by inheritance."""
        result: set[str] = set()
        queue = list(self.assignments.get(subject, set()))
        while queue:
            name = queue.pop()
            if name in result or name not in self.roles:
                continue
            result.add(name)
            queue.extend(self.roles[name].inherits)
        return result

    def effective_permissions(self, subject: str) -> set[Permission]:
        permissions: set[Permission] = set()
        for name in self.effective_roles(subject):
            permissions |= self.roles[name].permissions
        return permissions

    @staticmethod
    def _matches(granted: Permission, required: Permission) -> bool:
        """Wildcard matching on `resource:action`.

        `*` alone means everything. `invoice:*` means every action on
        invoices. `*:read` means read on everything.
        """
        if granted == "*" or granted == required:
            return True
        if ":" not in granted or ":" not in required:
            return False
        g_resource, g_action = granted.split(":", 1)
        r_resource, r_action = required.split(":", 1)
        return (g_resource in ("*", r_resource)) and (g_action in ("*", r_action))

    def can(self, subject: str, permission: Permission) -> bool:
        return any(self._matches(g, permission) for g in self.effective_permissions(subject))

    def explain(self, subject: str, permission: Permission) -> str:
        """Why the answer was what it was. Audit logs need this, not a bool."""
        for role_name in sorted(self.effective_roles(subject)):
            for granted in sorted(self.roles[role_name].permissions):
                if self._matches(granted, permission):
                    via = "" if granted == permission else f" (via wildcard {granted!r})"
                    direct = role_name in self.assignments.get(subject, set())
                    path = "directly assigned" if direct else "inherited"
                    return f"ALLOW: {subject!r} has role {role_name!r} ({path}){via}"
        held = sorted(self.effective_roles(subject)) or ["<none>"]
        return f"DENY: {subject!r} holds roles {held} and none grant {permission!r}"

    def subjects_with(self, permission: Permission) -> list[str]:
        """The reverse query an auditor actually asks."""
        return sorted(s for s in self.assignments if self.can(s, permission))
