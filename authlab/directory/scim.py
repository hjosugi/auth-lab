"""SCIM 2.0: System for Cross-domain Identity Management (RFC 7643 / 7644).

SCIM is how identities get *provisioned* -- created, updated, deactivated --
across systems, as opposed to how they *authenticate*. When someone joins your
company, an IdP (Okta, Entra, Google) pushes a SCIM "create user" to every
SaaS app. When they leave, it pushes a "deactivate". It is the plumbing behind
"deprovisioning", and getting it wrong is how ex-employees keep their access.

The data model is deliberately boring REST:

    POST   /Users              create
    GET    /Users/{id}         read
    GET    /Users?filter=...   query
    PUT    /Users/{id}         replace
    PATCH  /Users/{id}         partial update (add/remove/replace operations)
    DELETE /Users/{id}         remove

The security lessons that are specific to SCIM, rather than generic REST:

* Deactivation, not deletion, is the event that matters. The IdP sets
  `active: false`; if your app treats only DELETE as "revoke access" and the
  IdP only ever sends PATCH active=false, the account lingers. So `active`
  must gate every downstream session immediately.

* SCIM endpoints are extremely high value: one bearer token can create and
  modify every identity in the tenant. A leaked SCIM token is a tenant-wide
  account-creation primitive. It must be tenant-scoped and tightly held.

* `externalId` is the IdP's key; your `id` is yours. Matching users by
  email or username instead of externalId is how a rename or a re-used email
  silently merges two people's access.

* Filters (RFC 7644 section 3.4.2) are a query language, and injecting them
  into a backend query is the SCIM version of the LDAP-injection lesson.

This implementation keeps users in memory and returns SCIM-shaped JSON so a
drill can exercise the whole provisioning lifecycle.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from ..util.ct import random_token

USER_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:User"
GROUP_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:Group"
LIST_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
PATCH_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:PatchOp"
ERROR_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:Error"


class SCIMError(Exception):
    def __init__(self, status: int, detail: str, scim_type: str | None = None) -> None:
        self.status = status
        self.detail = detail
        self.scim_type = scim_type
        super().__init__(detail)

    def to_dict(self) -> dict[str, Any]:
        body = {"schemas": [ERROR_SCHEMA], "status": str(self.status), "detail": self.detail}
        if self.scim_type:
            body["scimType"] = self.scim_type
        return body


@dataclass
class SCIMUser:
    id: str
    user_name: str
    external_id: str | None = None
    active: bool = True
    emails: list[dict[str, Any]] = field(default_factory=list)
    name: dict[str, str] = field(default_factory=dict)
    groups: list[str] = field(default_factory=list)
    meta: dict[str, Any] = field(default_factory=dict)

    def to_resource(self, location_base: str) -> dict[str, Any]:
        return {
            "schemas": [USER_SCHEMA],
            "id": self.id,
            "externalId": self.external_id,
            "userName": self.user_name,
            "active": self.active,
            "name": self.name,
            "emails": self.emails,
            "groups": [{"value": g} for g in self.groups],
            "meta": {
                "resourceType": "User",
                "location": f"{location_base}/Users/{self.id}",
                **self.meta,
            },
        }


@dataclass
class SCIMGroup:
    id: str
    display_name: str
    members: list[str] = field(default_factory=list)
    external_id: str | None = None


class SCIMServer:
    """An in-memory SCIM 2.0 service provider."""

    def __init__(self, location_base: str = "https://api.auth-lab.local/scim/v2") -> None:
        self.location_base = location_base
        self.users: dict[str, SCIMUser] = {}
        self.groups: dict[str, SCIMGroup] = {}
        self.events: list[str] = []

    # ------------------------------------------------------------------
    # users
    # ------------------------------------------------------------------

    def create_user(self, body: dict[str, Any]) -> dict[str, Any]:
        user_name = body.get("userName")
        if not user_name:
            raise SCIMError(400, "userName is required", "invalidValue")
        # userName is unique per RFC 7643. A duplicate is 409, which is how the
        # IdP learns to PATCH the existing user instead of forking a second.
        for existing in self.users.values():
            if existing.user_name.lower() == user_name.lower():
                raise SCIMError(409, f"userName {user_name!r} already exists", "uniqueness")

        user = SCIMUser(
            id=random_token(12),
            user_name=user_name,
            external_id=body.get("externalId"),
            active=body.get("active", True),
            emails=body.get("emails", []),
            name=body.get("name", {}),
        )
        self.users[user.id] = user
        self.events.append(f"user.created {user.user_name} (active={user.active})")
        return user.to_resource(self.location_base)

    def get_user(self, user_id: str) -> dict[str, Any]:
        user = self.users.get(user_id)
        if user is None:
            raise SCIMError(404, f"user {user_id!r} not found")
        return user.to_resource(self.location_base)

    def replace_user(self, user_id: str, body: dict[str, Any]) -> dict[str, Any]:
        user = self.users.get(user_id)
        if user is None:
            raise SCIMError(404, f"user {user_id!r} not found")
        # PUT replaces the whole resource. A field absent from the body reverts
        # to its default -- which is why a PUT that forgets `active` can silently
        # reactivate a disabled account. We make the default explicit.
        user.user_name = body.get("userName", user.user_name)
        user.external_id = body.get("externalId", user.external_id)
        user.active = body.get("active", True)
        user.emails = body.get("emails", user.emails)
        user.name = body.get("name", user.name)
        self.events.append(f"user.replaced {user.user_name} (active={user.active})")
        return user.to_resource(self.location_base)

    def patch_user(self, user_id: str, body: dict[str, Any]) -> dict[str, Any]:
        """PATCH with add/remove/replace operations (RFC 7644 section 3.5.2).

        This is the operation that actually carries deprovisioning, because the
        IdP sends `replace active=false` rather than a full PUT. Handling it is
        not optional if you want offboarding to work.
        """
        user = self.users.get(user_id)
        if user is None:
            raise SCIMError(404, f"user {user_id!r} not found")
        operations = body.get("Operations") or body.get("operations")
        if not operations:
            raise SCIMError(400, "PATCH requires Operations", "invalidValue")

        for operation in operations:
            op = (operation.get("op") or "").lower()
            path = operation.get("path", "")
            value = operation.get("value")
            if op not in ("add", "remove", "replace"):
                raise SCIMError(400, f"unsupported op: {op!r}", "invalidValue")
            self._apply_patch(user, op, path, value)

        self.events.append(f"user.patched {user.user_name} (active={user.active})")
        return user.to_resource(self.location_base)

    def _apply_patch(self, user: SCIMUser, op: str, path: str, value: Any) -> None:
        # A PATCH with no path applies the value's keys at the top level.
        if not path and isinstance(value, dict):
            for key, item in value.items():
                self._set_attribute(user, key, item)
            return
        if op == "remove":
            self._set_attribute(user, path, None)
        else:
            self._set_attribute(user, path, value)

    def _set_attribute(self, user: SCIMUser, path: str, value: Any) -> None:
        attribute = path.lower().split(".")[0].split("[")[0]
        if attribute == "active":
            user.active = bool(value) if value is not None else False
        elif attribute == "username":
            user.user_name = value
        elif attribute == "name":
            user.name = value or {}
        elif attribute == "emails":
            user.emails = value or []
        elif attribute == "externalid":
            user.external_id = value
        # Unknown attributes are ignored rather than erroring, matching the
        # lenient behaviour real SCIM clients expect.

    def delete_user(self, user_id: str) -> None:
        if user_id not in self.users:
            raise SCIMError(404, f"user {user_id!r} not found")
        user = self.users.pop(user_id)
        self.events.append(f"user.deleted {user.user_name}")

    def deactivate_user(self, user_id: str) -> dict[str, Any]:
        """The offboarding shortcut, so a drill can show it plainly."""
        return self.patch_user(
            user_id,
            {"schemas": [PATCH_SCHEMA], "Operations": [{"op": "replace", "path": "active", "value": False}]},
        )

    def is_active(self, user_id: str) -> bool:
        """The check every downstream session must make on every request.

        SCIM makes an account inactive; it does nothing on its own. The app
        has to consult `active` -- ideally on each request, at least on each
        token refresh -- or a deactivated user keeps working until their token
        expires.
        """
        user = self.users.get(user_id)
        return bool(user and user.active)

    # ------------------------------------------------------------------
    # query
    # ------------------------------------------------------------------

    def list_users(self, filter_string: str | None = None, start_index: int = 1, count: int = 100) -> dict[str, Any]:
        matches = list(self.users.values())
        if filter_string:
            predicate = _parse_scim_filter(filter_string)
            matches = [u for u in matches if predicate(u)]
        # SCIM pagination is 1-based, which is off by one from every other
        # API and a reliable source of "the last user is missing" bugs.
        page = matches[start_index - 1 : start_index - 1 + count]
        return {
            "schemas": [LIST_SCHEMA],
            "totalResults": len(matches),
            "startIndex": start_index,
            "itemsPerPage": len(page),
            "Resources": [u.to_resource(self.location_base) for u in page],
        }


# --- SCIM filter (RFC 7644 3.4.2), the subset IdPs actually send ------------
# Supported: eq, ne, co, sw, ew, pr, and 'and'/'or'. Parsed, not string-matched,
# for the same injection-safety reason as the LDAP filter parser.

_TOKEN = re.compile(r'\s*(\(|\)|"[^"]*"|[^\s()]+)')


def _parse_scim_filter(text: str):
    tokens = _TOKEN.findall(text)
    pos = 0

    def peek() -> str | None:
        return tokens[pos] if pos < len(tokens) else None

    def parse_or():
        nonlocal pos
        left = parse_and()
        while peek() and peek().lower() == "or":
            pos += 1
            right = parse_and()
            l, r = left, right
            left = (lambda a, b: (lambda u: a(u) or b(u)))(l, r)
        return left

    def parse_and():
        nonlocal pos
        left = parse_term()
        while peek() and peek().lower() == "and":
            pos += 1
            right = parse_term()
            l, r = left, right
            left = (lambda a, b: (lambda u: a(u) and b(u)))(l, r)
        return left

    def parse_term():
        nonlocal pos
        if peek() == "(":
            pos += 1
            inner = parse_or()
            if peek() != ")":
                raise SCIMError(400, "unbalanced parentheses in filter", "invalidFilter")
            pos += 1
            return inner
        # attribute operator [value]
        attr = tokens[pos].lower(); pos += 1
        if pos >= len(tokens):
            raise SCIMError(400, "filter attribute without operator", "invalidFilter")
        operator = tokens[pos].lower(); pos += 1
        if operator == "pr":
            return lambda u: bool(_scim_attr(u, attr))
        if pos >= len(tokens):
            raise SCIMError(400, f"operator {operator!r} needs a value", "invalidFilter")
        raw = tokens[pos]; pos += 1
        value = raw[1:-1] if raw.startswith('"') else raw
        return _scim_comparison(attr, operator, value)

    predicate = parse_or()
    if pos != len(tokens):
        raise SCIMError(400, "trailing tokens in filter", "invalidFilter")
    return predicate


def _scim_attr(user: SCIMUser, attr: str) -> Any:
    mapping = {
        "username": user.user_name,
        "externalid": user.external_id,
        "active": user.active,
        "emails.value": user.emails[0]["value"] if user.emails else None,
    }
    return mapping.get(attr)


def _scim_comparison(attr: str, operator: str, value: str):
    def compare(user: SCIMUser) -> bool:
        actual = _scim_attr(user, attr)
        if actual is None:
            return False
        if isinstance(actual, bool):
            value_bool = value.lower() == "true"
            return actual == value_bool if operator == "eq" else actual != value_bool
        actual_str = str(actual)
        if operator == "eq":
            return actual_str.lower() == value.lower()
        if operator == "ne":
            return actual_str.lower() != value.lower()
        if operator == "co":
            return value.lower() in actual_str.lower()
        if operator == "sw":
            return actual_str.lower().startswith(value.lower())
        if operator == "ew":
            return actual_str.lower().endswith(value.lower())
        raise SCIMError(400, f"unsupported operator: {operator!r}", "invalidFilter")

    return compare
