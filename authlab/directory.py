"""LDAP-style directory operations and SCIM provisioning lifecycle."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from .passwords import hash_password, verify_password
from .util import AuthError, random_token

_DUMMY_PASSWORD_RECORD = hash_password(
    "not-a-real-directory-password",
    algorithm="pbkdf2-sha256",
    salt=b"\0" * 16,
)


def escape_filter(value: str) -> str:
    replacements = {
        "\\": r"\5c",
        "*": r"\2a",
        "(": r"\28",
        ")": r"\29",
        "\x00": r"\00",
    }
    return "".join(replacements.get(char, char) for char in value)


@dataclass
class DirectoryEntry:
    dn: str
    attributes: dict[str, list[str]]
    password_record: str | None = None


@dataclass
class LDAPDirectory:
    entries: dict[str, DirectoryEntry] = field(default_factory=dict)

    def add(
        self,
        dn: str,
        attributes: dict[str, list[str]],
        *,
        password: str | None = None,
    ) -> None:
        key = dn.casefold()
        if key in self.entries or "=" not in dn:
            raise AuthError("duplicate or invalid distinguished name")
        self.entries[key] = DirectoryEntry(
            dn,
            {name.casefold(): list(values) for name, values in attributes.items()},
            None if password is None else hash_password(password),
        )

    def bind(self, dn: str, password: str) -> bool:
        entry = self.entries.get(dn.casefold())
        record = (
            entry.password_record
            if entry and entry.password_record
            else _DUMMY_PASSWORD_RECORD
        )
        valid = verify_password(password, record)
        return bool(valid and entry and entry.password_record)

    def search(
        self,
        *,
        base_dn: str,
        attribute: str,
        value: str,
    ) -> list[DirectoryEntry]:
        attr = attribute.casefold()
        if not re.fullmatch(r"[a-zA-Z][a-zA-Z0-9-]*", attribute):
            raise AuthError("invalid LDAP attribute")
        return [
            entry
            for key, entry in self.entries.items()
            if key.endswith(base_dn.casefold())
            and value in entry.attributes.get(attr, [])
        ]


@dataclass
class SCIMUser:
    id: str
    user_name: str
    display_name: str
    active: bool
    version: int = 1

    def resource(self) -> dict[str, Any]:
        return {
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
            "id": self.id,
            "userName": self.user_name,
            "displayName": self.display_name,
            "active": self.active,
            "meta": {"resourceType": "User", "version": f'W/"{self.version}"'},
        }


@dataclass
class SCIMService:
    users: dict[str, SCIMUser] = field(default_factory=dict)

    def create_user(self, user_name: str, display_name: str) -> dict[str, Any]:
        if any(user.user_name.casefold() == user_name.casefold() for user in self.users.values()):
            raise AuthError("SCIM uniqueness conflict")
        user = SCIMUser(random_token(12), user_name, display_name, True)
        self.users[user.id] = user
        return user.resource()

    def patch_user(
        self,
        user_id: str,
        operations: list[dict[str, Any]],
        *,
        if_match: str,
    ) -> dict[str, Any]:
        user = self.users.get(user_id)
        if user is None:
            raise AuthError("SCIM user not found")
        if if_match != f'W/"{user.version}"':
            raise AuthError("SCIM version precondition failed")
        for operation in operations:
            if str(operation.get("op", "")).casefold() != "replace":
                raise AuthError("only SCIM replace is implemented in this lab")
            path = operation.get("path")
            if path == "active":
                user.active = bool(operation.get("value"))
            elif path == "displayName":
                user.display_name = str(operation.get("value"))
            else:
                raise AuthError("unsupported SCIM patch path")
        user.version += 1
        return user.resource()

    def list_users(self, filter_text: str | None = None) -> dict[str, Any]:
        users = list(self.users.values())
        if filter_text:
            match = re.fullmatch(r'userName eq "([^"]+)"', filter_text)
            if match is None:
                raise AuthError("unsupported or unsafe SCIM filter")
            expected = match.group(1).casefold()
            users = [user for user in users if user.user_name.casefold() == expected]
        return {
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
            "totalResults": len(users),
            "startIndex": 1,
            "itemsPerPage": len(users),
            "Resources": [user.resource() for user in users],
        }
