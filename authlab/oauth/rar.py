"""OAuth 2.0 Rich Authorization Requests (RAR), RFC 9396.

Scopes are short labels.  They cannot say "initiate this EUR 12.50 payment to
this creditor" without inventing an unparseable mini-language.  RAR carries
that structured intent in ``authorization_details`` and binds the approved
objects to the authorization code, access token, refresh token, and
introspection result.

The RFC intentionally leaves each ``type`` schema to the protected API.  This
module therefore validates the common fields and an explicit type allow-list;
an application-specific validator still owns fields such as instructedAmount.
"""

from __future__ import annotations

import json
from copy import deepcopy
from typing import Any
from urllib.parse import urlsplit

from .errors import InvalidAuthorizationDetails

MAX_AUTHORIZATION_DETAILS = 16


def validate_authorization_details(
    value: str | list[dict[str, Any]],
    *,
    supported_types: set[str] | list[str] | tuple[str, ...],
) -> list[dict[str, Any]]:
    """Parse and validate RFC 9396 common authorization detail fields."""

    if isinstance(value, str):
        try:
            value = json.loads(value)
        except (json.JSONDecodeError, TypeError) as exc:
            raise InvalidAuthorizationDetails("authorization_details is not valid JSON") from exc
    if not isinstance(value, list) or not value:
        raise InvalidAuthorizationDetails("authorization_details must be a non-empty array")
    if len(value) > MAX_AUTHORIZATION_DETAILS:
        raise InvalidAuthorizationDetails(
            f"authorization_details exceeds the {MAX_AUTHORIZATION_DETAILS}-item limit"
        )

    allowed = set(supported_types)
    validated: list[dict[str, Any]] = []
    for index, detail in enumerate(value):
        if not isinstance(detail, dict):
            raise InvalidAuthorizationDetails(f"detail {index} must be a JSON object")
        detail_type = detail.get("type")
        if not isinstance(detail_type, str) or not detail_type or not detail_type.isascii():
            raise InvalidAuthorizationDetails(f"detail {index} needs an ASCII type")
        if detail_type not in allowed:
            raise InvalidAuthorizationDetails(f"unsupported authorization detail type: {detail_type}")

        for name in ("actions", "datatypes", "privileges"):
            member = detail.get(name)
            if member is not None and (
                not isinstance(member, list)
                or not member
                or any(not isinstance(item, str) or not item for item in member)
            ):
                raise InvalidAuthorizationDetails(
                    f"detail {index} field {name} must be a non-empty string array"
                )

        locations = detail.get("locations")
        if locations is not None:
            if not isinstance(locations, list) or not locations:
                raise InvalidAuthorizationDetails(
                    f"detail {index} field locations must be a non-empty URI array"
                )
            for location in locations:
                if (
                    not isinstance(location, str)
                    or urlsplit(location).scheme != "https"
                    or not urlsplit(location).netloc
                ):
                    raise InvalidAuthorizationDetails(
                        f"detail {index} location must be an absolute HTTPS URI"
                    )

        identifier = detail.get("identifier")
        if identifier is not None and not isinstance(identifier, str):
            raise InvalidAuthorizationDetails(
                f"detail {index} field identifier must be a string"
            )
        credential_identifiers = detail.get("credential_identifiers")
        if credential_identifiers is not None and (
            not isinstance(credential_identifiers, list)
            or not credential_identifiers
            or any(not isinstance(item, str) or not item for item in credential_identifiers)
        ):
            raise InvalidAuthorizationDetails(
                f"detail {index} field credential_identifiers must be a non-empty string array"
            )
        validated.append(deepcopy(detail))
    return validated
