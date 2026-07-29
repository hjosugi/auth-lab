"""SAML 2.0 Web Browser SSO: service provider and identity provider.

SAML is what enterprise SSO ran on for fifteen years and still runs on in most
large organisations. It predates OAuth, is XML rather than JSON, and puts the
whole assertion in the browser -- but the shape is the same as OIDC:

    SAML                          OIDC
    ----------------------------  --------------------------------
    Service Provider (SP)         Relying Party / client
    Identity Provider (IdP)       OpenID Provider
    AuthnRequest                  /authorize request
    Assertion                     ID token
    <Audience>                    aud
    <Issuer>                      iss
    NameID                        sub
    RelayState                    state
    <AttributeStatement>          claims / userinfo
    AuthnContextClassRef          acr
    <Conditions NotOnOrAfter>     exp

Where SAML is genuinely different, and worse:
  * the assertion travels through the browser as a POST body, so it is large
    and visible to anything running on the page
  * signing is XML-DSig, which is far easier to get wrong than JWS
  * there is no standard equivalent of a refresh token, so session lifetime
    is entirely the SP's problem

Where it is better: it has had SLO (single logout) and rich attribute
statements since 2005, and it works without the SP ever calling the IdP --
no back channel is required at all.

The SP validation list below is the part worth memorising, because a SAML SP
that checks only the signature is fully bypassable.
"""

from __future__ import annotations

import base64
import zlib
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any
from urllib.parse import urlencode
from xml.etree import ElementTree as ET

from ..crypto.rsa import RSAPrivateKey, RSAPublicKey
from ..util.clock import Clock, SystemClock
from ..util.ct import constant_time_equals, random_token
from .signature import XMLSignatureError, sign_element, verify_signature

SAMLP = "urn:oasis:names:tc:SAML:2.0:protocol"
SAML = "urn:oasis:names:tc:SAML:2.0:assertion"

NAMEID_EMAIL = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
NAMEID_PERSISTENT = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"
NAMEID_TRANSIENT = "urn:oasis:names:tc:SAML:2.0:nameid-format:transient"

STATUS_SUCCESS = "urn:oasis:names:tc:SAML:2.0:status:Success"
BEARER = "urn:oasis:names:tc:SAML:2.0:cm:bearer"
AC_PASSWORD_PROTECTED = "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport"
AC_MFA = "urn:oasis:names:tc:SAML:2.0:ac:classes:MultiFactorAuthentication"

ET.register_namespace("samlp", SAMLP)
ET.register_namespace("saml", SAML)


class SAMLError(Exception):
    """Any SAML protocol or validation failure."""


def _utc(when: datetime) -> str:
    return when.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse_utc(text: str) -> datetime:
    return datetime.strptime(text, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


def deflate_encode(xml: str) -> str:
    """HTTP-Redirect binding: raw DEFLATE, then base64, then URL-encode."""
    compressor = zlib.compressobj(9, zlib.DEFLATED, -zlib.MAX_WBITS)
    data = compressor.compress(xml.encode("utf-8")) + compressor.flush()
    return base64.b64encode(data).decode("ascii")


def deflate_decode(value: str) -> str:
    return zlib.decompress(base64.b64decode(value), -zlib.MAX_WBITS).decode("utf-8")


@dataclass
class ServiceProvider:
    """The application. Builds AuthnRequests and validates Responses."""

    entity_id: str                      # our identifier, becomes <Audience>
    acs_url: str                        # Assertion Consumer Service URL
    idp_entity_id: str                  # who we trust to issue assertions
    idp_certificate_key: RSAPublicKey   # their signing key
    clock: Clock = field(default_factory=SystemClock)
    leeway: int = 60
    # request id -> issued-at. The SAML equivalent of `state`.
    pending: dict[str, int] = field(default_factory=dict)
    # assertion id -> expiry, so a captured assertion cannot be replayed.
    consumed: dict[str, int] = field(default_factory=dict)
    request_ttl: int = 600

    def build_authn_request(
        self, idp_sso_url: str, relay_state: str | None = None, force_authn: bool = False
    ) -> tuple[str, str]:
        """Returns (request_id, redirect_url)."""
        request_id = f"_{random_token(16)}"
        now = datetime.fromtimestamp(self.clock.now(), timezone.utc)

        request = ET.Element(
            f"{{{SAMLP}}}AuthnRequest",
            {
                "ID": request_id,
                "Version": "2.0",
                "IssueInstant": _utc(now),
                "Destination": idp_sso_url,
                "AssertionConsumerServiceURL": self.acs_url,
                "ProtocolBinding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
            },
        )
        if force_authn:
            request.set("ForceAuthn", "true")
        ET.SubElement(request, f"{{{SAML}}}Issuer").text = self.entity_id
        ET.SubElement(
            request, f"{{{SAMLP}}}NameIDPolicy",
            {"Format": NAMEID_PERSISTENT, "AllowCreate": "true"},
        )

        self.pending[request_id] = self.clock.now()
        xml = ET.tostring(request, encoding="unicode")
        params = {"SAMLRequest": deflate_encode(xml)}
        if relay_state:
            # RelayState is SAML's `state`: where to send the user afterwards.
            # It must be opaque and validated, or it is an open redirect.
            params["RelayState"] = relay_state
        return request_id, f"{idp_sso_url}?{urlencode(params)}"

    def consume_response(self, saml_response_b64: str, relay_state: str | None = None) -> dict[str, Any]:
        """Validate a Response and return the authenticated subject and attributes.

        The checks, in order. Skipping ANY of them is a known bypass:

          1. signature -> and use only the element that was signed
          2. the signed element is the Assertion (not just the Response, and
             not some other element the attacker planted)
          3. Issuer is the IdP we configured
          4. Status is Success
          5. Destination / Recipient point at OUR ACS URL, so an assertion
             minted for another SP cannot be replayed here
          6. InResponseTo matches a request WE started (the CSRF check)
          7. Conditions NotBefore / NotOnOrAfter, with small leeway
          8. AudienceRestriction contains our entity id
          9. the assertion ID has not been seen before (replay)
        """
        try:
            xml = base64.b64decode(saml_response_b64)
            response = ET.fromstring(xml)
        except Exception as exc:  # noqa: BLE001
            raise SAMLError(f"malformed SAMLResponse: {exc}") from exc

        # 1 + 2. Verify and keep the element that was actually signed.
        try:
            signed = verify_signature(response, self.idp_certificate_key)
        except XMLSignatureError as exc:
            raise SAMLError(f"signature validation failed: {exc}") from exc

        if signed.tag == f"{{{SAMLP}}}Response":
            assertions = signed.findall(f"{{{SAML}}}Assertion")
            if len(assertions) != 1:
                raise SAMLError(f"expected exactly 1 assertion, found {len(assertions)}")
            assertion = assertions[0]
        elif signed.tag == f"{{{SAML}}}Assertion":
            assertion = signed
        else:
            raise SAMLError(f"signature covers {signed.tag}, which is neither Response nor Assertion")

        # If the whole Response was signed, the assertion inside it is covered
        # too. If only an Assertion was signed, make sure the document does
        # not also carry other assertions we would be tempted to read.
        all_assertions = [e for e in response.iter() if e.tag == f"{{{SAML}}}Assertion"]
        if len(all_assertions) != 1:
            raise SAMLError(
                f"document contains {len(all_assertions)} assertions; refusing (wrapping attack)"
            )
        if all_assertions[0] is not assertion:
            raise SAMLError("the assertion in the document is not the one that was signed")

        # 3. Issuer
        issuer = assertion.findtext(f"{{{SAML}}}Issuer")
        if issuer != self.idp_entity_id:
            raise SAMLError(f"unexpected Issuer: {issuer!r}")

        # 4. Status
        status_code = response.find(f"{{{SAMLP}}}Status/{{{SAMLP}}}StatusCode")
        if status_code is None or status_code.get("Value") != STATUS_SUCCESS:
            value = status_code.get("Value") if status_code is not None else "missing"
            raise SAMLError(f"authentication failed: status {value}")

        now = datetime.fromtimestamp(self.clock.now(), timezone.utc)
        leeway = timedelta(seconds=self.leeway)

        subject = assertion.find(f"{{{SAML}}}Subject")
        if subject is None:
            raise SAMLError("assertion has no Subject")
        confirmation_data = subject.find(
            f"{{{SAML}}}SubjectConfirmation/{{{SAML}}}SubjectConfirmationData"
        )
        if confirmation_data is None:
            raise SAMLError("assertion has no SubjectConfirmationData")

        # 5. Recipient must be our ACS.
        recipient = confirmation_data.get("Recipient")
        if not recipient or not constant_time_equals(recipient, self.acs_url):
            raise SAMLError(f"Recipient {recipient!r} is not our ACS URL")
        destination = response.get("Destination")
        if destination and not constant_time_equals(destination, self.acs_url):
            raise SAMLError(f"Destination {destination!r} is not our ACS URL")

        # 6. InResponseTo -- the assertion must answer a request we made.
        in_response_to = confirmation_data.get("InResponseTo") or response.get("InResponseTo")
        if not in_response_to:
            # An unsolicited assertion (IdP-initiated SSO) has no InResponseTo.
            # It is also unauthenticated from our side: anyone who can get the
            # IdP to mint one can log in as that user with no request from us.
            # Refuse it unless you have a specific reason and compensating
            # controls.
            raise SAMLError("unsolicited assertion (no InResponseTo); refused")
        if in_response_to not in self.pending:
            raise SAMLError(f"InResponseTo {in_response_to!r} does not match any pending request")
        if self.clock.now() - self.pending[in_response_to] > self.request_ttl:
            del self.pending[in_response_to]
            raise SAMLError("the corresponding AuthnRequest has expired")

        not_on_or_after = confirmation_data.get("NotOnOrAfter")
        if not_on_or_after and now - leeway >= _parse_utc(not_on_or_after):
            raise SAMLError("SubjectConfirmationData has expired")

        # 7. Conditions
        conditions = assertion.find(f"{{{SAML}}}Conditions")
        if conditions is None:
            raise SAMLError("assertion has no Conditions")
        not_before = conditions.get("NotBefore")
        if not_before and now + leeway < _parse_utc(not_before):
            raise SAMLError("assertion is not yet valid")
        expires = conditions.get("NotOnOrAfter")
        if expires and now - leeway >= _parse_utc(expires):
            raise SAMLError("assertion has expired")

        # 8. Audience
        audiences = [
            e.text
            for e in conditions.iter(f"{{{SAML}}}Audience")
        ]
        if self.entity_id not in audiences:
            raise SAMLError(f"AudienceRestriction {audiences} does not include {self.entity_id!r}")

        # 9. Replay
        assertion_id = assertion.get("ID") or ""
        self._purge_consumed()
        if assertion_id in self.consumed:
            raise SAMLError("assertion replay detected")
        expiry_ts = int(_parse_utc(expires).timestamp()) if expires else self.clock.now() + 300
        self.consumed[assertion_id] = expiry_ts
        del self.pending[in_response_to]

        name_id = subject.find(f"{{{SAML}}}NameID")
        attributes: dict[str, list[str]] = {}
        for attribute in assertion.iter(f"{{{SAML}}}Attribute"):
            name = attribute.get("Name", "")
            values = [v.text or "" for v in attribute.findall(f"{{{SAML}}}AttributeValue")]
            attributes[name] = values

        authn_statement = assertion.find(f"{{{SAML}}}AuthnStatement")
        authn_context = None
        if authn_statement is not None:
            authn_context = authn_statement.findtext(
                f"{{{SAML}}}AuthnContext/{{{SAML}}}AuthnContextClassRef"
            )

        return {
            "name_id": name_id.text if name_id is not None else None,
            "name_id_format": name_id.get("Format") if name_id is not None else None,
            "attributes": attributes,
            "session_index": authn_statement.get("SessionIndex") if authn_statement is not None else None,
            "authn_context": authn_context,
            "assertion_id": assertion_id,
            "relay_state": relay_state,
        }

    def _purge_consumed(self) -> None:
        now = self.clock.now()
        for key in [k for k, exp in self.consumed.items() if exp < now]:
            del self.consumed[key]


@dataclass
class IdentityProvider:
    """The IdP. Issues signed assertions."""

    entity_id: str
    sso_url: str
    signing_key: RSAPrivateKey
    certificate_b64: str | None = None
    clock: Clock = field(default_factory=SystemClock)
    assertion_lifetime: int = 300

    def parse_authn_request(self, saml_request: str) -> dict[str, Any]:
        xml = deflate_decode(saml_request)
        request = ET.fromstring(xml)
        return {
            "id": request.get("ID"),
            "issuer": request.findtext(f"{{{SAML}}}Issuer"),
            "acs_url": request.get("AssertionConsumerServiceURL"),
            "destination": request.get("Destination"),
            "force_authn": request.get("ForceAuthn") == "true",
        }

    def build_response(
        self,
        *,
        request_id: str,
        sp_entity_id: str,
        acs_url: str,
        name_id: str,
        name_id_format: str = NAMEID_PERSISTENT,
        attributes: dict[str, list[str]] | None = None,
        authn_context: str = AC_PASSWORD_PROTECTED,
        sign_assertion: bool = True,
    ) -> str:
        """Build a signed Response and return it base64-encoded for HTTP-POST."""
        now = datetime.fromtimestamp(self.clock.now(), timezone.utc)
        expires = now + timedelta(seconds=self.assertion_lifetime)
        response_id = f"_{random_token(16)}"
        assertion_id = f"_{random_token(16)}"
        session_index = f"_{random_token(12)}"

        response = ET.Element(
            f"{{{SAMLP}}}Response",
            {
                "ID": response_id,
                "Version": "2.0",
                "IssueInstant": _utc(now),
                "Destination": acs_url,
                "InResponseTo": request_id,
            },
        )
        ET.SubElement(response, f"{{{SAML}}}Issuer").text = self.entity_id
        status = ET.SubElement(response, f"{{{SAMLP}}}Status")
        ET.SubElement(status, f"{{{SAMLP}}}StatusCode", {"Value": STATUS_SUCCESS})

        assertion = ET.SubElement(
            response,
            f"{{{SAML}}}Assertion",
            {"ID": assertion_id, "Version": "2.0", "IssueInstant": _utc(now)},
        )
        ET.SubElement(assertion, f"{{{SAML}}}Issuer").text = self.entity_id

        subject = ET.SubElement(assertion, f"{{{SAML}}}Subject")
        ET.SubElement(subject, f"{{{SAML}}}NameID", {"Format": name_id_format}).text = name_id
        confirmation = ET.SubElement(
            subject, f"{{{SAML}}}SubjectConfirmation", {"Method": BEARER}
        )
        ET.SubElement(
            confirmation,
            f"{{{SAML}}}SubjectConfirmationData",
            {
                "NotOnOrAfter": _utc(expires),
                "Recipient": acs_url,
                "InResponseTo": request_id,
            },
        )

        conditions = ET.SubElement(
            assertion,
            f"{{{SAML}}}Conditions",
            {"NotBefore": _utc(now - timedelta(seconds=30)), "NotOnOrAfter": _utc(expires)},
        )
        restriction = ET.SubElement(conditions, f"{{{SAML}}}AudienceRestriction")
        ET.SubElement(restriction, f"{{{SAML}}}Audience").text = sp_entity_id

        statement = ET.SubElement(
            assertion,
            f"{{{SAML}}}AuthnStatement",
            {"AuthnInstant": _utc(now), "SessionIndex": session_index},
        )
        context = ET.SubElement(statement, f"{{{SAML}}}AuthnContext")
        ET.SubElement(context, f"{{{SAML}}}AuthnContextClassRef").text = authn_context

        if attributes:
            attribute_statement = ET.SubElement(assertion, f"{{{SAML}}}AttributeStatement")
            for name, values in attributes.items():
                attribute = ET.SubElement(
                    attribute_statement,
                    f"{{{SAML}}}Attribute",
                    {"Name": name, "NameFormat": "urn:oasis:names:tc:SAML:2.0:attrname-format:uri"},
                )
                for value in values:
                    ET.SubElement(attribute, f"{{{SAML}}}AttributeValue").text = value

        if sign_assertion:
            sign_element(assertion, self.signing_key, assertion_id, self.certificate_b64)
        else:
            sign_element(response, self.signing_key, response_id, self.certificate_b64)

        xml = ET.tostring(response, encoding="utf-8")
        return base64.b64encode(xml).decode("ascii")
