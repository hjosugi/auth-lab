"""SAML Web Browser SSO simulator with strict assertion selection.

Real SAML uses XML Signature and schema-aware libraries. This lab uses an HMAC
over selected fields so the validation order remains readable.
"""

from __future__ import annotations

import hashlib
import hmac
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field

from .util import AuthError, ReplayCache, canonical_json, random_token, secure_equal

NS = "urn:oasis:names:tc:SAML:2.0:assertion"
PROTOCOL_NS = "urn:oasis:names:tc:SAML:2.0:protocol"
ET.register_namespace("saml", NS)
ET.register_namespace("samlp", PROTOCOL_NS)


def _signed_fields(
    *,
    response_id: str,
    assertion_id: str,
    issuer: str,
    subject: str,
    audience: str,
    destination: str,
    in_response_to: str,
    not_before: int,
    not_on_or_after: int,
) -> bytes:
    return canonical_json(
        {
            "response_id": response_id,
            "assertion_id": assertion_id,
            "issuer": issuer,
            "subject": subject,
            "audience": audience,
            "destination": destination,
            "in_response_to": in_response_to,
            "not_before": not_before,
            "not_on_or_after": not_on_or_after,
        }
    )


def issue_response(
    *,
    key: bytes,
    issuer: str,
    subject: str,
    audience: str,
    destination: str,
    in_response_to: str,
    now: int,
) -> str:
    response_id = "_" + random_token(12)
    assertion_id = "_" + random_token(12)
    not_before, not_on_or_after = now - 30, now + 300
    root = ET.Element(
        f"{{{PROTOCOL_NS}}}Response",
        {
            "ID": response_id,
            "Destination": destination,
            "InResponseTo": in_response_to,
        },
    )
    ET.SubElement(root, f"{{{NS}}}Issuer").text = issuer
    assertion = ET.SubElement(
        root,
        f"{{{NS}}}Assertion",
        {
            "ID": assertion_id,
            "NotBefore": str(not_before),
            "NotOnOrAfter": str(not_on_or_after),
        },
    )
    ET.SubElement(assertion, f"{{{NS}}}Issuer").text = issuer
    ET.SubElement(assertion, f"{{{NS}}}Subject").text = subject
    ET.SubElement(assertion, f"{{{NS}}}Audience").text = audience
    data = _signed_fields(
        response_id=response_id,
        assertion_id=assertion_id,
        issuer=issuer,
        subject=subject,
        audience=audience,
        destination=destination,
        in_response_to=in_response_to,
        not_before=not_before,
        not_on_or_after=not_on_or_after,
    )
    ET.SubElement(assertion, f"{{{NS}}}SignatureValue").text = hmac.new(
        key,
        data,
        hashlib.sha256,
    ).hexdigest()
    return ET.tostring(root, encoding="unicode")


@dataclass
class SAMLServiceProvider:
    idp_issuer: str
    audience: str
    acs_url: str
    verification_key: bytes
    replay_cache: ReplayCache = field(default_factory=ReplayCache)

    def validate(self, xml_text: str, *, request_id: str, now: int) -> str:
        if len(xml_text.encode()) > 100_000:
            raise AuthError("SAML response is too large")
        upper = xml_text.upper()
        if "<!DOCTYPE" in upper or "<!ENTITY" in upper:
            raise AuthError("DTD and entities are forbidden")
        try:
            root = ET.fromstring(xml_text)
        except ET.ParseError as exc:
            raise AuthError("invalid SAML XML") from exc
        if root.tag != f"{{{PROTOCOL_NS}}}Response":
            raise AuthError("unexpected SAML root element")
        assertions = root.findall(f"./{{{NS}}}Assertion")
        if len(assertions) != 1:
            raise AuthError("exactly one direct signed assertion is required")
        assertion = assertions[0]
        response_id = root.get("ID", "")
        assertion_id = assertion.get("ID", "")
        destination = root.get("Destination", "")
        in_response_to = root.get("InResponseTo", "")
        issuer = (assertion.findtext(f"./{{{NS}}}Issuer") or "").strip()
        response_issuer = (root.findtext(f"./{{{NS}}}Issuer") or "").strip()
        subject = (assertion.findtext(f"./{{{NS}}}Subject") or "").strip()
        audience = (assertion.findtext(f"./{{{NS}}}Audience") or "").strip()
        signature = (assertion.findtext(f"./{{{NS}}}SignatureValue") or "").strip()
        try:
            not_before = int(assertion.get("NotBefore", ""))
            not_on_or_after = int(assertion.get("NotOnOrAfter", ""))
        except ValueError as exc:
            raise AuthError("invalid SAML time condition") from exc
        if (
            not response_id
            or not assertion_id
            or issuer != self.idp_issuer
            or response_issuer != issuer
            or audience != self.audience
            or destination != self.acs_url
            or in_response_to != request_id
        ):
            raise AuthError("SAML binding or trust check failed")
        if now < not_before or now >= not_on_or_after:
            raise AuthError("SAML assertion is outside its validity window")
        data = _signed_fields(
            response_id=response_id,
            assertion_id=assertion_id,
            issuer=issuer,
            subject=subject,
            audience=audience,
            destination=destination,
            in_response_to=in_response_to,
            not_before=not_before,
            not_on_or_after=not_on_or_after,
        )
        expected = hmac.new(self.verification_key, data, hashlib.sha256).hexdigest()
        if not secure_equal(signature, expected):
            raise AuthError("invalid SAML signature")
        self.replay_cache.consume(assertion_id, not_on_or_after, now)
        return subject

