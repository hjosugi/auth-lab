"""Drill 09 -- SAML SSO and XML signature wrapping."""

from __future__ import annotations

import base64
from urllib.parse import parse_qsl, urlsplit
from xml.etree import ElementTree as ET

from _util import assert_true, expect_reject, note, step, title

from authlab.crypto import generate_rsa_keypair
from authlab.saml import NAMEID_EMAIL, IdentityProvider, ServiceProvider
from authlab.saml.protocol import SAML
from authlab.util.clock import FrozenClock


def main() -> None:
    title("Drill 09: SAML 2.0 SSO")
    clock = FrozenClock(1_700_000_000)
    idp_key = generate_rsa_keypair(2048)
    idp = IdentityProvider(entity_id="https://idp.lab/metadata", sso_url="https://idp.lab/sso",
                           signing_key=idp_key, clock=clock)
    sp = ServiceProvider(entity_id="https://sp.lab/metadata", acs_url="https://sp.lab/acs",
                         idp_entity_id=idp.entity_id, idp_certificate_key=idp_key.public, clock=clock)

    step(1, "SP builds an AuthnRequest (SAML's /authorize).")
    request_id, url = sp.build_authn_request(idp.sso_url, relay_state="/dashboard")
    parsed = idp.parse_authn_request(dict(parse_qsl(urlsplit(url).query))["SAMLRequest"])
    note(f"request from {parsed['issuer']} -> ACS {parsed['acs_url']}")

    step(2, "IdP mints a signed assertion; SP validates the whole checklist.")
    response = idp.build_response(
        request_id=parsed["id"], sp_entity_id=parsed["issuer"], acs_url=parsed["acs_url"],
        name_id="alice@lab", name_id_format=NAMEID_EMAIL,
        attributes={"groups": ["engineering", "admins"]},
    )
    result = sp.consume_response(response, relay_state="/dashboard")
    assert_true(result["name_id"] == "alice@lab", "assertion accepted, NameID read")
    note(f"attributes: {result['attributes']}")

    step(3, "The same assertion cannot be replayed.")
    expect_reject("assertion replay", lambda: sp.consume_response(response))

    def fresh() -> tuple[dict, str]:
        rid, u = sp.build_authn_request(idp.sso_url)
        p = idp.parse_authn_request(dict(parse_qsl(urlsplit(u).query))["SAMLRequest"])
        return p, idp.build_response(request_id=p["id"], sp_entity_id=p["issuer"], acs_url=p["acs_url"], name_id="alice@lab")

    step(4, "XML Signature Wrapping: inject a forged admin assertion.")
    parsed, signed = fresh()
    doc = ET.fromstring(base64.b64decode(signed))
    original = doc.find(f"{{{SAML}}}Assertion")
    forged = ET.fromstring(ET.tostring(original))
    for sig in forged.findall("{http://www.w3.org/2000/09/xmldsig#}Signature"):
        forged.remove(sig)
    forged.set("ID", "_forged")
    forged.find(f"{{{SAML}}}Subject/{{{SAML}}}NameID").text = "admin@lab"
    doc.insert(list(doc).index(original), forged)
    expect_reject(
        "XSW forged assertion",
        lambda: sp.consume_response(base64.b64encode(ET.tostring(doc)).decode()),
    )

    step(5, "Tampering the NameID breaks the signature digest.")
    parsed, signed = fresh()
    doc = ET.fromstring(base64.b64decode(signed))
    doc.find(f"{{{SAML}}}Assertion/{{{SAML}}}Subject/{{{SAML}}}NameID").text = "admin@lab"
    expect_reject("tampered NameID", lambda: sp.consume_response(base64.b64encode(ET.tostring(doc)).decode()))

    step(6, "An assertion minted for a different SP is refused (audience).")
    parsed, _ = fresh()
    wrong = idp.build_response(request_id=parsed["id"], sp_entity_id="https://other-sp/metadata",
                               acs_url=sp.acs_url, name_id="alice@lab")
    expect_reject("assertion for another SP", lambda: sp.consume_response(wrong))

    print("\nDrill 09 complete.")


if __name__ == "__main__":
    main()
