from __future__ import annotations

import base64
import json
from pathlib import Path
import tempfile
import unittest
from xml.etree import ElementTree as ET

from authlab.crypto import generate_rsa_keypair
from authlab.jose import JWK
from authlab.saml import sign_element
from scripts.run_interop import (
    FIXTURE_PASSWORD,
    Trace,
    parse_forms,
    redact,
    validate_saml_response,
)


ROOT = Path(__file__).resolve().parents[1]


class TestInteropTrace(unittest.TestCase):
    def test_redacts_nested_credentials_and_tokens(self):
        redacted = redact(
            {
                "password": FIXTURE_PASSWORD,
                "nested": {
                    "message": f"credential={FIXTURE_PASSWORD}",
                    "id_token": "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ4In0.signature",
                },
            }
        )
        serialized = json.dumps(redacted)
        self.assertNotIn(FIXTURE_PASSWORD, serialized)
        self.assertNotIn("eyJhbGci", serialized)
        self.assertEqual(redacted["password"], "[REDACTED]")
        self.assertEqual(redacted["nested"]["id_token"], "[REDACTED]")

    def test_trace_contains_only_redacted_details(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "trace.jsonl"
            trace = Trace(path)
            trace.record(
                "OIDC",
                "fixture",
                "PASS",
                password=FIXTURE_PASSWORD,
                message=f"received {FIXTURE_PASSWORD}",
            )
            document = path.read_text(encoding="utf-8")
            self.assertNotIn(FIXTURE_PASSWORD, document)
            self.assertEqual(json.loads(document)["status"], "PASS")

    def test_failure_message_is_redacted_before_serialization(self):
        result = redact(
            f"request password={FIXTURE_PASSWORD} "
            "token=eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ4In0.signature"
        )
        self.assertNotIn(FIXTURE_PASSWORD, result)
        self.assertNotIn("eyJhbGci", result)


class TestInteropParsing(unittest.TestCase):
    def test_html_forms_preserve_hidden_protocol_state(self):
        forms = parse_forms(
            """
            <form method="post" action="/login">
              <input type="hidden" name="session_code" value="opaque">
              <input name="username">
              <input type="password" name="password">
            </form>
            """
        )
        self.assertEqual(len(forms), 1)
        self.assertEqual(forms[0].action, "/login")
        self.assertEqual(
            forms[0].inputs,
            {"session_code": "opaque", "username": "", "password": ""},
        )

    def test_saml_response_requires_signed_subject_binding(self):
        document = b"""
        <samlp:Response
          xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
          xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
          xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
          <ds:Signature />
          <saml:Assertion>
            <saml:Subject><saml:NameID>learner</saml:NameID></saml:Subject>
          </saml:Assertion>
        </samlp:Response>
        """
        result = validate_saml_response(base64.b64encode(document).decode())
        self.assertEqual(
            result,
            {"root": "Response", "signature_verified": False, "subject_bound": True},
        )

    def test_saml_response_rejects_unsigned_assertion(self):
        document = b"""
        <Response>
          <Assertion><Subject><NameID>learner</NameID></Subject></Assertion>
        </Response>
        """
        with self.assertRaisesRegex(AssertionError, "Signature"):
            validate_saml_response(base64.b64encode(document).decode())

    def test_saml_signature_is_verified_against_matching_trusted_jwks(self):
        key = generate_rsa_keypair(1024)
        assertion = ET.fromstring(
            """
            <saml:Assertion
              xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
              ID="_fixture">
              <saml:Subject><saml:NameID>learner</saml:NameID></saml:Subject>
            </saml:Assertion>
            """
        )
        sign_element(
            assertion,
            key,
            "_fixture",
            certificate_b64="fixture-certificate",
        )
        response = ET.Element(
            "{urn:oasis:names:tc:SAML:2.0:protocol}Response",
            {"ID": "_response"},
        )
        response.append(assertion)
        xml_document = ET.tostring(response, encoding="utf-8")
        jwk = JWK.from_rsa_public(key.public, kid="fixture")
        jwks_document = {
            "keys": [{**jwk.data, "x5c": ["fixture-certificate"]}],
        }
        result = validate_saml_response(
            base64.b64encode(xml_document).decode(),
            jwks_document,
        )
        self.assertTrue(result["signature_verified"])

        tampered = xml_document.replace(b"learner", b"attacker")
        with self.assertRaisesRegex(Exception, "digest mismatch"):
            validate_saml_response(base64.b64encode(tampered).decode(), jwks_document)


class TestInteropComposeIsolation(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.compose = (ROOT / "interop" / "compose.yaml").read_text(encoding="utf-8")

    def test_fixture_network_is_internal(self):
        self.assertIn("internal: true", self.compose)

    def test_product_ports_are_not_published_to_the_host(self):
        self.assertNotIn("ports:", self.compose)

    def test_runner_joins_the_same_internal_network(self):
        self.assertIn("  runner:", self.compose)
        self.assertIn("AUTHLAB_INTEROP_INSIDE", self.compose)
        self.assertIn("../:/workspace:ro", self.compose)

    def test_fixture_values_are_explicitly_non_production(self):
        fixture_files = [
            ROOT / "interop" / "keycloak" / "auth-lab-interop-realm.json",
            ROOT / "interop" / "openldap" / "bootstrap.ldif",
            ROOT / "interop" / "kerberos" / "entrypoint.sh",
        ]
        for path in fixture_files:
            with self.subTest(path=path):
                self.assertIn("fixture-only-", path.read_text(encoding="utf-8"))

    def test_keycloak_heap_override_does_not_conflict_with_image_defaults(self):
        self.assertNotIn("HeapFreeRatio", self.compose)

    def test_saml_client_has_an_idp_initiated_url_name(self):
        realm = json.loads(
            (
                ROOT / "interop" / "keycloak" / "auth-lab-interop-realm.json"
            ).read_text(encoding="utf-8")
        )
        saml_client = next(
            client for client in realm["clients"] if client["clientId"] == "authlab-saml"
        )
        self.assertEqual(
            saml_client["attributes"]["saml_idp_initiated_sso_url_name"],
            "authlab-saml",
        )
        self.assertEqual(
            saml_client["attributes"]["saml_assertion_consumer_url_post"],
            "http://127.0.0.1:18090/saml/acs",
        )


if __name__ == "__main__":
    unittest.main()
