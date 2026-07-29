"""Tests for SAML, WebAuthn, Kerberos, LDAP, SCIM, and mTLS."""

import base64
import unittest
from urllib.parse import parse_qsl, urlsplit
from xml.etree import ElementTree as ET

from authlab.crypto import generate_rsa_keypair
from authlab.crypto.x509 import CertificateAuthority
from authlab.directory import LDAP, SCIMServer, SCIMError, escape_filter
from authlab.kerberos import KDC, KerberizedService, KerberosClient, KerberosError
from authlab.mtls import MutualTLSClient, MutualTLSServer, MTLSError, certificate_thumbprint
from authlab.saml import IdentityProvider, ServiceProvider, SAMLError
from authlab.saml.protocol import SAML
from authlab.util.clock import FrozenClock
from authlab.util.encoding import b64u_decode
from authlab.webauthn import RelyingParty, VirtualAuthenticator, WebAuthnError


class TestSAML(unittest.TestCase):
    def setUp(self):
        self.clock = FrozenClock(1_700_000_000)
        self.idp_key = generate_rsa_keypair(2048)
        self.idp = IdentityProvider(entity_id="https://idp/meta", sso_url="https://idp/sso",
                                    signing_key=self.idp_key, clock=self.clock)
        self.sp = ServiceProvider(entity_id="https://sp/meta", acs_url="https://sp/acs",
                                  idp_entity_id=self.idp.entity_id, idp_certificate_key=self.idp_key.public,
                                  clock=self.clock)

    def _flow(self):
        _, url = self.sp.build_authn_request(self.idp.sso_url)
        parsed = self.idp.parse_authn_request(dict(parse_qsl(urlsplit(url).query))["SAMLRequest"])
        return parsed, self.idp.build_response(request_id=parsed["id"], sp_entity_id=parsed["issuer"],
                                               acs_url=parsed["acs_url"], name_id="alice@lab")

    def test_happy_path(self):
        _, response = self._flow()
        result = self.sp.consume_response(response)
        self.assertEqual(result["name_id"], "alice@lab")

    def test_replay(self):
        _, response = self._flow()
        self.sp.consume_response(response)
        with self.assertRaises(SAMLError):
            self.sp.consume_response(response)

    def test_signature_wrapping(self):
        _, response = self._flow()
        doc = ET.fromstring(base64.b64decode(response))
        original = doc.find(f"{{{SAML}}}Assertion")
        forged = ET.fromstring(ET.tostring(original))
        for sig in forged.findall("{http://www.w3.org/2000/09/xmldsig#}Signature"):
            forged.remove(sig)
        forged.set("ID", "_forged")
        forged.find(f"{{{SAML}}}Subject/{{{SAML}}}NameID").text = "admin@lab"
        doc.insert(0, forged)
        with self.assertRaises(SAMLError):
            self.sp.consume_response(base64.b64encode(ET.tostring(doc)).decode())

    def test_tampered(self):
        _, response = self._flow()
        doc = ET.fromstring(base64.b64decode(response))
        doc.find(f"{{{SAML}}}Assertion/{{{SAML}}}Subject/{{{SAML}}}NameID").text = "admin@lab"
        with self.assertRaises(SAMLError):
            self.sp.consume_response(base64.b64encode(ET.tostring(doc)).decode())


class TestWebAuthn(unittest.TestCase):
    def setUp(self):
        self.clock = FrozenClock(1_700_000_000)
        self.rp = RelyingParty(rp_id="lab.local", origins=["https://lab.local"], clock=self.clock)
        self.auth = VirtualAuthenticator()
        self.uh = b"user-1"
        options = self.rp.registration_options("s1", self.uh, "alice")
        cred = self.auth.make_credential(rp_id="lab.local", origin="https://lab.local",
                                         challenge=b64u_decode(options["challenge"]), user_handle=self.uh, attestation="packed")
        self.rp.verify_registration("s1", cred, self.uh)

    def _login(self, session):
        options = self.rp.authentication_options(session, self.uh)
        return self.auth.get_assertion(rp_id="lab.local", origin="https://lab.local",
                                       challenge=b64u_decode(options["challenge"]))

    def test_login(self):
        result = self.rp.verify_authentication("s2", self._login("s2"))
        self.assertEqual(result.sign_count, 1)

    def test_phishing_no_key(self):
        with self.assertRaises(ValueError):
            self.auth.get_assertion(rp_id="1ab.local", origin="https://1ab.local", challenge=b"x" * 32)

    def test_replay(self):
        assertion = self._login("s3")
        self.rp.verify_authentication("s3", assertion)
        with self.assertRaises(WebAuthnError):
            self.rp.verify_authentication("s3", assertion)

    def test_clone_detection(self):
        options = self.rp.authentication_options("s4", self.uh)
        cloned = self.auth.get_assertion(rp_id="lab.local", origin="https://lab.local",
                                         challenge=b64u_decode(options["challenge"]), sign_count_override=1)
        # first advance the real counter beyond 1
        self.rp.verify_authentication("s5", self._login("s5"))
        with self.assertRaises(WebAuthnError):
            self.rp.verify_authentication("s4", cloned)


class TestKerberos(unittest.TestCase):
    def setUp(self):
        self.clock = FrozenClock(1_700_000_000)
        self.kdc = KDC(realm="LAB", clock=self.clock)
        self.kdc.add_principal("alice", "pw-alice", groups=["Users"])
        self.kdc.add_principal("HTTP/web", "svc-pw", is_service=True)
        self.web = KerberizedService(name="HTTP/web", realm="LAB", key=self.kdc.principals["HTTP/web"].key, clock=self.clock)
        self.client = KerberosClient(principal="alice", realm="LAB", kdc=self.kdc, clock=self.clock)
        self.client.kinit("pw-alice")

    def test_happy_path(self):
        ticket, auth = self.client.ap_req("HTTP/web")
        client, ap_rep = self.web.ap_req(ticket, auth, mutual=True)
        self.assertEqual(client.name, "alice@LAB")
        self.assertTrue(self.client.verify_ap_rep("HTTP/web", ap_rep))

    def test_wrong_password(self):
        with self.assertRaises(KerberosError):
            KerberosClient(principal="alice", realm="LAB", kdc=self.kdc, clock=self.clock).kinit("nope")

    def test_authenticator_replay(self):
        ticket, auth = self.client.ap_req("HTTP/web")
        self.web.ap_req(ticket, auth, mutual=False)
        with self.assertRaises(KerberosError):
            self.web.ap_req(ticket, auth, mutual=False)

    def test_kerberoasting(self):
        self.kdc.add_principal("svc_weak", "summer2023", is_service=True)
        material = self.client.get_service_ticket("svc_weak")
        self.assertEqual(self.kdc.crack_service_ticket(material.ticket, ["a", "summer2023"], "svc_weak"), "summer2023")


class TestLDAP(unittest.TestCase):
    def setUp(self):
        self.d = LDAP()
        self.d.add("dc=lab", {"objectClass": ["domain"]})
        self.d.add("uid=alice,dc=lab", {"uid": ["alice"]}, password="pw")

    def test_login(self):
        self.assertIsNotNone(self.d.authenticate("alice", "pw", base_dn="dc=lab"))

    def test_wrong_password(self):
        self.assertIsNone(self.d.authenticate("alice", "no", base_dn="dc=lab"))

    def test_empty_password(self):
        self.assertIsNone(self.d.authenticate("alice", "", base_dn="dc=lab"))
        with self.assertRaises(Exception):
            self.d.simple_bind("uid=alice,dc=lab", "")

    def test_injection(self):
        self.assertIsNone(self.d.authenticate("*)(uid=*", "x", base_dn="dc=lab"))
        self.assertEqual(len(self.d.search("dc=lab", f"(uid={escape_filter('*)(uid=*')})")), 0)


class TestSCIM(unittest.TestCase):
    def setUp(self):
        self.scim = SCIMServer()

    def test_lifecycle(self):
        user = self.scim.create_user({"userName": "bob", "externalId": "x"})
        self.assertTrue(self.scim.is_active(user["id"]))
        self.scim.deactivate_user(user["id"])
        self.assertFalse(self.scim.is_active(user["id"]))

    def test_duplicate(self):
        self.scim.create_user({"userName": "bob"})
        with self.assertRaises(SCIMError):
            self.scim.create_user({"userName": "bob"})

    def test_filter(self):
        self.scim.create_user({"userName": "bob", "emails": [{"value": "bob@lab"}]})
        self.assertEqual(self.scim.list_users('userName eq "bob"')["totalResults"], 1)


class TestMutualTLS(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ca = CertificateAuthority("test CA")
        cls.server_cert = cls.ca.issue("localhost", dns_names=["localhost"], ip_addresses=["127.0.0.1"], server_auth=True)
        cls.client_cert = cls.ca.issue("client", client_auth=True)

    def test_handshake(self):
        server = MutualTLSServer(ca=self.ca, server_cert=self.server_cert)
        port = server.start()
        try:
            response = MutualTLSClient(ca=self.ca, client_cert=self.client_cert).request(port, b"ping")
            self.assertTrue(response.startswith(b"OK"))
        finally:
            server.stop()

    def test_no_client_cert_rejected(self):
        server = MutualTLSServer(ca=self.ca, server_cert=self.server_cert)
        port = server.start()
        try:
            with self.assertRaises(MTLSError):
                MutualTLSClient(ca=self.ca, client_cert=None).request(port, b"ping")
        finally:
            server.stop()

    def test_thumbprint(self):
        self.assertEqual(len(certificate_thumbprint(self.client_cert.der)), 43)  # 32 bytes b64url


if __name__ == "__main__":
    unittest.main()
