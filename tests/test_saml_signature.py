"""W3C exc-c14n vectors and XML-DSig profile tests."""

import base64
import unittest
from xml.dom import minidom
from xml.etree import ElementTree as ET

from authlab.crypto import generate_rsa_keypair
from authlab.saml import (
    CanonicalizationError,
    XMLSignatureError,
    exclusive_canonicalize,
    sign_element,
    verify_signature,
)
from authlab.saml.signature import DS, EXC_C14N


class TestExclusiveCanonicalization(unittest.TestCase):
    def test_w3c_reenveloping_example_is_context_independent(self):
        source = minidom.parseString(
            b'<n0:local xmlns:n0="foo:bar" xmlns:n3="ftp://example.org">'
            b'<n1:elem2 xmlns:n1="http://example.net" xml:lang="en">'
            b'<n3:stuff xmlns:n3="ftp://example.org"/></n1:elem2></n0:local>'
        )
        reenveloped = minidom.parseString(
            b'<n2:pdu xmlns:n1="http://example.com" xmlns:n2="http://foo.example" '
            b'xml:lang="fr" xml:space="retain">'
            b'<n1:elem2 xmlns:n1="http://example.net" xml:lang="en">'
            b'<n3:stuff xmlns:n3="ftp://example.org"/></n1:elem2></n2:pdu>'
        )
        expected = (
            b'<n1:elem2 xmlns:n1="http://example.net" xml:lang="en">'
            b'<n3:stuff xmlns:n3="ftp://example.org"></n3:stuff></n1:elem2>'
        )
        for document in (source, reenveloped):
            element = document.getElementsByTagNameNS("http://example.net", "elem2")[0]
            self.assertEqual(exclusive_canonicalize(element), expected)

    def test_inclusive_prefix_list_carries_non_visible_namespace(self):
        document = minidom.parseString(
            b'<root xmlns:policy="urn:example:policy">'
            b'<payload><item/></payload></root>'
        )
        payload = document.getElementsByTagName("payload")[0]
        self.assertEqual(
            exclusive_canonicalize(payload, ["policy"]),
            b'<payload xmlns:policy="urn:example:policy"><item></item></payload>',
        )

    def test_default_token_carries_non_visible_default_namespace(self):
        document = minidom.parseString(
            b'<root xmlns="urn:values" xmlns:p="urn:payload">'
            b'<p:payload><p:item/></p:payload></root>'
        )
        payload = document.getElementsByTagNameNS("urn:payload", "payload")[0]
        self.assertEqual(
            exclusive_canonicalize(payload),
            b'<p:payload xmlns:p="urn:payload"><p:item></p:item></p:payload>',
        )
        self.assertEqual(
            exclusive_canonicalize(payload, ["#default"]),
            b'<p:payload xmlns="urn:values" xmlns:p="urn:payload">'
            b'<p:item></p:item></p:payload>',
        )

    def test_canonical_attribute_order_and_escaping(self):
        element = minidom.parseString(
            b'<p:e xmlns:p="urn:e" xmlns:z="urn:z" b="2" z:a="1" a="&quot;&amp;"/>'
        ).documentElement
        self.assertEqual(
            exclusive_canonicalize(element),
            b'<p:e xmlns:p="urn:e" xmlns:z="urn:z" a="&quot;&amp;" b="2" z:a="1"></p:e>',
        )

    def test_dtd_is_refused(self):
        with self.assertRaises(CanonicalizationError):
            exclusive_canonicalize('<!DOCTYPE x [<!ENTITY e "boom">]><x>&e;</x>')


class TestExclusiveXMLSignature(unittest.TestCase):
    def setUp(self):
        self.key = generate_rsa_keypair(2048)

    def _signed(self, prefixes=()):
        element = ET.fromstring(
            '<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" '
            'ID="_a">'
            '<saml:Attribute xsi:type="xs:string" '
            'xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">alice</saml:Attribute>'
            "</saml:Assertion>"
        )
        # ElementTree intentionally drops namespace declarations used only in
        # QName-valued text/attributes, so the caller supplies that context
        # explicitly when it asks for an inclusive prefix.
        element.set("xmlns:xs", "http://www.w3.org/2001/XMLSchema")
        sign_element(element, self.key, "_a", inclusive_prefixes=prefixes)
        return ET.tostring(element, encoding="utf-8")

    def test_signature_uses_exc_c14n_and_prefix_list(self):
        xml = self._signed(("xs",))
        document = ET.fromstring(xml)
        methods = document.findall(f".//{{{DS}}}CanonicalizationMethod")
        transforms = document.findall(f".//{{{DS}}}Transform")
        self.assertEqual(methods[0].get("Algorithm"), EXC_C14N)
        self.assertEqual(transforms[-1].get("Algorithm"), EXC_C14N)
        self.assertEqual(
            methods[0].find(f"{{{EXC_C14N}}}InclusiveNamespaces").get("PrefixList"),
            "xs",
        )
        verified = verify_signature(xml, self.key.public)
        self.assertEqual(verified.get("ID"), "_a")

    def test_declared_algorithm_must_match_actual_algorithm(self):
        document = ET.fromstring(self._signed())
        method = document.find(f".//{{{DS}}}CanonicalizationMethod")
        method.set("Algorithm", "http://www.w3.org/TR/xml-c14n2")
        with self.assertRaises(XMLSignatureError):
            verify_signature(ET.tostring(document), self.key.public)

    def test_reenveloping_signed_assertion_keeps_signature_valid(self):
        signed = self._signed(("xs",))
        # Preserve the wire prefixes while changing only the ancestor context.
        # Parsing and reserializing through ElementTree would intentionally
        # discard the non-visibly-used xs declaration before this test begins.
        response = (
            b'<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" '
            b'xmlns:unused="urn:untrusted:envelope" ID="_response">'
            + signed
            + b"</samlp:Response>"
        )
        verified = verify_signature(response, self.key.public)
        self.assertEqual(verified.get("ID"), "_a")

    def test_transform_substitution_is_refused(self):
        document = ET.fromstring(self._signed())
        transforms = document.findall(f".//{{{DS}}}Transform")
        transforms[-1].set("Algorithm", "http://www.w3.org/TR/xml-c14n2")
        with self.assertRaises(XMLSignatureError):
            verify_signature(ET.tostring(document), self.key.public)


if __name__ == "__main__":
    unittest.main()
