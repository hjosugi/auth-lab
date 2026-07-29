"""XML Signature (XML-DSig) for SAML assertions.

XML-DSig is the reason SAML is hard. JWS signs a byte string; XML-DSig signs
a *tree*, and a tree can be serialised many ways -- attribute order,
namespace prefixes, whitespace, self-closing tags. So the standard defines
canonicalization (c14n): a fixed serialisation everyone must agree on before
hashing.

The structure of an enveloped signature:

    <Assertion ID="_abc">
      <Signature>
        <SignedInfo>
          <CanonicalizationMethod .../>
          <SignatureMethod Algorithm="...rsa-sha256"/>
          <Reference URI="#_abc">                 <-- points AT the Assertion
            <Transforms>enveloped-signature, c14n</Transforms>
            <DigestValue>base64(sha256(c14n(Assertion minus Signature)))</DigestValue>
          </Reference>
        </SignedInfo>
        <SignatureValue>base64(rsa(sha256(c14n(SignedInfo))))</SignatureValue>
      </Signature>
      ... claims ...
    </Assertion>

Two hashes, one signature. The signature covers SignedInfo; SignedInfo
contains the digest of the referenced element. That indirection is exactly
where XML Signature Wrapping (XSW) lives: an attacker keeps the original
signed assertion somewhere in the document so the digest still matches, and
adds a *second*, unsigned assertion that the application actually reads.
Every major SAML library shipped this bug at some point -- see Somorovsky et
al., "On Breaking SAML: Be Whoever You Want to Be" (USENIX 2012).

The defence, implemented in verify_signature below, is to return the element
that was actually signed and require callers to use THAT object, never a
re-query of the document. If your API is `verify(doc) -> bool` followed by
`doc.find('Assertion')`, you have the bug. If it is
`verify(doc) -> signed_element`, you cannot have it.

One honest deviation: real SAML uses Exclusive XML Canonicalization
(exc-c14n, http://www.w3.org/2001/10/xml-exc-c14n#). The standard library
gives us C14N 2.0 via ElementTree.canonicalize, so that is what we use, and
we declare it in CanonicalizationMethod. Signatures here are self-consistent
and structurally identical to real ones; they will not interoperate with a
production IdP, which would need exc-c14n implemented by hand.
"""

from __future__ import annotations

import hashlib
import io
from xml.etree import ElementTree as ET

from ..crypto.rsa import RSAPrivateKey, RSAPublicKey, rsassa_pkcs1_v15_sign, rsassa_pkcs1_v15_verify
from ..util.encoding import b64u_decode, b64u_encode

DS = "http://www.w3.org/2000/09/xmldsig#"
C14N = "http://www.w3.org/TR/xml-c14n2"          # what we actually use
EXC_C14N = "http://www.w3.org/2001/10/xml-exc-c14n#"  # what production SAML uses
RSA_SHA256 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
SHA256 = "http://www.w3.org/2001/04/xmlenc#sha256"
ENVELOPED = "http://www.w3.org/2000/09/xmldsig#enveloped-signature"

ET.register_namespace("ds", DS)


class XMLSignatureError(Exception):
    """Raised for any signature problem. Never distinguishes which one to a caller."""


def _b64(data: bytes) -> str:
    """XML-DSig uses standard base64 with padding, not base64url."""
    import base64

    return base64.b64encode(data).decode("ascii")


def _unb64(text: str) -> bytes:
    import base64

    return base64.b64decode("".join(text.split()))


def canonicalize(element: ET.Element) -> bytes:
    """Serialise an element canonically (C14N 2.0)."""
    raw = ET.tostring(element, encoding="utf-8")
    return ET.canonicalize(xml_data=raw.decode("utf-8"), strip_text=False).encode("utf-8")


def _digest_without_signature(element: ET.Element) -> bytes:
    """Hash an element with its own <Signature> removed (enveloped transform).

    We copy the tree first. Mutating the caller's document to compute a digest
    is how you end up with a "verified" document that no longer contains what
    was verified.
    """
    clone = ET.fromstring(ET.tostring(element, encoding="utf-8"))
    for parent in clone.iter():
        for child in list(parent):
            if child.tag == f"{{{DS}}}Signature":
                parent.remove(child)
    return hashlib.sha256(canonicalize(clone)).digest()


def sign_element(element: ET.Element, key: RSAPrivateKey, reference_id: str,
                 certificate_b64: str | None = None) -> ET.Element:
    """Add an enveloped signature to `element`, which must carry ID=reference_id."""
    if element.get("ID") != reference_id:
        raise XMLSignatureError(f"element ID {element.get('ID')!r} != {reference_id!r}")

    digest = _digest_without_signature(element)

    signature = ET.Element(f"{{{DS}}}Signature")
    signed_info = ET.SubElement(signature, f"{{{DS}}}SignedInfo")
    ET.SubElement(signed_info, f"{{{DS}}}CanonicalizationMethod", {"Algorithm": C14N})
    ET.SubElement(signed_info, f"{{{DS}}}SignatureMethod", {"Algorithm": RSA_SHA256})
    reference = ET.SubElement(signed_info, f"{{{DS}}}Reference", {"URI": f"#{reference_id}"})
    transforms = ET.SubElement(reference, f"{{{DS}}}Transforms")
    ET.SubElement(transforms, f"{{{DS}}}Transform", {"Algorithm": ENVELOPED})
    ET.SubElement(transforms, f"{{{DS}}}Transform", {"Algorithm": C14N})
    ET.SubElement(reference, f"{{{DS}}}DigestMethod", {"Algorithm": SHA256})
    ET.SubElement(reference, f"{{{DS}}}DigestValue").text = _b64(digest)

    signature_value = rsassa_pkcs1_v15_sign(key, canonicalize(signed_info), "sha256")
    ET.SubElement(signature, f"{{{DS}}}SignatureValue").text = _b64(signature_value)

    if certificate_b64:
        key_info = ET.SubElement(signature, f"{{{DS}}}KeyInfo")
        x509_data = ET.SubElement(key_info, f"{{{DS}}}X509Data")
        ET.SubElement(x509_data, f"{{{DS}}}X509Certificate").text = certificate_b64

    # An enveloped signature is the first child of what it signs.
    element.insert(0, signature)
    return element


def verify_signature(document: ET.Element, key: RSAPublicKey) -> ET.Element:
    """Verify and RETURN THE SIGNED ELEMENT.

    Returning the element rather than a boolean is the anti-XSW measure. A
    caller that uses the return value cannot be tricked into reading an
    unsigned sibling, because the only object it ever sees is the one whose
    digest was checked.

    Also enforced here:
      * exactly one Signature in the document (a second one is the classic
        wrapping setup and has no legitimate use in a SAML response)
      * the Reference URI resolves to exactly one element by ID
      * the algorithm is the one we expect, read from configuration rather
        than dispatched on -- the XML equivalent of alg=none
    """
    signatures = [e for e in document.iter() if e.tag == f"{{{DS}}}Signature"]
    if not signatures:
        raise XMLSignatureError("document is not signed")
    if len(signatures) > 1:
        raise XMLSignatureError(
            f"{len(signatures)} signatures present; refusing (XML signature wrapping)"
        )
    signature = signatures[0]

    signed_info = signature.find(f"{{{DS}}}SignedInfo")
    if signed_info is None:
        raise XMLSignatureError("missing SignedInfo")

    method = signed_info.find(f"{{{DS}}}SignatureMethod")
    if method is None or method.get("Algorithm") != RSA_SHA256:
        raise XMLSignatureError(
            f"unexpected SignatureMethod: {method.get('Algorithm') if method is not None else None}"
        )
    digest_method = signed_info.find(f"{{{DS}}}Reference/{{{DS}}}DigestMethod")
    if digest_method is None or digest_method.get("Algorithm") != SHA256:
        raise XMLSignatureError("unexpected DigestMethod")

    reference = signed_info.find(f"{{{DS}}}Reference")
    uri = reference.get("URI", "") if reference is not None else ""
    if not uri.startswith("#") or len(uri) < 2:
        # An empty URI means "the whole document" and an external URI would
        # make the verifier fetch attacker-controlled content. Neither is
        # acceptable in a SAML response.
        raise XMLSignatureError(f"unsupported Reference URI: {uri!r}")
    reference_id = uri[1:]

    matches = [e for e in document.iter() if e.get("ID") == reference_id]
    if len(matches) != 1:
        # Duplicate IDs are the other half of several wrapping variants: the
        # verifier resolves one, the application reads the other.
        raise XMLSignatureError(f"Reference {uri} resolves to {len(matches)} elements, need exactly 1")
    signed_element = matches[0]

    # The signature must be inside the element it claims to sign.
    if signature not in list(signed_element):
        raise XMLSignatureError("signature is not enveloped in the referenced element")

    digest_value = reference.find(f"{{{DS}}}DigestValue")
    if digest_value is None or not digest_value.text:
        raise XMLSignatureError("missing DigestValue")

    from ..util.ct import constant_time_equals

    actual_digest = _digest_without_signature(signed_element)
    if not constant_time_equals(actual_digest, _unb64(digest_value.text)):
        raise XMLSignatureError("digest mismatch: the referenced element was modified")

    signature_value = signature.find(f"{{{DS}}}SignatureValue")
    if signature_value is None or not signature_value.text:
        raise XMLSignatureError("missing SignatureValue")
    if not rsassa_pkcs1_v15_verify(
        key, canonicalize(signed_info), _unb64(signature_value.text), "sha256"
    ):
        raise XMLSignatureError("SignatureValue does not verify")

    return signed_element
