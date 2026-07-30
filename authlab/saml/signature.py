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

SAML deployments normally use Exclusive XML Canonicalization 1.0
(exc-c14n, http://www.w3.org/2001/10/xml-exc-c14n#).  ``saml.c14n`` implements
the constrained W3C algorithm with the standard library so the algorithm named
in SignedInfo is the algorithm actually applied.
"""

from __future__ import annotations

import hashlib
import base64
import binascii
from collections.abc import Iterable
from xml.dom import Node
from xml.dom.minidom import Element as DOMElement
from xml.etree import ElementTree as ET

from ..crypto.rsa import RSAPrivateKey, RSAPublicKey, rsassa_pkcs1_v15_sign, rsassa_pkcs1_v15_verify
from .c14n import CanonicalizationError, exclusive_canonicalize, parse_xml_document

DS = "http://www.w3.org/2000/09/xmldsig#"
EXC_C14N = "http://www.w3.org/2001/10/xml-exc-c14n#"
RSA_SHA256 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
SHA256 = "http://www.w3.org/2001/04/xmlenc#sha256"
ENVELOPED = "http://www.w3.org/2000/09/xmldsig#enveloped-signature"

ET.register_namespace("ds", DS)
ET.register_namespace("ec", EXC_C14N)


class XMLSignatureError(Exception):
    """Raised for any signature problem. Never distinguishes which one to a caller."""


def _b64(data: bytes) -> str:
    """XML-DSig uses standard base64 with padding, not base64url."""
    return base64.b64encode(data).decode("ascii")


def _unb64(text: str) -> bytes:
    try:
        return base64.b64decode("".join(text.split()), validate=True)
    except (binascii.Error, ValueError) as exc:
        raise XMLSignatureError("invalid base64 in signature") from exc


def canonicalize(
    element: ET.Element | DOMElement | bytes | str,
    inclusive_prefixes: Iterable[str] = (),
) -> bytes:
    """Serialise an element with Exclusive XML Canonicalization 1.0."""

    return exclusive_canonicalize(element, inclusive_prefixes)


def _digest_without_signature(
    element: ET.Element | DOMElement,
    inclusive_prefixes: Iterable[str] = (),
    signature: DOMElement | None = None,
) -> bytes:
    """Hash an element with its own <Signature> removed (enveloped transform).

    We copy the tree first. Mutating the caller's document to compute a digest
    is how you end up with a "verified" document that no longer contains what
    was verified.
    """
    if isinstance(element, DOMElement):
        excluded = (signature,) if signature is not None else ()
        serialized = exclusive_canonicalize(
            element,
            inclusive_prefixes,
            exclude_elements=excluded,
        )
    else:
        dom = parse_xml_document(ET.tostring(element, encoding="utf-8"))
        signatures = dom.getElementsByTagNameNS(DS, "Signature")
        serialized = exclusive_canonicalize(
            dom.documentElement,
            inclusive_prefixes,
            exclude_elements=signatures,
        )
    return hashlib.sha256(serialized).digest()


def _prefix_list(parent: DOMElement) -> tuple[str, ...]:
    values = [
        child.getAttribute("PrefixList")
        for child in parent.childNodes
        if child.nodeType == Node.ELEMENT_NODE
        and child.namespaceURI == EXC_C14N
        and child.localName == "InclusiveNamespaces"
    ]
    if len(values) > 1:
        raise XMLSignatureError("multiple InclusiveNamespaces parameters")
    return tuple(values[0].split()) if values else ()


def _direct_children(parent: DOMElement, namespace: str, local_name: str) -> list[DOMElement]:
    return [
        child
        for child in parent.childNodes
        if child.nodeType == Node.ELEMENT_NODE
        and child.namespaceURI == namespace
        and child.localName == local_name
    ]


def _one_child(parent: DOMElement, namespace: str, local_name: str) -> DOMElement:
    matches = _direct_children(parent, namespace, local_name)
    if len(matches) != 1:
        raise XMLSignatureError(f"expected exactly one {local_name}, found {len(matches)}")
    return matches[0]


def _append_prefix_list(parent: ET.Element, inclusive_prefixes: tuple[str, ...]) -> None:
    if inclusive_prefixes:
        ET.SubElement(
            parent,
            f"{{{EXC_C14N}}}InclusiveNamespaces",
            {"PrefixList": " ".join(inclusive_prefixes)},
        )


def sign_element(
    element: ET.Element,
    key: RSAPrivateKey,
    reference_id: str,
    certificate_b64: str | None = None,
    inclusive_prefixes: Iterable[str] = (),
) -> ET.Element:
    """Add an enveloped signature to `element`, which must carry ID=reference_id."""
    if element.get("ID") != reference_id:
        raise XMLSignatureError(f"element ID {element.get('ID')!r} != {reference_id!r}")

    prefixes = tuple(inclusive_prefixes)
    digest = _digest_without_signature(element, prefixes)

    signature = ET.Element(f"{{{DS}}}Signature")
    signed_info = ET.SubElement(signature, f"{{{DS}}}SignedInfo")
    canonicalization_method = ET.SubElement(
        signed_info,
        f"{{{DS}}}CanonicalizationMethod",
        {"Algorithm": EXC_C14N},
    )
    _append_prefix_list(canonicalization_method, prefixes)
    ET.SubElement(signed_info, f"{{{DS}}}SignatureMethod", {"Algorithm": RSA_SHA256})
    reference = ET.SubElement(signed_info, f"{{{DS}}}Reference", {"URI": f"#{reference_id}"})
    transforms = ET.SubElement(reference, f"{{{DS}}}Transforms")
    ET.SubElement(transforms, f"{{{DS}}}Transform", {"Algorithm": ENVELOPED})
    canonicalization_transform = ET.SubElement(
        transforms,
        f"{{{DS}}}Transform",
        {"Algorithm": EXC_C14N},
    )
    _append_prefix_list(canonicalization_transform, prefixes)
    ET.SubElement(reference, f"{{{DS}}}DigestMethod", {"Algorithm": SHA256})
    ET.SubElement(reference, f"{{{DS}}}DigestValue").text = _b64(digest)

    signature_value_element = ET.SubElement(signature, f"{{{DS}}}SignatureValue")

    if certificate_b64:
        key_info = ET.SubElement(signature, f"{{{DS}}}KeyInfo")
        x509_data = ET.SubElement(key_info, f"{{{DS}}}X509Data")
        ET.SubElement(x509_data, f"{{{DS}}}X509Certificate").text = certificate_b64

    # An enveloped signature is the first child of what it signs.  Insert it
    # before canonicalizing SignedInfo so inherited namespaces named by an
    # InclusiveNamespaces PrefixList are in scope exactly as they will be on
    # the wire.
    element.insert(0, signature)
    dom = parse_xml_document(ET.tostring(element, encoding="utf-8"))
    dom_signatures = dom.getElementsByTagNameNS(DS, "Signature")
    dom_signed_info = _one_child(dom_signatures[0], DS, "SignedInfo")
    signature_value = rsassa_pkcs1_v15_sign(
        key,
        canonicalize(dom_signed_info, prefixes),
        "sha256",
    )
    signature_value_element.text = _b64(signature_value)
    return element


def verify_signature(document: ET.Element | bytes | str, key: RSAPublicKey) -> ET.Element:
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
    try:
        if isinstance(document, ET.Element):
            raw = ET.tostring(document, encoding="utf-8")
        else:
            raw = document
        dom = parse_xml_document(raw)
    except CanonicalizationError as exc:
        raise XMLSignatureError(f"malformed XML: {exc}") from exc
    except Exception as exc:  # noqa: BLE001 - normalize parser failures at the trust boundary
        raise XMLSignatureError(f"malformed XML: {exc}") from exc

    signatures = [
        element
        for element in dom.getElementsByTagNameNS(DS, "Signature")
        if isinstance(element, DOMElement)
    ]
    if not signatures:
        raise XMLSignatureError("document is not signed")
    if len(signatures) > 1:
        raise XMLSignatureError(
            f"{len(signatures)} signatures present; refusing (XML signature wrapping)"
        )
    signature = signatures[0]

    signed_info = _one_child(signature, DS, "SignedInfo")

    canonicalization_method = _one_child(signed_info, DS, "CanonicalizationMethod")
    if canonicalization_method.getAttribute("Algorithm") != EXC_C14N:
        raise XMLSignatureError("unexpected CanonicalizationMethod")
    signed_info_prefixes = _prefix_list(canonicalization_method)

    method = _one_child(signed_info, DS, "SignatureMethod")
    if method.getAttribute("Algorithm") != RSA_SHA256:
        raise XMLSignatureError(
            f"unexpected SignatureMethod: {method.getAttribute('Algorithm')!r}"
        )
    reference = _one_child(signed_info, DS, "Reference")
    digest_method = _one_child(reference, DS, "DigestMethod")
    if digest_method.getAttribute("Algorithm") != SHA256:
        raise XMLSignatureError("unexpected DigestMethod")

    uri = reference.getAttribute("URI")
    if not uri.startswith("#") or len(uri) < 2:
        # An empty URI means "the whole document" and an external URI would
        # make the verifier fetch attacker-controlled content. Neither is
        # acceptable in a SAML response.
        raise XMLSignatureError(f"unsupported Reference URI: {uri!r}")
    reference_id = uri[1:]

    matches = [
        element
        for element in dom.getElementsByTagName("*")
        if isinstance(element, DOMElement) and element.getAttribute("ID") == reference_id
    ]
    if len(matches) != 1:
        # Duplicate IDs are the other half of several wrapping variants: the
        # verifier resolves one, the application reads the other.
        raise XMLSignatureError(f"Reference {uri} resolves to {len(matches)} elements, need exactly 1")
    signed_element = matches[0]

    # The signature must be inside the element it claims to sign.
    if signature.parentNode is not signed_element:
        raise XMLSignatureError("signature is not enveloped in the referenced element")

    transforms = _one_child(reference, DS, "Transforms")
    transform_elements = _direct_children(transforms, DS, "Transform")
    algorithms = [transform.getAttribute("Algorithm") for transform in transform_elements]
    if algorithms != [ENVELOPED, EXC_C14N]:
        raise XMLSignatureError(f"unexpected transforms: {algorithms!r}")
    digest_prefixes = _prefix_list(transform_elements[1])

    digest_value = _one_child(reference, DS, "DigestValue")
    digest_text = "".join(
        child.nodeValue or ""
        for child in digest_value.childNodes
        if child.nodeType in (Node.TEXT_NODE, Node.CDATA_SECTION_NODE)
    )
    if not digest_text.strip():
        raise XMLSignatureError("missing DigestValue")

    from ..util.ct import constant_time_equals

    actual_digest = _digest_without_signature(
        signed_element,
        digest_prefixes,
        signature,
    )
    if not constant_time_equals(actual_digest, _unb64(digest_text)):
        raise XMLSignatureError("digest mismatch: the referenced element was modified")

    signature_value = _one_child(signature, DS, "SignatureValue")
    signature_text = "".join(
        child.nodeValue or ""
        for child in signature_value.childNodes
        if child.nodeType in (Node.TEXT_NODE, Node.CDATA_SECTION_NODE)
    )
    if not signature_text.strip():
        raise XMLSignatureError("missing SignatureValue")
    if not rsassa_pkcs1_v15_verify(
        key,
        canonicalize(signed_info, signed_info_prefixes),
        _unb64(signature_text),
        "sha256",
    ):
        raise XMLSignatureError("SignatureValue does not verify")

    # Return a fresh ElementTree created from the canonical bytes of exactly
    # the verified subtree.  This preserves the return-the-signed-element
    # anti-XSW API without leaking an unsigned sibling back to the caller.
    return ET.fromstring(canonicalize(signed_element, digest_prefixes))
