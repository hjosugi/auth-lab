"""Exclusive XML Canonicalization 1.0, implemented with the standard library.

ElementTree stores expanded names but discards the prefixes that appeared on
the wire.  Prefixes are significant input to XML canonicalization, so this
module uses minidom: it preserves qualified names and the namespace axis while
remaining dependency-free.

This is intentionally a constrained implementation of the algorithm in W3C
REC-xml-exc-c14n-20020718 section 3.1.  Its input is a well-formed element
subtree (the shape used by XML-DSig), all descendants and attributes are in the
node-set, and comments are omitted.  It supports visibly utilised namespaces,
ancestor namespace context, ``InclusiveNamespaces PrefixList``, default
namespace reset, canonical attribute ordering, and canonical escaping.

It is teaching code, not a replacement for a maintained XML security library.
"""

from __future__ import annotations

from collections.abc import Iterable
from urllib.parse import urlsplit
from xml.dom import Node, minidom
from xml.dom.minidom import Document, Element
from xml.etree import ElementTree as ET

XML = "http://www.w3.org/XML/1998/namespace"
XMLNS = "http://www.w3.org/2000/xmlns/"


class CanonicalizationError(ValueError):
    """The input cannot be represented by this exc-c14n profile."""


def parse_xml_document(xml: bytes | str) -> Document:
    """Parse XML after refusing DTD/entity declarations.

    SAML protocol messages do not need a DTD.  Refusing it also keeps this
    educational verifier away from entity expansion and external-entity
    resolution concerns that belong in a hardened production parser.
    """

    raw = xml if isinstance(xml, bytes) else xml.encode("utf-8")
    upper = raw.upper()
    if b"<!DOCTYPE" in upper or b"<!ENTITY" in upper:
        raise CanonicalizationError("DTD and entity declarations are not accepted")
    return minidom.parseString(raw)


def _to_dom(value: Element | ET.Element | bytes | str) -> Element:
    if isinstance(value, Element):
        return value
    if isinstance(value, ET.Element):
        document = parse_xml_document(ET.tostring(value, encoding="utf-8"))
    elif isinstance(value, (bytes, str)):
        document = parse_xml_document(value)
    else:
        raise TypeError(f"unsupported XML value: {type(value).__name__}")
    return document.documentElement


def _namespace_declarations(element: Element) -> dict[str, str]:
    declarations: dict[str, str] = {}
    for index in range(element.attributes.length):
        attribute = element.attributes.item(index)
        if attribute.name == "xmlns":
            declarations[""] = attribute.value
        elif attribute.prefix == "xmlns" or attribute.namespaceURI == XMLNS:
            declarations[attribute.localName or attribute.name.removeprefix("xmlns:")] = (
                attribute.value
            )
    return declarations


def _in_scope_namespaces(element: Element) -> dict[str, str]:
    lineage: list[Element] = []
    current: Node | None = element
    while current is not None:
        if current.nodeType == Node.ELEMENT_NODE:
            lineage.append(current)  # type: ignore[arg-type]
        current = current.parentNode

    namespaces = {"xml": XML}
    for ancestor in reversed(lineage):
        namespaces.update(_namespace_declarations(ancestor))
    return namespaces


def _escape_text(text: str) -> str:
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace("\r", "&#xD;")
    )


def _escape_attribute(value: str) -> str:
    return (
        value.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace('"', "&quot;")
        .replace("\t", "&#x9;")
        .replace("\n", "&#xA;")
        .replace("\r", "&#xD;")
    )


def _is_namespace_attribute(attribute: Node) -> bool:
    return (
        attribute.nodeName == "xmlns"
        or attribute.prefix == "xmlns"
        or attribute.namespaceURI == XMLNS
    )


def _validate_namespace(prefix: str, uri: str) -> None:
    if prefix and not uri:
        raise CanonicalizationError(f"prefix {prefix!r} has no in-scope namespace")
    if uri and not urlsplit(uri).scheme:
        raise CanonicalizationError(f"relative namespace URI is not canonicalizable: {uri!r}")


def _render_element(
    element: Element,
    *,
    inherited_namespaces: dict[str, str],
    rendered_namespaces: dict[str, str],
    inclusive_prefixes: frozenset[str],
    excluded: frozenset[int],
) -> str:
    in_scope = dict(inherited_namespaces)
    in_scope.update(_namespace_declarations(element))

    visible: set[str] = {element.prefix or ""}
    attributes: list[Node] = []
    for index in range(element.attributes.length):
        attribute = element.attributes.item(index)
        if _is_namespace_attribute(attribute):
            continue
        attributes.append(attribute)
        if attribute.prefix and attribute.prefix != "xml":
            visible.add(attribute.prefix)

    wanted = visible | inclusive_prefixes
    declarations: list[tuple[str, str]] = []
    next_rendered = dict(rendered_namespaces)
    for prefix in sorted(wanted):
        if prefix == "xml":
            continue
        # The errata says unused/undefined inclusive prefixes are ignored.
        if prefix not in in_scope and prefix not in visible:
            continue
        uri = in_scope.get(prefix, "")
        _validate_namespace(prefix, uri)
        if next_rendered.get(prefix) == uri:
            continue
        # An empty default namespace is emitted only to cancel a non-empty
        # namespace rendered by an output ancestor.
        if prefix == "" and uri == "" and "" not in next_rendered:
            continue
        declarations.append((prefix, uri))
        next_rendered[prefix] = uri

    parts = [f"<{element.tagName}"]
    for prefix, uri in declarations:
        name = "xmlns" if prefix == "" else f"xmlns:{prefix}"
        parts.append(f' {name}="{_escape_attribute(uri)}"')

    # Canonical XML sorts attributes first by namespace URI and then local
    # name; unqualified attributes therefore precede namespaced attributes.
    attributes.sort(key=lambda attr: (attr.namespaceURI or "", attr.localName or attr.nodeName))
    for attribute in attributes:
        parts.append(f' {attribute.nodeName}="{_escape_attribute(attribute.nodeValue or "")}"')
    parts.append(">")

    for child in element.childNodes:
        if child.nodeType == Node.ELEMENT_NODE:
            if id(child) not in excluded:
                parts.append(
                    _render_element(
                        child,  # type: ignore[arg-type]
                        inherited_namespaces=in_scope,
                        rendered_namespaces=next_rendered,
                        inclusive_prefixes=inclusive_prefixes,
                        excluded=excluded,
                    )
                )
        elif child.nodeType in (Node.TEXT_NODE, Node.CDATA_SECTION_NODE):
            parts.append(_escape_text(child.nodeValue or ""))
        elif child.nodeType == Node.PROCESSING_INSTRUCTION_NODE:
            data = f" {child.nodeValue}" if child.nodeValue else ""
            parts.append(f"<?{child.nodeName}{data}?>")
        # Exclusive c14n without comments intentionally omits comment nodes.

    parts.append(f"</{element.tagName}>")
    return "".join(parts)


def exclusive_canonicalize(
    value: Element | ET.Element | bytes | str,
    inclusive_prefixes: Iterable[str] = (),
    *,
    exclude_elements: Iterable[Element] = (),
) -> bytes:
    """Return Exclusive XML Canonicalization 1.0 without comments.

    ``#default`` in ``inclusive_prefixes`` denotes the default namespace, as
    specified by the W3C algorithm.  ``exclude_elements`` supports XML-DSig's
    enveloped-signature transform without mutating the caller's tree.
    """

    element = _to_dom(value)
    prefixes = frozenset("" if prefix == "#default" else prefix for prefix in inclusive_prefixes)
    excluded = frozenset(id(node) for node in exclude_elements)
    result = _render_element(
        element,
        inherited_namespaces=_in_scope_namespaces(element),
        rendered_namespaces={"xml": XML},
        inclusive_prefixes=prefixes,
        excluded=excluded,
    )
    return result.encode("utf-8")
