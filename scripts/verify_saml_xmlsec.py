#!/usr/bin/env python3
"""Cross-check auth-lab XML signatures with the external xmlsec1 implementation.

This optional interoperability check is deliberately separate from
``scripts/verify.py`` so the core lab remains dependency-free.  It verifies
both directions:

* auth-lab signs, xmlsec1 verifies;
* xmlsec1 signs the same template, auth-lab verifies.

Install the ``xmlsec1`` command and run:

    python scripts/verify_saml_xmlsec.py
"""

from __future__ import annotations

import base64
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from xml.etree import ElementTree as ET

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from authlab.crypto.x509 import CertificateAuthority
from authlab.saml import sign_element, verify_signature
from authlab.saml.signature import DS


def _run(argv: list[str]) -> None:
    result = subprocess.run(argv, check=False, capture_output=True, text=True)
    if result.returncode:
        details = (result.stdout + result.stderr).strip()
        raise RuntimeError(f"{' '.join(argv[:2])} failed:\n{details}")


def main() -> int:
    xmlsec = shutil.which("xmlsec1")
    openssl = shutil.which("openssl")
    if not xmlsec or not openssl:
        missing = ", ".join(
            name for name, path in (("xmlsec1", xmlsec), ("openssl", openssl)) if not path
        )
        print(f"SKIP: optional SAML interoperability tools are missing: {missing}")
        return 0

    authority = CertificateAuthority(common_name="auth-lab XML-DSig interop")
    assertion = ET.fromstring(
        '<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" '
        'ID="_interop" Version="2.0">'
        "<saml:Issuer>https://idp.example.test</saml:Issuer>"
        "<saml:Subject><saml:NameID>alice@example.test</saml:NameID></saml:Subject>"
        "</saml:Assertion>"
    )
    certificate_b64 = base64.b64encode(authority.certificate.der).decode("ascii")
    sign_element(assertion, authority.key, "_interop", certificate_b64)

    with tempfile.TemporaryDirectory(prefix="auth-lab-xmlsec-") as directory:
        root = Path(directory)
        authlab_signed = root / "authlab-signed.xml"
        certificate = root / "certificate.pem"
        private_key = root / "private-key.pem"
        public_key = root / "public-key.pem"
        template = root / "xmlsec-template.xml"
        xmlsec_signed = root / "xmlsec-signed.xml"

        authlab_signed.write_bytes(
            ET.tostring(assertion, encoding="utf-8", xml_declaration=True)
        )
        certificate.write_text(authority.ca_pem(), encoding="ascii")
        private_key.write_text(authority.certificate.key_pem(), encoding="ascii")

        _run(
            [
                openssl,
                "x509",
                "-in",
                str(certificate),
                "-pubkey",
                "-noout",
                "-out",
                str(public_key),
            ]
        )
        _run(
            [
                xmlsec,
                "--verify",
                "--lax-key-search",
                "--id-attr:ID",
                "Assertion",
                "--pubkey-pem",
                str(public_key),
                str(authlab_signed),
            ]
        )

        # xmlsec1 fills the empty DigestValue and SignatureValue in a template.
        digest = assertion.find(f".//{{{DS}}}DigestValue")
        signature_value = assertion.find(f".//{{{DS}}}SignatureValue")
        assert digest is not None and signature_value is not None
        digest.text = ""
        signature_value.text = ""
        template.write_bytes(ET.tostring(assertion, encoding="utf-8", xml_declaration=True))
        _run(
            [
                xmlsec,
                "--sign",
                "--lax-key-search",
                "--id-attr:ID",
                "Assertion",
                "--privkey-pem",
                f"{private_key},{certificate}",
                "--output",
                str(xmlsec_signed),
                str(template),
            ]
        )
        verified = verify_signature(xmlsec_signed.read_bytes(), authority.key.public)
        if verified.get("ID") != "_interop":
            raise RuntimeError("auth-lab did not return xmlsec1's signed Assertion")

    print("PASS: auth-lab <-> xmlsec1 exclusive-c14n signatures interoperate")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
