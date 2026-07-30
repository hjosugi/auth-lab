#!/usr/bin/env python3
"""Run the local-only interoperability profile.

The profile deliberately talks to real protocol implementations while keeping
all credentials, tokens, and assertions out of its trace.  Docker is an
optional test dependency; the auth-lab runtime remains standard-library-only.
"""

from __future__ import annotations

import argparse
import base64
from dataclasses import dataclass
from html.parser import HTMLParser
import http.cookiejar
import json
from pathlib import Path
import re
import subprocess
import sys
import time
from typing import Any, Callable
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from authlab.jose import JWKSet, JWTValidator  # noqa: E402
from authlab.saml import verify_signature  # noqa: E402


REALM = "auth-lab-interop"
KEYCLOAK = f"http://127.0.0.1:18080/realms/{REALM}"
FIXTURE_USER = "learner"
FIXTURE_PASSWORD = "fixture-only-password"
FIXTURE_CLIENT_SECRET = "fixture-only-client-secret"
FIXTURE_MASTER_PASSWORD = "fixture-only-master-password"
FIXTURE_ADMIN_PASSWORD = "fixture-only-admin-password"
TRACE_DEFAULT = ROOT / ".tmp" / "interop" / "trace.jsonl"
COMPOSE_FILE = ROOT / "interop" / "compose.yaml"

_KNOWN_SECRETS = (
    FIXTURE_PASSWORD,
    FIXTURE_CLIENT_SECRET,
    FIXTURE_MASTER_PASSWORD,
    FIXTURE_ADMIN_PASSWORD,
)
_SENSITIVE_KEY = re.compile(
    r"(?:password|secret|token|assertion|samlresponse|authorization)",
    re.IGNORECASE,
)
_JWT = re.compile(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*\b")


def redact(value: Any, *, key: str = "") -> Any:
    """Return a JSON-safe value with protocol credentials and artifacts hidden."""
    if _SENSITIVE_KEY.search(key):
        return "[REDACTED]"
    if isinstance(value, dict):
        return {str(name): redact(item, key=str(name)) for name, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [redact(item, key=key) for item in value]
    if isinstance(value, str):
        clean = value
        for secret in _KNOWN_SECRETS:
            clean = clean.replace(secret, "[REDACTED]")
        return _JWT.sub("[REDACTED]", clean)
    if value is None or isinstance(value, (bool, int, float)):
        return value
    return str(value)


@dataclass
class Trace:
    path: Path

    def __post_init__(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text("", encoding="utf-8")

    def record(self, protocol: str, scenario: str, status: str, **details: Any) -> None:
        event = {
            "protocol": protocol,
            "scenario": scenario,
            "status": status,
            "details": redact(details),
        }
        with self.path.open("a", encoding="utf-8") as stream:
            stream.write(json.dumps(event, ensure_ascii=False, sort_keys=True) + "\n")
        print(f"[interop] {protocol:<8} {scenario:<18} {status}")

    def preserve_diagnostics(self) -> None:
        """Keep sanitized container state for a failed CI run."""
        sections: list[str] = []
        for label, arguments in (
            ("compose ps", ("ps", "--all")),
            ("compose logs", ("logs", "--no-color", "--tail", "120")),
        ):
            result = compose(*arguments, check=False)
            output = "\n".join(part for part in (result.stdout, result.stderr) if part.strip())
            sections.append(f"## {label}\n{redact(output)}")
        diagnostics = self.path.with_name("diagnostics.txt")
        diagnostics.write_text("\n\n".join(sections) + "\n", encoding="utf-8")


@dataclass
class HTMLForm:
    action: str
    method: str
    inputs: dict[str, str]


class FormParser(HTMLParser):
    """Collect just enough form state to follow Keycloak's SAML login."""

    def __init__(self) -> None:
        super().__init__()
        self.forms: list[HTMLForm] = []
        self._current: HTMLForm | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attributes = {name: value or "" for name, value in attrs}
        if tag == "form":
            self._current = HTMLForm(
                action=attributes.get("action", ""),
                method=attributes.get("method", "get").lower(),
                inputs={},
            )
            self.forms.append(self._current)
        elif tag == "input" and self._current is not None:
            name = attributes.get("name")
            if name:
                self._current.inputs[name] = attributes.get("value", "")

    def handle_endtag(self, tag: str) -> None:
        if tag == "form":
            self._current = None


def parse_forms(document: str) -> list[HTMLForm]:
    parser = FormParser()
    parser.feed(document)
    return parser.forms


def request_json(
    url: str,
    *,
    data: dict[str, str] | None = None,
    timeout: float = 10,
) -> tuple[int, dict[str, Any]]:
    encoded = urllib.parse.urlencode(data).encode() if data is not None else None
    request = urllib.request.Request(
        url,
        data=encoded,
        headers={"Accept": "application/json"},
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:
        body = json.loads(response.read())
        if not isinstance(body, dict):
            raise ValueError("expected a JSON object")
        return response.status, body


def retry(label: str, operation: Callable[[], Any], *, timeout: float = 90) -> Any:
    deadline = time.monotonic() + timeout
    last_error: Exception | None = None
    while time.monotonic() < deadline:
        try:
            return operation()
        except Exception as exc:  # noqa: BLE001 - retry boundary
            last_error = exc
            time.sleep(2)
    raise RuntimeError(f"{label} did not become ready") from last_error


def compose(*arguments: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["docker", "compose", "-f", str(COMPOSE_FILE), *arguments],
        cwd=ROOT,
        check=check,
        text=True,
        capture_output=True,
    )


def check_oidc(trace: Trace) -> None:
    _, discovery = request_json(f"{KEYCLOAK}/.well-known/openid-configuration")
    token_endpoint = str(discovery["token_endpoint"])
    jwks_uri = str(discovery["jwks_uri"])

    _, token_response = request_json(
        token_endpoint,
        data={
            "grant_type": "password",
            "client_id": "authlab-oidc",
            "client_secret": FIXTURE_CLIENT_SECRET,
            "username": FIXTURE_USER,
            "password": FIXTURE_PASSWORD,
            "scope": "openid profile email",
        },
    )
    id_token = str(token_response["id_token"])
    _, jwks_document = request_json(jwks_uri)
    claims = JWTValidator(
        issuer=str(discovery["issuer"]),
        audience="authlab-oidc",
        allowed_algorithms=["RS256"],
        key=JWKSet.from_json(jwks_document).resolver(),
        leeway=5,
    ).validate(id_token)
    if claims.get("preferred_username") != FIXTURE_USER:
        raise AssertionError("OIDC subject was not bound to the fixture user")
    trace.record(
        "OIDC",
        "valid credentials",
        "PASS",
        issuer=claims.iss,
        audience="authlab-oidc",
        subject_bound=True,
        signature_verified=True,
    )

    try:
        request_json(
            token_endpoint,
            data={
                "grant_type": "password",
                "client_id": "authlab-oidc",
                "client_secret": "wrong-fixture-secret",
                "username": FIXTURE_USER,
                "password": FIXTURE_PASSWORD,
                "scope": "openid",
            },
        )
    except urllib.error.HTTPError as exc:
        if exc.code not in {400, 401}:
            raise
    else:
        raise AssertionError("OIDC accepted an invalid client secret")
    trace.record("OIDC", "wrong client secret", "REJECTED", status_code="4xx")


def _saml_login(username: str, password: str) -> tuple[list[HTMLForm], str]:
    cookie_jar = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cookie_jar))
    start_url = f"{KEYCLOAK}/protocol/saml/clients/authlab-saml"
    with opener.open(start_url, timeout=10) as response:
        login_url = response.geturl()
        document = response.read().decode("utf-8")

    login_form = next(
        (
            form
            for form in parse_forms(document)
            if "username" in form.inputs and "password" in form.inputs
        ),
        None,
    )
    if login_form is None:
        raise AssertionError("SAML login form was not returned")
    payload = dict(login_form.inputs)
    payload.update(username=username, password=password)
    submit_url = urllib.parse.urljoin(login_url, login_form.action)
    request = urllib.request.Request(
        submit_url,
        data=urllib.parse.urlencode(payload).encode(),
        method="POST",
    )
    with opener.open(request, timeout=10) as response:
        result_document = response.read().decode("utf-8")
    return parse_forms(result_document), result_document


def _saml_signing_key(xml_document: bytes, jwks_document: dict[str, Any]) -> Any:
    root = ET.fromstring(xml_document)
    certificate_elements = [
        node
        for node in root.iter()
        if node.tag
        == "{http://www.w3.org/2000/09/xmldsig#}X509Certificate"
    ]
    if len(certificate_elements) != 1:
        raise AssertionError("SAML response must carry exactly one signing certificate")
    certificate = "".join((certificate_elements[0].text or "").split())
    matches = [
        key
        for key in JWKSet.from_json(jwks_document).keys
        if certificate in key.data.get("x5c", [])
        and key.kty == "RSA"
        and key.data.get("use") == "sig"
    ]
    if len(matches) != 1:
        raise AssertionError("SAML signing certificate did not match exactly one trusted JWKS key")
    return matches[0].key_material()


def validate_saml_response(
    encoded: str,
    jwks_document: dict[str, Any] | None = None,
) -> dict[str, Any]:
    xml_document = base64.b64decode(encoded, validate=True)
    root = ET.fromstring(xml_document)
    if jwks_document is not None:
        signed = verify_signature(
            xml_document,
            _saml_signing_key(xml_document, jwks_document),
        )
        if signed.tag.rsplit("}", 1)[-1] not in {"Response", "Assertion"}:
            raise AssertionError("SAML signature did not cover a protocol response or assertion")
    local_names = [node.tag.rsplit("}", 1)[-1] for node in root.iter()]
    name_ids = [
        (node.text or "").strip()
        for node in root.iter()
        if node.tag.rsplit("}", 1)[-1] == "NameID"
    ]
    required = {"Response", "Assertion", "Signature", "NameID"}
    missing = required.difference(local_names)
    if missing:
        raise AssertionError(f"SAML response is missing required elements: {sorted(missing)}")
    if FIXTURE_USER not in name_ids:
        raise AssertionError("SAML NameID was not bound to the fixture user")
    return {
        "root": root.tag.rsplit("}", 1)[-1],
        "signature_verified": jwks_document is not None,
        "subject_bound": True,
    }


def check_saml(trace: Trace) -> None:
    forms, _ = _saml_login(FIXTURE_USER, FIXTURE_PASSWORD)
    response_form = next((form for form in forms if "SAMLResponse" in form.inputs), None)
    if response_form is None:
        raise AssertionError("SAML response form was not returned")
    _, discovery = request_json(f"{KEYCLOAK}/.well-known/openid-configuration")
    _, jwks_document = request_json(str(discovery["jwks_uri"]))
    validated = validate_saml_response(response_form.inputs["SAMLResponse"], jwks_document)
    trace.record("SAML", "valid credentials", "PASS", **validated)

    forms, document = _saml_login(FIXTURE_USER, "wrong-fixture-password")
    if any("SAMLResponse" in form.inputs for form in forms):
        raise AssertionError("SAML accepted an invalid password")
    if "invalid" not in document.lower() and "username" not in document.lower():
        raise AssertionError("SAML rejection did not return the login error state")
    trace.record("SAML", "wrong password", "REJECTED", response="login error state")


def check_ldap(trace: Trace) -> None:
    base = (
        "exec",
        "-T",
        "openldap",
        "ldapsearch",
        "-LLL",
        "-x",
        "-H",
        "ldap://127.0.0.1:1389",
        "-D",
        "uid=learner,ou=people,dc=auth-lab,dc=local",
    )
    result = compose(
        *base,
        "-w",
        FIXTURE_PASSWORD,
        "-b",
        "dc=auth-lab,dc=local",
        "(uid=learner)",
        "uid",
        check=False,
    )
    if result.returncode != 0 or "uid: learner" not in result.stdout:
        raise AssertionError("LDAP bind/search did not return the fixture entry")
    trace.record(
        "LDAP",
        "valid bind/search",
        "PASS",
        bind_dn="uid=learner,ou=people,dc=auth-lab,dc=local",
        entry_bound=True,
    )

    rejected = compose(
        *base,
        "-w",
        "wrong-fixture-password",
        "-b",
        "dc=auth-lab,dc=local",
        "(uid=learner)",
        check=False,
    )
    if rejected.returncode == 0:
        raise AssertionError("LDAP accepted an invalid password")
    trace.record("LDAP", "wrong password", "REJECTED", result="invalid credentials")


def check_kerberos(trace: Trace) -> None:
    success = compose(
        "exec",
        "-T",
        "kerberos",
        "sh",
        "-ec",
        (
            f"printf '%s\\n' '{FIXTURE_PASSWORD}' | "
            "kinit learner@AUTH-LAB.LOCAL && "
            "kvno HTTP/service.auth-lab.local@AUTH-LAB.LOCAL && "
            "klist"
        ),
        check=False,
    )
    if success.returncode != 0 or "HTTP/service.auth-lab.local" not in success.stdout:
        raise AssertionError("Kerberos did not issue the fixture service ticket")
    trace.record(
        "Kerberos",
        "valid AS/TGS",
        "PASS",
        principal="learner@AUTH-LAB.LOCAL",
        service_ticket_bound=True,
    )

    rejected = compose(
        "exec",
        "-T",
        "kerberos",
        "sh",
        "-ec",
        "printf '%s\\n' 'wrong-fixture-password' | kinit learner@AUTH-LAB.LOCAL",
        check=False,
    )
    if rejected.returncode == 0:
        raise AssertionError("Kerberos accepted an invalid password")
    trace.record("Kerberos", "wrong password", "REJECTED", result="preauthentication failed")


def wait_for_services() -> None:
    retry(
        "Keycloak",
        lambda: request_json(f"{KEYCLOAK}/.well-known/openid-configuration"),
        timeout=120,
    )

    def ldap_ready() -> None:
        result = compose("exec", "-T", "openldap", "ldapwhoami", "-x", check=False)
        if result.returncode != 0:
            raise RuntimeError("LDAP is not ready")

    def kerberos_ready() -> None:
        result = compose(
            "exec",
            "-T",
            "kerberos",
            "kadmin.local",
            "-q",
            "getprinc learner@AUTH-LAB.LOCAL",
            check=False,
        )
        if result.returncode != 0:
            raise RuntimeError("Kerberos is not ready")

    retry("OpenLDAP", ldap_ready)
    retry("MIT Kerberos", kerberos_ready)


def run(trace: Trace) -> None:
    wait_for_services()
    check_oidc(trace)
    check_saml(trace)
    check_ldap(trace)
    check_kerberos(trace)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--start",
        action="store_true",
        help="build and start the Docker Compose fixture before checking it",
    )
    parser.add_argument(
        "--keep",
        action="store_true",
        help="leave a fixture started with --start running after the check",
    )
    parser.add_argument("--trace", type=Path, default=TRACE_DEFAULT)
    arguments = parser.parse_args()

    trace = Trace(arguments.trace)
    started = False
    try:
        if arguments.start:
            print("[interop] building and starting local-only fixtures")
            started = True
            result = compose("up", "--build", "-d", check=False)
            if result.returncode != 0:
                sanitized = redact(result.stderr.strip())
                raise RuntimeError(f"Docker Compose startup failed: {sanitized}")
        run(trace)
    except Exception as exc:  # noqa: BLE001 - CLI reporting boundary
        safe_message = redact(str(exc))
        trace.record(
            "profile",
            "complete",
            "FAIL",
            error=type(exc).__name__,
            message=safe_message,
        )
        if started:
            trace.preserve_diagnostics()
        print(f"[interop] FAIL: {type(exc).__name__}: {safe_message}", file=sys.stderr)
        return 1
    finally:
        if started and not arguments.keep:
            compose("down", "--volumes", "--remove-orphans", check=False)

    trace.record("profile", "complete", "PASS", protocols=["OIDC", "SAML", "LDAP", "Kerberos"])
    print(f"[interop] redacted trace: {arguments.trace}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
