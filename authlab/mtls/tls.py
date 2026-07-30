"""Mutual TLS with a real TLS handshake, using our own CA.

Everywhere else in this repo the network is imaginary. Here it is not: this
module runs Python's `ssl` module over a real loopback socket, presents the
certificates minted by authlab.crypto.x509, and requires the client to
present one too. If the handshake completes, the operating system's TLS stack
genuinely verified both chains -- there is nothing simulated to get wrong.

Ordinary "one-way" TLS authenticates only the server: the client checks the
server's certificate against a trusted CA and its hostname, and then usually
authenticates itself with a password or token *inside* the encrypted channel.
Mutual TLS moves the client's authentication into the handshake itself: the
server demands a client certificate and verifies it against a CA it trusts.

Where mTLS earns its keep:
  * service-to-service inside a mesh (Istio, Linkerd), where every workload
    has a short-lived certificate from a shared CA and there are no passwords
    to leak between services
  * high-value APIs (banking, "FAPI") where a bearer token is not enough
  * binding OAuth tokens to a client certificate (RFC 8705) -- the token is
    only usable by the client that presented that exact certificate, which is
    the mTLS answer to the same problem DPoP solves in software

What mTLS costs, and why it is not everywhere:
  * certificate lifecycle: issuing, rotating, and revoking a certificate per
    client is real operational weight; this is why service meshes automate it
    with hours-long lifetimes
  * revocation is the same unsolved problem as everywhere in PKI -- CRLs are
    big and stale, OCSP soft-fails -- so short lifetimes do the real work
  * it terminates awkwardly: a TLS-terminating load balancer has to forward
    the verified certificate to the app in a header, and if the app trusts
    that header without the balancer stripping client-supplied copies, the
    header is spoofable

The RFC 8705 binding at the bottom (`x5t#S256`) is the concrete link back to
the OAuth layer: it is the SHA-256 of the DER certificate, and it is exactly
the value the authorization server put in the token's `cnf` claim.
"""

from __future__ import annotations

import hashlib
import socket
import ssl
import threading
from dataclasses import dataclass, field
from typing import Callable

from ..crypto.x509 import Certificate, CertificateAuthority
from ..util.encoding import b64u_encode


class MTLSError(Exception):
    """A handshake or verification failure."""


def certificate_thumbprint(der: bytes) -> str:
    """RFC 8705 x5t#S256: base64url(SHA-256(DER certificate))."""
    return b64u_encode(hashlib.sha256(der).digest())


def _write_pem_files(tmpdir: str, name: str, cert_pem: str, key_pem: str | None = None) -> tuple[str, str | None]:
    import os

    cert_path = os.path.join(tmpdir, f"{name}.crt")
    with open(cert_path, "w") as handle:
        handle.write(cert_pem)
    key_path = None
    if key_pem is not None:
        key_path = os.path.join(tmpdir, f"{name}.key")
        with open(key_path, "w") as handle:
            handle.write(key_pem)
    return cert_path, key_path


@dataclass
class MutualTLSServer:
    """A TLS server that requires and verifies a client certificate."""

    ca: CertificateAuthority
    server_cert: Certificate
    handler: Callable[[dict, socket.socket], bytes] | None = None
    host: str = "127.0.0.1"
    port: int = 0
    _thread: threading.Thread | None = None
    _sock: socket.socket | None = None
    _tmpdir: str = ""
    bound_port: int = 0
    connections: list[dict] = field(default_factory=list)

    def _server_context(self) -> ssl.SSLContext:
        import tempfile

        self._tmpdir = tempfile.mkdtemp(prefix="authlab-mtls-")
        cert_path, key_path = _write_pem_files(
            self._tmpdir, "server", self.server_cert.pem(), self.server_cert.key_pem()
        )
        ca_path, _ = _write_pem_files(self._tmpdir, "ca", self.ca.ca_pem())

        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        # TLS 1.2 floor. Everything below has known problems and no reason to
        # exist on a greenfield service.
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(certfile=cert_path, keyfile=key_path)
        # This one line is what makes it *mutual*: demand a client certificate
        # and fail the handshake if it does not verify against our CA.
        context.verify_mode = ssl.CERT_REQUIRED
        context.load_verify_locations(cafile=ca_path)
        return context

    def start(self) -> int:
        """Start serving on a background thread. Returns the bound port."""
        context = self._server_context()
        raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        raw.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        raw.bind((self.host, self.port))
        raw.listen(5)
        raw.settimeout(5.0)
        self.bound_port = raw.getsockname()[1]
        self._sock = raw

        def serve() -> None:
            try:
                while self._sock is not None:
                    try:
                        client_raw, _ = raw.accept()
                    except (socket.timeout, OSError):
                        break
                    self._handle(context, client_raw)
            finally:
                pass

        self._thread = threading.Thread(target=serve, daemon=True)
        self._thread.start()
        return self.bound_port

    def _handle(self, context: ssl.SSLContext, client_raw: socket.socket) -> None:
        try:
            tls = context.wrap_socket(client_raw, server_side=True)
        except ssl.SSLError as exc:
            # A client with no certificate, or one signed by a CA we do not
            # trust, dies right here in the handshake -- before a single byte
            # of application data. That is the property we want.
            self.connections.append({"ok": False, "error": str(exc)})
            client_raw.close()
            return

        peer_der = tls.getpeercert(binary_form=True)
        peer = tls.getpeercert()
        info = {
            "ok": True,
            "subject": _flatten_name(peer.get("subject", [])),
            "der": peer_der,
            "thumbprint": certificate_thumbprint(peer_der) if peer_der else None,
        }
        self.connections.append(info)

        try:
            request = tls.recv(4096)
            response = self.handler(info, tls) if self.handler else b"OK " + request
            tls.sendall(response)
        except OSError:
            pass
        finally:
            try:
                tls.close()
            except OSError:
                pass

    def stop(self) -> None:
        sock = self._sock
        self._sock = None
        if sock is not None:
            sock.close()
        if self._thread is not None:
            self._thread.join(timeout=2.0)
        if self._tmpdir:
            import shutil

            shutil.rmtree(self._tmpdir, ignore_errors=True)


@dataclass
class MutualTLSClient:
    """A TLS client that presents a certificate and pins the server CA."""

    ca: CertificateAuthority
    client_cert: Certificate | None
    host: str = "127.0.0.1"
    server_name: str = "localhost"

    def _client_context(self) -> tuple[ssl.SSLContext, str]:
        import tempfile

        tmpdir = tempfile.mkdtemp(prefix="authlab-mtls-client-")
        ca_path, _ = _write_pem_files(tmpdir, "ca", self.ca.ca_pem())

        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        # Verify the server against our CA and check the hostname against the
        # certificate's SAN -- the same checks a browser does.
        context.load_verify_locations(cafile=ca_path)
        context.verify_mode = ssl.CERT_REQUIRED
        context.check_hostname = True
        if self.client_cert is not None:
            cert_path, key_path = _write_pem_files(
                tmpdir, "client", self.client_cert.pem(), self.client_cert.key_pem()
            )
            context.load_cert_chain(certfile=cert_path, keyfile=key_path)
        return context, tmpdir

    def request(self, port: int, payload: bytes = b"hello", timeout: float = 5.0) -> bytes:
        """Connect, complete the handshake, send payload, return the response."""
        context, tmpdir = self._client_context()
        try:
            raw = socket.create_connection((self.host, port), timeout=timeout)
            try:
                tls = context.wrap_socket(raw, server_hostname=self.server_name)
            except ssl.SSLError as exc:
                raise MTLSError(f"TLS handshake failed: {exc}") from exc
            try:
                # In TLS 1.3 the server's certificate request and the client
                # certificate exchange happen after the initial handshake, so
                # a missing or untrusted client certificate surfaces as an
                # alert on the first read/write rather than in wrap_socket.
                tls.sendall(payload)
                return tls.recv(4096)
            except (OSError, ssl.SSLError) as exc:
                raise MTLSError(f"TLS certificate rejected: {exc}") from exc
            finally:
                try:
                    tls.close()
                except OSError:
                    pass
        finally:
            import shutil

            shutil.rmtree(tmpdir, ignore_errors=True)


def _flatten_name(name_tuples) -> dict[str, str]:
    """Turn ssl's nested RDN structure into a flat dict."""
    result: dict[str, str] = {}
    for rdn in name_tuples:
        for attr, value in rdn:
            result[attr] = value
    return result
