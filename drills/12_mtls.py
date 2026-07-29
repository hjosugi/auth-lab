"""Drill 12 -- Mutual TLS over a real handshake, plus RFC 8705 token binding."""

from __future__ import annotations

from _util import assert_true, expect_reject, note, step, title

from authlab.crypto.x509 import CertificateAuthority
from authlab.mtls import MutualTLSClient, MutualTLSServer, certificate_thumbprint
from authlab.oauth import AuthorizationServer, Client, ResourceServer
from authlab.util.clock import FrozenClock


def main() -> None:
    title("Drill 12: mutual TLS (real handshake)")

    step(1, "Mint a CA, a server cert, a client cert, and a rogue cert.")
    ca = CertificateAuthority("auth-lab mTLS CA")
    server_cert = ca.issue("localhost", dns_names=["localhost"], ip_addresses=["127.0.0.1"], server_auth=True)
    alice_cert = ca.issue("alice@auth-lab", client_auth=True, organization="Engineering")
    rogue_ca = CertificateAuthority("Rogue CA")
    rogue_cert = rogue_ca.issue("attacker", client_auth=True)
    note("these certificates also pass `openssl verify` against the CA.")

    server = MutualTLSServer(ca=ca, server_cert=server_cert)
    port = server.start()
    try:
        step(2, "A valid client certificate completes the handshake.")
        response = MutualTLSClient(ca=ca, client_cert=alice_cert).request(port, b"GET /whoami")
        subject = server.connections[-1]["subject"]["commonName"]
        assert_true(response.startswith(b"OK"), f"connected; server authenticated {subject}")

        step(3, "Missing / untrusted client certs are rejected in the handshake.")
        expect_reject("no client certificate", lambda: MutualTLSClient(ca=ca, client_cert=None).request(port, b"hi"))
        expect_reject("client cert from an untrusted CA", lambda: MutualTLSClient(ca=ca, client_cert=rogue_cert).request(port, b"hi"))

        step(4, "The client also rejects a server it does not trust.")
        expect_reject("server cert from an untrusted CA", lambda: MutualTLSClient(ca=rogue_ca, client_cert=alice_cert).request(port, b"hi"))

        thumbprint = certificate_thumbprint(alice_cert.der)
        assert_true(thumbprint == server.connections[0]["thumbprint"], "RFC 8705 thumbprint matches on both sides")
    finally:
        server.stop()

    step(5, "RFC 8705: bind an OAuth token to the client certificate.")
    clock = FrozenClock(1_700_000_000)
    as_server = AuthorizationServer(clock=clock)
    as_server.register_client(Client(
        client_id="svc", client_secret="s", grant_types=["client_credentials"], scopes=["orders:read"],
        token_endpoint_auth_method="tls_client_auth", tls_client_certificate_bound_access_tokens=True,
    ))
    token = as_server.token(
        {"grant_type": "client_credentials", "client_id": "svc", "scope": "orders:read"},
        tls_client_cert_thumbprint=thumbprint,
    )
    rs = ResourceServer(audience="https://api.auth-lab.local", issuer=as_server.issuer, jwks=as_server.jwks, clock=clock)
    assert_true(bool(rs.authenticate(f"Bearer {token['access_token']}", tls_client_cert_thumbprint=thumbprint)),
                "token accepted WITH the matching client certificate")
    expect_reject(
        "same token, a different certificate",
        lambda: rs.authenticate(f"Bearer {token['access_token']}", tls_client_cert_thumbprint="different"),
    )
    expect_reject("same token, no certificate", lambda: rs.authenticate(f"Bearer {token['access_token']}"))

    print("\nDrill 12 complete.")


if __name__ == "__main__":
    main()
