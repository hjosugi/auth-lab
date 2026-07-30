"""Drill 14 -- PAR, JAR, JARM, RAR, CIBA, and FAPI 2.0."""

from __future__ import annotations

from _util import assert_true, expect_reject, note, step, title

from authlab.crypto.rsa import generate_rsa_keypair
from authlab.jose.jwks import JWK
from authlab.oauth import (
    AuthorizationServer,
    CIBAService,
    CIBA_GRANT_TYPE,
    Client,
    FAPI2MessageSigning,
    FAPI2SecurityProfile,
    JWTAuthorizationRequests,
    JWTAuthorizationResponses,
    PushedAuthorizationRequests,
    User,
    pkce,
)
from authlab.util.clock import FrozenClock


def main() -> None:
    title("Drill 14: 高度な OAuth と FAPI 2.0 の束縛")
    clock = FrozenClock()
    server = AuthorizationServer(issuer="https://as.local", clock=clock)
    client_key = generate_rsa_keypair(512)
    server.register_user(User(subject="u-alice", username="alice", password_hash="fixture"))
    server.register_client(
        Client(
            client_id="fapi-client",
            redirect_uris=["https://client.local/cb"],
            scopes=["openid", "orders:read", "offline_access"],
            token_endpoint_auth_method="tls_client_auth",
            tls_client_certificate_bound_access_tokens=True,
            rotate_refresh_tokens=False,
        )
    )
    server.register_client(
        Client(
            client_id="resource-server",
            client_secret="fixture-secret",
            grant_types=["client_credentials"],
            response_types=[],
            introspection_audiences=["https://api.auth-lab.local"],
        )
    )

    jar = JWTAuthorizationRequests(server.issuer, clock=clock)
    jar.register_client_key(
        "fapi-client", JWK.from_rsa_public(client_key.public, kid="client-sign-1")
    )
    par = PushedAuthorizationRequests(server, jar=jar, clock=clock)
    security = FAPI2SecurityProfile(server, par)
    jarm = JWTAuthorizationResponses(
        server.issuer,
        server.signing_key,
        server.signing_kid,
        clock=clock,
    )
    signing = FAPI2MessageSigning(security, jarm)

    step(1, "JARで認可パラメータとRARの詳細権限へクライアント署名を付ける。")
    verifier, challenge = pkce.generate_pair()
    params = {
        "client_id": "fapi-client",
        "redirect_uri": "https://client.local/cb",
        "response_type": "code",
        "scope": "openid orders:read offline_access",
        "state": "browser-state",
        "nonce": "oidc-nonce",
        "code_challenge": challenge,
        "code_challenge_method": "S256",
        "resource": "https://api.auth-lab.local",
        "authorization_details": [
            {
                "type": "payment_initiation",
                "actions": ["initiate"],
                "instructedAmount": {"currency": "JPY", "amount": "1250"},
            }
        ],
    }
    request_object = jar.issue(params, client_key, kid="client-sign-1")
    note(f"Request Object: {request_object[:42]}...")

    step(2, "認証済みPARへ送り、ブラウザには短命なrequest_uriだけを渡す。")
    pushed = signing.pushed_authorization_request(
        {"client_id": "fapi-client", "request": request_object},
        tls_client_cert_thumbprint="cert-A",
    )
    assert_true(pushed["expires_in"] < 600, "PAR参照は600秒未満")
    validated = security.authorize(
        {"client_id": "fapi-client", "request_uri": pushed["request_uri"]}
    )
    assert_true(
        validated["authorization_details"][0]["type"] == "payment_initiation",
        "RARの構造化された権限が認可判断へ届く",
    )

    step(3, "認可コードをJARMで署名し、issuer・audience・stateをまとめて検証する。")
    code = server.issue_authorization_code(validated, "u-alice")
    response = signing.authorization_response(validated, code)
    claims = jarm.validate(
        response,
        client_id="fapi-client",
        server_jwks=server.jwks,
        expected_state="browser-state",
    )
    assert_true(claims["code"] == code, "JARM署名の内側のcodeだけを使用")

    step(4, "mTLS証明書へ束縛したtokenへ交換し、RARをtokenまで運ぶ。")
    tokens = security.token(
        {
            "grant_type": "authorization_code",
            "code": claims["code"],
            "redirect_uri": "https://client.local/cb",
            "client_id": "fapi-client",
            "code_verifier": verifier,
        },
        tls_client_cert_thumbprint="cert-A",
    )
    access = server.store.access_tokens[tokens["access_token"]]
    assert_true(access.cnf_x5t == "cert-A", "access tokenは提示した証明書へ束縛")
    assert_true(bool(tokens["authorization_details"]), "承認済みRARがtoken応答にも残る")

    step(5, "RFC 9701の署名付きintrospectionを専用typとaudienceで検証する。")
    envelope = signing.signed_introspection(
        tokens["access_token"],
        resource_server=server.store.clients["resource-server"],
        audience="https://api.auth-lab.local",
        basic_auth=("resource-server", "fixture-secret"),
    )
    body = signing.validate_introspection_response(
        envelope["body"],
        audience="https://api.auth-lab.local",
        server_jwks=server.jwks,
    )
    assert_true(body["active"], "署名付きintrospectionは対象APIにだけ有効")

    step(6, "PAR参照へのフロントチャネル上書きを拒否する。")
    fresh_object = jar.issue(params, client_key, kid="client-sign-1")
    fresh = signing.pushed_authorization_request(
        {"client_id": "fapi-client", "request": fresh_object},
        tls_client_cert_thumbprint="cert-A",
    )
    expect_reject(
        "redirect_uriをブラウザ側で差し替える",
        lambda: security.authorize(
            {
                "client_id": "fapi-client",
                "request_uri": fresh["request_uri"],
                "redirect_uri": "https://attacker.invalid/cb",
            }
        ),
    )

    step(7, "CIBAは利用端末のブラウザを通さず、別端末の承認へauth_req_idを束縛する。")
    server.register_client(
        Client(
            client_id="ciba-client",
            client_secret="ciba-secret",
            grant_types=[CIBA_GRANT_TYPE],
            response_types=[],
            scopes=["openid"],
        )
    )
    ciba = CIBAService(server, clock=clock)
    started = ciba.start(
        {
            "client_id": "ciba-client",
            "scope": "openid",
            "login_hint": "alice",
            "binding_message": "Approve 42",
        },
        basic_auth=("ciba-client", "ciba-secret"),
    )
    ciba.approve(started["auth_req_id"], "u-alice", amr=["hwk"])
    ciba_tokens = ciba.token(
        {
            "grant_type": CIBA_GRANT_TYPE,
            "client_id": "ciba-client",
            "auth_req_id": started["auth_req_id"],
        },
        basic_auth=("ciba-client", "ciba-secret"),
    )
    assert_true("id_token" in ciba_tokens, "別端末の承認後だけCIBA tokenを発行")

    print("\nDrill 14 complete.")


if __name__ == "__main__":
    main()
