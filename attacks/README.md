# attacks/

A catalog of the attacks this lab is built to resist. Each entry does two
things:

1. Shows a **naive implementation** that is vulnerable, and lands the exploit
   against it, so the bug is concrete rather than abstract.
2. Shows **authlab refusing** the same attack, and points at the line of code
   and the reasoning that makes the difference.

The point of keeping the vulnerable version next to the fixed one is that
"use a library" is not a lesson. Seeing the exact check that turns an accepted
forgery into a rejected one is.

Run the whole catalog:

```bash
PYTHONPATH=. python attacks/catalog.py
```

## The catalog

| # | Attack | Class | Defended by |
|---|--------|-------|-------------|
| 1 | `alg=none` | JWT forgery | required algorithm allow-list (`jose/jws.py`) |
| 2 | RS256 → HS256 confusion | JWT forgery | typed keys + allow-list |
| 3 | JWT `jwk` header injection | key substitution | forbidden headers (`jose/jws.py`) |
| 4 | Missing `state` → login CSRF | CSRF | `state` required + bound to session (`oauth/client.py`) |
| 5 | `redirect_uri` prefix matching | open redirect / code theft | exact match (`oauth/authorization_server.py`) |
| 6 | Authorization code replay | code theft | single-use + family revoke |
| 7 | PKCE downgrade / omission | code interception | PKCE required for public clients |
| 8 | Refresh token replay | token theft | rotation + reuse detection |
| 9 | ID token used as access token | token confusion | `typ` + `aud` checks (`oauth/resource_server.py`) |
| 10 | BOLA / IDOR | broken object authz | ownership check separate from scope |
| 11 | Bearer token replay (no DPoP) | token theft | sender-constrained tokens (`oauth/dpop.py`) |
| 12 | LDAP injection | injection | filter escaping + parser (`directory/ldap.py`) |
| 13 | LDAP anonymous bind | auth bypass | empty-password rejection |
| 14 | User enumeration by timing | info leak | constant-time `fake_verify` (`passwords/hasher.py`) |
| 15 | XML signature wrapping | SAML forgery | return-the-signed-element (`saml/signature.py`) |

Every row here corresponds to a real, repeatedly-shipped vulnerability class.
The mapping to CWE and to the OWASP API Security Top 10 is in
[`../docs/09_attack_matrix.md`](../docs/09_attack_matrix.md).
