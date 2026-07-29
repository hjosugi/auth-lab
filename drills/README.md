# 14 executable drills

Run every drill:

```bash
python drills/run_all.py
```

Each section prints the security invariant it just verified. Read the matching
module while stepping through with a debugger:

| Day | Drill | Implementation |
|---:|---|---|
| 1 | Password hashing | `authlab/passwords.py` |
| 2 | HOTP/TOTP | `authlab/mfa.py` |
| 3 | JWS/JWT/JWKS | `authlab/jose.py`, `authlab/rsa.py` |
| 4 | OAuth code + PKCE + OIDC | `authlab/oauth.py` |
| 5 | Refresh rotation | `authlab/oauth.py` |
| 6 | Client credentials | `authlab/oauth.py` |
| 7 | Device authorization | `authlab/oauth.py` |
| 8 | Introspection/revocation | `authlab/oauth.py` |
| 9 | RBAC/ABAC/ReBAC | `authlab/authorization.py` |
| 10 | SAML Web SSO | `authlab/saml.py` |
| 11 | Kerberos | `authlab/kerberos.py` |
| 12 | WebAuthn/passkeys | `authlab/webauthn.py` |
| 13 | mTLS + DPoP | `authlab/mtls.py`, `authlab/dpop.py` |
| 14 | LDAP + SCIM + HMAC | `authlab/directory.py`, `authlab/http_auth.py` |

