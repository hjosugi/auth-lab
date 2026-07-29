"""auth-lab: authentication and authorization protocols, implemented from scratch.

Everything here is built on the Python standard library only. No pip install.
The point is not to ship a production auth stack -- it is to make every byte
that touches a credential or a token readable in one sitting.

Layout
------
authlab.util        base64url, constant-time compare, integer/byte conversion
authlab.crypto      RSA keygen + PKCS#1 v1.5 signatures, written out longhand
authlab.passwords   password hashing (scrypt / PBKDF2) and verification
authlab.mfa         HOTP (RFC 4226) and TOTP (RFC 6238)
authlab.jose        JWS / JWT / JWKS
authlab.oauth       OAuth 2.0 authorization server, resource server, client
authlab.oidc        OpenID Connect provider on top of the OAuth server
authlab.authz       RBAC, ABAC, and ReBAC (Zanzibar-style) engines
authlab.web         a very small HTTP routing layer over http.server
"""

__version__ = "1.0.0"
