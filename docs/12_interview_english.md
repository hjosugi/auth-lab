# Interview script (English)

Talking points for authentication/authorization interviews. Say these out loud
until they are automatic. Each is a 20–40 second answer to a question you WILL
be asked. Keep it concrete: name the check, name the attack it stops.

---

## "Walk me through OAuth 2.0 authorization code with PKCE."

> The user clicks log in, and the client generates three things: a `state`
> value for CSRF, a `nonce` for the ID token, and a PKCE `code_verifier`. It
> sends the SHA-256 of the verifier — the `code_challenge` — on the
> `/authorize` request, so the verifier itself never travels through the
> browser. The authorization server authenticates the user and redirects back
> with a short-lived, single-use `code`. The client checks that the returned
> `state` matches what it stored, then makes a **back-channel** POST to the
> token endpoint with the code and the verifier. The server re-hashes the
> verifier, compares it to the stored challenge, and only then issues tokens.
> The point of PKCE is that a stolen code is useless: an attacker cannot
> produce the verifier, because SHA-256 doesn't run backwards.

## "Why did OAuth 2.1 remove the implicit and password grants?"

> The implicit grant returned the access token in the URL fragment, so it
> ended up in browser history, referrer headers, and every script on the page.
> The password grant made the client handle the user's actual password, which
> defeats the whole point of OAuth and makes MFA and federation impossible.
> Both are replaced by authorization code with PKCE.

## "What's the difference between an ID token and an access token?"

> An ID token is for the client — its audience is the `client_id`, and it
> answers "who logged in." An access token is for the API — its audience is
> the resource server, and it answers "may this call happen." The classic bug
> is sending an ID token to an API as a credential. A correct resource server
> rejects it on two grounds: the `typ` is `JWT` not `at+jwt`, and the
> audience is the client, not the API.

## "How do you verify a JWT safely?"

> The single most important thing: the verifier declares which algorithms it
> accepts, as a required parameter with no default. It never reads `alg` from
> the token to decide how to verify. That one rule kills both `alg=none` and
> the RS256-to-HS256 confusion attack. Then I check the signature against a
> key resolved by `kid` from a JWKS I control — never a key embedded in the
> token's `jwk` or `jku` header. Then the claims: `iss`, `aud` must contain
> me, `exp`, `nbf`, `iat`, and for OIDC the `nonce`. Signature alone is not
> validation.

## "What is the number one API security risk, and can a token check stop it?"

> Broken Object Level Authorization — BOLA, or IDOR. A valid token with a
> valid scope like `orders:read` says the client may read orders; it says
> nothing about *whose* orders. If the endpoint returns order 999 to anyone
> with `orders:read`, that's BOLA, and it's OWASP API number one. No token
> check closes it — you have to load the object and compare its owner to the
> token's subject. Scope is not authorization.

## "How does refresh token rotation with reuse detection work?"

> Every refresh returns a brand-new refresh token and invalidates the old one.
> All tokens descended from one login share a family id. If a rotated token is
> ever presented again, that means it leaked — two parties now hold tokens
> from one family — so the server revokes the entire family. Both the
> legitimate user and the attacker get logged out, which is the correct
> response to a demonstrated leak.

## "Why are passkeys phishing-resistant when TOTP isn't?"

> TOTP is a shared secret plus a clock. A real-time phishing proxy relays the
> code within its thirty-second window, so it's still phishable, and the
> secret sits on the server to be stolen. A passkey is a private key that
> never leaves the authenticator, and the signature is bound to the origin.
> A look-alike domain gets no signature at all, because the authenticator has
> no key for that origin — there's nothing to phish, and nothing at the server
> to steal but a public key.

## "What is DPoP and what does it fix?"

> A bearer token is usable by anyone who holds it. DPoP binds the token to a
> key the client owns: the client signs a proof for every request, and the
> token carries the key's thumbprint in its `cnf.jkt` claim. A stolen token is
> useless without the private key. The resource server checks the proof's
> method, URL, freshness, a one-time `jti`, and that the key thumbprint
> matches the token. mTLS solves the same problem at the TLS layer with a
> client certificate.

## "Explain the SAML XML signature wrapping attack."

> SAML signs an XML tree, not a byte string, and the signature references the
> signed element by ID. In a wrapping attack, the attacker keeps the original
> signed assertion so the digest still matches, but adds a second, unsigned
> assertion that the application actually reads. The defence is an API that
> returns the element that was signed, so the application can only ever use
> that object — never re-query the document and accidentally read the
> attacker's sibling.

## "Name the main Active Directory / Kerberos attacks."

> Kerberoasting: any user can request a service ticket for any service, which
> is encrypted with the service account's password-derived key, and crack it
> offline — no failed logins, no lockout. AS-REP roasting: if a user has
> pre-authentication disabled, anyone can request a crackable blob for them.
> Golden ticket: whoever has the `krbtgt` key can forge a TGT for anyone with
> any group membership. Pass-the-ticket: a stolen ticket replays from any
> host. The defences are long random service passwords or gMSAs, keeping
> pre-auth on, protecting and rotating `krbtgt`, and short ticket lifetimes.

## "How should passwords be stored?"

> Never the password — a slow, salted, memory-hard hash: scrypt or Argon2, not
> SHA-256. Per-user salt so identical passwords don't collide and rainbow
> tables don't work. Store the algorithm and cost parameters with the hash, so
> you can raise the cost later and re-hash each user transparently on their
> next login. And the login endpoint must take the same time for an unknown
> user as for a wrong password, or it becomes a user-enumeration oracle.

---

## Rapid-fire one-liners

- **state** protects the redirect (CSRF); **PKCE** protects the code; use both.
- **redirect_uri** is matched by exact string, never prefix — prefix is how `…/cb.attacker.net` steals codes.
- **alg=none** and **algorithm confusion** are both killed by a required algorithm allow-list.
- **`typ=at+jwt`** stops an ID token being accepted as an access token.
- **Deny-overrides + default-deny**: an explicit deny always wins, and no matching policy means denied.
- **SCIM deactivation, not deletion**, is what cuts access — and the app must check `active` every request.
- **mTLS / DPoP** turn a bearer token into a sender-constrained one.
- **Short access tokens** are the only real revocation lever for stateless JWTs.
