# Authentication and authorization interview script

## Sixty-second overview

Authentication establishes who or what is making a request. Authorization
decides whether that subject may perform an action on a resource in the current
context. I model every flow in terms of assets, trust boundaries, credential
binding, freshness, and revocation. A valid signature is only one check: I also
validate the issuer, audience, token type, time window, client or redirect
binding, and replay identifiers. Finally, every protected object gets a
server-side authorization decision with default deny.

## OAuth and OIDC

OAuth is a delegated authorization framework. OpenID Connect adds an identity
layer. The authorization code is delivered through the browser, while PKCE
binds its redemption to the client instance that created the verifier. State
binds the callback to the browser transaction. In OIDC, nonce binds the ID
token to the authentication request. The client consumes the ID token; the
resource server consumes the access token. I never send an ID token to an API.

## JWT validation

I pin the allowed algorithm and select keys only from a trusted issuer's JWKS.
I reject attacker-supplied key URLs or embedded keys. After signature
verification, I require an exact issuer and intended audience, enforce
expiration and not-before times with a small clock skew, distinguish token
types, and use a replay identifier where the protocol requires one. I also
design key rotation and metadata outage behavior.

## SAML

The difficult part of SAML is ensuring that the assertion used by the
application is exactly the assertion covered by signature validation. I
validate the trusted IdP, destination, audience, InResponseTo, time conditions,
and replay ID. I use a maintained, schema-aware SAML library and trusted
metadata instead of writing XML Signature code.

## Kerberos

Kerberos gives a client a ticket-granting ticket after pre-authentication. The
client uses that TGT to request a service-specific ticket, then presents the
ticket with a fresh authenticator. The password is not sent to every service.
The security model depends on KDC protection, service principal correctness,
DNS, time synchronization, short-lived authenticators, and replay caches.

## WebAuthn and passkeys

WebAuthn uses a public-key credential scoped to a relying party. The server
stores a public key, sends a fresh challenge, and verifies the browser's origin,
RP ID hash, user presence or verification flags, signature, and sign counter.
Its phishing resistance comes from browser and authenticator enforcement of
the origin and RP ID, not from user vigilance alone.

## Authorization

I use RBAC for stable job functions, ABAC for contextual policy, and ReBAC for
sharing and resource relationships. Authentication never implies object
authorization. Every API checks subject, action, resource, and context. Deny
overrides allow, tenant and ownership constraints are explicit, and decision
reasons are auditable without leaking sensitive policy details to callers.

## Proof of possession

Bearer tokens can be replayed by whoever steals them. mTLS binds a token to a
client certificate. DPoP binds it to a public key and adds a signed proof for
the HTTP method, target URI, issue time, unique identifier, and access-token
hash. These mechanisms reduce token replay, but they do not replace endpoint
authorization, secure key storage, or short token lifetimes.

