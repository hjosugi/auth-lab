# GitHub Copilot instructions

Follow `/AGENTS.md`.

Generate readable Python 3.11+ standard-library code. Keep protocol state
explicit and prefer small functions with precise validation errors. Do not
suggest custom cryptography for production use. Negative security tests must
stay local, deterministic where practical, and demonstrate rejection rather
than external exploitation.

For every authentication change, consider:

- trusted issuer/key/metadata source;
- subject, audience, client, redirect, origin, or RP binding;
- time validity and clock skew;
- replay identifier and one-time state;
- token or credential type separation;
- object-level authorization after authentication.

