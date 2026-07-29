# Safe attack regressions

These are local negative tests, not exploitation tools. They demonstrate that
the implementation rejects broken trust assumptions:

```bash
python attacks/run_regressions.py
```

Covered failures include `alg=none`, attacker-controlled JWKS, redirect URI
prefix matching, missing OAuth state, SAML duplicate assertion wrapping,
WebAuthn origin mismatch, and DPoP method mismatch.
