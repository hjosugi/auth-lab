"use strict";

(function publishPyodidePolicy(global) {
  const BLOCKED_IMPORT = /(?:^|\n)\s*(?:from\s+(?:authlab\.)?(?:mtls|crypto\.x509|ssl|socket)\b|import\s+(?:authlab\.)?(?:mtls|crypto\.x509)\b|import\s+(?:ssl|socket)\b)/mu;

  const DEFAULT_SOURCE = `import json

from authlab.jose import HS256, JWT, JWTValidator
from authlab.util.clock import FrozenClock
from authlab.util.encoding import b64u_encode, json_b64u

clock = FrozenClock()
key = b"fixture-only-browser-key"
issuer = JWT(clock)
validator = JWTValidator(
    issuer="https://as.auth-lab.local",
    audience="api://orders",
    allowed_algorithms=["HS256"],
    key=key,
    clock=clock,
    leeway=0,
)

token = issuer.issue(
    key,
    HS256,
    issuer="https://as.auth-lab.local",
    subject="learner",
    audience="api://orders",
)
claims = validator.validate(token)
print("VALID:", claims.sub, claims.aud)

header, _, signature = token.split(".")
forged_payload = {
    **claims.raw,
    "sub": "attacker",
    "scope": "admin",
}
forged = f"{header}.{json_b64u(forged_payload)}.{signature}"
try:
    validator.validate(forged)
except Exception as error:
    print("TAMPERED: REFUSED")
    print(type(error).__name__ + ":", error)
else:
    raise AssertionError("tampered JWT was accepted")
`;

  function browserIncompatibleModule(source) {
    const match = String(source).match(BLOCKED_IMPORT);
    if (!match) return null;
    return {
      module: match[0].trim(),
      message: "socket / ssl / mTLS はブラウザ WebAssembly では実行できません。ローカルで `python drills/12_mtls.py` を実行してください。",
    };
  }

  const api = { BLOCKED_IMPORT, DEFAULT_SOURCE, browserIncompatibleModule };
  if (typeof module !== "undefined" && module.exports) module.exports = api;
  global.AuthLabPyodidePolicy = api;
}(typeof globalThis === "undefined" ? self : globalThis));
