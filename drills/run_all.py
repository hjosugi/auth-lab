"""Run every drill in order. Exit non-zero if any drill fails its assertions."""

from __future__ import annotations

import importlib
import os
import sys
import traceback

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)
# The repo root too, so `python drills/run_all.py` works without PYTHONPATH.
sys.path.insert(1, os.path.dirname(_HERE))

DRILLS = [
    "01_passwords",
    "02_mfa_totp",
    "03_jwt",
    "04_authcode_pkce",
    "05_refresh_rotation",
    "06_device_and_cc",
    "07_dpop",
    "08_authz_models",
    "09_saml",
    "10_kerberos",
    "11_webauthn",
    "12_mtls",
    "13_ldap_scim",
    "14_advanced_oauth",
]


def main() -> int:
    failures = []
    for name in DRILLS:
        try:
            module = importlib.import_module(name)
            module.main()
        except Exception:  # noqa: BLE001
            failures.append(name)
            print(f"\n!!! drill {name} FAILED", file=sys.stderr)
            traceback.print_exc()

    print("\n" + "=" * 40)
    if failures:
        print(f"FAILED: {failures}")
        return 1
    print(f"All {len(DRILLS)} drills passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
