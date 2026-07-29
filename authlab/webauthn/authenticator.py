"""A virtual authenticator: what a YubiKey, Touch ID, or Windows Hello does.

The authenticator is the part users never see. It holds private keys, and its
whole contribution is that it will only sign for the origin it was registered
to. That single property is why passkeys are phishing-resistant and TOTP is
not: a user can be tricked into typing a code into evil.example, but a
platform authenticator will not produce a signature for evil.example, because
the browser hands it the real origin and the RP ID never matches.

authenticatorData layout (the exact bytes that get signed):

    32  rpIdHash        SHA-256 of the RP ID ("auth-lab.local")
     1  flags           bit 0 UP  user present   (they touched it)
                        bit 2 UV  user verified  (PIN/biometric, not just touch)
                        bit 3 BE  backup eligible  (a syncable passkey)
                        bit 4 BS  backup state     (currently synced)
                        bit 6 AT  attested credential data follows
                        bit 7 ED  extension data follows
     4  signCount       monotonic counter, big-endian
    ..  attestedCredentialData (registration only):
           16  AAGUID           authenticator model id
            2  credentialIdLen
           ..  credentialId
           ..  COSE public key

The signature at authentication time covers:

    authenticatorData || SHA-256(clientDataJSON)

Note what is NOT in that: the challenge is only in clientDataJSON, and it is
covered via its hash. So the RP must verify the challenge from the
clientDataJSON *and* confirm that hash is the one that was signed. Checking
one without the other is a real bug people ship.
"""

from __future__ import annotations

import hashlib
import json
import struct
from dataclasses import dataclass, field

from ..crypto.cbor import encode as cbor_encode
from ..crypto.ec import ECPrivateKey, ecdsa_sign, generate_ec_keypair, signature_to_der
from ..util.ct import random_bytes
from ..util.encoding import b64u_encode
from .cose import cose_encode_ec2

FLAG_UP = 0x01
FLAG_UV = 0x04
FLAG_BE = 0x08
FLAG_BS = 0x10
FLAG_AT = 0x40
FLAG_ED = 0x80

# A made-up model id. Real AAGUIDs identify the authenticator model, which is
# how an enterprise can say "only YubiKey 5 series" -- and also why privacy
# advocates argue about them.
LAB_AAGUID = bytes.fromhex("6c61622d61757468656e74696361746f72")[:16].ljust(16, b"\x00")


@dataclass
class StoredCredential:
    """What the authenticator keeps for one registration."""

    credential_id: bytes
    private_key: ECPrivateKey
    rp_id: str
    user_handle: bytes
    sign_count: int = 0


@dataclass
class VirtualAuthenticator:
    """A software authenticator for driving the ceremonies in tests."""

    credentials: dict[bytes, StoredCredential] = field(default_factory=dict)
    supports_uv: bool = True
    # A syncable passkey (iCloud Keychain, Google Password Manager) reports
    # BE/BS and does NOT keep a reliable signature counter -- it is the same
    # key on several devices. A hardware key does keep one. This flag drives
    # both behaviours so the RP-side clone detection can be demonstrated.
    is_platform_passkey: bool = False

    def _authenticator_data(
        self, rp_id: str, flags: int, sign_count: int, attested: bytes = b""
    ) -> bytes:
        return (
            hashlib.sha256(rp_id.encode("utf-8")).digest()
            + bytes([flags])
            + struct.pack(">I", sign_count)
            + attested
        )

    def make_credential(
        self,
        *,
        rp_id: str,
        origin: str,
        challenge: bytes,
        user_handle: bytes,
        user_verified: bool = True,
        attestation: str = "none",
    ) -> dict:
        """The registration ceremony (navigator.credentials.create)."""
        key = generate_ec_keypair()
        credential_id = random_bytes(32)

        client_data = {
            "type": "webauthn.create",
            "challenge": b64u_encode(challenge),
            "origin": origin,
            "crossOrigin": False,
        }
        client_data_json = json.dumps(client_data, separators=(",", ":")).encode("utf-8")

        flags = FLAG_UP | FLAG_AT
        if user_verified and self.supports_uv:
            flags |= FLAG_UV
        if self.is_platform_passkey:
            flags |= FLAG_BE | FLAG_BS

        cose_key = cose_encode_ec2(key.public)
        attested = (
            LAB_AAGUID
            + struct.pack(">H", len(credential_id))
            + credential_id
            + cose_key
        )
        auth_data = self._authenticator_data(rp_id, flags, 0, attested)

        if attestation == "packed":
            # Self-attestation: sign with the credential's own key. It proves
            # the key was made by *something* that holds the private key, and
            # nothing about which model of authenticator. Real "basic"
            # attestation uses a batch certificate; most RPs use "none",
            # because attestation mainly matters for enterprises that must
            # restrict authenticator models.
            signed = auth_data + hashlib.sha256(client_data_json).digest()
            signature = signature_to_der(ecdsa_sign(key, signed))
            att_stmt = {"alg": -7, "sig": signature}
            fmt = "packed"
        else:
            att_stmt = {}
            fmt = "none"

        attestation_object = cbor_encode(
            {"fmt": fmt, "attStmt": att_stmt, "authData": auth_data}
        )

        self.credentials[credential_id] = StoredCredential(
            credential_id=credential_id,
            private_key=key,
            rp_id=rp_id,
            user_handle=user_handle,
            sign_count=0,
        )

        return {
            "id": b64u_encode(credential_id),
            "rawId": credential_id,
            "type": "public-key",
            "response": {
                "clientDataJSON": client_data_json,
                "attestationObject": attestation_object,
            },
        }

    def get_assertion(
        self,
        *,
        rp_id: str,
        origin: str,
        challenge: bytes,
        credential_id: bytes | None = None,
        user_verified: bool = True,
        sign_count_override: int | None = None,
    ) -> dict:
        """The authentication ceremony (navigator.credentials.get).

        The rp_id check below is the phishing resistance, in one line: the
        authenticator refuses to sign for an RP ID it has no credential for.
        A phishing site at auth-1ab.local gets rp_id="auth-1ab.local" from the
        browser -- which the browser derives from the real origin and will not
        let a page override for another domain -- and there is simply no key.
        """
        candidates = [
            c for c in self.credentials.values()
            if c.rp_id == rp_id and (credential_id is None or c.credential_id == credential_id)
        ]
        if not candidates:
            raise ValueError(f"no credential for rp_id={rp_id!r} (this is the phishing defence)")
        credential = candidates[0]

        client_data = {
            "type": "webauthn.get",
            "challenge": b64u_encode(challenge),
            "origin": origin,
            "crossOrigin": False,
        }
        client_data_json = json.dumps(client_data, separators=(",", ":")).encode("utf-8")

        flags = FLAG_UP
        if user_verified and self.supports_uv:
            flags |= FLAG_UV
        if self.is_platform_passkey:
            flags |= FLAG_BE | FLAG_BS
            count = 0  # syncable passkeys report 0 and never increment
        else:
            credential.sign_count += 1
            count = credential.sign_count
        if sign_count_override is not None:
            count = sign_count_override

        auth_data = self._authenticator_data(rp_id, flags, count)
        signed = auth_data + hashlib.sha256(client_data_json).digest()
        signature = signature_to_der(ecdsa_sign(credential.private_key, signed))

        return {
            "id": b64u_encode(credential.credential_id),
            "rawId": credential.credential_id,
            "type": "public-key",
            "response": {
                "clientDataJSON": client_data_json,
                "authenticatorData": auth_data,
                "signature": signature,
                "userHandle": credential.user_handle,
            },
        }
