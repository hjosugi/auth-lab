"""The WebAuthn relying party: the server side of passkeys.

This is the checklist from the W3C spec, section 7.1 (registration) and 7.2
(authentication), written out with the reason for each step. An RP that skips
any of them is not phishing-resistant, whatever the marketing says.

Why passkeys beat every other factor:

  password   -- a shared secret. Phishable, reusable, breachable in bulk.
  TOTP       -- a shared secret plus a clock. Still phishable: a real-time
                proxy (Evilginx and friends) relays the code within its 30
                second window. Still bulk-stealable at the server.
  push       -- phishable by fatigue: send 40 prompts at 3am and one gets
                approved. Number matching helps and does not eliminate it.
  passkey    -- a private key that never leaves the authenticator, and a
                signature bound to the origin. There is no secret at the
                server to steal (only public keys), nothing for the user to
                type, and the signature is worthless on any other domain.

What passkeys do NOT solve:
  * account recovery. The recovery path becomes the weakest link, and it is
    usually still "email a link", which is a password behind one hop.
  * device loss, unless the passkey is syncable -- and a syncable passkey is
    only as strong as the cloud account holding it.
  * a fully compromised client. Malware with control of the browser can ask
    for a legitimate assertion at the right moment.
"""

from __future__ import annotations

import hashlib
import json
import struct
from dataclasses import dataclass, field
from typing import Any

from ..crypto.cbor import decode as cbor_decode
from ..crypto.ec import ECPublicKey, ecdsa_verify, signature_from_der
from ..crypto.ed25519 import Ed25519PublicKey, ed25519_verify
from ..util.clock import Clock, SystemClock
from ..util.ct import constant_time_equals, random_bytes
from ..util.encoding import b64u_decode, b64u_encode
from .authenticator import FLAG_AT, FLAG_BE, FLAG_BS, FLAG_UP, FLAG_UV
from .cose import (
    COSE_EDDSA,
    COSE_ES256,
    SUPPORTED_ALGORITHMS,
    cose_decode_public_key,
)

CredentialPublicKey = ECPublicKey | Ed25519PublicKey


class WebAuthnError(Exception):
    """Any ceremony failure."""


def verify_credential_signature(
    public_key: CredentialPublicKey, signed: bytes, signature: bytes
) -> bool:
    """Verify an authenticator signature against the key type we stored.

    The algorithm comes from the stored credential, never from the assertion.
    That is the WebAuthn form of the JWS `alg` lesson: if the RP read the
    algorithm out of the message it is checking, an attacker would get to pick
    it.
    """
    if isinstance(public_key, Ed25519PublicKey):
        # RFC 8032 signatures are fixed-length raw bytes, not DER.
        return ed25519_verify(public_key, signed, signature)
    try:
        parsed = signature_from_der(signature)
    except Exception as exc:  # noqa: BLE001
        raise WebAuthnError(f"malformed signature: {exc}") from exc
    return ecdsa_verify(public_key, signed, parsed)


@dataclass
class RegisteredCredential:
    """What the RP stores. Note there is no secret here."""

    credential_id: bytes
    public_key: CredentialPublicKey
    user_handle: bytes
    sign_count: int
    aaguid: bytes = b""
    backup_eligible: bool = False
    backup_state: bool = False
    transports: list[str] = field(default_factory=list)

    @property
    def algorithm(self) -> int:
        """The COSE algorithm this credential is pinned to."""
        return COSE_EDDSA if isinstance(self.public_key, Ed25519PublicKey) else COSE_ES256


@dataclass
class ParsedAuthenticatorData:
    rp_id_hash: bytes
    flags: int
    sign_count: int
    aaguid: bytes = b""
    credential_id: bytes = b""
    cose_key: bytes = b""

    @property
    def user_present(self) -> bool:
        return bool(self.flags & FLAG_UP)

    @property
    def user_verified(self) -> bool:
        return bool(self.flags & FLAG_UV)

    @property
    def has_attested_credential(self) -> bool:
        return bool(self.flags & FLAG_AT)

    @property
    def backup_eligible(self) -> bool:
        return bool(self.flags & FLAG_BE)

    @property
    def backup_state(self) -> bool:
        return bool(self.flags & FLAG_BS)


def parse_authenticator_data(data: bytes) -> ParsedAuthenticatorData:
    if len(data) < 37:
        raise WebAuthnError("authenticatorData is shorter than the 37-byte minimum")
    parsed = ParsedAuthenticatorData(
        rp_id_hash=data[:32],
        flags=data[32],
        sign_count=struct.unpack(">I", data[33:37])[0],
    )
    if parsed.has_attested_credential:
        if len(data) < 55:
            raise WebAuthnError("AT flag set but attested credential data is truncated")
        parsed.aaguid = data[37:53]
        length = struct.unpack(">H", data[53:55])[0]
        if len(data) < 55 + length:
            raise WebAuthnError("credentialId is truncated")
        parsed.credential_id = data[55 : 55 + length]
        parsed.cose_key = data[55 + length :]
    return parsed


@dataclass
class RelyingParty:
    """One RP identity: an RP ID and the origins allowed to speak for it."""

    rp_id: str                      # "auth-lab.local"
    origins: list[str]              # ["https://auth-lab.local"]
    rp_name: str = "auth-lab"
    clock: Clock = field(default_factory=SystemClock)
    require_user_verification: bool = True
    challenge_ttl: int = 300
    # user_handle -> credentials
    credentials: dict[bytes, list[RegisteredCredential]] = field(default_factory=dict)
    # session id -> (challenge, issued_at, ceremony)
    pending: dict[str, tuple[bytes, int, str]] = field(default_factory=dict)

    # ------------------------------------------------------------------
    # challenge management
    # ------------------------------------------------------------------

    def create_challenge(self, session_id: str, ceremony: str) -> bytes:
        """A fresh challenge per ceremony.

        Must be random, single-use, and server-generated. A predictable or
        reused challenge lets an attacker precompute or replay an assertion,
        which removes the only proof of freshness in the protocol.
        """
        challenge = random_bytes(32)
        self.pending[session_id] = (challenge, self.clock.now(), ceremony)
        return challenge

    def _take_challenge(self, session_id: str, ceremony: str) -> bytes:
        entry = self.pending.pop(session_id, None)  # single use: pop, not get
        if entry is None:
            raise WebAuthnError("no challenge outstanding for this session")
        challenge, issued_at, expected_ceremony = entry
        if expected_ceremony != ceremony:
            raise WebAuthnError(
                f"challenge was issued for {expected_ceremony!r}, not {ceremony!r}"
            )
        if self.clock.now() - issued_at > self.challenge_ttl:
            raise WebAuthnError("challenge has expired")
        return challenge

    # ------------------------------------------------------------------
    # options (what the server sends to navigator.credentials.*)
    # ------------------------------------------------------------------

    def registration_options(self, session_id: str, user_handle: bytes, username: str) -> dict:
        challenge = self.create_challenge(session_id, "webauthn.create")
        existing = self.credentials.get(user_handle, [])
        return {
            "rp": {"id": self.rp_id, "name": self.rp_name},
            "user": {"id": b64u_encode(user_handle), "name": username, "displayName": username},
            "challenge": b64u_encode(challenge),
            "pubKeyCredParams": [
                {"type": "public-key", "alg": algorithm}
                for algorithm in SUPPORTED_ALGORITHMS
            ],
            "timeout": self.challenge_ttl * 1000,
            "attestation": "none",
            "authenticatorSelection": {
                "userVerification": "required" if self.require_user_verification else "preferred",
                "residentKey": "preferred",
            },
            # Stops a user registering the same authenticator twice, which
            # would silently create a second credential they cannot tell apart.
            "excludeCredentials": [
                {"type": "public-key", "id": b64u_encode(c.credential_id)} for c in existing
            ],
        }

    def authentication_options(self, session_id: str, user_handle: bytes | None = None) -> dict:
        challenge = self.create_challenge(session_id, "webauthn.get")
        options: dict[str, Any] = {
            "challenge": b64u_encode(challenge),
            "rpId": self.rp_id,
            "timeout": self.challenge_ttl * 1000,
            "userVerification": "required" if self.require_user_verification else "preferred",
        }
        if user_handle is not None:
            options["allowCredentials"] = [
                {"type": "public-key", "id": b64u_encode(c.credential_id)}
                for c in self.credentials.get(user_handle, [])
            ]
        # With no allowCredentials the browser offers a discoverable credential
        # (a resident key) and the user picks an account -- this is what makes
        # usernameless "just tap to sign in" possible.
        return options

    # ------------------------------------------------------------------
    # shared clientData validation
    # ------------------------------------------------------------------

    def _verify_client_data(
        self, client_data_json: bytes, expected_type: str, expected_challenge: bytes
    ) -> dict:
        try:
            client_data = json.loads(client_data_json.decode("utf-8"))
        except Exception as exc:  # noqa: BLE001
            raise WebAuthnError(f"clientDataJSON is not valid JSON: {exc}") from exc

        if client_data.get("type") != expected_type:
            # Without this, a registration response can be replayed as an
            # authentication response and vice versa.
            raise WebAuthnError(
                f"clientData.type is {client_data.get('type')!r}, expected {expected_type!r}"
            )

        challenge = client_data.get("challenge", "")
        try:
            received = b64u_decode(challenge)
        except Exception as exc:  # noqa: BLE001
            raise WebAuthnError("clientData.challenge is not valid base64url") from exc
        if not constant_time_equals(received, expected_challenge):
            raise WebAuthnError("challenge mismatch (replay or wrong session)")

        origin = client_data.get("origin", "")
        if origin not in self.origins:
            # THE anti-phishing check. Exact string match against an allow
            # list -- never endswith(), never a regex. "https://auth-lab.local"
            # must not match "https://auth-lab.local.evil.net".
            raise WebAuthnError(f"origin {origin!r} is not in the allowed set {self.origins}")

        if client_data.get("crossOrigin"):
            # A credential invoked from inside a cross-origin iframe. Allowed
            # by spec with permissions policy, but if you do not need it,
            # refusing it removes a clickjacking surface.
            raise WebAuthnError("cross-origin ceremonies are refused by this RP")
        return client_data

    def _verify_rp_id_hash(self, parsed: ParsedAuthenticatorData) -> None:
        expected = hashlib.sha256(self.rp_id.encode("utf-8")).digest()
        if not constant_time_equals(parsed.rp_id_hash, expected):
            raise WebAuthnError("rpIdHash does not match this RP")

    def _verify_flags(self, parsed: ParsedAuthenticatorData) -> None:
        if not parsed.user_present:
            # UP means a human physically interacted. Without it, malware on
            # the machine could sign silently in the background.
            raise WebAuthnError("user presence (UP) flag is not set")
        if self.require_user_verification and not parsed.user_verified:
            # UV means PIN or biometric -- the difference between one factor
            # and two. If you advertise passkeys as MFA, you must require it.
            raise WebAuthnError("user verification (UV) required but not performed")

    # ------------------------------------------------------------------
    # registration
    # ------------------------------------------------------------------

    def verify_registration(
        self, session_id: str, credential: dict, user_handle: bytes
    ) -> RegisteredCredential:
        challenge = self._take_challenge(session_id, "webauthn.create")
        response = credential["response"]
        self._verify_client_data(response["clientDataJSON"], "webauthn.create", challenge)

        try:
            attestation = cbor_decode(response["attestationObject"])
        except Exception as exc:  # noqa: BLE001
            raise WebAuthnError(f"attestationObject is not valid CBOR: {exc}") from exc
        for required in ("fmt", "attStmt", "authData"):
            if required not in attestation:
                raise WebAuthnError(f"attestationObject is missing {required!r}")

        parsed = parse_authenticator_data(attestation["authData"])
        self._verify_rp_id_hash(parsed)
        self._verify_flags(parsed)

        if not parsed.has_attested_credential:
            raise WebAuthnError("registration response carries no attested credential data")

        try:
            public_key = cose_decode_public_key(parsed.cose_key)
        except ValueError as exc:
            raise WebAuthnError(f"unusable credential public key: {exc}") from exc

        if parsed.credential_id != credential.get("rawId"):
            raise WebAuthnError("credentialId in authData does not match rawId")

        for existing in self.credentials.get(user_handle, []):
            if existing.credential_id == parsed.credential_id:
                raise WebAuthnError("this credential is already registered")
        # Also check globally: the same credential id must not be claimable by
        # a second account.
        for handle, records in self.credentials.items():
            for existing in records:
                if existing.credential_id == parsed.credential_id and handle != user_handle:
                    raise WebAuthnError("credential id is already registered to another user")

        fmt = attestation["fmt"]
        if fmt == "packed":
            self._verify_packed_attestation(
                attestation, parsed, response["clientDataJSON"], public_key
            )
        elif fmt != "none":
            raise WebAuthnError(f"unsupported attestation format: {fmt!r}")

        record = RegisteredCredential(
            credential_id=parsed.credential_id,
            public_key=public_key,
            user_handle=user_handle,
            sign_count=parsed.sign_count,
            aaguid=parsed.aaguid,
            backup_eligible=parsed.backup_eligible,
            backup_state=parsed.backup_state,
        )
        self.credentials.setdefault(user_handle, []).append(record)
        return record

    def _verify_packed_attestation(
        self, attestation: dict, parsed: ParsedAuthenticatorData,
        client_data_json: bytes, public_key: CredentialPublicKey,
    ) -> None:
        """Self-attestation only: signed by the credential key itself."""
        statement = attestation["attStmt"]
        if "x5c" in statement:
            # Full attestation with a batch certificate. Verifying it properly
            # means checking the chain against the FIDO Metadata Service, which
            # is an enterprise requirement and out of scope here.
            raise WebAuthnError("x5c attestation is not supported by this RP")
        expected_alg = COSE_EDDSA if isinstance(public_key, Ed25519PublicKey) else COSE_ES256
        if statement.get("alg") != expected_alg:
            # Self-attestation is signed by the credential key, so the stated
            # alg must match the key we just decoded. A mismatch is either a
            # broken authenticator or an attempt to get us to run the wrong
            # verifier.
            raise WebAuthnError(f"unsupported attestation alg: {statement.get('alg')!r}")
        signed = attestation["authData"] + hashlib.sha256(client_data_json).digest()
        if not verify_credential_signature(public_key, signed, statement["sig"]):
            raise WebAuthnError("attestation signature does not verify")

    # ------------------------------------------------------------------
    # authentication
    # ------------------------------------------------------------------

    def verify_authentication(self, session_id: str, assertion: dict) -> RegisteredCredential:
        challenge = self._take_challenge(session_id, "webauthn.get")
        response = assertion["response"]
        self._verify_client_data(response["clientDataJSON"], "webauthn.get", challenge)

        credential_id = assertion.get("rawId")
        record = self._find_credential(credential_id)
        if record is None:
            raise WebAuthnError("unknown credential id")

        user_handle = response.get("userHandle")
        if user_handle and not constant_time_equals(user_handle, record.user_handle):
            # With a discoverable credential the authenticator tells us who
            # the user is. It must agree with what we stored, or someone is
            # trying to authenticate as another account with their own key.
            raise WebAuthnError("userHandle does not match the stored credential")

        parsed = parse_authenticator_data(response["authenticatorData"])
        self._verify_rp_id_hash(parsed)
        self._verify_flags(parsed)

        # The signature covers authenticatorData || SHA-256(clientDataJSON).
        signed = response["authenticatorData"] + hashlib.sha256(response["clientDataJSON"]).digest()
        if not verify_credential_signature(record.public_key, signed, response["signature"]):
            raise WebAuthnError("assertion signature does not verify")

        self._check_sign_count(record, parsed)

        # BS can change legitimately (a passkey gets backed up). Recording it
        # matters because "this credential is now syncable" may change your
        # risk posture for step-up decisions.
        record.backup_state = parsed.backup_state
        return record

    def _find_credential(self, credential_id: bytes | None) -> RegisteredCredential | None:
        if not credential_id:
            return None
        for records in self.credentials.values():
            for record in records:
                if constant_time_equals(record.credential_id, credential_id):
                    return record
        return None

    @staticmethod
    def _check_sign_count(record: RegisteredCredential, parsed: ParsedAuthenticatorData) -> None:
        """Clone detection.

        A hardware authenticator increments a counter on every assertion. If
        the server sees a counter that did not advance, either the credential
        was cloned (someone extracted the key) or a stale response is being
        replayed. Either way it deserves an alarm.

        The exception: syncable passkeys are deliberately the same key on
        several devices, so they report 0 forever. A server that treats 0 as
        "cloned" locks every iPhone user out, which is why the check is
        conditional on the counter having been non-zero at registration.
        """
        if record.sign_count == 0 and parsed.sign_count == 0:
            return  # syncable passkey; no counter available
        if parsed.sign_count <= record.sign_count:
            raise WebAuthnError(
                f"signature counter did not advance ({parsed.sign_count} <= {record.sign_count}): "
                "possible cloned authenticator or replayed assertion"
            )
        record.sign_count = parsed.sign_count
