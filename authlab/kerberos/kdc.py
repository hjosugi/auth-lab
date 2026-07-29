"""The Key Distribution Center: AS and TGS.

Simplifications, stated up front so nothing here is mistaken for real
Kerberos:

  * Real Kerberos serialises everything in ASN.1 DER over UDP/TCP 88. We pass
    Python objects, because the wire format teaches nothing the structures
    do not.
  * Real enctypes are aes256-cts-hmac-sha384-192 and friends, with a specific
    key derivation and cipher-text stealing. We use our own AES-CBC plus
    HMAC-SHA256 in encrypt-then-MAC order and call it `aes256-lab`.
  * string_to_key here is PBKDF2. Real AES enctypes use PBKDF2 with 4096
    iterations too (RFC 3962), so this one is actually close -- and 4096
    iterations is FAR too few in 2024, which is precisely why Kerberoasting
    works.

The message flow:

    AS-REQ   client -> KDC   "I am alice, I want a TGT"
                             + PA-ENC-TIMESTAMP: a timestamp encrypted with
                               the key derived from alice's password
    AS-REP   KDC -> client   TGT (encrypted with krbtgt key)
                             + session key (encrypted with alice's key)

    TGS-REQ  client -> KDC   TGT + authenticator + "I want HTTP/web"
    TGS-REP  KDC -> client   service ticket (encrypted with HTTP/web's key)
                             + new session key (encrypted with TGT session key)

    AP-REQ   client -> svc   service ticket + authenticator
    AP-REP   svc -> client   (optional) proof the service decrypted it
"""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass, field

from ..crypto.aes import encrypt_then_mac, verify_then_decrypt
from ..util.clock import Clock, SystemClock
from ..util.ct import constant_time_equals, random_bytes
from .messages import (
    APRep,
    ASRep,
    Authenticator,
    EncryptedData,
    EncTicketPart,
    TGSRep,
    TGT_SERVICE,
    Ticket,
)

ETYPE = "aes256-lab"
# RFC 3962 specifies 4096 iterations for the AES enctypes. Left at the real
# value on purpose: it is what makes offline cracking of a Kerberoasted
# ticket cheap, and pretending otherwise would hide the lesson.
STRING_TO_KEY_ITERATIONS = 4096


class KerberosError(Exception):
    """Any KDC or ticket failure."""


def string_to_key(password: str, salt: str, iterations: int = STRING_TO_KEY_ITERATIONS) -> bytes:
    """Derive a principal's long-term key from a password (RFC 3962).

    The salt is realm + principal name, so the same password in two realms
    produces different keys. What it is NOT is slow: 4096 iterations of
    PBKDF2-HMAC-SHA1 is a few milliseconds, so a GPU does millions of guesses
    a second. Everything called "roasting" in the AD attack literature depends
    on this.
    """
    return hashlib.pbkdf2_hmac("sha1", password.encode("utf-8"), salt.encode("utf-8"), iterations, 32)


def _split_key(key: bytes) -> tuple[bytes, bytes]:
    """Derive separate encryption and MAC keys from one long-term key.

    Using one key for both is a classic mistake: it lets an attacker who can
    influence one primitive attack the other. Real Kerberos does this with
    the DK() key-derivation function and distinct key usage numbers.
    """
    enc = hmac.new(key, b"lab-kerberos-enc", hashlib.sha256).digest()
    mac = hmac.new(key, b"lab-kerberos-mac", hashlib.sha256).digest()
    return enc, mac


def encrypt(key: bytes, plaintext: bytes, kvno: int = 1) -> EncryptedData:
    enc_key, mac_key = _split_key(key)
    return EncryptedData(ETYPE, kvno, encrypt_then_mac(enc_key, mac_key, plaintext))


def decrypt(key: bytes, data: EncryptedData) -> bytes:
    if data.etype != ETYPE:
        raise KerberosError(f"unsupported etype: {data.etype!r}")
    enc_key, mac_key = _split_key(key)
    try:
        return verify_then_decrypt(enc_key, mac_key, data.cipher)
    except ValueError as exc:
        raise KerberosError(f"decryption failed: {exc}") from exc


def _serialize(obj) -> bytes:
    """Stand-in for ASN.1 DER. Deterministic, which is all we need."""
    import pickle

    return pickle.dumps(obj, protocol=4)


def _deserialize(data: bytes):
    import pickle

    return pickle.loads(data)


@dataclass
class Principal:
    """A user, a service, or krbtgt."""

    name: str
    realm: str
    key: bytes
    kvno: int = 1
    # If false, the AS will issue an AS-REP without proof the requester knows
    # the password. That is "do not require Kerberos preauthentication", and
    # it is what AS-REP roasting harvests.
    require_preauth: bool = True
    is_service: bool = False
    groups: list[str] = field(default_factory=list)

    @property
    def full_name(self) -> str:
        return f"{self.name}@{self.realm}"


@dataclass
class KDC:
    """The Key Distribution Center for one realm."""

    realm: str = "LAB.LOCAL"
    clock: Clock = field(default_factory=SystemClock)
    principals: dict[str, Principal] = field(default_factory=dict)
    ticket_lifetime: int = 36_000     # 10 hours, the AD default
    clock_skew: int = 300             # 5 minutes, the AD default
    krbtgt_key: bytes = field(default_factory=lambda: random_bytes(32))
    # Every ticket the KDC issued, for the drills to inspect. A real KDC logs
    # events 4768/4769; this is the same information.
    log: list[str] = field(default_factory=list)

    def add_principal(
        self, name: str, password: str | None = None, *, is_service: bool = False,
        require_preauth: bool = True, groups: list[str] | None = None,
    ) -> Principal:
        key = (
            string_to_key(password, f"{self.realm}{name}")
            if password is not None
            else random_bytes(32)
        )
        principal = Principal(
            name=name, realm=self.realm, key=key, is_service=is_service,
            require_preauth=require_preauth, groups=groups or [],
        )
        self.principals[name] = principal
        return principal

    # ------------------------------------------------------------------
    # AS exchange
    # ------------------------------------------------------------------

    def as_req(self, client_name: str, pa_enc_timestamp: EncryptedData | None = None) -> ASRep:
        """AS-REQ -> AS-REP. Issues a TGT."""
        client = self.principals.get(client_name)
        if client is None:
            # A real KDC returns KDC_ERR_C_PRINCIPAL_UNKNOWN here, which is a
            # free username-enumeration oracle -- and is exactly how attackers
            # build a valid user list before spraying passwords at it.
            raise KerberosError(f"KDC_ERR_C_PRINCIPAL_UNKNOWN: {client_name!r}")

        now = self.clock.now()

        if client.require_preauth:
            if pa_enc_timestamp is None:
                raise KerberosError("KDC_ERR_PREAUTH_REQUIRED")
            try:
                stamp = int(decrypt(client.key, pa_enc_timestamp).decode("ascii"))
            except KerberosError:
                raise KerberosError("KDC_ERR_PREAUTH_FAILED: bad password") from None
            if abs(now - stamp) > self.clock_skew:
                raise KerberosError("KDC_ERR_SKEW: timestamp outside the allowed window")
        else:
            self.log.append(
                f"WARNING: {client_name} has preauth disabled -- AS-REP roastable"
            )

        session_key = random_bytes(32)
        enc_ticket = EncTicketPart(
            client=client.full_name,
            realm=self.realm,
            session_key=session_key,
            auth_time=now,
            start_time=now,
            end_time=now + self.ticket_lifetime,
            flags=["initial", "pre-authent"] if client.require_preauth else ["initial"],
            authorization_data={"groups": client.groups},
        )
        ticket = Ticket(
            realm=self.realm,
            service=TGT_SERVICE,
            # The TGT is encrypted with the krbtgt key. Whoever holds that key
            # can forge this structure at will -- the golden ticket.
            enc_part=encrypt(self.krbtgt_key, _serialize(enc_ticket)),
        )
        self.log.append(f"AS-REP: TGT issued to {client.full_name}")

        # The session key is returned encrypted with the CLIENT's long-term
        # key. With preauth disabled anyone can request this blob for any user
        # and crack it offline: AS-REP roasting.
        return ASRep(
            client=client.full_name,
            ticket=ticket,
            enc_part=encrypt(
                client.key, _serialize({"session_key": session_key, "end_time": enc_ticket.end_time})
            ),
        )

    # ------------------------------------------------------------------
    # TGS exchange
    # ------------------------------------------------------------------

    def tgs_req(self, tgt: Ticket, authenticator: EncryptedData, service_name: str) -> TGSRep:
        """TGS-REQ -> TGS-REP. Trades a TGT for a service ticket."""
        if tgt.service != TGT_SERVICE:
            raise KerberosError("KDC_ERR_POLICY: not a ticket-granting ticket")

        enc_ticket: EncTicketPart = _deserialize(decrypt(self.krbtgt_key, tgt.enc_part))
        now = self.clock.now()
        if now > enc_ticket.end_time:
            raise KerberosError("KRB_AP_ERR_TKT_EXPIRED")

        # The authenticator proves the requester holds the TGT's session key,
        # not merely a copy of the ticket bytes.
        auth: Authenticator = _deserialize(decrypt(enc_ticket.session_key, authenticator))
        if auth.client != enc_ticket.client:
            raise KerberosError("KRB_AP_ERR_BADMATCH: authenticator does not match the ticket")
        if abs(now - auth.timestamp) > self.clock_skew:
            raise KerberosError("KRB_AP_ERR_SKEW")

        service = self.principals.get(service_name)
        if service is None:
            raise KerberosError(f"KDC_ERR_S_PRINCIPAL_UNKNOWN: {service_name!r}")

        session_key = random_bytes(32)
        service_ticket_part = EncTicketPart(
            client=enc_ticket.client,
            realm=self.realm,
            session_key=session_key,
            auth_time=enc_ticket.auth_time,
            start_time=now,
            end_time=min(now + self.ticket_lifetime, enc_ticket.end_time),
            flags=list(enc_ticket.flags),
            authorization_data=dict(enc_ticket.authorization_data),
        )
        ticket = Ticket(
            realm=self.realm,
            service=service_name,
            # Encrypted with the SERVICE ACCOUNT's key -- which, for a service
            # running as a domain user, is derived from that user's password.
            # Any authenticated user may request this ticket for any SPN, take
            # it away, and brute-force the password offline. That is
            # Kerberoasting, and the fix is a long random service password (or
            # a Group Managed Service Account), not a firewall rule.
            enc_part=encrypt(service.key, _serialize(service_ticket_part), kvno=service.kvno),
        )
        self.log.append(f"TGS-REP: {enc_ticket.client} -> {service_name}")
        return TGSRep(
            client=enc_ticket.client,
            ticket=ticket,
            enc_part=encrypt(
                enc_ticket.session_key,
                _serialize({"session_key": session_key, "end_time": service_ticket_part.end_time}),
            ),
        )

    # ------------------------------------------------------------------
    # attack helpers, for the drills
    # ------------------------------------------------------------------

    def forge_golden_ticket(
        self, client_name: str, groups: list[str], lifetime: int = 315_360_000
    ) -> Ticket:
        """Mint a TGT from the krbtgt key alone, for any user, any groups.

        Included so the drill can *show* that this needs no password, no
        account, and no interaction with the KDC's normal paths -- an attacker
        who has dumped the krbtgt hash does this offline. Default lifetime is
        ten years, which is the tell: real TGTs last ten hours, so a long
        lifetime in a ticket is a detection signal.
        """
        now = self.clock.now()
        enc_ticket = EncTicketPart(
            client=f"{client_name}@{self.realm}",
            realm=self.realm,
            session_key=random_bytes(32),
            auth_time=now,
            start_time=now,
            end_time=now + lifetime,
            flags=["initial", "forged"],
            authorization_data={"groups": groups},
        )
        return Ticket(
            realm=self.realm,
            service=TGT_SERVICE,
            enc_part=encrypt(self.krbtgt_key, _serialize(enc_ticket)),
        )

    def kerberoastable_material(self, service_ticket: Ticket) -> bytes:
        """The ciphertext an attacker takes offline to crack a service password."""
        return service_ticket.enc_part.cipher

    def crack_service_ticket(
        self, service_ticket: Ticket, candidate_passwords: list[str], service_name: str
    ) -> str | None:
        """Offline dictionary attack against a Kerberoasted ticket.

        No network traffic, no failed-login events, no lockout. This is what
        makes it dangerous: the only real defences are password length and
        rotation.
        """
        for password in candidate_passwords:
            key = string_to_key(password, f"{self.realm}{service_name}")
            try:
                decrypt(key, service_ticket.enc_part)
                return password
            except KerberosError:
                continue
        return None
