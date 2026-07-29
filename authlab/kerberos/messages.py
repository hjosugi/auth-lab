"""Kerberos message structures.

Kerberos is the oldest protocol in this repo (MIT, 1980s) and still the one
running every Active Directory domain on earth. It is worth learning because
its trust model is the opposite of OAuth's: everything is symmetric, there
are no public keys, and the KDC knows every secret in the realm.

The cast:

    principal   a named identity: alice@LAB.LOCAL, HTTP/web.lab.local@LAB.LOCAL
    KDC         the Key Distribution Center; holds every principal's long-term
                key. Two logical halves:
                  AS  (Authentication Service) issues the TGT
                  TGS (Ticket Granting Service) issues service tickets
    TGT         Ticket Granting Ticket: your "I have logged in" token,
                encrypted with the krbtgt account's key
    ticket      a service ticket, encrypted with the TARGET SERVICE's key
    session key a fresh symmetric key the KDC generates per ticket and gives
                to both sides
    authenticator  a timestamp encrypted with the session key, which proves
                the client holds it right now (freshness, anti-replay)

The insight that makes it work: a ticket is encrypted with the service's own
long-term key, so the service can decrypt it *without ever calling the KDC*.
The KDC is only involved when you get a ticket, not when you use it. That is
why a domain controller can serve tens of thousands of machines.

The insight that makes it dangerous: whoever holds the krbtgt key can mint a
TGT for anyone, with any group membership, that every service in the realm
will honour, and nothing logs it. That is the golden ticket, and it is why
"we reset krbtgt twice" is a standard step in AD incident response.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

TGT_SERVICE = "krbtgt"


@dataclass
class EncryptedData:
    """A ciphertext plus the key id used, mirroring Kerberos EncryptedData."""

    etype: str            # our simplified enctype name
    kvno: int             # key version number, so keys can rotate
    cipher: bytes

    def __repr__(self) -> str:
        return f"EncryptedData(etype={self.etype!r}, kvno={self.kvno}, {len(self.cipher)} bytes)"


@dataclass
class Ticket:
    """A service ticket or TGT.

    Only `realm` and `service` are in the clear -- everything that matters is
    inside `enc_part`, encrypted with the service's long-term key. The client
    carries this around as an opaque blob; it cannot read it, and that is the
    point.
    """

    realm: str
    service: str
    enc_part: EncryptedData

    def __repr__(self) -> str:
        return f"Ticket(for={self.service}@{self.realm}, enc_part={self.enc_part!r})"


@dataclass
class EncTicketPart:
    """The plaintext inside a ticket, readable only by the target service."""

    client: str
    realm: str
    session_key: bytes
    auth_time: int
    start_time: int
    end_time: int
    renew_till: int = 0
    flags: list[str] = field(default_factory=list)
    # The PAC in Active Directory: group SIDs the service uses for
    # authorization. It is signed by the KDC, but a golden ticket forges the
    # signature too, which is how "Domain Admins" gets added out of thin air.
    authorization_data: dict[str, Any] = field(default_factory=dict)


@dataclass
class Authenticator:
    """Proof that the client holds the session key right now.

    Encrypted with the session key, so only the client and the service can
    read it. The timestamp is what makes a captured ticket useless on its own:
    a ticket is valid for hours, but an authenticator is valid for minutes and
    each one may be used once.
    """

    client: str
    realm: str
    timestamp: int
    microseconds: int = 0
    checksum: bytes = b""
    subkey: bytes | None = None
    sequence_number: int = 0


@dataclass
class ASRep:
    """AS-REP: the TGT plus the session key, the latter encrypted to the user."""

    client: str
    ticket: Ticket
    enc_part: EncryptedData  # encrypted with the CLIENT's long-term key


@dataclass
class TGSRep:
    """TGS-REP: a service ticket plus a new session key, encrypted with the
    TGT session key (not the user's password-derived key -- which is why you
    only type your password once)."""

    client: str
    ticket: Ticket
    enc_part: EncryptedData


@dataclass
class APRep:
    """AP-REP: the service proves it could decrypt the ticket.

    Optional in Kerberos, and skipping it means the client never authenticates
    the server -- so a rogue service can accept your ticket and impersonate the
    real one to you. Mutual authentication is exactly this message.
    """

    enc_part: EncryptedData
