"""The Kerberos client: the thing that holds your ticket cache."""

from __future__ import annotations

from dataclasses import dataclass, field

from ..util.clock import Clock, SystemClock
from ..util.ct import random_bytes
from .kdc import KDC, KerberosError, decrypt, encrypt, string_to_key, _serialize
from .messages import Authenticator, EncryptedData, TGT_SERVICE, Ticket


@dataclass
class CachedTicket:
    ticket: Ticket
    session_key: bytes
    end_time: int


@dataclass
class KerberosClient:
    """A client with a ticket cache (the equivalent of a krb5 ccache)."""

    principal: str
    realm: str
    kdc: KDC
    clock: Clock = field(default_factory=SystemClock)
    long_term_key: bytes | None = None
    tgt: CachedTicket | None = None
    service_tickets: dict[str, CachedTicket] = field(default_factory=dict)

    def kinit(self, password: str) -> CachedTicket:
        """Log in: obtain a TGT. This is the only step that touches the password.

        Note what happens to the password afterwards: nothing. It is used to
        derive the long-term key, the key decrypts the AS-REP, and from then
        on every request uses ticket session keys. That single-sign-on
        property is Kerberos's whole reason for existing.
        """
        self.long_term_key = string_to_key(password, f"{self.realm}{self.principal}")
        now = self.clock.now()

        # PA-ENC-TIMESTAMP: prove we know the password before the KDC will
        # hand out anything encrypted with our key.
        pa = encrypt(self.long_term_key, str(now).encode("ascii"))
        rep = self.kdc.as_req(self.principal, pa)

        payload = __import__("pickle").loads(decrypt(self.long_term_key, rep.enc_part))
        self.tgt = CachedTicket(rep.ticket, payload["session_key"], payload["end_time"])
        return self.tgt

    def _authenticator(self, session_key: bytes) -> EncryptedData:
        return encrypt(
            session_key,
            _serialize(
                Authenticator(
                    client=f"{self.principal}@{self.realm}",
                    realm=self.realm,
                    timestamp=self.clock.now(),
                    sequence_number=int.from_bytes(random_bytes(4), "big"),
                )
            ),
        )

    def get_service_ticket(self, service_name: str) -> CachedTicket:
        """Trade the TGT for a service ticket. No password involved.

        A still-valid cached ticket is used directly, without a TGT -- which is
        exactly why pass-the-ticket works: a stolen service ticket in the
        cache is usable on its own, no TGT and no password required.
        """
        cached = self.service_tickets.get(service_name)
        if cached and self.clock.now() < cached.end_time:
            return cached

        if self.tgt is None:
            raise KerberosError("no TGT: call kinit() first")
        if self.clock.now() > self.tgt.end_time:
            raise KerberosError("TGT has expired; re-run kinit()")

        rep = self.kdc.tgs_req(
            self.tgt.ticket, self._authenticator(self.tgt.session_key), service_name
        )
        payload = __import__("pickle").loads(decrypt(self.tgt.session_key, rep.enc_part))
        cached = CachedTicket(rep.ticket, payload["session_key"], payload["end_time"])
        self.service_tickets[service_name] = cached
        return cached

    def ap_req(self, service_name: str, mutual: bool = True) -> tuple[Ticket, EncryptedData]:
        """Build the AP-REQ a client sends to a service."""
        cached = self.get_service_ticket(service_name)
        return cached.ticket, self._authenticator(cached.session_key)

    def verify_ap_rep(self, service_name: str, ap_rep) -> bool:
        """Mutual authentication: only the real service could produce this.

        Skipping this step is how a client ends up talking to an impostor. The
        impostor cannot decrypt the ticket (it lacks the service key) so it
        cannot produce a valid AP-REP -- but a client that never asks will
        never notice.
        """
        cached = self.service_tickets.get(service_name)
        if cached is None:
            return False
        try:
            payload = __import__("pickle").loads(decrypt(cached.session_key, ap_rep.enc_part))
        except KerberosError:
            return False
        return "timestamp" in payload

    def import_ticket(self, service_name: str, ticket: Ticket, session_key: bytes, end_time: int) -> None:
        """Load a ticket obtained elsewhere: pass-the-ticket.

        An attacker who dumps LSASS on a compromised host walks away with
        exactly this -- a ticket and its session key -- and can replay them
        from their own machine until the ticket expires. No password needed.
        This is the method that makes it concrete.
        """
        self.service_tickets[service_name] = CachedTicket(ticket, session_key, end_time)

    def import_tgt(self, ticket: Ticket, session_key: bytes, end_time: int) -> None:
        self.tgt = CachedTicket(ticket, session_key, end_time)
