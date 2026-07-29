"""A Kerberized service: verifies AP-REQ, optionally answers AP-REP.

The service never talks to the KDC. It decrypts the ticket with its own
long-term key, reads the client name and the session key out of it, and then
uses the session key to check the authenticator. That is the whole
verification, and it is why Kerberos scales.

The replay cache is the part implementations get wrong. A ticket is valid for
hours; an authenticator carries a timestamp and is valid for minutes. Without
remembering which authenticators have been seen, an attacker who captures one
AP-REQ off the wire can replay it for the whole skew window.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ..util.clock import Clock, SystemClock
from .kdc import KerberosError, decrypt, encrypt, _deserialize, _serialize
from .messages import APRep, Authenticator, EncryptedData, EncTicketPart, Ticket


@dataclass
class AuthenticatedClient:
    name: str
    realm: str
    groups: list[str]
    session_key: bytes
    auth_time: int
    ticket_end: int
    flags: list[str]


@dataclass
class KerberizedService:
    """One service principal, e.g. HTTP/web.lab.local."""

    name: str
    realm: str
    key: bytes
    clock: Clock = field(default_factory=SystemClock)
    clock_skew: int = 300
    # (client, timestamp, sequence) tuples already seen. Sized by the skew
    # window; entries older than that can be dropped because the timestamp
    # check would reject them anyway.
    replay_cache: dict[tuple[str, int, int], int] = field(default_factory=dict)

    def ap_req(
        self, ticket: Ticket, authenticator: EncryptedData, mutual: bool = True
    ) -> tuple[AuthenticatedClient, APRep | None]:
        """Verify an AP-REQ. Returns the authenticated client."""
        if ticket.service != self.name:
            raise KerberosError(
                f"KRB_AP_ERR_NOKEY: ticket is for {ticket.service!r}, not {self.name!r}"
            )

        # Decrypting with our own key IS the proof that the KDC issued this
        # ticket: nobody else holds our long-term key.
        enc_ticket: EncTicketPart = _deserialize(decrypt(self.key, ticket.enc_part))

        now = self.clock.now()
        if now > enc_ticket.end_time:
            raise KerberosError("KRB_AP_ERR_TKT_EXPIRED")
        if now + self.clock_skew < enc_ticket.start_time:
            raise KerberosError("KRB_AP_ERR_TKT_NYV: ticket not yet valid")

        auth: Authenticator = _deserialize(decrypt(enc_ticket.session_key, authenticator))
        if auth.client != enc_ticket.client:
            raise KerberosError("KRB_AP_ERR_BADMATCH")
        if abs(now - auth.timestamp) > self.clock_skew:
            raise KerberosError("KRB_AP_ERR_SKEW: authenticator timestamp outside the window")

        self._purge_replay_cache(now)
        key = (auth.client, auth.timestamp, auth.sequence_number)
        if key in self.replay_cache:
            raise KerberosError("KRB_AP_ERR_REPEAT: authenticator replay detected")
        self.replay_cache[key] = now + self.clock_skew

        client = AuthenticatedClient(
            name=enc_ticket.client,
            realm=enc_ticket.realm,
            groups=list(enc_ticket.authorization_data.get("groups", [])),
            session_key=enc_ticket.session_key,
            auth_time=enc_ticket.auth_time,
            ticket_end=enc_ticket.end_time,
            flags=list(enc_ticket.flags),
        )

        ap_rep = None
        if mutual:
            # Echo the client's timestamp under the session key. Only a party
            # that could decrypt the ticket knows that key, so this proves we
            # are the real service.
            ap_rep = APRep(
                enc_part=encrypt(
                    enc_ticket.session_key,
                    _serialize({"timestamp": auth.timestamp, "sequence": auth.sequence_number}),
                )
            )
        return client, ap_rep

    def _purge_replay_cache(self, now: int) -> None:
        for key in [k for k, expiry in self.replay_cache.items() if expiry < now]:
            del self.replay_cache[key]
