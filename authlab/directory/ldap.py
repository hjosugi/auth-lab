"""A tiny LDAP directory, with the bind semantics that trip people up.

LDAP is the protocol behind Active Directory, OpenLDAP, and every "log in
with your corporate account" that predates SAML. You mostly meet it as the
backend of an authentication form, and that is exactly where it goes wrong.

Directory shape: a tree of entries, each named by a Distinguished Name that
reads leaf-first:

    uid=alice,ou=people,dc=lab,dc=local

Authentication is a BIND operation, and there are two kinds, with a crucial
difference:

  simple bind   send a DN and a password; the server checks them. The
                password crosses the wire, so simple bind without TLS is
                plaintext credentials on the network. Historically the default.
  SASL bind     a proper mechanism negotiation (EXTERNAL for client certs,
                GSSAPI for Kerberos, SCRAM for challenge-response). What you
                should use.

The two failure modes this module exists to demonstrate:

1. LDAP injection. The classic authentication filter is
       (&(uid=<input>)(userPassword=<input>))
   Put `*)(uid=*))(|(uid=*` in the username and the filter turns into
   something that matches everyone. Or supply `admin)(&)` to short-circuit.
   The fix is RFC 4515 filter escaping, applied below in escape_filter -- and
   the better fix is to never build a filter from user input at all: bind as
   a service account, search for the user with a parameter, then bind as the
   found DN.

2. The unauthenticated bind / anonymous bind trap. LDAPv3 says a bind with a
   valid DN but an EMPTY password is an *anonymous* bind, and it SUCCEEDS.
   So the naive "bind with the user's DN and their password; if it works they
   are authenticated" logic authenticates anyone who leaves the password box
   blank. This is CVE-grade and still shipping. We reject empty-password
   binds explicitly and return the same "did it succeed as this identity"
   answer the caller actually needs.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field

from ..passwords import PasswordHasher
from ..util.ct import constant_time_equals


class LDAPError(Exception):
    """Any directory error."""


# RFC 4515 section 3: these characters must be escaped in a search filter
# assertion value, as \\XX hex.
_FILTER_ESCAPE = {
    "\\": r"\5c",
    "*": r"\2a",
    "(": r"\28",
    ")": r"\29",
    "\x00": r"\00",
}


def escape_filter(value: str) -> str:
    """Escape a value for safe inclusion in an LDAP search filter."""
    return "".join(_FILTER_ESCAPE.get(char, char) for char in value)


# RFC 4514: DN special characters.
_DN_ESCAPE = set(',+"\\<>;=')


def escape_dn(value: str) -> str:
    """Escape a value for safe inclusion in a DN component."""
    out = []
    for index, char in enumerate(value):
        if char in _DN_ESCAPE or char == "\x00":
            out.append("\\" + char)
        elif char == " " and (index == 0 or index == len(value) - 1):
            out.append("\\ ")
        elif char == "#" and index == 0:
            out.append("\\#")
        else:
            out.append(char)
    return "".join(out)


@dataclass(frozen=True)
class DN:
    """A distinguished name, parsed into (attr, value) RDNs."""

    rdns: tuple[tuple[str, str], ...]

    @classmethod
    def parse(cls, text: str) -> "DN":
        rdns = []
        for part in _split_dn(text):
            if "=" not in part:
                raise LDAPError(f"malformed RDN: {part!r}")
            attr, value = part.split("=", 1)
            rdns.append((attr.strip().lower(), value.strip()))
        return cls(tuple(rdns))

    def __str__(self) -> str:
        return ",".join(f"{attr}={value}" for attr, value in self.rdns)

    @property
    def rdn(self) -> tuple[str, str]:
        return self.rdns[0]

    def is_child_of(self, base: "DN") -> bool:
        if len(base.rdns) > len(self.rdns):
            return False
        return self.rdns[len(self.rdns) - len(base.rdns):] == base.rdns


def _split_dn(text: str) -> list[str]:
    """Split on unescaped commas."""
    parts, current, escaped = [], [], False
    for char in text:
        if escaped:
            current.append(char)
            escaped = False
        elif char == "\\":
            current.append(char)
            escaped = True
        elif char == ",":
            parts.append("".join(current))
            current = []
        else:
            current.append(char)
    parts.append("".join(current))
    return parts


@dataclass
class Entry:
    """A directory entry: a DN plus multi-valued attributes."""

    dn: str
    attributes: dict[str, list[str]] = field(default_factory=dict)

    def get(self, name: str) -> list[str]:
        return self.attributes.get(name.lower(), [])

    def first(self, name: str) -> str | None:
        values = self.get(name)
        return values[0] if values else None


class LDAP:
    """An in-memory LDAP-like directory with bind and search."""

    def __init__(self, hasher: PasswordHasher | None = None) -> None:
        self.entries: dict[str, Entry] = {}
        self.hasher = hasher or PasswordHasher()

    def add(self, dn: str, attributes: dict[str, list[str]], password: str | None = None) -> Entry:
        normalized = str(DN.parse(dn))
        attrs = {k.lower(): list(v) for k, v in attributes.items()}
        if password is not None:
            # Stored as {SCHEME} prefixed hashes, the way real directories do
            # (RFC 2307). We use our own PHC string behind a {LAB} label.
            attrs["userpassword"] = ["{LAB}" + self.hasher.hash(password)]
        entry = Entry(dn=normalized, attributes=attrs)
        self.entries[normalized] = entry
        return entry

    # ------------------------------------------------------------------
    # bind
    # ------------------------------------------------------------------

    def simple_bind(self, dn: str, password: str) -> bool:
        """Authenticate by DN and password.

        The two guards that make this safe are both about the empty password:
        an LDAP simple bind with an empty password is an *anonymous* bind that
        the protocol says must succeed, so a login that treats bind-success as
        authentication lets anyone in with a blank password.
        """
        if password == "":
            # Unauthenticated / anonymous bind. Never counts as authenticating
            # the named identity.
            raise LDAPError("empty password: this is an anonymous bind, not authentication")

        try:
            normalized = str(DN.parse(dn))
        except LDAPError:
            return False
        entry = self.entries.get(normalized)
        if entry is None:
            # Do a dummy verify so a missing DN and a wrong password take the
            # same time -- otherwise bind timing enumerates valid DNs.
            self.hasher.fake_verify(password)
            return False

        stored = entry.first("userpassword")
        if not stored or not stored.startswith("{LAB}"):
            self.hasher.fake_verify(password)
            return False
        return self.hasher.verify(password, stored[len("{LAB}"):])

    def authenticate(self, username: str, password: str, *, base_dn: str, uid_attr: str = "uid") -> Entry | None:
        """The RIGHT way to authenticate a username/password against LDAP.

        Search-then-bind, never build-a-filter-from-input:
          1. as a trusted search, find the entry whose uid == username, with
             the username ESCAPED into the filter
          2. bind as the DN we found, with the supplied password
          3. reject empty passwords before step 2

        This structure is immune to LDAP injection (the username is a search
        value, never filter syntax) and to the anonymous-bind trap (empty
        password is refused).
        """
        if not password:
            return None
        matches = self.search(base_dn, f"({uid_attr}={escape_filter(username)})")
        if len(matches) != 1:
            # Zero: no such user. More than one: an ambiguous directory, which
            # must fail closed rather than pick one.
            self.hasher.fake_verify(password)
            return None
        entry = matches[0]
        if self.simple_bind(entry.dn, password):
            return entry
        return None

    # ------------------------------------------------------------------
    # search
    # ------------------------------------------------------------------

    def search(self, base_dn: str, filter_string: str) -> list[Entry]:
        """Search under base_dn with an RFC 4515 filter.

        The filter parser below is deliberately strict. It is the thing an
        injection payload has to get through, so it treats a malformed filter
        as an error, never as "match everything".
        """
        base = DN.parse(base_dn)
        predicate = _parse_filter(filter_string)
        return [
            entry
            for entry in self.entries.values()
            if DN.parse(entry.dn).is_child_of(base) and predicate(entry)
        ]


# --- RFC 4515 filter parsing ------------------------------------------------
# A real parser for the subset we need: presence, equality, substrings, and
# the &/|/! operators. Parsing rather than string-matching is what makes
# injection structurally impossible: an injected ")(" is a syntax error here,
# not a new clause.


def _parse_filter(text: str):
    text = text.strip()
    parser = _FilterParser(text)
    predicate = parser.parse()
    if parser.pos != len(text):
        raise LDAPError(f"trailing characters in filter at position {parser.pos}")
    return predicate


class _FilterParser:
    def __init__(self, text: str) -> None:
        self.text = text
        self.pos = 0

    def parse(self):
        if self.pos >= len(self.text) or self.text[self.pos] != "(":
            raise LDAPError("filter must start with '('")
        self.pos += 1  # consume '('
        if self.pos >= len(self.text):
            raise LDAPError("unterminated filter")

        char = self.text[self.pos]
        if char in "&|":
            self.pos += 1
            children = []
            while self.pos < len(self.text) and self.text[self.pos] == "(":
                children.append(self.parse())
            if not children:
                raise LDAPError(f"{char!r} needs at least one sub-filter")
            self._expect(")")
            if char == "&":
                return lambda entry: all(child(entry) for child in children)
            return lambda entry: any(child(entry) for child in children)
        if char == "!":
            self.pos += 1
            child = self.parse()
            self._expect(")")
            return lambda entry: not child(entry)

        # simple assertion: attr, then =, then value (up to the closing ')')
        assertion = []
        while self.pos < len(self.text) and self.text[self.pos] != ")":
            assertion.append(self.text[self.pos])
            self.pos += 1
        self._expect(")")
        return self._assertion("".join(assertion))

    def _assertion(self, text: str):
        if "=" not in text:
            raise LDAPError(f"malformed assertion: {text!r}")
        attr, value = text.split("=", 1)
        attr = attr.strip().lower()
        if value == "*":
            return lambda entry: bool(entry.get(attr))
        if "*" in value:
            parts = value.split("*")

            def substring(entry: Entry) -> bool:
                for candidate in entry.get(attr):
                    if _substring_match(candidate, parts):
                        return True
                return False

            return substring

        # An unescaped '(' or ')' can never reach here because parse() stops
        # at them, so a value is always a literal.
        unescaped = _unescape_filter_value(value)

        def equals(entry: Entry) -> bool:
            return any(constant_time_equals(v, unescaped) for v in entry.get(attr))

        return equals

    def _expect(self, char: str) -> None:
        if self.pos >= len(self.text) or self.text[self.pos] != char:
            raise LDAPError(f"expected {char!r} at position {self.pos}")
        self.pos += 1


def _substring_match(candidate: str, parts: list[str]) -> bool:
    if not candidate.startswith(parts[0]):
        return False
    if not candidate.endswith(parts[-1]):
        return False
    position = len(parts[0])
    for middle in parts[1:-1]:
        found = candidate.find(middle, position)
        if found == -1:
            return False
        position = found + len(middle)
    return len(parts[0]) + len(parts[-1]) <= len(candidate) or len(parts) == 1


def _unescape_filter_value(value: str) -> str:
    out, i = [], 0
    while i < len(value):
        if value[i] == "\\" and i + 2 < len(value) + 1:
            out.append(chr(int(value[i + 1 : i + 3], 16)))
            i += 3
        else:
            out.append(value[i])
            i += 1
    return "".join(out)
