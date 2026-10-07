"""Person-held keys, checked here (J14a, `specs/docs/design/person-held-keys.md`).

The root names who asked for every change, and until J14a this site believed
it: a root that put the owner's id on a forged change was obeyed. Now a
person's own key, made in their browser on the machine's loopback page and
pinned in the links file by the machine's privileged starter, is what the
site checks. The root never sees either half of it.

**What is signed** is an envelope this host builds (`envelope`) and hands to
the starter's page as canonical JSON: the change, this site's enrollment,
the person, the key, a sequence number and the time. The page signs those
bytes as given; `check` takes them back and refuses unless they are
canonical, every field matches the change this host holds and its own
enrollment, the sequence is greater than the last this person approved here,
the time is at most ten minutes old, and the signature verifies with a key
pinned to that person. `typ` and `v` keep the signature from meaning
anything else.

**Held changes** (`Held`) are the changes waiting for that: kept in this
host's own directory for a day, at most 32, the same change asked twice held
once. **The sequence** (`Sequence`) is per person and only grows, so a
signature that was valid once is refused once something newer was approved.

Keys are Ed25519, or ECDSA P-256 for a browser without Ed25519 (WebCrypto's
`r||s` signature). A key's id is the first 16 bytes of SHA-256 over its raw
public key; one whose id does not match is no key.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import secrets
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

from ._private_files import write_private_text

TYPE = "eugene-plexus/site-edit"
VERSION = 1
CONFIRM = "rules.confirm"
#: How old a signed envelope may be: long enough to read the change.
FRESH_SECONDS = 600
#: How far ahead its time may be. The page and this host share a clock.
AHEAD_SECONDS = 60
HELD_SECONDS = 24 * 3600
MAX_HELD = 32
_RAW_LENGTH = {"Ed25519": 32, "ES256": 65}


class NotSigned(Exception):
    """A signed approval this site will not take; the message says why."""


def canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def key_id(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()[:32]


@dataclass(frozen=True)
class PersonKey:
    id: str
    alg: str
    public: bytes
    label: str | None = None


def parse_key(id_: str, alg: str, public_b64: str, label: str | None = None) -> PersonKey | None:
    """A pinned key, or None when it is malformed or its id is not its own."""
    try:
        raw = base64.b64decode(public_b64, validate=True)
    except (binascii.Error, ValueError):
        return None
    if _RAW_LENGTH.get(alg) != len(raw) or key_id(raw) != id_:
        return None
    try:
        _public(alg, raw)
    except ValueError:
        return None
    return PersonKey(id_, alg, raw, label)


def _public(alg: str, raw: bytes) -> Ed25519PublicKey | ec.EllipticCurvePublicKey:
    if alg == "Ed25519":
        return Ed25519PublicKey.from_public_bytes(raw)
    if alg == "ES256" and raw[:1] == b"\x04":
        return ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), raw)
    raise ValueError(alg)


def verify(key: PersonKey, message: bytes, signature: bytes) -> bool:
    if len(signature) != 64:
        return False
    try:
        public = _public(key.alg, key.public)
        if isinstance(public, Ed25519PublicKey):
            public.verify(signature, message)
        else:
            r = int.from_bytes(signature[:32], "big")
            s = int.from_bytes(signature[32:], "big")
            public.verify(encode_dss_signature(r, s), message, ec.ECDSA(hashes.SHA256()))
    except (InvalidSignature, ValueError):
        return False
    return True


def envelope(
    *,
    site: str,
    enrolled_at: str,
    person: str,
    key: str,
    act: str,
    args: dict[str, Any],
    seq: int,
    iat: int | None = None,
) -> str:
    """The canonical envelope a person's key signs."""
    return canonical(
        {
            "typ": TYPE,
            "v": VERSION,
            "site": site,
            "enrolledAt": enrolled_at,
            "person": person,
            "key": key,
            "act": act,
            "args": args,
            "seq": seq,
            "iat": int(time.time()) if iat is None else iat,
        }
    )


@dataclass(frozen=True)
class Checked:
    key: PersonKey
    seq: int


def check(
    text: str,
    signature_b64: str,
    *,
    site: str,
    enrolled_at: str,
    person: str,
    act: str,
    args: dict[str, Any],
    keys: dict[str, PersonKey],
    key: str,
    last_seq: int,
    now: float | None = None,
) -> Checked:
    """The approval, checked; raises `NotSigned` saying why it is refused."""
    found = keys.get(key)
    if found is None:
        raise NotSigned("That key is not one this person has here. Add it again at the machine.")
    try:
        signature = base64.b64decode(signature_b64, validate=True)
    except (binascii.Error, ValueError):
        raise NotSigned("The signature could not be read.") from None
    message = text.encode("utf-8")
    if not verify(found, message, signature):
        raise NotSigned("The signature does not match this change and this key.")
    try:
        value = json.loads(text)
    except ValueError:
        raise NotSigned("The signed change could not be read.") from None
    if not isinstance(value, dict) or canonical(value) != text:
        raise NotSigned("The signed change is not in the form this site wrote it.")
    expected = {
        "typ": TYPE,
        "v": VERSION,
        "site": site,
        "enrolledAt": enrolled_at,
        "person": person,
        "key": key,
        "act": act,
        "args": args,
    }
    if set(value) != {*expected, "seq", "iat"}:
        raise NotSigned("The signed change has the wrong fields.")
    for name, wanted in expected.items():
        if value[name] != wanted:
            raise NotSigned(f"The signed change is not this one ({name} differs).")
    seq, iat = value["seq"], value["iat"]
    if type(seq) is not int or type(iat) is not int:
        raise NotSigned("The signed change has the wrong fields.")
    if seq <= last_seq:
        raise NotSigned("This approval is older than one already used here. Open the page again.")
    moment = time.time() if now is None else now
    if not moment - FRESH_SECONDS <= iat <= moment + AHEAD_SECONDS:
        raise NotSigned("This approval is too old. Open the page again.")
    return Checked(found, seq)


# --- what is kept ---------------------------------------------------------------


def _load(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return {}
    except (OSError, ValueError):
        # Unreadable is empty: a held change is asked again, and a lost
        # sequence is the case the time check bounds.
        return {}
    return value if isinstance(value, dict) and value.get("version") == 1 else {}


@dataclass
class Held:
    id: str
    subject: str
    action: str
    arguments: dict[str, Any]
    names: dict[str, str] = field(default_factory=dict)
    held_at: float = field(default_factory=time.time)

    @property
    def expires_at(self) -> float:
        return self.held_at + HELD_SECONDS

    def as_json(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "subject": self.subject,
            "action": self.action,
            "arguments": self.arguments,
            "names": self.names,
            "heldAt": self.held_at,
        }


class Full(Exception):
    """Too many changes are held already."""


class HeldStore:
    """Changes waiting for their person's approval at the machine."""

    def __init__(self, directory: Path) -> None:
        self.path = directory / "held.json"
        self._lock = threading.Lock()

    def _read(self) -> list[Held]:
        now = time.time()
        items: list[Held] = []
        for raw in _load(self.path).get("items") or []:
            try:
                item = Held(
                    str(raw["id"]),
                    str(raw["subject"]),
                    str(raw["action"]),
                    dict(raw["arguments"]),
                    {str(k): str(v) for k, v in (raw.get("names") or {}).items()},
                    float(raw["heldAt"]),
                )
            except (KeyError, TypeError, ValueError):
                continue
            if item.expires_at > now:
                items.append(item)
        return items

    def _write(self, items: list[Held]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        write_private_text(
            self.path,
            json.dumps({"version": 1, "items": [i.as_json() for i in items]}, ensure_ascii=False),
        )

    def all(self) -> list[Held]:
        with self._lock:
            return self._read()

    def for_subject(self, subject: str) -> list[Held]:
        return [item for item in self.all() if item.subject == subject]

    def get(self, ident: str) -> Held | None:
        return next((item for item in self.all() if item.id == ident), None)

    def add(
        self, subject: str, action: str, arguments: dict[str, Any], names: dict[str, str]
    ) -> Held:
        """Hold a change; the same change from the same person is held once."""
        with self._lock:
            items = self._read()
            same = canonical(arguments)
            for item in items:
                if (
                    item.subject == subject
                    and item.action == action
                    and canonical(item.arguments) == same
                ):
                    item.names = {**item.names, **names}
                    self._write(items)
                    return item
            if len(items) >= MAX_HELD:
                raise Full(
                    f"{MAX_HELD} changes are already waiting for approval at the machine. "
                    "Approve or turn some down there first."
                )
            item = Held(secrets.token_hex(8), subject, action, arguments, names)
            self._write([*items, item])
            return item

    def remove(self, ident: str) -> Held | None:
        with self._lock:
            items = self._read()
            kept = [item for item in items if item.id != ident]
            if len(kept) == len(items):
                return None
            self._write(kept)
            return next(item for item in items if item.id == ident)

    def forget_subject(self, subject: str) -> None:
        with self._lock:
            items = self._read()
            kept = [item for item in items if item.subject != subject]
            if len(kept) != len(items):
                self._write(kept)


class Sequence:
    """The last sequence number each person approved with here."""

    def __init__(self, directory: Path) -> None:
        self.path = directory / "signatures.json"
        self._lock = threading.Lock()

    def last(self, subject: str) -> int:
        with self._lock:
            value = (_load(self.path).get("seq") or {}).get(subject)
        return value if type(value) is int and value > 0 else 0

    def accept(self, subject: str, seq: int) -> None:
        with self._lock:
            seqs = dict(_load(self.path).get("seq") or {})
            if seq <= int(seqs.get(subject) or 0):
                raise NotSigned("This approval is older than one already used here.")
            seqs[subject] = seq
            self.path.parent.mkdir(parents=True, exist_ok=True)
            write_private_text(self.path, json.dumps({"version": 1, "seq": seqs}))


def local_token(directory: Path) -> str:
    """The token the starter's page uses on this host's loopback API (J53),
    made once, in this host's own directory."""
    path = directory / "local_token"
    try:
        token = path.read_text(encoding="utf-8").strip()
    except FileNotFoundError:
        token = ""
    if len(token) < 32:
        token = secrets.token_urlsafe(32)
        directory.mkdir(parents=True, exist_ok=True)
        write_private_text(path, token)
    return token
