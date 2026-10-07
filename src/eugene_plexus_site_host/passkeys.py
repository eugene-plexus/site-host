"""Passkeys from Workbench, pinned with a code shown at the machine (J14a.3).

Path B of `person-held-keys.md` (§4.2, §12.5). The owner may approve held
changes from Workbench, away from the machine, with a passkey: a key in their
own authenticator, which the root never holds. It is made in Workbench's
HTTPS origin, so its public half reaches this site through the root, which
could swap it. **The code** closes that: this host makes it (`Codes`), the
starter shows it at the machine (the loopback page, or the terminal on a
Linux system install), the person types it into Workbench, and Workbench
sends the public half with a MAC keyed by it (`binding`, `mac`). This host
pins the passkey only if the MAC checks. The code never crosses the root.

The code is ten characters of Crockford's base32 (50 bits), one per person at
a time, used once, gone after ten minutes or three pairings that do not
check. The MAC's key is PBKDF2 over it (600000 rounds), so a root that saw
the MAC cannot guess the code offline before it expires.

**What it does not close:** the code is typed into Workbench's page, whose
code the root's machine serves. A root that replaces Workbench's page at the
moment of pairing can pair its own key instead. Pinning a passkey is as
trustworthy as Workbench's page at that moment; afterwards each approval
needs the person's gesture, and the passkeys are listed and removed at the
machine (J45). The key at the machine (Path A) has no such window.

**An approval** is a WebAuthn assertion over SHA-256 of the same envelope the
loopback page signs (`signing.envelope`). `verify_assertion` checks it as
WebAuthn says: the client data is a `webauthn.get` with that challenge, from
an HTTPS origin under the passkey's pinned RP ID and not cross-origin; the
authenticator data carries that RP ID's hash, the person was present and
verified (UP, UV), and its sign count grows when the authenticator counts;
and the signature verifies with the pinned public key. Then `signing`'s
envelope checks run, unchanged.

Passkeys are kept in this host's own directory, never in the links file
(only the starter writes that). Each is bound to the link it was paired
under: removing the link, or linking the person again, leaves it unused.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import secrets
import threading
import time
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from ._private_files import write_private_text
from .signing import NotSigned, canonical

BINDING_TYPE = "eugene-plexus/site-passkey"
ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"  # Crockford's base32
CODE_LENGTH = 10
CODE_SECONDS = 600
CODE_TRIES = 3
ITERATIONS = 600_000
MAX_PER_PERSON = 8
EDDSA, ES256, RS256 = -8, -7, -257
ALGORITHMS = (EDDSA, ES256, RS256)
_UP, _UV = 0x01, 0x04


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _unb64url(text: str) -> bytes:
    if not isinstance(text, str) or not text or any(c in text for c in "+/="):
        raise ValueError("not base64url")
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def key_id(spki: bytes) -> str:
    """The id an envelope names: as `signing.key_id`, over the DER public key."""
    return hashlib.sha256(spki).hexdigest()[:32]


# --- the code ----------------------------------------------------------------------


def new_code() -> str:
    raw = "".join(secrets.choice(ALPHABET) for _ in range(CODE_LENGTH))
    return f"{raw[:5]}-{raw[5:]}"


def normalize(code: str) -> str:
    """As a person types it: any case, a dash or spaces, O for 0, I or L for 1."""
    cleaned = code.upper().replace("-", "").replace(" ", "")
    return cleaned.translate(str.maketrans("OIL", "011"))


def code_key(code: str, *, site: str, person: str) -> bytes:
    salt = f"{BINDING_TYPE}:{site}:{person}".encode()
    return hashlib.pbkdf2_hmac("sha256", normalize(code).encode("ascii"), salt, ITERATIONS, 32)


def binding(
    *, site: str, person: str, credential_id: str, public_key: str, alg: int, rp_id: str
) -> str:
    """The canonical object the pairing MAC covers (`SitePasskeyBinding`)."""
    return canonical(
        {
            "typ": BINDING_TYPE,
            "v": 1,
            "site": site,
            "person": person,
            "credentialId": credential_id,
            "publicKey": public_key,
            "alg": alg,
            "rpId": rp_id,
        }
    )


def mac(key: bytes, text: str) -> str:
    return _b64url(hmac.new(key, text.encode("utf-8"), hashlib.sha256).digest())


@dataclass
class _Code:
    code: str  # normalized
    expires_at: float
    tries: int = CODE_TRIES


class Codes:
    """The codes waiting at the machine, one per person, in memory: a host
    that restarts forgets them, and the person asks for a new one."""

    def __init__(self) -> None:
        self._codes: dict[str, _Code] = {}
        self._lock = threading.Lock()

    def make(self, subject: str, now: float | None = None) -> tuple[str, float]:
        code = new_code()
        expires = (time.time() if now is None else now) + CODE_SECONDS
        with self._lock:
            self._codes[subject] = _Code(normalize(code), expires)
        return code, expires

    def waiting(self, subject: str, now: float | None = None) -> float | None:
        moment = time.time() if now is None else now
        with self._lock:
            found = self._codes.get(subject)
            if found is None or found.expires_at <= moment:
                self._codes.pop(subject, None)
                return None
            return found.expires_at

    def check(self, subject: str, *, site: str, text: str, given: str) -> None:
        """Spend the code if `given` is the MAC over `text` keyed by it;
        raises `NotSigned` saying why not. Three wrong ones void it."""
        with self._lock:
            found = self._codes.get(subject)
            if found is None or found.expires_at <= time.time():
                self._codes.pop(subject, None)
                raise NotSigned(
                    "No code is waiting for you at the machine, or it has expired. "
                    "Make a new one there."
                )
            code = found.code
        # The slow part, outside the lock: the key is PBKDF2 over the code.
        wanted = mac(code_key(code, site=site, person=subject), text)
        with self._lock:
            current = self._codes.get(subject)
            if current is None or current.code != code:
                raise NotSigned("That code was replaced or used. Make a new one at the machine.")
            if not hmac.compare_digest(wanted, given):
                current.tries -= 1
                if current.tries <= 0:
                    self._codes.pop(subject, None)
                    raise NotSigned(
                        "That code did not match three times, so it is gone. "
                        "Make a new one at the machine."
                    )
                raise NotSigned(
                    "The code does not match the one shown at the machine, or the passkey "
                    "was changed on its way here."
                )
            self._codes.pop(subject, None)


# --- the public key ------------------------------------------------------------------


def load_public(alg: int, spki: bytes) -> Any:
    """The public key, if it is one `alg` can verify with; else ValueError."""
    try:
        key = serialization.load_der_public_key(spki)
    except (ValueError, UnsupportedAlgorithm):
        raise ValueError("not a public key") from None
    if alg == EDDSA and isinstance(key, Ed25519PublicKey):
        return key
    if (
        alg == ES256
        and isinstance(key, ec.EllipticCurvePublicKey)
        and isinstance(key.curve, ec.SECP256R1)
    ):
        return key
    if alg == RS256 and isinstance(key, rsa.RSAPublicKey) and key.key_size >= 2048:
        return key
    raise ValueError("not a key of that algorithm")


def _verify(alg: int, spki: bytes, signature: bytes, message: bytes) -> bool:
    try:
        key = load_public(alg, spki)
        if alg == EDDSA:
            key.verify(signature, message)
        elif alg == ES256:
            key.verify(signature, message, ec.ECDSA(hashes.SHA256()))
        else:
            key.verify(signature, message, padding.PKCS1v15(), hashes.SHA256())
    except (InvalidSignature, ValueError):
        return False
    return True


# --- what is kept ----------------------------------------------------------------------


@dataclass(frozen=True)
class Passkey:
    subject: str
    id: str
    credential_id: str
    alg: int
    public: bytes
    rp_id: str
    label: str
    added_at: str
    #: The link it was paired under: the account and when it was made.
    account: str
    linked_at: str
    sign_count: int = 0

    def view(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "credentialId": self.credential_id,
            "alg": self.alg,
            "rpId": self.rp_id,
            "label": self.label,
            "addedAt": self.added_at,
        }

    def as_json(self) -> dict[str, Any]:
        return {
            **self.view(),
            "subject": self.subject,
            "publicKey": base64.b64encode(self.public).decode("ascii"),
            "account": self.account,
            "linkedAt": self.linked_at,
            "signCount": self.sign_count,
        }


def _parse(raw: Any) -> Passkey | None:
    try:
        public = base64.b64decode(raw["publicKey"], validate=True)
        item = Passkey(
            subject=str(raw["subject"]),
            id=str(raw["id"]),
            credential_id=str(raw["credentialId"]),
            alg=int(raw["alg"]),
            public=public,
            rp_id=str(raw["rpId"]),
            label=str(raw.get("label") or ""),
            added_at=str(raw["addedAt"]),
            account=str(raw["account"]),
            linked_at=str(raw["linkedAt"]),
            sign_count=int(raw.get("signCount") or 0),
        )
        load_public(item.alg, item.public)
    except (KeyError, TypeError, ValueError, binascii.Error):
        return None
    # A passkey whose id is not its own is no passkey.
    return item if key_id(item.public) == item.id else None


class PasskeyStore:
    """The passkeys pinned here, in this host's own directory."""

    def __init__(self, directory: Path) -> None:
        self.path = directory / "passkeys.json"
        self._lock = threading.Lock()

    def _read(self) -> list[Passkey]:
        try:
            value = json.loads(self.path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return []
        except (OSError, ValueError):
            # Unreadable is none: the owner pairs again at the machine.
            return []
        if not isinstance(value, dict) or value.get("version") != 1:
            return []
        return [p for p in (_parse(raw) for raw in value.get("items") or []) if p is not None]

    def _write(self, items: list[Passkey]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        write_private_text(
            self.path,
            json.dumps({"version": 1, "items": [p.as_json() for p in items]}, ensure_ascii=False),
        )

    def for_subject(self, subject: str) -> list[Passkey]:
        with self._lock:
            return [p for p in self._read() if p.subject == subject]

    def add(self, passkey: Passkey) -> Passkey:
        with self._lock:
            items = self._read()
            mine = [p for p in items if p.subject == passkey.subject]
            if any(p.id == passkey.id or p.credential_id == passkey.credential_id for p in mine):
                raise NotSigned("That passkey is already pinned here.")
            if len(mine) >= MAX_PER_PERSON:
                raise NotSigned(
                    f"{MAX_PER_PERSON} passkeys are pinned to you here already. "
                    "Remove one at the machine first."
                )
            self._write([*items, passkey])
            return passkey

    def remove(self, subject: str, ident: str) -> bool:
        with self._lock:
            items = self._read()
            kept = [p for p in items if not (p.subject == subject and p.id == ident)]
            if len(kept) == len(items):
                return False
            self._write(kept)
            return True

    def counted(self, ident: str, count: int) -> None:
        """Record the sign count an accepted assertion carried."""
        with self._lock:
            items = self._read()
            self._write([replace(p, sign_count=count) if p.id == ident else p for p in items])


def pair(
    *,
    subject: str,
    site: str,
    account: str,
    linked_at: str,
    credential_id: str,
    public_key: str,
    alg: int,
    rp_id: str,
    label: str | None,
) -> Passkey:
    """The passkey a pairing names, once its parts are known to be well
    formed. The MAC is checked by `Codes.check` before this is kept."""
    if alg not in ALGORITHMS:
        raise NotSigned("That passkey uses an algorithm this site does not take.")
    try:
        public = base64.b64decode(public_key, validate=True)
        _unb64url(credential_id)
        load_public(alg, public)
    except (binascii.Error, ValueError):
        raise NotSigned("That passkey could not be read.") from None
    host = rp_id.strip().lower()
    if not host or host != rp_id or "/" in host or ":" in host or host.replace(".", "") == "":
        raise NotSigned("That passkey names no Workbench address this site can check.")
    return Passkey(
        subject=subject,
        id=key_id(public),
        credential_id=credential_id,
        alg=alg,
        public=public,
        rp_id=rp_id,
        label=(label or "A passkey from Workbench").strip()[:128],
        added_at=datetime.now(UTC).isoformat(timespec="seconds"),
        account=account,
        linked_at=linked_at,
    )


# --- an approval ---------------------------------------------------------------------


def challenge(envelope_text: str) -> str:
    """The WebAuthn challenge for an envelope: SHA-256 of its UTF-8 bytes."""
    return _b64url(hashlib.sha256(envelope_text.encode("utf-8")).digest())


def verify_assertion(
    passkey: Passkey,
    envelope_text: str,
    *,
    credential_id: str,
    authenticator_data: str,
    client_data_json: str,
    signature: str,
) -> int:
    """The assertion, checked; the sign count it carried. Raises `NotSigned`."""
    if credential_id != passkey.credential_id:
        raise NotSigned("That passkey is not the one this key names.")
    try:
        auth = _unb64url(authenticator_data)
        client = _unb64url(client_data_json)
        sig = _unb64url(signature)
        data = json.loads(client.decode("utf-8"))
    except (ValueError, UnicodeDecodeError, binascii.Error):
        raise NotSigned("The passkey's answer could not be read.") from None
    if not isinstance(data, dict) or data.get("type") != "webauthn.get":
        raise NotSigned("The passkey's answer is not an approval.")
    if not hmac.compare_digest(str(data.get("challenge") or ""), challenge(envelope_text)):
        raise NotSigned("The passkey signed something other than this change.")
    if data.get("crossOrigin") not in (None, False) or "topOrigin" in data:
        raise NotSigned("The passkey was used from inside another site's page.")
    origin = urlsplit(str(data.get("origin") or ""))
    host = (origin.hostname or "").lower()
    if origin.scheme != "https" or not (
        host == passkey.rp_id or host.endswith("." + passkey.rp_id)
    ):
        raise NotSigned("The passkey was used from an address it was not made for.")
    if len(auth) < 37 or not hmac.compare_digest(
        auth[:32], hashlib.sha256(passkey.rp_id.encode("ascii")).digest()
    ):
        raise NotSigned("The passkey's answer is for another address.")
    flags = auth[32]
    if not flags & _UP or not flags & _UV:
        raise NotSigned(
            "The passkey did not check that it was you (a fingerprint, face or PIN). "
            "Approve again, and confirm it on the device."
        )
    count = int.from_bytes(auth[33:37], "big")
    if not _verify(passkey.alg, passkey.public, sig, auth + hashlib.sha256(client).digest()):
        raise NotSigned("The passkey's signature does not match this change.")
    if (count or passkey.sign_count) and count <= passkey.sign_count:
        raise NotSigned(
            "This passkey's counter went backwards, which a copied passkey does. "
            "Remove it at the machine and pair it again."
        )
    return count
