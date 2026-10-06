"""This site's own enrollment (J19, J23): who it is, which root it belongs to,
and the key it signs its tokens with.

A Job Site is its own enrollment, held here and by nothing else. On a machine
that is also a node the agent starts this program; it holds none of what is
in this directory and relays nothing for it. Everything lives in the site's
data directory (`EUGENE_PLEXUS_APP_DATA_DIR`):

- `site.json`: the enrollment as the root answered it, recorded **once** at
  the join. Its `owner` is the only person whose management actions this
  site takes (J6b); no later answer from the root changes it.
- `site_key.pem`: the Ed25519 token key, generated here at the join. Only
  its public half ever left the machine.
- `root_tls.json`: the root's TLS keys this site accepts (J7a), when the
  root is reached over HTTPS.

A site token is EdDSA, `iss: site:<id>`, `sub: site`, `aud: control`, at
most five minutes long (`siteToken`, control.yaml). The root checks it
against its site registry, never a trust bundle.
"""

from __future__ import annotations

import base64
import json
import secrets
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from ._private_files import write_private_text

ENROLLMENT_FILE = "site.json"
KEY_FILE = "site_key.pem"
PINS_FILE = "root_tls.json"
TOKEN_SECONDS = 240
AUDIENCE = "control"


class IdentityError(Exception):
    """This site's enrollment on disk is missing or unusable; the message says which."""


@dataclass(frozen=True)
class Enrollment:
    site: str
    label: str
    owner: str
    ownerName: str
    url: str
    """The root's address, as the join command gave it."""
    rootKey: str
    """Base64 of the root's raw Ed25519 identity key: pinned from the join
    command when the root is reached over HTTPS (J7a), else as the root
    answered the join."""
    enrolledAt: str

    @property
    def pinned(self) -> bool:
        return self.url.startswith("https://")


def public_b64(key: Ed25519PrivateKey | Ed25519PublicKey) -> str:  # gitleaks:allow
    public = key.public_key() if isinstance(key, Ed25519PrivateKey) else key
    raw = public.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return base64.b64encode(raw).decode("ascii")


def load_public(value: str) -> Ed25519PublicKey:
    raw = base64.b64decode(value, validate=True)
    if len(raw) != 32:
        raise ValueError("an Ed25519 public key is 32 bytes")
    return Ed25519PublicKey.from_public_bytes(raw)


class Identity:
    """The files in this site's data directory that make it a site."""

    def __init__(self, data_dir: Path) -> None:
        self.data_dir = data_dir
        self._cached: tuple[float, Enrollment | None] | None = None
        self._key: Ed25519PrivateKey | None = None  # gitleaks:allow

    @property
    def pins_path(self) -> Path:
        return self.data_dir / PINS_FILE

    def load(self) -> Enrollment | None:
        """The enrollment, or None before the join. Re-read when the file changes."""
        path = self.data_dir / ENROLLMENT_FILE
        try:
            stamp = path.stat().st_mtime
        except FileNotFoundError:
            self._cached = None
            return None
        if self._cached is not None and self._cached[0] == stamp:
            return self._cached[1]
        try:
            raw: dict[str, Any] = json.loads(path.read_text(encoding="utf-8"))
            enrollment = Enrollment(**{k: str(raw[k]) for k in Enrollment.__dataclass_fields__})
        except (OSError, ValueError, KeyError, TypeError) as exc:
            raise IdentityError(f"this site's enrollment file is unreadable: {exc}") from None
        self._cached = (stamp, enrollment)
        self._key = None
        return enrollment

    def owner(self) -> str | None:
        try:
            enrollment = self.load()
        except IdentityError:
            return None
        return enrollment.owner if enrollment else None

    def key(self) -> Ed25519PrivateKey:
        if self._key is None:
            try:
                pem = (self.data_dir / KEY_FILE).read_bytes()
                loaded = serialization.load_pem_private_key(pem, password=None)
            except (OSError, ValueError) as exc:
                raise IdentityError(f"this site's key is unreadable: {exc}") from None
            if not isinstance(loaded, Ed25519PrivateKey):
                raise IdentityError("this site's key is not an Ed25519 key")
            self._key = loaded
        return self._key

    def record(self, key: Ed25519PrivateKey, enrollment: Enrollment) -> None:
        """Write the key, then the enrollment: a site with an enrollment file
        always has its key."""
        self.data_dir.mkdir(parents=True, exist_ok=True)
        pem = key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ).decode("ascii")
        write_private_text(self.data_dir / KEY_FILE, pem)
        write_private_text(self.data_dir / ENROLLMENT_FILE, json.dumps(asdict(enrollment)))
        self._cached = None
        self._key = key

    def forget(self) -> None:
        """Leave: the enrollment, the key and the pins go. The policy and the
        audit log stay; they are the owner's, and a site joined again by the
        same person reads them."""
        for name in (ENROLLMENT_FILE, KEY_FILE, PINS_FILE):
            (self.data_dir / name).unlink(missing_ok=True)
        self._cached = None
        self._key = None

    def token(self, enrollment: Enrollment) -> str:
        now = int(time.time())
        return jwt.encode(
            {
                "iss": f"site:{enrollment.site}",
                "sub": "site",
                "aud": AUDIENCE,
                "iat": now,
                "exp": now + TOKEN_SECONDS,
                "jti": secrets.token_urlsafe(12),
            },
            self.key(),
            algorithm="EdDSA",
        )
