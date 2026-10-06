"""Joining: this machine becomes a Job Site of its own (J19, J23).

Run at the machine, with the person's password on standard input (rule 1 of
remote-nodes.md §3.3). In order:

1. Refuse if this directory already holds an enrollment.
2. Generate the site's Ed25519 token key, in memory.
3. Over HTTPS, pin the root before anything is sent (J7a): fetch its signed
   TLS key list over the very connection it will use, check the list against
   the identity key from the join command, and check the connection's key is
   on it. Over plain HTTP the root is on this machine's own network, as a
   node's is (J31); nothing is pinned.
4. Send the invitation, the key's public half and the person's sign-in to
   `POST /v1/sites/enroll`.
5. Record the key, then the enrollment. The owner comes from the root's
   answer, once (J6b).
"""

from __future__ import annotations

from typing import Any

import httpx
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ._http import client_for
from .identity import Enrollment, Identity, IdentityError, public_b64
from .root_link import Pins, RootTlsError, fetch_list, pinned_client


class JoinError(Exception):
    """The join did not happen; the message says why, in a sentence."""


def _problem(answer: httpx.Response) -> str:
    try:
        body: Any = answer.json()
        detail = body.get("detail") if isinstance(body, dict) else None
        if isinstance(detail, dict):
            detail = detail.get("detail") or detail.get("title")
        if isinstance(detail, str) and detail:
            return detail
    except ValueError:
        pass
    return f"the root answered {answer.status_code}"


async def join(
    identity: Identity,
    *,
    url: str,
    token: str,
    owner: str,
    password: str,
    label: str,
    root_key: str | None,
    host_version: str | None,
) -> Enrollment:
    try:
        existing = identity.load()
    except IdentityError:
        existing = None
    if existing is not None:
        raise JoinError(
            f"This machine is already {existing.ownerName}'s job site {existing.label}. "
            "Leave first to join again."
        )
    url = url.rstrip("/")
    if not url.startswith(("http://", "https://")):
        raise JoinError("The root's address starts with http:// or https://.")
    key = Ed25519PrivateKey.generate()
    if url.startswith("https://"):
        if not root_key:
            raise JoinError(
                "Over HTTPS this machine pins the root's identity key before it sends "
                "anything. The join command carries it (--root-key)."
            )
        pins = Pins(identity.pins_path)
        try:
            pins.adopt(await fetch_list(url, root_key))
        except RootTlsError as exc:
            raise JoinError(f"The root could not be trusted: {exc}") from None
        client = pinned_client(url, pins.accepts, timeout=30.0)
    else:
        client = client_for(url, timeout=30.0, follow_redirects=False)
    body = {
        "token": token,
        "label": label,
        "tokenPublicKey": public_b64(key),
        "owner": {"name": owner, "password": password},
        "hostVersion": host_version,
    }
    try:
        async with client:
            answer = await client.post(url + "/v1/sites/enroll", json=body)
    except httpx.HTTPError as exc:
        raise JoinError(f"The root at {url} could not be reached: {exc}") from None
    if answer.status_code != 201:
        raise JoinError(f"The join was refused: {_problem(answer)}")
    value = answer.json()
    granted = str(value.get("controlPublicKey") or "")
    if root_key and granted != root_key:
        raise JoinError(
            "The root that answered is not the one the join command named. Nothing was kept."
        )
    enrollment = Enrollment(
        site=str(value["id"]),
        label=str(value["label"]),
        owner=str(value["owner"]),
        ownerName=str(value.get("ownerName") or owner),
        url=url,
        rootKey=root_key or granted,
        enrolledAt=str(value["enrolledAt"]),
    )
    identity.record(key, enrollment)
    return enrollment
