"""Passkeys from Workbench, pinned with a code shown at the machine (J14a.3).

The done-when of `person-held-keys.md` §9 for Path B: a passkey paired with
the machine's code approves a held change from Workbench, through the root;
a root that swaps the public key on its way is caught by the MAC; a replayed
approval is refused; and every way an assertion can be wrong is refused for
its own reason. The authenticator here is software, answering exactly as a
browser's does (`authenticatorData || SHA-256(clientDataJSON)`, signed);
`j14a3-browser-check.py` drives a real browser's.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import time
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

from eugene_plexus_site_host import local_channel
from eugene_plexus_site_host import passkeys as pk
from eugene_plexus_site_host.app import create_app
from eugene_plexus_site_host.host import RULES, NotHeld

from .conftest import (
    ADA,
    BO,
    ENROLLMENT,
    OTHER_ACCOUNT,
    OpenSite,
    Site,
    link_entry,
    settings_for,
    write_links,
)

RP = "workbench.example"
ORIGIN = f"https://{RP}"
FILES = "files"


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


@pytest.fixture(autouse=True)
def quick_codes(monkeypatch: pytest.MonkeyPatch) -> None:
    """PBKDF2 at a thousand rounds for speed; one test checks the real count."""
    monkeypatch.setattr(pk, "ITERATIONS", 1000)


class Authenticator:
    """A passkey as a browser's authenticator holds it, made for one RP ID."""

    def __init__(self, alg: int = pk.ES256, *, counting: bool = False) -> None:
        self.alg = alg
        if alg == pk.ES256:
            self.private: Any = ec.generate_private_key(ec.SECP256R1())
        elif alg == pk.EDDSA:
            self.private = Ed25519PrivateKey.generate()
        else:
            self.private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.spki = self.private.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        )
        self.id = pk.key_id(self.spki)
        self.credential_id = b64url(secrets.token_bytes(16))
        self.counting = counting
        self.count = 0

    @property
    def public(self) -> str:
        return base64.b64encode(self.spki).decode()

    def pairing(self, code: str, *, person: str = ADA, **override: Any) -> dict[str, Any]:
        """What Workbench sends: the public half and the MAC over it."""
        values = {
            "credentialId": self.credential_id,
            "publicKey": self.public,
            "alg": self.alg,
            "rpId": RP,
            "label": "Chrome on laptop",
        }
        bound = {**values, **{k: v for k, v in override.items() if k != "mac"}}
        text = pk.binding(
            site=ENROLLMENT.site,
            person=person,
            credential_id=bound["credentialId"],
            public_key=bound["publicKey"],
            alg=bound["alg"],
            rp_id=bound["rpId"],
        )
        mac = override.get("mac") or pk.mac(
            pk.code_key(code, site=ENROLLMENT.site, person=person), text
        )
        return {**bound, "mac": mac}

    def sign(self, message: bytes) -> bytes:
        if self.alg == pk.ES256:
            return bytes(self.private.sign(message, ec.ECDSA(hashes.SHA256())))
        if self.alg == pk.EDDSA:
            return bytes(self.private.sign(message))
        return bytes(self.private.sign(message, padding.PKCS1v15(), hashes.SHA256()))

    def approve(self, ident: str, envelope: str, **change: Any) -> dict[str, Any]:
        """`navigator.credentials.get()` over the envelope, as Workbench sends it."""
        if self.counting:
            self.count += 1
        client: dict[str, Any] = {
            "type": change.get("type", "webauthn.get"),
            "challenge": change.get("challenge", pk.challenge(envelope)),
            "origin": change.get("origin", ORIGIN),
            "crossOrigin": change.get("crossOrigin", False),
        }
        client_bytes = json.dumps(client).encode()
        flags = change.get("flags", 0x01 | 0x04)
        count = change.get("count", self.count)
        rp = change.get("rp", RP)
        auth = hashlib.sha256(rp.encode()).digest() + bytes([flags]) + count.to_bytes(4, "big")
        signer = change.get("signer", self)
        signature = signer.sign(auth + hashlib.sha256(client_bytes).digest())
        return {
            "id": ident,
            "envelope": envelope,
            "key": self.id,
            "credentialId": change.get("credentialId", self.credential_id),
            "authenticatorData": b64url(auth),
            "clientDataJSON": b64url(client_bytes),
            "signature": b64url(signature),
        }


async def paired(site: Site, passkey: Authenticator) -> dict[str, Any]:
    code = site.host.passkey_code(ADA)["code"]
    return await site.manage(ADA, "passkey.pair", **passkey.pairing(code))


async def listed(site: Site, passkey: Authenticator) -> dict[str, Any]:
    answer = await site.manage(ADA, "held.list", key=passkey.id)
    assert answer["status"] == "done", answer
    return dict(answer["result"])


async def approve(site: Site, passkey: Authenticator, ident: str, **change: Any) -> dict[str, Any]:
    items = (await listed(site, passkey))["items"]
    item = next(i for i in items if i["id"] == ident)
    return await site.manage(
        ADA, "held.approve", **passkey.approve(ident, item["envelope"], **change)
    )


@pytest.fixture
async def bare(open_site: OpenSite) -> Site:
    """A site whose owner has no key at the machine: a Linux system install's."""
    return await open_site(signed=False)


def names(site: Site) -> list[str]:
    return [f["name"] for f in site.host.policy.folders]


async def with_rules(site: Site, folder: Path) -> None:
    """A rule made before any key, on the root's word (an unsigned site)."""
    made = await site.manage(ADA, "folder.add", name="Notes", path=str(folder))
    assert made["status"] == "done", made


def other_folder(tmp_path: Path, name: str = "other") -> Path:
    where = tmp_path / name
    where.mkdir(exist_ok=True)
    return where


# --- pairing ---------------------------------------------------------------------------


@pytest.mark.parametrize("alg", [pk.ES256, pk.EDDSA, pk.RS256], ids=["ES256", "EdDSA", "RS256"])
async def test_a_paired_passkey_approves_the_rules_and_a_held_change(
    bare: Site, folder: Path, tmp_path: Path, alg: int
) -> None:
    passkey = Authenticator(alg)
    await with_rules(bare, folder)
    assert bare.host.signing_state() == "unsigned"
    answer = await paired(bare, passkey)
    assert answer["status"] == "done", answer
    assert answer["result"]["id"] == passkey.id and answer["result"]["rpId"] == RP
    assert bare.host.signing_state() == "unconfirmed"
    # Nothing runs until the rules are approved with it (J52).
    assert (await approve(bare, passkey, RULES))["status"] == "done"
    assert bare.host.signing_state() == "signed"
    other = other_folder(tmp_path)
    added = await bare.manage(ADA, "folder.add", name="Other", path=str(other), approve=False)
    assert added["status"] == "held"
    ident = bare.host.held.for_subject(ADA)[0].id
    done = await approve(bare, passkey, ident)
    assert done["status"] == "done", done
    assert names(bare) == ["Notes", "Other"]
    reasons = [e.get("reason") or "" for e in bare.host.audit.newest(10)]
    assert any(r.startswith("Approved from Workbench with passkey") for r in reasons)
    assert any("paired from Workbench" in r for r in reasons)


async def test_a_root_that_swaps_the_key_is_caught_by_the_mac(bare: Site) -> None:
    real, swapped = Authenticator(), Authenticator()
    code = bare.host.passkey_code(ADA)["code"]
    honest = real.pairing(code)
    forged = {**honest, "publicKey": swapped.public, "credentialId": swapped.credential_id}
    answer = await bare.manage(ADA, "passkey.pair", **forged)
    assert answer["status"] == "failed" and "does not match" in answer["message"]
    assert bare.host.passkeys_of(ADA) == []
    # The code still works for the real key: a forgery spent one of three tries.
    assert (await bare.manage(ADA, "passkey.pair", **honest))["status"] == "done"
    assert [p.id for p in bare.host.passkeys_of(ADA)] == [real.id]


async def test_three_wrong_pairings_end_the_code(bare: Site) -> None:
    passkey = Authenticator()
    code = bare.host.passkey_code(ADA)["code"]
    wrong = passkey.pairing("AAAAA-AAAAA")
    for _ in range(2):
        refused = await bare.manage(ADA, "passkey.pair", **wrong)
        assert "does not match" in refused["message"]
    third = await bare.manage(ADA, "passkey.pair", **wrong)
    assert "three times" in third["message"]
    late = await bare.manage(ADA, "passkey.pair", **passkey.pairing(code))
    assert late["status"] == "failed" and "No code is waiting" in late["message"]


async def test_a_code_works_once_and_a_new_one_replaces_it(bare: Site) -> None:
    first, second = Authenticator(), Authenticator()
    old = bare.host.passkey_code(ADA)["code"]
    new = bare.host.passkey_code(ADA)["code"]
    replaced = await bare.manage(ADA, "passkey.pair", **first.pairing(old))
    assert replaced["status"] == "failed"
    assert (await bare.manage(ADA, "passkey.pair", **first.pairing(new)))["status"] == "done"
    again = await bare.manage(ADA, "passkey.pair", **second.pairing(new))
    assert again["status"] == "failed" and "No code is waiting" in again["message"]


async def test_a_code_expires(bare: Site, monkeypatch: pytest.MonkeyPatch) -> None:
    passkey = Authenticator()
    code = bare.host.passkey_code(ADA)["code"]
    now = time.time()
    monkeypatch.setattr(pk.time, "time", lambda: now + pk.CODE_SECONDS + 1)
    late = await bare.manage(ADA, "passkey.pair", **passkey.pairing(code))
    assert late["status"] == "failed" and "expired" in late["message"]


def test_a_code_is_typed_as_people_type() -> None:
    code = pk.new_code()
    assert len(code) == 11 and code[5] == "-"
    assert set(code.replace("-", "")) <= set(pk.ALPHABET)
    assert pk.normalize(" abcde-fghjk ") == "ABCDEFGHJK"
    # Crockford's reading of the letters people mistake for digits.
    assert pk.normalize("o1i1l") == "01111"


def test_the_mac_key_is_pbkdf2_as_the_contract_says(monkeypatch: pytest.MonkeyPatch) -> None:
    """Workbench computes the same key in the browser: the parameters are
    the contract's (`SitePasskeyBinding`), checked against hashlib itself."""
    monkeypatch.setattr(pk, "ITERATIONS", 600_000)
    key = pk.code_key("ab cde-fghjk", site="s-1", person="p-1")
    wanted = hashlib.pbkdf2_hmac(
        "sha256", b"ABCDEFGHJK", b"eugene-plexus/site-passkey:s-1:p-1", 600_000, 32
    )
    assert key == wanted
    text = pk.binding(
        site="s-1", person="p-1", credential_id="cid", public_key="pub", alg=-7, rp_id="w.x"
    )
    assert text == (
        '{"alg":-7,"credentialId":"cid","person":"p-1","publicKey":"pub","rpId":"w.x",'
        '"site":"s-1","typ":"eugene-plexus/site-passkey","v":1}'
    )
    digest = hmac.new(wanted, text.encode(), hashlib.sha256).digest()
    assert pk.mac(key, text) == b64url(digest)


async def test_only_the_owner_gets_a_code(open_site: OpenSite, tmp_path: Path) -> None:
    site = await open_site(signed=False)
    links = site.host.settings.links_file
    assert links is not None
    write_links(
        links,
        link_entry(ADA, local_channel.own_account(), "ada"),
        link_entry(BO, OTHER_ACCOUNT, "bo"),
    )
    _touch(links)
    with pytest.raises(NotHeld):
        site.host.passkey_code(BO)
    with pytest.raises(NotHeld):
        site.host.passkey_code("person-nobody")
    assert site.host.passkey_code(ADA)["subject"] == ADA


async def test_a_malformed_passkey_is_refused_before_the_code_is_spent(bare: Site) -> None:
    passkey = Authenticator()
    code = bare.host.passkey_code(ADA)["code"]
    rsa_small = rsa.generate_private_key(public_exponent=65537, key_size=1024)
    weak = base64.b64encode(
        rsa_small.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        )
    ).decode()
    for bad in (
        {"publicKey": "bm90IGEga2V5"},
        {"publicKey": passkey.public, "alg": pk.EDDSA},  # an ES256 key named EdDSA
        {"publicKey": weak, "alg": pk.RS256},
        {"rpId": "https://workbench.example"},
    ):
        refused = await bare.manage(ADA, "passkey.pair", **passkey.pairing(code, **bad))
        assert refused["status"] == "failed", bad
    # None of them spent a try: the real one still pairs.
    assert (await bare.manage(ADA, "passkey.pair", **passkey.pairing(code)))["status"] == "done"


async def test_the_same_passkey_is_pinned_once_and_at_most_eight(bare: Site) -> None:
    first = Authenticator()
    assert (await paired(bare, first))["status"] == "done"
    twice = await paired(bare, first)
    assert twice["status"] == "failed" and "already pinned" in twice["message"]
    for _ in range(pk.MAX_PER_PERSON - 1):
        assert (await paired(bare, Authenticator()))["status"] == "done"
    full = await paired(bare, Authenticator())
    assert full["status"] == "failed" and "Remove one at the machine" in full["message"]


async def test_pairing_is_recorded_without_the_mac(bare: Site) -> None:
    passkey = Authenticator()
    code = bare.host.passkey_code(ADA)["code"]
    sent = passkey.pairing(code)
    await bare.manage(ADA, "passkey.pair", **sent)
    raw = bare.host.audit.path.read_text(encoding="utf-8")
    assert sent["mac"] not in raw and code not in raw and passkey.public not in raw


# --- an approval -------------------------------------------------------------------------


@pytest.fixture
async def ready(bare: Site, folder: Path, tmp_path: Path) -> tuple[Site, Authenticator, str]:
    """A site whose owner paired a passkey and approved its rules with it,
    and one change held for them: the folder `Other`."""
    passkey = Authenticator(counting=True)
    await with_rules(bare, folder)
    assert (await paired(bare, passkey))["status"] == "done"
    assert (await approve(bare, passkey, RULES))["status"] == "done"
    other = other_folder(tmp_path)
    held = await bare.manage(ADA, "folder.add", name="Other", path=str(other), approve=False)
    assert held["status"] == "held", held
    return bare, passkey, bare.host.held.for_subject(ADA)[0].id


@pytest.mark.parametrize(
    ("change", "says"),
    [
        ({"type": "webauthn.create"}, "not an approval"),
        ({"challenge": b64url(b"x" * 32)}, "something other than this change"),
        ({"origin": "http://workbench.example"}, "address it was not made for"),
        ({"origin": "https://evil.example"}, "address it was not made for"),
        ({"origin": "https://notworkbench.example"}, "address it was not made for"),
        ({"crossOrigin": True}, "inside another site's page"),
        ({"rp": "evil.example"}, "for another address"),
        ({"flags": 0x01}, "did not check that it was you"),
        ({"flags": 0x04}, "did not check that it was you"),
        ({"signer": Authenticator()}, "signature does not match"),
        ({"credentialId": b64url(b"another")}, "not the one this key names"),
    ],
    ids=[
        "create",
        "challenge",
        "http",
        "other-origin",
        "suffix-not-subdomain",
        "cross-origin",
        "rp-hash",
        "no-uv",
        "no-up",
        "other-key",
        "credential",
    ],
)
async def test_every_wrong_assertion_is_refused_for_its_reason(
    ready: tuple[Site, Authenticator, str], change: dict[str, Any], says: str
) -> None:
    site, passkey, ident = ready
    refused = await approve(site, passkey, ident, **change)
    assert refused["status"] == "failed" and says in refused["message"], refused
    assert names(site) == ["Notes"] and site.host.held.get(ident) is not None


async def test_a_subdomain_of_the_rp_id_may_use_it(ready: tuple[Site, Authenticator, str]) -> None:
    site, passkey, ident = ready
    done = await approve(site, passkey, ident, origin=f"https://app.{RP}:8443")
    assert done["status"] == "done", done


async def test_a_counter_that_goes_back_is_refused(ready: tuple[Site, Authenticator, str]) -> None:
    site, passkey, ident = ready
    refused = await approve(site, passkey, ident, count=1)
    assert refused["status"] == "failed" and "went backwards" in refused["message"]


async def test_a_passkey_that_does_not_count_is_taken(
    bare: Site, folder: Path, tmp_path: Path
) -> None:
    """Synced passkeys answer 0 every time; that is not a copy."""
    passkey = Authenticator(counting=False)
    await with_rules(bare, folder)
    await paired(bare, passkey)
    assert (await approve(bare, passkey, RULES))["status"] == "done"
    other = other_folder(tmp_path)
    await bare.manage(ADA, "folder.add", name="Other", path=str(other), approve=False)
    ident = bare.host.held.for_subject(ADA)[0].id
    assert (await approve(bare, passkey, ident))["status"] == "done"


async def test_a_used_passkey_approval_cannot_be_replayed(
    ready: tuple[Site, Authenticator, str], tmp_path: Path
) -> None:
    site, passkey, ident = ready
    items = (await listed(site, passkey))["items"]
    envelope = next(i for i in items if i["id"] == ident)["envelope"]
    signed = passkey.approve(ident, envelope)
    assert (await site.manage(ADA, "held.approve", **signed))["status"] == "done"
    third = other_folder(tmp_path, "third")
    await site.manage(ADA, "folder.add", name="Third", path=str(third), approve=False)
    again = site.host.held.for_subject(ADA)[0].id
    replayed = await site.manage(ADA, "held.approve", **{**signed, "id": again})
    assert replayed["status"] == "failed"
    assert names(site) == ["Notes", "Other"]


async def test_an_old_passkey_approval_of_the_same_change_is_spent(
    bare: Site, folder: Path, tmp_path: Path
) -> None:
    """The envelope names the change, not the hold. After the owner removes a
    folder they approved, a root that holds the same folder again and sends
    the old approval is refused by the sequence alone: a synced passkey's
    count stays 0, so the counter cannot."""
    passkey = Authenticator(counting=False)
    await with_rules(bare, folder)
    await paired(bare, passkey)
    assert (await approve(bare, passkey, RULES))["status"] == "done"
    other = other_folder(tmp_path)
    await bare.manage(ADA, "folder.add", name="Other", path=str(other), approve=False)
    first = bare.host.held.for_subject(ADA)[0].id
    items = (await listed(bare, passkey))["items"]
    signed = passkey.approve(first, next(i for i in items if i["id"] == first)["envelope"])
    assert (await bare.manage(ADA, "held.approve", **signed))["status"] == "done"
    gone = next(f["id"] for f in bare.host.policy.folders if f["name"] == "Other")
    assert (await bare.manage(ADA, "folder.remove", id=gone))["status"] == "done"
    await bare.manage(ADA, "folder.add", name="Other", path=str(other), approve=False)
    again = bare.host.held.for_subject(ADA)[0].id
    replayed = await bare.manage(ADA, "held.approve", **{**signed, "id": again})
    assert replayed["status"] == "failed", replayed
    assert "older than one already used" in replayed["message"]
    assert names(bare) == ["Notes"]


async def test_the_envelope_signed_must_be_this_change(
    ready: tuple[Site, Authenticator, str], tmp_path: Path
) -> None:
    site, passkey, ident = ready
    third = other_folder(tmp_path, "third")
    await site.manage(ADA, "folder.add", name="Third", path=str(third), approve=False)
    items = (await listed(site, passkey))["items"]
    second = next(i for i in items if i["id"] != ident)
    # A valid assertion over the other held change's envelope, sent for this one.
    swapped = passkey.approve(ident, second["envelope"])
    refused = await site.manage(ADA, "held.approve", **swapped)
    assert refused["status"] == "failed" and "differs" in refused["message"]


async def test_a_passkey_from_an_earlier_link_approves_nothing(
    ready: tuple[Site, Authenticator, str],
) -> None:
    site, passkey, _ident = ready
    links = site.host.settings.links_file
    assert links is not None
    relinked = {**link_entry(ADA, local_channel.own_account(), "ada"), "linkedAt": _later()}
    write_links(links, relinked)
    _touch(links)
    assert site.host.passkeys_of(ADA) == []
    assert site.host.signing_state() == "unsigned"
    refused = await site.manage(ADA, "held.list", key=passkey.id)
    assert refused["status"] == "failed" and "Pair it again" in refused["message"]


async def test_a_held_change_turned_down_from_workbench_is_dropped(
    ready: tuple[Site, Authenticator, str],
) -> None:
    site, _passkey, ident = ready
    done = await site.manage(ADA, "held.reject", id=ident)
    assert done["status"] == "done" and site.host.held.get(ident) is None
    assert names(site) == ["Notes"]
    assert site.host.audit.newest(1)[0]["reason"] == "Turned down from Workbench."
    gone = await site.manage(ADA, "held.reject", id=ident)
    assert gone["status"] == "failed"


async def test_nobody_but_the_owner_lists_or_approves(
    ready: tuple[Site, Authenticator, str],
) -> None:
    site, passkey, _ident = ready
    for action, arguments in (
        ("held.list", {"key": passkey.id}),
        ("held.reject", {"id": "x"}),
        ("passkey.pair", passkey.pairing("AAAAA-AAAAA")),
        ("passkey.remove", {"id": passkey.id}),
    ):
        refused = await site.manage(BO, action, **arguments)
        assert refused["status"] == "failed" and "Only this machine's owner" in refused["message"]


async def test_a_refused_passkey_action_is_recorded_without_its_secrets(
    ready: tuple[Site, Authenticator, str],
) -> None:
    """Refused before it reaches the passkey code (not the owner), the audit
    line still names the action only: no MAC, no public key, no assertion."""
    site, passkey, ident = ready
    sent = passkey.pairing("AAAAA-AAAAA")
    signed = passkey.approve(ident, "{}")
    for action, arguments in (("passkey.pair", sent), ("held.approve", signed)):
        refused = await site.manage(BO, action, **arguments)
        assert refused["status"] == "failed", action
    raw = site.host.audit.path.read_text(encoding="utf-8")
    for secret in (sent["mac"], passkey.public, signed["signature"], signed["clientDataJSON"]):
        assert secret not in raw


async def test_the_list_names_the_passkeys_and_the_summary_says_passkeys(
    ready: tuple[Site, Authenticator, str],
) -> None:
    site, passkey, _ident = ready
    without = (await site.manage(ADA, "held.list"))["result"]
    assert [p["id"] for p in without["passkeys"]] == [passkey.id]
    assert passkey.id in without["keys"]
    assert all(i["envelope"] is None for i in without["items"])
    summary = site.host.summary()
    assert summary is not None and summary["signing"]["passkeys"] is True
    assert summary["links"][0]["keys"] == 1


# --- at the machine: the starter's API ---------------------------------------------------


def test_the_passkey_api_answers_its_token_only_and_lists_and_removes(tmp_path: Path) -> None:
    settings = settings_for(tmp_path, channel=None)
    assert settings.links_file is not None
    write_links(settings.links_file, link_entry(ADA, local_channel.own_account(), "ada"))
    app = create_app(settings)
    token = (settings.data_dir / "local_token").read_text(encoding="utf-8").strip()
    good = {"Authorization": f"Bearer {token}"}
    with TestClient(app) as client:
        assert client.post("/v1/passkeys/code", json={"subject": ADA}).status_code == 401
        assert client.get("/v1/passkeys", params={"subject": ADA}).status_code == 401
        made = client.post("/v1/passkeys/code", json={"subject": ADA}, headers=good)
        assert made.status_code == 200 and made.headers["cache-control"] == "no-store"
        assert len(made.json()["code"]) == 11
        listed = client.get("/v1/passkeys", params={"subject": ADA}, headers=good).json()
        assert listed["passkeys"] == [] and listed["codeExpiresAt"] is not None
        nobody = client.post("/v1/passkeys/code", json={"subject": BO}, headers=good)
        assert nobody.status_code == 404
        gone = client.delete(f"/v1/passkeys/{'a' * 32}", params={"subject": ADA}, headers=good)
        assert gone.status_code == 404


async def test_a_passkey_removed_at_the_machine_approves_nothing_and_its_grants_stay(
    ready: tuple[Site, Authenticator, str],
) -> None:
    site, passkey, ident = ready
    assert (await approve(site, passkey, ident))["status"] == "done"
    site.host.passkey_remove(ADA, passkey.id)
    assert site.host.passkeys_of(ADA) == [] and site.host.signing_state() == "unsigned"
    assert names(site) == ["Notes", "Other"]
    assert site.host.audit.newest(1)[0]["action"] == "passkey.remove"
    with pytest.raises(NotHeld):
        site.host.passkey_remove(ADA, passkey.id)


async def test_a_passkey_removed_from_workbench_approves_nothing_and_its_grants_stay(
    ready: tuple[Site, Authenticator, str], tmp_path: Path
) -> None:
    """A lost phone (J60): the owner removes it from Workbench, not at the
    machine. What it approved stays; it approves nothing more."""
    site, passkey, ident = ready
    assert (await approve(site, passkey, ident))["status"] == "done"
    spare = Authenticator()
    assert (await paired(site, spare))["status"] == "done"
    gone = await site.manage(ADA, "passkey.remove", id=passkey.id)
    assert gone["status"] == "done", gone
    assert [p.id for p in site.host.passkeys_of(ADA)] == [spare.id]
    assert site.host.signing_state() == "signed" and names(site) == ["Notes", "Other"]
    newest = site.host.audit.newest(1)[0]
    assert newest["action"] == "passkey.remove" and newest["reason"] == "Removed from Workbench."
    again = await site.manage(ADA, "passkey.remove", id=passkey.id)
    assert again["status"] == "failed" and "not paired with this machine" in again["message"]
    third_folder = other_folder(tmp_path, "third")
    held = await site.manage(ADA, "folder.add", name="Third", path=str(third_folder), approve=False)
    assert held["status"] == "held"
    third = site.host.held.for_subject(ADA)[0].id
    items = (await listed(site, spare))["items"]
    envelope = next(i for i in items if i["id"] == third)["envelope"]
    refused = await site.manage(
        ADA, "held.approve", **{**passkey.approve(third, envelope), "key": passkey.id}
    )
    assert refused["status"] == "failed" and site.host.held.get(third) is not None


async def test_removing_the_last_key_from_workbench_stops_every_tool(
    ready: tuple[Site, Authenticator, str], tmp_path: Path
) -> None:
    """Fail closed: with no key left nothing runs, and a change the root
    makes meanwhile waits for the owner's next key to approve the rules."""
    site, passkey, _ident = ready
    assert (await site.manage(ADA, "passkey.remove", id=passkey.id))["status"] == "done"
    assert site.host.signing_state() == "unsigned"
    later = other_folder(tmp_path, "later")
    assert (await site.manage(ADA, "folder.add", name="Later", path=str(later)))["status"] == (
        "done"
    )
    fresh = Authenticator()
    assert (await paired(site, fresh))["status"] == "done"
    assert site.host.signing_state() == "unconfirmed"


def test_a_stored_passkey_whose_id_is_not_its_own_is_dropped(tmp_path: Path) -> None:
    store = pk.PasskeyStore(tmp_path)
    passkey = Authenticator()
    kept = pk.pair(
        subject=ADA,
        site=ENROLLMENT.site,
        account="acct",
        linked_at="t",
        credential_id=passkey.credential_id,
        public_key=passkey.public,
        alg=passkey.alg,
        rp_id=RP,
        label=None,
    )
    store.add(kept)
    raw = json.loads(store.path.read_text(encoding="utf-8"))
    raw["items"][0]["publicKey"] = Authenticator().public
    store.path.write_text(json.dumps(raw), encoding="utf-8")
    assert store.for_subject(ADA) == []


def _later() -> str:
    return "2026-10-07T12:00:00Z"


def _touch(path: Path) -> None:
    stamp = path.stat()
    os.utime(path, ns=(stamp.st_atime_ns, stamp.st_mtime_ns + 5_000_000_000))
