"""Person-held keys, checked at the site (J14a, `person-held-keys.md`).

The root names who asked for every change; the site now checks a signature
by a key pinned at the machine instead. These are the done-when of §9: a
signed change applies and the same change on the root's word alone does
not; a replayed or reordered approval is refused; an unsigned site says so
and runs no tool; a person with two keys loses one and signs with the other.
"""

from __future__ import annotations

import base64
import json
import time
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from fastapi.testclient import TestClient

from eugene_plexus_site_host import local_channel, signing
from eugene_plexus_site_host._generated.models import SiteApproval
from eugene_plexus_site_host.app import create_app
from eugene_plexus_site_host.host import RULES

from .conftest import (
    ADA,
    BO,
    ENROLLMENT,
    OTHER_ACCOUNT,
    OpenSite,
    PersonKey,
    Site,
    link_entry,
    settings_for,
    write_links,
)
from .test_app import Idle

FILES = "files"


def read(name: str = "Notes") -> dict[str, Any]:
    return {"name": "read_text", "arguments": {"folder": name, "path": "note.txt"}}


async def added(site: Site, folder: Path, *, writable: bool = False) -> str:
    answer = await site.add_workspace(ADA, name="Notes", path=str(folder), writable=writable)
    assert answer["status"] == "done", answer
    return str(answer["result"]["id"])


async def people(site: Site, folder_id: str, *who: tuple[str, bool], **kw: Any) -> dict[str, Any]:
    return await site.share_workspace(
        ADA,
        id=folder_id,
        people=list(who),
        **kw,
    )


def pins(site: Site, *keys: PersonKey) -> None:
    """The starter pins the owner's keys (and only those) at the machine."""
    path = site.host.settings.links_file
    assert path is not None
    write_links(path, link_entry(ADA, local_channel.own_account(), "ada", list(keys)))
    stamp = path.stat()
    import os

    os.utime(path, ns=(stamp.st_atime_ns, stamp.st_mtime_ns + 5_000_000_000))


class P256Key(PersonKey):
    """A browser without Ed25519: ECDSA P-256, WebCrypto's r||s signature."""

    def __init__(self) -> None:
        self.ec = ec.generate_private_key(ec.SECP256R1())
        self.raw = self.ec.public_key().public_bytes(
            serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
        )
        self.id = signing.key_id(self.raw)
        self.label = "Firefox on desk"

    def entry(self) -> dict[str, Any]:
        return {**super().entry(), "alg": "ES256"}

    def sign(self, text: str) -> str:
        der = self.ec.sign(text.encode(), ec.ECDSA(hashes.SHA256()))
        r, s = decode_dss_signature(der)
        return base64.b64encode(r.to_bytes(32, "big") + s.to_bytes(32, "big")).decode()


# --- the envelope and its check --------------------------------------------------------


def checked(key: PersonKey, text: str, **override: Any) -> signing.Checked:
    signature = override.pop("signature", None) or key.sign(text)
    values: dict[str, Any] = {
        "site": ENROLLMENT.site,
        "enrolled_at": ENROLLMENT.enrolledAt,
        "person": ADA,
        "act": "workspace.add",
        "args": {"name": "Notes", "path": "/x"},
        "keys": {key.id: signing.parse_key(key.id, *_alg_pub(key))},
        "key": key.id,
        "last_seq": 0,
        **override,
    }
    return signing.check(text, signature, **values)


def _alg_pub(key: PersonKey) -> tuple[str, str]:
    entry = key.entry()
    return entry["alg"], entry["publicKey"]


def envelope(key: PersonKey, **override: Any) -> str:
    values: dict[str, Any] = {
        "site": ENROLLMENT.site,
        "enrolled_at": ENROLLMENT.enrolledAt,
        "person": ADA,
        "key": key.id,
        "act": "workspace.add",
        "args": {"name": "Notes", "path": "/x"},
        "seq": 1,
        **override,
    }
    return signing.envelope(**values)


@pytest.mark.parametrize("make", [PersonKey, P256Key], ids=["Ed25519", "ES256"])
def test_a_signed_envelope_checks_with_either_kind_of_key(make: type[PersonKey]) -> None:
    key = make()
    text = envelope(key)
    assert checked(key, text).seq == 1
    other = make()
    with pytest.raises(signing.NotSigned, match="does not match"):
        checked(key, text, signature=other.sign(text))


def test_a_key_whose_id_is_not_its_own_is_no_key() -> None:
    key = PersonKey()
    alg, public = _alg_pub(key)
    assert signing.parse_key(key.id, alg, public) is not None
    assert signing.parse_key("0" * 32, alg, public) is None
    assert signing.parse_key(key.id, "ES256", public) is None
    assert signing.parse_key(key.id, alg, "not base64!") is None


@pytest.mark.parametrize(
    ("field", "value", "words"),
    [
        ("site", "s-" + "b" * 26, "site differs"),
        ("enrolled_at", "2026-10-07T00:00:00+00:00", "enrolledAt differs"),
        ("person", BO, "person differs"),
        ("act", "workspace.people", "act differs"),
        ("args", {"name": "Notes", "path": "/elsewhere"}, "args differs"),
    ],
)
def test_every_field_is_checked_against_what_the_site_holds(
    field: str, value: Any, words: str
) -> None:
    key = PersonKey()
    text = envelope(key)
    with pytest.raises(signing.NotSigned, match=words):
        checked(key, text, **{field: value})


def test_the_bytes_must_be_the_sites_own_canonical_form() -> None:
    key = PersonKey()
    value = json.loads(envelope(key))
    spaced = json.dumps(value, sort_keys=True)
    with pytest.raises(signing.NotSigned, match="not in the form"):
        checked(key, spaced)
    # A duplicated key reads as its last value; it is still refused.
    twice = envelope(key).replace('{"act":', '{"act":"settings.set","act":', 1)
    with pytest.raises(signing.NotSigned, match="not in the form"):
        checked(key, twice)
    extra = signing.canonical({**value, "more": 1})
    with pytest.raises(signing.NotSigned, match="wrong fields"):
        checked(key, extra)


def test_an_old_or_replayed_approval_is_refused() -> None:
    key = PersonKey()
    with pytest.raises(signing.NotSigned, match="older than one already used"):
        checked(key, envelope(key, seq=3), last_seq=3)
    stale = envelope(key, iat=int(time.time()) - signing.FRESH_SECONDS - 5)
    with pytest.raises(signing.NotSigned, match="too old"):
        checked(key, stale)
    ahead = envelope(key, iat=int(time.time()) + 3600)
    with pytest.raises(signing.NotSigned, match="too old"):
        checked(key, ahead)
    with pytest.raises(signing.NotSigned, match="not one this person has"):
        checked(key, envelope(key), keys={})


# --- on a site --------------------------------------------------------------------------


async def test_an_unsigned_site_says_so_and_runs_nothing(open_site: OpenSite, folder: Path) -> None:
    site = await open_site(
        signed=False,
        link_page="http://127.0.0.1:8079/link",
        approve_page="http://127.0.0.1:8079/link/approve",
    )
    notes = await added(site, folder)  # root-trusted, as before J14a (J48)
    assert (await people(site, notes, (ADA, False)))["status"] == "done"
    refused = await site.mcp(ADA, FILES, "tools/call", read())
    assert refused["status"] == "failed"
    assert "not added your own key" in refused["message"]
    assert "http://127.0.0.1:8079/link/approve" in refused["message"]
    summary = site.host.summary()
    assert summary is not None and summary["signing"]["state"] == "unsigned"


async def test_a_per_user_site_names_its_approve_page_with_no_link_page(
    open_site: OpenSite, folder: Path
) -> None:
    """J14a.2: a per-user install links nobody, so it has no link page; its
    approve page is its own setting, and the refusal and the summary name it."""
    page = "http://127.0.0.1:8079/link/approve"
    site = await open_site(signed=False, approve_page=page)
    notes = await added(site, folder)
    assert (await people(site, notes, (ADA, False)))["status"] == "done"
    refused = await site.mcp(ADA, FILES, "tools/call", read())
    assert refused["status"] == "failed" and page in refused["message"]
    summary = site.host.summary()
    assert summary is not None
    assert summary["linkPage"] is None and summary["signing"]["approvePage"] == page


async def test_a_change_that_gives_access_is_held_until_signed(site: Site, folder: Path) -> None:
    notes = await added(site, folder)
    held = await people(site, notes, (BO, False), approve=False)
    assert held["status"] == "held" and "approve it with your key" in held["message"]
    # Nothing changed on the root's word alone.
    assert site.host.policy.folders_for(BO) == []
    refused = await site.mcp(BO, FILES, "tools/call", read())
    assert refused["status"] == "failed"
    item = site.host.held.for_subject(ADA)[0]
    approved = await site.approve(item.id)
    assert approved["status"] == "done", approved
    assert [f["name"] for f, _ in site.host.policy.folders_for(BO)] == ["Notes"]
    assert site.host.signing_state() == "signed"
    served = await site.mcp(BO, FILES, "tools/call", read())
    assert served["status"] == "done", served
    log = site.host.audit.newest(5)
    assert any((e.get("reason") or "").startswith("Approved at the machine with key") for e in log)
    assert any(e.get("outcome") == "held" for e in log)


async def test_another_key_or_another_change_does_not_approve(site: Site, folder: Path) -> None:
    notes = await added(site, folder)
    await people(site, notes, (BO, False), approve=False)
    item = site.host.held.for_subject(ADA)[0]
    listed = site.host.held_list(ADA, site.key.id if site.key else None)
    text = next(i for i in listed["items"] if i["id"] == item.id)["envelope"]
    # A key the root made up, never pinned at the machine.
    stranger = PersonKey()
    forged = SiteApproval(
        subject=ADA, envelope=text, key=stranger.id, signature=stranger.sign(text)
    )
    refused = await site.host.approve(item.id, forged)
    assert refused["status"] == "failed" and "not one this person has" in refused["message"]
    # The owner's key over a different change.
    assert site.key is not None
    other = text.replace(BO, "person-cy")
    swapped = SiteApproval(
        subject=ADA, envelope=other, key=site.key.id, signature=site.key.sign(other)
    )
    refused = await site.host.approve(item.id, swapped)
    assert refused["status"] == "failed" and "args differs" in refused["message"]
    assert site.host.policy.folders_for(BO) == []
    assert site.host.held.get(item.id) is not None


async def test_a_used_approval_cannot_be_replayed(site: Site, folder: Path, tmp_path: Path) -> None:
    notes = await added(site, folder)
    other = tmp_path / "other"
    other.mkdir()
    await people(site, notes, (BO, False), approve=False)
    first = site.host.held.for_subject(ADA)[0]
    assert site.key is not None
    listed = site.host.held_list(ADA, site.key.id)
    text = next(i for i in listed["items"] if i["id"] == first.id)["envelope"]
    approval = SiteApproval(
        subject=ADA, envelope=text, key=site.key.id, signature=site.key.sign(text)
    )
    assert (await site.host.approve(first.id, approval))["status"] == "done"
    # Taken back to the bare list, then re-held by the root: the old
    # signature does not apply it again.
    assert (await people(site, notes))["status"] == "done"  # a reduction (J51)
    await people(site, notes, (BO, False), approve=False)
    again = site.host.held.for_subject(ADA)[0]
    replayed = await site.host.approve(again.id, approval)
    assert replayed["status"] == "failed" and "older than one already used" in replayed["message"]
    assert site.host.policy.folders_for(BO) == []


async def test_taking_access_away_needs_no_signature_and_keeps_the_rules_signed(
    site: Site, folder: Path
) -> None:
    notes = await added(site, folder, writable=True)
    assert (await people(site, notes, (ADA, True), (BO, True)))["status"] == "done"
    assert site.host.signing_state() == "signed"
    for change in (
        [(ADA, True), (BO, False)],  # bo may only read now
        [(ADA, True)],  # bo is gone
    ):
        answer = await people(site, notes, *change, approve=False)
        assert answer["status"] == "done", answer
        assert site.host.signing_state() == "signed"
    assert site.host.held.all() == []
    # Giving back is held, and so is a reader made a writer.
    assert (await people(site, notes, (ADA, True), (BO, False), approve=False))["status"] == "held"
    await site.approve(site.host.held.for_subject(ADA)[0].id)
    upgraded = await people(site, notes, (ADA, True), (BO, True), approve=False)
    assert upgraded["status"] == "held" and site.host.policy.folders_for(BO)[0][1] is False
    off = await site.manage(ADA, "settings.set", ownerInDevMode=False, approve=False)
    assert off["status"] == "done"
    on = await site.manage(ADA, "settings.set", ownerInDevMode=True, approve=False)
    assert on["status"] == "held"
    removed = await site.manage(ADA, "workspace.remove", id=notes, approve=False)
    assert removed["status"] == "done" and site.host.signing_state() == "signed"


async def test_rules_from_before_the_key_are_approved_as_a_whole(
    open_site: OpenSite, folder: Path, tmp_path: Path
) -> None:
    site = await open_site(signed=False)
    notes = await added(site, folder)
    assert (await people(site, notes, (ADA, False), (BO, False)))["status"] == "done"
    key = PersonKey()
    site.key = key
    pins(site, key)
    assert site.host.signing_state() == "unconfirmed"
    refused = await site.mcp(ADA, FILES, "tools/call", read())
    assert refused["status"] == "failed" and "approved your rules" in refused["message"]
    listed = site.host.held_list(ADA, key.id)
    rules = listed["items"][0]
    assert rules["id"] == RULES and rules["action"] == "rules.confirm"
    assert any(
        "Workspace “Notes”" in line and "read and search: allow" in line for line in rules["words"]
    )
    # The rules changed after they were listed: that approval is for other rules.
    stale_text = rules["envelope"]
    assert (await site.share_workspace(ADA, id=notes, people=[], approve=False))["status"] == "done"
    stale = SiteApproval(
        subject=ADA, envelope=stale_text, key=key.id, signature=key.sign(stale_text)
    )
    refused = await site.host.approve(RULES, stale)
    assert refused["status"] == "failed" and "args differs" in refused["message"]
    # A signed change does not approve the rest of the rules: only they as a
    # whole are. (Rules that grant nothing need no approval.)
    assert (await people(site, notes, (BO, False), approve=False))["status"] == "held"
    assert (await people(site, notes, (BO, False)))["status"] == "done"
    assert site.host.signing_state() == "unconfirmed"
    assert (await site.confirm_rules())["status"] == "done"
    assert site.host.signing_state() == "signed"


async def test_a_person_with_two_keys_loses_one_and_signs_with_the_other(
    site: Site, folder: Path
) -> None:
    assert site.key is not None
    laptop, phone = site.key, P256Key()
    pins(site, laptop, phone)
    notes = await added(site, folder)
    pins(site, phone)  # the laptop's browser was cleared: its key is gone
    await people(site, notes, (BO, False), approve=False)
    item = site.host.held.for_subject(ADA)[0]
    with pytest.raises(Exception):  # noqa: B017 - the page cannot even list for a gone key
        site.host.held_list(ADA, laptop.id)
    approved = await site.approve(item.id, key=phone)
    assert approved["status"] == "done", approved
    assert [f["name"] for f, _ in site.host.policy.folders_for(BO)] == ["Notes"]
    # What the gone key signed stays (J45).
    assert site.host.signing_state() == "signed"


async def test_held_changes_are_kept_once_named_and_turned_down_at_the_machine(
    site: Site, folder: Path
) -> None:
    notes = await added(site, folder)
    for _ in range(2):
        held = await people(site, notes, (BO, False), approve=False, names={BO: "Bo Bailey"})
        assert held["status"] == "held"
    [item] = site.host.held.for_subject(ADA)
    assert site.host.summary()["signing"]["held"] == 1  # type: ignore[index]
    listed = site.host.held_list(ADA, None)
    words = next(i for i in listed["items"] if i["id"] == item.id)["words"]
    assert words[0].startswith("Whom you share “Notes”")
    assert (
        "Bo Bailey (as Eugene names them; no account on this machine): read and search: allow; "
        "change files: deny (new)"
    ) in words[1]
    assert next(i for i in listed["items"] if i["id"] == item.id)["envelope"] is None
    # Only the person it is held for sees or decides it.
    with pytest.raises(Exception):  # noqa: B017
        site.host.reject(item.id, BO)
    site.host.reject(item.id, ADA)
    assert site.host.held.all() == []
    assert site.host.audit.newest(1)[0]["reason"] == "Turned down at the machine."


async def test_a_held_change_that_cannot_apply_is_refused_now(site: Site, folder: Path) -> None:
    notes = await added(site, folder)
    refused = await people(site, notes, (BO, True), approve=False)
    assert refused["status"] == "failed" and "read-only" in refused["message"]
    refused = await site.manage(
        ADA, "access.set", server="nothing", people=[{"subject": BO, "tools": []}], approve=False
    )
    assert refused["status"] == "failed"
    assert site.host.held.all() == []


async def test_a_held_change_expires(site: Site, folder: Path) -> None:
    notes = await added(site, folder)
    await people(site, notes, (BO, False), approve=False)
    path = site.host.held.path
    value = json.loads(path.read_text(encoding="utf-8"))
    value["items"][0]["heldAt"] = time.time() - signing.HELD_SECONDS - 1
    path.write_text(json.dumps(value), encoding="utf-8")
    assert site.host.held.all() == []


async def test_only_the_owner_signs_this_sites_rules(open_site: OpenSite, folder: Path) -> None:
    bo_key = PersonKey()
    site = await open_site()
    assert site.key is not None
    path = site.host.settings.links_file
    assert path is not None
    write_links(
        path,
        link_entry(ADA, local_channel.own_account(), "ada", [site.key]),
        link_entry(BO, OTHER_ACCOUNT, "bo", [bo_key]),
    )
    notes = await added(site, folder)
    await people(site, notes, (BO, False), approve=False)
    item = site.host.held.for_subject(ADA)[0]
    assert site.host.held_list(BO, bo_key.id)["items"] == []
    listed = site.host.held_list(ADA, site.key.id)
    text = next(i for i in listed["items"] if i["id"] == item.id)["envelope"]
    with pytest.raises(Exception):  # noqa: B017 - not held for bo
        await site.host.approve(
            item.id,
            SiteApproval(subject=BO, envelope=text, key=bo_key.id, signature=bo_key.sign(text)),
        )


# --- the loopback API (J53) ------------------------------------------------------------


def test_the_approval_api_answers_its_token_only(tmp_path: Path) -> None:
    key = PersonKey()
    settings = settings_for(tmp_path)
    assert settings.links_file is not None
    write_links(settings.links_file, link_entry(ADA, local_channel.own_account(), "ada", [key]))
    app = create_app(settings, channel=Idle())  # type: ignore[arg-type]
    token_file = settings.data_dir / "local_token"
    token = token_file.read_text(encoding="utf-8")
    assert len(token) >= 32
    # Made once: a second start reads the same token.
    assert signing.local_token(settings.data_dir) == token
    auth = {"Authorization": f"Bearer {token}"}
    with TestClient(app) as client:
        assert client.get("/v1/held", params={"subject": ADA}).status_code == 401
        wrong = {"Authorization": "Bearer " + "x" * 43}
        assert client.get("/v1/held", params={"subject": ADA}, headers=wrong).status_code == 401
        assert client.get("/v1/held", params={"subject": BO}, headers=auth).status_code == 404
        listed = client.get("/v1/held", params={"subject": ADA, "key": key.id}, headers=auth)
        assert listed.status_code == 200
        assert listed.json() == {
            "subject": ADA,
            "keys": [key.id],
            "passkeys": [],
            "state": "signed",
            "items": [],
        }
        assert listed.headers["cache-control"] == "no-store"
        assert (
            client.post("/v1/held/nothing/reject", json={"subject": ADA}, headers=auth).status_code
            == 404
        )
        bad = client.post("/v1/held/nothing/approve", json={"subject": ADA}, headers=auth)
        assert bad.status_code == 422


async def test_a_key_pinned_to_someone_else_does_not_approve_the_owners_change(
    open_site: OpenSite, folder: Path
) -> None:
    bo_key = PersonKey()
    site = await open_site()
    assert site.key is not None
    path = site.host.settings.links_file
    assert path is not None
    write_links(
        path,
        link_entry(ADA, local_channel.own_account(), "ada", [site.key]),
        link_entry(BO, OTHER_ACCOUNT, "bo", [bo_key]),
    )
    notes = await added(site, folder)
    await people(site, notes, (BO, False), approve=False)
    item = site.host.held.for_subject(ADA)[0]
    text = next(i for i in site.host.held_list(ADA, site.key.id)["items"] if i["id"] == item.id)[
        "envelope"
    ].replace(site.key.id, bo_key.id)
    refused = await site.host.approve(
        item.id,
        SiteApproval(subject=ADA, envelope=text, key=bo_key.id, signature=bo_key.sign(text)),
    )
    assert refused["status"] == "failed" and "not one this person has" in refused["message"]
    assert site.host.policy.folders_for(BO) == []


async def test_a_pinned_key_whose_id_is_not_its_own_is_no_key(
    open_site: OpenSite, folder: Path
) -> None:
    site = await open_site(signed=False)
    key = PersonKey()
    entry = link_entry(ADA, local_channel.own_account(), "ada", [key])
    entry["keys"][0]["id"] = "0" * 32
    path = site.host.settings.links_file
    assert path is not None
    write_links(path, entry)
    import os

    stamp = path.stat()
    os.utime(path, ns=(stamp.st_atime_ns, stamp.st_mtime_ns + 5_000_000_000))
    assert site.host.keys_of(ADA) == {}
    assert site.host.signing_state() == "unsigned"


async def test_two_approvals_of_one_change_apply_it_once(site: Site, folder: Path) -> None:
    notes = await added(site, folder)
    await people(site, notes, (BO, False), approve=False)
    item = site.host.held.for_subject(ADA)[0]
    assert site.key is not None
    first = next(i for i in site.host.held_list(ADA, site.key.id)["items"] if i["id"] == item.id)
    import asyncio

    def approval(text: str) -> SiteApproval:
        return SiteApproval(
            subject=ADA, envelope=text, key=site.key.id, signature=site.key.sign(text)
        )  # type: ignore[union-attr]

    # The second carries the next sequence number, as a page listing again
    # would. The change takes a moment to apply, so the second is already
    # waiting for the lock when the first finishes.
    listed_seq = json.loads(first["envelope"])["seq"]
    second = first["envelope"].replace(f'"seq":{listed_seq}', f'"seq":{listed_seq + 1}')
    assert second != first["envelope"]
    apply = site.host._workspace_people

    async def slowly(subject: str, arguments: dict[str, Any]) -> dict[str, Any]:
        await asyncio.sleep(0.05)
        return await apply(subject, arguments)

    site.host._workspace_people = slowly  # type: ignore[method-assign]
    answers = await asyncio.gather(
        site.host.approve(item.id, approval(first["envelope"])),
        site.host.approve(item.id, approval(second)),
        return_exceptions=True,
    )
    done = [a for a in answers if isinstance(a, dict) and a["status"] == "done"]
    assert len(done) == 1, answers
    assert (
        sum(
            1
            for e in site.host.audit.newest(20)
            if e.get("outcome") == "done" and e.get("action") == "workspace.people"
        )
        == 1
    )


async def test_leaving_drops_what_was_held(site: Site, folder: Path) -> None:
    notes = await added(site, folder)
    await people(site, notes, (BO, False), approve=False)
    assert site.host.held.all()
    site.host.identity.forget()
    assert site.host.held.all() == []
    assert site.host.policy.folders, "the owner's rules stay"


async def test_at_most_32_changes_wait(site: Site, folder: Path) -> None:
    notes = await added(site, folder)
    for i in range(signing.MAX_HELD):
        held = await people(site, notes, (f"person-{i}", False), approve=False)
        assert held["status"] == "held", held
    full = await people(site, notes, ("person-last", False), approve=False)
    assert full["status"] == "failed" and "32 changes are already waiting" in full["message"]
    assert len(site.host.held.all()) == signing.MAX_HELD
