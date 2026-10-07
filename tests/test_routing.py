"""Whose worker runs a call (§3.2, J27): a linked person's own, anyone else's
the owner's, and a refusal that says why when there is none to run it."""

from __future__ import annotations

import asyncio
import contextlib
import os
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from eugene_plexus_site_host import folder_io, local_channel
from eugene_plexus_site_host.local_channel import Connection

from .conftest import (
    ADA,
    BO,
    OTHER_ACCOUNT,
    OTHER_UID,
    OpenSite,
    Site,
    link_entry,
    local_server,
    write_links,
)

FILES = "files"
CY = "person-cy"
ME = local_channel.own_account()
#: What a refusal says for the account `OTHER_ACCOUNT`, which no worker holds.
ABSENT_WORDS = "not signed in" if OTHER_ACCOUNT.startswith("S-") else "not running"


def read(name: str = "Notes", path: str = "note.txt") -> dict[str, Any]:
    return {"name": "read_text", "arguments": {"folder": name, "path": path}}


def relink(site: Site, *entries: dict[str, Any]) -> None:
    """Rewrite the links as the starter would. The owner's entry keeps the
    owner's pinned key (J14a) unless it names keys of its own."""
    path = site.host.settings.links_file
    assert path is not None
    if site.key is not None:
        entries = tuple(
            {**e, "keys": [site.key.entry()]} if e["subject"] == ADA and "keys" not in e else e
            for e in entries
        )
    write_links(path, *entries)
    stamp = path.stat()
    os.utime(path, ns=(stamp.st_atime_ns, stamp.st_mtime_ns + 7_000_000_000))


def record_calls(site: Site) -> list[str]:
    """The account each call to a worker was sent to."""
    sent: list[str] = []
    real = site.host.workers.call

    async def spy(account: str, message: dict[str, Any], seconds: float) -> dict[str, Any]:
        sent.append(account)
        return await real(account, message, seconds)

    site.host.workers.call = spy  # type: ignore[method-assign]
    return sent


async def shared(site: Site, folder: Path, *people: str) -> str:
    """The owner registers `folder` as Notes and lets `people` read it."""
    added = await site.manage(ADA, "folder.add", name="Notes", path=str(folder))
    assert added["status"] == "done", added
    folder_id = str(added["result"]["id"])
    given = await site.manage(
        ADA,
        "folder.people",
        id=folder_id,
        people=[{"subject": s, "writable": False} for s in people],
    )
    assert given["status"] == "done", given
    return folder_id


async def drop_worker(site: Site) -> None:
    assert site.task is not None
    site.task.cancel()
    with contextlib.suppress(asyncio.CancelledError, Exception):
        await site.task
    deadline = time.perf_counter() + 10
    while site.host.workers.connected(site.account):
        assert time.perf_counter() < deadline, "the worker never went"
        await asyncio.sleep(0.02)


async def test_a_person_with_no_link_runs_in_the_owners_worker(
    open_site: OpenSite, folder: Path
) -> None:
    site = await open_site()
    await shared(site, folder, BO)
    sent = record_calls(site)
    got = await site.mcp(BO, FILES, "tools/call", read())
    assert got["status"] == "done" and "Notes from ada's desk" in str(got["response"]), got
    assert sent == [ME], "the owner's linked account's worker ran it"


async def test_a_linked_person_runs_in_their_own_workers_account_not_the_owners(
    open_site: OpenSite, folder: Path
) -> None:
    site = await open_site()
    await shared(site, folder, ADA, BO)
    # The owner is linked to an account with no worker; BO to the one with.
    relink(site, link_entry(ADA, OTHER_ACCOUNT, "ada"), link_entry(BO, site.account, "bo"))
    sent = record_calls(site)
    got = await site.mcp(BO, FILES, "tools/call", read())
    assert got["status"] == "done" and "Notes from ada's desk" in str(got["response"]), got
    assert sent == [ME]
    # The owner's own calls go to the owner's account, which has no worker.
    refused = await site.mcp(ADA, FILES, "tools/call", read())
    assert refused["status"] == "failed" and ABSENT_WORDS in refused["message"], refused
    assert sent == [ME], "nothing was sent to a worker that is not there"


async def test_a_linked_person_with_no_worker_is_not_served_by_the_owners(
    open_site: OpenSite, folder: Path
) -> None:
    """Linking someone means their calls run as them, or not at all: it never
    falls back to the owner's account."""
    site = await open_site()
    await shared(site, folder, BO)
    relink(site, link_entry(ADA, site.account, "ada"), link_entry(BO, OTHER_ACCOUNT, "bo"))
    sent = record_calls(site)
    refused = await site.mcp(BO, FILES, "tools/call", read())
    assert refused["status"] == "failed" and ABSENT_WORDS in refused["message"], refused
    assert "your own" in refused["message"].lower() or "Your" in refused["message"]
    assert sent == []


async def test_eugenes_owner_in_dev_mode_runs_in_the_owners_worker(
    open_site: OpenSite, folder: Path
) -> None:
    site = await open_site()
    folder_id = await shared(site, folder)
    record = site.host.policy.folder(folder_id)
    assert record is not None
    assert (await site.manage(ADA, "settings.set", ownerInDevMode=True))["status"] == "done"
    sent = record_calls(site)
    grants = [
        {
            "folderId": folder_id,
            "name": "Notes",
            "path": record["path"],
            "identity": record["identity"],
            "writable": False,
        }
    ]
    got = await site.mcp("operator", FILES, "tools/call", read(), grants=grants, mode="dev")
    assert got["status"] == "done", got
    assert sent == [ME]


async def test_the_owner_not_linked_means_nothing_runs_and_it_says_so(
    open_site: OpenSite, folder: Path
) -> None:
    site = await open_site()
    await shared(site, folder, ADA, BO, CY)
    relink(site, link_entry(BO, site.account, "bo"))
    sent = record_calls(site)
    # The owner's key is pinned with their link (J14a): no link, no key, and
    # an unsigned site runs nothing, a linked person's calls included (J48).
    for subject in (ADA, CY, BO):
        refused = await site.mcp(subject, FILES, "tools/call", read())
        assert refused["status"] == "failed" and "own key" in refused["message"], refused
    assert sent == []
    assert site.host.signing_state() == "unsigned"


@pytest.mark.parametrize(
    ("account", "words"),
    [
        ("S-1-5-21-1-2-3-1001", ("not signed in", "owner is not signed in")),
        (OTHER_UID, ("worker", "not running")),
    ],
)
async def test_the_owners_worker_absent_is_worded_for_the_kind_of_account(
    open_site: OpenSite, folder: Path, account: str, words: tuple[str, str]
) -> None:
    site = await open_site()
    await shared(site, folder, ADA, CY)
    relink(site, link_entry(ADA, account, "ada"))
    # The linked-but-absent owner is told about their own account.
    own = await site.mcp(ADA, FILES, "tools/call", read())
    assert own["status"] == "failed", own
    # Someone with no link of their own is told the owner's worker is why.
    other = await site.mcp(CY, FILES, "tools/call", read())
    assert other["status"] == "failed", other
    if account.startswith("S-"):
        assert "You are not signed in" in own["message"] and "(HOST/ada)" in own["message"]
        assert "owner is not signed in" in other["message"]
    else:
        assert "worker" in own["message"] and "is not running" in own["message"]
        assert "owner's worker" in other["message"] and "is not running" in other["message"]
        assert "signed in" not in own["message"] + other["message"]


async def test_the_owners_worker_dropping_away_refuses_with_its_reason(
    open_site: OpenSite, folder: Path
) -> None:
    site = await open_site()
    await shared(site, folder, BO)
    assert (await site.mcp(BO, FILES, "tools/call", read()))["status"] == "done"
    await drop_worker(site)
    refused = await site.mcp(BO, FILES, "tools/call", read())
    assert refused["status"] == "failed" and ABSENT_WORDS.split()[-1] in refused["message"]
    assert "owner" in refused["message"].lower()


async def test_no_sharing_means_only_the_owner_is_served(open_site: OpenSite, folder: Path) -> None:
    site = await open_site(sharing=False, local_servers=(local_server(),))
    folder_id = await shared(site, folder)
    assert (await site.manage(ADA, "server.enable", server="fixture", enabled=True))[
        "status"
    ] == "done"
    # Nobody but the owner can be given a folder or a server where sharing is off.
    refused = await site.manage(
        ADA, "folder.people", id=folder_id, people=[{"subject": BO, "writable": False}]
    )
    assert refused["status"] == "failed" and "serves only its owner" in refused["message"]
    refused = await site.manage(
        ADA,
        "access.set",
        server="fixture",
        people=[{"subject": BO, "tools": [{"name": "echo"}]}],
    )
    assert refused["status"] == "failed" and "serves only its owner" in refused["message"]
    # The owner may be granted, and their call runs.
    given = await site.manage(
        ADA, "folder.people", id=folder_id, people=[{"subject": ADA, "writable": False}]
    )
    assert given["status"] == "done", given
    got = await site.mcp(ADA, FILES, "tools/call", read())
    assert got["status"] == "done", got


async def test_no_sharing_refuses_a_non_owner_even_if_the_policy_file_names_them(
    open_site: OpenSite, folder: Path
) -> None:
    """The route refuses on its own: an edited policy cannot make a
    non-owner's calls run where sharing is off."""
    site = await open_site()
    folder_id = await shared(site, folder, BO)
    assert site.host.policy.folder(folder_id) is not None
    object.__setattr__(site.host.settings, "sharing", False)
    sent = record_calls(site)
    refused = await site.mcp(BO, FILES, "tools/call", read())
    assert refused["status"] == "failed" and "serves only its owner" in refused["message"]
    assert sent == []
    assert (await site.mcp(ADA, FILES, "tools/list"))["status"] == "failed"  # not granted
    assert (await site.manage(ADA, "audit.read"))["status"] == "done"


class FakeWorker:
    """A worker played by the test: connects as this process's account and
    answers each call from `answer`."""

    def __init__(self, site: Site, answer: Callable[[dict[str, Any]], dict[str, Any] | None]):
        self.site = site
        self.answer = answer
        self.calls: list[dict[str, Any]] = []
        self.conn: Connection | None = None
        self.task: asyncio.Task[None] | None = None

    async def start(self) -> None:
        settings = self.site.host.settings
        assert settings.channel is not None
        self.conn = await local_channel.connect(settings.channel, self.site.account, {})
        self.task = asyncio.create_task(self._serve())
        await self.site.until_connected()

    async def _serve(self) -> None:
        assert self.conn is not None
        while (message := await self.conn.receive()) is not None:
            if message.get("t") != "call":
                continue
            self.calls.append(message)
            reply = self.answer(message)
            if reply is None:
                await self.conn.close()
                return
            await self.conn.send({"t": "result", "id": message["id"], **reply})

    async def stop(self) -> None:
        if self.conn is not None:
            await self.conn.close()
        if self.task is not None:
            await asyncio.wait_for(self.task, 5)


@pytest.mark.parametrize(
    ("problem", "expected"),
    [
        ("denied", "Your account on this machine (HOST/ada) cannot open this folder."),
        ("missing", "was not found"),
        ("unsafe", "could not be opened safely"),
    ],
)
async def test_folder_add_names_the_account_when_the_worker_cannot_open_it(
    open_site: OpenSite, folder: Path, problem: str, expected: str
) -> None:
    site = await open_site(worker=False)
    fake = FakeWorker(site, lambda _m: {"ok": True, "problem": problem})
    await fake.start()
    refused = await site.manage(ADA, "folder.add", name="Notes", path=str(folder))
    await fake.stop()
    assert refused["status"] == "failed" and expected in refused["message"], refused
    assert fake.calls[0]["op"] == "inspect" and fake.calls[0]["path"] == str(folder)
    assert site.host.policy.folders == []


async def test_a_real_workers_denied_folder_names_the_account(
    open_site: OpenSite, folder: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    site = await open_site()

    def denied(*_args: Any) -> Any:
        raise PermissionError("no")

    monkeypatch.setattr(folder_io, "inspect", denied)
    refused = await site.manage(ADA, "folder.add", name="Notes", path=str(folder))
    assert refused["status"] == "failed" and "(HOST/ada)" in refused["message"], refused


async def test_folder_add_needs_the_owners_worker(open_site: OpenSite, folder: Path) -> None:
    site = await open_site(worker=False)
    refused = await site.manage(ADA, "folder.add", name="Notes", path=str(folder))
    assert refused["status"] == "failed" and "not" in refused["message"], refused
    assert "You are not signed in" in refused["message"] or "is not running" in refused["message"]


async def test_a_worker_that_dies_mid_call_leaves_a_write_uncertain_and_a_read_failed(
    open_site: OpenSite, folder: Path
) -> None:
    site = await open_site()
    folder_id = await shared(site, folder, BO)
    await site.manage(ADA, "folder.remove", id=folder_id)
    added = await site.manage(ADA, "folder.add", name="Notes", path=str(folder), writable=True)
    folder_id = str(added["result"]["id"])
    await site.manage(
        ADA, "folder.people", id=folder_id, people=[{"subject": BO, "writable": True}]
    )
    await drop_worker(site)
    fake = FakeWorker(site, lambda _m: None)
    await fake.start()
    write = {
        "name": "write_text",
        "arguments": {"folder": "Notes", "path": "x.txt", "text": "a", "expectedSha256": ""},
    }
    wrote = await site.mcp(BO, FILES, "tools/call", write)
    assert wrote["status"] == "uncertain" and "may have acted" in wrote["message"], wrote
    await fake.stop()
    fake = FakeWorker(site, lambda _m: None)
    await fake.start()
    listed = await site.mcp(BO, FILES, "tools/list")
    assert listed["status"] == "failed" and "may have acted" not in listed["message"], listed
    await fake.stop()
    assert not (folder / "x.txt").exists()


async def test_a_worker_that_refuses_with_a_message_is_a_refusal_in_its_words(
    open_site: OpenSite, folder: Path
) -> None:
    site = await open_site()
    await shared(site, folder, BO)
    await drop_worker(site)
    fake = FakeWorker(site, lambda _m: {"ok": False, "message": "No, said the worker."})
    await fake.start()
    refused = await site.mcp(BO, FILES, "tools/call", read())
    await fake.stop()
    assert refused == {"status": "failed", "message": "No, said the worker."}
    entry = site.host.audit.newest(1)[0]
    assert entry["decision"] == "refused" and entry["reason"] == "No, said the worker."


async def test_a_links_file_that_cannot_be_read_stops_every_call(
    open_site: OpenSite, folder: Path
) -> None:
    site = await open_site()
    await shared(site, folder, ADA, BO)
    path = site.host.settings.links_file
    assert path is not None
    path.write_text("nonsense", encoding="utf-8")
    stamp = path.stat()
    os.utime(path, ns=(stamp.st_atime_ns, stamp.st_mtime_ns + 9_000_000_000))
    sent = record_calls(site)
    for subject in (ADA, BO):
        refused = await site.mcp(subject, FILES, "tools/call", read())
        assert refused["status"] == "failed" and "links file" in refused["message"], refused
    assert sent == []
    assert site.host.reason() is not None and "links file" in str(site.host.reason())


async def test_the_summary_carries_links_link_page_and_sharing(
    open_site: OpenSite, tmp_path: Path, folder: Path
) -> None:
    links = tmp_path / "links.json"
    write_links(
        links,
        link_entry(ADA, ME, "ada"),
        link_entry(BO, OTHER_ACCOUNT, "bo"),
    )
    site = await open_site(link_page="http://127.0.0.1:8079/link")
    await shared(site, folder, BO)
    summary = site.host.summary()
    assert summary is not None
    assert summary["linkPage"] == "http://127.0.0.1:8079/link" and summary["sharing"] is True
    by_subject = {link["subject"]: link for link in summary["links"]}
    assert set(by_subject) == {ADA, BO}
    assert by_subject[ADA] == {
        "subject": ADA,
        "accountName": "HOST/ada",
        "available": True,
        "reason": None,
        "keys": 0,
    }
    assert summary["signing"] == {
        "state": "unsigned",
        "held": 0,
        "approvePage": "http://127.0.0.1:8079/link/approve",
    }
    assert by_subject[BO]["available"] is False and by_subject[BO]["accountName"] == "HOST/bo"
    assert ABSENT_WORDS in by_subject[BO]["reason"]
    await drop_worker(site)
    after = site.host.summary()
    assert after is not None
    assert {link["subject"]: link["available"] for link in after["links"]} == {
        ADA: False,
        BO: False,
    }


async def test_a_summary_with_no_links_file_says_no_links_and_no_link_page(
    open_site: OpenSite, tmp_path: Path
) -> None:
    site = await open_site(worker=False)
    path = site.host.settings.links_file
    assert path is not None
    path.unlink()
    summary = site.host.summary()
    assert summary is not None
    assert summary["links"] == [] and summary["linkPage"] is None


async def test_the_summary_ends_the_connection_of_an_account_whose_link_was_removed(
    open_site: OpenSite,
) -> None:
    site = await open_site()
    assert site.host.workers.connected(ME)
    relink(site)  # nobody is linked any more
    assert site.host.summary() is not None
    deadline = time.perf_counter() + 10
    while site.host.workers.connected(ME):
        assert time.perf_counter() < deadline, "the unlinked account's worker was never ended"
        await asyncio.sleep(0.05)
