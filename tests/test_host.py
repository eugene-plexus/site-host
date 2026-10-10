"""The site's policy is final (J8), its list is its own (rule 2), and its
owner is the one it pinned at its join (J6b). One file server per machine,
its tools taking a `folder` argument, granted folder by folder (J6g)."""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

import pytest

from eugene_plexus_site_host.host import Host
from eugene_plexus_site_host.policy import Policy

from .conftest import ADA, BO, OpenSite, Site, rpc, settings_for

FILES = "files"


async def add(site: Site, folder: Path, *, name: str = "Notes", writable: bool = False) -> str:
    added = await site.add_workspace(ADA, name=name, path=str(folder), writable=writable)
    assert added["status"] == "done", added
    assert added["result"]["people"] == []
    return str(added["result"]["id"])


async def give(site: Site, folder_id: str, *people: tuple[str, bool]) -> dict[str, Any]:
    answer = await site.share_workspace(
        ADA,
        id=folder_id,
        people=list(people),
    )
    assert answer["status"] == "done", answer
    return answer


def read(name: str = "Notes", path: str = "note.txt") -> dict[str, Any]:
    return {"name": "read_text", "arguments": {"folder": name, "path": path}}


def write(name: str, path: str, text: str = "hi") -> dict[str, Any]:
    return {
        "name": "write_text",
        "arguments": {"folder": name, "path": path, "text": text, "expectedSha256": ""},
    }


def text(answer: dict[str, Any]) -> str:
    return json.dumps(answer["response"]["result"])


def listed(answer: dict[str, Any]) -> dict[str, list[str]]:
    """Each tool listed, with the folders its `folder` argument offers."""
    return {
        t["name"]: t["inputSchema"]["properties"]["folder"]["enum"]
        for t in answer["response"]["result"]["tools"]
    }


async def test_nobody_but_its_holder_has_a_workspace_until_it_is_shared(
    site: Site, folder: Path
) -> None:
    """2b.3b (J69): the owner's folder is their workspace, theirs to read
    at once (§2.6); nobody else has it until the owner shares it."""
    await add(site, folder)
    refused = await site.mcp(BO, FILES, "tools/call", read())
    assert refused["status"] == "failed" and "has not given you" in refused["message"]
    assert (await site.mcp(BO, FILES, "tools/list"))["status"] == "failed"
    mine = await site.mcp(ADA, FILES, "tools/call", read())
    assert mine["status"] == "done" and "Notes from ada's desk" in text(mine)


async def test_the_folder_argument_lists_only_what_was_granted(
    site: Site, folder: Path, tmp_path: Path
) -> None:
    other = tmp_path / "other"
    other.mkdir()
    notes = await add(site, folder, writable=True)
    await add(site, other, name="Private", writable=True)
    await give(site, notes, (BO, False))
    answer = await site.mcp(BO, FILES, "tools/list")
    assert listed(answer) == {
        "list_directory": ["Notes"],
        "read_text": ["Notes"],
        "glob": ["Notes"],
        "grep": ["Notes"],
    }
    got = await site.mcp(BO, FILES, "tools/call", read())
    assert got["status"] == "done" and "Notes from ada's desk" in text(got)
    refused = await site.mcp(BO, FILES, "tools/call", read("Private"))
    assert refused["status"] == "failed" and "workspace named 'Private'" in refused["message"]
    unnamed = await site.mcp(
        BO, FILES, "tools/call", {"name": "read_text", "arguments": {"path": "note.txt"}}
    )
    assert unnamed["status"] == "failed"


async def test_changing_files_is_the_folders_standing_pre_approval(
    site: Site, folder: Path, tmp_path: Path
) -> None:
    other = tmp_path / "other"
    other.mkdir()
    notes = await add(site, folder, writable=True)
    drafts = await add(site, other, name="Drafts", writable=True)
    await give(site, notes, (BO, False))
    await give(site, drafts, (BO, True))
    answer = await site.mcp(BO, FILES, "tools/list")
    assert listed(answer)["write_text"] == ["Drafts"]
    assert listed(answer)["read_text"] == ["Notes", "Drafts"]
    refused = await site.mcp(BO, FILES, "tools/call", write("Notes", "new.txt"))
    assert refused["status"] == "failed" and "not change files" in refused["message"]
    assert not (folder / "new.txt").exists()
    wrote = await site.mcp(BO, FILES, "tools/call", write("Drafts", "new.txt"))
    assert wrote["status"] == "done", wrote
    assert (other / "new.txt").read_text(encoding="utf-8") == "hi"


async def test_a_reader_is_told_plainly_they_may_not_change_files(site: Site, folder: Path) -> None:
    notes = await add(site, folder, writable=True)
    await give(site, notes, (BO, False))
    refused = await site.mcp(BO, FILES, "tools/call", write("Notes", "new.txt"))
    assert refused["status"] == "failed" and "not change files" in refused["message"]
    assert not (folder / "new.txt").exists()


async def test_a_read_only_folder_takes_no_writer(site: Site, folder: Path) -> None:
    notes = await add(site, folder, writable=False)
    refused = await site.share_workspace(ADA, id=notes, people=[(BO, True)])
    assert refused["status"] == "failed" and "read-only" in refused["message"]


async def test_folders_are_not_granted_as_a_server(site: Site, folder: Path) -> None:
    await add(site, folder)
    refused = await site.manage(
        ADA, "access.set", server=FILES, people=[{"subject": BO, "tools": [{"name": "read_text"}]}]
    )
    assert refused["status"] == "failed" and "one by one" in refused["message"]
    off = await site.manage(ADA, "server.enable", server=FILES, enabled=False)
    assert off["status"] == "failed"


async def test_a_folder_name_is_unique_on_the_machine(
    site: Site, folder: Path, tmp_path: Path
) -> None:
    other = tmp_path / "other"
    other.mkdir()
    await add(site, folder)
    again = await site.add_workspace(ADA, name="notes", path=str(other))
    assert again["status"] == "failed" and "named notes already" in again["message"]


async def test_a_duplicate_name_from_before_reads_name_2(
    tmp_path: Path, folder: Path, open_site: OpenSite
) -> None:
    other = tmp_path / "other"
    other.mkdir()
    (other / "note.txt").write_text("the second", encoding="utf-8")
    first = await open_site(tmp_path)
    one = await add(first, folder)
    two = await add(first, other, name="Elsewhere")
    await first.close()
    policy = Policy.load(tmp_path / "data" / "policy.json")
    policy.folders[1]["name"] = "Notes"
    policy.save()
    site = await open_site(tmp_path)
    # Rules written behind the site's back run nothing until approved (J52).
    assert site.host.signing_state() == "unconfirmed"
    assert (await site.confirm_rules())["status"] == "done"
    await give(site, one, (BO, False))
    await give(site, two, (BO, False))
    assert listed(await site.mcp(BO, FILES, "tools/list"))["read_text"] == ["Notes", "Notes (2)"]
    got = await site.mcp(BO, FILES, "tools/call", read("Notes (2)"))
    assert got["status"] == "done" and "the second" in text(got)
    # The report carries each holder's own names; each view names its own.
    names = [w["name"] for w in site.host.summary()["workspaces"]]  # type: ignore[index]
    assert names == ["Notes", "Notes"]


async def test_an_owner_named_in_the_environment_is_not_the_owner(
    site: Site, folder: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Who owns the site is its enrollment's to say. Whatever the launch
    environment names, only the person the join pinned manages it."""
    monkeypatch.setenv("SITE_HOST_OWNER", BO)
    monkeypatch.setenv("EUGENE_PLEXUS_SITE_OWNER", BO)
    refused = await site.manage(BO, "settings.set", ownerInDevMode=True)
    assert refused["status"] == "failed" and "Only this machine's owner" in refused["message"]
    assert (await site.add_workspace(ADA, name="X", path=str(folder)))["status"] == "done"


async def test_editing_the_root_is_not_enough(site: Site, folder: Path) -> None:
    """Rule 2: only the owner the site pinned changes its list. Eugene's owner
    and every other person are refused, whatever the root says."""
    notes = await add(site, folder)
    for subject in ("operator", BO):
        refused = await site.share_workspace(subject, id=notes, people=[(BO, False)])
        assert refused["status"] == "failed" and "Only this machine's owner" in refused["message"]
        refused = await site.manage(subject, "settings.set", ownerInDevMode=True)
        assert refused["status"] == "failed" and "Only this machine's owner" in refused["message"]
    still = await site.mcp(BO, FILES, "tools/call", read())
    assert still["status"] == "failed"
    operator = await site.share_workspace(ADA, id=notes, people=[("operator", False)])
    assert operator["status"] == "failed" and "not a person here" in operator["message"]


async def test_the_list_survives_a_restart_and_is_the_sites_own_file(
    tmp_path: Path, folder: Path, open_site: OpenSite
) -> None:
    first = await open_site(tmp_path)
    notes = await add(first, folder)
    await give(first, notes, (BO, False))
    await first.close()
    again = await open_site(tmp_path)
    assert (await again.mcp(BO, FILES, "tools/call", read()))["status"] == "done"
    policy = Policy.load(tmp_path / "data" / "policy.json", ADA)
    assert [(f["name"], w) for f, w in policy.folders_for(BO)] == [("Notes", False)]


async def test_removing_a_folder_takes_its_grants_with_it(site: Site, folder: Path) -> None:
    notes = await add(site, folder)
    await give(site, notes, (BO, False))
    assert (await site.manage(ADA, "workspace.remove", id=notes))["status"] == "done"
    await add(site, folder)
    assert (await site.mcp(BO, FILES, "tools/call", read()))["status"] == "failed"


async def test_eugenes_owner_needs_dev_mode_a_grant_and_the_sites_say_so(
    site: Site, folder: Path
) -> None:
    notes = await add(site, folder)
    record = site.host.policy.folder(notes)  # type: ignore[union-attr]
    grants = [
        {
            "folderId": notes,
            "name": "Notes",
            "path": record["path"],
            "identity": record["identity"],
            "writable": False,
        }
    ]
    refused = await site.mcp("operator", FILES, "tools/call", read(), grants=grants, mode="dev")
    assert refused["status"] == "failed" and "Dev mode alone opens nothing" in refused["message"]
    assert (await site.manage(ADA, "settings.set", ownerInDevMode=True))["status"] == "done"
    production = await site.mcp(
        "operator", FILES, "tools/call", read(), grants=grants, mode="production"
    )
    assert production["status"] == "failed" and "production" in production["message"]
    no_grant = await site.mcp("operator", FILES, "tools/call", read(), mode="dev")
    assert no_grant["status"] == "failed"
    # A grant names a workspace by id alone (J76): one that is not the
    # owner's opens nothing, whatever path or identity it carries.
    forged = [{**grants[0], "folderId": "0" * 32}]
    assert (await site.mcp("operator", FILES, "tools/call", read(), grants=forged, mode="dev"))[
        "status"
    ] == "failed"
    got = await site.mcp("operator", FILES, "tools/call", read(), grants=grants, mode="dev")
    assert got["status"] == "done", got


async def test_an_operation_runs_once_and_in_time(site: Site, folder: Path) -> None:
    notes = await add(site, folder)
    await give(site, notes, (BO, False))
    first = await site.mcp(BO, FILES, "tools/call", read(), ident="op-1")
    assert first["status"] == "done"
    replay = await site.mcp(BO, FILES, "tools/call", read(), ident="op-1")
    assert replay["status"] == "failed" and "already used" in replay["message"]
    late = await site.mcp(BO, FILES, "tools/call", read(), expires=time.time() - 1)
    assert late["status"] == "failed"
    far = await site.mcp(BO, FILES, "tools/call", read(), expires=time.time() + 300)
    assert far["status"] == "failed"


async def test_only_the_2026_07_28_methods_cross(site: Site, folder: Path) -> None:
    notes = await add(site, folder)
    await give(site, notes, (BO, False))
    old = await site.mcp(BO, FILES, "tools/list", request=rpc("tools/list", version="2025-11-25"))
    assert old["status"] == "failed" and "2026-07-28" in old["message"]
    discover = await site.mcp(BO, FILES, "server/discover")
    assert discover["status"] == "done" and "2026-07-28" in text(discover)


async def test_the_audit_log_records_decisions_and_never_contents(site: Site, folder: Path) -> None:
    notes = await add(site, folder, writable=True)
    await give(site, notes, (BO, True))
    await site.mcp(BO, FILES, "tools/call", write("Notes", "s.txt", "SECRET"))
    await site.mcp(ADA, FILES, "tools/call", write("Notes", "t.txt", "SECRET"), sign=False)
    page = await site.manage(ADA, "audit.read", limit=10)
    entries = page["result"]["entries"]
    # The holder is asked before changing files (§2.6): with a key, unsigned,
    # it is held for their signature (J14b, J86), and nothing ran.
    assert entries[0]["subject"] == ADA and entries[0]["outcome"] == "held"
    assert entries[0]["rule"] == "ask" and "signed" not in entries[0]
    assert entries[1]["subject"] == BO and entries[1]["decision"] == "allowed"
    assert entries[1]["rule"] == "allow" and "reader" not in entries[1]
    assert entries[1]["tool"] == "write_text" and "SECRET" not in json.dumps(entries)
    assert "Notes" in entries[1]["arguments"]
    assert (await site.manage(BO, "audit.read"))["status"] == "failed"
    assert (await site.manage("operator", "audit.read"))["status"] == "failed"


async def test_a_write_whose_end_is_unknown_is_uncertain(
    site: Site, folder: Path, monkeypatch: Any
) -> None:
    from eugene_plexus_site_host import file_server, folder_io

    notes = await add(site, folder, writable=True)
    await give(site, notes, (BO, True))

    def broken(*_args: Any) -> Any:
        raise folder_io.WriteUncertain("The write did not finish reliably.")

    monkeypatch.setattr(file_server, "run", broken)
    answer = await site.mcp(BO, FILES, "tools/call", write("Notes", "x.txt", "a"))
    assert answer["status"] == "uncertain" and "did not finish" in answer["message"]


async def test_a_site_with_no_channel_for_its_workers_runs_nothing(
    tmp_path: Path, folder: Path
) -> None:
    """2b.2: what makes a machine unable to run tools is no way to reach a
    worker, not the lack of an isolated account (which retired)."""
    host = Host(settings_for(tmp_path, channel=None))
    await host.start()
    site = Site(host)
    refused = await site.add_workspace(ADA, name="Notes", path=str(folder))
    assert refused["status"] == "failed" and "no channel for its workers" in refused["message"]
    assert host.settings.unavailable() is not None and host.workers.problem is not None
    assert host.reason() is not None


async def test_the_report_is_the_sites_own_list(site: Site, folder: Path) -> None:
    assert site.host.summary()["servers"] == []  # type: ignore[index]
    notes = await add(site, folder)
    await give(site, notes, (BO, False))
    summary = site.host.summary()
    assert summary is not None
    assert summary["owner"] == ADA and summary["ownerInDevMode"] is False
    # By id and name, never path (J76).
    assert summary["workspaces"] == [
        {
            "id": notes,
            "name": "Notes",
            "holder": ADA,
            "writable": False,
            "rules": {"read": "allow", "change": "deny", "command": "deny"},
            "people": [{"subject": BO, "read": "allow", "change": "deny"}],
        }
    ]
    assert "folders" not in summary and str(folder) not in json.dumps(summary)
    files = summary["servers"][0]
    assert files["id"] == FILES and files["kind"] == "files" and files["enabled"] is True
    assert [t["name"] for t in files["tools"]] == [
        "list_directory",
        "read_text",
        "write_text",
        "edit_text",
        "glob",
        "grep",
    ]
    assert summary["access"] == []


async def test_the_file_server_itself_refuses_a_folder_it_was_not_given(
    folder: Path, tmp_path: Path
) -> None:
    """Below the policy check, the server built for a person knows only
    their folders, and changes files only in those they may change."""
    from eugene_plexus_site_host import dispatch, file_server, folder_io

    drafts = tmp_path / "drafts"
    drafts.mkdir()
    folders = {
        "Notes": {"path": str(folder), "identity": folder_io.inspect(str(folder), [])},
        "Drafts": {"path": str(drafts), "identity": folder_io.inspect(str(drafts), [])},
    }

    def built() -> Any:
        return file_server.server(folders, frozenset({"Drafts"}), [], file_server.Outcome())

    other = await dispatch.exchange(built(), rpc("tools/call", read("Private")))
    assert other["result"]["isError"] is True and "Private" in json.dumps(other)
    change = await dispatch.exchange(built(), rpc("tools/call", write("Notes", "x.txt")))
    assert change["result"]["isError"] is True and not (folder / "x.txt").exists()
    allowed = await dispatch.exchange(built(), rpc("tools/call", write("Drafts", "x.txt")))
    assert allowed["result"]["isError"] is False and (drafts / "x.txt").exists()


async def test_an_edited_policy_file_cannot_make_a_read_only_folder_writable(
    tmp_path: Path, folder: Path, open_site: OpenSite
) -> None:
    first = await open_site(tmp_path)
    notes = await add(first, folder, writable=False)
    await give(first, notes, (BO, False))
    policy = Policy.load(tmp_path / "data" / "policy.json")
    rules = policy.folders[0]["people"][0]["rules"]
    rules["write_text"] = rules["edit_text"] = "allow"
    policy.save()
    await first.close()
    site = await open_site(tmp_path)
    # An edited policy file is not the owner's rules: nothing runs (J52)...
    refused = await site.mcp(BO, FILES, "tools/list")
    assert refused["status"] == "failed" and "approved its rules" in refused["message"]
    # ...and approved as it stands, a reader still cannot write.
    assert (await site.confirm_rules())["status"] == "done"
    assert "write_text" not in listed(await site.mcp(BO, FILES, "tools/list"))
    refused = await site.mcp(BO, FILES, "tools/call", write("Notes", "x.txt"))
    assert refused["status"] == "failed" and not (folder / "x.txt").exists()
