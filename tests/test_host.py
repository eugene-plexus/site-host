"""The site's policy is final (J8), its list is its own (rule 2), and its
owner is the one it pinned at its join (J6b)."""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from eugene_plexus_site_host.host import Host
from eugene_plexus_site_host.policy import Policy

from .conftest import ADA, BO, Site, rpc, settings_for

READ = [{"name": "list_directory"}, {"name": "read_text"}]


async def add(site: Site, folder: Path, *, writable: bool = False) -> str:
    added = await site.manage(ADA, "folder.add", name="Notes", path=str(folder), writable=writable)
    assert added["status"] == "done", added
    return "files." + added["result"]["id"]


def text(answer: dict[str, Any]) -> str:
    return json.dumps(answer["response"]["result"])


async def test_nobody_has_anything_until_the_owner_says(site: Site, folder: Path) -> None:
    server = await add(site, folder)
    for subject in (ADA, BO):
        refused = await site.mcp(
            subject, server, "tools/call", {"name": "read_text", "arguments": {"path": "note.txt"}}
        )
        assert refused["status"] == "failed" and "has not given you" in refused["message"]
        listed = await site.mcp(subject, server, "tools/list")
        assert listed["status"] == "failed"


async def test_the_owner_grants_and_the_list_shows_only_what_was_granted(
    site: Site, folder: Path
) -> None:
    server = await add(site, folder, writable=True)
    granted = await site.manage(
        ADA, "access.set", server=server, people=[{"subject": BO, "tools": [{"name": "read_text"}]}]
    )
    assert granted["status"] == "done", granted
    listed = await site.mcp(BO, server, "tools/list")
    assert [t["name"] for t in listed["response"]["result"]["tools"]] == ["read_text"]
    read = await site.mcp(
        BO, server, "tools/call", {"name": "read_text", "arguments": {"path": "note.txt"}}
    )
    assert read["status"] == "done" and "Notes from ada's desk" in text(read)
    refused = await site.mcp(
        BO, server, "tools/call", {"name": "list_directory", "arguments": {"path": "."}}
    )
    assert refused["status"] == "failed" and "may not use" in refused["message"]


async def test_a_destructive_tool_is_a_standing_pre_approval_or_nothing(
    site: Site, folder: Path
) -> None:
    server = await add(site, folder, writable=True)
    plain = await site.manage(
        ADA,
        "access.set",
        server=server,
        people=[{"subject": BO, "tools": [{"name": "write_text"}]}],
    )
    assert plain["status"] == "failed" and "standing pre-approval" in plain["message"]
    standing = await site.manage(
        ADA,
        "access.set",
        server=server,
        people=[{"subject": BO, "tools": [{"name": "write_text", "standing": True}]}],
    )
    assert standing["status"] == "done", standing
    wrote = await site.mcp(
        BO,
        server,
        "tools/call",
        {
            "name": "write_text",
            "arguments": {"path": "new.txt", "text": "hi", "expectedSha256": ""},
        },
    )
    assert wrote["status"] == "done", wrote
    assert (folder / "new.txt").read_text(encoding="utf-8") == "hi"


async def test_a_read_only_folder_offers_no_write(site: Site, folder: Path) -> None:
    server = await add(site, folder, writable=False)
    refused = await site.manage(
        ADA,
        "access.set",
        server=server,
        people=[{"subject": BO, "tools": [{"name": "write_text", "standing": True}]}],
    )
    assert refused["status"] == "failed" and "no tool named" in refused["message"]


async def test_editing_the_root_is_not_enough(site: Site, folder: Path) -> None:
    """Rule 2: only the owner the site pinned changes its list. Eugene's owner
    and every other person are refused, whatever the root says."""
    server = await add(site, folder)
    for subject in ("operator", BO):
        refused = await site.manage(
            subject, "access.set", server=server, people=[{"subject": BO, "tools": READ}]
        )
        assert refused["status"] == "failed" and "Only this machine's owner" in refused["message"]
        refused = await site.manage(subject, "folder.add", name="X", path=str(folder))
        assert refused["status"] == "failed"
    still = await site.mcp(
        BO, server, "tools/call", {"name": "read_text", "arguments": {"path": "note.txt"}}
    )
    assert still["status"] == "failed"


async def test_the_list_survives_a_restart_and_is_the_sites_own_file(
    tmp_path: Path, folder: Path
) -> None:
    first = Site(Host(settings_for(tmp_path)))
    server = await add(first, folder)
    await first.manage(ADA, "access.set", server=server, people=[{"subject": BO, "tools": READ}])
    again = Site(Host(settings_for(tmp_path)))
    read = await again.mcp(
        BO, server, "tools/call", {"name": "read_text", "arguments": {"path": "note.txt"}}
    )
    assert read["status"] == "done"
    policy = Policy.load(tmp_path / "data" / "policy.json")
    assert policy.tools_for(BO, server) == {"list_directory": False, "read_text": False}


async def test_eugenes_owner_needs_dev_mode_a_grant_and_the_sites_say_so(
    site: Site, folder: Path
) -> None:
    server = await add(site, folder)
    folder_id = server.removeprefix("files.")
    record = site.host.policy.folder(folder_id)  # type: ignore[union-attr]
    grant = {
        "folderId": folder_id,
        "path": record["path"],
        "identity": record["identity"],
        "writable": False,
    }
    args = {"name": "read_text", "arguments": {"path": "note.txt"}}
    refused = await site.mcp("operator", server, "tools/call", args, grant=grant, mode="dev")
    assert refused["status"] == "failed" and "Dev mode alone opens nothing" in refused["message"]
    assert (await site.manage(ADA, "settings.set", ownerInDevMode=True))["status"] == "done"
    production = await site.mcp(
        "operator", server, "tools/call", args, grant=grant, mode="production"
    )
    assert production["status"] == "failed" and "production" in production["message"]
    no_grant = await site.mcp("operator", server, "tools/call", args, mode="dev")
    assert no_grant["status"] == "failed"
    read = await site.mcp("operator", server, "tools/call", args, grant=grant, mode="dev")
    assert read["status"] == "done", read


async def test_an_operation_runs_once_and_in_time(site: Site, folder: Path) -> None:
    server = await add(site, folder)
    await site.manage(ADA, "access.set", server=server, people=[{"subject": BO, "tools": READ}])
    args = {"name": "read_text", "arguments": {"path": "note.txt"}}
    first = await site.mcp(BO, server, "tools/call", args, ident="op-1")
    assert first["status"] == "done"
    replay = await site.mcp(BO, server, "tools/call", args, ident="op-1")
    assert replay["status"] == "failed" and "already used" in replay["message"]
    late = await site.mcp(BO, server, "tools/call", args, expires=time.time() - 1)
    assert late["status"] == "failed"
    far = await site.mcp(BO, server, "tools/call", args, expires=time.time() + 300)
    assert far["status"] == "failed"


async def test_only_the_2026_07_28_methods_cross(site: Site, folder: Path) -> None:
    server = await add(site, folder)
    await site.manage(ADA, "access.set", server=server, people=[{"subject": BO, "tools": READ}])
    old = await site.mcp(BO, server, "tools/list", request=rpc("tools/list", version="2025-11-25"))
    assert old["status"] == "failed" and "2026-07-28" in old["message"]
    discover = await site.mcp(BO, server, "server/discover")
    assert discover["status"] == "done" and "2026-07-28" in text(discover)


async def test_the_audit_log_records_decisions_and_never_contents(site: Site, folder: Path) -> None:
    server = await add(site, folder, writable=True)
    await site.manage(
        ADA,
        "access.set",
        server=server,
        people=[{"subject": BO, "tools": [{"name": "write_text", "standing": True}]}],
    )
    await site.mcp(
        BO,
        server,
        "tools/call",
        {
            "name": "write_text",
            "arguments": {"path": "s.txt", "text": "SECRET", "expectedSha256": ""},
        },
    )
    await site.mcp(ADA, server, "tools/call", {"name": "read_text", "arguments": {"path": "s.txt"}})
    page = await site.manage(ADA, "audit.read", limit=10)
    entries = page["result"]["entries"]
    assert entries[0]["subject"] == ADA and entries[0]["decision"] == "refused"
    assert entries[1]["subject"] == BO and entries[1]["decision"] == "allowed"
    assert entries[1]["tool"] == "write_text" and "SECRET" not in json.dumps(entries)
    assert (await site.manage(BO, "audit.read"))["status"] == "failed"
    assert (await site.manage("operator", "audit.read"))["status"] == "failed"


async def test_a_write_whose_end_is_unknown_is_uncertain(
    site: Site, folder: Path, monkeypatch: Any
) -> None:
    from eugene_plexus_site_host import file_server, folder_io

    server = await add(site, folder, writable=True)
    await site.manage(
        ADA,
        "access.set",
        server=server,
        people=[{"subject": BO, "tools": [{"name": "write_text", "standing": True}]}],
    )

    def broken(*_args: Any) -> Any:
        raise folder_io.WriteUncertain("The write did not finish reliably.")

    monkeypatch.setattr(file_server, "run", broken)
    answer = await site.mcp(
        BO,
        server,
        "tools/call",
        {"name": "write_text", "arguments": {"path": "x.txt", "text": "a", "expectedSha256": ""}},
    )
    assert answer["status"] == "uncertain" and "did not finish" in answer["message"]


async def test_a_machine_without_its_own_account_runs_nothing(tmp_path: Path, folder: Path) -> None:
    site = Site(Host(settings_for(tmp_path, account_kind=None)))
    refused = await site.manage(ADA, "folder.add", name="Notes", path=str(folder))
    assert refused["status"] == "failed" and "Windows service" in refused["message"]
    assert site.host.report()["ready"] is False


async def test_the_report_is_the_sites_own_list(site: Site, folder: Path) -> None:
    server = await add(site, folder)
    await site.manage(ADA, "access.set", server=server, people=[{"subject": BO, "tools": READ}])
    report = site.host.report()
    assert report["protocol"] == "mcp-2026-07-28" and report["mode"] == "site"
    summary = report["site"]
    assert summary["owner"] == ADA and summary["ownerInDevMode"] is False
    assert summary["folders"][0]["name"] == "Notes"
    assert summary["servers"][0]["id"] == server and summary["servers"][0]["kind"] == "files"
    assert summary["access"] == [
        {
            "subject": BO,
            "server": server,
            "tools": [
                {"name": "list_directory", "standing": False},
                {"name": "read_text", "standing": False},
            ],
        }
    ]
