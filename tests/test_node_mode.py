"""An ordinary LAN node: Eugene's owner writes policy from the console, and the
person's grants on the machine come with each call (J6d, J6g)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from eugene_plexus_site_host.host import Host

from .conftest import BO, Site, settings_for

FILES = "files"


def node(tmp_path: Path) -> Site:
    return Site(Host(settings_for(tmp_path, mode="node", owner=None)))


async def inspected(site: Site, folder: Path) -> dict[str, str]:
    answer = await site.manage("operator", "folder.inspect", path=str(folder))
    assert answer["status"] == "done", answer
    return answer["result"]


def grant(found: dict[str, str], name: str, ident: str, *, writable: bool) -> dict[str, Any]:
    return {
        "folderId": ident,
        "name": name,
        "path": found["path"],
        "identity": found["identity"],
        "writable": writable,
    }


async def test_only_eugenes_owner_inspects_a_folder_on_a_node(tmp_path: Path, folder: Path) -> None:
    site = node(tmp_path)
    assert (await site.manage(BO, "folder.inspect", path=str(folder)))["status"] == "failed"
    assert (await site.manage("operator", "folder.add", name="x", path=str(folder)))[
        "status"
    ] == "failed"
    result = await inspected(site, folder)
    assert result["path"] == str(folder) and result["identity"]


async def test_the_roots_grants_are_final_on_a_node(tmp_path: Path, folder: Path) -> None:
    site = node(tmp_path)
    other = tmp_path / "other"
    other.mkdir()
    grants = [
        grant(await inspected(site, folder), "Shared", "1", writable=False),
        grant(await inspected(site, other), "Drop", "2", writable=True),
    ]
    listed = await site.mcp(BO, FILES, "tools/list", grants=grants)
    tools = {
        t["name"]: t["inputSchema"]["properties"]["folder"]["enum"]
        for t in listed["response"]["result"]["tools"]
    }
    assert tools == {
        "list_directory": ["Shared", "Drop"],
        "read_text": ["Shared", "Drop"],
        "write_text": ["Drop"],
    }
    read = {"name": "read_text", "arguments": {"folder": "Shared", "path": "note.txt"}}
    assert (await site.mcp(BO, FILES, "tools/call", read, grants=grants))["status"] == "done"
    write = {
        "name": "write_text",
        "arguments": {"folder": "Shared", "path": "n.txt", "text": "x", "expectedSha256": ""},
    }
    assert (await site.mcp(BO, FILES, "tools/call", write, grants=grants))["status"] == "failed"
    write["arguments"]["folder"] = "Drop"
    assert (await site.mcp(BO, FILES, "tools/call", write, grants=grants))["status"] == "done"
    none = await site.mcp(BO, FILES, "tools/call", read)
    assert none["status"] == "failed" and "not been given" in none["message"]
    elsewhere = {"name": "read_text", "arguments": {"folder": "Elsewhere", "path": "note.txt"}}
    assert (await site.mcp(BO, FILES, "tools/call", elsewhere, grants=grants))["status"] == "failed"
    local = await site.mcp(BO, "fixture", "tools/list", grants=grants)
    assert local["status"] == "failed"


async def test_two_grants_with_one_name_read_name_2(tmp_path: Path, folder: Path) -> None:
    site = node(tmp_path)
    found = await inspected(site, folder)
    grants = [
        grant(found, "Docs", "1", writable=False),
        grant(found, "Docs", "2", writable=False),
    ]
    listed = await site.mcp(BO, FILES, "tools/list", grants=grants)
    enum = listed["response"]["result"]["tools"][0]["inputSchema"]["properties"]["folder"]["enum"]
    assert enum == ["Docs", "Docs (2)"]


async def test_a_replaced_folder_is_refused(tmp_path: Path, folder: Path) -> None:
    site = node(tmp_path)
    found = {**(await inspected(site, folder)), "identity": "0:0:0"}
    read = await site.mcp(
        BO,
        FILES,
        "tools/call",
        {"name": "read_text", "arguments": {"folder": "Gone", "path": "note.txt"}},
        grants=[grant(found, "Gone", "3", writable=False)],
    )
    assert read["status"] == "done"
    assert read["response"]["result"]["isError"] is True and "replaced" in str(read["response"])
