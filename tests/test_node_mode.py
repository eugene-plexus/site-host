"""An ordinary LAN node: Eugene's owner writes policy from the console, and the
root's grant comes with each call (J6d)."""

from __future__ import annotations

from pathlib import Path

from eugene_plexus_site_host.host import Host

from .conftest import BO, Site, settings_for


def node(tmp_path: Path) -> Site:
    return Site(Host(settings_for(tmp_path, mode="node", owner=None)))


async def inspected(site: Site, folder: Path) -> dict[str, str]:
    answer = await site.manage("operator", "folder.inspect", path=str(folder))
    assert answer["status"] == "done", answer
    return answer["result"]


async def test_only_eugenes_owner_inspects_a_folder_on_a_node(tmp_path: Path, folder: Path) -> None:
    site = node(tmp_path)
    assert (await site.manage(BO, "folder.inspect", path=str(folder)))["status"] == "failed"
    assert (await site.manage("operator", "folder.add", name="x", path=str(folder)))[
        "status"
    ] == "failed"
    result = await inspected(site, folder)
    assert result["path"] == str(folder) and result["identity"]


async def test_the_roots_grant_is_final_on_a_node(tmp_path: Path, folder: Path) -> None:
    site = node(tmp_path)
    found = await inspected(site, folder)
    folder_id = "a" * 32
    grant = {
        "folderId": folder_id,
        "path": found["path"],
        "identity": found["identity"],
        "writable": False,
    }
    server = "files." + folder_id
    read = await site.mcp(
        BO,
        server,
        "tools/call",
        {"name": "read_text", "arguments": {"path": "note.txt"}},
        grant=grant,
    )
    assert read["status"] == "done", read
    write = await site.mcp(
        BO,
        server,
        "tools/call",
        {"name": "write_text", "arguments": {"path": "n.txt", "text": "x", "expectedSha256": ""}},
        grant=grant,
    )
    assert write["status"] == "failed"
    none = await site.mcp(
        BO, server, "tools/call", {"name": "read_text", "arguments": {"path": "note.txt"}}
    )
    assert none["status"] == "failed" and "grant" in none["message"]
    other = await site.mcp(BO, "files." + "b" * 32, "tools/list", grant=grant)
    assert other["status"] == "failed"


async def test_a_replaced_folder_is_refused(tmp_path: Path, folder: Path) -> None:
    site = node(tmp_path)
    found = await inspected(site, folder)
    grant = {"folderId": "c" * 32, "path": found["path"], "identity": "0:0:0", "writable": False}
    read = await site.mcp(
        BO,
        "files." + "c" * 32,
        "tools/call",
        {"name": "read_text", "arguments": {"path": "note.txt"}},
        grant=grant,
    )
    assert read["status"] == "done"
    assert read["response"]["result"]["isError"] is True and "replaced" in str(read["response"])
