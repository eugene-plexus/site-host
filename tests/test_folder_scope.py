"""The folder code's own scope, through the file server (moved from the
agent's retired file helper, whose worker these tests first described)."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

import pytest

from eugene_plexus_site_host.host import Host

from .conftest import BO, Site, settings_for

FILES = "files"


async def granted(tmp_path: Path, root: Path, *, protected: tuple[Path, ...] = ()) -> Any:
    site = Site(
        Host(
            settings_for(
                tmp_path, mode="node", owner=None, protected=(tmp_path / "data", *protected)
            )
        )
    )
    found = await site.manage("operator", "folder.inspect", path=str(root))
    assert found["status"] == "done", found
    grants = [
        {
            "folderId": "1",
            "name": "Shared",
            "path": found["result"]["path"],
            "identity": found["result"]["identity"],
            "writable": True,
        }
    ]

    async def call(tool: str, **arguments: Any) -> dict[str, Any]:
        answer = await site.mcp(
            BO,
            FILES,
            "tools/call",
            {"name": tool, "arguments": {"folder": "Shared", **arguments}},
            grants=grants,
        )
        assert answer["status"] == "done", answer
        result: dict[str, Any] = answer["response"]["result"]
        return result

    return site, grants, call


def body(result: dict[str, Any]) -> dict[str, Any]:
    assert result["isError"] is False, result
    value: dict[str, Any] = json.loads(result["content"][0]["text"])
    return value


async def test_read_write_create_and_a_stale_edit(tmp_path: Path) -> None:
    root = tmp_path / "shared"
    root.mkdir()
    (root / "note.txt").write_text("Original", encoding="utf-8")
    _, _, call = await granted(tmp_path, root)
    read = body(await call("read_text", path="note.txt"))
    assert read["text"] == "Original"
    body(await call("write_text", path="note.txt", text="Updated", expectedSha256=read["sha256"]))
    assert (root / "note.txt").read_text(encoding="utf-8") == "Updated"
    stale = await call("write_text", path="note.txt", text="Again", expectedSha256=read["sha256"])
    assert stale["isError"] is True
    body(await call("write_text", path="new.txt", text="New", expectedSha256=""))
    assert (root / "new.txt").read_text(encoding="utf-8") == "New"
    body(await call("write_text", path="unicode.txt", text="\U0001f680" * 8192, expectedSha256=""))
    assert (root / "unicode.txt").stat().st_size == 32768


@pytest.mark.parametrize("bad", ["absolute", "traversal", "extra", "large"])
async def test_the_scope_does_not_grow(tmp_path: Path, bad: str) -> None:
    root = tmp_path / "shared"
    root.mkdir()
    (root / "note.txt").write_text("Original", encoding="utf-8")
    site, grants, _ = await granted(tmp_path, root)
    arguments: dict[str, Any] = {
        "folder": "Shared",
        "path": "note.txt",
        "text": "Wrong",
        "expectedSha256": "",
    }
    if bad == "absolute":
        arguments["path"] = str(root / "note.txt")
    if bad == "traversal":
        arguments["path"] = "../escaped.txt"
    if bad == "extra":
        arguments["followLinks"] = True
    if bad == "large":
        arguments["text"] = "x" * 8193
    answer = await site.mcp(
        BO, FILES, "tools/call", {"name": "write_text", "arguments": arguments}, grants=grants
    )
    refused = answer["status"] == "failed" or answer["response"]["result"]["isError"] is True
    assert refused, answer
    assert (root / "note.txt").read_text(encoding="utf-8") == "Original"
    assert not (tmp_path / "escaped.txt").exists()


async def test_a_protected_root_and_hard_links_are_refused(tmp_path: Path) -> None:
    secret = tmp_path / "private"
    secret.mkdir()
    (secret / "node.yaml").write_text("secret", encoding="utf-8")
    site = Site(
        Host(settings_for(tmp_path, mode="node", owner=None, protected=(tmp_path / "data", secret)))
    )
    around = await site.manage("operator", "folder.inspect", path=str(tmp_path))
    assert around["status"] == "failed", around
    shared = tmp_path / "shared"
    shared.mkdir()
    os.link(secret / "node.yaml", shared / "note.txt")
    _, _, call = await granted(tmp_path, shared, protected=(secret,))
    linked = await call("read_text", path="note.txt")
    assert linked["isError"] is True and "secret" not in json.dumps(linked)
