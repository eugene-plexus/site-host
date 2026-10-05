"""Local servers added at the machine: off until the owner turns them on,
never run if their program changed, and a `system` one never without an
administrator's consent (J9). A new tool needs no Eugene release."""

from __future__ import annotations

from pathlib import Path

from eugene_plexus_site_host.host import Host

from .conftest import ADA, BO, Site, local_server, settings_for


def site_with(tmp_path: Path, **server: object) -> Site:
    return Site(Host(settings_for(tmp_path, local_servers=(local_server(**server),))))  # type: ignore[arg-type]


async def test_a_local_server_is_off_until_its_owner_turns_it_on(tmp_path: Path) -> None:
    site = site_with(tmp_path)
    refused = await site.mcp(
        BO, "fixture", "tools/call", {"name": "echo", "arguments": {"text": "hi"}}
    )
    assert refused["status"] == "failed" and "is off" in refused["message"]
    view = next(s for s in site.host.report()["site"]["servers"] if s["id"] == "fixture")
    assert view["enabled"] is False and view["tools"] == []


async def test_a_new_tool_arrives_with_its_server_and_runs_under_the_sites_policy(
    tmp_path: Path,
) -> None:
    site = site_with(tmp_path)
    on = await site.manage(ADA, "server.enable", server="fixture", enabled=True)
    assert on["status"] == "done", on
    tools = {t["name"]: t for t in on["result"]["server"]["tools"]}
    assert tools["echo"]["readOnly"] and not tools["echo"]["destructive"]
    assert tools["touch"]["destructive"], "an unmarked tool is destructive, as MCP defaults"
    refused = await site.manage(
        ADA, "access.set", server="fixture", people=[{"subject": BO, "tools": [{"name": "touch"}]}]
    )
    assert refused["status"] == "failed" and "standing pre-approval" in refused["message"]
    granted = await site.manage(
        ADA, "access.set", server="fixture", people=[{"subject": BO, "tools": [{"name": "echo"}]}]
    )
    assert granted["status"] == "done", granted
    echoed = await site.mcp(
        BO, "fixture", "tools/call", {"name": "echo", "arguments": {"text": "hi"}}
    )
    assert echoed["status"] == "done" and "echo: hi" in str(echoed["response"]), echoed
    touched = await site.mcp(
        BO, "fixture", "tools/call", {"name": "touch", "arguments": {"name": "m.txt"}}
    )
    assert touched["status"] == "failed"
    assert not (tmp_path / "data" / "tools" / "fixture" / "m.txt").exists()
    listed = await site.mcp(BO, "fixture", "tools/list")
    assert [t["name"] for t in listed["response"]["result"]["tools"]] == ["echo"]


async def test_turning_a_server_off_takes_back_what_it_granted(tmp_path: Path) -> None:
    site = site_with(tmp_path)
    await site.manage(ADA, "server.enable", server="fixture", enabled=True)
    await site.manage(
        ADA, "access.set", server="fixture", people=[{"subject": BO, "tools": [{"name": "echo"}]}]
    )
    await site.manage(ADA, "server.enable", server="fixture", enabled=False)
    await site.manage(ADA, "server.enable", server="fixture", enabled=True)
    refused = await site.mcp(
        BO, "fixture", "tools/call", {"name": "echo", "arguments": {"text": "hi"}}
    )
    assert refused["status"] == "failed"


async def test_a_program_that_changed_is_not_run(tmp_path: Path) -> None:
    site = site_with(tmp_path, sha="0" * 64)
    refused = await site.manage(ADA, "server.enable", server="fixture", enabled=True)
    assert (
        refused["status"] == "failed"
        and "changed since an administrator added it" in refused["message"]
    )


async def test_a_system_server_needs_an_administrators_consent(tmp_path: Path) -> None:
    """J9: no consent recorded at the machine, no system tool, whatever the owner says."""
    site = site_with(tmp_path, system=True)
    refused = await site.manage(ADA, "server.enable", server="fixture", enabled=True)
    assert refused["status"] == "failed" and "no administrator has consented" in refused["message"]
    view = next(s for s in site.host.report()["site"]["servers"] if s["id"] == "fixture")
    assert view["system"] is True and view["available"] is False

    consented = site_with(tmp_path / "again", system=True, consented=True)
    assert (await consented.manage(ADA, "server.enable", server="fixture", enabled=True))[
        "status"
    ] == "done"


async def test_eugenes_owner_never_reaches_a_local_server(tmp_path: Path) -> None:
    site = site_with(tmp_path)
    await site.manage(ADA, "server.enable", server="fixture", enabled=True)
    await site.manage(ADA, "settings.set", ownerInDevMode=True)
    refused = await site.mcp("operator", "fixture", "tools/list", mode="dev")
    assert refused["status"] == "failed"
    refused = await site.manage(
        ADA,
        "access.set",
        server="fixture",
        people=[{"subject": "operator", "tools": [{"name": "echo"}]}],
    )
    assert refused["status"] == "failed"
