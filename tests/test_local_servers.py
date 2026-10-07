"""Local servers added at the machine: off until the owner turns them on,
never run if their program changed, and a `system` one never without an
administrator's consent (J9). A new tool needs no Eugene release."""

from __future__ import annotations

from pathlib import Path

from .conftest import ADA, BO, OpenSite, Site, local_server


async def site_with(open_site: OpenSite, tmp_path: Path, **server: object) -> Site:
    return await open_site(tmp_path, local_servers=(local_server(**server),))  # type: ignore[arg-type]


async def test_a_local_server_is_off_until_its_owner_turns_it_on(
    tmp_path: Path, open_site: OpenSite
) -> None:
    site = await site_with(open_site, tmp_path)
    refused = await site.mcp(
        BO, "fixture", "tools/call", {"name": "echo", "arguments": {"text": "hi"}}
    )
    assert refused["status"] == "failed" and "is off" in refused["message"]
    view = next(s for s in site.host.summary()["servers"] if s["id"] == "fixture")
    assert view["enabled"] is False and view["tools"] == []


async def test_a_new_tool_arrives_with_its_server_and_runs_under_the_sites_policy(
    tmp_path: Path, open_site: OpenSite
) -> None:
    site = await site_with(open_site, tmp_path)
    # Turning a server on is held for the owner's key (J14a), then approved.
    held = await site.manage(ADA, "server.enable", approve=False, server="fixture", enabled=True)
    assert held["status"] == "held" and not site.host.policy.enabled.get("fixture")
    on = await site.approve(site.host.held.for_subject(ADA)[0].id)
    assert on["status"] == "done", on
    tools = {t["name"]: t for t in on["result"]["server"]["tools"]}
    assert tools["echo"]["readOnly"] and not tools["echo"]["destructive"]
    assert tools["touch"]["destructive"], "an unmarked tool is destructive, as MCP defaults"
    # A destructive tool may be granted, and is asked about by default (J78);
    # a tool the server does not list is refused now, never held (J14a).
    unknown = await site.manage(
        ADA,
        "access.set",
        approve=False,
        server="fixture",
        people=[{"subject": BO, "tools": [{"name": "rm"}]}],
    )
    assert unknown["status"] == "failed" and "no tool named 'rm'" in unknown["message"]
    assert site.host.held.all() == []
    granted = await site.manage(
        ADA, "access.set", server="fixture", people=[{"subject": BO, "tools": [{"name": "echo"}]}]
    )
    assert granted["status"] == "done", granted
    # A tool more for someone already on the list is held too.
    more = await site.manage(
        ADA,
        "access.set",
        approve=False,
        server="fixture",
        people=[{"subject": BO, "tools": [{"name": "echo"}, {"name": "touch", "standing": True}]}],
    )
    assert more["status"] == "held" and site.host.policy.tools_for(BO, "fixture") == {
        "echo": "allow"
    }
    site.host.reject(site.host.held.for_subject(ADA)[0].id, ADA)
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


async def test_turning_a_server_off_takes_back_what_it_granted(
    tmp_path: Path, open_site: OpenSite
) -> None:
    site = await site_with(open_site, tmp_path)
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


async def test_a_program_that_changed_is_not_run(tmp_path: Path, open_site: OpenSite) -> None:
    site = await site_with(open_site, tmp_path, sha="0" * 64)
    refused = await site.manage(ADA, "server.enable", server="fixture", enabled=True)
    assert (
        refused["status"] == "failed"
        and "changed since an administrator added it" in refused["message"]
    )


async def test_a_system_server_needs_an_administrators_consent(
    tmp_path: Path, open_site: OpenSite
) -> None:
    """J9: no consent recorded at the machine, no system tool, whatever the owner says."""
    site = await site_with(open_site, tmp_path, system=True)
    refused = await site.manage(ADA, "server.enable", server="fixture", enabled=True)
    assert refused["status"] == "failed" and "no administrator has consented" in refused["message"]
    view = next(s for s in site.host.summary()["servers"] if s["id"] == "fixture")
    assert view["system"] is True and view["available"] is False

    consented = await site_with(open_site, tmp_path / "again", system=True, consented=True)
    assert (await consented.manage(ADA, "server.enable", server="fixture", enabled=True))[
        "status"
    ] == "done"


async def test_eugenes_owner_never_reaches_a_local_server(
    tmp_path: Path, open_site: OpenSite
) -> None:
    site = await site_with(open_site, tmp_path)
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
