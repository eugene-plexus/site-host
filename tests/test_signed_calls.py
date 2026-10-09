"""J14b and 2b.4: a person with a key signs their own calls, and commands
run only with that signature (`person-held-keys.md` §8, §13, J81-J91).

ADA owns the site and has a key at the machine (`Site.keys`); `sign=False`
sends a call as a root would on its own, so what the site holds is seen.
"""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path
from typing import Any

import pytest
import yaml

from eugene_plexus_site_host import commands as cmd
from eugene_plexus_site_host.host import SIGNED_META

from .conftest import ADA, BO, OpenSite, Site, link_entry, local_channel, write_links
from .test_passkeys import Authenticator, paired, quick_codes  # noqa: F401

FILES = "files"


def consent(path: Path, at: str = "2026-10-08T12:00:00Z", by: str = "admin") -> Path:
    path.write_text(
        yaml.safe_dump({"servers": [], "commands": {"consentedAt": at, "by": by}}), "utf-8"
    )
    return path


def no_consent(path: Path) -> Path:
    path.write_text(yaml.safe_dump({"servers": []}), "utf-8")
    return path


async def workspace(site: Site, folder: Path, name: str = "Work", **more: Any) -> str:
    added = await site.manage(ADA, "workspace.add", name=name, path=str(folder), **more)
    assert added["status"] == "done", added
    return str(added["result"]["id"])


def call(tool: str, **arguments: Any) -> dict[str, Any]:
    return {"name": tool, "arguments": arguments}


def read(folder: str = "Work") -> dict[str, Any]:
    return call("read_text", folder=folder, path="note.txt")


def structured(answer: dict[str, Any]) -> dict[str, Any]:
    assert answer["status"] == "done", answer
    result = answer["response"]["result"]
    assert result["isError"] is False, result
    return dict(result["structuredContent"])


def failure(answer: dict[str, Any]) -> str:
    assert answer["status"] == "done", answer
    result = answer["response"]["result"]
    assert result["isError"] is True, result
    return str(result["content"][0]["text"])


async def tools(site: Site, subject: str = ADA) -> dict[str, dict[str, Any]]:
    answer = await site.mcp(subject, FILES, "tools/list")
    assert answer["status"] == "done", answer
    return {t["name"]: t for t in answer["response"]["result"]["tools"]}


def sleeping(seconds: int) -> str:
    return f"Start-Sleep -Seconds {seconds}" if sys.platform == "win32" else f"sleep {seconds}"


@pytest.fixture
async def commanding(open_site: OpenSite, tmp_path: Path, folder: Path) -> Site:
    """ADA's site where an administrator consented to commands, with ADA's
    workspace `Work` (the `folder` fixture), whose rules ask about commands."""
    site = await open_site(local_servers_file=consent(tmp_path / "servers.yaml"))
    await workspace(site, folder)
    return site


# --- the window (J81, J82, J90) ------------------------------------------------------


async def test_a_read_waits_for_a_window_then_runs_inside_it(site: Site, folder: Path) -> None:
    await workspace(site, folder)
    held = await site.mcp(ADA, FILES, "tools/call", read(), sign=False)
    assert held["status"] == "held", held
    assert held["held"]["kind"] == "window" and held["held"]["minutes"] == 60
    assert held["windowUntil"] is None and held["held"]["approved"] is False
    assert "60 minutes" in held["held"]["words"][0]
    # Signed at the machine, on its page, as the person would.
    signed = await site.approve(held["held"]["id"], ADA)
    assert signed["status"] == "done" and signed["result"]["windowUntil"]
    again = await site.mcp(
        ADA, FILES, "tools/call", read(), sign=False, approval={"held": held["held"]["id"]}
    )
    assert "Notes from ada's desk" in json.dumps(structured(again))
    assert again["windowUntil"] == signed["result"]["windowUntil"]
    # Inside the window, an allowed tool needs nothing more.
    assert structured(await site.mcp(ADA, FILES, "tools/call", read(), sign=False))
    line = site.host.audit.newest(1, ADA)[0]
    assert line["signed"].startswith("In the window signed at the machine with key")
    summary = site.host.summary()
    assert summary is not None and summary["links"][0]["windowUntil"] == again["windowUntil"]
    # Closing it needs no signature, and the next read waits again.
    closed = await site.manage(ADA, "window.close")
    assert closed["status"] == "done" and closed["result"] == {"closed": True}
    assert (await site.mcp(ADA, FILES, "tools/call", read(), sign=False))["status"] == "held"


async def test_a_window_ends_after_its_time(
    site: Site, folder: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    await workspace(site, folder)
    assert structured(await site.mcp(ADA, FILES, "tools/call", read()))
    later = time.time() + 61 * 60
    monkeypatch.setattr(time, "time", lambda: later)
    assert site.host.calls.window(ADA) is None


async def test_tools_say_the_site_checks_signatures_for_a_person_with_a_key(
    site: Site, open_site: OpenSite, folder: Path, tmp_path: Path
) -> None:
    await workspace(site, folder)
    listed = await tools(site)
    assert listed["read_text"]["_meta"][SIGNED_META] is True
    bare = await open_site(tmp_path / "bare", signed=False)
    await bare.manage(ADA, "workspace.add", name="Work", path=str(folder))
    answer = await bare.mcp(ADA, FILES, "tools/list")
    # An unsigned owner runs nothing (J48): nothing claims a signature either.
    assert answer["status"] == "failed" and SIGNED_META not in json.dumps(answer)


# --- per call (J86, J91) ---------------------------------------------------------------


async def test_an_ask_call_is_held_until_signed_and_the_root_cannot_forge_it(
    site: Site, folder: Path
) -> None:
    await workspace(site, folder)
    write = call("write_text", folder="Work", path="new.txt", text="x", expectedSha256="")
    held = await site.mcp(ADA, FILES, "tools/call", write, sign=False)
    assert held["status"] == "held" and held["held"]["kind"] == "call", held
    ident = held["held"]["id"]
    assert any("new.txt" in line for line in held["held"]["words"])
    # The root claiming approval, or naming the held id unsigned, runs nothing;
    # asking again while the person signs is not recorded each time.
    lines = len(site.host.audit.newest(50, ADA))
    claimed = await site.mcp(ADA, FILES, "tools/call", write, sign=False, approval={"held": ident})
    assert claimed["status"] == "held" and not (folder / "new.txt").exists()
    assert len(site.host.audit.newest(50, ADA)) == lines
    # An approval for another call does not stretch to this one.
    other = call("write_text", folder="Work", path="evil.txt", text="x", expectedSha256="")
    refused = await site.mcp(ADA, FILES, "tools/call", other, sign=False, approval={"held": ident})
    assert refused["status"] == "failed" and "another call" in refused["message"]
    # Signed at the machine: sent again, it runs, once.
    assert (await site.approve(ident, ADA))["status"] == "done"
    ran = await site.mcp(ADA, FILES, "tools/call", write, sign=False, approval={"held": ident})
    assert structured(ran) and (folder / "new.txt").read_text(encoding="utf-8") == "x"
    replay = await site.mcp(ADA, FILES, "tools/call", write, sign=False, approval={"held": ident})
    assert replay["status"] == "failed" and "not waiting" in replay["message"]
    lines = site.host.audit.newest(6, ADA)
    assert lines[0]["decision"] == "refused" and "not waiting" in lines[0]["reason"]
    assert lines[1]["signed"].startswith("Signed at the machine with key")
    assert lines[1]["outcome"] == "done" and "[left out]" in lines[1]["arguments"]


async def test_an_open_window_does_not_cover_an_ask_call(site: Site, folder: Path) -> None:
    await workspace(site, folder)
    assert structured(await site.mcp(ADA, FILES, "tools/call", read()))  # opens the window
    write = call("write_text", folder="Work", path="w.txt", text="x", expectedSha256="")
    held = await site.mcp(ADA, FILES, "tools/call", write, sign=False)
    assert held["status"] == "held" and held["held"]["kind"] == "call"


async def test_held_calls_are_listed_first_at_the_machine_and_can_be_turned_down(
    site: Site, folder: Path
) -> None:
    await workspace(site, folder)
    write = call("write_text", folder="Work", path="t.txt", text="x", expectedSha256="")
    held = await site.mcp(ADA, FILES, "tools/call", write, sign=False)
    assert site.key is not None
    listed = site.host.held_list(ADA, site.key.id)
    first = listed["items"][0]
    assert first["id"] == held["held"]["id"] and first["action"] == "call"
    assert json.loads(first["envelope"])["act"] == "call"
    assert json.loads(first["envelope"])["args"]["tool"] == "write_text"
    site.host.reject(first["id"], ADA)
    assert site.host.calls.get(first["id"]) is None
    line = site.host.audit.newest(1, ADA)[0]
    assert line["decision"] == "refused" and line["reason"] == "Turned down at the machine."


async def test_a_passkey_signs_a_held_call_in_workbench(open_site: OpenSite, folder: Path) -> None:
    site = await open_site(signed=False)
    passkey = Authenticator()
    assert (await paired(site, passkey))["status"] == "done"
    added = await site.manage(ADA, "workspace.add", approve=False, name="Work", path=str(folder))
    assert added["status"] == "held", added
    # The workspace and the owner's rules, approved with the passkey (J52).
    for _ in range(3):
        items = (await site.manage(ADA, "held.list", key=passkey.id))["result"]["items"]
        if not items:
            break
        approved = await site.manage(
            ADA, "held.approve", **passkey.approve(items[0]["id"], items[0]["envelope"])
        )
        assert approved["status"] == "done", approved
    write = call("write_text", folder="Work", path="p.txt", text="y", expectedSha256="")
    held = await site.mcp(ADA, FILES, "tools/call", write, sign=False)
    assert held["status"] == "held", held
    envelope = held["held"]["envelopes"][passkey.id]
    signed = passkey.approve(held["held"]["id"], envelope)
    approval = {"held": signed.pop("id"), **signed}
    # A tampered assertion is refused and recorded, and nothing runs.
    bad = {**approval, "signature": Authenticator().approve("x", envelope)["signature"]}
    refused = await site.mcp(ADA, FILES, "tools/call", write, sign=False, approval=bad)
    assert refused["status"] == "failed" and not (folder / "p.txt").exists()
    assert site.host.audit.newest(1, ADA)[0]["decision"] == "refused"
    ran = await site.mcp(ADA, FILES, "tools/call", write, sign=False, approval=approval)
    assert structured(ran) and (folder / "p.txt").read_text(encoding="utf-8") == "y"
    assert site.host.audit.newest(1, ADA)[0]["signed"].startswith(
        "Signed from Workbench with passkey"
    )
    # The same assertion again: its sequence is spent.
    again = await site.mcp(ADA, FILES, "tools/call", write, sign=False)
    approval2 = {**approval, "held": again["held"]["id"]}
    stale = await site.mcp(ADA, FILES, "tools/call", write, sign=False, approval=approval2)
    assert stale["status"] == "failed" and "older" in stale["message"]


async def test_removing_a_passkey_closes_the_window_it_may_have_opened(
    open_site: OpenSite, folder: Path
) -> None:
    site = await open_site()
    await workspace(site, folder)
    assert structured(await site.mcp(ADA, FILES, "tools/call", read()))
    assert site.host.calls.window(ADA) is not None
    passkey = Authenticator()
    assert (await paired(site, passkey))["status"] == "done"
    site.host.passkey_remove(ADA, passkey.id)
    assert site.host.calls.window(ADA) is None


async def test_a_person_with_no_key_keeps_workbenchs_word_and_is_never_offered_commands(
    open_site: OpenSite, tmp_path: Path, folder: Path
) -> None:
    write_links(
        tmp_path / "links.json",
        link_entry(ADA, local_channel.own_account(), "ada"),
    )
    site = await open_site(signed=False, local_servers_file=consent(tmp_path / "servers.yaml"))
    assert not site.host._keyed(ADA)
    await site.manage(ADA, "workspace.add", name="Work", path=str(folder))
    # Unsigned owner: nothing runs at all (J48), commands least of all.
    answer = await site.mcp(
        ADA, FILES, "tools/call", call("run_command", folder="Work", command="echo hi")
    )
    assert answer["status"] == "failed"


# --- commands (2b.4, J84, J87-J89) ------------------------------------------------------


async def test_commands_are_offered_only_with_the_administrators_consent(
    open_site: OpenSite, tmp_path: Path, folder: Path
) -> None:
    servers = no_consent(tmp_path / "servers.yaml")
    site = await open_site(local_servers_file=servers)
    await workspace(site, folder)
    assert "run_command" not in await tools(site)
    refused = await site.mcp(
        ADA, FILES, "tools/call", call("run_command", folder="Work", command="echo hi")
    )
    assert refused["status"] == "failed" and "has not allowed commands" in refused["message"]
    summary = site.host.summary()
    assert summary is not None and summary["commands"]["allowed"] is False
    consent(servers)
    listed = await tools(site)
    assert listed["run_command"]["inputSchema"]["properties"]["folder"]["enum"] == ["Work"]
    assert "command_output" in listed and "command_stop" in listed
    assert cmd.shell_name() in listed["run_command"]["description"]


async def test_a_command_runs_only_with_its_own_signature_even_in_a_window(
    commanding: Site, folder: Path
) -> None:
    site = commanding
    assert structured(await site.mcp(ADA, FILES, "tools/call", read()))  # a window is open
    run = call("run_command", folder="Work", command="echo made > forged.txt")
    held = await site.mcp(ADA, FILES, "tools/call", run, sign=False)
    assert held["status"] == "held" and held["held"]["kind"] == "call", held
    assert any("echo made > forged.txt" in line for line in held["held"]["words"])
    assert not (folder / "forged.txt").exists()
    lines = site.host.audit.newest(1, ADA)
    assert lines[0]["tool"] == "run_command" and lines[0]["outcome"] == "held"
    ran = await site.mcp(ADA, FILES, "tools/call", run)
    result = structured(ran)
    assert result["exitCode"] == 0 and result["running"] is False
    assert (folder / "forged.txt").exists()
    line = site.host.audit.newest(1, ADA)[0]
    assert line["signed"].startswith("Signed at the machine") and "Exit code 0" in line["reason"]


async def test_a_command_says_its_output_and_exit_code(commanding: Site) -> None:
    ran = await commanding.mcp(
        ADA, FILES, "tools/call", call("run_command", folder="Work", command="echo hello; exit 3")
    )
    result = structured(ran)
    assert result["exitCode"] == 3 and "hello" in result["output"]


async def test_a_long_command_answers_with_a_handle_then_is_followed_and_stopped(
    commanding: Site, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(cmd, "WAIT_SECONDS", 1.0)
    started = time.perf_counter()
    ran = await commanding.mcp(
        ADA,
        FILES,
        "tools/call",
        call("run_command", folder="Work", command="echo begun; " + sleeping(60)),
    )
    result = structured(ran)
    assert result["running"] is True and time.perf_counter() - started < 10
    handle = result["handle"]
    # Following it is a read of what the person started: a window covers it.
    more = structured(
        await commanding.mcp(
            ADA, FILES, "tools/call", call("command_output", handle=handle, wait=1)
        )
    )
    assert more["running"] is True and "begun" in more["output"]
    stopped = structured(
        await commanding.mcp(
            ADA, FILES, "tools/call", call("command_stop", handle=handle), sign=False
        )
    )
    assert stopped["running"] is False and stopped["stopped"] == "stop"


async def test_a_command_starts_only_in_a_folder_of_the_workspace(
    commanding: Site, folder: Path
) -> None:
    (folder / "sub").mkdir()
    inside = await commanding.mcp(
        ADA,
        FILES,
        "tools/call",
        call("run_command", folder="Work", path="sub", command="echo here > here.txt"),
    )
    assert structured(inside)["exitCode"] == 0 and (folder / "sub" / "here.txt").exists()
    outside = await commanding.mcp(
        ADA, FILES, "tools/call", call("run_command", folder="Work", path="../x", command="echo")
    )
    assert "relative path" in failure(outside)


async def test_the_worker_refuses_commands_without_the_consent_it_reads_itself(
    commanding: Site, tmp_path: Path
) -> None:
    """The site host alone cannot start a program (J89): the worker's own list
    says no, so the worker offers no command whatever the host sends."""
    worker = commanding.worker
    assert worker is not None
    worker.servers_file = no_consent(tmp_path / "workers-own.yaml")
    answer = await commanding.mcp(
        ADA, FILES, "tools/call", call("run_command", folder="Work", command="echo hi")
    )
    assert "no tool named 'run_command'" in failure(answer)


async def test_the_owner_takes_consent_back_and_a_later_consent_counts(
    commanding: Site, tmp_path: Path
) -> None:
    withdrawn = await commanding.manage(ADA, "commands.withdraw")
    assert withdrawn["status"] == "done" and withdrawn["result"]["allowed"] is False
    assert withdrawn["result"]["withdrawnAt"] is not None
    assert "run_command" not in await tools(commanding)
    refused = await commanding.mcp(
        ADA, FILES, "tools/call", call("run_command", folder="Work", command="echo hi")
    )
    assert "turned commands off" in refused["message"]
    consent(tmp_path / "servers.yaml", at="2026-10-09T08:30:00Z", by="the administrator")
    assert "run_command" in await tools(commanding)


async def test_commands_are_never_offered_in_a_shared_or_read_only_workspace(
    commanding: Site, tmp_path: Path
) -> None:
    other = tmp_path / "ro"
    other.mkdir()
    refused = await commanding.manage(
        ADA,
        "workspace.add",
        name="Ro",
        path=str(other),
        writable=False,
        rules={"read": "allow", "change": "deny", "command": "ask"},
    )
    assert refused["status"] == "failed" and "read only" in refused["message"]
    listed = await tools(commanding)
    assert listed["run_command"]["inputSchema"]["properties"]["folder"]["enum"] == ["Work"]
    assert BO not in json.dumps(listed)


async def test_a_workspace_from_before_commands_denies_them(
    commanding: Site, tmp_path: Path
) -> None:
    older = tmp_path / "older"
    older.mkdir()
    await workspace(commanding, older, "Older", rules={"read": "allow", "change": "ask"})
    listed = await tools(commanding)
    assert "Older" not in listed["run_command"]["inputSchema"]["properties"]["folder"]["enum"]
