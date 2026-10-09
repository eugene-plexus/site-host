"""2b.3b: each linked person's own workspaces, rules and keys at the site
(J67-J72, J76-J80, `job-sites-own-enrollment.md` §3.3).

ADA owns the site; BO is linked to an account of their own. One worker runs
in these tests, as this process's account, so whoever is "at" that account
is linked to it and the other to an account no worker holds (`at`).
"""

from __future__ import annotations

import json
import os
import secrets
import sys
import time
from pathlib import Path
from typing import Any

import pytest

from eugene_plexus_site_host import folder_io
from eugene_plexus_site_host._generated.models import SiteApproval, SiteCall
from eugene_plexus_site_host.host import ASK_META, NotHeld
from eugene_plexus_site_host.policy import Policy

from .conftest import (
    ADA,
    BO,
    OTHER_ACCOUNT,
    OpenSite,
    PersonKey,
    Site,
    link_entry,
    local_server,
    rpc,
    write_links,
)

FILES = "files"
CY = "person-cy"


def at(site: Site, here: str, bo_keys: list[PersonKey] | None = None) -> None:
    """Rewrite the links as the starter would: `here` on this process's
    account, the other on one no worker holds. Each keeps their own keys."""
    path = site.host.settings.links_file
    assert path is not None and site.key is not None
    me, away = site.account, OTHER_ACCOUNT
    if bo_keys:
        site.keys[BO] = bo_keys[0]
    else:
        site.keys.pop(BO, None)
    write_links(
        path,
        link_entry(ADA, me if here == ADA else away, "ada", [site.key]),
        link_entry(BO, me if here == BO else away, "bo", bo_keys),
    )
    stamp = path.stat()
    os.utime(path, ns=(stamp.st_atime_ns, stamp.st_mtime_ns + 7_000_000_000))


async def call(
    site: Site,
    subject: str,
    tool: str,
    asked: bool = False,
    sign: bool = True,
    **arguments: Any,
) -> dict[str, Any]:
    return await site.run(
        SiteCall.model_validate(
            {
                "id": secrets.token_hex(8),
                "expiresAt": time.time() + 20,
                "subject": subject,
                "server": FILES,
                "request": rpc("tools/call", {"name": tool, "arguments": arguments}),
                "installMode": "production",
                "asked": asked,
            }
        ),
        sign=sign,
    )


async def tools(site: Site, subject: str) -> dict[str, dict[str, Any]]:
    answer = await site.mcp(subject, FILES, "tools/list")
    assert answer["status"] == "done", answer
    return {t["name"]: t for t in answer["response"]["result"]["tools"]}


def enum(listed: dict[str, dict[str, Any]], tool: str) -> list[str]:
    return list(listed[tool]["inputSchema"]["properties"]["folder"]["enum"])


def result(answer: dict[str, Any]) -> dict[str, Any]:
    assert answer["status"] == "done", answer
    outcome = answer["response"]["result"]
    assert outcome["isError"] is False, outcome
    return dict(outcome["structuredContent"])


async def approve_as(site: Site, subject: str, key: PersonKey, ident: str) -> dict[str, Any]:
    listed = site.host.held_list(subject, key.id)
    item = next(i for i in listed["items"] if i["id"] == ident)
    return await site.host.approve(
        ident,
        SiteApproval(
            subject=subject,
            envelope=item["envelope"],
            key=key.id,
            signature=key.sign(item["envelope"]),
        ),
    )


def approval(subject: str, key: PersonKey, envelope: str) -> SiteApproval:
    return SiteApproval(
        subject=subject, envelope=envelope, key=key.id, signature=key.sign(envelope)
    )


async def held_change(site: Site, subject: str, action: str, **arguments: Any) -> str:
    answer = await site.manage(subject, action, approve=False, **arguments)
    assert answer["status"] == "held", answer
    return next(h.id for h in reversed(site.host.held.for_subject(subject)) if h.action == action)


@pytest.fixture
async def two(open_site: OpenSite, tmp_path: Path) -> tuple[Site, PersonKey, Path]:
    """ADA's `Notes`, shared with BO to read; BO linked with a key, at the
    worker, with a workspace of their own, `Mine`, approved with BO's key."""
    site = await open_site(tmp_path)
    notes = tmp_path / "notes"
    notes.mkdir()
    (notes / "note.txt").write_text("ada's note", encoding="utf-8")
    added = await site.manage(ADA, "workspace.add", name="Notes", path=str(notes))
    assert added["status"] == "done", added
    shared = await site.manage(
        ADA,
        "workspace.people",
        id=added["result"]["id"],
        people=[{"subject": BO, "read": "allow", "change": "deny"}],
    )
    assert shared["status"] == "done", shared
    bo = PersonKey("bo's browser")
    at(site, BO, [bo])
    mine = tmp_path / "mine"
    mine.mkdir()
    (mine / "plan.txt").write_text("bo's plan", encoding="utf-8")
    ident = await held_change(site, BO, "workspace.add", name="Mine", path=str(mine))
    assert (await approve_as(site, BO, bo, ident))["status"] == "done"
    return site, bo, mine


# --- held for each person's own key (J67, J68) -------------------------------------


async def test_a_linked_persons_workspace_waits_for_their_own_key(
    open_site: OpenSite, tmp_path: Path
) -> None:
    site = await open_site(tmp_path)
    at(site, BO)  # linked, with no key yet
    mine = tmp_path / "mine"
    mine.mkdir()
    answer = await site.manage(BO, "workspace.add", approve=False, name="Mine", path=str(mine))
    assert answer["status"] == "held" and "Waiting for your own key" in answer["message"]
    assert site.host.policy.own(BO) == []
    link = next(v for v in site.host.summary()["links"] if v["subject"] == BO)  # type: ignore[index]
    assert link["signing"] == "unsigned" and link["held"] == 1
    # The owner's count is the owner's alone.
    assert site.host.summary()["signing"]["held"] == 0  # type: ignore[index]
    ident = site.host.held.for_subject(BO)[0].id
    # With no key of BO's, nothing approves it: not the owner's key either.
    assert site.key is not None
    assert ident not in {i["id"] for i in site.host.held_list(ADA, site.key.id)["items"]}
    with pytest.raises(NotHeld):
        await site.host.approve(ident, approval(ADA, site.key, "{}"))
    bo = PersonKey()
    at(site, BO, [bo])
    done = await approve_as(site, BO, bo, ident)
    assert done["status"] == "done", done
    assert [w["name"] for w in site.host.policy.own(BO)] == ["Mine"]
    assert site.host.signing_state(BO) == "signed"
    assert enum(await tools(site, BO), "read_text") == ["Mine"]


async def test_neither_persons_key_approves_the_others_changes(
    two: tuple[Site, PersonKey, Path], tmp_path: Path
) -> None:
    site, bo, _mine = two
    assert site.key is not None
    # BO's change, signed with ADA's key as though it were BO's: refused.
    other = tmp_path / "other"
    other.mkdir()
    ident = await held_change(site, BO, "workspace.add", name="Other", path=str(other))
    envelope = next(i for i in site.host.held_list(BO, bo.id)["items"] if i["id"] == ident)[
        "envelope"
    ]
    forged = await site.host.approve(
        ident,
        SiteApproval(subject=BO, envelope=envelope, key=bo.id, signature=site.key.sign(envelope)),
    )
    assert forged["status"] == "failed"
    assert [w["name"] for w in site.host.policy.own(BO)] == ["Mine"]
    # ADA's change, approved with BO's key: BO is not who it is held for.
    at(site, ADA, [bo])
    notes = site.host.policy.own(ADA)[0]["id"]
    ada_change = await held_change(
        site,
        ADA,
        "workspace.people",
        id=notes,
        people=[{"subject": BO, "read": "allow", "change": "allow"}],
    )
    with pytest.raises(NotHeld):
        await site.host.approve(ada_change, approval(BO, bo, "{}"))
    assert site.host.policy.own(ADA)[0]["people"][0]["rules"]["write_text"] == "deny"


async def test_a_rule_the_root_forges_is_refused(two: tuple[Site, PersonKey, Path]) -> None:
    """The root names BO on a change BO never made: it waits for BO's key and
    never applies on the root's word (J68). A rule written behind the site's
    back runs nothing (J52, per person)."""
    site, bo, _mine = two
    mine = site.host.policy.own(BO)[0]
    looser = await site.manage(
        BO,
        "rules.set",
        approve=False,
        id=mine["id"],
        rules={"read": "allow", "change": "allow"},
        deny=[],
    )
    assert looser["status"] == "held"
    assert site.host.policy.own(BO)[0]["rules"]["write_text"] == "ask"
    # The owner cannot change a rule of BO's, nor share BO's workspace.
    for action, arguments in (
        (
            "rules.set",
            {"id": mine["id"], "rules": {"read": "allow", "change": "allow"}, "deny": []},
        ),
        (
            "workspace.people",
            {"id": mine["id"], "people": [{"subject": CY, "read": "allow", "change": "deny"}]},
        ),
        ("workspace.remove", {"id": mine["id"]}),
    ):
        refused = await site.manage(ADA, action, approve=False, **arguments)
        assert refused["status"] == "failed" and "no such workspace" in refused["message"], action
    # Written into the file directly: BO's own workspace stops until BO
    # approves the rules as they are; the owner's keep running (J79).
    path = site.host.settings.data_dir / "policy.json"
    edited = Policy.load(path, ADA)
    edited.own(BO)[0]["rules"]["write_text"] = "allow"
    edited.save()
    site.host.policy = Policy.load(path, ADA)
    refused = await call(site, BO, "read_text", folder="Mine", path="plan.txt")
    assert refused["status"] == "failed" and "approved your rules" in refused["message"]
    assert result(await call(site, BO, "read_text", folder="Notes", path="note.txt"))
    assert site.host.signing_state(BO) == "unconfirmed"
    assert (await approve_as(site, BO, bo, "rules"))["status"] == "done"
    assert result(await call(site, BO, "read_text", folder="Mine", path="plan.txt"))


async def test_the_owner_sees_none_of_another_persons_workspaces(
    two: tuple[Site, PersonKey, Path],
) -> None:
    site, _bo, mine = two
    assert result(await call(site, BO, "read_text", folder="Mine", path="plan.txt"))
    at(site, ADA, [PersonKey()])
    listed = await tools(site, ADA)
    assert all(enum(listed, t) == ["Notes"] for t in ("read_text", "glob", "grep"))
    assert (await call(site, ADA, "read_text", folder="Mine", path="plan.txt"))[
        "status"
    ] == "failed"
    own = await site.manage(ADA, "workspace.list")
    assert [w["name"] for w in own["result"]["workspaces"]] == ["Notes"]
    # The report names BO's workspace by id and name, never its path (J76).
    report = json.dumps(site.host.summary())
    assert '"Mine"' in report and str(mine) not in report
    # The audit log: each reads their own lines (J80).
    ada_lines = (await site.manage(ADA, "audit.read", limit=200))["result"]["entries"]
    # ADA's own refused try at "Mine" is ADA's line; none of BO's is.
    leaked = [e for e in ada_lines if e["subject"] == BO and "Mine" in json.dumps(e)]
    assert not leaked, leaked
    at(site, BO, [PersonKey()])
    bo_lines = (await site.manage(BO, "audit.read", limit=200))["result"]["entries"]
    assert any(e.get("tool") == "read_text" and "Mine" in (e["arguments"] or "") for e in bo_lines)
    assert not any(e.get("action") == "workspace.people" for e in bo_lines)


async def test_a_person_without_a_link_keeps_nothing(two: tuple[Site, PersonKey, Path]) -> None:
    site, _bo, mine = two
    for action, arguments in (
        ("workspace.add", {"name": "X", "path": str(mine)}),
        ("workspace.list", {}),
        ("audit.read", {}),
    ):
        refused = await site.manage(CY, action, approve=False, **arguments)
        assert refused["status"] == "failed" and "not linked" in refused["message"], action
    for action in ("workspace.people", "access.set", "settings.set"):
        refused = await site.manage(BO, action, approve=False, id="0" * 32, people=[])
        assert refused["status"] == "failed" and "Only this machine's owner" in refused["message"]


# --- rules (J70, J72) and hidden paths --------------------------------------------------


async def test_allow_runs_ask_needs_the_persons_word_and_deny_is_never_offered(
    two: tuple[Site, PersonKey, Path],
) -> None:
    site, _bo, mine = two
    listed = await tools(site, BO)
    assert enum(listed, "write_text") == ["Mine"]  # Notes is read-only for BO
    assert listed["write_text"]["_meta"][ASK_META] == ["Mine"]
    assert listed["read_text"]["_meta"][ASK_META] == []
    # BO has a key, so Workbench's word is not enough (J14b): held, unrun.
    held = await call(
        site,
        BO,
        "write_text",
        asked=True,
        sign=False,
        folder="Mine",
        path="new.txt",
        text="x",
        expectedSha256="",
    )
    assert held["status"] == "held" and held["held"]["kind"] == "call", held
    assert not (mine / "new.txt").exists()
    wrote = await call(
        site, BO, "write_text", folder="Mine", path="new.txt", text="x", expectedSha256=""
    )
    assert result(wrote) and (mine / "new.txt").read_text(encoding="utf-8") == "x"
    lines = site.host.audit.newest(10, BO)
    assert lines[0]["rule"] == "ask" and lines[0]["signed"].startswith("Signed at the machine")
    assert lines[1]["action"] == "call" and lines[1]["outcome"] == "held"  # signed, not run
    assert lines[2]["rule"] == "ask" and lines[2]["outcome"] == "held"
    denied = await call(
        site,
        BO,
        "write_text",
        asked=True,
        folder="Notes",
        path="n.txt",
        text="x",
        expectedSha256="",
    )
    assert denied["status"] == "failed" and "may not change files" in denied["message"]
    # Tightening applies at once and stays BO's approved rules (J51).
    workspace = site.host.policy.own(BO)[0]["id"]
    tighter = await site.manage(
        BO,
        "rules.set",
        approve=False,
        id=workspace,
        rules={"read": "allow", "change": "deny"},
        deny=[],
    )
    assert tighter["status"] == "done", tighter
    assert site.host.signing_state(BO) == "signed"
    assert "write_text" not in await tools(site, BO)
    # Read `allow` runs without a word.
    assert (
        result(await call(site, BO, "read_text", folder="Mine", path="plan.txt"))["text"]
        == "bo's plan"
    )


async def test_a_hidden_path_is_left_out_of_every_listing_and_refused_by_name(
    two: tuple[Site, PersonKey, Path],
) -> None:
    site, _bo, mine = two
    (mine / ".env").write_text("TOKEN=1", encoding="utf-8")
    (mine / "secrets").mkdir()
    (mine / "secrets" / "key.txt").write_text("TOKEN=2", encoding="utf-8")
    (mine / "src").mkdir()
    (mine / "src" / ".env").write_text("TOKEN=3", encoding="utf-8")
    (mine / "src" / "app.py").write_text("print('TOKEN')", encoding="utf-8")
    workspace = site.host.policy.own(BO)[0]["id"]
    # Hiding only takes access away: it applies at once (J51).
    hid = await site.manage(
        BO,
        "rules.set",
        approve=False,
        id=workspace,
        rules={"read": "allow", "change": "ask"},
        deny=[".env", "secrets/"],
    )
    assert hid["status"] == "done", hid
    names = result(await call(site, BO, "list_directory", folder="Mine", path="."))["names"]
    assert ".env" not in names and "secrets" not in names and "src" in names
    found = result(await call(site, BO, "glob", folder="Mine", pattern="**/*"))
    assert sorted(found["paths"]) == ["plan.txt", "src/app.py"]
    assert "skipped" not in found  # what is hidden is not counted either
    grepped = result(await call(site, BO, "grep", folder="Mine", pattern="TOKEN", output="content"))
    assert grepped["lines"] == "src/app.py:1:print('TOKEN')"
    for path in (".env", "src/.env", "secrets/key.txt", "secrets/none.txt", "nowhere/.env"):
        refused = await call(site, BO, "read_text", folder="Mine", path=path)
        outcome = refused["response"]["result"]
        assert outcome["isError"] is True and folder_io.HIDDEN in json.dumps(outcome), path
    for tool, arguments in (
        ("glob", {"pattern": "secrets/*"}),
        ("grep", {"pattern": "TOKEN", "path": "secrets"}),
        ("list_directory", {"path": "secrets"}),
    ):
        refused = await call(site, BO, tool, folder="Mine", **arguments)
        assert folder_io.HIDDEN in json.dumps(refused["response"]["result"]), tool
    # Dropping a pattern gives access back: held for BO's key (J51).
    looser = await site.manage(
        BO,
        "rules.set",
        approve=False,
        id=workspace,
        rules={"read": "allow", "change": "ask"},
        deny=[".env"],
    )
    assert looser["status"] == "held"


def test_hidden_matches_as_git_does_and_both_ways_when_the_kind_is_not_known() -> None:
    hidden = folder_io.Hidden(["secrets/", "*.pem", "/build"])
    assert hidden.hides(["secrets"], True) and not hidden.hides(["secrets"], False)
    assert hidden.hides(["secrets"]) and hidden.hides(["a", "secrets", "x.txt"])
    assert hidden.hides(["deep", "k.pem"]) and hidden.hides(["build", "out"])
    assert not hidden.hides(["src", "build"]) and not hidden.hides(["src", "a.py"])
    assert not folder_io.Hidden([]).hides([".env"]) and not folder_io.Hidden()
    # A folder's contents are hidden with it, however the pattern names it.
    for pattern in ("secrets", "secrets/", "/secrets", "**/secrets"):
        assert folder_io.Hidden([pattern]).hides(["secrets", "deep", "key.txt"], False), pattern


# --- whose approval a call needs (J79) ---------------------------------------------------


async def test_the_owners_unconfirmed_rules_do_not_stop_another_persons_own(
    two: tuple[Site, PersonKey, Path],
) -> None:
    site, _bo, _mine = two
    path = site.host.settings.data_dir / "policy.json"
    edited = Policy.load(path, ADA)
    edited.own(ADA)[0]["name"] = "Renamed"
    edited.save()
    site.host.policy = Policy.load(path, ADA)
    assert site.host.signing_state(ADA) == "unconfirmed"
    assert result(await call(site, BO, "read_text", folder="Mine", path="plan.txt"))
    shared = await call(site, BO, "read_text", folder="Renamed", path="note.txt")
    assert shared["status"] == "failed" and "owner has not approved its rules" in shared["message"]
    assert enum(await tools(site, BO), "read_text") == ["Mine"]


async def test_with_both_unconfirmed_each_refusal_names_whose_rules_to_approve(
    two: tuple[Site, PersonKey, Path],
) -> None:
    """Nothing offered, and each workspace blocked for a different person's
    rules: the call is told about the one it names (J79), not the first."""
    site, _bo, _mine = two
    path = site.host.settings.data_dir / "policy.json"
    edited = Policy.load(path, ADA)
    edited.own(ADA)[0]["rules"]["write_text"] = "allow"
    edited.own(BO)[0]["rules"]["write_text"] = "allow"
    edited.save()
    site.host.policy = Policy.load(path, ADA)
    assert site.host.signing_state(ADA) == site.host.signing_state(BO) == "unconfirmed"
    for folder, words in (
        ("Notes", "owner has not approved its rules"),
        ("Mine", "approved your rules"),
    ):
        refused = await call(site, BO, "read_text", folder=folder, path="x.txt")
        assert refused["status"] == "failed" and words in refused["message"], (folder, refused)


async def test_a_name_in_a_persons_view_is_unique_there(
    two: tuple[Site, PersonKey, Path], tmp_path: Path
) -> None:
    site, bo, _mine = two
    theirs = tmp_path / "bo-notes"
    theirs.mkdir()
    (theirs / "note.txt").write_text("bo's own note", encoding="utf-8")
    ident = await held_change(site, BO, "workspace.add", name="notes", path=str(theirs))
    assert (await approve_as(site, BO, bo, ident))["status"] == "done"
    assert enum(await tools(site, BO), "read_text") == ["Mine", "notes", "Notes (2)"]
    shared = result(await call(site, BO, "read_text", folder="Notes (2)", path="note.txt"))
    assert shared["text"] == "ada's note"
    own = result(await call(site, BO, "read_text", folder="notes", path="note.txt"))
    assert own["text"] == "bo's own note"


async def test_an_unlinked_holders_workspace_is_never_opened_by_the_owners_worker(
    two: tuple[Site, PersonKey, Path],
) -> None:
    site, _bo, _mine = two
    path = site.host.settings.links_file
    assert path is not None and site.key is not None
    write_links(path, link_entry(ADA, site.account, "ada", [site.key]))
    stamp = path.stat()
    os.utime(path, ns=(stamp.st_atime_ns, stamp.st_mtime_ns + 9_000_000_000))
    refused = await call(site, BO, "read_text", folder="Mine", path="plan.txt")
    assert refused["status"] == "failed" and "linked your own account" in refused["message"]
    assert "Mine" not in json.dumps(await site.mcp(BO, FILES, "tools/list"))


# --- version 1 becomes the owner's workspaces (J69) ---------------------------------------


def test_a_version_1_policy_is_the_owners_workspaces_with_what_each_had(tmp_path: Path) -> None:
    path = tmp_path / "policy.json"
    folder = {"id": "a" * 32, "name": "Notes", "path": "/srv/notes", "identity": "1:2:3"}
    path.write_text(
        json.dumps(
            {
                "version": 1,
                "folders": [
                    {
                        **folder,
                        "writable": True,
                        "people": [
                            {"subject": ADA, "writable": True},
                            {"subject": BO, "writable": True},
                            {"subject": CY, "writable": False},
                        ],
                    }
                ],
                "access": [
                    {
                        "subject": BO,
                        "server": "git",
                        "tools": [{"name": "push", "standing": True}, {"name": "log"}],
                    },
                    {"subject": BO, "server": "files.old", "tools": [{"name": "read_text"}]},
                ],
                "enabled": {"git": True},
                "ownerInDevMode": False,
                "authorized": "f" * 64,
            }
        ),
        encoding="utf-8",
    )
    policy = Policy.load(path, ADA)
    [notes] = policy.workspaces
    assert notes["holder"] == ADA and notes["deny"] == []
    assert notes["rules"]["read_text"] == "allow" and notes["rules"]["write_text"] == "ask"
    people = {p["subject"]: p["rules"] for p in notes["people"]}
    assert set(people) == {BO, CY}  # the owner has rules of their own now
    assert people[BO]["edit_text"] == "allow" and people[CY]["write_text"] == "deny"
    assert policy.tools_for(BO, "git") == {"push": "allow", "log": None}
    assert policy.access == [policy.access[0]]  # the per-folder servers grant nothing
    # The digest's shape changed: the owner approves their rules once more.
    assert policy.authorized == {} and not policy.approved(ADA)
    policy.save()
    assert json.loads(path.read_text(encoding="utf-8"))["version"] == 2


# --- local servers under allow and ask (J78) ---------------------------------------------


async def test_a_destructive_local_tool_is_asked_about_by_default(
    open_site: OpenSite, tmp_path: Path
) -> None:
    site = await open_site(tmp_path, local_servers=(local_server(),))
    assert (await site.manage(ADA, "server.enable", server="fixture", enabled=True))[
        "status"
    ] == "done"
    granted = await site.manage(
        ADA,
        "access.set",
        server="fixture",
        people=[{"subject": BO, "tools": [{"name": "echo"}, {"name": "touch"}]}],
    )
    assert granted["status"] == "done", granted
    assert site.host.policy.tools_for(BO, "fixture") == {"echo": "allow", "touch": "ask"}
    listed = await site.mcp(BO, "fixture", "tools/list")
    meta = {t["name"]: t["_meta"][ASK_META] for t in listed["response"]["result"]["tools"]}
    assert meta == {"echo": False, "touch": True}
    marker = tmp_path / "data" / "tools" / "fixture" / "m.txt"
    request = rpc("tools/call", {"name": "touch", "arguments": {"name": "m.txt"}})

    async def touch(asked: bool) -> dict[str, Any]:
        return await site.host.mcp(
            SiteCall.model_validate(
                {
                    "id": secrets.token_hex(8),
                    "expiresAt": time.time() + 20,
                    "subject": BO,
                    "server": "fixture",
                    "request": request,
                    "installMode": "production",
                    "asked": asked,
                }
            )
        )

    assert (await touch(False))["status"] == "failed" and not marker.exists()
    assert (await touch(True))["status"] == "done" and marker.exists()


async def test_a_read_only_workspace_takes_no_change_rule(
    two: tuple[Site, PersonKey, Path], tmp_path: Path
) -> None:
    site, _bo, _mine = two
    reading = tmp_path / "reading"
    reading.mkdir()
    refused = await site.manage(
        BO,
        "workspace.add",
        approve=False,
        name="Reading",
        path=str(reading),
        writable=False,
        rules={"read": "allow", "change": "ask"},
    )
    assert refused["status"] == "failed" and "read only" in refused["message"]
    assert site.host.held.for_subject(BO) == []


@pytest.mark.skipif(
    sys.platform != "win32", reason="Windows names are caseless and have 8.3 aliases"
)
def test_on_windows_a_hidden_name_is_hidden_in_any_case_and_no_short_name_reaches_it() -> None:
    hidden = folder_io.Hidden([".env", "secrets/"])
    assert hidden.hides([".ENV"]) and hidden.hides(["Secrets", "key.txt"])
    assert folder_io.Hidden([".ENV", "*.PEM"]).hides([".env"]) and folder_io.Hidden(
        ["*.PEM"]
    ).hides(["certs", "site.pem"])
    with pytest.raises(folder_io.FolderError, match="short name"):
        hidden.check(["SECRE~1", "key.txt"])
    folder_io.Hidden().check(["SECRE~1"])  # no patterns, nothing to reach


async def test_the_file_server_reads_only_where_the_rules_let_it(tmp_path: Path) -> None:
    from eugene_plexus_site_host import dispatch, file_server

    a, b = tmp_path / "a", tmp_path / "b"
    for where in (a, b):
        where.mkdir()
        (where / "x.txt").write_text("x", encoding="utf-8")
    folders = {
        "A": {"path": str(a), "identity": folder_io.inspect(str(a), [])},
        "B": {"path": str(b), "identity": folder_io.inspect(str(b), [])},
    }
    built = file_server.server(
        folders, frozenset({"B"}), [], file_server.Outcome(), frozenset({"A"})
    )
    read_b = {"name": "read_text", "arguments": {"folder": "B", "path": "x.txt"}}
    answer = await dispatch.exchange(built, rpc("tools/call", read_b))
    assert answer["result"]["isError"] is True


async def test_deny_on_reading_is_not_offered_where_changing_is(
    two: tuple[Site, PersonKey, Path],
) -> None:
    site, _bo, _mine = two
    workspace = site.host.policy.own(BO)[0]["id"]
    tighter = await site.manage(
        BO,
        "rules.set",
        approve=False,
        id=workspace,
        rules={"read": "deny", "change": "ask"},
        deny=[],
    )
    assert tighter["status"] == "done", tighter
    listed = await tools(site, BO)
    assert enum(listed, "read_text") == ["Notes"] and enum(listed, "write_text") == ["Mine"]
    refused = await call(site, BO, "read_text", folder="Mine", path="plan.txt")
    assert refused["status"] == "failed" and "may not read or search" in refused["message"]


async def test_with_nothing_offered_a_person_without_a_key_is_told_to_add_one(
    open_site: OpenSite, tmp_path: Path
) -> None:
    """J48 says why no tool runs: before a first workspace, a linked person
    with no key is told to add one, not that they have no workspace."""
    site = await open_site(tmp_path, signed=False)
    refused = await site.mcp(ADA, FILES, "tools/list")
    assert refused["status"] == "failed" and "own key" in refused["message"], refused
    at_bo = await open_site(tmp_path / "bo")
    at(at_bo, BO, [PersonKey()])
    keyed = await at_bo.mcp(BO, FILES, "tools/list")
    assert keyed["status"] == "failed" and "no workspace" in keyed["message"], keyed
