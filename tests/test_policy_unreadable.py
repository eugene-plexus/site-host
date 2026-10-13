"""A policy file that cannot be used stops the site running anything, not starting.

`Policy.load` used to raise in `Host.__init__` for a file it did not read: a
site that would not start, and a message that named neither the file nor what
was wrong with it. Now the host runs on `Policy.unreadable`: nothing is
allowed, nothing may be saved over the file, the report says why (naming the
file and the fault), a copy is kept beside it, and a file put right is read
again without a restart.

**Version 1 is not read any more.** It was the form from 2026-10-05 to
2026-10-07, in dev builds only: the first release with a site host came after,
and 2b.3b made it version 2. The fixture is a real one, written by the host
of that time (`4f6c075`), so the case that matters, an old file this host
no longer converts, is the file that build wrote and not a guess at it.
"""

from __future__ import annotations

import json
import logging
import os
import re
import secrets
import time
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from eugene_plexus_site_host._generated.models import (
    SiteManage,
    SiteReport,
    SiteServer,
    SiteSummary,
)
from eugene_plexus_site_host.app import create_app
from eugene_plexus_site_host.channel import Channel
from eugene_plexus_site_host.host import FILES, REASON_LIMIT, Host, clipped
from eugene_plexus_site_host.identity import Identity
from eugene_plexus_site_host.policy import (
    PROBLEM_LIMIT,
    UNREADABLE_SUFFIX,
    VERSION,
    Policy,
    PolicyUnreadable,
)

from .conftest import ADA, OpenSite, local_server, settings_for
from .test_app import Idle

#: What site-host 4f6c075 wrote with `Policy.save`: a folder with three people
#: on it, a local server with two tools granted, and the owner's approval.
V1_POLICY = """{
  "version": 1,
  "folders": [
    {
      "id": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      "name": "Notes",
      "path": "/srv/notes",
      "identity": "1:2:3",
      "writable": true,
      "people": [
        {
          "subject": "person-ada",
          "writable": true
        },
        {
          "subject": "person-bo",
          "writable": true
        },
        {
          "subject": "person-cy",
          "writable": false
        }
      ]
    }
  ],
  "access": [
    {
      "subject": "person-bo",
      "server": "git",
      "tools": [
        {
          "name": "push",
          "standing": true
        },
        {
          "name": "log"
        }
      ]
    }
  ],
  "enabled": {
    "git": true
  },
  "ownerInDevMode": false,
  "authorized": "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
}"""


def a_workspace(**changes: Any) -> dict[str, Any]:
    """A workspace as `Host._add` writes one."""
    rules = {"read_text": "allow", "write_text": "ask"}
    return {
        "id": secrets.token_hex(16),
        "name": "Notes",
        "path": "/srv/notes",
        "identity": "1:2:3",
        "holder": ADA,
        "writable": True,
        "rules": rules,
        "deny": [],
        "people": [],
        **changes,
    }


def a_policy(**changes: Any) -> bytes:
    value = {
        "version": VERSION,
        "workspaces": [a_workspace()],
        "access": [],
        "enabled": {},
        "ownerInDevMode": False,
        "authorized": {},
        **changes,
    }
    return json.dumps(value).encode("utf-8")


def without(workspace: dict[str, Any], key: str) -> dict[str, Any]:
    return {k: v for k, v in workspace.items() if k != key}


#: name -> (the file's bytes, what the problem must say)
BROKEN: dict[str, tuple[bytes, str]] = {
    "not JSON": (b"{ this is not json", "is not valid JSON (Expecting property name"),
    "empty": (b"", "is not valid JSON (Expecting value, line 1, column 1)"),
    "a byte order mark": (b"\xef\xbb\xbf" + a_policy(), "is not valid JSON (Unexpected UTF-8 BOM"),
    "not text": (b"\xff\xfe\x00\x01", "is not UTF-8 text"),
    "a list": (b"[]", "holds list, not a policy"),
    "version 1": (V1_POLICY.encode("utf-8"), "is policy version 1, and this host reads version 2"),
    "a later version": (a_policy(version=3), "is policy version 3, and this host reads version 2"),
    "no version": (b"{}", "is policy version None, and this host reads version 2"),
    "a workspace with no holder": (
        a_policy(workspaces=[without(a_workspace(), "holder")]),
        "cannot be used: workspace 1 has no holder",
    ),
    "a workspace that is not an object": (
        a_policy(workspaces=["Notes"]),
        "cannot be used: workspace 1 is not an object",
    ),
    "a rule that is not a decision": (
        a_policy(workspaces=[a_workspace(rules={"read_text": "maybe"})]),
        "workspace 1 has a rule that is not allow, ask or deny ('read_text': 'maybe')",
    ),
    "a person with no rules": (
        a_policy(workspaces=[a_workspace(people=[{"subject": "person-bo"}])]),
        "workspace 1, person 1 has no rules",
    ),
    "an access entry with no tools": (
        a_policy(access=[{"subject": "person-bo", "server": "git"}]),
        "access entry 1 has no list of tools",
    ),
    "workspaces that are not a list": (
        a_policy(workspaces="Notes"),
        "workspaces is not a list",
    ),
}


def policy_path(tmp_path: Path) -> Path:
    return tmp_path / "data" / "policy.json"


def host_over(tmp_path: Path, content: bytes | None) -> Host:
    """A host over a data directory whose policy file holds `content`."""
    settings = settings_for(tmp_path)
    if content is not None:
        policy_path(tmp_path).write_bytes(content)
    return Host(settings)


# --------------------------------------------------------------------------- #
# The loader names the file and what is wrong
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("case", list(BROKEN))
def test_a_file_that_cannot_be_used_is_refused_naming_the_file_and_the_fault(
    tmp_path: Path, case: str
) -> None:
    content, words = BROKEN[case]
    path = tmp_path / "policy.json"
    path.write_bytes(content)

    with pytest.raises(PolicyUnreadable) as caught:
        Policy.load(path, ADA)

    assert str(caught.value).startswith("policy.json "), "it must say which file, by its name"
    assert str(tmp_path) not in str(caught.value), "and not where it is"
    assert words in str(caught.value), str(caught.value)


def test_a_file_that_is_a_directory_is_refused_naming_what_the_system_said(
    tmp_path: Path,
) -> None:
    path = tmp_path / "policy.json"
    path.mkdir()

    with pytest.raises(PolicyUnreadable) as caught:
        Policy.load(path)

    assert str(caught.value).startswith("policy.json could not be read (")
    assert str(tmp_path) not in str(caught.value)


def test_a_policy_this_host_saved_loads(tmp_path: Path) -> None:
    """The check refuses nothing a host writes: every entry `Host` creates has
    the fields it asks for."""
    path = tmp_path / "policy.json"
    policy = Policy.load(path, ADA)
    policy.add_workspace(
        a_workspace(people=[{"subject": "person-bo", "rules": {"read_text": "allow"}}])
    )
    policy.set_enabled("git", True)
    policy.set_access(
        "git", [{"subject": "person-bo", "tools": [{"name": "log", "decision": None}]}]
    )

    again = Policy.load(path, ADA)

    assert again.workspaces == policy.workspaces and again.access == policy.access
    assert again.problem is None


def test_no_file_is_an_empty_policy(tmp_path: Path) -> None:
    policy = Policy.load(tmp_path / "policy.json", ADA)
    assert policy.problem is None and policy.workspaces == []


def test_an_unreadable_policy_is_never_saved_over_its_file(tmp_path: Path) -> None:
    path = tmp_path / "policy.json"
    path.write_bytes(b"{ not json, but the owner's rules are in here")
    policy = Policy.unreadable(path, ADA, PolicyUnreadable("it is broken"))

    with pytest.raises(PolicyUnreadable):
        policy.save()
    with pytest.raises(PolicyUnreadable):
        policy.add_workspace(a_workspace())

    assert path.read_bytes() == b"{ not json, but the owner's rules are in here"


# --------------------------------------------------------------------------- #
# The host starts, and runs nothing
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("case", list(BROKEN))
def test_a_host_over_a_policy_that_cannot_be_used_starts_and_says_why(
    tmp_path: Path, case: str, caplog: pytest.LogCaptureFixture
) -> None:
    content, words = BROKEN[case]
    with caplog.at_level(logging.ERROR):
        host = host_over(tmp_path, content)

    path = policy_path(tmp_path)
    reason = host.reason()
    assert reason is not None
    assert reason.startswith("This site's policy could not be used: ")
    assert "policy.json" in reason and words in reason, reason
    assert str(path) not in reason, "the reason goes to the root; the path is the log's"
    assert "Nothing runs here until the file is restored, or removed" in reason
    # Said in the log once, in the same words, and with where the file is.
    logged = [r.getMessage() for r in caplog.records if r.levelno == logging.ERROR]
    assert logged == [f"{reason} The file is {path}."]
    # The file is where it was, as it was, and a copy is beside it.
    assert path.read_bytes() == content
    assert (tmp_path / "data" / ("policy.json" + UNREADABLE_SUFFIX)).read_bytes() == content
    assert "A copy is kept as policy.json.unreadable." in reason
    # Allowing nothing is the whole of the policy that is run on.
    assert host.policy.workspaces == [] and host.policy.access == []
    assert not any(host.policy.enabled.values())


def test_a_host_over_a_directory_in_the_policys_place_starts_and_says_why(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    settings = settings_for(tmp_path)
    policy_path(tmp_path).mkdir()
    with caplog.at_level(logging.WARNING):
        host = Host(settings)

    reason = host.reason()
    assert reason is not None and "policy.json could not be read (" in reason
    assert str(policy_path(tmp_path)) not in reason
    # There is nothing to copy, and that is said, not raised.
    assert "A copy is kept" not in reason
    assert any("could not keep a copy" in r.getMessage() for r in caplog.records)


def test_a_policy_that_is_fine_leaves_no_copy_and_no_complaint(tmp_path: Path) -> None:
    host = host_over(tmp_path, a_policy())

    assert host.policy.problem is None and len(host.policy.workspaces) == 1
    assert not (tmp_path / "data" / ("policy.json" + UNREADABLE_SUFFIX)).exists()
    assert host.reason() is None


def test_the_copy_of_the_file_is_private(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """It holds people's rules: created asking for 0600, whole or not at all."""
    calls: list[tuple[str, int, int]] = []
    real = os.open

    def spy(path: Any, flags: int, mode: int = 0o777, *args: Any, **kw: Any) -> int:
        calls.append((os.fspath(path), flags, mode))
        return real(path, flags, mode, *args, **kw)

    monkeypatch.setattr(os, "open", spy)
    host_over(tmp_path, b"{ broken")

    made = [(f, m) for p, f, m in calls if Path(p).name.startswith(".policy.json.")]
    assert made and all(m == 0o600 and f & os.O_EXCL for f, m in made)
    assert [p.name for p in policy_path(tmp_path).parent.glob("*.tmp")] == []


@pytest.mark.parametrize("case", ["not JSON", "version 1", "a workspace with no holder"])
async def test_nothing_is_run_listed_or_changed_from_a_policy_that_cannot_be_used(
    tmp_path: Path, open_site: OpenSite, case: str
) -> None:
    content, _ = BROKEN[case]
    policy_path(tmp_path).parent.mkdir(parents=True, exist_ok=True)
    policy_path(tmp_path).write_bytes(content)
    site = await open_site(tmp_path, worker=False)
    reason = site.host.reason()
    assert reason is not None and "policy could not be used" in reason

    # A call is refused with it, before anything routes it.
    called = await site.mcp(ADA, FILES, "tools/list")
    assert called["status"] == "failed" and called["message"] == reason
    # So is every change; the file is not written over, and nothing is held.
    for action, arguments in (
        ("workspace.add", {"name": "notes", "path": str(tmp_path), "writable": False}),
        ("workspace.list", {}),
        ("settings.set", {"ownerInDevMode": True}),
    ):
        answer = await site.manage(ADA, action, approve=False, **arguments)
        assert answer == {"status": "failed", "message": reason}, (action, answer)
    assert site.host.held.for_subject(ADA) == []
    assert policy_path(tmp_path).read_bytes() == content
    # What does not depend on the policy still works: the audit log is read.
    audit = await site.host.manage(
        SiteManage.model_validate(
            {
                "id": secrets.token_hex(8),
                "expiresAt": time.time() + 20,
                "subject": ADA,
                "action": "audit.read",
                "arguments": {},
            }
        )
    )
    assert audit["status"] == "done"
    # And the refusals were recorded as every refusal is.
    assert any(row.get("reason") == reason for row in site.host.audit.newest(50)), (
        "the audit log did not record the refusal"
    )


def test_the_health_report_and_the_poll_both_name_the_file(tmp_path: Path) -> None:
    settings = settings_for(tmp_path)
    policy_path(tmp_path).write_bytes(V1_POLICY.encode("utf-8"))
    with TestClient(create_app(settings, channel=Idle())) as client:  # type: ignore[arg-type]
        answer = client.get("/healthz")
        report = client.app.state.host.summary()  # type: ignore[attr-defined]

    body = answer.json()
    assert answer.status_code == 503 and body["ready"] is False
    assert "policy.json is policy version 1, and this host reads version 2" in body["reason"]
    assert str(tmp_path) not in body["reason"], "the open health report carries no path"
    # What the site reports to its root says the same, and offers nothing.
    assert report is not None and report["workspaces"] == [] and report["access"] == []


# --------------------------------------------------------------------------- #
# Put right, it is read again; so is a file that is edited and still no good
# --------------------------------------------------------------------------- #


def test_a_policy_put_right_is_read_again_without_a_restart(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    host = host_over(tmp_path, V1_POLICY.encode("utf-8"))
    assert host.reason() is not None

    policy_path(tmp_path).write_bytes(a_policy())
    with caplog.at_level(logging.WARNING):
        assert host.reason() is None

    assert [w["name"] for w in host.policy.workspaces] == ["Notes"]
    assert any("reads again" in r.getMessage() for r in caplog.records)
    # The copy of the file that was no good stays: it is the owner's to remove.
    assert (tmp_path / "data" / ("policy.json" + UNREADABLE_SUFFIX)).read_bytes() == (
        V1_POLICY.encode("utf-8")
    )


def test_a_policy_removed_is_the_start_with_nothing_the_message_offers(tmp_path: Path) -> None:
    host = host_over(tmp_path, b"{ broken")
    assert host.reason() is not None

    policy_path(tmp_path).unlink()

    assert host.reason() is None
    assert host.policy.workspaces == []
    host.policy.add_workspace(a_workspace())  # and it can be saved again
    assert json.loads(policy_path(tmp_path).read_text(encoding="utf-8"))["version"] == VERSION


def test_a_file_edited_and_still_no_good_is_reported_as_it_is_now(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    host = host_over(tmp_path, b"{ broken")
    first = host.reason()
    assert first is not None and "is not valid JSON" in first
    caplog.clear()  # what the start said is not what is asked about
    # Left as it was, nothing more is said.
    with caplog.at_level(logging.ERROR):
        assert host.reason() == first and host.reason() == first
    assert caplog.records == []

    policy_path(tmp_path).write_bytes(V1_POLICY.encode("utf-8"))
    with caplog.at_level(logging.ERROR):
        second = host.reason()

    assert second is not None and "is policy version 1" in second
    assert [r.getMessage() for r in caplog.records] == [
        f"{second} The file is {policy_path(tmp_path)}."
    ]
    assert (tmp_path / "data" / ("policy.json" + UNREADABLE_SUFFIX)).read_bytes() == (
        V1_POLICY.encode("utf-8")
    )


# --------------------------------------------------------------------------- #
# A signature is not spent on a change that cannot be applied
# --------------------------------------------------------------------------- #


async def test_an_approval_is_refused_before_its_signature_is_spent(
    tmp_path: Path, open_site: OpenSite
) -> None:
    """A change held before a restart is approved after one, onto a policy
    that cannot be used: refused, with the signature still good."""
    first = await open_site(tmp_path, worker=False)
    folder = tmp_path / "notes"
    folder.mkdir()
    held = await first.manage(ADA, "workspace.add", approve=False, name="notes", path=str(folder))
    assert held["status"] == "held", held
    [item] = first.host.held.for_subject(ADA)
    await first.close()

    policy_path(tmp_path).write_bytes(V1_POLICY.encode("utf-8"))
    second = await open_site(tmp_path, worker=False)
    before = second.host.sequence.last(ADA)
    approved = await second.approve(item.id, ADA)

    assert approved["status"] == "failed"
    assert "policy could not be used" in approved["message"]
    assert second.host.sequence.last(ADA) == before, "the signature was spent"
    assert second.host.held.get(item.id) is not None, "the held change was dropped"
    assert policy_path(tmp_path).read_bytes() == V1_POLICY.encode("utf-8")


# --------------------------------------------------------------------------- #
# What the reason says: the file by its name, and only so much
#
# The reason is on the open /healthz, which "never carries a path, a name or a
# person", and in every report the site sends its root, which refuses a poll
# whose reason is over 1024 characters. On a per-user install the path holds
# the OS account's name.
# --------------------------------------------------------------------------- #

BACKSLASH = chr(92)

#: `maxLength` of every reason in the contract (`openapi/components/sites.yaml`,
#: five places): written out, so the code's own constant is not what it is
#: measured against.
CAP = 1024


def no_directory(text: str, tmp_path: Path) -> None:
    """`text` names `policy.json` and nothing of where it is: not the data
    directory, not a drive letter, not a separator in front of the name,
    whichever way this platform writes one."""
    assert "policy.json" in text, text
    for where in (tmp_path, policy_path(tmp_path).parent, policy_path(tmp_path)):
        assert str(where) not in text, text
    for separator in ("/", BACKSLASH):
        assert separator + "policy.json" not in text, text
    assert not re.search("[A-Za-z]:[/" + BACKSLASH * 2 + "]", text), text


def reported(tmp_path: Path, content: bytes) -> tuple[Host, dict[str, Any]]:
    """A host over `content` as its policy file, with one local server, and
    what its channel would send the root in the next poll."""
    settings = settings_for(tmp_path, local_servers=(local_server(),))
    policy_path(tmp_path).write_bytes(content)
    host = Host(settings)
    return host, Channel(host, Identity(settings.data_dir), settings).report()


@pytest.mark.parametrize("case", list(BROKEN))
def test_the_reason_names_the_file_and_not_the_directory_it_is_in(
    tmp_path: Path, case: str
) -> None:
    reason = host_over(tmp_path, BROKEN[case][0]).reason()

    assert reason is not None
    no_directory(reason, tmp_path)


def test_the_reason_for_a_directory_in_the_policys_place_names_no_path(tmp_path: Path) -> None:
    settings = settings_for(tmp_path)
    policy_path(tmp_path).mkdir()

    reason = Host(settings).reason()

    assert reason is not None
    no_directory(reason, tmp_path)


@pytest.mark.parametrize("case", ["not JSON", "version 1", "a rule that is not a decision"])
def test_the_open_health_report_names_no_path(tmp_path: Path, case: str) -> None:
    settings = settings_for(tmp_path)
    policy_path(tmp_path).write_bytes(BROKEN[case][0])
    with TestClient(create_app(settings, channel=Idle())) as client:  # type: ignore[arg-type]
        answer = client.get("/healthz")

    assert answer.status_code == 503
    no_directory(answer.json()["reason"], tmp_path)


@pytest.mark.parametrize("case", ["not JSON", "version 1", "a rule that is not a decision"])
def test_what_the_site_reports_to_its_root_names_no_path(tmp_path: Path, case: str) -> None:
    host, report = reported(tmp_path, BROKEN[case][0])

    SiteReport.model_validate(report)  # what the root checks the poll against
    [server] = report["site"]["servers"]
    for reason in (report["reason"], server["reason"]):
        no_directory(reason, tmp_path)
    view = host._server_view("fixture")
    SiteServer.model_validate(view)
    no_directory(view["reason"], tmp_path)


def test_the_log_still_says_where_the_file_is(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    with caplog.at_level(logging.ERROR):
        host_over(tmp_path, b"{ broken")

    [line] = [r.getMessage() for r in caplog.records if r.levelno == logging.ERROR]
    assert line.endswith(f"The file is {policy_path(tmp_path)}.")


JUNK = "x" * 3000

#: What the file supplied that the problem quotes, each 3000 characters long.
TOO_LONG: dict[str, bytes] = {
    "a rule's decision": a_policy(workspaces=[a_workspace(rules={"read_text": JUNK})]),
    "a rule's tool": a_policy(workspaces=[a_workspace(rules={JUNK: "maybe"})]),
    "a person's rule": a_policy(
        workspaces=[a_workspace(people=[{"subject": "person-bo", "rules": {"read_text": JUNK}}])]
    ),
    "a version": a_policy(version=JUNK),
    "a decision that is a list": a_policy(workspaces=[a_workspace(rules={"read_text": [JUNK]})]),
    "a decision that is an object": a_policy(
        workspaces=[a_workspace(rules={"read_text": {JUNK: JUNK}})]
    ),
    "a tool's decision on a server": a_policy(
        access=[
            {
                "subject": "person-bo",
                "server": "git",
                "tools": [{"name": "log", "decision": [JUNK]}],
            }
        ]
    ),
}


@pytest.mark.parametrize("case", list(TOO_LONG))
def test_a_long_value_in_the_file_cannot_make_the_reason_long_or_the_report_invalid(
    tmp_path: Path, case: str
) -> None:
    host, report = reported(tmp_path, TOO_LONG[case])

    reason = host.reason()
    assert reason is not None and len(reason) <= 600, len(reason or "")
    assert "x" * 100 not in reason, "the file's own words were not cut"
    no_directory(reason, tmp_path)
    # What the owner does next is whole, whatever the file held.
    assert "Nothing runs here until the file is restored, or removed" in reason
    assert reason.endswith("A copy is kept as policy.json.unreadable.")
    # And the poll carrying it is one the contract accepts: before, the root
    # refused it, and the site could not say why it was down.
    SiteReport.model_validate(report)
    assert report["reason"] == reason


def test_a_rule_that_is_a_long_decision_is_quoted_cut_and_marked(tmp_path: Path) -> None:
    reason = host_over(tmp_path, TOO_LONG["a rule's decision"]).reason()

    assert reason is not None
    assert "('read_text': '" + "x" * 30 in reason
    assert "x…)" in reason, "the cut is marked"


@pytest.mark.parametrize("decision", [["allow"], {"allow": True}, 5, None, True])
def test_a_decision_that_is_not_a_word_is_named_and_not_raised(
    tmp_path: Path, decision: Any
) -> None:
    """A list or an object is unhashable, and `decision in {"allow", ...}`
    raised `TypeError` out of the loader: the site did not start, instead of
    running on nothing and saying why."""
    policy_path(tmp_path).parent.mkdir(parents=True, exist_ok=True)
    policy_path(tmp_path).write_bytes(
        a_policy(workspaces=[a_workspace(rules={"read_text": decision})])
    )

    with pytest.raises(PolicyUnreadable, match="has a rule that is not allow, ask or deny"):
        Policy.load(policy_path(tmp_path), ADA)
    assert "policy.json" in str(host_over(tmp_path, None).reason())


@pytest.mark.parametrize("decision", [["allow"], {"allow": True}, 5, True])
def test_a_tool_decision_on_a_server_that_is_not_a_word_is_named_and_not_raised(
    tmp_path: Path, decision: Any
) -> None:
    policy_path(tmp_path).parent.mkdir(parents=True, exist_ok=True)
    policy_path(tmp_path).write_bytes(
        a_policy(
            access=[
                {
                    "subject": "person-bo",
                    "server": "git",
                    "tools": [{"name": "log", "decision": decision}],
                }
            ]
        )
    )

    with pytest.raises(PolicyUnreadable, match="has a tool whose decision is not allow"):
        Policy.load(policy_path(tmp_path), ADA)


def test_the_whole_problem_is_cut_at_the_limit_and_keeps_what_the_owner_does_next(
    tmp_path: Path,
) -> None:
    """Whatever a source puts in `PolicyUnreadable`: the fault is what is cut,
    never the part that says what to do or where the copy is."""
    policy = Policy.unreadable(
        tmp_path / "policy.json",
        ADA,
        PolicyUnreadable("y" * 5000),
        tmp_path / ("policy.json" + UNREADABLE_SUFFIX),
    )

    assert PROBLEM_LIMIT == 600
    assert policy.problem is not None and len(policy.problem) == 600
    assert policy.problem.startswith("This site's policy could not be used: yyy")
    assert "y…. Nothing runs here until the file is restored, or removed" in policy.problem
    assert policy.problem.endswith("A copy is kept as policy.json.unreadable.")


def test_a_short_problem_is_left_exactly_as_it_was() -> None:
    policy = Policy.unreadable(
        Path("policy.json"), ADA, PolicyUnreadable("policy.json is not valid JSON (x)")
    )

    assert policy.problem == (
        "This site's policy could not be used: policy.json is not valid JSON (x). "
        "Nothing runs here until the file is restored, or removed to start with no workspaces."
    )


async def test_a_reason_over_the_contracts_cap_is_cut_wherever_the_report_carries_one(
    tmp_path: Path, open_site: OpenSite, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The backstop. Each source bounds its own reason (the policy's problem is
    cut at 600), and this is what a source that does not cannot take the
    report down with: the root refuses a poll carrying a reason over 1024
    characters, in any of the five places the contract caps one."""
    site = await open_site(tmp_path, worker=False, local_servers=(local_server(),))
    host = site.host
    host.policy.add_workspace(a_workspace())  # so the file server is in the report too
    # Four sources of a reason that are not the policy's, each far over the cap.
    host.workers.problem = "w" * 5000
    monkeypatch.setattr(Host, "_not_running", lambda self, link, own: "n" * 5000)
    monkeypatch.setattr(Host, "_commands_reason", lambda self, state: "c" * 5000)

    report = Channel(host, host.identity, host.settings).report()

    SiteReport.model_validate(report)
    summary = report["site"]
    SiteSummary.model_validate(summary)
    assert len(report["reason"]) == CAP
    assert {s["id"]: len(s["reason"]) for s in summary["servers"]} == {FILES: CAP, "fixture": CAP}
    assert [len(link["reason"]) for link in summary["links"]] == [CAP]
    assert len(summary["commands"]["reason"]) == CAP
    for server in (FILES, "fixture"):
        view = host._server_view(server)
        SiteServer.model_validate(view)
        assert len(view["reason"]) == CAP


def test_a_reason_within_the_cap_is_never_touched() -> None:
    assert REASON_LIMIT == CAP
    assert clipped(None) is None
    assert clipped("") == ""
    assert clipped("w" * CAP) == "w" * CAP
    assert clipped("w" * (CAP + 1)) == "w" * (CAP - 1) + "…"
