"""A person's worker: what it checks on its own, without trusting the site
host (§3.2) — who it runs as, which programs it may run, which paths are
never a folder."""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path
from typing import Any

import pytest
import yaml

from eugene_plexus_site_host import accounts, folder_io, local_channel, worker
from eugene_plexus_site_host.local_channel import MAX_FRAME
from eugene_plexus_site_host.policy import default_groups, per_tool
from eugene_plexus_site_host.worker import Worker, WorkerError

from .conftest import ADA, BO, OpenSite, link_entry, local_server, rpc, write_links

FILES = "files"
SID = "S-1-5-21-1-2-3-1001"


def bare(tmp_path: Path, **own: Any) -> Worker:
    values: dict[str, Any] = {
        "account": local_channel.own_account(),
        "channel": "unused",
        "host": "someone-else",
        "servers": (),
        "protected": [],
        "workspace": tmp_path / "workspace",
    }
    values.update(own)
    return Worker(**values)


def folder_work(path: Path, name: str = "Notes") -> dict[str, Any]:
    return {
        "kind": "files",
        "folders": {name: {"path": str(path), "identity": folder_io.inspect(str(path), [])}},
        "writable": [],
    }


def listing(name: str = "Notes", path: str = ".") -> dict[str, Any]:
    return rpc(
        "tools/call", {"name": "list_directory", "arguments": {"folder": name, "path": path}}
    )


# --- which programs it may run --------------------------------------------------


async def test_a_server_the_workers_own_list_lacks_is_refused_whatever_the_site_host_says(
    tmp_path: Path,
) -> None:
    entry = local_server()
    empty = bare(tmp_path)
    for message in (
        {"op": "tools", "server": "fixture", "fresh": True},
        {"op": "mcp", "work": {"kind": "local", "server": "fixture"}, "request": rpc("tools/list")},
    ):
        with pytest.raises(WorkerError, match="not on this machine's list"):
            await empty.handle(message)
    # Naming the program in the message changes nothing: the list is the worker's.
    with pytest.raises(WorkerError, match="not on this machine's list"):
        await empty.handle(
            {
                "op": "mcp",
                "work": {"kind": "local", "server": "evil", "command": entry.command},
                "request": rpc("tools/list"),
            }
        )
    listed = await bare(tmp_path, servers=(entry,)).handle(
        {"op": "tools", "server": "fixture", "fresh": True}
    )
    assert {t["name"] for t in listed["tools"]} == {"echo", "touch"}


async def test_through_the_site_a_server_only_the_hosts_list_has_cannot_be_turned_on(
    open_site: OpenSite,
) -> None:
    site = await open_site(local_servers=(local_server(),), worker=False)
    await site.start_worker(servers=())  # this worker's own list is empty
    refused = await site.manage(ADA, "server.enable", server="fixture", enabled=True)
    assert refused["status"] == "failed" and "not on this machine's list" in refused["message"]
    assert site.host.policy.enabled.get("fixture") in (None, False)


async def test_the_worker_checks_the_programs_hash_the_site_host_does_not(
    tmp_path: Path, open_site: OpenSite
) -> None:
    changed = local_server(sha="0" * 64)
    with pytest.raises(WorkerError, match="changed since an administrator added it"):
        await bare(tmp_path, servers=(changed,)).handle(
            {"op": "tools", "server": "fixture", "fresh": True}
        )
    site = await open_site(local_servers=(local_server(),), worker=False)
    await site.start_worker(servers=(changed,))
    refused = await site.manage(ADA, "server.enable", server="fixture", enabled=True)
    assert refused["status"] == "failed" and "changed since" in refused["message"]


def test_the_local_server_list_is_read_by_the_worker_itself(tmp_path: Path) -> None:
    path = tmp_path / "servers.yaml"
    entry = {"id": "fixture", "name": "X", "command": "/bin/x", "sha256": "a" * 64}
    path.write_text(yaml.safe_dump({"servers": [entry]}), encoding="utf-8")
    assert [s.id for s in worker.read_servers(path)] == ["fixture"]
    assert worker.read_servers(None) == ()
    assert worker.read_servers(tmp_path / "missing.yaml") == ()


def test_an_unreadable_server_list_means_no_servers_and_says_so(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    path = tmp_path / "servers.yaml"
    path.write_text("servers: [ {id: x} ]", encoding="utf-8")
    assert worker.read_servers(path) == ()
    path.write_text("servers: [", encoding="utf-8")
    assert worker.read_servers(path) == ()
    assert capsys.readouterr().err.count("could not be read") == 2


# --- which paths are never a folder --------------------------------------------


async def test_a_folder_inside_the_workers_protected_roots_is_refused_though_the_host_allows_it(
    tmp_path: Path, open_site: OpenSite
) -> None:
    secret = tmp_path / "private"
    secret.mkdir()
    (secret / "node.yaml").write_text("secret", encoding="utf-8")
    work = folder_work(secret)
    # Without the root protected it reads: the protection is what refuses.
    open_read = await bare(tmp_path).handle({"op": "mcp", "work": work, "request": listing()})
    assert open_read["response"]["result"]["isError"] is False
    guarded = bare(tmp_path, protected=[secret])
    refused = await guarded.handle({"op": "mcp", "work": work, "request": listing()})
    assert refused["response"]["result"]["isError"] is True
    assert "node.yaml" not in json.dumps(refused)
    # Registering one is refused too.
    inspected = await guarded.handle({"op": "inspect", "path": str(secret)})
    assert inspected["problem"] == "unsafe" and "path" not in inspected

    # Through the site: the host's protected roots lack `secret`, the worker's has it.
    site = await open_site(worker=False)
    await site.start_worker()
    record = {
        "id": "f1",
        "name": "Secret",
        "path": str(secret),
        "identity": work["folders"]["Notes"]["identity"],
        "holder": ADA,
        "writable": False,
        "rules": per_tool(default_groups(False)),
        "deny": [],
        "people": [{"subject": BO, "rules": per_tool({"read": "allow", "change": "deny"})}],
    }
    site.host.policy.add_workspace(record)
    # Written behind the site's back, so approved at the machine first (J52).
    assert (await site.confirm_rules())["status"] == "done"
    read = {"name": "read_text", "arguments": {"folder": "Secret", "path": "node.yaml"}}
    control = await site.mcp(BO, FILES, "tools/call", read)
    assert control["status"] == "done" and "secret" in json.dumps(control["response"]), control
    # The worker's own protected roots grow; the site host's list never did.
    assert site.worker is not None
    site.worker.protected.append(secret)
    answer = await site.mcp(BO, FILES, "tools/call", read)
    assert answer["status"] == "done" and answer["response"]["result"]["isError"] is True
    assert "secret" not in json.dumps(answer["response"])


async def test_inspect_says_missing_and_denied_and_unsafe(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    w = bare(tmp_path)
    found = await w.handle({"op": "inspect", "path": str(tmp_path)})
    assert found["path"] and found["identity"]
    assert (await w.handle({"op": "inspect", "path": str(tmp_path / "nope")}))[
        "problem"
    ] == "missing"

    def denied(*_a: Any) -> Any:
        raise PermissionError("no")

    monkeypatch.setattr(folder_io, "inspect", denied)
    assert (await w.handle({"op": "inspect", "path": str(tmp_path)}))["problem"] == "denied"
    with pytest.raises(WorkerError, match="not valid"):
        await w.handle({"op": "inspect", "path": 5})


async def test_a_worker_answers_ping_and_refuses_what_it_does_not_know(tmp_path: Path) -> None:
    w = bare(tmp_path)
    assert await w.handle({"op": "ping"}) == {}
    with pytest.raises(WorkerError, match="does not know that request"):
        await w.handle({"op": "format-the-disk"})
    for work in (None, {"kind": "shell"}, {"kind": "files", "folders": [], "writable": {}}):
        with pytest.raises(WorkerError, match="not valid"):
            await w.handle({"op": "mcp", "work": work, "request": rpc("tools/list")})
    with pytest.raises(WorkerError, match="2026-07-28"):
        await w.handle(
            {
                "op": "mcp",
                "work": {"kind": "files", "folders": {}, "writable": []},
                "request": rpc("tools/list", version="2025-11-25"),
            }
        )


async def test_an_answer_too_large_for_the_channel_is_a_refusal_not_a_hang(
    open_site: OpenSite,
) -> None:
    site = await open_site()
    assert site.worker is not None

    async def big(_message: dict[str, Any]) -> dict[str, Any]:
        return {"pad": "x" * MAX_FRAME}

    site.worker.handle = big  # type: ignore[method-assign]
    answer = await site.host.workers.call(site.account, {"op": "ping"}, 10)
    assert answer["ok"] is False and "larger than the local channel" in answer["message"]


async def test_a_worker_the_site_host_refuses_says_so_and_stops(
    open_site: OpenSite, capsys: pytest.CaptureFixture[str]
) -> None:
    site = await open_site(worker=False)
    path = site.host.settings.links_file
    assert path is not None
    write_links(path, link_entry(ADA, "S-1-5-21-9-9-9-9" if sys.platform == "win32" else "4242"))
    w = bare(
        site.host.settings.data_dir,
        channel=site.host.settings.channel,
        host=site.account,
    )
    # It stops for good: `run()` returns rather than reconnecting, and its
    # starter decides whether to start another.
    await asyncio.wait_for(w.run(), 10)
    assert "the site host refused this worker" in capsys.readouterr().err


# --- who it runs as ---------------------------------------------------------------


@pytest.mark.parametrize(
    ("account", "why"),
    [
        ("S-1-5-18", "a system account"),
        ("S-1-5-19", "a system account"),
        ("S-1-5-20", "a system account"),
        ("S-1-5-80-1-2-3-4-5", "a service or virtual account"),
        ("S-1-5-82-1-2-3-4-5", "a service or virtual account"),
        ("S-1-5-90-0-1", "a service or virtual account"),
        ("S-1-5-96-0-1", "a service or virtual account"),
        ("S-1-5-32-544", "not a person's account"),
        ("S-1-1-0", "not a person's account"),
        (SID, None),
        ("S-1-12-1-111-222-333-444", None),
        ("0", "root"),
        ("65534", "a system account" if sys.platform == "darwin" else "nobody"),
        ("1000", None),
        ("123456", None),
        ("jessie", "not an account this system knows"),
        ("", "not an account this system knows"),
    ],
)
def test_who_is_never_a_person(account: str, why: str | None) -> None:
    assert accounts.not_a_person(account) == why


@pytest.mark.parametrize(
    ("platform", "uid", "why"),
    [
        ("linux", "999", "a system account"),
        ("linux", "1", "a system account"),
        ("linux", "500", "a system account"),
        ("linux", "1000", None),
        ("darwin", "499", "a system account"),
        ("darwin", "500", None),
        ("darwin", "501", None),
    ],
)
def test_the_lowest_uid_of_a_person_depends_on_the_system(
    monkeypatch: pytest.MonkeyPatch, platform: str, uid: str, why: str | None
) -> None:
    monkeypatch.setattr(accounts.sys, "platform", platform)
    assert accounts.not_a_person(uid) == why


def serving_as(monkeypatch: pytest.MonkeyPatch, account: str, *, elevated: bool = False) -> None:
    monkeypatch.setattr(accounts, "own", lambda: account)
    monkeypatch.setattr(accounts, "elevated", lambda: elevated)


def test_a_worker_run_as_the_wrong_account_refuses_to_serve(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    serving_as(monkeypatch, SID)
    why = accounts.refuse_to_serve("S-1-5-21-1-2-3-1002", "S-1-5-21-1-2-3-1500")
    assert why is not None and "not the account it was started for" in why
    assert SID in why


@pytest.mark.parametrize(
    ("account", "words"),
    [
        ("S-1-5-18", "system account"),
        ("S-1-5-80-1-2-3-4-5", "service or virtual account"),
        ("S-1-5-32-544", "not a person's account"),
        ("0", "root"),
        ("65534", "never a person's"),
    ],
)
def test_a_worker_never_serves_as_a_system_or_service_account_or_root(
    monkeypatch: pytest.MonkeyPatch, account: str, words: str
) -> None:
    serving_as(monkeypatch, account)
    why = accounts.refuse_to_serve(account, "S-1-5-21-1-2-3-1500")
    assert why is not None and words in why


def test_a_worker_on_a_linux_system_uid_is_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(accounts.sys, "platform", "linux")
    serving_as(monkeypatch, "500")
    why = accounts.refuse_to_serve("500", "1500")
    assert why is not None and "system account" in why


def test_a_worker_never_serves_as_the_site_hosts_own_account(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    serving_as(monkeypatch, SID)
    why = accounts.refuse_to_serve(SID, SID)
    assert why is not None and "site host's own account" in why


def test_a_per_user_worker_shares_the_site_hosts_account_when_its_starter_says_so(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # A per-user install (J38): the site host runs as the one person it
    # serves. Only the starter's explicit word makes that acceptable.
    serving_as(monkeypatch, SID)
    assert accounts.refuse_to_serve(SID, SID, shared=True) is None
    # Saying so does not excuse anything else.
    serving_as(monkeypatch, SID, elevated=True)
    why = accounts.refuse_to_serve(SID, SID, shared=True)
    assert why is not None and "elevated" in why
    serving_as(monkeypatch, "S-1-5-18")
    assert accounts.refuse_to_serve("S-1-5-18", "S-1-5-18", shared=True) is not None


def test_an_elevated_worker_is_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    serving_as(monkeypatch, SID, elevated=True)
    why = accounts.refuse_to_serve(SID, "S-1-5-21-1-2-3-1500")
    assert why is not None and "elevated" in why


def test_a_person_in_their_own_account_may_serve(monkeypatch: pytest.MonkeyPatch) -> None:
    serving_as(monkeypatch, SID)
    assert accounts.refuse_to_serve(SID, "S-1-5-21-1-2-3-1500") is None
    assert accounts.refuse_to_serve(SID, None) is None


def test_the_command_line_refuses_before_it_connects(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    serving_as(monkeypatch, "S-1-5-18")

    def never(*_a: Any, **_k: Any) -> Any:
        raise AssertionError("served")

    monkeypatch.setattr(worker.asyncio, "run", never)
    monkeypatch.setattr(local_channel, "connect", never)
    with pytest.raises(SystemExit, match="system account"):
        worker.main(["--account", "S-1-5-18", "--channel", "x", "--host", SID])
    with pytest.raises(SystemExit, match="not the account"):
        worker.main(["--account", SID, "--channel", "x", "--host", "S-1-5-21-9-9-9-9"])


def test_the_real_account_is_the_one_the_system_reports() -> None:
    mine = accounts.own()
    assert mine == local_channel.own_account()
    if sys.platform == "win32":
        assert mine.startswith("S-1-5-")
    else:
        assert mine.isdigit()


async def test_naming_servers_or_roots_in_a_call_changes_neither_list(tmp_path: Path) -> None:
    """The site host's message can name no program and no protected root: both
    are the worker's own."""
    entry = local_server()
    named = {
        "kind": "local",
        "server": "fixture",
        "servers": [entry.model_dump(mode="json", by_alias=True)],
    }
    with pytest.raises(WorkerError, match="not on this machine's list"):
        await bare(tmp_path).handle({"op": "mcp", "work": named, "request": rpc("tools/list")})
    secret = tmp_path / "private"
    secret.mkdir()
    (secret / "node.yaml").write_text("secret", encoding="utf-8")
    work = {**folder_work(secret), "protected": []}
    refused = await bare(tmp_path, protected=[secret]).handle(
        {"op": "mcp", "work": work, "request": listing()}
    )
    assert refused["response"]["result"]["isError"] is True


async def test_a_worker_another_worker_replaced_stops_for_good(open_site: OpenSite) -> None:
    site = await open_site()
    assert site.task is not None
    first = site.task
    settings = site.host.settings
    assert settings.channel is not None
    second = Worker(
        account=site.account,
        channel=settings.channel,
        host=site.account,
        servers=(),
        protected=[],
        workspace=settings.data_dir,
    )
    replacing = asyncio.create_task(second.run())
    try:
        # It ends rather than reconnecting and trading the connection back.
        await asyncio.wait_for(first, 10)
    finally:
        replacing.cancel()


def test_the_command_line_hands_the_worker_what_it_was_started_with(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(accounts, "own", lambda: SID)
    monkeypatch.setattr(accounts, "elevated", lambda: False)
    made: list[dict[str, Any]] = []

    class Capture:
        def __init__(self, **kwargs: Any) -> None:
            made.append(kwargs)

        async def run(self) -> None:
            return None

    monkeypatch.setattr(worker, "Worker", Capture)
    servers = tmp_path / "servers.yaml"
    servers.write_text(
        yaml.safe_dump(
            {"servers": [{"id": "fixture", "name": "X", "command": "/bin/x", "sha256": "a" * 64}]}
        ),
        encoding="utf-8",
    )
    kept = tmp_path / "keep"
    # The site host's own account is this worker's, and the starter says so.
    worker.main(
        [
            "--account", SID, "--channel", "x", "--host", SID, "--shared-account",
            "--servers", str(servers), "--protect", str(kept), "--workspace", str(tmp_path),
        ]
    )  # fmt: skip
    assert len(made) == 1
    assert [s.id for s in made[0]["servers"]] == ["fixture"]
    assert kept in made[0]["protected"] and Path(worker.__file__).parent in made[0]["protected"]
