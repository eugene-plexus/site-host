"""The site host's side of the channel: one worker per linked account, an
unlinked account refused, a newer worker replacing an older one, and calls
that end as an answer, a timeout, or a worker that went away."""

from __future__ import annotations

import asyncio
import contextlib
import os
import sys
import time
from collections.abc import AsyncIterator, Callable
from pathlib import Path
from typing import Any

import pytest

from eugene_plexus_site_host import local_channel
from eugene_plexus_site_host.links import Links
from eugene_plexus_site_host.local_channel import Connection
from eugene_plexus_site_host.workers import WorkerAbsent, WorkerGone, Workers, WorkerTimeout

from .conftest import OTHER_ACCOUNT, drop_channel, link_entry, new_channel, write_links

ME = local_channel.own_account()


async def until(check: Callable[[], bool], seconds: float = 10.0) -> None:
    deadline = time.perf_counter() + seconds
    while not check():
        if time.perf_counter() > deadline:
            raise AssertionError("the condition never came true")
        await asyncio.sleep(0.02)


def bump(path: Path, seconds: int) -> None:
    """Make the file look changed even inside one timestamp tick."""
    stamp = path.stat()
    os.utime(path, ns=(stamp.st_atime_ns, stamp.st_mtime_ns + seconds * 1_000_000_000))


class Rig:
    def __init__(self, path: Path, workers: Workers, channel: str) -> None:
        self.path = path
        self.workers = workers
        self.channel = channel
        self.clients: list[Connection] = []

    async def worker(self) -> Connection:
        conn = await local_channel.connect(self.channel, ME, {"protocol": 1})
        self.clients.append(conn)
        return conn


@pytest.fixture
async def rig(tmp_path: Path) -> AsyncIterator[Rig]:
    path = tmp_path / "links.json"
    write_links(path, link_entry("p1", ME, "me"))
    channel = new_channel()
    workers = Workers(Links(path), channel, ME)
    await workers.start()
    assert workers.problem is None, workers.problem
    made = Rig(path, workers, channel)
    yield made
    for conn in made.clients:
        with contextlib.suppress(Exception):
            await conn.close()
    await workers.stop()
    drop_channel(channel)


async def answer_calls(conn: Connection) -> None:
    """A worker that answers every call with its own message back."""
    while (message := await conn.receive()) is not None:
        if message.get("t") == "call":
            await conn.send({"t": "result", "id": message["id"], "ok": True, "echo": message})


async def test_a_linked_account_connects_and_is_called(rig: Rig) -> None:
    conn = await rig.worker()
    serving = asyncio.create_task(answer_calls(conn))
    await until(lambda: rig.workers.connected(ME))
    answer = await rig.workers.call(ME, {"op": "ping", "n": 1}, 5)
    assert answer["ok"] is True and answer["echo"]["op"] == "ping" and answer["echo"]["n"] == 1
    assert answer["echo"]["t"] == "call" and answer["id"] == answer["echo"]["id"]
    assert not rig.workers.connected(OTHER_ACCOUNT)
    await conn.close()
    await asyncio.wait_for(serving, 5)


async def test_an_unlinked_account_is_refused_and_disconnected(rig: Rig) -> None:
    write_links(rig.path, link_entry("p1", OTHER_ACCOUNT, "someone"))
    bump(rig.path, 5)
    conn = await rig.worker()
    first = await asyncio.wait_for(conn.receive(), 10)
    assert first is not None and first["t"] == "refused" and "not linked" in first["message"]
    assert await asyncio.wait_for(conn.receive(), 10) is None
    assert not rig.workers.connected(ME)
    with pytest.raises(WorkerAbsent):
        await rig.workers.call(ME, {"op": "ping"}, 1)


async def test_a_second_worker_for_the_account_replaces_the_first(rig: Rig) -> None:
    old = await rig.worker()
    await until(lambda: rig.workers.connected(ME))
    new = await rig.worker()
    # The old one is told it was replaced, so it stops rather than
    # reconnecting, and the site host ends its connection...
    assert await asyncio.wait_for(old.receive(), 10) == {"t": "replaced"}
    assert await asyncio.wait_for(old.receive(), 10) is None
    # ...and the account stays connected, through the new one.
    serving = asyncio.create_task(answer_calls(new))
    await until(lambda: rig.workers.connected(ME))
    answer = await rig.workers.call(ME, {"op": "ping"}, 5)
    assert answer["ok"] is True
    await new.close()
    await asyncio.wait_for(serving, 5)
    await until(lambda: not rig.workers.connected(ME))


async def test_pruning_after_the_link_is_removed_disconnects_the_worker(rig: Rig) -> None:
    conn = await rig.worker()
    await until(lambda: rig.workers.connected(ME))
    await rig.workers.prune()
    assert rig.workers.connected(ME), "a still-linked account is kept"
    write_links(rig.path)
    bump(rig.path, 5)
    await rig.workers.prune()
    assert not rig.workers.connected(ME)
    assert await asyncio.wait_for(conn.receive(), 10) is None


async def test_a_call_that_is_not_answered_times_out_and_leaves_nothing_pending(
    rig: Rig,
) -> None:
    conn = await rig.worker()
    await until(lambda: rig.workers.connected(ME))
    started = time.perf_counter()
    with pytest.raises(WorkerTimeout):
        await rig.workers.call(ME, {"op": "slow"}, 0.3)
    assert 0.25 < time.perf_counter() - started < 5
    heard = await asyncio.wait_for(conn.receive(), 5)
    assert heard is not None and heard["op"] == "slow"
    # The worker is still connected, and a later call still works.
    serving = asyncio.create_task(answer_calls(conn))
    assert (await rig.workers.call(ME, {"op": "again"}, 5))["ok"] is True
    await conn.close()
    await asyncio.wait_for(serving, 5)


async def test_a_worker_that_goes_away_mid_call_is_gone_not_a_timeout(rig: Rig) -> None:
    conn = await rig.worker()
    await until(lambda: rig.workers.connected(ME))

    async def die_on_first_call() -> None:
        await conn.receive()
        await conn.close()

    dying = asyncio.create_task(die_on_first_call())
    started = time.perf_counter()
    with pytest.raises(WorkerGone):
        await rig.workers.call(ME, {"op": "x"}, 20)
    assert time.perf_counter() - started < 10, "gone was noticed, not waited out"
    await dying
    await until(lambda: not rig.workers.connected(ME))


async def test_calls_in_flight_are_matched_by_id_whatever_order_they_end(rig: Rig) -> None:
    conn = await rig.worker()
    await until(lambda: rig.workers.connected(ME))

    async def reverse() -> None:
        held: list[dict[str, Any]] = []
        while len(held) < 3:
            message = await conn.receive()
            assert message is not None
            held.append(message)
        for message in reversed(held):
            await conn.send(
                {"t": "result", "id": message["id"], "ok": True, "which": message["which"]}
            )

    serving = asyncio.create_task(reverse())
    answers = await asyncio.gather(
        *(rig.workers.call(ME, {"op": "x", "which": n}, 10) for n in range(3))
    )
    assert [a["which"] for a in answers] == [0, 1, 2]
    await serving


async def test_a_message_that_is_not_a_result_is_ignored(rig: Rig) -> None:
    conn = await rig.worker()
    await until(lambda: rig.workers.connected(ME))

    async def noisy() -> None:
        message = await conn.receive()
        assert message is not None
        await conn.send({"t": "chatter"})
        await conn.send({"t": "result", "id": "someone-elses", "ok": True})
        await conn.send({"t": "result", "id": message["id"], "ok": True, "fine": True})

    serving = asyncio.create_task(noisy())
    assert (await rig.workers.call(ME, {"op": "x"}, 5))["fine"] is True
    await serving


async def test_no_channel_is_a_problem_not_a_crash(tmp_path: Path) -> None:
    workers = Workers(Links(None), None, ME)
    await workers.start()
    assert workers.problem is not None and "no channel" in workers.problem
    assert not workers.connected(ME)
    await workers.stop()


@pytest.mark.skipif(sys.platform != "win32", reason="a taken pipe name is a Windows property")
async def test_a_taken_channel_name_is_said_in_the_problem(rig: Rig, tmp_path: Path) -> None:
    second = Workers(Links(None), rig.channel, ME)
    await second.start()
    assert second.problem is not None and "already holds" in second.problem
    await second.stop()
    # The first still takes workers.
    await rig.worker()
    await until(lambda: rig.workers.connected(ME))
