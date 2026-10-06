"""The channel between the site host and a worker (§3.2): who is at the other
end is read from the operating system, frames are bounded, and a client
that finds the wrong account serving refuses to say anything."""

from __future__ import annotations

import asyncio
import contextlib
import sys
from collections.abc import AsyncIterator
from dataclasses import dataclass, field
from typing import Any

import pytest

from eugene_plexus_site_host import local_channel
from eugene_plexus_site_host.local_channel import MAX_FRAME, ChannelError, Connection

from .conftest import OTHER_ACCOUNT, drop_channel, new_channel

WINDOWS = sys.platform == "win32"


@dataclass
class Harness:
    channel: str
    server: local_channel.Server
    accepted: list[Connection] = field(default_factory=list)
    arrivals: asyncio.Queue[Connection] = field(default_factory=asyncio.Queue)

    async def next(self) -> Connection:
        return await asyncio.wait_for(self.arrivals.get(), 10)


@pytest.fixture
async def harness() -> AsyncIterator[Harness]:
    channel = new_channel()
    seen: list[Harness] = []

    async def accept(conn: Connection) -> None:
        seen[0].accepted.append(conn)
        await seen[0].arrivals.put(conn)

    server = await local_channel.serve(channel, local_channel.own_account(), accept)
    seen.append(Harness(channel, server))
    yield seen[0]
    for conn in seen[0].accepted:
        with contextlib.suppress(Exception):
            await conn.close()
    with contextlib.suppress(Exception):
        await server.close()
    drop_channel(channel)


async def raw_send(conn: Connection, data: bytes) -> None:
    """Bytes onto the wire with none of `send`'s own bound, to play a peer
    that does not keep it."""
    if WINDOWS:
        await asyncio.to_thread(conn.pipe.write_all, data)  # type: ignore[attr-defined]
    else:
        conn.writer.write(data)  # type: ignore[attr-defined]
        await conn.writer.drain()  # type: ignore[attr-defined]


async def test_the_server_learns_the_account_from_the_system_and_keeps_the_hello(
    harness: Harness,
) -> None:
    me = local_channel.own_account()
    client = await local_channel.connect(harness.channel, me, {"protocol": 1, "account": "LIES"})
    server_side = await harness.next()
    # What the worker claims is kept as the hello and never as its account.
    assert server_side.account == me
    assert server_side.hello["t"] == "hello" and server_side.hello["account"] == "LIES"
    assert client.account == me
    await client.send({"t": "ping"})
    assert await asyncio.wait_for(server_side.receive(), 10) == {"t": "ping"}
    await server_side.send({"t": "pong"})
    assert await asyncio.wait_for(client.receive(), 10) == {"t": "pong"}
    await client.close()


async def test_a_frame_over_the_limit_is_refused_going_out(harness: Harness) -> None:
    client = await local_channel.connect(harness.channel, local_channel.own_account(), {})
    await harness.next()
    with pytest.raises(ChannelError, match="256 KiB"):
        await client.send({"t": "big", "pad": "x" * MAX_FRAME})
    # Just under the bound still goes.
    await client.send({"t": "ok", "pad": "x" * (MAX_FRAME - 100)})
    await client.close()


async def test_a_frame_over_the_limit_is_refused_coming_in(harness: Harness) -> None:
    client = await local_channel.connect(harness.channel, local_channel.own_account(), {})
    server_side = await harness.next()
    await raw_send(client, b'{"t":"x","pad":"' + b"x" * (MAX_FRAME + 10) + b'"}\n')
    with pytest.raises(ChannelError, match="256 KiB"):
        await asyncio.wait_for(server_side.receive(), 10)
    await client.close()


async def test_a_message_that_is_not_json_is_refused(harness: Harness) -> None:
    client = await local_channel.connect(harness.channel, local_channel.own_account(), {})
    server_side = await harness.next()
    await raw_send(client, b"not json\n")
    with pytest.raises(ChannelError, match="not JSON"):
        await asyncio.wait_for(server_side.receive(), 10)
    await raw_send(client, b"[1,2]\n")
    with pytest.raises(ChannelError, match="not a message"):
        await asyncio.wait_for(server_side.receive(), 10)
    await client.close()


async def test_a_client_that_finds_the_wrong_account_serving_says_nothing(
    harness: Harness,
) -> None:
    """The server here is this process's account; a worker told the site host
    is someone else must refuse before it sends a hello."""
    with pytest.raises(ChannelError):
        await local_channel.connect(harness.channel, OTHER_ACCOUNT, {"secret": "hello"})
    await asyncio.sleep(0.5)
    assert harness.accepted == []


@pytest.mark.skipif(not WINDOWS, reason="a taken pipe name is a Windows property")
async def test_a_second_server_on_a_taken_pipe_name_is_refused(harness: Harness) -> None:
    async def never(_conn: Connection) -> None:
        raise AssertionError("a second server accepted")

    with pytest.raises(ChannelError, match="already holds"):
        await local_channel.serve(harness.channel, local_channel.own_account(), never)
    # The first still serves.
    client = await local_channel.connect(harness.channel, local_channel.own_account(), {})
    await harness.next()
    await client.close()


@pytest.mark.skipif(WINDOWS, reason="a socket path that is not ours is POSIX")
async def test_a_path_that_is_not_a_socket_is_not_taken_over(tmp_path: Any) -> None:
    path = tmp_path / "channel"
    path.write_text("a file", encoding="utf-8")

    async def never(_conn: Connection) -> None:
        raise AssertionError("served")

    with pytest.raises(ChannelError, match="Remove it"):
        await local_channel.serve(str(path), local_channel.own_account(), never)
    assert path.read_text(encoding="utf-8") == "a file"


async def test_after_the_site_host_closes_connecting_says_it_is_not_running() -> None:
    channel = new_channel()

    async def accept(_conn: Connection) -> None:
        return None

    server = await local_channel.serve(channel, local_channel.own_account(), accept)
    await server.close()
    try:
        with pytest.raises(ChannelError, match=r"not running|could not be reached"):
            await local_channel.connect(channel, local_channel.own_account(), {})
    finally:
        drop_channel(channel)


async def test_a_channel_that_never_existed_says_it_is_not_running() -> None:
    channel = new_channel()
    try:
        with pytest.raises(ChannelError, match="not running"):
            await local_channel.connect(channel, local_channel.own_account(), {})
    finally:
        drop_channel(channel)


async def test_several_calls_in_flight_are_answered_out_of_order(harness: Harness) -> None:
    client = await local_channel.connect(harness.channel, local_channel.own_account(), {})
    server_side = await harness.next()

    async def serve_calls() -> None:
        async def reply(message: dict[str, Any]) -> None:
            await asyncio.sleep(message["delay"])
            await server_side.send({"t": "result", "id": message["id"]})

        tasks = []
        while True:
            message = await server_side.receive()
            if message is None:
                break
            tasks.append(asyncio.create_task(reply(message)))
        await asyncio.gather(*tasks)

    serving = asyncio.create_task(serve_calls())
    for ident, delay in (("a", 0.4), ("b", 0.05), ("c", 0.2)):
        await client.send({"t": "call", "id": ident, "delay": delay})
    order = [(await asyncio.wait_for(client.receive(), 10) or {})["id"] for _ in range(3)]
    assert order == ["b", "c", "a"]
    await client.close()
    await asyncio.wait_for(serving, 10)


async def test_a_closed_connection_reads_as_gone_at_the_other_end(harness: Harness) -> None:
    client = await local_channel.connect(harness.channel, local_channel.own_account(), {})
    server_side = await harness.next()
    await client.close()
    assert await asyncio.wait_for(server_side.receive(), 10) is None


# --- the pipe's own security (Windows) ---------------------------------------------------


def _capture(monkeypatch: pytest.MonkeyPatch, name: str) -> list[tuple[Any, ...]]:
    """Record every call to one of the module's Win32 entry points, then make it."""
    real = getattr(local_channel, name)
    calls: list[tuple[Any, ...]] = []

    def spy(*args: Any) -> Any:
        calls.append(args)
        return real(*args)

    monkeypatch.setattr(local_channel, name, spy)
    return calls


@pytest.mark.skipif(not WINDOWS, reason="a pipe's security descriptor is Windows's")
async def test_the_pipe_is_owned_by_the_site_host_and_grants_clients_only_data_rights(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sddl = _capture(monkeypatch, "_ConvertSddl")
    created = _capture(monkeypatch, "_CreateNamedPipeW")
    opened = _capture(monkeypatch, "_CreateFileW")
    me = local_channel.own_account()
    channel = new_channel()

    async def accept(_conn: Connection) -> None:
        return None

    server = await local_channel.serve(channel, me, accept)
    try:
        client = await local_channel.connect(channel, me, {})
        await client.close()
    finally:
        await server.close()
        drop_channel(channel)
    text = sddl[0][0]
    # The owner is named, so a client can tell who made the pipe it opened.
    assert text.startswith(f"O:{me}D:P(")
    aces = text.split("D:P", 1)[1]
    assert aces == f"(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;{me})(A;;0x{local_channel.CLIENT_ACCESS:x};;;AU)"
    # Clients read and write data and read the pipe's security, and can never make
    # another instance of it (FILE_CREATE_PIPE_INSTANCE, 0x4), nor hold a generic right.
    assert local_channel.CLIENT_ACCESS == 0x00120083
    assert not local_channel.CLIENT_ACCESS & 0x4
    assert not local_channel.CLIENT_ACCESS & 0xF0000000
    # Only the machine's own clients: the first instance is exclusive, none is remote.
    assert created and all(call[2] & local_channel.PIPE_REJECT_REMOTE_CLIENTS for call in created)
    assert created[0][1] & local_channel.FILE_FLAG_FIRST_PIPE_INSTANCE
    assert not any(call[1] & local_channel.FILE_FLAG_FIRST_PIPE_INSTANCE for call in created[1:])
    # A worker lets the site host learn who it is and never act as it.
    flags = opened[0][5]
    assert flags & local_channel.SECURITY_SQOS_PRESENT
    assert flags & local_channel.SECURITY_IDENTIFICATION


@pytest.mark.skipif(not WINDOWS, reason="the impersonation is Windows's")
async def test_a_thread_that_cannot_revert_from_a_worker_ends_the_process(
    harness: Harness, monkeypatch: pytest.MonkeyPatch
) -> None:
    exits: list[int] = []
    real = local_channel._RevertToSelf

    def failing() -> bool:
        real()
        return False

    monkeypatch.setattr(local_channel, "_RevertToSelf", failing)
    monkeypatch.setattr(local_channel.os, "_exit", exits.append)
    client = await local_channel.connect(harness.channel, local_channel.own_account(), {})
    await harness.next()
    assert exits == [70]
    await client.close()


@pytest.mark.skipif(not WINDOWS, reason="the first frame is read from a raw pipe on Windows")
async def test_a_first_frame_that_is_not_a_hello_is_not_served(harness: Harness) -> None:
    pipe = local_channel._open_client(harness.channel, local_channel.own_account())
    try:
        await asyncio.to_thread(pipe.write_all, b'{"t":"call","id":"x"}\n')
        await asyncio.sleep(0.5)
        assert harness.accepted == []
    finally:
        pipe.close()


@pytest.mark.skipif(not WINDOWS, reason="the first frame is read from a raw pipe on Windows")
async def test_a_first_frame_over_the_limit_is_dropped_at_once(harness: Harness) -> None:
    pipe = local_channel._open_client(harness.channel, local_channel.own_account())
    try:
        await asyncio.to_thread(pipe.write_all, b"x" * (MAX_FRAME + 10))
        # The site host closes the pipe; waiting for a newline instead would
        # hold it until the hello deadline.
        answer = await asyncio.to_thread(pipe.read, 2000)
        assert answer == b"" and harness.accepted == []
    finally:
        pipe.close()


async def test_bytes_with_no_end_of_line_are_refused_at_the_limit(harness: Harness) -> None:
    client = await local_channel.connect(harness.channel, local_channel.own_account(), {})
    server_side = await harness.next()
    await raw_send(client, b"x" * (MAX_FRAME + 10))
    with pytest.raises(ChannelError, match="256 KiB"):
        await asyncio.wait_for(server_side.receive(), 10)
    await client.close()
