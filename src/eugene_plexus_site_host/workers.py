"""The site host's end of the local channel: one worker per linked account.

A worker connects; the operating system says which account it runs as
(`local_channel.py`); an account in no link is refused and disconnected. A
second worker for one account replaces the first. A link removed later ends
that account's connection at the next check (`prune`).

Calls carry an id and are answered in any order; one that is not answered in
time is a timeout, and the caller decides whether it may have acted.
"""

from __future__ import annotations

import asyncio
import contextlib
import secrets
from typing import Any

from . import local_channel
from .links import Links


class WorkerAbsent(Exception):
    """No worker is connected for that account."""


class WorkerTimeout(Exception):
    """The worker did not answer in time; a call may have acted."""


class WorkerGone(Exception):
    """The worker went away before it answered; a call may have acted."""


class _Worker:
    def __init__(self, conn: local_channel.Connection) -> None:
        self.conn = conn
        self.pending: dict[str, asyncio.Future[dict[str, Any]]] = {}
        self.task: asyncio.Task[None] | None = None

    def fail_all(self) -> None:
        for future in self.pending.values():
            if not future.done():
                future.set_exception(WorkerGone())
        self.pending.clear()


class Workers:
    def __init__(self, links: Links, channel: str | None, own_account: str | None) -> None:
        self.links = links
        self.channel = channel
        self.own_account = own_account
        self.problem: str | None = None
        self._by_account: dict[str, _Worker] = {}
        self._server: local_channel.Server | None = None

    async def start(self) -> None:
        if not self.channel or not self.own_account:
            self.problem = "This site was started with no channel for its workers."
            return
        try:
            self._server = await local_channel.serve(self.channel, self.own_account, self._accept)
        except (local_channel.ChannelError, OSError) as exc:
            self.problem = (
                str(exc)
                if isinstance(exc, local_channel.ChannelError)
                else (f"This site's channel for its workers could not be opened ({exc}).")
            )

    async def stop(self) -> None:
        for worker in list(self._by_account.values()):
            await self._drop(worker)
        if self._server is not None:
            await self._server.close()

    async def _accept(self, conn: local_channel.Connection) -> None:
        link = self.links.for_account(conn.account)
        if link is None:
            with contextlib.suppress(Exception):
                await conn.send(
                    {
                        "t": "refused",
                        "message": "This account is not linked to anyone on this site.",
                    }
                )
            await conn.close()
            return
        old = self._by_account.get(conn.account)
        worker = _Worker(conn)
        self._by_account[conn.account] = worker
        if old is not None:
            # The one it replaces stops for good rather than reconnecting, so
            # a worker left behind by an earlier starter never trades the
            # connection back and forth with its replacement.
            with contextlib.suppress(Exception):
                await old.conn.send({"t": "replaced"})
            await self._drop(old)
        worker.task = asyncio.create_task(self._read(worker))

    async def _read(self, worker: _Worker) -> None:
        try:
            while True:
                try:
                    message = await worker.conn.receive()
                except local_channel.ChannelError:
                    message = None
                if message is None:
                    return
                if message.get("t") != "result":
                    continue
                future = worker.pending.pop(str(message.get("id")), None)
                if future is not None and not future.done():
                    future.set_result(message)
        finally:
            if self._by_account.get(worker.conn.account) is worker:
                del self._by_account[worker.conn.account]
            worker.fail_all()
            with contextlib.suppress(Exception):
                await worker.conn.close()

    async def _drop(self, worker: _Worker) -> None:
        if self._by_account.get(worker.conn.account) is worker:
            del self._by_account[worker.conn.account]
        worker.fail_all()
        with contextlib.suppress(Exception):
            await worker.conn.close()
        if worker.task is not None and worker.task is not asyncio.current_task():
            worker.task.cancel()

    async def prune(self) -> None:
        """End the connection of any account no longer in a link."""
        for account, worker in list(self._by_account.items()):
            if self.links.for_account(account) is None:
                await self._drop(worker)

    def connected(self, account: str) -> bool:
        return account in self._by_account

    async def call(self, account: str, message: dict[str, Any], seconds: float) -> dict[str, Any]:
        worker = self._by_account.get(account)
        if worker is None:
            raise WorkerAbsent
        ident = secrets.token_hex(12)
        future: asyncio.Future[dict[str, Any]] = asyncio.get_running_loop().create_future()
        worker.pending[ident] = future
        try:
            await worker.conn.send({**message, "t": "call", "id": ident})
            return await asyncio.wait_for(future, seconds)
        except TimeoutError:
            raise WorkerTimeout from None
        except (local_channel.ChannelError, OSError, ConnectionError):
            raise WorkerGone from None
        finally:
            worker.pending.pop(ident, None)
