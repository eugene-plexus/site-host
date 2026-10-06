"""A person's worker: their tools, run as them (§2.4, §3.2, J24, J27).

    python -I -m eugene_plexus_site_host.worker --account <SID or uid>
        --channel <pipe name or socket path> --host <SID or uid>
        [--servers <file>] [--protect <path>]... [--workspace <dir>]

The machine's privileged starter runs one for each linked person, as that
person: the agent on Windows, with their session token while they are signed
in (J25); root's `eugene-plexus-site-worker@<uid>.service` on a Linux
system install; the agent's own child on a per-user install.

**Before it serves anything** it checks that it runs as `--account`, that
this is a person's account and not elevated (`accounts.py`), and that the
far end of the channel is `--host`, the site host's own account. Then it
says hello and answers what the site host sends:

- `mcp`: one MCP request to the file server (the folders the site host
  resolved for this call, each still confined to its folder and checked
  against this worker's own protected roots) or to a local server, which
  must be on the list this worker reads itself (`--servers`). The site host
  never names a program for it to run.
- `inspect`: a folder's identity, when its owner registers it.
- `tools`: a local server's tool list.

The site host has already checked the site's policy; this process adds what
it can know without trusting the site host: who it is, which programs it
may run, and which paths are never a folder.
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import os
import sys
import time
from pathlib import Path
from typing import Any

import yaml
from pydantic import ValidationError

from . import accounts, dispatch, file_server, folder_io, local_channel
from ._generated.models import SiteLocalServerList
from .local_servers import LocalServers

PROTOCOL = 1
MAX_CALLS = 8
RETRY_SECONDS = (1, 2, 5, 10, 15)


class WorkerError(Exception):
    """A request this worker answers with a refusal; the message says why."""


class Stopped(Exception):
    """The site host refused this worker, or another took its place: it
    stops rather than reconnect. Its starter decides whether to start one."""


def read_servers(path: Path | None) -> tuple[Any, ...]:
    """The local servers an administrator added at the machine, read here and
    never taken from the site host."""
    if path is None:
        return ()
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        listed = SiteLocalServerList.model_validate(raw)
    except FileNotFoundError:
        return ()
    except (OSError, yaml.YAMLError, ValidationError):
        print("eugene-plexus-site-worker: the local-server list could not be read", file=sys.stderr)
        return ()
    return tuple(listed.servers)


def default_workspace() -> Path:
    if sys.platform == "win32":
        base = os.environ.get("LOCALAPPDATA") or str(Path.home() / "AppData" / "Local")
        return Path(base) / "EugenePlexus" / "site-worker"
    base = os.environ.get("XDG_STATE_HOME") or str(Path.home() / ".local" / "state")
    return Path(base) / "eugene-plexus-site-worker"


class Worker:
    def __init__(
        self,
        *,
        account: str,
        channel: str,
        host: str,
        servers: tuple[Any, ...],
        protected: list[Path],
        workspace: Path,
    ) -> None:
        self.account = account
        self.channel = channel
        self.host = host
        self.protected = protected
        self.local = LocalServers(servers, workspace)
        self._slots = asyncio.Semaphore(MAX_CALLS)

    # --- the requests --------------------------------------------------------

    async def handle(self, message: dict[str, Any]) -> dict[str, Any]:
        op = message.get("op")
        if op == "mcp":
            return await self._mcp(message)
        if op == "inspect":
            return await self._inspect(message)
        if op == "tools":
            return await self._tools(message)
        if op == "ping":
            return {}
        raise WorkerError("This worker does not know that request. Update Eugene on this machine.")

    def _entry(self, server: Any) -> Any:
        entry = self.local.entries.get(str(server))
        if entry is None:
            raise WorkerError("That server is not on this machine's list.")
        if problem := self.local.problem(entry):
            raise WorkerError(problem)
        return entry

    async def _mcp(self, message: dict[str, Any]) -> dict[str, Any]:
        request = message.get("request")
        work = message.get("work")
        if not isinstance(request, dict) or not isinstance(work, dict):
            raise WorkerError("This request is not valid.")
        try:
            dispatch.check(request)
        except dispatch.NotServed as exc:
            raise WorkerError(str(exc)) from None
        outcome = file_server.Outcome()
        if work.get("kind") == "files":
            folders = work.get("folders")
            writable = work.get("writable")
            if not isinstance(folders, dict) or not isinstance(writable, list):
                raise WorkerError("This request is not valid.")
            server = file_server.server(
                folders, frozenset(str(w) for w in writable), list(self.protected), outcome
            )
        elif work.get("kind") == "local":
            server = self.local.server(self._entry(work.get("server")), outcome)
        else:
            raise WorkerError("This request is not valid.")
        response = await dispatch.exchange(server, request)
        return {"response": response, "uncertain": outcome.uncertain}

    async def _inspect(self, message: dict[str, Any]) -> dict[str, Any]:
        path = message.get("path")
        if not isinstance(path, str):
            raise WorkerError("This request is not valid.")
        try:
            full = folder_io.check_root_path(path, self.protected)
            identity = await asyncio.to_thread(folder_io.inspect, full, self.protected)
        except folder_io.FolderError as exc:
            return {"problem": "unsafe", "message": str(exc)}
        except PermissionError:
            return {"problem": "denied"}
        except FileNotFoundError:
            return {"problem": "missing"}
        except (OSError, ValueError):
            return {"problem": "unsafe"}
        return {"path": full, "identity": identity}

    async def _tools(self, message: dict[str, Any]) -> dict[str, Any]:
        entry = self._entry(message.get("server"))
        listed = await self.local.tools(entry, fresh=bool(message.get("fresh")))
        return {
            "tools": [t.model_dump(mode="json", by_alias=True, exclude_none=True) for t in listed]
        }

    # --- the channel ---------------------------------------------------------

    async def _answer(self, conn: local_channel.Connection, message: dict[str, Any]) -> None:
        async with self._slots:
            ident = message.get("id")
            try:
                result = await self.handle(message)
                reply = {"t": "result", "id": ident, "ok": True, **result}
            except WorkerError as exc:
                reply = {"t": "result", "id": ident, "ok": False, "message": str(exc)}
            except Exception as exc:
                reply = {
                    "t": "result",
                    "id": ident,
                    "ok": False,
                    "failed": type(exc).__name__,
                }
            try:
                await conn.send(reply)
            except local_channel.ChannelError:
                await conn.send(
                    {
                        "t": "result",
                        "id": ident,
                        "ok": False,
                        "message": "The answer is larger than the local channel carries. "
                        "Ask for less.",
                    }
                )

    async def serve_once(self) -> None:
        conn = await local_channel.connect(
            self.channel,
            self.host,
            {"protocol": PROTOCOL, "pid": os.getpid(), "account": self.account},
        )
        tasks: set[asyncio.Task[None]] = set()
        try:
            while True:
                message = await conn.receive()
                if message is None:
                    return
                if message.get("t") == "refused":
                    print(
                        f"eugene-plexus-site-worker: the site host refused this worker: "
                        f"{message.get('message')}",
                        file=sys.stderr,
                    )
                    raise Stopped
                if message.get("t") == "replaced":
                    print(
                        "eugene-plexus-site-worker: another worker for this account took over",
                        file=sys.stderr,
                    )
                    raise Stopped
                if message.get("t") != "call":
                    continue
                task = asyncio.create_task(self._answer(conn, message))
                tasks.add(task)
                task.add_done_callback(tasks.discard)
        finally:
            for task in tasks:
                task.cancel()
            with contextlib.suppress(Exception):
                await conn.close()

    async def run(self) -> None:
        attempt = 0
        while True:
            started = time.perf_counter()
            try:
                await self.serve_once()
            except Stopped:
                return
            except local_channel.ChannelError as exc:
                print(f"eugene-plexus-site-worker: {exc}", file=sys.stderr)
            if time.perf_counter() - started > 60:
                attempt = 0
            await asyncio.sleep(RETRY_SECONDS[min(attempt, len(RETRY_SECONDS) - 1)])
            attempt += 1


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="eugene-plexus-site-worker")
    parser.add_argument("--account", required=True, help="the person's SID or uid")
    parser.add_argument("--channel", required=True, help="the site host's pipe or socket")
    parser.add_argument("--host", required=True, help="the site host's SID or uid")
    parser.add_argument("--servers", help="the local-server list")
    parser.add_argument("--protect", action="append", default=[], help="never a folder")
    parser.add_argument("--workspace", help="where local servers keep their own files")
    parser.add_argument(
        "--shared-account",
        action="store_true",
        help="the site host runs as this same person (a per-user install, J38)",
    )
    args = parser.parse_args(argv)
    if why := accounts.refuse_to_serve(args.account, args.host, shared=args.shared_account):
        sys.exit(f"eugene-plexus-site-worker: {why}")
    protected = [Path(sys.prefix), Path(__file__).parent, *(Path(p) for p in args.protect)]
    worker = Worker(
        account=args.account,
        channel=args.channel,
        host=args.host,
        servers=read_servers(Path(args.servers) if args.servers else None),
        protected=protected,
        workspace=Path(args.workspace) if args.workspace else default_workspace(),
    )
    with contextlib.suppress(KeyboardInterrupt):
        asyncio.run(worker.run())


if __name__ == "__main__":
    main()
