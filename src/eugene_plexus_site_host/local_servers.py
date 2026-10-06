"""Local MCP servers a machine administrator added at the machine (§6.2).

Each is a program on this machine, spoken to over stdio by the SDK, and
presented to the root as an MCP server like Eugene's own folders are. The
administrator added it with an elevated CLI, which wrote it into the
install's protected configuration with the program's SHA-256; the agent
hands that list to the host at start (`settings.py`). Who may use it, and
whether it is on at all, is the site owner's policy.

**A program that changed since it was added is not run.** **A server marked
`system`** could alter the operating system, so it does not run without an
administrator's consent, recorded at the machine with the program's hash
(J9). No such server ships with Eugene; the gate exists for the first one.

These programs run in the worker of whoever calls them, as that person, or
as the site's owner for someone with no link (J27): trusted code the
administrator chose, not sandboxes. Their standard error is discarded,
because a program can print the credentials in its environment there.
"""

from __future__ import annotations

import asyncio
import hashlib
import os
import sys
import time
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import mcp_types as types
from mcp import Client
from mcp.client.stdio import StdioServerParameters, stdio_client
from mcp.server.lowlevel import Server

from ._generated.models import SiteLocalServer
from .file_server import Outcome

MAX_PROCESSES = 4
TOOLS_SECONDS = 300.0
CALL_SECONDS = 20.0
MAX_TOOLS = 64
_PRIVATE_HOME = (
    "HOME",
    "USERPROFILE",
    "APPDATA",
    "LOCALAPPDATA",
    "TEMP",
    "TMP",
    "TMPDIR",
    "XDG_CACHE_HOME",
    "XDG_CONFIG_HOME",
    "XDG_DATA_HOME",
)


class LocalServerError(Exception):
    """An observed failure, safe to show: it names no argument or variable."""


def program_hash(command: str) -> str:
    digest = hashlib.sha256()
    with open(command, "rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def environment_for(workspace: Path, command: str, extra: dict[str, str]) -> dict[str, str]:
    """A system PATH, the program's own directory, the administrator's
    values, and a home that is the server's own workspace."""
    system = os.environ.get("SYSTEMROOT", r"C:\Windows")
    path = os.pathsep.join(
        [str(Path(command).parent), str(Path(system) / "System32"), system]
        if os.name == "nt"
        else [str(Path(command).parent), "/usr/local/bin", "/usr/bin", "/bin"]
    )
    env = {"PATH": path, "PYTHONUNBUFFERED": "1", "PYTHONUTF8": "1", **extra}
    env.update({key: str(workspace) for key in _PRIVATE_HOME})
    if os.name == "nt":
        env["HOMEDRIVE"] = workspace.drive
        env["HOMEPATH"] = str(workspace)[len(workspace.drive) :]
        env["SYSTEMROOT"] = system
    return env


@dataclass
class _Listing:
    at: float
    tools: list[types.Tool]


class LocalServers:
    def __init__(
        self, entries: tuple[SiteLocalServer, ...], data_dir: Path, *, verify: bool = True
    ) -> None:
        self.entries = {e.id: e for e in entries}
        self.data_dir = data_dir
        #: Whether `problem()` reads the program to check its hash. The site
        #: host does not (it may not be able to read a program in a person's
        #: own folders, and runs none); each worker does, before every run.
        self.verify = verify
        self.active = 0
        self._hashes: dict[str, tuple[int, int, str]] = {}
        self._listings: dict[str, _Listing] = {}

    # --- whether it may run ---------------------------------------------------

    def problem(self, entry: SiteLocalServer) -> str | None:
        """Why this server cannot run, or None. Checks the program and the
        administrator's consent, not the owner's policy."""
        command = Path(entry.command)
        if not command.is_absolute():
            return f"{entry.name}: its program must be named by its full path."
        if os.name == "nt" and command.suffix.lower() != ".exe":
            return f"{entry.name}: on Windows its program must be an .exe."
        if entry.system and entry.consentedAt is None:
            return (
                f"{entry.name} can change this machine's system, and no administrator has "
                "consented at the machine. An administrator runs "
                f"`eugene-plexus-agent site server add --system` there."
            )
        if not self.verify:
            return None
        try:
            info = command.stat()
        except OSError:
            return f"{entry.name}: its program is not on this machine any more."
        known = self._hashes.get(entry.id)
        if known is None or known[:2] != (info.st_mtime_ns, info.st_size):
            try:
                known = (info.st_mtime_ns, info.st_size, program_hash(entry.command))
            except OSError:
                return f"{entry.name}: its program cannot be read."
            self._hashes[entry.id] = known
        if known[2] != entry.sha256:
            return (
                f"{entry.name}: its program changed since an administrator added it. "
                "Add it again at the machine to run the new one."
            )
        return None

    # --- talking to it --------------------------------------------------------

    def _parameters(self, entry: SiteLocalServer) -> StdioServerParameters:
        command, args = entry.command, [a.root for a in entry.args or []]
        if os.name != "nt":
            # The guard owns the process group, so the SDK's stop reaps the
            # server's own children too (C5b).
            args = ["-I", "-u", str(Path(__file__).with_name("_stdio_guard.py")), command, *args]
            command = sys.executable
        workspace = (self.data_dir / "tools" / entry.id).resolve()
        workspace.mkdir(parents=True, exist_ok=True, mode=0o700)
        return StdioServerParameters(
            command=command,
            args=args,
            cwd=workspace,
            env=environment_for(workspace, entry.command, dict(entry.env or {})),
        )

    @asynccontextmanager
    async def client(self, entry: SiteLocalServer) -> AsyncIterator[Any]:
        if self.active >= MAX_PROCESSES:
            raise LocalServerError(
                f"{MAX_PROCESSES} local servers are running on this machine. Try again shortly."
            )
        self.active += 1
        try:
            params = await asyncio.to_thread(self._parameters, entry)
            with open(os.devnull, "w", encoding="utf-8") as errors:  # noqa: ASYNC230
                transport = stdio_client(params, errlog=errors)
                async with Client(
                    transport, read_timeout_seconds=CALL_SECONDS, cache=None
                ) as client:
                    yield client
        finally:
            self.active -= 1

    async def tools(self, entry: SiteLocalServer, *, fresh: bool = False) -> list[types.Tool]:
        """The server's tools, listed by starting it; kept five minutes."""
        listing = self._listings.get(entry.id)
        if listing and not fresh and time.perf_counter() - listing.at < TOOLS_SECONDS:
            return listing.tools
        found: list[types.Tool] = []
        async with self.client(entry) as client:
            cursor = None
            for _ in range(8):
                page = await client.list_tools(cursor=cursor)
                found.extend(page.tools)
                cursor = page.next_cursor
                if cursor is None:
                    break
        if len(found) > MAX_TOOLS:
            raise LocalServerError(f"{entry.name} offers more than {MAX_TOOLS} tools.")
        self._listings[entry.id] = _Listing(time.perf_counter(), found)
        return found

    def stale(self, entry: SiteLocalServer) -> bool:
        listing = self._listings.get(entry.id)
        return listing is None or time.perf_counter() - listing.at >= TOOLS_SECONDS

    def known_tools(self, entry: SiteLocalServer) -> list[types.Tool]:
        listing = self._listings.get(entry.id)
        return listing.tools if listing else []

    def forget(self, server_id: str) -> None:
        self._listings.pop(server_id, None)

    def remember(self, server_id: str, tools: list[types.Tool]) -> None:
        """A tool list a worker reported, kept as if listed here."""
        if len(tools) > MAX_TOOLS:
            raise LocalServerError(f"{server_id} offers more than {MAX_TOOLS} tools.")
        self._listings[server_id] = _Listing(time.perf_counter(), list(tools))

    def server(self, entry: SiteLocalServer, outcome: Outcome) -> Server:
        """An in-process MCP server that forwards to the program, for one request."""

        async def list_tools(_ctx: Any, _params: Any) -> types.ListToolsResult:
            return types.ListToolsResult(tools=await self.tools(entry))

        async def call_tool(_ctx: Any, params: types.CallToolRequestParams) -> types.CallToolResult:
            sent = False
            try:
                async with self.client(entry) as client:
                    sent = True
                    result: types.CallToolResult = await client.session.call_tool(
                        params.name, dict(params.arguments or {}), read_timeout_seconds=CALL_SECONDS
                    )
                    return result
            except LocalServerError as exc:
                return types.CallToolResult(
                    content=[types.TextContent(type="text", text=str(exc))], is_error=True
                )
            except Exception as exc:
                if not sent:
                    return types.CallToolResult(
                        content=[
                            types.TextContent(
                                type="text",
                                text=f"{entry.name} could not be started ({type(exc).__name__}). "
                                "Nothing ran. Check its program at the machine.",
                            )
                        ],
                        is_error=True,
                    )
                # Sent, and no answer: it may have acted.
                outcome.uncertain = (
                    f"{entry.name} did not answer this call ({type(exc).__name__}). "
                    "It may have acted. Check before trying again."
                )
                return types.CallToolResult(
                    content=[types.TextContent(type="text", text=outcome.uncertain)], is_error=True
                )

        return Server(entry.id, on_list_tools=list_tools, on_call_tool=call_tool)
