"""Every request checked against this machine's policy, then served (J8).

The order for an MCP request is fixed, and every refusal stops it before
anything runs:

1. The operation's id has not been used and its deadline has not passed,
   so a replayed operation runs at most once.
2. It is one of the three methods of MCP 2026-07-28.
3. Tools can run on this machine at all (an isolated account).
4. The server exists and is on.
5. The person may use it (`site` mode: this machine's own list; `node`
   mode: the root's grants that came with the call). On the file server
   that means at least one folder (J6g).
6. For `tools/call`: the tool is one the person may use, and a destructive
   tool has a standing pre-approval. On the file server, the `folder` it
   names is one they may use, and for `write_text` one they may change.

Then the SDK serves it, `tools/list` is cut to the person's tools (the file
server's `folder` argument to their folders), and the call is recorded in
the audit log, as every refusal is.

A management action is taken from the owner this site pinned at its join,
and from nobody else, Eugene's owner included (J6b). On an ordinary node the
only action is the root's request to inspect a folder.
"""

from __future__ import annotations

import asyncio
import contextlib
import importlib.metadata
import json
import secrets
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any

import mcp_types as types
from mcp.server.lowlevel import Server
from pydantic import BaseModel, ValidationError

from . import _build, dispatch, file_server, folder_io
from ._generated.models import (
    SiteAccessSet,
    SiteAuditRead,
    SiteCall,
    SiteFolderAdd,
    SiteFolderInspect,
    SiteFolderPeople,
    SiteFolderRemove,
    SiteGrantHint,
    SiteLocalServer,
    SiteManage,
    SiteServerEnable,
    SiteSettings,
)
from .audit import Audit
from .local_servers import LocalServerError, LocalServers
from .policy import Policy
from .settings import Settings

PROTOCOL = "mcp-2026-07-28"
MAX_ANSWER = 70_000
OPERATOR = "operator"
FILES = file_server.SERVER
READING = {"list_directory": False, "read_text": False}


class Refused(Exception):
    """The site's refusal, in its own words. Nothing ran."""


def is_destructive(tool: types.Tool) -> bool:
    """MCP's own defaults: a tool not marked read-only may change something,
    unless it says `destructiveHint: false`."""
    annotations = tool.annotations
    if annotations is None:
        return True
    if annotations.read_only_hint:
        return False
    return annotations.destructive_hint is not False


def tool_view(tool: types.Tool) -> dict[str, Any]:
    title = tool.title or (tool.annotations.title if tool.annotations else None)
    return {
        "name": tool.name,
        "title": title,
        "description": (tool.description or "")[:2048] or None,
        "readOnly": bool(tool.annotations and tool.annotations.read_only_hint),
        "destructive": is_destructive(tool),
    }


def version() -> str:
    try:
        return _build.commit() or importlib.metadata.version("eugene-plexus-site-host")
    except importlib.metadata.PackageNotFoundError:
        return "dev"


@dataclass
class Target:
    """One server, resolved for one request: what it offers and what this
    person may use of it (a tool name, and whether it is pre-approved). For
    the file server, also the folders they may use by name, and which of
    those they may change."""

    id: str
    name: str
    tools: dict[str, types.Tool]
    allowed: dict[str, bool]
    make: Callable[[file_server.Outcome], Server]
    folders: dict[str, dict[str, Any]] | None = None
    writable: frozenset[str] = frozenset()


class Host:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.audit = Audit(settings.data_dir)
        self.policy = (
            Policy.load(settings.data_dir / "policy.json") if settings.mode == "site" else None
        )
        self.local = LocalServers(settings.local_servers, settings.data_dir)
        self.lock = asyncio.Lock()
        self.used: dict[str, float] = {}
        self._refreshing: set[str] = set()
        self._tasks: set[asyncio.Task[None]] = set()

    @property
    def protected(self) -> list[Any]:
        return list(self.settings.protected)

    # --- once, and in time ------------------------------------------------------

    def _fresh(self, ident: str, expires: float) -> None:
        now = time.time()
        self.used = {k: until for k, until in self.used.items() if until >= now}
        if not ident or ident in self.used or not now < expires <= now + 30:
            raise Refused("This operation expired or was already used.")
        if len(self.used) >= 4096:
            raise Refused("Too many operations at once. Try again shortly.")
        self.used[ident] = expires

    # --- MCP --------------------------------------------------------------------

    async def mcp(self, call: SiteCall) -> dict[str, Any]:
        request = call.request.model_dump(mode="json", exclude_none=True, by_alias=True)
        method = str(request.get("method"))
        params = request.get("params") or {}
        tool = params.get("name") if method == "tools/call" else None
        entry: dict[str, Any] = {
            "subject": call.subject,
            "kind": "mcp",
            "server": call.server,
            "method": method,
            "tool": tool if isinstance(tool, str) else None,
            "arguments": params.get("arguments") if method == "tools/call" else None,
        }
        try:
            self._fresh(call.id, call.expiresAt)
            try:
                dispatch.check(request)
            except dispatch.NotServed as exc:
                raise Refused(str(exc)) from None
            if reason := self.settings.unavailable():
                raise Refused(reason)
            target = await self._target(call)
            if not target.allowed:
                raise Refused(self._not_listed(target))
            if method == "tools/call":
                self._may_call(target, tool, params.get("arguments"))
        except Refused as exc:
            self.audit.record(**entry, decision="refused", reason=str(exc))
            return {"status": "failed", "message": str(exc)}

        outcome = file_server.Outcome()
        try:
            response = await dispatch.exchange(target.make(outcome), request)
        except Exception as exc:
            status = "uncertain" if method == "tools/call" else "failed"
            message = f"{target.name} did not answer ({type(exc).__name__})." + (
                " It may have acted. Check before trying again." if status == "uncertain" else ""
            )
            self.audit.record(**entry, decision="allowed", outcome=status, reason=message)
            return {"status": status, "message": message}
        if method == "tools/list" and isinstance(response.get("result"), dict):
            listed = response["result"].get("tools") or []
            response["result"]["tools"] = [t for t in listed if t.get("name") in target.allowed]
        status = "uncertain" if outcome.uncertain else "done"
        if len(json.dumps(response, ensure_ascii=False).encode()) > MAX_ANSWER:
            message = "The answer is larger than 70,000 bytes. Ask for less."
            self.audit.record(**entry, decision="allowed", outcome="failed", reason=message)
            return {
                "status": "uncertain" if status == "uncertain" else "failed",
                "message": message,
            }
        self.audit.record(**entry, decision="allowed", outcome=status, reason=outcome.uncertain)
        return {"status": status, "message": outcome.uncertain, "response": response}

    def _not_listed(self, target: Target) -> str:
        what = "any of its folders" if target.folders is not None else target.name
        if self.settings.mode == "site":
            return (
                f"This machine's owner has not given you {what}. They can, from "
                "Workbench (Job sites)."
            )
        return f"You have not been given {what}."

    def _may_call(self, target: Target, tool: Any, arguments: Any) -> None:
        if not isinstance(tool, str) or tool not in target.allowed:
            raise Refused(f"You may not use {tool!r} on {target.name}.")
        offered = target.tools.get(tool)
        if offered is None:
            raise Refused(f"{target.name} has no tool named {tool!r}.")
        if is_destructive(offered) and not target.allowed[tool]:
            raise Refused(
                f"{tool} can change things on this machine, and its owner has not pre-approved "
                "it for you. Approving each call at the machine is not available yet."
            )
        if target.folders is None:
            return
        name = arguments.get("folder") if isinstance(arguments, dict) else None
        if not isinstance(name, str) or name not in target.folders:
            raise Refused(f"You have not been given a folder named {name!r} on this machine.")
        if tool == "write_text" and name not in target.writable:
            raise Refused(f"You may read {name} but not change files in it.")

    async def _target(self, call: SiteCall) -> Target:
        server = str(call.server)
        if self.settings.mode == "node":
            if server != FILES:
                raise Refused("This machine has no such server.")
            return self._node_target(call)
        assert self.policy is not None
        if server == FILES:
            if call.subject == OPERATOR:
                return self._owner_in_dev_mode(call)
            names = self.policy.names()
            return self._files_target(
                [
                    (names[folder["id"]], folder, writable)
                    for folder, writable in self.policy.folders_for(call.subject)
                ]
            )
        local = self.local.entries.get(server)
        if local is None:
            raise Refused("This machine has no such server.")
        if call.subject == OPERATOR:
            raise Refused(
                "Eugene's owner reaches this machine's folders only, and only in dev mode."
            )
        if not self.policy.enabled.get(server):
            raise Refused(f"{local.name} is off on this machine.")
        if problem := self.local.problem(local):
            raise Refused(problem)
        try:
            listed = await self.local.tools(local)
        except Exception as exc:
            raise Refused(
                f"{local.name} could not list its tools ({type(exc).__name__})."
            ) from None
        allowed = self.policy.tools_for(call.subject, server)
        return Target(
            server,
            local.name,
            {t.name: t for t in listed},
            {name: standing for name, standing in allowed.items()},
            lambda outcome: self.local.server(local, outcome),
        )

    def _files_target(self, usable: list[tuple[str, dict[str, Any], bool]]) -> Target:
        """The file server for one person: `usable` is each folder they may
        use, by its name here, and whether they may change files in it."""
        folders = {name: folder for name, folder, _ in usable}
        writable = frozenset(name for name, _, may_write in usable if may_write)
        offered = {
            t.name: t
            for t in file_server.tools(list(folders), [n for n in folders if n in writable])
        }
        allowed = dict(READING) if folders else {}
        if writable:
            # Writing is the folder's own standing pre-approval (J6g).
            allowed["write_text"] = True
        protected = self.protected
        return Target(
            FILES,
            "this machine's file server",
            offered,
            allowed,
            lambda outcome: file_server.server(folders, writable, protected, outcome),
            folders,
            writable,
        )

    @staticmethod
    def _grants(call: SiteCall) -> list[SiteGrantHint]:
        return list(call.grants or [])

    def _node_target(self, call: SiteCall) -> Target:
        """An ordinary node: the root's grants are final, and come with the call."""
        grants = self._grants(call)
        names = file_server.unique_names([g.name for g in grants])
        return self._files_target(
            [
                (
                    name,
                    {
                        "id": g.folderId,
                        "path": g.path,
                        "identity": g.identity,
                        "writable": g.writable,
                    },
                    g.writable,
                )
                for g, name in zip(grants, names, strict=True)
            ]
        )

    def _owner_in_dev_mode(self, call: SiteCall) -> Target:
        """Eugene's owner on a site: only in dev mode, only with grants the
        root holds for them, and only if this site's owner said so here (J6e)."""
        assert self.policy is not None
        if not self.policy.owner_in_dev_mode:
            raise Refused(
                "This machine's owner has not let Eugene's owner in. Dev mode alone opens "
                "nothing on a job site."
            )
        if call.installMode.value != "dev":
            raise Refused("Eugene is in production mode: its owner's own access does not work.")
        names = self.policy.names()
        usable: list[tuple[str, dict[str, Any], bool]] = []
        for grant in self._grants(call):
            folder = self.policy.folder(grant.folderId)
            if (
                folder is None
                or grant.path != folder["path"]
                or grant.identity != folder["identity"]
            ):
                continue
            usable.append(
                (names[folder["id"]], folder, bool(grant.writable and folder["writable"]))
            )
        if not usable:
            raise Refused("Eugene's owner has not been given any folder on this machine.")
        return self._files_target(usable)

    # --- management -------------------------------------------------------------

    async def manage(self, action: SiteManage) -> dict[str, Any]:
        name = action.action.value
        arguments = dict(action.arguments or {})
        entry = {
            "subject": action.subject,
            "kind": "manage",
            "action": name,
            "arguments": None if name == "audit.read" else arguments,
        }
        try:
            self._fresh(action.id, action.expiresAt)
            if self.settings.mode == "node":
                if name != "folder.inspect" or action.subject != OPERATOR:
                    raise Refused(
                        "On this machine, only Eugene's owner registers folders, from the console."
                    )
                result = await self._inspect(arguments)
            else:
                if name == "folder.inspect" or action.subject != self.settings.owner:
                    raise Refused(
                        "Only this machine's owner changes what it allows. They do it from "
                        "Workbench (Job sites)."
                    )
                handler = self._handlers()[name]
                async with self.lock:
                    result = await handler(arguments)
        except Refused as exc:
            self.audit.record(**entry, decision="refused", reason=str(exc))
            return {"status": "failed", "message": str(exc)}
        if name != "audit.read":
            self.audit.record(**entry, decision="allowed", outcome="done")
        return {"status": "done", "result": result}

    def _handlers(self) -> dict[str, Callable[[dict[str, Any]], Awaitable[dict[str, Any]]]]:
        return {
            "folder.add": self._folder_add,
            "folder.remove": self._folder_remove,
            "folder.people": self._folder_people,
            "access.set": self._access_set,
            "server.enable": self._server_enable,
            "settings.set": self._settings_set,
            "audit.read": self._audit_read,
        }

    @staticmethod
    def _parse[M: BaseModel](model: type[M], arguments: dict[str, Any]) -> M:
        try:
            return model.model_validate(arguments)
        except ValidationError as exc:
            first = exc.errors()[0]
            where = ".".join(str(p) for p in first["loc"]) or "arguments"
            raise Refused(f"This request is not valid: {where}: {first['msg']}.") from None

    async def _open(self, path: str) -> tuple[str, str]:
        if reason := self.settings.unavailable():
            raise Refused(reason)
        if not path.strip() or any(ord(c) < 32 for c in path):
            raise Refused("Use a folder path without control characters.")
        try:
            full = folder_io.check_root_path(path.strip(), self.protected)
            identity = await asyncio.to_thread(folder_io.inspect, full, self.protected)
        except folder_io.FolderError as exc:
            raise Refused(str(exc)) from None
        except PermissionError:
            raise Refused(
                "The file helper's OS account cannot open this folder. Give it permission first."
            ) from None
        except FileNotFoundError:
            raise Refused("This folder was not found on this machine.") from None
        except (OSError, ValueError):
            raise Refused(
                "The folder could not be opened safely. Links and special folders are not "
                "supported."
            ) from None
        return full, identity

    async def _inspect(self, arguments: dict[str, Any]) -> dict[str, Any]:
        value = self._parse(SiteFolderInspect, arguments)
        path, identity = await self._open(value.path)
        return {"path": path, "identity": identity}

    async def _folder_add(self, arguments: dict[str, Any]) -> dict[str, Any]:
        assert self.policy is not None
        value = self._parse(SiteFolderAdd, arguments)
        name = value.name.strip()
        if not name or any(ord(c) < 32 for c in name):
            raise Refused("Use a folder name without control characters.")
        if name.casefold() in {n.casefold() for n in self.policy.names().values()}:
            raise Refused(f"A folder named {name} is registered already. Choose another name.")
        path, identity = await self._open(value.path)
        if any(f["identity"] == identity for f in self.policy.folders):
            raise Refused("This folder is registered already.")
        folder = {
            "id": secrets.token_hex(16),
            "name": name,
            "path": path,
            "identity": identity,
            "writable": bool(value.writable),
        }
        try:
            self.policy.add_folder(folder)
        except ValueError as exc:
            raise Refused(str(exc)) from None
        return self._folder_view(self.policy.folder(str(folder["id"])) or folder)

    async def _folder_remove(self, arguments: dict[str, Any]) -> dict[str, Any]:
        assert self.policy is not None
        value = self._parse(SiteFolderRemove, arguments)
        if self.policy.folder(value.id) is None:
            raise Refused("This folder is no longer registered.")
        self.policy.remove_folder(value.id)
        return {"id": value.id}

    async def _folder_people(self, arguments: dict[str, Any]) -> dict[str, Any]:
        """Who may use one folder, and who may change files in it (J6g)."""
        assert self.policy is not None
        value = self._parse(SiteFolderPeople, arguments)
        folder = self.policy.folder(value.id)
        if folder is None:
            raise Refused("This folder is no longer registered.")
        people: list[dict[str, Any]] = []
        for person in value.people:
            if person.subject == OPERATOR:
                raise Refused(
                    "Eugene's owner is not a person here. Let them in for dev mode in this "
                    "site's settings instead."
                )
            if any(p["subject"] == person.subject for p in people):
                raise Refused("Each person is named once.")
            if person.writable and not folder["writable"]:
                raise Refused(
                    f"Nobody may change files in {folder['name']}: it was registered read-only."
                )
            people.append({"subject": person.subject, "writable": person.writable})
        self.policy.set_folder_people(value.id, people)
        return self._folder_view(folder)

    async def _offered(self, server: str) -> tuple[str, dict[str, types.Tool]]:
        """A local server's name and every tool it offers, for granting."""
        assert self.policy is not None
        if server == FILES:
            raise Refused("Folders are given to people one by one, not through the file server.")
        local = self.local.entries.get(server)
        if local is None:
            raise Refused("This machine has no such server.")
        if not self.policy.enabled.get(server):
            raise Refused(f"Turn {local.name} on before saying who may use it.")
        if problem := self.local.problem(local):
            raise Refused(problem)
        try:
            listed = await self.local.tools(local, fresh=True)
        except (LocalServerError, Exception) as exc:
            raise Refused(
                f"{local.name} could not list its tools ({type(exc).__name__})."
            ) from None
        return local.name, {t.name: t for t in listed}

    async def _access_set(self, arguments: dict[str, Any]) -> dict[str, Any]:
        assert self.policy is not None
        value = self._parse(SiteAccessSet, arguments)
        server = str(value.server)
        name, offered = await self._offered(server)
        people: list[dict[str, Any]] = []
        for person in value.people:
            if person.subject == OPERATOR:
                raise Refused(
                    "Eugene's owner is not a person here. Let them in for dev mode in this "
                    "site's settings instead."
                )
            if any(p["subject"] == person.subject for p in people):
                raise Refused("Each person is named once.")
            tools: list[dict[str, Any]] = []
            for grant in person.tools:
                tool = offered.get(grant.name)
                if tool is None:
                    raise Refused(f"{name} has no tool named {grant.name!r}.")
                if any(t["name"] == grant.name for t in tools):
                    raise Refused(f"{grant.name} is named twice for one person.")
                destructive = is_destructive(tool)
                if destructive and not grant.standing:
                    raise Refused(
                        f"{grant.name} can change things on this machine. Grant it as a standing "
                        "pre-approval, or not at all."
                    )
                tools.append({"name": grant.name, "standing": bool(destructive and grant.standing)})
            people.append({"subject": person.subject, "tools": tools})
        self.policy.set_access(server, people)
        return {"server": self._server_view(server), "people": self.policy.people(server)}

    async def _server_enable(self, arguments: dict[str, Any]) -> dict[str, Any]:
        assert self.policy is not None
        value = self._parse(SiteServerEnable, arguments)
        server = str(value.server)
        if server == FILES:
            raise Refused("The file server is on while a folder is registered.")
        local = self.local.entries.get(server)
        if local is None:
            raise Refused("This machine has no such server.")
        if value.enabled:
            if problem := self.local.problem(local):
                raise Refused(problem)
            try:
                await self.local.tools(local, fresh=True)
            except Exception as exc:
                raise Refused(
                    f"{local.name} did not list its tools when started ({type(exc).__name__}). "
                    "Check its program at the machine."
                ) from None
        else:
            self.local.forget(server)
        self.policy.set_enabled(server, value.enabled)
        return {"server": self._server_view(server), "people": self.policy.people(server)}

    async def _settings_set(self, arguments: dict[str, Any]) -> dict[str, Any]:
        assert self.policy is not None
        value = self._parse(SiteSettings, arguments)
        self.policy.set_owner_in_dev_mode(value.ownerInDevMode)
        return {"ownerInDevMode": value.ownerInDevMode}

    async def _audit_read(self, arguments: dict[str, Any]) -> dict[str, Any]:
        value = self._parse(SiteAuditRead, arguments)
        limit = value.limit or 50
        return {"entries": await asyncio.to_thread(self.audit.newest, limit)}

    # --- report -----------------------------------------------------------------

    def _folder_view(self, folder: dict[str, Any]) -> dict[str, Any]:
        assert self.policy is not None
        return {
            "id": folder["id"],
            "name": self.policy.names()[folder["id"]],
            "path": folder["path"],
            "writable": folder["writable"],
            "people": [
                {"subject": p["subject"], "writable": p["writable"]} for p in folder["people"]
            ],
        }

    def _files_view(self, reason: str | None) -> dict[str, Any]:
        assert self.policy is not None
        names = list(self.policy.names().values())
        writable = [self.policy.names()[f["id"]] for f in self.policy.folders if f["writable"]]
        return {
            "id": FILES,
            "name": "Files",
            "kind": "files",
            "system": False,
            "enabled": bool(names),
            "available": bool(names) and reason is None,
            "reason": reason if names else "No folder is registered on this machine.",
            "tools": [tool_view(t) for t in file_server.tools(names, writable)],
        }

    def _server_view(self, server: str) -> dict[str, Any]:
        reason = self.settings.unavailable()
        if server == FILES:
            return self._files_view(reason)
        local = self.local.entries[server]
        return self._local_view(local, reason)

    def _local_view(self, local: SiteLocalServer, reason: str | None) -> dict[str, Any]:
        assert self.policy is not None
        enabled = bool(self.policy.enabled.get(local.id))
        problem = reason or self.local.problem(local)
        if not problem and not enabled:
            problem = f"{local.name} is off. Its owner turns it on from Workbench."
        return {
            "id": local.id,
            "name": local.name,
            "kind": "local",
            "system": bool(local.system),
            "enabled": enabled,
            "available": enabled and problem is None,
            "reason": problem,
            "tools": [tool_view(t) for t in self.local.known_tools(local)] if enabled else [],
        }

    def report(self) -> dict[str, Any]:
        reason = self.settings.unavailable()
        value: dict[str, Any] = {
            "protocol": PROTOCOL,
            "version": version()[:64],
            "mode": self.settings.mode,
            "ready": reason is None,
            "reason": reason,
            "site": None,
        }
        if self.policy is None:
            return value
        self._refresh_stale()
        servers = [self._files_view(reason)] if self.policy.folders else []
        servers += [self._local_view(local, reason) for local in self.local.entries.values()]
        value["site"] = {
            "owner": self.settings.owner,
            "ownerInDevMode": self.policy.owner_in_dev_mode,
            "folders": [self._folder_view(f) for f in self.policy.folders],
            "servers": servers,
            "access": [
                {"subject": e["subject"], "server": e["server"], "tools": e["tools"]}
                for e in self.policy.access
            ],
        }
        return value

    def _refresh_stale(self) -> None:
        """Keep an enabled server's tool list current without blocking a report."""
        assert self.policy is not None
        for local in self.local.entries.values():
            if not self.policy.enabled.get(local.id) or local.id in self._refreshing:
                continue
            if self.local.known_tools(local) and not self.local.stale(local):
                continue
            if self.local.problem(local):
                continue
            self._refreshing.add(local.id)
            task = asyncio.get_running_loop().create_task(self._refresh(local))
            self._tasks.add(task)
            task.add_done_callback(self._tasks.discard)

    async def _refresh(self, local: SiteLocalServer) -> None:
        # A server that will not list keeps what it last listed.
        try:
            with contextlib.suppress(Exception):
                await self.local.tools(local, fresh=True)
        finally:
            self._refreshing.discard(local.id)
