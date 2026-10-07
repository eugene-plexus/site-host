"""Every request checked against this machine's policy, then run as a person (J8, J27).

The order for an MCP request is fixed, and every refusal stops it before
anything runs:

1. The operation's id has not been used and its deadline has not passed,
   so a replayed operation runs at most once.
2. It is one of the three methods of MCP 2026-07-28.
3. Tools can run on this machine at all.
4. The server exists and is on.
5. The person may use it: this site's own list says so (rule 2 of
   remote-nodes.md §3.3). On the file server that means at least one
   folder (J6g).
6. **Whose worker runs it** (§3.2): a linked person's own, as their own
   account; anyone else's (no link, or Eugene's owner in dev mode) runs in
   the owner's, as the owner, confined to the folder as every call is
   (J27). With no worker connected, it is refused, saying why.
7. For `tools/call`: the tool is one the person may use, and a destructive
   tool has a standing pre-approval. On the file server, the `folder` it
   names is one they may use, and for `write_text` one they may change.

Then the worker serves it, `tools/list` is cut to the person's tools (the
file server's `folder` argument to their folders), and the call is recorded
in the audit log, as every refusal is. **This host opens no one's files and
runs no one's programs**: registering a folder and listing a local server's
tools run in the owner's worker too.

A management action is taken from the owner this site recorded at its join,
and from nobody else, Eugene's owner included (J6b).

**The owner's own key** (J14a, `person-held-keys.md`). Until the owner has a
key pinned at the machine and has approved the site's rules with it, no tool
runs here (J48, J52). Once they have, a change that gives access is not
applied on the root's word: it is **held** until the owner approves it at the
machine, on the starter's loopback page, which signs the envelope this host
gives it (`signing.py`); this host checks that signature against the pinned
key. A change that only takes access away is applied at once (J51).
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
from datetime import UTC, datetime
from typing import Any

import mcp_types as types
from pydantic import BaseModel, ValidationError

from . import _build, accounts, dispatch, file_server, folder_io, signing
from ._generated.models import (
    SiteAccessSet,
    SiteApproval,
    SiteAuditRead,
    SiteCall,
    SiteFolderAdd,
    SiteFolderPeople,
    SiteFolderRemove,
    SiteGrantHint,
    SiteLocalServer,
    SiteManage,
    SiteServerEnable,
    SiteSettings,
)
from .audit import Audit
from .identity import Identity
from .links import Link, Links
from .local_servers import LocalServerError, LocalServers
from .policy import Policy
from .settings import Settings
from .signing import PersonKey
from .workers import WorkerAbsent, WorkerGone, Workers, WorkerTimeout

PROTOCOL = "mcp-2026-07-28"
MAX_ANSWER = 70_000
OPERATOR = "operator"
FILES = file_server.SERVER
READING = {"list_directory": False, "read_text": False}
#: How long a worker has to answer one call. A local server's own limit is
#: 20 s (`local_servers.CALL_SECONDS`), and a claimed operation lives 30 s.
WORKER_SECONDS = 25.0


class Refused(Exception):
    """The site's refusal, in its own words. Nothing ran."""


class NotHeld(Exception):
    """No such person, key or held change here, for the starter's page."""


#: The id of the one item that is not a held change: the site's rules as a
#: whole, approved once the owner has a key (J52).
RULES = "rules"


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


def _iso(moment: float) -> str:
    return datetime.fromtimestamp(moment, UTC).isoformat()


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
    those they may change. `work` is what the worker is sent to rebuild it:
    the worker never takes a program's name from here."""

    id: str
    name: str
    tools: dict[str, types.Tool]
    allowed: dict[str, bool]
    work: dict[str, Any]
    folders: dict[str, dict[str, Any]] | None = None
    writable: frozenset[str] = frozenset()


class Host:
    def __init__(self, settings: Settings, identity: Identity | None = None) -> None:
        self.settings = settings
        self.identity = identity or Identity(settings.data_dir)
        self.audit = Audit(settings.data_dir)
        self.policy = Policy.load(settings.data_dir / "policy.json")
        self.local = LocalServers(settings.local_servers, settings.data_dir, verify=False)
        self.links = Links(settings.links_file)
        self.held = signing.HeldStore(settings.data_dir)
        self.sequence = signing.Sequence(settings.data_dir)
        self.workers = Workers(self.links, settings.channel, None)
        self.lock = asyncio.Lock()
        self.used: dict[str, float] = {}
        self._refreshing: set[str] = set()
        self._tasks: set[asyncio.Task[None]] = set()

    async def start(self) -> None:
        if self.settings.channel is not None:
            self.workers.own_account = accounts.own()
        await self.workers.start()

    async def stop(self) -> None:
        await self.workers.stop()

    @property
    def protected(self) -> list[Any]:
        return list(self.settings.protected)

    def _spawn(self, coroutine: Any) -> None:
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            coroutine.close()
            return
        task = loop.create_task(coroutine)
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)

    # --- once, and in time ------------------------------------------------------

    def _fresh(self, ident: str, expires: float) -> None:
        now = time.time()
        self.used = {k: until for k, until in self.used.items() if until >= now}
        if not ident or ident in self.used or not now < expires <= now + 30:
            raise Refused("This operation expired or was already used.")
        if len(self.used) >= 4096:
            raise Refused("Too many operations at once. Try again shortly.")
        self.used[ident] = expires

    # --- whose worker -------------------------------------------------------------

    def _machine(self) -> str:
        try:
            enrollment = self.identity.load()
        except Exception:
            enrollment = None
        return enrollment.label if enrollment else "this machine"

    def _not_running(self, link: Link, own: bool) -> str:
        machine = self._machine()
        signed_in = link.account.startswith("S-")
        if own:
            if signed_in:
                return (
                    f"You are not signed in on {machine}. Your calls there run as your own "
                    f"account ({link.account_name}) only while you are."
                )
            return f"Your worker on {machine} is not running. It starts with the machine."
        if signed_in:
            return (
                f"{machine}'s owner is not signed in there. Calls from people without their "
                "own account on it run as the owner, and only while the owner is signed in."
            )
        return f"The owner's worker on {machine} is not running. It starts with the machine."

    def _route(self, subject: str) -> str:
        """The account whose worker runs `subject`'s calls (§3.2, J27)."""
        if self.workers.problem:
            raise Refused(self.workers.problem)
        self.links.all()  # reads the file again if it changed, and so its problem
        if self.links.problem:
            raise Refused(self.links.problem)
        own = self.links.for_subject(subject) if subject != OPERATOR else None
        if own is not None:
            if not self.workers.connected(own.account):
                raise Refused(self._not_running(own, own=True))
            return own.account
        owner = self.identity.owner()
        if subject != owner and not self.settings.sharing:
            raise Refused(
                f"{self._machine()} serves only its owner: it has no folder boundary yet."
            )
        link = self.links.for_subject(owner) if owner else None
        if link is None:
            if subject == owner:
                raise Refused(
                    f"You have not linked your own account on {self._machine()} yet, so "
                    "nothing runs there. Do it at the machine."
                )
            raise Refused(
                f"{self._machine()}'s owner has not linked their own account there yet, so "
                "nothing runs on it. They do it at the machine."
            )
        if not self.workers.connected(link.account):
            raise Refused(self._not_running(link, own=subject == owner))
        return link.account

    def _owner_account(self) -> str:
        owner = self.identity.owner()
        if owner is None:
            raise Refused("This machine has not joined yet.")
        return self._route(owner)

    async def _ask(self, account: str, message: dict[str, Any]) -> dict[str, Any]:
        try:
            answer = await self.workers.call(account, message, WORKER_SECONDS)
        except WorkerAbsent:
            raise Refused("The worker went away. Try again.") from None
        if not answer.get("ok"):
            if answer.get("message"):
                raise Refused(str(answer["message"]))
            raise RuntimeError(str(answer.get("failed") or "the worker failed"))
        return answer

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
            if reason := self._unapproved():
                raise Refused(reason)
            target = self._target(call)
            if not target.allowed:
                raise Refused(self._not_listed(target))
            account = self._route(call.subject)
            if target.work["kind"] == "local":
                target.tools = await self._local_tools(target.id, account)
            if method == "tools/call":
                self._may_call(target, tool, params.get("arguments"))
        except Refused as exc:
            self.audit.record(**entry, decision="refused", reason=str(exc))
            return {"status": "failed", "message": str(exc)}

        try:
            answer = await self._ask(
                account, {"op": "mcp", "work": target.work, "request": request}
            )
        except Refused as exc:
            self.audit.record(**entry, decision="refused", reason=str(exc))
            return {"status": "failed", "message": str(exc)}
        except (WorkerTimeout, WorkerGone, RuntimeError) as exc:
            status = "uncertain" if method == "tools/call" else "failed"
            message = f"{target.name} did not answer ({type(exc).__name__})." + (
                " It may have acted. Check before trying again." if status == "uncertain" else ""
            )
            self.audit.record(**entry, decision="allowed", outcome=status, reason=message)
            return {"status": status, "message": message}
        response = answer.get("response")
        if not isinstance(response, dict):
            message = f"{target.name} answered with nothing."
            self.audit.record(**entry, decision="allowed", outcome="failed", reason=message)
            return {"status": "failed", "message": message}
        uncertain = answer.get("uncertain") or None
        if method == "tools/list" and isinstance(response.get("result"), dict):
            listed = response["result"].get("tools") or []
            response["result"]["tools"] = [t for t in listed if t.get("name") in target.allowed]
        status = "uncertain" if uncertain else "done"
        if len(json.dumps(response, ensure_ascii=False).encode()) > MAX_ANSWER:
            message = "The answer is larger than 70,000 bytes. Ask for less."
            self.audit.record(**entry, decision="allowed", outcome="failed", reason=message)
            return {
                "status": "uncertain" if status == "uncertain" else "failed",
                "message": message,
            }
        self.audit.record(**entry, decision="allowed", outcome=status, reason=uncertain)
        return {"status": status, "message": uncertain, "response": response}

    def _not_listed(self, target: Target) -> str:
        what = "any of its folders" if target.folders is not None else target.name
        return (
            f"This machine's owner has not given you {what}. They can, from Workbench (Job sites)."
        )

    def _may_call(self, target: Target, tool: Any, arguments: Any) -> None:
        if target.folders is not None and tool == "write_text" and tool not in target.allowed:
            raise Refused(
                "You may read folders here but not change files in them. This machine's owner "
                "can let you, from Workbench (Job sites)."
            )
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

    def _target(self, call: SiteCall) -> Target:
        server = str(call.server)
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
        allowed = self.policy.tools_for(call.subject, server)
        return Target(
            server,
            local.name,
            {},
            {name: standing for name, standing in allowed.items()},
            {"kind": "local", "server": server},
        )

    async def _local_tools(self, server: str, account: str) -> dict[str, types.Tool]:
        """A local server's tools: what a worker listed last, or listed now by
        the worker that will run the call."""
        local = self.local.entries[server]
        if self.local.known_tools(local) and not self.local.stale(local):
            return {t.name: t for t in self.local.known_tools(local)}
        try:
            listed = await self._list(account, server, fresh=False)
        except (WorkerTimeout, WorkerGone, RuntimeError, LocalServerError) as exc:
            raise Refused(
                f"{local.name} could not list its tools ({type(exc).__name__})."
            ) from None
        return {t.name: t for t in listed}

    async def _list(self, account: str, server: str, *, fresh: bool) -> list[types.Tool]:
        answer = await self._ask(account, {"op": "tools", "server": server, "fresh": fresh})
        listed = [types.Tool.model_validate(t) for t in answer.get("tools") or []]
        self.local.remember(server, listed)
        return listed

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
        return Target(
            FILES,
            "this machine's file server",
            offered,
            allowed,
            {
                "kind": "files",
                "folders": {
                    name: {"path": f["path"], "identity": f["identity"]}
                    for name, f in folders.items()
                },
                "writable": sorted(writable),
            },
            folders,
            writable,
        )

    @staticmethod
    def _grants(call: SiteCall) -> list[SiteGrantHint]:
        return list(call.grants or [])

    def _owner_in_dev_mode(self, call: SiteCall) -> Target:
        """Eugene's owner on a site: only in dev mode, only with grants the
        root holds for them, and only if this site's owner said so here (J6e)."""
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
            owner = self.identity.owner()
            if owner is None or action.subject != owner:
                raise Refused(
                    "Only this machine's owner changes what it allows. They do it from "
                    "Workbench (Job sites)."
                )
            handler = self._handlers()[name]
            async with self.lock:
                changes = name != "audit.read"
                reduces = changes and self._reduces(name, arguments)
                if changes and not reduces and self.keys_of(owner):
                    message = self._hold(action, arguments)
                    self.audit.record(**entry, decision="allowed", outcome="held", reason=message)
                    return {"status": "held", "message": message}
                approved = self.policy.approved()
                result = await handler(arguments)
                if reduces and approved and not self.policy.approved():
                    # Less than the owner approved is still theirs (J51).
                    self.policy.authorize()
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
        """A folder's path and identity, read by the owner's worker as the
        owner: what they can open is what can be registered."""
        if reason := self.settings.unavailable():
            raise Refused(reason)
        if not path.strip() or any(ord(c) < 32 for c in path):
            raise Refused("Use a folder path without control characters.")
        try:
            folder_io.check_root_path(path.strip(), self.protected)
        except folder_io.FolderError as exc:
            raise Refused(str(exc)) from None
        account = self._owner_account()
        link = self.links.for_account(account)
        who = link.account_name if link else "your account"
        try:
            answer = await self._ask(account, {"op": "inspect", "path": path.strip()})
        except (WorkerTimeout, WorkerGone, RuntimeError):
            raise Refused("The folder could not be checked. Try again.") from None
        problem = answer.get("problem")
        if problem == "denied":
            raise Refused(f"Your account on this machine ({who}) cannot open this folder.")
        if problem == "missing":
            raise Refused("This folder was not found on this machine.")
        if problem == "unsafe":
            raise Refused(
                str(answer.get("message") or "")
                or "The folder could not be opened safely. Links and special folders are not "
                "supported."
            )
        full, identity = answer.get("path"), answer.get("identity")
        if not isinstance(full, str) or not isinstance(identity, str):
            raise Refused("The folder could not be checked. Try again.")
        return full, identity

    async def _folder_add(self, arguments: dict[str, Any]) -> dict[str, Any]:
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
        value = self._parse(SiteFolderRemove, arguments)
        if self.policy.folder(value.id) is None:
            raise Refused("This folder is no longer registered.")
        self.policy.remove_folder(value.id)
        return {"id": value.id}

    def _only_owner(self, subject: str) -> None:
        if not self.settings.sharing and subject != self.identity.owner():
            raise Refused(
                f"{self._machine()} serves only its owner: it has no folder boundary yet."
            )

    async def _folder_people(self, arguments: dict[str, Any]) -> dict[str, Any]:
        """Who may use one folder, and who may change files in it (J6g)."""
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
            self._only_owner(person.subject)
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
            listed = await self._list(self._owner_account(), server, fresh=True)
        except (WorkerTimeout, WorkerGone, RuntimeError, LocalServerError) as exc:
            raise Refused(
                f"{local.name} could not list its tools ({type(exc).__name__})."
            ) from None
        return local.name, {t.name: t for t in listed}

    async def _access_set(self, arguments: dict[str, Any]) -> dict[str, Any]:
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
            self._only_owner(person.subject)
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
                await self._list(self._owner_account(), server, fresh=True)
            except (WorkerTimeout, WorkerGone, RuntimeError, LocalServerError) as exc:
                raise Refused(
                    f"{local.name} did not list its tools when started ({type(exc).__name__}). "
                    "Check its program at the machine."
                ) from None
        else:
            self.local.forget(server)
        self.policy.set_enabled(server, value.enabled)
        return {"server": self._server_view(server), "people": self.policy.people(server)}

    async def _settings_set(self, arguments: dict[str, Any]) -> dict[str, Any]:
        value = self._parse(SiteSettings, arguments)
        self.policy.set_owner_in_dev_mode(value.ownerInDevMode)
        return {"ownerInDevMode": value.ownerInDevMode}

    async def _audit_read(self, arguments: dict[str, Any]) -> dict[str, Any]:
        value = self._parse(SiteAuditRead, arguments)
        limit = value.limit or 50
        return {"entries": await asyncio.to_thread(self.audit.newest, limit)}

    # --- the owner's own key (J14a) ------------------------------------------------

    def keys_of(self, subject: str) -> dict[str, PersonKey]:
        """The keys pinned at the machine to `subject`'s link."""
        link = self.links.for_subject(subject) if subject != OPERATOR else None
        return {key.id: key for key in link.keys} if link else {}

    def signing_state(self) -> str:
        owner = self.identity.owner()
        if owner is None or not self.keys_of(owner):
            return "unsigned"
        return "signed" if self.policy.approved() else "unconfirmed"

    def approve_page(self) -> str | None:
        page = self.settings.link_page
        return f"{page.rstrip('/')}/approve" if page else None

    def _at_the_machine(self) -> str:
        page = self.approve_page()
        return f"on {self._machine()}, at {page}" if page else f"at {self._machine()} itself"

    def _unapproved(self) -> str | None:
        """Why no tool runs here yet (J48, J52), or None."""
        self.links.all()  # the keys are in the links file: its problem first
        if self.links.problem:
            return self.links.problem
        state = self.signing_state()
        if state == "signed":
            return None
        if state == "unsigned":
            return (
                f"{self._machine()}'s owner has not added their own key there yet, so no tool "
                f"runs on it. They add it {self._at_the_machine()}."
            )
        return (
            f"{self._machine()}'s owner has not approved its rules with their key yet, so no "
            f"tool runs on it. They do it {self._at_the_machine()}."
        )

    def _reduces(self, name: str, arguments: dict[str, Any]) -> bool:
        """Whether a change only takes access away (J51): it needs no
        signature, and less than the owner approved is still theirs."""
        try:
            if name == "folder.remove":
                return True
            if name == "server.enable":
                return SiteServerEnable.model_validate(arguments).enabled is False
            if name == "settings.set":
                return SiteSettings.model_validate(arguments).ownerInDevMode is False
            if name == "folder.people":
                people = SiteFolderPeople.model_validate(arguments)
                folder = self.policy.folder(people.id)
                if folder is None:
                    return False
                before = {p["subject"]: bool(p["writable"]) for p in folder["people"]}
                return all(
                    p.subject in before and (before[p.subject] or not p.writable)
                    for p in people.people
                )
            if name == "access.set":
                access = SiteAccessSet.model_validate(arguments)
                server = str(access.server)
                local = self.local.entries.get(server)
                known = {t.name: t for t in self.local.known_tools(local)} if local else {}
                for person in access.people:
                    before = self.policy.tools_for(person.subject, server)
                    for grant in person.tools:
                        if grant.name not in before:
                            return False
                        tool = known.get(grant.name)
                        matters = tool is None or is_destructive(tool)
                        if matters and grant.standing and not before[grant.name]:
                            return False
                return True
        except ValidationError:
            return False
        return False

    def _hold(self, action: SiteManage, arguments: dict[str, Any]) -> str:
        """Check what can be checked now, then keep the change for its
        owner's approval at the machine. The message for Workbench."""
        name = action.action.value
        self._precheck(name, arguments)
        subjects = self._named(name, arguments)
        names = {k: str(v)[:256] for k, v in (action.names or {}).items() if k in subjects}
        try:
            self.held.add(action.subject, name, arguments, names)
        except signing.Full as exc:
            raise Refused(str(exc)) from None
        return (
            f"Waiting for your approval {self._at_the_machine()}. Nothing changes until you "
            "approve it there with your key."
        )

    def _precheck(self, name: str, arguments: dict[str, Any]) -> None:
        """The cheap half of each change's checks, so a change that cannot
        be applied is refused now rather than held."""
        if name == "folder.add":
            value = self._parse(SiteFolderAdd, arguments)
            folder_name, path = value.name.strip(), value.path.strip()
            if not folder_name or any(ord(c) < 32 for c in folder_name):
                raise Refused("Use a folder name without control characters.")
            if folder_name.casefold() in {n.casefold() for n in self.policy.names().values()}:
                raise Refused(
                    f"A folder named {folder_name} is registered already. Choose another name."
                )
            if not path or any(ord(c) < 32 for c in path):
                raise Refused("Use a folder path without control characters.")
            try:
                folder_io.check_root_path(path, self.protected)
            except folder_io.FolderError as exc:
                raise Refused(str(exc)) from None
        elif name == "folder.people":
            people = self._parse(SiteFolderPeople, arguments)
            folder = self.policy.folder(people.id)
            if folder is None:
                raise Refused("This folder is no longer registered.")
            seen: set[str] = set()
            for person in people.people:
                if person.subject == OPERATOR:
                    raise Refused(
                        "Eugene's owner is not a person here. Let them in for dev mode in this "
                        "site's settings instead."
                    )
                self._only_owner(person.subject)
                if person.subject in seen:
                    raise Refused("Each person is named once.")
                seen.add(person.subject)
                if person.writable and not folder["writable"]:
                    raise Refused(
                        f"Nobody may change files in {folder['name']}: it was registered read-only."
                    )
        elif name == "access.set":
            access = self._parse(SiteAccessSet, arguments)
            server = str(access.server)
            local = self.local.entries.get(server)
            if server == FILES:
                raise Refused(
                    "Folders are given to people one by one, not through the file server."
                )
            if local is None:
                raise Refused("This machine has no such server.")
            if not self.policy.enabled.get(server):
                raise Refused(f"Turn {local.name} on before saying who may use it.")
            # The tools it listed last, when it has: the rest is checked again
            # with a fresh list when the change is approved.
            known = {t.name: t for t in self.local.known_tools(local)}
            for entry in access.people:
                if entry.subject == OPERATOR:
                    raise Refused(
                        "Eugene's owner is not a person here. Let them in for dev mode in this "
                        "site's settings instead."
                    )
                self._only_owner(entry.subject)
                for grant in entry.tools if known else ():
                    tool = known.get(grant.name)
                    if tool is None:
                        raise Refused(f"{local.name} has no tool named {grant.name!r}.")
                    if is_destructive(tool) and not grant.standing:
                        raise Refused(
                            f"{grant.name} can change things on this machine. Grant it as a "
                            "standing pre-approval, or not at all."
                        )
        elif name == "server.enable":
            enable = self._parse(SiteServerEnable, arguments)
            local = self.local.entries.get(str(enable.server))
            if local is None:
                raise Refused("This machine has no such server.")
            if problem := self.local.problem(local):
                raise Refused(problem)
        elif name == "settings.set":
            self._parse(SiteSettings, arguments)

    @staticmethod
    def _named(name: str, arguments: dict[str, Any]) -> set[str]:
        people = arguments.get("people") if name in ("folder.people", "access.set") else None
        if not isinstance(people, list):
            return set()
        return {str(p.get("subject")) for p in people if isinstance(p, dict)}

    # --- the starter's page: list, approve, turn down -------------------------------

    def held_list(self, subject: str, key: str | None) -> dict[str, Any]:
        """What `subject` has waiting, for the page at the machine; with one
        of their keys, each with the envelope to sign."""
        keys = self.keys_of(subject)
        if self.links.for_subject(subject) is None or (key is not None and key not in keys):
            raise NotHeld(subject)
        enrollment = self.identity.load()
        owner = self.identity.owner()
        seq = self.sequence.last(subject) + 1

        def envelope(act: str, args: dict[str, Any]) -> str | None:
            if key is None or enrollment is None:
                return None
            return signing.envelope(
                site=enrollment.site,
                enrolled_at=enrollment.enrolledAt,
                person=subject,
                key=key,
                act=act,
                args=args,
                seq=seq,
            )

        items: list[dict[str, Any]] = []
        if subject == owner and keys and not self.policy.approved():
            items.append(
                {
                    "id": RULES,
                    "action": signing.CONFIRM,
                    "words": self._rules_words(),
                    "heldAt": None,
                    "envelope": envelope(signing.CONFIRM, {"digest": self.policy.digest()}),
                }
            )
        for held in self.held.for_subject(subject):
            items.append(
                {
                    "id": held.id,
                    "action": held.action,
                    "words": self._words(held),
                    "heldAt": _iso(held.held_at),
                    "expiresAt": _iso(held.expires_at),
                    "envelope": envelope(held.action, held.arguments),
                }
            )
        return {
            "subject": subject,
            "keys": sorted(keys),
            "state": self.signing_state() if subject == owner else None,
            "items": items,
        }

    async def approve(self, ident: str, approval: SiteApproval) -> dict[str, Any]:
        """Apply a held change (or the rules as a whole) once its person's
        key has signed it at the machine."""
        subject = approval.subject
        if self.links.for_subject(subject) is None:
            raise NotHeld(subject)
        owner = self.identity.owner()
        held = None if ident == RULES else self.held.get(ident)
        if ident == RULES:
            if subject != owner:
                raise NotHeld(ident)
            act, args = signing.CONFIRM, {"digest": self.policy.digest()}
        elif held is None or held.subject != subject:
            raise NotHeld(ident)
        else:
            act, args = held.action, held.arguments
        entry = {"subject": subject, "kind": "manage", "action": act, "arguments": args}
        async with self.lock:
            # Another approval of the same change may have run while this one
            # waited: what is applied is what is still held.
            if ident != RULES and self.held.get(ident) is None:
                raise NotHeld(ident)
            try:
                enrollment = self.identity.load()
                if enrollment is None or subject != owner:
                    raise Refused("Only this machine's owner changes what it allows.")
                if ident == RULES:
                    # The rules as they are now, not as they were when listed.
                    args = {"digest": self.policy.digest()}
                try:
                    checked = signing.check(
                        approval.envelope,
                        approval.signature,
                        site=enrollment.site,
                        enrolled_at=enrollment.enrolledAt,
                        person=subject,
                        act=act,
                        args=args,
                        keys=self.keys_of(subject),
                        key=approval.key,
                        last_seq=self.sequence.last(subject),
                    )
                    # Spent before it is applied: one signature, one try.
                    self.sequence.accept(subject, checked.seq)
                except signing.NotSigned as exc:
                    raise Refused(str(exc)) from None
                result: dict[str, Any] = {}
                if ident == RULES:
                    self.policy.authorize()
                else:
                    approved = self.policy.approved()
                    result = await self._handlers()[act](args)
                    self.held.remove(ident)
                    if approved:
                        self.policy.authorize()
            except Refused as exc:
                self.audit.record(**entry, decision="refused", reason=str(exc))
                return {"status": "failed", "message": str(exc)}
        self.audit.record(
            **entry,
            decision="allowed",
            outcome="done",
            reason=f"Approved at the machine with key {checked.key.id[:8]}.",
        )
        return {"status": "done", "result": result}

    def reject(self, ident: str, subject: str) -> None:
        held = self.held.get(ident)
        if held is None or held.subject != subject:
            raise NotHeld(ident)
        self.held.remove(ident)
        self.audit.record(
            subject=subject,
            kind="manage",
            action=held.action,
            arguments=held.arguments,
            decision="refused",
            reason="Turned down at the machine.",
        )

    # --- a change in this site's own words ------------------------------------------

    def _who(self, subject: str, names: dict[str, str]) -> str:
        if subject == self.identity.owner():
            return "you"
        link = self.links.for_subject(subject)
        if link is not None:
            return f"{link.name or subject} ({link.account_name} on this machine)"
        name = names.get(subject)
        if name:
            return f"{name} (as Eugene names them; no account on this machine)"
        return f"a person with no account on this machine (Eugene id {subject})"

    def _server_name(self, server: str) -> str:
        local = self.local.entries.get(server)
        return local.name if local else server

    def _words(self, held: signing.Held) -> list[str]:
        args, names = held.arguments, held.names
        try:
            if held.action == "folder.add":
                add = SiteFolderAdd.model_validate(args)
                return [
                    f"Add the folder {add.path.strip()} as “{add.name.strip()}”.",
                    "People you allow may change files in it."
                    if add.writable
                    else "It is read only: nobody may change files in it.",
                    "Nobody may use it until you say who.",
                ]
            if held.action == "folder.people":
                return self._people_words(SiteFolderPeople.model_validate(args), names)
            if held.action == "access.set":
                access = SiteAccessSet.model_validate(args)
                lines = [f"Who may use {self._server_name(str(access.server))}'s tools:"]
                for person in access.people:
                    tools = ", ".join(
                        t.name + (" (pre-approved: may change things)" if t.standing else "")
                        for t in person.tools
                    )
                    lines.append(f"• {self._who(person.subject, names)}: {tools or 'none'}")
                if not access.people:
                    lines.append("• nobody")
                return lines
            if held.action == "server.enable":
                enable = SiteServerEnable.model_validate(args)
                local = self.local.entries.get(str(enable.server))
                program = (
                    f": {' '.join([local.command, *(a.root for a in local.args or [])])}"
                    if local
                    else ""
                )
                return [
                    f"Turn on {self._server_name(str(enable.server))}.",
                    f"Its program runs as you to list its tools{program}.",
                    "Nobody may use it until you say who.",
                ]
            if held.action == "settings.set":
                return [
                    "Let Eugene's owner use the folders they give themselves here, while "
                    "Eugene is in dev mode."
                ]
        except ValidationError:
            pass
        return [f"{held.action}: {signing.canonical(args)[:900]}"]

    def _people_words(self, people: SiteFolderPeople, names: dict[str, str]) -> list[str]:
        folder = self.policy.folder(people.id)
        label = f"“{folder['name']}” ({folder['path']})" if folder else "a folder"
        before = {p["subject"]: p["writable"] for p in (folder or {}).get("people", [])}
        lines = [f"Who may use {label}:"]
        for person in people.people:
            what = "read and change files" if person.writable else "read"
            if person.subject not in before:
                what += " (new)"
            elif person.writable and not before[person.subject]:
                what += " (now also changes files)"
            lines.append(f"• {self._who(person.subject, names)}: {what}")
        kept = {p.subject for p in people.people}
        lines += [f"• no longer: {self._who(s, names)}" for s in before if s not in kept]
        if not people.people:
            lines.append("• nobody")
        return lines

    def _rules_words(self) -> list[str]:
        lines = ["Keep this machine's rules as they are now:"]
        none: dict[str, str] = {}
        if not self.policy.folders:
            lines.append("• No folders.")
        for folder in self.policy.folders:
            mode = "files may be changed" if folder["writable"] else "read only"
            people = "; ".join(
                f"{self._who(p['subject'], none)} "
                f"({'read and change files' if p['writable'] else 'read'})"
                for p in folder["people"]
            )
            lines.append(
                f"• Folder “{folder['name']}” ({folder['path']}), {mode}: {people or 'nobody'}."
            )
        for server, on in sorted(self.policy.enabled.items()):
            if not on:
                continue
            people = "; ".join(
                f"{self._who(e['subject'], none)}: {', '.join(t['name'] for t in e['tools'])}"
                for e in self.policy.access
                if e["server"] == server
            )
            lines.append(f"• {self._server_name(server)} is on: {people or 'nobody may use it'}.")
        lines.append(
            "• Eugene's owner may use the folders they give themselves here, in dev mode."
            if self.policy.owner_in_dev_mode
            else "• Eugene's owner is not let in."
        )
        return lines

    # --- report -----------------------------------------------------------------

    def reason(self) -> str | None:
        """Why no tool can run here now, or None: the platform, the channel
        for workers, or the links file."""
        self.links.all()  # a problem is only known once the file has been read
        return self.settings.unavailable() or self.workers.problem or self.links.problem

    def _folder_view(self, folder: dict[str, Any]) -> dict[str, Any]:
        return {
            "id": folder["id"],
            "name": self.policy.names()[folder["id"]],
            "path": folder["path"],
            "identity": folder["identity"],
            "writable": folder["writable"],
            "people": [
                {"subject": p["subject"], "writable": p["writable"]} for p in folder["people"]
            ],
        }

    def _files_view(self, reason: str | None) -> dict[str, Any]:
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
        reason = self.reason()
        if server == FILES:
            return self._files_view(reason)
        local = self.local.entries[server]
        return self._local_view(local, reason)

    def _local_view(self, local: SiteLocalServer, reason: str | None) -> dict[str, Any]:
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

    def _links_view(self) -> list[dict[str, Any]]:
        """Each linked person, worded for that person: Workbench shows each
        their own line."""
        views = []
        for link in self.links.all():
            available = self.workers.connected(link.account)
            views.append(
                {
                    "subject": link.subject,
                    "accountName": link.account_name,
                    "available": available,
                    "reason": None if available else self._not_running(link, own=True),
                    "keys": len(link.keys),
                }
            )
        return views

    def summary(self) -> dict[str, Any] | None:
        """What this site holds (`SiteSummary`), for its next poll; None
        before it has joined."""
        owner = self.identity.owner()
        if owner is None:
            return None
        reason = self.reason()
        self._spawn(self.workers.prune())
        self._refresh_stale()
        servers = [self._files_view(reason)] if self.policy.folders else []
        servers += [self._local_view(local, reason) for local in self.local.entries.values()]
        return {
            "owner": owner,
            "ownerInDevMode": self.policy.owner_in_dev_mode,
            "folders": [self._folder_view(f) for f in self.policy.folders],
            "servers": servers,
            "access": [
                {"subject": e["subject"], "server": e["server"], "tools": e["tools"]}
                for e in self.policy.access
            ],
            "links": self._links_view(),
            "linkPage": self.settings.link_page,
            "sharing": self.settings.sharing,
            "signing": {
                "state": self.signing_state(),
                "held": len(self.held.all()),
                "approvePage": self.approve_page(),
            },
        }

    def _refresh_stale(self) -> None:
        """Keep an enabled server's tool list current without blocking a
        report, through the owner's worker when it is connected."""
        for local in self.local.entries.values():
            if not self.policy.enabled.get(local.id) or local.id in self._refreshing:
                continue
            if self.local.known_tools(local) and not self.local.stale(local):
                continue
            if self.local.problem(local):
                continue
            self._refreshing.add(local.id)
            self._spawn(self._refresh(local))

    async def _refresh(self, local: SiteLocalServer) -> None:
        # A server that will not list keeps what it last listed.
        try:
            with contextlib.suppress(Exception):
                await self._list(self._owner_account(), local.id, fresh=True)
        finally:
            self._refreshing.discard(local.id)
