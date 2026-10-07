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
   workspace: their own, or one the owner shared with them (J69).
6. **Whose approval it runs under** (J79): a person's own workspace runs
   under their own approved rules; a workspace the owner shared, a local
   server and dev mode under the owner's.
7. **Whose worker runs it** (§3.2): a linked person's own, as their own
   account; anyone else's (no link, or Eugene's owner in dev mode) runs in
   the owner's, as the owner, confined to the workspace as every call is
   (J27). A person's own workspaces are opened only by their own worker.
   With no worker connected, it is refused, saying why.
8. For `tools/call`: the rule for the tool there (J70). `deny` is refused;
   `ask` runs only when the call says the person approved it
   (`SiteCall.asked`, J72), which this site cannot check until J14b and so
   records as claimed.

Then the worker serves it, `tools/list` is cut to the person's tools (the
file server's `folder` argument to their workspaces) and each tool says in
its `_meta` (`eugene-plexus/ask`) where it must be asked about, and the call
is recorded in the audit log, as every refusal is. **This host opens no
one's files and runs no one's programs**: adding a workspace and listing a
local server's tools run in a worker too.

**Who may change what** (2b.3b, J67). Any linked person adds, changes and
removes their own workspaces and rules; only the owner this site recorded at
its join shares their workspaces, turns local servers on, grants them and
changes the site's settings. Eugene's owner changes nothing (J6b).

**Each person's own key** (J14a, J67, `person-held-keys.md`). A change that
gives access is not applied on the root's word: it is **held** until its
person approves it with their own key, at the machine on the starter's
loopback page, which signs the envelope this host gives it (`signing.py`), or
from Workbench with a passkey (`passkeys.py`). A linked person's change waits
even before they have a key (J68); the site's owner keeps J52's way, where
with no key their changes apply and nothing runs under them until they
approve them as a whole. A change that only takes access away is applied at
once (J51).
"""

from __future__ import annotations

import asyncio
import contextlib
import importlib.metadata
import json
import secrets
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

import mcp_types as types
import pathspec
from pydantic import BaseModel, ValidationError

from . import _build, accounts, dispatch, file_server, folder_io, signing
from . import passkeys as pk
from ._generated.models import (
    SiteAccessSet,
    SiteApproval,
    SiteAuditRead,
    SiteCall,
    SiteDenyPattern,
    SiteFolderAdd,
    SiteFolderPeople,
    SiteFolderRemove,
    SiteHeldListRequest,
    SiteHeldRejectRequest,
    SiteLocalServer,
    SiteManage,
    SitePasskeyApproval,
    SitePasskeyPair,
    SitePasskeyRemove,
    SiteRules,
    SiteRulesSet,
    SiteServerEnable,
    SiteSettings,
    SiteToolGrant,
    SiteWorkspaceAdd,
    SiteWorkspaceListRequest,
    SiteWorkspacePeople,
    SiteWorkspaceRemove,
)
from .audit import Audit
from .identity import Identity
from .links import Link, Links
from .local_servers import LocalServerError, LocalServers
from .policy import (
    GROUPS,
    MAX_DENY,
    Policy,
    default_groups,
    group_of,
    looser,
    per_group,
    per_tool,
)
from .settings import Settings
from .signing import PersonKey
from .workers import WorkerAbsent, WorkerGone, Workers, WorkerTimeout

PROTOCOL = "mcp-2026-07-28"
MAX_ANSWER = 70_000
OPERATOR = "operator"
FILES = file_server.SERVER
#: The `_meta` key on each tool `tools/list` returns: where Workbench must ask.
ASK_META = "eugene-plexus/ask"
#: How long a worker has to answer one call. A local server's own limit is
#: 20 s (`local_servers.CALL_SECONDS`), and a claimed operation lives 30 s.
WORKER_SECONDS = 25.0


class Refused(Exception):
    """The site's refusal, in its own words. Nothing ran."""


class NotHeld(Exception):
    """No such person, key or held change here, for the starter's page."""


_NOT_WAITING = "That is no longer waiting. Open the list again."
_NO_SUCH_PASSKEY = "That passkey is not paired with this machine. Open the list again."
_NO_PASSKEY = (
    "That passkey is not one of yours on this machine any more. Pair it again with a code "
    "from the machine."
)
_OPERATOR_NOT_A_PERSON = (
    "Eugene's owner is not a person here. Let them in for dev mode in this site's settings instead."
)
_ONLY_OWNER = (
    "Only this machine's owner changes what it allows. They do it from Workbench (Job sites)."
)
_NO_WORKSPACE = "You have no such workspace here. Open the list again."


#: The id of the one item that is not a held change: a person's rules as a
#: whole, approved once they have a key (J52).
RULES = "rules"
#: The site actions that carry a passkey's work from Workbench (J14a.3):
#: none of them is a change to what this machine allows.
PASSKEY_ACTIONS = frozenset(
    {"passkey.pair", "held.list", "held.approve", "held.reject", "passkey.remove"}
)
#: Any linked person, for their own items (J67).
PERSON_ACTIONS = frozenset(
    {"workspace.add", "workspace.remove", "rules.set", "workspace.list", "audit.read"}
)
#: The site's owner alone.
OWNER_ACTIONS = frozenset(
    {
        "workspace.people",
        "access.set",
        "server.enable",
        "settings.set",
        "folder.add",
        "folder.remove",
        "folder.people",
    }
)
#: Actions that change nothing.
READS = frozenset({"workspace.list", "audit.read"})


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


def grant_decision(grant: SiteToolGrant, tool: types.Tool | None) -> str | None:
    """A local server's tool as granted (J78): the decision given, else
    `allow` for a standing pre-approval, else by whether the tool is
    destructive; None when that is not known yet."""
    if grant.decision is not None:
        return grant.decision.value
    if grant.standing:
        return "allow"
    if tool is None:
        return None
    return "ask" if is_destructive(tool) else "allow"


def _grant_view(grant: dict[str, Any]) -> dict[str, Any]:
    decision = grant.get("decision")
    return {"name": grant["name"], **({"decision": decision} if decision else {})}


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
    person may use of it (each tool's decision; None follows whether the tool
    is destructive). For the file server, also the workspaces they may use by
    name, their rules in each, and those their approvals keep closed. `work`
    is what the worker is sent to rebuild it: the worker never takes a
    program's name from here."""

    id: str
    name: str
    tools: dict[str, types.Tool]
    allowed: dict[str, str | None]
    work: dict[str, Any]
    folders: dict[str, dict[str, Any]] | None = None
    rules: dict[str, dict[str, str]] = field(default_factory=dict)
    #: Each workspace in their view whose rules are not approved: why, and
    #: its holder.
    blocked: dict[str, tuple[str, str]] = field(default_factory=dict)

    def ask(self, tool: str) -> list[str] | bool:
        """Where `tool` must be asked about: the workspaces, on the file
        server; whether, on a local server."""
        if self.folders is None:
            offered = self.tools.get(tool)
            decision = self.allowed.get(tool) or (
                "ask" if offered is None or is_destructive(offered) else "allow"
            )
            return decision == "ask"
        group = group_of(tool)
        return [n for n, rules in self.rules.items() if group and rules[group] == "ask"]


class Host:
    def __init__(self, settings: Settings, identity: Identity | None = None) -> None:
        self.settings = settings
        self.identity = identity or Identity(settings.data_dir)
        self.audit = Audit(settings.data_dir)
        self.policy = Policy.load(settings.data_dir / "policy.json", self.identity.owner())
        self.local = LocalServers(settings.local_servers, settings.data_dir, verify=False)
        self.links = Links(settings.links_file)
        self.held = signing.HeldStore(settings.data_dir)
        self.sequence = signing.Sequence(settings.data_dir)
        self.passkeys = pk.PasskeyStore(settings.data_dir)
        self.codes = pk.Codes()
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

    def _owner(self) -> str | None:
        """The owner this site recorded at its join, which the policy needs to
        tell the owner's rules from everyone else's."""
        owner = self.identity.owner()
        self.policy.owner = owner
        return owner

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

    def _broken(self) -> str | None:
        """Why no call can run here: no channel for workers, or a links file
        that cannot be read (which holds every person's link and keys)."""
        if self.workers.problem:
            return self.workers.problem
        self.links.all()  # reads the file again if it changed, and so its problem
        return self.links.problem

    def _not_linked(self) -> str:
        return (
            f"You have not linked your own account on {self._machine()} yet, so nothing of "
            "yours runs there. Do it at the machine."
        )

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
        owner = self._owner()
        if subject != owner and not self.settings.sharing:
            raise Refused(
                f"{self._machine()} serves only its owner: it has no folder boundary yet."
            )
        link = self.links.for_subject(owner) if owner else None
        if link is None:
            if subject == owner:
                raise Refused(self._not_linked())
            raise Refused(
                f"{self._machine()}'s owner has not linked their own account there yet, so "
                "nothing runs on it. They do it at the machine."
            )
        if not self.workers.connected(link.account):
            raise Refused(self._not_running(link, own=subject == owner))
        return link.account

    def _own_account(self, subject: str) -> str:
        """`subject`'s own worker, and never anyone else's: what opens their
        own workspaces."""
        if self.workers.problem:
            raise Refused(self.workers.problem)
        self.links.all()
        if self.links.problem:
            raise Refused(self.links.problem)
        link = self.links.for_subject(subject) if subject != OPERATOR else None
        if link is None:
            raise Refused(self._not_linked())
        if not self.workers.connected(link.account):
            raise Refused(self._not_running(link, own=True))
        return link.account

    def _owner_account(self) -> str:
        owner = self._owner()
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
        arguments = params.get("arguments") if method == "tools/call" else None
        entry: dict[str, Any] = {
            "subject": call.subject,
            "kind": "mcp",
            "server": call.server,
            "method": method,
            "tool": tool if isinstance(tool, str) else None,
            "arguments": arguments,
            # Whose line it is (J80): the workspace's holder once it is known.
            "reader": self._owner(),
        }
        try:
            self._fresh(call.id, call.expiresAt)
            try:
                dispatch.check(request)
            except dispatch.NotServed as exc:
                raise Refused(str(exc)) from None
            if reason := self.settings.unavailable() or self._broken():
                raise Refused(reason)
            target = self._target(call)
            entry["reader"] = self._reader(target, arguments) or entry["reader"]
            if not target.allowed:
                if target.blocked:
                    raise Refused(next(iter(target.blocked.values()))[0])
                raise Refused(self._not_listed(target, call.subject))
            account = self._route(call.subject)
            if target.work["kind"] == "local":
                target.tools = await self._local_tools(target.id, account)
            if method == "tools/call":
                rule = self._rule(target, tool, arguments)
                entry["rule"] = rule
                if rule == "ask":
                    entry["asked"] = bool(call.asked)
                    if not call.asked:
                        raise Refused(
                            f"{tool} needs your approval each time here, and this call did not "
                            "say you gave it. Workbench asks you before it runs."
                        )
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
            # Only a call that can change something may have acted: a file
            # server read or search that ran out of time did not.
            reads = target.folders is not None and tool in file_server.READ_ONLY
            status = "uncertain" if method == "tools/call" and not reads else "failed"
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
            kept = []
            for offered in listed:
                if not isinstance(offered, dict) or offered.get("name") not in target.allowed:
                    continue
                found = offered.get("_meta")
                meta: dict[str, Any] = found if isinstance(found, dict) else {}
                kept.append({**offered, "_meta": {**meta, ASK_META: target.ask(offered["name"])}})
            response["result"]["tools"] = kept
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

    @staticmethod
    def _reader(target: Target, arguments: Any) -> str | None:
        """The holder of the workspace a file server call names (J80)."""
        if target.folders is None or not isinstance(arguments, dict):
            return None
        name = arguments.get("folder")
        if not isinstance(name, str):
            return None
        if name in target.folders:
            return str(target.folders[name]["holder"])
        if name in target.blocked:
            return target.blocked[name][1]
        return None

    def _not_listed(self, target: Target, subject: str) -> str:
        if target.folders is None:
            return (
                f"This machine's owner has not given you {target.name}. They can, from "
                "Workbench (Job sites)."
            )
        if self.links.for_subject(subject) is not None:
            return (
                f"You have no workspace on {self._machine()} yet. Add one from Workbench "
                "(Job sites)."
            )
        return (
            "This machine's owner has not given you any of its workspaces. They can, from "
            "Workbench (Job sites)."
        )

    def _rule(self, target: Target, tool: Any, arguments: Any) -> str:
        """The rule this call runs under, `allow` or `ask`, or why it is
        refused (J70, J78)."""
        if target.folders is not None:
            name = arguments.get("folder") if isinstance(arguments, dict) else None
            if isinstance(name, str) and name in target.blocked:
                raise Refused(target.blocked[name][0])
            if not isinstance(tool, str) or tool not in target.allowed:
                if tool in file_server.DESTRUCTIVE:
                    raise Refused(
                        "You may read workspaces here but not change files in them. Their "
                        "holder's rules decide that, in Workbench (Job sites)."
                    )
                raise Refused(f"You may not use {tool!r} on {target.name}.")
            if not isinstance(name, str) or name not in target.folders:
                raise Refused(f"You have no workspace named {name!r} on this machine.")
            group = group_of(tool)
            decision = target.rules[name][group] if group else "deny"
            if decision == "deny":
                what = "change files" if group == "change" else "read or search"
                raise Refused(f"In {name} you may not {what}: its rules say so.")
            return decision
        if not isinstance(tool, str) or tool not in target.allowed:
            raise Refused(f"You may not use {tool!r} on {target.name}.")
        offered = target.tools.get(tool)
        if offered is None:
            raise Refused(f"{target.name} has no tool named {tool!r}.")
        return target.allowed[tool] or ("ask" if is_destructive(offered) else "allow")

    def _target(self, call: SiteCall) -> Target:
        server = str(call.server)
        if server == FILES:
            if call.subject == OPERATOR:
                return self._owner_in_dev_mode(call)
            return self._person_files(call.subject)
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
        owner = self._owner()
        allowed = self.policy.tools_for(call.subject, server)
        if allowed and owner and (reason := self._unapproved(owner, call.subject)):
            # A local server runs under its owner's rules (J79).
            raise Refused(reason)
        return Target(server, local.name, {}, dict(allowed), {"kind": "local", "server": server})

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

    def _person_files(self, subject: str) -> Target:
        """The file server for a person: their own workspaces, opened only by
        their own worker, then those the owner shared with them (J69)."""
        owner = self._owner()
        linked = self.links.for_subject(subject) is not None
        if subject == owner and not linked:
            raise Refused(self._not_linked())
        view = self.policy.view(subject)
        rows = [
            (name, workspace, rules, subject if mine else owner)
            for name, workspace, rules, mine in view
            if linked or not mine
        ]
        target = self._files_target(subject, rows)
        # What the filter left out is theirs, opened only by their own worker:
        # it says to link, whatever their keys' state.
        kept = {name for name, *_ in rows}
        for name, workspace, _, _ in view:
            if name not in kept:
                target.blocked[name] = (self._not_linked(), str(workspace["holder"]))
        return target

    def _files_target(
        self, caller: str, rows: list[tuple[str, dict[str, Any], dict[str, str], str | None]]
    ) -> Target:
        """The file server for one caller: `rows` is each workspace in their
        view, by its name there, with their rules in it per group and whose
        approval it runs under (J79)."""
        folders: dict[str, dict[str, Any]] = {}
        rules: dict[str, dict[str, str]] = {}
        blocked: dict[str, tuple[str, str]] = {}
        # Each approver's state once a call: it reads the links and passkeys.
        reasons: dict[str | None, str | None] = {None: "This machine has no owner."}
        for name, workspace, groups, approver in rows:
            if all(groups[g] == "deny" for g in GROUPS):
                continue
            if approver not in reasons:
                reasons[approver] = self._unapproved(str(approver), caller)
            reason = reasons[approver]
            if reason:
                blocked[name] = (reason, str(workspace["holder"]))
                continue
            folders[name] = workspace
            rules[name] = groups
        readable = [n for n in folders if rules[n]["read"] != "deny"]
        writable = [n for n in folders if rules[n]["change"] != "deny"]
        offered = {t.name: t for t in file_server.tools(readable, writable)}
        return Target(
            FILES,
            "this machine's file server",
            offered,
            {name: None for name in offered},
            {
                "kind": "files",
                "folders": {
                    name: {"path": w["path"], "identity": w["identity"], "deny": list(w["deny"])}
                    for name, w in folders.items()
                },
                "readable": readable,
                "writable": writable,
            },
            folders,
            rules,
            blocked,
        )

    def _owner_in_dev_mode(self, call: SiteCall) -> Target:
        """Eugene's owner on a site: only in dev mode, only with grants the
        root holds for them, only on the site owner's workspaces, and only if
        this site's owner said so here (J6e). A grant names a workspace by id
        alone (J76): the root keeps no paths."""
        if not self.policy.owner_in_dev_mode:
            raise Refused(
                "This machine's owner has not let Eugene's owner in. Dev mode alone opens "
                "nothing on a job site."
            )
        if call.installMode.value != "dev":
            raise Refused("Eugene is in production mode: its owner's own access does not work.")
        owner = self._owner()
        if owner is None:
            raise Refused("This machine has not joined yet.")
        by_id = {w["id"]: (name, w) for name, w, _, _ in self.policy.view(owner)}
        rows: list[tuple[str, dict[str, Any], dict[str, str], str | None]] = []
        for grant in call.grants or []:
            found = by_id.get(grant.folderId)
            if found is None:
                continue
            name, workspace = found
            writable = bool(grant.writable and workspace["writable"])
            rows.append(
                (
                    name,
                    workspace,
                    {"read": "allow", "change": "allow" if writable else "deny"},
                    owner,
                )
            )
        if not rows:
            raise Refused("Eugene's owner has not been given any folder on this machine.")
        return self._files_target(OPERATOR, rows)

    # --- management -------------------------------------------------------------

    async def manage(self, action: SiteManage) -> dict[str, Any]:
        name = action.action.value
        arguments = dict(action.arguments or {})
        subject = action.subject
        owner = self._owner()
        personal = (name in PERSON_ACTIONS or name in PASSKEY_ACTIONS) and subject != OPERATOR
        entry = {
            "subject": subject,
            "kind": "manage",
            "action": name,
            "arguments": None if name in READS or name in PASSKEY_ACTIONS else arguments,
            "reader": subject if personal else owner,
        }
        try:
            self._fresh(action.id, action.expiresAt)
            if owner is None:
                raise Refused("This machine has not joined yet.")
            if name in OWNER_ACTIONS and subject != owner:
                raise Refused(_ONLY_OWNER)
            if subject != owner and (
                subject == OPERATOR or self.links.for_subject(subject) is None
            ):
                raise Refused(
                    f"You are not linked to an account on {self._machine()}, so you keep "
                    "nothing there. Link yourself at the machine first."
                )
            if name in PASSKEY_ACTIONS:
                return await self._passkey_action(name, subject, arguments)
            handler = self._handlers()[name]
            async with self.lock:
                changes = name not in READS
                reduces = changes and self._reduces(name, subject, arguments)
                # A linked person's change waits for their own key, even
                # before they have one (J68); the owner keeps J52's way.
                if changes and not reduces and (subject != owner or self.has_key(subject)):
                    message = self._hold(action, arguments)
                    self.audit.record(**entry, decision="allowed", outcome="held", reason=message)
                    return {"status": "held", "message": message}
                approved = self.policy.approved(subject)
                result = await handler(subject, arguments)
                if reduces and approved and not self.policy.approved(subject):
                    # Less than the person approved is still theirs (J51).
                    self.policy.authorize(subject)
        except Refused as exc:
            self.audit.record(**entry, decision="refused", reason=str(exc))
            return {"status": "failed", "message": str(exc)}
        if name not in READS:
            self.audit.record(**entry, decision="allowed", outcome="done")
        return {"status": "done", "result": result}

    def _handlers(
        self,
    ) -> dict[str, Callable[[str, dict[str, Any]], Awaitable[dict[str, Any]]]]:
        return {
            "workspace.add": self._workspace_add,
            "workspace.remove": self._workspace_remove,
            "workspace.people": self._workspace_people,
            "rules.set": self._rules_set,
            "workspace.list": self._workspace_list,
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

    async def _open(self, path: str, subject: str) -> tuple[str, str]:
        """A folder's path and identity, read by `subject`'s own worker as
        them: what they can open is what can be a workspace of theirs."""
        if reason := self.settings.unavailable():
            raise Refused(reason)
        if not path.strip() or any(ord(c) < 32 for c in path):
            raise Refused("Use a folder path without control characters.")
        try:
            folder_io.check_root_path(path.strip(), self.protected)
        except folder_io.FolderError as exc:
            raise Refused(str(exc)) from None
        account = self._own_account(subject)
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

    # --- the checks a change shares, held or applied --------------------------------

    @staticmethod
    def _groups(rules: SiteRules | None, writable: bool) -> dict[str, str]:
        groups = (
            {"read": rules.read.value, "change": rules.change.value}
            if rules is not None
            else default_groups(writable)
        )
        if not writable and groups["change"] != "deny":
            raise Refused(
                "Nobody may change files in a workspace registered read only. Set changing "
                "files to deny."
            )
        return groups

    @staticmethod
    def _deny(patterns: list[SiteDenyPattern] | None) -> list[str]:
        """A workspace's deny patterns, each one `.gitignore` reads, once."""
        kept: list[str] = []
        for pattern in patterns or []:
            text = pattern.root
            if text in kept:
                continue
            if text.startswith("!") or any(ord(c) < 32 for c in text):
                raise Refused(f"{text!r} is not a pattern this site takes. Patterns only hide.")
            try:
                pathspec.GitIgnoreSpec.from_lines([text])
            except (ValueError, TypeError):
                raise Refused(f"{text!r} is not a pattern this site can read.") from None
            kept.append(text)
        if len(kept) > MAX_DENY:
            raise Refused(f"A workspace takes at most {MAX_DENY} patterns.")
        return kept

    def _new_workspace(self, subject: str, name: str, path: str) -> tuple[str, str]:
        """The cheap checks on a new workspace of `subject`'s."""
        if reason := self.settings.unavailable() or self._broken():
            raise Refused(reason)
        name, path = name.strip(), path.strip()
        if not name or any(ord(c) < 32 for c in name):
            raise Refused("Use a workspace name without control characters.")
        if name.casefold() in {w["name"].casefold() for w in self.policy.own(subject)}:
            raise Refused(f"You have a workspace named {name} already. Choose another name.")
        if not path or any(ord(c) < 32 for c in path):
            raise Refused("Use a folder path without control characters.")
        try:
            folder_io.check_root_path(path, self.protected)
        except folder_io.FolderError as exc:
            raise Refused(str(exc)) from None
        if self.links.for_subject(subject) is None:
            raise Refused(self._not_linked())
        return name, path

    def _own_workspace(self, subject: str, workspace_id: str) -> dict[str, Any]:
        workspace = self.policy.workspace(workspace_id)
        if workspace is None or workspace["holder"] != subject:
            raise Refused(_NO_WORKSPACE)
        return workspace

    def _shares(
        self, workspace: dict[str, Any], people: list[tuple[str, dict[str, str]]]
    ) -> list[dict[str, Any]]:
        """Whom the owner shares `workspace` with, checked (J69)."""
        owner = self._owner()
        out: list[dict[str, Any]] = []
        for subject, groups in people:
            if subject == OPERATOR:
                raise Refused(_OPERATOR_NOT_A_PERSON)
            if subject == owner:
                raise Refused("A workspace of yours is yours already: share it with others.")
            self._only_owner(subject)
            if any(p["subject"] == subject for p in out):
                raise Refused("Each person is named once.")
            if not workspace["writable"] and groups["change"] != "deny":
                raise Refused(
                    f"Nobody may change files in {workspace['name']}: it was registered read-only."
                )
            out.append({"subject": subject, "rules": per_tool(groups)})
        return out

    def _only_owner(self, subject: str) -> None:
        if not self.settings.sharing and subject != self._owner():
            raise Refused(
                f"{self._machine()} serves only its owner: it has no folder boundary yet."
            )

    # --- each person's workspaces (2b.3b) -----------------------------------------

    async def _add(
        self,
        subject: str,
        name: str,
        path: str,
        writable: bool,
        groups: dict[str, str],
        deny: list[str],
    ) -> dict[str, Any]:
        name, path = self._new_workspace(subject, name, path)
        full, identity = await self._open(path, subject)
        if any(w["identity"] == identity for w in self.policy.own(subject)):
            raise Refused("This folder is one of your workspaces already.")
        workspace = {
            "id": secrets.token_hex(16),
            "name": name,
            "path": full,
            "identity": identity,
            "holder": subject,
            "writable": writable,
            "rules": per_tool(groups),
            "deny": deny,
            "people": [],
        }
        try:
            self.policy.add_workspace(workspace)
        except ValueError as exc:
            raise Refused(str(exc)) from None
        return workspace

    async def _workspace_add(self, subject: str, arguments: dict[str, Any]) -> dict[str, Any]:
        value = self._parse(SiteWorkspaceAdd, arguments)
        writable = value.writable is not False
        workspace = await self._add(
            subject,
            value.name,
            value.path,
            writable,
            self._groups(value.rules, writable),
            self._deny(value.deny),
        )
        return self._workspace_detail(workspace)

    async def _workspace_remove(self, subject: str, arguments: dict[str, Any]) -> dict[str, Any]:
        value = self._parse(SiteWorkspaceRemove, arguments)
        self._own_workspace(subject, value.id)
        self.policy.remove_workspace(value.id)
        return {"id": value.id}

    async def _workspace_people(self, subject: str, arguments: dict[str, Any]) -> dict[str, Any]:
        value = self._parse(SiteWorkspacePeople, arguments)
        workspace = self._own_workspace(subject, value.id)
        people = self._shares(
            workspace,
            [(p.subject, {"read": p.read.value, "change": p.change.value}) for p in value.people],
        )
        self.policy.set_people(value.id, people)
        return self._workspace_detail(workspace)

    async def _rules_set(self, subject: str, arguments: dict[str, Any]) -> dict[str, Any]:
        value = self._parse(SiteRulesSet, arguments)
        workspace = self._own_workspace(subject, value.id)
        groups = self._groups(value.rules, bool(workspace["writable"]))
        self.policy.set_rules(value.id, per_tool(groups), self._deny(value.deny))
        return self._workspace_detail(workspace)

    async def _workspace_list(self, subject: str, arguments: dict[str, Any]) -> dict[str, Any]:
        self._parse(SiteWorkspaceListRequest, arguments)
        return {"workspaces": [self._workspace_detail(w) for w in self.policy.own(subject)]}

    # --- the owner's, for a root from before 2b.3b ------------------------------------

    async def _folder_add(self, subject: str, arguments: dict[str, Any]) -> dict[str, Any]:
        value = self._parse(SiteFolderAdd, arguments)
        writable = bool(value.writable)
        workspace = await self._add(
            subject, value.name, value.path, writable, default_groups(writable), []
        )
        return self._folder_view(workspace)

    async def _folder_remove(self, subject: str, arguments: dict[str, Any]) -> dict[str, Any]:
        value = self._parse(SiteFolderRemove, arguments)
        workspace = self.policy.workspace(value.id)
        if workspace is None or workspace["holder"] != subject:
            raise Refused("This folder is no longer registered.")
        self.policy.remove_workspace(value.id)
        return {"id": value.id}

    @staticmethod
    def _folder_groups(
        value: SiteFolderPeople, owner: str | None
    ) -> list[tuple[str, dict[str, str]]]:
        """An older root's list as rules: changing files was a standing
        pre-approval, so it reads `allow`. The owner, whom J11 put on their
        own lists, has rules of their own now."""
        return [
            (p.subject, {"read": "allow", "change": "allow" if p.writable else "deny"})
            for p in value.people
            if p.subject != owner
        ]

    async def _folder_people(self, subject: str, arguments: dict[str, Any]) -> dict[str, Any]:
        value = self._parse(SiteFolderPeople, arguments)
        workspace = self.policy.workspace(value.id)
        if workspace is None or workspace["holder"] != subject:
            raise Refused("This folder is no longer registered.")
        people = self._shares(workspace, self._folder_groups(value, subject))
        self.policy.set_people(value.id, people)
        return self._folder_view(workspace)

    # --- the owner's: local servers and settings ---------------------------------------

    async def _offered(self, server: str) -> tuple[str, dict[str, types.Tool]]:
        """A local server's name and every tool it offers, for granting."""
        if server == FILES:
            raise Refused("Workspaces are shared one by one, not through the file server.")
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

    async def _access_set(self, subject: str, arguments: dict[str, Any]) -> dict[str, Any]:
        value = self._parse(SiteAccessSet, arguments)
        server = str(value.server)
        name, offered = await self._offered(server)
        people: list[dict[str, Any]] = []
        for person in value.people:
            if person.subject == OPERATOR:
                raise Refused(_OPERATOR_NOT_A_PERSON)
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
                tools.append({"name": grant.name, "decision": grant_decision(grant, tool)})
            people.append({"subject": person.subject, "tools": tools})
        self.policy.set_access(server, people)
        return {"server": self._server_view(server), "people": self._access_people(server)}

    def _access_people(self, server: str) -> list[dict[str, Any]]:
        return [
            {"subject": p["subject"], "tools": [_grant_view(t) for t in p["tools"]]}
            for p in self.policy.people(server)
        ]

    async def _server_enable(self, subject: str, arguments: dict[str, Any]) -> dict[str, Any]:
        value = self._parse(SiteServerEnable, arguments)
        server = str(value.server)
        if server == FILES:
            raise Refused("The file server is on while a workspace exists.")
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
        return {"server": self._server_view(server), "people": self._access_people(server)}

    async def _settings_set(self, subject: str, arguments: dict[str, Any]) -> dict[str, Any]:
        value = self._parse(SiteSettings, arguments)
        self.policy.set_owner_in_dev_mode(value.ownerInDevMode)
        return {"ownerInDevMode": value.ownerInDevMode}

    async def _audit_read(self, subject: str, arguments: dict[str, Any]) -> dict[str, Any]:
        """The lines that belong to `subject` (J80): the owner's include the
        lines from before each line had a reader."""
        value = self._parse(SiteAuditRead, arguments)
        limit = value.limit or 50
        owner = subject == self._owner()
        return {"entries": await asyncio.to_thread(self.audit.newest, limit, subject, owner)}

    # --- each person's own key (J14a, J67) -----------------------------------------

    def keys_of(self, subject: str) -> dict[str, PersonKey]:
        """The keys pinned at the machine to `subject`'s link."""
        link = self.links.for_subject(subject) if subject != OPERATOR else None
        return {key.id: key for key in link.keys} if link else {}

    def passkeys_of(self, subject: str) -> list[pk.Passkey]:
        """The passkeys paired under `subject`'s current link (J14a.3): one
        paired under an earlier link, or for a person no longer linked,
        approves nothing."""
        link = self.links.for_subject(subject) if subject != OPERATOR else None
        if link is None:
            return []
        return [
            p
            for p in self.passkeys.for_subject(subject)
            if p.account == link.account and p.linked_at == link.linked_at
        ]

    def has_key(self, subject: str) -> bool:
        """Whether `subject` has any key here that approves: one pinned at
        the machine (Path A) or a passkey (Path B). Either makes a change
        that gives access wait for it."""
        return bool(self.keys_of(subject) or self.passkeys_of(subject))

    def signing_state(self, subject: str | None = None) -> str:
        """The state of `subject`'s own rules (the owner's by default): no
        key, rules their key has not approved as they are, or approved."""
        owner = self._owner()
        person = subject if subject is not None else owner
        if person is None or not self.has_key(person):
            return "unsigned"
        return "signed" if self.policy.approved(person) else "unconfirmed"

    def approve_page(self) -> str | None:
        if self.settings.approve_page:
            return self.settings.approve_page
        # An agent from before J14a.2 named only the link page.
        page = self.settings.link_page
        return f"{page.rstrip('/')}/approve" if page else None

    def _at_the_machine(self) -> str:
        page = self.approve_page()
        return f"on {self._machine()}, at {page}" if page else f"at {self._machine()} itself"

    def _unapproved(self, approver: str, caller: str) -> str | None:
        """Why nothing runs under `approver`'s rules for `caller` yet (J48,
        J52, J79), or None."""
        self.links.all()  # the keys are in the links file: its problem first
        if self.links.problem:
            return self.links.problem
        state = self.signing_state(approver)
        if state == "signed":
            return None
        machine = self._machine()
        if approver == caller:
            if state == "unsigned":
                return (
                    f"You have not added your own key on {machine} yet, so nothing runs there "
                    f"under your rules. Add it {self._at_the_machine()}."
                )
            return (
                f"You have not approved your rules on {machine} with your key yet, so nothing "
                f"runs under them. Do it {self._at_the_machine()}."
            )
        if state == "unsigned":
            return (
                f"{machine}'s owner has not added their own key there yet, so nothing they "
                f"shared or allow there runs. They add it {self._at_the_machine()}."
            )
        return (
            f"{machine}'s owner has not approved its rules with their key yet, so nothing they "
            f"shared or allow there runs. They do it {self._at_the_machine()}."
        )

    def _reduces(self, name: str, subject: str, arguments: dict[str, Any]) -> bool:
        """Whether a change only takes access away (J51): it needs no
        signature, and less than the person approved is still theirs."""
        try:
            if name in ("folder.remove", "workspace.remove"):
                return True
            if name == "server.enable":
                return SiteServerEnable.model_validate(arguments).enabled is False
            if name == "settings.set":
                return SiteSettings.model_validate(arguments).ownerInDevMode is False
            if name == "rules.set":
                rules = SiteRulesSet.model_validate(arguments)
                workspace = self.policy.workspace(rules.id)
                if workspace is None or workspace["holder"] != subject:
                    return False
                before = per_group(workspace["rules"], workspace["writable"])
                after = {"read": rules.rules.read.value, "change": rules.rules.change.value}
                kept = {p.root for p in rules.deny}
                return (
                    not any(looser(after[g], before[g]) for g in GROUPS)
                    and set(workspace["deny"]) <= kept
                )
            if name in ("workspace.people", "folder.people"):
                if name == "folder.people":
                    folder = SiteFolderPeople.model_validate(arguments)
                    workspace_id, people = folder.id, self._folder_groups(folder, subject)
                else:
                    shared = SiteWorkspacePeople.model_validate(arguments)
                    workspace_id = shared.id
                    people = [
                        (p.subject, {"read": p.read.value, "change": p.change.value})
                        for p in shared.people
                    ]
                workspace = self.policy.workspace(workspace_id)
                if workspace is None or workspace["holder"] != subject:
                    return False
                shared_before = {
                    p["subject"]: per_group(p["rules"], workspace["writable"])
                    for p in workspace["people"]
                }
                for person, groups in people:
                    old = shared_before.get(person)
                    if old is None or any(looser(groups[g], old[g]) for g in GROUPS):
                        return False
                return True
            if name == "access.set":
                access = SiteAccessSet.model_validate(arguments)
                server = str(access.server)
                local = self.local.entries.get(server)
                known = {t.name: t for t in self.local.known_tools(local)} if local else {}
                for grantee in access.people:
                    granted = self.policy.tools_for(grantee.subject, server)
                    for grant in grantee.tools:
                        if grant.name not in granted:
                            return False
                        tool = known.get(grant.name)
                        now, then = grant_decision(grant, tool), granted[grant.name]
                        if then is None and tool is not None:
                            then = "ask" if is_destructive(tool) else "allow"
                        if now is None or then is None:
                            if now != then:
                                return False
                        elif looser(now, then):
                            return False
                return True
        except ValidationError:
            return False
        return False

    def _hold(self, action: SiteManage, arguments: dict[str, Any]) -> str:
        """Check what can be checked now, then keep the change for its
        person's approval with their own key. The message for Workbench."""
        name = action.action.value
        self._precheck(name, action.subject, arguments)
        subjects = self._named(name, arguments)
        names = {k: str(v)[:256] for k, v in (action.names or {}).items() if k in subjects}
        try:
            self.held.add(action.subject, name, arguments, names)
        except signing.Full as exc:
            raise Refused(str(exc)) from None
        if not self.has_key(action.subject):
            return (
                f"Waiting for your own key. You have none on {self._machine()} yet: add one "
                f"{self._at_the_machine()}, then approve this with it. Nothing changes until "
                "you do."
            )
        return (
            f"Waiting for your approval {self._at_the_machine()}, or from Workbench with a "
            "passkey. Nothing changes until you approve it with your key."
        )

    def _precheck(self, name: str, subject: str, arguments: dict[str, Any]) -> None:
        """The cheap half of each change's checks, so a change that cannot
        be applied is refused now rather than held."""
        if name == "workspace.add":
            add = self._parse(SiteWorkspaceAdd, arguments)
            writable = add.writable is not False
            self._new_workspace(subject, add.name, add.path)
            self._groups(add.rules, writable)
            self._deny(add.deny)
        elif name == "folder.add":
            folder = self._parse(SiteFolderAdd, arguments)
            self._new_workspace(subject, folder.name, folder.path)
        elif name == "rules.set":
            rules = self._parse(SiteRulesSet, arguments)
            workspace = self._own_workspace(subject, rules.id)
            self._groups(rules.rules, bool(workspace["writable"]))
            self._deny(rules.deny)
        elif name == "workspace.people":
            shared = self._parse(SiteWorkspacePeople, arguments)
            workspace = self._own_workspace(subject, shared.id)
            self._shares(
                workspace,
                [
                    (p.subject, {"read": p.read.value, "change": p.change.value})
                    for p in shared.people
                ],
            )
        elif name == "folder.people":
            listed = self._parse(SiteFolderPeople, arguments)
            folder_of = self.policy.workspace(listed.id)
            if folder_of is None or folder_of["holder"] != subject:
                raise Refused("This folder is no longer registered.")
            self._shares(folder_of, self._folder_groups(listed, subject))
        elif name == "access.set":
            access = self._parse(SiteAccessSet, arguments)
            server = str(access.server)
            local = self.local.entries.get(server)
            if server == FILES:
                raise Refused("Workspaces are shared one by one, not through the file server.")
            if local is None:
                raise Refused("This machine has no such server.")
            if not self.policy.enabled.get(server):
                raise Refused(f"Turn {local.name} on before saying who may use it.")
            # The tools it listed last, when it has: the rest is checked again
            # with a fresh list when the change is approved.
            known = {t.name: t for t in self.local.known_tools(local)}
            for entry in access.people:
                if entry.subject == OPERATOR:
                    raise Refused(_OPERATOR_NOT_A_PERSON)
                self._only_owner(entry.subject)
                for grant in entry.tools if known else ():
                    if grant.name not in known:
                        raise Refused(f"{local.name} has no tool named {grant.name!r}.")
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
        shares = ("folder.people", "access.set", "workspace.people")
        people = arguments.get("people") if name in shares else None
        if not isinstance(people, list):
            return set()
        return {str(p.get("subject")) for p in people if isinstance(p, dict)}

    # --- the starter's page: list, approve, turn down -------------------------------

    def held_list(self, subject: str, key: str | None) -> dict[str, Any]:
        """What `subject` has waiting, for the page at the machine; with one
        of their keys, each with the envelope to sign."""
        keys = set(self.keys_of(subject))
        passkeys = self.passkeys_of(subject)
        keys |= {p.id for p in passkeys}
        if self.links.for_subject(subject) is None or (key is not None and key not in keys):
            raise NotHeld(subject)
        enrollment = self.identity.load()
        self._owner()
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
        if keys and not self.policy.approved(subject):
            items.append(
                {
                    "id": RULES,
                    "action": signing.CONFIRM,
                    "words": self._rules_words(subject),
                    "heldAt": None,
                    "envelope": envelope(signing.CONFIRM, {"digest": self.policy.digest(subject)}),
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
            "passkeys": [p.view() for p in passkeys],
            "state": self.signing_state(subject),
            "items": items,
        }

    async def approve(self, ident: str, approval: SiteApproval) -> dict[str, Any]:
        """Apply a held change (or a person's rules as a whole) once that
        person's key has signed it at the machine."""
        subject = approval.subject

        def verify(site: str, enrolled_at: str, act: str, args: dict[str, Any]) -> tuple[str, int]:
            checked = signing.check(
                approval.envelope,
                approval.signature,
                site=site,
                enrolled_at=enrolled_at,
                person=subject,
                act=act,
                args=args,
                keys=self.keys_of(subject),
                key=approval.key,
                last_seq=self.sequence.last(subject),
            )
            return checked.key.id, checked.seq

        return await self._approve(ident, subject, verify, "at the machine with key")

    async def approve_passkey(self, subject: str, approval: SitePasskeyApproval) -> dict[str, Any]:
        """The same, approved from Workbench with one of `subject`'s passkeys
        (J14a.3): the assertion, then the envelope's own checks."""

        def verify(site: str, enrolled_at: str, act: str, args: dict[str, Any]) -> tuple[str, int]:
            found = next((p for p in self.passkeys_of(subject) if p.id == approval.key), None)
            if found is None:
                raise signing.NotSigned(
                    "That passkey is not one of yours here. Pair it again with a code from "
                    "the machine."
                )
            count = pk.verify_assertion(
                found,
                approval.envelope,
                credential_id=approval.credentialId,
                authenticator_data=approval.authenticatorData,
                client_data_json=approval.clientDataJSON,
                signature=approval.signature,
            )
            seq = signing.check_envelope(
                approval.envelope,
                site=site,
                enrolled_at=enrolled_at,
                person=subject,
                act=act,
                args=args,
                key=approval.key,
                last_seq=self.sequence.last(subject),
            )
            self.passkeys.counted(found.id, count)
            return found.id, seq

        return await self._approve(approval.id, subject, verify, "from Workbench with passkey")

    async def _approve(
        self,
        ident: str,
        subject: str,
        verify: Callable[[str, str, str, dict[str, Any]], tuple[str, int]],
        how: str,
    ) -> dict[str, Any]:
        """Each person's key approves only their own items (J67): a held
        change is theirs, and the rules they confirm are their own."""
        if self.links.for_subject(subject) is None:
            raise NotHeld(subject)
        owner = self._owner()
        held = None if ident == RULES else self.held.get(ident)
        if ident == RULES:
            act, args = signing.CONFIRM, {"digest": self.policy.digest(subject)}
        elif held is None or held.subject != subject:
            raise NotHeld(ident)
        else:
            act, args = held.action, held.arguments
        entry = {
            "subject": subject,
            "kind": "manage",
            "action": act,
            "arguments": args,
            "reader": subject if act not in OWNER_ACTIONS else owner,
        }
        async with self.lock:
            # Another approval of the same change may have run while this one
            # waited: what is applied is what is still held.
            if ident != RULES and self.held.get(ident) is None:
                raise NotHeld(ident)
            try:
                enrollment = self.identity.load()
                if enrollment is None:
                    raise Refused("This machine has not joined yet.")
                if act in OWNER_ACTIONS and subject != owner:
                    raise Refused(_ONLY_OWNER)
                if ident == RULES:
                    # The rules as they are now, not as they were when listed.
                    args = {"digest": self.policy.digest(subject)}
                try:
                    key_id, seq = verify(enrollment.site, enrollment.enrolledAt, act, args)
                    # Spent before it is applied: one signature, one try.
                    self.sequence.accept(subject, seq)
                except signing.NotSigned as exc:
                    raise Refused(str(exc)) from None
                result: dict[str, Any] = {}
                if ident == RULES:
                    self.policy.authorize(subject)
                else:
                    approved = self.policy.approved(subject)
                    result = await self._handlers()[act](subject, args)
                    self.held.remove(ident)
                    if approved:
                        self.policy.authorize(subject)
            except Refused as exc:
                self.audit.record(**entry, decision="refused", reason=str(exc))
                return {"status": "failed", "message": str(exc)}
        self.audit.record(
            **entry,
            decision="allowed",
            outcome="done",
            reason=f"Approved {how} {key_id[:8]}.",
        )
        return {"status": "done", "result": result}

    def reject(self, ident: str, subject: str, where: str = "at the machine") -> None:
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
            reason=f"Turned down {where}.",
            reader=subject if held.action not in OWNER_ACTIONS else self._owner(),
        )

    # --- passkeys from Workbench (J14a.3, J67) ---------------------------------------

    async def _passkey_action(
        self, name: str, subject: str, arguments: dict[str, Any]
    ) -> dict[str, Any]:
        """A passkey's work from Workbench, through the root, for the person
        who asks. None of it is a change to what this machine allows: pairing
        needs the code shown at the machine, an approval needs the passkey's
        signature, and turning a change down keeps access from being given, as
        removing a passkey takes a key away (a lost phone)."""
        if name == "held.approve":
            approval = self._parse(SitePasskeyApproval, arguments)
            try:
                return await self.approve_passkey(subject, approval)
            except NotHeld:
                return {"status": "failed", "message": _NOT_WAITING}
        if name == "held.list":
            value = self._parse(SiteHeldListRequest, arguments)
            try:
                listed = await asyncio.to_thread(self.held_list, subject, value.key)
            except NotHeld:
                return {"status": "failed", "message": _NO_PASSKEY}
            return {"status": "done", "result": listed}
        if name == "held.reject":
            rejected = self._parse(SiteHeldRejectRequest, arguments)
            try:
                self.reject(rejected.id, subject, "from Workbench")
            except NotHeld:
                return {"status": "failed", "message": _NOT_WAITING}
            return {"status": "done", "result": {}}
        if name == "passkey.remove":
            removed = self._parse(SitePasskeyRemove, arguments)
            # Not while an approval with it is being checked.
            async with self.lock:
                try:
                    await asyncio.to_thread(
                        self.passkey_remove, subject, removed.id, "from Workbench"
                    )
                except NotHeld:
                    return {"status": "failed", "message": _NO_SUCH_PASSKEY}
            return {"status": "done", "result": {}}
        pairing = self._parse(SitePasskeyPair, arguments)
        entry = {
            "subject": subject,
            "kind": "manage",
            "action": name,
            "arguments": {"rpId": pairing.rpId, "label": pairing.label},
            "reader": subject,
        }
        try:
            passkey = await self._pair(subject, pairing)
        except Refused as exc:
            self.audit.record(**entry, decision="refused", reason=str(exc))
            return {"status": "failed", "message": str(exc)}
        self.audit.record(
            **entry,
            decision="allowed",
            outcome="done",
            reason=f"Passkey {passkey.id[:8]} paired from Workbench with the code shown here.",
        )
        return {"status": "done", "result": passkey.view()}

    async def _pair(self, subject: str, value: SitePasskeyPair) -> pk.Passkey:
        enrollment = self.identity.load()
        link = self.links.for_subject(subject)
        if enrollment is None or link is None:
            raise Refused(
                f"You are not linked to an account on {self._machine()}, so it has no code "
                "for you. Link yourself there first."
            )
        alg = int(value.alg.value)
        try:
            passkey = pk.pair(
                subject=subject,
                site=enrollment.site,
                account=link.account,
                linked_at=link.linked_at,
                credential_id=value.credentialId,
                public_key=value.publicKey,
                alg=alg,
                rp_id=value.rpId,
                label=value.label,
            )
            text = pk.binding(
                site=enrollment.site,
                person=subject,
                credential_id=value.credentialId,
                public_key=value.publicKey,
                alg=alg,
                rp_id=value.rpId,
            )
            await asyncio.to_thread(
                self.codes.check, subject, site=enrollment.site, text=text, given=value.mac
            )
            return self.passkeys.add(passkey)
        except signing.NotSigned as exc:
            raise Refused(str(exc)) from None

    def _linked_here(self, subject: str) -> Link:
        link = self.links.for_subject(subject)
        if link is None:
            raise NotHeld(subject)
        return link

    def passkey_code(self, subject: str) -> dict[str, Any]:
        """A code for the starter to show (`POST /v1/passkeys/code`), for any
        linked person: each person's keys approve only their own items (J67)."""
        self._linked_here(subject)
        code, expires = self.codes.make(subject)
        return {"subject": subject, "code": code, "expiresAt": _iso(expires)}

    def passkey_list(self, subject: str) -> dict[str, Any]:
        self._linked_here(subject)
        waiting = self.codes.waiting(subject)
        return {
            "subject": subject,
            "passkeys": [p.view() for p in self.passkeys_of(subject)],
            "codeExpiresAt": _iso(waiting) if waiting is not None else None,
        }

    def passkey_remove(self, subject: str, ident: str, where: str = "at the machine") -> None:
        """A passkey goes, at the machine (J45) or from Workbench (J60). What
        it approved stays; with no key left, nothing runs under that person's
        rules (J48, J79)."""
        self._linked_here(subject)
        if not self.passkeys.remove(subject, ident):
            raise NotHeld(ident)
        self.audit.record(
            subject=subject,
            kind="manage",
            action="passkey.remove",
            arguments={"id": ident},
            decision="allowed",
            outcome="done",
            reason=f"Removed {where}.",
            reader=subject,
        )

    # --- a change in this site's own words ------------------------------------------

    def _who(self, subject: str, names: dict[str, str]) -> str:
        if subject == self._owner():
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

    @staticmethod
    def _rules_text(groups: dict[str, str]) -> str:
        return f"read and search: {groups['read']}; change files: {groups['change']}"

    def _words(self, held: signing.Held) -> list[str]:
        args, names = held.arguments, held.names
        try:
            if held.action == "workspace.add":
                add = SiteWorkspaceAdd.model_validate(args)
                writable = add.writable is not False
                groups = self._groups(add.rules, writable)
                lines = [
                    f"Add the workspace {add.path.strip()} as “{add.name.strip()}”, opened as "
                    "your own account.",
                    f"Your rules there: {self._rules_text(groups)}.",
                ]
                if not writable:
                    lines.append("It is read only: no file in it may be changed.")
                if add.deny:
                    lines.append("Hidden from every tool: " + ", ".join(p.root for p in add.deny))
                return lines
            if held.action == "rules.set":
                rules = SiteRulesSet.model_validate(args)
                workspace = self.policy.workspace(rules.id)
                label = (
                    f"“{workspace['name']}” ({workspace['path']})" if workspace else "a workspace"
                )
                groups = {"read": rules.rules.read.value, "change": rules.rules.change.value}
                return [
                    f"Your rules in {label}: {self._rules_text(groups)}.",
                    "Hidden from every tool: " + ", ".join(p.root for p in rules.deny)
                    if rules.deny
                    else "Nothing in it is hidden.",
                ]
            if held.action == "workspace.people":
                shared = SiteWorkspacePeople.model_validate(args)
                return self._people_words(
                    shared.id,
                    [
                        (p.subject, {"read": p.read.value, "change": p.change.value})
                        for p in shared.people
                    ],
                    names,
                )
            if held.action == "folder.add":
                add_folder = SiteFolderAdd.model_validate(args)
                return [
                    f"Add the folder {add_folder.path.strip()} as “{add_folder.name.strip()}”.",
                    "You may read it without asking, and are asked before files change."
                    if add_folder.writable
                    else "It is read only: nobody may change files in it.",
                    "Nobody else may use it until you say who.",
                ]
            if held.action == "folder.people":
                folder = SiteFolderPeople.model_validate(args)
                return self._people_words(
                    folder.id, self._folder_groups(folder, held.subject), names
                )
            if held.action == "access.set":
                access = SiteAccessSet.model_validate(args)
                local = self.local.entries.get(str(access.server))
                known = {t.name: t for t in self.local.known_tools(local)} if local else {}
                lines = [f"Who may use {self._server_name(str(access.server))}'s tools:"]
                for person in access.people:
                    tools = ", ".join(
                        t.name + f" ({grant_decision(t, known.get(t.name)) or 'as the tool says'})"
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
        except (ValidationError, Refused):
            pass
        return [f"{held.action}: {signing.canonical(args)[:900]}"]

    def _people_words(
        self, workspace_id: str, people: list[tuple[str, dict[str, str]]], names: dict[str, str]
    ) -> list[str]:
        workspace = self.policy.workspace(workspace_id)
        label = f"“{workspace['name']}” ({workspace['path']})" if workspace else "a workspace"
        writable = bool(workspace and workspace["writable"])
        before = {
            p["subject"]: per_group(p["rules"], writable)
            for p in (workspace or {}).get("people", [])
        }
        lines = [f"Whom you share {label} with:"]
        for subject, groups in people:
            what = self._rules_text(groups)
            if subject not in before:
                what += " (new)"
            elif any(looser(groups[g], before[subject][g]) for g in GROUPS):
                what += " (more than before)"
            lines.append(f"• {self._who(subject, names)}: {what}")
        kept = {subject for subject, _ in people}
        lines += [f"• no longer: {self._who(s, names)}" for s in before if s not in kept]
        if not people:
            lines.append("• nobody")
        return lines

    def _rules_words(self, subject: str) -> list[str]:
        """`subject`'s own rules as a whole, as their key approves them."""
        lines = ["Keep your rules on this machine as they are now:"]
        none: dict[str, str] = {}
        own = self.policy.own(subject)
        if not own:
            lines.append("• No workspaces.")
        for workspace in own:
            mode = "" if workspace["writable"] else ", read only"
            lines.append(
                f"• Workspace “{workspace['name']}” ({workspace['path']}){mode}: "
                f"{self._rules_text(per_group(workspace['rules'], workspace['writable']))}."
            )
            if workspace["deny"]:
                lines.append("  Hidden from every tool: " + ", ".join(workspace["deny"]))
            for person in workspace["people"]:
                groups = per_group(person["rules"], workspace["writable"])
                who = self._who(person["subject"], none)
                lines.append(f"  Shared with {who}: {self._rules_text(groups)}.")
        if subject != self._owner():
            return lines
        for server, on in sorted(self.policy.enabled.items()):
            if not on:
                continue
            people = "; ".join(
                f"{self._who(e['subject'], none)}: "
                + ", ".join(
                    f"{t['name']} ({t.get('decision') or 'as the tool says'})" for t in e["tools"]
                )
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

    def _shared_view(self, workspace: dict[str, Any]) -> list[dict[str, Any]]:
        return [
            {"subject": p["subject"], **per_group(p["rules"], workspace["writable"])}
            for p in workspace["people"]
        ]

    def _workspace_view(self, workspace: dict[str, Any]) -> dict[str, Any]:
        """`SiteWorkspace`: what the root keeps, never the path (J76)."""
        return {
            "id": workspace["id"],
            "name": workspace["name"],
            "holder": workspace["holder"],
            "writable": workspace["writable"],
            "rules": per_group(workspace["rules"], workspace["writable"]),
            "people": self._shared_view(workspace),
        }

    def _workspace_detail(self, workspace: dict[str, Any]) -> dict[str, Any]:
        """`SiteWorkspaceDetail`: for its holder alone, read live."""
        return {
            **self._workspace_view(workspace),
            "path": workspace["path"],
            "deny": list(workspace["deny"]),
        }

    def _folder_view(self, workspace: dict[str, Any]) -> dict[str, Any]:
        """`SiteFolder`, for a root from before 2b.3b."""
        names = {w["id"]: name for name, w, _, _ in self.policy.view(str(workspace["holder"]))}
        return {
            "id": workspace["id"],
            "name": names.get(workspace["id"], workspace["name"]),
            "path": workspace["path"],
            "identity": workspace["identity"],
            "writable": workspace["writable"],
            "people": [
                {"subject": p["subject"], "writable": p["change"] != "deny"}
                for p in self._shared_view(workspace)
            ],
        }

    def _files_view(self, reason: str | None) -> dict[str, Any]:
        any_workspace = bool(self.policy.workspaces)
        return {
            "id": FILES,
            "name": "Files",
            "kind": "files",
            "system": False,
            "enabled": any_workspace,
            "available": any_workspace and reason is None,
            "reason": reason if any_workspace else "No workspace is registered on this machine.",
            "tools": [tool_view(t) for t in file_server.tools(["workspace"], ["workspace"])],
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
        their own line, with the state of their own rules (J67)."""
        views = []
        for link in self.links.all():
            available = self.workers.connected(link.account)
            views.append(
                {
                    "subject": link.subject,
                    "accountName": link.account_name,
                    "available": available,
                    "reason": None if available else self._not_running(link, own=True),
                    "keys": len(link.keys) + len(self.passkeys_of(link.subject)),
                    "signing": self.signing_state(link.subject),
                    "held": len(self.held.for_subject(link.subject)),
                }
            )
        return views

    def summary(self) -> dict[str, Any] | None:
        """What this site holds (`SiteSummary`), for its next poll; None
        before it has joined."""
        owner = self._owner()
        if owner is None:
            return None
        reason = self.reason()
        self._spawn(self.workers.prune())
        self._refresh_stale()
        servers = [self._files_view(reason)] if self.policy.workspaces else []
        servers += [self._local_view(local, reason) for local in self.local.entries.values()]
        return {
            "owner": owner,
            "ownerInDevMode": self.policy.owner_in_dev_mode,
            "workspaces": [self._workspace_view(w) for w in self.policy.workspaces],
            "servers": servers,
            "access": [
                {
                    "subject": e["subject"],
                    "server": e["server"],
                    "tools": [_grant_view(t) for t in e["tools"]],
                }
                for e in self.policy.access
            ],
            "links": self._links_view(),
            "linkPage": self.settings.link_page,
            "sharing": self.settings.sharing,
            "signing": {
                "state": self.signing_state(owner),
                "held": len(self.held.for_subject(owner)),
                "approvePage": self.approve_page(),
                "passkeys": True,
                "people": True,
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
