"""A job site's own policy: each person's workspaces and rules, who may use
what, and its settings.

This file is the list rule 2 of §3.3 speaks of: the site keeps it and
refuses anyone not on it, so editing the root's state is not enough to get
in (J6b). It is written whole, atomically, beside the host's audit log in
the host's own directory.

**Workspaces** (2b.3b, J67-J70, `job-sites-own-enrollment.md` §3.3). A
workspace is a folder one linked person, its holder, works in; their own
worker, as their own account, opens it. Today's folders became the site
owner's workspaces (J69), and only the owner's may be shared. Each person's
rules there say `allow`, `ask` or `deny`, stored per tool (J70) so commands
add tools of their own later; the contract speaks of two groups, read and
change. Path patterns on a workspace can only deny, for everyone who uses
it. A workspace registered read-only (`writable: false`) denies every
change, whatever the rules say.

A local server is off until the site's owner turns it on, and a person has
none of its tools until the owner names them, each `allow` or `ask` (J78).

**A file that cannot be used is not run on in part.** One that cannot be read,
is not version 2 or holds an entry this host could not use makes `Policy.load`
raise `PolicyUnreadable`, naming the file and what is wrong. The host then
runs on `Policy.unreadable`: nothing is allowed, nothing may be saved over the
file, and the report says why. A copy of the file is kept beside it, and a
file put right is read again at the next check.

**Approved, per person** (J14a, J52, J67, J79): `authorized` holds, for each
person, the digest of their own rules as they last approved them with their
own key. The owner's covers their workspaces, whom they shared them with,
the local servers and dev mode; anyone else's covers their own workspaces.
Rules whose digest is not the one approved were changed without that
person's key, and nothing runs under them until the person approves them as
a whole. Rules that grant nothing need no approval.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import logging
import os
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .file_server import COMMANDS, DESTRUCTIVE, READ_ONLY, unique_names

log = logging.getLogger(__name__)

VERSION = 2
#: Where a policy file that could not be used is kept, beside itself. One
#: fixed name: the next start has the same file to keep.
UNREADABLE_SUFFIX = ".unreadable"
# Without it a Windows descriptor is in the C runtime's text mode.
_O_BINARY = getattr(os, "O_BINARY", 0)
MAX_WORKSPACES = 512
MAX_PER_PERSON = 64
MAX_DENY = 64
#: The tool groups the contract speaks of (`SiteRules`). `command` (2b.4,
#: J88) is `ask` or `deny`; a workspace's rules from before it have no
#: decision for `run_command`, which reads `deny`, so no approval changes.
GROUPS: dict[str, frozenset[str]] = {
    "read": READ_ONLY,
    "change": DESTRUCTIVE,
    "command": COMMANDS,
}
#: The groups a shared workspace's people have rules for: commands run only
#: in a workspace the caller holds.
SHARED_GROUPS = ("read", "change")
_ORDER = {"allow": 0, "ask": 1, "deny": 2}


def group_of(tool: str) -> str | None:
    return next((group for group, tools in GROUPS.items() if tool in tools), None)


def stricter(a: str, b: str) -> str:
    return a if _ORDER[a] >= _ORDER[b] else b


def looser(a: str, b: str) -> bool:
    """Whether decision `a` lets more through than `b`."""
    return _ORDER[a] < _ORDER[b]


def default_groups(writable: bool, commands: bool = False) -> dict[str, str]:
    """§2.6: a person in their own workspace reads without asking and is
    asked before changing files. A new workspace of their own also asks
    before each command (`commands`, J88); everything older denies them."""
    return {
        "read": "allow",
        "change": "ask" if writable else "deny",
        "command": "ask" if writable and commands else "deny",
    }


def per_tool(groups: dict[str, str]) -> dict[str, str]:
    """`SiteRules` as stored: one decision per tool. A group not given is
    denied."""
    return {
        tool: groups.get(group, "deny") for group, tools in GROUPS.items() for tool in sorted(tools)
    }


def per_group(tools: dict[str, str], writable: bool) -> dict[str, str]:
    """Stored rules as `SiteRules`: each group's strictest decision. A tool
    with no decision (one added after the rules were written) is denied."""
    groups: dict[str, str] = {}
    for group, members in GROUPS.items():
        decision = "allow"
        for tool in members:
            decision = stricter(decision, tools.get(tool, "deny"))
        groups[group] = decision
    if not writable:
        groups["change"] = "deny"
        groups["command"] = "deny"
    return groups


def decision_for(tools: dict[str, str], tool: str, writable: bool) -> str:
    if not writable and (tool in DESTRUCTIVE or tool in COMMANDS):
        return "deny"
    return tools.get(tool, "deny")


class PolicyUnreadable(ValueError):
    """The policy file cannot be used. The message names the file and what is
    wrong with it."""


_DECISIONS = frozenset({"allow", "ask", "deny"})


def _text(value: Any) -> bool:
    return isinstance(value, str) and bool(value)


def _rules_problem(rules: Any, where: str) -> str | None:
    if not isinstance(rules, dict):
        return f"{where} has no rules"
    for tool, decision in rules.items():
        if decision not in _DECISIONS:
            return f"{where} has a rule that is not allow, ask or deny ({tool}: {decision!r})"
    return None


def _workspace_problem(workspace: Any, where: str) -> str | None:
    if not isinstance(workspace, dict):
        return f"{where} is not an object"
    for key in ("id", "name", "path", "identity", "holder"):
        if not _text(workspace.get(key)):
            return f"{where} has no {key}"
    if not isinstance(workspace.get("writable"), bool):
        return f"{where} does not say whether it is writable"
    if problem := _rules_problem(workspace.get("rules"), where):
        return problem
    deny = workspace.get("deny") or []
    if not isinstance(deny, list) or not all(isinstance(p, str) for p in deny):
        return f"{where} has a deny list that is not a list of patterns"
    people = workspace.get("people") or []
    if not isinstance(people, list):
        return f"{where} has a list of people that is not a list"
    for number, person in enumerate(people, start=1):
        if not isinstance(person, dict) or not _text(person.get("subject")):
            return f"{where}, person {number} has no subject"
        if problem := _rules_problem(person.get("rules"), f"{where}, person {number}"):
            return problem
    return None


def _access_problem(entry: Any, where: str) -> str | None:
    if not isinstance(entry, dict):
        return f"{where} is not an object"
    for key in ("subject", "server"):
        if not _text(entry.get(key)):
            return f"{where} has no {key}"
    tools = entry.get("tools")
    if not isinstance(tools, list):
        return f"{where} has no list of tools"
    for tool in tools:
        if not isinstance(tool, dict) or not _text(tool.get("name")):
            return f"{where} has a tool with no name"
        if tool.get("decision") is not None and tool["decision"] not in _DECISIONS:
            return f"{where} has a tool whose decision is not allow, ask or deny"
    return None


def problem_in(value: dict[str, Any]) -> str | None:
    """The first thing wrong with the entries of a version 2 policy, or None.

    Only what this host indexes without asking: a hand-edited file that parses
    is as much "not run on in part" as one that does not."""
    workspaces = value.get("workspaces") or []
    if not isinstance(workspaces, list):
        return "workspaces is not a list"
    for number, workspace in enumerate(workspaces, start=1):
        if problem := _workspace_problem(workspace, f"workspace {number}"):
            return problem
    access = value.get("access") or []
    if not isinstance(access, list):
        return "access is not a list"
    for number, entry in enumerate(access, start=1):
        if problem := _access_problem(entry, f"access entry {number}"):
            return problem
    if not isinstance(value.get("enabled") or {}, dict):
        return "enabled is not an object"
    return None


def keep_a_copy(path: Path) -> Path | None:
    """The file that could not be used, kept beside itself, private: it holds
    people's rules. None when it could not be copied; this runs while a
    failure is explained, and must not add a second."""
    target = path.with_name(path.name + UNREADABLE_SUFFIX)
    temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    try:
        data = path.read_bytes()
        # Private from the first byte, whole or not at all, as every file here.
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | _O_BINARY, 0o600)
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, target)
        except BaseException:
            with contextlib.suppress(OSError):
                os.unlink(temporary)
            raise
    except OSError as exc:
        log.warning("could not keep a copy of %s as %s: %s", path, target.name, exc)
        return None
    return target


@dataclass
class Policy:
    path: Path
    owner: str | None = None
    workspaces: list[dict[str, Any]] = field(default_factory=list)
    access: list[dict[str, Any]] = field(default_factory=list)
    enabled: dict[str, bool] = field(default_factory=dict)
    owner_in_dev_mode: bool = False
    authorized: dict[str, str] = field(default_factory=dict)
    problem: str | None = None
    """Why this policy is empty when its file is not: set by `unreadable`. The
    host refuses everything while it is, and nothing is saved over the file."""
    cause: str | None = None
    """What was wrong with the file, as `PolicyUnreadable` said it, so a file
    edited and still no good is told apart from one left as it was."""

    @classmethod
    def load(cls, path: Path, owner: str | None = None) -> Policy:
        """The policy at `path`, empty when there is no file yet.

        Raises `PolicyUnreadable`, naming the file and what is wrong, for a
        file that cannot be read, is not version 2, or holds an entry this
        host could not use."""
        policy = cls(path, owner)
        if not path.exists():
            return policy
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError as exc:
            raise PolicyUnreadable(
                f"{path} is not UTF-8 text ({exc.reason} at byte {exc.start})"
            ) from exc
        except OSError as exc:
            raise PolicyUnreadable(f"{path} could not be read ({exc.strerror or exc})") from exc
        try:
            value = json.loads(text)
        except json.JSONDecodeError as exc:
            raise PolicyUnreadable(
                f"{path} is not valid JSON ({exc.msg}, line {exc.lineno}, column {exc.colno})"
            ) from exc
        if not isinstance(value, dict):
            raise PolicyUnreadable(
                f"{path} holds {type(value).__name__}, not a policy: a policy is an object"
            )
        if value.get("version") != VERSION:
            raise PolicyUnreadable(
                f"{path} is policy version {value.get('version')!r}, "
                f"and this host reads version {VERSION}"
            )
        if problem := problem_in(value):
            raise PolicyUnreadable(f"{path} cannot be used: {problem}")
        policy.workspaces = [
            {
                **w,
                "deny": list(w.get("deny") or []),
                "people": list(w.get("people") or []),
            }
            for w in value.get("workspaces") or []
        ]
        policy.access = list(value.get("access") or [])
        policy.enabled = {str(k): bool(v) for k, v in (value.get("enabled") or {}).items()}
        policy.owner_in_dev_mode = bool(value.get("ownerInDevMode"))
        authorized = value.get("authorized")
        policy.authorized = (
            {str(k): str(v) for k, v in authorized.items() if isinstance(v, str)}
            if isinstance(authorized, dict)
            else {}
        )
        return policy

    @classmethod
    def unreadable(
        cls, path: Path, owner: str | None, error: PolicyUnreadable, kept: Path | None = None
    ) -> Policy:
        """What a site runs on while its policy file cannot be used: nothing is
        allowed, and `save` refuses to write over the file."""
        policy = cls(path, owner)
        policy.cause = str(error)
        policy.problem = (
            f"This site's policy could not be used: {error}. Nothing runs here until the "
            "file is restored, or removed to start with no workspaces."
            + (f" A copy is kept as {kept.name}." if kept is not None else "")
        )
        return policy

    @classmethod
    def load_or_degrade(cls, path: Path, owner: str | None = None) -> Policy:
        """`load`, or `unreadable` with the file kept beside itself and the
        failure logged: it never raises, so a bad file cannot stop a site from
        starting, only from running anything."""
        try:
            return cls.load(path, owner)
        except PolicyUnreadable as exc:
            policy = cls.unreadable(path, owner, exc, keep_a_copy(path))
            log.error("%s", policy.problem)
            return policy

    def save(self) -> None:
        if self.problem:
            # The file is not this policy: writing it would replace what could
            # not be read with what could.
            raise PolicyUnreadable(self.problem)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        data = json.dumps(
            {
                "version": VERSION,
                "workspaces": self.workspaces,
                "access": self.access,
                "enabled": self.enabled,
                "ownerInDevMode": self.owner_in_dev_mode,
                "authorized": self.authorized,
            },
            ensure_ascii=False,
            indent=2,
        ).encode()
        temporary = self.path.with_suffix(".tmp")
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, self.path)

    # --- approved by each person's own key (J52, J67, J79) ----------------------

    def _rules_of(self, subject: str) -> dict[str, Any]:
        rules: dict[str, Any] = {"workspaces": self.own(subject)}
        if subject == self.owner:
            rules["access"] = self.access
            rules["enabled"] = {k: v for k, v in sorted(self.enabled.items()) if v}
            rules["ownerInDevMode"] = self.owner_in_dev_mode
        return rules

    def digest(self, subject: str) -> str:
        """SHA-256 over `subject`'s own rules, in a form that does not depend
        on order of writing: what their key approves as a whole."""
        text = json.dumps(
            self._rules_of(subject), sort_keys=True, separators=(",", ":"), ensure_ascii=False
        )
        return hashlib.sha256(text.encode()).hexdigest()

    def grants_nothing(self, subject: str) -> bool:
        if self.own(subject):
            return False
        if subject != self.owner:
            return True
        return not self.access and not any(self.enabled.values()) and not self.owner_in_dev_mode

    def approved(self, subject: str) -> bool:
        return self.grants_nothing(subject) or self.authorized.get(subject) == self.digest(subject)

    def authorize(self, subject: str) -> None:
        """`subject`'s rules as they are now are theirs."""
        self.authorized[subject] = self.digest(subject)
        self.save()

    # --- reads ---------------------------------------------------------------

    def workspace(self, workspace_id: str) -> dict[str, Any] | None:
        return next((w for w in self.workspaces if w["id"] == workspace_id), None)

    def own(self, subject: str) -> list[dict[str, Any]]:
        return [w for w in self.workspaces if w["holder"] == subject]

    def shared_with(self, subject: str) -> list[tuple[dict[str, Any], dict[str, Any]]]:
        """The owner's workspaces shared with `subject`, each with their entry."""
        found = []
        for workspace in self.own(self.owner) if self.owner else []:
            person = next((p for p in workspace["people"] if p["subject"] == subject), None)
            if person is not None:
                found.append((workspace, person))
        return found

    def view(self, subject: str) -> list[tuple[str, dict[str, Any], dict[str, str], bool]]:
        """Every workspace `subject` may be offered, in order: their own, then
        those the owner shared with them. Each with its name as their `folder`
        argument takes it, their rules there per group, and whether it is
        their own. The root names a person's view the same way."""
        rows: list[tuple[dict[str, Any], dict[str, str], bool]] = [
            (w, per_group(w["rules"], w["writable"]), True) for w in self.own(subject)
        ]
        rows += [
            (w, per_group(p["rules"], w["writable"]), False) for w, p in self.shared_with(subject)
        ]
        names = unique_names([w["name"] for w, _, _ in rows])
        return [
            (name, w, groups, mine) for name, (w, groups, mine) in zip(names, rows, strict=True)
        ]

    # --- as version 1 read them: folders are workspaces ------------------------

    @property
    def folders(self) -> list[dict[str, Any]]:
        return self.workspaces

    def folder(self, folder_id: str) -> dict[str, Any] | None:
        return self.workspace(folder_id)

    def folders_for(self, subject: str) -> list[tuple[dict[str, Any], bool]]:
        """The workspaces in `subject`'s view, each with whether their rules
        there let them change files at all."""
        return [(w, groups["change"] != "deny") for _, w, groups, _ in self.view(subject)]

    def tools_for(self, subject: str, server: str) -> dict[str, str | None]:
        """The tools `subject` may use on local `server`, each with its
        decision (None: follows whether the tool is destructive, J78). Empty
        when they are not on the list."""
        for entry in self.access:
            if entry["subject"] == subject and entry["server"] == server:
                return {t["name"]: t.get("decision") for t in entry["tools"]}
        return {}

    def people(self, server: str) -> list[dict[str, Any]]:
        return [
            {"subject": e["subject"], "tools": e["tools"]}
            for e in self.access
            if e["server"] == server
        ]

    # --- changes (through the host) ------------------------------------------

    def add_workspace(self, workspace: dict[str, Any]) -> None:
        if len(self.workspaces) >= MAX_WORKSPACES:
            raise ValueError(
                f"This machine already has {MAX_WORKSPACES} workspaces. Remove one first."
            )
        if len(self.own(workspace["holder"])) >= MAX_PER_PERSON:
            raise ValueError(
                f"You already have {MAX_PER_PERSON} workspaces here. Remove one first."
            )
        self.workspaces.append({**workspace, "people": list(workspace.get("people") or [])})
        self.save()

    def remove_workspace(self, workspace_id: str) -> None:
        self.workspaces = [w for w in self.workspaces if w["id"] != workspace_id]
        self.save()

    def set_people(self, workspace_id: str, people: list[dict[str, Any]]) -> None:
        workspace = self.workspace(workspace_id)
        assert workspace is not None
        workspace["people"] = people
        self.save()

    def set_rules(self, workspace_id: str, rules: dict[str, str], deny: list[str]) -> None:
        workspace = self.workspace(workspace_id)
        assert workspace is not None
        workspace["rules"] = rules
        workspace["deny"] = deny
        self.save()

    def set_access(self, server: str, people: list[dict[str, Any]]) -> None:
        self.access = [e for e in self.access if e["server"] != server] + [
            {"subject": p["subject"], "server": server, "tools": p["tools"]}
            for p in people
            if p["tools"]
        ]
        self.save()

    def set_enabled(self, server: str, enabled: bool) -> None:
        self.enabled[server] = enabled
        if not enabled:
            # Turning a server off is not a pause: what was granted on it
            # goes, so turning it on again opens nothing by itself.
            self.access = [e for e in self.access if e["server"] != server]
        self.save()

    def set_owner_in_dev_mode(self, value: bool) -> None:
        self.owner_in_dev_mode = value
        self.save()
