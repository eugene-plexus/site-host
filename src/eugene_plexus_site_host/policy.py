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

**Approved, per person** (J14a, J52, J67, J79): `authorized` holds, for each
person, the digest of their own rules as they last approved them with their
own key. The owner's covers their workspaces, whom they shared them with,
the local servers and dev mode; anyone else's covers their own workspaces.
Rules whose digest is not the one approved were changed without that
person's key, and nothing runs under them until the person approves them as
a whole. Rules that grant nothing need no approval.
"""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .file_server import DESTRUCTIVE, READ_ONLY, SERVER, unique_names

VERSION = 2
MAX_WORKSPACES = 512
MAX_PER_PERSON = 64
MAX_DENY = 64
#: The tool groups the contract speaks of (`SiteRules`).
GROUPS: dict[str, frozenset[str]] = {"read": READ_ONLY, "change": DESTRUCTIVE}
_ORDER = {"allow": 0, "ask": 1, "deny": 2}


def group_of(tool: str) -> str | None:
    return next((group for group, tools in GROUPS.items() if tool in tools), None)


def stricter(a: str, b: str) -> str:
    return a if _ORDER[a] >= _ORDER[b] else b


def looser(a: str, b: str) -> bool:
    """Whether decision `a` lets more through than `b`."""
    return _ORDER[a] < _ORDER[b]


def default_groups(writable: bool) -> dict[str, str]:
    """§2.6: a person in their own workspace reads without asking and is
    asked before changing files."""
    return {"read": "allow", "change": "ask" if writable else "deny"}


def per_tool(groups: dict[str, str]) -> dict[str, str]:
    """`SiteRules` as stored: one decision per tool."""
    return {tool: groups[group] for group, tools in GROUPS.items() for tool in sorted(tools)}


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
    return groups


def decision_for(tools: dict[str, str], tool: str, writable: bool) -> str:
    if not writable and tool in DESTRUCTIVE:
        return "deny"
    return tools.get(tool, "deny")


def _from_v1(value: dict[str, Any], owner: str | None) -> dict[str, Any]:
    """Version 1's folders as the owner's workspaces (J69), with §2.6's
    defaults for the owner and, for each person on a folder's list, what
    they had: changing files was a standing pre-approval, so it reads
    `allow`. The owner's approval is not carried: its digest's shape
    changed, and they approve their rules once more."""
    workspaces = []
    for folder in value.get("folders") or []:
        writable = bool(folder.get("writable"))
        people = [
            {
                "subject": str(p["subject"]),
                "rules": per_tool(
                    {
                        "read": "allow",
                        "change": "allow" if writable and p.get("writable") else "deny",
                    }
                ),
            }
            for p in folder.get("people") or []
            if p.get("subject") != owner
        ]
        workspaces.append(
            {
                "id": folder["id"],
                "name": folder["name"],
                "path": folder["path"],
                "identity": folder["identity"],
                "holder": owner,
                "writable": writable,
                "rules": per_tool(default_groups(writable)),
                "deny": [],
                "people": people,
            }
        )
    access = [
        {
            "subject": e["subject"],
            "server": e["server"],
            # A tool granted without `standing` was one the site did not treat
            # as destructive: its decision follows the tool (J78).
            "tools": [
                {"name": t["name"], "decision": "allow" if t.get("standing") else None}
                for t in e.get("tools") or []
            ],
        }
        for e in value.get("access") or []
        # Grants on the first build's per-folder servers (`files.<id>`) grant
        # nothing now.
        if not str(e.get("server")).startswith(SERVER)
    ]
    return {
        "workspaces": workspaces,
        "access": access,
        "enabled": value.get("enabled") or {},
        "ownerInDevMode": bool(value.get("ownerInDevMode")),
        "authorized": {},
    }


@dataclass
class Policy:
    path: Path
    owner: str | None = None
    workspaces: list[dict[str, Any]] = field(default_factory=list)
    access: list[dict[str, Any]] = field(default_factory=list)
    enabled: dict[str, bool] = field(default_factory=dict)
    owner_in_dev_mode: bool = False
    authorized: dict[str, str] = field(default_factory=dict)

    @classmethod
    def load(cls, path: Path, owner: str | None = None) -> Policy:
        policy = cls(path, owner)
        if not path.exists():
            return policy
        value = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(value, dict) or value.get("version") not in (1, VERSION):
            raise ValueError("the site's policy file is not one this host reads")
        if value["version"] == 1:
            value = _from_v1(value, owner)
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

    def save(self) -> None:
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
