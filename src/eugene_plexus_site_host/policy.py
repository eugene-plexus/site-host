"""A job site's own policy: its folders, who may use what, and its settings.

This file is the list rule 2 of §3.3 speaks of: the site keeps it and
refuses anyone not on it, so editing the root's state is not enough to get
in (J6b). It changes only through a management action from the owner the
site pinned at its join, and it is written whole, atomically, beside the
host's audit log in the host's own directory.

Default deny (J8). A folder is open only to the people on its own list: to
read, or also to change files, which is a standing pre-approval for
`write_text` and `edit_text` (J6g). A local server is off until its owner
turns it on, and a person has none of its tools until the owner names them;
a destructive tool is named with `standing: true`, a standing pre-approval,
or not at all.

**Approved** (J14a, J52): `authorized` is the digest of the rules as their
owner last approved them with their own key, at the machine. Rules whose
digest is not it were changed on the root's word alone, and no tool runs
until the owner approves them as a whole. Rules that grant nothing need no
approval.
"""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .file_server import SERVER, unique_names

VERSION = 1
MAX_FOLDERS = 64


@dataclass
class Policy:
    path: Path
    folders: list[dict[str, Any]] = field(default_factory=list)
    access: list[dict[str, Any]] = field(default_factory=list)
    enabled: dict[str, bool] = field(default_factory=dict)
    owner_in_dev_mode: bool = False
    authorized: str | None = None

    @classmethod
    def load(cls, path: Path) -> Policy:
        policy = cls(path)
        if not path.exists():
            return policy
        value = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(value, dict) or value.get("version") != VERSION:
            raise ValueError("the site's policy file is not one this host reads")
        policy.folders = [
            {**f, "people": list(f.get("people") or [])} for f in value.get("folders") or []
        ]
        # Folder grants live on each folder. Grants on the first build's
        # per-folder servers (`files.<id>`) grant nothing now.
        policy.access = [
            e for e in value.get("access") or [] if not str(e.get("server")).startswith(SERVER)
        ]
        policy.enabled = {str(k): bool(v) for k, v in (value.get("enabled") or {}).items()}
        policy.owner_in_dev_mode = bool(value.get("ownerInDevMode"))
        authorized = value.get("authorized")
        policy.authorized = authorized if isinstance(authorized, str) else None
        return policy

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        data = json.dumps(
            {
                "version": VERSION,
                "folders": self.folders,
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

    # --- approved by the owner's key (J52) -------------------------------------

    def digest(self) -> str:
        """SHA-256 over every rule, in a form that does not depend on order of
        writing: what an owner's key approves as a whole."""
        rules = {
            "folders": self.folders,
            "access": self.access,
            "enabled": {k: v for k, v in sorted(self.enabled.items()) if v},
            "ownerInDevMode": self.owner_in_dev_mode,
        }
        text = json.dumps(rules, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        return hashlib.sha256(text.encode()).hexdigest()

    def grants_nothing(self) -> bool:
        return (
            not self.folders
            and not self.access
            and not any(self.enabled.values())
            and not self.owner_in_dev_mode
        )

    def approved(self) -> bool:
        return self.grants_nothing() or self.authorized == self.digest()

    def authorize(self) -> None:
        """The rules as they are now are their owner's."""
        self.authorized = self.digest()
        self.save()

    # --- reads ---------------------------------------------------------------

    def folder(self, folder_id: str) -> dict[str, Any] | None:
        return next((f for f in self.folders if f["id"] == folder_id), None)

    def names(self) -> dict[str, str]:
        """Each folder's id and its name as the `folder` argument takes it."""
        unique = unique_names([f["name"] for f in self.folders])
        return {f["id"]: name for f, name in zip(self.folders, unique, strict=True)}

    def folders_for(self, subject: str) -> list[tuple[dict[str, Any], bool]]:
        """The folders `subject` may use, in order, each with whether they may
        change files in it (never more than the folder allows)."""
        found: list[tuple[dict[str, Any], bool]] = []
        for folder in self.folders:
            person = next((p for p in folder["people"] if p["subject"] == subject), None)
            if person is not None:
                found.append((folder, bool(person["writable"] and folder["writable"])))
        return found

    def tools_for(self, subject: str, server: str) -> dict[str, bool]:
        """The tools `subject` may use on local `server`, each with whether it
        is pre-approved. Empty when they are not on the list."""
        for entry in self.access:
            if entry["subject"] == subject and entry["server"] == server:
                return {t["name"]: bool(t.get("standing")) for t in entry["tools"]}
        return {}

    def people(self, server: str) -> list[dict[str, Any]]:
        return [
            {"subject": e["subject"], "tools": e["tools"]}
            for e in self.access
            if e["server"] == server
        ]

    # --- changes (the owner's, through the host) -----------------------------

    def add_folder(self, folder: dict[str, Any]) -> None:
        if len(self.folders) >= MAX_FOLDERS:
            raise ValueError(f"This machine already has {MAX_FOLDERS} folders. Remove one first.")
        self.folders.append({**folder, "people": []})
        self.save()

    def remove_folder(self, folder_id: str) -> None:
        self.folders = [f for f in self.folders if f["id"] != folder_id]
        self.save()

    def set_folder_people(self, folder_id: str, people: list[dict[str, Any]]) -> None:
        folder = self.folder(folder_id)
        assert folder is not None
        folder["people"] = [
            {"subject": p["subject"], "writable": bool(p["writable"])} for p in people
        ]
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
