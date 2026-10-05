"""A job site's own policy: its folders, who may use what, and its settings.

This file is the list rule 2 of §3.3 speaks of: the site keeps it and
refuses anyone not on it, so editing the root's state is not enough to get
in (J6b). It changes only through a management action from the owner the
site pinned at its join, and it is written whole, atomically, beside the
host's audit log in the host's own directory.

Default deny (J8): a local server is off until its owner turns it on, and a
person has no tool until the owner names it for them. A destructive tool is
named with `standing: true`, a standing pre-approval, or not at all.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

VERSION = 1
MAX_FOLDERS = 64


@dataclass
class Policy:
    path: Path
    folders: list[dict[str, Any]] = field(default_factory=list)
    access: list[dict[str, Any]] = field(default_factory=list)
    enabled: dict[str, bool] = field(default_factory=dict)
    owner_in_dev_mode: bool = False

    @classmethod
    def load(cls, path: Path) -> Policy:
        policy = cls(path)
        if not path.exists():
            return policy
        value = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(value, dict) or value.get("version") != VERSION:
            raise ValueError("the site's policy file is not one this host reads")
        policy.folders = list(value.get("folders") or [])
        policy.access = list(value.get("access") or [])
        policy.enabled = {str(k): bool(v) for k, v in (value.get("enabled") or {}).items()}
        policy.owner_in_dev_mode = bool(value.get("ownerInDevMode"))
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

    # --- reads ---------------------------------------------------------------

    def folder(self, folder_id: str) -> dict[str, Any] | None:
        return next((f for f in self.folders if f["id"] == folder_id), None)

    def tools_for(self, subject: str, server: str) -> dict[str, bool]:
        """The tools `subject` may use on `server`, each with whether it is
        pre-approved. Empty when they are not on the list."""
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
        self.folders.append(folder)
        self.save()

    def remove_folder(self, folder_id: str) -> None:
        server = "files." + folder_id
        self.folders = [f for f in self.folders if f["id"] != folder_id]
        self.access = [e for e in self.access if e["server"] != server]
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
