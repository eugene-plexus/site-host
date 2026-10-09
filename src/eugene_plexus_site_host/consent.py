"""The administrator's consent to commands on this machine (2b.4, J9, J30,
J89, `specs/docs/design/person-held-keys.md` §13).

It is kept where an administrator alone writes, beside the local servers
(`SiteLocalServerList.commands` in `servers.yaml`), and recorded only by an
elevated process at the machine: the join's question, the Windows tray behind
UAC, the one-liner again, or the elevated `site consent` CLI. This host reads
it and can never write it; each worker reads it too, and starts no command
without it.

**Taking it back** (J30) is the site's owner's, from Workbench, and needs no
proof: it only takes access away. That is kept in this host's own directory,
with the consent it took back, so a later consent at the machine counts again.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml
from pydantic import ValidationError

from ._generated.models import SiteLocalServerList
from ._private_files import write_private_text


@dataclass(frozen=True)
class State:
    allowed: bool
    consented_at: str | None
    withdrawn_at: str | None


class Consent:
    def __init__(self, servers_file: Path | None, data_dir: Path) -> None:
        self.servers_file = servers_file
        self.path = data_dir / "commands.json"
        self._seen: tuple[float, int] | None = None
        self._given: str | None = None

    def given(self) -> str | None:
        """When an administrator consented, as the list says now; read again
        whenever the file changed."""
        if self.servers_file is None:
            return None
        try:
            info = self.servers_file.stat()
        except OSError:
            self._seen, self._given = None, None
            return None
        seen = (info.st_mtime, info.st_size)
        if seen != self._seen:
            self._seen = seen
            self._given = self._read()
        return self._given

    def _read(self) -> str | None:
        assert self.servers_file is not None
        try:
            raw = yaml.safe_load(self.servers_file.read_text(encoding="utf-8")) or {}
            listed = SiteLocalServerList.model_validate(raw)
        except (OSError, yaml.YAMLError, ValidationError):
            return None
        if listed.commands is None:
            return None
        return listed.commands.consentedAt.isoformat()

    def _withdrawal(self) -> dict[str, Any]:
        try:
            value = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return {}
        return value if isinstance(value, dict) and value.get("version") == 1 else {}

    def state(self) -> State:
        given = self.given()
        withdrawal = self._withdrawal()
        withdrawn = withdrawal.get("withdrawnAt")
        # A withdrawal counts against the consent it took back, not a later one.
        standing = withdrawn is not None and withdrawal.get("consentedAt") == given
        return State(
            allowed=given is not None and not standing,
            consented_at=given,
            withdrawn_at=withdrawn if standing else None,
        )

    def allowed(self) -> bool:
        return self.state().allowed

    def withdraw(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        write_private_text(
            self.path,
            json.dumps(
                {
                    "version": 1,
                    "withdrawnAt": datetime.fromtimestamp(time.time(), UTC).isoformat(),
                    "consentedAt": self.given(),
                }
            ),
        )
