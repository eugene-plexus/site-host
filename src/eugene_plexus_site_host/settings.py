"""What the agent tells the host when it starts it, and nothing else.

Everything arrives in the launch environment the agent builds
(`specs/openapi/site-host.yaml`): the host reads no configuration file of
the agent's and asks nothing of the root. Two facts here are the agent's to
state and never the host's to change:

- **The owner** (`site` mode): the person the site pinned at its join, the
  only one whose management actions the host accepts (J6b).
- **The local servers**: written by a machine administrator, proven elevated,
  into the install's protected configuration, which the host's own account
  cannot write (§6.2). A server marked `system` carries that administrator's
  consent (J9).
"""

from __future__ import annotations

import json
import os
import sys
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

from pydantic import ValidationError

from ._generated.models import SiteLocalServer

Mode = Literal["site", "node"]

#: The only accounts the file tools run under: a Windows service's or a
#: Linux system unit's, each the host's own (C1).
ISOLATED_ACCOUNTS = frozenset({"windows_service", "systemd"})


class SettingsError(Exception):
    """The launch environment is unusable; the message says which part."""


@dataclass(frozen=True)
class Settings:
    data_dir: Path
    port: int
    credential: str
    mode: Mode
    owner: str | None = None
    account_kind: str | None = None
    protected: tuple[Path, ...] = ()
    local_servers: tuple[SiteLocalServer, ...] = field(default_factory=tuple)

    def unavailable(self) -> str | None:
        """Why tools cannot run here at all, or None."""
        if self.account_kind not in ISOLATED_ACCOUNTS:
            return (
                "Tools on this machine need Eugene installed as a Windows service or a Linux "
                "system service, so they run in an account of their own."
            )
        if sys.platform not in {"win32", "linux"}:
            return "Tools on this machine are supported on Windows and Linux."
        return None


def from_environment(env: Mapping[str, str] | None = None) -> Settings:
    values = os.environ if env is None else env
    try:
        data = Path(values["EUGENE_PLEXUS_APP_DATA_DIR"])
        port = int(values["EUGENE_PLEXUS_APP_BIND_PORT"])
        credential = values["EUGENE_PLEXUS_APP_ADMIN_TOKEN"]
    except (KeyError, ValueError) as exc:
        raise SettingsError(f"the agent did not provide {exc}") from None
    if not credential:
        raise SettingsError("the agent provided an empty credential")
    mode = values.get("SITE_HOST_MODE", "node")
    if mode not in ("site", "node"):
        raise SettingsError(f"SITE_HOST_MODE is {mode!r}, not site or node")
    owner = values.get("SITE_HOST_OWNER") or None
    if mode == "site" and owner is None:
        raise SettingsError("a job site's host needs its owner (SITE_HOST_OWNER)")
    try:
        roots = json.loads(values.get("SITE_HOST_PROTECTED_ROOTS", "[]"))
        raw_servers = json.loads(values.get("SITE_HOST_LOCAL_SERVERS", "[]"))
        servers = tuple(SiteLocalServer.model_validate(s) for s in raw_servers)
    except (ValueError, ValidationError, TypeError) as exc:
        raise SettingsError(f"the agent's lists could not be read: {type(exc).__name__}") from None
    if mode != "site" and servers:
        raise SettingsError("local servers run on a job site only")
    if len({s.id for s in servers}) != len(servers):
        raise SettingsError("two local servers share an id")
    if any(s.id.startswith("files") for s in servers):
        raise SettingsError("a local server's id begins 'files', which is Eugene's file server")
    protected = (data, Path(sys.prefix), Path(__file__).parent, *(Path(p) for p in roots))
    return Settings(
        data_dir=data,
        port=port,
        credential=credential,
        mode=mode,  # type: ignore[arg-type]
        owner=owner,
        account_kind=values.get("EUGENE_PLEXUS_APP_ACCOUNT_KIND"),
        protected=protected,
        local_servers=servers,
    )
