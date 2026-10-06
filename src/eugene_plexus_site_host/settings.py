"""What the starter tells the host when it starts it, and nothing else.

Everything arrives in the launch environment (`specs/openapi/site-host.yaml`):
the host reads no configuration file of the agent's. Who the site is, which
root it belongs to and who owns it are its own enrollment, in its data
directory (`identity.py`), never the environment. Two files are named here
that the host reads and can never write, because each lives in the install's
administrator-only place (§3.2):

- **the links** (`SITE_HOST_LINKS_FILE`): who is which OS account here. Only
  the machine's privileged starter makes a link, at the machine.
- **the local servers** (`SITE_HOST_LOCAL_SERVERS_FILE`): written by a machine
  administrator, proven elevated (§6.2). A server marked `system` carries
  that administrator's consent (J9). Each worker reads the same file itself,
  so this host can never name a program for a worker to run.

The host opens no one's files (§3.2): every tool runs in a person's worker.
"""

from __future__ import annotations

import json
import os
import sys
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path

import yaml
from pydantic import ValidationError

from ._generated.models import SiteLocalServer, SiteLocalServerList


class SettingsError(Exception):
    """The launch environment is unusable; the message says which part."""


@dataclass(frozen=True)
class Settings:
    data_dir: Path
    port: int
    account_kind: str | None = None
    protected: tuple[Path, ...] = ()
    local_servers: tuple[SiteLocalServer, ...] = field(default_factory=tuple)
    links_file: Path | None = None
    channel: str | None = None
    link_page: str | None = None
    #: Whether anyone but the owner may be served. False on macOS, which has
    #: no folder boundary yet (§2.6).
    sharing: bool = sys.platform != "darwin"

    def unavailable(self) -> str | None:
        """Why tools cannot run here at all, or None."""
        if sys.platform not in {"win32", "linux", "darwin"}:
            return "Tools on this machine are supported on Windows, Linux and macOS."
        if self.channel is None:
            return "This site was started with no channel for its workers. Update Eugene here."
        return None


def read_local_servers(path: Path | None) -> tuple[SiteLocalServer, ...]:
    """The administrator's list (`SiteLocalServerList`), or none."""
    if path is None:
        return ()
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except FileNotFoundError:
        return ()
    except (OSError, yaml.YAMLError) as exc:
        raise SettingsError(f"the local servers file could not be read: {exc}") from None
    try:
        servers = tuple(SiteLocalServerList.model_validate(raw).servers)
    except ValidationError as exc:
        raise SettingsError(
            f"the local servers file is not valid: {exc.error_count()} errors"
        ) from None
    if len({s.id for s in servers}) != len(servers):
        raise SettingsError("two local servers share an id")
    if any(s.id.startswith("files") for s in servers):
        raise SettingsError("a local server's id begins 'files', which is Eugene's file server")
    return servers


def from_environment(env: Mapping[str, str] | None = None) -> Settings:
    values = os.environ if env is None else env
    try:
        data = Path(values["EUGENE_PLEXUS_APP_DATA_DIR"])
        port = int(values["EUGENE_PLEXUS_APP_BIND_PORT"])
    except (KeyError, ValueError) as exc:
        raise SettingsError(f"the starter did not provide {exc}") from None
    try:
        roots = json.loads(values.get("SITE_HOST_PROTECTED_ROOTS", "[]"))
    except (ValueError, TypeError) as exc:
        raise SettingsError(
            f"the protected roots could not be read: {type(exc).__name__}"
        ) from None
    servers_file = values.get("SITE_HOST_LOCAL_SERVERS_FILE")
    servers = read_local_servers(Path(servers_file) if servers_file else None)
    links = values.get("SITE_HOST_LINKS_FILE")
    protected = (data, Path(sys.prefix), Path(__file__).parent, *(Path(p) for p in roots))
    return Settings(
        data_dir=data,
        port=port,
        account_kind=values.get("EUGENE_PLEXUS_APP_ACCOUNT_KIND"),
        protected=protected,
        local_servers=servers,
        links_file=Path(links) if links else None,
        channel=values.get("SITE_HOST_CHANNEL") or None,
        link_page=values.get("SITE_HOST_LINK_PAGE") or None,
    )
