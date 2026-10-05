from __future__ import annotations

import hashlib
import secrets
import sys
import time
from pathlib import Path
from typing import Any

import pytest

from eugene_plexus_site_host._generated.models import SiteCall, SiteLocalServer, SiteManage
from eugene_plexus_site_host.host import Host
from eugene_plexus_site_host.settings import Settings

ADA = "person-ada"
BO = "person-bo"
FIXTURE = Path(__file__).parent / "fixtures" / "local_server.py"
KIND = "windows_service" if sys.platform == "win32" else "systemd"


def rpc(
    method: str, params: dict[str, Any] | None = None, version: str = "2026-07-28"
) -> dict[str, Any]:
    return {
        "jsonrpc": "2.0",
        "id": secrets.randbelow(10_000),
        "method": method,
        "params": {
            **(params or {}),
            "_meta": {
                "io.modelcontextprotocol/protocolVersion": version,
                "io.modelcontextprotocol/clientInfo": {"name": "tests", "version": "1"},
                "io.modelcontextprotocol/clientCapabilities": {},
            },
        },
    }


def local_server(
    *, system: bool = False, consented: bool = False, sha: str | None = None
) -> SiteLocalServer:
    program = sys.executable
    digest = sha or hashlib.sha256(Path(program).read_bytes()).hexdigest()
    return SiteLocalServer.model_validate(
        {
            "id": "fixture",
            "name": "Fixture",
            "command": program,
            "args": ["-I", str(FIXTURE)],
            "sha256": digest,
            "system": system,
            "consentedAt": "2026-10-05T12:00:00Z" if consented else None,
        }
    )


class Site:
    """A host and the calls the agent would relay to it."""

    def __init__(self, host: Host) -> None:
        self.host = host

    async def mcp(
        self,
        subject: str,
        server: str,
        method: str,
        params: dict[str, Any] | None = None,
        *,
        grants: list[dict[str, Any]] | None = None,
        mode: str = "production",
        request: dict[str, Any] | None = None,
        ident: str | None = None,
        expires: float | None = None,
    ) -> dict[str, Any]:
        call = SiteCall.model_validate(
            {
                "id": ident or secrets.token_hex(8),
                "expiresAt": expires if expires is not None else time.time() + 20,
                "subject": subject,
                "server": server,
                "request": request or rpc(method, params),
                "grants": grants or [],
                "installMode": mode,
            }
        )
        return await self.host.mcp(call)

    async def manage(self, subject: str, action: str, **arguments: Any) -> dict[str, Any]:
        return await self.host.manage(
            SiteManage.model_validate(
                {
                    "id": secrets.token_hex(8),
                    "expiresAt": time.time() + 20,
                    "subject": subject,
                    "action": action,
                    "arguments": arguments,
                }
            )
        )


def settings_for(tmp_path: Path, **overrides: Any) -> Settings:
    data = tmp_path / "data"
    data.mkdir(parents=True, exist_ok=True)
    values: dict[str, Any] = {
        "data_dir": data,
        "port": 0,
        "credential": "secret",
        "mode": "site",
        "owner": ADA,
        "account_kind": KIND,
        "protected": (data,),
    }
    values.update(overrides)
    return Settings(**values)


@pytest.fixture
def folder(tmp_path: Path) -> Path:
    shared = tmp_path / "shared"
    shared.mkdir()
    (shared / "note.txt").write_text("Notes from ada's desk", encoding="utf-8")
    return shared


@pytest.fixture
def site(tmp_path: Path) -> Site:
    return Site(Host(settings_for(tmp_path)))
