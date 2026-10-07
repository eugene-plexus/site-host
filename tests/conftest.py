from __future__ import annotations

import asyncio
import base64
import contextlib
import hashlib
import json
import os
import secrets
import shutil
import sys
import tempfile
import time
from collections.abc import AsyncIterator, Awaitable, Callable
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from eugene_plexus_site_host import local_channel, signing
from eugene_plexus_site_host._generated.models import (
    SiteApproval,
    SiteCall,
    SiteLocalServer,
    SiteManage,
)
from eugene_plexus_site_host.host import Host
from eugene_plexus_site_host.identity import Enrollment, Identity
from eugene_plexus_site_host.settings import Settings
from eugene_plexus_site_host.worker import Worker

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


def new_channel() -> str:
    """A channel name no other test (or program) holds: a pipe name on
    Windows, a socket path in a short directory elsewhere (`AF_UNIX` paths
    are short)."""
    if sys.platform == "win32":
        return "\\\\.\\pipe\\eugene-plexus-site-test-" + secrets.token_hex(8)
    return str(Path(tempfile.mkdtemp(prefix="eps")) / "channel")


def drop_channel(channel: str) -> None:
    if sys.platform != "win32":
        shutil.rmtree(Path(channel).parent, ignore_errors=True)


class PersonKey:
    """A person's key as their browser holds it at the machine (J14a): the
    private half stays here; `entry` is what the starter pins."""

    def __init__(self, label: str = "Chrome on desk") -> None:
        self.private = Ed25519PrivateKey.generate()
        self.raw = self.private.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        self.id = signing.key_id(self.raw)
        self.label = label

    def entry(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "alg": "Ed25519",
            "publicKey": base64.b64encode(self.raw).decode(),
            "label": self.label,
            "addedAt": "2026-10-06T12:00:00Z",
        }

    def sign(self, text: str) -> str:
        return base64.b64encode(self.private.sign(text.encode("utf-8"))).decode()


def link_entry(
    subject: str, account: str, name: str = "person", keys: list[PersonKey] | None = None
) -> dict[str, Any]:
    entry: dict[str, Any] = {
        "subject": subject,
        "name": name,
        "account": account,
        "accountName": "HOST/" + name,
        "linkedAt": "2026-10-06T12:00:00Z",
    }
    if keys:
        entry["keys"] = [key.entry() for key in keys]
    return entry


def write_links(path: Path, *entries: dict[str, Any]) -> None:
    path.write_text(json.dumps({"version": 1, "links": list(entries)}), encoding="utf-8")


#: An account no worker of these tests ever holds: a SID shape on Windows, a
#: uid on POSIX. Never a fixed uid: GitHub's runner IS uid 1001, so a fixed
#: "1001" made every stranger check the test's own account and one test waited
#: for a refusal that never came (CI hung an hour, 2026-10-06).
OTHER_UID = str(os.getuid() + 1) if hasattr(os, "getuid") else "1001"
OTHER_ACCOUNT = "S-1-5-21-1-2-3-1001" if sys.platform == "win32" else OTHER_UID


class Site:
    """A real site host and the calls the agent would relay to it, with a real
    worker (in this process, as this process's own account) joined to it over
    a real channel. Eugene's owner `ADA` is linked to that account; anyone
    else is served by the owner's worker (J27)."""

    def __init__(self, host: Host, key: PersonKey | None = None) -> None:
        self.host = host
        self.key = key
        """The owner's key, pinned with their link; None for an unsigned site."""
        self.worker: Worker | None = None
        self.task: asyncio.Task[None] | None = None
        self.closed = False

    @property
    def account(self) -> str:
        return local_channel.own_account()

    async def start_worker(self, **own: Any) -> None:
        """Connect a worker. `own` replaces what it is given of its own
        (`servers`, `protected`): a worker reads its own list and keeps its own
        protected roots, which need not be the site host's."""
        settings = self.host.settings
        assert settings.channel is not None
        values: dict[str, Any] = {
            "account": self.account,
            "channel": settings.channel,
            "host": self.account,
            "servers": settings.local_servers,
            "protected": list(settings.protected),
            "workspace": settings.data_dir,
            **own,
        }
        self.worker = Worker(**values)
        self.task = asyncio.create_task(self.worker.run())
        await self.until_connected()

    async def until_connected(self, seconds: float = 15.0) -> None:
        deadline = time.perf_counter() + seconds
        while not self.host.workers.connected(self.account):
            if time.perf_counter() > deadline:
                raise AssertionError("the worker never connected to the site host")
            await asyncio.sleep(0.02)

    async def close(self) -> None:
        if self.closed:
            return
        self.closed = True
        if self.task is not None:
            self.task.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await self.task
        await self.host.stop()
        if self.host.settings.channel:
            drop_channel(self.host.settings.channel)

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

    async def manage(
        self,
        subject: str,
        action: str,
        *,
        approve: bool = True,
        names: dict[str, str] | None = None,
        **arguments: Any,
    ) -> dict[str, Any]:
        """A management action from the root. A change the site holds is
        approved at once with the owner's key, as the owner would at the
        machine, unless `approve` is False."""
        answer = await self.host.manage(
            SiteManage.model_validate(
                {
                    "id": secrets.token_hex(8),
                    "expiresAt": time.time() + 20,
                    "subject": subject,
                    "action": action,
                    "arguments": arguments,
                    "names": names,
                }
            )
        )
        if answer.get("status") != "held" or not approve:
            return answer
        held = [h for h in self.host.held.for_subject(subject) if h.action == action]
        assert held, answer
        return await self.approve(held[-1].id, subject)

    async def approve(self, ident: str, subject: str = ADA, key: PersonKey | None = None) -> Any:
        """Sign one listed item at the machine with `key` (the owner's)."""
        key = key or self.key
        assert key is not None, "this site's owner has no key"
        listed = self.host.held_list(subject, key.id)
        item = next(i for i in listed["items"] if i["id"] == ident)
        return await self.host.approve(
            ident,
            SiteApproval(
                subject=subject,
                envelope=item["envelope"],
                key=key.id,
                signature=key.sign(item["envelope"]),
            ),
        )

    async def confirm_rules(self) -> Any:
        """The owner approves the site's rules as a whole (J52)."""
        return await self.approve("rules")


ENROLLMENT = Enrollment(
    site="s-" + "a" * 26,
    label="desk",
    owner=ADA,
    ownerName="ada",
    url="http://127.0.0.1:9",
    rootKey="",
    enrolledAt="2026-10-06T12:00:00+00:00",
)


def joined(data: Path, enrollment: Enrollment = ENROLLMENT) -> Identity:
    """A data directory holding a site's enrollment, as `join` leaves it."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    identity = Identity(data)
    identity.record(Ed25519PrivateKey.generate(), enrollment)
    return identity


def settings_for(tmp_path: Path, *, enrolled: bool = True, **overrides: Any) -> Settings:
    data = tmp_path / "data"
    data.mkdir(parents=True, exist_ok=True)
    if enrolled and not (data / "site.json").exists():
        joined(data)
    values: dict[str, Any] = {
        "data_dir": data,
        "port": 0,
        "account_kind": KIND,
        "protected": (data,),
        "links_file": tmp_path / "links.json",
        "channel": new_channel(),
    }
    values.update(overrides)
    return Settings(**values)


@pytest.fixture
def folder(tmp_path: Path) -> Path:
    shared = tmp_path / "shared"
    shared.mkdir()
    (shared / "note.txt").write_text("Notes from ada's desk", encoding="utf-8")
    return shared


OpenSite = Callable[..., Awaitable[Site]]


@pytest.fixture
async def open_site(tmp_path: Path) -> AsyncIterator[OpenSite]:
    """`await open_site(path, **settings)`: a started host with its owner
    linked to this process's account, with a key pinned (J14a; `signed=False`
    for none), and that account's worker connected."""
    opened: list[Site] = []
    keys: dict[Path, PersonKey] = {}

    async def make(
        path: Path | None = None, *, worker: bool = True, signed: bool = True, **overrides: Any
    ) -> Site:
        where = path or tmp_path
        settings = settings_for(where, **overrides)
        assert settings.links_file is not None
        key = keys.setdefault(where, PersonKey()) if signed else None
        if not settings.links_file.exists():
            write_links(
                settings.links_file,
                link_entry(ADA, local_channel.own_account(), "ada", [key] if key else None),
            )
        made = Site(Host(settings), key)
        opened.append(made)
        await made.host.start()
        assert made.host.workers.problem is None, made.host.workers.problem
        if worker:
            await made.start_worker()
        return made

    yield make
    for made in reversed(opened):
        await made.close()


@pytest.fixture
async def site(open_site: OpenSite) -> Site:
    return await open_site()
