"""The loopback API: the agent's credential, bounded bodies, the contract's shapes."""

from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path

from fastapi.testclient import TestClient

from eugene_plexus_site_host.app import create_app
from eugene_plexus_site_host.settings import SettingsError, from_environment

from .conftest import ADA, KIND, rpc, settings_for

FIXTURE_SERVER = {"id": "fixture", "name": "X", "command": "/bin/x", "sha256": "a" * 64}


def site_env(tmp_path: Path) -> dict[str, str]:
    return {
        "EUGENE_PLEXUS_APP_DATA_DIR": str(tmp_path),
        "EUGENE_PLEXUS_APP_BIND_PORT": "8300",
        "EUGENE_PLEXUS_APP_ADMIN_TOKEN": "t",
        "EUGENE_PLEXUS_APP_ACCOUNT_KIND": KIND,
        "SITE_HOST_MODE": "site",
        "SITE_HOST_OWNER": ADA,
    }


def servers_file(tmp_path: Path, *servers: dict[str, object]) -> dict[str, str]:
    data = json.dumps(list(servers)).encode()
    path = tmp_path / "site-servers.json"
    path.write_bytes(data)
    return {
        "SITE_HOST_LOCAL_SERVERS_FILE": str(path),
        "SITE_HOST_LOCAL_SERVERS_SHA256": hashlib.sha256(data).hexdigest(),
    }


def test_everything_but_health_needs_the_agents_credential(tmp_path: Path) -> None:
    client = TestClient(create_app(settings_for(tmp_path)))
    assert client.get("/healthz").status_code == 200
    assert client.get("/v1/report").status_code == 403
    assert client.get("/v1/report", headers={"Authorization": "Bearer wrong"}).status_code == 403
    report = client.get("/v1/report", headers={"Authorization": "Bearer secret"})
    assert report.status_code == 200 and report.json()["site"]["owner"] == ADA


def test_a_large_body_is_refused_unread(tmp_path: Path) -> None:
    client = TestClient(create_app(settings_for(tmp_path)))
    body = {
        "id": "x",
        "expiresAt": time.time() + 20,
        "subject": ADA,
        "server": "files",
        "request": rpc("tools/call", {"name": "read_text", "arguments": {"path": "a" * 70_000}}),
        "installMode": "production",
    }
    answer = client.post("/v1/mcp", json=body, headers={"Authorization": "Bearer secret"})
    assert answer.status_code == 413


def test_a_site_starts_only_knowing_its_owner(tmp_path: Path) -> None:
    env = {
        "EUGENE_PLEXUS_APP_DATA_DIR": str(tmp_path),
        "EUGENE_PLEXUS_APP_BIND_PORT": "8300",
        "EUGENE_PLEXUS_APP_ADMIN_TOKEN": "t",
        "EUGENE_PLEXUS_APP_ACCOUNT_KIND": KIND,
        "SITE_HOST_MODE": "site",
    }
    try:
        from_environment(env)
    except SettingsError as exc:
        assert "owner" in str(exc)
    else:
        raise AssertionError("a site without an owner started")
    settings = from_environment({**env, "SITE_HOST_OWNER": ADA})
    assert settings.owner == ADA and settings.mode == "site"
    try:
        from_environment(
            {**env, "SITE_HOST_MODE": "node", **servers_file(tmp_path, FIXTURE_SERVER)}
        )
    except SettingsError:
        pass
    else:
        raise AssertionError("a node took local servers")


def test_a_local_server_cannot_take_the_file_servers_name(tmp_path: Path) -> None:
    env = {**site_env(tmp_path), **servers_file(tmp_path, {**FIXTURE_SERVER, "id": "files-extra"})}
    try:
        from_environment(env)
    except SettingsError as exc:
        assert "files" in str(exc)
    else:
        raise AssertionError("a local server took the file server's name")


def test_local_servers_come_in_a_file_the_agent_vouches_for(tmp_path: Path) -> None:
    """A list of any length, and any characters, in a file whose SHA-256 the
    agent names; a file changed since is refused."""
    big = {**FIXTURE_SERVER, "args": ["{not-a-placeholder}"] + ["x" * 4000] * 8}
    files = servers_file(tmp_path, big)
    settings = from_environment({**site_env(tmp_path), **files})
    assert settings.local_servers[0].id == "fixture"
    Path(files["SITE_HOST_LOCAL_SERVERS_FILE"]).write_bytes(b"[]")
    try:
        from_environment({**site_env(tmp_path), **files})
    except SettingsError as exc:
        assert "not the one the agent wrote" in str(exc)
    else:
        raise AssertionError("a changed local servers file was taken")
