"""The process: its health on loopback, and the launch environment."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from fastapi.testclient import TestClient

from eugene_plexus_site_host.app import create_app
from eugene_plexus_site_host.settings import SettingsError, from_environment

from .conftest import ENROLLMENT, KIND, settings_for

FIXTURE_SERVER = {"id": "fixture", "name": "X", "command": "/bin/x", "sha256": "a" * 64}


def site_env(tmp_path: Path) -> dict[str, str]:
    return {
        "EUGENE_PLEXUS_APP_DATA_DIR": str(tmp_path),
        "EUGENE_PLEXUS_APP_BIND_PORT": "8300",
        "EUGENE_PLEXUS_APP_ACCOUNT_KIND": KIND,
    }


def servers_file(tmp_path: Path, *servers: dict[str, object]) -> dict[str, str]:
    data = json.dumps(list(servers)).encode()
    path = tmp_path / "site-servers.json"
    path.write_bytes(data)
    return {
        "SITE_HOST_LOCAL_SERVERS_FILE": str(path),
        "SITE_HOST_LOCAL_SERVERS_SHA256": hashlib.sha256(data).hexdigest(),
    }


class Idle:
    """A channel that never reaches a root, for the process's own tests."""

    last_contact = None
    problem = "This site has not reached its root yet."

    async def run(self) -> None:
        return None


def test_health_names_the_site_and_nothing_else(tmp_path: Path) -> None:
    with TestClient(create_app(settings_for(tmp_path), channel=Idle())) as client:  # type: ignore[arg-type]
        answer = client.get("/healthz")
    assert answer.status_code == 200
    assert answer.json() == {
        "ready": True,
        "reason": "This site has not reached its root yet.",
        "site": ENROLLMENT.site,
        "lastContactAt": None,
    }


def test_health_before_the_join_and_without_an_account(tmp_path: Path) -> None:
    settings = settings_for(tmp_path, enrolled=False)
    with TestClient(create_app(settings, channel=Idle())) as client:  # type: ignore[arg-type]
        assert client.get("/healthz").json()["site"] is None
    unisolated = settings_for(tmp_path / "other", account_kind=None)
    with TestClient(create_app(unisolated, channel=Idle())) as client:  # type: ignore[arg-type]
        answer = client.get("/healthz")
    assert answer.status_code == 503 and "Windows service" in answer.json()["reason"]


def test_nothing_but_health_is_served(tmp_path: Path) -> None:
    with TestClient(create_app(settings_for(tmp_path), channel=Idle())) as client:  # type: ignore[arg-type]
        for path in ("/v1/report", "/v1/mcp", "/v1/manage"):
            assert client.post(path, json={}).status_code in (404, 405)


def test_the_environment_names_no_owner_and_no_mode(tmp_path: Path) -> None:
    """Who owns the site is its enrollment's to say, never the launch's."""
    settings = from_environment({**site_env(tmp_path), "SITE_HOST_OWNER": "someone"})
    assert not hasattr(settings, "owner") and not hasattr(settings, "mode")


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
