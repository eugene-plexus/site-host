"""The loopback API: the agent's credential, bounded bodies, the contract's shapes."""

from __future__ import annotations

import time
from pathlib import Path

from fastapi.testclient import TestClient

from eugene_plexus_site_host.app import create_app
from eugene_plexus_site_host.settings import SettingsError, from_environment

from .conftest import ADA, KIND, rpc, settings_for


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
        "server": "files." + "a" * 32,
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
            {**env, "SITE_HOST_MODE": "node", "SITE_HOST_LOCAL_SERVERS": '[{"id": "x"}]'}
        )
    except SettingsError:
        pass
    else:
        raise AssertionError("a node took local servers")
