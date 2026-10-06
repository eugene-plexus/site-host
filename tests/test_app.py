"""The process: its health on loopback, and the launch environment."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml
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
    """The administrator's list, a YAML file the host reads itself (§3.2)."""
    path = tmp_path / "servers.yaml"
    path.write_text(yaml.safe_dump({"servers": list(servers)}), encoding="utf-8")
    return {"SITE_HOST_LOCAL_SERVERS_FILE": str(path)}


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


def test_health_before_the_join_and_without_a_channel_for_workers(tmp_path: Path) -> None:
    settings = settings_for(tmp_path, enrolled=False)
    with TestClient(create_app(settings, channel=Idle())) as client:  # type: ignore[arg-type]
        assert client.get("/healthz").json()["site"] is None
    # 2b.2: what makes tools unavailable is no channel to reach workers on.
    unreachable = settings_for(tmp_path / "other", channel=None)
    with TestClient(create_app(unreachable, channel=Idle())) as client:  # type: ignore[arg-type]
        answer = client.get("/healthz")
    assert answer.status_code == 503 and "no channel for its workers" in answer.json()["reason"]


def test_health_says_when_the_links_file_cannot_be_read(tmp_path: Path) -> None:
    settings = settings_for(tmp_path)
    assert settings.links_file is not None
    settings.links_file.write_text("{not json", encoding="utf-8")
    with TestClient(create_app(settings, channel=Idle())) as client:  # type: ignore[arg-type]
        # The links are read when asked about: a report asks.
        client.app.state.host.links.for_subject("x")  # type: ignore[attr-defined]
        answer = client.get("/healthz")
    assert answer.status_code == 503 and "links file" in answer.json()["reason"]


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


def test_local_servers_come_in_a_yaml_file_the_host_reads_directly(tmp_path: Path) -> None:
    """A list of any length and any characters; no hash of the file travels in
    the environment any more: the file's place (administrator-only) vouches."""
    big = {**FIXTURE_SERVER, "args": ["{not-a-placeholder}"] + ["x" * 4000] * 8}
    settings = from_environment({**site_env(tmp_path), **servers_file(tmp_path, big)})
    assert settings.local_servers[0].id == "fixture"
    assert len(settings.local_servers[0].args or []) == 9


def test_duplicate_server_ids_are_refused(tmp_path: Path) -> None:
    env = {**site_env(tmp_path), **servers_file(tmp_path, FIXTURE_SERVER, FIXTURE_SERVER)}
    with pytest.raises(SettingsError, match="share an id"):
        from_environment(env)


def test_a_missing_servers_file_means_no_servers(tmp_path: Path) -> None:
    env = {**site_env(tmp_path), "SITE_HOST_LOCAL_SERVERS_FILE": str(tmp_path / "nope.yaml")}
    assert from_environment(env).local_servers == ()


def test_a_malformed_servers_file_is_refused_by_name(tmp_path: Path) -> None:
    path = tmp_path / "bad.yaml"
    path.write_text("servers: [ {id: x} ]", encoding="utf-8")
    with pytest.raises(SettingsError, match="not valid"):
        from_environment({**site_env(tmp_path), "SITE_HOST_LOCAL_SERVERS_FILE": str(path)})
    path.write_text("servers: [", encoding="utf-8")
    with pytest.raises(SettingsError, match="could not be read"):
        from_environment({**site_env(tmp_path), "SITE_HOST_LOCAL_SERVERS_FILE": str(path)})


def test_the_links_channel_and_link_page_come_from_the_environment(tmp_path: Path) -> None:
    env = {
        **site_env(tmp_path),
        "SITE_HOST_LINKS_FILE": str(tmp_path / "links.json"),
        "SITE_HOST_CHANNEL": "chan-1",
        "SITE_HOST_LINK_PAGE": "http://127.0.0.1:8079/link",
    }
    settings = from_environment(env)
    assert settings.links_file == tmp_path / "links.json"
    assert settings.channel == "chan-1" and settings.link_page == "http://127.0.0.1:8079/link"
    bare = from_environment(site_env(tmp_path))
    assert bare.links_file is None and bare.channel is None and bare.link_page is None
    assert bare.unavailable() is not None


def test_unavailable_is_only_the_platform_and_the_channel(tmp_path: Path) -> None:
    assert settings_for(tmp_path, channel="x").unavailable() is None
    assert "no channel" in (settings_for(tmp_path, channel=None).unavailable() or "")
    assert settings_for(tmp_path, channel="x", account_kind=None).unavailable() is None
