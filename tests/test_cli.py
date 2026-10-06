"""`check-person`: root links someone from their Eugene sign-in typed at the
machine (J36)."""

from __future__ import annotations

import io
import json
from pathlib import Path
from typing import Any

import pytest

from eugene_plexus_site_host import __main__ as cli
from eugene_plexus_site_host.channel import Channel


def test_check_person_prints_who_as_json_and_sends_the_typed_password(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    asked: list[tuple[str, str]] = []

    async def check(_self: Channel, name: str, password: str) -> dict[str, Any]:
        asked.append((name, password))
        return {"subject": "person-jo", "name": "jo"}

    monkeypatch.setattr(Channel, "check_person", check)
    monkeypatch.setattr(cli.sys, "stdin", io.StringIO("hunter2\n"))
    cli.main(["check-person", "--name", "jo", "--data-dir", str(tmp_path)])
    assert json.loads(capsys.readouterr().out) == {"subject": "person-jo", "name": "jo"}
    assert asked == [("jo", "hunter2")]


def test_check_person_exits_with_the_roots_words_when_it_says_no(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    async def check(_self: Channel, _name: str, _password: str) -> dict[str, Any]:
        raise PermissionError("That name or password is not right.")

    monkeypatch.setattr(Channel, "check_person", check)
    monkeypatch.setattr(cli.sys, "stdin", io.StringIO("wrong\n"))
    with pytest.raises(SystemExit, match="not right"):
        cli.main(["check-person", "--name", "jo", "--data-dir", str(tmp_path)])


def test_check_person_needs_a_password(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(cli.sys, "stdin", io.StringIO("\n"))
    with pytest.raises(SystemExit, match="password is needed"):
        cli.main(["check-person", "--name", "jo", "--data-dir", str(tmp_path)])
