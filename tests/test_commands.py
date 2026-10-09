"""2b.4's command runner (`commands.py`, J84, J87): what is kept of the
output, how long it waits, and that the whole tree stops."""

from __future__ import annotations

import asyncio
import sys
import time
from pathlib import Path
from typing import Any

import pytest

from eugene_plexus_site_host import commands as cmd
from eugene_plexus_site_host.workspace_tools import ANSWER_BUDGET, answer_bytes


def sleeping(seconds: int) -> str:
    return f"Start-Sleep -Seconds {seconds}" if sys.platform == "win32" else f"sleep {seconds}"


def lines(count: int) -> str:
    if sys.platform == "win32":
        return f'1..{count} | ForEach-Object {{ "line $_" }}'
    return f"for i in $(seq 1 {count}); do echo line $i; done"


class Fake:
    """A finished command's buffers, without a process."""

    def __init__(self) -> None:
        self.entry = cmd.Running("c" + "0" * 12, "Work", "x", process=None, job=None)  # type: ignore[arg-type]
        self.entry.exit_code = 0
        self.entry.ended = time.perf_counter()


def test_output_keeps_its_start_and_its_newest_bytes(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(cmd, "HEAD_BYTES", 10)
    monkeypatch.setattr(cmd, "TAIL_BYTES", 20)
    entry = Fake().entry
    entry.take(b"0123456789abcdefghij")
    entry.take(b"KLMNOPQRSTUVWXYZ")
    assert bytes(entry.head) == b"0123456789"
    assert entry.total == 36 and entry.dropped == 6 and entry.tail_from == 16
    data, start, skipped = entry.piece(0, 100)
    assert data == b"0123456789" and start == 0 and skipped == 0  # nothing joins the gap
    data, start, skipped = entry.piece(12, 5)
    assert data == b"ghijK" and start == 16 and skipped == 4
    data, start, skipped = entry.piece(30, 100)
    assert data == b"UVWXYZ" and start == 30


def test_a_summary_shows_the_start_and_the_end_of_long_output() -> None:
    entry = Fake().entry
    entry.take(("x" * 100 + "\n").encode() * 2000)
    value = entry.answer(None)
    assert value["outputBytes"] == 202_000 and value["leftOut"] > 0
    assert "bytes not shown" in value["output"]
    assert value["nextByte"] == 202_000
    assert answer_bytes(value) <= ANSWER_BUDGET


def test_an_answer_fits_its_budget_however_its_output_escapes() -> None:
    entry = Fake().entry
    entry.take(b'"\\' * 30_000)
    assert answer_bytes(entry.answer(0)) <= ANSWER_BUDGET


async def test_a_handle_is_checked_and_unknown_ones_say_why() -> None:
    commands = cmd.Commands()
    with pytest.raises(cmd.CommandError, match="not a command handle"):
        commands.get("../etc")
    with pytest.raises(cmd.CommandError, match="10 minutes"):
        commands.get("c" + "1" * 12)


async def test_an_empty_or_huge_command_is_refused(tmp_path: Path) -> None:
    commands = cmd.Commands()
    with pytest.raises(cmd.CommandError, match="Give the command"):
        await commands.run(folder="w", cwd=str(tmp_path), command="  ", budget=1)
    with pytest.raises(cmd.CommandError, match="at most"):
        await commands.run(folder="w", cwd=str(tmp_path), command="x" * 9000, budget=1)


async def test_a_command_runs_where_it_was_started_and_its_exit_code_is_kept(
    tmp_path: Path,
) -> None:
    commands = cmd.Commands()
    value = await commands.run(
        folder="w", cwd=str(tmp_path), command="echo inside > here.txt; exit 4", budget=10
    )
    assert value["exitCode"] == 4 and value["running"] is False
    assert (tmp_path / "here.txt").exists()


async def test_a_programs_own_exit_code_is_passed_through(tmp_path: Path) -> None:
    """The last program's code, not the shell's: PowerShell's `-Command`
    would say 1 for `cmd /c exit 7`."""
    probe = "cmd /c exit 7" if sys.platform == "win32" else "sh -c 'exit 7'"
    value = await cmd.Commands().run(folder="w", cwd=str(tmp_path), command=probe, budget=10)
    assert value["exitCode"] == 7


async def test_eugenes_own_variables_do_not_reach_a_command(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("EUGENE_PLEXUS_SECRET_THING", "leaked")
    probe = (
        "echo $env:EUGENE_PLEXUS_SECRET_THING"
        if sys.platform == "win32"
        else "echo $EUGENE_PLEXUS_SECRET_THING"
    )
    value = await cmd.Commands().run(folder="w", cwd=str(tmp_path), command=probe, budget=10)
    assert "leaked" not in value["output"]


async def test_a_long_command_is_followed_by_its_handle_and_its_output_read_on(
    tmp_path: Path,
) -> None:
    commands = cmd.Commands()
    value = await commands.run(
        folder="w", cwd=str(tmp_path), command=lines(3) + "; " + sleeping(2), budget=0.5
    )
    assert value["running"] is True and "line 1" in value["output"]
    ended = await commands.output(value["handle"], value["nextByte"], 10)
    assert ended["running"] is False and ended["exitCode"] == 0


async def test_a_command_past_its_limit_is_stopped(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(cmd, "LIMIT_SECONDS", 1.0)
    value = await cmd.Commands().run(folder="w", cwd=str(tmp_path), command=sleeping(30), budget=8)
    assert value["running"] is False and value["stopped"] == "limit"


async def test_stop_ends_the_whole_tree(tmp_path: Path) -> None:
    """What the command started goes with it: the child writes a file after
    a second, which never appears."""
    marker = tmp_path / "late.txt"
    if sys.platform == "win32":
        child = (
            "Start-Process -NoNewWindow powershell -ArgumentList '-NoProfile','-Command',"
            f"'Start-Sleep 2; Set-Content -Path \"{marker}\" -Value late'"
        )
    else:
        child = f"(sleep 2; echo late > '{marker}') &"
    commands = cmd.Commands()
    value = await commands.run(
        folder="w", cwd=str(tmp_path), command=child + "\n" + sleeping(30), budget=0.5
    )
    assert value["running"] is True
    stopped = await commands.stop(value["handle"])
    assert stopped["running"] is False and stopped["stopped"] == "stop"
    await asyncio.sleep(3)
    assert not marker.exists()


async def test_what_a_command_leaves_running_stops_when_it_ends(tmp_path: Path) -> None:
    marker = tmp_path / "orphan.txt"
    if sys.platform == "win32":
        child = (
            "Start-Process -WindowStyle Hidden powershell -ArgumentList '-NoProfile','-Command',"
            f"'Start-Sleep 2; Set-Content -Path \"{marker}\" -Value orphan'"
        )
    else:
        child = f"(sleep 2; echo orphan > '{marker}') &"
    value = await cmd.Commands().run(
        folder="w", cwd=str(tmp_path), command=child + "\necho left", budget=10
    )
    assert value["running"] is False and "left" in value["output"]
    await asyncio.sleep(3)
    assert not marker.exists()


async def test_at_most_four_run_at_once(tmp_path: Path) -> None:
    commands = cmd.Commands()
    handles: list[Any] = []
    try:
        for _ in range(cmd.MAX_RUNNING):
            value = await commands.run(
                folder="w", cwd=str(tmp_path), command=sleeping(30), budget=0
            )
            handles.append(value["handle"])
        with pytest.raises(cmd.CommandError, match="running already"):
            await commands.run(folder="w", cwd=str(tmp_path), command="echo", budget=0)
    finally:
        await commands.close()
