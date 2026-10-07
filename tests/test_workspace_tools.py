"""2b.3a: the workspace tools beyond list, read and write, through the real
site host and a real worker (`job-sites-own-enrollment.md` §3.3): a read of
any part of a file, `edit_text`, `glob` and `grep`."""

from __future__ import annotations

import hashlib
import json
import os
import sys
import time
from pathlib import Path
from typing import Any

import pytest

from eugene_plexus_site_host import file_server, workspace_tools

from .conftest import ADA, BO, OpenSite, rpc
from .test_folder_scope import FILES, body, granted
from .test_routing import FakeWorker, drop_worker
from .test_worker import bare, folder_work

ANSWER_LIMIT = 70_000


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def link_to(target: Path, at: Path) -> None:
    """A link the tools must not follow: a junction on Windows (no privilege
    needed), a symlink elsewhere."""
    if sys.platform == "win32":
        import _winapi

        _winapi.CreateJunction(str(target), str(at))
    else:
        at.symlink_to(target, target_is_directory=True)


@pytest.fixture
def tree(tmp_path: Path) -> Path:
    """A small repository: code at two depths, an ignored build folder and
    log, a `.git`, a binary file, and a link to a secret outside it."""
    root = tmp_path / "repo"
    (root / "src" / "deep").mkdir(parents=True)
    (root / "build").mkdir()
    (root / ".git").mkdir()
    (root / "src" / "main.py").write_text(
        "def main():\n    return 'Hello'\n", encoding="utf-8", newline="\n"
    )
    (root / "src" / "deep" / "util.py").write_text(
        "def helper():\n    return 'hello again'\n", encoding="utf-8"
    )
    (root / "setup.py").write_text("print('hello setup')\n", encoding="utf-8", newline="\n")
    (root / "README.md").write_text("Say hello.\n", encoding="utf-8", newline="\n")
    (root / "build" / "out.py").write_text("hello = 'built'\n", encoding="utf-8", newline="\n")
    (root / "debug.log").write_text("hello from the log\n", encoding="utf-8", newline="\n")
    (root / ".git" / "config.py").write_text("hello = 'git'\n", encoding="utf-8", newline="\n")
    (root / "image.bin").write_bytes(b"hello\x00\x01\x02")
    (root / ".gitignore").write_text("build/\n*.log\n", encoding="utf-8", newline="\n")
    secret = tmp_path / "secret"
    secret.mkdir()
    (secret / "keys.py").write_text("hello = 'secret'\n", encoding="utf-8", newline="\n")
    link_to(secret, root / "linked")
    # Newest first is checked, so give the files distinct times.
    for age, name in enumerate(["src/main.py", "src/deep/util.py", "setup.py"]):
        stamp = time.time() - 100 * (age + 1)
        os.utime(root / name, (stamp, stamp))
    return root


async def answered(call: Any, tool: str, **arguments: Any) -> dict[str, Any]:
    return body(await call(tool, **arguments))


async def refused(call: Any, tool: str, **arguments: Any) -> str:
    result = await call(tool, **arguments)
    assert result["isError"] is True, result
    text: str = result["content"][0]["text"]
    return text


# --- read_text -----------------------------------------------------------------


async def test_a_read_takes_any_part_and_always_the_whole_files_hash(
    tmp_path: Path, open_site: OpenSite
) -> None:
    root = tmp_path / "shared"
    root.mkdir()
    big = root / "big.txt"
    big.write_text("".join(f"line {n}\n" for n in range(1, 5001)), encoding="utf-8", newline="\n")
    _, _, call = await granted(open_site, tmp_path, root)
    first = await answered(call, "read_text", path="big.txt")
    assert first["sha256"] == sha(big) and first["totalLines"] == 5000
    assert first["fromLine"] == 1 and first["toLine"] == 2000 and first["nextLine"] == 2001
    assert first["text"].startswith("line 1\n") and first["text"].endswith("line 2000\n")
    assert "stoppedShort" not in first
    part = await answered(call, "read_text", path="big.txt", offset=4999, limit=10)
    assert part["text"] == "line 4999\nline 5000\n" and part["sha256"] == sha(big)
    assert part["toLine"] == 5000 and "nextLine" not in part
    past = await refused(call, "read_text", path="big.txt", offset=5001)
    assert "has 5000 lines" in past


async def test_a_large_file_is_read_in_pieces_that_fit_and_say_so(
    tmp_path: Path, open_site: OpenSite
) -> None:
    root = tmp_path / "shared"
    root.mkdir()
    # Quotes and backslashes are escaped twice in an answer: the worst case.
    line = '"\\' * 40 + "\n"
    (root / "quotes.txt").write_text(line * 1500, encoding="utf-8", newline="\n")
    (root / "wide.txt").write_text(
        ("\U0001f680" * 60 + "\n") * 1500, encoding="utf-8", newline="\n"
    )
    site, grants, _ = await granted(open_site, tmp_path, root)
    for name in ("quotes.txt", "wide.txt"):
        answer = await site.mcp(
            BO,
            FILES,
            "tools/call",
            {"name": "read_text", "arguments": {"folder": "Shared", "path": name}},
            grants=grants,
        )
        assert answer["status"] == "done", answer
        assert len(json.dumps(answer["response"], ensure_ascii=False).encode()) < ANSWER_LIMIT
        result = body(answer["response"]["result"])
        assert result["toLine"] < 1500 and result["nextLine"] == result["toLine"] + 1
        assert "size limit" in result["stoppedShort"]


async def test_a_long_line_is_cut_and_named_and_a_huge_file_refused(
    tmp_path: Path, open_site: OpenSite
) -> None:
    root = tmp_path / "shared"
    root.mkdir()
    (root / "min.js").write_text("short\n" + "x" * 5000 + "\nend\n", encoding="utf-8", newline="\n")
    with (root / "huge.txt").open("wb") as handle:
        handle.truncate(workspace_tools.MAX_FILE + 1)
    _, _, call = await granted(open_site, tmp_path, root)
    read = await answered(call, "read_text", path="min.js")
    assert read["cutLines"] == [2] and "Do not copy" in read["cutNote"]
    assert read["text"] == "short\n" + "x" * 2000 + "\nend\n"
    assert "at most 16 MiB" in await refused(call, "read_text", path="huge.txt")


# --- edit_text -----------------------------------------------------------------


async def test_an_edit_replaces_one_exact_passage_in_place(
    tmp_path: Path, open_site: OpenSite
) -> None:
    root = tmp_path / "shared"
    root.mkdir()
    target = root / "app.py"
    target.write_text(
        "a = 1\nb = 2\nb = 2\n" + "# padding\n" * 4000, encoding="utf-8", newline="\n"
    )
    before = os.stat(target)
    _, _, call = await granted(open_site, tmp_path, root)
    read = await answered(call, "read_text", path="app.py", limit=3)
    edited = await answered(
        call,
        "edit_text",
        path="app.py",
        oldText="a = 1",
        newText="a = 10",
        expectedSha256=read["sha256"],
    )
    assert edited["replaced"] == 1 and edited["sha256"] == sha(target)
    assert target.read_text(encoding="utf-8").startswith("a = 10\nb = 2\n")
    assert os.stat(target).st_ino == before.st_ino  # in place: the same file
    twice = await refused(
        call,
        "edit_text",
        path="app.py",
        oldText="b = 2",
        newText="b = 3",
        expectedSha256=edited["sha256"],
    )
    assert "appears 2 times" in twice
    every = await answered(
        call,
        "edit_text",
        path="app.py",
        oldText="b = 2",
        newText="b = 3",
        expectedSha256=edited["sha256"],
        replaceAll=True,
    )
    assert every["replaced"] == 2 and "b = 2" not in target.read_text(encoding="utf-8")
    stale = await refused(
        call,
        "edit_text",
        path="app.py",
        oldText="a = 10",
        newText="a = 11",
        expectedSha256=edited["sha256"],
    )
    assert "changed" in stale and "a = 10" in target.read_text(encoding="utf-8")
    missing = await refused(
        call,
        "edit_text",
        path="app.py",
        oldText="nowhere",
        newText="x",
        expectedSha256=every["sha256"],
    )
    assert "not found" in missing
    shrunk = await answered(
        call,
        "edit_text",
        path="app.py",
        oldText="# padding\n",
        newText="",
        expectedSha256=every["sha256"],
        replaceAll=True,
    )
    assert target.read_bytes() == b"a = 10\nb = 3\nb = 3\n" and shrunk["written"] == 19
    binary = await refused(
        call,
        "edit_text",
        path="app.py",
        oldText="a = 10",
        newText="a = 10\x00",
        expectedSha256=shrunk["sha256"],
    )
    assert "binary" in binary and target.read_bytes() == b"a = 10\nb = 3\nb = 3\n"
    same = await refused(
        call,
        "edit_text",
        path="app.py",
        oldText="a = 10",
        newText="a = 10",
        expectedSha256=every["sha256"],
    )
    assert "nothing would change" in same


async def test_an_edit_keeps_a_files_crlf_endings(tmp_path: Path, open_site: OpenSite) -> None:
    root = tmp_path / "shared"
    root.mkdir()
    target = root / "win.txt"
    target.write_bytes(b"one\r\ntwo\r\nthree\r\n")
    _, _, call = await granted(open_site, tmp_path, root)
    edited = await answered(
        call,
        "edit_text",
        path="win.txt",
        oldText="one\ntwo",
        newText="one\n2\ntwo",
        expectedSha256=sha(target),
    )
    assert edited["replaced"] == 1
    assert target.read_bytes() == b"one\r\n2\r\ntwo\r\nthree\r\n"


async def test_an_edit_too_large_or_in_a_read_only_folder_is_refused(
    tmp_path: Path, open_site: OpenSite
) -> None:
    root = tmp_path / "shared"
    root.mkdir()
    target = root / "big.txt"
    target.write_text("x" * (workspace_tools.MAX_EDIT - 1) + "\n", encoding="utf-8", newline="\n")
    site, grants, call = await granted(open_site, tmp_path, root)
    grown = await refused(
        call,
        "edit_text",
        path="big.txt",
        oldText="x",
        newText="xy",
        expectedSha256=sha(target),
        replaceAll=True,
    )
    assert "at most 1 MiB" in grown
    (tmp_path / "reading").mkdir()
    found = await site.manage(ADA, "folder.add", name="Reading", path=str(tmp_path / "reading"))
    assert found["status"] == "done", found
    await site.manage(
        ADA, "folder.people", id=found["result"]["id"], people=[{"subject": BO, "writable": False}]
    )
    answer = await site.mcp(
        BO,
        FILES,
        "tools/call",
        {
            "name": "edit_text",
            "arguments": {
                "folder": "Reading",
                "path": "x",
                "oldText": "a",
                "newText": "b",
                "expectedSha256": "0" * 64,
            },
        },
        grants=grants,
    )
    assert answer["status"] == "failed" and "may not change files" in answer["message"], answer


# --- glob ----------------------------------------------------------------------


async def test_glob_finds_by_name_newest_first_and_keeps_inside(
    tmp_path: Path, open_site: OpenSite, tree: Path
) -> None:
    _, _, call = await granted(open_site, tmp_path, tree)
    every = await answered(call, "glob", pattern="**/*.py")
    assert every["paths"] == ["src/main.py", "src/deep/util.py", "setup.py"]
    assert every["skipped"]["ignored"] == 2 and every["skipped"]["links"] == 1
    top = await answered(call, "glob", pattern="*.py")
    assert top["paths"] == ["setup.py"]
    under = await answered(call, "glob", pattern="src/**")
    assert sorted(under["paths"]) == ["src/deep/util.py", "src/main.py"]
    inside = await answered(call, "glob", pattern="*.py", path="src/deep")
    assert inside["paths"] == ["src/deep/util.py"]
    ignored = await answered(call, "glob", pattern="**/*", includeIgnored=True)
    assert "build/out.py" in ignored["paths"] and "debug.log" in ignored["paths"]
    assert not any(p.startswith((".git/", "linked/")) for p in ignored["paths"])
    assert "a file" in await refused(call, "glob", pattern="*", path="setup.py")
    assert "no empty" in await refused(call, "glob", pattern="src/../*")


async def test_glob_classes_never_match_the_separator(
    tmp_path: Path, open_site: OpenSite, tree: Path
) -> None:
    _, _, call = await granted(open_site, tmp_path, tree)
    assert (await answered(call, "glob", pattern="**/src[!x]main.py"))["paths"] == []
    assert (await answered(call, "glob", pattern="**/src/ma[!x]n.py"))["paths"] == ["src/main.py"]
    assert (await answered(call, "glob", pattern="s?tup.[p]y"))["paths"] == ["setup.py"]


# --- grep ----------------------------------------------------------------------


async def test_grep_finds_files_lines_and_counts(
    tmp_path: Path, open_site: OpenSite, tree: Path
) -> None:
    _, _, call = await granted(open_site, tmp_path, tree)
    files = await answered(call, "grep", pattern="hello")
    assert files["files"] == ["README.md", "src/deep/util.py", "setup.py"]
    assert files["skipped"]["binary"] == 1 and files["skipped"]["ignored"] == 2
    cased = await answered(call, "grep", pattern="hello", ignoreCase=True, output="count")
    assert {"path": "src/main.py", "lines": 1} in cased["counts"]
    lines = await answered(call, "grep", pattern="^def ", output="content", context=1)
    assert "src/deep/util.py:1:def helper():" in lines["lines"]
    assert "src/deep/util.py-2-    return 'hello again'" in lines["lines"]
    only = await answered(call, "grep", pattern="hello", glob="*.md")
    assert only["files"] == ["README.md"]
    pathed = await answered(call, "grep", pattern="hello", glob="src/**/*.py", ignoreCase=True)
    assert sorted(pathed["files"]) == ["src/deep/util.py", "src/main.py"]
    one = await answered(call, "grep", pattern="setup", path="setup.py", output="content")
    assert one["lines"] == "setup.py:1:print('hello setup')"
    assert "regular expression" in await refused(call, "grep", pattern="(unclosed")


async def test_grep_stops_a_pattern_that_would_never_finish(
    tmp_path: Path, open_site: OpenSite, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "shared"
    root.mkdir()
    (root / "slow.txt").write_text("a" * 60 + "\n", encoding="utf-8", newline="\n")
    monkeypatch.setattr(workspace_tools, "SEARCH_SECONDS", 0.5)
    _, _, call = await granted(open_site, tmp_path, root)
    started = time.perf_counter()
    stopped = await answered(call, "grep", pattern="(a|aa)+c")
    assert time.perf_counter() - started < 5
    assert "stopped after 0.5 seconds" in stopped["stoppedShort"] and stopped["files"] == []


async def test_a_search_that_runs_out_of_time_failed_it_did_not_act(
    open_site: OpenSite, folder: Path
) -> None:
    site = await open_site()
    added = await site.manage(ADA, "folder.add", name="Notes", path=str(folder))
    await site.manage(
        ADA, "folder.people", id=added["result"]["id"], people=[{"subject": BO, "writable": False}]
    )
    await drop_worker(site)
    fake = FakeWorker(site, lambda _m: None)
    await fake.start()
    searched = await site.mcp(
        BO,
        FILES,
        "tools/call",
        {"name": "grep", "arguments": {"folder": "Notes", "pattern": "x"}},
    )
    await fake.stop()
    assert searched["status"] == "failed" and "may have acted" not in searched["message"]


# --- arguments -----------------------------------------------------------------


@pytest.mark.parametrize(
    ("tool", "arguments"),
    [
        ("read_text", {"path": "a", "offset": 0}),
        ("read_text", {"path": "a", "limit": True}),
        ("read_text", {"path": "a", "limit": 2001}),
        ("edit_text", {"path": "a", "oldText": "", "newText": "b", "expectedSha256": "0" * 64}),
        ("edit_text", {"path": "a", "oldText": "a", "newText": "b", "expectedSha256": ""}),
        ("glob", {"pattern": "*", "followLinks": True}),
        ("grep", {"pattern": "x", "output": "everything"}),
        ("grep", {"pattern": "x", "context": 6}),
        ("grep", {"path": "."}),
    ],
)
def test_the_worker_checks_every_argument_itself(tool: str, arguments: dict[str, Any]) -> None:
    with pytest.raises(file_server.folder_io.FolderError):
        file_server.check_arguments(tool, arguments)


def test_a_writer_is_offered_both_ways_of_changing_files_and_a_reader_neither() -> None:
    offered = {t.name for t in file_server.tools(["A"], ["A"])}
    assert offered == {"list_directory", "read_text", "write_text", "edit_text", "glob", "grep"}
    reading = {t.name for t in file_server.tools(["A"], [])}
    assert reading == {"list_directory", "read_text", "glob", "grep"}
    assert offered == file_server.READ_ONLY | file_server.DESTRUCTIVE


async def test_each_gitignore_counts_where_it_is_and_from_where_a_search_starts(
    tmp_path: Path, open_site: OpenSite
) -> None:
    root = tmp_path / "nested"
    (root / "src" / "gen").mkdir(parents=True)
    (root / "docs").mkdir()
    (root / ".gitignore").write_text("*.log\n", encoding="utf-8", newline="\n")
    (root / "src" / ".gitignore").write_text("gen/\n!keep.log\n", encoding="utf-8", newline="\n")
    for name in ("src/a.py", "src/gen/b.py", "src/trace.log", "src/keep.log", "docs/guide.md"):
        (root / name).write_text("hello\n", encoding="utf-8", newline="\n")
    (root / "top.md").write_text("hello\n", encoding="utf-8", newline="\n")
    _, _, call = await granted(open_site, tmp_path, root)
    found = await answered(call, "grep", pattern="hello", path="src")
    # The root's *.log reaches src/trace.log though the search starts in
    # src; src's own file hides gen/ and lets keep.log back in.
    assert sorted(found["files"]) == ["src/a.py", "src/keep.log"], found
    # From the top, src's file is met on the way down rather than loaded
    # as an ancestor of where the search starts.
    everywhere = await answered(call, "grep", pattern="hello")
    assert sorted(everywhere["files"]) == ["docs/guide.md", "src/a.py", "src/keep.log", "top.md"]
    named = await answered(call, "grep", pattern="hello", glob="*.md")
    assert sorted(named["files"]) == ["docs/guide.md", "top.md"]
    pathed = await answered(call, "grep", pattern="hello", glob="docs/*.md")
    assert pathed["files"] == ["docs/guide.md"]


async def test_a_file_under_an_ignored_folder_stays_hidden_as_git_keeps_it(
    tmp_path: Path, open_site: OpenSite
) -> None:
    root = tmp_path / "kept"
    (root / "build").mkdir(parents=True)
    (root / ".gitignore").write_text("build/\n!build/keep.py\n", encoding="utf-8", newline="\n")
    for name in ("build/keep.py", "main.py"):
        (root / name).write_text("hello\n", encoding="utf-8", newline="\n")
    _, _, call = await granted(open_site, tmp_path, root)
    # Git never re-includes a file under a folder it excluded, so the folder
    # is passed over whole; checked file by file, keep.py would come back.
    assert (await answered(call, "grep", pattern="hello"))["files"] == ["main.py"]
    assert (await answered(call, "glob", pattern="**/*.py"))["paths"] == ["main.py"]


async def test_the_site_refuses_arguments_a_new_tool_does_not_take(
    tmp_path: Path, open_site: OpenSite, tree: Path
) -> None:
    site, grants, _ = await granted(open_site, tmp_path, tree)
    for name, arguments in (
        ("glob", {"pattern": "*", "followLinks": True}),
        ("read_text", {"path": "setup.py", "offset": 0}),
        ("grep", {"pattern": "x", "context": 9}),
    ):
        answer = await site.mcp(
            BO,
            FILES,
            "tools/call",
            {"name": name, "arguments": {"folder": "Shared", **arguments}},
            grants=grants,
        )
        result = answer.get("response", {}).get("result", {})
        assert answer["status"] == "failed" or result.get("isError") is True, answer


async def test_the_worker_will_not_change_files_in_a_folder_the_host_says_is_read_only(
    tmp_path: Path,
) -> None:
    shared = tmp_path / "shared"
    shared.mkdir()
    (shared / "note.txt").write_text("Original", encoding="utf-8", newline="\n")
    other = tmp_path / "other"
    other.mkdir()
    # The tool is offered, for the other folder: the worker's own check is
    # what refuses this one.
    work = folder_work(shared)
    work["folders"]["Other"] = folder_work(other)["folders"]["Notes"]
    work["writable"] = ["Other"]
    edit = rpc(
        "tools/call",
        {
            "name": "edit_text",
            "arguments": {
                "folder": "Notes",
                "path": "note.txt",
                "oldText": "Original",
                "newText": "Changed",
                "expectedSha256": sha(shared / "note.txt"),
            },
        },
    )
    answer = await bare(tmp_path).handle({"op": "mcp", "work": work, "request": edit})
    assert answer["response"]["result"]["isError"] is True
    assert (shared / "note.txt").read_text(encoding="utf-8") == "Original"
