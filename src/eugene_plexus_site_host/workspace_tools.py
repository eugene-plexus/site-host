"""The workspace tools beyond listing and writing (2b.3a): a read of any part
of a file, an exact edit, and search by name (`glob`) and by content
(`grep`). `specs/docs/design/job-sites-own-enrollment.md` §2.6, §3.3.

Everything runs inside `folder_io`'s held folder, on its handles:

- **A read** takes a file of up to 16 MiB, answers the lines asked for (2,000
  by default) and always the whole file's SHA-256, which an edit needs. A
  line over 2,000 characters is shown cut, and the answer names it.
- **An edit** replaces one exact passage, or every copy of it when asked, in
  a file of up to 1 MiB whose hash is still the one the person read. It is
  written in place, as `write_text` is (`folder_io.rewrite`).
- **A search walks** one name at a time relative to the folder: it never
  follows a link or enters another mount, skips `.git`, honours each
  `.gitignore` on its way unless asked not to (J73), and stops after 10 s or
  20,000 entries. Patterns run on the `regex` package with what is left of
  those 10 s as their timeout, so a pattern that would never finish stops
  (J74): Python's own `re` cannot be stopped, and its thread would hold one
  of the worker's call slots for good. What the workspace's deny patterns
  hide (`folder_io.Hidden`, J70) is passed over without a word: it is not
  counted among what was skipped.

**Every answer fits.** The site refuses an answer over 70,000 bytes, and an
MCP answer carries the result twice, as text and as structured content. So
each tool cuts its own answer to `ANSWER_BUDGET` bytes for both together,
says that it stopped short, and says where to go on from.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import sys
import time
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from typing import Any

import pathspec
import regex

from .folder_io import Entry, FolderError, Hidden, parts, regular, rewrite

MAX_FILE = 16 * 1024 * 1024
MAX_EDIT = 1024 * 1024
MAX_LINES = 2000
LONG_LINE = 2000
#: Bytes for the result's text and structured copies together, under the
#: site's 70,000 with room for the MCP envelope around them.
ANSWER_BUDGET = 60_000
SEARCH_SECONDS = 10.0
MAX_VISITED = 20_000
MAX_PATHS = 500
GREP_LIMIT = 100
GREP_MAX = 500
GREP_LINE = 500
MAX_IGNORE_FILE = 65_536
#: `folder_io.parts` takes at most 32 names in a path.
MAX_DEPTH = 32

_BINARY = re.compile(rb"[\x00-\x08\x0b\x0c\x0e-\x1f]")
#: Windows matches names without regard to case, so its globs do too.
_CASELESS = sys.platform == "win32"


# --- reading -------------------------------------------------------------------


def read_all(fd: int, limit: int, too_large: str) -> bytes:
    regular(fd)
    if os.fstat(fd).st_size > limit:
        raise FolderError(too_large)
    os.lseek(fd, 0, os.SEEK_SET)
    data = bytearray()
    while len(data) <= limit:
        chunk = os.read(fd, min(1 << 20, limit + 1 - len(data)))
        if not chunk:
            break
        data.extend(chunk)
    if len(data) > limit:
        raise FolderError(too_large)
    return bytes(data)


def text_of(data: bytes) -> str:
    if _BINARY.search(data):
        raise FolderError("Only UTF-8 text files without binary control characters are supported.")
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        raise FolderError("This is not a UTF-8 text file.") from None


def split_lines(text: str) -> list[str]:
    """Each line with its own ending, split on `\\n` only, as editors count."""
    pieces = text.split("\n")
    lines = [piece + "\n" for piece in pieces[:-1]]
    if pieces[-1]:
        lines.append(pieces[-1])
    return lines


def answer_bytes(result: dict[str, Any]) -> int:
    """What `result` adds to an MCP answer: as JSON text inside a JSON
    string, and again as structured content."""
    inner = json.dumps(result, ensure_ascii=False)
    return len(json.dumps(inner, ensure_ascii=False).encode()) + len(inner.encode())


def fit(build: Callable[[int], dict[str, Any]], count: int) -> dict[str, Any]:
    """The answer with as many of `count` pieces as fit the budget."""
    whole = build(count)
    if answer_bytes(whole) <= ANSWER_BUDGET:
        return whole
    low, high = 0, count - 1
    while low < high:
        middle = (low + high + 1) // 2
        if answer_bytes(build(middle)) <= ANSWER_BUDGET:
            low = middle
        else:
            high = middle - 1
    return build(low)


def read_text(folder: Any, names: list[str], arguments: dict[str, Any]) -> dict[str, Any]:
    offset: int = arguments.get("offset", 1)
    limit: int = arguments.get("limit", MAX_LINES)
    with folder.file(names) as fd:
        data = read_all(fd, MAX_FILE, "read_text reads files of at most 16 MiB.")
    text = text_of(data)
    digest = hashlib.sha256(data).hexdigest()
    lines = split_lines(text)
    total = len(lines)
    if offset > max(total, 1):
        raise FolderError(f"This file has {total} lines. Start at line {max(total, 1)} or before.")
    window = lines[offset - 1 : offset - 1 + limit]
    shown: list[str] = []
    cut: list[int] = []
    for number, line in enumerate(window, start=offset):
        body = line.rstrip("\r\n")
        if len(body) > LONG_LINE:
            cut.append(number)
            line = body[:LONG_LINE] + line[len(body) :]
        shown.append(line)

    def build(k: int) -> dict[str, Any]:
        result: dict[str, Any] = {"text": "".join(shown[:k]), "sha256": digest, "totalLines": total}
        if k:
            result["fromLine"] = offset
            result["toLine"] = offset + k - 1
        if cuts := [n for n in cut if n < offset + k]:
            result["cutLines"] = cuts
            result["cutNote"] = (
                f"These lines are longer than {LONG_LINE} characters and are shown cut. Do not "
                "copy them into an edit."
            )
        after = offset - 1 + k
        if after < total:
            result["nextLine"] = after + 1
        if k < len(shown):
            result["stoppedShort"] = (
                f"The answer reached its size limit after line {after}. Read on from line "
                f"{after + 1}."
            )
        return result

    return fit(build, len(shown))


# --- editing -------------------------------------------------------------------


def edit_text(folder: Any, names: list[str], arguments: dict[str, Any]) -> dict[str, Any]:
    old: str = arguments["oldText"]
    new: str = arguments["newText"]
    every = bool(arguments.get("replaceAll", False))
    if not old:
        raise FolderError("oldText is empty. Copy the exact passage to replace.")
    if old == new:
        raise FolderError("oldText and newText are the same, so nothing would change.")
    too_large = "edit_text edits files of at most 1 MiB."
    with folder.file(names, write=True) as fd:
        data = read_all(fd, MAX_EDIT, too_large)
        if hashlib.sha256(data).hexdigest() != arguments["expectedSha256"]:
            raise FolderError("The file changed. Read it again before proposing another edit.")
        text = text_of(data)
        count = text.count(old)
        if not count and "\r\n" in text and "\n" in old and "\r\n" not in old:
            # The file ends its lines with \r\n and the passage came with \n.
            old = old.replace("\n", "\r\n")
            new = new.replace("\r\n", "\n").replace("\n", "\r\n")
            count = text.count(old)
        if not count:
            raise FolderError(
                "oldText was not found in this file. Read it again and copy the passage exactly."
            )
        if count > 1 and not every:
            raise FolderError(
                f"oldText appears {count} times in this file. Include more of the text around "
                "it so it appears once, or set replaceAll to replace every copy."
            )
        changed = text.replace(old, new) if every else text.replace(old, new, 1)
        try:
            out = changed.encode("utf-8")
        except UnicodeEncodeError:
            raise FolderError("newText must be valid UTF-8 text.") from None
        text_of(out)
        if len(out) > MAX_EDIT:
            raise FolderError(too_large)
        rewrite(fd, out)
    return {
        "replaced": count if every else 1,
        "written": len(out),
        "sha256": hashlib.sha256(out).hexdigest(),
    }


# --- walking -------------------------------------------------------------------


@dataclass
class Walk:
    """One search's budget, and what it passed over."""

    deadline: float
    visited: int = 0
    searched: int = 0
    stopped: str | None = None
    skipped: dict[str, int] = field(default_factory=dict)

    def skip(self, why: str) -> None:
        self.skipped[why] = self.skipped.get(why, 0) + 1

    def remaining(self) -> float:
        return max(0.001, self.deadline - time.perf_counter())

    def out(self) -> bool:
        if self.stopped is None:
            if time.perf_counter() >= self.deadline:
                self.stopped = "time"
            elif self.visited >= MAX_VISITED:
                self.stopped = "entries"
        return self.stopped is not None

    def report(self, result: dict[str, Any]) -> dict[str, Any]:
        if self.skipped:
            result["skipped"] = dict(sorted(self.skipped.items()))
        if self.stopped == "time":
            result["stoppedShort"] = (
                f"The search stopped after {SEARCH_SECONDS:g} seconds and may have missed "
                "matches. Narrow the path or the pattern."
            )
        elif self.stopped == "entries":
            result["stoppedShort"] = (
                f"The search stopped after looking at {MAX_VISITED:,} entries and may have "
                "missed matches. Narrow the path or the pattern."
            )
        return result


def _addressable(name: str) -> bool:
    """A name the other tools can take back, so a search never offers a path
    that read_text would refuse."""
    try:
        parts(name)
    except FolderError:
        return False
    return True


class Ignores:
    """Each `.gitignore` met on the way, applied as git does: patterns from a
    deeper folder decide over a shallower one's."""

    def __init__(self) -> None:
        self.specs: dict[tuple[str, ...], pathspec.GitIgnoreSpec] = {}

    def load(self, folder: Any, directory: list[str]) -> None:
        try:
            with folder.file([*directory, ".gitignore"]) as fd:
                data = read_all(fd, MAX_IGNORE_FILE, "too large")
            spec = pathspec.GitIgnoreSpec.from_lines(
                data.decode("utf-8", errors="replace").splitlines()
            )
        except (FolderError, OSError, ValueError):
            # Missing, a link, too large, or a pattern this cannot read.
            return
        self.specs[tuple(directory)] = spec

    def ignored(self, path: list[str], directory: bool) -> bool:
        decision: bool | None = None
        for depth in range(len(path)):
            spec = self.specs.get(tuple(path[:depth]))
            if spec is None:
                continue
            relative = "/".join(path[depth:]) + ("/" if directory else "")
            include = spec.check_file(relative).include
            if include is not None:
                decision = include
        return bool(decision)


def walk(
    folder: Any,
    start: list[str],
    state: Walk,
    *,
    ignore: bool,
    max_depth: int | None,
    hidden: Hidden | None = None,
) -> Iterator[tuple[list[str], Entry]]:
    """Every file below `start`, in name order, each with its entry. Links,
    other mounts and `.git` are passed over; so is what a `.gitignore` names
    when `ignore` is set, and, silently, what `hidden` hides. `max_depth`
    counts levels below `start`."""
    hidden = hidden or Hidden()
    ignores = Ignores()
    if ignore:
        for depth in range(len(start) + 1):
            ignores.load(folder, start[:depth])
    stack: list[tuple[list[str], int]] = [(start, 0)]
    while stack and not state.out():
        directory, depth = stack.pop()
        try:
            listed = folder.entries(directory, MAX_VISITED - state.visited + 1)
        except (FolderError, OSError):
            state.skip("foldersNotOpened")
            continue
        if (
            ignore
            and directory != start
            and any(e.name == ".gitignore" and e.kind == "file" for e in listed)
        ):
            ignores.load(folder, directory)
        below: list[list[str]] = []
        for entry in sorted(listed, key=lambda e: e.name):
            if state.out():
                return
            state.visited += 1
            path = [*directory, entry.name]
            if hidden and hidden.hides(path, entry.kind == "dir"):
                continue
            if entry.kind == "link":
                state.skip("links")
            elif entry.kind != "dir" and entry.kind != "file":
                state.skip("other")
            elif not _addressable(entry.name):
                state.skip("unusableNames")
            elif entry.kind == "dir":
                if entry.name == ".git":
                    continue
                if ignore and ignores.ignored(path, True):
                    state.skip("ignored")
                elif len(path) < MAX_DEPTH and (max_depth is None or depth + 1 < max_depth):
                    below.append(path)
            elif ignore and ignores.ignored(path, False):
                state.skip("ignored")
            else:
                yield path, entry
        stack.extend((path, depth + 1) for path in reversed(below))


# --- globs ---------------------------------------------------------------------


@dataclass(frozen=True)
class Glob:
    """A compiled glob: the literal folders it starts in, how deep it reaches
    below them (None for `**`), and the pattern for the rest."""

    prefix: list[str]
    depth: int | None
    pattern: Any
    names_only: bool

    def matches(self, relative: str, seconds: float) -> bool:
        return bool(self.pattern.fullmatch(relative, timeout=seconds))


def _component(source: str) -> str:
    out: list[str] = []
    i = 0
    while i < len(source):
        ch = source[i]
        if ch == "*":
            while i + 1 < len(source) and source[i + 1] == "*":
                i += 1
            out.append("[^/]*")
        elif ch == "?":
            out.append("[^/]")
        elif ch == "[":
            j = i + 1
            if j < len(source) and source[j] in "!^":
                j += 1
            if j < len(source) and source[j] == "]":
                j += 1
            end = source.find("]", j)
            if end < 0:
                out.append(regex.escape(ch))
            else:
                body = source[i + 1 : end]
                negate = body[:1] in ("!", "^")
                if negate:
                    body = body[1:]
                chars = "".join("-" if c == "-" else regex.escape(c) for c in body)
                # A class never matches the separator, negated or not.
                out.append(f"[^/{chars}]" if negate else f"[{chars}]")
                i = end
        else:
            out.append(regex.escape(ch))
        i += 1
    return "".join(out)


def compile_glob(source: str, *, start_inside: bool = True) -> Glob:
    """`start_inside`: take the pattern's leading literal folders as where a
    walk starts, and match the rest below them. A filter (grep's `glob`)
    matches the whole pattern instead."""
    if (
        not source
        or len(source) > 512
        or source.startswith("/")
        or "\\" in source
        or any(ord(c) < 32 for c in source)
    ):
        raise FolderError("Use a relative glob pattern with / separators, such as **/*.py.")
    components = source.split("/")
    if any(c in ("", ".", "..") for c in components):
        raise FolderError("A glob pattern has no empty, . or .. parts.")
    prefix: list[str] = []
    for component in components[:-1] if start_inside else ():
        if any(c in component for c in "*?["):
            break
        prefix.append(component)
    if prefix:
        parts("/".join(prefix))
    rest = components[len(prefix) :]
    last = len(rest) - 1
    body = "".join(
        (".*" if i == last else "(?:[^/]+/)*")
        if c == "**"
        else _component(c) + ("" if i == last else "/")
        for i, c in enumerate(rest)
    )
    flags = regex.IGNORECASE if _CASELESS else 0
    depth = None if "**" in rest else len(rest)
    return Glob(prefix, depth, regex.compile(body, flags), "/" not in source)


def _base(folder: Any, names: list[str], tool: str) -> None:
    if not folder.is_directory(names):
        raise FolderError(f"{tool} searches a folder, and this path is a file.")


def glob(
    folder: Any, names: list[str], arguments: dict[str, Any], hidden: Hidden | None = None
) -> dict[str, Any]:
    pattern = compile_glob(arguments["pattern"])
    start = [*names, *pattern.prefix]
    if hidden:
        # The pattern's leading folders name a path as `path` does.
        hidden.check(start)
    _base(folder, names, "glob")
    state = Walk(time.perf_counter() + SEARCH_SECONDS)
    found: list[tuple[int, str]] = []
    try:
        for path, entry in walk(
            folder,
            start,
            state,
            ignore=not arguments.get("includeIgnored", False),
            max_depth=pattern.depth,
            hidden=hidden,
        ):
            if pattern.matches("/".join(path[len(start) :]), state.remaining()):
                found.append((entry.mtime_ns, "/".join(path)))
    except TimeoutError:
        state.stopped = "time"
    found.sort(key=lambda f: (-f[0], f[1]))
    paths = [p for _, p in found]

    def build(k: int) -> dict[str, Any]:
        result: dict[str, Any] = {"paths": paths[:k], "matched": len(paths)}
        state.report(result)
        if k < len(paths):
            result["shown"] = (
                f"The {k} most recently changed of {len(paths)} matches. Narrow the pattern "
                "to see the rest."
            )
        return result

    return fit(build, min(len(paths), MAX_PATHS))


# --- grep ----------------------------------------------------------------------


def _lines_hit(pattern: Any, text: str, seconds: float, first_only: bool) -> list[int]:
    """The 0-based numbers of the lines a match starts on, in order."""
    hits: list[int] = []
    line = 0
    scanned = 0
    for match in pattern.finditer(text, timeout=seconds):
        start = match.start()
        line += text.count("\n", scanned, start)
        scanned = start
        if not hits or hits[-1] != line:
            hits.append(line)
            if first_only:
                break
    return hits


def _shown(line: str) -> str:
    line = line.rstrip("\r")
    return line if len(line) <= GREP_LINE else line[:GREP_LINE] + " [cut]"


def grep(
    folder: Any, names: list[str], arguments: dict[str, Any], hidden: Hidden | None = None
) -> dict[str, Any]:
    source: str = arguments["pattern"]
    flags = regex.MULTILINE | (regex.IGNORECASE if arguments.get("ignoreCase") else 0)
    try:
        pattern = regex.compile(source, flags)
    except regex.error as exc:
        raise FolderError(f"The pattern is not a regular expression: {exc}.") from None
    only = compile_glob(arguments["glob"], start_inside=False) if arguments.get("glob") else None
    output: str = arguments.get("output", "files")
    context: int = arguments.get("context", 0)
    limit: int = arguments.get("limit", GREP_LIMIT)
    state = Walk(time.perf_counter() + SEARCH_SECONDS)
    single = not folder.is_directory(names)
    targets: Iterator[tuple[list[str], Entry | None]] = (
        iter([(names, None)])
        if single
        else walk(
            folder,
            names,
            state,
            ignore=not arguments.get("includeIgnored", False),
            max_depth=None,
            hidden=hidden,
        )
    )
    files: list[tuple[int, str]] = []
    counts: list[dict[str, Any]] = []
    pieces: list[str] = []
    hits_shown = 0
    full = False
    try:
        for path, entry in targets:
            if only is not None and not single:
                relative = path[-1] if only.names_only else "/".join(path[len(names) :])
                if not only.matches(relative, state.remaining()):
                    continue
            if entry is not None and entry.size > MAX_FILE:
                state.skip("tooLarge")
                continue
            try:
                with folder.file(path) as fd:
                    data = read_all(fd, MAX_FILE, "too large")
            except (FolderError, OSError):
                if single:
                    raise
                state.skip("unreadable")
                continue
            if _BINARY.search(data):
                state.skip("binary")
                continue
            try:
                text = data.decode("utf-8")
            except UnicodeDecodeError:
                state.skip("notText")
                continue
            state.searched += 1
            hits = _lines_hit(pattern, text, state.remaining(), output == "files")
            if not hits:
                continue
            shown_path = "/".join(path)
            if output == "files":
                files.append((entry.mtime_ns if entry else 0, shown_path))
            elif output == "count":
                counts.append({"path": shown_path, "lines": len(hits)})
            else:
                lines = text.split("\n")
                groups: list[tuple[int, int]] = []
                for hit in hits:
                    low, high = max(0, hit - context), min(len(lines) - 1, hit + context)
                    if groups and low <= groups[-1][1] + 1:
                        groups[-1] = (groups[-1][0], high)
                    else:
                        groups.append((low, high))
                hit_set = set(hits)
                for low, high in groups:
                    if context and pieces:
                        pieces.append("--")
                    for n in range(low, high + 1):
                        mark = ":" if n in hit_set else "-"
                        if n in hit_set:
                            if hits_shown >= limit:
                                full = True
                                break
                            hits_shown += 1
                        pieces.append(f"{shown_path}{mark}{n + 1}{mark}{_shown(lines[n])}")
                    if full:
                        break
                if full:
                    break
    except TimeoutError:
        state.stopped = "time"

    if output == "files":
        files.sort(key=lambda f: (-f[0], f[1]))
        paths = [p for _, p in files]

        def build_files(k: int) -> dict[str, Any]:
            result: dict[str, Any] = {
                "files": paths[:k],
                "matchedFiles": len(paths),
                "searchedFiles": state.searched,
            }
            state.report(result)
            if k < len(paths):
                result["shown"] = (
                    f"The {k} most recently changed of {len(paths)} files. Narrow the search "
                    "to see the rest."
                )
            return result

        return fit(build_files, min(len(paths), limit))
    if output == "count":

        def build_counts(k: int) -> dict[str, Any]:
            result: dict[str, Any] = {
                "counts": counts[:k],
                "matchedFiles": len(counts),
                "searchedFiles": state.searched,
            }
            state.report(result)
            if k < len(counts):
                result["shown"] = f"{k} of {len(counts)} files. Narrow the search to see the rest."
            return result

        return fit(build_counts, min(len(counts), limit))

    def build_lines(k: int) -> dict[str, Any]:
        result: dict[str, Any] = {"lines": "\n".join(pieces[:k]), "searchedFiles": state.searched}
        state.report(result)
        if full or k < len(pieces):
            result["shown"] = (
                "Not every matching line is shown. Narrow the search, or raise limit, to see "
                "the rest."
            )
        return result

    return fit(build_lines, len(pieces))


# --- dispatch ------------------------------------------------------------------


def run(
    folder: Any,
    tool: str,
    names: list[str],
    arguments: dict[str, Any],
    hidden: Hidden | None = None,
) -> dict[str, Any]:
    """One tool. `names` was checked against `hidden` before the folder was
    opened (`folder_io._operate`)."""
    if tool == "read_text":
        return read_text(folder, names, arguments)
    if tool == "edit_text":
        return edit_text(folder, names, arguments)
    if tool == "glob":
        return glob(folder, names, arguments, hidden)
    if tool == "grep":
        return grep(folder, names, arguments, hidden)
    raise FolderError("This file tool is not supported.")
