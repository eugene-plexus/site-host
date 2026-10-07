"""Bounded text operations on held file handles, never a checked-then-opened path.

Linux uses Landlock and one-component no-link traversal on held handles. Windows
walks one name at a time relative to retained directory handles, refusing
reparse points and holding parents against rename. Only regular, singly
linked files are used. No shell and no automatic retries. The one traversal,
a search's walk (`workspace_tools`), opens one name at a time on the same
handles, follows no link, enters no other mount and stops at a budget.
"""

from __future__ import annotations

import hashlib
import os
import re
import stat
import sys
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any

MAX_BYTES = 32_768
MAX_CHARACTERS = 16_384
MAX_ENTRIES = 200
#: The tools that change files: the folder's handle may write for them only.
WRITING = frozenset({"write_text", "edit_text"})
#: The tools whose `path` names a folder, `.` for the folder itself.
DIRECTORY_PATHS = frozenset({"list_directory", "glob", "grep"})


class FolderError(Exception):
    """Safe to return to the person and model; contains no host path."""


class WriteUncertain(FolderError):
    """A write began but its completion could not be established."""


@dataclass(frozen=True)
class Entry:
    """One name in a directory, as its handle lists it: `kind` is `file`,
    `dir`, `link` (a symlink, junction or other reparse point, never
    followed) or `other`."""

    name: str
    kind: str
    size: int
    mtime_ns: int


def _utf8(text: str) -> bytes:
    try:
        return text.encode("utf-8")
    except UnicodeEncodeError:
        raise FolderError("File names and contents must be valid UTF-8 text.") from None


def parts(path: str, *, directory: bool = False) -> list[str]:
    if directory and path == ".":
        return []
    names = path.split("/")
    if (
        not path
        or len(path) > 1024
        or len(names) > 32
        or any(
            not n
            or n in {".", ".."}
            or n.endswith((".", " "))
            or len(_utf8(n)) > 255
            or any(ord(c) < 32 or c in '\\:<>"|?*' or ord(c) == 127 for c in n)
            or re.fullmatch(r"(?i)(con|prn|aux|nul|com[1-9¹²³]|lpt[1-9¹²³])(?:\..*)?", n)
            for n in names
        )
    ):
        raise FolderError(
            "Use a relative path with / separators, without links, .. or device names."
        )
    return names


def identity(fd: int) -> str:
    info = os.fstat(fd)
    if sys.platform == "win32":
        created = str(info.st_birthtime_ns)
    else:
        from .folder_linux import birth_time

        created = birth_time(fd)
    return f"{info.st_dev}:{info.st_ino}:{created}"


def regular(fd: int) -> None:
    info = os.fstat(fd)
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise FolderError("Only ordinary files with one hard link are supported.")


def text_bytes(text: str) -> bytes:
    if any(ord(c) < 32 and c not in "\t\r\n" for c in text):
        raise FolderError("Only UTF-8 text files without binary control characters are supported.")
    data = _utf8(text)
    if len(data) > MAX_BYTES or len(text) > MAX_CHARACTERS:
        raise FolderError("Use a text file of at most 32 KiB and 16384 characters.")
    return data


def _read(fd: int) -> tuple[str, str]:
    regular(fd)
    if os.fstat(fd).st_size > MAX_BYTES:
        raise FolderError("Use a text file of at most 32 KiB and 16384 characters.")
    os.lseek(fd, 0, os.SEEK_SET)
    data = bytearray()
    while len(data) <= MAX_BYTES:
        chunk = os.read(fd, min(8192, MAX_BYTES + 1 - len(data)))
        if not chunk:
            break
        data.extend(chunk)
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        raise FolderError("This is not a UTF-8 text file.") from None
    text_bytes(text)
    return text, hashlib.sha256(data).hexdigest()


@contextmanager
def root(path: str, expected: str | None = None) -> Iterator[Any]:
    if sys.platform == "win32":
        from .folder_windows import Root
    elif sys.platform.startswith("linux"):
        from .folder_linux import Root
    else:
        raise FolderError("Folder tools require Windows or Linux with Landlock support.")
    with Root(path) as folder:
        if expected is not None and identity(folder.fd) != expected:
            raise FolderError(
                "This folder was replaced. Ask the owner to remove and grant it again."
            )
        yield folder


def inspect(path: str, protected: list[Path]) -> str:
    with root(path) as folder:
        check_root_path(folder.path, protected)
        return identity(folder.fd)


def operate(
    path: str, expected: str, tool: str, arguments: dict[str, Any], protected: list[Path]
) -> dict[str, Any]:
    if sys.platform.startswith("linux"):
        from .folder_linux import isolated

        return isolated(lambda: _operate(path, expected, tool, arguments, protected))
    return _operate(path, expected, tool, arguments, protected)


def _operate(
    path: str, expected: str, tool: str, arguments: dict[str, Any], protected: list[Path]
) -> dict[str, Any]:
    names = parts(arguments.get("path", "."), directory=tool in DIRECTORY_PATHS)
    with root(path, expected) as folder:
        check_root_path(folder.path, protected)
        if sys.platform.startswith("linux"):
            folder.restrict(tool in WRITING)
        if tool in {"read_text", "edit_text", "glob", "grep"}:
            from . import workspace_tools

            return workspace_tools.run(folder, tool, names, arguments)
        if tool == "list_directory":
            entries = folder.names(names, MAX_ENTRIES + 1)
            for entry in entries:
                _utf8(entry)
            return {"names": sorted(entries[:MAX_ENTRIES]), "truncated": len(entries) > MAX_ENTRIES}
        if tool != "write_text":
            raise FolderError("This file tool is not supported.")
        data = text_bytes(arguments["text"])
        before = arguments["expectedSha256"]
        # Empty expected hash means create-only; a SHA-256 means edit exactly
        # the version the person approved. Never truncate while opening.
        with folder.file(names, write=True, create=before == "") as fd:
            regular(fd)
            if before:
                _, digest = _read(fd)
                if digest != before:
                    raise FolderError(
                        "The file changed. Read it again before proposing another edit."
                    )
            rewrite(fd, data)
        return {"written": len(data), "sha256": hashlib.sha256(data).hexdigest()}


def rewrite(fd: int, data: bytes) -> None:
    """The file's whole content, written in place over the open handle, then
    flushed to disk. In place keeps the file's identity and permissions; a
    write that stops midway is `WriteUncertain`, never retried."""
    try:
        os.lseek(fd, 0, os.SEEK_SET)
        pending = memoryview(data)
        while pending:
            written = os.write(fd, pending)
            if written == 0:
                raise OSError("The write made no progress.")
            pending = pending[written:]
        os.ftruncate(fd, len(data))
        os.fsync(fd)
    except OSError:
        raise WriteUncertain(
            "The write did not finish reliably. The file may be partially "
            "changed. Check it before trying again."
        ) from None


def check_root_path(path: str, protected: list[Path]) -> str:
    candidate = Path(path)
    if not candidate.is_absolute() or "\x00" in path or ".." in candidate.parts:
        raise FolderError("Use the full path to an existing folder on Workbench's host.")
    # Lexical overlap is checked before opening. Native traversal rejects
    # aliases through symlinks/reparse points; identity is pinned separately.
    for private in protected:
        for boundary in (private.absolute(), private.resolve()):
            if candidate.is_relative_to(boundary) or boundary.is_relative_to(candidate):
                raise FolderError("Workbench's private files and installation cannot be granted.")
    return str(candidate)
