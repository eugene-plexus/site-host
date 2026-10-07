"""Eugene's own file server: one MCP server for the machine, `files` (J6g),
which is the workspace server (J28: *"a unified MCP server"*).

The tools the helper used to take as a bespoke `{tool, arguments}` command
(`remote-nodes.md` §2.1) are MCP tools, served by the SDK like any other
server's (J6). 2b.3a added a read of any part of a file, `edit_text`, `glob`
and `grep` (`workspace_tools.py`). `inspect` is not a tool: registering a
folder is a management action (`folder.add`).

Each tool takes a `folder` argument, the folder's name on this machine. The
server is built for one person and one request: the `folder` argument lists
only the folders that person may use, and the tools that change files
(`write_text`, `edit_text`) appear, listing only the folders they may
change, only when there is one.

Every argument is checked here as well as by the schema the model was given,
because the person's worker must not depend on what checked it before. The
folder code underneath holds handles, refuses links, walks one name at a
time, and on Linux confines each operation with Landlock (`folder_io.py`).
"""

from __future__ import annotations

import asyncio
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import mcp_types as types
from mcp.server.lowlevel import Server

from . import folder_io, workspace_tools

SERVER = "files"
READ_ONLY = frozenset({"list_directory", "read_text", "glob", "grep"})
DESTRUCTIVE = folder_io.WRITING

_PATH = {
    "type": "string",
    "minLength": 1,
    "maxLength": 1024,
    "description": "Relative path inside the folder, using / separators. No .. or links.",
}
_FOLDER_PATH = {
    **_PATH,
    "description": "Relative folder inside the folder, using / separators; '.' (the default) "
    "for the folder itself.",
}
_HASH = {"type": "string", "pattern": "^[a-f0-9]{64}$"}
_IGNORED = {
    "type": "boolean",
    "description": "Also look in what .gitignore files name. .git is always skipped.",
}
#: Each tool: its description, its properties, and which are required
#: besides `folder`.
_DEFINITIONS: tuple[tuple[str, str, dict[str, Any], tuple[str, ...]], ...] = (
    (
        "list_directory",
        "List up to 200 names. Use path '.' for the folder itself.",
        {"path": _PATH},
        ("path",),
    ),
    (
        "read_text",
        "Read a UTF-8 text file of up to 16 MiB: up to `limit` lines (2000 at most, the "
        "default) from line `offset` (1, the default). Always returns the whole file's SHA-256, "
        "which write_text and edit_text need, and totalLines. nextLine says where to read on; "
        "stoppedShort says the answer reached its size limit first. Lines over 2000 "
        "characters are shown cut and listed in cutLines.",
        {
            "path": _PATH,
            "offset": {"type": "integer", "minimum": 1, "maximum": 10_000_000},
            "limit": {"type": "integer", "minimum": 1, "maximum": workspace_tools.MAX_LINES},
        },
        ("path",),
    ),
    (
        "write_text",
        "Create or replace a UTF-8 text file of up to 32 KiB. expectedSha256 must be the hash "
        "from read_text to replace a file, or empty for create-only. To change part of a "
        "larger file, use edit_text. No directories are created. A write is not "
        "automatically retried or undone.",
        {
            "path": _PATH,
            "text": {"type": "string", "maxLength": 8192},
            "expectedSha256": {"type": "string", "pattern": "^(?:[a-f0-9]{64})?$"},
        },
        ("path", "text", "expectedSha256"),
    ),
    (
        "edit_text",
        "Replace an exact passage in a UTF-8 text file of up to 1 MiB. oldText must appear "
        "exactly once, copied from read_text, unless replaceAll is true. expectedSha256 must "
        "be the hash read_text returned. Returns the new hash. A write is not automatically "
        "retried or undone.",
        {
            "path": _PATH,
            "oldText": {"type": "string", "minLength": 1, "maxLength": 4096},
            "newText": {"type": "string", "maxLength": 8192},
            "expectedSha256": _HASH,
            "replaceAll": {"type": "boolean"},
        },
        ("path", "oldText", "newText", "expectedSha256"),
    ),
    (
        "glob",
        "Find files by name: a glob pattern relative to path, such as **/*.py ('**' is any "
        "number of folders, '*' and '?' stay within one name). Returns up to 500 paths "
        "relative to the folder, most recently changed first. Skips links, .git and what "
        "a .gitignore names, and stops after 10 seconds or 20000 entries, saying so.",
        {
            "pattern": {"type": "string", "minLength": 1, "maxLength": 512},
            "path": _FOLDER_PATH,
            "includeIgnored": _IGNORED,
        },
        ("pattern",),
    ),
    (
        "grep",
        "Search file contents with a regular expression (Python syntax; ^ and $ match at "
        "each line). output 'files' (the default) lists matching files, most recently changed "
        "first; 'content' shows path:line:text for each matching line, with `context` lines "
        "around it; 'count' gives matching lines per file. path may be a folder or one file; "
        "glob limits the files searched (a pattern without / matches file names). Skips links, "
        ".git, binary files and what a .gitignore names, and stops after 10 seconds, saying "
        "so.",
        {
            "pattern": {"type": "string", "minLength": 1, "maxLength": 1000},
            "path": _FOLDER_PATH,
            "glob": {"type": "string", "minLength": 1, "maxLength": 512},
            "ignoreCase": {"type": "boolean"},
            "output": {"type": "string", "enum": ["files", "content", "count"]},
            "context": {"type": "integer", "minimum": 0, "maximum": 5},
            "limit": {"type": "integer", "minimum": 1, "maximum": workspace_tools.GREP_MAX},
            "includeIgnored": _IGNORED,
        },
        ("pattern",),
    ),
)
_SCHEMAS = {name: (props, frozenset(required)) for name, _, props, required in _DEFINITIONS}


def tools(readable: list[str], writable: list[str]) -> list[types.Tool]:
    """The tools for one person: `folder` names only `readable` (for
    a tool that changes files, only `writable`), and a tool with no folder is
    not offered."""
    offered: list[types.Tool] = []
    for name, description, properties, required in _DEFINITIONS:
        names = writable if name in DESTRUCTIVE else readable
        if not names:
            continue
        folder = {
            "type": "string",
            "enum": list(names),
            "description": "Which folder on this machine, by its name.",
        }
        offered.append(
            types.Tool(
                name=name,
                description=description,
                input_schema={
                    "type": "object",
                    "properties": {"folder": folder, **properties},
                    "required": ["folder", *required],
                    "additionalProperties": False,
                },
                annotations=types.ToolAnnotations(
                    read_only_hint=name in READ_ONLY,
                    destructive_hint=name in DESTRUCTIVE,
                    idempotent_hint=name in READ_ONLY,
                    open_world_hint=False,
                ),
            )
        )
    return offered


@dataclass
class Outcome:
    """What one request learned beyond its MCP answer: that a write began
    and its end could not be established (`uncertain`)."""

    uncertain: str | None = None


def _failure(message: str) -> types.CallToolResult:
    return types.CallToolResult(
        content=[types.TextContent(type="text", text=message)], is_error=True
    )


def _valid(value: Any, schema: dict[str, Any]) -> bool:
    """`value` against the few schema words these tools use."""
    kind = schema["type"]
    if kind == "boolean":
        return isinstance(value, bool)
    if kind == "integer":
        return (
            isinstance(value, int)
            and not isinstance(value, bool)
            and schema.get("minimum", value) <= value <= schema.get("maximum", value)
        )
    if not isinstance(value, str):
        return False
    if not schema.get("minLength", 0) <= len(value) <= schema.get("maxLength", len(value)):
        return False
    if "enum" in schema and value not in schema["enum"]:
        return False
    return "pattern" not in schema or re.fullmatch(schema["pattern"], value) is not None


def check_arguments(tool: str, arguments: dict[str, Any]) -> None:
    """The arguments a tool takes, and nothing else, each as its schema says."""
    properties, required = _SCHEMAS[tool]
    if not required <= set(arguments) <= set(properties):
        raise folder_io.FolderError("This file operation's arguments are not supported.")
    for key, value in arguments.items():
        if not _valid(value, properties[key]):
            raise folder_io.FolderError(f"This file operation's {key} is not valid.")


def run(
    path: str, identity: str, tool: str, arguments: dict[str, Any], protected: list[Path]
) -> dict[str, Any]:
    """One operation on one folder, with the worker's argument rules
    (`folder_io`). `arguments` no longer carries `folder`."""
    check_arguments(tool, arguments)
    return folder_io.operate(path, identity, tool, arguments, protected)


def server(
    folders: dict[str, dict[str, Any]],
    writable: frozenset[str],
    protected: list[Path],
    outcome: Outcome,
) -> Server:
    """The file server for one person and one request. `folders` maps each
    name they may use to its record; `writable` names those they may change."""
    offered = {t.name: t for t in tools(list(folders), [n for n in folders if n in writable])}

    async def list_tools(_ctx: Any, _params: Any) -> types.ListToolsResult:
        return types.ListToolsResult(tools=list(offered.values()))

    async def call_tool(_ctx: Any, params: types.CallToolRequestParams) -> types.CallToolResult:
        if params.name not in offered:
            return _failure(f"This machine's file server has no tool named {params.name!r}.")
        arguments = dict(params.arguments or {})
        name = arguments.pop("folder", None)
        folder = folders.get(name) if isinstance(name, str) else None
        if folder is None or (params.name in DESTRUCTIVE and name not in writable):
            return _failure(f"You may not use a folder named {name!r} for {params.name}.")
        try:
            result = await asyncio.to_thread(
                run, folder["path"], folder["identity"], params.name, arguments, protected
            )
        except folder_io.WriteUncertain as exc:
            outcome.uncertain = str(exc)
            return _failure(str(exc))
        except folder_io.FolderError as exc:
            return _failure(str(exc))
        except PermissionError:
            return _failure(
                "The file helper's OS account cannot access this folder. Check its permissions."
            )
        except FileNotFoundError:
            return _failure("This file or folder was not found.")
        except (ValueError, KeyError, TypeError, OSError):
            # Before the write began: `folder_io` raises WriteUncertain once it has.
            return _failure(
                "The file could not be opened safely. Check its path, permissions and file type."
            )
        return types.CallToolResult(
            content=[types.TextContent(type="text", text=json.dumps(result, ensure_ascii=False))],
            structured_content=result,
            is_error=False,
        )

    return Server(SERVER, on_list_tools=list_tools, on_call_tool=call_tool)


def unique_names(names: list[str]) -> list[str]:
    """Each name as the `folder` argument takes it: a name already taken,
    ignoring case, by a folder before it reads `Name (2)`, `Name (3)`..."""
    taken: set[str] = set()
    out: list[str] = []
    for name in names:
        candidate, n = name, 1
        while candidate.casefold() in taken:
            n += 1
            candidate = f"{name} ({n})"
        taken.add(candidate.casefold())
        out.append(candidate)
    return out
