"""Eugene's own file server: one MCP server for the machine, `files` (J6g).

The four tools the helper used to take as a bespoke `{tool, arguments}`
command (`remote-nodes.md` §2.1) are MCP tools now, served by the SDK like
any other server's (J6). `inspect` is not a tool: registering a folder is a
management action (`folder.add`, or `folder.inspect` on an ordinary node).

Each tool takes a `folder` argument, the folder's name on this machine. The
server is built for one person and one request: the `folder` argument lists
only the folders that person may use, and `write_text` appears, listing only
the folders they may change, only when there is one.

The folder code underneath is unchanged: it holds handles, refuses links,
walks one name at a time, and on Linux confines each operation with
Landlock (`folder_io.py`).
"""

from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import mcp_types as types
from mcp.server.lowlevel import Server

from . import folder_io

SERVER = "files"
READ_ONLY = frozenset({"list_directory", "read_text"})
DESTRUCTIVE = frozenset({"write_text"})

_PATH = {
    "type": "string",
    "minLength": 1,
    "maxLength": 1024,
    "description": "Relative path inside the folder, using / separators. No .. or links.",
}
_DEFINITIONS: tuple[tuple[str, str, dict[str, Any]], ...] = (
    (
        "list_directory",
        "List up to 200 names. Use path '.' for the folder itself.",
        {"path": _PATH},
    ),
    (
        "read_text",
        "Read a UTF-8 text file, at most 32 KiB/16384 characters, and its SHA-256.",
        {"path": _PATH},
    ),
    (
        "write_text",
        "Create or edit a UTF-8 text file. expectedSha256 must be the hash from read_text "
        "for an edit, or empty for create-only. No directories are created. A write is not "
        "automatically retried or undone.",
        {
            "path": _PATH,
            "text": {"type": "string", "maxLength": 8192},
            "expectedSha256": {"type": "string", "pattern": "^(?:[a-f0-9]{64})?$"},
        },
    ),
)


def tools(readable: list[str], writable: list[str]) -> list[types.Tool]:
    """The tools for one person: `folder` names only `readable` (for
    `write_text`, only `writable`), and a tool with no folder is not offered."""
    offered: list[types.Tool] = []
    for name, description, properties in _DEFINITIONS:
        names = writable if name == "write_text" else readable
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
                    "required": ["folder", *properties],
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


def run(
    path: str, identity: str, tool: str, arguments: dict[str, Any], protected: list[Path]
) -> dict[str, Any]:
    """One operation on one folder, with the worker's argument rules
    (`folder_io`). `arguments` no longer carries `folder`."""
    if not isinstance(arguments.get("path"), str):
        raise folder_io.FolderError("A file operation needs a text path.")
    required = {"path", "text", "expectedSha256"} if tool == "write_text" else {"path"}
    if set(arguments) != required:
        raise folder_io.FolderError("This file operation's arguments are not supported.")
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
        if folder is None or (params.name == "write_text" and name not in writable):
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
