"""Eugene's own file server: one MCP server for each registered folder.

The four tools the helper used to take as a bespoke `{tool, arguments}`
command (`remote-nodes.md` §2.1) are MCP tools now, served by the SDK like
any other server's (J6). `inspect` is not a tool: registering a folder is a
management action (`folder.add`, or `folder.inspect` on an ordinary node).

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

READ_ONLY = frozenset({"list_directory", "read_text"})
DESTRUCTIVE = frozenset({"write_text"})

_PATH = {
    "type": "string",
    "minLength": 1,
    "maxLength": 1024,
    "description": "Relative path inside this folder, using / separators. No .. or links.",
}
_DEFINITIONS: tuple[tuple[str, str, dict[str, Any]], ...] = (
    ("list_directory", "List up to 200 names. Use path '.' for this folder.", {"path": _PATH}),
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


def tools(writable: bool) -> list[types.Tool]:
    """The folder's tools; `write_text` only on a writable folder."""
    return [
        types.Tool(
            name=name,
            description=description,
            input_schema={
                "type": "object",
                "properties": properties,
                "required": list(properties),
                "additionalProperties": False,
            },
            annotations=types.ToolAnnotations(
                read_only_hint=name in READ_ONLY,
                destructive_hint=name in DESTRUCTIVE,
                idempotent_hint=name in READ_ONLY,
                open_world_hint=False,
            ),
        )
        for name, description, properties in _DEFINITIONS
        if name != "write_text" or writable
    ]


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
    """One operation, with the worker's argument rules (`folder_io`)."""
    if not isinstance(arguments.get("path"), str):
        raise folder_io.FolderError("A file operation needs a text path.")
    required = {"path", "text", "expectedSha256"} if tool == "write_text" else {"path"}
    if set(arguments) != required:
        raise folder_io.FolderError("This file operation's arguments are not supported.")
    return folder_io.operate(path, identity, tool, arguments, protected)


def server(
    folder: dict[str, Any], writable: bool, protected: list[Path], outcome: Outcome
) -> Server:
    """An MCP server for one folder and one request."""
    offered = {t.name: t for t in tools(writable)}

    async def list_tools(_ctx: Any, _params: Any) -> types.ListToolsResult:
        return types.ListToolsResult(tools=list(offered.values()))

    async def call_tool(_ctx: Any, params: types.CallToolRequestParams) -> types.CallToolResult:
        if params.name not in offered:
            return _failure(f"This folder has no tool named {params.name!r}.")
        arguments = dict(params.arguments or {})
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

    return Server(f"files.{folder['id']}", on_list_tools=list_tools, on_call_tool=call_tool)
