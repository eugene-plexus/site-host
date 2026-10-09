"""Eugene's own file server: one MCP server for the machine, `files` (J6g),
which is the workspace server (J28: *"a unified MCP server"*).

The tools the helper used to take as a bespoke `{tool, arguments}` command
(`remote-nodes.md` §2.1) are MCP tools, served by the SDK like any other
server's (J6). 2b.3a added a read of any part of a file, `edit_text`, `glob`
and `grep` (`workspace_tools.py`). `inspect` is not a tool: registering a
folder is a management action (`folder.add`).

Each tool takes a `folder` argument, a workspace's name in the person's view
(their own workspaces, then those the owner shared with them, 2b.3b). The
server is built for one person and one request: the tools that read list only
the workspaces whose rules let that person read, and the tools that change
files (`write_text`, `edit_text`) only those whose rules let them change
files; a tool with no workspace is not offered. A workspace's hidden paths
(`folder_io.Hidden`) travel with it.

**Commands** (2b.4, J84, J87): `run_command` runs one command, as the person,
starting in one of their own workspaces whose rules say `command: ask`
(`commandable`), and `command_output` and `command_stop` follow it by its
handle (`commands.py`). They are offered only when the worker serving the call
has a command registry, which it has only where an administrator consented at
the machine (J9).

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

from . import commands as cmd
from . import folder_io, workspace_tools

SERVER = "files"
READ_ONLY = frozenset({"list_directory", "read_text", "glob", "grep"})
DESTRUCTIVE = folder_io.WRITING
#: The tool that runs a program (J88's group), and those that follow one by
#: its handle, which take no `folder`.
COMMANDS = frozenset({"run_command"})
HANDLES = frozenset({"command_output", "command_stop"})
COMMAND_TOOLS = COMMANDS | HANDLES
_HANDLE = {
    "type": "string",
    "pattern": "^c[a-f0-9]{12}$",
    "description": "The handle run_command gave.",
}

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


def _command_definitions() -> tuple[tuple[str, str, dict[str, Any], tuple[str, ...]], ...]:
    shell = cmd.shell_name()
    wait = int(cmd.WAIT_SECONDS)
    limit = int(cmd.LIMIT_SECONDS // 60)
    return (
        (
            "run_command",
            f"Run one command in {shell}, as your own account on this machine, starting in the "
            "folder (or path inside it). It can do whatever your account can, not only in the "
            "folder. No input is given; stdout and stderr come together. Each command needs "
            f"your signature. Waits up to {wait} seconds: if it is still running, the answer has "
            "what it printed so far and a handle for command_output and command_stop. It is "
            f"stopped after {limit} minutes, and anything it leaves running is stopped when it "
            f"ends. At most {cmd.MAX_RUNNING} run at once.",
            {
                "command": {"type": "string", "minLength": 1, "maxLength": cmd.MAX_COMMAND},
                "path": _FOLDER_PATH,
            },
            ("command",),
        ),
        (
            "command_output",
            "Read on in a command's output from byte `from` (nextByte of the last answer; "
            f"omitted, its start and newest output), waiting up to `wait` seconds ({wait} at "
            "most) for it to end. Says whether it is still running, and its exit code.",
            {
                "handle": _HANDLE,
                "from": {"type": "integer", "minimum": 0, "maximum": 1 << 40},
                "wait": {"type": "integer", "minimum": 0, "maximum": wait},
            },
            ("handle",),
        ),
        (
            "command_stop",
            "Stop a running command and everything it started, and show its last output.",
            {"handle": _HANDLE},
            ("handle",),
        ),
    )


_SCHEMAS = {
    name: (props, frozenset(required))
    for name, _, props, required in (*_DEFINITIONS, *_command_definitions())
}


def tools(
    readable: list[str], writable: list[str], commandable: list[str] | None = None
) -> list[types.Tool]:
    """The tools for one person: `folder` names only `readable` (for
    a tool that changes files, only `writable`; for `run_command`, only
    `commandable`), and a tool with no folder is not offered. The tools that
    follow a command come with `run_command`."""
    offered: list[types.Tool] = []
    for name, description, properties, required in (*_DEFINITIONS, *_command_definitions()):
        if name in COMMAND_TOOLS:
            names = list(commandable or [])
        else:
            names = writable if name in DESTRUCTIVE else readable
        if not names:
            continue
        folder = {
            "type": "string",
            "enum": list(names),
            "description": "Which folder on this machine, by its name.",
        }
        takes_folder = name not in HANDLES
        offered.append(
            types.Tool(
                name=name,
                description=description,
                input_schema={
                    "type": "object",
                    "properties": {"folder": folder, **properties} if takes_folder else properties,
                    "required": ["folder", *required] if takes_folder else list(required),
                    "additionalProperties": False,
                },
                annotations=types.ToolAnnotations(
                    read_only_hint=name in READ_ONLY or name == "command_output",
                    destructive_hint=name in DESTRUCTIVE or name in COMMANDS | {"command_stop"},
                    idempotent_hint=name in READ_ONLY,
                    open_world_hint=name in COMMANDS,
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
    path: str,
    identity: str,
    tool: str,
    arguments: dict[str, Any],
    protected: list[Path],
    deny: list[str] | None = None,
) -> dict[str, Any]:
    """One operation on one folder, with the worker's argument rules
    (`folder_io`) and the workspace's hidden paths. `arguments` no longer
    carries `folder`."""
    check_arguments(tool, arguments)
    return folder_io.operate(path, identity, tool, arguments, protected, deny)


def _result(result: dict[str, Any]) -> types.CallToolResult:
    return types.CallToolResult(
        content=[types.TextContent(type="text", text=json.dumps(result, ensure_ascii=False))],
        structured_content=result,
        is_error=False,
    )


def start_in(folder: dict[str, Any], path: str, protected: list[Path]) -> str:
    """Where a command starts: the workspace, or a folder inside it, checked as
    the file tools check a path (no links, no `..`, nothing hidden). The
    command is not confined to it: it runs with the person's whole account."""
    names = folder_io.parts(path, directory=True)
    deny = folder.get("deny")
    folder_io.Hidden([str(p) for p in deny] if isinstance(deny, list) else None).check(names)
    with folder_io.root(folder["path"], folder["identity"]) as held:
        folder_io.check_root_path(held.path, protected)
        if names and not held.is_directory(names):
            raise folder_io.FolderError("That is not a folder in this workspace.")
        return str(Path(held.path, *names))


def server(
    folders: dict[str, dict[str, Any]],
    writable: frozenset[str],
    protected: list[Path],
    outcome: Outcome,
    readable: frozenset[str] | None = None,
    commandable: frozenset[str] = frozenset(),
    commands: cmd.Commands | None = None,
    budget: float = cmd.WAIT_SECONDS,
) -> Server:
    """The file server for one person and one request. `folders` maps each
    name they may use to its record (`path`, `identity`, and `deny`, its
    hidden paths); `readable` names those they may read and search (all of
    them when None), `writable` those they may change, `commandable` those
    they may start a command in, when `commands` (this worker's registry) is
    given. `budget` is how long this call may take, in seconds."""
    reads = frozenset(folders) if readable is None else readable
    runs = frozenset(n for n in folders if n in commandable) if commands else frozenset()
    offered = {
        t.name: t
        for t in tools(
            [n for n in folders if n in reads],
            [n for n in folders if n in writable],
            [n for n in folders if n in runs],
        )
    }

    async def list_tools(_ctx: Any, _params: Any) -> types.ListToolsResult:
        return types.ListToolsResult(tools=list(offered.values()))

    async def command(tool: str, arguments: dict[str, Any]) -> types.CallToolResult:
        assert commands is not None
        try:
            given = {k: v for k, v in arguments.items() if k != "folder"}
            check_arguments(tool, given if tool in COMMANDS else arguments)
            if tool == "run_command":
                name = arguments.get("folder")
                folder = folders.get(name) if isinstance(name, str) else None
                if folder is None or name not in runs:
                    return _failure(f"You may not run commands in a folder named {name!r}.")
                cwd = await asyncio.to_thread(
                    start_in, folder, arguments.get("path", "."), protected
                )
                # Once it started it may have acted, whatever happens next.
                outcome.uncertain = "The command started; it may have acted."
                result = await commands.run(
                    folder=str(name), cwd=cwd, command=arguments["command"], budget=budget
                )
                outcome.uncertain = None
            elif tool == "command_output":
                wait = min(float(arguments.get("wait", 0)), max(0.0, budget))
                result = await commands.output(arguments["handle"], arguments.get("from"), wait)
            else:
                result = await commands.stop(arguments["handle"])
        except (cmd.CommandError, folder_io.FolderError) as exc:
            return _failure(str(exc))
        except PermissionError:
            return _failure("Your account cannot open that folder.")
        except FileNotFoundError:
            return _failure("That folder was not found.")
        except (ValueError, KeyError, TypeError, OSError):
            return _failure("The folder could not be opened safely. Check its path.")
        return _result(result)

    async def call_tool(_ctx: Any, params: types.CallToolRequestParams) -> types.CallToolResult:
        if params.name not in offered:
            return _failure(f"This machine's file server has no tool named {params.name!r}.")
        arguments = dict(params.arguments or {})
        if params.name in COMMAND_TOOLS:
            return await command(params.name, arguments)
        name = arguments.pop("folder", None)
        folder = folders.get(name) if isinstance(name, str) else None
        may = writable if params.name in DESTRUCTIVE else reads
        if folder is None or name not in may:
            return _failure(f"You may not use a folder named {name!r} for {params.name}.")
        deny = folder.get("deny")
        try:
            result = await asyncio.to_thread(
                run,
                folder["path"],
                folder["identity"],
                params.name,
                arguments,
                protected,
                [str(p) for p in deny] if isinstance(deny, list) else None,
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
        return _result(result)

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
