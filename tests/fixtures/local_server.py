"""A local MCP server for the tests: one read-only tool, one that changes things.

Run over stdio by the host, as an administrator's server would be. `touch`
writes a marker into the working directory the host gives it, so a test can
see whether a call ran.
"""

from __future__ import annotations

from pathlib import Path

from mcp.server.mcpserver import MCPServer
from mcp_types import ToolAnnotations

server = MCPServer("fixture")


@server.tool(annotations=ToolAnnotations(readOnlyHint=True))
def echo(text: str) -> str:
    """Say the text back."""
    return f"echo: {text}"


@server.tool()
def touch(name: str) -> str:
    """Leave a marker file. Unmarked, so the site treats it as destructive."""
    Path(name).write_text("touched", encoding="utf-8")
    return f"touched {name}"


if __name__ == "__main__":
    server.run("stdio")
