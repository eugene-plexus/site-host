"""One 2026-07-28 MCP request, served in-process by the SDK.

A request arrives already whole: one JSON-RPC request with its protocol
version in `params._meta`, no handshake and no session (J6a). That is the
revision's single exchange, and the SDK already serves it. So the host hands
the request to the SDK's own handler for that exchange, in this process,
rather than writing any MCP itself (J6c, C5's rule). The SDK answers
`server/discover`, checks the request's shape, and wraps errors as the
revision says.
"""

from __future__ import annotations

from typing import Any

import httpx2
from mcp.server.lowlevel import Server
from mcp.server.streamable_http_manager import StreamableHTTPSessionManager
from mcp_types import PROTOCOL_VERSION_META_KEY

PROTOCOL = "2026-07-28"
METHODS = frozenset({"server/discover", "tools/list", "tools/call"})


class NotServed(Exception):
    """The request is not one the site serves; the message says why."""


def check(request: dict[str, Any]) -> None:
    """Refuse anything but the three methods of the 2026-07-28 revision."""
    if request.get("jsonrpc") != "2.0" or "id" not in request:
        raise NotServed("This is not a JSON-RPC request.")
    if request.get("method") not in METHODS:
        raise NotServed(
            f"A site serves {', '.join(sorted(METHODS))}, not {request.get('method')!r}."
        )
    params = request.get("params") or {}
    meta = params.get("_meta") if isinstance(params, dict) else None
    version = meta.get(PROTOCOL_VERSION_META_KEY) if isinstance(meta, dict) else None
    if version != PROTOCOL:
        raise NotServed(f"A site speaks MCP {PROTOCOL}, and this request says {version!r}.")


async def exchange(server: Server, request: dict[str, Any]) -> dict[str, Any]:
    """The server's JSON-RPC response to `request`."""
    manager = StreamableHTTPSessionManager(app=server, json_response=True, stateless=True)
    params = request.get("params") or {}
    headers = {
        "MCP-Protocol-Version": PROTOCOL,
        "Accept": "application/json, text/event-stream",
        "Content-Type": "application/json",
        "Mcp-Method": str(request["method"]),
    }
    if request["method"] == "tools/call" and isinstance(params.get("name"), str):
        headers["Mcp-Name"] = params["name"]
    async with manager.run():
        transport = httpx2.ASGITransport(app=manager.handle_request)
        async with httpx2.AsyncClient(transport=transport, base_url="http://site-host") as client:
            response = await client.post("/mcp", json=request, headers=headers)
    value = response.json()
    if not isinstance(value, dict):
        raise ValueError("the server's answer is not a JSON-RPC response")
    return value
