"""The host's loopback API (`specs/openapi/site-host.yaml`).

Only the agent talks to it, with the credential it generated for this host.
Bodies are bounded at 65,536 bytes and never logged: they carry paths and
arguments.
"""

from __future__ import annotations

import hmac
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
from typing import Any

from fastapi import Depends, FastAPI, HTTPException, Request, Response
from fastapi.responses import JSONResponse

from ._generated.models import SiteCall, SiteManage
from .host import Host
from .settings import Settings

MAX_REQUEST = 65_536


def create_app(settings: Settings) -> FastAPI:
    host = Host(settings)

    @asynccontextmanager
    async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
        yield

    app = FastAPI(
        title="Eugene Plexus site host",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
        lifespan=lifespan,
    )
    app.state.host = host

    @app.middleware("http")
    async def bounded(
        request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        length = request.headers.get("content-length")
        if request.headers.get("transfer-encoding") or (length and int(length) > MAX_REQUEST):
            return JSONResponse(
                {"status": "failed", "message": "This request is too large."}, status_code=413
            )
        response: Response = await call_next(request)
        response.headers["Cache-Control"] = "no-store"
        return response

    def agent(request: Request) -> None:
        expected = "Bearer " + settings.credential
        if not hmac.compare_digest(request.headers.get("authorization", ""), expected):
            raise HTTPException(403, "The site host's credential is wrong.")

    @app.get("/healthz")
    async def healthz() -> JSONResponse:
        reason = settings.unavailable()
        return JSONResponse(
            {"ready": reason is None, "reason": reason}, status_code=200 if reason is None else 503
        )

    @app.get("/v1/report", dependencies=[Depends(agent)])
    async def report() -> dict[str, Any]:
        return host.report()

    @app.post("/v1/mcp", dependencies=[Depends(agent)])
    async def mcp(call: SiteCall) -> dict[str, Any]:
        return await host.mcp(call)

    @app.post("/v1/manage", dependencies=[Depends(agent)])
    async def manage(action: SiteManage) -> dict[str, Any]:
        return await host.manage(action)

    return app
