"""The site host's process: its channel to its root, and its health on loopback.

The site host holds this site's enrollment and reaches its root itself
(`channel.py`, J23); nothing calls in to it but the agent's health check.
`/healthz` is open: it says whether tools can run here, which site this is,
and when the root last answered it. It never carries a path, a name or a
person.
"""

from __future__ import annotations

import asyncio
import contextlib
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.responses import JSONResponse

from .channel import Channel
from .host import Host
from .identity import Identity, IdentityError
from .settings import Settings


def create_app(settings: Settings, *, channel: Channel | None = None) -> FastAPI:
    identity = Identity(settings.data_dir)
    host = Host(settings, identity)
    link = channel or Channel(host, identity, settings)

    @asynccontextmanager
    async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
        task = asyncio.create_task(link.run())
        try:
            yield
        finally:
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await task

    app = FastAPI(
        title="Eugene Plexus site host",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
        lifespan=lifespan,
    )
    app.state.host = host
    app.state.channel = link

    @app.get("/healthz")
    async def healthz() -> JSONResponse:
        unavailable = settings.unavailable()
        try:
            enrollment = identity.load()
        except IdentityError as exc:
            enrollment, unavailable = None, unavailable or str(exc)
        contact = link.last_contact
        return JSONResponse(
            {
                "ready": unavailable is None,
                "reason": unavailable or link.problem,
                "site": enrollment.site if enrollment else None,
                "lastContactAt": contact.isoformat() if contact else None,
            },
            status_code=200 if unavailable is None else 503,
            headers={"Cache-Control": "no-store"},
        )

    return app
