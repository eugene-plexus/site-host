"""The site host's process: its channel to its root, and its loopback surface.

The site host holds this site's enrollment and reaches its root itself
(`channel.py`, J23). Two things call in to it, both on loopback:

- `/healthz`, open: whether tools can run here, which site this is, and when
  the root last answered it. It never carries a path, a name or a person.
- `/v1/held`, the starter's approval API (J14a, J53): the changes held for a
  person, and their approvals, signed at the machine with that person's key.
  It answers only to the token this host writes to `local_token` in its own
  data directory, which its starter can read and nobody else; and even then
  the signature, not the caller, decides.
"""

from __future__ import annotations

import asyncio
import contextlib
import secrets
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI, Query, Request
from fastapi.responses import JSONResponse, Response
from pydantic import ValidationError

from . import signing
from ._generated.models import SiteApproval, SiteHeldReject
from .channel import Channel
from .host import Host, NotHeld
from .identity import Identity, IdentityError
from .settings import Settings

_PRIVATE = {"Cache-Control": "no-store"}


def create_app(settings: Settings, *, channel: Channel | None = None) -> FastAPI:
    identity = Identity(settings.data_dir)
    host = Host(settings, identity)
    link = channel or Channel(host, identity, settings)
    token = signing.local_token(settings.data_dir)

    @asynccontextmanager
    async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
        await host.start()
        task = asyncio.create_task(link.run())
        try:
            yield
        finally:
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await task
            await host.stop()

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
        unavailable = host.reason()
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
            headers=_PRIVATE,
        )

    # --- the starter's approval API (J14a) -----------------------------------------

    def allowed(request: Request) -> bool:
        given = request.headers.get("authorization", "")
        return secrets.compare_digest(given.encode(), f"Bearer {token}".encode())

    def unauthorized() -> Response:
        return Response(status_code=401, headers={**_PRIVATE, "WWW-Authenticate": "Bearer"})

    def not_found() -> Response:
        return Response(status_code=404, headers=_PRIVATE)

    async def body(request: Request) -> Any:
        try:
            return await request.json()
        except ValueError:
            return None

    @app.get("/v1/held")
    async def held(
        request: Request,
        subject: str = Query(min_length=1, max_length=64),
        key: str | None = Query(default=None, pattern="^[a-f0-9]{32}$"),
    ) -> Response:
        if not allowed(request):
            return unauthorized()
        try:
            listed = await asyncio.to_thread(host.held_list, subject, key)
        except NotHeld:
            return not_found()
        return JSONResponse(listed, headers=_PRIVATE)

    @app.post("/v1/held/{ident}/approve")
    async def approve(request: Request, ident: str) -> Response:
        if not allowed(request):
            return unauthorized()
        try:
            approval = SiteApproval.model_validate(await body(request))
        except ValidationError:
            return JSONResponse({"detail": "This approval is not valid."}, status_code=422)
        try:
            answer = await host.approve(ident, approval)
        except NotHeld:
            return not_found()
        return JSONResponse(answer, headers=_PRIVATE)

    @app.post("/v1/held/{ident}/reject")
    async def reject(request: Request, ident: str) -> Response:
        if not allowed(request):
            return unauthorized()
        try:
            value = SiteHeldReject.model_validate(await body(request))
        except ValidationError:
            return JSONResponse({"detail": "This request is not valid."}, status_code=422)
        try:
            await asyncio.to_thread(host.reject, ident, value.subject)
        except NotHeld:
            return not_found()
        return Response(status_code=204, headers=_PRIVATE)

    return app
