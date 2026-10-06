"""This site's channel to its root (J6a, J23): report, wait, claim, answer.

The site host holds the site's enrollment and polls the root itself, with a
token its own key signs; nothing relays for it. Each poll carries the site's
report (`SiteReport`), which the root keeps as a cache for listings. When the
root has an operation queued, the site claims it, checks it is bound to this
enrollment, lets its policy decide (J8), and posts the answer. A claimed
operation is never run twice: a lost acknowledgement is not a reason to run
it again.

**A root that refuses this site's token** has removed it, or this site left:
the channel says so and keeps the enrollment on disk, because a root that was
restored from a backup, or a clock far off, can say the same thing. Leaving
at the machine (`leave`) is what forgets it.
"""

from __future__ import annotations

import asyncio
import logging
import time
from datetime import UTC, datetime
from typing import Any

import httpx
from pydantic import ValidationError

from ._generated.models import SiteCall, SiteManage
from .host import PROTOCOL, Host, version
from .identity import Enrollment, Identity, IdentityError
from .join import _problem
from .root_link import RootLink, RootTlsError
from .settings import Settings

log = logging.getLogger(__name__)
RECHECK_SECONDS = 60.0


class Removed(Exception):
    """The root refused this site's token."""


class Channel:
    def __init__(self, host: Host, identity: Identity, settings: Settings) -> None:
        self.host = host
        self.identity = identity
        self.settings = settings
        self.link: RootLink | None = None
        self._for: Enrollment | None = None
        self.last_contact: datetime | None = None
        self.problem: str | None = "This site has not reached its root yet."
        self._recheck_at = 0.0

    async def _link(self, enrollment: Enrollment) -> RootLink:
        if self.link is None or self._for != enrollment:
            if self.link is not None:
                await self.link.aclose()
            self.link = RootLink(enrollment, self.identity.pins_path)
            self._for = enrollment
        return self.link

    def report(self) -> dict[str, Any]:
        reason = self.settings.unavailable()
        return {
            "protocol": PROTOCOL,
            "hostVersion": version()[:64],
            "ready": reason is None,
            "reason": reason,
            "account": self.settings.account_kind,
            "site": self.host.summary(),
        }

    async def step(self) -> None:
        enrollment = self.identity.load()
        if enrollment is None:
            self.problem = "This machine has not joined as a job site yet."
            await asyncio.sleep(2)
            return
        link = await self._link(enrollment)
        headers = {"Authorization": "Bearer " + self.identity.token(enrollment)}
        answer = await link.request("POST", "/v1/sites/poll", json=self.report(), headers=headers)
        if answer.status_code == 401:
            raise Removed(_problem(answer))
        answer.raise_for_status()
        self.last_contact = datetime.now(UTC)
        self.problem = None
        ident = answer.json().get("operation")
        if ident:
            # Claimed immediately before running: the root checks permission again.
            claim = await link.request(
                "POST", f"/v1/sites/operations/{ident}/claim", headers=headers
            )
            if claim.status_code in (403, 404):
                return  # withdrawn, cancelled or expired while it waited
            claim.raise_for_status()
            outcome = await self.perform(claim.json(), enrollment)
            done = await link.request(
                "POST", f"/v1/sites/operations/{ident}/result", json=outcome, headers=headers
            )
            if done.status_code != 404:
                done.raise_for_status()
        if time.perf_counter() >= self._recheck_at:
            self._recheck_at = time.perf_counter() + RECHECK_SECONDS
            await link.recheck()

    async def perform(self, op: dict[str, Any], enrollment: Enrollment) -> dict[str, Any]:
        """One claimed operation. Bound to this enrollment first; then the
        site's own policy decides (J8)."""
        if op.get("site") != enrollment.site or op.get("enrolledAt") != enrollment.enrolledAt:
            return {"status": "failed", "message": "This operation is not for this site."}
        acting = op.get("kind") == "mcp" and (op.get("request") or {}).get("method") == "tools/call"
        try:
            if op.get("kind") == "mcp":
                value = await self.host.mcp(
                    SiteCall.model_validate(
                        {
                            "id": op.get("id"),
                            "expiresAt": op.get("expiresAt"),
                            "subject": op.get("subject"),
                            "server": op.get("server"),
                            "request": op.get("request"),
                            "grants": op.get("grants") or [],
                            "installMode": op.get("installMode") or "production",
                        }
                    )
                )
            elif op.get("kind") == "manage":
                value = await self.host.manage(
                    SiteManage.model_validate(
                        {
                            "id": op.get("id"),
                            "expiresAt": op.get("expiresAt"),
                            "subject": op.get("subject"),
                            "action": op.get("action"),
                            "arguments": op.get("arguments") or {},
                        }
                    )
                )
            else:
                raise ValueError(op.get("kind"))
        except (ValidationError, ValueError):
            return {
                "status": "failed",
                "message": "The root sent an operation this site does not take. Update Eugene.",
            }
        except Exception as exc:
            log.warning("a site operation failed: %s", type(exc).__name__)
            return {
                "status": "uncertain" if acting else "failed",
                "message": "This site's tools did not confirm the operation."
                + (" It may have run; check before trying again." if acting else ""),
            }
        answer = {k: v for k, v in value.items() if v is not None}
        if isinstance(answer.get("message"), str):
            answer["message"] = answer["message"][:1024]
        return answer

    async def leave(self) -> None:
        """Tell the root this site is leaving, then forget the enrollment. The
        enrollment is forgotten even when the root cannot be told: leaving
        needs no one's permission (remote-nodes.md §3.3)."""
        enrollment = self.identity.load()
        if enrollment is None:
            return
        try:
            link = await self._link(enrollment)
            headers = {"Authorization": "Bearer " + self.identity.token(enrollment)}
            await link.request("POST", "/v1/sites/leave", headers=headers)
        except (httpx.HTTPError, RootTlsError, IdentityError) as exc:
            log.warning("the root could not be told this site left: %s", exc)
        finally:
            await self.aclose()
            self.identity.forget()

    async def run(self) -> None:
        try:
            while True:
                try:
                    await self.step()
                except Removed as exc:
                    self.problem = f"The root does not know this site any more: {exc}"
                    log.warning("%s", self.problem)
                    await asyncio.sleep(30)
                except (httpx.HTTPError, ValueError, KeyError, OSError, IdentityError) as exc:
                    self.problem = f"This site cannot reach its root ({type(exc).__name__})."
                    log.debug("%s: %s", self.problem, exc)
                    await asyncio.sleep(5)
        finally:
            await self.aclose()

    async def aclose(self) -> None:
        if self.link is not None:
            await self.link.aclose()
            self.link = None
            self._for = None
