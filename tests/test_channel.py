"""The site's own enrollment and its channel to its root (J19, J23), against a
fake root that checks what a real one would."""

from __future__ import annotations

import base64
import json
import time
from pathlib import Path
from typing import Any

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from eugene_plexus_site_host import channel as channel_module
from eugene_plexus_site_host import join as join_module
from eugene_plexus_site_host._generated.models import SiteCall
from eugene_plexus_site_host.channel import Channel, Removed
from eugene_plexus_site_host.host import Host
from eugene_plexus_site_host.identity import Identity, load_public, public_b64
from eugene_plexus_site_host.join import JoinError, join

from .conftest import ADA, settings_for

SITE = "s-" + "b" * 26
ROOT_KEY = public_b64(Ed25519PrivateKey.generate())


class FakeRoot:
    """What `POST /v1/sites/*` does, as far as a site can see it."""

    def __init__(self) -> None:
        self.public: str | None = None
        self.enrolled_at = "2026-10-06T12:00:00+00:00"
        self.queue: list[dict[str, Any]] = []
        self.results: dict[str, dict[str, Any]] = {}
        self.refuse = False
        self.left = False
        self.reports: list[dict[str, Any]] = []
        self.enroll_answer: tuple[int, dict[str, Any]] | None = None
        self.person_answer: tuple[int, dict[str, Any]] = (
            200,
            {"subject": "person-jo", "name": "jo"},
        )
        self.person_checks: list[dict[str, Any]] = []

    def check(self, request: httpx.Request) -> None:
        token = request.headers["authorization"].removeprefix("Bearer ")
        claims = jwt.decode(
            token, load_public(self.public or ""), algorithms=["EdDSA"], audience="control"
        )
        assert claims["iss"] == f"site:{SITE}" and claims["sub"] == "site"
        assert claims["exp"] - claims["iat"] <= 300

    def handle(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path == "/v1/sites/enroll":
            body = json.loads(request.content)
            if self.enroll_answer is not None:
                return httpx.Response(self.enroll_answer[0], json=self.enroll_answer[1])
            assert body["owner"] == {"name": "ada", "password": "pw"}
            self.public = body["tokenPublicKey"]
            return httpx.Response(
                201,
                json={
                    "id": SITE,
                    "label": body["label"],
                    "owner": ADA,
                    "ownerName": "ada",
                    "controlPublicKey": ROOT_KEY,
                    "enrolledAt": self.enrolled_at,
                },
            )
        if self.refuse:
            return httpx.Response(401, json={"detail": {"detail": "This site is not enrolled."}})
        self.check(request)
        if path == "/v1/sites/poll":
            self.reports.append(json.loads(request.content))
            ident = self.queue[0]["id"] if self.queue else None
            return httpx.Response(200, json={"operation": ident})
        if path.endswith("/claim"):
            op = self.queue.pop(0)
            return httpx.Response(200, json=op)
        if path.endswith("/result"):
            self.results[path.split("/")[-2]] = json.loads(request.content)
            return httpx.Response(204)
        if path == "/v1/sites/links/check":
            self.person_checks.append(json.loads(request.content))
            return httpx.Response(self.person_answer[0], json=self.person_answer[1])
        if path == "/v1/sites/leave":
            self.left = True
            return httpx.Response(204)
        return httpx.Response(404)

    def client(self, *_args: Any, **_kwargs: Any) -> httpx.AsyncClient:
        return httpx.AsyncClient(transport=httpx.MockTransport(self.handle))


@pytest.fixture
def root(monkeypatch: pytest.MonkeyPatch) -> FakeRoot:
    fake = FakeRoot()
    monkeypatch.setattr(join_module, "client_for", fake.client)

    class Link:
        def __init__(self, enrollment: Any, _pins: Path) -> None:
            self.enrollment = enrollment
            self._client = fake.client()

        async def request(self, method: str, path: str, **kwargs: Any) -> httpx.Response:
            return await self._client.request(method, self.enrollment.url + path, **kwargs)

        async def recheck(self) -> None:
            return None

        async def aclose(self) -> None:
            await self._client.aclose()

    monkeypatch.setattr(channel_module, "RootLink", Link)
    return fake


async def joined_site(tmp_path: Path, root: FakeRoot) -> tuple[Identity, Channel]:
    settings = settings_for(tmp_path, enrolled=False)
    identity = Identity(settings.data_dir)
    await join(
        identity,
        url="http://192.168.1.5:8083",
        token="invitation",
        owner="ada",
        password="pw",
        label="desk",
        root_key=None,
        host_version="test",
    )
    return identity, Channel(Host(settings, identity), identity, settings)


async def test_a_join_records_the_owner_from_the_roots_answer(
    tmp_path: Path, root: FakeRoot
) -> None:
    identity, _ = await joined_site(tmp_path, root)
    enrollment = identity.load()
    assert enrollment is not None
    assert (enrollment.site, enrollment.owner, enrollment.rootKey) == (SITE, ADA, ROOT_KEY)
    # Only the public half left the machine, and the key on disk is its other half.
    assert public_b64(identity.key()) == root.public
    with pytest.raises(JoinError, match="already"):
        await join(
            identity,
            url="http://192.168.1.5:8083",
            token="t",
            owner="ada",
            password="pw",
            label="desk",
            root_key=None,
            host_version=None,
        )


async def test_over_https_a_join_needs_the_roots_key_and_sends_nothing_without_it(
    tmp_path: Path, root: FakeRoot
) -> None:
    identity = Identity(settings_for(tmp_path, enrolled=False).data_dir)
    with pytest.raises(JoinError, match="root-key"):
        await join(
            identity,
            url="https://nodes.example.test",
            token="t",
            owner="ada",
            password="pw",
            label="desk",
            root_key=None,
            host_version=None,
        )
    assert root.public is None and identity.load() is None


async def test_a_refused_join_says_why_and_keeps_nothing(tmp_path: Path, root: FakeRoot) -> None:
    root.enroll_answer = (401, {"detail": {"detail": "That name and password do not match."}})
    identity = Identity(settings_for(tmp_path, enrolled=False).data_dir)
    with pytest.raises(JoinError, match="do not match"):
        await join(
            identity,
            url="http://192.168.1.5:8083",
            token="t",
            owner="ada",
            password="pw",
            label="desk",
            root_key=None,
            host_version=None,
        )
    assert identity.load() is None and not (identity.data_dir / "site_key.pem").exists()


async def test_a_root_answering_with_another_identity_is_not_kept(
    tmp_path: Path, root: FakeRoot
) -> None:
    identity = Identity(settings_for(tmp_path, enrolled=False).data_dir)
    other = base64.b64encode(b"\x01" * 32).decode()
    with pytest.raises(JoinError, match="not the one"):
        await join(
            identity,
            url="http://192.168.1.5:8083",
            token="t",
            owner="ada",
            password="pw",
            label="desk",
            root_key=other,
            host_version=None,
        )
    assert identity.load() is None


async def test_the_channel_reports_and_runs_an_operation_for_this_enrollment(
    tmp_path: Path, root: FakeRoot
) -> None:
    _, link = await joined_site(tmp_path, root)
    root.queue.append(
        {
            "id": "op-1",
            "expiresAt": time.time() + 20,
            "site": SITE,
            "enrolledAt": root.enrolled_at,
            "subject": ADA,
            "kind": "manage",
            "action": "audit.read",
            "arguments": {"limit": 5},
            "installMode": "production",
            "grants": [],
        }
    )
    await link.step()
    assert root.results["op-1"]["status"] == "done"
    report = root.reports[-1]
    assert report["protocol"] == "mcp-2026-07-28" and report["site"]["owner"] == ADA
    assert link.problem is None and link.last_contact is not None


@pytest.mark.parametrize("asked", [True, False, None])
async def test_a_call_carries_workbenchs_word_that_the_person_was_asked(
    tmp_path: Path, root: FakeRoot, asked: bool | None
) -> None:
    """J72: the root's `asked` reaches the policy; dropped on the way, every
    "ask" tool would be refused after the person approved it in Workbench."""
    _, link = await joined_site(tmp_path, root)
    seen: list[SiteCall] = []

    async def mcp(call: SiteCall) -> dict[str, Any]:
        seen.append(call)
        return {"status": "done", "response": {}}

    link.host.mcp = mcp  # type: ignore[method-assign]
    root.queue.append(
        {
            "id": "op-1",
            "expiresAt": time.time() + 20,
            "site": SITE,
            "enrolledAt": root.enrolled_at,
            "subject": ADA,
            "kind": "mcp",
            "server": "files",
            "request": {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}},
            "installMode": "production",
            "grants": [],
            **({} if asked is None else {"asked": asked}),
        }
    )
    await link.step()
    assert root.results["op-1"]["status"] == "done", root.results
    assert [c.asked for c in seen] == [bool(asked)]


async def test_an_operation_for_another_enrollment_never_runs(
    tmp_path: Path, root: FakeRoot
) -> None:
    _, link = await joined_site(tmp_path, root)
    for ident, changed in (
        ("op-old", {"enrolledAt": "2026-01-01T00:00:00+00:00"}),
        ("op-x", {"site": "s-" + "c" * 26}),
    ):
        root.queue.append(
            {
                "id": ident,
                "expiresAt": time.time() + 20,
                "site": SITE,
                "enrolledAt": root.enrolled_at,
                "subject": ADA,
                "kind": "manage",
                "action": "audit.read",
                "arguments": {},
                "installMode": "production",
                "grants": [],
                **changed,
            }
        )
        await link.step()
        assert root.results[ident] == {
            "status": "failed",
            "message": "This operation is not for this site.",
        }


async def test_a_root_that_refuses_the_token_is_said_so_and_the_enrollment_kept(
    tmp_path: Path, root: FakeRoot
) -> None:
    identity, link = await joined_site(tmp_path, root)
    root.refuse = True
    with pytest.raises(Removed, match="not enrolled"):
        await link.step()
    assert identity.load() is not None


async def test_leaving_tells_the_root_and_forgets_the_enrollment(
    tmp_path: Path, root: FakeRoot
) -> None:
    identity, link = await joined_site(tmp_path, root)
    await link.leave()
    assert root.left is True
    assert identity.load() is None and not (identity.data_dir / "site_key.pem").exists()


async def test_check_person_asks_the_root_with_the_sites_token_and_returns_who(
    tmp_path: Path, root: FakeRoot
) -> None:
    _, link = await joined_site(tmp_path, root)
    # `FakeRoot.check` verifies the EdDSA token against the site's public key.
    who = await link.check_person("jo", "hunter2")
    assert who == {"subject": "person-jo", "name": "jo"}
    assert root.person_checks == [{"name": "jo", "password": "hunter2"}]


async def test_check_person_names_the_name_typed_when_the_root_gives_none(
    tmp_path: Path, root: FakeRoot
) -> None:
    _, link = await joined_site(tmp_path, root)
    root.person_answer = (200, {"subject": "person-jo"})
    assert await link.check_person("Jo", "pw") == {"subject": "person-jo", "name": "Jo"}


@pytest.mark.parametrize(
    ("status", "words"),
    [
        (401, "name or password is not right"),
        (403, "turned off, or is not a person on a site"),
        (429, "Too many tries"),
        (500, r"could not check it \(500\)"),
        (200, "answer could not be read"),
    ],
)
async def test_check_person_says_what_the_root_said_no_to(
    tmp_path: Path, root: FakeRoot, status: int, words: str
) -> None:
    _, link = await joined_site(tmp_path, root)
    root.person_answer = (status, {"detail": "x"})
    with pytest.raises(PermissionError, match=words):
        await link.check_person("jo", "pw")
    assert root.person_checks, "the root was asked"


@pytest.mark.parametrize(
    ("detail", "words"),
    [
        (
            "Eugene's owner has not let you use job sites as yourself.",
            "^Eugene's owner has not let you use job sites as yourself.$",
        ),
        ("two\nlines", "turned off, or is not a person on a site"),
        ("   ", "turned off, or is not a person on a site"),
        (7, "turned off, or is not a person on a site"),
    ],
)
async def test_check_person_refused_says_the_roots_own_reason(
    tmp_path: Path, root: FakeRoot, detail: Any, words: str
) -> None:
    """J77: a person not let use job sites is told so, in the root's words,
    which say where it is changed; a reason that is not one line is not
    relayed."""
    _, link = await joined_site(tmp_path, root)
    root.person_answer = (403, {"detail": {"title": "Not allowed", "detail": detail}})
    with pytest.raises(PermissionError, match=words):
        await link.check_person("jo", "pw")


async def test_check_person_on_a_machine_that_has_not_joined_asks_nobody(
    tmp_path: Path, root: FakeRoot
) -> None:
    settings = settings_for(tmp_path, enrolled=False)
    identity = Identity(settings.data_dir)
    link = Channel(Host(settings, identity), identity, settings)
    with pytest.raises(PermissionError, match="not a job site"):
        await link.check_person("jo", "pw")
    assert root.person_checks == []
