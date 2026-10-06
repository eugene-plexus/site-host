"""A Job Site trusts its root by the root's identity key (J7a), checked in the
site host that holds the enrollment (slice 2b.1).

Real TLS servers on loopback with throwaway certificates: the root's, and an
impostor's presenting a different key. The impostor serves the root's own
signed list, which is the strongest thing a party in the middle could replay.
"""

from __future__ import annotations

import asyncio
import contextlib
import datetime as dt
import json
import socket
import ssl
import threading
import time
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import jwt
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.x509.oid import NameOID

from eugene_plexus_site_host import root_link as root_tls
from eugene_plexus_site_host.identity import Enrollment, public_b64


def _certificate(tmp: Path, name: str) -> tuple[Path, Path, bytes]:
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    now = dt.datetime.now(dt.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=1))
        .not_valid_after(now + dt.timedelta(days=2))
        .sign(key, hashes.SHA256())
    )
    cert_path, key_path = tmp / f"{name}.crt", tmp / f"{name}.key"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    return cert_path, key_path, cert.public_bytes(serialization.Encoding.DER)


class _Server:
    def __init__(self, cert: Path, key: Path, routes: dict[str, Any]) -> None:
        self.hits: list[str] = []
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                outer.hits.append(self.path)
                entry = routes.get(self.path, {"missing": self.path})
                status = 200 if self.path in routes else 404
                if isinstance(entry, tuple):
                    status, entry = entry
                body = json.dumps(entry).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            do_POST = do_GET

            def log_message(self, *args: Any) -> None:
                pass

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert, key)
        self.httpd.socket = context.wrap_socket(self.httpd.socket, server_side=True)
        self.port = self.httpd.server_address[1]
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def close(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()


def _signed_list(identity: Any, origin: str, ders: list[bytes], iat: int | None = None) -> str:
    keys = [{"spki": root_tls.spki_pin(d)[0], "notAfter": root_tls.spki_pin(d)[1]} for d in ders]
    return jwt.encode(
        {"iat": iat or int(time.time()), "origin": origin, "keys": keys},
        identity,
        algorithm="EdDSA",
        headers={"typ": root_tls.TYP_ROOT_TLS},
    )


@pytest.fixture
def root(tmp_path: Path) -> Iterator[dict[str, Any]]:
    identity = Ed25519PrivateKey.generate()
    cert, key, der = _certificate(tmp_path, "root")
    holder: dict[str, Any] = {}
    real = _Server(cert, key, holder)
    url = f"https://127.0.0.1:{real.port}"
    holder["/v1/trust/tls"] = {"jws": _signed_list(identity, url, [der])}
    holder["/ping"] = {"ok": True}
    yield {
        "url": url,
        "key": public_b64(identity),
        "identity": identity,
        "der": der,
        "server": real,
        "routes": holder,
    }
    real.close()


def test_the_list_from_the_root_verifies_and_names_the_key_shown(root: dict[str, Any]) -> None:
    claims = asyncio.run(root_tls.fetch_list(root["url"], root["key"]))
    assert claims["keys"][0]["spki"] == root_tls.spki_pin(root["der"])[0]


def test_an_impostor_replaying_the_roots_own_list_is_refused(
    root: dict[str, Any], tmp_path: Path
) -> None:
    """A party in the middle at the root's address, with the root's own signed
    list (which names the root's key, not the impostor's)."""
    cert, key, _ = _certificate(tmp_path, "middle")
    routes: dict[str, Any] = {}
    middle = _Server(cert, key, routes)
    url = f"https://127.0.0.1:{middle.port}"
    routes["/v1/trust/tls"] = {"jws": _signed_list(root["identity"], url, [root["der"]])}
    try:
        with pytest.raises(root_tls.RootTlsError, match="not one its root signed"):
            asyncio.run(root_tls.fetch_list(url, root["key"]))
    finally:
        middle.close()


def test_a_list_signed_by_any_other_key_is_refused(root: dict[str, Any]) -> None:
    stranger = Ed25519PrivateKey.generate()
    root["routes"]["/v1/trust/tls"] = {"jws": _signed_list(stranger, root["url"], [root["der"]])}
    with pytest.raises(root_tls.RootTlsError, match="pinned key"):
        asyncio.run(root_tls.fetch_list(root["url"], root["key"]))


def test_a_root_whose_clock_runs_ahead_is_still_believed(root: dict[str, Any]) -> None:
    """A root a few seconds ahead of the site (WSL2 behind its NAT, measured
    2.4 s, 2026-10-05) signs a list "issued" in the site's future. Every token
    here allows the same clock skew; so does this list."""
    ahead = int(time.time()) + 30
    root["routes"]["/v1/trust/tls"] = {
        "jws": _signed_list(root["identity"], root["url"], [root["der"]], iat=ahead)
    }
    claims = asyncio.run(root_tls.fetch_list(root["url"], root["key"]))
    assert claims["iat"] == ahead
    far = int(time.time()) + root_tls.LEEWAY_SECONDS + 60
    root["routes"]["/v1/trust/tls"] = {
        "jws": _signed_list(root["identity"], root["url"], [root["der"]], iat=far)
    }
    with pytest.raises(root_tls.RootTlsError, match="clock"):
        asyncio.run(root_tls.fetch_list(root["url"], root["key"]))


def test_a_list_for_another_origin_is_refused(root: dict[str, Any]) -> None:
    root["routes"]["/v1/trust/tls"] = {
        "jws": _signed_list(root["identity"], "https://elsewhere.example:8443", [root["der"]])
    }
    with pytest.raises(root_tls.RootTlsError, match="is for"):
        asyncio.run(root_tls.fetch_list(root["url"], root["key"]))


def test_a_pinned_client_refuses_a_key_before_sending_anything(root: dict[str, Any]) -> None:
    async def go() -> None:
        async with root_tls.pinned_client(root["url"], lambda _pin: False, timeout=5) as client:
            with pytest.raises(Exception) as caught:
                await client.post(root["url"] + "/ping", content=b"SECRET")
            assert root_tls.refused_pin(caught.value) == root_tls.spki_pin(root["der"])[0]

    asyncio.run(go())
    assert "/ping" not in root["server"].hits


def test_a_site_adopts_a_new_key_the_root_signed_and_carries_on(
    root: dict[str, Any], tmp_path: Path
) -> None:
    enrollment = Enrollment(
        site="s-x",
        label="desk",
        owner="p",
        ownerName="Ada",
        url=root["url"],
        rootKey=root["key"],
        enrolledAt="2026-10-06T00:00:00+00:00",
    )
    link = root_tls.RootLink(enrollment, tmp_path / "root_tls.json")
    assert link.pins.keys == {}

    async def go() -> int:
        answer = await link.request("GET", "/ping")
        await link.aclose()
        return answer.status_code

    assert asyncio.run(go()) == 200
    assert link.pins.accepts(root_tls.spki_pin(root["der"])[0])
    saved = json.loads((tmp_path / "root_tls.json").read_text())
    assert saved["origin"] == root["url"]


def test_an_older_list_cannot_bring_back_a_dropped_key(tmp_path: Path) -> None:
    pins = root_tls.Pins(tmp_path / "root_tls.json")
    pins.adopt({"iat": 200, "origin": "https://a", "keys": [{"spki": "new", "notAfter": 2**40}]})
    with pytest.raises(root_tls.RootTlsError, match="older"):
        pins.adopt(
            {"iat": 100, "origin": "https://a", "keys": [{"spki": "old", "notAfter": 2**40}]}
        )
    assert pins.accepts("new") and not pins.accepts("old")


def test_an_expired_key_is_not_accepted(tmp_path: Path) -> None:
    pins = root_tls.Pins(tmp_path / "root_tls.json", keys={"gone": int(time.time()) - 1})
    assert not pins.accepts("gone")


def test_the_pin_is_checked_inside_a_proxys_tunnel(
    root: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    """The helper honours proxies (§3.1), and the pin still holds through one."""
    tunnels: list[str] = []
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen()
    proxy_port = listener.getsockname()[1]

    def pump(a: socket.socket, b: socket.socket) -> None:
        try:
            while data := a.recv(65536):
                b.sendall(data)
        except OSError:
            pass
        finally:
            for s in (a, b):
                with contextlib.suppress(OSError):
                    s.shutdown(socket.SHUT_RDWR)

    def serve() -> None:
        while True:
            try:
                conn, _ = listener.accept()
            except OSError:
                return
            request = b""
            while b"\r\n\r\n" not in request:
                request += conn.recv(4096)
            target = request.split(b" ")[1].decode()
            tunnels.append(target)
            host, port = target.rsplit(":", 1)
            upstream = socket.create_connection((host, int(port)))
            conn.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
            threading.Thread(target=pump, args=(conn, upstream), daemon=True).start()
            threading.Thread(target=pump, args=(upstream, conn), daemon=True).start()

    threading.Thread(target=serve, daemon=True).start()
    # A root off this machine's network: a dotted name is egress, and so
    # gets the proxy. It resolves to loopback through the proxy alone.
    url = root["url"].replace("127.0.0.1", "root.example.test")
    monkeypatch.setattr(root_tls, "proxy_for", lambda _u: f"http://127.0.0.1:{proxy_port}")

    async def go(accept: bool) -> int:
        async with root_tls.pinned_client(url, lambda _pin: accept, timeout=5) as client:
            return (await client.get(url + "/ping")).status_code

    # The proxy resolves the name; point it at loopback.
    monkeypatch.setattr(socket, "getaddrinfo", _resolving(socket.getaddrinfo))
    assert asyncio.run(go(True)) == 200
    assert tunnels and tunnels[0].startswith("root.example.test:")
    with pytest.raises(Exception) as caught:
        asyncio.run(go(False))
    assert root_tls.refused_pin(caught.value)
    listener.close()


def _resolving(real: Any) -> Any:
    def resolve(host: Any, *args: Any, **kwargs: Any) -> Any:
        if host in ("root.example.test", b"root.example.test"):
            host = "127.0.0.1"
        return real(host, *args, **kwargs)

    return resolve


def _signed_custom(identity: Any, claims: dict[str, Any], typ: str | None) -> str:
    headers = {"typ": typ} if typ else {}
    return jwt.encode(claims, identity, algorithm="EdDSA", headers=headers)


def test_a_signed_document_that_is_not_a_tls_key_list_is_refused(root: dict[str, Any]) -> None:
    """Signed by the root's own key, but not made as a key list."""
    keys = [{"spki": root_tls.spki_pin(root["der"])[0], "notAfter": 2**40}]
    claims = {"iat": int(time.time()), "origin": root["url"], "keys": keys}
    root["routes"]["/v1/trust/tls"] = {
        "jws": _signed_custom(root["identity"], claims, "ep-trust-bundle+jwt")
    }
    with pytest.raises(root_tls.RootTlsError, match="not a TLS key list"):
        asyncio.run(root_tls.fetch_list(root["url"], root["key"]))


def test_the_key_shown_must_be_listed_and_unexpired(root: dict[str, Any]) -> None:
    shown = root_tls.spki_pin(root["der"])[0]
    claims = {
        "iat": int(time.time()),
        "origin": root["url"],
        "keys": [{"spki": shown, "notAfter": int(time.time()) - 5}],
    }
    root["routes"]["/v1/trust/tls"] = {
        "jws": _signed_custom(root["identity"], claims, root_tls.TYP_ROOT_TLS)
    }
    with pytest.raises(root_tls.RootTlsError, match="not one its root signed"):
        asyncio.run(root_tls.fetch_list(root["url"], root["key"]))


ENROLLED = {
    "id": "s-" + "a" * 26,
    "label": "desk",
    "owner": "p-ada",
    "ownerName": "ada",
    "enrolledAt": "2026-10-06T10:00:00+00:00",
}


def test_a_join_over_https_pins_the_root_first_and_then_sends(
    root: dict[str, Any], tmp_path: Path
) -> None:
    from eugene_plexus_site_host.identity import Identity
    from eugene_plexus_site_host.join import join

    root["routes"]["/v1/sites/enroll"] = (201, {**ENROLLED, "controlPublicKey": root["key"]})
    identity = Identity(tmp_path / "site")
    enrollment = asyncio.run(
        join(
            identity,
            url=root["url"],
            token="t",
            owner="ada",
            password="pw",
            label="desk",
            root_key=root["key"],
            host_version=None,
        )
    )
    assert enrollment.pinned and enrollment.site == ENROLLED["id"]
    saved = json.loads(identity.pins_path.read_text())
    assert root_tls.spki_pin(root["der"])[0] in saved["keys"], "the root's key was pinned"
    assert root["server"].hits.index("/v1/trust/tls") < root["server"].hits.index(
        "/v1/sites/enroll"
    )


def test_a_join_over_https_sends_nothing_to_an_impostor(
    root: dict[str, Any], tmp_path: Path
) -> None:
    from eugene_plexus_site_host.identity import Identity
    from eugene_plexus_site_host.join import JoinError, join

    cert, key, _ = _certificate(tmp_path, "middle")
    routes: dict[str, Any] = {"/v1/sites/enroll": (201, {**ENROLLED, "controlPublicKey": "x"})}
    middle = _Server(cert, key, routes)
    url = f"https://127.0.0.1:{middle.port}"
    routes["/v1/trust/tls"] = {"jws": _signed_list(root["identity"], url, [root["der"]])}
    identity = Identity(tmp_path / "site")
    try:
        with pytest.raises(JoinError, match="could not be trusted"):
            asyncio.run(
                join(
                    identity,
                    url=url,
                    token="secret-invitation",
                    owner="ada",
                    password="pw",
                    label="desk",
                    root_key=root["key"],
                    host_version=None,
                )
            )
    finally:
        middle.close()
    assert "/v1/sites/enroll" not in middle.hits and identity.load() is None
