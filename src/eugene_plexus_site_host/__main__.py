"""The site host's commands.

- no command (or `serve`): run the site, as the agent's launcher starts any
  app: its channel to its root, and its health on loopback.
- `join`: make this machine a Job Site (`join.py`). Run at the machine, with
  the owner's password as the first line of standard input.
- `leave`: tell the root this site is leaving, and forget its enrollment.
- `check-person`: who a person is, from their Eugene sign-in typed at the
  machine (J36), for root to link them on a Linux system install.
- `pair`: show a code for pairing the owner's passkey from Workbench, and
  wait for it (J14a.3). A Linux system install has no page at the machine,
  so this is where its code is shown. `passkeys` lists and removes them.
  Both ask the running host on loopback, with the token in its directory.

`--data-dir` defaults to `EUGENE_PLEXUS_APP_DATA_DIR`, the directory the
agent gave this app.
"""

from __future__ import annotations

import argparse
import asyncio
import getpass
import json
import os
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Any

import httpx
import uvicorn

from ._http import sync_client_for
from .app import create_app
from .channel import Channel
from .host import Host, version
from .identity import Identity
from .join import JoinError, join
from .settings import Settings, SettingsError, from_environment


def _data_dir(value: str | None) -> Path:
    chosen = value or os.environ.get("EUGENE_PLEXUS_APP_DATA_DIR")
    if not chosen:
        sys.exit("eugene-plexus-site-host: give --data-dir, the site's own directory")
    return Path(chosen)


def _password() -> str:
    if sys.stdin is not None and not sys.stdin.isatty():
        line = sys.stdin.readline()
        return line.rstrip("\r\n")
    return getpass.getpass("Your Eugene password: ")


def _serve() -> None:
    try:
        settings = from_environment()
    except SettingsError as exc:
        sys.exit(f"eugene-plexus-site-host: {exc}")
    # Never an access log: a request line can name a server.
    uvicorn.run(
        create_app(settings),
        host="127.0.0.1",
        port=settings.port,
        log_level="warning",
        access_log=False,
    )


def _join(args: argparse.Namespace) -> None:
    identity = Identity(_data_dir(args.data_dir))
    password = _password()
    if not password:
        sys.exit("eugene-plexus-site-host: the owner's password is needed to join")
    try:
        enrollment = asyncio.run(
            join(
                identity,
                url=args.url,
                token=args.token,
                owner=args.owner,
                password=password,
                label=args.label,
                root_key=args.root_key,
                host_version=version()[:64],
            )
        )
    except JoinError as exc:
        sys.exit(f"eugene-plexus-site-host: {exc}")
    print(f"Joined as {enrollment.ownerName}'s job site {enrollment.label} ({enrollment.site}).")


def _leave(args: argparse.Namespace) -> None:
    data = _data_dir(args.data_dir)
    identity = Identity(data)
    settings = Settings(data_dir=data, port=0)
    channel = Channel(Host(settings, identity), identity, settings)
    asyncio.run(channel.leave())
    print("This machine is no longer a job site.")


def _check_person(args: argparse.Namespace) -> None:
    """Root links someone on a Linux system install (J36): who they are,
    from their Eugene sign-in, as JSON on standard output."""
    data = _data_dir(args.data_dir)
    identity = Identity(data)
    password = _password()
    if not password:
        sys.exit("eugene-plexus-site-host: the person's password is needed")
    settings = Settings(data_dir=data, port=0)
    channel = Channel(Host(settings, identity), identity, settings)
    try:
        person = asyncio.run(channel.check_person(args.name, password))
    except PermissionError as exc:
        sys.exit(f"eugene-plexus-site-host: {exc}")
    print(json.dumps(person))


def _starter(args: argparse.Namespace) -> tuple[httpx.Client, str, Any]:
    """A client for the running host's loopback API, the person it is for,
    and the enrollment."""
    data = _data_dir(args.data_dir)
    try:
        enrollment = Identity(data).load()
    except Exception as exc:  # an unreadable enrollment is the message
        sys.exit(f"eugene-plexus-site-host: the site's enrollment could not be read ({exc})")
    if enrollment is None:
        sys.exit("eugene-plexus-site-host: this machine is not a job site yet")
    port = args.port or os.environ.get("EUGENE_PLEXUS_APP_BIND_PORT")
    if not port or not str(port).isdigit():
        sys.exit("eugene-plexus-site-host: give --port, the port the site host listens on")
    try:
        token = (data / "local_token").read_text(encoding="utf-8").strip()
    except OSError:
        sys.exit(
            "eugene-plexus-site-host: the site host has not started here yet, so it has no codes"
        )
    url = f"http://127.0.0.1:{port}"
    client = sync_client_for(
        url, base_url=url, headers={"Authorization": f"Bearer {token}"}, timeout=10
    )
    return client, args.subject or enrollment.owner, enrollment


def _ask(client: httpx.Client, method: str, path: str, **kwargs: Any) -> httpx.Response:
    try:
        return client.request(method, path, **kwargs)
    except httpx.HTTPError:
        sys.exit(
            "eugene-plexus-site-host: the site host is not answering here. Start it "
            "(sudo systemctl start eugene-plexus-site-host) and run this again."
        )


def _clock(iso: str) -> str:
    try:
        return datetime.fromisoformat(iso).astimezone().strftime("%H:%M")
    except ValueError:
        return iso


def _pair(args: argparse.Namespace) -> None:
    client, subject, enrollment = _starter(args)
    with client:
        before = _ask(client, "GET", "/v1/passkeys", params={"subject": subject})
        if before.status_code != 200:
            sys.exit(
                f"eugene-plexus-site-host: {enrollment.ownerName} is not linked to an account "
                "here. Link them first (--site-link)."
            )
        known = {p["id"] for p in before.json().get("passkeys", [])}
        made = _ask(client, "POST", "/v1/passkeys/code", json={"subject": subject})
        if made.status_code != 200:
            sys.exit(
                f"eugene-plexus-site-host: only this site's owner, {enrollment.ownerName}, "
                "pairs a passkey here."
            )
        code = made.json()
        print(f"Pair {enrollment.ownerName}'s passkey with {enrollment.label}:")
        print(f"  1. In Workbench, at its https address, open Job sites, then {enrollment.label}.")
        print("  2. Choose Add a passkey, and type this code there:")
        print()
        print(f"       {code['code']}")
        print()
        print(
            f"  It works once, until {_clock(code['expiresAt'])}. It stays on this machine and "
            "in your browser; Eugene's root never sees it."
        )
        # Shown now, not when this exits: through a pipe (`| tee`, a harness)
        # print buffers, and the code would arrive only once it had expired.
        sys.stdout.flush()
        if args.no_wait:
            return
        print("Waiting for the passkey (Ctrl-C stops waiting; the code still works)...", flush=True)
        try:
            while True:
                time.sleep(2)
                now = _ask(client, "GET", "/v1/passkeys", params={"subject": subject})
                if now.status_code != 200:
                    sys.exit("eugene-plexus-site-host: the owner's link went away while waiting")
                listed = now.json()
                fresh = [p for p in listed.get("passkeys", []) if p["id"] not in known]
                if fresh:
                    key = fresh[0]
                    print(f"Paired: {key['label']} ({key['id'][:8]}), for {key['rpId']}.")
                    print("Next, in Workbench, approve this machine's rules with it.")
                    return
                if listed.get("codeExpiresAt") is None:
                    sys.exit(
                        "eugene-plexus-site-host: the code expired, or did not match three "
                        "times, and no passkey was paired. Run this again for a new code."
                    )
        except KeyboardInterrupt:
            print()
            print(f"Stopped waiting. The code works until {_clock(code['expiresAt'])}.")


def _passkeys(args: argparse.Namespace) -> None:
    client, subject, enrollment = _starter(args)
    with client:
        if args.remove:
            gone = _ask(
                client, "DELETE", f"/v1/passkeys/{args.remove}", params={"subject": subject}
            )
            if gone.status_code != 204:
                sys.exit("eugene-plexus-site-host: no such passkey here")
            print("Removed. What it approved stays approved.")
            return
        listed = _ask(client, "GET", "/v1/passkeys", params={"subject": subject})
        if listed.status_code != 200:
            sys.exit(f"eugene-plexus-site-host: {enrollment.ownerName} is not linked here")
        keys = listed.json().get("passkeys", [])
        if not keys:
            print(f"No passkeys are pinned to {enrollment.ownerName} here.")
        for key in keys:
            print(f"{key['id']}  {key['label']}  ({key['rpId']}, added {key['addedAt'][:10]})")


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="eugene-plexus-site-host")
    commands = parser.add_subparsers(dest="command")
    checking = commands.add_parser("check-person", help="who a person is, from their sign-in")
    checking.add_argument("--name", required=True, help="how the person signs in")
    checking.add_argument("--data-dir", dest="data_dir")
    commands.add_parser("serve", help="run the site (the default)")
    joining = commands.add_parser("join", help="make this machine a job site")
    joining.add_argument("--url", required=True, help="the root's address")
    joining.add_argument("--token", required=True, help="the site invitation")
    joining.add_argument("--owner", required=True, help="the owner's sign-in name")
    joining.add_argument("--label", required=True, help="this machine's name in the install")
    joining.add_argument("--root-key", dest="root_key", help="the root's identity key (HTTPS)")
    joining.add_argument("--data-dir", dest="data_dir")
    leaving = commands.add_parser("leave", help="leave the install")
    leaving.add_argument("--data-dir", dest="data_dir")
    pairing = commands.add_parser("pair", help="a code for pairing the owner's passkey")
    pairing.add_argument("--data-dir", dest="data_dir")
    pairing.add_argument("--port", help="the port the running site host listens on")
    pairing.add_argument("--subject", help=argparse.SUPPRESS)
    pairing.add_argument("--no-wait", dest="no_wait", action="store_true")
    listing = commands.add_parser("passkeys", help="the owner's passkeys pinned here")
    listing.add_argument("--data-dir", dest="data_dir")
    listing.add_argument("--port", help="the port the running site host listens on")
    listing.add_argument("--subject", help=argparse.SUPPRESS)
    listing.add_argument("--remove", metavar="ID", help="remove this passkey")
    args = parser.parse_args(argv)
    if args.command == "check-person":
        _check_person(args)
    elif args.command == "join":
        _join(args)
    elif args.command == "leave":
        _leave(args)
    elif args.command == "pair":
        _pair(args)
    elif args.command == "passkeys":
        _passkeys(args)
    else:
        _serve()


if __name__ == "__main__":
    main()
