"""The site host's commands.

- no command (or `serve`): run the site, as the agent's launcher starts any
  app: its channel to its root, and its health on loopback.
- `join`: make this machine a Job Site (`join.py`). Run at the machine, with
  the owner's password as the first line of standard input.
- `leave`: tell the root this site is leaving, and forget its enrollment.
- `check-person`: who a person is, from their Eugene sign-in typed at the
  machine (J36), for root to link them on a Linux system install.

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
from pathlib import Path

import uvicorn

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
    args = parser.parse_args(argv)
    if args.command == "check-person":
        _check_person(args)
    elif args.command == "join":
        _join(args)
    elif args.command == "leave":
        _leave(args)
    else:
        _serve()


if __name__ == "__main__":
    main()
