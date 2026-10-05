"""Start the host on loopback, as the agent's launcher starts any app."""

from __future__ import annotations

import sys

import uvicorn

from .app import create_app
from .settings import SettingsError, from_environment


def main() -> None:
    try:
        settings = from_environment()
    except SettingsError as exc:
        sys.exit(f"eugene-plexus-site-host: {exc}")
    # Never an access log: a request line can name a server, and the bodies
    # carry paths and arguments.
    uvicorn.run(
        create_app(settings),
        host="127.0.0.1",
        port=settings.port,
        log_level="warning",
        access_log=False,
    )


if __name__ == "__main__":
    main()
