"""What the starter hands the host in its launch environment."""

from __future__ import annotations

import json
import sys
from pathlib import Path

from eugene_plexus_site_host.settings import from_environment


def test_the_starters_protected_roots_are_the_hosts_own_too(tmp_path: Path) -> None:
    kept = tmp_path / "config"
    found = from_environment(
        {
            "EUGENE_PLEXUS_APP_DATA_DIR": str(tmp_path / "data"),
            "EUGENE_PLEXUS_APP_BIND_PORT": "9",
            "SITE_HOST_PROTECTED_ROOTS": json.dumps([str(kept)]),
        }
    )
    assert kept in found.protected
    assert tmp_path / "data" in found.protected and Path(sys.prefix) in found.protected
