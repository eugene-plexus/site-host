"""The site's own audit log: who asked for what, and what the site decided (J8).

Kept on the machine, in the host's own directory, and read by the site's
owner, never by Eugene's owner. One JSON object a line. It never holds a
file's contents or a tool's result: arguments are cut at 1,024 characters
and a write's text is left out.

When the file passes 5 MB it becomes `audit.1.jsonl` and a new one starts,
so the log is bounded at about 10 MB.
"""

from __future__ import annotations

import json
import threading
from collections import deque
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

MAX_BYTES = 5_000_000
MAX_ARGUMENTS = 1024
#: Argument names whose values are contents, never recorded.
CONTENT_KEYS = frozenset({"text"})


def summarize(arguments: Any) -> str | None:
    if arguments is None:
        return None
    if isinstance(arguments, dict):
        arguments = {k: ("[left out]" if k in CONTENT_KEYS else v) for k, v in arguments.items()}
    text = json.dumps(arguments, ensure_ascii=False, sort_keys=True)
    return text if len(text) <= MAX_ARGUMENTS else text[: MAX_ARGUMENTS - 1] + "…"


class Audit:
    def __init__(self, directory: Path) -> None:
        self.path = directory / "audit.jsonl"
        self.previous = directory / "audit.1.jsonl"
        self.lock = threading.Lock()

    def record(self, **entry: Any) -> None:
        entry = {"at": datetime.now(UTC).isoformat(), **entry}
        if "arguments" in entry:
            entry["arguments"] = summarize(entry["arguments"])
        line = json.dumps(entry, ensure_ascii=False) + "\n"
        with self.lock:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            if self.path.exists() and self.path.stat().st_size + len(line) > MAX_BYTES:
                self.path.replace(self.previous)
            with self.path.open("a", encoding="utf-8") as handle:
                handle.write(line)

    def newest(self, limit: int) -> list[dict[str, Any]]:
        """The newest `limit` entries, newest first."""
        with self.lock:
            kept: deque[str] = deque(maxlen=limit)
            for path in (self.previous, self.path):
                if path.exists():
                    with path.open(encoding="utf-8") as handle:
                        for line in handle:
                            kept.append(line)
        entries = []
        for line in reversed(kept):
            try:
                entries.append(json.loads(line))
            except ValueError:
                continue
        return entries
