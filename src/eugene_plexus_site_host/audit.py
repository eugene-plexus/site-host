"""The site's own audit log: who asked for what, and what the site decided (J8).

Kept on the machine, in the host's own directory, never read by Eugene's
owner. Each line belongs to one person, its `reader` (J80), who alone reads
it through the root: a call or change in a workspace, its holder; one about
a person's own keys, them; the rest, the site's owner, who also reads the
lines from before lines had a reader. One JSON object a line. It never holds a
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

    def newest(
        self, limit: int, reader: str | None = None, owner: bool = False
    ) -> list[dict[str, Any]]:
        """The newest `limit` entries, newest first: every one, or with
        `reader` only theirs (and, for the site's `owner`, the lines that
        name no reader). The reader itself is not part of an entry."""
        kept: deque[dict[str, Any]] = deque(maxlen=limit)
        with self.lock:
            for path in (self.previous, self.path):
                if not path.exists():
                    continue
                with path.open(encoding="utf-8") as handle:
                    for line in handle:
                        try:
                            entry = json.loads(line)
                        except ValueError:
                            continue
                        if not isinstance(entry, dict):
                            continue
                        whose = entry.pop("reader", None)
                        if reader is None or whose == reader or (owner and whose is None):
                            kept.append(entry)
        return list(reversed(kept))
