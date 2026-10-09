"""Signed calls (J14b, `specs/docs/design/person-held-keys.md` §8, §13).

For a person with a key, the site checks their calls as it checks their
changes: a tool whose rule is `ask`, and every command, runs only with the
person's own signature over that call (`act: call`); a tool whose rule is
`allow` runs only inside a window they opened with their key (`act:
window.open`, J81, J82). A call without one is **held** here (J86): listed on
the machine's page, and answered with what to sign. It runs when the call
comes again naming the held item, signed at the machine (a click on the page,
J83) or with a passkey in Workbench.

What is kept here is kept in memory: a held call lives 30 minutes, a window at
most 60, and a restart of the site host drops both, which asks again (J90).
"""

from __future__ import annotations

import secrets
import time
from dataclasses import dataclass, field
from typing import Any

from .signing import canonical

CALL = "call"
WINDOW = "window.open"
#: How long a held call waits for its signature: as long as Workbench waits.
HOLD_SECONDS = 30 * 60
WINDOW_MINUTES = 60
MAX_PER_PERSON = 16


class TooMany(Exception):
    """Too many calls wait for this person already."""


@dataclass
class Pending:
    id: str
    subject: str
    #: `call` or `window` (`SiteHeldCallKind`).
    kind: str
    act: str
    args: dict[str, Any]
    words: list[str]
    held_at: float = field(default_factory=time.time)
    #: How it was signed, once it was (at the machine, or with a passkey).
    signed: str | None = None

    @property
    def expires_at(self) -> float:
        return self.held_at + HOLD_SECONDS

    def matches(self, server: str, tool: str, arguments: Any) -> bool:
        """Whether this held call is exactly the call sent again."""
        return self.kind == "call" and canonical(self.args) == canonical(
            call_args(server, tool, arguments)
        )


def call_args(server: str, tool: str, arguments: Any) -> dict[str, Any]:
    """`act: call`'s `args`: the one tool call the person signs."""
    return {
        "server": server,
        "tool": tool,
        "arguments": arguments if isinstance(arguments, dict) else {},
    }


def window_args(minutes: int = WINDOW_MINUTES) -> dict[str, Any]:
    return {"minutes": minutes}


@dataclass
class Window:
    until: float
    signed: str


class Calls:
    """The calls held for their person's signature, and each person's window."""

    def __init__(self) -> None:
        self._pending: dict[str, Pending] = {}
        self._windows: dict[str, Window] = {}

    def _prune(self) -> None:
        now = time.time()
        self._pending = {k: p for k, p in self._pending.items() if p.expires_at > now}
        self._windows = {k: w for k, w in self._windows.items() if w.until > now}

    # --- held ----------------------------------------------------------------------

    def hold(self, subject: str, kind: str, args: dict[str, Any], words: list[str]) -> Pending:
        """Hold a call or a window for `subject`; the same one asked twice is
        held once, and unsigned again (a fresh envelope)."""
        self._prune()
        act = CALL if kind == "call" else WINDOW
        same = canonical(args)
        for item in self._pending.values():
            if (
                item.subject == subject
                and item.act == act
                and canonical(item.args) == same
                and item.signed is None
            ):
                return item
        mine = [p for p in self._pending.values() if p.subject == subject]
        if len(mine) >= MAX_PER_PERSON:
            raise TooMany(
                f"{MAX_PER_PERSON} calls already wait for your signature here. Sign or turn some "
                "down first."
            )
        item = Pending(secrets.token_hex(8), subject, kind, act, args, words)
        self._pending[item.id] = item
        return item

    def get(self, ident: str) -> Pending | None:
        self._prune()
        return self._pending.get(ident)

    def for_subject(self, subject: str) -> list[Pending]:
        """What waits for `subject`, newest first."""
        self._prune()
        return sorted(
            (p for p in self._pending.values() if p.subject == subject),
            key=lambda p: p.held_at,
            reverse=True,
        )

    def remove(self, ident: str) -> Pending | None:
        return self._pending.pop(ident, None)

    def sign(self, item: Pending, how: str) -> None:
        """`item` was signed, `how` says by which key and where. A window opens
        now; a call runs when it is sent again."""
        item.signed = how
        if item.kind == "window":
            minutes = item.args.get("minutes")
            span = minutes if isinstance(minutes, int) and 0 < minutes <= WINDOW_MINUTES else 0
            self._windows[item.subject] = Window(time.time() + 60 * span, how)

    # --- windows ---------------------------------------------------------------------

    def window(self, subject: str) -> Window | None:
        self._prune()
        return self._windows.get(subject)

    def close(self, subject: str) -> bool:
        return self._windows.pop(subject, None) is not None

    def forget(self, subject: str) -> None:
        """Everything of `subject`'s: their link or last key went."""
        self._windows.pop(subject, None)
        self._pending = {k: p for k, p in self._pending.items() if p.subject != subject}
