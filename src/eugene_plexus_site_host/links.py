"""Who is who on this machine: the links file (§2.2, §3.2, J27).

A link says *this Eugene person is this OS account here*. The machine's
privileged starter makes it, at the machine, and writes it to a file this
host reads and cannot write: the agent on a Windows service install, root on
a Linux system install, the join on a per-user install. Neither the root nor
this host can make one.

The file is read again whenever it changes, so a new link takes effect
without a restart, and a removed one ends that account's worker connection
at the next check. A file that cannot be read or does not parse means no
links: nobody's calls run as anybody until it is put right, and the report
says why.
"""

from __future__ import annotations

import json
import threading
from dataclasses import dataclass
from pathlib import Path

from pydantic import ValidationError

from ._generated.models import SiteLinkFile


@dataclass(frozen=True)
class Link:
    subject: str
    account: str
    account_name: str
    name: str | None


class Links:
    def __init__(self, path: Path | None) -> None:
        self.path = path
        self.problem: str | None = None
        self._stamp: tuple[int, int] | None = None
        self._by_subject: dict[str, Link] = {}
        self._by_account: dict[str, Link] = {}
        self._lock = threading.Lock()

    def _refresh(self) -> None:
        if self.path is None:
            self._by_subject, self._by_account, self.problem = {}, {}, None
            return
        try:
            info = self.path.stat()
        except FileNotFoundError:
            self._stamp = None
            self._by_subject, self._by_account, self.problem = {}, {}, None
            return
        except OSError as exc:
            self._stamp = None
            self._by_subject, self._by_account = {}, {}
            self.problem = f"The links file could not be read ({exc.strerror})."
            return
        stamp = (info.st_mtime_ns, info.st_size)
        if stamp == self._stamp:
            return
        try:
            parsed = SiteLinkFile.model_validate(json.loads(self.path.read_text(encoding="utf-8")))
        except (OSError, ValueError, ValidationError):
            self._stamp = stamp
            self._by_subject, self._by_account = {}, {}
            self.problem = "The links file could not be read. Link people again at the machine."
            return
        by_subject: dict[str, Link] = {}
        by_account: dict[str, Link] = {}
        broken_subjects: set[str] = set()
        broken_accounts: set[str] = set()
        for entry in parsed.links:
            link = Link(entry.subject, entry.account, entry.accountName, entry.name)
            # One link per person and one person per account: a file that
            # breaks either rule is the starter's mistake, and the safe
            # reading drops every entry involved rather than choose.
            if (
                entry.subject in by_subject
                or entry.account in by_account
                or entry.subject in broken_subjects
                or entry.account in broken_accounts
            ):
                broken_subjects.add(entry.subject)
                broken_accounts.add(entry.account)
                for earlier in (by_subject.get(entry.subject), by_account.get(entry.account)):
                    if earlier is not None:
                        broken_subjects.add(earlier.subject)
                        broken_accounts.add(earlier.account)
                        by_subject.pop(earlier.subject, None)
                        by_account.pop(earlier.account, None)
                continue
            by_subject[entry.subject] = link
            by_account[entry.account] = link
        self._stamp = stamp
        self._by_subject, self._by_account, self.problem = by_subject, by_account, None

    def for_subject(self, subject: str) -> Link | None:
        with self._lock:
            self._refresh()
            return self._by_subject.get(subject)

    def for_account(self, account: str) -> Link | None:
        with self._lock:
            self._refresh()
            return self._by_account.get(account)

    def all(self) -> list[Link]:
        with self._lock:
            self._refresh()
            return list(self._by_subject.values())
