"""Commands, run as the person in their own worker (2b.4, J84, J87,
`specs/docs/design/person-held-keys.md` §13).

`run_command` starts one command in one of the person's workspaces and waits
about 15 s for it: a site operation gets 20 s at the root, so a longer one
answers with what it printed so far and a handle, which `command_output`
reads on from and `command_stop` ends. Nothing here checks the person's
signature or rules: the site host did, before it sent the call to this
worker. What this worker checks itself is the administrator's consent to
commands on this machine (J9), which it reads from the same list as its local
servers, so a site host alone cannot start a program here.

**What a command is** (J87). On Windows, Windows PowerShell 5.1, with UTF-8
output and the last command's exit code passed through; elsewhere `bash -c`,
or `sh -c` where there is no bash. No input; stdout and stderr together, at
most 1 MiB kept (the first 64 KiB and the newest bytes; what falls between is
counted, not kept). It is stopped after 10 minutes, and at most four run at
once. **The whole tree goes with it**: on Windows a Job object that kills
everything in it when closed, which the command is placed in before it runs a
single instruction; elsewhere its own process group. Whatever a command leaves
running when it ends is stopped too, so nothing outlives it as the person.
"""

from __future__ import annotations

import asyncio
import base64
import contextlib
import os
import re
import secrets
import signal
import sys
import time
from dataclasses import dataclass, field
from typing import Any

from .workspace_tools import ANSWER_BUDGET, answer_bytes

#: How long `run_command` waits before it answers with a handle. The root
#: gives an operation 20 s; the call's own budget can make it shorter.
WAIT_SECONDS = 15.0
#: A command still running after this is stopped.
LIMIT_SECONDS = 600.0
MAX_RUNNING = 4
#: Finished commands kept for `command_output`, and for how long.
MAX_KEPT = 16
KEEP_SECONDS = 600.0
MAX_COMMAND = 8192
HEAD_BYTES = 64 * 1024
TAIL_BYTES = 1024 * 1024 - HEAD_BYTES
#: Output shown in one answer at most; the answer carries it twice.
SHOW_BYTES = 24_000
#: Of a summary of a long output, how much of its start is shown.
SUMMARY_HEAD = 4_000
STOP_GRACE = 2.0

_ANSI = re.compile(rb"\x1b\[[0-9;?]*[ -/]*[@-~]|\x1b\][^\x07]*\x07")
_HANDLE = re.compile(r"^c[a-f0-9]{12}$")


class CommandError(Exception):
    """A command this worker will not start or does not know; the message says why."""


def shell_name() -> str:
    """The shell commands run in here, as the tool's description names it."""
    if sys.platform == "win32":
        return "Windows PowerShell 5.1"
    return "bash" if os.path.exists("/bin/bash") else "sh"


def _powershell() -> str:
    root = os.environ.get("SYSTEMROOT") or os.environ.get("WINDIR") or r"C:\Windows"
    return os.path.join(root, "System32", "WindowsPowerShell", "v1.0", "powershell.exe")


#: UTF-8 out whatever the code page. The command itself arrives as base64,
#: so no quoting can change it, and runs as a script block: `-EncodedCommand`
#: would write errors as CLIXML.
_LOADER = (
    "$ProgressPreference='SilentlyContinue';"
    "[Console]::OutputEncoding=[System.Text.UTF8Encoding]::new($false);"
    "$OutputEncoding=[System.Text.UTF8Encoding]::new($false);"
    "$s=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('{}'));"
    ". ([scriptblock]::Create($s))"
)
#: The last command's failure as the exit code: `-Command` passes a native
#: program's code on as 1.
_EPILOGUE = "\nif (-not $?) { if ($LASTEXITCODE) { exit $LASTEXITCODE } else { exit 1 } }\nexit 0\n"
#: Windows' limit on a command line is 32,767 characters.
_MAX_LINE = 30_000


def argv(command: str) -> list[str]:
    if sys.platform == "win32":
        encoded = base64.b64encode((command + _EPILOGUE).encode("utf-8")).decode("ascii")
        loader = _LOADER.replace("{}", encoded)
        if len(loader) > _MAX_LINE:
            raise CommandError("This command is too long for Windows. Shorten it.")
        return [
            _powershell(),
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            loader,
        ]
    shell = "/bin/bash" if os.path.exists("/bin/bash") else "/bin/sh"
    return [shell, "-c", command]


def environment() -> dict[str, str]:
    """The worker's own environment, which is the person's, less Eugene's."""
    env = {
        k: v
        for k, v in os.environ.items()
        if not k.upper().startswith(("EUGENE_PLEXUS_", "SITE_HOST_"))
    }
    env["NO_COLOR"] = "1"
    if sys.platform != "win32":
        env["TERM"] = "dumb"
    return env


# --- Windows: a Job object around the whole tree ----------------------------------


class _Job:
    """A Job object that kills everything in it when closed (Windows)."""

    def __init__(self) -> None:
        assert sys.platform == "win32"
        import ctypes
        from ctypes import wintypes

        self._ctypes = ctypes
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)  # type: ignore[attr-defined,unused-ignore]
        kernel32.CreateJobObjectW.restype = wintypes.HANDLE
        kernel32.CreateJobObjectW.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR]
        kernel32.SetInformationJobObject.restype = wintypes.BOOL
        kernel32.SetInformationJobObject.argtypes = [
            wintypes.HANDLE,
            ctypes.c_int,
            ctypes.c_void_p,
            wintypes.DWORD,
        ]
        kernel32.AssignProcessToJobObject.restype = wintypes.BOOL
        kernel32.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
        kernel32.TerminateJobObject.restype = wintypes.BOOL
        kernel32.TerminateJobObject.argtypes = [wintypes.HANDLE, wintypes.UINT]
        kernel32.CloseHandle.restype = wintypes.BOOL
        kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
        self._kernel32 = kernel32

        class Basic(ctypes.Structure):
            _fields_ = [
                ("PerProcessUserTimeLimit", ctypes.c_int64),
                ("PerJobUserTimeLimit", ctypes.c_int64),
                ("LimitFlags", wintypes.DWORD),
                ("MinimumWorkingSetSize", ctypes.c_size_t),
                ("MaximumWorkingSetSize", ctypes.c_size_t),
                ("ActiveProcessLimit", wintypes.DWORD),
                ("Affinity", ctypes.c_size_t),
                ("PriorityClass", wintypes.DWORD),
                ("SchedulingClass", wintypes.DWORD),
            ]

        class Io(ctypes.Structure):
            _fields_ = [(name, ctypes.c_uint64) for name in ("r", "w", "o", "rb", "wb", "ob")]

        class Extended(ctypes.Structure):
            _fields_ = [
                ("BasicLimitInformation", Basic),
                ("IoInfo", Io),
                ("ProcessMemoryLimit", ctypes.c_size_t),
                ("JobMemoryLimit", ctypes.c_size_t),
                ("PeakProcessMemoryUsed", ctypes.c_size_t),
                ("PeakJobMemoryUsed", ctypes.c_size_t),
            ]

        handle = kernel32.CreateJobObjectW(None, None)
        if not handle:
            raise OSError(ctypes.get_last_error(), "CreateJobObject failed")  # type: ignore[attr-defined,unused-ignore]
        self.handle: int | None = handle
        info = Extended()
        info.BasicLimitInformation.LimitFlags = 0x2000  # JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        if not kernel32.SetInformationJobObject(
            handle, 9, ctypes.byref(info), ctypes.sizeof(info)
        ):  # JobObjectExtendedLimitInformation
            error = ctypes.get_last_error()  # type: ignore[attr-defined,unused-ignore]
            self.close()
            raise OSError(error, "SetInformationJobObject failed")

    def adopt(self, process_handle: int) -> None:
        """Put a process created suspended in the job, then let it run."""
        assert sys.platform == "win32"
        ctypes = self._ctypes
        if not self._kernel32.AssignProcessToJobObject(self.handle, process_handle):
            raise OSError(ctypes.get_last_error(), "AssignProcessToJobObject failed")
        ntdll = ctypes.WinDLL("ntdll")
        ntdll.NtResumeProcess.restype = ctypes.c_long
        ntdll.NtResumeProcess.argtypes = [ctypes.c_void_p]
        status = ntdll.NtResumeProcess(process_handle)
        if status != 0:
            raise OSError(status, "NtResumeProcess failed")

    def kill(self) -> None:
        if self.handle:
            self._kernel32.TerminateJobObject(self.handle, 1)

    def close(self) -> None:
        handle, self.handle = self.handle, None
        if handle:
            self._kernel32.CloseHandle(handle)


# --- one command ----------------------------------------------------------------------


@dataclass
class Running:
    handle: str
    folder: str
    command: str
    process: asyncio.subprocess.Process
    job: _Job | None
    started: float = field(default_factory=time.perf_counter)
    head: bytearray = field(default_factory=bytearray)
    tail: bytearray = field(default_factory=bytearray)
    dropped: int = 0
    exit_code: int | None = None
    ended: float | None = None
    stopped: str | None = None
    done: asyncio.Event = field(default_factory=asyncio.Event)
    more: asyncio.Event = field(default_factory=asyncio.Event)
    tasks: list[asyncio.Task[None]] = field(default_factory=list)

    @property
    def total(self) -> int:
        return len(self.head) + self.dropped + len(self.tail)

    @property
    def tail_from(self) -> int:
        return len(self.head) + self.dropped

    def take(self, data: bytes) -> None:
        room = HEAD_BYTES - len(self.head)
        if room > 0:
            self.head += data[:room]
            data = data[room:]
        if data:
            self.tail += data
            extra = len(self.tail) - TAIL_BYTES
            if extra > 0:
                del self.tail[:extra]
                self.dropped += extra
        self.more.set()

    def piece(self, start: int, limit: int) -> tuple[bytes, int, int]:
        """Up to `limit` kept bytes from `start`: the bytes, where they begin,
        and how many bytes were skipped because they were not kept."""
        start = max(0, min(start, self.total))
        if start < len(self.head):
            data = bytes(self.head[start : start + limit])
            if len(data) < limit and self.dropped == 0:
                data += bytes(self.tail[: limit - len(data)])
            return data, start, 0
        skipped = 0
        if start < self.tail_from:
            skipped = self.tail_from - start
            start = self.tail_from
        offset = start - self.tail_from
        return bytes(self.tail[offset : offset + limit]), start, skipped

    def kill(self) -> None:
        """The whole tree, now."""
        if self.job is not None:
            self.job.kill()
        elif sys.platform != "win32":
            with contextlib.suppress(ProcessLookupError, PermissionError, OSError):
                os.killpg(self.process.pid, signal.SIGKILL)

    def terminate(self) -> None:
        """The whole tree, asked first where the platform can ask."""
        if self.job is not None:
            self.job.kill()
        elif sys.platform != "win32":
            with contextlib.suppress(ProcessLookupError, PermissionError, OSError):
                os.killpg(self.process.pid, signal.SIGTERM)

    def answer(self, start: int | None) -> dict[str, Any]:
        """What the model sees: from `start`, or a summary (the start and the
        newest output) when None. Cut to fit the answer's budget."""
        shown = SHOW_BYTES
        while True:
            value = self._answer(start, shown)
            if answer_bytes(value) <= ANSWER_BUDGET or shown <= 1000:
                return value
            shown //= 2

    def _answer(self, start: int | None, shown: int) -> dict[str, Any]:
        total = self.total
        if start is None and total > shown:
            first, _, _ = self.piece(0, min(SUMMARY_HEAD, shown // 4))
            last_from = max(len(first), total - (shown - len(first)))
            last, last_at, _ = self.piece(last_from, shown - len(first))
            left_out = last_at - len(first)
            text = _text(first) + f"\n… {left_out} bytes not shown …\n" + _text(last)
            shown_from, next_byte = 0, last_at + len(last)
        else:
            data, shown_from, left_out = self.piece(start or 0, shown)
            text = _text(data)
            next_byte = shown_from + len(data)
        running = self.exit_code is None
        seconds = (self.ended if self.ended is not None else time.perf_counter()) - self.started
        value: dict[str, Any] = {
            "handle": self.handle,
            "folder": self.folder,
            "running": running,
            "exitCode": self.exit_code,
            "seconds": round(seconds, 1),
            "output": text,
            "outputBytes": total,
            "shownFrom": shown_from,
            "nextByte": next_byte,
            "leftOut": left_out,
        }
        if self.stopped:
            value["stopped"] = self.stopped
        if running:
            value["note"] = (
                "Still running. Call command_output with this handle to read on (from nextByte) "
                "and wait for it, or command_stop to end it."
            )
        elif next_byte < total:
            value["note"] = "More output was kept: command_output with from=nextByte reads it."
        return value


def _text(data: bytes) -> str:
    return _ANSI.sub(b"", data).decode("utf-8", "replace").replace("\r\n", "\n")


# --- the registry, one per worker ---------------------------------------------------


class Commands:
    """The commands one worker runs, by handle."""

    def __init__(self) -> None:
        self.entries: dict[str, Running] = {}

    def _prune(self) -> None:
        now = time.perf_counter()
        for handle, entry in list(self.entries.items()):
            if entry.ended is not None and now - entry.ended > KEEP_SECONDS:
                del self.entries[handle]
        finished = sorted(
            (e for e in self.entries.values() if e.ended is not None), key=lambda e: e.ended or 0
        )
        while len(self.entries) > MAX_KEPT and finished:
            del self.entries[finished.pop(0).handle]

    def running(self) -> int:
        return sum(1 for e in self.entries.values() if e.exit_code is None)

    def get(self, handle: Any) -> Running:
        if not isinstance(handle, str) or not _HANDLE.match(handle):
            raise CommandError("That is not a command handle.")
        self._prune()
        entry = self.entries.get(handle)
        if entry is None:
            raise CommandError(
                "No command with that handle here: it ended more than 10 minutes ago, or this "
                "worker started again since."
            )
        return entry

    async def run(self, *, folder: str, cwd: str, command: str, budget: float) -> dict[str, Any]:
        if not isinstance(command, str) or not command.strip():
            raise CommandError("Give the command to run.")
        if len(command) > MAX_COMMAND or "\x00" in command:
            raise CommandError(f"A command is at most {MAX_COMMAND} characters, without NUL.")
        self._prune()
        if self.running() >= MAX_RUNNING:
            raise CommandError(
                f"{MAX_RUNNING} commands are running already. Wait for one (command_output) or "
                "stop one (command_stop)."
            )
        entry = await self._start(folder, cwd, command)
        await self._wait(entry, budget)
        return entry.answer(None)

    async def output(self, handle: Any, start: Any, wait: float) -> dict[str, Any]:
        entry = self.get(handle)
        if start is not None and (not isinstance(start, int) or isinstance(start, bool)):
            raise CommandError("from is a byte offset: nextByte from the last answer.")
        if entry.exit_code is None and wait > 0:
            entry.more.clear()
            with contextlib.suppress(TimeoutError):
                await asyncio.wait_for(entry.done.wait(), wait)
        return entry.answer(start)

    async def stop(self, handle: Any) -> dict[str, Any]:
        entry = self.get(handle)
        if entry.exit_code is None:
            entry.stopped = "stop"
            entry.terminate()
            with contextlib.suppress(TimeoutError):
                await asyncio.wait_for(entry.done.wait(), STOP_GRACE)
            if entry.exit_code is None:
                entry.kill()
                with contextlib.suppress(TimeoutError):
                    await asyncio.wait_for(entry.done.wait(), STOP_GRACE)
        return entry.answer(None)

    async def close(self) -> None:
        """Everything still running, when the worker stops."""
        tasks: list[asyncio.Task[None]] = []
        for entry in list(self.entries.values()):
            if entry.exit_code is None:
                entry.stopped = "worker"
                entry.kill()
            tasks += entry.tasks
        if tasks:
            with contextlib.suppress(TimeoutError):
                await asyncio.wait_for(asyncio.gather(*tasks, return_exceptions=True), 5.0)
        for entry in self.entries.values():
            if entry.job is not None:
                entry.job.close()

    async def _wait(self, entry: Running, budget: float) -> None:
        wait = max(0.0, min(WAIT_SECONDS, budget))
        with contextlib.suppress(TimeoutError):
            await asyncio.wait_for(entry.done.wait(), wait)

    async def _start(self, folder: str, cwd: str, command: str) -> Running:
        job: _Job | None = None
        kwargs: dict[str, Any] = {}
        if sys.platform == "win32":
            job = _Job()
            # CREATE_SUSPENDED | CREATE_NO_WINDOW | CREATE_NEW_PROCESS_GROUP: it
            # runs nothing until it is in the job.
            kwargs["creationflags"] = 0x00000004 | 0x08000000 | 0x00000200
        else:
            kwargs["start_new_session"] = True
        try:
            process = await asyncio.create_subprocess_exec(
                *argv(command),
                cwd=cwd,
                env=environment(),
                stdin=asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
                **kwargs,
            )
        except OSError as exc:
            if job is not None:
                job.close()
            raise CommandError(
                f"The command could not be started: {exc.strerror or exc}."
            ) from None
        if job is not None:
            try:
                popen = process._transport.get_extra_info("subprocess")  # type: ignore[attr-defined]
                job.adopt(int(popen._handle))
            except Exception as exc:
                with contextlib.suppress(ProcessLookupError, OSError):
                    process.kill()
                job.close()
                raise CommandError(f"The command could not be started safely ({exc}).") from None
        entry = Running("c" + secrets.token_hex(6), folder, command, process, job)
        self.entries[entry.handle] = entry
        entry.tasks.append(asyncio.create_task(self._watch(entry)))
        return entry

    async def _read(self, entry: Running) -> None:
        stream = entry.process.stdout
        assert stream is not None
        while True:
            data = await stream.read(65536)
            if not data:
                return
            entry.take(data)

    @staticmethod
    async def _exited(process: asyncio.subprocess.Process) -> None:
        """Until the command's own process ends. Not `process.wait()`, which
        returns only once every pipe is closed: a child it left running would
        hold the pipe, and the command would seem to run as long as the child."""
        # No event is set on the exit alone, so it is looked at, 20 times a second.
        while process.returncode is None:  # noqa: ASYNC110
            await asyncio.sleep(0.05)

    async def _watch(self, entry: Running) -> None:
        reader = asyncio.create_task(self._read(entry))
        try:
            try:
                await asyncio.wait_for(self._exited(entry.process), LIMIT_SECONDS)
            except TimeoutError:
                entry.stopped = "limit"
                entry.terminate()
                try:
                    await asyncio.wait_for(self._exited(entry.process), STOP_GRACE)
                except TimeoutError:
                    entry.kill()
                    await self._exited(entry.process)
            # What it left behind goes with it, and with that its hold on the pipe.
            entry.kill()
            with contextlib.suppress(TimeoutError):
                await asyncio.wait_for(reader, 5.0)
            with contextlib.suppress(TimeoutError):
                await asyncio.wait_for(entry.process.wait(), 5.0)
        finally:
            reader.cancel()
            code = entry.process.returncode
            entry.exit_code = code if code is not None else -1
            entry.ended = time.perf_counter()
            if entry.job is not None:
                entry.job.close()
            entry.done.set()
            entry.more.set()
