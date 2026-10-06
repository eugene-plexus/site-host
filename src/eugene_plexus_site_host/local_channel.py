"""The local channel between the site host and each person's worker (§3.2).

A named pipe on Windows, a Unix socket elsewhere, carrying newline-delimited
JSON, each frame at most `MAX_FRAME` bytes. **Who is at the other end is read
from the connection, never from what it says:**

- the site host learns each worker's account from the operating system
  (Windows: by impersonating the client at Identification level after its
  first frame; Linux: `SO_PEERCRED`; macOS: `getpeereid`), and decides from
  the links file whether that account may connect at all;
- a worker checks the far end is the site host's own account (Windows: the
  pipe's owner, which only its creator can set to itself; elsewhere the
  peer's uid) before it serves anything.

On Windows the pipe is made with `FILE_FLAG_FIRST_PIPE_INSTANCE`, so a pipe
someone else made first under this name stops the site host instead of
being served beside it. Clients are granted only to read and write data and
to read the pipe's security: generic write on a pipe includes the right to
create another server instance of it, which would let any local account sit
in the middle. Workers connect with `SECURITY_IDENTIFICATION`, so the site
host can learn who a worker is and can never act as it.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import os
import socket
import stat
import struct
import sys
import threading
from collections.abc import Callable, Coroutine
from typing import Any

MAX_FRAME = 256 * 1024
HELLO_SECONDS = 5.0


class ChannelError(Exception):
    """The channel could not be used; the message says why, in plain words."""


def encode(message: dict[str, Any]) -> bytes:
    data = (json.dumps(message, separators=(",", ":"), ensure_ascii=False) + "\n").encode()
    if len(data) > MAX_FRAME:
        raise ChannelError("A message on the local channel is larger than 256 KiB.")
    return data


def decode(line: bytes) -> dict[str, Any]:
    try:
        value = json.loads(line)
    except ValueError:
        raise ChannelError("The other end sent something that is not JSON.") from None
    if not isinstance(value, dict):
        raise ChannelError("The other end sent something that is not a message.")
    return value


class Connection:
    """One worker's connection, as either end sees it. `account` is the far
    end's account as the operating system reported it (a SID or a uid in
    decimal); `hello` is the first frame it sent, read before anything else."""

    account: str
    hello: dict[str, Any]

    async def send(self, message: dict[str, Any]) -> None:
        raise NotImplementedError

    async def receive(self) -> dict[str, Any] | None:
        """The next message, or None when the other end has gone."""
        raise NotImplementedError

    async def close(self) -> None:
        raise NotImplementedError


Accept = Callable[[Connection], Coroutine[Any, Any, None]]


# --- POSIX: a Unix socket ---------------------------------------------------------


def _peer_uid(sock: socket.socket) -> int:
    if sys.platform.startswith("linux"):
        raw = sock.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
        _pid, uid, _gid = struct.unpack("3i", raw)
        return int(uid)
    import ctypes
    import ctypes.util

    libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)
    uid, gid = ctypes.c_uint32(), ctypes.c_uint32()
    if libc.getpeereid(sock.fileno(), ctypes.byref(uid), ctypes.byref(gid)) != 0:
        raise ChannelError("The other end's account could not be read.")
    return int(uid.value)


class _StreamConnection(Connection):
    def __init__(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, account: str
    ) -> None:
        self.reader = reader
        self.writer = writer
        self.account = account
        self.hello = {}
        self._lock = asyncio.Lock()

    async def send(self, message: dict[str, Any]) -> None:
        data = encode(message)
        async with self._lock:
            self.writer.write(data)
            await self.writer.drain()

    async def receive(self) -> dict[str, Any] | None:
        try:
            line = await self.reader.readuntil(b"\n")
        except asyncio.IncompleteReadError as exc:
            if exc.partial:
                raise ChannelError("The other end stopped in the middle of a message.") from None
            return None
        except asyncio.LimitOverrunError:
            raise ChannelError("A message on the local channel is larger than 256 KiB.") from None
        except (ConnectionError, OSError):
            return None
        return decode(line)

    async def close(self) -> None:
        self.writer.close()
        with contextlib.suppress(Exception):
            await self.writer.wait_closed()


async def _first_frame(conn: Connection) -> dict[str, Any]:
    try:
        hello = await asyncio.wait_for(conn.receive(), HELLO_SECONDS)
    except TimeoutError:
        raise ChannelError("The other end said nothing.") from None
    if hello is None or hello.get("t") != "hello":
        raise ChannelError("The other end did not say hello.")
    return hello


if sys.platform != "win32":

    async def _serve_posix(path: str, accept: Accept) -> asyncio.AbstractServer:
        try:
            info = os.lstat(path)
        except FileNotFoundError:
            pass
        else:
            if not stat.S_ISSOCK(info.st_mode) or info.st_uid != os.getuid():
                raise ChannelError(f"{path} exists and is not this site host's channel. Remove it.")
            os.unlink(path)

        async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            sock = writer.get_extra_info("socket")
            try:
                conn = _StreamConnection(reader, writer, str(_peer_uid(sock)))
                conn.hello = await _first_frame(conn)
            except (ChannelError, OSError):
                writer.close()
                return
            await accept(conn)

        server = await asyncio.start_unix_server(handle, path=path, limit=MAX_FRAME + 1)
        # Connecting needs write permission on the socket; who may stay is the
        # peer check's to decide, not the file mode's.
        os.chmod(path, 0o666)
        return server

    async def _connect_posix(path: str, host: str) -> Connection:
        try:
            reader, writer = await asyncio.open_unix_connection(path, limit=MAX_FRAME + 1)
        except FileNotFoundError:
            raise ChannelError("The site host is not running.") from None
        except OSError as exc:
            raise ChannelError(f"The site host could not be reached ({exc.strerror}).") from None
        uid = str(_peer_uid(writer.get_extra_info("socket")))
        if uid != host:
            writer.close()
            raise ChannelError(
                f"The channel at {path} belongs to uid {uid}, not the site host's account."
            )
        return _StreamConnection(reader, writer, uid)


# --- Windows: a named pipe --------------------------------------------------------

if sys.platform == "win32":
    import ctypes
    from ctypes import wintypes

    _k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    _adv = ctypes.WinDLL("advapi32", use_last_error=True)

    _INVALID = wintypes.HANDLE(-1).value
    PIPE_ACCESS_DUPLEX = 0x3
    FILE_FLAG_OVERLAPPED = 0x40000000
    FILE_FLAG_FIRST_PIPE_INSTANCE = 0x00080000
    PIPE_REJECT_REMOTE_CLIENTS = 0x8
    PIPE_UNLIMITED_INSTANCES = 255
    #: FILE_READ_DATA | FILE_WRITE_DATA | FILE_READ_ATTRIBUTES | READ_CONTROL
    #: | SYNCHRONIZE. Never FILE_CREATE_PIPE_INSTANCE (0x4), which is what
    #: generic write would also grant.
    CLIENT_ACCESS = 0x00120083
    SECURITY_SQOS_PRESENT = 0x00100000
    SECURITY_IDENTIFICATION = 0x00010000
    OPEN_EXISTING = 3
    TOKEN_QUERY = 0x8
    TOKEN_USER = 1
    SE_FILE_OBJECT = 1
    OWNER_SECURITY_INFORMATION = 0x1
    WAIT_OBJECT_0 = 0
    WAIT_TIMEOUT = 0x102
    ERROR_FILE_NOT_FOUND = 2
    ERROR_ACCESS_DENIED = 5
    ERROR_BROKEN_PIPE = 109
    ERROR_PIPE_BUSY = 231
    ERROR_NO_DATA = 232
    ERROR_PIPE_NOT_CONNECTED = 233
    ERROR_MORE_DATA = 234
    ERROR_PIPE_CONNECTED = 535
    ERROR_OPERATION_ABORTED = 995
    ERROR_IO_PENDING = 997
    _GONE = {ERROR_BROKEN_PIPE, ERROR_NO_DATA, ERROR_PIPE_NOT_CONNECTED, ERROR_OPERATION_ABORTED}

    class _OVERLAPPED(ctypes.Structure):
        _fields_ = [
            ("Internal", ctypes.c_void_p),
            ("InternalHigh", ctypes.c_void_p),
            ("Offset", wintypes.DWORD),
            ("OffsetHigh", wintypes.DWORD),
            ("hEvent", wintypes.HANDLE),
        ]

    class _SECURITY_ATTRIBUTES(ctypes.Structure):
        _fields_ = [
            ("nLength", wintypes.DWORD),
            ("lpSecurityDescriptor", ctypes.c_void_p),
            ("bInheritHandle", wintypes.BOOL),
        ]

    def _api(lib: Any, name: str, restype: Any, *argtypes: Any) -> Any:
        fn = getattr(lib, name)
        fn.restype = restype
        fn.argtypes = list(argtypes)
        return fn

    _LPOV = ctypes.POINTER(_OVERLAPPED)
    _CreateNamedPipeW = _api(
        _k32,
        "CreateNamedPipeW",
        wintypes.HANDLE,
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.POINTER(_SECURITY_ATTRIBUTES),
    )
    _ConnectNamedPipe = _api(_k32, "ConnectNamedPipe", wintypes.BOOL, wintypes.HANDLE, _LPOV)
    _DisconnectNamedPipe = _api(_k32, "DisconnectNamedPipe", wintypes.BOOL, wintypes.HANDLE)
    _CreateFileW = _api(
        _k32,
        "CreateFileW",
        wintypes.HANDLE,
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.c_void_p,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    )
    _WaitNamedPipeW = _api(_k32, "WaitNamedPipeW", wintypes.BOOL, wintypes.LPCWSTR, wintypes.DWORD)
    _ReadFile = _api(
        _k32,
        "ReadFile",
        wintypes.BOOL,
        wintypes.HANDLE,
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.c_void_p,
        _LPOV,
    )
    _WriteFile = _api(
        _k32,
        "WriteFile",
        wintypes.BOOL,
        wintypes.HANDLE,
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.c_void_p,
        _LPOV,
    )
    _GetOverlappedResult = _api(
        _k32,
        "GetOverlappedResult",
        wintypes.BOOL,
        wintypes.HANDLE,
        _LPOV,
        ctypes.POINTER(wintypes.DWORD),
        wintypes.BOOL,
    )
    _CancelIoEx = _api(_k32, "CancelIoEx", wintypes.BOOL, wintypes.HANDLE, _LPOV)
    _CreateEventW = _api(
        _k32,
        "CreateEventW",
        wintypes.HANDLE,
        ctypes.c_void_p,
        wintypes.BOOL,
        wintypes.BOOL,
        wintypes.LPCWSTR,
    )
    _SetEvent = _api(_k32, "SetEvent", wintypes.BOOL, wintypes.HANDLE)
    _WaitForSingleObject = _api(
        _k32, "WaitForSingleObject", wintypes.DWORD, wintypes.HANDLE, wintypes.DWORD
    )
    _WaitForMultipleObjects = _api(
        _k32,
        "WaitForMultipleObjects",
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.HANDLE),
        wintypes.BOOL,
        wintypes.DWORD,
    )
    _CloseHandle = _api(_k32, "CloseHandle", wintypes.BOOL, wintypes.HANDLE)
    _GetCurrentThread = _api(_k32, "GetCurrentThread", wintypes.HANDLE)
    _GetCurrentProcess = _api(_k32, "GetCurrentProcess", wintypes.HANDLE)
    _LocalFree = _api(_k32, "LocalFree", ctypes.c_void_p, ctypes.c_void_p)
    _GetNamedPipeClientProcessId = _api(
        _k32,
        "GetNamedPipeClientProcessId",
        wintypes.BOOL,
        wintypes.HANDLE,
        ctypes.POINTER(wintypes.ULONG),
    )
    _ImpersonateNamedPipeClient = _api(
        _adv, "ImpersonateNamedPipeClient", wintypes.BOOL, wintypes.HANDLE
    )
    _RevertToSelf = _api(_adv, "RevertToSelf", wintypes.BOOL)
    _OpenThreadToken = _api(
        _adv,
        "OpenThreadToken",
        wintypes.BOOL,
        wintypes.HANDLE,
        wintypes.DWORD,
        wintypes.BOOL,
        ctypes.POINTER(wintypes.HANDLE),
    )
    _OpenProcessToken = _api(
        _adv,
        "OpenProcessToken",
        wintypes.BOOL,
        wintypes.HANDLE,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.HANDLE),
    )
    _GetTokenInformation = _api(
        _adv,
        "GetTokenInformation",
        wintypes.BOOL,
        wintypes.HANDLE,
        ctypes.c_int,
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
    )
    _ConvertSidToStringSidW = _api(
        _adv,
        "ConvertSidToStringSidW",
        wintypes.BOOL,
        ctypes.c_void_p,
        ctypes.POINTER(wintypes.LPWSTR),
    )
    _ConvertSddl = _api(
        _adv,
        "ConvertStringSecurityDescriptorToSecurityDescriptorW",
        wintypes.BOOL,
        wintypes.LPCWSTR,
        wintypes.DWORD,
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(wintypes.ULONG),
    )
    _GetSecurityInfo = _api(
        _adv,
        "GetSecurityInfo",
        wintypes.DWORD,
        wintypes.HANDLE,
        ctypes.c_int,
        wintypes.DWORD,
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
    )

    def _error(what: str) -> OSError:
        code = ctypes.get_last_error()
        return OSError(code, f"{what} failed ({code})")

    def _sid_string(psid: int | None) -> str:
        text = wintypes.LPWSTR()
        if not _ConvertSidToStringSidW(psid, ctypes.byref(text)):
            raise _error("ConvertSidToStringSid")
        try:
            return str(text.value)
        finally:
            _LocalFree(ctypes.cast(text, ctypes.c_void_p))

    def token_user(token: Any) -> str:
        """The SID of a token's user, as a string."""
        size = wintypes.DWORD(0)
        _GetTokenInformation(token, TOKEN_USER, None, 0, ctypes.byref(size))
        buffer = ctypes.create_string_buffer(size.value)
        if not _GetTokenInformation(token, TOKEN_USER, buffer, size, ctypes.byref(size)):
            raise _error("GetTokenInformation")
        psid = ctypes.cast(buffer, ctypes.POINTER(ctypes.c_void_p))[0]
        return _sid_string(psid)

    def own_sid() -> str:
        token = wintypes.HANDLE()
        if not _OpenProcessToken(_GetCurrentProcess(), TOKEN_QUERY, ctypes.byref(token)):
            raise _error("OpenProcessToken")
        try:
            return token_user(token)
        finally:
            _CloseHandle(token)

    class _Pipe:
        """One end of a pipe opened for overlapped I/O, used from blocking
        threads. Reads and writes each wait on their own event, so a pending
        read never holds up a write."""

        def __init__(self, handle: int, server: bool) -> None:
            self.handle = handle
            self.server = server
            self._closed = False
            self._lock = threading.Lock()

        def _io(self, fn: Any, buffer: Any, size: int, timeout: int = 0xFFFFFFFF) -> int:
            ov = _OVERLAPPED()
            ov.hEvent = _CreateEventW(None, True, False, None)
            if not ov.hEvent:
                raise _error("CreateEvent")
            try:
                if not fn(self.handle, buffer, size, None, ctypes.byref(ov)):
                    code = ctypes.get_last_error()
                    if code in _GONE:
                        return 0
                    if code not in (ERROR_IO_PENDING, ERROR_MORE_DATA):
                        raise OSError(code, f"pipe I/O failed ({code})")
                if _WaitForSingleObject(ov.hEvent, timeout) == WAIT_TIMEOUT:
                    _CancelIoEx(self.handle, ctypes.byref(ov))
                    done = wintypes.DWORD(0)
                    _GetOverlappedResult(self.handle, ctypes.byref(ov), ctypes.byref(done), True)
                    raise TimeoutError
                done = wintypes.DWORD(0)
                if not _GetOverlappedResult(
                    self.handle, ctypes.byref(ov), ctypes.byref(done), True
                ):
                    code = ctypes.get_last_error()
                    if code == ERROR_MORE_DATA:
                        return int(done.value)
                    if code in _GONE:
                        return 0
                    raise OSError(code, f"pipe I/O failed ({code})")
                return int(done.value)
            finally:
                _CloseHandle(ov.hEvent)

        def read(self, timeout: int = 0xFFFFFFFF) -> bytes:
            buffer = ctypes.create_string_buffer(65536)
            n = self._io(_ReadFile, buffer, 65536, timeout)
            return buffer.raw[:n]

        def write_all(self, data: bytes) -> None:
            view = memoryview(data)
            while view:
                chunk = bytes(view[:65536])
                n = self._io(_WriteFile, chunk, len(chunk))
                if n <= 0:
                    raise ConnectionError("The other end has gone.")
                view = view[n:]

        def close(self) -> None:
            with self._lock:
                if self._closed:
                    return
                self._closed = True
            _CancelIoEx(self.handle, None)
            if self.server:
                _DisconnectNamedPipe(self.handle)
            _CloseHandle(self.handle)

    class _PipeConnection(Connection):
        """The asyncio side of a pipe: one reader thread per connection feeds a
        queue; writes run in a worker thread, one at a time."""

        def __init__(self, pipe: _Pipe, account: str, loop: asyncio.AbstractEventLoop) -> None:
            self.pipe = pipe
            self.account = account
            self.hello = {}
            self._loop = loop
            self._queue: asyncio.Queue[bytes] = asyncio.Queue()
            self._buffer = bytearray()
            self._write_lock = asyncio.Lock()
            self._reader: threading.Thread | None = None

        def start_reading(self, already: bytes = b"") -> None:
            self._buffer += already
            self._reader = threading.Thread(target=self._read_loop, daemon=True)
            self._reader.start()

        def _read_loop(self) -> None:
            while True:
                try:
                    chunk = self.pipe.read()
                except (OSError, TimeoutError):
                    chunk = b""
                with contextlib.suppress(RuntimeError):
                    self._loop.call_soon_threadsafe(self._queue.put_nowait, chunk)
                if not chunk:
                    return

        async def receive(self) -> dict[str, Any] | None:
            while b"\n" not in self._buffer:
                if len(self._buffer) > MAX_FRAME:
                    raise ChannelError("A message on the local channel is larger than 256 KiB.")
                chunk = await self._queue.get()
                if not chunk:
                    if self._buffer:
                        raise ChannelError("The other end stopped in the middle of a message.")
                    return None
                self._buffer += chunk
            line, _, rest = bytes(self._buffer).partition(b"\n")
            self._buffer = bytearray(rest)
            if len(line) + 1 > MAX_FRAME:
                raise ChannelError("A message on the local channel is larger than 256 KiB.")
            return decode(line)

        async def send(self, message: dict[str, Any]) -> None:
            data = encode(message)
            async with self._write_lock:
                await asyncio.to_thread(self.pipe.write_all, data)

        async def close(self) -> None:
            await asyncio.to_thread(self.pipe.close)

    def _identify(pipe: _Pipe) -> tuple[str, bytes]:
        """Read the client's first frame, then learn its account by
        impersonating it at Identification level on this thread. Windows
        lets a server impersonate only once it has read from the pipe."""
        data = b""
        while b"\n" not in data:
            chunk = pipe.read(int(HELLO_SECONDS * 1000))
            if not chunk:
                raise ChannelError("The other end said nothing.")
            data += chunk
            if len(data) > MAX_FRAME:
                raise ChannelError("A message on the local channel is larger than 256 KiB.")
        if not _ImpersonateNamedPipeClient(pipe.handle):
            raise _error("ImpersonateNamedPipeClient")
        try:
            token = wintypes.HANDLE()
            if not _OpenThreadToken(_GetCurrentThread(), TOKEN_QUERY, True, ctypes.byref(token)):
                raise _error("OpenThreadToken")
            try:
                account = token_user(token)
            finally:
                _CloseHandle(token)
        finally:
            if not _RevertToSelf():
                # A thread left running as someone else must not run on.
                os._exit(70)
        return account, data

    class _PipeServer:
        def __init__(self, name: str, owner: str, accept: Accept) -> None:
            self.name = name
            self.owner = owner
            self.accept = accept
            self.loop = asyncio.get_running_loop()
            self._stop = _CreateEventW(None, True, False, None)
            sddl = (
                f"O:{owner}D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;{owner})"
                f"(A;;0x{CLIENT_ACCESS:x};;;AU)"
            )
            self._sd = ctypes.c_void_p()
            if not _ConvertSddl(sddl, 1, ctypes.byref(self._sd), None):
                raise _error("ConvertStringSecurityDescriptorToSecurityDescriptor")
            self._sa = _SECURITY_ATTRIBUTES(
                ctypes.sizeof(_SECURITY_ATTRIBUTES), self._sd.value, False
            )
            self._first = self._instance(first=True)
            self._thread = threading.Thread(target=self._accept_loop, daemon=True)

        def _instance(self, *, first: bool) -> int:
            mode = PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED
            if first:
                mode |= FILE_FLAG_FIRST_PIPE_INSTANCE
            handle = _CreateNamedPipeW(
                self.name,
                mode,
                PIPE_REJECT_REMOTE_CLIENTS,
                PIPE_UNLIMITED_INSTANCES,
                65536,
                65536,
                0,
                ctypes.byref(self._sa),
            )
            if handle == _INVALID or not handle:
                code = ctypes.get_last_error()
                if first and code == ERROR_ACCESS_DENIED:
                    raise ChannelError(
                        f"Another program already holds this site's channel ({self.name}). "
                        "Nothing can be served until it is gone."
                    )
                raise OSError(code, f"CreateNamedPipe failed ({code})")
            return int(handle)

        def start(self) -> None:
            self._thread.start()

        def _accept_loop(self) -> None:
            handle = self._first
            while True:
                ov = _OVERLAPPED()
                ov.hEvent = _CreateEventW(None, True, False, None)
                connected = bool(_ConnectNamedPipe(handle, ctypes.byref(ov)))
                if not connected:
                    code = ctypes.get_last_error()
                    if code == ERROR_PIPE_CONNECTED:
                        connected = True
                    elif code == ERROR_IO_PENDING:
                        events = (wintypes.HANDLE * 2)(ov.hEvent, self._stop)
                        which = _WaitForMultipleObjects(2, events, False, 0xFFFFFFFF)
                        if which != WAIT_OBJECT_0:
                            _CancelIoEx(handle, ctypes.byref(ov))
                            _CloseHandle(ov.hEvent)
                            _CloseHandle(handle)
                            return
                        done = wintypes.DWORD(0)
                        connected = bool(
                            _GetOverlappedResult(handle, ctypes.byref(ov), ctypes.byref(done), True)
                        )
                _CloseHandle(ov.hEvent)
                pipe = _Pipe(handle, server=True)
                if connected:
                    threading.Thread(target=self._welcome, args=(pipe,), daemon=True).start()
                else:
                    pipe.close()
                if _WaitForSingleObject(self._stop, 0) == WAIT_OBJECT_0:
                    return
                try:
                    handle = self._instance(first=False)
                except OSError:
                    return

        def _welcome(self, pipe: _Pipe) -> None:
            try:
                account, first = _identify(pipe)
            except (ChannelError, OSError, TimeoutError):
                pipe.close()
                return
            conn = _PipeConnection(pipe, account, self.loop)
            line, _, rest = first.partition(b"\n")
            try:
                hello = decode(line)
            except ChannelError:
                pipe.close()
                return
            if hello.get("t") != "hello":
                pipe.close()
                return
            conn.hello = hello
            conn.start_reading(rest)
            asyncio.run_coroutine_threadsafe(self.accept(conn), self.loop)

        def close(self) -> None:
            _SetEvent(self._stop)
            self._thread.join(timeout=5)
            _CloseHandle(self._stop)
            if self._sd.value:
                _LocalFree(self._sd)
                self._sd = ctypes.c_void_p()

    def _pipe_owner(handle: int) -> str:
        owner = ctypes.c_void_p()
        sd = ctypes.c_void_p()
        code = _GetSecurityInfo(
            handle,
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION,
            ctypes.byref(owner),
            None,
            None,
            None,
            ctypes.byref(sd),
        )
        if code != 0:
            raise OSError(code, f"GetSecurityInfo failed ({code})")
        try:
            return _sid_string(owner.value)
        finally:
            _LocalFree(sd)

    def _open_client(name: str, host: str) -> _Pipe:
        for _ in range(10):
            handle = _CreateFileW(
                name,
                CLIENT_ACCESS,
                0,
                None,
                OPEN_EXISTING,
                FILE_FLAG_OVERLAPPED | SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION,
                None,
            )
            if handle != _INVALID and handle:
                break
            code = ctypes.get_last_error()
            if code == ERROR_PIPE_BUSY:
                _WaitNamedPipeW(name, 2000)
                continue
            if code == ERROR_FILE_NOT_FOUND:
                raise ChannelError("The site host is not running.")
            raise ChannelError(f"The site host could not be reached ({code}).")
        else:
            raise ChannelError("The site host's channel stayed busy.")
        try:
            owner = _pipe_owner(int(handle))
        except OSError:
            _CloseHandle(handle)
            raise ChannelError("The channel's owner could not be read.") from None
        if owner != host:
            _CloseHandle(handle)
            raise ChannelError(
                f"The channel {name} belongs to {owner}, not the site host's account."
            )
        return _Pipe(int(handle), server=False)


# --- both ---------------------------------------------------------------------------


class Server:
    """The site host's end: every connection that sends a hello is handed to
    `accept` with the account the operating system reported for it."""

    def __init__(self, inner: Any) -> None:
        self._inner = inner

    async def close(self) -> None:
        if sys.platform == "win32":
            await asyncio.to_thread(self._inner.close)
        else:
            self._inner.close()
            with contextlib.suppress(Exception):
                await self._inner.wait_closed()


async def serve(channel: str, owner: str, accept: Accept) -> Server:
    """Start listening on `channel`. `owner` is this process's own account
    (the pipe's owner on Windows; unused elsewhere)."""
    if sys.platform == "win32":
        server = _PipeServer(channel, owner, accept)
        server.start()
        return Server(server)
    else:
        return Server(await _serve_posix(channel, accept))


async def connect(channel: str, host: str, hello: dict[str, Any]) -> Connection:
    """A worker's end: connect, check the far end is `host` (a SID, or a uid
    in decimal), and say hello."""
    if sys.platform == "win32":
        pipe = await asyncio.to_thread(_open_client, channel, host)
        conn: Connection = _PipeConnection(pipe, host, asyncio.get_running_loop())
        conn.start_reading()  # type: ignore[attr-defined]
    else:
        conn = await _connect_posix(channel, host)
    await conn.send({**hello, "t": "hello"})
    return conn


def own_account() -> str:
    """This process's own account: its SID on Windows, its uid elsewhere."""
    if sys.platform == "win32":
        return own_sid()
    return str(os.getuid())
