"""Which OS accounts a worker may run as (§2.4, §3.2).

A worker runs one linked person's tools as that person. It refuses to serve
unless its own account is the one it was started for, and it never serves
as an account that is not a person's: LocalSystem, a service or virtual
account, root, a Linux system uid, or the site host's own account. On
Windows it also refuses an elevated token: tools never run elevated.
"""

from __future__ import annotations

import os
import sys

#: Well-known Windows accounts that are never a person: LocalSystem, Local
#: Service, Network Service.
_SYSTEM_SIDS = frozenset({"S-1-5-18", "S-1-5-19", "S-1-5-20"})
#: Prefixes of service, window-manager and font-driver virtual accounts, and
#: IIS application pools: accounts Windows makes for programs, not people.
_PROGRAM_PREFIXES = ("S-1-5-80-", "S-1-5-82-", "S-1-5-90-", "S-1-5-96-")
#: The lowest uid a Linux distribution gives a person (`UID_MIN`), and
#: macOS's.
LINUX_UID_MIN = 1000
MACOS_UID_MIN = 500


def not_a_person(account: str) -> str | None:
    """Why `account` is never a person's, or None."""
    if account.startswith("S-"):
        if account in _SYSTEM_SIDS:
            return "a system account"
        if account.startswith(_PROGRAM_PREFIXES):
            return "a service or virtual account"
        if not account.startswith("S-1-5-21-") and not account.startswith("S-1-12-1-"):
            # Local and domain accounts are S-1-5-21-…; Entra ID accounts
            # S-1-12-1-…. Anything else is a well-known or program account.
            return "not a person's account"
        return None
    try:
        uid = int(account)
    except ValueError:
        return "not an account this system knows"
    if uid == 0:
        return "root"
    floor = MACOS_UID_MIN if sys.platform == "darwin" else LINUX_UID_MIN
    if uid < floor:
        return "a system account"
    if uid == 65534:
        return "nobody"
    return None


def elevated() -> bool:
    """Whether this process holds administrator power right now: an elevated
    token, or the Administrators group enabled (UAC off). Never on POSIX,
    where root is refused by account instead."""
    if sys.platform != "win32":
        return False
    import ctypes
    from ctypes import wintypes

    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    adv = ctypes.WinDLL("advapi32", use_last_error=True)
    k32.GetCurrentProcess.restype = wintypes.HANDLE
    adv.OpenProcessToken.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.HANDLE),
    ]
    adv.GetTokenInformation.argtypes = [
        wintypes.HANDLE,
        ctypes.c_int,
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
    ]
    adv.CheckTokenMembership.argtypes = [
        wintypes.HANDLE,
        ctypes.c_void_p,
        ctypes.POINTER(wintypes.BOOL),
    ]
    adv.ConvertStringSidToSidW.argtypes = [wintypes.LPCWSTR, ctypes.POINTER(ctypes.c_void_p)]
    k32.LocalFree.argtypes = [ctypes.c_void_p]
    token = wintypes.HANDLE()
    if not adv.OpenProcessToken(k32.GetCurrentProcess(), 0x8, ctypes.byref(token)):
        return True  # Cannot tell: refuse rather than guess.
    try:
        value = wintypes.DWORD(0)
        size = wintypes.DWORD(0)
        if not adv.GetTokenInformation(token, 20, ctypes.byref(value), 4, ctypes.byref(size)):
            return True
        if value.value:
            return True
    finally:
        k32.CloseHandle(token)
    sid = ctypes.c_void_p()
    if not adv.ConvertStringSidToSidW("S-1-5-32-544", ctypes.byref(sid)):
        return True
    try:
        member = wintypes.BOOL(False)
        if not adv.CheckTokenMembership(None, sid, ctypes.byref(member)):
            return True
        return bool(member.value)
    finally:
        k32.LocalFree(sid)


def own() -> str:
    """This process's account: its SID on Windows, its uid elsewhere."""
    if sys.platform == "win32":
        from .local_channel import own_sid

        return own_sid()
    return str(os.geteuid())


def refuse_to_serve(expected: str, host: str | None) -> str | None:
    """Why a worker started for `expected` must not serve, or None."""
    mine = own()
    if mine != expected:
        return f"This worker runs as {mine}, not the account it was started for ({expected})."
    if host is not None and mine == host:
        return "This worker runs as the site host's own account, which is never a person's."
    if why := not_a_person(mine):
        return f"This worker runs as {why}, which is never a person's."
    if elevated():
        return "This worker runs elevated. Tools never run with administrator power."
    return None
