"""POSIX stdio process-group owner, launched only by the MCP transport.

SDK 2.3 reaps a group only if its leader misses the grace period. A server
that exits normally can leave ordinary children behind. Keep a leader alive
until its pipes close, then reap the entire group even after a graceful exit.
Protocol parsing and negotiation remain in the SDK. Standard library only.
"""

from __future__ import annotations

import contextlib
import os
import signal
import subprocess
import sys
import threading


def main() -> None:
    # Never signal a caller's group if someone invokes this module directly.
    if sys.platform == "win32":
        raise SystemExit("The stdio guard is for POSIX processes only.")
    if os.getpgrp() != os.getpid():
        raise SystemExit("The stdio guard requires its own POSIX process group.")
    child = subprocess.Popen(sys.argv[1:], stdin=subprocess.PIPE, stdout=subprocess.PIPE, bufsize=0)
    assert child.stdin is not None and child.stdout is not None
    stopped = threading.Event()

    def pump(source: int, destination: int, *, close_input: bool = False) -> None:
        try:
            while chunk := os.read(source, 65_536):
                pending = memoryview(chunk)
                while pending:
                    pending = pending[os.write(destination, pending) :]
        except OSError:
            pass  # Closed pipe: finish the process scope below.
        finally:
            if close_input:
                with contextlib.suppress(OSError):
                    assert child.stdin is not None
                    child.stdin.close()
            stopped.set()

    incoming = threading.Thread(
        target=pump,
        args=(sys.stdin.fileno(), child.stdin.fileno()),
        kwargs={"close_input": True},
        daemon=True,
    )
    outgoing = threading.Thread(
        target=pump, args=(child.stdout.fileno(), sys.stdout.fileno()), daemon=True
    )
    try:
        incoming.start()
        outgoing.start()
        while child.poll() is None and not stopped.wait(0.05):
            pass
        with contextlib.suppress(subprocess.TimeoutExpired):
            child.wait(timeout=1)
        # Flush a last response before closing, bounded even if a child has
        # inherited stdout. The outer SDK also bounds guard shutdown.
        outgoing.join(timeout=1)
    finally:
        # Includes this guard, ordinary descendants and an already-exited
        # server's children. Programs that deliberately daemonize are unsupported.
        os.killpg(os.getpid(), signal.SIGKILL)


if __name__ == "__main__":
    main()
