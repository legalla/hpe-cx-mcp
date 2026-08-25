#!/usr/bin/env python3
"""Manually trigger a hot reload of the running CX MCP server.

Sends ``SIGHUP`` to the server process so it reloads the **tokens** file and the
**inventory** file in place, WITHOUT a container rebuild or restart. Run it
inside the container:

    docker compose exec cx-mcp python cx_reload.py

The reload is performed asynchronously by the server; this command only delivers
the signal. The actual outcome (number of tokens / devices reloaded, or any
error) is written to the server logs:

    docker compose logs --tail=20 cx-mcp

Reloading the tokens also lifts LOCKED mode once a first token exists, so after
creating the first token you can run this instead of restarting the container.
"""

import os
import signal
import sys


def _find_server_pid() -> int:
    """Locate the running server process.

    It is the container entrypoint (PID 1), but we scan ``/proc`` for a python
    process running ``server.py`` to stay robust if the process tree changes.
    Falls back to PID 1.
    """
    try:
        entries = os.listdir("/proc")
    except OSError:
        return 1
    me = os.getpid()
    for entry in entries:
        if not entry.isdigit():
            continue
        pid = int(entry)
        if pid == me:
            continue
        try:
            with open(f"/proc/{pid}/cmdline", "rb") as fh:
                cmd = fh.read().replace(b"\x00", b" ").decode(errors="replace")
        except OSError:
            continue
        if "server.py" in cmd and "python" in cmd.lower():
            return pid
    return 1


def main() -> int:
    pid = _find_server_pid()
    try:
        os.kill(pid, signal.SIGHUP)
    except ProcessLookupError:
        print(f"Error: CX MCP server process (PID {pid}) not found.", file=sys.stderr)
        return 1
    except PermissionError:
        print(f"Error: not allowed to signal PID {pid}.", file=sys.stderr)
        return 1

    print(f"\U0001f504 Reload signal (SIGHUP) sent to CX MCP server (PID {pid}).")
    print("   The server is reloading the tokens and inventory files in place.")
    print("   Check the result in the logs: docker compose logs --tail=20 cx-mcp")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
