"""
Asynchronous SSH client for ArubaOS-CX.

Allows running CLI commands (typically `show ...`) on an ArubaOS-CX device and
retrieving their output, for cases the REST API does not cover.

The implementation relies on `asyncssh` (fully async) and opens an interactive
shell session: paging is disabled (`no page`), then each command is sent and its
output read until the prompt returns.
"""

import asyncio
import logging
import re

import asyncssh

logger = logging.getLogger(__name__)

# ANSI escape sequences (the vt100 terminal may emit them).
_ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]")

# ArubaOS-CX prompt at the end of the buffer: 'switch#', 'switch>', 'switch(config)#'…
_PROMPT_RE = re.compile(r"[\r\n][A-Za-z0-9._\-]+(\([A-Za-z0-9._\-]+\))?[#>]\s*$")
# A line that is ONLY the prompt (used to clean up the end of the output).
_PROMPT_ONLY_RE = re.compile(r"^[A-Za-z0-9._\-]+(\([A-Za-z0-9._\-]+\))?[#>]\s*$")
# Residual paging marker (safety net if `no page` fails).
_MORE_RE = re.compile(r"--+\s*more\s*--+", re.IGNORECASE)


class ArubaSSHError(Exception):
    """SSH connection or execution error on an ArubaOS-CX device."""


def _strip_ansi(text: str) -> str:
    return _ANSI_RE.sub("", text)


class ArubaOSCXSSHClient:
    """Asynchronous SSH client for running CLI commands on ArubaOS-CX."""

    def __init__(
        self,
        host: str,
        username: str,
        password: str,
        port: int = 22,
        timeout: int = 30,
    ):
        self.host = host
        self.username = username
        self.password = password
        self.port = port
        self.timeout = timeout
        self._conn: asyncssh.SSHClientConnection | None = None
        self._process: asyncssh.SSHClientProcess | None = None
        self._closed = True
        self._lock: asyncio.Lock | None = None

    @property
    def is_connected(self) -> bool:
        return self._conn is not None and self._process is not None and not self._closed

    async def __aenter__(self):
        await self.connect()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        # The pool handles closing explicitly; we do not close here.
        return None

    async def connect(self) -> None:
        """Open the SSH session (idempotent) and disable paging."""
        if self.is_connected:
            return
        if self._lock is None:
            self._lock = asyncio.Lock()
        async with self._lock:
            if self.is_connected:
                return
            try:
                self._conn = await asyncio.wait_for(
                    asyncssh.connect(
                        self.host,
                        port=self.port,
                        username=self.username,
                        password=self.password,
                        known_hosts=None,      # lab: no host-key verification
                        client_keys=None,      # password authentication only
                    ),
                    timeout=self.timeout,
                )
                self._process = await self._conn.create_process(
                    term_type="vt100",
                    term_size=(512, 10000),
                )
                self._closed = False
                # Consume the login banner + the first prompt.
                await self._read_until_prompt()
                # Disable paging to retrieve complete output.
                await self.run_command("no page")
            except (asyncssh.Error, asyncio.TimeoutError, OSError) as exc:
                await self.close()
                raise ArubaSSHError(
                    f"SSH connection to {self.host}:{self.port} failed: {exc}"
                ) from exc

    async def _read_until_prompt(self, timeout: float | None = None) -> str:
        """Read output until the prompt is detected (or the timeout expires)."""
        assert self._process is not None
        loop = asyncio.get_event_loop()
        timeout = timeout if timeout is not None else self.timeout
        deadline = loop.time() + timeout
        buf = ""
        while True:
            remaining = deadline - loop.time()
            if remaining <= 0:
                raise ArubaSSHError(
                    f"Timed out waiting for the prompt on {self.host}."
                )
            try:
                chunk = await asyncio.wait_for(
                    self._process.stdout.read(4096), timeout=remaining
                )
            except asyncio.TimeoutError:
                raise ArubaSSHError(
                    f"Timed out waiting for the prompt on {self.host}."
                )
            if chunk == "":  # EOF: the session was closed on the device side
                self._closed = True
                break
            buf += chunk
            clean = _strip_ansi(buf)
            # Safety net if paging stayed active.
            if _MORE_RE.search(clean.rstrip()[-20:]):
                self._process.stdin.write(" ")
                continue
            if _PROMPT_RE.search(clean):
                break
        return _strip_ansi(buf)

    def _clean_output(self, command: str, raw: str) -> str:
        """Strip the command echo and the trailing prompt from the raw output."""
        text = raw.replace("\r\n", "\n").replace("\r", "\n")
        lines = text.split("\n")
        # Remove the command echo (first non-empty line).
        idx = 0
        while idx < len(lines) and lines[idx].strip() == "":
            idx += 1
        if idx < len(lines) and lines[idx].strip() == command.strip():
            idx += 1
        lines = lines[idx:]
        # Remove the trailing prompt and empty lines at the end of the output.
        while lines and (lines[-1].strip() == "" or _PROMPT_ONLY_RE.match(lines[-1].strip())):
            lines.pop()
        return "\n".join(lines)

    async def run_command(self, command: str) -> str:
        """Send a CLI command and return its cleaned output."""
        if self._process is None or self._closed:
            raise ArubaSSHError(
                f"SSH session not connected to {self.host}. Call connect()."
            )
        try:
            self._process.stdin.write(command + "\n")
            raw = await self._read_until_prompt()
        except ArubaSSHError:
            # A prompt timeout leaves the channel desynchronized (the late output
            # would be read by the next command). Invalidate the session so it is
            # not reused: the pool will reconnect a fresh one on the next call.
            self._closed = True
            raise
        except (asyncssh.Error, OSError) as exc:
            self._closed = True
            raise ArubaSSHError(
                f"Failed to run '{command}' on {self.host}: {exc}"
            ) from exc
        return self._clean_output(command, raw)

    async def run_commands(self, commands: list[str]) -> list[dict]:
        """Run a list of commands within the same SSH session.

        Returns a list of dicts {command, output, ok, error}. If a command
        breaks the session, the following ones are marked as errored.
        """
        results: list[dict] = []
        for command in commands:
            if self._closed:
                results.append({
                    "command": command,
                    "ok": False,
                    "output": "",
                    "error": "SSH session closed before execution.",
                })
                continue
            try:
                output = await self.run_command(command)
                results.append({"command": command, "ok": True, "output": output})
            except ArubaSSHError as exc:
                results.append({
                    "command": command,
                    "ok": False,
                    "output": "",
                    "error": str(exc),
                })
        return results

    async def close(self) -> bool:
        """Close the SSH session (best-effort, idempotent)."""
        was_open = self.is_connected
        self._closed = True
        conn = self._conn
        self._conn = None
        self._process = None
        if conn is not None:
            conn.close()
            try:
                await conn.wait_closed()
            except Exception:  # noqa: BLE001
                pass
        return was_open
