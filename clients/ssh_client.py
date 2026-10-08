"""
Asynchronous SSH client for ArubaOS-CX.

Allows running CLI commands (typically `show ...`) on an ArubaOS-CX device and
retrieving their output, for cases the REST API does not cover.

The implementation relies on `asyncssh` (fully async) and opens an interactive
shell session: paging is disabled (`no page`), then each command is sent and its
output read until the prompt returns.
"""

import asyncio
import json
import logging
import os
import re

import asyncssh

logger = logging.getLogger(__name__)

# ANSI escape sequences (the vt100 terminal may emit them).
_ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]")

# Trust-on-first-use SSH host-key store: {"host:port": "SHA256:..."}. Lives in
# the same read-write secrets volume as the Bearer tokens (see cx_auth.py).
_HOST_KEYS_FILE = os.environ.get("CX_SSH_KNOWN_HOSTS_FILE", "/app/secrets/ssh_known_hosts.json")


def _load_host_keys(path: str) -> dict:
    if not os.path.exists(path):
        return {}
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except (json.JSONDecodeError, OSError) as exc:
        logger.warning("⚠️  SSH known-hosts store '%s' could not be parsed (%s).", path, exc)
        return {}
    return data if isinstance(data, dict) else {}


def _save_host_keys(hosts: dict, path: str) -> None:
    parent = os.path.dirname(path) or "."
    os.makedirs(parent, exist_ok=True)
    tmp = f"{path}.tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(hosts, fh, indent=2, sort_keys=True)
        fh.write("\n")
    os.replace(tmp, path)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


class _TofuSSHClient(asyncssh.SSHClient):
    """Trust-on-first-use SSH host-key validation.

    The first connection to a given ``host:port`` records the server's key
    fingerprint; every later connection is compared against the stored
    value, so a key that suddenly changes (device replaced/reimaged, or a
    possible MITM) is rejected instead of silently accepted.
    """

    def __init__(self, host: str, port: int, store_path: str = _HOST_KEYS_FILE):
        self._lookup_host = f"{host}:{port}"
        self._store_path = store_path

    def validate_host_public_key(self, host, addr, port, key) -> bool:
        fingerprint = key.get_fingerprint("sha256")
        hosts = _load_host_keys(self._store_path)
        known = hosts.get(self._lookup_host)
        if known is None:
            hosts[self._lookup_host] = fingerprint
            _save_host_keys(hosts, self._store_path)
            logger.info("🔑 Trusting new SSH host key for %s (%s) — recorded for future checks.",
                        self._lookup_host, fingerprint)
            return True
        if known != fingerprint:
            logger.warning(
                "🚫 SSH host key MISMATCH for %s: expected %s, got %s. Refusing to connect "
                "(possible MITM, or the device's key legitimately changed — if so, remove "
                "the '%s' entry from '%s' to re-trust it).",
                self._lookup_host, known, fingerprint, self._lookup_host, self._store_path,
            )
            return False
        return True

# ArubaOS-CX prompt at the end of the buffer: 'switch#', 'switch>', 'switch(config)#',
# 'switch(config-if-1/1/1)#', 'switch(config-if-<1/1/1-1/1/24>)#', 'switch(config-vlan-10)#'…
# The parenthesised mode may contain '/', '<', '>', '-', ',' so accept anything but ')'.
_PROMPT_RE = re.compile(r"[\r\n][A-Za-z0-9._\-]+(\([^()\r\n]*\))?[#>]\s*$")
# A line that is ONLY the prompt (used to clean up the end of the output).
_PROMPT_ONLY_RE = re.compile(r"^[A-Za-z0-9._\-]+(\([^()\r\n]*\))?[#>]\s*$")
# Short read used to re-synchronise the channel after a prompt timeout.
_RESYNC_TIMEOUT = 3.0
# Residual paging marker (safety net if `no page` fails).
_MORE_RE = re.compile(r"--+\s*more\s*--+", re.IGNORECASE)
# Interactive confirmation at the end of the buffer, e.g. 'Do you want to
# continue (y/n)?' (shutdown of vxlan1, inter-vxlan-bridging-mode, ...).
_CONFIRM_RE = re.compile(r"(\(y/n\)|\[y/n\]|\(yes/no\)|\[yes/no\])\s*[?:]?\s*$", re.IGNORECASE)
# CLI error lines: printed in place of the output, so only the first lines are
# checked (a 'show' table may legitimately contain these words further down).
_CLI_ERROR_RE = re.compile(
    r"^\s*%?\s*(Invalid input|Command incomplete|Incomplete command|Ambiguous command|"
    r"Unknown command|Error\b|ERROR\b|.*\bis not configured\b|.*\balready configured with\b|"
    r".*\bdoes not exist\b|Cannot\b|Unable to\b)",
    re.IGNORECASE)
_CLI_ERROR_LINES = 3


def cli_error(output: str) -> str | None:
    """The CLI error message in `output`, or None when it looks successful."""
    lines = [l.strip() for l in (output or "").splitlines() if l.strip()]
    for line in lines[:_CLI_ERROR_LINES]:
        if _CLI_ERROR_RE.match(line):
            return line
    return None


class ArubaSSHError(Exception):
    """SSH connection or execution error on an ArubaOS-CX device."""

    def __init__(self, message: str, partial: str = ""):
        super().__init__(message)
        self.partial = partial


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
        # confirmation prompts met by the last run_command: [{prompt, answer}]
        self.last_confirmations: list[dict] = []

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
                        # known_hosts=b'' (not None) so asyncssh still calls our
                        # client's validate_host_public_key() below instead of
                        # skipping host-key checking altogether.
                        known_hosts=b"",
                        client_keys=None,      # password authentication only
                        client_factory=lambda: _TofuSSHClient(self.host, self.port),
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

    async def _read_until_prompt(self, timeout: float | None = None,
                                 confirm: str | None = None) -> str:
        """Read output until the prompt is detected (or the timeout expires).
        A '(y/n)' confirmation is answered with `confirm` ('y' / 'n') so the
        session never hangs on it; None leaves it unanswered (old behaviour)."""
        assert self._process is not None
        loop = asyncio.get_event_loop()
        timeout = timeout if timeout is not None else self.timeout
        deadline = loop.time() + timeout
        buf = ""
        answered_at = 0
        while True:
            remaining = deadline - loop.time()
            if remaining <= 0:
                raise ArubaSSHError(
                    f"Timed out waiting for the prompt on {self.host}.",
                    partial=_strip_ansi(buf),
                )
            try:
                chunk = await asyncio.wait_for(
                    self._process.stdout.read(4096), timeout=remaining
                )
            except asyncio.TimeoutError:
                raise ArubaSSHError(
                    f"Timed out waiting for the prompt on {self.host}.",
                    partial=_strip_ansi(buf),
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
            if confirm and _CONFIRM_RE.search(clean[answered_at:]):
                tail = clean[answered_at:].strip().splitlines()
                self.last_confirmations.append(
                    {"prompt": tail[-1] if tail else "", "answer": confirm})
                self._process.stdin.write(confirm + "\n")
                answered_at = len(clean)
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

    async def run_command(self, command: str, *, auto_confirm: bool = False) -> str:
        """Send a CLI command and return its cleaned output. An interactive
        '(y/n)' prompt is answered 'y' with `auto_confirm`, otherwise 'n' (the
        command is then NOT applied — see `last_confirmations`)."""
        if self._process is None or self._closed:
            raise ArubaSSHError(
                f"SSH session not connected to {self.host}. Call connect()."
            )
        self.last_confirmations = []
        try:
            self._process.stdin.write(command + "\n")
            raw = await self._read_until_prompt(confirm="y" if auto_confirm else "n")
        except ArubaSSHError as exc:
            # A prompt timeout may leave the channel desynchronized (late output
            # would be read by the next command). Try to resync with a bare
            # newline first; only invalidate the session if that fails too.
            if not self._closed and await self._resync():
                raise ArubaSSHError(
                    f"Timed out waiting for the prompt on {self.host} after '{command}' "
                    f"(session resynchronised, kept open). Partial output: "
                    f"{exc.partial.strip()[-500:]!r}",
                    partial=exc.partial,
                ) from exc
            self._closed = True
            raise
        except (asyncssh.Error, OSError) as exc:
            self._closed = True
            raise ArubaSSHError(
                f"Failed to run '{command}' on {self.host}: {exc}"
            ) from exc
        return self._clean_output(command, raw)

    async def _resync(self) -> bool:
        """Send a bare newline and check a prompt comes back quickly."""
        try:
            self._process.stdin.write("\n")
            await self._read_until_prompt(timeout=_RESYNC_TIMEOUT)
            return not self._closed
        except (ArubaSSHError, asyncssh.Error, OSError):
            return False

    async def run_commands(self, commands: list[str], *, auto_confirm: bool = False,
                           stop_on_error: bool = False) -> list[dict]:
        """Run a list of commands within the same SSH session.

        Returns a list of dicts {command, output, ok, error, executed}. A CLI
        error message in the output (Invalid input, Command incomplete, ...)
        or a declined confirmation makes the command `ok: false`. If the
        session breaks (or `stop_on_error` and a command fails), the following
        commands are NOT sent and are marked `executed: false`.
        """
        results: list[dict] = []
        abort_reason = None
        for command in commands:
            if abort_reason or self._closed:
                results.append({
                    "command": command,
                    "ok": False,
                    "executed": False,
                    "output": "",
                    "error": f"not executed: {abort_reason or 'SSH session closed'}",
                })
                continue
            try:
                output = await self.run_command(command, auto_confirm=auto_confirm)
            except ArubaSSHError as exc:
                results.append({
                    "command": command,
                    "ok": False,
                    "executed": True,
                    "output": exc.partial or "",
                    "error": str(exc),
                })
                if self._closed or stop_on_error:
                    abort_reason = f"previous command '{command}' failed"
                continue
            entry = {"command": command, "ok": True, "executed": True, "output": output}
            if self.last_confirmations:
                entry["confirmations"] = list(self.last_confirmations)
            declined = [c for c in self.last_confirmations if c["answer"] != "y"]
            err = cli_error(output)
            if declined:
                entry.update(ok=False, error=(
                    f"interactive confirmation declined ('{declined[0]['prompt']}') — "
                    "command NOT applied; re-run with auto_confirm=true"))
            elif err:
                entry.update(ok=False, error=f"CLI error: {err}")
            results.append(entry)
            if not entry["ok"] and stop_on_error:
                abort_reason = f"stop_on_error after '{command}'"
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
