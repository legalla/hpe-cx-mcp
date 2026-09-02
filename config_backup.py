"""SFTP and TFTP export of AOS-CX configuration snapshots."""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
import os
from pathlib import PurePosixPath
import string
from io import BytesIO

import asyncssh
import tftpy


DEFAULT_FILENAME_FORMAT = "{hostname}_{timestamp}_config.cfg"
_ALLOWED_FIELDS = {"hostname", "timestamp"}


class ConfigBackupError(Exception):
    """Raised when an SFTP configuration export cannot be performed."""


def _required_env(name: str) -> str:
    value = os.getenv(name, "").strip()
    if not value:
        raise ConfigBackupError(f"Missing required environment variable: {name}.")
    return value


def render_filename(filename_format: str | None, hostname: str, timestamp: str) -> str:
    """Render a filename while allowing only hostname and timestamp fields."""
    template = (filename_format or DEFAULT_FILENAME_FORMAT).strip()
    if not template:
        template = DEFAULT_FILENAME_FORMAT
    try:
        fields = {
            field_name for _, field_name, _, _ in string.Formatter().parse(template)
            if field_name is not None
        }
    except ValueError as exc:
        raise ConfigBackupError(f"Invalid filename_format: {exc}") from exc
    if not fields.issubset(_ALLOWED_FIELDS):
        unsupported = ", ".join(sorted(fields - _ALLOWED_FIELDS))
        raise ConfigBackupError(
            f"filename_format only supports {{hostname}} and {{timestamp}}; unsupported: {unsupported}."
        )
    try:
        filename = template.format(hostname=hostname, timestamp=timestamp)
    except (KeyError, ValueError) as exc:
        raise ConfigBackupError(f"Invalid filename_format: {exc}") from exc
    if not filename or filename in (".", "..") or "/" in filename or "\\" in filename:
        raise ConfigBackupError("filename_format must render a filename, not a path.")
    return filename


async def export_config(
    *,
    protocol: str,
    server: str | None,
    remote_directory: str | None,
    filename_format: str | None,
    hostname: str,
    content: str,
) -> dict:
    """Export one config without returning its content."""
    protocol = (protocol or "sftp").strip().lower()
    if protocol not in ("sftp", "tftp"):
        raise ConfigBackupError("protocol must be 'sftp' or 'tftp'.")
    prefix = f"CX_BACKUP_{protocol.upper()}"
    configured_server = os.getenv(f"{prefix}_HOST", "").strip()
    target_server = (server or configured_server).strip()
    if not target_server:
        raise ConfigBackupError(f"Provide 'server' or set {prefix}_HOST.")
    if configured_server and target_server != configured_server:
        raise ConfigBackupError(
            f"The requested server is not the configured {protocol.upper()} target ({prefix}_HOST)."
        )

    allowed_hosts = {
        host.strip() for host in os.getenv(f"{prefix}_ALLOWED_HOSTS", "").split(",")
        if host.strip()
    }
    if allowed_hosts and target_server not in allowed_hosts:
        raise ConfigBackupError(f"The requested server is not in {prefix}_ALLOWED_HOSTS.")

    port = int(os.getenv(f"{prefix}_PORT", "22" if protocol == "sftp" else "69"))
    if not 1 <= port <= 65535:
        raise ConfigBackupError(f"{prefix}_PORT must be between 1 and 65535.")

    directory = remote_directory or os.getenv(f"{prefix}_DIRECTORY", "/")
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    filename = render_filename(filename_format, hostname, timestamp)
    timeout = float(os.getenv(f"{prefix}_TIMEOUT", "30"))

    if protocol == "sftp":
        if not directory.startswith("/"):
            raise ConfigBackupError("remote_directory must be an absolute POSIX path for SFTP.")
        remote_path = str(PurePosixPath(directory) / filename)
        username = _required_env("CX_BACKUP_SFTP_USERNAME")
        password = _required_env("CX_BACKUP_SFTP_PASSWORD")
        try:
            async with asyncio.timeout(timeout):
                async with asyncssh.connect(
                    target_server,
                    port=port,
                    username=username,
                    password=password,
                    known_hosts=None,
                    client_keys=None,
                ) as connection:
                    async with connection.start_sftp_client() as sftp:
                        await sftp.makedirs(str(PurePosixPath(directory)), exist_ok=True)
                        async with sftp.open(remote_path, "wb") as remote_file:
                            await remote_file.write(content.encode("utf-8"))
        except (asyncssh.Error, OSError, asyncio.TimeoutError, ValueError) as exc:
            raise ConfigBackupError(f"SFTP export to {target_server} failed: {exc}") from exc
    else:
        normalized_directory = directory.strip("/")
        if ".." in PurePosixPath(normalized_directory).parts:
            raise ConfigBackupError("remote_directory must not contain '..' for TFTP.")
        remote_path = str(PurePosixPath(normalized_directory) / filename)
        try:
            client = tftpy.TftpClient(target_server, port)
            await asyncio.wait_for(
                asyncio.to_thread(client.upload, remote_path, BytesIO(content.encode("utf-8"))),
                timeout=timeout,
            )
        except (tftpy.TftpException, OSError, asyncio.TimeoutError, ValueError) as exc:
            raise ConfigBackupError(f"TFTP export to {target_server} failed: {exc}") from exc

    return {
        "status": "exported",
        "protocol": protocol,
        "server": target_server,
        "remote_path": remote_path,
        "bytes": len(content.encode("utf-8")),
        "timestamp": timestamp,
    }