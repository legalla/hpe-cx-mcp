"""Structured audit logging for the CX MCP server.

Emits one JSON object per line (JSON Lines) describing every audited tool call::

    {"ts": "...", "actor": "vscode-dev", "src_ip": "192.0.2.10",
     "tool": "configure_bgp", "category": "write", "device": "Access-01",
     "arguments": {...}, "outcome": "completed", "duration_ms": 412}

The *actor* field is the name of the Bearer token used for the request, which
is how traceability ("who did what") is achieved. Secrets in the arguments are
redacted before being written.
"""

from __future__ import annotations

import json
import logging
import os
import sys
from datetime import datetime, timezone
from logging.handlers import RotatingFileHandler

# Tool-name heuristics used to tag each call as a read or a (potentially)
# mutating write. The exact tool name is always recorded too, so the tag is
# only a convenience for filtering.
_WRITE_PREFIXES = ("configure_", "create_", "delete_", "add_", "set_", "apply_", "render_", "load_")
_WRITE_NAMES = {
    "manage_config",
    "run_cli_command",
    "run_ssh_command",
    "run_ssh_commands",
    "run_on_site",
    "refresh_inventory",
}

# Argument keys whose value must never be written to the audit log.
_SECRET_HINTS = ("password", "passwd", "secret", "token", "bearer", "credential", "private_key", "apikey", "api_key")

_REDACTED = "***redacted***"
_MAX_STR = 2000  # cap individual string values to keep audit lines bounded


def classify_tool(tool: str | None) -> str:
    """Return ``"write"`` or ``"read"`` for a tool name (best effort)."""
    if not tool:
        return "read"
    if tool in _WRITE_NAMES:
        return "write"
    if any(tool.startswith(p) for p in _WRITE_PREFIXES):
        return "write"
    return "read"


def _is_secret_key(key: str) -> bool:
    low = key.lower()
    return any(hint in low for hint in _SECRET_HINTS)


def redact(value, _key: str = ""):
    """Recursively redact secret-looking values and cap long strings."""
    if isinstance(value, dict):
        return {k: (_REDACTED if _is_secret_key(str(k)) else redact(v, str(k))) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [redact(v, _key) for v in value]
    if isinstance(value, str) and len(value) > _MAX_STR:
        return value[:_MAX_STR] + "…[truncated]"
    return value


class AuditLogger:
    """Writes JSON-line audit records to a file (with rotation) and/or stdout."""

    def __init__(
        self,
        enabled: bool = False,
        path: str = "/app/logs/audit.jsonl",
        level: str = "all",
        to_stdout: bool = False,
        max_bytes: int = 10 * 1024 * 1024,
        backups: int = 5,
    ):
        self.enabled = bool(enabled)
        self.path = path
        self.level = (level or "all").strip().lower()
        self.to_stdout = bool(to_stdout)
        self._logger: logging.Logger | None = None
        self._fallback = False

        if not self.enabled:
            return

        logger = logging.getLogger("cx-mcp.audit")
        logger.setLevel(logging.INFO)
        logger.propagate = False
        # Avoid duplicate handlers if re-initialized.
        for h in list(logger.handlers):
            logger.removeHandler(h)

        formatter = logging.Formatter("%(message)s")
        try:
            parent = os.path.dirname(self.path) or "."
            os.makedirs(parent, exist_ok=True)
            handler = RotatingFileHandler(
                self.path, maxBytes=max_bytes, backupCount=backups, encoding="utf-8"
            )
            handler.setFormatter(formatter)
            logger.addHandler(handler)
        except OSError as exc:
            # If the file is not writable (permissions / read-only mount), fall
            # back to stdout so audit is never silently lost.
            self._fallback = True
            self.to_stdout = True
            logging.getLogger(__name__).warning(
                "⚠️  Audit file '%s' not writable (%s) — falling back to stdout.",
                self.path, exc,
            )

        if self.to_stdout:
            sh = logging.StreamHandler(sys.stdout)
            sh.setFormatter(formatter)
            logger.addHandler(sh)

        self._logger = logger

    def _should_record(self, category: str) -> bool:
        if not self.enabled:
            return False
        if self.level == "writes":
            return category == "write"
        return True  # "all" (default)

    def record(self, *, tool: str | None, actor: str = "anonymous", src_ip: str = "unknown",
               session: str | None = None, arguments: dict | None = None,
               outcome: str = "completed", status_code: int | None = None,
               duration_ms: float | None = None, error: str | None = None) -> None:
        """Write a single audit record (no-op when disabled or filtered out)."""
        if self._logger is None:
            return
        category = classify_tool(tool)
        if not self._should_record(category):
            return

        args = arguments if isinstance(arguments, dict) else {}
        device = args.get("device") or args.get("site") or args.get("router_name")
        event = {
            "ts": datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z"),
            "actor": actor or "anonymous",
            "src_ip": src_ip or "unknown",
            "session": (session[:8] + "…") if session else None,
            "tool": tool,
            "category": category,
            "device": device,
            "arguments": redact(args),
            "outcome": outcome,
            "status_code": status_code,
            "duration_ms": round(duration_ms, 1) if duration_ms is not None else None,
        }
        if error:
            event["error"] = error[:_MAX_STR]
        try:
            self._logger.info(json.dumps(event, ensure_ascii=False, default=str))
        except Exception:  # pragma: no cover - audit must never crash the server
            logging.getLogger(__name__).exception("Failed to write audit record")
