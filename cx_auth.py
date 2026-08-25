"""Named Bearer-token authentication for the CX MCP server.

Tokens are stored in a JSON file with the following shape::

    {
      "vscode-dev": {
        "token": "cx_xxxxxxxxxxxxxxxxxxxxxxxxxxx",
        "description": "VSCode development client",
        "created": "2026-06-20T10:30:00Z"
      }
    }

The *name* (the JSON key) is the identity attached to every audited action,
so you always know "who did what". This module is intentionally limited to the
Python standard library so the companion CLI (``cx_token_manager.py``) can run
on the host without installing the MCP dependencies.
"""

from __future__ import annotations

import json
import logging
import os
import secrets
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

# Default location of the tokens file inside the container. It lives in a
# dedicated, read-write secrets volume so the file can be generated and read
# from inside the container by the (non-root) server process itself.
DEFAULT_TOKENS_FILE = os.environ.get("CX_TOKENS_FILE", "/app/secrets/.tokens")

# All generated tokens carry this prefix to make them recognizable in logs and
# configuration (the secret part still has full entropy).
TOKEN_PREFIX = "cx_"


def generate_token() -> str:
    """Return a cryptographically secure, URL-safe Bearer token (~256 bits)."""
    return f"{TOKEN_PREFIX}{secrets.token_urlsafe(32)}"


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def load_tokens(path: str | None = None) -> dict:
    """Load the tokens mapping ``{name: {...}}`` from *path*.

    Returns an empty dict when the file is missing or unreadable so callers can
    treat "no tokens" uniformly.
    """
    path = path or DEFAULT_TOKENS_FILE
    if not os.path.exists(path):
        return {}
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except PermissionError as exc:
        logger.warning(
            "⚠️  Tokens file '%s' exists but is not readable (%s). "
            "Ensure the secrets directory is owned by the container user "
            "(uid 1000), e.g. `chown -R 1000:1000 ./secrets`.",
            path, exc,
        )
        return {}
    except (json.JSONDecodeError, OSError) as exc:
        logger.warning("⚠️  Tokens file '%s' could not be parsed (%s).", path, exc)
        return {}
    return data if isinstance(data, dict) else {}


def save_tokens(tokens: dict, path: str | None = None) -> None:
    """Persist *tokens* atomically with strict 0600 permissions.

    The file lives in a dedicated read-write secrets volume owned by the
    container user (uid 1000), so the same process both writes and reads it and
    no world-readable relaxation is needed. Keep this directory off any
    shared/public path; the filesystem is the trust boundary.
    """
    path = path or DEFAULT_TOKENS_FILE
    parent = os.path.dirname(path) or "."
    os.makedirs(parent, exist_ok=True)
    tmp = f"{path}.tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(tokens, fh, indent=2, sort_keys=True)
        fh.write("\n")
    os.replace(tmp, path)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def add_token(name: str, description: str = "", path: str | None = None) -> dict:
    """Create a new named token and persist it.

    Raises ``ValueError`` when *name* is empty or already exists. Returns the
    stored record (including the clear-text token, shown only once).
    """
    name = (name or "").strip()
    if not name:
        raise ValueError("A non-empty token name is required.")
    tokens = load_tokens(path)
    if name in tokens:
        raise ValueError(f"A token named '{name}' already exists. Revoke it first to rotate.")
    record = {
        "token": generate_token(),
        "description": description or f"Token for {name}",
        "created": _utc_now(),
    }
    tokens[name] = record
    save_tokens(tokens, path)
    return record


def revoke_token(name: str, path: str | None = None) -> bool:
    """Delete a named token. Returns ``True`` when something was removed."""
    tokens = load_tokens(path)
    if name not in tokens:
        return False
    del tokens[name]
    save_tokens(tokens, path)
    return True


class TokenStore:
    """In-memory reverse index (token -> name) loaded from a tokens file.

    The server builds one of these at startup and uses :meth:`resolve` on every
    request to map a presented Bearer token back to its owner name.
    """

    def __init__(self, path: str | None = None):
        self.path = path or DEFAULT_TOKENS_FILE
        self._by_token: dict[str, str] = {}
        self.reload()

    def reload(self) -> int:
        """(Re)load tokens from disk. Returns the number of valid tokens."""
        tokens = load_tokens(self.path)
        self._by_token = {
            rec["token"]: name
            for name, rec in tokens.items()
            if isinstance(rec, dict) and rec.get("token")
        }
        return len(self._by_token)

    def resolve(self, token: str) -> str | None:
        """Return the owner name for *token*, or ``None`` if unknown."""
        if not token:
            return None
        return self._by_token.get(token)

    def __len__(self) -> int:  # pragma: no cover - trivial
        return len(self._by_token)
