"""ArubaOS-CX MCP server — entry point.

Shared state, session pools, and inventory/security bootstrap live in
``core/server_core.py`` (which also defines the inventory/session meta-tools:
list_devices, list_sites, list_inventory_sources, find_devices, resolve_device,
refresh_inventory, run_on_site, logout). Every other tool is implemented in a
``tools/tools_*.py`` module, imported below purely for its ``@mcp.tool()`` /
``@mcp.prompt()`` registration side effect.

Each ``tools_*`` module is imported with ``import *`` so its (non-underscore)
tool functions become attributes of THIS module too — required because
dispatch/flat_tools.py / dispatch/deferred_tools.py resolve legacy tool
functions via ``getattr(sys.modules[__name__], tool_name)``, capturing this
module (the process entry point) as ``srv``.
"""

import asyncio
import json
import os
import signal
import sys
import time

from core import server_core
from core.server_core import (
    mcp, logger, _get_client, _reload_runtime,
    _AUTH_ENABLED, _MCP_PATH, _TRUST_FORWARDED, _host, _port,
    list_devices, list_sites, list_inventory_sources, find_devices,
    resolve_device, refresh_inventory, run_on_site, logout,
    _canonical_device, _resolve_devices, _is_ssh_write_command,
)
from dispatch.write_safety import write_safety

from tools.tools_exec import *  # noqa: F401,F403
from tools.tools_system import *  # noqa: F401,F403
from tools.tools_switching_routing import *  # noqa: F401,F403
from tools.tools_overlay_redundancy import *  # noqa: F401,F403
from tools.tools_access import *  # noqa: F401,F403
from tools.tools_config import *  # noqa: F401,F403
from tools.tools_service import *  # noqa: F401,F403
from tools.tools_configure import *  # noqa: F401,F403
from tools.tools_verify import *  # noqa: F401,F403
from tools.prompts import *  # noqa: F401,F403

# ══════════════════════════════════════════════════════════════════════
# ENTRY POINT
# ══════════════════════════════════════════════════════════════════════

class _StaleSessionMiddleware:
    """Log a warning when a client POSTs with an mcp-session-id that no longer exists on this server."""

    def __init__(self, app):
        self._app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or scope.get("method") not in ("POST", "GET"):
            await self._app(scope, receive, send)
            return

        session_id = next(
            (v.decode("utf-8", errors="replace") for k, v in scope.get("headers", []) if k == b"mcp-session-id"),
            None,
        )

        if not session_id:
            await self._app(scope, receive, send)
            return

        method = scope.get("method", "")

        async def _send(message):
            if message["type"] == "http.response.start" and message.get("status") == 404:
                stream_hint = " (SSE stream)" if method == "GET" else ""
                logger.warning(
                    "⚠️  Stale MCP session%s [ID: %s...] — the client is using a session identifier "
                    "that no longer exists (container restart?). "
                    "Solution: disconnect then reconnect the MCP server in the client "
                    "(VS Code: Ctrl+Shift+P → 'MCP: Disconnect from server' then 'MCP: Connect to server').",
                    stream_hint,
                    session_id[:8],
                )
            await send(message)

        await self._app(scope, receive, _send)


class _SecurityMiddleware:
    """Optional Bearer authentication + structured audit logging (ASGI).

    Runs in the same task as the HTTP request, so the Bearer token (hence the
    actor identity) and the client IP are reliably available here — unlike the
    tool-execution task in stateful streamable-http. Both features can be
    toggled independently; when both are off this is a near zero-cost passthrough.
    """

    def __init__(self, app, *, auth_enabled, token_store, audit, mcp_path,
                 trust_forwarded):
        self._app = app
        self._auth_enabled = auth_enabled
        self._token_store = token_store
        self._audit = audit
        self._mcp_path = mcp_path
        self._trust_forwarded = trust_forwarded

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self._app(scope, receive, send)
            return

        path = scope.get("path", "")
        # Only the MCP endpoint is guarded/audited.
        if not path.startswith(self._mcp_path):
            await self._app(scope, receive, send)
            return

        audit_on = self._audit is not None and self._audit.enabled
        if not self._auth_enabled and not audit_on:
            await self._app(scope, receive, send)
            return

        headers = {k.decode("latin-1").lower(): v.decode("latin-1")
                   for k, v in scope.get("headers", [])}
        src_ip = self._client_ip(scope, headers)

        actor = "anonymous"
        if self._auth_enabled:
            # LOCKED mode: auth is required but no token exists yet. Refuse every
            # MCP request (503) so the endpoint is unusable until an operator
            # creates the first token and restarts the container.
            if self._token_store is None or len(self._token_store) == 0:
                logger.warning("🔒 MCP request refused — server LOCKED (no token "
                               "configured) from %s %s", src_ip, path)
                await self._send_503_locked(send)
                return
            actor = self._resolve_actor(headers)
            if actor is None:
                logger.warning("🚫 Rejected unauthenticated request from %s %s",
                               src_ip, path)
                await self._send_401(send)
                return

        method = scope.get("method", "")
        if audit_on and method == "POST":
            body = await self._read_body(receive)
            info = self._parse_tool_call(body)
            receive = self._replay(body)
            if info is not None:
                start = time.perf_counter()
                captured: dict = {"code": None}

                async def _send(message):
                    if message["type"] == "http.response.start":
                        captured["code"] = message.get("status")
                    await send(message)

                session = headers.get("mcp-session-id")
                try:
                    await self._app(scope, receive, _send)
                except Exception as exc:  # noqa: BLE001
                    self._audit.record(
                        tool=info["tool"], actor=actor, src_ip=src_ip, session=session,
                        arguments=info["arguments"], outcome="exception",
                        error=repr(exc),
                        duration_ms=(time.perf_counter() - start) * 1000.0,
                        status_code=captured["code"],
                    )
                    raise
                self._audit.record(
                    tool=info["tool"], actor=actor, src_ip=src_ip, session=session,
                    arguments=info["arguments"], outcome="completed",
                    duration_ms=(time.perf_counter() - start) * 1000.0,
                    status_code=captured["code"],
                )
                return

        await self._app(scope, receive, send)

    # -- helpers ------------------------------------------------------

    def _resolve_actor(self, headers: dict) -> str | None:
        auth = headers.get("authorization", "")
        if not auth.startswith("Bearer "):
            return None
        token = auth[7:].strip()
        return self._token_store.resolve(token)

    def _client_ip(self, scope, headers: dict) -> str:
        if self._trust_forwarded:
            xff = headers.get("x-forwarded-for")
            if xff:
                return xff.split(",")[0].strip()
        client = scope.get("client")
        return client[0] if client else "unknown"

    @staticmethod
    async def _read_body(receive) -> bytes:
        chunks: list[bytes] = []
        while True:
            message = await receive()
            if message["type"] == "http.request":
                chunks.append(message.get("body", b""))
                if not message.get("more_body", False):
                    break
            elif message["type"] == "http.disconnect":
                break
        return b"".join(chunks)

    @staticmethod
    def _replay(body: bytes):
        sent = False

        async def receive():
            nonlocal sent
            if not sent:
                sent = True
                return {"type": "http.request", "body": body, "more_body": False}
            return {"type": "http.disconnect"}

        return receive

    @staticmethod
    def _parse_tool_call(body: bytes) -> dict | None:
        try:
            data = json.loads(body)
        except (ValueError, TypeError):
            return None

        def _extract(obj):
            if isinstance(obj, dict) and obj.get("method") == "tools/call":
                params = obj.get("params") or {}
                return {"tool": params.get("name"),
                        "arguments": params.get("arguments") or {}}
            return None

        if isinstance(data, list):
            for item in data:
                info = _extract(item)
                if info:
                    return info
            return None
        return _extract(data)

    @staticmethod
    async def _send_401(send) -> None:
        payload = json.dumps({"error": "Missing or invalid bearer token"}).encode()
        await send({
            "type": "http.response.start",
            "status": 401,
            "headers": [
                (b"content-type", b"application/json"),
                (b"content-length", str(len(payload)).encode()),
                (b"www-authenticate", b"Bearer"),
            ],
        })
        await send({"type": "http.response.body", "body": payload})

    @staticmethod
    async def _send_503_locked(send) -> None:
        payload = json.dumps({
            "error": "Service locked: authentication is enabled but no token is "
                     "configured. Create the first token with "
                     "`docker compose exec cx-mcp python cx_token_manager.py "
                     "generate --name <client>`, then restart the container.",
        }).encode()
        await send({
            "type": "http.response.start",
            "status": 503,
            "headers": [
                (b"content-type", b"application/json"),
                (b"content-length", str(len(payload)).encode()),
                (b"retry-after", b"0"),
            ],
        })
        await send({"type": "http.response.body", "body": payload})


# ── Write-safety rollback tool (Tier-1) ───────────────────────────────


@mcp.tool()
async def rollback(rollback_id: str) -> dict:
    """Undo a previously applied, reversible write by its `rollback_id`.

    A `rollback_id` is returned by `apply_plan` after applying a reversible plan
    (currently the VLAN-service provisioning workflow). The inverse actions are
    replayed last-created-first. Idempotent config merges (most `configure_*`
    tools) have no automatic inverse and are reported as 'unsupported'.
    """
    if write_safety is None or not write_safety.enabled:
        return {"ok": False, "error": "write safety is disabled"}
    if not rollback_id:
        return {"ok": False, "error": "rollback_id is required"}

    async def _executor(device: str, inverse: str, args: dict):
        async with _get_client(device) as client:
            if inverse == "delete_svi":
                return await client.delete_svi(args["vlan"])
            if inverse == "delete_evpn_vlan_rt":
                return await client.delete_evpn_vlan_rt(args["vlan"])
            if inverse == "delete_l2vni":
                return await client.delete_l2vni(args["vni"])
            if inverse == "delete_vlan":
                return await client.delete_vlan(args["vlan"])
            if inverse == "remove_vlan_from_trunk":
                return await client.remove_vlan_from_trunk(args["interface"], args["vlan"])
            raise ValueError(f"no executor for inverse action: {inverse}")

    try:
        return await write_safety.rollback(rollback_id, _executor)
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "error": type(exc).__name__, "detail": str(exc)}


# ── Progressive-disclosure install (Tier-1/Tier-2 + functional prefixes) ──
# Runs once, after every @mcp.tool() above is registered. Fail-open: any error
# here leaves the server advertising its full, unmodified tool set.

def _install_progressive_disclosure() -> None:
    # Flat toolset takes precedence: when CX_FLAT_TOOLSET is on (DEFAULT now),
    # the ~101 atomic tools are collapsed into ~23 flat dispatchers and the
    # Tier-1/2 deferred layer + functional prefixes are intentionally skipped
    # (mutually exclusive). Set CX_FLAT_TOOLSET=false to opt back into legacy.
    if os.getenv("CX_FLAT_TOOLSET", "true").strip().lower() in ("1", "true", "yes", "on"):
        try:
            import sys
            from dispatch.flat_tools import install_flat_toolset
            summary = install_flat_toolset(mcp, sys.modules[__name__])
            logger.info("flat_tools: %s", summary)
        except Exception:
            logger.exception("install_flat_toolset failed — tools left unchanged")
        return

    try:
        from dispatch.deferred_tools import install_deferred_tools
        summary = install_deferred_tools(mcp)
        logger.info("deferred_tools: %s", summary)
    except Exception:
        logger.exception("install_deferred_tools failed — tools left unchanged")
    try:
        from dispatch.tool_prefixes import apply_tool_prefixes
        summary = apply_tool_prefixes(mcp)
        logger.info("tool_prefixes: %s", summary)
    except Exception:
        logger.exception("apply_tool_prefixes failed — names left unchanged")


_install_progressive_disclosure()


if __name__ == "__main__":
    import uvicorn

    server_core._init_security()

    transport = os.environ.get("MCP_TRANSPORT", "streamable-http").lower()
    if transport == "streamable-http":
        async def _run() -> None:
            app = _StaleSessionMiddleware(mcp.streamable_http_app())
            app = _SecurityMiddleware(
                app,
                auth_enabled=_AUTH_ENABLED,
                token_store=server_core._token_store,
                audit=server_core._audit,
                mcp_path=_MCP_PATH,
                trust_forwarded=_TRUST_FORWARDED,
            )

            # Manual hot reload on SIGHUP: reload tokens + inventory without a
            # restart. Triggered from inside the container by `python cx_reload.py`.
            def _on_sighup() -> None:
                logger.info("📥 SIGHUP received — hot-reloading tokens & inventory…")
                asyncio.ensure_future(_reload_runtime())

            try:
                asyncio.get_running_loop().add_signal_handler(signal.SIGHUP, _on_sighup)
            except (NotImplementedError, AttributeError):
                logger.warning("⚠️  SIGHUP hot-reload not available on this platform.")

            config = uvicorn.Config(app, host=_host, port=_port, log_level="info")
            uvi_server = uvicorn.Server(config)

            async def _announce_ready() -> None:
                # Wait until Uvicorn reports "Uvicorn running on ..." (i.e. the
                # socket is bound and the app is ready to accept requests).
                while not uvi_server.started:
                    await asyncio.sleep(0.1)
                logger.info(
                    "✅ hpe-cx-mcp server is up and running on http://%s:%s — "
                    "if your agent already has an open MCP connection, reset it "
                    "(MCP: Disconnect → Connect) to pick up the current tools.",
                    _host,
                    _port,
                )

            await asyncio.gather(uvi_server.serve(), _announce_ready())

        try:
            asyncio.run(_run())
        except Exception:
            logger.exception("❌ hpe-cx-mcp server failed to start")
            raise
    else:
        mcp.run(transport=transport)
