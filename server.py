"""ArubaOS-CX MCP server."""

import asyncio
import json
import logging
import os
import re
import signal
import sys
import time

from mcp.server.fastmcp import FastMCP

from aruba_client import ArubaOSCXClient, ArubaAPIError
from aruba_client import (
    _v_mac, _v_ipv4_host, _v_ip_host, _v_ipv4_cidr, _v_int_range,
    _v_vlan, _v_vni, _v_mtu, _v_asn, _v_route_target, _v_ospf_area,
)
from config import DeviceConfig, load_inventory, Inventory, InventoryError
from config_backup import ConfigBackupError, export_config
from inventory_sources import InventoryManager, InventorySourceError
from ssh_client import ArubaOSCXSSHClient, ArubaSSHError
import cx_auth
from cx_audit import AuditLogger

# Progressive-disclosure / write-safety layers (optional, fail-open). All three
# are gated by their own env flags and are no-ops unless explicitly enabled.
try:
    from write_safety import write_safety
except Exception:  # pragma: no cover - never let an import break the server
    write_safety = None

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)


def _check_env_vars() -> None:
    """Check the environment variables at startup and log warnings if needed."""
    missing: list[str] = []

    if not os.environ.get("ARUBA_DEFAULT_PASSWORD"):
        missing.append("ARUBA_DEFAULT_PASSWORD")

    if not os.environ.get("ARUBA_DEFAULT_USERNAME"):
        missing.append("ARUBA_DEFAULT_USERNAME")

    if missing:
        logger.warning(
            "⚠️  Undefined environment variables: %s — "
            "connections to devices may fail. "
            "Define them in your .env file or docker-compose.yml.",
            ", ".join(missing),
        )

    inventory = os.environ.get("INVENTORY_FILE", "/app/inventory/inventory.yaml")
    if not os.path.exists(inventory):
        logger.warning(
            "⚠️  Inventory file not found: %s — "
            "set INVENTORY_FILE or mount the file into the container.",
            inventory,
        )


_check_env_vars()

# ── Initialization ────────────────────────────────────────────────────

_host = os.environ.get("MCP_HOST", "0.0.0.0")
_port = int(os.environ.get("MCP_PORT", "8000"))

mcp = FastMCP("cx-mcp", host=_host, port=_port)

_inventory_path = os.environ.get("INVENTORY_FILE", "/app/inventory/inventory.yaml")
_devices: dict[str, DeviceConfig] = {}
_inventory: Inventory | None = None
_inv_manager: InventoryManager | None = None


# ── Security: optional Bearer auth + audit logging ────────────────────
# Both features are OFF by default (backward compatible). Enable them via the
# environment variables below (typically in docker-compose.yml).


def _env_bool(name: str, default: bool = False) -> bool:
    val = os.environ.get(name)
    if val is None:
        return default
    return val.strip().lower() in ("1", "true", "yes", "on")


_AUTH_ENABLED = _env_bool("CX_AUTH_ENABLED", False)
_TOKENS_FILE = os.environ.get("CX_TOKENS_FILE", cx_auth.DEFAULT_TOKENS_FILE)
_MCP_PATH = os.environ.get("CX_MCP_PATH", "/mcp")
_TRUST_FORWARDED = _env_bool("CX_TRUST_FORWARDED_FOR", False)

_AUDIT_ENABLED = _env_bool("CX_AUDIT_ENABLED", False)
_AUDIT_FILE = os.environ.get("CX_AUDIT_FILE", "/app/logs/audit.jsonl")
_AUDIT_LEVEL = os.environ.get("CX_AUDIT_LEVEL", "all")
_AUDIT_STDOUT = _env_bool("CX_AUDIT_STDOUT", False)

# Lazily built at startup (see __main__): a token store and an audit logger.
_token_store: "cx_auth.TokenStore | None" = None
_audit: AuditLogger | None = None


def _init_security() -> None:
    """Build the token store / audit logger and enforce startup rules.

    Policy: if Bearer auth is enabled but no valid token is available, the server
    still starts but in LOCKED mode — every MCP request is refused (HTTP 503)
    until at least one token exists. This lets an operator create the first token
    (e.g. `docker compose exec cx-mcp python cx_token_manager.py generate ...`)
    without first disabling authentication. A restart is then required for the
    new token to take effect.
    """
    global _token_store, _audit

    if _AUTH_ENABLED:
        _token_store = cx_auth.TokenStore(_TOKENS_FILE)
        if len(_token_store) == 0:
            logger.warning(
                "🔒 CX_AUTH_ENABLED=true but no token found in '%s'. Starting in "
                "LOCKED mode: all MCP requests are refused (HTTP 503) until a token "
                "exists. Create the first one with: "
                "docker compose exec cx-mcp python cx_token_manager.py generate "
                "--name <client> — then RESTART the container.",
                _TOKENS_FILE,
            )
        else:
            logger.info("🔒 Bearer authentication ENABLED — %d token(s) loaded from %s",
                        len(_token_store), _TOKENS_FILE)
    else:
        logger.warning("🔓 Bearer authentication is DISABLED (CX_AUTH_ENABLED not set). "
                       "The MCP endpoint is open to any client that can reach it.")


    _audit = AuditLogger(
        enabled=_AUDIT_ENABLED,
        path=_AUDIT_FILE,
        level=_AUDIT_LEVEL,
        to_stdout=_AUDIT_STDOUT,
    )
    if _AUDIT_ENABLED:
        logger.info("📝 Audit logging ENABLED (level=%s) → %s", _AUDIT_LEVEL, _AUDIT_FILE)


def _bootstrap_dynamic_inventory() -> None:
    """Pull devices from external sources and resolve Vault credentials.

    Runs only when non-local sources or Vault are configured, so a purely local
    inventory keeps a fast, network-free startup. Failures degrade gracefully:
    the local inventory remains usable even if an external source is down."""
    global _inv_manager
    if _inventory is None:
        return
    _inv_manager = InventoryManager(_inventory)

    needs_async = _inv_manager.has_external_sources or _inventory.vault.enabled
    if not needs_async:
        return

    async def _run() -> None:
        # 1) Merge external sources into the local device map (priority-aware).
        if _inv_manager.has_external_sources:
            try:
                summary = await _inv_manager.prefetch(_devices)
                if summary["added"] or summary["updated"]:
                    logger.info(
                        "🔄 Dynamic inventory: +%d new, %d updated from %s",
                        len(summary["added"]), len(summary["updated"]),
                        ", ".join(summary["sources"]) or "—",
                    )
                for src, err in summary.get("errors", {}).items():
                    logger.warning("⚠️  Source '%s' error: %s", src, err)
            except Exception as exc:  # noqa: BLE001
                logger.warning("⚠️  Dynamic inventory prefetch failed: %s", exc)

        # 2) Resolve Vault credentials for devices that need them.
        if _inventory.vault.enabled and _inv_manager.vault.configured:
            resolved = 0
            for dev in _devices.values():
                if not (dev.vault or _inventory.vault.enabled):
                    continue
                try:
                    creds = await _inv_manager.resolve_credentials(dev)
                except Exception as exc:  # noqa: BLE001
                    logger.warning("⚠️  Vault resolution failed for %s: %s", dev.name, exc)
                    continue
                if creds.get("source") == "vault":
                    dev.username = creds["username"]
                    dev.password = creds["password"]
                    dev.ssh_username = creds["ssh_username"]
                    dev.ssh_password = creds["ssh_password"]
                    resolved += 1
            if resolved:
                logger.info("🔐 Vault: resolved credentials for %d device(s)", resolved)

    try:
        asyncio.run(_run())
    except Exception as exc:  # noqa: BLE001
        logger.warning("⚠️  Dynamic inventory bootstrap error: %s", exc)


try:
    _inventory = load_inventory(_inventory_path)
except FileNotFoundError:
    logger.warning("⚠️  Inventory not found: %s", _inventory_path)
except InventoryError as e:
    # The inventory file exists but is malformed (YAML syntax error) or violates
    # the expected schema. Refuse to start so the problem is fixed up-front
    # instead of silently running with an empty/partial inventory.
    logger.error(
        "❌ Inventory file '%s' failed validation — the server will NOT start.\n"
        "   %s\n"
        "   Fix the inventory file, then restart the container.",
        _inventory_path, e,
    )
    sys.exit(1)
except Exception as e:
    # Any other parsing/loading failure is treated the same way: do not start
    # with a broken inventory.
    logger.error(
        "❌ Inventory file '%s' could not be loaded — the server will NOT start.\n"
        "   %s\n"
        "   Fix the inventory file, then restart the container.",
        _inventory_path, e,
    )
    sys.exit(1)
else:
    _devices = _inventory.devices
    logger.info("✅ %d device(s) loaded: %s", len(_devices), list(_devices.keys()))
    _src_summary = ", ".join(
        f"{s['name']}({s['type']})" for s in
        [{"name": n, "type": _inventory.sources[n].type} for n in _inventory.source_order]
    )
    logger.info("📚 Inventory sources (priority order): %s", _src_summary)
    _bootstrap_dynamic_inventory()



def _canonical_device(device: str) -> str:
    """Resolve an identifier (inventory name or IP/hostname) to the canonical
    device name in the inventory."""
    if device in _devices:
        return device
    matched = next((name for name, dev in _devices.items() if dev.host == device), None)
    if matched is None:
        available = ", ".join(_devices.keys()) if _devices else "none"
        raise ValueError(f"Device '{device}' not found. Available: {available}")
    return matched


# ── Pool de sessions REST ─────────────────────────────────────────────
# Sessions are pooled and reused across requests during a workflow (a single
# login per device), then closed explicitly via the `logout` tool at the end of
# the workflow. A lazy "reaper" also closes sessions left idle beyond
# _SESSION_IDLE_TTL (a safety net against session leaks, which cause "access
# denied" errors).
_CLIENT_POOL: dict[str, dict] = {}  # canonical name → {"client": ArubaOSCXClient, "last_used": float}
_SESSION_IDLE_TTL = float(os.environ.get("CX_SESSION_IDLE_TTL", "600"))  # seconds
_REAPER_TASKS: set = set()  # keeps a reference to background logout tasks (anti-GC)


def _new_client(name: str) -> ArubaOSCXClient:
    dev = _devices[name]
    client = ArubaOSCXClient(
        host=dev.host,
        username=dev.username,
        password=dev.password,
        api_version=dev.api_version,
        verify_ssl=dev.verify_ssl,
        timeout=dev.timeout,
    )
    client.set_write_enabled(dev.can_write)
    client._auto_logout = False  # pooled session: no logout on each request
    return client


def _device_can_write(device: str) -> bool:
    name = _canonical_device(device)
    return _devices[name].can_write


def _deny_read_only(device: str, operation: str) -> dict:
    name = _canonical_device(device)
    dev = _devices[name]
    return {
        "status": "forbidden",
        "error": (
            f"Operation '{operation}' denied on device '{name}' ({dev.host}): "
            "device access_mode is read-only."
        ),
        "device": name,
        "host": dev.host,
        "access_mode": dev.access_mode,
    }


def _deny_read_only_many(devices: list[str], operation: str) -> dict | None:
    denied = []
    allowed = []
    for d in devices:
        name = _canonical_device(d)
        if _devices[name].can_write:
            allowed.append(name)
        else:
            denied.append({
                "device": name,
                "host": _devices[name].host,
                "access_mode": _devices[name].access_mode,
            })
    if denied:
        return {
            "status": "forbidden",
            "error": (
                f"Operation '{operation}' denied: one or more target devices are read-only."
            ),
            "denied_devices": denied,
            "writable_devices": sorted(set(allowed)),
        }
    return None


def _is_ssh_write_command(command: str) -> bool:
    cmd = (command or "").strip().lower()
    if not cmd:
        return False
    readonly_prefixes = (
        "show",
        "ping",
        "traceroute",
        "nslookup",
        "whoami",
    )
    return not cmd.startswith(readonly_prefixes)


def _get_client(device: str) -> ArubaOSCXClient:
    """Return a pooled-session client (reused during the workflow).

    The returned client is always used via `async with _get_client(dev) as c:`,
    but does NOT close its session on exit: it stays open for the subsequent
    steps and is closed by `logout`/the reaper.
    """
    name = _canonical_device(device)
    _reap_idle_sessions(exclude=name)
    entry = _CLIENT_POOL.get(name)
    if entry is None:
        entry = {"client": _new_client(name), "last_used": time.monotonic()}
        _CLIENT_POOL[name] = entry
    entry["last_used"] = time.monotonic()
    return entry["client"]


def _reap_idle_sessions(exclude: str | None = None) -> None:
    """Close (best-effort) pooled sessions that have been idle for too long.
    Called lazily on every pool access: no background task required.
    A recently used session (currently in use) is never closed."""
    if _SESSION_IDLE_TTL <= 0:
        return
    now = time.monotonic()
    stale = [
        n for n, e in list(_CLIENT_POOL.items())
        if n != exclude and (now - e["last_used"]) > _SESSION_IDLE_TTL
    ]
    for n in stale:
        entry = _CLIENT_POOL.pop(n, None)
        if entry is not None:
            task = asyncio.create_task(_safe_logout(entry["client"]))
            _REAPER_TASKS.add(task)
            task.add_done_callback(_REAPER_TASKS.discard)


async def _safe_logout(client: ArubaOSCXClient) -> bool:
    try:
        return await client.logout()
    except Exception:  # noqa: BLE001
        return False


async def _close_sessions(names) -> list[str]:
    """Close the pooled sessions of the given devices. Returns the names that were
    actually closed (session open at call time)."""
    closed: list[str] = []
    for name in names:
        try:
            canon = _canonical_device(name)
        except ValueError:
            continue
        entry = _CLIENT_POOL.pop(canon, None)
        if entry is not None:
            if await _safe_logout(entry["client"]):
                closed.append(canon)
    return closed


# ── Pool de sessions SSH ──────────────────────────────────────────────
# Pooled SSH sessions (a shell connection reused across requests), closed by the
# `logout` tool or by the lazy idle reaper.
_SSH_POOL: dict[str, dict] = {}  # canonical name → {"client": ArubaOSCXSSHClient, "last_used": float}
_SSH_IDLE_TTL = float(os.environ.get("CX_SSH_IDLE_TTL", "300"))  # seconds


def _reap_idle_ssh(exclude: str | None = None) -> None:
    """Close (best-effort) the SSH sessions that have been idle for too long."""
    if _SSH_IDLE_TTL <= 0:
        return
    now = time.monotonic()
    stale = [
        n for n, e in list(_SSH_POOL.items())
        if n != exclude and (now - e["last_used"]) > _SSH_IDLE_TTL
    ]
    for n in stale:
        entry = _SSH_POOL.pop(n, None)
        if entry is not None:
            task = asyncio.create_task(_safe_ssh_close(entry["client"]))
            _REAPER_TASKS.add(task)
            task.add_done_callback(_REAPER_TASKS.discard)


async def _safe_ssh_close(client: ArubaOSCXSSHClient) -> bool:
    try:
        return await client.close()
    except Exception:  # noqa: BLE001
        return False


async def _get_ssh_client(device: str) -> ArubaOSCXSSHClient:
    """Return a connected SSH client (pooled session), (re)connecting if needed.
    The session stays open for subsequent requests."""
    name = _canonical_device(device)
    _reap_idle_ssh(exclude=name)
    entry = _SSH_POOL.get(name)
    if entry is None or not entry["client"].is_connected:
        dev = _devices[name]
        client = ArubaOSCXSSHClient(
            host=dev.host,
            username=dev.ssh_username,
            password=dev.ssh_password,
            port=dev.ssh_port,
            timeout=dev.timeout,
        )
        await client.connect()
        entry = {"client": client, "last_used": time.monotonic()}
        _SSH_POOL[name] = entry
    entry["last_used"] = time.monotonic()
    return entry["client"]


async def _close_ssh_sessions(names) -> list[str]:
    """Close the pooled SSH sessions of the given devices."""
    closed: list[str] = []
    for name in names:
        try:
            canon = _canonical_device(name)
        except ValueError:
            continue
        entry = _SSH_POOL.pop(canon, None)
        if entry is not None:
            if await _safe_ssh_close(entry["client"]):
                closed.append(canon)
    return closed


async def _ssh_exec(device: str, runner):
    """Run an SSH operation with one self-healing retry on a stale pooled session.

    `runner` is an async callable taking the connected client. If a REUSED pooled
    session fails (e.g. a prompt timeout left it desynchronized), it is dropped,
    a fresh session is reconnected, and the operation is retried ONCE. A failure
    on a freshly connected session is surfaced as-is (genuine error, not retried,
    so a write command is never silently replayed)."""
    name = _canonical_device(device)
    was_pooled = name in _SSH_POOL and _SSH_POOL[name]["client"].is_connected
    client = await _get_ssh_client(device)
    try:
        return await runner(client)
    except ArubaSSHError:
        if not was_pooled:
            raise
        entry = _SSH_POOL.pop(name, None)
        if entry is not None:
            await _safe_ssh_close(entry["client"])
        client = await _get_ssh_client(device)
        return await runner(client)


def _devices_in_site(site: str) -> dict[str, DeviceConfig]:
    """Return the devices belonging to the given site (case-insensitive
    comparison). Raises ValueError if the site is unknown."""
    target = site.strip().lower()
    matched = {
        name: dev for name, dev in _devices.items()
        if (dev.site or "").strip().lower() == target
    }
    if not matched:
        known = sorted({dev.site for dev in _devices.values() if dev.site})
        known_str = ", ".join(known) if known else "no site defined in the inventory"
        raise ValueError(
            f"No device in site '{site}'. Available sites: {known_str}."
        )
    return matched


def _resolve_devices(device: str = None, site: str = None) -> list[str]:
    """
    Resolve the target of a request into a list of device names.

    - site provided: all devices of the site (filtered by 'device' if it is
      also provided and present in the site).
    - site absent: the single 'device' provided.

    The site notion is therefore optional; without it, the historical
    single-device behavior is preserved.
    """
    if site:
        in_site = _devices_in_site(site)
        if device:
            # Restrict to the requested device if it is in the site
            if device in in_site:
                return [device]
            matched = next((n for n, d in in_site.items() if d.host == device), None)
            if matched is None:
                raise ValueError(
                    f"Device '{device}' does not belong to site '{site}'."
                )
            return [matched]
        return list(in_site.keys())
    if device:
        return [device]
    raise ValueError("You must provide 'device' and/or 'site'.")


def _safe_targets(device: str = None, site: str = None) -> list[str]:
    """Like `_resolve_devices` but returns [] instead of raising. Used to build
    a plan preview before `_domain_write` performs the authoritative resolution
    (and surfaces any error)."""
    try:
        return _resolve_devices(device=device, site=site)
    except ValueError:
        return []


def _precheck(checks: list) -> dict | None:
    """Run input-compliance validators up front (covers BOTH plan and apply,
    before any device is contacted). `checks` is a list of (field_label,
    zero-arg callable) where the callable runs a validator (e.g. _v_ipv4_cidr).

    On the first failure returns a clear, structured `invalid_input` response
    that names the field, explains the problem and tells the agent to ask the
    user for a corrected value. Returns None when every check passes."""
    for field, fn in checks:
        try:
            fn()
        except ArubaAPIError as exc:
            msg = str(exc)
            if msg.startswith("[HTTP 400] "):
                msg = msg[len("[HTTP 400] "):]
            return {
                "status": "invalid_input",
                "field": field,
                "error": msg,
                "action_required": (
                    f"The value provided for '{field}' is not valid. Do NOT "
                    "contact the device. Correct the value and retry; if it "
                    "came from the user, ask them for a valid value first."),
            }
    return None



# ══════════════════════════════════════════════════════════════════════
# TOOLS — Inventory
# ══════════════════════════════════════════════════════════════════════

@mcp.tool()
def list_devices(site: str = None) -> dict:
    """List the inventory devices. Optional `site` filter: returns only the
    devices belonging to that site."""
    if not _devices:
        return {"devices": [], "message": "No device configured. Check your inventory file."}
    if site:
        try:
            selected = _devices_in_site(site)
        except ValueError as exc:
            return {"devices": [], "count": 0, "site": site, "message": str(exc)}
    else:
        selected = _devices
    return {
        "devices": [
            {
                "name": name,
                "host": dev.host,
                "api_version": dev.api_version,
                "verify_ssl": dev.verify_ssl,
                "access_mode": dev.access_mode,
                "source": dev.source,
                "site": dev.site or None,
                "tags": dev.tags,
            }
            for name, dev in selected.items()
        ],
        "count": len(selected),
        "site": site,
    }


@mcp.tool()
def list_sites() -> dict:
    """List the sites defined in the inventory along with their attached devices.
    Lets the client then target a site via the `site` parameter of the tools."""
    sites: dict[str, list[str]] = {}
    unassigned: list[str] = []
    for name, dev in _devices.items():
        if dev.site:
            sites.setdefault(dev.site, []).append(name)
        else:
            unassigned.append(name)
    return {
        "sites": [
            {"name": s, "devices": sorted(devs), "count": len(devs)}
            for s, devs in sorted(sites.items())
        ],
        "count": len(sites),
        "devices_without_site": sorted(unassigned),
    }


@mcp.tool()
async def list_inventory_sources(probe: bool = False) -> dict:
    """List the configured inventory sources and their priority order.

    A source is either `local` (the inventory file) or an external source of
    truth (`netbox`, `nautobot`, `infrahub`). The lower the `priority` number,
    the higher the precedence when a device exists in several sources.

    Tokens are never returned; only a masked hint and a `has_token` flag are
    exposed. Set `probe=True` to test reachability of each external source and
    of Vault."""
    if _inv_manager is None:
        return {
            "sources": [{"name": "local", "type": "local", "priority": 0, "is_default": True}],
            "source_priority": ["local"],
            "default_source": "local",
            "vault": {"enabled": False},
        }

    result = {
        "sources": _inv_manager.list_sources(),
        "source_priority": list(_inventory.source_order),
        "default_source": "local",
        "vault": {
            "enabled": _inventory.vault.enabled,
            "configured": _inv_manager.vault.configured,
            "url": _inventory.vault.url or None,
            "mount": _inventory.vault.mount,
            "kv_version": _inventory.vault.kv_version,
        },
    }
    if probe:
        result["health"] = await _inv_manager.sources_health()
        result["vault"]["health"] = await _inv_manager.vault.health()
    return result


@mcp.tool()
async def find_devices(
    source: str = None,
    name: str = None,
    site: str = None,
    tenant: str = None,
    location: str = None,
    rack: str = None,
    zone: str = None,
    device_group: str = None,
    tag: str = None,
    custom_fields: dict = None,
    limit: int = 100,
) -> dict:
    """Search devices across the configured inventory sources.

    Native filters: `name` (the device), `site`, `tenant`, `location`, `rack`,
    `zone`, `device_group`, `tag`. For Infrahub these map to GraphQL filters:
    `device_group` -> group membership, `location`/`site`/`rack`/`zone` ->
    location relationships, `name` -> the device name. Any non-native attribute
    passed via `custom_fields` (a {key: value} map) is resolved as a
    NetBox/Nautobot custom field (and matched against tags for the local
    source). Restrict to one source with `source` (e.g. "infrahub"); by default
    all sources are queried in priority order and merged by device name
    (higher-priority source wins)."""
    if _inv_manager is None:
        return {"devices": [], "count": 0, "message": "Dynamic inventory not initialized."}

    filters: dict = {}
    for key, value in (("name", name), ("site", site), ("tenant", tenant),
                       ("location", location), ("rack", rack), ("zone", zone),
                       ("device_group", device_group), ("tag", tag)):
        if value:
            filters[key] = value
    if custom_fields:
        filters.update(custom_fields)

    try:
        result = await _inv_manager.find_devices(
            filters, source=source, local_devices=_devices, limit=limit
        )
    except InventorySourceError as exc:
        return {"devices": [], "count": 0, "error": str(exc)}

    return {
        "devices": result["devices"],
        "count": len(result["devices"]),
        "queried_sources": result["queried_sources"],
        "errors": result["errors"],
        "filters": filters,
    }


@mcp.tool()
async def resolve_device(device: str) -> dict:
    """Resolve a device (by name or management IP) across all sources, honoring
    source priority, and return the merged connection information plus which
    source provided it. Credentials are never returned in clear text."""
    if _inv_manager is None:
        # Fall back to the local inventory.
        try:
            name = _canonical_device(device)
        except ValueError as exc:
            return {"found": False, "error": str(exc)}
        dev = _devices[name]
        return {
            "found": True, "name": name, "host": dev.host, "source": dev.source,
            "api_version": dev.api_version, "access_mode": dev.access_mode,
        }

    rec = await _inv_manager.resolve_device(device, local_devices=_devices)
    if not rec:
        return {"found": False, "device": device,
                "message": "Device not found in any configured source."}

    # Enrich with the effective in-memory device (after prefetch/vault) if known.
    name = rec.get("name")
    dev = _devices.get(name)
    cred_source = "inventory/env"
    if dev is not None:
        if _inventory.vault.enabled or dev.vault:
            try:
                creds = await _inv_manager.resolve_credentials(dev)
                cred_source = creds.get("source", cred_source)
            except InventorySourceError:
                pass
        elif dev.explicit:
            cred_source = "device-specific"
    return {
        "found": True,
        "name": name,
        "host": rec.get("host"),
        "winning_source": rec.get("source"),
        "credential_source": cred_source,
        "api_version": dev.api_version if dev else None,
        "access_mode": dev.access_mode if dev else None,
        "site": rec.get("site") or (dev.site if dev else None),
        "tags": rec.get("tags", []),
        "extra": rec.get("extra", {}),
    }


@mcp.tool()
async def refresh_inventory() -> dict:
    """Reload the inventory file and re-pull devices from the external sources
    (priority-aware), refreshing Vault-backed credentials. Returns a summary of
    added/updated devices and any source errors."""
    return await _reload_inventory()


async def _reload_inventory() -> dict:
    """(Re)load the inventory file, re-pull external sources and refresh
    Vault-backed credentials. Shared by the `refresh_inventory` MCP tool and the
    SIGHUP hot-reload handler. Returns a summary dict."""
    global _inventory, _devices, _inv_manager
    try:
        _inventory = load_inventory(_inventory_path)
    except Exception as exc:  # noqa: BLE001
        return {"status": "error", "error": f"Failed to reload inventory: {exc}"}

    _devices = _inventory.devices
    _inv_manager = InventoryManager(_inventory)

    summary = {"added": [], "updated": [], "errors": {}, "sources": []}
    if _inv_manager.has_external_sources:
        try:
            summary = await _inv_manager.prefetch(_devices)
        except Exception as exc:  # noqa: BLE001
            summary["errors"]["_prefetch"] = str(exc)

    vault_resolved = 0
    if _inventory.vault.enabled and _inv_manager.vault.configured:
        for dev in _devices.values():
            if not (dev.vault or _inventory.vault.enabled):
                continue
            try:
                creds = await _inv_manager.resolve_credentials(dev)
            except Exception as exc:  # noqa: BLE001
                summary["errors"]["_vault"] = str(exc)
                continue
            if creds.get("source") == "vault":
                dev.username = creds["username"]
                dev.password = creds["password"]
                dev.ssh_username = creds["ssh_username"]
                dev.ssh_password = creds["ssh_password"]
                vault_resolved += 1

    return {
        "status": "ok",
        "device_count": len(_devices),
        "added": summary.get("added", []),
        "updated": summary.get("updated", []),
        "sources": summary.get("sources", []),
        "vault_resolved": vault_resolved,
        "errors": summary.get("errors", {}),
    }


async def _reload_runtime() -> dict:
    """Hot-reload the tokens file and the inventory file in the running server,
    without a container rebuild/restart. Triggered manually by SIGHUP, sent from
    inside the container by `python cx_reload.py`.

    Because the security middleware shares the same `TokenStore` instance,
    reloading it here takes effect immediately on the next request — including
    lifting LOCKED mode once the first token exists.
    """
    result: dict = {"tokens": None, "inventory": None}

    if _AUTH_ENABLED and _token_store is not None:
        try:
            count = _token_store.reload()
            result["tokens"] = {"status": "ok", "count": count}
            logger.info("🔄 Reloaded tokens — %d token(s) now active from %s",
                        count, _TOKENS_FILE)
            if count == 0:
                logger.warning("🔒 Still LOCKED: no token in '%s' after reload.",
                               _TOKENS_FILE)
        except Exception as exc:  # noqa: BLE001
            result["tokens"] = {"status": "error", "error": str(exc)}
            logger.warning("⚠️  Token reload failed: %s", exc)

    try:
        inv = await _reload_inventory()
        result["inventory"] = inv
        if inv.get("status") == "ok":
            logger.info("🔄 Reloaded inventory — %d device(s).", inv.get("device_count"))
        else:
            logger.warning("⚠️  Inventory reload error: %s", inv.get("error"))
    except Exception as exc:  # noqa: BLE001
        result["inventory"] = {"status": "error", "error": str(exc)}
        logger.warning("⚠️  Inventory reload failed: %s", exc)

    return result


# Read-only operations allowed for site-wide execution.
# Each entry maps an operation name to the corresponding client method.
_SITE_OPERATIONS: dict[str, str] = {
    "get_system_info": "get_system_info",
    "get_hardware_health": "get_hardware_health",
    "get_boot_history": "get_boot_history",
    "get_ssh_config": "get_ssh_config",
    "list_troubleshoot_features": "list_troubleshoot_features",
    "run_troubleshoot": "run_troubleshoot",
    "get_transceivers": "get_transceivers",
    "get_interfaces": "get_interfaces",
    "get_interface_counters": "get_interface_counters",
    "get_supported_transceivers": "get_supported_transceivers",
    "get_poe_status": "get_poe_status",
    "get_loopbacks": "get_loopbacks",
    "get_routed_ports": "get_routed_ports",
    "get_vlan_interfaces": "get_vlan_interfaces",
    "get_lag": "get_lag",
    "get_vlans": "get_vlans",
    "get_lldp_neighbors": "get_lldp_neighbors",
    "get_routing_table": "get_routing_table",
    "get_mac_table": "get_mac_table",
    "get_arp_table": "get_arp_table",
    "get_logs": "get_logs",
    "get_spanning_tree": "get_spanning_tree",
    "get_bgp_neighbors": "get_bgp_neighbors",
    "get_bgp_config": "get_bgp_config",
    "get_bgp_routes": "get_bgp_routes",
    "get_ospf_overview": "get_ospf_overview",
    "get_ospf_neighbors": "get_ospf_neighbors",
    "get_ospf_interfaces": "get_ospf_interfaces",
    "get_evpn_config": "get_evpn_config",
    "get_evpn_routes": "get_evpn_routes",
    "get_vxlan_config": "get_vxlan_config",
    "get_vxlan_tunnels": "get_vxlan_tunnels",
    "get_vxlan_static_peers": "get_vxlan_static_peers",
    "get_evpn_vtep_neighbors": "get_evpn_vtep_neighbors",
    "get_vsx_status": "get_vsx_status",
    "get_vsx_config": "get_vsx_config",
    "get_vsx_sync": "get_vsx_sync",
    "get_vsf_status": "get_vsf_status",
    "get_vsf_config": "get_vsf_config",
    "get_maintenance_mode": "get_maintenance_mode",
    "get_port_access_clients": "get_port_access_clients",
    "get_port_access_auth_config": "get_port_access_auth_config",
    "get_port_access_summary": "get_port_access_summary",
    "get_radius_servers": "get_radius_servers",
    "get_tacacs_servers": "get_tacacs_servers",
    "get_aaa_authentication": "get_aaa_authentication",
    "get_app_recognition": "get_app_recognition",
    "get_app_visibility": "get_app_visibility",
}


@mcp.tool()
async def run_on_site(site: str, operation: str, params: dict = None) -> dict:
    """Run a (read-only) diagnostic operation on all devices of a site, in
    parallel. `operation` = op name (list returned if unknown);
    `params` = optional args (e.g. {"vrf": "default"})."""
    if operation not in _SITE_OPERATIONS:
        return {
            "error": f"Operation '{operation}' not allowed or unknown.",
            "available_operations": sorted(_SITE_OPERATIONS.keys()),
        }
    try:
        device_names = _resolve_devices(site=site)
    except ValueError as exc:
        return {"error": str(exc)}

    method_name = _SITE_OPERATIONS[operation]
    kwargs = params or {}

    async def _run_one(name: str) -> tuple[str, dict]:
        try:
            async with _get_client(name) as client:
                method = getattr(client, method_name)
                data = await method(**kwargs)
                return name, {"ok": True, "data": data}
        except Exception as exc:  # noqa: BLE001 — isolate the failure per device
            return name, {"ok": False, "error": str(exc)}

    results = await asyncio.gather(*[_run_one(n) for n in device_names])
    results_by_device = {name: res for name, res in results}
    succeeded = [n for n, r in results_by_device.items() if r["ok"]]
    failed = [n for n, r in results_by_device.items() if not r["ok"]]

    # End of workflow: close the sessions opened on the targeted devices.
    await _close_sessions(device_names)

    return {
        "site": site,
        "operation": operation,
        "params": kwargs,
        "devices_targeted": device_names,
        "results": results_by_device,
        "summary": {
            "total": len(device_names),
            "succeeded": len(succeeded),
            "failed": len(failed),
            "failed_devices": failed,
        },
    }


@mcp.tool()
async def logout(device: str = None, site: str = None) -> dict:
    """Close the pooled REST and SSH sessions (to call at the end of a workflow).
    Without arguments: closes everything. `device`/`site`: specific target. Idempotent."""
    if device is None and site is None:
        names = list(_CLIENT_POOL.keys())
    else:
        try:
            names = _resolve_devices(device=device, site=site)
        except ValueError as exc:
            return {"status": "error", "error": str(exc)}

    closed = await _close_sessions(names)
    if device is None and site is None:
        ssh_names = list(_SSH_POOL.keys())
    else:
        ssh_names = names
    ssh_closed = await _close_ssh_sessions(ssh_names)
    return {
        "status": "ok",
        "closed": closed,
        "ssh_closed": ssh_closed,
        "still_open": list(_CLIENT_POOL.keys()),
        "ssh_still_open": list(_SSH_POOL.keys()),
        "note": f"{len(closed)} REST session(s) and {len(ssh_closed)} SSH session(s) closed.",
    }


# ══════════════════════════════════════════════════════════════════════
# TOOLS — SSH / CLI
# ══════════════════════════════════════════════════════════════════════

# When enabled (default), a read-only `show …` command that is already covered
# by a dedicated REST/MCP tool is REFUSED on the SSH/CLI escape hatches and the
# agent is redirected to the proper tool. This turns the "fallback only" docstring
# guidance into a hard, prompt-independent guarantee. Set CX_SSH_TOOL_REDIRECT
# to "false" to disable (pure docstring guidance only). Per-call override: force=True.
_SSH_TOOL_REDIRECT = os.getenv("CX_SSH_TOOL_REDIRECT", "true").strip().lower() in (
    "1", "true", "yes", "on",
)


def _dedicated_tool_for(command: str) -> str | None:
    """If a read-only 'show …' command is already covered by a dedicated tool,
    return that tool's name; otherwise None. Reuses the CLI→tool mapping so SSH,
    /cli and search stay consistent."""
    if not isinstance(command, str):
        return None
    normalized = " ".join(command.strip().lower().split())
    best, best_len = None, -1
    for prefix, tool in ArubaOSCXClient._CLI_REST_FALLBACKS:
        if (normalized == prefix or normalized.startswith(prefix + " ")) and len(prefix) > best_len:
            best, best_len = tool, len(prefix)
    return best


def _ssh_redirect_payload(tool: str, command: str) -> dict:
    """Build the 'use the dedicated tool instead of SSH' redirect."""
    return {
        "use_tool": tool,
        "command": command,
        "how": (
            f"A dedicated tool '{tool}' already covers this command — use it instead "
            f"of raw SSH. If '{tool}' is not in your visible tool list, it is a Tier-2 "
            f"tool: discover it with search_tools(query='{tool}'), then run it via "
            f"invoke_tool(name='{tool}', ...). To override and force raw SSH anyway, "
            f"call again with force=true."
        ),
    }


@mcp.tool()
async def run_ssh_command(device: str, command: str, force: bool = False) -> dict:
    """FALLBACK ONLY — use a dedicated tool if one exists, INCLUDING Tier-2 tools
    (discover them first with `search_tools`, then run them via `invoke_tool`).
    Only when no specific tool covers the need, run an arbitrary CLI command
    (e.g. 'show ...' not covered by REST) over SSH. Among the generic escape
    hatches, PREFER this over `run_cli_command` (the /cli REST path is limited).
    If the command is covered by a dedicated tool, this is REFUSED and you are
    redirected to that tool (pass force=true to override). Pagination disabled
    automatically. Call `logout` at the end."""
    if _SSH_TOOL_REDIRECT and not force:
        tool = _dedicated_tool_for(command)
        if tool:
            return {
                "device": device,
                "command": command,
                "ok": False,
                "redirect": True,
                "error": f"Use the dedicated tool '{tool}' instead of SSH for this command.",
                **_ssh_redirect_payload(tool, command),
            }
    try:
        if _is_ssh_write_command(command) and not _device_can_write(device):
            denied = _deny_read_only(device, "run_ssh_command")
            return {
                "device": denied["device"],
                "command": command,
                "ok": False,
                "error": denied["error"],
                "access_mode": denied["access_mode"],
            }
    except ValueError as exc:
        return {"device": device, "command": command, "ok": False, "error": str(exc)}
    try:
        output = await _ssh_exec(device, lambda c: c.run_command(command))
    except (ArubaSSHError, ValueError) as exc:
        return {"device": device, "command": command, "ok": False, "error": str(exc)}
    return {"device": device, "command": command, "ok": True, "output": output}


@mcp.tool()
async def run_ssh_commands(device: str, commands: list[str], force: bool = False) -> dict:
    """FALLBACK ONLY — use a dedicated tool if one exists, INCLUDING Tier-2 tools
    (discover them with `search_tools`, then run them via `invoke_tool`). Batch
    variant of `run_ssh_command`: only when no specific tool covers the need, run
    several CLI commands via SSH within a single session. Commands covered by a
    dedicated tool are REFUSED and redirected to that tool (pass force=true to
    override). Each command returns {command, output, ok, error}. Call `logout`
    at the end."""
    if not commands:
        return {"device": device, "ok": False, "error": "No command provided.", "results": []}
    if _SSH_TOOL_REDIRECT and not force:
        redirects = [
            _ssh_redirect_payload(tool, c)
            for c in commands
            if (tool := _dedicated_tool_for(c))
        ]
        if redirects:
            return {
                "device": device,
                "ok": False,
                "redirect": True,
                "error": ("One or more commands are covered by dedicated tools — use those "
                          "instead of SSH (pass force=true to override). See 'redirects'."),
                "redirects": redirects,
                "results": [],
            }
    try:
        blocked = [c for c in commands if _is_ssh_write_command(c)]
        if blocked and not _device_can_write(device):
            denied = _deny_read_only(device, "run_ssh_commands")
            return {
                "device": denied["device"],
                "ok": False,
                "error": denied["error"],
                "access_mode": denied["access_mode"],
                "blocked_commands": blocked,
                "results": [],
            }
    except ValueError as exc:
        return {"device": device, "ok": False, "error": str(exc), "results": []}
    try:
        results = await _ssh_exec(device, lambda c: c.run_commands(commands))
    except (ArubaSSHError, ValueError) as exc:
        return {"device": device, "ok": False, "error": str(exc), "results": []}
    failed = [r["command"] for r in results if not r["ok"]]
    return {
        "device": device,
        "ok": not failed,
        "results": results,
        "summary": {
            "total": len(results),
            "succeeded": len(results) - len(failed),
            "failed": len(failed),
            "failed_commands": failed,
        },
    }


# ══════════════════════════════════════════════════════════════════════
# TOOLS — System
# ══════════════════════════════════════════════════════════════════════

@mcp.tool()
async def get_system_info(device: str) -> dict:
    """System info + synthetic hardware status (modules, PSU, fans, sensors)."""
    async with _get_client(device) as client:
        return await client.get_system_info()


@mcp.tool()
async def get_hardware_health(device: str) -> dict:
    """Detailed hardware status: modules, PSU, fans, temperature sensors, LEDs,
    with the list of detected anomalies."""
    async with _get_client(device) as client:
        return await client.get_hardware_health()


@mcp.tool()
async def get_capacities(device: str) -> dict:
    """System resource capacities and their current consumption (grouped):
    `capacities` (scale/hardware limits) + `capacities_status` (amount currently
    consumed). Equivalent to CLI `show capacities` + `show capacities-status`.
    Returns a `utilization` list (most-used first, with utilization_pct) plus the
    raw `capacities` and `capacities_status` maps."""
    async with _get_client(device) as client:
        return await client.get_capacities()


@mcp.tool()
async def get_boot_history(device: str) -> dict:
    """Reboot history: per module (management_module, line_card), list of reboots
    (timestamp, reason, version), last boot and cause counters
    (reboot_statistics)."""
    async with _get_client(device) as client:
        return await client.get_boot_history()


@mcp.tool()
async def list_troubleshoot_features(device: str, feature_name: str = None) -> dict:
    """List the on-device troubleshoot features and their components (AOS-CX
    Troubleshoot API, firmware 10.18+). Source: the
    `troubleshoot_feature_components` resource. Each feature exposes components
    with the check types they support (basic health / config check / operations).
    Pass `feature_name` to inspect a single feature. Returns supported=False on
    firmware older than 10.18 (Troubleshoot is unavailable there)."""
    async with _get_client(device) as client:
        return await client.list_troubleshoot_features(feature_name)


@mcp.tool()
async def run_troubleshoot(
    device: str,
    feature_name: str,
    choice: str = "health",
    component_name: str = None,
    user_input: str = None,
    verbose: bool = False,
    timeout: float = 120.0,
) -> dict:
    """Run an on-device automated troubleshoot/diagnostic (AOS-CX Troubleshoot
    API, firmware 10.18+) and return the structured result.

    - `feature_name`: feature to troubleshoot — discover valid names via
      list_troubleshoot_features (e.g. 'l3', 'multicast', 'system').
    - `choice`: run depth — 'basic-health' (health checks only), 'config'
      (configuration checks), 'health' (basic + config, default), 'operations'
      or 'detailed' (advanced feature troubleshoot).
    - `component_name` / `user_input`: optional narrowing / extra context.
    - `verbose`: also return verbose logs and raw error reports.

    Launches the run (POST), polls until completion (or `timeout` seconds), then
    removes the volatile instance. Returns the alerts (basic / config / advanced,
    each with severity, root cause and recommendation) plus the health, config
    and troubleshoot text results. Returns supported=False on firmware older than
    10.18."""
    async with _get_client(device) as client:
        return await client.run_troubleshoot(
            feature_name,
            choice=choice,
            component_name=component_name,
            user_input=user_input,
            verbose=verbose,
            timeout=timeout,
        )


@mcp.tool()
async def get_ssh_config(device: str) -> dict:
    """SSH server config: global parameters (port, algos, allow-list) and, per VRF,
    the activation (ssh_enable/ssh_server_status) and the source-interface."""
    async with _get_client(device) as client:
        return await client.get_ssh_config()



@mcp.tool()
async def get_transceivers(device: str, interface: str = None) -> dict:
    """Transceiver status (SFP/QSFP): connector, vendor, optical diagnostics (DOM)
    and alarms. `interface` to target a port, otherwise all."""
    async with _get_client(device) as client:
        return await client.get_transceivers(interface)


# ══════════════════════════════════════════════════════════════════════
# TOOLS — Interfaces
# ══════════════════════════════════════════════════════════════════════

@mcp.tool()
async def get_interfaces(device: str, interface: str = None) -> dict:
    """List interfaces."""
    async with _get_client(device) as client:
        return await client.get_interfaces(interface)


@mcp.tool()
async def get_interface_counters(device: str, interface: str = None) -> dict:
    """Interface traffic counters: rx/tx bytes & packets, error counters
    (CRC/frame/runts/giants), drops and aggregate totals. `interface` to target a
    port, otherwise all."""
    async with _get_client(device) as client:
        return await client.get_interface_counters(interface)


@mcp.tool()
async def get_supported_transceivers(device: str, search: str = None) -> dict:
    """Catalog of transceivers (SFP/QSFP/DAC ...) supported by the device
    (`show supported-transceivers`). `search` filters by product number or
    description."""
    async with _get_client(device) as client:
        return await client.get_supported_transceivers(search)


@mcp.tool()
async def get_poe_status(device: str, interface: str = None) -> dict:
    """PoE (Power over Ethernet) status: per-port power draw (watts/current/
    voltage), powering state (delivering/searching/denied/fault/…), powered-
    device type/class, plus the chassis-wide PoE power budget (available/
    drawn/reserved/redundant/failover power, in watts, supplied by the PSUs).
    `interface` to target a single port, otherwise every PoE-capable port is
    scanned. Use this to answer 'how much power is this site/switch/port
    drawing over PoE'."""
    async with _get_client(device) as client:
        return await client.get_poe_status(interface)


@mcp.tool()
async def get_loopbacks(device: str) -> dict:
    """List the loopback interfaces (loopback0/1, …): VRF and IP addresses.
    Loopbacks are typically used as router-id and VTEP source."""
    async with _get_client(device) as client:
        return await client.get_loopbacks()


@mcp.tool()
async def get_routed_ports(device: str) -> dict:
    """List the routed (L3) ports: physical/LAG/sub-interfaces with routing
    enabled (point-to-point uplinks, L3 links). Excludes L2 switched ports,
    VLAN SVIs and loopbacks."""
    async with _get_client(device) as client:
        return await client.get_routed_ports()


@mcp.tool()
async def get_vlan_interfaces(device: str) -> dict:
    """List the VLAN interfaces / SVIs (vlanN): the L3 gateways of the VLANs,
    with their VRF and IP addresses."""
    async with _get_client(device) as client:
        return await client.get_vlan_interfaces()


@mcp.tool()
async def get_lag(device: str, lag: str = None) -> dict:
    """Link aggregation (LAG / port-channel) status — for STATIC and LACP bonds.
    Returns each LAG's mode (static / lacp-active / lacp-passive), aggregate
    speed and state, member count, and per-member LACP actor/partner flags
    (synchronization / collecting / distributing) to pinpoint a degraded member.
    `lag` optional (e.g. 'lag256' or '256') — omit for all LAGs."""
    async with _get_client(device) as client:
        return await client.get_lag(lag)


# ══════════════════════════════════════════════════════════════════════
# TOOLS — VLANs
# ══════════════════════════════════════════════════════════════════════

@mcp.tool()
async def get_vlans(device: str, vlan_id: int = None) -> dict:
    """List VLANs."""
    async with _get_client(device) as client:
        return await client.get_vlans(vlan_id)


# ══════════════════════════════════════════════════════════════════════
# TOOLS — LLDP
# ══════════════════════════════════════════════════════════════════════

@mcp.tool()
async def get_lldp_neighbors(device: str) -> dict:
    """Discover directly-connected neighbors via LLDP — THE tool to build a
    physical topology / cabling map or answer "what is connected to this switch".
    Returns, per local interface, the neighbor's system name (chassis_name),
    description (chassis_description), chassis id, remote port id/description,
    management IPs and advertised VLANs. For a whole site at once, prefer
    run_on_site(operation='get_lldp_neighbors'). Not related to system logs."""
    async with _get_client(device) as client:
        return await client.get_lldp_neighbors()


# ══════════════════════════════════════════════════════════════════════
# TOOLS — Routing
# ══════════════════════════════════════════════════════════════════════

@mcp.tool()
async def get_routing_table(device: str, vrf: str = "default") -> dict:
    """Routing table: vrf='default'/name for one VRF, 'all' for all. Each route:
    prefix, protocol, distance, metric, nexthops. Broken down by VRF and
    protocol."""
    async with _get_client(device) as client:
        return await client.get_routing_table(vrf)


# ══════════════════════════════════════════════════════════════════════
# TOOLS — Tables MAC / ARP
# ══════════════════════════════════════════════════════════════════════

@mcp.tool()
async def get_mac_table(device: str, vlan_id: int = None) -> dict:
    """MAC table."""
    async with _get_client(device) as client:
        return await client.get_mac_table(vlan_id)


@mcp.tool()
async def get_arp_table(device: str, vrf: str = "default") -> dict:
    """ARP table."""
    async with _get_client(device) as client:
        return await client.get_arp_table(vrf)


# ══════════════════════════════════════════════════════════════════════
# TOOLS — Logs
# ══════════════════════════════════════════════════════════════════════

@mcp.tool()
async def get_logs(device: str, limit: int = 50, priority: str = None) -> dict:
    """System event log (syslog) messages: timestamped events, warnings and errors
    from the switch. Use ONLY for event/incident history or troubleshooting a
    fault — NOT for topology, neighbors or cabling (use get_lldp_neighbors for
    that). priority: 0-7 or a range e.g. '0-3'."""
    async with _get_client(device) as client:
        return await client.get_logs(limit=limit, priority=priority)


# ══════════════════════════════════════════════════════════════════════
# TOOLS — Spanning Tree
# ══════════════════════════════════════════════════════════════════════

@mcp.tool()
async def get_spanning_tree(device: str) -> dict:
    """Spanning tree."""
    async with _get_client(device) as client:
        return await client.get_spanning_tree()


# ══════════════════════════════════════════════════════════════════════
# TOOLS — BGP
# ══════════════════════════════════════════════════════════════════════

@mcp.tool()
async def get_bgp_neighbors(device: str, vrf: str = "default") -> dict:
    """BGP neighbors."""
    async with _get_client(device) as client:
        return await client.get_bgp_neighbors(vrf)


@mcp.tool()
async def get_bgp_config(device: str, vrf: str = "default") -> dict:
    """BGP config."""
    async with _get_client(device) as client:
        return await client.get_bgp_config(vrf)


@mcp.tool()
async def get_bgp_routes(device: str, vrf: str = "default", address_family: str = "ipv4-unicast") -> dict:
    """BGP routes."""
    async with _get_client(device) as client:
        return await client.get_bgp_routes(vrf, address_family)


@mcp.tool()
async def get_bgp_neighbor_routes(device: str, vrf: str = "default", neighbor: str = None,
                                  address_family: str = "ipv4-unicast",
                                  direction: str = "all") -> dict:
    """BGP advertised / received routes per neighbor, with path attributes
    (AS-path, origin, local-pref, MED, flags). `direction`: advertised | received
    | all. `neighbor` filters to a single peer IP. Backs the CLI
    `show bgp <af> neighbors <ip> advertised-routes` / `received-routes`."""
    async with _get_client(device) as client:
        return await client.get_bgp_neighbor_routes(vrf, neighbor, address_family, direction)


# ══════════════════════════════════════════════════════════════════════
# TOOLS — OSPF
# ══════════════════════════════════════════════════════════════════════

@mcp.tool()
async def get_ospf_overview(device: str, vrf: str = "default") -> dict:
    """OSPF overview."""
    async with _get_client(device) as client:
        return await client.get_ospf_overview(vrf)


@mcp.tool()
async def get_ospf_neighbors(device: str, vrf: str = "default") -> dict:
    """OSPF neighbors."""
    async with _get_client(device) as client:
        return await client.get_ospf_neighbors(vrf)


@mcp.tool()
async def get_ospf_interfaces(device: str, vrf: str = "default") -> dict:
    """OSPF interfaces."""
    async with _get_client(device) as client:
        return await client.get_ospf_interfaces(vrf)


# ══════════════════════════════════════════════════════════════════════
# TOOLS — CLI
# ══════════════════════════════════════════════════════════════════════

@mcp.tool()
async def get_cli_supported_commands(device: str) -> dict:
    """Try to list the CLI commands (GET /cli rarely supported; prefer run_cli_command)."""
    async with _get_client(device) as client:
        commands = await client.get_cli_supported_commands()
    return {
        "device": device,
        "supported_commands": commands,
        "count": len(commands),
        "note": "GET /cli is not supported by most ArubaOS-CX firmwares. Use run_cli_command with a 'show' command." if not commands else None,
    }


@mcp.tool()
async def run_cli_command(device: str, command: str, force: bool = False) -> dict:
    """LAST-RESORT FALLBACK — use a dedicated tool if one exists, INCLUDING Tier-2
    tools (discover them with `search_tools`, then run them via `invoke_tool`),
    and PREFER `run_ssh_command` over this. Use the /cli REST endpoint for 'show'
    commands ONLY when SSH is unavailable (e.g. only REST/443 reachable, port 22
    blocked). /cli is limited and refuses many commands. If the command is covered
    by a dedicated tool, this is REFUSED and you are redirected to it (pass
    force=true to override). If not executable, returns supported=False with
    'fallback_tool' (equivalent REST tool)."""
    if not command.strip().lower().startswith("show"):
        raise ValueError("Only 'show' commands are allowed.")
    if _SSH_TOOL_REDIRECT and not force:
        tool = _dedicated_tool_for(command)
        if tool:
            return {
                "device": device,
                "command": command,
                "supported": False,
                "ok": False,
                "redirect": True,
                "error": f"Use the dedicated tool '{tool}' instead of /cli for this command.",
                **_ssh_redirect_payload(tool, command),
            }
    async with _get_client(device) as client:
        return await client.run_cli_command(command)


# ══════════════════════════════════════════════════════════════════════
# TOOLS — EVPN
# ══════════════════════════════════════════════════════════════════════

@mcp.tool()
async def get_evpn_config(device: str, vni_id: int = None) -> dict:
    """EVPN config."""
    async with _get_client(device) as client:
        return await client.get_evpn_config(vni_id)


@mcp.tool()
async def get_evpn_routes(device: str, vrf: str = "default", route_type: int = None) -> dict:
    """EVPN routes."""
    async with _get_client(device) as client:
        return await client.get_evpn_routes(vrf, route_type)


@mcp.tool()
async def get_evpn_multihoming(device: str) -> dict:
    """EVPN multihoming (RFC 7432 Ethernet Segments): global multihoming-system-id
    plus, per Ethernet Segment, its ESI, mode (all-active), operational status,
    RD/import-RT, ES port, local/peer VTEPs and the per-VLAN Designated Forwarder
    election (which VTEP is the DF for each EVPN VLAN). Returns configured=False
    (no error) when the feature is not supported/configured."""
    async with _get_client(device) as client:
        return await client.get_evpn_multihoming()



# ══════════════════════════════════════════════════════════════════════
# TOOLS — VXLAN
# ══════════════════════════════════════════════════════════════════════

@mcp.tool()
async def get_vxlan_config(device: str) -> dict:
    """VXLAN config."""
    async with _get_client(device) as client:
        return await client.get_vxlan_config()


@mcp.tool()
async def get_vxlan_tunnels(device: str) -> dict:
    """Established VXLAN tunnels (EVPN + static) with traffic statistics."""
    async with _get_client(device) as client:
        return await client.get_vxlan_tunnels()


@mcp.tool()
async def get_vxlan_static_peers(device: str) -> dict:
    """Statically configured VXLAN peers (ingress replication list)."""
    async with _get_client(device) as client:
        return await client.get_vxlan_static_peers()


@mcp.tool()
async def get_evpn_vtep_neighbors(device: str, vrf: str = "default") -> dict:
    """VTEP neighbors learned dynamically via EVPN."""
    async with _get_client(device) as client:
        return await client.get_evpn_vtep_neighbors(vrf)


# ══════════════════════════════════════════════════════════════════════
# TOOLS — VSX (Virtual Switching Extension)
# ══════════════════════════════════════════════════════════════════════

@mcp.tool()
async def get_vsx_status(device: str) -> dict:
    """VSX status and member details (roles, system-mac, ISL, keepalive, peer).
    If VSX is not supported/configured, returns configured=False (no error)."""
    async with _get_client(device) as client:
        return await client.get_vsx_status()


@mcp.tool()
async def get_vsx_config(device: str) -> dict:
    """VSX configuration: role, system-mac, ISL and keepalive ports, timers, options.
    If VSX is not supported/configured, returns configured=False (no error)."""
    async with _get_client(device) as client:
        return await client.get_vsx_config()


@mcp.tool()
async def get_vsx_sync(device: str) -> dict:
    """Elements synchronized between VSX cluster members (vsx-sync).
    If VSX is not supported/configured, returns configured=False (no error)."""
    async with _get_client(device) as client:
        return await client.get_vsx_sync()


# ══════════════════════════════════════════════════════════════════════
# TOOLS — VSF (Virtual Switching Framework / stacking)
# ══════════════════════════════════════════════════════════════════════

@mcp.tool()
async def get_vsf_status(device: str) -> dict:
    """VSF stack status: members (role, status, memory), stack links, topology
    (ring/chain/standalone) and split detection. A single member = standalone."""
    async with _get_client(device) as client:
        return await client.get_vsf_status()


@mcp.tool()
async def get_vsf_config(device: str) -> dict:
    """VSF config: members (role, status, links), topology and split detection
    (method, secondary_member, traps). A single member = standalone."""
    async with _get_client(device) as client:
        return await client.get_vsf_config()


# ══════════════════════════════════════════════════════════════════════
# TOOLS — Maintenance Mode
# ══════════════════════════════════════════════════════════════════════

@mcp.tool()
async def get_maintenance_mode(device: str) -> dict:
    """Maintenance Mode status: configured or not, active or not, applied profiles
    and units (BGP/OSPF feature-sets) under maintenance."""
    async with _get_client(device) as client:
        return await client.get_maintenance_mode()


# ══════════════════════════════════════════════════════════════════════
# TOOLS — Containers (on-switch application hosting)
# ══════════════════════════════════════════════════════════════════════

@mcp.tool()
async def get_containers(device: str, name: str = None) -> dict:
    """On-switch application containers: per container the enable flag, runtime
    `status`, `image_status`/version/location, manifest status, CPU/memory limits
    and attached VRF networks. Optional `name` to target one container. Returns
    supported=False (no error) when the container feature is absent."""
    async with _get_client(device) as client:
        return await client.get_containers(name)


# ══════════════════════════════════════════════════════════════════════
# TOOLS — Licensing (feature pack)
# ══════════════════════════════════════════════════════════════════════

@mcp.tool()
async def get_feature_pack(device: str) -> dict:
    """Licensing / feature-pack (subscription) state: installed pack name, type,
    management mode (cloud_managed/file_based/honor), validity `state`, expiration,
    designated platform/serials, and per-feature enforcement mode/state
    (active/strict/honor). Returns supported=False (no error) when licensing is
    not available on the platform/firmware."""
    async with _get_client(device) as client:
        return await client.get_feature_pack()


# ══════════════════════════════════════════════════════════════════════
# TOOLS — Aruba Central (HPE ANW Central) cloud management
# ══════════════════════════════════════════════════════════════════════

@mcp.tool()
async def get_aruba_central(device: str) -> dict:
    """HPE ANW Central (formerly Aruba Central) cloud-management state: whether the
    switch is connected, instantiation (public/on_premise), config source
    (cli/activate/dhcp), connected location, VRF and source IP used, plus
    operational status (connection state, disconnection reason, Activate
    connectivity). Returns supported=False (no error) when Central is not
    available on the platform/firmware."""
    async with _get_client(device) as client:
        return await client.get_aruba_central()




# ══════════════════════════════════════════════════════════════════════
# TOOLS — NAE (Network Analytics Engine)
# ══════════════════════════════════════════════════════════════════════

@mcp.tool()
async def get_nae_scripts(device: str) -> dict:
    """List of installed NAE scripts with validation status and number of agents."""
    async with _get_client(device) as client:
        return await client.get_nae_scripts()


@mcp.tool()
async def get_nae_script(device: str, name: str, include_script: bool = False) -> dict:
    """NAE script detail (checksum, validation, errors). include_script=True
    includes the decoded content.
    """
    async with _get_client(device) as client:
        return await client.get_nae_script(name, include_script=include_script)


@mcp.tool()
async def get_nae_agents(device: str, script: str = None) -> dict:
    """NAE agents (policies) with state, alert level and errors. Filterable by script."""
    async with _get_client(device) as client:
        return await client.get_nae_agents(script)


@mcp.tool()
async def get_nae_agent(device: str, script: str, agent: str) -> dict:
    """Full detail of a NAE agent: status, alerts, errors, statistics, monitors, rules."""
    async with _get_client(device) as client:
        return await client.get_nae_agent(script, agent)


# ══════════════════════════════════════════════════════════════════════
# TOOLS — Port-Access (802.1X / MAC-Auth)
# ══════════════════════════════════════════════════════════════════════

@mcp.tool()
async def get_port_access_clients(
    device: str,
    interface: str = None,
    auth_method: str = None,
    status: str = None,
) -> dict:
    """Port-access clients: authentication status, method (802.1X/MAC-Auth/
    Web-Auth), applied role, assigned VLAN and RADIUS server."""
    async with _get_client(device) as client:
        return await client.get_port_access_clients(
            interface=interface, auth_method=auth_method, status=status
        )


@mcp.tool()
async def get_port_access_auth_config(device: str, interface: str = None) -> dict:
    """Per-port authentication config: configured methods (802.1X/MAC-Auth/
    Web-Auth), activation, reauth and RADIUS group — even without a connected
    client. `interface` to target a port."""
    async with _get_client(device) as client:
        return await client.get_port_access_auth_config(interface=interface)



@mcp.tool()
async def get_port_access_summary(device: str) -> dict:
    """Port-access summary."""
    async with _get_client(device) as client:
        return await client.get_port_access_summary()


@mcp.tool()
async def get_port_access_client_detail(device: str, interface: str, mac: str) -> dict:
    """Full detail of an authenticated client: VLAN, role, RADIUS attributes,
    failure reason, EAP method, 802.1X stats. `interface` (e.g. '1/1/5'), `mac`.
    """
    async with _get_client(device) as client:
        return await client.get_port_access_client_detail(interface, mac)


# ══════════════════════════════════════════════════════════════════════
# TOOLS — RADIUS / TACACS+ / AAA
# ══════════════════════════════════════════════════════════════════════

@mcp.tool()
async def get_radius_servers(device: str, vrf: str = None) -> dict:
    """RADIUS servers: address, port, reachability, group, tracking, auth/accounting
    stats. By default searches ALL VRFs (servers are usually in the mgmt VRF);
    pass `vrf` only to restrict to a single VRF.
    """
    async with _get_client(device) as client:
        return await client.get_radius_servers(vrf)


@mcp.tool()
async def get_tacacs_servers(device: str, vrf: str = None) -> dict:
    """TACACS+ servers: address, TCP port, reachability, group, auth stats. By
    default searches ALL VRFs (servers are usually in the mgmt VRF); pass `vrf`
    only to restrict to a single VRF.
    """
    async with _get_client(device) as client:
        return await client.get_tacacs_servers(vrf)


@mcp.tool()
async def get_aaa_authentication(device: str) -> dict:
    """AAA config: server groups and lookup order per session type
    (802.1x, MAC-auth, mgmt…) for auth/authz/accounting.
    """
    async with _get_client(device) as client:
        return await client.get_aaa_authentication()


@mcp.tool()
async def get_aaa_accounting(device: str, with_logs: bool = False, limit: int = 50) -> dict:
    """AAA accounting config per session type. with_logs=True includes the latest
    logs (limit, default 50).
    """
    async with _get_client(device) as client:
        return await client.get_aaa_accounting(with_logs=with_logs, limit=limit)


# ══════════════════════════════════════════════════════════════════════
# TOOLS — Port-Access Policies / Roles
# ══════════════════════════════════════════════════════════════════════

@mcp.tool()
async def get_port_access_policies(device: str, policy_name: str = None) -> dict:
    """Port Access Policies: rules (QoS, ACL, redirection) applied to clients.
    `policy_name` for the detail of a policy.
    """
    async with _get_client(device) as client:
        return await client.get_port_access_policies(policy_name)


@mcp.tool()
async def get_port_access_roles(device: str, role_name: str = None) -> dict:
    """Port Access Roles: profiles assigned to clients (VLAN, QoS, reauth, policy,
    captive portal…). `role_name` for the full detail.
    """
    async with _get_client(device) as client:
        return await client.get_port_access_roles(role_name)


# ══════════════════════════════════════════════════════════════════════
# TOOLS — GBP / ABP / App Recognition
# ══════════════════════════════════════════════════════════════════════

@mcp.tool()
async def get_port_access_gbps(device: str, gbp_name: str = None) -> dict:
    """Group-Based Policies: policies between groups (SGT/GBP tag). `gbp_name` for
    the detail (class/drop/reflect entries, stats).
    """
    async with _get_client(device) as client:
        return await client.get_port_access_gbps(gbp_name)


@mcp.tool()
async def get_gbp_role_maps(device: str) -> dict:
    """Mapping GBP role name ↔ role-id (interprets the SGT/GBP tags of clients).
    """
    async with _get_client(device) as client:
        return await client.get_gbp_role_maps()


@mcp.tool()
async def get_port_access_abps(device: str, abp_name: str = None) -> dict:
    """Application-Based Policies (ABP): policies based on ARC (QoS, drop,
    mirroring per application). `abp_name` for the detail (entries, stats).
    """
    async with _get_client(device) as client:
        return await client.get_port_access_abps(abp_name)


@mcp.tool()
async def get_app_recognition(device: str, include_apps: bool = False) -> dict:
    """ARC (Application Recognition and Control): status, detection mode, ABP
    session limit. include_apps=True adds the list of applications (large).
    """
    async with _get_client(device) as client:
        return await client.get_app_recognition(include_apps=include_apps)


@mcp.tool()
async def get_app_visibility(
    device: str,
    top_n: int = 10,
    include_flows: bool = True,
    include_monitors: bool = True,
) -> dict:
    """Application visibility collector (Traffic Insight + ARC), 100% via REST API
    (no SSH). First checks the prerequisites — App Recognition (ARC) active and
    operational, Traffic Insight enabled, ARC applied on interfaces or
    user-roles — then collects the application flows and returns the top talkers
    (by client, destination, application, category) as well as the TopN reports
    of the Traffic Insight monitors. The `blockers` field details any missing prerequisite.

    top_n: number of entries per ranking. include_flows / include_monitors:
    enable collection of application flows and TopN monitors respectively.
    """
    async with _get_client(device) as client:
        return await client.get_app_visibility(
            top_n=top_n,
            include_flows=include_flows,
            include_monitors=include_monitors,
        )


# ══════════════════════════════════════════════════════════════════════
# TOOLS — Configuration
# ══════════════════════════════════════════════════════════════════════

@mcp.tool()
async def list_configs(device: str) -> dict:
    """List the available configs: running-config, startup-config, checkpoints."""
    async with _get_client(device) as client:
        return await client.list_configs()


@mcp.tool()
async def compare_configs(
    device: str,
    config_a: str = "running-config",
    config_b: str = "startup-config",
    color: bool = True,
    context_lines: int = 3,
) -> dict:
    """Compare two configs (unified diff). config_a/config_b: 'running-config',
    'startup-config' or checkpoint. `color` (ANSI), `context_lines`.
    """
    async with _get_client(device) as client:
        return await client.compare_configs(
            config_a=config_a,
            config_b=config_b,
            color=color,
            context_lines=context_lines,
        )


@mcp.tool()
async def get_config(
    device: str,
    name: str = "running-config",
    diff: str = None,
    mode: str = None,
) -> dict:
    """CLI config (text). `name`: running-config/startup-config/checkpoint. `diff`
    to compare name against this config. `mode`: additions/deletions/shell.
    """
    async with _get_client(device) as client:
        return await client.get_config(name=name, diff=diff, mode=mode)


@mcp.tool()
async def get_full_config(device: str, name: str = "running-config") -> dict:
    """Full config in JSON (REST format), for structural analysis. `name`:
    running-config/startup-config/checkpoint.
    """
    async with _get_client(device) as client:
        return await client.get_full_config(name=name)


@mcp.tool()
async def manage_config(
    device: str,
    action: str,
    name: str = None,
    source: str = "running-config",
    target: str = "running-config",
    from_config: str = None,
    to_config: str = None,
    config_a: str = None,
    config_b: str = None,
    minutes: int = 10,
    mode: str = None,
) -> dict:
    """Config management (checkpoints, backup, copy, restore, diff).
    `action`:
      - list_checkpoints: list the checkpoints (date, age, author, version).
      - write_memory: running-config → startup-config ("write memory").
      - create_checkpoint: snapshot named `name` from `source` (name must not exist).
      - copy_config: `from_config` → `to_config` (running/startup/checkpoint, src≠dst).
      - restore_checkpoint: restore `name` to `target` (running [default]/startup).
      - auto_checkpoint: arm a confirmed commit (`minutes` 1–60, default 10);
        without `confirm` before the deadline, automatic return to the previous config.
      - confirm: validate the auto checkpoint in progress.
      - diff: compare `config_a`/`config_b` (`mode='deep'` for firmware diff).
    """
    action = (action or "").strip().lower()
    write_actions = {
        "write_memory",
        "create_checkpoint",
        "copy_config",
        "restore_checkpoint",
        "auto_checkpoint",
        "confirm",
    }
    if action in write_actions and not _device_can_write(device):
        return _deny_read_only(device, f"manage_config:{action}")
    async with _get_client(device) as client:
        if action == "list_checkpoints":
            return await client.list_checkpoints()

        if action == "write_memory":
            return await client.save_config()

        if action == "create_checkpoint":
            if not name:
                return {"status": "error", "error": "The 'name' parameter (checkpoint name) is required."}
            return await client.create_checkpoint(name=name, source=source)

        if action == "copy_config":
            if not from_config or not to_config:
                return {"status": "error",
                        "error": "The 'from_config' and 'to_config' parameters are required."}
            return await client.copy_config(from_config=from_config, to_config=to_config)

        if action == "restore_checkpoint":
            if not name:
                return {"status": "error", "error": "The 'name' parameter (checkpoint to restore) is required."}
            return await client.restore_checkpoint(name=name, target=target)

        if action == "auto_checkpoint":
            return await client.set_auto_checkpoint(minutes=minutes)

        if action == "confirm":
            return await client.confirm_auto_checkpoint()

        if action == "diff":
            a = config_a or "running-config"
            b = config_b or "startup-config"
            if mode == "deep":
                # Native structural diff of the firmware (CLI text), via /configs/{a}?diff=...
                return await client.get_config(name=a, diff=client._uri(f"/configs/{b}"), mode="deep")
            return await client.compare_configs(config_a=a, config_b=b)

        return {
            "status": "error",
            "error": f"Unknown action: '{action}'.",
            "available_actions": [
                "list_checkpoints", "write_memory", "create_checkpoint", "copy_config",
                "restore_checkpoint", "auto_checkpoint", "confirm", "diff",
            ],
        }


@mcp.tool()
async def backup_config(
    device: str = None,
    site: str = None,
    protocol: str = "sftp",
    server: str = None,
    remote_directory: str = None,
    filename_format: str = None,
    source: str = "running-config",
) -> dict:
    """Export a configuration backup campaign to a configured SFTP or TFTP server.

    Target one `device` or every device in `site`. `server` must match the
    configured `CX_BACKUP_<PROTOCOL>_HOST` when that variable is set. `protocol`
    is sftp (default) or tftp. `source` is
    running-config (default) or startup-config. `filename_format` supports only
    `{hostname}` and `{timestamp}`; default: `{hostname}_{timestamp}_config.cfg`.
    SFTP credentials are read only from CX_BACKUP_SFTP_* environment variables;
    TFTP does not use credentials.
    """
    protocol = (protocol or "sftp").strip().lower()
    if protocol not in ("sftp", "tftp"):
        return {"status": "invalid_input", "field": "protocol",
                "error": "protocol must be 'sftp' or 'tftp'."}
    if source not in ("running-config", "startup-config"):
        return {
            "status": "invalid_input",
            "field": "source",
            "error": "source must be 'running-config' or 'startup-config'.",
        }
    try:
        device_names = _resolve_devices(device=device, site=site)
    except ValueError as exc:
        return {"status": "invalid_input", "error": str(exc)}

    async def _backup_one(name: str) -> tuple[str, dict]:
        try:
            async with _get_client(name) as client:
                config = await client.get_config(name=source)
                hostname = name
                try:
                    system = await client.get_system_info()
                    hostname = system.get("hostname") or name
                except Exception:  # noqa: BLE001 - inventory name is a safe fallback
                    pass
                exported = await export_config(
                    protocol=protocol,
                    server=server,
                    remote_directory=remote_directory,
                    filename_format=filename_format,
                    hostname=str(hostname),
                    content=config["content"],
                )
            return name, {"ok": True, "source": source, **exported}
        except (ConfigBackupError, ArubaAPIError, KeyError) as exc:
            return name, {"ok": False, "error": str(exc)}
        except Exception as exc:  # noqa: BLE001 - one target must not stop a campaign
            return name, {"ok": False, "error": str(exc)}

    results = dict(await asyncio.gather(*[_backup_one(name) for name in device_names]))
    failed = [name for name, result in results.items() if not result["ok"]]
    return {
        "status": "exported" if not failed else "partial",
        "protocol": protocol,
        "source": source,
        "targets": device_names,
        "results": results,
        "summary": {
            "total": len(device_names),
            "succeeded": len(device_names) - len(failed),
            "failed": len(failed),
            "failed_devices": failed,
        },
    }


# ══════════════════════════════════════════════════════════════════════
# TOOLS — Debug / raw API
# ══════════════════════════════════════════════════════════════════════

@mcp.tool()
async def get_raw_api(device: str, path: str, depth: int = 2) -> dict:
    """Raw API call."""
    async with _get_client(device) as client:
        return await client.get_raw_api(path, depth)


# ══════════════════════════════════════════════════════════════════════
# TOOLS — Service provisioning (VLAN creation)
# ══════════════════════════════════════════════════════════════════════

def _match_inventory_device(system_name: str, mgmt_addr: str) -> str | None:
    """Match an LLDP neighbor (system-name / management address) to an inventory
    device. Returns its name, or None."""
    for name, dev in _devices.items():
        if system_name and (system_name.lower() == name.lower()
                            or name.lower() in system_name.lower()
                            or system_name.lower() in name.lower()):
            return name
        if mgmt_addr and dev.host and dev.host in str(mgmt_addr):
            return name
    return None


async def _gather_fabric_contexts(device_names: list[str]) -> dict:
    """Retrieve the fabric context of each target device in parallel."""
    async def _one(name: str):
        try:
            async with _get_client(name) as client:
                return name, {"ok": True, "ctx": await client.get_fabric_context()}
        except Exception as exc:  # noqa: BLE001
            return name, {"ok": False, "error": str(exc)}
    results = await asyncio.gather(*[_one(n) for n in device_names])
    return dict(results)


def _aggregate_fabric_context(ctxs: list[dict]) -> dict:
    """
    Aggregate the context of several VTEPs to make the deductions more reliable
    (a single reference VTEP is misleading: VNI/RT/MAC conventions vary).

    - vni_offset: kept only if ALL VTEPs agree on a single value.
    - vni_by_vlan: union (allows reusing a VNI already assigned to this VLAN).
    - rt_template: union of the distinct (admin, source) pairs (de-duplicated).
    - active_gateway_mac: the most frequent MAC.
    """
    from collections import Counter
    offsets: set = set()
    vni_by_vlan: dict = {}
    rt_pairs: list = []
    gw_macs: Counter = Counter()
    bgp_asn = None
    vxlan_iface = "vxlan1"
    for c in ctxs:
        if c.get("vni_offset") is not None:
            offsets.add(c["vni_offset"])
        vni_by_vlan.update(c.get("vni_by_vlan") or {})
        for entry in (c.get("rt_template") or []):
            pair = (entry["admin"], entry["source"])
            if pair not in rt_pairs:
                rt_pairs.append(pair)
        if c.get("active_gateway_mac"):
            gw_macs[c["active_gateway_mac"]] += 1
        if c.get("bgp_asn") and bgp_asn is None:
            bgp_asn = c["bgp_asn"]
        if c.get("vxlan_interface"):
            vxlan_iface = c["vxlan_interface"]
    return {
        "vni_offset": offsets.pop() if len(offsets) == 1 else None,
        "vni_by_vlan": {int(k): int(v) for k, v in vni_by_vlan.items()},
        "rt_template": [{"admin": a, "source": s} for a, s in rt_pairs] or None,
        "active_gateway_mac": gw_macs.most_common(1)[0][0] if gw_macs else None,
        "bgp_asn": bgp_asn,
        "vxlan_interface": vxlan_iface,
    }



@mcp.tool()
async def create_vlan_service(
    vlan_id: int,
    name: str = None,
    devices: list[str] = None,
    site: str = None,
    network_type: str = None,
    vni: int = None,
    gateway: str = None,
    gateway_mac: str = None,
    vrf: str = None,
    import_route_targets: list = None,
    export_route_targets: list = None,
    tag_uplinks: bool = True,
    apply: bool = False,
) -> dict:
    """Create a VLAN service, adapting to the network type (auto-detection unless
    `network_type` is forced):
      - VXLAN/EVPN fabric (VTEP): VLAN + L2VNI + deduced Route-Targets, and if
        `gateway` is provided, the SVI with anycast active-gateway. Without
        `devices`, all the VTEPs (filterable by `site`).
      - Traditional (non-VTEP): VLAN + tagged addition on the LLDP uplinks (also
        created on the upstream inventory switch).

    Params: `vlan_id` (required), `name` (default VLAN<id>), `devices`/`site` (targets),
    `vni` (deduced if omitted), `gateway` (anycast IP/CIDR; otherwise pure L2), `vrf`
    (required if `gateway`), `gateway_mac`/`import_route_targets`/`export_route_targets`
    (deduced if omitted), `apply` (False=plan only, True=applies).

    If information is missing, returns status='need_info' with `questions`.
    """
    # 1. Resolve the candidate targets
    try:
        if devices:
            candidates = []
            for d in devices:
                candidates.extend(_resolve_devices(device=d, site=site))
        elif site:
            candidates = _resolve_devices(site=site)
        else:
            candidates = list(_devices.keys())
    except ValueError as exc:
        return {"status": "error", "error": str(exc)}

    if not candidates:
        return {"status": "error", "error": "No resolved target device."}

    if apply:
        denied = _deny_read_only_many(candidates, "create_vlan_service")
        if denied:
            return denied

    # 2. Detect the network type (unless forced)
    contexts = await _gather_fabric_contexts(candidates)
    reachable = {n: r["ctx"] for n, r in contexts.items() if r.get("ok")}
    unreachable = {n: r["error"] for n, r in contexts.items() if not r.get("ok")}
    vtep_devices = [n for n, c in reachable.items() if c.get("fabric")]

    if network_type not in (None, "fabric", "traditional"):
        return {"status": "error",
                "error": "network_type must be 'fabric', 'traditional' or omitted."}

    if network_type is None:
        detected = "fabric" if vtep_devices else "traditional"
    else:
        detected = network_type

    if detected == "fabric":
        result = await _provision_fabric_service(
            vlan_id=vlan_id, name=name, explicit_devices=devices, site=site,
            candidates=candidates, reachable=reachable, vtep_devices=vtep_devices,
            unreachable=unreachable, vni=vni, gateway=gateway, gateway_mac=gateway_mac,
            vrf=vrf, import_rts=import_route_targets, export_rts=export_route_targets,
            apply=apply,
        )
    else:
        result = await _provision_traditional_service(
            vlan_id=vlan_id, name=name, targets=candidates, unreachable=unreachable,
            tag_uplinks=tag_uplinks, apply=apply,
        )

    # End of workflow: close the sessions opened on the targeted devices.
    await _close_sessions(candidates)
    # Preview of a write -> freeze a replayable dry_run_token (no-op if disabled).
    if (not apply and write_safety is not None and isinstance(result, dict)
            and result.get("status") == "planned"):
        try:
            write_safety.freeze_recipe(
                result, "create_vlan_service",
                result.get("targets") or [], result.get("plan") or {},
                tool="create_vlan_service",
                arguments=dict(
                    vlan_id=vlan_id, name=name, devices=devices, site=site,
                    network_type=network_type, vni=vni, gateway=gateway,
                    gateway_mac=gateway_mac, vrf=vrf,
                    import_route_targets=import_route_targets,
                    export_route_targets=export_route_targets,
                    tag_uplinks=tag_uplinks,
                ),
            )
        except Exception:
            logger.exception("freeze_recipe failed for create_vlan_service")
    return result


async def _provision_fabric_service(*, vlan_id, name, explicit_devices, site, candidates,
                                    reachable, vtep_devices, unreachable, vni, gateway,
                                    gateway_mac, vrf, import_rts, export_rts, apply) -> dict:
    # Target = explicitly requested VTEPs, otherwise all reachable VTEPs
    if explicit_devices:
        targets = [d for d in candidates if d in vtep_devices]
        non_vtep = [d for d in candidates if d in reachable and d not in vtep_devices]
    else:
        targets = vtep_devices
        non_vtep = []
    if not targets:
        return {"status": "error",
                "error": "No reachable VTEP among the targets.",
                "unreachable": unreachable}

    # Aggregated context of ALL target VTEPs (a single reference VTEP is misleading)
    ref_ctx = _aggregate_fabric_context([reachable[t] for t in targets])

    # VNI deduction
    questions: list[dict] = []
    eff_vni = vni
    if eff_vni is None:
        existing_vni = ref_ctx["vni_by_vlan"].get(vlan_id)
        offset = ref_ctx.get("vni_offset")
        if existing_vni is not None:
            eff_vni = existing_vni  # VLAN already mapped on the fabric: reuse its VNI
        elif offset is not None:
            eff_vni = vlan_id + offset
        else:
            questions.append({
                "key": "vni",
                "question": f"Which L2 VNI to use for VLAN {vlan_id}? "
                            "(the VTEPs do not use a homogeneous VLAN→VNI offset, "
                            "automatic deduction is impossible)",
            })


    # Route-Target deduction
    eff_import = import_rts
    eff_export = export_rts
    if (eff_import is None or eff_export is None) and eff_vni is not None:
        from aruba_client import ArubaOSCXClient as _Cli
        deduced = _Cli.deduce_route_targets(ref_ctx.get("rt_template"), vlan_id,
                                            eff_vni, ref_ctx.get("bgp_asn"))
        eff_import = eff_import or deduced
        eff_export = eff_export or deduced

    # Active-gateway (optional)
    eff_gw_mac = gateway_mac
    if gateway:
        if not vrf:
            questions.append({
                "key": "vrf",
                "question": f"In which VRF to place the SVI interface vlan{vlan_id} "
                            f"(active-gateway {gateway})?",
            })
        if not eff_gw_mac:
            eff_gw_mac = ref_ctx.get("active_gateway_mac")
            if not eff_gw_mac:
                questions.append({
                    "key": "gateway_mac",
                    "question": "Which active-gateway MAC to use? "
                                "(no common MAC found on the existing SVIs)",
                })

    if questions:
        return {
            "status": "need_info",
            "network_type": "fabric",
            "service": {"vlan": vlan_id, "vni": eff_vni},
            "targets": targets,
            "questions": questions,
        }

    # Build the plan
    svc_name = name or f"VLAN{vlan_id}"
    steps_template = [
        {"action": "create_vlan", "vlan": vlan_id, "name": svc_name},
        {"action": "create_l2vni", "vni": eff_vni, "vlan": vlan_id,
         "vxlan_interface": ref_ctx.get("vxlan_interface", "vxlan1")},
        {"action": "set_evpn_vlan_rt", "vlan": vlan_id,
         "import_route_targets": eff_import, "export_route_targets": eff_export},
    ]
    if gateway:
        steps_template.append({
            "action": "create_svi", "vlan": vlan_id, "vrf": vrf,
            "ip4_address": gateway, "active_gateway_ip": gateway,
            "active_gateway_mac": eff_gw_mac,
        })

    plan = {dev: steps_template for dev in targets}
    service = {
        "vlan": vlan_id, "name": svc_name, "network_type": "fabric", "vni": eff_vni,
        "import_route_targets": eff_import, "export_route_targets": eff_export,
        "gateway": gateway, "vrf": vrf, "active_gateway_mac": eff_gw_mac,
    }
    if not apply:
        return {"status": "planned", "service": service, "targets": targets,
                "plan": plan, "apply": False, "unreachable": unreachable,
                "ignored_non_vtep": non_vtep,
                "note": "Preview only. Re-run with apply=true to apply."}

    # Application — with automatic per-device rollback on a mid-course failure
    # (only what THIS pass actually created is undone).
    async def _apply_one(dev: str):
        steps_done = []
        try:
            async with _get_client(dev) as client:
                steps_done.append(await client.create_vlan(vlan_id, svc_name))
                steps_done.append(await client.create_l2vni(
                    eff_vni, vlan_id, ref_ctx.get("vxlan_interface", "vxlan1")))
                steps_done.append(await client.set_evpn_vlan_rt(
                    vlan_id, eff_import, eff_export))
                if gateway:
                    steps_done.append(await client.create_svi(
                        vlan_id, vrf, gateway, active_gateway_ip=gateway,
                        active_gateway_mac=eff_gw_mac))
            return dev, {"ok": True, "steps": steps_done}
        except Exception as exc:  # noqa: BLE001
            # Best-effort rollback of what this pass created on this device.
            rb_report = await _rollback_fabric(dev, vlan_id, eff_vni, steps_done, gateway)
            return dev, {"ok": False, "error": str(exc), "steps": steps_done,
                         "rolled_back": rb_report}

    results = dict(await asyncio.gather(*[_apply_one(d) for d in targets]))
    failed = [d for d, r in results.items() if not r["ok"]]
    return {
        "status": "applied" if not failed else "partial",
        "service": service, "targets": targets, "apply": True,
        "results": results, "unreachable": unreachable, "ignored_non_vtep": non_vtep,
        "summary": {"total": len(targets), "succeeded": len(targets) - len(failed),
                    "failed": len(failed), "failed_devices": failed},
    }


async def _rollback_fabric(dev: str, vlan_id: int, vni: int, steps_done: list,
                           gateway: str | None) -> list:
    """
    Undo (best-effort) a partially applied fabric service on a device.
    Only the objects that this pass actually created (status='created' in
    steps_done) are deleted, in reverse order of creation.
    """
    created = {s.get("status"): s for s in steps_done}
    report: list = []
    try:
        async with _get_client(dev) as client:
            # Reverse order: SVI → EVPN RT → L2VNI → VLAN
            if gateway and any(s.get("interface") == f"vlan{vlan_id}"
                               and s.get("status") == "created" for s in steps_done):
                report.append(await client.delete_svi(vlan_id))
            if any("import_route_targets" in s and s.get("status") == "created"
                   for s in steps_done):
                report.append(await client.delete_evpn_vlan_rt(vlan_id))
            if any(s.get("vni") == vni and s.get("status") == "created"
                   for s in steps_done):
                report.append(await client.delete_l2vni(vni))
            if any(s.get("vlan") == vlan_id and s.get("status") == "created"
                   and "vni" not in s and "import_route_targets" not in s
                   for s in steps_done):
                report.append(await client.delete_vlan(vlan_id))
    except Exception as exc:  # noqa: BLE001
        report.append({"rollback_error": str(exc)})
    return report



async def _provision_traditional_service(*, vlan_id, name, targets, unreachable,
                                         tag_uplinks, apply) -> dict:
    if not targets:
        return {"status": "error", "error": "No reachable target device.",
                "unreachable": unreachable}

    svc_name = name or f"VLAN{vlan_id}"
    inv_names = set(_devices.keys())
    inv_hosts = {d.host for d in _devices.values() if d.host}

    # Discovery of uplinks and upstream switches (plan)
    plan: dict[str, list] = {}
    upstream_to_create: dict[str, dict] = {}  # inventory name → {via}

    async def _plan_one(dev: str):
        steps = [{"action": "create_vlan", "vlan": vlan_id, "name": svc_name}]
        uplinks = []
        if tag_uplinks:
            try:
                async with _get_client(dev) as client:
                    uplinks = await client.get_uplink_interfaces(
                        neighbor_system_names=inv_names, neighbor_hosts=inv_hosts)
            except Exception as exc:  # noqa: BLE001
                return dev, steps, [], {"uplink_error": str(exc)}
            for u in uplinks:
                steps.append({"action": "add_vlan_to_trunk",
                              "interface": u["interface"], "vlan": vlan_id,
                              "neighbor": u.get("neighbor_system_name")})
        return dev, steps, uplinks, None

    plan_results = await asyncio.gather(*[_plan_one(d) for d in targets])
    for dev, steps, uplinks, _err in plan_results:
        plan[dev] = steps
        for u in uplinks:
            upstream = _match_inventory_device(
                u.get("neighbor_system_name", ""), u.get("neighbor_mgmt_address", ""))
            if upstream and upstream not in targets:
                upstream_to_create[upstream] = {"via": dev}

    # The VLAN must also exist on the upstream inventory switches
    for up in upstream_to_create:
        plan.setdefault(up, []).insert(
            0, {"action": "create_vlan", "vlan": vlan_id, "name": svc_name,
                "reason": f"upstream switch (via {upstream_to_create[up]['via']})"})

    service = {"vlan": vlan_id, "name": svc_name, "network_type": "traditional",
               "tag_uplinks": tag_uplinks,
               "upstream_devices": list(upstream_to_create.keys())}

    if not apply:
        return {"status": "planned", "service": service,
                "targets": list(plan.keys()), "plan": plan, "apply": False,
                "unreachable": unreachable,
                "note": "Preview only. Re-run with apply=true to apply."}

    # Application
    async def _apply_one(dev: str, steps: list):
        done = []
        try:
            async with _get_client(dev) as client:
                for st in steps:
                    if st["action"] == "create_vlan":
                        done.append(await client.create_vlan(vlan_id, svc_name))
                    elif st["action"] == "add_vlan_to_trunk":
                        done.append(await client.add_vlan_to_trunk(st["interface"], vlan_id))
            return dev, {"ok": True, "steps": done}
        except Exception as exc:  # noqa: BLE001
            return dev, {"ok": False, "error": str(exc), "steps": done}

    results = dict(await asyncio.gather(*[_apply_one(d, s) for d, s in plan.items()]))
    failed = [d for d, r in results.items() if not r["ok"]]
    return {
        "status": "applied" if not failed else "partial",
        "service": service, "targets": list(plan.keys()), "apply": True,
        "results": results, "unreachable": unreachable,
        "summary": {"total": len(plan), "succeeded": len(plan) - len(failed),
                    "failed": len(failed), "failed_devices": failed},
    }


@mcp.tool()
async def delete_vlan_service(
    vlan_id: int,
    devices: list[str] = None,
    site: str = None,
    network_type: str = None,
    remove_from_trunks: bool = True,
    apply: bool = False,
) -> dict:
    """Delete (rollback) a VLAN service, in reverse order of creation
    (auto-detection unless `network_type` is forced):
      - VXLAN/EVPN fabric: SVI → EVPN config (RT/RD) → L2VNI → VLAN.
      - Traditional: remove the VLAN from the tagged uplinks then delete the VLAN.

    Target `devices`/`site` (otherwise everywhere the VLAN/L2VNI is present). `apply`
    (False=plan only, True=applies). Idempotent (object absent → status='absent').
    """
    # 1. Candidate targets
    try:
        if devices:
            candidates = []
            for d in devices:
                candidates.extend(_resolve_devices(device=d, site=site))
        elif site:
            candidates = _resolve_devices(site=site)
        else:
            candidates = list(_devices.keys())
    except ValueError as exc:
        return {"status": "error", "error": str(exc)}

    if apply:
        denied = _deny_read_only_many(candidates, "delete_vlan_service")
        if denied:
            return denied

    # 2. Inventory of service presence per device (read-only)
    async def _inspect(dev: str):
        try:
            async with _get_client(dev) as client:
                has_vlan = await client.vlan_exists(vlan_id)
                ctx = await client.get_fabric_context()
                vni = (ctx.get("vni_by_vlan") or {}).get(vlan_id)
                is_fabric = bool(ctx.get("fabric"))
                has_svi = await client.svi_exists(vlan_id)
                has_evpn = await client.evpn_vlan_exists(vlan_id)
                trunks = []
                if not is_fabric and remove_from_trunks:
                    trunks = await client.list_trunks_with_vlan(vlan_id)
                return dev, {"ok": True, "has_vlan": has_vlan, "vni": vni,
                             "is_fabric": is_fabric, "has_svi": has_svi,
                             "has_evpn": has_evpn, "trunks": trunks}
        except Exception as exc:  # noqa: BLE001
            return dev, {"ok": False, "error": str(exc)}

    inspected = dict(await asyncio.gather(*[_inspect(d) for d in candidates]))
    reachable = {d: i for d, i in inspected.items() if i.get("ok")}
    unreachable = {d: i["error"] for d, i in inspected.items() if not i.get("ok")}

    # Detect the type if not forced: fabric if at least one VTEP is involved
    if network_type not in (None, "fabric", "traditional"):
        return {"status": "error",
                "error": "network_type must be 'fabric', 'traditional' or omitted."}
    fabric_present = any(i.get("is_fabric") for i in reachable.values())
    detected = network_type or ("fabric" if fabric_present else "traditional")

    # 3. Build the plan: only the devices where something remains to clean up
    plan: dict[str, list] = {}
    for dev, info in reachable.items():
        steps = []
        if detected == "fabric" and info.get("is_fabric"):
            if info.get("has_svi"):
                steps.append({"action": "delete_svi", "interface": f"vlan{vlan_id}"})
            if info.get("has_evpn"):
                steps.append({"action": "delete_evpn_vlan_rt", "vlan": vlan_id})
            if info.get("vni") is not None:
                steps.append({"action": "delete_l2vni", "vni": info["vni"]})
            if info.get("has_vlan"):
                steps.append({"action": "delete_vlan", "vlan": vlan_id})
        else:
            for t in info.get("trunks", []):
                steps.append({"action": "remove_vlan_from_trunk", "interface": t, "vlan": vlan_id})
            if info.get("has_vlan"):
                steps.append({"action": "delete_vlan", "vlan": vlan_id})
        if steps:
            plan[dev] = steps

    summary_target = list(plan.keys())
    service = {"vlan": vlan_id, "network_type": detected}
    if not apply:
        # End of workflow (inspection only): close the opened sessions.
        await _close_sessions(candidates)
        planned = {"status": "planned", "service": service, "targets": summary_target,
                   "plan": plan, "apply": False, "unreachable": unreachable,
                   "note": "Preview only. Re-run with apply=true to delete."}
        if write_safety is not None:
            try:
                write_safety.freeze_recipe(
                    planned, "delete_vlan_service", summary_target, plan,
                    tool="delete_vlan_service",
                    arguments=dict(vlan_id=vlan_id, devices=devices, site=site,
                                   network_type=network_type,
                                   remove_from_trunks=remove_from_trunks),
                )
            except Exception:
                logger.exception("freeze_recipe failed for delete_vlan_service")
        return planned

    if not plan:
        await _close_sessions(candidates)
        return {"status": "noop", "service": service, "targets": [],
                "unreachable": unreachable,
                "note": "Nothing to delete: the service is already absent everywhere."}

    # 4. Apply the deletion
    async def _delete_one(dev: str, steps: list):
        done = []
        try:
            async with _get_client(dev) as client:
                for st in steps:
                    act = st["action"]
                    if act == "delete_svi":
                        done.append(await client.delete_svi(vlan_id))
                    elif act == "delete_evpn_vlan_rt":
                        done.append(await client.delete_evpn_vlan_rt(vlan_id))
                    elif act == "delete_l2vni":
                        done.append(await client.delete_l2vni(st["vni"]))
                    elif act == "delete_vlan":
                        done.append(await client.delete_vlan(vlan_id))
                    elif act == "remove_vlan_from_trunk":
                        done.append(await client.remove_vlan_from_trunk(st["interface"], vlan_id))
            return dev, {"ok": True, "steps": done}
        except Exception as exc:  # noqa: BLE001
            return dev, {"ok": False, "error": str(exc), "steps": done}

    results = dict(await asyncio.gather(*[_delete_one(d, s) for d, s in plan.items()]))
    failed = [d for d, r in results.items() if not r["ok"]]
    # End of workflow: close the sessions opened on the targeted devices.
    await _close_sessions(candidates)
    return {
        "status": "applied" if not failed else "partial",
        "service": service, "targets": summary_target, "apply": True,
        "results": results, "unreachable": unreachable,
        "summary": {"total": len(plan), "succeeded": len(plan) - len(failed),
                    "failed": len(failed), "failed_devices": failed},
    }


# ══════════════════════════════════════════════════════════════════════
# TOOLS — Configuration domains (write, idempotent, plan/apply)
# ══════════════════════════════════════════════════════════════════════

async def _exec_on_devices(candidates: list[str], executor) -> dict:
    """Run `executor(dev, client)` on each device with a pooled session.
    Returns {dev: {"ok": bool, "result"|"error": ...}}."""
    async def _one(dev: str):
        try:
            async with _get_client(dev) as client:
                res = await executor(dev, client)
            return dev, {"ok": True, "result": res}
        except Exception as exc:  # noqa: BLE001
            return dev, {"ok": False, "error": str(exc)}
    return dict(await asyncio.gather(*[_one(d) for d in candidates]))


async def _domain_write(operation: str, device, site, plan: dict, executor,
                        apply: bool) -> dict:
    """Shared plan/apply wrapper for the configuration-domain tools.

    apply=False → returns the computed plan only (no write). apply=True →
    enforces the read-only guard, runs `executor` on every target, closes the
    sessions and returns a per-device result map."""
    try:
        candidates = _resolve_devices(device=device, site=site)
    except ValueError as exc:
        return {"status": "error", "error": str(exc)}
    if not candidates:
        return {"status": "error", "error": "No resolved target device."}
    if not apply:
        return {"status": "planned", "operation": operation, "targets": candidates,
                "plan": plan, "apply": False,
                "note": "Preview only. Re-run with apply=true to apply."}
    denied = _deny_read_only_many(candidates, operation)
    if denied:
        return denied
    results = await _exec_on_devices(candidates, executor)
    await _close_sessions(candidates)
    failed = [d for d, r in results.items() if not r["ok"]]
    return {
        "status": "applied" if not failed else "partial", "operation": operation,
        "targets": candidates, "plan": plan, "apply": True, "results": results,
        "summary": {"total": len(candidates),
                    "succeeded": len(candidates) - len(failed),
                    "failed": len(failed), "failed_devices": failed},
    }


def _af_bool_map(value):
    """Normalise an address-family input into the API dict shape.
    list ["l2vpn-evpn"] → {"l2vpn-evpn": True}; dict passed through."""
    if value is None:
        return None
    if isinstance(value, dict):
        return value
    if isinstance(value, (list, tuple)):
        return {af: True for af in value}
    return value


@mcp.tool()
async def configure_loopback(name: str, ip_address: str, device: str = None,
                             site: str = None, vrf: str = "default",
                             apply: bool = False) -> dict:
    """Create/update a loopback interface (idempotent), optionally attached to a
    VRF. `name` e.g. 'loopback0', `ip_address` in CIDR form e.g. '10.0.0.1/32'.
    If `vrf` is omitted, the default VRF is used. `apply`=False returns the plan only."""
    err = _precheck([("ip_address", lambda: _v_ipv4_cidr(ip_address, "ip_address"))])
    if err:
        return err
    vrf = vrf or "default"
    plan = {dev: [{"action": "create_loopback", "interface": name,
                   "ip4_address": ip_address, "vrf": vrf}]
            for dev in (_safe_targets(device, site))}

    async def _exec(dev, client):
        return await client.create_loopback(name, ip_address, vrf=vrf)

    return await _domain_write("configure_loopback", device, site, plan, _exec, apply)


@mcp.tool()
async def configure_routed_port(interface: str, device: str = None, site: str = None,
                                ip_address: str = None, description: str = None,
                                mtu: int = None, vrf: str = "default",
                                enable: bool = True, apply: bool = False) -> dict:
    """Configure a physical port as a routed (L3) interface (idempotent): no
    switchport, IP address, optional VRF/MTU. Typical for point-to-point underlay
    links. `ip_address` in CIDR form (e.g. '10.1.1.0/31'). If `vrf` is omitted, the
    default VRF is used. `apply`=False = plan."""
    err = _precheck([
        ("ip_address", lambda: _v_ipv4_cidr(ip_address, "ip_address")
         if ip_address is not None else None),
        ("mtu", lambda: _v_mtu(mtu, "mtu") if mtu is not None else None),
    ])
    if err:
        return err
    vrf = vrf or "default"
    plan = {dev: [{"action": "configure_routed_interface", "interface": interface,
                   "ip4_address": ip_address, "vrf": vrf, "mtu": mtu,
                   "admin": "up" if enable else "down"}]
            for dev in (_safe_targets(device, site))}

    async def _exec(dev, client):
        return await client.configure_routed_interface(
            interface, ip_cidr=ip_address, description=description, mtu=mtu,
            vrf=vrf, enable=enable)

    return await _domain_write("configure_routed_port", device, site, plan, _exec,
                               apply)


@mcp.tool()
async def configure_vxlan_interface(device: str = None, site: str = None,
                                    interface: str = "vxlan1", source_ip: str = None,
                                    dest_udp_port: int = None,
                                    inter_vxlan_bridging_mode: str = None,
                                    static_peers: list = None,
                                    remove_static_peers: list = None,
                                    apply: bool = False) -> dict:
    """Configure the VXLAN VTEP interface (idempotent). Also the tool to make a
    device a STUB VTEP / set its inter-VxLAN bridging behaviour and to manage
    STATIC VXLAN peers.

    - `source_ip`: VTEP source IP (options.local_ip).
    - `dest_udp_port`: VXLAN UDP port (default 4789 on the device).
    - `inter_vxlan_bridging_mode`: deny | static-evpn | static-all — the Stub
        VTEP / Scaled Design key. static-evpn bridges static<->dynamic tunnels on
        the same L2VNI; static-all bridges all tunnels; deny disables bridging.
    - `static_peers`: list of static VXLAN tunnels (non-EVPN flood), each
        {"destination": "<remote VTEP IP>", "vnis": [10010, ...], "vrf": "default"}.
    - `remove_static_peers`: list of remote VTEP IPs to remove.
    `apply`=False returns the plan only."""
    _checks = []
    if source_ip is not None:
        _checks.append(("source_ip", lambda: _v_ip_host(source_ip, "source_ip")))
    if dest_udp_port is not None:
        _checks.append(("dest_udp_port",
                        lambda: _v_int_range(dest_udp_port, 1, 65535, "dest_udp_port")))
    for _i, _p in enumerate(static_peers or []):
        _checks.append((f"static_peers[{_i}].destination",
                        lambda _p=_p: _v_ip_host(_p.get("destination"), "destination")))
        for _v in (_p.get("vnis") or []):
            _checks.append((f"static_peers[{_i}].vnis",
                            lambda _v=_v: _v_vni(_v, "vni")))
    for _d in (remove_static_peers or []):
        _checks.append(("remove_static_peers",
                        lambda _d=_d: _v_ip_host(_d, "destination")))
    err = _precheck(_checks)
    if err:
        return err
    plan = {dev: {"interface": interface, "source_ip": source_ip,
                  "dest_udp_port": dest_udp_port,
                  "inter_vxlan_bridging_mode": inter_vxlan_bridging_mode,
                  "static_peers": static_peers or [],
                  "remove_static_peers": remove_static_peers or []}
            for dev in (_safe_targets(device, site))}

    async def _exec(dev, client):
        out = {"interface": await client.ensure_vxlan_interface(
            interface, source_ip=source_ip, dest_udp_port=dest_udp_port,
            inter_vxlan_bridging_mode=inter_vxlan_bridging_mode)}
        out["static_peers"] = []
        for p in (static_peers or []):
            out["static_peers"].append(await client.add_static_vxlan_peer(
                p["destination"], p.get("vnis", []), vxlan_interface=interface,
                vrf=p.get("vrf") or "default"))
        out["removed_peers"] = []
        for dest in (remove_static_peers or []):
            out["removed_peers"].append(await client.remove_static_vxlan_peer(
                dest, vxlan_interface=interface))
        return out

    return await _domain_write("configure_vxlan_interface", device, site, plan,
                               _exec, apply)


@mcp.tool()
async def configure_evpn(device: str = None, site: str = None,
                         dyn_vxlan_tunnel_bridging_mode: str = None,
                         arp_suppression: bool = None, nd_suppression: bool = None,
                         options: dict = None, apply: bool = False) -> dict:
    """Configure the global EVPN feature (idempotent).

    - `dyn_vxlan_tunnel_bridging_mode`: no-bridging | ibgp-ebgp (Scaled Design
       inter-VxLAN bridging).
    - `arp_suppression` / `nd_suppression`: enable ARP/ND suppression.
    - `options`: passthrough of any other /system/evpn field (mac_move_count,
       mac_move_timer, oism_enable, igmp_mld_proxy_enable, redistribute, ...).
    `apply`=False returns the plan only."""
    plan = {dev: {"dyn_vxlan_tunnel_bridging_mode": dyn_vxlan_tunnel_bridging_mode,
                  "arp_suppression_enable": arp_suppression,
                  "nd_suppression_enable": nd_suppression, "options": options or {}}
            for dev in (_safe_targets(device, site))}

    async def _exec(dev, client):
        return await client.set_evpn_global(
            dyn_vxlan_tunnel_bridging_mode=dyn_vxlan_tunnel_bridging_mode,
            arp_suppression_enable=arp_suppression,
            nd_suppression_enable=nd_suppression, extra=options)

    return await _domain_write("configure_evpn", device, site, plan, _exec, apply)


@mcp.tool()
async def configure_ospf(device: str = None, site: str = None, vrf: str = "default",
                         instance_tag: int = 1, router_id: str = None,
                         passive_interface_default: bool = None, area_id: str = None,
                         area_type: str = None, interfaces: list = None,
                         apply: bool = False) -> dict:
    """Configure an OSPF router instance in a VRF (idempotent).

    - `vrf`/`instance_tag`/`router_id`: OSPF process identity.
    - `passive_interface_default`: make all interfaces passive by default.
    - `area_id` (dotted, e.g. '0.0.0.0') + `area_type` (default/stub/nssa/...).
    - `interfaces`: list of interface names to attach to `area_id`.
    If `vrf` is omitted, the default VRF is used. `apply`=False returns the plan only."""
    err = _precheck([
        ("router_id", lambda: _v_ipv4_host(router_id, "router_id")
         if router_id is not None else None),
        ("area_id", lambda: _v_ospf_area(area_id, "area_id")
         if area_id is not None else None),
    ])
    if err:
        return err
    vrf = vrf or "default"
    plan = {dev: {"vrf": vrf, "instance_tag": instance_tag, "router_id": router_id,
                  "passive_interface_default": passive_interface_default,
                  "area_id": area_id, "area_type": area_type,
                  "interfaces": interfaces or []}
            for dev in (_safe_targets(device, site))}

    async def _exec(dev, client):
        out = {"router": await client.ensure_ospf_router(
            vrf=vrf, instance_tag=instance_tag, router_id=router_id,
            passive_interface_default=passive_interface_default)}
        if area_id is not None:
            out["area"] = await client.ensure_ospf_area(
                area_id, vrf=vrf, instance_tag=instance_tag, area_type=area_type)
            out["interfaces"] = []
            for intf in (interfaces or []):
                out["interfaces"].append(await client.add_ospf_interface(
                    intf, area_id, vrf=vrf, instance_tag=instance_tag))
        return out

    return await _domain_write("configure_ospf", device, site, plan, _exec, apply)


@mcp.tool()
async def configure_bgp(asn: int, device: str = None, site: str = None,
                        vrf: str = "default", router_id: str = None,
                        neighbors: list = None, options: dict = None,
                        apply: bool = False) -> dict:
    """Configure BGP in a VRF: router (ASN/router-id) + neighbors/peer-groups,
    including the L2VPN-EVPN overlay and Route-Reflector clients (idempotent).

    `neighbors`: list of dicts, each:
      {"neighbor": "10.0.0.1" | "<group-name>",
       "remote_as": 65001, "is_peer_group": false,
       "peer_group": "<group-name>",          # bind a member to a group
       "update_source": "10.0.0.2",           # or:
       "local_interface": "loopback0",        # update-source loopback
       "activate": ["l2vpn-evpn"],            # or {"l2vpn-evpn": true}
       "route_reflector_client": ["l2vpn-evpn"],
       "send_community": {"l2vpn-evpn": "both"},
       "next_hop_unchanged": ["l2vpn-evpn"],
       "description": "...", "password": "...", "bfd_enable": true,
       "ebgp_hop_count": 2, "passive": false, "shutdown": false,
       "extra": { ... any other BGP_Neighbor field ... }}
    `options`: passthrough of any other BGP_Router field (maximum_paths,
    bestpath_*, timers, redistribute, ...). If `vrf` is omitted, the default VRF
    is used. `apply`=False returns the plan only."""
    _checks = [("asn", lambda: _v_asn(asn, "asn"))]
    if router_id is not None:
        _checks.append(("router_id", lambda: _v_ipv4_host(router_id, "router_id")))
    for _i, _nbr in enumerate(neighbors or []):
        _ra = _nbr.get("remote_as")
        if _ra is not None:
            _checks.append((f"neighbors[{_i}].remote_as",
                            lambda _ra=_ra: _v_asn(_ra, "remote_as")))
        _name = _nbr.get("neighbor") or _nbr.get("name")
        if _name and not _nbr.get("is_peer_group", False):
            if re.match(r"^[0-9.]+$", str(_name)):
                _checks.append((f"neighbors[{_i}].neighbor",
                                lambda _name=_name: _v_ipv4_host(_name, "neighbor")))
            elif ":" in str(_name) and re.match(r"^[0-9A-Fa-f:]+$", str(_name)):
                _checks.append((f"neighbors[{_i}].neighbor",
                                lambda _name=_name: _v_ip_host(_name, "neighbor")))
    err = _precheck(_checks)
    if err:
        return err
    vrf = vrf or "default"
    plan = {dev: {"vrf": vrf, "asn": asn, "router_id": router_id,
                  "neighbors": neighbors or [], "options": options or {}}
            for dev in (_safe_targets(device, site))}

    async def _exec(dev, client):
        out = {"router": await client.ensure_bgp_router(
            asn, vrf=vrf, router_id=router_id, extra=options)}
        out["neighbors"] = []
        for nbr in (neighbors or []):
            name = nbr.get("neighbor") or nbr.get("name")
            if not name:
                raise ArubaAPIError(
                    "Each BGP neighbor requires a 'neighbor' (IP or group name).",
                    400)
            out["neighbors"].append(await client.create_bgp_neighbor(
                name, asn, vrf=vrf,
                remote_as=nbr.get("remote_as"),
                is_peer_group=nbr.get("is_peer_group", False),
                peer_group=nbr.get("peer_group"),
                update_source=nbr.get("update_source"),
                local_interface=nbr.get("local_interface"),
                activate=_af_bool_map(nbr.get("activate")),
                route_reflector_client=_af_bool_map(
                    nbr.get("route_reflector_client")),
                send_community=nbr.get("send_community"),
                next_hop_unchanged=_af_bool_map(nbr.get("next_hop_unchanged")),
                description=nbr.get("description"),
                password=nbr.get("password"),
                bfd_enable=nbr.get("bfd_enable"),
                ebgp_hop_count=nbr.get("ebgp_hop_count"),
                passive=nbr.get("passive"),
                shutdown=nbr.get("shutdown"),
                extra=nbr.get("extra")))
        return out

    return await _domain_write("configure_bgp", device, site, plan, _exec, apply)


@mcp.tool()
async def configure_vrf(name: str, device: str = None, site: str = None,
                        rd: str = None, import_route_targets: list = None,
                        export_route_targets: list = None,
                        address_families: list = None, options: dict = None,
                        apply: bool = False) -> dict:
    """Create/update a VRF with its Route-Distinguisher and EVPN Route-Targets
    (idempotent).

    - `rd`: route-distinguisher (ASN:nn or IP:nn).
    - `import_route_targets`/`export_route_targets`: VRF-level EVPN RTs.
    - `address_families`: optional per-AF RT config, list of
        {"address_family": "ipv4-unicast", "import_route_targets": [...],
         "export_route_targets": [...]}.
    - `options`: passthrough of any other VRF field. `apply`=False = plan only."""
    _checks = []
    if rd is not None:
        _checks.append(("rd", lambda: _v_route_target(rd, "rd")))
    for _r in (import_route_targets or []):
        _checks.append(("import_route_targets",
                        lambda _r=_r: _v_route_target(_r, "import_rt")))
    for _r in (export_route_targets or []):
        _checks.append(("export_route_targets",
                        lambda _r=_r: _v_route_target(_r, "export_rt")))
    for _i, _af in enumerate(address_families or []):
        for _r in (_af.get("import_route_targets") or []):
            _checks.append((f"address_families[{_i}].import_route_targets",
                            lambda _r=_r: _v_route_target(_r, "import_rt")))
        for _r in (_af.get("export_route_targets") or []):
            _checks.append((f"address_families[{_i}].export_route_targets",
                            lambda _r=_r: _v_route_target(_r, "export_rt")))
    err = _precheck(_checks)
    if err:
        return err
    plan = {dev: {"name": name, "rd": rd,
                  "import_route_targets": import_route_targets,
                  "export_route_targets": export_route_targets,
                  "address_families": address_families or [], "options": options or {}}
            for dev in (_safe_targets(device, site))}

    async def _exec(dev, client):
        out = {"vrf": await client.ensure_vrf(
            name, rd=rd, evpn_import_rts=import_route_targets,
            evpn_export_rts=export_route_targets, extra=options)}
        out["address_families"] = []
        for af in (address_families or []):
            out["address_families"].append(await client.set_vrf_address_family(
                name, af.get("address_family", "ipv4-unicast"),
                import_rts=af.get("import_route_targets"),
                export_rts=af.get("export_route_targets"), extra=af.get("extra")))
        return out

    return await _domain_write("configure_vrf", device, site, plan, _exec, apply)


@mcp.tool()
async def configure_port_auth(interfaces: list, device: str = None, site: str = None,
                              methods: dict = None, auth_mode: str = None,
                              clients_limit: int = None,
                              mda_data_clients_limit: int = None,
                              roles: dict = None, create_roles: list = None,
                              auth_precedence: list = None, auth_priority: list = None,
                              concurrent_onboarding: bool = None,
                              radius_override: bool = None,
                              apply: bool = False) -> dict:
    """Configure port authentication (802.1X and/or MAC-Auth) on access ports,
    with all options + user roles (idempotent).

    - `interfaces`: list of port names to configure.
    - `methods`: per-method options, e.g.
        {"dot1x": {"auth_enable": true, "reauth_enable": true,
                   "reauth_period": 3600, "max_retries": 2, "eapol_timeout": 30,
                   "quiet_period": 60, "max_requests": 2},
         "mac-auth": {"auth_enable": true, "cached_reauth_enable": true,
                      "radius_server_group": "RADIUS-GRP"}}.
    - `auth_mode`: client-mode | device-mode | multi-domain | proxy-mode.
    - `clients_limit` / `mda_data_clients_limit`: per-port client limits.
    - `roles`: logical→role-name bindings
        {"auth": "EMPLOYEE", "fallback": "GUEST", "critical": "CRITICAL",
         "critical_voice": "VOICE", "reject": "QUARANTINE", "pre_auth": "PREAUTH"}.
        ("guest" is an alias of "fallback".)
    - `create_roles`: list of user roles to create first, each
        {"name": "GUEST", "vlan_tag": 999, "description": "...",
         "gateway_zone": "...", "reauth_period": 3600,
         "captive_portal_profile": "...", "extra": { ... }}.
    - `auth_precedence`/`auth_priority`: ordered method list (["dot1x","mac-auth"]).
    - `concurrent_onboarding` / `radius_override`: per-port behaviour.
    `apply`=False returns the plan only."""
    if not interfaces:
        return {"status": "error", "error": "`interfaces` is required (list of ports)."}
    _checks = []
    for _i, _r in enumerate(create_roles or []):
        _vt = _r.get("vlan_tag")
        if _vt is not None:
            _checks.append((f"create_roles[{_i}].vlan_tag",
                            lambda _vt=_vt: _v_vlan(_vt, "vlan_tag")))
        for _v in (_r.get("vlan_trunks") or []):
            _checks.append((f"create_roles[{_i}].vlan_trunks",
                            lambda _v=_v: _v_vlan(_v, "vlan_trunk")))
    err = _precheck(_checks)
    if err:
        return err
    plan = {dev: {"interfaces": interfaces, "methods": methods or {},
                  "auth_mode": auth_mode, "clients_limit": clients_limit,
                  "roles": roles or {}, "create_roles": create_roles or [],
                  "auth_precedence": auth_precedence,
                  "radius_override": radius_override}
            for dev in (_safe_targets(device, site))}

    async def _exec(dev, client):
        out = {"roles": [], "interfaces": []}
        for r in (create_roles or []):
            out["roles"].append(await client.create_port_access_role(
                r["name"], vlan_tag=r.get("vlan_tag"),
                vlan_name_tag=r.get("vlan_name_tag"),
                vlan_trunks=r.get("vlan_trunks"),
                vlan_name_trunks=r.get("vlan_name_trunks"),
                vlan_mode=r.get("vlan_mode"), description=r.get("description"),
                gateway_zone=r.get("gateway_zone"),
                reauth_period=r.get("reauth_period"),
                captive_portal_profile=r.get("captive_portal_profile"),
                extra=r.get("extra")))
        for intf in interfaces:
            intf_res = {"interface": intf, "methods": []}
            for method, opts in (methods or {}).items():
                opts = opts or {}
                intf_res["methods"].append(await client.set_port_access_auth_method(
                    intf, method, auth_enable=opts.get("auth_enable", True),
                    extra={k: v for k, v in opts.items() if k != "auth_enable"}))
            intf_res["interface_cfg"] = await client.configure_interface_port_access(
                intf, auth_mode=auth_mode, clients_limit=clients_limit,
                mda_data_clients_limit=mda_data_clients_limit,
                concurrent_onboarding=concurrent_onboarding,
                radius_override=radius_override, auth_precedence=auth_precedence,
                auth_priority=auth_priority, roles=roles)
            out["interfaces"].append(intf_res)
        return out

    return await _domain_write("configure_port_auth", device, site, plan, _exec, apply)


@mcp.tool()
async def configure_app_recognition(device: str = None, site: str = None,
                                    enable: bool = None, mode: str = None,
                                    abp_session_limit_exceed_action: str = None,
                                    options: dict = None, apply: bool = False) -> dict:
    """Configure Application Recognition & Control (ARC) (idempotent).

    - `enable`: enable/disable the ARC feature.
    - `mode`: fast | default.
    - `abp_session_limit_exceed_action`: drop-new-flows | log-only.
    - `options`: passthrough of any other /system/app_recognition field.
    `apply`=False returns the plan only."""
    plan = {dev: {"enable": enable, "mode": mode,
                  "abp_session_limit_exceed_action": abp_session_limit_exceed_action,
                  "options": options or {}}
            for dev in (_safe_targets(device, site))}

    async def _exec(dev, client):
        return await client.set_app_recognition(
            enable=enable, mode=mode,
            abp_session_limit_exceed_action=abp_session_limit_exceed_action,
            extra=options)

    return await _domain_write("configure_app_recognition", device, site, plan,
                               _exec, apply)


@mcp.tool()
async def configure_virtual_mac(mac: str, device: str = None, site: str = None,
                                apply: bool = False) -> dict:
    """Configure the global EVPN virtual MAC (System.virtual_mac) — the MAC that
    EVPN Symmetric IRB advertises as the router's MAC for all symmetric routes
    (idempotent).

    This is NOT the VSX system MAC. On a VSX pair, BOTH peers MUST share the SAME
    virtual MAC: target the whole VSX pair (e.g. via `site`, or `device` as a
    list-of-one per peer) with one identical `mac`. Format AA:BB:CC:DD:EE:FF.
    `apply`=False returns the plan only."""
    err = _precheck([("mac", lambda: _v_mac(mac, "virtual_mac"))])
    if err:
        return err
    plan = {dev: {"virtual_mac": mac} for dev in _safe_targets(device, site)}

    async def _exec(dev, client):
        return await client.set_virtual_mac(mac)

    return await _domain_write("configure_virtual_mac", device, site, plan, _exec,
                               apply)


@mcp.tool()
async def configure_aaa(device: str = None, site: str = None,
                        server_groups: list = None, radius_servers: list = None,
                        tacacs_servers: list = None, authentication: dict = None,
                        accounting: dict = None, authorization: dict = None,
                        delete: bool = False, apply: bool = False) -> dict:
    """Configure GLOBAL AAA (idempotent): RADIUS/TACACS+ servers, AAA
    server-groups, and the GLOBAL authentication/authorization/accounting
    server-group order per management session-type (ssh/console/https-server/
    telnet/gnmi/default). This is the device/management AAA, NOT per-interface
    dot1x — for 802.1X/MAC-Auth on ports use configure_port_auth.

    - `server_groups`: [{"name": "MYGRP", "type": "radius"|"tacacs"}].
    - `radius_servers`: [{"address","vrf"(=mgmt),"passkey","port"(=1812),
        "port_type"(=udp),"accounting_udp_port","auth_type"(pap|chap),"timeout",
        "retries","server_group":{"MYGRP":1},"tracking_enable"}].
    - `tacacs_servers`: [{"address","vrf"(=mgmt),"passkey","tcp_port"(=49),
        "auth_type","timeout","group":["MYGRP"],"default_group_priority"(=1),
        "user_group_priority"}].
    - `authentication`/`authorization`/`accounting`: {session_type: [group names
        in priority order]} e.g. {"ssh": ["MYGRP","local"]}. Pass [] to clear.
    - `delete`=True: remove the listed servers/groups instead of creating them
        (authentication/authorization/accounting are ignored when delete=True).
    `apply`=False returns the plan only. Order applied: groups -> servers ->
    priorities (so server-group references resolve)."""
    server_groups = server_groups or []
    radius_servers = radius_servers or []
    tacacs_servers = tacacs_servers or []
    _checks = []
    for _i, _s in enumerate(radius_servers):
        _checks.append((f"radius_servers[{_i}].address",
                        lambda _s=_s: _v_ip_host(_s.get("address"), "address")))
    for _i, _s in enumerate(tacacs_servers):
        _checks.append((f"tacacs_servers[{_i}].address",
                        lambda _s=_s: _v_ip_host(_s.get("address"), "address")))
    err = _precheck(_checks)
    if err:
        return err
    plan = {dev: {"server_groups": server_groups, "radius_servers": radius_servers,
                  "tacacs_servers": tacacs_servers,
                  "authentication": authentication or {},
                  "authorization": authorization or {},
                  "accounting": accounting or {}, "delete": delete}
            for dev in _safe_targets(device, site)}

    async def _exec(dev, client):
        out: dict = {"server_groups": [], "radius_servers": [], "tacacs_servers": [],
                     "priorities": []}
        if delete:
            for s in radius_servers:
                out["radius_servers"].append(await client.delete_radius_server(
                    s["address"], vrf=s.get("vrf", "mgmt"),
                    port=int(s.get("port", 1812)),
                    port_type=s.get("port_type", "udp")))
            for s in tacacs_servers:
                out["tacacs_servers"].append(await client.delete_tacacs_server(
                    s["address"], vrf=s.get("vrf", "mgmt"),
                    tcp_port=int(s.get("tcp_port", 49))))
            for g in server_groups:
                out["server_groups"].append(
                    await client.delete_aaa_server_group(g["name"]))
            return out
        for g in server_groups:
            out["server_groups"].append(await client.ensure_aaa_server_group(
                g["name"], group_type=g.get("type", "tacacs")))
        for s in radius_servers:
            out["radius_servers"].append(await client.ensure_radius_server(
                s["address"], vrf=s.get("vrf", "mgmt"), passkey=s.get("passkey"),
                port=int(s.get("port", 1812)), port_type=s.get("port_type", "udp"),
                accounting_udp_port=s.get("accounting_udp_port"),
                auth_type=s.get("auth_type"), timeout=s.get("timeout"),
                retries=s.get("retries"), server_group=s.get("server_group"),
                tracking_enable=s.get("tracking_enable"), extra=s.get("extra")))
        for s in tacacs_servers:
            out["tacacs_servers"].append(await client.ensure_tacacs_server(
                s["address"], vrf=s.get("vrf", "mgmt"), passkey=s.get("passkey"),
                tcp_port=int(s.get("tcp_port", 49)), auth_type=s.get("auth_type"),
                timeout=s.get("timeout"), group=s.get("group"),
                default_group_priority=int(s.get("default_group_priority", 1)),
                user_group_priority=s.get("user_group_priority"),
                extra=s.get("extra")))
        session_types = set(authentication or {}) | set(authorization or {}) \
            | set(accounting or {})
        for st in session_types:
            out["priorities"].append(await client.set_aaa_group_prios(
                st, authentication=(authentication or {}).get(st),
                authorization=(authorization or {}).get(st),
                accounting=(accounting or {}).get(st)))
        return out

    return await _domain_write("configure_aaa", device, site, plan, _exec, apply)


@mcp.tool()
async def configure_user_roles(device: str = None, site: str = None,
                               roles: list = None, gbp_tags: list = None,
                               gbps: list = None, abps: list = None,
                               delete: bool = False, apply: bool = False) -> dict:
    """Configure local user roles and group/application-based policies
    (idempotent): Port-Access roles, GBP (Group-Based Policy) role tags + policies,
    and ABP (Application-Based Policy) policies.

    - `roles`: [{"name","vlan_tag","vlan_mode","description","reauth_period",
        "gateway_zone","captive_portal_profile","extra"}] (Port_Access_Role).
    - `gbp_tags`: [{"role_name","role_id"}] — GBP role-name <-> id (SGT) maps.
    - `gbps`: [{"name","entries":[{"sequence_number","class","class_type"(=gbp),
        "comment","drop","reflect"}]}] — `class` must reference an EXISTING Class.
    - `abps`: [{"name","entries":[{"sequence_number","class","class_type"
        (=application),"comment","drop","dscp","local_priority","mirror"}]}].
    - `delete`=True: remove the named roles/tags/gbps/abps instead of creating.
    `apply`=False returns the plan only. Order applied: gbp_tags -> gbps -> abps
    -> roles (so policy/tag references resolve before roles bind them).
    Note: GBP/ABP `class` objects (traffic classifiers) must already exist; this
    tool references them by name, it does not create Class resources."""
    roles = roles or []
    gbp_tags = gbp_tags or []
    gbps = gbps or []
    abps = abps or []
    plan = {dev: {"roles": roles, "gbp_tags": gbp_tags, "gbps": gbps,
                  "abps": abps, "delete": delete}
            for dev in _safe_targets(device, site)}

    async def _exec(dev, client):
        out: dict = {"gbp_tags": [], "gbps": [], "abps": [], "roles": []}
        if delete:
            for a in abps:
                out["abps"].append(await client.delete_port_access_abp(a["name"]))
            for g in gbps:
                out["gbps"].append(await client.delete_port_access_gbp(g["name"]))
            for t in gbp_tags:
                out["gbp_tags"].append(
                    await client.delete_gbp_role_map(t["role_name"]))
            for r in roles:
                out["roles"].append(
                    await client.delete_port_access_role(r["name"]))
            return out
        for t in gbp_tags:
            out["gbp_tags"].append(await client.set_gbp_role_map(
                t["role_name"], t["role_id"]))
        for g in gbps:
            res = await client.ensure_port_access_gbp(g["name"])
            res["entries"] = []
            for e in (g.get("entries") or []):
                res["entries"].append(await client.set_gbp_entry(
                    g["name"], e["sequence_number"], class_name=e.get("class"),
                    class_type=e.get("class_type", "gbp"), comment=e.get("comment"),
                    drop=e.get("drop"), reflect=e.get("reflect")))
            out["gbps"].append(res)
        for a in abps:
            res = await client.ensure_port_access_abp(a["name"])
            res["entries"] = []
            for e in (a.get("entries") or []):
                res["entries"].append(await client.set_abp_entry(
                    a["name"], e["sequence_number"], class_name=e.get("class"),
                    class_type=e.get("class_type", "application"),
                    comment=e.get("comment"), drop=e.get("drop"),
                    dscp=e.get("dscp"), local_priority=e.get("local_priority"),
                    mirror=e.get("mirror")))
            out["abps"].append(res)
        for r in roles:
            out["roles"].append(await client.create_port_access_role(
                r["name"], vlan_tag=r.get("vlan_tag"),
                vlan_name_tag=r.get("vlan_name_tag"),
                vlan_trunks=r.get("vlan_trunks"), vlan_mode=r.get("vlan_mode"),
                description=r.get("description"), gateway_zone=r.get("gateway_zone"),
                reauth_period=r.get("reauth_period"),
                captive_portal_profile=r.get("captive_portal_profile"),
                extra=r.get("extra")))
        return out

    return await _domain_write("configure_user_roles", device, site, plan, _exec,
                               apply)


# ══════════════════════════════════════════════════════════════════════
# TOOLS — Configuration verification (read-back of applied config)
# ══════════════════════════════════════════════════════════════════════

async def _domain_verify(operation: str, device, site, reader) -> dict:
    """Shared read-back wrapper: run `reader(dev, client)` on every target,
    close the sessions, return a per-device map. Read-only (no apply)."""
    try:
        candidates = _resolve_devices(device=device, site=site)
    except ValueError as exc:
        return {"status": "error", "error": str(exc)}
    if not candidates:
        return {"status": "error", "error": "No resolved target device."}
    results = await _exec_on_devices(candidates, reader)
    await _close_sessions(candidates)
    failed = [d for d, r in results.items() if not r["ok"]]
    return {
        "status": "ok" if not failed else "partial", "operation": operation,
        "targets": candidates, "results": results,
        "summary": {"total": len(candidates),
                    "succeeded": len(candidates) - len(failed),
                    "failed": len(failed), "failed_devices": failed},
    }


@mcp.tool()
async def verify_loopback(name: str, device: str = None, site: str = None) -> dict:
    """Verify a loopback interface (read-back of the applied config): presence,
    ip4_address, vrf, admin state. Pair with configure_loopback."""
    return await _domain_verify(
        "verify_loopback", device, site,
        lambda dev, client: client.read_loopback(name))


@mcp.tool()
async def verify_routed_port(interface: str, device: str = None,
                             site: str = None) -> dict:
    """Verify a routed (L3) port: routing flag, ip4_address, ip_mtu, vrf, admin.
    Pair with configure_routed_port."""
    return await _domain_verify(
        "verify_routed_port", device, site,
        lambda dev, client: client.read_routed_interface(interface))


@mcp.tool()
async def verify_vxlan_interface(device: str = None, site: str = None,
                                 interface: str = "vxlan1") -> dict:
    """Verify the VXLAN VTEP interface (read-back): source IP (options.local_ip),
    UDP port, inter_vxlan_bridging_mode (Stub VTEP bridging mode) and the
    configured static VXLAN peers. Pair with configure_vxlan_interface."""
    return await _domain_verify(
        "verify_vxlan_interface", device, site,
        lambda dev, client: client.read_vxlan_interface(interface))


@mcp.tool()
async def verify_evpn(device: str = None, site: str = None) -> dict:
    """Verify the global EVPN config (dyn_vxlan_tunnel_bridging_mode, ARP/ND
    suppression). Pair with configure_evpn."""
    return await _domain_verify(
        "verify_evpn", device, site,
        lambda dev, client: client.read_evpn())


@mcp.tool()
async def verify_ospf(device: str = None, site: str = None, vrf: str = "default",
                      instance_tag: int = 1) -> dict:
    """Verify an OSPF router instance: router-id, passive-interface-default,
    areas (with type) and the interfaces attached to each area. If `vrf` is
    omitted, the default VRF is used. Pair with configure_ospf."""
    vrf = vrf or "default"
    return await _domain_verify(
        "verify_ospf", device, site,
        lambda dev, client: client.read_ospf(vrf=vrf, instance_tag=instance_tag))


@mcp.tool()
async def verify_bgp(asn: int, device: str = None, site: str = None,
                     vrf: str = "default") -> dict:
    """Verify a BGP router and its neighbors/peer-groups: remote-as, peer-group
    membership, update-source/local-interface, per-AF activate, route-reflector
    -client and send-community. If `vrf` is omitted, the default VRF is used.
    Pair with configure_bgp."""
    err = _precheck([("asn", lambda: _v_asn(asn, "asn"))])
    if err:
        return err
    vrf = vrf or "default"
    return await _domain_verify(
        "verify_bgp", device, site,
        lambda dev, client: client.read_bgp(asn, vrf=vrf))


@mcp.tool()
async def verify_vrf(name: str, device: str = None, site: str = None) -> dict:
    """Verify a VRF: RD, EVPN import/export route-targets and per-address-family
    route-targets. Pair with configure_vrf."""
    return await _domain_verify(
        "verify_vrf", device, site,
        lambda dev, client: client.read_vrf(name))


@mcp.tool()
async def verify_port_auth(interfaces: list, device: str = None,
                           site: str = None) -> dict:
    """Verify port authentication on one or more ports: configured methods
    (802.1X/MAC-Auth with their options), auth-mode, client limits, RADIUS
    override, method precedence/priority and role bindings. Pair with
    configure_port_auth."""
    if not interfaces:
        return {"status": "error", "error": "`interfaces` is required (list of ports)."}

    async def _reader(dev, client):
        out = {}
        for intf in interfaces:
            out[intf] = await client.read_port_auth(intf)
        return out

    return await _domain_verify("verify_port_auth", device, site, _reader)


@mcp.tool()
async def verify_app_recognition(device: str = None, site: str = None) -> dict:
    """Verify the Application Recognition (ARC) global config (enable, mode,
    abp_session_limit_exceed_action). Pair with configure_app_recognition."""
    return await _domain_verify(
        "verify_app_recognition", device, site,
        lambda dev, client: client.read_app_recognition())


@mcp.tool()
async def verify_virtual_mac(device: str = None, site: str = None) -> dict:
    """Verify the global EVPN virtual MAC (System.virtual_mac) on one or more
    devices. On a VSX pair both peers must report the SAME value: the result adds
    `virtual_macs` (per device) and `consistent` (True when all targets share the
    same virtual MAC). Pair with configure_virtual_mac."""
    res = await _domain_verify(
        "verify_virtual_mac", device, site,
        lambda dev, client: client.read_virtual_mac())
    if res.get("status") in ("ok", "partial"):
        macs = {d: (r.get("result") or {}).get("virtual_mac")
                for d, r in res.get("results", {}).items() if r.get("ok")}
        res["virtual_macs"] = macs
        distinct = {m for m in macs.values()}
        res["consistent"] = len(distinct) <= 1
        if len(distinct) > 1:
            res["warning"] = ("Virtual MAC differs across targets; VSX peers must "
                              "share the same virtual MAC.")
    return res


@mcp.tool()
async def verify_aaa(device: str = None, site: str = None) -> dict:
    """Verify the GLOBAL AAA config (read-back): RADIUS servers, TACACS+ servers,
    AAA server-groups and the per-session-type authentication/authorization/
    accounting server-group order. Pair with configure_aaa."""
    async def _reader(dev, client):
        return {
            "radius_servers": await client.get_radius_servers(),
            "tacacs_servers": await client.get_tacacs_servers(),
            "aaa": await client.get_aaa_authentication(),
        }

    return await _domain_verify("verify_aaa", device, site, _reader)


@mcp.tool()
async def verify_user_roles(device: str = None, site: str = None) -> dict:
    """Verify local user roles and group/application-based policies (read-back):
    Port-Access roles, GBP role tags, GBP policies and ABP policies. Pair with
    configure_user_roles."""
    async def _reader(dev, client):
        return {
            "roles": await client.get_port_access_roles(),
            "gbp_role_maps": await client.get_gbp_role_maps(),
            "gbps": await client.get_port_access_gbps(),
            "abps": await client.get_port_access_abps(),
        }

    return await _domain_verify("verify_user_roles", device, site, _reader)


# ══════════════════════════════════════════════════════════════════════
# PROMPTS — reusable ArubaOS-CX diagnostic templates
# ══════════════════════════════════════════════════════════════════════

@mcp.prompt()
def diagnostic_equipement(device: str) -> str:
    """Full health check of an ArubaOS-CX switch."""
    return (
        f"Perform a full health check of the switch '{device}'.\n\n"
        "Steps:\n"
        f"1. Retrieve the system info with get_system(device='{device}', scope='info') "
        "(model, firmware version, uptime, CPU/memory).\n"
        f"2. Check the interface status with get_interfaces(device='{device}', "
        "scope='physical'): spot the down/err-disabled interfaces, the errors and drops.\n"
        f"3. List the VLANs (get_switching(device='{device}', scope='vlans')) and the "
        "spanning-tree (get_switching(scope='spanning_tree')) to detect blocked ports.\n"
        f"4. Inspect the latest logs with get_logs('{device}', priority='0-3') "
        "for critical events.\n"
        "5. Summarize the status in a table (component, status, observation) "
        "and list the points of attention ranked by criticality.\n"
        f"Tip: diagnose(device='{device}', scope='device') returns steps 1-4 in one call."
    )


@mcp.prompt()
def troubleshoot_routing(device: str, vrf: str = "default") -> str:
    """Diagnose the dynamic routing (BGP + OSPF) of a switch."""
    return (
        f"Diagnose the dynamic routing of the switch '{device}' in the VRF '{vrf}'.\n\n"
        f"1. BGP: get_routing(device='{device}', scope='bgp_summary', vrf='{vrf}') then "
        "scope='bgp_config' and scope='bgp_routes'. Spot the neighbors that are not in "
        "Established state and explain why (ASN, timers, prefixes received/advertised).\n"
        f"2. OSPF: get_routing(device='{device}', scope='ospf_overview', vrf='{vrf}') then "
        "scope='ospf_neighbors' and scope='ospf_interfaces'. Spot the stuck adjacencies "
        "(Init/2-Way/ExStart) and the misconfigured interfaces (area, network type, MTU).\n"
        f"3. Cross-check with get_routing(device='{device}', scope='route_table', vrf='{vrf}') "
        "to verify that the expected prefixes are properly installed.\n"
        "4. Conclude with a clear diagnosis and the recommended corrective actions."
    )


@mcp.prompt()
def troubleshoot_client_8021x(device: str, interface: str = "") -> str:
    """Troubleshoot an 802.1X / MAC-Auth client (port-access)."""
    cible = f"interface '{interface}'" if interface else "the interfaces involved"
    arg_if = f", interface='{interface}'" if interface else ""
    return (
        f"A client cannot authenticate on the switch '{device}' on {cible}.\n\n"
        f"1. Overview: get_access(device='{device}', scope='summary') then "
        f"get_access(device='{device}', scope='clients'{arg_if}) to spot the failing clients.\n"
        "2. For each failing client, call get_access(scope='client_detail', interface=..., "
        "mac=...) (assigned VLAN, role, RADIUS attributes, EAP method, failure reason).\n"
        f"3. Check the reachability of the servers: get_access(device='{device}', scope='radius') "
        f"and get_access(device='{device}', scope='authentication') (group order per session type).\n"
        f"4. Consult get_access(scope='roles') and get_access(scope='policies') on '{device}' "
        "to validate that the returned role/policy exists and is consistent.\n"
        "5. Give the probable root cause (unreachable server, wrong role, "
        "nonexistent VLAN, EAP failure…) and the fix."
    )


@mcp.prompt()
def verifier_evpn_vxlan(device: str) -> str:
    """Verify the EVPN/VXLAN fabric on a switch."""
    return (
        f"Check the health of the EVPN/VXLAN overlay on the switch '{device}'.\n\n"
        f"1. get_overlay(device='{device}', scope='vxlan_config') and scope='vxlan_tunnels': "
        "check the VTEPs, the VNIs and the tunnel status (up/down).\n"
        f"2. get_overlay(device='{device}', scope='evpn_config'): validate the VNIs, the "
        "RD/RT and the mapped VLANs.\n"
        f"3. get_overlay(device='{device}', scope='evpn_routes'): verify the presence of the "
        "expected type-2 (MAC/IP) and type-3 (IMET) routes; flag the VNIs without a route.\n"
        f"4. Cross-check with get_routing(device='{device}', scope='bgp_neighbors') for the EVPN AF.\n"
        "5. Summarize the fabric status and the anomalies (tunnel down, orphan VNI, "
        "missing route).\n"
        f"Tip: diagnose(device='{device}', scope='evpn') runs steps 1-4 in one call."
    )


@mcp.prompt()
def localiser_client(device: str, mac: str = "") -> str:
    """Locate a MAC address / a client in the L2 network."""
    arg_mac = f" Search in particular for the MAC '{mac}'." if mac else ""
    return (
        f"Locate a client on the switch '{device}'.{arg_mac}\n\n"
        f"1. get_switching(device='{device}', scope='mac') to find the port and the VLAN of the MAC.\n"
        f"2. get_routing(device='{device}', scope='arp') to associate the MAC with an IP address.\n"
        f"3. get_switching(device='{device}', scope='lldp') to identify the neighbor device "
        "connected to the port (if it is another switch/AP).\n"
        f"4. If the client is authenticated, complete with get_access(device='{device}', "
        "scope='clients') for the role and the 802.1X status.\n"
        "5. Present the result: MAC, IP, port, VLAN, LLDP neighbor, role.\n"
        f"Tip: diagnose(device='{device}', scope='client') runs steps 1-4 in one call."
    )


@mcp.prompt()
def audit_configuration(device: str) -> str:
    """Audit the configuration and AAA access of a switch."""
    return (
        f"Perform a configuration and security audit of the switch '{device}'.\n\n"
        f"1. Retrieve the running-config with get_config(device='{device}', scope='running').\n"
        f"2. Examine the AAA: get_access(device='{device}', scope='authentication'), "
        f"scope='radius' and scope='tacacs' (reachable servers, order, fallback).\n"
        f"3. List the available checkpoints with get_config(device='{device}', scope='list') "
        "and offer to compare running-config / startup-config (scope='compare').\n"
        "4. Identify the deviations from best practices (unnecessary services, "
        "missing AAA fallback, default VLAN, identifiable weak passwords).\n"
        "5. Provide an audit report with prioritized recommendations."
    )


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
            from flat_tools import install_flat_toolset
            summary = install_flat_toolset(mcp, sys.modules[__name__])
            logger.info("flat_tools: %s", summary)
        except Exception:
            logger.exception("install_flat_toolset failed — tools left unchanged")
        return

    try:
        from deferred_tools import install_deferred_tools
        summary = install_deferred_tools(mcp)
        logger.info("deferred_tools: %s", summary)
    except Exception:
        logger.exception("install_deferred_tools failed — tools left unchanged")
    try:
        from tool_prefixes import apply_tool_prefixes
        summary = apply_tool_prefixes(mcp)
        logger.info("tool_prefixes: %s", summary)
    except Exception:
        logger.exception("apply_tool_prefixes failed — names left unchanged")


_install_progressive_disclosure()


if __name__ == "__main__":
    import uvicorn

    _init_security()

    transport = os.environ.get("MCP_TRANSPORT", "streamable-http").lower()
    if transport == "streamable-http":
        async def _run() -> None:
            app = _StaleSessionMiddleware(mcp.streamable_http_app())
            app = _SecurityMiddleware(
                app,
                auth_enabled=_AUTH_ENABLED,
                token_store=_token_store,
                audit=_audit,
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
