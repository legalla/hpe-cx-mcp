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

from clients.aruba_client import ArubaOSCXClient, ArubaAPIError
from clients.aruba_client import (
    _v_mac, _v_ipv4_host, _v_ip_host, _v_ipv4_cidr, _v_int_range,
    _v_vlan, _v_vni, _v_mtu, _v_asn, _v_route_target, _v_ospf_area,
)
from .config import DeviceConfig, load_inventory, Inventory, InventoryError
from .config_backup import ConfigBackupError, export_config
from .inventory_sources import InventoryManager, InventorySourceError
from clients.ssh_client import ArubaOSCXSSHClient, ArubaSSHError
from security import cx_auth
from security.cx_audit import AuditLogger

# Progressive-disclosure / write-safety layers (optional, fail-open). All three
# are gated by their own env flags and are no-ops unless explicitly enabled.
try:
    from dispatch.write_safety import write_safety
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


def _read_version() -> str:
    """Image/app version: CX_VERSION env (set by the Dockerfile build arg),
    else the VERSION file next to server.py, else 'dev'."""
    env = os.environ.get("CX_VERSION", "").strip()
    if env:
        return env
    try:
        with open(os.path.join(os.path.dirname(os.path.dirname(__file__)), "VERSION"),
                  encoding="utf-8") as fh:
            return fh.read().strip() or "dev"
    except OSError:
        return "dev"


__version__ = _read_version()

# Runtime health state surfaced by GET /healthz (see server.py).
_HEALTH: dict = {
    "started_at": time.time(),
    "inventory_loaded_at": None,
    "inventory_error": None,
    "inventory_reloads": 0,
}

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
                summary = await _inv_manager.prefetch(_devices, defaults=_inventory.defaults)
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
    _HEALTH["inventory_loaded_at"] = time.time()
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


_VSF_SUFFIX_RE = re.compile(r"^(.*?)[-_ ]?(\d+)$")


def _vsf_member_of(name: str) -> str | None:
    """Conductor of a secondary VSF/VC member listed as its own inventory entry
    (NetBox virtual-chassis master, else: no management IP of its own and
    named '<conductor><N>', e.g. Campus-6300-VSF2 -> Campus-6300-VSF)."""
    dev = _devices.get(name)
    if dev is None:
        return None
    explicit = (dev.extra or {}).get("vsf_member_of")
    if explicit:
        return explicit
    if dev.host and dev.host != name:
        return None
    m = _VSF_SUFFIX_RE.match(name)
    if m and m.group(1) in _devices and _devices[m.group(1)].host != m.group(1):
        return m.group(1)
    return None


# ── Pool de sessions REST ─────────────────────────────────────────────
# Sessions are pooled and reused across requests during a workflow (a single
# login per device), then closed explicitly via the `logout` tool at the end of
# the workflow. A lazy "reaper" also closes sessions left idle beyond
# _SESSION_IDLE_TTL (a safety net against session leaks, which cause "access
# denied" errors).
_CLIENT_POOL: dict[str, dict] = {}  # canonical name → {"client": ArubaOSCXClient, "last_used": float}
_SESSION_IDLE_TTL = float(os.environ.get("CX_SESSION_IDLE_TTL", "600"))  # seconds
_REAPER_TASKS: set = set()  # keeps a reference to background logout tasks (anti-GC)

# ── Write options propagated from the dispatchers to _domain_write ────
# Set per call (contextvars follow the task tree, so asyncio.gather fan-out
# inherits them). `force` lifts the CX_PROTECTED_OBJECTS guard for one apply.
import contextvars  # noqa: E402
FORCE_PROTECTED: contextvars.ContextVar[bool] = contextvars.ContextVar(
    "cx_force_protected", default=False)
# Firmware auto-checkpoint (confirmed-commit) wrapped around every apply.
# Global default from CX_AUTO_CHECKPOINT (true); a call may opt out with
# auto_checkpoint=false (contextvar; None = use the global default).
_AUTO_CHECKPOINT = _env_bool("CX_AUTO_CHECKPOINT", True)
_AUTO_CHECKPOINT_MINUTES = max(1, min(60, int(os.environ.get("CX_AUTO_CHECKPOINT_MINUTES", "10"))))
AUTO_CHECKPOINT_OVERRIDE: contextvars.ContextVar = contextvars.ContextVar(
    "cx_auto_checkpoint_override", default=None)
# Apply results: compact per-item lists by default (summary + failures only);
# verbose=true on the dispatcher returns the full per-object detail.
VERBOSE_RESULT: contextvars.ContextVar[bool] = contextvars.ContextVar(
    "cx_verbose_result", default=False)


def auto_checkpoint_enabled() -> bool:
    override = AUTO_CHECKPOINT_OVERRIDE.get()
    return _AUTO_CHECKPOINT if override is None else bool(override)


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
    _ensure_background_reaper()
    entry = _CLIENT_POOL.get(name)
    if entry is None:
        entry = {"client": _new_client(name), "last_used": time.monotonic()}
        _CLIENT_POOL[name] = entry
    entry["last_used"] = time.monotonic()
    return entry["client"]


def _reap_idle_sessions(exclude: str | None = None) -> None:
    """Close (best-effort) pooled sessions that have been idle for too long.
    Called lazily on every pool access and by the background reaper.
    A session currently in use is never closed."""
    if _SESSION_IDLE_TTL <= 0:
        return
    now = time.monotonic()
    stale = [
        n for n, e in list(_CLIENT_POOL.items())
        if n != exclude and (now - e["last_used"]) > _SESSION_IDLE_TTL
        and getattr(e["client"], "_active", 0) <= 0
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


_REAPER_INTERVAL = float(os.environ.get("CX_SESSION_REAPER_INTERVAL", "60"))
_BG_REAPER: asyncio.Task | None = None


def _ensure_background_reaper() -> None:
    """Start (once per event loop) a task that closes idle REST/SSH sessions
    even when no other device is accessed — the lazy reaper alone leaves the
    last-used devices' sessions open on the switch."""
    global _BG_REAPER
    if _REAPER_INTERVAL <= 0:
        return
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        return
    if _BG_REAPER is not None and not _BG_REAPER.done() and _BG_REAPER.get_loop() is loop:
        return

    async def _loop():
        while True:
            await asyncio.sleep(_REAPER_INTERVAL)
            _reap_idle_sessions()
            _reap_idle_ssh()
    _BG_REAPER = loop.create_task(_loop())


async def _close_sessions(names) -> list[str]:
    """Close the pooled sessions of the given devices. Returns the names that were
    actually closed (session open at call time)."""
    closed: list[str] = []
    for name in names:
        try:
            canon = _canonical_device(name)
        except ValueError:
            continue
        entry = _CLIENT_POOL.get(canon)
        if entry is None:
            continue
        client = entry["client"]
        if getattr(client, "_active", 0) > 0:
            # A parallel operation is mid-request on this session: let its last
            # user close it instead of pulling the connector from under it.
            client._close_when_idle = True
            continue
        _CLIENT_POOL.pop(canon, None)
        if await _safe_logout(client):
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
    _ensure_background_reaper()
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
        # Only retry when the pooled session really died; a timeout on a
        # still-synchronised session is a genuine command error (no replay).
        if not was_pooled or client.is_connected:
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


def _coerce_device_list(device) -> list:
    """Normalize a ``device`` argument into a list of identifiers.

    Accepts a real list, a JSON-array-looking string ('["A","B"]' / "['A','B']"),
    a comma-separated string ("A, B") or a single name. MCP clients sometimes
    serialize arrays as strings, so every entry point must tolerate all forms."""
    if device is None:
        return []
    if isinstance(device, (list, tuple, set)):
        return [str(d).strip() for d in device if d is not None and str(d).strip()]
    if isinstance(device, str):
        s = device.strip()
        if not s:
            return []
        if s[0] == "[" and s[-1] == "]":
            try:
                parsed = json.loads(s)
                if isinstance(parsed, list):
                    return [str(d).strip() for d in parsed if str(d).strip()]
            except Exception:  # noqa: BLE001 — tolerate single quotes / loose fmt
                pass
            return [p.strip().strip("'\"") for p in s[1:-1].split(",")
                    if p.strip().strip("'\"")]
        if "," in s:
            return [p.strip() for p in s.split(",") if p.strip()]
        return [s]
    return [str(device)]


def _resolve_devices(device: str = None, site: str = None) -> list[str]:
    """
    Resolve the target of a request into a de-duplicated list of canonical
    device names.

    - `device` accepts ONE name/IP, a list, or a comma-separated string
      ("A,B,C") — every write tool therefore fans out over several devices.
    - site provided: all devices of the site (restricted to `device` entries
      when both are given; an entry outside the site raises).
    - site absent: the `device` entries, resolved to canonical names.
    """
    wanted = _coerce_device_list(device)
    out: list[str] = []

    def _add(name: str) -> None:
        conductor = _vsf_member_of(name)
        if conductor:
            raise ValueError(
                f"Device '{name}' is a VSF/stack member of '{conductor}' (no management "
                f"plane of its own) — target '{conductor}' instead.")
        if name not in out:
            out.append(name)

    if site:
        in_site = _devices_in_site(site)
        if not wanted:
            return [n for n in in_site if not _vsf_member_of(n)]
        for d in wanted:
            if d in in_site:
                _add(d)
                continue
            matched = next((n for n, dv in in_site.items() if dv.host == d), None)
            if matched is None:
                raise ValueError(
                    f"Device '{d}' does not belong to site '{site}'."
                )
            _add(matched)
        return out
    if wanted:
        for d in wanted:
            try:
                _add(_canonical_device(d))
            except ValueError:
                _add(d)  # unknown: let the per-device call surface the error
        return out
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
                **({"vsf_member_of": _vsf_member_of(name),
                    "note": "stack member — not directly manageable, target its conductor"}
                   if _vsf_member_of(name) else {}),
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
        _HEALTH["inventory_error"] = f"{type(exc).__name__}: {exc}"
        return {"status": "error", "error": f"Failed to reload inventory: {exc}"}

    _devices = _inventory.devices
    _inv_manager = InventoryManager(_inventory)
    _HEALTH["inventory_loaded_at"] = time.time()
    _HEALTH["inventory_error"] = None
    _HEALTH["inventory_reloads"] += 1

    summary = {"added": [], "updated": [], "errors": {}, "sources": []}
    if _inv_manager.has_external_sources:
        try:
            summary = await _inv_manager.prefetch(_devices, defaults=_inventory.defaults)
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


def health_snapshot() -> tuple[int, dict]:
    """(http_status, body) for GET /healthz — no secrets, no device I/O.

    503 when the server cannot serve: LOCKED (auth on, 0 tokens) or an empty
    inventory. 200 otherwise, with status 'ok' or 'degraded' (last inventory
    reload failed, external source errors)."""
    now = time.time()
    tokens = len(_token_store) if _token_store is not None else 0
    locked = _AUTH_ENABLED and tokens == 0
    problems: list[str] = []
    if locked:
        problems.append("locked: CX_AUTH_ENABLED with 0 tokens")
    if not _devices:
        problems.append("inventory: 0 devices loaded")
    if _HEALTH.get("inventory_error"):
        problems.append(f"inventory reload failed: {_HEALTH['inventory_error']}")
    fatal = locked or not _devices
    status = "unavailable" if fatal else ("degraded" if problems else "ok")
    sites = sorted({d.site for d in _devices.values() if d.site})
    body = {
        "status": status,
        "version": __version__,
        "uptime_seconds": int(now - _HEALTH["started_at"]),
        "problems": problems,
        "inventory": {
            "devices": len(_devices),
            "sites": len(sites),
            "writable_devices": sum(1 for d in _devices.values() if d.can_write),
            "sources": list(_inventory.source_order) if _inventory else [],
            "loaded_at": _HEALTH.get("inventory_loaded_at"),
            "reloads": _HEALTH.get("inventory_reloads", 0),
            "last_error": _HEALTH.get("inventory_error"),
        },
        "auth": {"enabled": _AUTH_ENABLED, "tokens": tokens, "locked": locked},
        "audit": {"enabled": _AUDIT_ENABLED, "level": _AUDIT_LEVEL,
                  "stdout": _AUDIT_STDOUT},
        "write_safety": {
            "enabled": _env_bool("CX_WRITE_SAFETY", False),
            "require_dry_run_token": _env_bool("CX_REQUIRE_DRY_RUN_TOKEN", False),
            "auto_checkpoint": _AUTO_CHECKPOINT,
            "auto_checkpoint_minutes": _AUTO_CHECKPOINT_MINUTES,
            "protected_objects": [
                p.strip() for p in os.environ.get("CX_PROTECTED_OBJECTS", "").split(",")
                if p.strip()],
        },
        "sessions": {"rest": len(_CLIENT_POOL), "ssh": len(_SSH_POOL)},
        "tools_advertised": len(getattr(getattr(mcp, "_tool_manager", None), "_tools", {}) or {}),
    }
    return (503 if fatal else 200), body


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


