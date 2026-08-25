"""Deferred-tools / progressive-disclosure layer for the cx-mcp server.

This module is **completely standalone**: importing it has NO effect on the
existing server. Nothing here runs until you explicitly call
``install_deferred_tools(mcp, ...)`` once, at the very end of ``server.py``
(after all 101 ``@mcp.tool()`` definitions).

Goal
----
Keep ONE MCP server but advertise only a small, curated **Tier-1** set on
``tools/list`` (+ two meta-tools ``search_tools`` / ``invoke_tool``). Every
other tool becomes **Tier-2**: hidden from ``tools/list`` but still reachable
through ``invoke_tool``. This works for ANY MCP client — including "dumb"
clients that do not understand dynamic tool loading — because all the logic
lives server-side and the advertised tool surface never changes.

Activation is gated by the ``CX_DEFERRED_TOOLS`` environment variable:

    * ``CX_DEFERRED_TOOLS=true``  -> Tier-1 (+ meta-tools) advertised (~23 tools)
    * ``CX_DEFERRED_TOOLS=false`` (default) -> nothing is demoted; the server
      keeps advertising all of its tools exactly like today (rollback / no-op).

Write guard
-----------
``invoke_tool`` is the single choke point for the long tail. A deferred tool
flagged as ``write`` is refused when writes are disabled. Two layers:

    * the global env ``CX_INVOKE_WRITES`` (default ``true``);
    * an optional ``writes_allowed`` callback passed to
      ``install_deferred_tools`` (signature: ``(ToolSpec, dict) -> bool``),
      so you can plug in your existing per-device read/write policy later.

Tier-1 tools that happen to write (``create_vlan_service`` etc.) keep their
own internal guards — they are NOT routed through ``invoke_tool``.

FastMCP internals
-----------------
Demotion needs to read and mutate FastMCP's tool registry. The accessors below
try several attribute names so the module survives minor FastMCP version
differences; if the registry cannot be located, ``install_deferred_tools``
logs a warning and leaves the server untouched (safe fail-open to current
behaviour).
"""

from __future__ import annotations

import difflib
import inspect
import logging
import os
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

log = logging.getLogger("cx-mcp.deferred")

# Optional sibling modules (present in the same package). Imported defensively
# so this module keeps working even if they are absent.
try:  # functional-prefix layer (advertised-name aliasing)
    import tool_prefixes as _tp
except Exception:  # pragma: no cover
    _tp = None

try:  # dry_run_token + rollback_id layer
    from write_safety import write_safety as _ws
except Exception:  # pragma: no cover
    _ws = None

# Live FastMCP registry captured at install time (for Tier-1 fn resolution
# by apply_plan, possibly under a prefixed advertised name).
_LIVE_REGISTRY: Optional[dict] = None

# ──────────────────────────────────────────────────────────────────────
# Catalog data structures
# ──────────────────────────────────────────────────────────────────────


@dataclass
class ToolSpec:
    """A single deferred (Tier-2) tool captured out of FastMCP's registry."""

    name: str
    fn: Callable[..., Any]
    schema: dict
    description: str
    tags: list[str] = field(default_factory=list)
    write: bool = False


# Populated by ``install_deferred_tools`` at startup; empty until then.
_DEFERRED: dict[str, ToolSpec] = {}


# ──────────────────────────────────────────────────────────────────────
# Tier-1 set — the only "real" tools advertised on tools/list
# (plus the two meta-tools registered by this module).
# Names that do not exist in the server are harmless (ignored).
# ──────────────────────────────────────────────────────────────────────

TIER1: set[str] = {
    # Discovery / navigation
    "list_devices", "list_sites", "find_devices", "resolve_device", "run_on_site",
    # Core diagnostics (top 80%)
    "get_system_info", "get_interfaces", "get_vlans", "get_lldp_neighbors",
    "get_routing_table", "get_mac_table", "get_arp_table", "get_bgp_neighbors",
    "get_logs", "get_hardware_health", "get_capacities",
    # Universal escape hatches
    "run_cli_command", "get_raw_api", "run_ssh_command",
    # Config read / save
    "get_config", "manage_config",
    # Orchestrated provisioning
    "create_vlan_service", "delete_vlan_service",
    # Hygiene + write-safety rollback (Tier-1 meta)
    "logout", "rollback",
}

# The meta-tools this module registers; never demote these.
_META: set[str] = {"search_tools", "invoke_tool", "apply_plan"}


# ──────────────────────────────────────────────────────────────────────
# Tools that MODIFY device/server state (used by the invoke_tool guard).
# ──────────────────────────────────────────────────────────────────────

WRITE_TOOLS: set[str] = {
    "configure_loopback", "configure_routed_port", "configure_vxlan_interface",
    "configure_evpn", "configure_ospf", "configure_bgp", "configure_vrf",
    "configure_port_auth", "configure_app_recognition", "configure_virtual_mac",
    "configure_aaa", "configure_user_roles",
    "run_ssh_commands", "refresh_inventory",
}


# ──────────────────────────────────────────────────────────────────────
# Domain tags — feed search_tools so the agent can find Tier-2 tools.
# Any tool missing here is auto-tagged from its name at install time.
# ──────────────────────────────────────────────────────────────────────

TOOL_TAGS: dict[str, list[str]] = {
    # Inventory / sessions
    "list_inventory_sources": ["inventory", "sources"],
    "refresh_inventory": ["inventory", "reload", "write"],
    "run_ssh_commands": ["cli", "ssh", "batch", "write"],
    # System / hardware
    "get_boot_history": ["system", "boot", "reboot", "uptime"],
    "get_ssh_config": ["system", "ssh", "management"],
    "get_transceivers": ["interfaces", "optics", "transceiver", "sfp", "dom"],
    "get_containers": ["system", "containers", "docker"],
    "get_feature_pack": ["system", "licensing", "feature-pack"],
    "get_maintenance_mode": ["ops", "maintenance"],
    "get_aruba_central": ["cloud", "central", "management"],
    # Diagnostics / troubleshoot (AOS-CX 10.18+)
    "run_troubleshoot": ["diagnostics", "troubleshoot", "diagnose", "health-check",
                         "self-test", "config-check", "root-cause", "operations"],
    "list_troubleshoot_features": ["diagnostics", "troubleshoot", "features",
                                   "capabilities", "components", "catalog"],
    # Interfaces L1/L2/L3
    "get_loopbacks": ["interfaces", "loopback", "l3"],
    "get_routed_ports": ["interfaces", "routed", "l3"],
    "get_vlan_interfaces": ["interfaces", "svi", "vlan", "l3"],
    "get_lag": ["interfaces", "lag", "lacp", "link-aggregation",
                "port-channel", "bond", "aggregate", "trunk", "etherchannel"],
    "get_spanning_tree": ["l2", "spanning-tree", "stp", "rpvst", "mstp"],
    # Routing
    "get_bgp_config": ["routing", "bgp", "config"],
    "get_bgp_routes": ["routing", "bgp", "routes"],
    "get_ospf_overview": ["routing", "ospf", "overview"],
    "get_ospf_neighbors": ["routing", "ospf", "neighbors", "adjacency"],
    "get_ospf_interfaces": ["routing", "ospf", "interfaces"],
    # Overlay (EVPN / VXLAN)
    "get_evpn_config": ["overlay", "evpn", "config"],
    "get_evpn_routes": ["overlay", "evpn", "routes", "type-2", "type-5"],
    "get_evpn_multihoming": ["overlay", "evpn", "multihoming", "esi"],
    "get_evpn_vtep_neighbors": ["overlay", "evpn", "vtep", "neighbors"],
    "get_vxlan_config": ["overlay", "vxlan", "vtep", "config"],
    "get_vxlan_tunnels": ["overlay", "vxlan", "tunnels"],
    "get_vxlan_static_peers": ["overlay", "vxlan", "static", "static-vtep", "stub-vtep"],
    # Redundancy / stacking
    "get_vsx_status": ["redundancy", "vsx", "status"],
    "get_vsx_config": ["redundancy", "vsx", "config"],
    "get_vsx_sync": ["redundancy", "vsx", "sync", "isl"],
    "get_vsf_status": ["stacking", "vsf", "status"],
    "get_vsf_config": ["stacking", "vsf", "config"],
    # NAE / monitoring
    "get_nae_scripts": ["nae", "monitoring", "scripts"],
    "get_nae_script": ["nae", "monitoring", "script"],
    "get_nae_agents": ["nae", "monitoring", "agents"],
    "get_nae_agent": ["nae", "monitoring", "agent"],
    # Security — port-access / AAA / GBP / ABP
    "get_port_access_clients": ["security", "port-access", "clients", "dot1x", "mac-auth"],
    "get_port_access_auth_config": ["security", "port-access", "auth", "dot1x"],
    "get_port_access_summary": ["security", "port-access", "summary"],
    "get_port_access_client_detail": ["security", "port-access", "client", "detail"],
    "get_port_access_policies": ["security", "port-access", "policies"],
    "get_port_access_roles": ["security", "user-roles", "port-access", "roles"],
    "get_port_access_gbps": ["security", "gbp", "group-based-policy"],
    "get_gbp_role_maps": ["security", "gbp", "tags", "role-id", "sgt"],
    "get_port_access_abps": ["security", "abp", "application-based-policy"],
    "get_radius_servers": ["security", "aaa", "radius", "servers"],
    "get_tacacs_servers": ["security", "aaa", "tacacs", "servers"],
    "get_aaa_authentication": ["security", "aaa", "authentication"],
    "get_aaa_accounting": ["security", "aaa", "accounting"],
    # App visibility
    "get_app_recognition": ["app", "arc", "app-recognition"],
    "get_app_visibility": ["app", "visibility", "traffic-insight", "top-talkers"],
    # Config management
    "list_configs": ["config", "checkpoints", "list"],
    "compare_configs": ["config", "diff", "compare"],
    "get_full_config": ["config", "full", "running-config"],
    # Writes — configure_*
    "configure_loopback": ["interfaces", "loopback", "l3", "write"],
    "configure_routed_port": ["interfaces", "routed", "l3", "write"],
    "configure_vxlan_interface": ["overlay", "vxlan", "vtep", "stub-vtep", "static", "write"],
    "configure_evpn": ["overlay", "evpn", "write"],
    "configure_ospf": ["routing", "ospf", "write"],
    "configure_bgp": ["routing", "bgp", "write"],
    "configure_vrf": ["routing", "vrf", "write"],
    "configure_port_auth": ["security", "port-access", "dot1x", "mac-auth", "write"],
    "configure_app_recognition": ["app", "arc", "write"],
    "configure_virtual_mac": ["redundancy", "vsx", "virtual-mac", "write"],
    "configure_aaa": ["security", "aaa", "radius", "tacacs", "write"],
    "configure_user_roles": ["security", "user-roles", "gbp", "abp", "write"],
    # Verifies — verify_*
    "verify_loopback": ["verify", "interfaces", "loopback"],
    "verify_routed_port": ["verify", "interfaces", "routed"],
    "verify_vxlan_interface": ["verify", "overlay", "vxlan", "stub-vtep"],
    "verify_evpn": ["verify", "overlay", "evpn"],
    "verify_ospf": ["verify", "routing", "ospf"],
    "verify_bgp": ["verify", "routing", "bgp"],
    "verify_vrf": ["verify", "routing", "vrf"],
    "verify_port_auth": ["verify", "security", "port-access"],
    "verify_app_recognition": ["verify", "app", "arc"],
    "verify_virtual_mac": ["verify", "redundancy", "vsx"],
    "verify_aaa": ["verify", "security", "aaa", "radius", "tacacs"],
    "verify_user_roles": ["verify", "security", "user-roles", "gbp", "abp"],
}


def _auto_tags(name: str) -> list[str]:
    """Best-effort tags for a tool not present in TOOL_TAGS."""
    parts = [p for p in name.split("_") if p not in ("get", "list")]
    tags = list(dict.fromkeys(parts))  # dedupe, keep order
    if name.startswith("configure_") or name in WRITE_TOOLS:
        tags.append("write")
    if name.startswith("verify_"):
        tags.append("verify")
    return tags


# ──────────────────────────────────────────────────────────────────────
# FastMCP registry accessors (version-defensive)
# ──────────────────────────────────────────────────────────────────────


def _tool_manager(mcp: Any):
    return getattr(mcp, "_tool_manager", None) or getattr(mcp, "tool_manager", None)


def _registry(mcp: Any) -> Optional[dict]:
    """Return the live {name: ToolObject} dict, or None if not found."""
    mgr = _tool_manager(mcp)
    if mgr is None:
        return None
    for attr in ("_tools", "tools"):
        d = getattr(mgr, attr, None)
        if isinstance(d, dict):
            return d
    return None


def _tool_fn(tool_obj: Any) -> Optional[Callable]:
    for attr in ("fn", "func", "handler", "callback", "_fn"):
        f = getattr(tool_obj, attr, None)
        if callable(f):
            return f
    return None


def _tool_schema(tool_obj: Any) -> dict:
    for attr in ("parameters", "inputSchema", "input_schema", "schema"):
        s = getattr(tool_obj, attr, None)
        if isinstance(s, dict):
            return s
    return {}


def _tool_description(tool_obj: Any) -> str:
    return getattr(tool_obj, "description", "") or ""


# ──────────────────────────────────────────────────────────────────────
# Write guard
# ──────────────────────────────────────────────────────────────────────

# Optional external policy, installed via install_deferred_tools.
_WRITES_ALLOWED_CB: Optional[Callable[[ToolSpec, dict], bool]] = None


def _env_true(name: str, default: str = "false") -> bool:
    return os.getenv(name, default).strip().lower() in ("1", "true", "yes", "on")


def _write_permitted(spec: ToolSpec, arguments: dict) -> bool:
    if not spec.write:
        return True
    if not _env_true("CX_INVOKE_WRITES", "true"):
        return False
    if _WRITES_ALLOWED_CB is not None:
        try:
            return bool(_WRITES_ALLOWED_CB(spec, arguments))
        except Exception:  # pragma: no cover - policy must never crash invoke
            log.exception("writes_allowed callback raised; denying write")
            return False
    return True


# ──────────────────────────────────────────────────────────────────────
# Prefix-aware name coherence + Tier-1 fn resolution
# ──────────────────────────────────────────────────────────────────────


def _prefixes_active() -> bool:
    return _tp is not None and _env_true("CX_TOOL_PREFIXES")


def _display_name(original_name: str) -> str:
    """Advertised name for a deferred tool (prefixed when prefixes are on)."""
    if _prefixes_active():
        try:
            return _tp.prefixed(original_name)
        except Exception:
            return original_name
    return original_name


def _resolve_original(name: str) -> str:
    """Map an incoming (possibly prefixed) tool name to its original key."""
    if name in _DEFERRED:
        return name
    if _tp is not None:
        try:
            o = _tp.original(name)
        except Exception:
            o = name
        if o in _DEFERRED:
            return o
    return name


def _resolve_fn(tool: str) -> Optional[Callable[..., Any]]:
    """Resolve a callable for a tool name, whether it is deferred (Tier-2) or
    still advertised (Tier-1, possibly under a prefixed registry key)."""
    spec = _DEFERRED.get(tool)
    if spec is None and _tp is not None:
        try:
            spec = _DEFERRED.get(_tp.original(tool))
        except Exception:
            spec = None
    if spec is not None:
        return spec.fn
    if _LIVE_REGISTRY is not None:
        obj = _LIVE_REGISTRY.get(tool)
        if obj is None and _tp is not None:
            try:
                obj = _LIVE_REGISTRY.get(_tp.prefixed(tool))
            except Exception:
                obj = None
        if obj is not None:
            return _tool_fn(obj)
    return None


# ──────────────────────────────────────────────────────────────────────
# Meta-tool implementations (registered onto the FastMCP instance)
# ──────────────────────────────────────────────────────────────────────


async def _search_tools(query: str, limit: int = 8,
                        include_write: bool = True,
                        tags: Optional[list] = None) -> dict:
    """Discover deferred (Tier-2) tools by keyword.

    Use this when the capability you need is not among the always-loaded
    Tier-1 tools (e.g. "vxlan static peer", "radius server", "ospf neighbor").
    Then call the chosen tool through ``invoke_tool``.

    Returns each match's name, description, tags, whether it writes config,
    and its JSON-Schema parameters (ready to pass to ``invoke_tool``).
    """
    if not query or not query.strip():
        return {"error": "query is required", "results": [], "count": 0}
    try:
        limit = max(1, min(int(limit), 25))
    except (TypeError, ValueError):
        limit = 8
    want_tags = {t.lower() for t in (tags or [])}
    words = [w for w in query.lower().split() if w]

    scored: list[tuple[int, dict]] = []
    for spec in _DEFERRED.values():
        if spec.write and not include_write:
            continue
        if want_tags and not want_tags.issubset({t.lower() for t in spec.tags}):
            continue
        hay = f"{spec.name} {spec.description} {' '.join(spec.tags)}".lower()
        score = sum(1 for w in words if w in hay)
        if words and score == 0:
            continue
        scored.append((score, {
            "name": _display_name(spec.name),
            "description": spec.description,
            "tags": spec.tags,
            "write": spec.write,
            "parameters": spec.schema,
        }))

    scored.sort(key=lambda x: (-x[0], x[1]["name"]))
    results = [item for _, item in scored[:limit]]
    return {"query": query, "count": len(results), "results": results}


async def _invoke_tool(name: str, arguments: Optional[dict] = None) -> dict:
    """Execute a deferred (Tier-2) tool by name with the given arguments.

    Discover names/parameters first with ``search_tools``. ``arguments`` must
    match the tool's JSON-Schema. Returns an envelope:
    ``{"ok": true, "tool": <name>, "result": <tool output>}`` on success, or
    ``{"ok": false, "error": ...}`` on any failure (never raises).
    """
    arguments = arguments or {}
    if not isinstance(arguments, dict):
        return {"ok": False, "error": "arguments must be an object/dict"}

    orig = _resolve_original(name)
    spec = _DEFERRED.get(orig)
    if spec is None:
        base = name
        if _tp is not None:
            try:
                base = _tp.original(name)
            except Exception:
                base = name
        if base in TIER1 or base in _META:
            return {"ok": False, "error": f"'{name}' is a Tier-1 tool; call it directly"}
        suggestions = difflib.get_close_matches(base, list(_DEFERRED), n=3)
        return {"ok": False, "error": f"unknown deferred tool: {name}",
                "did_you_mean": suggestions}

    if not _write_permitted(spec, arguments):
        return {"ok": False, "error": "write tools are disabled in this context",
                "tool": spec.name}

    apply_flag = bool(arguments.get("apply"))
    # Enforcement: when a dry_run_token is required, a direct apply via
    # invoke_tool is refused — the caller must preview then call apply_plan.
    if spec.write and apply_flag and _ws is not None and _ws.requires_token:
        return {"ok": False, "tool": spec.name,
                "error": "dry_run_token required: invoke with apply=false to "
                         "preview, then call apply_plan(dry_run_token=...)."}

    try:
        result = spec.fn(**arguments)
        if inspect.isawaitable(result):
            result = await result
    except TypeError as exc:
        return {"ok": False, "error": "invalid arguments", "detail": str(exc),
                "tool": spec.name, "parameters": spec.schema}
    except Exception as exc:  # surface tool failures as data, not protocol errors
        return {"ok": False, "error": type(exc).__name__, "detail": str(exc),
                "tool": spec.name}

    # Preview of a write -> freeze a replayable dry_run_token onto the result.
    token = None
    if (spec.write and not apply_flag and _ws is not None and _ws.enabled
            and isinstance(result, dict) and result.get("status") == "planned"):
        try:
            _ws.freeze_recipe(
                result, spec.name,
                result.get("targets") or [], result.get("plan") or {},
                tool=spec.name, arguments=arguments,
            )
            token = result.get("dry_run_token")
        except Exception:  # token issuance must never break the preview
            log.exception("freeze_recipe failed for %s", spec.name)

    envelope = {"ok": True, "tool": spec.name, "result": result}
    if token:
        envelope["dry_run_token"] = token
    return envelope


async def _apply_plan(dry_run_token: str) -> dict:
    """Apply a previously previewed write plan by its ``dry_run_token``.

    Re-runs the exact tool + arguments captured at preview time: first a fresh
    preview (apply=false) to confirm the plan is unchanged (TOCTOU guard), then
    the real apply (apply=true). Returns the applied result and, when the plan
    is reversible, a ``rollback_id`` usable with the ``rollback`` tool.
    """
    if _ws is None or not _ws.enabled:
        return {"ok": False, "error": "write safety is disabled"}
    if not dry_run_token:
        return {"ok": False, "error": "dry_run_token is required"}

    ok, reason, recipe = _ws.redeem(dry_run_token)
    if not ok:
        return {"ok": False, "error": reason}
    if not recipe or "tool" not in recipe:
        return {"ok": False, "error": "token has no replay recipe"}

    tool = recipe["tool"]
    args = dict(recipe.get("arguments") or {})
    fn = _resolve_fn(tool)
    if fn is None:
        return {"ok": False, "error": f"tool not found for replay: {tool}"}

    # 1) Re-preview and confirm the plan hash still matches the frozen one.
    try:
        preview = fn(**{**args, "apply": False})
        if inspect.isawaitable(preview):
            preview = await preview
    except Exception as exc:
        return {"ok": False, "error": "re-preview failed", "detail": str(exc)}
    fresh_plan = preview.get("plan") if isinstance(preview, dict) else None
    ok2, reason2, _ = _ws.redeem(dry_run_token, operation=tool, plan=fresh_plan)
    if not ok2:
        return {"ok": False, "error": f"plan changed since preview: {reason2}"}

    # 2) Apply for real.
    try:
        applied = fn(**{**args, "apply": True})
        if inspect.isawaitable(applied):
            applied = await applied
    except Exception as exc:
        return {"ok": False, "error": "apply failed", "detail": str(exc)}

    _ws.consume(dry_run_token)

    rollback_id = None
    if isinstance(applied, dict) and applied.get("status") in ("applied", "partial"):
        try:
            targets = list(fresh_plan.keys()) if isinstance(fresh_plan, dict) else []
            rollback_id = _ws.record(tool, targets, fresh_plan or {})
            if rollback_id:
                applied["rollback_id"] = rollback_id
        except Exception:
            log.exception("rollback journaling failed for %s", tool)

    return {"ok": True, "tool": tool, "result": applied, "rollback_id": rollback_id}


# ──────────────────────────────────────────────────────────────────────
# Public entry point — call ONCE at the end of server.py
# ──────────────────────────────────────────────────────────────────────


def install_deferred_tools(
    mcp: Any,
    *,
    writes_allowed: Optional[Callable[[ToolSpec, dict], bool]] = None,
    enabled_env: str = "CX_DEFERRED_TOOLS",
) -> dict:
    """Wire the progressive-disclosure layer onto an existing FastMCP server.

    Idempotent and safe: when ``$CX_DEFERRED_TOOLS`` is not truthy this is a
    no-op and the server keeps advertising every tool exactly as before.

    Parameters
    ----------
    mcp:
        The FastMCP instance (the same object decorated with ``@mcp.tool()``).
    writes_allowed:
        Optional policy ``(ToolSpec, arguments) -> bool`` consulted by
        ``invoke_tool`` for write tools. If omitted, writes are allowed when
        ``$CX_INVOKE_WRITES`` is truthy (default true) and the underlying
        tool's own guards apply.
    enabled_env:
        Name of the activation flag (default ``CX_DEFERRED_TOOLS``).

    Returns
    -------
    A summary dict ``{"enabled", "advertised", "deferred", "missing_tier1"}``.
    """
    global _WRITES_ALLOWED_CB
    _WRITES_ALLOWED_CB = writes_allowed

    if not _env_true(enabled_env):
        log.info("Deferred tools DISABLED (%s not set) — server unchanged.", enabled_env)
        return {"enabled": False, "advertised": None, "deferred": 0,
                "missing_tier1": []}

    registry = _registry(mcp)
    if registry is None:
        log.warning("Could not locate FastMCP tool registry — leaving server "
                    "unchanged (all tools stay advertised).")
        return {"enabled": False, "advertised": None, "deferred": 0,
                "missing_tier1": []}

    global _LIVE_REGISTRY
    _LIVE_REGISTRY = registry

    # 1) Register the meta-tools (advertised, Tier-1).
    mcp.tool()(_search_tools)
    mcp.tool()(_invoke_tool)
    # FastMCP keys tools by function name; rename the registry entries so they
    # appear as 'search_tools' / 'invoke_tool' regardless of the private fn name.
    _rename_registry_entry(registry, "_search_tools", "search_tools")
    _rename_registry_entry(registry, "_invoke_tool", "invoke_tool")
    # apply_plan only makes sense when the write-safety layer is active.
    if _ws is not None and _ws.enabled:
        mcp.tool()(_apply_plan)
        _rename_registry_entry(registry, "_apply_plan", "apply_plan")

    # 2) Demote everything that is not Tier-1 and not a meta-tool.
    _DEFERRED.clear()
    for tool_name in list(registry.keys()):
        if tool_name in TIER1 or tool_name in _META:
            continue
        tool_obj = registry[tool_name]
        fn = _tool_fn(tool_obj)
        if fn is None:
            log.warning("Tool %s has no callable; not demoting.", tool_name)
            continue
        _DEFERRED[tool_name] = ToolSpec(
            name=tool_name,
            fn=fn,
            schema=_tool_schema(tool_obj),
            description=_tool_description(tool_obj),
            tags=TOOL_TAGS.get(tool_name) or _auto_tags(tool_name),
            write=tool_name in WRITE_TOOLS,
        )
        del registry[tool_name]

    advertised = sorted(registry.keys())
    missing = sorted(n for n in TIER1 if n not in registry and n not in _DEFERRED)
    log.info("Deferred tools ENABLED: %d advertised, %d deferred.",
             len(advertised), len(_DEFERRED))
    if missing:
        log.info("Tier-1 names not found in registry (ignored): %s",
                 ", ".join(missing))
    return {"enabled": True, "advertised": advertised,
            "deferred": len(_DEFERRED), "missing_tier1": missing}


def _rename_registry_entry(registry: dict, old: str, new: str) -> None:
    """Move a freshly registered meta-tool from its private fn name to the
    public name, fixing the tool's own .name attribute if present."""
    if old in registry and new not in registry:
        obj = registry.pop(old)
        for attr in ("name", "_name"):
            if getattr(obj, attr, None) == old:
                try:
                    setattr(obj, attr, new)
                except Exception:
                    pass
        registry[new] = obj
