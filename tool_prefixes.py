"""Functional tool-prefix layer for the cx-mcp server (PROPOSAL / PREPARED).

Standalone and inert: importing this module changes nothing. The advertised
tool names are only rewritten if you call ``apply_tool_prefixes(mcp)`` once at
the end of ``server.py`` AND set ``CX_TOOL_PREFIXES=true``.

Principle (as requested)
------------------------
Add a *functional prefix* in front of each existing tool name, keeping the
original name unchanged after the ``__`` separator. This is a pure, mechanical,
reversible mapping::

    get_bgp_neighbors        -> routing__get_bgp_neighbors
    configure_user_roles     -> security__configure_user_roles
    manage_config            -> config__manage_config

Why an aliasing layer instead of editing 101 decorators?
--------------------------------------------------------
The Python function names stay as they are; only the *advertised* MCP tool name
(what the agent sees on ``tools/list``) is rewritten at startup by mutating
FastMCP's registry. Same approach as ``deferred_tools.py``: one hook, fully
gated, fail-open to current behaviour if anything is off.

Activation (LATER, not now)
---------------------------
1. At the very end of ``server.py`` (after every ``@mcp.tool()``):

       from tool_prefixes import apply_tool_prefixes
       apply_tool_prefixes(mcp)

2. In ``docker-compose.yml`` under ``environment:``::

       CX_TOOL_PREFIXES: "true"   # absent/false = names unchanged (default)

Composition with deferred_tools.py
----------------------------------
If you enable BOTH features, apply prefixes is just a display-name rewrite, so
it must run AFTER ``install_deferred_tools`` so that the Tier-1 / WRITE_TOOLS
sets (which use the ORIGINAL names) still match. Use ``prefixed(name)`` /
``original(name)`` below to translate between the two name spaces. The
recommended order at the end of server.py is::

       install_deferred_tools(mcp)   # demote using original names
       apply_tool_prefixes(mcp)      # then prefix the survivors + meta-tools

(With deferral on, only ~23 names survive to be prefixed — cheap and safe.)
"""

from __future__ import annotations

import logging
import os
from typing import Any, Optional

log = logging.getLogger("cx-mcp.prefixes")


# ──────────────────────────────────────────────────────────────────────
# Domain -> original tool names. New name = "<domain>__" + original.
# Names that do not exist in the running server are ignored (harmless).
# ──────────────────────────────────────────────────────────────────────

DOMAINS: dict[str, list[str]] = {
    "inventory": [
        "list_inventory_sources", "list_devices", "list_sites",
        "find_devices", "resolve_device", "refresh_inventory", "run_on_site",
    ],
    "exec": [  # universal escape hatches / raw execution
        "run_cli_command", "get_cli_supported_commands",
        "run_ssh_command", "run_ssh_commands", "get_raw_api",
    ],
    "system": [
        "get_system_info", "get_hardware_health", "get_boot_history",
        "get_capacities", "get_ssh_config", "get_containers", "get_feature_pack",
        "get_maintenance_mode", "get_aruba_central", "get_logs", "logout",
    ],
    "diag": [  # on-device automated troubleshoot / diagnostics (AOS-CX 10.18+)
        "list_troubleshoot_features", "run_troubleshoot",
    ],
    "interface": [
        "get_interfaces", "get_transceivers", "get_loopbacks",
        "get_interface_counters", "get_supported_transceivers",
        "get_poe_status",
        "get_routed_ports", "get_vlan_interfaces", "get_lag",
        "configure_loopback", "configure_routed_port",
        "verify_loopback", "verify_routed_port",
    ],
    "switching": [  # L2
        "get_vlans", "get_mac_table", "get_lldp_neighbors", "get_spanning_tree",
    ],
    "routing": [
        "get_routing_table", "get_arp_table",
        "get_bgp_neighbors", "get_bgp_config", "get_bgp_routes",
        "get_bgp_neighbor_routes",
        "get_ospf_overview", "get_ospf_neighbors", "get_ospf_interfaces",
        "configure_bgp", "configure_ospf", "configure_vrf",
        "verify_bgp", "verify_ospf", "verify_vrf",
    ],
    "overlay": [  # EVPN / VXLAN
        "get_evpn_config", "get_evpn_routes", "get_evpn_multihoming",
        "get_evpn_vtep_neighbors", "get_vxlan_config", "get_vxlan_tunnels",
        "get_vxlan_static_peers", "configure_vxlan_interface", "configure_evpn",
        "verify_vxlan_interface", "verify_evpn",
    ],
    "redundancy": [
        "get_vsx_status", "get_vsx_config", "get_vsx_sync",
        "get_vsf_status", "get_vsf_config",
        "configure_virtual_mac", "verify_virtual_mac",
    ],
    "security": [
        "get_port_access_clients", "get_port_access_auth_config",
        "get_port_access_summary", "get_port_access_client_detail",
        "get_port_access_policies", "get_port_access_roles",
        "get_port_access_gbps", "get_gbp_role_maps", "get_port_access_abps",
        "get_radius_servers", "get_tacacs_servers",
        "get_aaa_authentication", "get_aaa_accounting",
        "configure_port_auth", "configure_aaa", "configure_user_roles",
        "verify_port_auth", "verify_aaa", "verify_user_roles",
    ],
    "app": [
        "get_app_recognition", "get_app_visibility",
        "configure_app_recognition", "verify_app_recognition",
    ],
    "nae": [
        "get_nae_scripts", "get_nae_script", "get_nae_agents", "get_nae_agent",
    ],
    "config": [
        "list_configs", "compare_configs", "get_config",
        "get_full_config", "manage_config", "backup_config",
    ],
    "service": [  # orchestrated provisioning
        "create_vlan_service", "delete_vlan_service",
    ],
    "meta": [  # registered by deferred_tools.py / write-safety layer
        "search_tools", "invoke_tool", "apply_plan", "rollback",
    ],
}

SEP = "__"

# original -> prefixed  (e.g. "get_bgp_neighbors" -> "routing__get_bgp_neighbors")
RENAME_MAP: dict[str, str] = {
    name: f"{domain}{SEP}{name}"
    for domain, names in DOMAINS.items()
    for name in names
}

# prefixed -> original  (reverse lookup)
REVERSE_MAP: dict[str, str] = {new: old for old, new in RENAME_MAP.items()}


def prefixed(original_name: str) -> str:
    """Return the advertised (prefixed) name for an original tool name."""
    return RENAME_MAP.get(original_name, original_name)


def original(prefixed_name: str) -> str:
    """Return the original tool name for a prefixed advertised name."""
    return REVERSE_MAP.get(prefixed_name, prefixed_name)


def domain_of(original_name: str) -> Optional[str]:
    """Return the domain prefix assigned to a tool, or None if unmapped."""
    new = RENAME_MAP.get(original_name)
    return new.split(SEP, 1)[0] if new else None


# ──────────────────────────────────────────────────────────────────────
# Startup aliasing (inert until called + env-gated)
# ──────────────────────────────────────────────────────────────────────


def _env_true(name: str, default: str = "false") -> bool:
    return os.getenv(name, default).strip().lower() in ("1", "true", "yes", "on")


def _registry(mcp: Any) -> Optional[dict]:
    mgr = getattr(mcp, "_tool_manager", None) or getattr(mcp, "tool_manager", None)
    if mgr is None:
        return None
    for attr in ("_tools", "tools"):
        d = getattr(mgr, attr, None)
        if isinstance(d, dict):
            return d
    return None


def _set_tool_name(tool_obj: Any, new_name: str) -> None:
    for attr in ("name", "_name"):
        if hasattr(tool_obj, attr):
            try:
                setattr(tool_obj, attr, new_name)
            except Exception:  # pragma: no cover
                pass


def apply_tool_prefixes(mcp: Any, *, enabled_env: str = "CX_TOOL_PREFIXES") -> dict:
    """Rewrite advertised tool names with their functional prefix.

    No-op (and safe) when ``$CX_TOOL_PREFIXES`` is not truthy or when the
    FastMCP registry cannot be located. Already-prefixed names are skipped, so
    the call is idempotent.

    Returns ``{"enabled", "renamed", "skipped", "unmapped"}``.
    """
    if not _env_true(enabled_env):
        log.info("Tool prefixes DISABLED (%s not set) — names unchanged.", enabled_env)
        return {"enabled": False, "renamed": 0, "skipped": 0, "unmapped": []}

    registry = _registry(mcp)
    if registry is None:
        log.warning("Could not locate FastMCP tool registry — names unchanged.")
        return {"enabled": False, "renamed": 0, "skipped": 0, "unmapped": []}

    renamed = 0
    skipped = 0
    unmapped: list[str] = []
    for old_name in list(registry.keys()):
        if SEP in old_name and old_name in REVERSE_MAP:
            skipped += 1  # already prefixed
            continue
        new_name = RENAME_MAP.get(old_name)
        if new_name is None:
            unmapped.append(old_name)
            continue
        if new_name in registry:
            log.warning("Prefix collision for %s -> %s; skipping.", old_name, new_name)
            continue
        tool_obj = registry.pop(old_name)
        _set_tool_name(tool_obj, new_name)
        registry[new_name] = tool_obj
        renamed += 1

    log.info("Tool prefixes ENABLED: %d renamed, %d skipped.", renamed, skipped)
    if unmapped:
        log.info("Tools with no domain mapping (left as-is): %s", ", ".join(sorted(unmapped)))
    return {"enabled": True, "renamed": renamed, "skipped": skipped,
            "unmapped": sorted(unmapped)}
