"""Flat dispatcher toolset for the cx-mcp server (gated by ``CX_FLAT_TOOLSET``).

This module is **completely standalone**: importing it has NO effect on the
existing server. Nothing runs until ``install_flat_toolset(mcp, srv)`` is called
once, at the very end of ``server.py`` (after every ``@mcp.tool()`` definition).

Goal
----
Collapse the ~101 atomic tools into a small, curated set of **flat dispatchers**
(scope/action driven). Every dispatcher simply *routes* to the existing legacy
tool functions/REST client methods — there is **zero REST regression** because
the firmware-aware client code is untouched.

Activation is gated by ``CX_FLAT_TOOLSET``:

    * ``CX_FLAT_TOOLSET=true``  -> legacy tools are de-advertised and ~23 flat
      dispatchers (+ a handful of kept-atomic tools) are advertised instead.
    * ``CX_FLAT_TOOLSET=false`` (default) -> no-op; the server behaves exactly as
      today. This is the instant rollback path.

Design
------
* **Batch everywhere**: every read dispatcher accepts ``device: str | list`` (or
  ``site``) and fans out the underlying REST call in parallel, returning a single
  envelope ``{scope, results, errors, summary}``.
* **REST-first**: dispatchers only call the existing client/tool functions. SSH
  remains reachable through the kept-atomic ``run_ssh_commands`` tool.
* **Writes keep the plan/apply lifecycle**: ``action=plan|apply|verify`` maps to
  the existing ``configure_*``/``verify_*`` functions (which already embed the
  read-only guard, ``_domain_write`` and write-safety rollback).

FastMCP internals
-----------------
De-advertising legacy tools needs to mutate FastMCP's tool registry. The
accessors below try several attribute names so the module survives minor FastMCP
version differences; if the registry cannot be located, ``install_flat_toolset``
logs a warning and leaves the server untouched (safe fail-open).
"""

from __future__ import annotations

import asyncio
import inspect
import json
import logging
import os
from typing import Any, Callable, Optional

log = logging.getLogger("cx-mcp.flat")

# Server module, captured at install time so dispatchers can reach the legacy
# tool functions and the shared helpers (_resolve_devices, _get_client, ...).
_SRV: Any = None


# ──────────────────────────────────────────────────────────────────────
# Env helper
# ──────────────────────────────────────────────────────────────────────
def _env_true(name: str, default: str = "false") -> bool:
    return os.getenv(name, default).strip().lower() in ("1", "true", "yes", "on")


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


# ──────────────────────────────────────────────────────────────────────
# Target resolution + parallel fan-out
# ──────────────────────────────────────────────────────────────────────
def _coerce_device_list(device) -> list:
    """Normalize the ``device`` argument into a list of device names.

    Tolerant of MCP clients that serialize an array as a *string* instead of a
    real JSON array — e.g. ``'["Access-01","Access-02"]'``, ``"['A','B']"`` or
    plain comma-separated ``"Access-01, Access-02"``. A single device name passes
    through unchanged. This keeps batched reads working regardless of how the
    calling client encodes list arguments."""
    if device is None:
        return []
    if isinstance(device, (list, tuple)):
        return [str(d).strip() for d in device if d is not None and str(d).strip()]
    if isinstance(device, str):
        s = device.strip()
        if not s:
            return []
        # JSON-array-looking string: '["A","B"]' or "['A','B']"
        if s[0] == "[" and s[-1] == "]":
            try:
                parsed = json.loads(s)
                if isinstance(parsed, list):
                    return [str(d).strip() for d in parsed if str(d).strip()]
            except Exception:  # noqa: BLE001 — tolerate single quotes / loose fmt
                pass
            inner = s[1:-1]
            return [p.strip().strip("'\"") for p in inner.split(",")
                    if p.strip().strip("'\"")]
        # Comma-separated string: "A,B"
        if "," in s:
            return [p.strip() for p in s.split(",") if p.strip()]
        return [s]
    return [device]


async def _resolve_targets(device, site, source: str = None) -> list[str]:
    """Resolve targets into a de-duplicated, order-preserving list of canonical
    device names. Precedence: `source` (external SoT query via find_devices,
    intersected with the locally-connectable inventory) > `site` >
    `device` (str | list[str] | stringified list)."""
    names: list[str] = []
    if source:
        try:
            res = await _SRV.find_devices(source=source, site=site)
            ext = [d.get("name") for d in (res.get("devices") or []) if d.get("name")]
        except Exception as exc:  # noqa: BLE001 — targeting must never crash a read
            log.warning("flat_tools: find_devices(source=%s) failed: %s", source, exc)
            ext = []
        for n in ext:
            try:  # keep only devices that are locally connectable
                names.append(_SRV._canonical_device(n))
            except Exception:
                continue
    elif site:
        names.extend(_SRV._resolve_devices(site=site))
    else:
        for d in _coerce_device_list(device):
            names.extend(_SRV._resolve_devices(device=d))
    seen: set[str] = set()
    out: list[str] = []
    for n in names:
        if n not in seen:
            seen.add(n)
            out.append(n)
    return out


def _filtered_kwargs(fn: Callable, kwargs: dict) -> dict:
    """Keep only the kwargs the target function actually accepts (drop None)."""
    try:
        params = inspect.signature(fn).parameters
    except (TypeError, ValueError):
        return {k: v for k, v in kwargs.items() if v is not None}
    return {k: v for k, v in kwargs.items()
            if k in params and k != "device" and v is not None}


async def _fanout(fn_name: str, targets: list[str], kwargs: dict) -> tuple[dict, dict]:
    """Call ``_SRV.<fn_name>(device=t, **filtered)`` on every target in parallel.
    Returns (results_by_device, errors_by_device)."""
    fn = getattr(_SRV, fn_name, None)
    if fn is None:
        return {}, {t: f"internal: unknown function '{fn_name}'" for t in targets}
    allowed = _filtered_kwargs(fn, kwargs)

    async def _one(target: str):
        try:
            return target, await fn(device=target, **allowed), None
        except Exception as exc:  # noqa: BLE001 — isolate per-device failure
            return target, None, f"{type(exc).__name__}: {exc}"

    pairs = await asyncio.gather(*[_one(t) for t in targets])
    results: dict[str, Any] = {}
    errors: dict[str, str] = {}
    for target, data, err in pairs:
        if err is None:
            results[target] = data
        else:
            errors[target] = err
    return results, errors


def _envelope(scope: str, targets: list[str], results: dict, errors: dict) -> dict:
    return {
        "scope": scope,
        "results": results,
        "errors": errors,
        "summary": {"ok": len(results), "failed": len(errors),
                    "total": len(targets), "devices": targets},
    }


def _apply_limit(results: dict, limit: Optional[int]) -> dict:
    """Safety-net truncation: when `limit` is set (>0), cap every list field of
    each per-device result to `limit` items and annotate what was truncated.
    Opt-in (no effect when limit is None/<=0) so full data is returned by
    default."""
    if not limit or limit <= 0:
        return results
    for data in results.values():
        if not isinstance(data, dict):
            continue
        for key, value in list(data.items()):
            if isinstance(value, list) and len(value) > limit:
                data[key] = value[:limit]
                data[f"{key}_truncated"] = {"shown": limit, "total": len(value)}
    return results


async def _read_dispatch(tool: str, mapping: dict, scope: str,
                         device, site, kwargs: dict, source: str = None,
                         limit: int = None) -> dict:
    """Generic read dispatcher: resolve scope→legacy fn, fan out, wrap."""
    fn_name = mapping.get(scope)
    if not fn_name:
        return {"error": f"[{tool}] unknown scope '{scope}'",
                "valid_scopes": sorted(mapping)}
    targets = await _resolve_targets(device, site, source)
    if not targets:
        return {"error": f"[{tool}] no target device — provide `device`, `site` or `source`."}
    results, errors = await _fanout(fn_name, targets, kwargs)
    _apply_limit(results, limit)
    return _envelope(scope, targets, results, errors)


# ──────────────────────────────────────────────────────────────────────
# Scope → legacy-function maps
# ──────────────────────────────────────────────────────────────────────
_MAP_SYSTEM = {
    "info": "get_system_info", "environment": "get_hardware_health",
    "capacity": "get_capacities", "boot": "get_boot_history",
    "maintenance": "get_maintenance_mode", "containers": "get_containers",
    "feature_pack": "get_feature_pack", "central": "get_aruba_central",
    "ssh": "get_ssh_config",
    "supported_transceivers": "get_supported_transceivers",
    # "inventory" is handled specially (reshaped from get_hardware_health).
}
_MAP_INTERFACES = {
    "physical": "get_interfaces", "transceivers": "get_transceivers",
    "counters": "get_interface_counters",
    "supported_transceivers": "get_supported_transceivers",
    "poe": "get_poe_status",
    "loopbacks": "get_loopbacks", "routed": "get_routed_ports",
    "svi": "get_vlan_interfaces", "lag": "get_lag",
}
_MAP_SWITCHING = {
    "vlans": "get_vlans", "mac": "get_mac_table",
    "lldp": "get_lldp_neighbors", "spanning_tree": "get_spanning_tree",
}
_MAP_ROUTING = {
    "bgp_summary": "get_bgp_neighbors", "bgp_neighbors": "get_bgp_neighbors",
    "bgp_config": "get_bgp_config", "bgp_routes": "get_bgp_routes",
    "neighbor_routes": "get_bgp_neighbor_routes",
    "ospf_overview": "get_ospf_overview", "ospf_neighbors": "get_ospf_neighbors",
    "ospf_interfaces": "get_ospf_interfaces", "route_table": "get_routing_table",
    "arp": "get_arp_table",
}
_MAP_OVERLAY = {
    "evpn_config": "get_evpn_config", "evpn_routes": "get_evpn_routes",
    "evpn_multihoming": "get_evpn_multihoming",
    "vtep_neighbors": "get_evpn_vtep_neighbors", "vxlan_config": "get_vxlan_config",
    "vxlan_tunnels": "get_vxlan_tunnels", "vxlan_static_peers": "get_vxlan_static_peers",
}
_MAP_REDUNDANCY = {
    "vsx_status": "get_vsx_status", "vsx_config": "get_vsx_config",
    "vsx_sync": "get_vsx_sync", "vsf_status": "get_vsf_status",
    "vsf_config": "get_vsf_config",
}
_MAP_ACCESS = {
    "clients": "get_port_access_clients", "client_detail": "get_port_access_client_detail",
    "auth_config": "get_port_access_auth_config", "summary": "get_port_access_summary",
    "roles": "get_port_access_roles", "gbp": "get_port_access_gbps",
    "gbp_maps": "get_gbp_role_maps", "abp": "get_port_access_abps",
    "policies": "get_port_access_policies", "radius": "get_radius_servers",
    "tacacs": "get_tacacs_servers", "authentication": "get_aaa_authentication",
    "accounting": "get_aaa_accounting",
}
_MAP_AUTOMATION = {
    "nae_scripts": "get_nae_scripts", "nae_script": "get_nae_script",
    "nae_agents": "get_nae_agents", "nae_agent": "get_nae_agent",
}
_MAP_APPS = {
    "recognition": "get_app_recognition", "visibility": "get_app_visibility",
}

# Writes: scope -> (configure_fn, verify_fn)
_MAP_W_INTERFACE = {
    "loopback": ("configure_loopback", "verify_loopback"),
    "routed_port": ("configure_routed_port", "verify_routed_port"),
    "vxlan": ("configure_vxlan_interface", "verify_vxlan_interface"),
    "virtual_mac": ("configure_virtual_mac", "verify_virtual_mac"),
}
_MAP_W_ROUTING = {
    "ospf": ("configure_ospf", "verify_ospf"),
    "bgp": ("configure_bgp", "verify_bgp"),
    "vrf": ("configure_vrf", "verify_vrf"),
    "evpn": ("configure_evpn", "verify_evpn"),
}
_MAP_W_SECURITY = {
    "port_auth": ("configure_port_auth", "verify_port_auth"),
    "aaa": ("configure_aaa", "verify_aaa"),
    "user_roles": ("configure_user_roles", "verify_user_roles"),
    "app_recognition": ("configure_app_recognition", "verify_app_recognition"),
}

# Diagnose: scope -> ordered list of (label, legacy_fn, extra_kwargs)
_MAP_DIAGNOSE = {
    "device": [("system", "get_system_info", {}), ("interfaces", "get_interfaces", {}),
               ("vlans", "get_vlans", {}), ("logs", "get_logs", {"limit": 20})],
    "evpn": [("evpn_config", "get_evpn_config", {}), ("vxlan_tunnels", "get_vxlan_tunnels", {}),
             ("vtep_neighbors", "get_evpn_vtep_neighbors", {}),
             ("bgp_neighbors", "get_bgp_neighbors", {})],
    "client": [("mac", "get_mac_table", {}), ("arp", "get_arp_table", {}),
               ("lldp", "get_lldp_neighbors", {}), ("port_access", "get_port_access_summary", {})],
}


# ──────────────────────────────────────────────────────────────────────
# Write dispatch helper
# ──────────────────────────────────────────────────────────────────────
async def _write_dispatch(tool: str, mapping: dict, scope: str, action: str,
                          device, site, params: dict) -> dict:
    entry = mapping.get(scope)
    if not entry:
        return {"error": f"[{tool}] unknown scope '{scope}'",
                "valid_scopes": sorted(mapping)}
    cfg_name, verify_name = entry
    base = dict(params or {})
    if action == "verify":
        fn = getattr(_SRV, verify_name, None)
        if fn is None:
            return {"error": f"[{tool}] no verify action for scope '{scope}'"}
        call = _filtered_kwargs(fn, dict(base, site=site))
        return await fn(device=device, site=site, **{k: v for k, v in call.items()
                                                     if k != "site"})
    if action not in ("plan", "apply"):
        return {"error": f"[{tool}] invalid action '{action}'",
                "valid_actions": ["plan", "apply", "verify"]}
    fn = getattr(_SRV, cfg_name)
    apply = action == "apply"
    call = _filtered_kwargs(fn, dict(base, site=site, apply=apply))
    return await fn(device=device, **call)


# ──────────────────────────────────────────────────────────────────────
# Dispatcher tool implementations
# ──────────────────────────────────────────────────────────────────────
async def manage_inventory(scope: str = "sources", device: str = None,
                           site: str = None, source: str = None,
                           role: str = None, model: str = None,
                           tag: str = None, probe: bool = False) -> dict:
    """Inventory management. `scope`:
      - sources : list configured inventory sources (probe=True to test reachability)
      - resolve : resolve a device name/alias/IP -> canonical record (needs `device`)
      - refresh : reload the dynamic inventory cache
      - find    : search devices by site/source/role/model/tag filters
    """
    if scope == "sources":
        return await _SRV.list_inventory_sources(probe=probe)
    if scope == "refresh":
        return await _SRV.refresh_inventory()
    if scope == "resolve":
        if not device:
            return {"error": "[manage_inventory] resolve requires `device`."}
        return await _SRV.resolve_device(device)
    if scope == "find":
        fn = _SRV.find_devices
        kw = _filtered_kwargs(fn, {"site": site, "source": source, "role": role,
                                   "model": model, "tag": tag})
        return await fn(**kw)
    return {"error": f"[manage_inventory] unknown scope '{scope}'",
            "valid_scopes": ["sources", "resolve", "refresh", "find"]}


async def get_system(device: "str | list[str]" = None, scope: str = "info",
                     site: str = None, source: str = None, name: str = None,
                     limit: int = None, params: dict = None) -> dict:
    """System/platform facts. `device` = one name, several as a COMMA-SEPARATED
    string (e.g. `device='Border,Access-01'`), or a list; `site` targets every
    device of a site; `source` targets devices from an external source of truth
    (NetBox/Nautobot/Infrahub), intersected with the connectable inventory. All
    fan out in a SINGLE batched call. `scope`:
      info | inventory | environment | capacity | boot | maintenance |
      containers | feature_pack | central | ssh | supported_transceivers
    (`inventory` = component list with part/serial numbers, per device;
    `supported_transceivers` = catalog of transceiver models the device
    supports, `params={'search': '25G'}` filters it.)"""
    if scope == "inventory":
        targets = await _resolve_targets(device, site, source)
        if not targets:
            return {"error": "[get_system] no target device — provide `device`, `site` or `source`."}

        async def _inv_one(t):
            try:
                hw = await _SRV.get_hardware_health(device=t)
            except Exception as exc:  # noqa: BLE001
                return t, None, f"{type(exc).__name__}: {exc}"
            mods = hw.get("modules") if isinstance(hw, dict) else None
            if not isinstance(mods, list):
                return t, {"raw": hw}, None
            comps = [{"type": m.get("type"), "name": m.get("name"),
                      "product_name": m.get("product_name"),
                      "part_number": m.get("part_number"),
                      "serial_number": m.get("serial_number"),
                      "device_version": m.get("device_version")}
                     for m in mods if isinstance(m, dict)]
            return t, {"components": comps, "count": len(comps)}, None

        pairs = await asyncio.gather(*[_inv_one(t) for t in targets])
        results, errors = {}, {}
        for t, data, err in pairs:
            (results if err is None else errors)[t] = data if err is None else err
        _apply_limit(results, limit)
        return _envelope("inventory", targets, results, errors)
    return await _read_dispatch("get_system", _MAP_SYSTEM, scope, device, site,
                                {"name": name, **(params or {})},
                                source=source, limit=limit)


async def get_interfaces(device: "str | list[str]" = None, scope: str = "physical",
                         site: str = None, source: str = None, interface: str = None,
                         lag: str = None, limit: int = None, params: dict = None) -> dict:
    """Interface state. For MULTIPLE devices pass a COMMA-SEPARATED string
    (e.g. `device='Access-01,Access-02'`) or a list; `site` targets a whole site
    — all fan out in a SINGLE batched call. `scope`: physical | transceivers |
    counters | supported_transceivers | poe | loopbacks | routed | svi | lag.
    `interface` filters physical/transceivers/counters/poe; `lag` filters lag.
    `counters` returns rx/tx/error/drop traffic counters; `supported_transceivers`
    lists the transceiver models the device supports; `poe` returns per-port
    Power-over-Ethernet draw (watts) plus the chassis-wide PoE power budget —
    use it for site/switch/port electrical (PoE) consumption questions."""
    return await _read_dispatch("get_interfaces", _MAP_INTERFACES, scope, device,
                                site, {"interface": interface, "lag": lag,
                                       **(params or {})}, source=source, limit=limit)


async def get_switching(device: "str | list[str]" = None, scope: str = "vlans",
                        site: str = None, source: str = None, vlan_id: int = None,
                        limit: int = None, params: dict = None) -> dict:
    """L2 switching. For MULTIPLE devices pass a COMMA-SEPARATED string
    (e.g. `device='Access-01,Access-02'`) or a list; `site` targets a whole site
    — all fan out in a SINGLE batched call. `scope`: vlans | mac | lldp |
    spanning_tree. `vlan_id` filters vlans/mac."""
    return await _read_dispatch("get_switching", _MAP_SWITCHING, scope, device,
                                site, {"vlan_id": vlan_id, **(params or {})},
                                source=source, limit=limit)


async def get_routing(device: "str | list[str]" = None, scope: str = "bgp_summary",
                      site: str = None, source: str = None, vrf: str = "default",
                      address_family: str = None, route_type: int = None,
                      neighbor: str = None, direction: str = None,
                      limit: int = None, params: dict = None) -> dict:
    """L3 routing. For MULTIPLE devices pass a COMMA-SEPARATED string
    (e.g. `device='Access-01,Access-02'`) or a list; `site` targets a whole site
    — all fan out in a SINGLE batched call. `scope`: bgp_summary | bgp_neighbors |
    bgp_config | bgp_routes | neighbor_routes | ospf_overview | ospf_neighbors |
    ospf_interfaces | route_table | arp. Most scopes accept `vrf`; bgp_routes
    accepts `address_family`. `neighbor_routes` returns BGP advertised/received
    routes with path attributes — use `direction` (advertised|received|all),
    optional `neighbor` (peer IP) and `address_family`."""
    return await _read_dispatch("get_routing", _MAP_ROUTING, scope, device, site,
                                {"vrf": vrf, "address_family": address_family,
                                 "route_type": route_type, "neighbor": neighbor,
                                 "direction": direction, **(params or {})},
                                source=source, limit=limit)


async def get_overlay(device: "str | list[str]" = None, scope: str = "evpn_config",
                      site: str = None, source: str = None, vrf: str = "default",
                      vni_id: int = None, route_type: int = None, limit: int = None,
                      params: dict = None) -> dict:
    """EVPN/VXLAN overlay. For MULTIPLE devices pass a COMMA-SEPARATED string
    (e.g. `device='Leaf-01,Leaf-02'`) or a list; `site` targets a whole site — all
    fan out in a SINGLE batched call. `scope`: evpn_config | evpn_routes |
    evpn_multihoming | vtep_neighbors | vxlan_config | vxlan_tunnels |
    vxlan_static_peers."""
    return await _read_dispatch("get_overlay", _MAP_OVERLAY, scope, device, site,
                                {"vrf": vrf, "vni_id": vni_id,
                                 "route_type": route_type, **(params or {})},
                                source=source, limit=limit)


async def get_redundancy(device: "str | list[str]" = None, scope: str = "vsx_status",
                         site: str = None, source: str = None, limit: int = None,
                         params: dict = None) -> dict:
    """VSX / VSF redundancy. For MULTIPLE devices pass a COMMA-SEPARATED string
    (e.g. `device='Access-01,Access-02'`) or a list; `site` targets a whole site
    — all fan out in a SINGLE batched call. `scope`: vsx_status | vsx_config |
    vsx_sync | vsf_status | vsf_config."""
    return await _read_dispatch("get_redundancy", _MAP_REDUNDANCY, scope, device,
                                site, {**(params or {})}, source=source, limit=limit)


async def get_access(device: "str | list[str]" = None, scope: str = "summary",
                     site: str = None, source: str = None, interface: str = None,
                     mac: str = None, vrf: str = None, limit: int = None,
                     params: dict = None) -> dict:
    """Port-access (802.1X/MAC-auth) + AAA. For MULTIPLE devices pass a
    COMMA-SEPARATED string (e.g. `device='Access-01,Access-02'`) or a list; `site`
    targets a whole site — all fan out in a SINGLE batched call. `scope`: clients |
    client_detail | auth_config | summary | roles | gbp | gbp_maps | abp |
    policies | radius | tacacs | authentication | accounting. `client_detail`
    needs `interface`+`mac`."""
    return await _read_dispatch("get_access", _MAP_ACCESS, scope, device, site,
                                {"interface": interface, "mac": mac, "vrf": vrf,
                                 **(params or {})}, source=source, limit=limit)


async def get_automation(device: "str | list[str]" = None, scope: str = "nae_scripts",
                         site: str = None, source: str = None, name: str = None,
                         script: str = None, agent: str = None, limit: int = None,
                         params: dict = None) -> dict:
    """Network Analytics Engine (NAE). For MULTIPLE devices pass a COMMA-SEPARATED
    string (e.g. `device='Access-01,Access-02'`) or a list; `site` targets a whole
    site — all fan out in a SINGLE batched call. `scope`: nae_scripts | nae_script
    | nae_agents | nae_agent. `nae_script` needs `name`; `nae_agent` needs
    `script`+`agent`."""
    return await _read_dispatch("get_automation", _MAP_AUTOMATION, scope, device,
                                site, {"name": name, "script": script,
                                       "agent": agent, **(params or {})},
                                source=source, limit=limit)


async def get_apps(device: "str | list[str]" = None, scope: str = "recognition",
                   site: str = None, source: str = None, limit: int = None,
                   params: dict = None) -> dict:
    """Application visibility/recognition (DPI). For MULTIPLE devices pass a
    COMMA-SEPARATED string (e.g. `device='Access-01,Access-02'`) or a list; `site`
    targets a whole site — all fan out in a SINGLE batched call. `scope`:
    recognition | visibility."""
    return await _read_dispatch("get_apps", _MAP_APPS, scope, device, site,
                                {**(params or {})}, source=source, limit=limit)


async def get_config(device: "str | list[str]" = None, scope: str = "running",
                     site: str = None, source: str = None, name: str = None,
                     diff: str = None, mode: str = None, path: str = None,
                     depth: int = 2, limit: int = None, params: dict = None) -> dict:
    """Device configuration. For MULTIPLE devices pass a COMMA-SEPARATED string
    (e.g. `device='Access-01,Access-02'`) or a list; `site` targets a whole site
    — all fan out in a SINGLE batched call. `scope`:
      running  : running-config (CLI text)
      startup  : startup-config (CLI text)
      full     : full running-config in JSON (REST structure)
      list     : list available config checkpoints
      compare  : diff `name` against `diff` (both checkpoint names)
      raw      : raw REST GET at `path` (depth-limited)
    """
    targets = await _resolve_targets(device, site, source)
    if not targets:
        return {"error": "[get_config] no target device — provide `device`, `site` or `source`."}
    base = dict(params or {})
    if scope == "running":
        kw = {"name": name or "running-config", "diff": diff, "mode": mode, **base}
        fn_name = "get_config"
    elif scope == "startup":
        kw = {"name": name or "startup-config", "diff": diff, "mode": mode, **base}
        fn_name = "get_config"
    elif scope == "compare":
        kw = {"name": name or "running-config", "diff": diff, "mode": mode, **base}
        fn_name = "get_config"
    elif scope == "full":
        kw = {"name": name or "running-config", **base}
        fn_name = "get_full_config"
    elif scope == "list":
        kw = {**base}
        fn_name = "list_configs"
    elif scope == "raw":
        if not path:
            return {"error": "[get_config] scope 'raw' requires `path`."}
        kw = {"path": path, "depth": depth, **base}
        fn_name = "get_raw_api"
    else:
        return {"error": f"[get_config] unknown scope '{scope}'",
                "valid_scopes": ["running", "startup", "full", "list", "compare", "raw"]}
    results, errors = await _fanout(fn_name, targets, kw)
    _apply_limit(results, limit)
    return _envelope(scope, targets, results, errors)


async def configure_interface(scope: str, action: str = "plan", device: str = None,
                              site: str = None, params: dict = None) -> dict:
    """Configure an interface. `scope`: loopback | routed_port | vxlan | virtual_mac.
    `action`: plan (preview, default) | apply | verify. Pass the domain fields in
    `params`, e.g. loopback -> {name, ip_address, vrf}; routed_port ->
    {interface, ip_address, vrf, mtu, enable}; virtual_mac -> {mac}; vxlan ->
    {interface, source_ip, static_peers, ...}."""
    return await _write_dispatch("configure_interface", _MAP_W_INTERFACE, scope,
                                 action, device, site, params)


async def configure_routing(scope: str, action: str = "plan", device: str = None,
                            site: str = None, params: dict = None) -> dict:
    """Configure routing. `scope`: ospf | bgp | vrf | evpn. `action`: plan
    (default) | apply | verify. Pass domain fields in `params`, e.g. bgp ->
    {asn, vrf, router_id, neighbors}; ospf -> {vrf, router_id, area_id,
    interfaces}; vrf -> {name, ...}; evpn -> {...}."""
    return await _write_dispatch("configure_routing", _MAP_W_ROUTING, scope,
                                 action, device, site, params)


async def configure_security(scope: str, action: str = "plan", device: str = None,
                             site: str = None, params: dict = None) -> dict:
    """Configure access security. `scope`: port_auth | aaa | user_roles |
    app_recognition. `action`: plan (default) | apply | verify. Pass domain
    fields in `params`, e.g. port_auth -> {interfaces, ...}."""
    return await _write_dispatch("configure_security", _MAP_W_SECURITY, scope,
                                 action, device, site, params)


async def configure_service(scope: str = "vlan", action: str = "plan",
                            device: str = None, site: str = None,
                            params: dict = None) -> dict:
    """Orchestrated L2/L3 VLAN service. `scope`: vlan. `action`:
      plan        : preview the create plan (default)
      apply       : create/update the service
      delete      : remove the service
      delete_plan : preview the delete plan
      verify      : check the resulting VLAN state
    Pass service fields in `params` (vlan_id, name, vni, svi_ip, vrf, interfaces…)."""
    if scope != "vlan":
        return {"error": f"[configure_service] unknown scope '{scope}'",
                "valid_scopes": ["vlan"]}
    base = dict(params or {})
    if action in ("plan", "apply"):
        fn = _SRV.create_vlan_service
        kw = _filtered_kwargs(fn, dict(base, site=site, apply=(action == "apply")))
        return await fn(device=device, **kw)
    if action in ("delete", "delete_plan"):
        fn = _SRV.delete_vlan_service
        kw = _filtered_kwargs(fn, dict(base, site=site, apply=(action == "delete")))
        return await fn(device=device, **kw)
    if action == "verify":
        targets = await _resolve_targets(device, site)
        if not targets:
            return {"error": "[configure_service] no target device."}
        results, errors = await _fanout("get_vlans", targets,
                                        {"vlan_id": base.get("vlan_id")})
        return _envelope("vlan", targets, results, errors)
    return {"error": f"[configure_service] invalid action '{action}'",
            "valid_actions": ["plan", "apply", "delete", "delete_plan", "verify"]}


async def diagnose(device: "str | list[str]" = None, scope: str = "device",
                   site: str = None, source: str = None, params: dict = None) -> dict:
    """Deterministic multi-check diagnostic bundle. For MULTIPLE devices pass a
    COMMA-SEPARATED string (e.g. `device='Access-01,Access-02'`) or a list; `site`
    targets a whole site — all fan out in a SINGLE batched call. `scope`:
      device : system + interfaces + vlans + recent logs
      evpn   : evpn config + vxlan tunnels + vtep neighbors + bgp
      client : mac + arp + lldp + port-access summary
    Returns one combined block per device. (For guided, open-ended workflows,
    use the MCP prompts instead.)"""
    checks = _MAP_DIAGNOSE.get(scope)
    if checks is None:
        return {"error": f"[diagnose] unknown scope '{scope}'",
                "valid_scopes": sorted(_MAP_DIAGNOSE)}
    targets = await _resolve_targets(device, site, source)
    if not targets:
        return {"error": "[diagnose] no target device — provide `device`, `site` or `source`."}
    extra = dict(params or {})

    async def _one(target: str):
        block: dict[str, Any] = {}
        for label, fn_name, kw in checks:
            fn = getattr(_SRV, fn_name, None)
            if fn is None:
                block[label] = {"error": f"unknown function '{fn_name}'"}
                continue
            call = _filtered_kwargs(fn, {**kw, **extra})
            try:
                block[label] = await fn(device=target, **call)
            except Exception as exc:  # noqa: BLE001
                block[label] = {"error": f"{type(exc).__name__}: {exc}"}
        return target, block

    pairs = await asyncio.gather(*[_one(t) for t in targets])
    return {"scope": scope, "results": {t: b for t, b in pairs},
            "summary": {"total": len(targets), "devices": targets,
                        "checks": [c[0] for c in checks]}}


async def troubleshoot(device: "str | list[str]" = None, feature_name: str = None,
                       choice: str = "health", site: str = None, source: str = None,
                       component_name: str = None, user_input: str = None,
                       verbose: bool = False, timeout: float = 120.0,
                       limit: int = None, params: dict = None) -> dict:
    """On-device automated troubleshoot / diagnostic (AOS-CX Troubleshoot API,
    firmware 10.18+). For MULTIPLE devices pass a COMMA-SEPARATED string
    (e.g. `device='Leaf-01,Leaf-02'`) or a list; `site`/`source` target a whole
    site/source — all fan out in a SINGLE batched call.

    - Omit `feature_name` to LIST the troubleshoot features/components supported
      by each target (discovery, via `troubleshoot_feature_components`).
    - Provide `feature_name` to RUN a troubleshoot on it (e.g. 'l3', 'multicast',
      'system'). `choice` = run depth: basic-health | config | health (default,
      basic + config) | operations | detailed.
    - `component_name` / `user_input`: optional narrowing / extra context.
      `verbose`: include verbose logs. `timeout`: max seconds to poll per device.

    Each run launches a volatile request, polls until completion, returns alerts
    (basic / config / advanced, with severity, root cause and recommendation)
    plus health/config/troubleshoot text results, then cleans up the instance.
    Returns supported=False per device on firmware older than 10.18."""
    targets = await _resolve_targets(device, site, source)
    if not targets:
        return {"error": "[troubleshoot] no target device — provide `device`, `site` or `source`."}
    extra = dict(params or {})
    if not feature_name:
        results, errors = await _fanout(
            "list_troubleshoot_features", targets,
            {"feature_name": extra.get("feature_name")},
        )
        _apply_limit(results, limit)
        return _envelope("features", targets, results, errors)
    results, errors = await _fanout(
        "run_troubleshoot", targets,
        {"feature_name": feature_name, "choice": choice,
         "component_name": component_name, "user_input": user_input,
         "verbose": verbose, "timeout": timeout, **extra},
    )
    _apply_limit(results, limit)
    return _envelope(choice, targets, results, errors)


# Ordered list of the flat dispatchers to register.
_DISPATCHERS: list[Callable] = [
    manage_inventory, get_system, get_interfaces, get_switching, get_routing,
    get_overlay, get_redundancy, get_access, get_automation, get_apps, get_config,
    configure_interface, configure_routing, configure_security, configure_service,
    diagnose, troubleshoot,
]

# Legacy atomic tools that stay advertised as-is (never de-advertised).
_KEEP_ATOMIC: set[str] = {
    "list_devices", "list_sites", "get_logs", "run_ssh_commands",
    "manage_config", "backup_config", "logout", "rollback",
}


# ──────────────────────────────────────────────────────────────────────
# Install
# ──────────────────────────────────────────────────────────────────────
def install_flat_toolset(mcp: Any, srv: Any) -> dict:
    """When ``CX_FLAT_TOOLSET`` is truthy: register the flat dispatchers and
    de-advertise every other (non-kept) legacy tool. No-op otherwise.

    Returns a small summary dict. Never raises (fail-open): on any error the
    server is left advertising its full, unmodified tool set."""
    global _SRV
    if not _env_true("CX_FLAT_TOOLSET", "true"):
        return {"active": False, "reason": "CX_FLAT_TOOLSET disabled"}

    _SRV = srv
    reg_before = _registry(mcp)
    if reg_before is None:
        log.warning("flat_tools: FastMCP registry not found — server left unchanged")
        return {"active": False, "reason": "registry not found"}

    # 1) Register the flat dispatchers (advertised, Tier-1).
    #    A legacy tool may share a dispatcher's name (e.g. ``get_interfaces``).
    #    FastMCP's ``tool()`` keeps the FIRST registration on a name clash, which
    #    would silently shadow the dispatcher with the legacy tool — so drop any
    #    colliding legacy entry from the registry first.
    new_names: list[str] = []
    for fn in _DISPATCHERS:
        try:
            existing = _registry(mcp)
            if existing is not None and fn.__name__ in existing:
                del existing[fn.__name__]
            mcp.tool()(fn)
            new_names.append(fn.__name__)
        except Exception:  # pragma: no cover - one bad tool must not break the rest
            log.exception("flat_tools: failed to register %s", fn.__name__)

    # 2) De-advertise every legacy tool that is neither kept nor a new dispatcher.
    reg = _registry(mcp) or reg_before
    keep = _KEEP_ATOMIC | set(new_names)
    removed: list[str] = []
    for name in list(reg.keys()):
        if name not in keep:
            try:
                del reg[name]
                removed.append(name)
            except Exception:  # pragma: no cover
                log.exception("flat_tools: failed to remove %s", name)

    advertised = sorted(reg.keys())
    summary = {"active": True, "advertised": len(advertised),
               "dispatchers": new_names, "kept": sorted(_KEEP_ATOMIC & set(advertised)),
               "removed": len(removed), "tools": advertised}
    log.info("flat_tools: active — %d tools advertised (%d removed)",
             len(advertised), len(removed))
    return summary
