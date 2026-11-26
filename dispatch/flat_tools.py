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

try:  # write-safety facade (dry_run_token / rollback_id); optional
    from .write_safety import write_safety as _ws
except Exception:  # pragma: no cover
    _ws = None

try:  # per-call write options (force on protected objects)
    from core import server_core as _core
except Exception:  # pragma: no cover
    _core = None

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
    """Normalize the ``device`` argument into a list of device names (real
    list, JSON-array string, comma-separated string or single name). Delegates
    to the shared server_core implementation so reads and writes agree."""
    if _core is not None and hasattr(_core, "_coerce_device_list"):
        return _core._coerce_device_list(device)
    if device is None:
        return []
    if isinstance(device, (list, tuple)):
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
            inner = s[1:-1]
            return [p.strip().strip("'\"") for p in inner.split(",")
                    if p.strip().strip("'\"")]
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
    "unnumbered": "get_unnumbered_interfaces",
    "supported_transceivers": "get_supported_transceivers",
    "poe": "get_poe_status",
    "loopbacks": "get_loopbacks", "routed": "get_routed_ports",
    "svi": "get_vlan_interfaces", "lag": "get_lag",
    "dhcp_relay": "get_dhcp_relay",
    "interface_group": "get_interface_groups",
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
    "lag": ("configure_lag", "verify_lag"),
    "vxlan": ("configure_vxlan_interface", "verify_vxlan_interface"),
    "virtual_mac": ("configure_virtual_mac", "verify_virtual_mac"),
    "vlan": ("configure_vlan", "verify_vlan"),
    "svi": ("configure_svi", "verify_svi"),
    "trunk": ("configure_trunk", "verify_trunk"),
    "admin": ("configure_interface_admin", "verify_interface_admin"),
    "dhcp_relay": ("configure_dhcp_relay", "verify_dhcp_relay"),
    "interface_group": ("configure_interface_group", "verify_interface_group"),
    "hostname": ("configure_hostname", "verify_hostname"),
    # Orchestrators (multi-step, create/update/delete)
    "l3_link": ("orchestrate_l3_link", "verify_routed_port"),
    "access_port": ("orchestrate_access_port", "verify_access_port"),
    "static_vxlan": ("orchestrate_static_vxlan", "verify_static_vxlan"),
    "overlay": ("orchestrate_overlay", "verify_overlay"),
    "overlay_service": ("orchestrate_overlay_service", "verify_overlay_service"),
}
_MAP_W_ROUTING = {
    "ospf": ("configure_ospf", "verify_ospf"),
    "bgp": ("configure_bgp", "verify_bgp"),
    "vrf": ("configure_vrf", "verify_vrf"),
    "evpn": ("configure_evpn", "verify_evpn"),
    "static_route": ("configure_static_route", "verify_static_route"),
    "redistribute": ("configure_redistribute", "verify_redistribute"),
    "evpn_vlan": ("orchestrate_evpn_vlan", "verify_evpn_vlan"),
}
_MAP_W_SECURITY = {
    "port_auth": ("configure_port_auth", "verify_port_auth"),
    "aaa": ("configure_aaa", "verify_aaa"),
    "user_roles": ("configure_user_roles", "verify_user_roles"),
    "app_recognition": ("configure_app_recognition", "verify_app_recognition"),
    "radius_dot1x": ("orchestrate_radius_dot1x", "verify_radius_dot1x"),
}
_MAP_W_REDUNDANCY = {
    "vsx": ("configure_vsx", "verify_vsx"),
    "vsx_pair": ("orchestrate_vsx_pair", "verify_vsx_cluster"),
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
_TOKEN_HINT = ("dry_run_token required: run the same call with action='plan' "
               "first, then re-run with action='apply' and the returned "
               "dry_run_token.")


def _ws_active() -> bool:
    return _ws is not None and _ws.enabled


def _caller_session() -> Optional[str]:
    """Identity of the MCP session running this tool call (None if unavailable)."""
    try:
        return f"s{id(_core.mcp.get_context().session)}"
    except Exception:  # noqa: BLE001 — outside a request / API differences
        return None


def _nothing_written(applied) -> bool:
    """True when an apply failed on EVERY target before writing anything (so its
    one-shot dry_run_token can safely be given back)."""
    if not isinstance(applied, dict):
        return False
    status = applied.get("status")
    if status in ("error", "forbidden"):
        return True
    results = applied.get("results")
    if status != "partial" or not isinstance(results, dict) or not results:
        return False
    return all(isinstance(r, dict) and not r.get("ok") and "nothing written"
               in str(r.get("error", "")) for r in results.values())


async def _guarded_write(operation: str, fn: Callable, device, call: dict,
                         apply: bool, dry_run_token: Optional[str],
                         force: bool = False,
                         auto_checkpoint: Optional[bool] = None,
                         verbose: bool = False) -> dict:
    """Run a legacy plan/apply write with the dry_run_token lifecycle.

    plan  → ``fn(apply=False)``; a ``status=planned`` result is frozen and gets a
            ``dry_run_token`` (no-op when write safety is disabled).
    apply → when ``CX_REQUIRE_DRY_RUN_TOKEN`` is on, a missing token is refused.
            A provided token is validated against a FRESH preview (same plan
            hash → TOCTOU guard), consumed, then ``fn(apply=True)`` runs and a
            ``rollback_id`` is journaled for the objects it created.
    ``force`` lifts the CX_PROTECTED_OBJECTS guard for this apply only.
    ``auto_checkpoint`` (None = CX_AUTO_CHECKPOINT default) lets a caller opt
    out of the firmware auto-checkpoint safety net for this apply only."""
    if not apply:
        result = await fn(device=device, **{**call, "apply": False})
        if (_ws_active() and isinstance(result, dict)
                and result.get("status") == "planned" and "dry_run_token" not in result):
            try:
                sess = _caller_session()
                _ws.freeze(result, operation, result.get("targets") or [],
                           result.get("plan") or {},
                           **({"issued_by": sess} if sess else {}))
            except Exception:  # token issuance must never break the preview
                log.exception("flat_tools: freeze failed for %s", operation)
        return result

    token_origin: dict = {}
    if _ws_active():
        if not dry_run_token:
            if _ws.requires_token:
                return {"status": "error", "operation": operation, "error": _TOKEN_HINT}
        else:
            token_origin = _ws.token_origin(dry_run_token, _caller_session())
            if (token_origin.get("same_session") is False
                    and os.environ.get("CX_TOKEN_SESSION_BOUND", "false").lower() == "true"):
                return {"status": "error", "operation": operation,
                        "error": ("dry_run_token was issued to a different MCP session "
                                  "(CX_TOKEN_SESSION_BOUND=true): run the plan again in "
                                  "this session.")}
            preview = await fn(device=device, **{**call, "apply": False})
            fresh_plan = preview.get("plan") if isinstance(preview, dict) else None
            err = _ws.require_token(dry_run_token, operation, fresh_plan or {})
            if err:
                return {**err, "operation": operation}

    force_ctx = ckpt_ctx = verb_ctx = None
    if _core is not None:
        force_ctx = _core.FORCE_PROTECTED.set(bool(force))
        ckpt_ctx = _core.AUTO_CHECKPOINT_OVERRIDE.set(
            None if auto_checkpoint is None else bool(auto_checkpoint))
        if hasattr(_core, "VERBOSE_RESULT"):
            verb_ctx = _core.VERBOSE_RESULT.set(bool(verbose))
    try:
        applied = await fn(device=device, **{**call, "apply": True})
    finally:
        if force_ctx is not None:
            _core.FORCE_PROTECTED.reset(force_ctx)
            _core.AUTO_CHECKPOINT_OVERRIDE.reset(ckpt_ctx)
        if verb_ctx is not None:
            _core.VERBOSE_RESULT.reset(verb_ctx)
    if isinstance(applied, dict) and token_origin:
        applied["dry_run_token_origin"] = token_origin
        if token_origin.get("same_session") is False:
            applied["warning"] = (
                (applied.get("warning", "") + " The dry_run_token was issued by ANOTHER "
                 "MCP session (plan hash matched, so this is the previewed plan); "
                 "set CX_TOKEN_SESSION_BOUND=true to refuse such tokens.").strip())
    if (dry_run_token and _ws_active() and _nothing_written(applied)
            and _ws.restore_token(dry_run_token)):
        applied["token_restored"] = True
        applied["note"] = ((applied.get("note", "") +
                            " Nothing was written: the dry_run_token is still valid, "
                            "re-run the same apply.").strip())
    if (_ws_active() and isinstance(applied, dict)
            and applied.get("status") in ("applied", "partial")):
        try:
            # Prefer the created-object list (exact inverse); fall back to the
            # step plan emitted by the vlan-service orchestrators.
            plan = applied.get("reversible") or applied.get("plan") or {}
            targets = applied.get("targets") or (list(plan) if isinstance(plan, dict) else [])
            rid = _ws.record(operation, targets, plan)
            if rid:
                applied["rollback_id"] = rid
        except Exception:
            log.exception("flat_tools: rollback journaling failed for %s", operation)
    return applied


def _flag_ignored_params(result, base: dict, call: dict, scope: str):
    """Surface params the target function does not accept (they are dropped by
    `_filtered_kwargs`) instead of letting a plan/apply look complete."""
    ignored = sorted(k for k, v in base.items()
                     if v is not None and k not in call and k != "device")
    if ignored and isinstance(result, dict):
        result["ignored_params"] = ignored
        note = (f"params NOT supported by '{scope}' were ignored: {ignored}. "
                "They were not applied — check the documented params.")
        result["warning"] = f"{result['warning']} {note}" if result.get("warning") else note
    return result


async def _write_dispatch(tool: str, mapping: dict, scope: str, action: str,
                          device, site, params: dict,
                          dry_run_token: Optional[str] = None,
                          force: bool = False,
                          auto_checkpoint: Optional[bool] = None,
                          verbose: bool = False) -> dict:
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
    call = _filtered_kwargs(fn, dict(base, site=site))
    result = await _guarded_write(cfg_name, fn, device, call,
                                  action == "apply", dry_run_token, force,
                                  auto_checkpoint, verbose)
    return _flag_ignored_params(result, base, call, scope)


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
    counters | supported_transceivers | poe | loopbacks | routed | svi | lag |
    dhcp_relay | interface_group. `interface` filters physical/transceivers/
    counters/poe/dhcp_relay (dhcp_relay: omit to discover ALL relays on the
    device); `lag` filters lag; interface_group takes an optional
    `params={'subsystem': 'line_card,1/1'}` to scope to one line card/chassis.
    `counters` returns rx/tx/error/drop traffic counters;
    `supported_transceivers` lists the transceiver models the device supports;
    `poe` returns per-port Power-over-Ethernet draw (watts) plus the
    chassis-wide PoE power budget — use it for site/switch/port electrical
    (PoE) consumption questions. `physical` includes `l1_state` (bool, Layer 1
    ready) + `l1_state_down_reason` (e.g. `group_speed_mismatch`,
    `profile_mismatch`, `module_incompatible`, ... — only set when
    `l1_state` is False) so a speed-mismatch/module fault is diagnosable
    without `get_config(scope='raw')`/SSH. `svi` adds the active-gateway
    (`vsx_virtual_ip4/ip6`, `vsx_virtual_gw_mac_v4/v6`, `active_gateway`;
    same fields for an EVPN anycast gateway) and `ip_mtu`; `statistics` is
    null (with `statistics_note`) when the device reports no counters."""
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
                              site: str = None, params: dict = None,
                              dry_run_token: str = None, force: bool = False,
                              auto_checkpoint: bool = None,
                              verbose: bool = False) -> dict:
    """Configure an interface. `device` accepts ONE name, a COMMA-SEPARATED
    string ('A,B,C') or a list; `site` targets a whole site — the SAME change is
    applied to every target in ONE call (per-device results + summary).
    `scope`: loopback | routed_port | lag | vxlan | virtual_mac | vlan | svi |
    trunk | admin | dhcp_relay | interface_group | hostname | l3_link |
    access_port | static_vxlan | overlay | overlay_service.
    PER-DEVICE ADDRESSES: `ip_address` (loopback, routed_port, l3_link) and
    `source_ip` (vxlan, static_vxlan) must differ on each switch — for several
    devices pass a mapping {"<device>": "<ip>", ...}. The same address is only
    accepted on the 2 members of one VSX pair (anycast VTEP / keepalive-less
    designs); any other duplicate is refused before writing.
    `action`: plan (preview, default) | apply | verify. Pass the domain fields in `params`:
      loopback    -> {name, ip_address, vrf}
      routed_port -> {interface, ip_address (CIDR), vrf, create_vrf (bool: create
                     the VRF first if missing), mtu, description, enable,
                     remove_from_lag, delete_empty_lags}. THIS is the tool to put an IP on a
                     physical port (L3 / no switchport). For SEVERAL ports on
                     the SAME device set in ONE call, pass `interfaces`: [{
                     interface, ip_address, mtu, description, enable, vrf,
                     create_vrf, remove_from_lag}, ...] instead of `interface`.
      lag         -> {lag_id, members, mode (static/lacp-active/lacp-passive),
                     lacp_fallback, lacp_rate, mclag_enabled, vlan_mode
                     (access/trunk/native-tagged/native-untagged), access_vlan,
                     native_vlan, trunk_vlans, description, mtu,
                     evpn_multihoming_esi, ...} — one call builds a complete
                     trunk MC-LAG (covers standard, VSX MC-LAG and ESI-LAG).
      vlan        -> {vlan_id, name, description, delete} for ONE VLAN, or
                     {vlans: [{vlan_id, name, description}, ...]} for a BATCH
                     (device x vlan matrix, one status per cell). Bare VLAN
                     definition (no VNI/SVI/RT). `delete: true, cascade: true`
                     also removes each VLAN's SVI/active-gateway, EVPN RT and
                     L2VNI first (core -> spine cleanup).
      svi         -> {vlan_id, vrf, ip_cidr, active_gateway_ip,
                     active_gateway_mac, delete}; batch delete: {vlans: [..],
                     delete: true}
      trunk       -> {interface, add_vlans, remove_vlans}
      admin       -> {interface, enable} (plain L2 port up/down; if the operational
                     admin_state does not follow, a real down/up flap is done)
      hostname    -> {hostname} for one device, or {hostnames: {"<device>":
                     "<hostname>", ...}} to rename 50 switches in ONE call.
      virtual_mac -> {mac};  vxlan -> {interface, source_ip, static_peers, ...}
      dhcp_relay  -> {interface, vrf, ipv4_servers, ipv6_servers, bootp_gateway,
                     delete} (`vrf` MUST match the interface's actual VRF).
      interface_group -> {group, speed (5g|10g|25g|40g|50g|100g|200g),
                     subsystem (optional, 'line_card,1/1'), delete}: set a
                     port-group's link speed (CLI `system interface-group`);
                     WARNING it can bounce every port in the block.
    ORCHESTRATORS (multi-step, idempotent, `delete: true` tears down):
      l3_link     -> {interface, ip_address (CIDR), vrf, create_vrf, vrf_rd,
                     vrf_import_rts, vrf_export_rts (optional EVPN RD/RT), mtu,
                     description, ospf_area, ospf_instance_tag,
                     ospf_network_type (='point_to_point'; None = broadcast),
                     remove_from_lag, delete_empty_lags, ensure_internal_vlan_range,
                     internal_vlan_range_size, verify_connected_route,
                     delete, delete_vrf}: VRF -> routed port -> OSPF router/area
                     (created if missing) -> OSPF interface in one call. After
                     apply, an MTU mismatch with the LLDP neighbour (if in the
                     inventory) is reported in `warnings`/`mtu_mismatches`.
                     For SEVERAL point-to-point links on the SAME device set in
                     ONE call (one shared VRF context), pass `links`: [{
                     interface, ip_address, mtu, description, enable, ospf_area,
                     ospf_instance_tag, remove_from_lag}, ...] instead of
                     `interface`/`ip_address`/etc.
      access_port -> {interfaces (list/CSV/range '1/1/1-1/1/24'), access_vlan,
                     voice_vlan, description, enable, stp_edge, bpdu_guard,
                     root_guard, loop_guard, port_auth: {methods|dot1x|mac_auth,
                     auth_precedence, roles, ...}, delete}: no routing + access
                     VLAN + no shutdown + admin-edge/bpdu-guard + 802.1X per port.
      static_vxlan -> {vxlan_interface (=vxlan1), source_ip ({device: ip}
                     mapping for several VTEPs), dest_udp_port,
                     inter_vxlan_bridging_mode (deny|static-evpn|static-all),
                     vlans: [{vlan_id, vni, name}] | {vlan_id: vni}, peers:
                     [{destination, vnis (default all), vrf}] (only VTEPs outside
                     the call — with a source_ip mapping the VTEPs of the call
                     are meshed automatically, full_mesh=true), delete,
                     delete_vlans, delete_vxlan_interface}: static VXLAN
                     (head-end replication, NO EVPN): VTEP + VLAN/VNI maps +
                     static tunnels to every remote VTEP in one call.
      overlay     -> {vxlan_interface (=vxlan1), source_ip ({device: ip}
                     mapping), dest_udp_port, mode (evpn|static|stub, =evpn),
                     inter_vxlan_bridging_mode (auto 'static-evpn' for
                     mode=stub), evpn_options: {dyn_vxlan_tunnel_bridging_mode,
                     arp_suppression, nd_suppression, redistribute_local_mac,
                     redistribute_local_svi, options}, virtual_mac
                     ({device: mac} mapping), bgp_evpn: {asn, router_id
                     ({device: ip} or 'loopback0'), vrf,
                     neighbors, options} (OMITTED by default — nothing
                     BGP-related is touched unless given), delete,
                     delete_vxlan_interface, verify_operational (=true: the
                     result is NOT ok if vxlan1/VNIs/EVIs are not up)}: DEVICE-level VTEP bring-up —
                     VXLAN interface -> (mode evpn/stub) global EVPN + virtual
                     MAC + optional BGP-EVPN. mode='static' (Extended Edge)
                     stops after the interface.
      overlay_service -> {services: [{vlan_id, vni, name, description, attach
                     (evpn|static|stub, =evpn), rd, import_rts, export_rts,
                     route_target_auto_mode, svi_vrf, svi_ip ({device: cidr}
                     mapping accepted),
                     active_gateway_ip, active_gateway_mac, static_peers: [
                     {destination, vnis, vrf}]}], vxlan_interface (=vxlan1),
                     require_vxlan_interface (=true), delete, delete_vlans}:
                     BATCH VLAN -> L2VNI -> EVPN route-target and/or static
                     peer, several services in ONE call. Requires
                     `orchestrate_overlay` (scope=overlay) to have run first on
                     the target (refuses otherwise); attach='stub' additionally
                     requires mode='stub' there.
    Workflow: `plan` returns a `dry_run_token`; `apply` REQUIRES that token
    (same params) and re-checks the plan before writing. Each apply runs inside
    a firmware auto-checkpoint (auto-revert on failure; opt out for this call
    with `auto_checkpoint=false`). `force=true` overrides the
    CX_PROTECTED_OBJECTS guard (uplinks, peer-groups, mgmt VRF...). Long
    per-object result lists are compacted to a summary (count/ok/failed +
    failed items); `verbose=true` returns the full detail."""
    return await _write_dispatch("configure_interface", _MAP_W_INTERFACE, scope,
                                 action, device, site, params, dry_run_token, force,
                                 auto_checkpoint, verbose)


async def configure_routing(scope: str, action: str = "plan", device: str = None,
                            site: str = None, params: dict = None,
                            dry_run_token: str = None, force: bool = False,
                            auto_checkpoint: bool = None,
                            verbose: bool = False) -> dict:
    """Configure routing. `device` accepts ONE name, a COMMA-SEPARATED string
    ('A,B,C') or a list; `site` targets a whole site — ONE call applies to every
    target. `scope`: ospf | bgp | vrf | evpn | static_route |
    redistribute | evpn_vlan. `action`: plan (default) | apply | verify. Pass domain
    fields in `params`, e.g. bgp -> {asn, vrf, router_id ({device: ip} or
    'loopback0'), neighbors, wait_established (s: wait for Established, report
    the last BGP error otherwise)}; ospf ->
    {vrf, router_id ({device: ip} mapping or 'loopback0'), area_id,
    interfaces, passive_interfaces, passive_interface_default}; vrf -> {name,
    delete, ...}; evpn ->
    {dyn_vxlan_tunnel_bridging_mode, arp_suppression, nd_suppression,
    redistribute_local_mac, redistribute_local_svi, options}; static_route -> {prefix, vrf, nexthops, delete}
    (batch delete: {prefixes: [...], delete: true}); redistribute ->
    {protocol ('bgp'|'ospf'), vrf, asn, instance_tag, address_family, sources}.
    vrf -> {name, rd ('ASN:nn'|'IP:nn', {device: rd} mapping, or 'auto' =
    <loopback0>:<l3vni>), import_route_targets,
    export_route_targets (VRF-level EVPN RTs, 'auto' allowed), l3vni (alias
    vni; binds the L3 VNI to the VRF on `vxlan_interface`=vxlan1), bgp_vrf
    (default true with l3vni: router bgp / vrf / address-family ipv4 unicast
    for type-5), bgp_asn (default: default-VRF ASN), redistribute
    (['connected','static',...]),
    address_families: [{address_family, import/export RTs}] (non-EVPN only)}.
    bgp neighbors: members of a peer-group listed in the same call get the
    group's remote_as + activate only (update-source/send-community/RR-client
    are inherited on the device, never duplicated); 'loopback0' as
    update_source is written as the local interface;
    send_community 'both' on l2vpn-evpn is sent as 'extended'.
    Params the scope does not accept are NOT applied and are listed in the
    result's `ignored_params`/`warning`.
    ORCHESTRATOR evpn_vlan -> {vlan_id, name, vni, vxlan_interface (=vxlan1),
    vxlan_source_ip (sets the VTEP source if given; {device: ip} mapping for
    several devices, same IP only on a VSX pair), evpn (bool), rd (='auto'),
    import_rts / export_rts (='auto'; explicit 'ASN:nn' lists accepted),
    route_target_auto_mode (default|legacy), svi_vrf, svi_ip (CIDR),
    active_gateway_ip, active_gateway_mac, delete}: VLAN -> L2VNI -> `evpn vlan`
    RD/RT -> optional anycast SVI, with EXPLICIT RD/RT (vs configure_service
    scope=vlan which auto-discovers the fabric and deduces RTs); `delete: true`
    removes SVI -> RT -> L2VNI -> VLAN.
    Workflow: `plan` returns a `dry_run_token`; `apply` REQUIRES that token
    (same params) and re-checks the plan before writing. Each apply runs inside
    a firmware auto-checkpoint (auto-revert on failure; opt out for this call
    with `auto_checkpoint=false`). `force=true` overrides the
    CX_PROTECTED_OBJECTS guard (uplinks, peer-groups, mgmt VRF...)."""
    return await _write_dispatch("configure_routing", _MAP_W_ROUTING, scope,
                                 action, device, site, params, dry_run_token, force,
                                 auto_checkpoint, verbose)


async def configure_redundancy(scope: str, action: str = "plan", device: str = None,
                               site: str = None, params: dict = None,
                               dry_run_token: str = None, force: bool = False,
                               auto_checkpoint: bool = None,
                               verbose: bool = False) -> dict:
    """Configure VSX / VSF redundancy. `scope`: vsx | vsx_pair. `action`: plan
    (default) | apply | verify.
      vsx_pair (ORCHESTRATOR, preferred for a new pair or a full teardown) ->
        {peer_device, isl_members: ['1/1/49','1/1/50'], peer_isl_members,
         isl_lag_id (=256), isl_mode (=lacp-active), keepalive_interface,
         peer_keepalive_interface, keepalive_ip / peer_keepalive_ip (CIDR),
         keepalive_vrf (=KEEPALIVE), keepalive_udp_port, system_mac, role
         (=primary), config_sync (bool), config_sync_features ['vlan','vrf',
         'aaa',...], linkup_delay_timer, split_recovery, delete,
         delete_keepalive_vrf, verify}: creates the keepalive VRF + routed
        keepalive port + ISL LAG + VSX pairing on BOTH members (role mirrored,
        keepalive IPs swapped) and reads the ISL state afterwards; `delete:
        true` removes VSX + ISL LAG + keepalive on both members.
      vsx (atomic /system/vsx only) -> {peer_device, role, peer_role,
        isl_interface, peer_isl_interface, keepalive_interface,
        peer_keepalive_interface, keepalive_vrf, keepalive_src_ip,
        keepalive_peer_ip, system_mac, delete} — assumes ISL LAG / keepalive
        port already exist.
    Workflow: `plan` returns a `dry_run_token`; `apply` REQUIRES that token
    (same params) and re-checks the plan before writing. Each apply runs inside
    a firmware auto-checkpoint (auto-revert on failure; opt out for this call
    with `auto_checkpoint=false`). `force=true` overrides the
    CX_PROTECTED_OBJECTS guard."""
    return await _write_dispatch("configure_redundancy", _MAP_W_REDUNDANCY, scope,
                                 action, device, site, params, dry_run_token, force,
                                 auto_checkpoint, verbose)


async def configure_security(scope: str, action: str = "plan", device: str = None,
                             site: str = None, params: dict = None,
                             dry_run_token: str = None, force: bool = False,
                             auto_checkpoint: bool = None,
                             verbose: bool = False) -> dict:
    """Configure access security / AAA. `device` accepts ONE name, a
    COMMA-SEPARATED string ('A,B,C') or a list; `site` targets a whole site —
    ONE call applies to every target. `scope`: port_auth | aaa | user_roles |
    app_recognition | radius_dot1x. `action`: plan (default) | apply | verify. `params`:
      radius_dot1x (ORCHESTRATOR, preferred for a NAC bring-up) ->
                    {radius_servers: [{address, passkey, vrf (=mgmt), port,
                    accounting_udp_port, timeout, retries, tracking_enable}],
                    server_group (=RADIUS), dot1x, mac_auth, coa (RADIUS
                    dyn-authorization), coa_udp_port, accounting,
                    mac_auth_address_format, roles: [{name, vlan_tag, ...}],
                    interfaces (list/CSV/range), port_auth: {...}, delete,
                    delete_roles}: group -> servers -> global dot1x/mac-auth
                    enable + CoA -> roles -> per-port 802.1X in one call;
                    `delete: true` unwinds everything in reverse order.
      aaa        -> GLOBAL RADIUS/TACACS+ servers + server groups + management
                    authentication order: {server_groups: [{name, type:
                    radius|tacacs}], radius_servers: [{address, vrf, passkey,
                    port, auth_type, timeout, retries, server_group: {GRP: 1},
                    tracking_enable}], tacacs_servers: [...], authentication/
                    authorization/accounting: {ssh: ["GRP","local"]}, delete}.
                    Use this BEFORE port_auth so the server group exists.
      user_roles -> local Port-Access roles + GBP/ABP policies: {roles: [{name,
                    vlan_tag, vlan_mode, description, reauth_period, ...}],
                    gbp_tags, gbps, abps, delete}.
      port_auth  -> 802.1X / MAC-auth on access ports (many ports in ONE call):
                    {interfaces: ["1/1/1", ...], methods: {dot1x: true |
                    {auth_enable, reauth_enable, reauth_period, max_retries,
                    eapol_timeout, ...}, "mac-auth": true | {auth_enable,
                    cached_reauth_enable, radius_server_group}},
                    auth_precedence: ["dot1x","mac-auth"] (or "dot1x mac-auth"),
                    auth_priority, auth_mode (client-mode|device-mode|
                    multi-domain|proxy-mode), clients_limit,
                    mda_data_clients_limit, roles: {auth, fallback|guest,
                    critical, critical_voice, reject, pre_auth}, create_roles:
                    [{name, vlan_tag, ...}] (roles created first),
                    concurrent_onboarding, radius_override}. Shortcuts
                    `dot1x: true` / `mac_auth: true` are accepted; a malformed
                    shape returns the expected schema instead of writing.
      app_recognition -> {enable, mode, abp_session_limit_exceed_action}.
    Workflow: `plan` returns a `dry_run_token`; `apply` REQUIRES that token
    (same params) and re-checks the plan before writing. Each apply runs inside
    a firmware auto-checkpoint (auto-revert on failure; opt out for this call
    with `auto_checkpoint=false`). `force=true` overrides the
    CX_PROTECTED_OBJECTS guard. Per-interface results are compacted to a
    summary (ok/failed/failed_items) unless `verbose=true`."""
    return await _write_dispatch("configure_security", _MAP_W_SECURITY, scope,
                                 action, device, site, params, dry_run_token, force,
                                 auto_checkpoint, verbose)


async def configure_service(scope: str = "vlan", action: str = "plan",
                            device: str = None, site: str = None,
                            params: dict = None, dry_run_token: str = None,
                            force: bool = False, auto_checkpoint: bool = None,
                            verbose: bool = False) -> dict:
    """Orchestrated L2/L3 VLAN service. `scope`: vlan. `action`:
      plan        : preview the create plan (default) -> returns dry_run_token
      apply       : create/update the service (REQUIRES the plan's dry_run_token)
      delete_plan : preview the delete plan -> returns dry_run_token
      delete      : remove the service (REQUIRES the delete_plan's dry_run_token)
      verify      : check the resulting VLAN state
    Pass service fields in `params` (vlan_id, name, vni, svi_ip, vrf, interfaces,
    evpn — set evpn=false for an Extended Edge / Stub-VTEP device: maps the VLAN
    to a VNI WITHOUT an EVPN route-target, no BGP-EVPN participation).
    For EXPLICIT RD / route-targets (no fabric discovery / RT deduction) use
    configure_routing(scope='evpn_vlan') instead.
    (The VLAN-service orchestrator has its own per-device rollback; the
    firmware auto-checkpoint / `auto_checkpoint` flag apply to configure_*.)"""
    if scope != "vlan":
        return {"error": f"[configure_service] unknown scope '{scope}'",
                "valid_scopes": ["vlan"]}
    base = dict(params or {})

    def _adapt_devices_kw(fn: Callable) -> Callable:
        """create_vlan_service/delete_vlan_service take `devices` (a list), not
        `device` \u2014 _guarded_write always calls fn(device=..., **kw)."""
        async def _wrapped(*, device=None, **kwargs):
            if device is not None and "devices" not in kwargs:
                kwargs["devices"] = _coerce_device_list(device)
            return await fn(**kwargs)
        return _wrapped

    if action in ("plan", "apply"):
        fn = _SRV.create_vlan_service
        kw = _filtered_kwargs(fn, dict(base, site=site))
        return await _guarded_write("create_vlan_service", _adapt_devices_kw(fn),
                                    device, kw, action == "apply", dry_run_token,
                                    force, auto_checkpoint, verbose)
    if action in ("delete", "delete_plan"):
        fn = _SRV.delete_vlan_service
        kw = _filtered_kwargs(fn, dict(base, site=site))
        return await _guarded_write("delete_vlan_service", _adapt_devices_kw(fn),
                                    device, kw, action == "delete", dry_run_token,
                                    force, auto_checkpoint, verbose)
    if action == "verify":
        targets = await _resolve_targets(device, site)
        if not targets:
            return {"error": "[configure_service] no target device."}
        results, errors = await _fanout("get_vlans", targets,
                                        {"vlan_id": base.get("vlan_id")})
        return _envelope("vlan", targets, results, errors)
    return {"error": f"[configure_service] invalid action '{action}'",
            "valid_actions": ["plan", "apply", "delete", "delete_plan", "verify"]}


# Single entry point for every multi-step orchestrator: name -> (orchestrate_fn,
# verify_fn|None). Deliberately excludes orchestrate_fabric_underlay (it takes
# `spines`/`leafs` device LISTS instead of a single device/site target — see
# _KEEP_ATOMIC; call it directly, it doesn't fit this device=/site= dispatch).
_MAP_ORCHESTRATORS: dict[str, tuple[str, Optional[str]]] = {
    "vsx_pair": ("orchestrate_vsx_pair", "verify_vsx_cluster"),
    "l3_link": ("orchestrate_l3_link", "verify_routed_port"),
    "access_port": ("orchestrate_access_port", "verify_access_port"),
    "static_vxlan": ("orchestrate_static_vxlan", "verify_static_vxlan"),
    "evpn_vlan": ("orchestrate_evpn_vlan", "verify_evpn_vlan"),
    "radius_dot1x": ("orchestrate_radius_dot1x", "verify_radius_dot1x"),
    "overlay": ("orchestrate_overlay", "verify_overlay"),
    "overlay_service": ("orchestrate_overlay_service", "verify_overlay_service"),
}


async def orchestrator(name: str, action: str = "plan", device: str = None,
                       site: str = None, params: dict = None,
                       dry_run_token: str = None, force: bool = False,
                       auto_checkpoint: bool = None, verbose: bool = False) -> dict:
    """Single entry point for every multi-step orchestrator: `name` selects
    which one, `params` carries its own arguments (unknown keys for that
    orchestrator are silently dropped, never rejected). Same as calling
    `configure_interface`/`configure_routing`/`configure_security`/
    `configure_redundancy` with that scope directly — this dispatcher just
    collapses all of them into one discoverable name/params surface.

    Valid `name` values (see configure_interface/routing/security/redundancy
    docstrings for each one's exact `params` shape):
      vsx_pair        : VSX pairing (new pair) or full teardown (`delete=true`)
      l3_link         : routed P2P link + optional VRF/OSPF, single or batched
                        (`links=[...]`)
      access_port     : L2 access port(s) + STP + 802.1X in one call
      static_vxlan    : VTEP + VLAN/VNI maps + static peers (no EVPN) — legacy,
                        prefer `overlay` + `overlay_service` for a fabric VTEP
      evpn_vlan       : ONE EVPN VLAN service with explicit RD/RT — legacy,
                        prefer `overlay_service` (batch, `attach` modes)
      radius_dot1x    : RADIUS server(s) + group + global AAA + per-port 802.1X
      overlay         : device-level VXLAN interface + (mode=evpn|stub) global
                        EVPN + virtual-MAC + optional BGP-EVPN control-plane;
                        mode=static (Extended Edge) stops after the interface
      overlay_service : BATCH VLAN -> L2VNI -> EVPN route-target and/or static
                        peer (`attach`='evpn'|'static'|'stub' per entry);
                        requires `overlay` to have run first on the target

    `action`: 'plan' (preview, returns `dry_run_token`) | 'apply' (requires
    that token) | 'verify' (read-back via the paired verify_* function).
    Each apply runs inside a firmware auto-checkpoint (auto-revert on
    failure; opt out with `auto_checkpoint=false`). `force=true` overrides
    the CX_PROTECTED_OBJECTS guard. `orchestrate_fabric_underlay` and
    `orchestrate_fabric_overlay` are NOT reachable here (their `spines`/
    `leafs` lists replace device/site entirely) — call them directly."""
    entry = _MAP_ORCHESTRATORS.get(name)
    if not entry:
        return {"error": f"[orchestrator] unknown name '{name}'",
                "valid_names": sorted(_MAP_ORCHESTRATORS)}
    cfg_name, verify_name = entry
    base = dict(params or {})
    if action == "verify":
        if not verify_name:
            return {"error": f"[orchestrator] no verify action for '{name}'"}
        fn = getattr(_SRV, verify_name, None)
        if fn is None:
            return {"error": f"[orchestrator] verify function '{verify_name}' not found"}
        call = _filtered_kwargs(fn, dict(base, site=site))
        return await fn(device=device, site=site, **{k: v for k, v in call.items()
                                                     if k != "site"})
    if action not in ("plan", "apply"):
        return {"error": f"[orchestrator] invalid action '{action}'",
                "valid_actions": ["plan", "apply", "verify"]}
    fn = getattr(_SRV, cfg_name, None)
    if fn is None:
        return {"error": f"[orchestrator] function '{cfg_name}' not found"}
    call = _filtered_kwargs(fn, dict(base, site=site))
    result = await _guarded_write(cfg_name, fn, device, call,
                                  action == "apply", dry_run_token, force,
                                  auto_checkpoint, verbose)
    return _flag_ignored_params(result, base, call, name)


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
    configure_redundancy, orchestrator, diagnose, troubleshoot,
]

# Legacy atomic tools that stay advertised as-is (never de-advertised).
_KEEP_ATOMIC: set[str] = {
    "list_devices", "list_sites", "get_logs", "run_ssh_commands",
    "manage_config", "backup_config", "logout", "rollback",
    # Doesn't fit the single-device configure_*(scope=...) generic dispatch
    # model (_guarded_write always calls fn(device=..., **call)) — it takes
    # `spines`/`leafs` device LISTS instead of one `device`/`site` target.
    "orchestrate_fabric_underlay", "orchestrate_fabric_overlay",
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
