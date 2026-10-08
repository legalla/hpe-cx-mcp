"""Write (``configure_*``) tools: idempotent plan/apply domain configuration,
each paired with a ``verify_*`` read-back tool in tools_verify.py."""

import asyncio
import re

from clients.aruba_client import (
    ArubaAPIError, _v_mac, _v_ipv4_host, _v_ip_host, _v_ipv4_cidr, _v_int_range,
    _v_vlan, _v_vni, _v_mtu, _v_asn, _v_route_target, _v_ospf_area, _v_esi,
    _v_vrf_rd, _v_vrf_route_target,
)
from core import server_core as _core
from core.server_core import (
    mcp, _get_client, _resolve_devices, _safe_targets, _precheck,
    _deny_read_only_many, _close_sessions,
)

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


def _normalize_ospf_interfaces(interfaces) -> list[dict]:
    """Accept `interfaces` as a list of plain names (str) OR dicts
    {"interface": name, "network_type"/"passive"/"cost"/"bfd": ...}. Raises
    ArubaAPIError(400) on a malformed entry (e.g. a dict without an
    'interface' key, or any other type) instead of letting it reach
    urllib.parse.quote() and blow up with a cryptic 'quote_from_bytes()
    expected bytes' further down the call stack."""
    normalized = []
    for item in (interfaces or []):
        if isinstance(item, str):
            normalized.append({"interface": item})
        elif isinstance(item, dict):
            name = item.get("interface")
            if not isinstance(name, str) or not name:
                raise ArubaAPIError(
                    f"Invalid interfaces entry {item!r}: expected a dict with "
                    "a non-empty string 'interface' key.", 400)
            normalized.append(dict(item))
        else:
            raise ArubaAPIError(
                f"Invalid interfaces entry {item!r}: expected an interface "
                "name (str) or a dict with an 'interface' key.", 400)
    return normalized


# Executor result shapes (status == "created") → reversible forward action.
# Only objects with a verified, unambiguous delete primitive are listed.
_CREATED_SHAPES = (
    ("interface", "create_loopback", lambda r: str(r["interface"]).startswith("loopback")),
    ("vni", "create_l3vni", lambda r: "vlan" not in r),
    ("vrf", "ensure_vrf", lambda r: "address_family" not in r and "vni" not in r
     and "interface" not in r),
)


def _created_actions(result) -> list[dict]:
    """Walk an executor result and list the objects it CREATED, as plan-style
    ``{"action": <forward>, ...args}`` items usable by write_safety rollback."""
    out: list[dict] = []
    if isinstance(result, dict):
        if result.get("status") == "created":
            for key, forward, pred in _CREATED_SHAPES:
                if key in result and pred(result):
                    out.append({"action": forward, key: result[key]})
                    break
        for v in result.values():
            out.extend(_created_actions(v))
    elif isinstance(result, list):
        for v in result:
            out.extend(_created_actions(v))
    return out


def _guarded_executor(executor):
    """Wrap a domain executor with the write-time safety rails:

    * ``force`` (contextvar) lifts the CX_PROTECTED_OBJECTS guard for this apply;
    * firmware auto-checkpoint (confirmed commit, unless disabled globally via
      CX_AUTO_CHECKPOINT=false or per call via auto_checkpoint=false): armed
      BEFORE the write, confirmed only if the executor succeeds. On failure the checkpoint is left
      armed so the switch reverts by itself at the deadline — the MCP dying
      mid-apply can no longer leave a half-applied configuration behind."""
    force = _core.FORCE_PROTECTED.get()
    minutes = _core._AUTO_CHECKPOINT_MINUTES

    async def _run(dev, client):
        client.allow_protected = force
        try:
            if not _core.auto_checkpoint_enabled():
                return {"result": await executor(dev, client), "checkpoint": "disabled"}
            try:
                await client.set_auto_checkpoint(minutes)
            except ArubaAPIError as exc:
                raise ArubaAPIError(
                    f"auto-checkpoint could not be armed — apply refused "
                    f"(nothing written): {exc.args[0] if exc.args else exc}. Confirm/clear "
                    f"the pending checkpoint on the device or set CX_AUTO_CHECKPOINT=false.",
                    exc.status_code or 409) from exc
            writes_before = getattr(client, "writes", 0)
            try:
                res = await executor(dev, client)
            except Exception as exc:
                msg = exc.args[0] if isinstance(exc, ArubaAPIError) and exc.args else str(exc)
                if getattr(client, "writes", 0) == writes_before:
                    # Pre-flight refusal (guard, validation, 404…): nothing was
                    # written, so confirming just disarms the timer.
                    try:
                        await client.confirm_auto_checkpoint()
                        tail = " [nothing written; auto-checkpoint disarmed]"
                    except Exception:  # noqa: BLE001
                        tail = (f" [nothing written; auto-checkpoint still armed, "
                                f"reverts in {minutes} min]")
                else:
                    tail = (f" [auto-checkpoint left ARMED: the device reverts to "
                            f"its previous configuration in {minutes} min unless "
                            f"manage_config(action='confirm') is called]")
                raise ArubaAPIError(f"{msg}{tail}",
                                    getattr(exc, "status_code", None)) from exc
            await client.confirm_auto_checkpoint()
            return {"result": res, "checkpoint": "confirmed"}
        finally:
            client.allow_protected = False
    return _run


async def _domain_write(operation: str, device, site, plan: dict, executor,
                        apply: bool) -> dict:
    """Shared plan/apply wrapper for the configuration-domain tools.

    apply=False → returns the computed plan only (no write). apply=True →
    enforces the read-only guard, runs `executor` on every target inside an
    auto-checkpoint (see `_guarded_executor`), closes the sessions and returns
    a per-device result map plus `reversible` (created objects, for rollback)."""
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
    raw = await _exec_on_devices(candidates, _guarded_executor(executor))
    await _close_sessions(candidates)
    verbose = _core.VERBOSE_RESULT.get()
    results: dict = {}
    reversible: dict = {}
    for dev, r in raw.items():
        if r["ok"]:
            wrapped = r["result"]
            res = wrapped["result"]
            partial = (isinstance(res, dict) and isinstance(res.get("summary"), dict)
                       and res["summary"].get("failed", 0) > 0)
            results[dev] = {"ok": not partial,
                            "result": res if verbose else _compact_result(res),
                            "checkpoint": wrapped["checkpoint"]}
            if partial:
                steps = res["summary"].get("partial_steps") or res["summary"].get("failed_items")
                results[dev]["error"] = (
                    f"{res['summary']['failed']} item(s) failed on this device"
                    + (f" ({steps})" if steps else "")
                    + " — see result.summary / failed_items (writes on the other items were kept)")
            created = _created_actions(res)
            if created:
                reversible[dev] = created
        else:
            results[dev] = r
    failed = [d for d, r in results.items() if not r["ok"]]
    return {
        "status": "applied" if not failed else "partial", "operation": operation,
        "targets": candidates, "plan": plan, "apply": True, "results": results,
        "reversible": reversible,
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


_COMPACT_MIN_ITEMS = 6


async def _is_vsx_pair(dev_a: str, dev_b: str) -> tuple[bool, str]:
    """True when both devices run VSX with the same cluster identity (identical
    configured system_mac or operational system id) — i.e. they are peers."""
    ids: dict = {}
    for dev in (dev_a, dev_b):
        try:
            async with _get_client(dev) as client:
                st = await client.get_vsx_status()
        except Exception as exc:  # noqa: BLE001
            return False, f"could not read VSX state on {dev}: {exc}"
        if not st.get("configured"):
            return False, f"{dev} is not a VSX member"
        ids[dev] = (st.get("system_mac"), st.get("oper_system_id"))
    a, b = ids[dev_a], ids[dev_b]
    same = (a[0] not in (None, "N/A") and a[0] == b[0]) or \
           (a[1] not in (None, "N/A") and a[1] == b[1])
    if not same:
        return False, f"{dev_a} and {dev_b} are VSX members of DIFFERENT clusters ({a} vs {b})"
    return True, ""


async def _per_device_value(value, targets: list, field: str, *, required: bool = False):
    """Resolve a per-device parameter (an IP address that must be unique per
    switch: VTEP source, routed-port /31, loopback...). Accepts ONE value when
    there is ONE target, or a {device: value} mapping (keys = inventory names or
    IPs) covering every target. The SAME value on two devices is allowed ONLY
    when they are the two members of one VSX cluster (anycast VTEP / active-
    gateway); a bare single value with exactly two VSX-peer targets is accepted
    too. Returns ({canonical_device: value}, error|None)."""
    def _bad(msg, action="Give each device its own value; nothing was written."):
        return None, {"status": "invalid_input", "field": field, "error": msg,
                      "action_required": action}

    if value is None:
        if required:
            return _bad(f"`{field}` is required.", "Provide the value and re-run; nothing was written.")
        return {d: None for d in targets}, None
    if isinstance(value, dict):
        out: dict = {}
        for k, v in value.items():
            try:
                canon = _resolve_devices(device=k)[0]
            except ValueError as exc:
                return None, {"status": "error", "error": str(exc)}
            out[canon] = v
        missing = [d for d in targets if d not in out]
        if missing:
            return _bad(f"`{field}` mapping has no entry for target(s) {missing}.",
                        f"Add `{field}` for every target device; nothing was written.")
        mapping = {d: out[d] for d in targets}
    elif len(targets) > 2:
        example = ", ".join(f'"{d}": "<ip>"' for d in targets)
        return _bad(f"`{field}`='{value}' for {len(targets)} devices would configure the SAME "
                    f"address on every switch (only allowed on the 2 members of a VSX pair). "
                    f"Pass a per-device mapping: {field}={{{example}}}.")
    else:
        mapping = {d: value for d in targets}
    # Shared values: only a VSX pair (exactly 2 devices, same cluster) may share one.
    groups: dict = {}
    for d, v in mapping.items():
        groups.setdefault(str(v), []).append(d)
    for v, devs in groups.items():
        if len(devs) < 2:
            continue
        if len(devs) > 2:
            return _bad(f"`{field}`='{v}' is shared by {len(devs)} devices {devs}: an address may "
                        f"only be shared by the 2 members of a VSX pair.")
        ok, why = await _is_vsx_pair(devs[0], devs[1])
        if not ok:
            return _bad(f"`{field}`='{v}' is shared by {devs} but they are not a VSX pair ({why}). "
                        f"The same address is only allowed on the 2 members of one VSX cluster.")
    return mapping, None


_AUTO_ID_VALUES = ("auto", "loopback0")


def _is_auto_id(value) -> bool:
    return isinstance(value, str) and value.strip().lower() in _AUTO_ID_VALUES


async def _per_device_id(value, targets: list, field: str):
    """Per-device identifier that must be UNIQUE per switch (router-id, RD...):
    a {device: value} mapping, ONE value for ONE target, or 'auto'/'loopback0'
    (resolved at apply time from each device's loopback0). Unlike
    `_per_device_value`, a shared literal is refused even on a VSX pair."""
    if value is None or _is_auto_id(value):
        return {d: value for d in targets}, None
    if isinstance(value, dict):
        out: dict = {}
        for k, v in value.items():
            try:
                out[_resolve_devices(device=k)[0]] = v
            except ValueError as exc:
                return None, {"status": "error", "error": str(exc)}
        missing = [d for d in targets if d not in out]
        if missing:
            return None, {"status": "invalid_input", "field": field,
                          "error": f"`{field}` mapping has no entry for target(s) {missing}.",
                          "action_required": f"Add `{field}` for every target device "
                                             "(or use 'loopback0'); nothing was written."}
        return {d: out[d] for d in targets}, None
    if len(targets) > 1:
        return None, {"status": "invalid_input", "field": field,
                      "error": f"`{field}`='{value}' would be the SAME on {len(targets)} devices.",
                      "action_required": f"Pass {field}={{device: value}} or "
                                         f"{field}='loopback0'; nothing was written."}
    return {d: value for d in targets}, None


async def _resolve_auto_id(client, value):
    """'auto'/'loopback0' -> the device's loopback0 address; else unchanged."""
    if _is_auto_id(value):
        return await client.loopback_ip("loopback0")
    return value


async def _batch(ids: list, fn, key: str) -> dict:
    """Run `fn(id)` for each id, tolerant per item (one failure doesn't stop
    the others); returns {items, summary} like the other batch tools."""
    cells, failed = [], []
    for i in ids:
        try:
            res = await fn(i)
            cells.append({key: i, "ok": True, **(res if isinstance(res, dict) else {"result": res})})
        except ArubaAPIError as exc:
            cells.append({key: i, "ok": False, "status": "failed",
                          "error": exc.args[0] if exc.args else str(exc)})
            failed.append(i)
    return {"items": cells, "summary": {"ok": len(ids) - len(failed), "failed": len(failed),
                                        "failed_items": failed}}


def _item_failed(item) -> bool:
    if not isinstance(item, dict):
        return False
    if item.get("ok") is False:
        return True
    if str(item.get("status", "")).lower() in ("error", "failed", "forbidden", "partial"):
        return True
    # orchestrator steps are {"action", "result": {...status...}}
    nested = item.get("result")
    return isinstance(nested, dict) and "action" in item and _item_failed(nested)


def _compact_result(value):
    """Collapse long lists of per-object results into {count, statuses, failed,
    sample}. Failed items are always kept in full; short lists are untouched."""
    if isinstance(value, list):
        if len(value) >= _COMPACT_MIN_ITEMS and all(isinstance(v, dict) for v in value):
            statuses: dict = {}
            for v in value:
                status = v.get("status")
                if status is None and isinstance(v.get("result"), dict):
                    status = v["result"].get("status")
                key = str(status or ("ok" if v.get("ok", True) else "failed"))
                statuses[key] = statuses.get(key, 0) + 1
            failed = [v for v in value if _item_failed(v)]
            return {"count": len(value), "ok": len(value) - len(failed),
                    "failed": len(failed), "statuses": statuses,
                    "failed_items": failed, "sample": _compact_result(value[0]),
                    "note": "compacted — pass verbose=true for the full per-item list"}
        return [_compact_result(v) for v in value]
    if isinstance(value, dict):
        return {k: _compact_result(v) for k, v in value.items()}
    return value


@mcp.tool()
async def configure_loopback(name: str, ip_address, device: str = None,
                             site: str = None, vrf: str = "default",
                             apply: bool = False) -> dict:
    """Create/update a loopback interface (idempotent), optionally attached to a
    VRF. `name` e.g. 'loopback0', `ip_address` in CIDR form e.g. '10.0.0.1/32'
    — for SEVERAL devices pass a per-device mapping {"<device>": "<cidr>", ...}
    (the same address is only accepted on the 2 members of one VSX pair).
    If `vrf` is omitted, the default VRF is used. `apply`=False returns the plan only."""
    targets = _safe_targets(device, site)
    ips, err = await _per_device_value(ip_address, targets, "ip_address", required=True)
    if err:
        return err
    err = _precheck([(f"ip_address[{d}]", lambda _v=v: _v_ipv4_cidr(_v, "ip_address"))
                     for d, v in ips.items()])
    if err:
        return err
    vrf = vrf or "default"
    plan = {dev: [{"action": "create_loopback", "interface": name,
                   "ip4_address": ips[dev], "vrf": vrf}]
            for dev in targets}

    async def _exec(dev, client):
        return await client.create_loopback(name, ips[dev], vrf=vrf)

    return await _domain_write("configure_loopback", device, site, plan, _exec, apply)


@mcp.tool()
async def configure_routed_port(interface: str = None, device: str = None, site: str = None,
                                ip_address=None, description: str = None,
                                mtu: int = None, vrf: str = "default",
                                create_vrf: bool = False,
                                enable: bool = True,
                                remove_from_lag: bool = False,
                                delete_empty_lags: bool = False,
                                ensure_internal_vlan_range: bool = False,
                                internal_vlan_range_size: int = 128,
                                verify_connected_route: bool = True,
                                interfaces: list = None,
                                apply: bool = False) -> dict:
    """Configure a physical port as a routed (L3) interface (idempotent): no
    switchport, IP address, optional VRF/MTU. Typical for point-to-point underlay
    links and VSX keepalive links. `ip_address` in CIDR form (e.g.
    '10.1.1.0/31'); for SEVERAL devices pass a per-device mapping {"<device>":
    "<cidr>", ...} (one address per switch — sharing is only accepted between
    the 2 members of a VSX pair). If `vrf` is omitted, the default VRF is used;
    `create_vrf=True` creates a missing non-default VRF first (bare VRF, no RD/RT).

    - `interfaces`: to configure SEVERAL ports on the SAME device set in ONE
      call, pass a list instead of `interface`: [{"interface": "1/1/1",
      "ip_address": "10.1.1.0/31" | {device: cidr}, "mtu", "description",
      "enable", "vrf", "create_vrf", "remove_from_lag"}, ...] — any field
      omitted on an entry falls back to the matching top-level param.
    - `remove_from_lag=True`: if the port is currently a LAG member, pull it out
      of that LAG FIRST in this same call (result.interface.removed_from_lag
      names the LAG, with a warning that this bounces the remaining bundle) —
      instead of requiring a separate manual LAG-membership removal beforehand.
      `delete_empty_lags=True` deletes the LAG once its last member is gone.
    - `ensure_internal_vlan_range`/`internal_vlan_range_size`: some platforms
      silently produce a non-routing port (`routing:true`+IP written, but NO
      connected route / line-protocol down) unless a non-empty `system
      internal-vlan-range` pool exists. When `ip_address` is set, this is
      checked first; by default the call FAILS EXPLICITLY (no write) with an
      actionable message if the pool is empty — pass
      `ensure_internal_vlan_range=True` to have it auto-configured instead.
    - `verify_connected_route` (default True): after applying, re-reads the
      route table to confirm the connected route actually installed;
      otherwise the result is `status='partial'` with a `warning`, not a bare
      success.
    `apply`=False = plan."""
    targets = _safe_targets(device, site)
    vrf = vrf or "default"

    if interfaces:
        if interface is not None:
            return {"status": "invalid_input", "field": "interface",
                    "error": "pass EITHER `interface` OR `interfaces`, not both.",
                    "action_required": "remove one of the two."}
        raw_ports = interfaces
    else:
        if not interface:
            return {"status": "invalid_input", "field": "interface",
                    "error": "`interface` (or `interfaces`) is required.",
                    "action_required": "pass an interface name."}
        raw_ports = [{"interface": interface, "ip_address": ip_address, "mtu": mtu,
                    "description": description, "enable": enable, "vrf": vrf,
                    "create_vrf": create_vrf, "remove_from_lag": remove_from_lag}]

    port_specs = []
    for i, item in enumerate(raw_ports):
        if not isinstance(item, dict) or not item.get("interface"):
            return {"status": "invalid_input", "field": f"interfaces[{i}]",
                    "error": "each entry needs an 'interface' name.",
                    "action_required": "pass {'interface': <name>, ...} per port."}
        port_specs.append({
            "interface": item["interface"], "ip_address": item.get("ip_address", ip_address),
            "mtu": item.get("mtu", mtu), "description": item.get("description", description),
            "enable": item.get("enable", enable), "vrf": item.get("vrf", vrf) or "default",
            "create_vrf": item.get("create_vrf", create_vrf),
            "remove_from_lag": item.get("remove_from_lag", remove_from_lag),
        })

    resolved = []  # (spec, {dev: ip})
    for spec in port_specs:
        field = f"interfaces[{spec['interface']}].ip_address" if interfaces else "ip_address"
        ips, err = await _per_device_value(spec["ip_address"], targets, field)
        if err:
            return err
        resolved.append((spec, ips))

    err = _precheck([
        *[(f"{spec['interface']}.ip_address[{d}]", lambda _v=v: _v_ipv4_cidr(_v, "ip_address"))
          for spec, ips in resolved for d, v in ips.items() if v is not None],
        *[(f"{spec['interface']}.mtu", lambda _m=spec["mtu"]: _v_mtu(_m, "mtu"))
          for spec in port_specs if spec["mtu"] is not None],
    ])
    if err:
        return err

    def _steps(dev):
        steps = []
        vrfs_done = set()
        for spec, ips in resolved:
            v = spec["vrf"]
            if spec["create_vrf"] and v != "default" and v not in vrfs_done:
                steps.append({"action": "ensure_vrf", "vrf": v})
                vrfs_done.add(v)
            if spec["remove_from_lag"]:
                steps.append({"action": "remove_from_lag", "interface": spec["interface"]})
            steps.append({"action": "configure_routed_interface", "interface": spec["interface"],
                         "ip4_address": ips.get(dev), "vrf": v, "mtu": spec["mtu"],
                         "admin": "up" if spec["enable"] else "down"})
        return steps

    plan = {dev: _steps(dev) for dev in targets}

    async def _exec(dev, client):
        vrfs_done = set()
        results = []
        for spec, ips in resolved:
            v = spec["vrf"]
            entry = {}
            if spec["create_vrf"] and v != "default" and v not in vrfs_done:
                entry["vrf"] = await client.ensure_vrf(v)
                vrfs_done.add(v)
            entry["interface"] = await client.configure_routed_interface(
                spec["interface"], ip_cidr=ips.get(dev), description=spec["description"],
                mtu=spec["mtu"], vrf=v, enable=spec["enable"],
                remove_from_lag=spec["remove_from_lag"],
                delete_empty_lag=delete_empty_lags,
                ensure_internal_vlan_range=ensure_internal_vlan_range,
                internal_vlan_range_size=internal_vlan_range_size,
                verify_connected_route=verify_connected_route)
            results.append(entry)
        if len(results) == 1:
            return results[0]
        failed = [r["interface"]["interface"] for r in results
                 if r["interface"].get("status") not in ("configured",)]
        return {"interfaces": results,
                "summary": {"ok": len(results) - len(failed), "failed": len(failed),
                           "failed_interfaces": failed}}

    return await _domain_write("configure_routed_port", device, site, plan, _exec,
                               apply)


@mcp.tool()
async def configure_lag(lag_id, device: str = None, site: str = None,
                        members: list = None, remove_members: list = None,
                        mode: str = "static", lacp_rate: str = None,
                        lacp_fallback: bool = None, mclag_enabled: bool = None,
                        vlan_mode: str = None, access_vlan: int = None,
                        native_vlan: int = None, trunk_vlans: list = None,
                        evpn_multihoming_esi: str = None,
                        evpn_multihoming_es_rd: str = None,
                        evpn_multihoming_es_import_rt: str = None,
                        description: str = None, mtu: int = None,
                        enable: bool = True,
                        delete: bool = False, apply: bool = False) -> dict:
    """Create/update (or delete) a LAG (Link Aggregation Group / port-channel),
    idempotent. One tool covers all 4 flavours:

    - Standard/single-device STATIC LAG: `mode='static'` (default).
    - Standard/single-device LACP LAG: `mode='lacp-active'|'lacp-passive'`.
    - Multi-chassis LAG (MC-LAG / VSX): add `mclag_enabled=True` and target
      BOTH VSX peers (`device=[peerA, peerB]` or `site=...`) with the SAME
      `lag_id` and `mode` (local member port names may differ per peer).
    - EVPN Multihoming (ESI-LAG, L2 only): add `evpn_multihoming_esi` (e.g.
      '015c.a47d.2510.0000.0100' or 'type1-auto'), optionally
      `evpn_multihoming_es_rd` / `evpn_multihoming_es_import_rt`. Requires the
      global `multihoming_system_id` set once per VTEP (configure_evpn with
      `options={'multihoming_system_id': '<mac>'}`).

    `lag_id` accepts an int (e.g. 1) or a name ('lag1'). `members`/
    `remove_members` are MERGED into the existing member set (additive, not a
    replace) so repeated calls stay idempotent. `vlan_mode`:
    access|trunk|native-tagged|native-untagged (+ `access_vlan`/`native_vlan`/
    `trunk_vlans`); `description`, `mtu`, `lacp_fallback`, `lacp_rate` are set
    in the same call. `delete=True` removes the LAG entirely. `apply`=False
    returns the plan only."""
    _checks = []
    if access_vlan is not None:
        _checks.append(("access_vlan", lambda: _v_vlan(access_vlan, "access_vlan")))
    if native_vlan is not None:
        _checks.append(("native_vlan", lambda: _v_vlan(native_vlan, "native_vlan")))
    if mtu is not None:
        _checks.append(("mtu", lambda: _v_mtu(mtu, "mtu")))
    for _i, _v in enumerate(trunk_vlans or []):
        _checks.append((f"trunk_vlans[{_i}]", lambda _v=_v: _v_vlan(_v, "trunk_vlan")))
    if evpn_multihoming_esi is not None:
        _checks.append(("evpn_multihoming_esi",
                        lambda: _v_esi(evpn_multihoming_esi)))
    err = _precheck(_checks)
    if err:
        return err
    plan = {dev: {"lag_id": lag_id, "members": members or [],
                  "remove_members": remove_members or [], "mode": mode,
                  "mclag_enabled": mclag_enabled, "vlan_mode": vlan_mode,
                  "native_vlan": native_vlan, "trunk_vlans": trunk_vlans,
                  "description": description, "mtu": mtu,
                  "lacp_fallback": lacp_fallback,
                  "evpn_multihoming_esi": evpn_multihoming_esi, "delete": delete}
            for dev in (_safe_targets(device, site))}

    async def _exec(dev, client):
        return await client.configure_lag(
            lag_id, members=members, remove_members=remove_members, mode=mode,
            lacp_rate=lacp_rate, lacp_fallback=lacp_fallback,
            mclag_enabled=mclag_enabled, vlan_mode=vlan_mode,
            access_vlan=access_vlan, native_vlan=native_vlan,
            trunk_vlans=trunk_vlans, evpn_multihoming_esi=evpn_multihoming_esi,
            evpn_multihoming_es_rd=evpn_multihoming_es_rd,
            evpn_multihoming_es_import_rt=evpn_multihoming_es_import_rt,
            description=description, mtu=mtu, enable=enable, delete=delete)

    return await _domain_write("configure_lag", device, site, plan, _exec, apply)


@mcp.tool()
async def configure_vxlan_interface(device: str = None, site: str = None,
                                    interface: str = "vxlan1", source_ip=None,
                                    dest_udp_port: int = None,
                                    inter_vxlan_bridging_mode: str = None,
                                    static_peers: list = None,
                                    remove_static_peers: list = None,
                                    apply: bool = False) -> dict:
    """Configure the VXLAN VTEP interface (idempotent). Also the tool to make a
    device a STUB VTEP / set its inter-VxLAN bridging behaviour and to manage
    STATIC VXLAN peers.

    - `source_ip`: VTEP source IP (options.local_ip). For SEVERAL devices pass a
        per-device mapping {"<device>": "<ip>", ...} — each VTEP needs its OWN
        source IP; the same IP is only accepted on the 2 members of a VSX pair
        (anycast VTEP).
    - `dest_udp_port`: VXLAN UDP port (default 4789 on the device).
    - `inter_vxlan_bridging_mode`: deny | static-evpn | static-all — the Stub
        VTEP / Scaled Design key. static-evpn bridges static<->dynamic tunnels on
        the same L2VNI; static-all bridges all tunnels; deny disables bridging.
    - `static_peers`: list of static VXLAN tunnels (non-EVPN flood), each
        {"destination": "<remote VTEP IP>", "vnis": [10010, ...], "vrf": "default"}.
        A peer whose destination is the device's own source IP is skipped.
    - `remove_static_peers`: list of remote VTEP IPs to remove.
    `apply`=False returns the plan only."""
    targets = _safe_targets(device, site)
    src, err = await _per_device_value(source_ip, targets, "source_ip")
    if err:
        return err
    _checks = [(f"source_ip[{d}]", lambda _v=v: _v_ip_host(_v, "source_ip"))
               for d, v in src.items() if v is not None]
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

    def _peers_for(dev):
        own = str(src.get(dev) or "").split("/")[0]
        return [p for p in (static_peers or []) if str(p.get("destination")).split("/")[0] != own]

    plan = {dev: {"interface": interface, "source_ip": src.get(dev),
                  "dest_udp_port": dest_udp_port,
                  "inter_vxlan_bridging_mode": inter_vxlan_bridging_mode,
                  "static_peers": _peers_for(dev),
                  "remove_static_peers": remove_static_peers or []}
            for dev in targets}

    async def _exec(dev, client):
        out = {"interface": await client.ensure_vxlan_interface(
            interface, source_ip=src.get(dev), dest_udp_port=dest_udp_port,
            inter_vxlan_bridging_mode=inter_vxlan_bridging_mode)}
        out["static_peers"] = []
        for p in _peers_for(dev):
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
                         redistribute_local_mac: bool = None,
                         redistribute_local_svi: bool = None,
                         options: dict = None, apply: bool = False) -> dict:
    """Configure the global EVPN feature (idempotent).

    - `dyn_vxlan_tunnel_bridging_mode`: no-bridging | ibgp-ebgp (Scaled Design
       inter-VxLAN bridging).
    - `arp_suppression` / `nd_suppression`: enable ARP/ND suppression.
    - `redistribute_local_mac` / `redistribute_local_svi`: CLI `redistribute
       local-mac` / `redistribute local-svi` (Type-2 routes for the local system
       MAC / the SVI IP+MAC); true enables, false disables, omitted = untouched.
    - `options`: passthrough of any other /system/evpn field (mac_move_count,
       mac_move_timer, oism_enable, igmp_mld_proxy_enable, ...).
    The result is `partial` (+ `not_applied`) if the device did not keep a field.
    `apply`=False returns the plan only."""
    plan = {dev: {"dyn_vxlan_tunnel_bridging_mode": dyn_vxlan_tunnel_bridging_mode,
                  "arp_suppression_enable": arp_suppression,
                  "nd_suppression_enable": nd_suppression, "options": options or {},
                  **({"redistribute_local_mac": redistribute_local_mac}
                     if redistribute_local_mac is not None else {}),
                  **({"redistribute_local_svi": redistribute_local_svi}
                     if redistribute_local_svi is not None else {})}
            for dev in (_safe_targets(device, site))}

    async def _exec(dev, client):
        res = await client.set_evpn_global(
            dyn_vxlan_tunnel_bridging_mode=dyn_vxlan_tunnel_bridging_mode,
            arp_suppression_enable=arp_suppression,
            nd_suppression_enable=nd_suppression,
            redistribute_local_mac=redistribute_local_mac,
            redistribute_local_svi=redistribute_local_svi, extra=options)
        if res.get("status") == "partial":
            res["summary"] = {"ok": 0, "failed": 1}
        return res

    return await _domain_write("configure_evpn", device, site, plan, _exec, apply)


@mcp.tool()
async def configure_ospf(device: str = None, site: str = None, vrf: str = "default",
                         instance_tag: int = 1, router_id=None,
                         passive_interface_default: bool = None, area_id: str = None,
                         area_type: str = None, interfaces: list = None,
                         passive_interfaces: list = None,
                         apply: bool = False) -> dict:
    """Configure an OSPF router instance in a VRF (idempotent).

    - `vrf`/`instance_tag`/`router_id`: OSPF process identity. For SEVERAL
      devices pass `router_id` as a per-device mapping {"<device>": "<ip>"}
      or 'loopback0' (each device's loopback0 address).
    - `passive_interface_default`: make all interfaces passive by default.
    - `passive_interfaces`: interface names (e.g. ['loopback0', 'vlan100']) to
      mark passive on the router (independent of area attachment).
    - `area_id` (dotted, e.g. '0.0.0.0') + `area_type` (default/stub/nssa/...).
    - `interfaces`: list of interface names to attach to `area_id`. Each entry
      is either a plain name ('1/1/1') or a dict for per-interface options:
      {"interface": "1/1/1", "network_type": "point_to_point", "passive":
      true, "cost": 10, "bfd": "enable"}. `network_type` also accepts a raw
      'ospf_iftype_*' value; `bfd` is enable|disable|default.
    If `vrf` is omitted, the default VRF is used. `apply`=False returns the plan only."""
    targets = _safe_targets(device, site)
    rids, err = await _per_device_id(router_id, targets, "router_id")
    if err:
        return err
    err = _precheck([
        *[(f"router_id[{d}]", lambda _v=v: _v_ipv4_host(_v, "router_id"))
          for d, v in rids.items() if v is not None and not _is_auto_id(v)],
        ("area_id", lambda: _v_ospf_area(area_id, "area_id")
         if area_id is not None else None),
    ])
    if err:
        return err
    try:
        norm_interfaces = _normalize_ospf_interfaces(interfaces)
    except ArubaAPIError as exc:
        return {"status": "invalid_input", "field": "interfaces",
                "error": str(exc), "action_required":
                "pass a list of interface names (str) or dicts with an "
                "'interface' key."}
    if norm_interfaces and area_id is None:
        return {"status": "invalid_input", "field": "area_id",
                "error": "area_id is required to attach interfaces.",
                "action_required": "pass area_id (e.g. '0.0.0.0') alongside interfaces."}
    vrf = vrf or "default"
    plan = {dev: {"vrf": vrf, "instance_tag": instance_tag, "router_id": rids.get(dev),
                  "passive_interface_default": passive_interface_default,
                  "area_id": area_id, "area_type": area_type,
                  "interfaces": norm_interfaces,
                  **({"passive_interfaces": list(passive_interfaces)}
                     if passive_interfaces else {})}
            for dev in targets}

    async def _exec(dev, client):
        out = {"router": await client.ensure_ospf_router(
            vrf=vrf, instance_tag=instance_tag,
            router_id=await _resolve_auto_id(client, rids.get(dev)),
            passive_interface_default=passive_interface_default)}
        if area_id is not None:
            out["area"] = await client.ensure_ospf_area(
                area_id, vrf=vrf, instance_tag=instance_tag, area_type=area_type)
            out["interfaces"] = []
            for item in norm_interfaces:
                intf = item["interface"]
                res = await client.add_ospf_interface(
                    intf, area_id, vrf=vrf, instance_tag=instance_tag)
                opts = {k: item[k] for k in ("network_type", "cost", "bfd") if k in item}
                if opts:
                    res["options"] = await client.configure_ospf_interface_options(
                        intf, **opts)
                if "passive" in item:
                    res["passive"] = await client.set_ospf_interface_passive(
                        intf, bool(item["passive"]), vrf=vrf, instance_tag=instance_tag)
                out["interfaces"].append(res)
        if passive_interfaces:
            out["passive_interfaces"] = [
                await client.set_ospf_interface_passive(
                    name, True, vrf=vrf, instance_tag=instance_tag)
                for name in passive_interfaces]
        return out

    return await _domain_write("configure_ospf", device, site, plan, _exec, apply)


@mcp.tool()
async def configure_bgp(asn: int, device: str = None, site: str = None,
                        vrf: str = "default", router_id=None,
                        neighbors: list = None, options: dict = None,
                        wait_established: int = 0,
                        apply: bool = False) -> dict:
    """Configure BGP in a VRF: router (ASN/router-id) + neighbors/peer-groups,
    including the L2VPN-EVPN overlay and Route-Reflector clients (idempotent).

    `router_id`: one IP for one device, a per-device mapping {"<device>":
    "<ip>"} for several, or 'loopback0' (each device's loopback0 address).
    `neighbors`: list of dicts, each:
      {"neighbor": "10.0.0.1" | "<group-name>",
       "remote_as": 65001, "is_peer_group": false,
       "peer_group": "<group-name>",          # bind a member to a group
       "update_source": "10.0.0.2",           # or:
       "local_interface": "loopback0",        # update-source loopback
       "activate": ["l2vpn-evpn"],            # or {"l2vpn-evpn": true, "ipv4-unicast": false}
       "route_reflector_client": ["l2vpn-evpn"],
       "send_community": {"l2vpn-evpn": "extended"},   # 'both' is sent as 'extended' on EVPN
       "next_hop_unchanged": ["l2vpn-evpn"],
       "description": "...", "password": "...", "bfd_enable": true,
       "ebgp_hop_count": 2, "passive": false, "shutdown": false,
       "extra": { ... any other BGP_Neighbor field ... }}
    A member of a peer-group INHERITS update-source/send-community/RR-client
    from the group on the device: only its own explicit fields are written
    (plus the group's remote-as and per-AF `activate`, which REST does not cascade).
    `wait_established` (seconds, 0 = no wait, max 300): after apply, poll until
    every IP neighbor of the call is Established; the ones that are not are
    reported (state + last BGP error) and the device result is partial.
    `options`: passthrough of any other BGP_Router field (maximum_paths,
    bestpath_*, timers, redistribute, ...). If `vrf` is omitted, the default VRF
    is used. `apply`=False returns the plan only."""
    targets = _safe_targets(device, site)
    rids, err = await _per_device_id(router_id, targets, "router_id")
    if err:
        return err
    _checks = [("asn", lambda: _v_asn(asn, "asn")),
               ("wait_established", lambda: _v_int_range(wait_established or 0, 0, 300,
                                                         "wait_established"))]
    for _d, _rid in rids.items():
        if _rid is not None and not _is_auto_id(_rid):
            _checks.append((f"router_id[{_d}]", lambda _r=_rid: _v_ipv4_host(_r, "router_id")))
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
    plan = {dev: {"vrf": vrf, "asn": asn, "router_id": rids.get(dev),
                  "neighbors": neighbors or [], "options": options or {},
                  **({"wait_established": wait_established} if wait_established else {})}
            for dev in targets}

    async def _exec(dev, client):
        out = {"router": await client.ensure_bgp_router(
            asn, vrf=vrf, router_id=await _resolve_auto_id(client, rids.get(dev)),
            extra=options)}
        out["neighbors"] = await _apply_bgp_neighbors(client, asn, vrf, neighbors or [])
        failed = [n["neighbor"] for n in out["neighbors"] if n.get("status") == "partial"]
        if wait_established:
            peers = [n["neighbor"] for n in out["neighbors"] if not n.get("is_peer_group")]
            out["sessions"] = await client.wait_bgp_established(
                peers, vrf=vrf, timeout=wait_established)
            failed += [f"{p}:not_established" for p in out["sessions"]["not_established"]]
        out["summary"] = {"ok": len(out["neighbors"]) - len(failed),
                          "failed": len(failed), "failed_neighbors": failed}
        return out

    return await _domain_write("configure_bgp", device, site, plan, _exec, apply)


# Attributes a peer-group member inherits on the device: never copied onto it.
_BGP_INHERITED = ("update_source", "local_interface", "send_community",
                  "next_hop_unchanged", "route_reflector_client", "password",
                  "bfd_enable", "ebgp_hop_count")


async def _apply_bgp_neighbors(client, asn, vrf: str, neighbors: list) -> list:
    """Create peer-groups first, then members. A member only gets its OWN
    explicit fields + the group's `activate` map (REST doesn't cascade AF
    activation); inherited attributes stay on the group, so a member never
    carries a conflicting copy (CLI: 'Update source is already configured
    with different transport address')."""
    groups = {(n.get("neighbor") or n.get("name")): n
              for n in neighbors if n.get("is_peer_group")}
    results = []
    for nbr in sorted(neighbors, key=lambda n: not n.get("is_peer_group")):
        name = nbr.get("neighbor") or nbr.get("name")
        if not name:
            raise ArubaAPIError(
                "Each BGP neighbor requires a 'neighbor' (IP or group name).", 400)
        grp = groups.get(nbr.get("peer_group")) if not nbr.get("is_peer_group") else None

        def _own(field, _n=nbr, _g=grp):
            val = _n.get(field)
            if grp is not None and field in _BGP_INHERITED and val is not None \
                    and val == (_g or {}).get(field):
                return None  # same as the group: let the device inherit it
            return val

        activate = nbr.get("activate")
        if activate is None and grp is not None:
            activate = grp.get("activate")
        remote_as = nbr.get("remote_as")
        if remote_as is None and grp is not None:
            remote_as = grp.get("remote_as")  # harmless duplicate; some firmware needs it on POST
        results.append(await client.create_bgp_neighbor(
            name, asn, vrf=vrf,
            remote_as=remote_as,
            is_peer_group=nbr.get("is_peer_group", False),
            peer_group=nbr.get("peer_group"),
            update_source=_own("update_source"),
            local_interface=_own("local_interface"),
            activate=_af_bool_map(activate),
            route_reflector_client=_af_bool_map(_own("route_reflector_client")),
            send_community=_own("send_community"),
            next_hop_unchanged=_af_bool_map(_own("next_hop_unchanged")),
            description=nbr.get("description"),
            password=_own("password"),
            bfd_enable=_own("bfd_enable"),
            ebgp_hop_count=_own("ebgp_hop_count"),
            passive=nbr.get("passive"),
            shutdown=nbr.get("shutdown"),
            extra=nbr.get("extra")))
    return results


@mcp.tool()
async def configure_vrf(name: str, device: str = None, site: str = None,
                        rd=None, import_route_targets: list = None,
                        export_route_targets: list = None,
                        address_families: list = None, options: dict = None,
                        l3vni: int = None, vni: int = None,
                        vxlan_interface: str = "vxlan1",
                        bgp_vrf: bool = None, bgp_asn: int = None,
                        redistribute: list = None,
                        delete: bool = False, apply: bool = False) -> dict:
    """Create/update a VRF with its Route-Distinguisher and EVPN Route-Targets
    (idempotent).

    - `rd`: route-distinguisher, explicit `ASN:nn` or `IP:nn`; for several
        devices a per-device mapping {"<device>": "<rd>"}; or 'auto' =
        `<loopback0 IP>:<l3vni>` derived on each device (needs `l3vni`).
    - `import_route_targets`/`export_route_targets`: VRF-level EVPN RTs
        (`ASN:nn`, IP:nn or 'auto') — this is where an EVPN/L3VNI VRF's RTs go.
    - `l3vni` (alias `vni`): bind this L3 VNI to the VRF (CLI: under `interface
        vxlan1`: `vni <id>` / `vrf <name>` / `routing`). Needs the VXLAN
        interface (`vxlan_interface`, default vxlan1) to exist already.
    - `bgp_vrf` (default True when `l3vni` is set): also create `router bgp
        <asn>` / `vrf <name>` / `address-family ipv4 unicast` (needed for EVPN
        type-5). `bgp_asn` defaults to the ASN of the default-VRF BGP router;
        `redistribute` (e.g. ['connected', 'static']) is set under that AF.
    - `address_families`: optional per-AF RT config (non-EVPN L3VPN only), list
        of {"address_family": "ipv4-unicast", "import_route_targets": [...],
         "export_route_targets": [...]}.
    - `options`: passthrough of any other VRF field.
    - `delete=True`: remove the VRF (and its `l3vni` binding if given); refuses
        the reserved default/mgmt VRFs.
    `apply`=False = plan only."""
    l3vni = l3vni if l3vni is not None else vni
    if l3vni is not None:
        err = _precheck([("l3vni", lambda: _v_vni(l3vni, "l3vni"))])
        if err:
            return err
    if delete:
        steps = ([{"action": "delete_vni", "vni": int(l3vni)}] if l3vni is not None else [])
        steps.append({"action": "delete_vrf", "vrf": name})
        plan = {dev: list(steps) for dev in (_safe_targets(device, site))}

        async def _exec_del(dev, client):
            out = {}
            if l3vni is not None:
                out["l3vni"] = await client.delete_vni(int(l3vni))
            out["vrf"] = await client.delete_vrf(name)
            return out if l3vni is not None else out["vrf"]

        return await _domain_write("configure_vrf", device, site, plan, _exec_del,
                                   apply)
    targets = _safe_targets(device, site)
    rds, err = await _per_device_id(rd, targets, "rd")
    if err:
        return err
    if any(_is_auto_id(v) for v in rds.values()) and l3vni is None:
        return {"status": "invalid_input", "field": "rd",
                "error": "rd='auto' is derived as <loopback0>:<l3vni> and needs `l3vni`.",
                "action_required": "pass l3vni, an explicit rd or a per-device mapping."}
    if bgp_vrf is None:
        bgp_vrf = l3vni is not None
    _checks = []
    for _d, _rd in rds.items():
        if _rd is not None and not _is_auto_id(_rd):
            _checks.append((f"rd[{_d}]", lambda _rd=_rd: _v_vrf_rd(_rd, "rd")))
    if bgp_asn is not None:
        _checks.append(("bgp_asn", lambda: _v_asn(bgp_asn, "bgp_asn")))
    for _s in (redistribute or []):
        if _s not in ("connected", "local-loopback", "static", "ospf"):
            return {"status": "invalid_input", "field": "redistribute",
                    "error": f"unknown source '{_s}'.",
                    "action_required": "use connected | local-loopback | static | ospf."}
    for _r in (import_route_targets or []):
        _checks.append(("import_route_targets",
                        lambda _r=_r: _v_vrf_route_target(_r, "import_rt")))
    for _r in (export_route_targets or []):
        _checks.append(("export_route_targets",
                        lambda _r=_r: _v_vrf_route_target(_r, "export_rt")))
    for _i, _af in enumerate(address_families or []):
        for _r in (_af.get("import_route_targets") or []):
            _checks.append((f"address_families[{_i}].import_route_targets",
                            lambda _r=_r: _v_vrf_route_target(_r, "import_rt")))
        for _r in (_af.get("export_route_targets") or []):
            _checks.append((f"address_families[{_i}].export_route_targets",
                            lambda _r=_r: _v_vrf_route_target(_r, "export_rt")))
    err = _precheck(_checks)
    if err:
        return err
    plan = {dev: {"name": name, "rd": rds.get(dev),
                  "import_route_targets": import_route_targets,
                  "export_route_targets": export_route_targets,
                  "address_families": address_families or [], "options": options or {},
                  **({"l3vni": int(l3vni), "vxlan_interface": vxlan_interface}
                     if l3vni is not None else {}),
                  **({"bgp_vrf": {"asn": bgp_asn or "auto (default-VRF BGP ASN)",
                                  "redistribute": list(redistribute or [])}}
                     if bgp_vrf else {})}
            for dev in targets}

    async def _exec(dev, client):
        my_rd = rds.get(dev)
        if _is_auto_id(my_rd):
            my_rd = f"{await client.loopback_ip('loopback0')}:{int(l3vni)}"
        out = {"vrf": await client.ensure_vrf(
            name, rd=my_rd, evpn_import_rts=import_route_targets,
            evpn_export_rts=export_route_targets, extra=options)}
        failed = []
        if l3vni is not None:
            out["l3vni"] = await client.create_l3vni(int(l3vni), name, vxlan_interface)
        if bgp_vrf:
            asn = bgp_asn or await client.detect_bgp_asn("default")
            if asn is None:
                out["bgp_vrf"] = {"status": "error", "error":
                                  "no BGP router in the default VRF — pass bgp_asn."}
                failed.append("bgp_vrf")
            else:
                out["bgp_vrf"] = await client.ensure_bgp_vrf(
                    asn, name, redistribute=redistribute)
        out["address_families"] = []
        for af in (address_families or []):
            af_name = af.get("address_family", "ipv4-unicast")
            try:
                out["address_families"].append(await client.set_vrf_address_family(
                    name, af_name,
                    import_rts=af.get("import_route_targets"),
                    export_rts=af.get("export_route_targets"), extra=af.get("extra")))
            except ArubaAPIError as exc:
                msg = exc.args[0] if exc.args else str(exc)
                out["address_families"].append(
                    {"address_family": af_name, "status": "error", "error": msg})
                failed.append(af_name)
        if out["vrf"].get("not_applied"):
            failed.append("vrf:" + ",".join(out["vrf"]["not_applied"]))
        if failed:
            out["summary"] = {"ok": 0, "failed": len(failed), "failed_items": failed}
        return out

    return await _domain_write("configure_vrf", device, site, plan, _exec, apply)


_PORT_AUTH_METHODS = ("dot1x", "mac-auth")
_PORT_AUTH_METHOD_ALIASES = {"dot1x": "dot1x", "802.1x": "dot1x", "8021x": "dot1x",
                             "mac-auth": "mac-auth", "mac_auth": "mac-auth",
                             "macauth": "mac-auth", "mac": "mac-auth"}
_PORT_AUTH_SCHEMA = {
    "interfaces": ["1/1/1", "1/1/2"],
    "methods": {"dot1x": "true | {auth_enable, reauth_enable, reauth_period, "
                         "max_retries, eapol_timeout, quiet_period, ...}",
                "mac-auth": "true | {auth_enable, cached_reauth_enable, "
                            "radius_server_group, ...}"},
    "auth_precedence": ["dot1x", "mac-auth"],
    "auth_priority": ["dot1x", "mac-auth"],
    "auth_mode": "client-mode | device-mode | multi-domain | proxy-mode",
    "clients_limit": 2, "mda_data_clients_limit": 1,
    "roles": {"auth": "ROLE", "fallback": "ROLE", "critical": "ROLE",
              "critical_voice": "ROLE", "reject": "ROLE", "pre_auth": "ROLE"},
    "create_roles": [{"name": "GUEST", "vlan_tag": 999}],
    "concurrent_onboarding": False, "radius_override": False,
}


def _port_auth_invalid(field: str, msg: str) -> dict:
    return {"status": "invalid_input", "field": field, "error": msg,
            "expected_schema": _PORT_AUTH_SCHEMA,
            "action_required": "Fix the parameter shape (see expected_schema) and "
                               "re-run; nothing was written."}


def _norm_method_name(name) -> str | None:
    return _PORT_AUTH_METHOD_ALIASES.get(str(name).strip().lower().replace(" ", ""))


_IFACE_RANGE_RE = re.compile(r"^(\d+/\d+/)(\d+)-(?:\d+/\d+/)?(\d+)$")


def _expand_interfaces(value) -> list[str]:
    """'1/1/1-1/1/4, 1/1/10' | ['1/1/1-4'] -> ['1/1/1','1/1/2','1/1/3','1/1/4','1/1/10']
    (CLI-style ranges expanded; REST addresses one port at a time)."""
    if value is None:
        return []
    if isinstance(value, str):
        value = [p for p in re.split(r"[\s,]+", value.strip()) if p]
    out: list[str] = []
    for item in value:
        s = str(item).strip()
        m = _IFACE_RANGE_RE.match(s)
        if m and int(m.group(2)) <= int(m.group(3)):
            out.extend(f"{m.group(1)}{i}" for i in range(int(m.group(2)), int(m.group(3)) + 1))
        elif s and s not in out:
            out.append(s)
    return out


def _norm_method_list(value, field: str):
    """'dot1x mac-auth' | 'dot1x,mac-auth' | ['dot1x','mac-auth'] -> canonical list."""
    if value is None:
        return None, None
    if isinstance(value, str):
        value = [p for p in re.split(r"[\s,]+", value.strip()) if p]
    if not isinstance(value, (list, tuple)):
        return None, _port_auth_invalid(field, f"`{field}` must be an ordered list "
                                        f"of methods, e.g. [\"dot1x\",\"mac-auth\"].")
    out = []
    for m in value:
        canon = _norm_method_name(m)
        if canon is None:
            return None, _port_auth_invalid(
                field, f"Unknown method '{m}' in `{field}`; valid: {list(_PORT_AUTH_METHODS)}.")
        if canon not in out:
            out.append(canon)
    return out, None


def _norm_methods(methods, dot1x, mac_auth):
    """Accept {dot1x: true}, {dot1x: {...}}, {'mac_auth': ...}, plus top-level
    shortcuts dot1x=True / mac_auth=True -> {canonical: {opts}}."""
    out: dict = {}
    if methods is not None and not isinstance(methods, dict):
        return None, _port_auth_invalid(
            "methods", "`methods` must be a dict keyed by method (dot1x / mac-auth).")
    for raw_name, opts in (methods or {}).items():
        canon = _norm_method_name(raw_name)
        if canon is None:
            return None, _port_auth_invalid(
                "methods", f"Unknown method '{raw_name}'; valid keys: {list(_PORT_AUTH_METHODS)}.")
        if opts is None or isinstance(opts, bool):
            out[canon] = {"auth_enable": True if opts is None else bool(opts)}
        elif isinstance(opts, dict):
            out[canon] = {"auth_enable": True, **opts}
        else:
            return None, _port_auth_invalid(
                f"methods.{raw_name}", "Method options must be `true`/`false` or a dict "
                                       "such as {\"auth_enable\": true, \"reauth_period\": 3600}.")
    for shortcut, canon in ((dot1x, "dot1x"), (mac_auth, "mac-auth")):
        if shortcut is None:
            continue
        if isinstance(shortcut, bool):
            out.setdefault(canon, {})["auth_enable"] = shortcut
        elif isinstance(shortcut, dict):
            out[canon] = {"auth_enable": True, **out.get(canon, {}), **shortcut}
        else:
            return None, _port_auth_invalid(
                canon.replace("-", "_"), "Shortcut must be a bool or a dict of options.")
    return out, None


@mcp.tool()
async def configure_port_auth(interfaces: list, device: str = None, site: str = None,
                              methods: dict = None, dot1x=None, mac_auth=None,
                              auth_mode: str = None,
                              clients_limit: int = None,
                              mda_data_clients_limit: int = None,
                              roles: dict = None, create_roles: list = None,
                              auth_precedence=None, auth_priority=None,
                              concurrent_onboarding: bool = None,
                              radius_override: bool = None,
                              apply: bool = False) -> dict:
    """Configure port authentication (802.1X and/or MAC-Auth) on access ports,
    with all options + user roles (idempotent). Many ports in ONE call; each
    interface is processed independently (a failure on one port does not stop
    the others — see result.summary.failed_interfaces).

    - `interfaces`: list of port names to configure. Also accepts a CSV string
      and CLI-style ranges ('1/1/1-1/1/24' or '1/1/1-24'), expanded server-side.
    - `methods`: per-method options, e.g.
        {"dot1x": {"auth_enable": true, "reauth_enable": true,
                   "reauth_period": 3600, "max_retries": 2, "eapol_timeout": 30,
                   "quiet_period": 60, "max_requests": 2},
         "mac-auth": {"auth_enable": true, "cached_reauth_enable": true,
                      "radius_server_group": "RADIUS-GRP"}}.
      Shortcuts accepted: `methods: {"dot1x": true, "mac-auth": true}` or the
      top-level `dot1x=true` / `mac_auth=true` (bool or options dict).
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
    - `auth_precedence`/`auth_priority`: ordered method list (["dot1x","mac-auth"]
      or the string "dot1x mac-auth").
    - `concurrent_onboarding` / `radius_override`: per-port behaviour.
    A malformed parameter returns `invalid_input` + `expected_schema` BEFORE any
    device is contacted. `apply`=False returns the plan only."""
    if isinstance(interfaces, str) or isinstance(interfaces, (list, tuple)):
        interfaces = _expand_interfaces(interfaces)
    if not interfaces or not isinstance(interfaces, (list, tuple)):
        return _port_auth_invalid("interfaces", "`interfaces` is required (list of ports).")
    methods, err = _norm_methods(methods, dot1x, mac_auth)
    if err:
        return err
    auth_precedence, err = _norm_method_list(auth_precedence, "auth_precedence")
    if err:
        return err
    auth_priority, err = _norm_method_list(auth_priority, "auth_priority")
    if err:
        return err
    if roles is not None and not isinstance(roles, dict):
        return _port_auth_invalid("roles", "`roles` must be a dict logical->role name.")
    if create_roles is not None and not isinstance(create_roles, (list, tuple)):
        return _port_auth_invalid("create_roles", "`create_roles` must be a list of role dicts.")
    for _i, _r in enumerate(create_roles or []):
        if not isinstance(_r, dict) or not _r.get("name"):
            return _port_auth_invalid(f"create_roles[{_i}]", "Each role needs at least a `name`.")
    if auth_mode is not None and auth_mode not in (
            "client-mode", "device-mode", "multi-domain", "proxy-mode"):
        return _port_auth_invalid("auth_mode", f"Unknown auth_mode '{auth_mode}'.")
    _checks = []
    for _i, _r in enumerate(create_roles or []):
        _vt = _r.get("vlan_tag")
        if _vt is not None:
            _checks.append((f"create_roles[{_i}].vlan_tag",
                            lambda _vt=_vt: _v_vlan(_vt, "vlan_tag")))
        for _v in (_r.get("vlan_trunks") or []):
            _checks.append((f"create_roles[{_i}].vlan_trunks",
                            lambda _v=_v: _v_vlan(_v, "vlan_trunk")))
    if clients_limit is not None:
        _checks.append(("clients_limit", lambda: _v_int_range(clients_limit, 1, 256, "clients_limit")))
    err = _precheck(_checks)
    if err:
        return err
    plan = {dev: {"interfaces": list(interfaces), "methods": methods or {},
                  "auth_mode": auth_mode, "clients_limit": clients_limit,
                  "roles": roles or {}, "create_roles": create_roles or [],
                  "auth_precedence": auth_precedence, "auth_priority": auth_priority,
                  "radius_override": radius_override}
            for dev in (_safe_targets(device, site))}

    async def _exec(dev, client):
        return await _apply_port_auth(
            client, interfaces, methods=methods, auth_mode=auth_mode,
            clients_limit=clients_limit, mda_data_clients_limit=mda_data_clients_limit,
            concurrent_onboarding=concurrent_onboarding, radius_override=radius_override,
            auth_precedence=auth_precedence, auth_priority=auth_priority, roles=roles,
            create_roles=create_roles)

    return await _domain_write("configure_port_auth", device, site, plan, _exec, apply)


async def _apply_port_auth(client, interfaces, *, methods=None, auth_mode=None,
                           clients_limit=None, mda_data_clients_limit=None,
                           concurrent_onboarding=None, radius_override=None,
                           auth_precedence=None, auth_priority=None, roles=None,
                           create_roles=None) -> dict:
    """Shared executor: create roles, then per-interface auth methods + port
    settings, tolerant per interface (summary.failed_interfaces)."""
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
    failed: list = []
    for intf in interfaces:
        intf_res = {"interface": intf, "ok": True, "methods": []}
        try:
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
        except ArubaAPIError as exc:
            intf_res["ok"] = False
            intf_res["status"] = "failed"
            intf_res["error"] = exc.args[0] if exc.args else str(exc)
            failed.append(intf)
        out["interfaces"].append(intf_res)
    out["summary"] = {"ok": len(interfaces) - len(failed), "failed": len(failed),
                      "failed_interfaces": failed}
    return out


async def _clear_port_auth(client, interfaces) -> dict:
    """Inverse of _apply_port_auth: delete per-method auth configs and reset the
    interface-level port-access bindings, tolerant per interface."""
    out = {"interfaces": []}
    failed: list = []
    for intf in interfaces:
        res = {"interface": intf, "ok": True, "methods": []}
        try:
            for m in _PORT_AUTH_METHODS:
                res["methods"].append(await client.delete_port_access_auth_method(intf, m))
            res["interface_cfg"] = await client.clear_interface_port_access(intf)
        except ArubaAPIError as exc:
            res.update(ok=False, status="failed", error=exc.args[0] if exc.args else str(exc))
            failed.append(intf)
        out["interfaces"].append(res)
    out["summary"] = {"ok": len(interfaces) - len(failed), "failed": len(failed),
                      "failed_interfaces": failed}
    return out


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
# TOOLS — Atomic L2 primitives (decoupled from configure_service/vlan-service)
# ══════════════════════════════════════════════════════════════════════

@mcp.tool()
async def configure_vlan(vlan_id: int = None, device: str = None, site: str = None,
                         name: str = None, description: str = None,
                         vlans: list = None, cascade: bool = False,
                         delete: bool = False, apply: bool = False) -> dict:
    """Create/delete bare VLAN definitions (no VNI/SVI/RT). ONE VLAN via
    `vlan_id` (+ `name`/`description`) or a BATCH via `vlans=[{vlan_id, name,
    description}, ...]` (also accepts a list of ints); combined with several
    `device`s this is a device x vlan matrix applied in ONE call, with one
    status per cell (created / already_exists / failed) — a failing VLAN does
    not stop the others (see result.summary). `delete=true, cascade=true`
    first removes what hangs off each VLAN — SVI (with its active-gateway),
    EVPN RD/RT, L2VNI — then the VLAN (decommissioning a core turned spine).
    For the full orchestrated fabric
    VLAN service (VLAN + L2VNI + EVPN RT + optional SVI), use
    configure_service(scope='vlan') / create_vlan_service instead.
    `apply`=False = plan only."""
    items: list[dict] = []
    if vlans:
        if not isinstance(vlans, (list, tuple)):
            return {"status": "invalid_input", "field": "vlans",
                    "error": "`vlans` must be a list: [{vlan_id, name, description}, ...] or [10, 20].",
                    "action_required": "Fix the parameter shape and re-run; nothing was written."}
        for i, v in enumerate(vlans):
            if isinstance(v, dict):
                if v.get("vlan_id") is None and v.get("id") is None:
                    return {"status": "invalid_input", "field": f"vlans[{i}]",
                            "error": "Each entry needs a `vlan_id`.",
                            "action_required": "Fix the parameter shape and re-run; nothing was written."}
                items.append({"vlan_id": v.get("vlan_id", v.get("id")),
                              "name": v.get("name"), "description": v.get("description")})
            else:
                items.append({"vlan_id": v, "name": None, "description": None})
    if vlan_id is not None:
        items.append({"vlan_id": vlan_id, "name": name, "description": description})
    if not items:
        return {"status": "invalid_input", "field": "vlan_id",
                "error": "Provide `vlan_id` (single VLAN) or `vlans` (batch).",
                "action_required": "Add the missing parameter and re-run; nothing was written."}
    err = _precheck([(f"vlans[{i}].vlan_id", lambda _v=it["vlan_id"]: _v_vlan(_v, "vlan_id"))
                     for i, it in enumerate(items)])
    if err:
        return err
    action = "delete_vlan" if delete else "create_vlan"
    cascade = bool(cascade and delete)
    plan = {dev: [step for it in items for step in (
                ([{"action": "delete_svi", "vlan": it["vlan_id"]},
                  {"action": "delete_evpn_vlan_rt", "vlan": it["vlan_id"]},
                  {"action": "delete_l2vni", "vlan": it["vlan_id"], "vni": "(mapped)"}]
                 if cascade else [])
                + [{"action": action, "vlan": it["vlan_id"],
                    **({} if delete else {"name": it["name"]})}])]
            for dev in (_safe_targets(device, site))}

    async def _exec(dev, client):
        cells: list = []
        failed: list = []
        for it in items:
            vid = it["vlan_id"]
            try:
                if delete:
                    extra = {}
                    if cascade:
                        extra["svi"] = (await client.delete_svi(vid))["status"]
                        extra["evpn"] = (await client.delete_evpn_vlan_rt(vid))["status"]
                        extra["l2vni"] = [await client.delete_l2vni(v)
                                          for v in await client.l2vnis_for_vlan(vid)]
                    res = {**await client.delete_vlan(vid), **extra}
                else:
                    res = await client.create_vlan(vid, name=it["name"],
                                                   description=it["description"])
                cells.append({"vlan_id": vid, "ok": True, **(res if isinstance(res, dict) else {"result": res})})
            except ArubaAPIError as exc:
                cells.append({"vlan_id": vid, "ok": False, "status": "failed",
                              "error": exc.args[0] if exc.args else str(exc)})
                failed.append(vid)
        if len(items) == 1:
            return cells[0]
        return {"vlans": cells,
                "summary": {"ok": len(items) - len(failed), "failed": len(failed),
                            "failed_vlans": failed}}

    return await _domain_write("configure_vlan", device, site, plan, _exec, apply)


_HOSTNAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9\-_.]{0,63}$")


@mcp.tool()
async def configure_hostname(hostname: str = None, device: str = None, site: str = None,
                             hostnames=None, apply: bool = False) -> dict:
    """Set device hostnames (System.hostname), idempotent. Two forms:
    - ONE device: `device` + `hostname`.
    - BATCH (50 switches in ONE call): `hostnames` = {"<device>": "<hostname>", ...}
      or [{"device": "...", "hostname": "..."}, ...]; `device`/`site` are then
      optional (they only restrict the target set). Each device gets ITS OWN name;
      one status per device. `apply`=False = plan only."""
    mapping: dict[str, str] = {}
    if hostnames:
        if isinstance(hostnames, dict):
            pairs = list(hostnames.items())
        elif isinstance(hostnames, (list, tuple)):
            pairs = []
            for i, it in enumerate(hostnames):
                if not isinstance(it, dict) or not it.get("device") or not it.get("hostname"):
                    return {"status": "invalid_input", "field": f"hostnames[{i}]",
                            "error": "Each entry needs `device` and `hostname`.",
                            "action_required": "Fix the parameter shape and re-run; nothing was written."}
                pairs.append((it["device"], it["hostname"]))
        else:
            return {"status": "invalid_input", "field": "hostnames",
                    "error": "`hostnames` must be {device: hostname} or [{device, hostname}].",
                    "action_required": "Fix the parameter shape and re-run; nothing was written."}
        for dev, hn in pairs:
            try:
                canon = _resolve_devices(device=dev)[0]
            except ValueError as exc:
                return {"status": "error", "error": str(exc)}
            mapping[canon] = str(hn).strip()
        targets = _safe_targets(device, site) if (device or site) else list(mapping)
        mapping = {d: h for d, h in mapping.items() if d in targets}
        if not mapping:
            return {"status": "error",
                    "error": "No device of `hostnames` matches the `device`/`site` target set."}
    else:
        hostname = (hostname or "").strip()
        if not hostname:
            return {"status": "invalid_input", "field": "hostname",
                    "error": "Provide `hostname` (single device) or `hostnames` (batch).",
                    "action_required": "Add the missing parameter and re-run; nothing was written."}
        targets = _safe_targets(device, site)
        if len(targets) > 1:
            return {"status": "error",
                    "error": f"One `hostname` for {len(targets)} devices is almost never "
                             "intended — use `hostnames={device: hostname, ...}` for a batch."}
        mapping = {d: hostname for d in targets}
    for dev, hn in mapping.items():
        if not _HOSTNAME_RE.match(hn):
            return {"status": "invalid_input", "field": f"hostnames[{dev}]",
                    "error": f"'{hn}' is not a valid hostname: 1-64 chars (letters, digits, "
                             "'-', '_', '.'), must start with a letter or digit.",
                    "action_required": "Ask the user for a valid hostname."}
    plan = {dev: {"hostname": hn} for dev, hn in mapping.items()}

    async def _exec(dev, client):
        return await client.set_hostname(mapping[dev])

    return await _domain_write("configure_hostname", list(mapping) or device, site if not mapping else None,
                               plan, _exec, apply)


@mcp.tool()
async def configure_svi(vlan_id: int = None, device: str = None, site: str = None,
                        vrf: str = "default", ip_cidr: str = None,
                        active_gateway_ip: str = None,
                        active_gateway_mac: str = None,
                        vlans: list = None,
                        delete: bool = False, apply: bool = False) -> dict:
    """Create/update (or delete) an SVI (routed VLAN interface `interface
    vlan<id>`), decoupled from the VLAN-service orchestrator. `vrf` (default
    VRF if omitted), `ip_cidr` (CIDR form), optional anycast active-gateway
    (`active_gateway_ip`/`active_gateway_mac`, identical across VTEPs).
    `delete=True` removes the SVI (and its active-gateway with it); with
    `vlans=[10, 20, ...]` several SVIs are deleted in ONE call (absent ones
    are reported 'absent'). `apply`=False = plan only."""
    if delete:
        ids = [v for v in (vlans or [])] + ([vlan_id] if vlan_id is not None else [])
        if not ids:
            return {"status": "invalid_input", "field": "vlan_id",
                    "error": "Provide `vlan_id` or `vlans`.",
                    "action_required": "Add the missing parameter; nothing was written."}
        err = _precheck([(f"vlans[{i}]", lambda _v=v: _v_vlan(_v, "vlan"))
                         for i, v in enumerate(ids)])
        if err:
            return err
        plan = {dev: [{"action": "delete_svi", "vlan": v} for v in ids]
                for dev in (_safe_targets(device, site))}

        async def _exec_del(dev, client):
            if len(ids) == 1:
                return await client.delete_svi(ids[0])
            return await _batch(ids, client.delete_svi, "vlan")

        return await _domain_write("configure_svi", device, site, plan, _exec_del,
                                   apply)
    if vlans:
        return {"status": "invalid_input", "field": "vlans",
                "error": "`vlans` (batch) is only supported with delete=true.",
                "action_required": "Use one call per SVI to create them."}
    if vlan_id is None:
        return {"status": "invalid_input", "field": "vlan_id",
                "error": "`vlan_id` is required.",
                "action_required": "Add the missing parameter; nothing was written."}

    err = _precheck([
        ("ip_cidr", lambda: _v_ipv4_cidr(ip_cidr, "ip_cidr") if ip_cidr else None),
        ("active_gateway_ip",
         lambda: _v_ip_host(str(active_gateway_ip).split("/")[0], "active_gateway_ip")
         if active_gateway_ip else None),
        ("active_gateway_mac",
         lambda: _v_mac(active_gateway_mac, "active_gateway_mac")
         if active_gateway_mac else None),
    ])
    if err:
        return err
    vrf = vrf or "default"
    plan = {dev: [{"action": "create_svi", "vlan": vlan_id, "vrf": vrf,
                   "ip4_address": ip_cidr}]
            for dev in (_safe_targets(device, site))}

    async def _exec(dev, client):
        return await client.create_svi(vlan_id, vrf, ip_cidr=ip_cidr,
                                       active_gateway_ip=active_gateway_ip,
                                       active_gateway_mac=active_gateway_mac)

    return await _domain_write("configure_svi", device, site, plan, _exec, apply)


@mcp.tool()
async def configure_trunk(interface: str, device: str = None, site: str = None,
                          add_vlans: list = None, remove_vlans: list = None,
                          apply: bool = False) -> dict:
    """Add/remove tagged VLANs on a trunk interface (idempotent), decoupled
    from the VLAN-service orchestrator. `add_vlans`/`remove_vlans`: lists of
    VLAN IDs. `apply`=False = plan only."""
    _checks = []
    for _i, _v in enumerate(add_vlans or []):
        _checks.append((f"add_vlans[{_i}]", lambda _v=_v: _v_vlan(_v, "vlan")))
    for _i, _v in enumerate(remove_vlans or []):
        _checks.append((f"remove_vlans[{_i}]", lambda _v=_v: _v_vlan(_v, "vlan")))
    err = _precheck(_checks)
    if err:
        return err
    plan = {dev: ([{"action": "add_vlan_to_trunk", "interface": interface, "vlan": v}
                   for v in (add_vlans or [])]
                  + [{"action": "remove_vlan_from_trunk", "interface": interface,
                      "vlan": v} for v in (remove_vlans or [])])
            for dev in (_safe_targets(device, site))}

    async def _exec(dev, client):
        results = {"added": [], "removed": []}
        for v in (add_vlans or []):
            results["added"].append(await client.add_vlan_to_trunk(interface, v))
        for v in (remove_vlans or []):
            results["removed"].append(await client.remove_vlan_from_trunk(interface, v))
        return results

    return await _domain_write("configure_trunk", device, site, plan, _exec, apply)


@mcp.tool()
async def configure_interface_admin(interface: str, device: str = None,
                                    site: str = None, enable: bool = True,
                                    apply: bool = False) -> dict:
    """Admin up/down a plain L2 interface (not a LAG member or routed port —
    use configure_lag's/configure_routed_port's own `enable` for those).
    `apply`=False = plan only."""
    plan = {dev: [{"action": "set_interface_admin", "interface": interface,
                   "admin": "up" if enable else "down"}]
            for dev in (_safe_targets(device, site))}

    async def _exec(dev, client):
        res = await client.set_interface_admin(interface, enable=enable)
        if res.get("status") == "partial":
            res["summary"] = {"ok": 0, "failed": 1}
        return res

    return await _domain_write("configure_interface_admin", device, site, plan,
                               _exec, apply)


# ══════════════════════════════════════════════════════════════════════
# TOOLS — Static routing / redistribution
# ══════════════════════════════════════════════════════════════════════

@mcp.tool()
async def configure_static_route(prefix: str = None, device: str = None, site: str = None,
                                 vrf: str = "default", nexthops: list = None,
                                 name: str = None, prefixes: list = None,
                                 delete: bool = False,
                                 apply: bool = False) -> dict:
    """Create/update (or delete) a static route (idempotent). `prefix` in CIDR
    form e.g. '192.168.0.0/16'. `nexthops`: list of {ip_address, port,
    type ('forward'|'nullroute'|'reject', default 'forward'), distance, tag,
    bfd_enable, use_forwarding_address} — the FULL desired set (existing
    nexthops not listed here are removed). `delete=True` removes the whole
    route; with `prefixes=[...]` several routes of `vrf` are deleted in ONE
    call. `apply`=False = plan only."""
    vrf = vrf or "default"
    if delete and prefixes:
        ids = list(prefixes) + ([prefix] if prefix else [])
        err = _precheck([(f"prefixes[{i}]", lambda _p=p: _v_ipv4_cidr(_p, "prefix"))
                         for i, p in enumerate(ids)])
        if err:
            return err
        plan = {dev: [{"action": "delete_static_route", "prefix": p, "vrf": vrf} for p in ids]
                for dev in (_safe_targets(device, site))}

        async def _exec_bdel(dev, client):
            return await _batch(ids, lambda p: client.delete_static_route(p, vrf=vrf), "prefix")

        return await _domain_write("configure_static_route", device, site, plan,
                                   _exec_bdel, apply)
    if not prefix:
        return {"status": "invalid_input", "field": "prefix",
                "error": "`prefix` is required (or `prefixes` with delete=true).",
                "action_required": "Add the missing parameter; nothing was written."}
    _checks = [("prefix", lambda: _v_ipv4_cidr(prefix, "prefix"))]
    for _i, _nh in enumerate(nexthops or []):
        if _nh.get("ip_address") is not None:
            _checks.append((f"nexthops[{_i}].ip_address",
                            lambda _nh=_nh: _v_ip_host(_nh["ip_address"], "ip_address")))
    err = _precheck(_checks)
    if err:
        return err
    vrf = vrf or "default"
    if delete:
        plan = {dev: [{"action": "delete_static_route", "prefix": prefix, "vrf": vrf}]
                for dev in (_safe_targets(device, site))}

        async def _exec_del(dev, client):
            return await client.delete_static_route(prefix, vrf=vrf)

        return await _domain_write("configure_static_route", device, site, plan,
                                   _exec_del, apply)

    plan = {dev: [{"action": "configure_static_route", "prefix": prefix, "vrf": vrf,
                   "nexthops": nexthops or []}]
            for dev in (_safe_targets(device, site))}

    async def _exec(dev, client):
        return await client.configure_static_route(prefix, vrf=vrf,
                                                    nexthops=nexthops, name=name)

    return await _domain_write("configure_static_route", device, site, plan, _exec,
                               apply)


@mcp.tool()
async def configure_redistribute(protocol: str, device: str = None, site: str = None,
                                 vrf: str = "default", asn: int = None,
                                 instance_tag: int = 1,
                                 address_family: str = "ipv4-unicast",
                                 sources: list = None, apply: bool = False) -> dict:
    """Configure route redistribution into BGP or OSPF (idempotent).
    `protocol`: 'bgp' (needs `asn`; `sources` subset of connected|
    local-loopback|static|ospf, applied to `address_family`) or 'ospf'
    (`sources` subset of connected|local_loopback|static|bgp|rip).
    `apply`=False = plan only."""
    if protocol not in ("bgp", "ospf"):
        return {"status": "invalid_input", "field": "protocol",
                "error": f"protocol must be 'bgp' or 'ospf', got '{protocol}'.",
                "action_required": "Ask the user to confirm 'bgp' or 'ospf'."}
    if protocol == "bgp" and asn is None:
        return {"status": "invalid_input", "field": "asn",
                "error": "asn is required when protocol='bgp'.",
                "action_required": "Ask the user for the BGP ASN."}
    if asn is not None:
        err = _precheck([("asn", lambda: _v_asn(asn, "asn"))])
        if err:
            return err
    vrf = vrf or "default"
    plan = {dev: [{"action": f"configure_{protocol}_redistribute", "vrf": vrf,
                   "asn": asn, "instance_tag": instance_tag,
                   "address_family": address_family, "sources": sources or []}]
            for dev in (_safe_targets(device, site))}

    async def _exec(dev, client):
        if protocol == "bgp":
            return await client.configure_bgp_redistribute(
                asn, sources or [], vrf=vrf, address_family=address_family)
        return await client.configure_ospf_redistribute(
            sources or [], vrf=vrf, instance_tag=instance_tag)

    return await _domain_write("configure_redistribute", device, site, plan, _exec,
                               apply)


# ══════════════════════════════════════════════════════════════════════
# TOOLS — VSX pairing (asymmetric: role/keepalive differ per peer)
# ══════════════════════════════════════════════════════════════════════

@mcp.tool()
async def configure_vsx(device: str, peer_device: str = None, site: str = None,
                        role: str = None, peer_role: str = None,
                        isl_interface: str = None, peer_isl_interface: str = None,
                        keepalive_interface: str = None,
                        peer_keepalive_interface: str = None,
                        keepalive_vrf: str = None, keepalive_src_ip: str = None,
                        keepalive_peer_ip: str = None, system_mac: str = None,
                        delete: bool = False, apply: bool = False) -> dict:
    """Pair (or tear down) a VSX cluster. VSX is inherently a PAIR: pass
    `peer_device` to configure BOTH members symmetrically in ONE call — `role`
    is mirrored automatically (primary<->secondary, defaulting `role` to
    'primary' when a peer is given) unless `peer_role` is provided, and
    `keepalive_src_ip`/`keepalive_peer_ip` are swapped on the peer.
    `isl_interface`/`keepalive_interface` (+ their `peer_*` counterparts, if the
    local port names differ between the two devices) are LOCAL port names.
    `system_mac` must be identical on both peers (sent unchanged to both).
    Without `peer_device`, only `device`/`site` are touched (e.g. to fix one
    member). `delete=True` removes the VSX configuration (teardown — e.g.
    converting a legacy VSX core pair to standalone Spines), applied to the
    same target set. `apply`=False = plan only."""
    if system_mac is not None:
        err = _precheck([("system_mac", lambda: _v_mac(system_mac, "system_mac"))])
        if err:
            return err
    try:
        candidates = _resolve_devices(device=device, site=site)
    except ValueError as exc:
        return {"status": "error", "error": str(exc)}
    peer_set: set = set()
    if peer_device:
        try:
            peer_candidates = _resolve_devices(device=peer_device)
        except ValueError as exc:
            return {"status": "error", "error": str(exc)}
        peer_set = set(peer_candidates)
        candidates = candidates + [d for d in peer_candidates if d not in candidates]
    if not candidates:
        return {"status": "error", "error": "No resolved target device."}

    eff_role = role or ("primary" if peer_set else None)
    inv_role = {"primary": "secondary", "secondary": "primary"}.get(eff_role)
    eff_peer_role = peer_role or inv_role

    def _cfg_for(dev: str) -> dict:
        if dev in peer_set:
            return {"role": eff_peer_role,
                    "isl_interface": peer_isl_interface or isl_interface,
                    "keepalive_interface": peer_keepalive_interface or keepalive_interface,
                    "keepalive_src_ip": keepalive_peer_ip,
                    "keepalive_peer_ip": keepalive_src_ip}
        return {"role": eff_role, "isl_interface": isl_interface,
                "keepalive_interface": keepalive_interface,
                "keepalive_src_ip": keepalive_src_ip,
                "keepalive_peer_ip": keepalive_peer_ip}

    if delete:
        plan = {dev: [{"action": "delete_vsx"}] for dev in candidates}
    else:
        plan = {dev: [{"action": "configure_vsx", **_cfg_for(dev)}] for dev in candidates}

    if not apply:
        return {"status": "planned", "operation": "configure_vsx",
                "targets": candidates, "plan": plan, "apply": False,
                "note": "Preview only. Re-run with apply=true to apply."}

    denied = _deny_read_only_many(candidates, "configure_vsx")
    if denied:
        return denied

    async def _exec(dev, client):
        if delete:
            return await client.delete_vsx()
        cfg = _cfg_for(dev)
        return await client.configure_vsx(
            role=cfg["role"], isl_interface=cfg["isl_interface"],
            keepalive_interface=cfg["keepalive_interface"], keepalive_vrf=keepalive_vrf,
            keepalive_src_ip=cfg["keepalive_src_ip"],
            keepalive_peer_ip=cfg["keepalive_peer_ip"], system_mac=system_mac)

    raw = await _exec_on_devices(candidates, _guarded_executor(_exec))
    await _close_sessions(candidates)
    results: dict = {}
    for dev, r in raw.items():
        if r["ok"]:
            wrapped = r["result"]
            results[dev] = {"ok": True, "result": wrapped["result"],
                            "checkpoint": wrapped["checkpoint"]}
        else:
            results[dev] = r
    failed = [d for d, r in results.items() if not r["ok"]]
    return {"status": "applied" if not failed else "partial",
            "operation": "configure_vsx", "targets": candidates, "plan": plan,
            "apply": True, "results": results, "reversible": {},
            "summary": {"total": len(candidates),
                       "succeeded": len(candidates) - len(failed),
                       "failed": len(failed), "failed_devices": failed}}


# ══════════════════════════════════════════════════════════════════════
# TOOLS — DHCP relay (per VRF + L3 port/SVI)
# ══════════════════════════════════════════════════════════════════════

@mcp.tool()
async def configure_dhcp_relay(interface: str, device: str = None, site: str = None,
                               vrf: str = "default", ipv4_servers: list = None,
                               ipv6_servers: list = None, bootp_gateway: str = None,
                               delete: bool = False, apply: bool = False) -> dict:
    """Create/update (or delete) the DHCP relay (helper-address) on an L3 port
    or SVI (idempotent). `vrf` is the VRF through which the DHCP server is
    reachable — this MUST match the interface's actual VRF (a relay pointing at
    the wrong VRF silently fails to reach the server). `ipv4_servers`/
    `ipv6_servers`: the FULL desired list of server IPs (replaces any existing
    list, up to 8 each). `delete=True` removes the relay config entirely.
    `apply`=False = plan only."""
    vrf = vrf or "default"
    _checks = []
    for _i, _s in enumerate(ipv4_servers or []):
        _checks.append((f"ipv4_servers[{_i}]", lambda _s=_s: _v_ip_host(_s, "ipv4_servers")))
    for _i, _s in enumerate(ipv6_servers or []):
        _checks.append((f"ipv6_servers[{_i}]", lambda _s=_s: _v_ip_host(_s, "ipv6_servers")))
    err = _precheck(_checks)
    if err:
        return err

    if delete:
        plan = {dev: [{"action": "delete_dhcp_relay", "interface": interface, "vrf": vrf}]
                for dev in (_safe_targets(device, site))}

        async def _exec_del(dev, client):
            return await client.delete_dhcp_relay(interface, vrf=vrf)

        return await _domain_write("configure_dhcp_relay", device, site, plan,
                                   _exec_del, apply)

    plan = {dev: [{"action": "configure_dhcp_relay", "interface": interface, "vrf": vrf,
                   "ipv4_servers": ipv4_servers or [], "ipv6_servers": ipv6_servers or []}]
            for dev in (_safe_targets(device, site))}

    async def _exec(dev, client):
        return await client.configure_dhcp_relay(
            interface, vrf=vrf, ipv4_servers=ipv4_servers, ipv6_servers=ipv6_servers,
            bootp_gateway=bootp_gateway)

    return await _domain_write("configure_dhcp_relay", device, site, plan, _exec, apply)


# ══════════════════════════════════════════════════════════════════════
# TOOLS — Interface groups (system interface-group speed)
# ══════════════════════════════════════════════════════════════════════

@mcp.tool()
async def configure_interface_group(group: str, speed: str = None, device: str = None,
                                    site: str = None, subsystem: str = None,
                                    delete: bool = False, apply: bool = False) -> dict:
    """Set the link speed of an interface group — the CLI `system
    interface-group <id> speed <speed>` (idempotent). Interface groups are
    blocks of ports on a subsystem that share ONE selectable speed (e.g. 10g OR
    25g, not both); `speed` is one of 5g|10g|25g|40g|50g|100g|200g (restricted
    per group to what the hardware supports). `subsystem` targets a specific
    line card / chassis ('line_card,1/1' or bare '1/1') — omit it when the
    device has a single interface-group-capable subsystem. `delete=True` resets
    the group to its default. WARNING: changing a group's speed can bounce every
    port in that block. `apply`=False = plan only."""
    if not delete:
        _speeds = ("5g", "10g", "25g", "40g", "50g", "100g", "200g")

        def _v_speed():
            if speed is None:
                raise ArubaAPIError("`speed` is required unless delete=True.", 400)
            s = str(speed).lower().strip()
            if s not in _speeds:
                raise ArubaAPIError(
                    f"Invalid speed '{speed}'. Use one of: {', '.join(_speeds)}.", 400)
            return s

        err = _precheck([("speed", _v_speed)])
        if err:
            return err

    if delete:
        plan = {dev: [{"action": "delete_interface_group", "group": group,
                       "subsystem": subsystem}]
                for dev in (_safe_targets(device, site))}

        async def _exec_del(dev, client):
            return await client.configure_interface_group(
                group, subsystem=subsystem, delete=True)

        return await _domain_write("configure_interface_group", device, site, plan,
                                   _exec_del, apply)

    plan = {dev: [{"action": "configure_interface_group", "group": group,
                   "speed": speed, "subsystem": subsystem}]
            for dev in (_safe_targets(device, site))}

    async def _exec(dev, client):
        return await client.configure_interface_group(
            group, speed, subsystem=subsystem)

    return await _domain_write("configure_interface_group", device, site, plan,
                               _exec, apply)

