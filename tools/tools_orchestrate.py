"""Orchestrators: multi-step, multi-object workflows composed from the atomic
``configure_*`` primitives (VSX pair, L3 link, access port, RADIUS/802.1X).

Every orchestrator supports create/update (idempotent re-run) AND teardown
(``delete=True``), runs through the same plan -> dry_run_token -> apply cycle
as the domain tools (``_domain_write``: read-only guard, auto-checkpoint,
compacted results) and exposes its steps in the plan so the agent can review
exactly what will be touched on each device."""

import asyncio
import ipaddress
import itertools
from urllib.parse import quote

from clients.aruba_client import (
    ArubaAPIError, _v_mac, _v_ip_host, _v_ipv4_cidr, _v_int_range, _v_vlan, _v_vni, _v_mtu,
    _v_ospf_area, _v_route_target, _v_lag_name, _v_asn, _v_ipv4_host,
    _v_vrf_rd, _v_vrf_route_target,
)
from core.server_core import mcp, _resolve_devices, _safe_targets, _precheck, _get_client
from core import server_core as _core
from tools.tools_configure import (
    _domain_write, _apply_port_auth, _clear_port_auth, _norm_methods,
    _norm_method_list, _expand_interfaces, _port_auth_invalid, _per_device_value, _af_bool_map,
    _per_device_id, _is_auto_id, _resolve_auto_id, _apply_bgp_neighbors,
)


# ══════════════════════════════════════════════════════════════════════
# Shared step runner
# ══════════════════════════════════════════════════════════════════════

def _step(action: str, run, **args) -> dict:
    """A plan step: `action` + JSON-able args + the coroutine factory `run(client)`."""
    return {"action": action, **args, "_run": run}


def _plan_view(steps: list) -> list:
    return [{k: v for k, v in s.items() if k != "_run"} for s in steps]


async def _run_steps(dev: str, client, steps: list) -> dict:
    """Run the steps in order; stop at the first failure (raising keeps the
    auto-checkpoint armed so the device reverts). Per-step results are kept."""
    done = []
    for s in steps:
        try:
            res = await s["_run"](client)
        except ArubaAPIError as exc:
            msg = exc.args[0] if exc.args else str(exc)
            raise ArubaAPIError(
                f"step '{s['action']}' failed after {len(done)} step(s): {msg}",
                exc.status_code) from exc
        done.append({"action": s["action"], "result": res})
    partial = [d for d in done if isinstance(d["result"], dict)
               and d["result"].get("status") == "partial"]
    summary = {"steps": len(done), "failed": len(partial)}
    if partial:
        summary["partial_steps"] = [d["action"] for d in partial]
        # always visible, even when `steps` gets compacted
        summary["failed_items"] = [
            {"action": d["action"],
             **{k: d["result"].get(k) for k in ("interface", "neighbor", "vrf", "warning",
                                                 "not_applied", "failed_neighbors",
                                                 "l1_state_down_reason")
                if d["result"].get(k) is not None}}
            for d in partial]
    return {"steps": done, "summary": summary}


async def _orchestrate(operation: str, steps_by_device: dict, apply: bool,
                       post=None) -> dict:
    """`_domain_write` over a per-device step list (asymmetric plans allowed).
    `post(result)` may enrich the applied result (e.g. an operational check)."""
    if not steps_by_device:
        return {"status": "error", "error": "No resolved target device."}
    plan = {dev: _plan_view(steps) for dev, steps in steps_by_device.items()}

    async def _exec(dev, client):
        return await _run_steps(dev, client, steps_by_device[dev])

    res = await _domain_write(operation, list(steps_by_device), None, plan, _exec, apply)
    if apply and post is not None and res.get("status") in ("applied", "partial"):
        try:
            await post(res)
        except Exception as exc:  # noqa: BLE001 — a check must not mask the apply
            res["post_check_error"] = str(exc)
    return res


def _invalid(field: str, msg: str) -> dict:
    return {"status": "invalid_input", "field": field, "error": msg,
            "action_required": "Fix the parameter and re-run; nothing was written."}


def _host(cidr: str) -> str:
    return str(cidr).split("/")[0]


async def _bgp_router(client, asn, vrf, router_id, options=None):
    return await client.ensure_bgp_router(
        asn, vrf=vrf, router_id=await _resolve_auto_id(client, router_id), extra=options)


async def _bgp_neighbors_step(client, asn, vrf, neighbors):
    res = await _apply_bgp_neighbors(client, asn, vrf, neighbors)
    partial = [n["neighbor"] for n in res if n.get("status") == "partial"]
    return {"neighbors": res, "status": "partial" if partial else "configured",
            **({"failed_neighbors": partial} if partial else {})}


def _flag_device(res: dict, dev: str, error: str, **extra) -> None:
    """Turn an applied device result into a failure after a post-check."""
    entry = (res.get("results") or {}).get(dev)
    if not isinstance(entry, dict):
        return
    entry["ok"] = False
    entry["error"] = f"{entry['error']}; {error}" if entry.get("error") else error
    entry.update(extra)
    res["status"] = "partial"
    summ = res.setdefault("summary", {})
    failed = [d for d, r in res["results"].items() if not r.get("ok")]
    summ.update({"failed": len(failed), "failed_devices": failed,
                 "succeeded": summ.get("total", len(res["results"])) - len(failed)})


async def _mark_vxlan_operational(res: dict, devices: list, vxlan_interface: str) -> None:
    async def _one(dev):
        async with _get_client(dev) as client:
            return dev, await client.check_vxlan_operational(vxlan_interface)
    ok_devs = [d for d in devices if ((res.get("results") or {}).get(d) or {}).get("ok")]
    checks = dict(await asyncio.gather(*[_one(d) for d in ok_devs]))
    res["vxlan_check"] = checks
    for dev, chk in checks.items():
        if not chk.get("operational"):
            _flag_device(res, dev, f"{vxlan_interface} written but NOT operational: "
                         f"{chk.get('problems')}")


# ══════════════════════════════════════════════════════════════════════
# VSX pair
# ══════════════════════════════════════════════════════════════════════

_VSX_SYNC_FEATURES = (
    "aaa", "acl-log-timer", "arp-security", "bfd-global", "bgp", "control-plane-acls",
    "copp-policy", "dhcp-relay", "dhcp-server", "dhcp-snooping", "dns", "evpn",
    "icmp-tcp", "lldp", "loop-protect-global", "mac-lockout", "mclag-interfaces",
    "mgmd-global", "neighbor", "ntp", "ospf", "qos-global", "rip", "route-map",
    "sflow-global", "snmp", "ssh", "static-routes", "stp-global", "time", "udp-forwarder",
    "vlan", "vrf", "vsx-global",
)


@mcp.tool()
async def orchestrate_vsx_pair(device: str, peer_device: str = None,
                               isl_members: list = None, peer_isl_members: list = None,
                               isl_lag_id=256, isl_mode: str = "lacp-active",
                               keepalive_interface: str = None,
                               peer_keepalive_interface: str = None,
                               keepalive_ip: str = None, peer_keepalive_ip: str = None,
                               keepalive_vrf: str = "KEEPALIVE",
                               keepalive_udp_port: int = None,
                               system_mac: str = None, role: str = "primary",
                               config_sync: bool = True, config_sync_features: list = None,
                               linkup_delay_timer: int = None,
                               split_recovery: bool = None,
                               delete: bool = False, delete_keepalive_vrf: bool = True,
                               verify: bool = True, apply: bool = False) -> dict:
    """Build (or tear down) a COMPLETE VSX pair in ONE call, on BOTH members:
    keepalive VRF -> routed keepalive port -> ISL LAG (LACP, all VLANs) ->
    /system/vsx pairing (role mirrored, keepalive IPs swapped on the peer,
    identical system_mac, vsx-sync features, linkup-delay-timer, split-recovery).

    Create/update (idempotent): `device` (primary) + `peer_device` (secondary),
    `isl_members` ['1/1/49','1/1/50'] (+ `peer_isl_members` if the peer uses
    other ports), `keepalive_interface` (+ `peer_keepalive_interface`),
    `keepalive_ip` / `peer_keepalive_ip` in CIDR (e.g. '192.168.255.1/30' and
    '.2/30'), `system_mac` (recommended, same on both), `config_sync_features`
    (e.g. ['vlan','vrf','aaa','snmp']; omit = leave as is; `config_sync=false`
    disables vsx-sync), `linkup_delay_timer` (s), `split_recovery` (bool).
    Teardown: `delete=true` removes VSX, the ISL LAG, the keepalive IP/VRF
    binding on both members (`delete_keepalive_vrf=false` keeps the VRF).
    After apply, `verify=true` reads the operational VSX state on both members
    (ISL in-sync can take up to ~1 min — re-check with get_redundancy vsx).
    `apply`=False = plan only (per-device step list)."""
    if not peer_device:
        return _invalid("peer_device", "VSX is a PAIR: `peer_device` is required.")
    try:
        primary = _resolve_devices(device=device)
        secondary = _resolve_devices(device=peer_device)
    except ValueError as exc:
        return {"status": "error", "error": str(exc)}
    if len(primary) != 1 or len(secondary) != 1 or primary[0] == secondary[0]:
        return _invalid("device", "Exactly ONE `device` and ONE distinct `peer_device`.")
    a, b = primary[0], secondary[0]
    lag_name = _v_lag_name(isl_lag_id)
    kvrf = keepalive_vrf or "default"
    peer_isl_members = peer_isl_members or isl_members
    peer_keepalive_interface = peer_keepalive_interface or keepalive_interface

    if delete:
        def _teardown(kif):
            steps = [_step("delete_vsx", lambda c: c.delete_vsx()),
                     _step("delete_interface", lambda c: c.delete_interface(lag_name),
                           interface=lag_name)]
            if kif:
                steps.append(_step("reset_routed_interface",
                                   lambda c, i=kif: c.reset_routed_interface(i), interface=kif))
            if delete_keepalive_vrf and kvrf != "default":
                steps.append(_step("delete_vrf", lambda c: c.delete_vrf(kvrf), vrf=kvrf))
            return steps
        return await _orchestrate("orchestrate_vsx_pair",
                                  {a: _teardown(keepalive_interface),
                                   b: _teardown(peer_keepalive_interface)}, apply)

    missing = [n for n, v in (("isl_members", isl_members), ("keepalive_interface", keepalive_interface),
                              ("keepalive_ip", keepalive_ip), ("peer_keepalive_ip", peer_keepalive_ip))
               if not v]
    if missing:
        return _invalid(missing[0], f"Required for a VSX pair: {missing}.")
    if role not in ("primary", "secondary"):
        return _invalid("role", "role must be 'primary' or 'secondary'.")
    if isl_mode not in ("static", "lacp-active", "lacp-passive"):
        return _invalid("isl_mode", "isl_mode must be static | lacp-active | lacp-passive.")
    bad = [f for f in (config_sync_features or []) if f not in _VSX_SYNC_FEATURES]
    if bad:
        return _invalid("config_sync_features",
                        f"Unknown vsx-sync feature(s) {bad}. Valid: {list(_VSX_SYNC_FEATURES)}")
    err = _precheck([
        ("keepalive_ip", lambda: _v_ipv4_cidr(keepalive_ip, "keepalive_ip")),
        ("peer_keepalive_ip", lambda: _v_ipv4_cidr(peer_keepalive_ip, "peer_keepalive_ip")),
        ("system_mac", lambda: _v_mac(system_mac, "system_mac") if system_mac else None),
        ("linkup_delay_timer", lambda: _v_int_range(linkup_delay_timer, 0, 600, "linkup_delay_timer")
         if linkup_delay_timer is not None else None),
        ("keepalive_udp_port", lambda: _v_int_range(keepalive_udp_port, 1024, 65535, "keepalive_udp_port")
         if keepalive_udp_port is not None else None),
    ])
    if err:
        return err
    try:
        if ipaddress.ip_interface(keepalive_ip).network != ipaddress.ip_interface(peer_keepalive_ip).network:
            return _invalid("peer_keepalive_ip",
                            "keepalive_ip and peer_keepalive_ip must be in the same subnet.")
    except ValueError:
        pass
    peer_role = "secondary" if role == "primary" else "primary"
    extra = {k: v for k, v in {
        "config_sync_features": config_sync_features,
        "split_recovery_disable": (not split_recovery) if split_recovery is not None else None,
        "keepalive_udp_port": keepalive_udp_port}.items() if v is not None}

    def _build(my_role, members, kif, my_ip, peer_ip):
        steps = []
        if kvrf != "default":
            steps.append(_step("ensure_vrf", lambda c: c.ensure_vrf(kvrf), vrf=kvrf))
        steps.append(_step("configure_routed_interface",
                           lambda c: c.configure_routed_interface(
                               kif, ip_cidr=my_ip, vrf=kvrf, description="VSX keepalive"),
                           interface=kif, ip4_address=my_ip, vrf=kvrf))
        steps.append(_step("configure_lag",
                           lambda c: c.configure_lag(
                               lag_name, members=members, mode=isl_mode,
                               vlan_mode="native-untagged", description="VSX ISL"),
                           lag=lag_name, members=members, mode=isl_mode,
                           vlan_mode="native-untagged (all VLANs allowed)"))
        steps.append(_step("configure_vsx",
                           lambda c: c.configure_vsx(
                               role=my_role, isl_interface=lag_name, keepalive_interface=kif,
                               keepalive_vrf=kvrf, keepalive_src_ip=_host(my_ip),
                               keepalive_peer_ip=_host(peer_ip), system_mac=system_mac,
                               config_sync_disable=(not config_sync) if config_sync is not None else None,
                               linkup_delay_timer=linkup_delay_timer, extra=extra or None),
                           role=my_role, isl_port=lag_name, keepalive_port=kif,
                           keepalive_vrf=kvrf, keepalive_src_ip=_host(my_ip),
                           keepalive_peer_ip=_host(peer_ip), system_mac=system_mac,
                           config_sync=config_sync, linkup_delay_timer=linkup_delay_timer, **extra))
        return steps

    steps_by_device = {
        a: _build(role, isl_members, keepalive_interface, keepalive_ip, peer_keepalive_ip),
        b: _build(peer_role, peer_isl_members, peer_keepalive_interface, peer_keepalive_ip, keepalive_ip),
    }

    async def _post(res: dict):
        if not verify:
            return
        from core.server_core import _get_client, _close_sessions
        status: dict = {}
        for _ in range(5):  # ~15 s: ISL/keepalive negotiation is not instantaneous
            await asyncio.sleep(3)
            for dev in (a, b):
                async with _get_client(dev) as client:
                    s = await client.get_vsx_status()
                status[dev] = {k: s.get(k) for k in (
                    "configured", "overall_state", "device_role", "isl_protocol_state",
                    "isl_link_state", "keepalive_state", "config_sync_state")}
            # Live 6405 pair reports islp_device_state='peer_established' when healthy.
            if all(str(v.get("isl_protocol_state", "")).lower() in
                   ("in_sync", "in-sync", "peer_established") for v in status.values()):
                break
        await _close_sessions([a, b])
        res["vsx_status"] = status
        res["note"] = ("ISL In-Sync may take up to ~1 min after apply; if not yet in_sync "
                       "re-check with get_redundancy(scope='vsx').")

    return await _orchestrate("orchestrate_vsx_pair", steps_by_device, apply, post=_post)


# ══════════════════════════════════════════════════════════════════════
# L3 point-to-point link (routed port + optional VRF/RD/RT + OSPF)
# ══════════════════════════════════════════════════════════════════════

@mcp.tool()
async def orchestrate_l3_link(interface: str = None, device: str = None, site: str = None,
                              ip_address: str = None, vrf: str = "default",
                              create_vrf: bool = True, vrf_rd: str = None,
                              vrf_import_rts: list = None, vrf_export_rts: list = None,
                              mtu: int = None, description: str = None,
                              enable: bool = True, ospf_area: str = None,
                              ospf_instance_tag: int = 1,
                              ospf_network_type: str = "point_to_point",
                              remove_from_lag: bool = False,
                              delete_empty_lags: bool = False,
                              ensure_internal_vlan_range: bool = False,
                              internal_vlan_range_size: int = 128,
                              verify_connected_route: bool = True,
                              links: list = None,
                              delete: bool = False, delete_vrf: bool = False,
                              apply: bool = False) -> dict:
    """Bring up a routed point-to-point link (or SEVERAL, on the same device
    set) in ONE call: (optional) VRF with RD + EVPN route-targets -> routed
    port(s) with IP/MTU/description -> (optional) OSPF area attachment per
    port. `ip_address` (CIDR) is PER DEVICE: for several devices pass
    {"<device>": "<cidr>", ...} (a /31 differs on each end; the same address
    is only accepted on the 2 members of a VSX pair).
    `vrf_rd`/`vrf_import_rts`/`vrf_export_rts` are OPTIONAL
    (Symmetric IRB / EVPN L3VNI VRFs); a plain VRF is created without them —
    ONE VRF context is shared across every link in this call.
    `remove_from_lag=True`: if `interface` is currently a LAG member, pull it
    out of that LAG FIRST in this same call instead of requiring a separate
    manual step (bounces the remaining bundle — see configure_routed_port).
    `ensure_internal_vlan_range=True` (+ `internal_vlan_range_size`, default
    128) configures the 'system internal-vlan-range' pool when it is empty
    instead of failing; `verify_connected_route` (default True) marks the
    result partial when the connected route does not install.
    `ospf_network_type` (default 'point_to_point', per link overridable;
    None = leave Broadcast) is set on every port attached to `ospf_area`.

    `links`: for MULTIPLE point-to-point ports on the SAME device set in ONE
    call, pass a list instead of `interface`/`ip_address`/etc: [{"interface":
    "1/1/1", "ip_address": "10.1.1.0/31" | {device: cidr}, "mtu", "description",
    "enable", "ospf_area", "ospf_instance_tag", "remove_from_lag"}, ...] — any
    field omitted on an entry falls back to the matching top-level param.

    Teardown: `delete=true` detaches OSPF, clears IP + VRF binding (port shut)
    on every link (`interface` or `links`); `delete_vrf=true` also removes the
    (non-default) VRF. `apply`=False = plan only."""
    vrf = vrf or "default"
    targets = _safe_targets(device, site)
    if not targets:
        return {"status": "error", "error": "No resolved target device — provide `device` or `site`."}

    if links:
        if interface is not None:
            return _invalid("interface", "pass EITHER `interface` OR `links`, not both.")
        raw_links = links
    else:
        if not interface:
            return _invalid("interface", "`interface` (or `links`) is required.")
        raw_links = [{"interface": interface, "ip_address": ip_address, "mtu": mtu,
                    "description": description, "enable": enable, "ospf_area": ospf_area,
                    "ospf_instance_tag": ospf_instance_tag,
                    "ospf_network_type": ospf_network_type,
                    "remove_from_lag": remove_from_lag}]

    link_specs = []
    for i, item in enumerate(raw_links):
        if not isinstance(item, dict) or not item.get("interface"):
            return _invalid(f"links[{i}]", "each entry needs an 'interface' name.")
        link_specs.append({
            "interface": item["interface"],
            "ip_address": item.get("ip_address", ip_address),
            "mtu": item.get("mtu", mtu),
            "description": item.get("description", description),
            "enable": item.get("enable", enable),
            "ospf_area": item.get("ospf_area", ospf_area),
            "ospf_instance_tag": item.get("ospf_instance_tag", ospf_instance_tag),
            "ospf_network_type": item.get("ospf_network_type", ospf_network_type),
            "remove_from_lag": item.get("remove_from_lag", remove_from_lag),
        })

    if delete:
        def _teardown():
            steps = []
            for spec in link_specs:
                intf = spec["interface"]
                if spec["ospf_area"] is not None:
                    steps.append(_step(
                        "remove_ospf_interface",
                        lambda c, _i=intf, _a=spec["ospf_area"], _t=spec["ospf_instance_tag"]:
                            c.remove_ospf_interface(_i, _a, vrf=vrf, instance_tag=_t),
                        interface=intf, area_id=spec["ospf_area"], vrf=vrf))
                steps.append(_step(
                    "reset_routed_interface",
                    lambda c, _i=intf: c.reset_routed_interface(_i), interface=intf))
            if delete_vrf and vrf != "default":
                steps.append(_step("delete_vrf", lambda c: c.delete_vrf(vrf), vrf=vrf))
            return steps
        return await _orchestrate("orchestrate_l3_link", {d: _teardown() for d in targets}, apply)

    resolved = []  # (spec, {dev: ip})
    for spec in link_specs:
        if not spec["ip_address"]:
            return _invalid(f"links[{spec['interface']}].ip_address" if links else "ip_address",
                            "`ip_address` (CIDR, e.g. '10.1.1.0/31') is required.")
        ips, err = await _per_device_value(
            spec["ip_address"], targets,
            f"links[{spec['interface']}].ip_address" if links else "ip_address", required=True)
        if err:
            return err
        resolved.append((spec, ips))

    err = _precheck([
        *[(f"{spec['interface']}.ip_address[{d}]", lambda _v=v: _v_ipv4_cidr(_v, "ip_address"))
          for spec, ips in resolved for d, v in ips.items()],
        *[(f"{spec['interface']}.mtu", lambda _m=spec["mtu"]: _v_mtu(_m, "mtu"))
          for spec in link_specs if spec["mtu"] is not None],
        *[(f"{spec['interface']}.ospf_area", lambda _a=spec["ospf_area"]: _v_ospf_area(_a, "ospf_area"))
          for spec in link_specs if spec["ospf_area"] is not None],
        ("vrf_rd", lambda: _v_vrf_rd(vrf_rd, "vrf_rd") if vrf_rd else None),
        *[(f"vrf_import_rts[{i}]", lambda _r=r: _v_vrf_route_target(_r, "import_rt"))
          for i, r in enumerate(vrf_import_rts or [])],
        *[(f"vrf_export_rts[{i}]", lambda _r=r: _v_vrf_route_target(_r, "export_rt"))
          for i, r in enumerate(vrf_export_rts or [])],
    ])
    if err:
        return err

    def _build(dev):
        steps = []
        ospf_ready = set()
        released: dict = {}
        lag_ports = [spec["interface"] for spec, _ in resolved if spec["remove_from_lag"]]
        batch_release = len(resolved) > 1 and bool(lag_ports)
        if vrf != "default" and create_vrf:
            steps.append(_step("ensure_vrf",
                               lambda c: c.ensure_vrf(vrf, rd=vrf_rd, evpn_import_rts=vrf_import_rts,
                                                      evpn_export_rts=vrf_export_rts),
                               vrf=vrf, rd=vrf_rd, evpn_import_rts=vrf_import_rts,
                               evpn_export_rts=vrf_export_rts))
        if batch_release:
            # several ports of one LAG: release them all before routing any,
            # so the last-member LAG deletion precedes every port flap
            async def _release(c, _ports=tuple(lag_ports)):
                res = await c.release_lag_members(list(_ports), delete_empty=delete_empty_lags)
                released.update(res.get("released") or {})
                return res
            steps.append(_step("release_lag_members", _release, interfaces=lag_ports,
                               delete_empty_lags=delete_empty_lags))
        for spec, ips in resolved:
            intf, my_ip = spec["interface"], ips[dev]
            steps.append(_step(
                "configure_routed_interface",
                lambda c, _i=intf, _ip=my_ip, _m=spec["mtu"], _d=spec["description"],
                _e=spec["enable"], _r=spec["remove_from_lag"] and not batch_release:
                c.configure_routed_interface(
                    _i, ip_cidr=_ip, description=_d, mtu=_m, vrf=vrf, enable=_e,
                    remove_from_lag=_r, delete_empty_lag=delete_empty_lags,
                    force_admin_flap=_i in released,
                    ensure_internal_vlan_range=ensure_internal_vlan_range,
                    internal_vlan_range_size=internal_vlan_range_size,
                    verify_connected_route=verify_connected_route),
                interface=intf, ip4_address=my_ip, vrf=vrf, mtu=spec["mtu"],
                admin="up" if spec["enable"] else "down"))
            if spec["ospf_area"] is not None:
                key = (spec["ospf_instance_tag"], spec["ospf_area"])
                if key not in ospf_ready:
                    ospf_ready.add(key)
                    steps.append(_step(
                        "ensure_ospf_router",
                        lambda c, _t=key[0]: c.ensure_ospf_router(vrf=vrf, instance_tag=_t),
                        vrf=vrf, instance_tag=key[0]))
                    steps.append(_step(
                        "ensure_ospf_area",
                        lambda c, _t=key[0], _a=key[1]: c.ensure_ospf_area(
                            _a, vrf=vrf, instance_tag=_t),
                        area_id=key[1], vrf=vrf))
                steps.append(_step(
                    "add_ospf_interface",
                    lambda c, _i=intf, _a=spec["ospf_area"], _t=spec["ospf_instance_tag"]:
                        c.add_ospf_interface(_i, _a, vrf=vrf, instance_tag=_t),
                    interface=intf, area_id=spec["ospf_area"], vrf=vrf,
                    instance_tag=spec["ospf_instance_tag"]))
            if spec["ospf_area"] is not None and spec["ospf_network_type"]:
                steps.append(_step(
                    "configure_ospf_interface_options",
                    lambda c, _i=intf, _n=spec["ospf_network_type"]:
                        c.configure_ospf_interface_options(_i, network_type=_n),
                    interface=intf, network_type=spec["ospf_network_type"]))
        return steps

    async def _post(res):
        pairs = await _lldp_peer_pairs(
            {d: [spec["interface"] for spec, _ in resolved] for d in targets})
        mismatches = await _link_mtu_check(pairs)
        if mismatches:
            res["mtu_mismatches"] = mismatches
            res.setdefault("warnings", []).append(
                "MTU differs from the far end on "
                f"{[(m['a_device'], m['a_interface']) for m in mismatches]} — set the "
                "same mtu on the peer (OSPF can stick in ExStart).")

    return await _orchestrate("orchestrate_l3_link", {d: _build(d) for d in targets}, apply,
                              post=_post)


async def _lldp_peer_pairs(ports_by_device: dict) -> list:
    """(dev, if, peer_dev, peer_if) for each port whose LLDP neighbour is an
    inventory device (best-effort; unknown neighbours are skipped)."""
    async def _one(dev, ports):
        out = []
        try:
            async with _get_client(dev) as client:
                data = await client.get_lldp_neighbors()
        except Exception:  # noqa: BLE001
            return out
        for nbr in data.get("lldp_neighbors") or []:
            if nbr.get("local_interface") not in ports:
                continue
            peer, peer_if = nbr.get("neighbor_system_name"), nbr.get("neighbor_port_id")
            if not peer or peer == "N/A" or not peer_if or peer_if == "N/A":
                continue
            try:
                peer_dev = _resolve_devices(device=peer)[0]
            except (ValueError, IndexError):
                continue
            out.append((dev, nbr["local_interface"], peer_dev, peer_if))
        return out
    found = await asyncio.gather(*[_one(d, p) for d, p in ports_by_device.items()])
    return [p for lst in found for p in lst]


# ══════════════════════════════════════════════════════════════════════
# Fabric underlay (loopbacks + P2P routed links + OSPF, ONE call)
# ══════════════════════════════════════════════════════════════════════

async def _discover_fabric_cabling(spines: list[str], leafs: list[str]) -> list[dict]:
    """Auto-discover spine<->leaf P2P adjacencies via LLDP, read from every
    spine only (a physical link always has a spine endpoint in a fabric, so
    one-sided discovery is enough — no dedup needed). Leaf<->leaf or
    spine<->spine links (if any) are ignored."""
    leaf_set = set(leafs)

    async def _one(dev):
        async with _get_client(dev) as client:
            return dev, await client.get_lldp_neighbors()

    results = dict(await asyncio.gather(*[_one(d) for d in spines]))
    links = []
    for spine, data in results.items():
        for nbr in (data.get("lldp_neighbors") or []):
            peer = nbr.get("neighbor_system_name")
            peer_port = nbr.get("neighbor_port_id")
            if not peer or peer == "N/A" or peer not in leaf_set:
                continue
            if not peer_port or peer_port == "N/A":
                continue
            links.append({"a_device": spine, "a_interface": nbr["local_interface"],
                         "b_device": peer, "b_interface": peer_port})
    return links


@mcp.tool()
async def orchestrate_fabric_underlay(spines: list, leafs: list,
                                      underlay_subnet: str,
                                      loopback0_subnet: str,
                                      loopback1_subnet: str = None,
                                      cabling: list = None,
                                      vsx_pairs: list = None,
                                      ospf_area: str = "0.0.0.0",
                                      ospf_instance_tag: int = 1,
                                      vrf: str = "default",
                                      mtu: int = None,
                                      remove_from_lag: bool = False,
                                      delete_empty_lags: bool = False,
                                      extended_edges: list = None,
                                      ensure_internal_vlan_range: bool = False,
                                      internal_vlan_range_size: int = 128,
                                      auto_checkpoint: bool = None,
                                      apply: bool = False) -> dict:
    """Bring up an ENTIRE fabric underlay in ONE call: unique loopback0 (OSPF
    router-id) per device, loopback1 (VTEP source) per leaf — shared by a
    VSX pair, auto-numbered /31 P2P routed links on every spine<->leaf
    adjacency, and OSPF (area + point-to-point network-type + passive
    loopbacks) on every device — replacing what would otherwise be N
    routed-port + N OSPF calls with ONE plan->apply, then verifies every
    resulting OSPF adjacency is Full.

    - `spines`/`leafs`: device name lists (Border/Access-VTEP/Stub-VTEP all
      count as 'leafs' here — anything OSPF-adjacent to the spines).
    - `extended_edges`: [{"edge": <device>, "stub": <leaf>, "links":
      [{"stub_interface": "1/1/10", "edge_interface": "1/1/49"}, ...]}] —
      each Extended Edge gets a loopback0 from `loopback0_subnet`, a /31
      routed link per entry (from `underlay_subnet`) towards its Stub VTEP
      (which must be in `leafs`) and OSPF on both ends. No loopback1/EVPN.
    - `underlay_subnet`: CIDR pool (e.g. '10.140.253.0/24'); one /31 is
      carved per spine<->leaf adjacency (RFC 3021, both addresses usable).
    - `loopback0_subnet`: CIDR pool (e.g. '10.140.254.0/24'), ONE /32 per
      device (spines included — every fabric device needs an OSPF router-id).
    - `loopback1_subnet`: CIDR pool (e.g. '10.140.255.0/24'), ONE /32 per
      leaf (VTEP source) — spines are excluded (not VTEPs). Omit entirely to
      skip loopback1 (e.g. a Spine-only underlay dry run). `vsx_pairs`
      ([[devA, devB], ...]) makes the two peers SHARE one /32 (anycast VTEP
      source) instead of getting one each — both must be in `leafs`.
    - `cabling`: explicit adjacency list [{"a_device", "a_interface",
      "b_device", "b_interface"}, ...] (`a_device` must be a spine,
      `b_device` a leaf). When omitted, adjacencies are AUTO-DISCOVERED via
      LLDP from every spine.
    - `remove_from_lag`: pull each underlay port out of the LAG it currently
      belongs to (legacy uplinks) before routing it — done as ONE first step
      per device, followed by a shutdown/no shutdown of every released port.
      `delete_empty_lags=true` also deletes the LAGs left without members
      (MC-LAG: on each VSX peer); otherwise they are reported in a warning.
    - `ensure_internal_vlan_range` / `internal_vlan_range_size`: configure the
      'system internal-vlan-range' pool when it is empty instead of failing.
    - `auto_checkpoint`: False = no firmware auto-checkpoint for this apply
      (default: CX_AUTO_CHECKPOINT).
    The result is `partial` (with a `warning`) when OSPF does not reach as
    many Full adjacencies as there are underlay links.
    `apply`=False returns the full plan (allocated IPs + cabling used) with
    NO device configuration written; the LLDP discovery read itself always
    runs when `cabling` is omitted (needed to build the plan)."""
    spines = list(dict.fromkeys(spines or []))
    leafs = list(dict.fromkeys(leafs or []))
    if not spines or not leafs:
        return _invalid("spines/leafs", "Both `spines` and `leafs` must be non-empty lists.")
    overlap = set(spines) & set(leafs)
    if overlap:
        return _invalid("spines/leafs",
                        f"Device(s) {sorted(overlap)} listed as both spine and leaf.")
    err = _precheck([
        ("ospf_area", lambda: _v_ospf_area(ospf_area, "ospf_area")),
        ("mtu", lambda: _v_mtu(mtu, "mtu") if mtu is not None else None),
    ])
    if err:
        return err
    try:
        underlay_net = ipaddress.IPv4Network(underlay_subnet, strict=False)
        lo0_net = ipaddress.IPv4Network(loopback0_subnet, strict=False)
        lo1_net = (ipaddress.IPv4Network(loopback1_subnet, strict=False)
                  if loopback1_subnet else None)
    except ValueError as exc:
        return _invalid("underlay_subnet/loopback0_subnet/loopback1_subnet", str(exc))

    if cabling:
        links = [dict(link) for link in cabling]
        for i, link in enumerate(links):
            missing = {"a_device", "a_interface", "b_device", "b_interface"} - set(link)
            if missing:
                return _invalid("cabling", f"cabling[{i}] missing {sorted(missing)}.")
    else:
        links = await _discover_fabric_cabling(spines, leafs)
        if not links:
            return {"status": "error", "error":
                    "No spine<->leaf adjacency discovered via LLDP — pass `cabling` explicitly."}
    for i, link in enumerate(links):
        if link["a_device"] not in spines or link["b_device"] not in leafs:
            return _invalid("cabling", f"cabling[{i}] must go from a spine to a leaf "
                            f"(got {link['a_device']} -> {link['b_device']}).")

    edges: list[str] = []
    for i, ee in enumerate(extended_edges or []):
        if not isinstance(ee, dict) or not ee.get("edge") or not ee.get("stub"):
            return _invalid("extended_edges", f"extended_edges[{i}] needs 'edge' and 'stub'.")
        edge, stub = ee["edge"], ee["stub"]
        if stub not in leafs:
            return _invalid("extended_edges", f"stub '{stub}' must be listed in `leafs`.")
        if edge in spines or edge in leafs:
            return _invalid("extended_edges", f"edge '{edge}' must not be a spine or a leaf.")
        if not ee.get("links"):
            return _invalid("extended_edges", f"extended_edges[{i}].links is empty.")
        for j, lk in enumerate(ee["links"]):
            if not isinstance(lk, dict) or not lk.get("stub_interface") \
                    or not lk.get("edge_interface"):
                return _invalid("extended_edges", f"extended_edges[{i}].links[{j}] needs "
                                "'stub_interface' and 'edge_interface'.")
            links.append({"a_device": stub, "a_interface": lk["stub_interface"],
                          "b_device": edge, "b_interface": lk["edge_interface"],
                          "extended_edge": True})
        if edge not in edges:
            edges.append(edge)

    p2p_subnets = list(itertools.islice(underlay_net.subnets(new_prefix=31), len(links)))
    if len(p2p_subnets) < len(links):
        return _invalid("underlay_subnet",
                        f"pool too small for {len(links)} link(s) "
                        f"(only {len(p2p_subnets)} /31s available).")

    all_devices = spines + leafs + edges
    lo0_hosts = list(itertools.islice(lo0_net.hosts(), len(all_devices)))
    if len(lo0_hosts) < len(all_devices):
        return _invalid("loopback0_subnet", "pool too small for all devices.")
    loopback0 = {dev: f"{ip}/32" for dev, ip in zip(all_devices, lo0_hosts)}

    loopback1: dict[str, str] = {}
    if lo1_net is not None:
        vsx_pairs = vsx_pairs or []
        paired: dict[str, str] = {}
        for pair in vsx_pairs:
            if len(pair) != 2:
                return _invalid("vsx_pairs", f"each entry must be [devA, devB], got {pair}.")
            a, b = pair
            if a not in leafs or b not in leafs:
                return _invalid("vsx_pairs", f"{pair} must both be in `leafs`.")
            paired[a] = b
            paired[b] = a
        assigned = {}
        lo1_iter = lo1_net.hosts()
        for dev in leafs:
            if dev in assigned:
                continue
            ip = next(lo1_iter, None)
            if ip is None:
                return _invalid("loopback1_subnet", "pool too small for all leafs.")
            assigned[dev] = ip
            peer = paired.get(dev)
            if peer:
                assigned[peer] = ip
        loopback1 = {dev: f"{ip}/32" for dev, ip in assigned.items()}

    link_interfaces: dict[str, list[str]] = {dev: [] for dev in all_devices}
    p2p_steps: dict[str, list] = {dev: [] for dev in all_devices}
    # per-device {port: lag} filled at apply time by the release_lag_members step
    released: dict[str, dict] = {dev: {} for dev in all_devices}

    def _routed(dev, intf, ip):
        return _step(
            "configure_routed_interface",
            lambda c, _if=intf, _ip=ip, _rel=released[dev]: c.configure_routed_interface(
                _if, ip_cidr=_ip, vrf=vrf, mtu=mtu, force_admin_flap=_if in _rel,
                ensure_internal_vlan_range=ensure_internal_vlan_range,
                internal_vlan_range_size=internal_vlan_range_size),
            interface=intf, ip4_address=ip, vrf=vrf, mtu=mtu)

    for idx, link in enumerate(links):
        addrs = list(p2p_subnets[idx])  # /31 (RFC 3021): both addresses usable
        a_dev, a_if, a_ip = link["a_device"], link["a_interface"], addrs[0]
        b_dev, b_if, b_ip = link["b_device"], link["b_interface"], addrs[1]
        p2p_steps[a_dev].append(_routed(a_dev, a_if, f"{a_ip}/31"))
        p2p_steps[b_dev].append(_routed(b_dev, b_if, f"{b_ip}/31"))
        link_interfaces[a_dev].append(a_if)
        link_interfaces[b_dev].append(b_if)

    steps_by_device: dict[str, list] = {}
    for dev in all_devices:
        s = []
        if remove_from_lag and link_interfaces[dev]:
            async def _release(c, _ports=tuple(link_interfaces[dev]), _rel=released[dev]):
                res = await c.release_lag_members(list(_ports), delete_empty=delete_empty_lags)
                _rel.update(res.get("released") or {})
                return res
            s.append(_step("release_lag_members", _release,
                           interfaces=list(link_interfaces[dev]),
                           delete_empty_lags=delete_empty_lags))
        s.append(_step("create_loopback",
                   lambda c, _ip=loopback0[dev]: c.create_loopback("loopback0", _ip, vrf=vrf),
                   interface="loopback0", ip4_address=loopback0[dev], vrf=vrf))
        if dev in loopback1:
            s.append(_step(
                "create_loopback",
                lambda c, _ip=loopback1[dev]: c.create_loopback("loopback1", _ip, vrf=vrf),
                interface="loopback1", ip4_address=loopback1[dev], vrf=vrf))
        s.extend(p2p_steps[dev])
        s.append(_step(
            "ensure_ospf_router",
            lambda c, _rid=_host(loopback0[dev]): c.ensure_ospf_router(
                vrf=vrf, instance_tag=ospf_instance_tag, router_id=_rid),
            vrf=vrf, instance_tag=ospf_instance_tag, router_id=_host(loopback0[dev])))
        s.append(_step("ensure_ospf_area",
                       lambda c: c.ensure_ospf_area(ospf_area, vrf=vrf, instance_tag=ospf_instance_tag),
                       area_id=ospf_area, vrf=vrf))
        for intf in link_interfaces[dev]:
            s.append(_step(
                "add_ospf_interface",
                lambda c, _i=intf: c.add_ospf_interface(
                    _i, ospf_area, vrf=vrf, instance_tag=ospf_instance_tag),
                interface=intf, area_id=ospf_area, vrf=vrf))
            s.append(_step(
                "configure_ospf_interface_options",
                lambda c, _i=intf: c.configure_ospf_interface_options(
                    _i, network_type="point_to_point"),
                interface=intf, network_type="point_to_point"))
        for pintf in (["loopback0"] + (["loopback1"] if dev in loopback1 else [])):
            s.append(_step(
                "add_ospf_interface",
                lambda c, _i=pintf: c.add_ospf_interface(
                    _i, ospf_area, vrf=vrf, instance_tag=ospf_instance_tag),
                interface=pintf, area_id=ospf_area, vrf=vrf))
            s.append(_step(
                "set_ospf_interface_passive",
                lambda c, _i=pintf: c.set_ospf_interface_passive(
                    _i, True, vrf=vrf, instance_tag=ospf_instance_tag),
                interface=pintf, passive=True, vrf=vrf))
        steps_by_device[dev] = s

    async def _post(res):
        async def _one(dev):
            async with _get_client(dev) as client:
                return dev, await client.get_ospf_neighbors(vrf=vrf)
        expected = {dev: len(link_interfaces[dev]) for dev in all_devices}
        summary: dict = {}
        for attempt in range(6):  # adjacencies need a few seconds to reach Full
            if attempt:
                await asyncio.sleep(5)
            results = dict(await asyncio.gather(*[_one(d) for d in all_devices]))
            summary = {}
            for dev, data in results.items():
                neighbors = data.get("ospf_neighbors") or []
                full = [n for n in neighbors if str(n.get("state", "")).lower() == "full"]
                summary[dev] = {"neighbors": len(neighbors), "full": len(full),
                                "expected": expected[dev]}
            if all(s["full"] >= s["expected"] for s in summary.values()):
                break
        res["ospf_neighbor_check"] = summary
        mismatches = await _link_mtu_check(
            [(l["a_device"], l["a_interface"], l["b_device"], l["b_interface"]) for l in links])
        if mismatches:
            res["mtu_mismatches"] = mismatches
            res.setdefault("warnings", []).append(
                f"MTU differs on {len(mismatches)} link(s) — OSPF may stay in ExStart/Exchange; "
                "align both ends (see mtu_mismatches).")
        missing = {d: s for d, s in summary.items() if s["full"] < s["expected"]}
        if missing:
            res["status"] = "partial"
            res["warning"] = (
                f"Configuration written but OSPF is NOT converged on {sorted(missing)} "
                "(fewer Full adjacencies than underlay links). Check "
                "get_interfaces(scope='physical') l1_state, get_routing(scope="
                "'ospf_interfaces') and the OSPF interface state before moving on.")

    ckpt_token = None
    if auto_checkpoint is not None:
        ckpt_token = _core.AUTO_CHECKPOINT_OVERRIDE.set(bool(auto_checkpoint))
    try:
        result = await _orchestrate("orchestrate_fabric_underlay", steps_by_device,
                                    apply, post=_post)
    finally:
        if ckpt_token is not None:
            _core.AUTO_CHECKPOINT_OVERRIDE.reset(ckpt_token)
    result["cabling_used"] = links
    result["ip_allocation"] = {
        "loopback0": loopback0, "loopback1": loopback1,
        "p2p_links": [{"a_device": l["a_device"], "a_interface": l["a_interface"],
                       "b_device": l["b_device"], "b_interface": l["b_interface"],
                       "subnet": str(p2p_subnets[i]),
                       **({"extended_edge": True} if l.get("extended_edge") else {})}
                      for i, l in enumerate(links)]}
    return result


async def _read_port_mtu(dev: str, intf: str) -> dict:
    async with _get_client(dev) as client:
        data = await client._get(
            f"/system/interfaces/{quote(intf, safe='')}",
            params={"depth": "1", "attributes": "ip_mtu,mtu,user_config"})
    data = data if isinstance(data, dict) else {}
    return {"ip_mtu": data.get("ip_mtu"),
            "mtu": (data.get("user_config") or {}).get("mtu") or data.get("mtu")}


async def _link_mtu_check(pairs: list) -> list:
    """Compare ip_mtu / L2 mtu on both ends of each (devA, ifA, devB, ifB)
    link; returns the mismatching ones (unreadable ends are skipped)."""
    async def _one(a_dev, a_if, b_dev, b_if):
        try:
            a, b = await asyncio.gather(_read_port_mtu(a_dev, a_if), _read_port_mtu(b_dev, b_if))
        except Exception:  # noqa: BLE001 — best-effort warning only
            return None
        if a["ip_mtu"] != b["ip_mtu"] or (a["mtu"] and b["mtu"] and a["mtu"] != b["mtu"]):
            return {"a_device": a_dev, "a_interface": a_if, "a": a,
                    "b_device": b_dev, "b_interface": b_if, "b": b}
        return None
    found = await asyncio.gather(*[_one(*p) for p in pairs])
    return [m for m in found if m]


# ══════════════════════════════════════════════════════════════════════
# Fabric overlay (iBGP EVPN: spines = route-reflectors, leafs = clients)
# ══════════════════════════════════════════════════════════════════════

_EVPN_AF = {"l2vpn-evpn": True, "ipv4-unicast": False}


@mcp.tool()
async def orchestrate_fabric_overlay(spines: list, leafs: list, asn: int,
                                     loopback0: dict = None,
                                     spine_peer_group: str = "EVPN-RR-CLIENTS",
                                     leaf_peer_group: str = "EVPN-SPINES",
                                     vrf: str = "default",
                                     bfd: bool = None,
                                     wait_established: int = 60,
                                     delete: bool = False,
                                     auto_checkpoint: bool = None,
                                     apply: bool = False) -> dict:
    """Bring up the ENTIRE iBGP-EVPN control plane of a fabric in ONE call,
    symmetric to orchestrate_fabric_underlay (run it after the underlay):

    - every device: `router bgp <asn>`, router-id = its loopback0 address.
    - spines: peer-group `spine_peer_group` (remote-as `asn`, update-source
      loopback0, route-reflector-client, send-community extended, l2vpn-evpn
      activated, ipv4-unicast DEACTIVATED) with every leaf loopback0 as member.
    - leafs: peer-group `leaf_peer_group` (same, without RR-client) with every
      spine loopback0 as member.
    `loopback0`: optional {device: ip} override; by default each device's
    loopback0 address is READ from the device (also in plan mode — needed to
    list the neighbours). `bfd`: set bfd on both peer-groups when given.
    `wait_established` (s, 0-300, default 60): after apply, wait until every
    session is Established; the others are reported with their last BGP
    error and the device result is partial. Teardown: `delete=true` removes
    the members then the peer-groups (the BGP router itself is kept).
    `apply`=False = plan only."""
    spines = list(dict.fromkeys(_core._coerce_device_list(spines) or []))
    leafs = list(dict.fromkeys(_core._coerce_device_list(leafs) or []))
    if not spines or not leafs:
        return _invalid("spines/leafs", "Both `spines` and `leafs` must be non-empty lists.")
    if set(spines) & set(leafs):
        return _invalid("spines/leafs", f"{sorted(set(spines) & set(leafs))} listed twice.")
    err = _precheck([("asn", lambda: _v_asn(asn, "asn")),
                     ("wait_established", lambda: _v_int_range(wait_established or 0, 0, 300,
                                                               "wait_established"))])
    if err:
        return err
    all_devices = spines + leafs
    lo0: dict = {}
    for k, v in (loopback0 or {}).items():
        try:
            lo0[_resolve_devices(device=k)[0]] = _host(v)
        except ValueError as exc:
            return {"status": "error", "error": str(exc)}
    try:
        canon = {d: _resolve_devices(device=d)[0] for d in all_devices}
    except ValueError as exc:
        return {"status": "error", "error": str(exc)}
    spines = [canon[d] for d in spines]
    leafs = [canon[d] for d in leafs]
    all_devices = spines + leafs

    async def _read_lo0(dev):
        try:
            async with _get_client(dev) as client:
                return dev, await client.loopback_ip("loopback0"), None
        except Exception as exc:  # noqa: BLE001
            return dev, None, str(exc)
    missing = [d for d in all_devices if d not in lo0]
    errors = {}
    for dev, ip, why in await asyncio.gather(*[_read_lo0(d) for d in missing]):
        if ip:
            lo0[dev] = ip
        else:
            errors[dev] = why
    if errors:
        return {"status": "error", "field": "loopback0",
                "error": f"loopback0 address unknown on {sorted(errors)}: {errors}",
                "action_required": "run orchestrate_fabric_underlay first, or pass loopback0="
                                   "{device: ip}; nothing was written."}
    err = _precheck([(f"loopback0[{d}]", lambda _v=v: _v_ipv4_host(_v, "loopback0"))
                     for d, v in lo0.items()])
    if err:
        return err

    def _group(name, rr_client):
        g = {"neighbor": name, "is_peer_group": True, "remote_as": asn,
             "local_interface": "loopback0", "activate": dict(_EVPN_AF),
             "send_community": {"l2vpn-evpn": "extended"}}
        if rr_client:
            g["route_reflector_client"] = {"l2vpn-evpn": True}
        if bfd is not None:
            g["bfd_enable"] = bool(bfd)
        return g

    neighbors_by_dev: dict = {}
    for dev in spines:
        neighbors_by_dev[dev] = [_group(spine_peer_group, True)] + [
            {"neighbor": lo0[l], "peer_group": spine_peer_group, "description": l}
            for l in leafs]
    for dev in leafs:
        neighbors_by_dev[dev] = [_group(leaf_peer_group, False)] + [
            {"neighbor": lo0[s], "peer_group": leaf_peer_group, "description": s}
            for s in spines]

    steps_by_device: dict = {}
    for dev in all_devices:
        nbrs = neighbors_by_dev[dev]
        if delete:
            s = [_step("delete_bgp_neighbor",
                       lambda c, _n=n["neighbor"]: c.delete_bgp_neighbor(_n, asn, vrf=vrf),
                       vrf=vrf, neighbor=n["neighbor"])
                 for n in reversed(nbrs)]
        else:
            s = [_step("ensure_bgp_router",
                       lambda c, _rid=lo0[dev]: c.ensure_bgp_router(asn, vrf=vrf, router_id=_rid),
                       vrf=vrf, asn=asn, router_id=lo0[dev]),
                 _step("configure_bgp_neighbors",
                       lambda c, _n=nbrs: _bgp_neighbors_step(c, asn, vrf, _n),
                       vrf=vrf, peer_group=nbrs[0]["neighbor"],
                       members=[n["neighbor"] for n in nbrs[1:]])]
        steps_by_device[dev] = s

    async def _post(res):
        if delete or not wait_established:
            return
        async def _one(dev):
            peers = [n["neighbor"] for n in neighbors_by_dev[dev][1:]]
            async with _get_client(dev) as client:
                return dev, await client.wait_bgp_established(
                    peers, vrf=vrf, timeout=wait_established)
        ok_devs = [d for d in all_devices if ((res.get("results") or {}).get(d) or {}).get("ok")]
        sessions = dict(await asyncio.gather(*[_one(d) for d in ok_devs]))
        res["bgp_sessions"] = sessions
        for dev, st in sessions.items():
            if st["not_established"]:
                _flag_device(res, dev, f"BGP not Established after {wait_established}s: "
                             f"{st['not_established']}")

    ckpt_token = None
    if auto_checkpoint is not None:
        ckpt_token = _core.AUTO_CHECKPOINT_OVERRIDE.set(bool(auto_checkpoint))
    try:
        result = await _orchestrate("orchestrate_fabric_overlay", steps_by_device, apply,
                                    post=_post)
    finally:
        if ckpt_token is not None:
            _core.AUTO_CHECKPOINT_OVERRIDE.reset(ckpt_token)
    result["loopback0"] = lo0
    return result


# ══════════════════════════════════════════════════════════════════════
# Access port (L2 + STP edge/guards + optional 802.1X / MAC-auth)
# ══════════════════════════════════════════════════════════════════════

def _port_auth_kwargs(port_auth: dict):
    """Normalise a nested `port_auth` block (same keys as configure_port_auth)."""
    pa = dict(port_auth or {})
    methods, err = _norm_methods(pa.get("methods"), pa.get("dot1x"), pa.get("mac_auth"))
    if err:
        return None, err
    prec, err = _norm_method_list(pa.get("auth_precedence"), "auth_precedence")
    if err:
        return None, err
    prio, err = _norm_method_list(pa.get("auth_priority"), "auth_priority")
    if err:
        return None, err
    if not methods:
        return None, _port_auth_invalid("port_auth.methods",
                                        "port_auth needs at least one method (dot1x / mac-auth).")
    return {"methods": methods, "auth_mode": pa.get("auth_mode"),
            "clients_limit": pa.get("clients_limit"),
            "mda_data_clients_limit": pa.get("mda_data_clients_limit"),
            "concurrent_onboarding": pa.get("concurrent_onboarding"),
            "radius_override": pa.get("radius_override"),
            "auth_precedence": prec, "auth_priority": prio,
            "roles": pa.get("roles"), "create_roles": pa.get("create_roles")}, None


@mcp.tool()
async def orchestrate_access_port(interfaces, device: str = None, site: str = None,
                                  access_vlan: int = None, voice_vlan: int = None,
                                  description: str = None, enable: bool = True,
                                  stp_edge: bool = True, bpdu_guard: bool = True,
                                  root_guard: bool = None, loop_guard: bool = None,
                                  port_auth: dict = None,
                                  delete: bool = False, apply: bool = False) -> dict:
    """Provision end-user access ports in ONE call (many ports, many devices):
    `no routing` + `vlan access <access_vlan>` (or native `access_vlan` +
    tagged `voice_vlan`), description, `no shutdown` (`enable`), spanning-tree
    `port-type admin-edge` (`stp_edge`), `bpdu-guard`, optional `root_guard` /
    `loop_guard`, and optionally 802.1X / MAC-auth via `port_auth` = the same
    keys as configure_port_auth ({methods|dot1x|mac_auth, auth_precedence,
    auth_mode, clients_limit, roles, create_roles, ...}). `interfaces` accepts a
    list, a CSV string and CLI ranges ('1/1/1-1/1/24'). Each port is processed
    independently (result.summary.failed_interfaces).
    Teardown: `delete=true` removes port-access config and resets the ports to
    VLAN 1 access, no description, STP options cleared (admin state kept).
    `apply`=False = plan only."""
    ports = _expand_interfaces(interfaces)
    if not ports:
        return _invalid("interfaces", "`interfaces` is required (list / CSV / range).")
    targets = _safe_targets(device, site)
    if not targets:
        return {"status": "error", "error": "No resolved target device — provide `device` or `site`."}

    if delete:
        async def _run_del(c):
            l2 = {"interfaces": [], "summary": {"ok": 0, "failed": 0, "failed_interfaces": []}}
            for p in ports:
                try:
                    l2["interfaces"].append(await c.reset_l2_access_port(p))
                    l2["summary"]["ok"] += 1
                except ArubaAPIError as exc:
                    l2["interfaces"].append({"interface": p, "ok": False, "status": "failed",
                                             "error": exc.args[0] if exc.args else str(exc)})
                    l2["summary"]["failed"] += 1
                    l2["summary"]["failed_interfaces"].append(p)
            return l2
        steps = [_step("clear_port_auth", lambda c: _clear_port_auth(c, ports), interfaces=ports),
                 _step("reset_l2_access_port", _run_del, interfaces=ports)]
        return await _orchestrate("orchestrate_access_port", {d: list(steps) for d in targets}, apply)

    err = _precheck([
        ("access_vlan", lambda: _v_vlan(access_vlan, "access_vlan") if access_vlan is not None else None),
        ("voice_vlan", lambda: _v_vlan(voice_vlan, "voice_vlan") if voice_vlan is not None else None),
    ])
    if err:
        return err
    pa_kwargs = None
    if port_auth:
        pa_kwargs, err = _port_auth_kwargs(port_auth)
        if err:
            return err
    stp = {k: v for k, v in {"admin_edge_port_enable": stp_edge, "bpdu_guard_enable": bpdu_guard,
                             "root_guard_enable": root_guard, "loop_guard_enable": loop_guard}.items()
           if v is not None}

    async def _run_l2(c):
        out = {"interfaces": [], "summary": {"ok": 0, "failed": 0, "failed_interfaces": []}}
        for p in ports:
            try:
                out["interfaces"].append(await c.configure_l2_access_port(
                    p, access_vlan=access_vlan, voice_vlan=voice_vlan, description=description,
                    enable=enable, stp=stp or None))
                out["summary"]["ok"] += 1
            except ArubaAPIError as exc:
                out["interfaces"].append({"interface": p, "ok": False, "status": "failed",
                                          "error": exc.args[0] if exc.args else str(exc)})
                out["summary"]["failed"] += 1
                out["summary"]["failed_interfaces"].append(p)
        return out

    steps = [_step("configure_l2_access_port", _run_l2, interfaces=ports, access_vlan=access_vlan,
                   voice_vlan=voice_vlan, description=description,
                   admin="up" if enable else "down", stp=stp)]
    if pa_kwargs:
        steps.append(_step("configure_port_auth", lambda c: _apply_port_auth(c, ports, **pa_kwargs),
                           interfaces=ports, **{k: v for k, v in pa_kwargs.items() if v is not None}))

    async def _exec_steps(dev, client):
        res = await _run_steps(dev, client, steps)
        # Surface per-port failures at the top level so _domain_write flags the device partial.
        failed: list = []
        for st in res["steps"]:
            failed.extend((st["result"].get("summary") or {}).get("failed_interfaces", []))
        res["summary"] = {"steps": len(res["steps"]), "failed": len(set(failed)),
                          "failed_interfaces": sorted(set(failed))}
        return res

    plan = {d: _plan_view(steps) for d in targets}
    return await _domain_write("orchestrate_access_port", targets, None, plan, _exec_steps, apply)


# ══════════════════════════════════════════════════════════════════════
# EVPN VLAN (VLAN + L2VNI + EVPN RD/RT + optional SVI / VXLAN source)
# ══════════════════════════════════════════════════════════════════════

def _rt_list(value, default):
    if value is None:
        return list(default)
    if isinstance(value, str):
        return [p for p in value.replace(",", " ").split() if p]
    return list(value)


@mcp.tool()
async def orchestrate_evpn_vlan(vlan_id: int, device: str = None, site: str = None,
                                name: str = None, description: str = None,
                                vni: int = None, vxlan_interface: str = "vxlan1",
                                vxlan_source_ip: str = None, evpn: bool = True,
                                rd: str = "auto", import_rts=None, export_rts=None,
                                route_target_auto_mode: str = None,
                                svi_vrf: str = None, svi_ip: str = None,
                                active_gateway_ip: str = None,
                                active_gateway_mac: str = None,
                                delete: bool = False, apply: bool = False) -> dict:
    """Provision an EVPN-VXLAN L2 service (+ optional anycast SVI) with EXPLICIT
    RD / route-targets, on every `device` (list/CSV/site): VLAN -> (VXLAN
    interface source IP, if `vxlan_source_ip` — PER DEVICE: pass {"<device>":
    "<ip>"} for several devices, the same IP only on a VSX pair) -> L2VNI mapping `vni` <-> VLAN
    under `vxlan_interface` -> `evpn vlan <id>` with `rd` + `import_rts` /
    `export_rts` (default 'auto' for all three; explicit 'ASN:nn' / 'IP:nn'
    accepted, lists or 'a:b c:d' strings) -> optional SVI `interface vlan<id>`
    in `svi_vrf` with `svi_ip` (CIDR) and active-gateway (`active_gateway_ip`
    / `active_gateway_mac`, identical on every VTEP). `evpn=false` maps the VNI
    without an EVPN RT (Extended Edge / Stub-VTEP). Idempotent (re-run =
    update). Teardown: `delete=true` removes SVI -> EVPN RT -> L2VNI -> VLAN
    (needs `vni`). For the auto-discovering, RT-deducing variant use
    configure_service(scope='vlan'). `apply`=False = plan only."""
    targets = _safe_targets(device, site)
    if not targets:
        return {"status": "error", "error": "No resolved target device — provide `device` or `site`."}
    vsrc, err = await _per_device_value(vxlan_source_ip, targets, "vxlan_source_ip")
    if err:
        return err
    imp = _rt_list(import_rts, ["auto"])
    exp = _rt_list(export_rts, ["auto"])
    err = _precheck([
        ("vlan_id", lambda: _v_vlan(vlan_id, "vlan_id")),
        ("vni", lambda: _v_vni(vni, "vni") if vni is not None else None),
        ("rd", lambda: _v_route_target(rd, "rd") if rd not in (None, "auto") else None),
        *[(f"import_rts[{i}]", lambda _r=r: _v_route_target(_r, "import_rt"))
          for i, r in enumerate(imp) if r != "auto"],
        *[(f"export_rts[{i}]", lambda _r=r: _v_route_target(_r, "export_rt"))
          for i, r in enumerate(exp) if r != "auto"],
        *[(f"vxlan_source_ip[{d}]", lambda _v=v: _v_ip_host(_v, "vxlan_source_ip"))
          for d, v in vsrc.items() if v],
        ("svi_ip", lambda: _v_ipv4_cidr(svi_ip, "svi_ip") if svi_ip else None),
        ("active_gateway_ip", lambda: _v_ip_host(active_gateway_ip, "active_gateway_ip")
         if active_gateway_ip else None),
        ("active_gateway_mac", lambda: _v_mac(active_gateway_mac, "active_gateway_mac")
         if active_gateway_mac else None),
    ])
    if err:
        return err
    if route_target_auto_mode not in (None, "default", "legacy"):
        return _invalid("route_target_auto_mode", "route_target_auto_mode must be 'default' (RFC 8365) or 'legacy' (RFC 4364).")
    want_svi = bool(svi_vrf or svi_ip or active_gateway_ip)

    if delete:
        steps = [_step("delete_svi", lambda c: c.delete_svi(vlan_id), vlan=vlan_id),
                 _step("delete_evpn_vlan_rt", lambda c: c.delete_evpn_vlan_rt(vlan_id), vlan=vlan_id)]
        if vni is not None:
            steps.append(_step("delete_l2vni", lambda c: c.delete_l2vni(vni), vni=vni, vlan=vlan_id))
        steps.append(_step("delete_vlan", lambda c: c.delete_vlan(vlan_id), vlan=vlan_id))
        res = await _orchestrate("orchestrate_evpn_vlan", {d: list(steps) for d in targets}, apply)
        if vni is None:
            res["warning"] = "`vni` not given: the L2VNI mapping was NOT removed (pass vni to delete it)."
        return res

    if vni is None:
        return _invalid("vni", "`vni` is required to map the VLAN to a VXLAN L2VNI.")
    if want_svi and not svi_vrf:
        svi_vrf = "default"

    steps = [_step("create_vlan", lambda c: c.create_vlan(vlan_id, name=name, description=description),
                   vlan=vlan_id, name=name)]
    steps.append(_step("create_l2vni",
                       lambda c: c.create_l2vni(vni, vlan_id, vxlan_interface=vxlan_interface),
                       vni=vni, vlan=vlan_id, interface=vxlan_interface))
    if evpn:
        async def _rt(c):
            res = await c.set_evpn_vlan_rt(vlan_id, imp, exp, rd=rd or "auto")
            if route_target_auto_mode:
                await c._put_merge(f"/system/evpn/evpn_vlans/{vlan_id}",
                                   {"route_target_auto_mode": route_target_auto_mode})
                res["route_target_auto_mode"] = route_target_auto_mode
            return res
        steps.append(_step("set_evpn_vlan_rt", _rt, vlan=vlan_id, rd=rd or "auto",
                           import_route_targets=imp, export_route_targets=exp,
                           **({"route_target_auto_mode": route_target_auto_mode}
                              if route_target_auto_mode else {})))
    if want_svi:
        steps.append(_step("create_svi",
                           lambda c: c.create_svi(vlan_id, svi_vrf, ip_cidr=svi_ip,
                                                  active_gateway_ip=active_gateway_ip,
                                                  active_gateway_mac=active_gateway_mac),
                           vlan=vlan_id, vrf=svi_vrf, ip4_address=svi_ip,
                           active_gateway_ip=active_gateway_ip, active_gateway_mac=active_gateway_mac))

    def _for(dev):
        my = vsrc.get(dev)
        if not my:
            return list(steps)
        # Per-device VTEP source goes right after the VLAN, before the L2VNI mapping.
        return [steps[0],
                _step("ensure_vxlan_interface",
                      lambda c, _ip=my: c.ensure_vxlan_interface(vxlan_interface, source_ip=_ip),
                      interface=vxlan_interface, source_ip=my),
                *steps[1:]]

    return await _orchestrate("orchestrate_evpn_vlan", {d: _for(d) for d in targets}, apply)


# ══════════════════════════════════════════════════════════════════════
# Static VXLAN (no EVPN control plane): VTEP + VLAN/VNI maps + static peers
# ══════════════════════════════════════════════════════════════════════

def _norm_vlan_vni_list(vlans):
    """[{vlan_id, vni, name}] | {vlan_id: vni} | [[vlan, vni], ...] -> list of dicts."""
    if vlans is None:
        return [], None
    items = []
    if isinstance(vlans, dict):
        for k, v in vlans.items():
            items.append({"vlan_id": k, "vni": v, "name": None})
    elif isinstance(vlans, (list, tuple)):
        for i, it in enumerate(vlans):
            if isinstance(it, dict):
                if it.get("vlan_id") is None or it.get("vni") is None:
                    return None, _invalid(f"vlans[{i}]", "Each entry needs `vlan_id` and `vni`.")
                items.append({"vlan_id": it["vlan_id"], "vni": it["vni"], "name": it.get("name")})
            elif isinstance(it, (list, tuple)) and len(it) == 2:
                items.append({"vlan_id": it[0], "vni": it[1], "name": None})
            else:
                return None, _invalid(f"vlans[{i}]", "Use {vlan_id, vni, name} or [vlan_id, vni].")
    else:
        return None, _invalid("vlans", "`vlans` must be a list of {vlan_id, vni, name} or {vlan_id: vni}.")
    for it in items:
        it["vlan_id"] = int(it["vlan_id"])
        it["vni"] = int(it["vni"])
    return items, None


@mcp.tool()
async def orchestrate_static_vxlan(device: str = None, site: str = None,
                                   vxlan_interface: str = "vxlan1",
                                   source_ip=None, dest_udp_port: int = None,
                                   inter_vxlan_bridging_mode: str = None,
                                   vlans=None, peers: list = None,
                                   full_mesh: bool = True,
                                   delete: bool = False, delete_vlans: bool = True,
                                   delete_vxlan_interface: bool = False,
                                   apply: bool = False) -> dict:
    """Static VXLAN (head-end replication, NO EVPN / BGP) in ONE call per
    device set: VTEP interface (`vxlan_interface`, `source_ip`, `dest_udp_port`,
    `inter_vxlan_bridging_mode` deny|static-evpn|static-all) -> VLANs + L2VNI
    mappings (`vlans` = [{vlan_id, vni, name}] or {vlan_id: vni}) -> static
    peers (`peers` = [{destination: '<remote VTEP IP>', vnis: [...] (default:
    ALL the VNIs of `vlans`), vrf (=default)}]).
    `source_ip` is PER DEVICE: for several devices pass {"<device>": "<ip>",
    ...} — every VTEP needs its own source IP; the same IP is only accepted on
    the 2 members of a VSX pair (anycast VTEP). With a mapping and
    `full_mesh=true` (default) the other VTEPs of the mapping are added as
    static peers automatically (a device never peers with its own IP), so
    `peers` is only needed for VTEPs outside this call. Idempotent; re-run with
    more peers/VLANs to extend. Teardown: `delete=true` removes the listed
    peers (+ mesh peers), then the L2VNI mappings (+ VLANs unless
    `delete_vlans=false`), and the VTEP interface if
    `delete_vxlan_interface=true`. `apply`=False = plan only."""
    targets = _safe_targets(device, site)
    if not targets:
        return {"status": "error", "error": "No resolved target device — provide `device` or `site`."}
    src, err = await _per_device_value(source_ip, targets, "source_ip")
    if err:
        return err
    items, err = _norm_vlan_vni_list(vlans)
    if err:
        return err
    peers = [dict(p) for p in (peers or [])]
    if any(not isinstance(p, dict) or not p.get("destination") for p in peers):
        return _invalid("peers", "`peers` must be a list of {destination, vnis, vrf}.")
    if inter_vxlan_bridging_mode not in (None, "deny", "static-evpn", "static-all"):
        return _invalid("inter_vxlan_bridging_mode", "Valid: deny | static-evpn | static-all.")
    all_vnis = sorted({it["vni"] for it in items})
    for p in peers:
        p["vnis"] = [int(v) for v in (p.get("vnis") or all_vnis)]
        p["vrf"] = p.get("vrf") or "default"
    # Full mesh between the VTEPs of this call (distinct source IPs only).
    mesh_ips = sorted({str(v).split("/")[0] for v in src.values() if v}) if full_mesh else []
    known = {str(p["destination"]).split("/")[0] for p in peers}
    for ip in mesh_ips:
        if ip not in known:
            peers.append({"destination": ip, "vnis": list(all_vnis), "vrf": "default", "_mesh": True})
    err = _precheck([
        *[(f"source_ip[{d}]", lambda _v=v: _v_ip_host(_v, "source_ip")) for d, v in src.items() if v],
        ("dest_udp_port", lambda: _v_int_range(dest_udp_port, 1, 65535, "dest_udp_port")
         if dest_udp_port is not None else None),
        *[(f"vlans[{i}].vlan_id", lambda _v=it["vlan_id"]: _v_vlan(_v, "vlan_id")) for i, it in enumerate(items)],
        *[(f"vlans[{i}].vni", lambda _v=it["vni"]: _v_vni(_v, "vni")) for i, it in enumerate(items)],
        *[(f"peers[{i}].destination", lambda _p=p: _v_ip_host(_p["destination"], "destination"))
          for i, p in enumerate(peers)],
        *[(f"peers[{i}].vnis", lambda _v=v: _v_vni(_v, "vni")) for i, p in enumerate(peers) for v in p["vnis"]],
    ])
    if err:
        return err
    for i, p in enumerate(peers):
        if not p["vnis"]:
            return _invalid(f"peers[{i}].vnis", "No VNI for this peer: pass `vnis` or define `vlans`.")

    def _peers_for(dev):
        own = str(src.get(dev) or "").split("/")[0]
        return [p for p in peers if str(p["destination"]).split("/")[0] != own]

    if delete:
        def _teardown(dev):
            steps = []
            for p in _peers_for(dev):
                steps.append(_step("remove_static_vxlan_peer",
                                   lambda c, _p=p: c.remove_static_vxlan_peer(
                                       _p["destination"], vxlan_interface=vxlan_interface, vrf=_p["vrf"]),
                                   destination=p["destination"], vrf=p["vrf"]))
            for it in items:
                steps.append(_step("delete_l2vni", lambda c, _v=it["vni"]: c.delete_l2vni(_v),
                                   vni=it["vni"], vlan=it["vlan_id"]))
            if delete_vlans:
                for it in items:
                    steps.append(_step("delete_vlan", lambda c, _v=it["vlan_id"]: c.delete_vlan(_v),
                                       vlan=it["vlan_id"]))
            if delete_vxlan_interface:
                steps.append(_step("delete_interface", lambda c: c.delete_interface(vxlan_interface),
                                   interface=vxlan_interface))
            return steps
        plans = {d: _teardown(d) for d in targets}
        if not any(plans.values()):
            return _invalid("delete", "Nothing to delete: give `peers`, `vlans` or `delete_vxlan_interface`.")
        return await _orchestrate("orchestrate_static_vxlan", plans, apply)

    if not items and not peers and not (any(src.values()) or dest_udp_port or inter_vxlan_bridging_mode):
        return _invalid("vlans", "Nothing to do: give `vlans`, `peers` and/or VTEP settings.")

    def _build(dev):
        my_src = src.get(dev)
        steps = [_step("ensure_vxlan_interface",
                       lambda c: c.ensure_vxlan_interface(
                           vxlan_interface, source_ip=my_src, dest_udp_port=dest_udp_port,
                           inter_vxlan_bridging_mode=inter_vxlan_bridging_mode),
                       interface=vxlan_interface, source_ip=my_src, dest_udp_port=dest_udp_port,
                       inter_vxlan_bridging_mode=inter_vxlan_bridging_mode)]
        for it in items:
            steps.append(_step("create_vlan",
                               lambda c, _it=it: c.create_vlan(_it["vlan_id"], name=_it["name"]),
                               vlan=it["vlan_id"], name=it["name"]))
            steps.append(_step("create_l2vni",
                               lambda c, _it=it: c.create_l2vni(_it["vni"], _it["vlan_id"],
                                                                vxlan_interface=vxlan_interface),
                               vni=it["vni"], vlan=it["vlan_id"], interface=vxlan_interface))
        for p in _peers_for(dev):
            steps.append(_step("add_static_vxlan_peer",
                               lambda c, _p=p: c.add_static_vxlan_peer(
                                   _p["destination"], _p["vnis"], vxlan_interface=vxlan_interface, vrf=_p["vrf"]),
                               destination=p["destination"], vnis=p["vnis"], vrf=p["vrf"],
                               interface=vxlan_interface, **({"mesh": True} if p.get("_mesh") else {})))
        return steps

    return await _orchestrate("orchestrate_static_vxlan", {d: _build(d) for d in targets}, apply)


# ══════════════════════════════════════════════════════════════════════
# Overlay device bring-up: VXLAN interface + EVPN global + virtual-MAC + BGP-EVPN
# ══════════════════════════════════════════════════════════════════════

_OVERLAY_MODES = ("evpn", "static", "stub")


@mcp.tool()
async def orchestrate_overlay(device: str = None, site: str = None,
                              vxlan_interface: str = "vxlan1",
                              source_ip=None, dest_udp_port: int = None,
                              mode: str = "evpn",
                              inter_vxlan_bridging_mode: str = None,
                              evpn_options: dict = None,
                              virtual_mac=None,
                              bgp_evpn: dict = None,
                              delete: bool = False,
                              delete_vxlan_interface: bool = False,
                              verify_operational: bool = True,
                              apply: bool = False) -> dict:
    """Device-level VTEP overlay bring-up (ONE call per device set): creates
    /configures the VXLAN interface (`source_ip` -> `options.local_ip`
    ACTIVATES the tunnel), then branches on `mode`:

    - `mode='evpn'` (default, Access-VTEP/Border): + global EVPN options
      (`evpn_options`={dyn_vxlan_tunnel_bridging_mode, arp_suppression,
      nd_suppression, redistribute_local_mac, redistribute_local_svi,
      options}) + virtual system-MAC (`virtual_mac`) +
      OPTIONAL BGP-EVPN control-plane (`bgp_evpn`={asn, router_id, vrf
      (=default), neighbors:[...], options} — SAME shape as configure_bgp's
      `neighbors`). `bgp_evpn` is OMITTED by default: nothing BGP-related is
      touched unless explicitly given, so re-running this on a device that's
      already peered never risks a partial write on a shared peer-group.
    - `mode='static'` (Extended Edge): interface ONLY — no EVPN global, no
      virtual-MAC, no BGP (an Extended Edge never joins BGP-EVPN). Any
      `evpn_options`/`virtual_mac`/`bgp_evpn` given are IGNORED (reported
      under `skipped`) rather than silently applied.
    - `mode='stub'` (Stub VTEP): identical to 'evpn', AND defaults
      `inter_vxlan_bridging_mode` to 'static-evpn' unless overridden — pair
      with `orchestrate_overlay_service(attach='stub')` for the per-VLAN
      part (bridges dynamic EVPN + a static tunnel for the same VNI).

    `source_ip`/`virtual_mac` accept a per-device mapping ({"<device>":
    "<value>", ...}) like the other overlay orchestrators — a SHARED value is
    only accepted on the 2 members of a VSX pair. `bgp_evpn.router_id` takes a
    per-device mapping or 'loopback0'. Idempotent (merge-safe
    PUTs, never a blind overwrite of unrelated fields).
    `verify_operational` (default True): after apply, checks that the VXLAN
    interface is operational and that no VNI/EVI is down (CLI `show evpn evi
    summary`); otherwise the device result is NOT ok (status partial) instead
    of a bare 'applied'. Teardown:
    `delete=true` removes the `bgp_evpn` neighbors (if given) and the VXLAN
    interface (if `delete_vxlan_interface=true`) — the global EVPN config is
    NEVER auto-reset (device-wide shared object, not exclusive to this call).
    `apply`=False = plan only."""
    if mode not in _OVERLAY_MODES:
        return _invalid("mode", f"`mode` must be one of {_OVERLAY_MODES}.")
    targets = _safe_targets(device, site)
    if not targets:
        return {"status": "error", "error": "No resolved target device — provide `device` or `site`."}
    src, err = await _per_device_value(source_ip, targets, "source_ip")
    if err:
        return err
    vmac, err = await _per_device_value(virtual_mac, targets, "virtual_mac")
    if err:
        return err
    if inter_vxlan_bridging_mode is None and mode == "stub":
        inter_vxlan_bridging_mode = "static-evpn"
    if inter_vxlan_bridging_mode not in (None, "deny", "static-evpn", "static-all"):
        return _invalid("inter_vxlan_bridging_mode", "Valid: deny | static-evpn | static-all.")
    evpn_options = dict(evpn_options or {})
    bridging_mode = evpn_options.get("dyn_vxlan_tunnel_bridging_mode")
    if bridging_mode not in (None, "no-bridging", "ibgp-ebgp"):
        return _invalid("evpn_options.dyn_vxlan_tunnel_bridging_mode",
                        "Valid: no-bridging | ibgp-ebgp.")
    bgp = dict(bgp_evpn or {})
    neighbors = bgp.get("neighbors") or []
    bgp_rids, err = await _per_device_id(bgp.get("router_id"), targets, "bgp_evpn.router_id")
    if err:
        return err
    checks = [
        *[(f"source_ip[{d}]", lambda _v=v: _v_ip_host(_v, "source_ip")) for d, v in src.items() if v],
        *[(f"virtual_mac[{d}]", lambda _v=v: _v_mac(_v, "virtual_mac")) for d, v in vmac.items() if v],
        ("dest_udp_port", lambda: _v_int_range(dest_udp_port, 1, 65535, "dest_udp_port")
         if dest_udp_port is not None else None),
    ]
    if bgp:
        checks.append(("bgp_evpn.asn", lambda: _v_asn(bgp.get("asn"), "asn")))
        for _d, _rid in bgp_rids.items():
            if _rid is not None and not _is_auto_id(_rid):
                checks.append((f"bgp_evpn.router_id[{_d}]",
                               lambda _r=_rid: _v_ipv4_host(_r, "router_id")))
        for i, nbr in enumerate(neighbors):
            ra = nbr.get("remote_as")
            if ra is not None:
                checks.append((f"bgp_evpn.neighbors[{i}].remote_as", lambda _r=ra: _v_asn(_r, "remote_as")))
    err = _precheck(checks)
    if err:
        return err
    if bgp and bgp.get("asn") is None:
        return _invalid("bgp_evpn.asn", "`bgp_evpn.asn` is required when `bgp_evpn` is given.")

    skipped = {}
    if mode == "static" and (evpn_options or any(vmac.values()) or bgp):
        skipped = {"evpn_options": bool(evpn_options), "virtual_mac": bool(any(vmac.values())),
                  "bgp_evpn": bool(bgp)}

    def _build(dev):
        steps = [_step("ensure_vxlan_interface",
                       lambda c: c.ensure_vxlan_interface(
                           vxlan_interface, source_ip=src.get(dev), dest_udp_port=dest_udp_port,
                           inter_vxlan_bridging_mode=inter_vxlan_bridging_mode),
                       interface=vxlan_interface, source_ip=src.get(dev), dest_udp_port=dest_udp_port,
                       inter_vxlan_bridging_mode=inter_vxlan_bridging_mode)]
        if mode == "static":
            return steps
        steps.append(_step("configure_evpn_global",
                           lambda c: c.set_evpn_global(
                               dyn_vxlan_tunnel_bridging_mode=bridging_mode,
                               arp_suppression_enable=evpn_options.get("arp_suppression"),
                               nd_suppression_enable=evpn_options.get("nd_suppression"),
                               redistribute_local_mac=evpn_options.get("redistribute_local_mac"),
                               redistribute_local_svi=evpn_options.get("redistribute_local_svi"),
                               extra=evpn_options.get("options")),
                           **evpn_options))
        if vmac.get(dev):
            steps.append(_step("set_virtual_mac", lambda c, _m=vmac[dev]: c.set_virtual_mac(_m),
                               mac=vmac[dev]))
        if bgp:
            vrf = bgp.get("vrf") or "default"
            asn = bgp["asn"]
            steps.append(_step("ensure_bgp_router",
                               lambda c, _rid=bgp_rids.get(dev): _bgp_router(
                                   c, asn, vrf, _rid, bgp.get("options")),
                               vrf=vrf, asn=asn, router_id=bgp_rids.get(dev)))
            if neighbors:
                steps.append(_step("configure_bgp_neighbors",
                                   lambda c: _bgp_neighbors_step(c, asn, vrf, neighbors),
                                   vrf=vrf, neighbors=[n.get("neighbor") or n.get("name")
                                                       for n in neighbors]))
        return steps

    if delete:
        def _teardown(dev):
            steps = []
            if bgp:
                vrf = bgp.get("vrf") or "default"
                asn = bgp["asn"]
                for nbr in reversed(neighbors):
                    name = nbr.get("neighbor") or nbr.get("name")
                    if name:
                        steps.append(_step("delete_bgp_neighbor",
                                           lambda c, _nm=name: c.delete_bgp_neighbor(_nm, asn, vrf=vrf),
                                           vrf=vrf, neighbor=name))
            if delete_vxlan_interface:
                steps.append(_step("delete_interface", lambda c: c.delete_interface(vxlan_interface),
                                   interface=vxlan_interface))
            return steps
        plans = {d: _teardown(d) for d in targets}
        if not any(plans.values()):
            return _invalid("delete", "Nothing to delete: give `bgp_evpn` and/or `delete_vxlan_interface=true`.")
        res = await _orchestrate("orchestrate_overlay", plans, apply)
        if skipped:
            res["skipped"] = skipped
        return res

    async def _post(res):
        if not verify_operational or mode == "static":
            return
        await _mark_vxlan_operational(res, targets, vxlan_interface)

    res = await _orchestrate("orchestrate_overlay", {d: _build(d) for d in targets}, apply,
                             post=_post)
    if skipped:
        res["skipped"] = skipped
    if mode in ("evpn", "stub") and not any(vmac.values()) and not res.get("status") == "error":
        res.setdefault("warnings", []).append(
            "no `virtual_mac` given — every VTEP except an Extended Edge needs one configured.")
    return res


# ══════════════════════════════════════════════════════════════════════
# Overlay service (batch): VLAN -> L2VNI -> EVPN route-target and/or static peer
# ══════════════════════════════════════════════════════════════════════

_ATTACH_MODES = ("evpn", "static", "stub")


def _norm_overlay_services(services):
    if not services:
        return None, _invalid("services", "`services` is required — a non-empty list of {vlan_id, vni, attach, ...}.")
    if not isinstance(services, list):
        return None, _invalid("services", "`services` must be a list of service dicts.")
    out = []
    for i, s in enumerate(services):
        if not isinstance(s, dict):
            return None, _invalid(f"services[{i}]", "Each service must be a dict.")
        if s.get("vlan_id") is None or s.get("vni") is None:
            return None, _invalid(f"services[{i}]", "Each service needs `vlan_id` and `vni`.")
        attach = s.get("attach", "evpn")
        if attach not in _ATTACH_MODES:
            return None, _invalid(f"services[{i}].attach", f"`attach` must be one of {_ATTACH_MODES}.")
        item = dict(s)
        item["vlan_id"] = int(item["vlan_id"])
        item["vni"] = int(item["vni"])
        item["attach"] = attach
        item["static_peers"] = [dict(p) for p in (item.get("static_peers") or [])]
        out.append(item)
    return out, None


@mcp.tool()
async def orchestrate_overlay_service(services: list, device: str = None, site: str = None,
                                      vxlan_interface: str = "vxlan1",
                                      require_vxlan_interface: bool = True,
                                      delete: bool = False, delete_vlans: bool = True,
                                      apply: bool = False) -> dict:
    """Provision/tear down a BATCH of L2 overlay services in ONE call per
    device set: for each entry in `services`, create_vlan -> create_l2vni ->
    attach per `attach`:

    - `attach='evpn'` (default): `set_evpn_vlan_rt` (rd/import_rts/export_rts,
      default 'auto') + optional SVI (`svi_vrf`/`svi_ip`/`active_gateway_ip`/
      `active_gateway_mac`). Normal Access-VTEP/Border service.
    - `attach='static'`: NO route-target (Extended Edge — never joins
      BGP-EVPN) + `static_peers`=[{destination, vnis (default: [this vni]),
      vrf}] (required).
    - `attach='stub'`: SAME as 'evpn' (fully EVPN-configured, incl. optional
      SVI) PLUS `static_peers` (required) for the SAME vni — the Stub VTEP
      case (bridges dynamic EVPN + a static tunnel to an Extended Edge, for
      this VNI). Requires the device's `vxlan_interface` to already be in
      `inter_vxlan_bridging_mode='static-evpn'` (see `orchestrate_overlay(
      mode='stub')`) — refused with a clear error otherwise.

    `services` = [{vlan_id, vni, name, description, attach, rd, import_rts,
    export_rts, route_target_auto_mode, svi_vrf, svi_ip, active_gateway_ip,
    active_gateway_mac, static_peers}]. `svi_ip` is one CIDR (same on every
    target, e.g. EVPN anycast) or a per-device mapping {"<device>": "<cidr>"}.
    By default (`require_vxlan_interface=
    true`) refuses with a clear error if `vxlan_interface` is absent on a
    target instead of silently creating it with unintended defaults — run
    `orchestrate_overlay` first. This is ONE transaction per device (like
    every orchestrator here): a failure on any one service ABORTS THE WHOLE
    BATCH for that device (auto-checkpoint reverts, consistent with every
    other orchestrator) — split into several calls if you want independent
    per-VLAN failure isolation. Idempotent re-run = update. Teardown:
    `delete=true` reverses every entry (static peers -> SVI -> RT -> L2VNI ->
    VLAN unless `delete_vlans=false`), in reverse order. `apply`=False = plan
    only."""
    targets = _safe_targets(device, site)
    if not targets:
        return {"status": "error", "error": "No resolved target device — provide `device` or `site`."}
    items, err = _norm_overlay_services(services)
    if err:
        return err
    checks = []
    for i, it in enumerate(items):
        checks.append((f"services[{i}].vlan_id", lambda _v=it["vlan_id"]: _v_vlan(_v, "vlan_id")))
        checks.append((f"services[{i}].vni", lambda _v=it["vni"]: _v_vni(_v, "vni")))
        for j, p in enumerate(it["static_peers"]):
            checks.append((f"services[{i}].static_peers[{j}].destination",
                           lambda _p=p: _v_ip_host(_p.get("destination"), "destination")))
        rd = it.get("rd", "auto")
        if rd not in (None, "auto"):
            checks.append((f"services[{i}].rd", lambda _r=rd: _v_route_target(_r, "rd")))
        for rk in ("import_rts", "export_rts"):
            for j, r in enumerate(_rt_list(it.get(rk), ["auto"])):
                if r != "auto":
                    checks.append((f"services[{i}].{rk}[{j}]", lambda _r=r, _rk=rk: _v_route_target(_r, _rk)))
        if isinstance(it.get("svi_ip"), dict):
            try:
                mapping = {_resolve_devices(device=k)[0]: v for k, v in it["svi_ip"].items()}
            except ValueError as exc:
                return {"status": "error", "error": str(exc)}
            missing = [d for d in targets if d not in mapping]
            if missing:
                return _invalid(f"services[{i}].svi_ip", f"mapping has no entry for {missing}.")
            it["svi_ip"] = mapping
            for d, v in mapping.items():
                checks.append((f"services[{i}].svi_ip[{d}]",
                               lambda _v=v: _v_ipv4_cidr(_v, "svi_ip")))
        elif it.get("svi_ip"):
            checks.append((f"services[{i}].svi_ip", lambda _v=it["svi_ip"]: _v_ipv4_cidr(_v, "svi_ip")))
        if it.get("active_gateway_ip"):
            checks.append((f"services[{i}].active_gateway_ip",
                           lambda _v=it["active_gateway_ip"]: _v_ip_host(_v, "active_gateway_ip")))
        if it.get("active_gateway_mac"):
            checks.append((f"services[{i}].active_gateway_mac",
                           lambda _v=it["active_gateway_mac"]: _v_mac(_v, "active_gateway_mac")))
    err = _precheck(checks)
    if err:
        return err
    for i, it in enumerate(items):
        for j, p in enumerate(it["static_peers"]):
            if not isinstance(p, dict) or not p.get("destination"):
                return _invalid(f"services[{i}].static_peers[{j}]", "Each peer needs a `destination`.")
        if it["attach"] in ("static", "stub") and not it["static_peers"]:
            return _invalid(f"services[{i}].static_peers",
                            f"attach='{it['attach']}' requires at least one static peer.")

    needs_stub = any(it["attach"] == "stub" for it in items)

    def _build(dev):
        steps = []
        if require_vxlan_interface or needs_stub:
            async def _check(c):
                info = await c.read_vxlan_interface(vxlan_interface)
                if require_vxlan_interface and not info.get("present"):
                    raise ArubaAPIError(
                        f"vxlan interface '{vxlan_interface}' absent — run "
                        "orchestrate_overlay first (nothing was written).", 400)
                if needs_stub and info.get("inter_vxlan_bridging_mode") != "static-evpn":
                    raise ArubaAPIError(
                        f"attach='stub' needs inter_vxlan_bridging_mode='static-evpn' "
                        f"on {vxlan_interface} (currently "
                        f"{info.get('inter_vxlan_bridging_mode')!r}) — run "
                        "orchestrate_overlay(mode='stub') first.", 400)
                return info
            steps.append(_step("check_vxlan_interface", _check, interface=vxlan_interface))
        for it in items:
            vlan_id, vni, attach = it["vlan_id"], it["vni"], it["attach"]
            steps.append(_step("create_vlan",
                               lambda c, _it=it: c.create_vlan(_it["vlan_id"], name=_it.get("name"),
                                                               description=_it.get("description")),
                               vlan=vlan_id, name=it.get("name")))
            steps.append(_step("create_l2vni",
                               lambda c, _it=it: c.create_l2vni(_it["vni"], _it["vlan_id"],
                                                                vxlan_interface=vxlan_interface),
                               vni=vni, vlan=vlan_id, interface=vxlan_interface))
            if attach in ("evpn", "stub"):
                imp = _rt_list(it.get("import_rts"), ["auto"])
                exp = _rt_list(it.get("export_rts"), ["auto"])
                rd = it.get("rd", "auto") or "auto"
                rtam = it.get("route_target_auto_mode")

                async def _rt(c, _vlan=vlan_id, _imp=imp, _exp=exp, _rd=rd, _rtam=rtam):
                    res = await c.set_evpn_vlan_rt(_vlan, _imp, _exp, rd=_rd)
                    if _rtam:
                        await c._put_merge(f"/system/evpn/evpn_vlans/{_vlan}",
                                           {"route_target_auto_mode": _rtam})
                        res["route_target_auto_mode"] = _rtam
                    return res
                steps.append(_step("set_evpn_vlan_rt", _rt, vlan=vlan_id, rd=rd,
                                   import_route_targets=imp, export_route_targets=exp))
                want_svi = bool(it.get("svi_vrf") or it.get("svi_ip") or it.get("active_gateway_ip"))
                if want_svi:
                    svi_vrf = it.get("svi_vrf") or "default"
                    my_ip = it.get("svi_ip")
                    if isinstance(my_ip, dict):
                        my_ip = my_ip.get(dev)
                    steps.append(_step("create_svi",
                                       lambda c, _it=it, _vrf=svi_vrf, _ip=my_ip: c.create_svi(
                                           _it["vlan_id"], _vrf, ip_cidr=_ip,
                                           active_gateway_ip=_it.get("active_gateway_ip"),
                                           active_gateway_mac=_it.get("active_gateway_mac")),
                                       vlan=vlan_id, vrf=svi_vrf, ip4_address=my_ip,
                                       active_gateway_ip=it.get("active_gateway_ip"),
                                       active_gateway_mac=it.get("active_gateway_mac")))
            for p in it["static_peers"]:
                vnis = [int(v) for v in (p.get("vnis") or [vni])]
                vrf = p.get("vrf") or "default"
                steps.append(_step("add_static_vxlan_peer",
                                   lambda c, _p=p, _vnis=vnis, _vrf=vrf: c.add_static_vxlan_peer(
                                       _p["destination"], _vnis, vxlan_interface=vxlan_interface, vrf=_vrf),
                                   destination=p["destination"], vnis=vnis, vrf=vrf,
                                   interface=vxlan_interface))
        return steps

    if delete:
        def _teardown(dev):
            steps = []
            for it in reversed(items):
                vlan_id, vni, attach = it["vlan_id"], it["vni"], it["attach"]
                for p in reversed(it["static_peers"]):
                    vrf = p.get("vrf") or "default"
                    steps.append(_step("remove_static_vxlan_peer",
                                       lambda c, _p=p, _vrf=vrf: c.remove_static_vxlan_peer(
                                           _p["destination"], vxlan_interface=vxlan_interface, vrf=_vrf),
                                       destination=p["destination"], vrf=vrf))
                if attach in ("evpn", "stub"):
                    want_svi = bool(it.get("svi_vrf") or it.get("svi_ip") or it.get("active_gateway_ip"))
                    if want_svi:
                        steps.append(_step("delete_svi", lambda c, _v=vlan_id: c.delete_svi(_v), vlan=vlan_id))
                    steps.append(_step("delete_evpn_vlan_rt", lambda c, _v=vlan_id: c.delete_evpn_vlan_rt(_v),
                                       vlan=vlan_id))
                steps.append(_step("delete_l2vni", lambda c, _v=vni: c.delete_l2vni(_v), vni=vni, vlan=vlan_id))
                if delete_vlans:
                    steps.append(_step("delete_vlan", lambda c, _v=vlan_id: c.delete_vlan(_v), vlan=vlan_id))
            return steps
        return await _orchestrate("orchestrate_overlay_service", {d: _teardown(d) for d in targets}, apply)

    async def _post(res):
        if any(it["attach"] in ("evpn", "stub") for it in items):
            await _mark_vxlan_operational(res, targets, vxlan_interface)

    return await _orchestrate("orchestrate_overlay_service", {d: _build(d) for d in targets}, apply,
                              post=_post)


# ══════════════════════════════════════════════════════════════════════
# RADIUS + 802.1X / MAC-auth end-to-end
# ══════════════════════════════════════════════════════════════════════

@mcp.tool()
async def orchestrate_radius_dot1x(device: str = None, site: str = None,
                                   radius_servers: list = None,
                                   server_group: str = "RADIUS",
                                   dot1x: bool = True, mac_auth: bool = True,
                                   coa: bool = True, coa_udp_port: int = None,
                                   accounting: bool = True,
                                   mac_auth_address_format: str = None,
                                   mac_auth_password: str = None,
                                   roles: list = None, interfaces=None,
                                   port_auth: dict = None,
                                   delete: bool = False, delete_roles: bool = True,
                                   apply: bool = False) -> dict:
    """End-to-end NAC bring-up in ONE call per device set: RADIUS server group
    -> RADIUS servers (with passkey, tracking, VRF) -> GLOBAL `aaa
    authentication port-access dot1x|mac-auth authenticator enable` bound to
    the group (+ accounting group) -> `radius dyn-authorization enable` (CoA)
    -> local port-access roles -> optional 802.1X/MAC-auth on `interfaces`
    (`port_auth` = configure_port_auth keys; defaults to the enabled methods
    with precedence dot1x then mac-auth).
    `radius_servers`: [{address, passkey, vrf (=mgmt), port (=1812),
    accounting_udp_port, timeout, retries, tracking_enable}]. `roles`: [{name,
    vlan_tag, description, ...}]. `interfaces` accepts list / CSV / ranges.
    Teardown: `delete=true` clears port-access on `interfaces`, deletes the
    roles (`delete_roles`), disables global dot1x/mac-auth/CoA, removes the
    servers then the group. `apply`=False = plan only."""
    targets = _safe_targets(device, site)
    if not targets:
        return {"status": "error", "error": "No resolved target device — provide `device` or `site`."}
    ports = _expand_interfaces(interfaces) if interfaces else []
    servers = radius_servers or []
    if not isinstance(servers, list) or any(not isinstance(s, dict) for s in servers):
        return _invalid("radius_servers", "`radius_servers` must be a list of {address, passkey, ...}.")
    err = _precheck([
        *[(f"radius_servers[{i}].address", lambda _s=s: _v_ip_host(_s.get("address"), "address"))
          for i, s in enumerate(servers)],
        *[(f"roles[{i}].vlan_tag", lambda _r=r: _v_vlan(_r.get("vlan_tag"), "vlan_tag"))
          for i, r in enumerate(roles or []) if isinstance(r, dict) and r.get("vlan_tag") is not None],
        ("coa_udp_port", lambda: _v_int_range(coa_udp_port, 1024, 49151, "coa_udp_port")
         if coa_udp_port is not None else None),
    ])
    if err:
        return err
    for i, r in enumerate(roles or []):
        if not isinstance(r, dict) or not r.get("name"):
            return _invalid(f"roles[{i}]", "Each role needs at least a `name`.")

    if delete:
        steps = []
        if ports:
            steps.append(_step("clear_port_auth", lambda c: _clear_port_auth(c, ports), interfaces=ports))
        if delete_roles:
            for r in (roles or []):
                steps.append(_step("delete_port_access_role",
                                   lambda c, n=r["name"]: c.delete_port_access_role(n), role=r["name"]))
        steps.append(_step("set_port_access_global",
                           lambda c: c.set_port_access_global(dot1x_enable=False, mac_auth_enable=False,
                                                              coa_enable=False),
                           dot1x_enable=False, mac_auth_enable=False, coa_enable=False))
        for s in servers:
            steps.append(_step("delete_radius_server",
                               lambda c, _s=s: c.delete_radius_server(
                                   _s["address"], vrf=_s.get("vrf", "mgmt"),
                                   port=int(_s.get("port", 1812)), port_type=_s.get("port_type", "udp")),
                               address=s["address"], vrf=s.get("vrf", "mgmt")))
        steps.append(_step("delete_aaa_server_group", lambda c: c.delete_aaa_server_group(server_group),
                           server_group=server_group))
        return await _orchestrate("orchestrate_radius_dot1x", {d: list(steps) for d in targets}, apply)

    if not servers:
        return _invalid("radius_servers", "At least one RADIUS server is required.")
    pa_kwargs = None
    if ports:
        pa = dict(port_auth or {})
        if not any(k in pa for k in ("methods", "dot1x", "mac_auth")):
            pa["methods"] = {m: True for m, on in (("dot1x", dot1x), ("mac-auth", mac_auth)) if on}
        pa.setdefault("auth_precedence", [m for m, on in (("dot1x", dot1x), ("mac-auth", mac_auth)) if on])
        pa_kwargs, err = _port_auth_kwargs(pa)
        if err:
            return err

    steps = [_step("ensure_aaa_server_group",
                   lambda c: c.ensure_aaa_server_group(server_group, group_type="radius"),
                   server_group=server_group, type="radius")]
    for s in servers:
        steps.append(_step("ensure_radius_server",
                           lambda c, _s=s: c.ensure_radius_server(
                               _s["address"], vrf=_s.get("vrf", "mgmt"), passkey=_s.get("passkey"),
                               port=int(_s.get("port", 1812)), port_type=_s.get("port_type", "udp"),
                               accounting_udp_port=_s.get("accounting_udp_port"),
                               auth_type=_s.get("auth_type"), timeout=_s.get("timeout"),
                               retries=_s.get("retries"), server_group={server_group: 1},
                               tracking_enable=_s.get("tracking_enable")),
                           address=s["address"], vrf=s.get("vrf", "mgmt"), port=int(s.get("port", 1812)),
                           server_group=server_group, tracking_enable=s.get("tracking_enable"),
                           passkey="***" if s.get("passkey") else None))
    steps.append(_step("set_port_access_global",
                       lambda c: c.set_port_access_global(
                           dot1x_enable=dot1x, dot1x_server_group=server_group if dot1x else None,
                           mac_auth_enable=mac_auth, mac_auth_server_group=server_group if mac_auth else None,
                           mac_auth_password=mac_auth_password,
                           mac_auth_address_format=mac_auth_address_format,
                           accounting_server_group=server_group if accounting else None,
                           coa_enable=coa, coa_udp_port=coa_udp_port),
                       dot1x_enable=dot1x, mac_auth_enable=mac_auth, server_group=server_group,
                       accounting=accounting, coa_enable=coa, coa_udp_port=coa_udp_port,
                       mac_auth_address_format=mac_auth_address_format))
    for r in (roles or []):
        steps.append(_step("create_port_access_role",
                           lambda c, _r=r: c.create_port_access_role(
                               _r["name"], vlan_tag=_r.get("vlan_tag"), vlan_name_tag=_r.get("vlan_name_tag"),
                               vlan_trunks=_r.get("vlan_trunks"), vlan_mode=_r.get("vlan_mode"),
                               description=_r.get("description"), gateway_zone=_r.get("gateway_zone"),
                               reauth_period=_r.get("reauth_period"),
                               captive_portal_profile=_r.get("captive_portal_profile"), extra=_r.get("extra")),
                           **{k: v for k, v in r.items() if k != "extra"}))
    if pa_kwargs:
        steps.append(_step("configure_port_auth", lambda c: _apply_port_auth(c, ports, **pa_kwargs),
                           interfaces=ports, **{k: v for k, v in pa_kwargs.items() if v is not None}))

    async def _exec_steps(dev, client):
        res = await _run_steps(dev, client, steps)
        failed: list = []
        for st in res["steps"]:
            if isinstance(st["result"], dict):
                failed.extend((st["result"].get("summary") or {}).get("failed_interfaces", []))
        if failed:
            res["summary"] = {"steps": len(res["steps"]), "failed": len(set(failed)),
                              "failed_interfaces": sorted(set(failed))}
        return res

    plan = {d: _plan_view(steps) for d in targets}
    return await _domain_write("orchestrate_radius_dot1x", targets, None, plan, _exec_steps, apply)
