"""Write (``configure_*``) tools: idempotent plan/apply domain configuration,
each paired with a ``verify_*`` read-back tool in tools_verify.py."""

import asyncio
import re

from clients.aruba_client import (
    ArubaAPIError, _v_mac, _v_ipv4_host, _v_ip_host, _v_ipv4_cidr, _v_int_range,
    _v_vlan, _v_vni, _v_mtu, _v_asn, _v_route_target, _v_ospf_area,
)
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


