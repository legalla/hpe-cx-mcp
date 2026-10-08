"""``verify_*`` read-back tools, each paired with a ``configure_*`` write tool
in tools_configure.py (whose ``_exec_on_devices`` helper is reused here)."""

from clients.aruba_client import _v_asn
from core.server_core import mcp, _resolve_devices, _close_sessions
from tools.tools_configure import _exec_on_devices

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
async def verify_hostname(device: str = None, site: str = None) -> dict:
    """Read back the configured hostname. Pair with configure_hostname."""
    return await _domain_verify(
        "verify_hostname", device, site,
        lambda dev, client: client.read_hostname())


@mcp.tool()
async def verify_access_port(interfaces, device: str = None, site: str = None) -> dict:
    """Read back access ports (L2 mode/VLANs, admin, STP edge/guards, 802.1X /
    MAC-auth config). `interfaces`: list / CSV / range. Pair with
    orchestrate_access_port."""
    from tools.tools_configure import _expand_interfaces
    ports = _expand_interfaces(interfaces)
    if not ports:
        return {"status": "error", "error": "`interfaces` is required."}

    async def _read(dev, client):
        return {"interfaces": [await client.read_access_port(p) for p in ports]}

    return await _domain_verify("verify_access_port", device, site, _read)


@mcp.tool()
async def verify_evpn_vlan(vlan_id: int, vni: int = None, device: str = None,
                           site: str = None) -> dict:
    """Read back an EVPN VLAN service: VLAN, L2VNI mapping (`vni` or found by
    VLAN), `evpn vlan` RD / import / export route-targets, SVI (VRF, IP,
    active-gateway). Pair with orchestrate_evpn_vlan."""
    from urllib.parse import quote

    async def _read(dev, client):
        out = {"vlan_id": vlan_id}
        vlan = await client._get_config(f"/system/vlans/{vlan_id}", depth=1)
        out["vlan"] = {"present": vlan is not None,
                       "name": (vlan or {}).get("name"), "admin": (vlan or {}).get("admin")}
        l2vni = None
        if vni is not None:
            l2vni = await client._get_config(
                f"/system/virtual_network_ids/{quote(f'vxlan_vni,{vni}', safe='')}", depth=1)
        else:
            coll = await client._get_config("/system/virtual_network_ids", depth=2) or {}
            for key, v in (coll.items() if isinstance(coll, dict) else []):
                if isinstance(v, dict) and client._ref_name(v.get("vlan")) == str(vlan_id):
                    l2vni = dict(v, id=v.get("id") or key.split(",")[-1])
                    break
        out["l2vni"] = {"present": l2vni is not None,
                        "vni": (l2vni or {}).get("id", vni),
                        "vxlan_interface": client._ref_name((l2vni or {}).get("interface"))}
        ev = await client._get_config(f"/system/evpn/evpn_vlans/{vlan_id}", depth=1)
        out["evpn"] = {"present": ev is not None, "rd": (ev or {}).get("rd"),
                       "import_route_targets": (ev or {}).get("import_route_targets"),
                       "export_route_targets": (ev or {}).get("export_route_targets"),
                       "route_target_auto_mode": (ev or {}).get("route_target_auto_mode")}
        svi = await client._get_config(f"/system/interfaces/vlan{vlan_id}", depth=2)
        out["svi"] = {"present": svi is not None,
                      "vrf": client._ref_name((svi or {}).get("vrf")) or ("default" if svi else None),
                      "ip4_address": (svi or {}).get("ip4_address"),
                      "active_gateway_ip": (svi or {}).get("vsx_virtual_ip4"),
                      "active_gateway_mac": (svi or {}).get("vsx_virtual_gw_mac_v4")}
        return out

    return await _domain_verify("verify_evpn_vlan", device, site, _read)


@mcp.tool()
async def verify_static_vxlan(device: str = None, site: str = None,
                              vxlan_interface: str = "vxlan1") -> dict:
    """Read back a static-VXLAN VTEP: source IP, UDP port, inter-VXLAN bridging
    mode, static peers with their VNIs, and every VLAN<->L2VNI mapping bound to
    `vxlan_interface`. Pair with orchestrate_static_vxlan."""
    async def _read(dev, client):
        out = await client.read_vxlan_interface(vxlan_interface)
        coll = await client._get_config("/system/virtual_network_ids", depth=2) or {}
        maps = []
        for key, v in (coll.items() if isinstance(coll, dict) else []):
            if not isinstance(v, dict) or v.get("type", "vxlan_vni") != "vxlan_vni":
                continue
            if client._ref_name(v.get("interface")) not in (None, vxlan_interface):
                continue
            maps.append({"vni": v.get("id") or key.split(",")[-1],
                         "vlan": client._ref_name(v.get("vlan"))})
        out["l2vni_mappings"] = sorted(maps, key=lambda m: int(m["vni"]) if str(m["vni"]).isdigit() else 0)
        return out

    return await _domain_verify("verify_static_vxlan", device, site, _read)


@mcp.tool()
async def verify_overlay(device: str = None, site: str = None,
                         vxlan_interface: str = "vxlan1") -> dict:
    """Read back a device's overlay bring-up: VXLAN interface (source IP, UDP
    port, inter_vxlan_bridging_mode), global EVPN config, and the virtual
    system-MAC. Pair with orchestrate_overlay."""
    async def _read(dev, client):
        return {"vxlan": await client.read_vxlan_interface(vxlan_interface),
                "evpn": await client.read_evpn(),
                "virtual_mac": await client.read_virtual_mac()}

    return await _domain_verify("verify_overlay", device, site, _read)


@mcp.tool()
async def verify_overlay_service(services: list, device: str = None, site: str = None,
                                 vxlan_interface: str = "vxlan1") -> dict:
    """Read back a BATCH of L2 overlay services: for each `services` entry
    ({vlan_id, vni}), VLAN presence, L2VNI mapping, EVPN route-target (RD /
    import / export), SVI, and the static peers configured for that VNI on
    `vxlan_interface`. Pair with orchestrate_overlay_service."""
    from urllib.parse import quote

    if not services or not isinstance(services, list):
        return {"status": "error", "error": "`services` must be a non-empty list of {vlan_id, vni}."}

    async def _read(dev, client):
        vxlan = await client.read_vxlan_interface(vxlan_interface)
        peers_by_vni: dict = {}
        for p in vxlan.get("static_peers", []):
            for vni in p.get("vnis", []):
                peers_by_vni.setdefault(int(vni), []).append(p["destination"])
        out = []
        for s in services:
            vlan_id, vni = s.get("vlan_id"), s.get("vni")
            entry = {"vlan_id": vlan_id, "vni": vni}
            vlan = await client._get_config(f"/system/vlans/{vlan_id}", depth=1)
            entry["vlan"] = {"present": vlan is not None, "name": (vlan or {}).get("name")}
            l2vni = await client._get_config(
                f"/system/virtual_network_ids/{quote(f'vxlan_vni,{vni}', safe='')}", depth=1)
            entry["l2vni"] = {"present": l2vni is not None,
                              "vxlan_interface": client._ref_name((l2vni or {}).get("interface"))}
            ev = await client._get_config(f"/system/evpn/evpn_vlans/{vlan_id}", depth=1)
            entry["evpn"] = {"present": ev is not None, "rd": (ev or {}).get("rd"),
                             "import_route_targets": (ev or {}).get("import_route_targets"),
                             "export_route_targets": (ev or {}).get("export_route_targets")}
            svi = await client._get_config(f"/system/interfaces/vlan{vlan_id}", depth=2)
            entry["svi"] = {"present": svi is not None,
                            "vrf": client._ref_name((svi or {}).get("vrf")) if svi else None,
                            "ip4_address": (svi or {}).get("ip4_address")}
            entry["static_peers"] = peers_by_vni.get(int(vni), [])
            out.append(entry)
        return {"vxlan_interface": {k: vxlan.get(k) for k in
                                    ("present", "source_ip", "inter_vxlan_bridging_mode")},
                "services": out}

    return await _domain_verify("verify_overlay_service", device, site, _read)


@mcp.tool()
async def verify_radius_dot1x(device: str = None, site: str = None,
                              vrf: str = "mgmt") -> dict:
    """Read back the global port-access AAA state (dot1x / mac-auth enable +
    server groups, accounting group, RADIUS CoA) and the RADIUS servers in
    `vrf`. Pair with orchestrate_radius_dot1x."""
    async def _read(dev, client):
        out = await client.read_port_access_global()
        out["radius_servers"] = await client.list_radius_servers(vrf=vrf)
        return out

    return await _domain_verify("verify_radius_dot1x", device, site, _read)


@mcp.tool()
async def verify_vsx_cluster(device: str, peer_device: str = None,
                             site: str = None) -> dict:
    """Operational + configured VSX state on BOTH members (roles, ISL/keepalive
    state, config-sync, system-mac consistency). Pair with orchestrate_vsx_pair."""
    try:
        devs = list(dict.fromkeys(_resolve_devices(device=device)
                                  + (_resolve_devices(device=peer_device) if peer_device else [])))
    except ValueError as exc:
        return {"status": "error", "error": str(exc)}

    async def _read(dev, client):
        status = await client.get_vsx_status()
        cfg = await client.read_vsx()
        return {"config": cfg, "status": {k: status.get(k) for k in (
            "configured", "overall_state", "device_role", "isl_protocol_state",
            "isl_link_state", "keepalive_state", "config_sync_state", "system_mac")}}

    res = await _domain_verify("verify_vsx_cluster", devs, None, _read)
    macs = {d: (r.get("result") or {}).get("config", {}).get("system_mac")
            for d, r in res.get("results", {}).items() if r.get("ok")}
    roles = {d: (r.get("result") or {}).get("config", {}).get("device_role")
             for d, r in res.get("results", {}).items() if r.get("ok")}
    res["consistent"] = (len(set(macs.values())) <= 1
                         and sorted(v for v in roles.values() if v) in ([], ["primary"], ["secondary"], ["primary", "secondary"]))
    if len(devs) == 2 and sorted(v for v in roles.values() if v) != ["primary", "secondary"]:
        res["warning"] = f"roles are not primary/secondary: {roles}"
    if len(set(macs.values())) > 1:
        res["warning"] = f"system_mac differs between peers: {macs}"
    return res


@mcp.tool()
async def verify_lag(lag: str = None, device: str = None, site: str = None) -> dict:
    """Verify a LAG (read-back): mode (static/lacp-active/lacp-passive),
    members + LACP flags, mclag_enabled, EVPN multihoming ESI. Pair with
    configure_lag. `lag` optional (e.g. 'lag1') — omit for all LAGs."""
    return await _domain_verify(
        "verify_lag", device, site,
        lambda dev, client: client.get_lag(lag))


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
# TOOLS — Atomic L2 primitives / static routing / VSX (read-back)
# ══════════════════════════════════════════════════════════════════════

@mcp.tool()
async def verify_vlan(vlan_id: int, device: str = None, site: str = None) -> dict:
    """Verify a bare VLAN definition. Pair with configure_vlan."""
    return await _domain_verify(
        "verify_vlan", device, site,
        lambda dev, client: client.read_vlan(vlan_id))


@mcp.tool()
async def verify_svi(vlan_id: int, device: str = None, site: str = None) -> dict:
    """Verify an SVI (interface vlan<id>): VRF, IP, active-gateway. Pair with
    configure_svi."""
    return await _domain_verify(
        "verify_svi", device, site,
        lambda dev, client: client.read_svi(vlan_id))


@mcp.tool()
async def verify_trunk(interface: str, device: str = None, site: str = None) -> dict:
    """Verify the tagged-VLAN set (vlan_trunks) of a trunk interface. Pair with
    configure_trunk."""
    return await _domain_verify(
        "verify_trunk", device, site,
        lambda dev, client: client.read_trunk(interface))


@mcp.tool()
async def verify_interface_admin(interface: str, device: str = None,
                                 site: str = None) -> dict:
    """Verify the admin state of a plain interface. Pair with
    configure_interface_admin."""
    return await _domain_verify(
        "verify_interface_admin", device, site,
        lambda dev, client: client.read_interface_admin(interface))


@mcp.tool()
async def verify_static_route(prefix: str, device: str = None, site: str = None,
                              vrf: str = "default") -> dict:
    """Verify a static route and its nexthops. Pair with configure_static_route."""
    vrf = vrf or "default"
    return await _domain_verify(
        "verify_static_route", device, site,
        lambda dev, client: client.read_static_route(prefix, vrf=vrf))


@mcp.tool()
async def verify_redistribute(protocol: str, device: str = None, site: str = None,
                              vrf: str = "default", asn: int = None,
                              instance_tag: int = 1) -> dict:
    """Verify route redistribution into BGP ('bgp', needs `asn`) or OSPF
    ('ospf'). Pair with configure_redistribute."""
    vrf = vrf or "default"
    if protocol == "bgp":
        return await _domain_verify(
            "verify_redistribute", device, site,
            lambda dev, client: client.read_bgp_redistribute(asn, vrf=vrf))
    return await _domain_verify(
        "verify_redistribute", device, site,
        lambda dev, client: client.read_ospf_redistribute(instance_tag, vrf=vrf))


@mcp.tool()
async def verify_vsx(device: str = None, site: str = None) -> dict:
    """Verify VSX pairing configuration (role, ISL/keepalive ports, system-mac).
    Pair with configure_vsx."""
    return await _domain_verify(
        "verify_vsx", device, site,
        lambda dev, client: client.read_vsx())


@mcp.tool()
async def verify_dhcp_relay(interface: str, device: str = None, site: str = None,
                            vrf: str = "default") -> dict:
    """Verify the DHCP relay (helper-address) config on an L3 port/SVI. Pair
    with configure_dhcp_relay."""
    vrf = vrf or "default"
    return await _domain_verify(
        "verify_dhcp_relay", device, site,
        lambda dev, client: client.read_dhcp_relay(interface, vrf=vrf))


@mcp.tool()
async def verify_interface_group(group: str, device: str = None, site: str = None,
                                 subsystem: str = None) -> dict:
    """Verify an interface group's speed settings (configured / applied /
    default + supported speeds). Pair with configure_interface_group."""
    return await _domain_verify(
        "verify_interface_group", device, site,
        lambda dev, client: client.read_interface_group(group, subsystem=subsystem))


