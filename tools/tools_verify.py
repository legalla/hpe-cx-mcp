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


