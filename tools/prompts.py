"""Reusable ArubaOS-CX diagnostic prompt templates."""

from core.server_core import mcp

# ══════════════════════════════════════════════════════════════════════
# PROMPTS — reusable ArubaOS-CX diagnostic templates
# ══════════════════════════════════════════════════════════════════════

@mcp.prompt()
def diagnostic_equipement(device: str) -> str:
    """Full health check of an ArubaOS-CX switch."""
    return (
        f"Perform a full health check of the switch '{device}'.\n\n"
        "Steps:\n"
        f"1. Retrieve the system info with get_system(device='{device}', scope='info') "
        "(model, firmware version, uptime, CPU/memory).\n"
        f"2. Check the interface status with get_interfaces(device='{device}', "
        "scope='physical'): spot the down/err-disabled interfaces, the errors and drops.\n"
        f"3. List the VLANs (get_switching(device='{device}', scope='vlans')) and the "
        "spanning-tree (get_switching(scope='spanning_tree')) to detect blocked ports.\n"
        f"4. Inspect the latest logs with get_logs('{device}', priority='0-3') "
        "for critical events.\n"
        "5. Summarize the status in a table (component, status, observation) "
        "and list the points of attention ranked by criticality.\n"
        f"Tip: diagnose(device='{device}', scope='device') returns steps 1-4 in one call."
    )


@mcp.prompt()
def troubleshoot_routing(device: str, vrf: str = "default") -> str:
    """Diagnose the dynamic routing (BGP + OSPF) of a switch."""
    return (
        f"Diagnose the dynamic routing of the switch '{device}' in the VRF '{vrf}'.\n\n"
        f"1. BGP: get_routing(device='{device}', scope='bgp_summary', vrf='{vrf}') then "
        "scope='bgp_config' and scope='bgp_routes'. Spot the neighbors that are not in "
        "Established state and explain why (ASN, timers, prefixes received/advertised).\n"
        f"2. OSPF: get_routing(device='{device}', scope='ospf_overview', vrf='{vrf}') then "
        "scope='ospf_neighbors' and scope='ospf_interfaces'. Spot the stuck adjacencies "
        "(Init/2-Way/ExStart) and the misconfigured interfaces (area, network type, MTU).\n"
        f"3. Cross-check with get_routing(device='{device}', scope='route_table', vrf='{vrf}') "
        "to verify that the expected prefixes are properly installed.\n"
        "4. Conclude with a clear diagnosis and the recommended corrective actions."
    )


@mcp.prompt()
def troubleshoot_client_8021x(device: str, interface: str = "") -> str:
    """Troubleshoot an 802.1X / MAC-Auth client (port-access)."""
    cible = f"interface '{interface}'" if interface else "the interfaces involved"
    arg_if = f", interface='{interface}'" if interface else ""
    return (
        f"A client cannot authenticate on the switch '{device}' on {cible}.\n\n"
        f"1. Overview: get_access(device='{device}', scope='summary') then "
        f"get_access(device='{device}', scope='clients'{arg_if}) to spot the failing clients.\n"
        "2. For each failing client, call get_access(scope='client_detail', interface=..., "
        "mac=...) (assigned VLAN, role, RADIUS attributes, EAP method, failure reason).\n"
        f"3. Check the reachability of the servers: get_access(device='{device}', scope='radius') "
        f"and get_access(device='{device}', scope='authentication') (group order per session type).\n"
        f"4. Consult get_access(scope='roles') and get_access(scope='policies') on '{device}' "
        "to validate that the returned role/policy exists and is consistent.\n"
        "5. Give the probable root cause (unreachable server, wrong role, "
        "nonexistent VLAN, EAP failure…) and the fix."
    )


@mcp.prompt()
def verifier_evpn_vxlan(device: str) -> str:
    """Verify the EVPN/VXLAN fabric on a switch."""
    return (
        f"Check the health of the EVPN/VXLAN overlay on the switch '{device}'.\n\n"
        f"1. get_overlay(device='{device}', scope='vxlan_config') and scope='vxlan_tunnels': "
        "check the VTEPs, the VNIs and the tunnel status (up/down).\n"
        f"2. get_overlay(device='{device}', scope='evpn_config'): validate the VNIs, the "
        "RD/RT and the mapped VLANs.\n"
        f"3. get_overlay(device='{device}', scope='evpn_routes'): verify the presence of the "
        "expected type-2 (MAC/IP) and type-3 (IMET) routes; flag the VNIs without a route.\n"
        f"4. Cross-check with get_routing(device='{device}', scope='bgp_neighbors') for the EVPN AF.\n"
        "5. Summarize the fabric status and the anomalies (tunnel down, orphan VNI, "
        "missing route).\n"
        f"Tip: diagnose(device='{device}', scope='evpn') runs steps 1-4 in one call."
    )


@mcp.prompt()
def localiser_client(device: str, mac: str = "") -> str:
    """Locate a MAC address / a client in the L2 network."""
    arg_mac = f" Search in particular for the MAC '{mac}'." if mac else ""
    return (
        f"Locate a client on the switch '{device}'.{arg_mac}\n\n"
        f"1. get_switching(device='{device}', scope='mac') to find the port and the VLAN of the MAC.\n"
        f"2. get_routing(device='{device}', scope='arp') to associate the MAC with an IP address.\n"
        f"3. get_switching(device='{device}', scope='lldp') to identify the neighbor device "
        "connected to the port (if it is another switch/AP).\n"
        f"4. If the client is authenticated, complete with get_access(device='{device}', "
        "scope='clients') for the role and the 802.1X status.\n"
        "5. Present the result: MAC, IP, port, VLAN, LLDP neighbor, role.\n"
        f"Tip: diagnose(device='{device}', scope='client') runs steps 1-4 in one call."
    )


@mcp.prompt()
def audit_configuration(device: str) -> str:
    """Audit the configuration and AAA access of a switch."""
    return (
        f"Perform a configuration and security audit of the switch '{device}'.\n\n"
        f"1. Retrieve the running-config with get_config(device='{device}', scope='running').\n"
        f"2. Examine the AAA: get_access(device='{device}', scope='authentication'), "
        f"scope='radius' and scope='tacacs' (reachable servers, order, fallback).\n"
        f"3. List the available checkpoints with get_config(device='{device}', scope='list') "
        "and offer to compare running-config / startup-config (scope='compare').\n"
        "4. Identify the deviations from best practices (unnecessary services, "
        "missing AAA fallback, default VLAN, identifiable weak passwords).\n"
        "5. Provide an audit report with prioritized recommendations."
    )
