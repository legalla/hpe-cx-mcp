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


@mcp.prompt()
def hardening_compliance_check(device: str) -> str:
    """Audit a switch against the official AOS-CX 10.17 Hardening Guide."""
    return (
        f"Check whether the switch '{device}' is configured compliant with the "
        "official AOS-CX 10.17 Hardening Guide, and if not, list exactly what "
        "is missing (with the CLI command to fix it).\n\n"
        f"1. Pull the CLI running-config once: get_config(device='{device}', "
        "scope='running'). It is the primary evidence source for most domains "
        "below — search its text for the keywords listed.\n"
        "2. Mgmt/physical: 'ssh server vrf' / 'https-server vrf' (mgmt-VRF "
        "scoping), 'telnet' enabled anywhere (must be disabled/absent), "
        "'front-panel-security factory-reset' (should be absent/disabled), "
        "'no usb' or 'bluetooth disable' (should be present when unused).\n"
        f"3. AAA: get_access(device='{device}', scope='authentication'/'radius'/"
        "'tacacs'/'accounting') for the structured view, plus grep for "
        "'aaa authentication login-attempts' (lockout), 'aaa authorization "
        "commands', 'radius-server auth-type chap'/'tacacs-server auth-type "
        "chap' (CHAP > PAP), 'radius-server host ... tls' (RadSec preferred).\n"
        f"4. SSH: get_system(device='{device}', scope='ssh') plus grep 'ssh "
        "server allow-list', 'ssh ciphers'/'ssh macs' (only if NDcPP required), "
        "'user ... authorized-key' (pubkey auth in use).\n"
        "5. Session/shell: grep 'cli-session' (max-per-user/timeout/"
        "tracking-range) and a start-shell deny rule or enhanced secure mode.\n"
        "6. SNMP: grep 'snmp-server community' (flag public/private-looking "
        "strings), 'snmp-server snmpv3-only' (should be present), "
        "'snmpv3 user ... auth ... priv ...'.\n"
        "7. Control-plane ACLs: grep 'apply access-list ip ... control-plane "
        "vrf ...' — required especially on platforms with no mgmt VRF.\n"
        "8. Time: grep 'ntp authentication', 'ntp authentication-key ... md5', "
        "'ntp server ... prefer'.\n"
        "9. PKI/TLS: grep 'crypto pki certificate', 'tls check-key-usage' "
        "(should be on).\n"
        f"10. Logging: grep 'logging ... vrf' + 'include-auditable-events', "
        f"cross-check with get_logs(device='{device}', limit=20).\n"
        "11. CoPP: grep for a custom 'copp-policy ... / apply copp-policy ...' "
        "(absence isn't a gap by itself — the factory default is always active "
        "— but mark 'unreviewed' if no one tuned it).\n"
        f"12. L2: get_switching(device='{device}', scope='spanning_tree') plus "
        "grep 'spanning-tree bpdu-guard'/'root-guard', 'dhcpv4-snooping'/"
        "'dhcpv6-snooping' (+ 'trust'/'authorized-server'), 'arp inspection' "
        "(+ 'trust'), 'nd-snooping'/'ra-guard'/'destination-guard'/"
        "'source-lockdown'. Flag any access VLAN with DHCP clients but no "
        "DHCP snooping/ARP inspection.\n"
        "13. Routing: grep 'passive-interface default' + 'ip ospf "
        "authentication hmac-sha-512' (OSPF), 'neighbor <ip> password' + "
        "'neighbor <ip> ttl-security-hops' (BGP MD5/GTSM); cross-check with "
        f"get_routing(device='{device}', scope='bgp_config'/'ospf_overview').\n"
        "14. Multicast (if relevant): grep 'accept-register access-list', "
        "'accept-rp ... access-list', 'router msdp' + 'password'.\n"
        f"15. NAE scripts: get_automation(device='{device}', "
        "scope='nae_scripts') — check for copp.5.1, "
        "stp_bpdu_tcn_rate_monitor.2.0, arp_request_monitor.2.0.\n\n"
        "Report a table (domain | compliant/gap/unknown | evidence | exact "
        "remediation command), then a prioritized remediation list (Telnet/"
        "AAA/SNMP-community gaps first, then SSH/logging/NTP, then L2, then "
        "routing/multicast). Mark a domain 'unknown' rather than 'compliant' "
        "when the running-config doesn't settle it and no dedicated scope "
        "exists (enhanced secure mode, live CoPP counters). See the "
        "aoscx-hardening-compliance skill for full detail."
    )


# ══════════════════════════════════════════════════════════════════════
# Data Center
# ══════════════════════════════════════════════════════════════════════

@mcp.prompt()
def fabric_health_check(site: str) -> str:
    """Site-wide DC fabric health check (spines + leafs, overlay, redundancy)."""
    return (
        f"Produce a site-wide health check of the DC fabric at site '{site}'.\n\n"
        f"1. diagnose(site='{site}', scope='device') — system + interfaces + "
        "vlans + recent logs for every switch in one batched call.\n"
        f"2. get_overlay(site='{site}', scope='vxlan_tunnels') and "
        "scope='evpn_routes' — flag any VTEP with a down tunnel, or a VNI "
        "missing its expected type-2/type-3 routes.\n"
        f"3. get_redundancy(site='{site}', scope='vsx_status') — flag any pair "
        "not in sync or with a degraded keepalive.\n"
        f"4. get_routing(site='{site}', scope='bgp_summary') — flag any "
        "underlay/overlay BGP session not Established.\n"
        "5. Summarize per-device and fabric-wide verdicts (healthy / degraded / "
        "critical) with the most impactful issues first."
    )


@mcp.prompt()
def provision_vlan_service_guide(device: str, vlan_id: int = 0) -> str:
    """Guided plan -> apply -> verify walkthrough for a new VLAN service."""
    vlan_hint = f" for VLAN {vlan_id}" if vlan_id else ""
    return (
        f"Guide me through provisioning a new VLAN service{vlan_hint} on "
        f"'{device}' (a single device, several as a comma-separated string, "
        "or a whole site).\n\n"
        "1. Ask me for anything missing: vlan_id, name, VNI (fabric/EVPN "
        "deployments only), svi_ip/gateway, vrf, and the interfaces/uplinks "
        "to attach.\n"
        f"2. Preview the plan: configure_service(device='{device}', "
        "scope='vlan', action='plan', params={...}) — show me exactly what "
        "will be created (VLAN, L2VNI, EVPN route-target, SVI, trunk "
        "assignments) before touching anything.\n"
        "3. After I confirm, apply it: same call with action='apply'.\n"
        "4. Verify the result: action='verify' (and cross-check with "
        f"get_switching(device='{device}', scope='vlans', vlan_id={vlan_id or 'vlan_id'})).\n"
        "5. If anything went wrong mid-apply, note that create_vlan_service "
        "auto-rolls-back objects it created on that device before reporting "
        "the failure — tell me what was rolled back."
    )


@mcp.prompt()
def verify_vsx_pair(device_a: str, device_b: str) -> str:
    """Cross-check both members of a VSX pair for consistency."""
    return (
        f"Verify the VSX pair formed by '{device_a}' and '{device_b}'.\n\n"
        f"1. get_redundancy(device='{device_a},{device_b}', scope='vsx_status') "
        "— both members should report the same role pairing (primary/"
        "secondary) and an 'in sync' state, with no split-brain indication.\n"
        "2. scope='vsx_config' on both — the ISL/keepalive configuration "
        "(interfaces, VLAN, IP) must be consistent between peers; flag any "
        "mismatch.\n"
        "3. scope='vsx_sync' — confirm config-sync is current, not showing a "
        "stale/aborted synchronization.\n"
        "4. Cross-check that the keepalive runs over a dedicated/OOB link, "
        "not a shared data VLAN (best practice — a data-plane outage should "
        "never also take out the keepalive).\n"
        "5. Summarize: consistent/inconsistent, and the exact fields that "
        "differ if inconsistent."
    )


@mcp.prompt()
def capacity_and_license_review(device: str) -> str:
    """Capacity, feature-pack licensing and container review for a device or site."""
    return (
        f"Review the capacity and licensing status of '{device}' (a device, "
        "comma-separated list, or a whole site).\n\n"
        f"1. get_system(device='{device}', scope='capacity') — flag any "
        "resource near its scale limit (utilization_pct close to 100%).\n"
        f"2. get_system(device='{device}', scope='feature_pack') — confirm "
        "the licensing state (valid/expired/central_disconnected/…) and list "
        "any feature running in 'honor' mode that should be properly "
        "licensed.\n"
        f"3. get_system(device='{device}', scope='containers') — list any "
        "on-switch application container and its enabled/status.\n"
        "4. Summarize per device: resources close to exhaustion, license "
        "issues, and any container that shouldn't be running."
    )


# ══════════════════════════════════════════════════════════════════════
# Campus
# ══════════════════════════════════════════════════════════════════════

@mcp.prompt()
def rollout_8021x_guide(device: str, interfaces: str = "") -> str:
    """Guided plan -> apply -> verify rollout of 802.1X/MAC-Auth port access."""
    on_ifaces = f" on interfaces '{interfaces}'" if interfaces else ""
    return (
        f"Guide me through rolling out 802.1X/MAC-Auth port access on "
        f"'{device}'{on_ifaces}.\n\n"
        f"1. Check the AAA backend is reachable first: get_access(device="
        f"'{device}', scope='radius') and scope='tacacs' — do not proceed if "
        "no server is reachable, this would lock users out.\n"
        f"2. Ask me for anything missing: authentication methods (dot1x/"
        "mac-auth), role bindings (auth/fallback/guest/critical/"
        "critical_voice/reject), and whether new user-roles need creating.\n"
        f"3. Preview the plan: configure_security(device='{device}', "
        "scope='port_auth', action='plan', params={interfaces: [...], "
        "methods: {...}, ...}).\n"
        "4. After I confirm, apply it: action='apply'.\n"
        "5. Verify: action='verify', and cross-check live client state with "
        f"get_access(device='{device}', scope='clients').\n"
        "6. Warn me explicitly before applying to a port that is currently "
        "up with a connected client — this WILL cause a re-authentication."
    )


@mcp.prompt()
def poe_budget_check(device: str) -> str:
    """PoE power budget audit across access switches."""
    return (
        f"Audit the PoE power budget on '{device}' (a device, comma-"
        "separated list, or a whole site).\n\n"
        f"1. get_interfaces(device='{device}', scope='poe') — per-port draw "
        "(watts) plus the chassis-wide PoE power budget.\n"
        "2. Flag any chassis close to its total PoE budget (little headroom "
        "left for new devices).\n"
        "3. Flag any port drawing 0W that is expected to power a device "
        "(e.g. an AP or phone per naming/description), and any port drawing "
        "unexpectedly high wattage.\n"
        "4. Summarize per switch: total budget, used, headroom, and any "
        "port-level anomaly."
    )


@mcp.prompt()
def campus_topology_audit(site: str) -> str:
    """Site-wide LLDP-based topology discovery and anomaly detection."""
    return (
        f"Map the physical topology of the campus site '{site}' via LLDP.\n\n"
        f"1. get_switching(site='{site}', scope='lldp') — collect the LLDP "
        "neighbor table for every switch in the site in one batched call.\n"
        "2. Build the switch-to-switch and switch-to-AP adjacency map from "
        "the neighbor entries.\n"
        "3. Flag anomalies: a port expected to face another switch/AP that "
        "reports no LLDP neighbor, an unexpected neighbor (a device that "
        "doesn't belong on that port), or a neighbor seen on more ports "
        "than expected (possible loop/mis-cable).\n"
        "4. Present the topology as a table (device, port, neighbor device, "
        "neighbor port) and call out the anomalies separately."
    )


@mcp.prompt()
def guest_network_audit(device: str) -> str:
    """Audit guest/BYOD access policies for inconsistent role bindings."""
    return (
        f"Audit the guest/BYOD network access configuration on '{device}'.\n\n"
        f"1. get_access(device='{device}', scope='roles') — list the "
        "available user-roles and their VLAN/ACL bindings.\n"
        f"2. get_access(device='{device}', scope='gbp') and scope='gbp_maps' "
        "— Group-Based Policy groups and their role mappings.\n"
        f"3. get_access(device='{device}', scope='abp') — Application-Based "
        "Policy bindings.\n"
        f"4. get_access(device='{device}', scope='policies') — confirm the "
        "guest/BYOD role references an existing, restrictive policy (not "
        "accidentally inheriting a broad/default one).\n"
        "5. Flag any role that grants more access than a guest/BYOD network "
        "should have (e.g. reachability to internal management VLANs), and "
        "any policy referenced by a role but not actually defined."
    )


# ══════════════════════════════════════════════════════════════════════
# Cross-domain (DC + Campus)
# ══════════════════════════════════════════════════════════════════════

@mcp.prompt()
def pre_change_safety_guide(device: str) -> str:
    """Checkpoint-before-change workflow with compare/restore safety net."""
    return (
        f"Guide me through making a safe configuration change on '{device}'.\n\n"
        f"1. Create a checkpoint before anything changes: manage_config("
        f"device='{device}', action='create_checkpoint', name=<a descriptive "
        "name, e.g. 'pre_change_YYYYMMDD'>).\n"
        "2. Ask me what change I want to make, then perform it using the "
        "appropriate configure_* tool (plan first, apply only after I "
        "confirm the plan).\n"
        f"3. After applying, compare against the checkpoint: manage_config("
        f"device='{device}', action='diff', config_a=<checkpoint name>, "
        "config_b='running-config') — show me exactly what changed.\n"
        "4. If I'm not satisfied with the result, offer to restore: "
        f"manage_config(device='{device}', action='restore_checkpoint', "
        "name=<checkpoint name>, target='running-config') — confirm with me "
        "before restoring, this reverts the change.\n"
        "5. If I'm satisfied, remind me the checkpoint persists (no delete "
        "API exists) and offer write_memory (copy running->startup) if the "
        "change should survive a reboot."
    )


@mcp.prompt()
def spanning_tree_loop_check(site: str) -> str:
    """Site-wide STP state check cross-referenced with LLDP to spot loops."""
    return (
        f"Check for spanning-tree issues (blocking ports, loops, instability) "
        f"across the site '{site}'.\n\n"
        f"1. get_switching(site='{site}', scope='spanning_tree') — collect "
        "per-port STP state for every switch in one batched call.\n"
        "2. Flag ports stuck in blocking/listening/learning for longer than "
        "expected, and any port with a high or fast-increasing Topology "
        "Change Notification (TCN) count (sign of instability).\n"
        f"3. Cross-reference with get_switching(site='{site}', scope='lldp') "
        "to identify what's actually connected to the affected ports "
        "(another switch, an AP, an end device) and whether the physical "
        "topology matches what's expected (e.g. no unexpected redundant "
        "path that would explain a blocked port).\n"
        "4. Summarize: which ports are blocking and why (normal redundancy "
        "vs. a likely mis-cable/loop), and any port showing signs of BPDU "
        "flooding or repeated TCNs that warrants BPDU-guard/root-guard "
        "review."
    )
