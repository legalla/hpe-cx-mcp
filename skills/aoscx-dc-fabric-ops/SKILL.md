---
name: aoscx-dc-fabric-ops
description: Troubleshoot and operate an ArubaOS-CX EVPN/VXLAN Data Center fabric (VTEPs, tunnels, VSX pairs, underlay BGP/OSPF) via the cx-mcp tools. Use for DC fabric health checks, tunnel-down triage, VSX split-brain/config-sync issues, and overlay/underlay cross-checks.
---

# AOS-CX Data Center Fabric Operations

Domain knowledge for operating an EVPN/VXLAN fabric built on ArubaOS-CX
switches, mapped to `cx-mcp` tool calls. Pair with the `fabric_health_check`
and `verify_vsx_pair` prompts for guided workflows.

## Fabric building blocks

- **Underlay**: point-to-point links between leafs/spines, usually running
  BGP (eBGP unnumbered or numbered) or OSPF to distribute loopback/VTEP
  reachability. Check with `get_routing(scope='bgp_summary'/'ospf_overview')`.
- **Overlay (EVPN/VXLAN)**: VTEPs (usually the leafs, sometimes borders)
  originate VXLAN tunnels keyed by a local source IP
  (`get_overlay(scope='vxlan_config')`). EVPN (BGP AFI l2vpn-evpn) advertises
  MAC/IP (type-2), IMET (type-3, tunnel endpoint discovery) and sometimes
  type-5 (IP prefix) routes — `get_overlay(scope='evpn_config'/'evpn_routes')`.
- **VSX**: a pair of switches presenting as one logical device to
  downstream/upstream neighbors (active/active), synchronizing MAC/ARP/route
  tables over an ISL and using a separate keepalive link for split-brain
  detection — `get_redundancy(scope='vsx_status'/'vsx_config'/'vsx_sync')`.

## Diagnostic playbook: "a VNI/tunnel looks down"

1. `get_overlay(device, scope='vxlan_tunnels')` — is the tunnel to the
   remote VTEP up? If down, check the underlay reachability of the remote
   VTEP's loopback first (`get_routing(scope='route_table')`) before
   assuming an overlay-specific problem — most "tunnel down" issues are
   actually underlay routing issues.
2. `get_overlay(device, scope='evpn_config')` — is the VNI actually mapped
   on this device (VLAN-to-VNI, RD/RT)? A VNI present on one VTEP but not
   its peers will never establish end-to-end reachability.
3. `get_overlay(device, scope='evpn_routes')` — are type-3 (IMET) routes
   present for every VTEP that should be a member of the VNI? Missing
   type-3 = that VTEP won't receive BUM traffic for the VNI.
4. `get_overlay(device, scope='evpn_multihoming')` — if the VNI is
   dual-homed via an ESI, check the DF (Designated Forwarder) election
   isn't stuck (both peers claiming/denying DF for the same VLAN is a
   split-brain symptom, not a normal transient state).
5. Cross-check underlay BGP/OSPF is Established/Full to every relevant
   peer — an overlay route depends on a working underlay session.

## Diagnostic playbook: "VSX pair looks unhealthy"

1. `get_redundancy(scope='vsx_status')` on **both** peers — compare role
   (primary/secondary), and confirm neither reports the other as
   unreachable (that's the split-brain precursor).
2. `get_redundancy(scope='vsx_sync')` — config-sync should be current; a
   stale/aborted sync means the two peers' running-configs have silently
   diverged (dangerous — one peer may be enforcing security policy the
   other isn't).
3. `get_redundancy(scope='vsx_config')` — confirm the keepalive interface
   is NOT the same as a data-carrying uplink; keepalive over a shared
   data path defeats its purpose (an outage that takes down the data path
   also takes down the split-brain detector).
4. A VSX pair should always be targeted TOGETHER for any check (both peer
   names in one `device=` comma-separated call) — asymmetric findings
   between the two peers are themselves the signal.

## Common pitfalls

- Don't assume a "VNI mismatch" is a config bug before confirming both
  VTEPs are even reachable at the underlay level — an unreachable peer
  looks identical to a missing VNI mapping from a single-device read.
- EVPN multihoming DF election is per-VLAN, not per-ESI — a peer can be DF
  for VLAN 100 and not-DF for VLAN 101 on the very same ESI; don't
  conflate the two.
- Spines are typically NOT VTEPs (no VXLAN termination) — exclude them
  from overlay-scope queries; they only need to pass the underlay
  checks.
