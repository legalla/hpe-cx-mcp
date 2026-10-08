---
name: aoscx-legacy-to-fabric-migration
description: Guided, safety-gated workflow to migrate a legacy ArubaOS-CX network (VSX core, LAGs, VLANs, core-localized routing/static routes) to a VXLAN-EVPN Fabric (OSPF underlay, BGP-EVPN overlay with Spines as Route-Reflectors, VNIs, VRFs) via cx-mcp. Use when asked to migrate/convert/transition a legacy campus or DC network to an EVPN fabric.
---

# Legacy → VXLAN-EVPN Fabric Migration

Built entirely on **atomic** cx-mcp tools (no dedicated "migrate" tool exists,
and none should be assumed) — this skill is the sequencing/decision logic that
ties them together. Pair with `aoscx-change-management` (checkpoint/rollback
discipline — mandatory here), `aoscx-inventory-targeting` (batched targeting),
and `aoscx-dc-fabric-ops` (post-migration health checks).

## Non-goals / hard rule

Never reconfigure a device before the user has explicitly approved the target
topology proposal (Phase 2). Never skip a `plan`/`dry_run_token` preview before
an `apply`. Never touch VSX or run a CLI fallback without a fresh checkpoint
immediately before it.

**Never widen VLAN scope.** Replicate each device's EXISTING VLAN membership
exactly, per device — do not add a VLAN to a device that didn't already carry
it, even if a sibling device does. E.g. if the Stub VTEP currently has VLANs
100-110 and another Access-VTEP has 105-116, the target fabric keeps that
same asymmetric distribution (Stub: 100-110, other: 105-116) — never
homogenize to the union (100-116) on either device. Same for an Extended
Edge: if it only carries VLANs 105-107, the static tunnel only carries VNIs
for 105-107, never the Stub's full VLAN range.

**Every migrated SVI must be attached to the target VRF** — never leave it in
the default VRF, even if that's simpler. If the legacy SVI had a DHCP relay/
helper-address configured, it MUST be reapplied on the new SVI using the
target VRF (the VRF through which the DHCP server is reachable) — DHCP relay
is a `{vrf},{port}`-keyed object on AOS-CX, so it has to be (re)created
against the correct VRF, not silently left pointing at `default`.

## Phase 0 — Discovery (read-only, safe anytime)

Build the picture from live data before proposing anything:

- `get_redundancy(scope='vsx_status'|'vsx_config')` on every candidate — find
  existing VSX pairs (legacy core candidates).
- `get_switching(scope='vlans'|'lldp')` + `get_interfaces(scope='lag')` — map
  VLANs, LAG uplinks and neighbor adjacency to see which devices hang off the
  core (Access-VTEP candidates). Record the EXACT per-device VLAN membership
  (not a global union) — this per-device set is what gets replicated in
  Phase 3, unchanged.
- For each legacy SVI found, check for a DHCP relay/helper-address:
  `get_interfaces(scope='dhcp_relay', device=<dev>)` (omit `interface` to
  discover ALL configured relays on the device in one call). Record the
  server address(es) and the VRF it was reachable through — needed to
  recreate it correctly in Phase 3 step 6.
- `get_routing(scope='bgp_summary'|'ospf_overview'|'route_table', vrf='all')`
  on the core candidates — enumerate existing VRFs and any OSPF/BGP/static
  routing "localized" there (`route_table` entries with `type=='static'` are
  the static routes that will need a home on Border).
- For any OSPF/BGP found, go one level deeper for the FULL config (needed to
  faithfully transpose it in Phase 3 step 7): `get_routing(scope=
  'ospf_interfaces', vrf='all')` (area/area-type/passive per interface) and
  `get_routing(scope='bgp_config', vrf='all')` (ASN, router-id, every
  neighbor's remote-as/update-source/address-families/filters). Also record
  whether the core redistributes connected/static into OSPF/BGP or vice
  versa (`bgp_config`/`ospf_overview` surface the router-level redistribute
  settings) — this decides whether Phase 3 step 7 needs `configure_routing(
  scope='redistribute')` at all.
- `get_config(scope='full')` as a fallback cross-check when a read scope
  doesn't expose enough detail (e.g. exact static-route parameters).
- `manage_config(action='list_checkpoints')` / `create_checkpoint` readiness
  check — confirm you *can* checkpoint every device you're about to touch.
- `get_switching(scope='lldp')` again, this time run from each Access-VTEP
  candidate outward (not just towards the core) — any further device found
  hanging off an Access-VTEP candidate (not itself core-adjacent) is an
  **Extended Edge** candidate: a device that will stay OUTSIDE the EVPN
  control-plane and reach the fabric only through a static VXLAN tunnel.

Derive a **candidate** classification only — never final until validated:
- Spine candidates = current VSX-paired core(s).
- Access-VTEP candidates = devices LLDP/LAG-adjacent to the core, carrying
  access VLANs.
- **Stub VTEP** = any Access-VTEP candidate that has an Extended Edge behind
  it. Same device, additional role — it terminates the fabric's dynamic
  EVPN overlay AND a static VXLAN tunnel towards its Extended Edge.
- **Extended Edge** = a device found behind a Stub VTEP with no direct
  fabric adjacency of its own — it never joins BGP-EVPN; it only gets a
  static VXLAN tunnel back to its Stub VTEP (see Phase 3 step 8).
- Border = never deduced automatically — always ask (below), even when an
  obvious candidate exists, because Border needs a deliberate placement
  decision for external/inter-domain routing.

## Phase 1 — Required inputs

If not already given in the prompt, ask the user (one batch of questions)
before drafting the target topology:

1. Which device(s) must be Border?
2. IP addressing plan for underlay routed (point-to-point) links?
3. IP addressing plan for underlay loopbacks (OSPF router-id, `loopback0`)?
4. IP addressing plan for overlay loopbacks (VTEP source, `loopback1`)?
5. Base number for L2VNI allocation (default **10000**). Formula: `L2VNI =
   base + vlan_id` — e.g. base `10000` + VLAN `101` → L2VNI `10101`. Exception:
   if a VNI is already in use for that VLAN elsewhere, reuse it instead of
   renumbering.
6. VRF name to host the migrated L2VNIs, and the L3VNI ID (default **20000**).
7. ASN for the new Fabric (default **65000**).
8. Route-Target format for each L2VNI's EVPN import/export RTs: `auto` or
   `ASN:VLAN_ID`. If `ASN:VLAN_ID`, use the Fabric ASN from Q7 (e.g. `65000`)
   and the VLAN's own ID (e.g. VLAN `101` → RT `65000:101`) — this feeds the
   `set_evpn_vlan_rt`/`configure_service(scope='vlan')` call in Phase 3 step 6.
9. If two devices are designated as Border, confirm whether they should form
   a VSX pair (common when Border = the new redundant edge to the outside).
10. A MAC address range/pool to draw from for (a) any new VSX pairing's
    VSX system-MAC and (b) the virtual system-MAC assigned to each VTEP (one
    value per VSX pair, one per standalone VTEP) — ask for this whenever a new
    VSX pair is being created (Phase 3 step 1) or any VTEP still lacks a
    virtual MAC, unless the user already supplied explicit values.

## Phase 2 — Target topology proposal (mandatory validation gate)

Write up the proposal and **stop** for explicit approval before any write:

- Device → target role table (Spine / Access-VTEP / Border / unchanged).
- Underlay: loopback0 + P2P addressing per device, OSPF area design.
- Overlay: loopback1 (VTEP) addressing, ASN, RR design — **Spines are the
  Route-Reflectors** (`route_reflector_client` on their peer-group for AF
  `l2vpn-evpn`), **every other fabric device (Access-VTEP, Stub VTEP,
  Border) is an RR-client** (plain neighbors to each Spine, `activate:
  l2vpn-evpn`, update-source = loopback1) — **the Extended Edge is
  EXCLUDED** (no BGP session at all, it never joins EVPN — see Phase 3
  step 8).
- VNI/VRF plan: per-VLAN L2VNI (`base + vlan_id`, e.g. base `10000` + VLAN
  `101` → `10101`) and the target VRF/L3VNI on Border (+ Access-VTEPs if IRB
  is local there).
- Per-device VLAN membership table, taken as-is from Phase 0 — no VLAN is
  added to a device that didn't already have it (see hard rule above).
- Explicit line: *"Core(s) X/Y become Spines — every VLAN currently on them
  (list them) will be REMOVED, since a Spine carries no VLANs in the target
  design"* — state this for EVERY core becoming a Spine that currently has
  non-default VLANs, independent of its VSX status.
- Explicit line: *"Core(s) X/Y become Spines and their VSX pairing will be
  REMOVED"* — state this ONLY if that specific condition holds (core → Spine
  AND currently VSX).
- Explicit line: *"Border X/Y will be paired as VSX"* — state this ONLY when
  two devices are designated Border and the user confirmed (Q9) they should
  run VSX between them.
- If any Stub VTEP / Extended Edge pair was found in Phase 0, call it out
  explicitly: *"Device X is behind Access-VTEP Y with no fabric adjacency of
  its own — Y becomes a Stub VTEP, X becomes an Extended Edge reached via a
  static VXLAN tunnel (not EVPN)"*.
- Explicit mapping of which legacy VLANs/VRFs/OSPF/BGP/static routes move to
  which Access-VTEP/Border, and into which VRF.
- **Per-device configuration table** — one row per device, listing every
  object that will be created/changed on it (empty cell = nothing to do on
  that device for that object). This is what the user actually approves —
  the bullets above are the rationale, this table is the concrete plan:

  | Device | Role | loopback0 | loopback1 | routed ports | OSPF | BGP (RR/client) | VXLAN (mode) | virtual-MAC | VRF/L3VNI | L2VNI(s) | VSX action | Static tunnel |
  |---|---|---|---|---|---|---|---|---|---|---|---|---|
  | Spine-01 | Spine | 10.0.0.1/32 | — | 2 P2P | area 0.0.0.0 | RR | — (not a VTEP) | — | — | — | — | — |
  | Border-01 | Border | 10.0.0.11/32 | 10.0.1.11/32 | 2 P2P | area 0.0.0.0 | client | static-evpn | `02:00:00:00:AA:01` (shared w/ Border-02) | `TENANT1`/20000 | — | pair w/ Border-02 | — |
  | Access-01 | Access-VTEP | 10.0.0.21/32 | 10.0.1.21/32 | 1 P2P | area 0.0.0.0 | client | deny | `02:00:00:00:AA:02` | — | 10100, 10101 | — | — |
  | Access-02 | Stub VTEP | 10.0.0.22/32 | 10.0.1.22/32 | 1 P2P | area 0.0.0.0 | client | static-evpn | `02:00:00:00:AA:03` | — | 10105-10107 | — | dest=Extended-Edge-lo0, vnis 10105-10107 |
  | Extended-Edge | Extended Edge | 10.0.2.1/32 (own pool) | — (uses lo0) | 1 P2P | area 0.0.0.0 (to Stub only) | — (no EVPN) | source-only, no bridging-mode | — | — | 10105-10107 (static, no RT) | — | dest=Access-02-lo1 |

  Keep the SAME per-device row set through Phase 6 — the final summary table
  is this same table with an added `Result`/`Rollback ref` column per action.

## Phase 3 — Phased execution (minimize disruption)

Before the first write on ANY device: `manage_config(action='create_checkpoint',
name=<device+ticket/date>)`. Every write below is `plan` → review → `apply`
with the returned `dry_run_token` — never collapse the two steps.

1. **Border VSX pairing (conditional, before underlay/overlay on Borders)**
   - Only when two devices are designated Border and the user confirmed they
     should run VSX (Phase 1 Q9).
   - `configure_redundancy(scope='vsx', action='plan', device=<Border-A>,
     params={peer_device: <Border-B>, isl_interface, keepalive_interface,
     keepalive_vrf, keepalive_src_ip, keepalive_peer_ip, system_mac})` —
     configures BOTH peers symmetrically in ONE call (role mirrored
     primary/secondary automatically). Review the plan, then `action='apply'`
     with the returned `dry_run_token` (right after a fresh checkpoint on
     each peer — this still runs inside the firmware auto-checkpoint safety
     net like every other `configure_*`).
   - Verify: `configure_redundancy(scope='vsx', action='verify')` (or
     `get_redundancy(scope='vsx_status')`) → `configured: true`/present on both
     peers with a healthy ISL/keepalive before proceeding to the underlay.
   - Once paired, treat both Borders as ONE unit for the rest of the fabric
     config: `loopback1` (step 3) and the virtual system-MAC (step 4) must be
     identical on both — never configure them independently per peer.

2. **Interface health check & speed-mismatch remediation** — MUST be done
   BEFORE the underlay (step 3); an OSPF adjacency will never come up over a
   port that's down or negotiating the wrong speed, and diagnosing that
   AFTER wiring up OSPF just wastes time.
   - For every interface that will carry an underlay P2P link (Spines,
     Access-VTEPs, Borders): check its L1 state — `get_interfaces(
     scope='physical', interface=<name>)` now surfaces `l1_state` (bool,
     Layer 1 ready) + `l1_state_down_reason` (only set when `l1_state` is
     False) directly, e.g. `group_speed_mismatch`, `profile_mismatch`,
     `invalid_speeds`, `module_incompatible`, ... — no more `get_config(
     scope='raw', ...)`/`run_ssh_commands('show interface brief')` fallback
     needed for this read.
   - If a `group_speed_mismatch` (or similar group-level issue) is found:
     `get_interfaces(scope='interface_group', device=<dev>)` — shows each
     interface group's `configured_speed`/`applied_speed`/`default_speed`/
     `supported_speeds`. Identify the group covering the affected port(s) and
     the speed it SHOULD run at (matching the far-end/transceiver).
   - Fix: `configure_interface(scope='interface_group', action='plan',
     device=<dev>, params={group: <id>, speed: <target speed>})` — review the
     plan (changing a group's speed can bounce EVERY port in that group, not
     just the one you're fixing — call this out to the user before applying),
     then `action='apply'` with the token.
   - Verify: `configure_interface(scope='interface_group', action='verify',
     ...)` (or `get_interfaces(scope='interface_group')`) shows the corrected
     speed applied; re-check the previously-affected port(s) with
     `get_interfaces(scope='physical')` — `link_state: up`, no down-reason.
   - Do NOT proceed to step 3 (Underlay) while any intended underlay link is
     still down/mismatched.

3. **Underlay (new, built in parallel to the still-live legacy net)**
   - `configure_interface(scope='loopback', ...)` — loopback0 (router-id) +
     loopback1 (VTEP source) on Spines/Access-VTEPs/Borders. **If the device
     is part of a VSX pair** (Border pair from step 1, or any other VSX-paired
     VTEP), `loopback1` MUST be configured with the SAME IP on both peers —
     it's the shared anycast VTEP source address that lets either peer
     originate/terminate VXLAN tunnels for the same MLAG-attached traffic.
     `loopback0` (router-id) stays unique per device as usual.
   - `configure_interface(scope='routed_port', ...)` on every P2P underlay link.
     A port that is still a LAG member (legacy uplink) needs
     `remove_from_lag: true` — it is pulled out of the LAG first (this bounces
     the rest of the bundle: say so before applying). Add
     `delete_empty_lags: true` so a LAG left without members is deleted (on
     8360 an empty LAG keeps its ex-members in `pspo_enablement_layer_down`;
     MC-LAG: run on both VSX peers). `orchestrate_fabric_underlay` releases
     all the LAG ports of a device in ONE first step, then flaps each
     released port (shutdown/no shutdown). After conversion the
     tool checks the OPERATIONAL `admin_state` and does a real down/up flap
     when it stays down while the config says up (a same-value rewrite is a
     no-op for the device); a `status: partial` + warning means the port is
     still not up — fix it before the OSPF step, do not carry on. If a
     platform answers "system internal-vlan-range pool is empty", re-run with
     `ensure_internal_vlan_range: true` (supported by `routed_port`, `l3_link`
     and `orchestrate_fabric_underlay`); if the REST write does not stick, the
     error gives the CLI line (`system internal-vlan-range start 1024 end 1151
     confirm`).
   - `configure_routing(scope='ospf', ...)` — router-id (per device:
     `router_id: {<device>: <ip>}`), area, interfaces (dict entries accept
     `network_type: 'point_to_point'`), `passive_interfaces: [...]` for
     loopbacks/SVIs. `scope='l3_link'` does routed port + OSPF router/area +
     interface + `point_to_point` in one call (`ospf_network_type` default).
     Each OSPF interface is now created WITH its port binding and read back;
     the result tells you if the device did not keep it.
   - Verify before continuing: `get_routing(scope='ospf_neighbors')` = Full on
     every link. `orchestrate_fabric_underlay` returns `status: partial` with a
     `warning` (and the per-device `ospf_neighbor_check`
     neighbors/full/expected) when the adjacencies do not converge — never treat
     an underlay as done on `applied` alone. If an OSPF interface shows
     `State Down / Cost 0` while its port is up, re-run the same call: a row
     without port binding is detected and re-created ("rebound").
   - Extended Edges: `orchestrate_fabric_underlay(extended_edges=[{edge,
     stub, links: [{stub_interface, edge_interface}]}])` gives the Edge a
     loopback0 and routed /31 links + OSPF towards its Stub VTEP in the same
     call. A `mtu_mismatches` warning means both ends of a link differ (OSPF
     can stick in ExStart) — align them before moving on.
   - Run applies on the SAME device one after the other. If an apply returns
     `token_restored: true`, nothing was written and the same `dry_run_token`
     can be re-applied; otherwise (network error after a write, `Connector is
     closed`, ...) re-plan, and treat an `absent`/`deleted` answer on the retry
     of a delete as success. An `ignored_params` list in a plan/apply result
     means params the scope does not support were NOT applied — fix the call,
     do not carry on.

4. **Overlay (new, non-disruptive)**
   - Preferred: `orchestrate_fabric_overlay(spines, leafs, asn)` in ONE call
     (after the underlay): router-id = loopback0 everywhere, spines get an RR
     peer-group with every leaf loopback0, leafs a peer-group with every
     spine loopback0, send-community extended, l2vpn-evpn on / ipv4-unicast
     off; then waits `wait_established` s and reports each non-Established
     session with its last BGP error. The manual per-device form below stays
     valid.
   - BGP EVPN control-plane — **Spines are Route-Reflectors, every other
     fabric device (Access-VTEP, Stub VTEP, Border) is an RR-client; the
     Extended Edge is EXCLUDED (it never runs BGP-EVPN at all)**:
     - On each **Spine**: `configure_routing(scope='bgp', action='plan',
       device=<Spine>, params={asn: <fabric ASN>, router_id: <loopback0>,
       neighbors: [{neighbor: 'spine-RR', is_peer_group: true,
       activate: {'l2vpn-evpn': true},
       route_reflector_client: {'l2vpn-evpn': true}},
       {neighbor: <loopback1 of each Access-VTEP/Stub-VTEP/Border>,
       remote_as: <fabric ASN>, peer_group: 'spine-RR',
       update_source: <Spine loopback1 or loopback0 per design>}, ...]})` —
       ONE neighbor entry per non-Extended-Edge fabric device, all bound to
       the `spine-RR` peer-group that carries `route_reflector_client`. A
       member only gets the group's `remote_as` + `activate` (REST does not
       cascade AF activation); update-source / send-community / RR-client
       stay on the group and are inherited — duplicating them on the member
       made the CLI answer "Update source is already configured with different
       transport address". `update_source: 'loopback0'` is written as the
       local interface (the field itself is an IP). The tool
       refuses to report success when the device did
       not keep a field (`status: partial`, `not_applied`). Use
       `send_community: {'l2vpn-evpn': 'extended'}` (`'both'` is rejected by the
       firmware on EVPN and is converted to `extended`). New sessions are
       created with `shutdown: false` explicitly.
     - On each **Access-VTEP / Stub VTEP / Border**: `configure_routing(
       scope='bgp', action='plan', device=<device>, params={asn: <fabric
       ASN>, router_id: <loopback0>, neighbors: [{neighbor: <loopback1 of
       each Spine>, remote_as: <fabric ASN>, update_source: <own loopback1>,
       activate: {'l2vpn-evpn': true}}, ...]})` — plain neighbor(s) to EVERY
       Spine, NO `route_reflector_client` on this side (that flag only means
       something on the reflector).
     - Review each plan, then `action='apply'` with the token.
   - `configure_interface(scope='vxlan', ...)` on Access-VTEPs + Borders only
     (Spines are not VTEPs — exclude them). `vxlan1` is created with
     `type: vxlan`, top-level `admin: up` and UDP port 4789 (like the CLI);
     `scope='overlay'` does the interface + EVPN global
     (incl. `evpn_options.redistribute_local_svi`) + virtual MAC (+ optional
     BGP) per VTEP in one call, then checks vxlan1/VNIs/EVIs are up
     (`vxlan_check`) and marks the device NOT ok otherwise.
   - `configure_routing(scope='evpn', ...)` — arp_suppression, bridging mode,
     and `redistribute_local_svi: true` (CLI `redistribute local-svi` under
     `evpn`: advertises the SVI IP+MAC as type-2 routes, needed for the
     migrated routed VLANs/SVIs to be reachable across the fabric). Set it on
     every VTEP that hosts SVIs (Access-VTEP, Stub VTEP, Border). With
     `scope='overlay'` pass it via `evpn_options: {redistribute_local_svi:
     true}`. Only the given keys are touched; `status: partial` +
     `not_applied: ['redistribute.local-svi']` means the device did not keep
     it. Verify with `get_overlay(scope='evpn_config')` (exposes
     `redistribute_local_svi`).
   - `configure_interface(scope='virtual_mac', ...)` — every VTEP (any
     Access-VTEP, Stub VTEP, or Border — excluding the Extended Edge, which
     isn't EVPN) MUST have a virtual system-MAC configured. If the VTEP is
     part of a VSX pair, the SAME MAC value must be pushed to BOTH peers —
     target the pair together (`device=[peerA, peerB]` or `site=`) with one
     identical `mac`, exactly like the anycast `loopback1` above.
   - Verify: `get_routing(scope='bgp_neighbors')` Established + EVPN AF active,
     `get_overlay(scope='vtep_neighbors'|'vxlan_tunnels')` up; for any VSX
     pair, `verify_virtual_mac`/`configure_interface(scope='virtual_mac',
     action='verify')` should report the value as consistent across both peers.

5. **VRF/L3VNI on Border** (mirrors the legacy core's routed VRF)
   - `configure_routing(scope='vrf', params={name, rd, import_route_targets,
     export_route_targets, l3vni})` on Border (+ Access-VTEPs if local IRB is
     needed for that VRF). `rd` must be explicit (`ASN:nn` / `IP:nn`, e.g.
     `65000:20000`) — `auto` is NOT valid on a VRF (it only exists for
     per-VLAN EVPN RDs); the VRF-level RTs may be `auto` or explicit. `l3vni`
     (alias `vni`) binds the L3 VNI to the VRF on `vxlan1`, which must exist
     already (step 4). Put EVPN RTs at VRF level; `address_families` is only
     for non-EVPN L3VPN and may 500 on some firmware.
   - Verify: `configure_routing(scope='vrf', action='verify', ...)` — shows
     `rd`, the RTs and `l3vni`.

6. **VLAN-by-VLAN cutover to Access-VTEPs** — the disruption-sensitive step;
   do ONE VLAN at a time and confirm with the user between VLANs on a first run.
   - For each VLAN, target ONLY the Access-VTEP(s) that already carried it in
     the legacy config (Phase 0 per-device membership) — do not provision it
     on an Access-VTEP that didn't already have it.
   - `configure_service(scope='vlan', action='plan', params={vlan_id,
     vni: base + vlan_id (e.g. 10000 + 101 = 10101), vrf: <target vrf>,
     import_route_targets/export_route_targets: per Q8 — either 'auto' or the
     explicit `ASN:VLAN_ID` pair (e.g. ASN `65000` + VLAN `101` → `65000:101`),
     svi_ip/active_gateway, ...})` on the target Access-VTEP(s), review, then
     `action='apply'` with the token. `vrf` is REQUIRED here — never omit it
     and let the SVI fall back to `default`, even for a VLAN that was
     routed in the default VRF on the legacy core; it must land in the
     target VRF from Phase 1 Q6.
   - If the legacy SVI for that VLAN had a DHCP relay/helper-address
     (recorded in Phase 0), reapply it on the new SVI right after it's
     created: `configure_interface(scope='dhcp_relay', action='plan',
     params={interface: 'vlan<id>', vrf: <target vrf>, ipv4_servers: [...]})`
     — pointing at the SAME server address(es) but through the TARGET VRF
     (not whatever VRF it used to be reachable through on the legacy core;
     `vrf` MUST match the SVI's actual VRF or the relay silently won't
     forward), then `action='apply'` with the token.
   - Keep the legacy core's SVI/gateway for that VLAN alive until the new
     anycast gateway is confirmed reachable — this dual-gateway coexistence
     window is what keeps the cutover soft. Retire the old one only in Phase 4.
   - Verify each VLAN with `configure_service(scope='vlan', action='verify')`
     before moving to the next one; verify DHCP relay separately with
     `configure_interface(scope='dhcp_relay', action='verify', params=
     {interface: 'vlan<id>', vrf: <target vrf>})` (or `get_interfaces(
     scope='dhcp_relay', interface='vlan<id>')`) and test an actual DHCP
     lease if possible before declaring that VLAN done.

7. **Routing migration: rehome legacy L3 config from the cores to Border, in
   the target VRF** — whatever routing was "localized on the cores" (Phase 0
   discovery) gets FAITHFULLY transposed onto Border, inside the target VRF
   from Phase 1 Q6. Do this per protocol, each with its own plan → review →
   apply, and don't skip any protocol just because another one is absent.
   - **Static routes**: for EVERY static route found on the legacy core(s) in
     Phase 0 (`get_routing(scope='route_table', vrf='all')` entries with
     `type=='static'`), recreate it on Border with the SAME prefix/nexthop(s)/
     distance/tag, but inside the target VRF:
     `configure_routing(scope='static_route', action='plan', device=<Border>,
     params={prefix, vrf: <target>, nexthops: [{ip_address, distance, tag,
     ...}]})`. Review the plan (one static route at a time, or batched if
     the user prefers), then `action='apply'` with the token. If Border is a
     VSX pair, apply to both peers together.
   - **OSPF**: if the legacy core ran OSPF, replicate the SAME router-id
     scheme (adapted to Border's own loopback0), the SAME area(s)/area
     type(s), and the SAME set of participating interfaces/networks —
     `configure_routing(scope='ospf', action='plan', device=<Border>,
     vrf=<target>, params={instance_tag, router_id, area_id, area_type,
     interfaces, passive_interface_default})`. Don't silently drop a
     `passive_interface_default`, a stub/NSSA area type, or a secondary area
     found on the core — carry it over as-is unless the user says otherwise.
     Review, then `action='apply'` with the token.
   - **BGP**: if the legacy core ran BGP (distinct from the Fabric's own
     overlay BGP — this is the core's OWN routing-protocol session towards
     upstream/external peers), replicate the SAME ASN, router-id, and EVERY
     neighbor (remote-as, update-source, address-families activated,
     filters/route-maps if any) into the target VRF on Border:
     `configure_routing(scope='bgp', action='plan', device=<Border>,
     vrf=<target>, params={asn, router_id, neighbors: [...]})`. This is a
     SEPARATE BGP instance from the Fabric's overlay BGP (which runs in the
     default VRF for `l2vpn-evpn` — see step 4); don't conflate the two or
     collapse them into one call. Review, then `action='apply'` with the token.
   - **Redistribution**: if the legacy core redistributed connected/static
     routes into OSPF/BGP (or vice versa) to leak reachability between the
     two, replicate that with `configure_routing(scope='redistribute',
     action='plan', device=<Border>, params={protocol: 'bgp'|'ospf', vrf:
     <target>, asn/instance_tag, address_family, sources: [...]})`. Review,
     then `action='apply'` with the token. Don't assume redistribution is
     needed if Phase 0 didn't show it in the legacy config — don't add new
     redistribution the legacy core didn't have.
   - Verify EACH protocol before moving on: `configure_routing(scope=
     'static_route'|'ospf'|'bgp'|'redistribute', action='verify', device=
     <Border>, vrf=<target>)` and/or `get_routing(scope='route_table'|
     'ospf_neighbors'|'bgp_neighbors', vrf=<target>)` — confirm the routes/
     adjacencies show up in the TARGET VRF specifically, not `default`.

8. **Stub VTEP ↔ Extended Edge bridging** (conditional, one pass per
   Stub/Extended-Edge pair found in Phase 0)
   - Enable inter-VXLAN bridging on the Stub VTEP's VXLAN interface:
     `configure_interface(scope='vxlan', device=<Stub VTEP>,
     params={interface: 'vxlan1', inter_vxlan_bridging_mode: 'static-evpn'})`
     — this is what lets the Stub bridge between its dynamic EVPN-learned
     VNIs and the statically-tunneled VNIs towards the Extended Edge.
   - OSPF between the Stub VTEP and the Extended Edge, using loopback0 on
     both sides: `configure_interface(scope='routed_port', ...)` on the link
     on both devices, `configure_interface(scope='loopback', params={name:
     'loopback0', ip_address: ...})` on the Extended Edge (new to the fabric —
     it has no loopback yet), then `configure_routing(scope='ospf',
     params={interfaces: [<routed_port>, 'loopback0'], area_id, ...})` on both.
     Note: the Stub VTEP's `loopback1` (its fabric VTEP source) must also be
     reachable to the Extended Edge — include it in the same OSPF interface
     list on the Stub side, since the Extended Edge's own static peer will
     target it (see next step).
   - Static VXLAN tunnel: on the Stub VTEP, `configure_interface(scope='vxlan',
     params={interface: 'vxlan1', static_peers: [{destination: <Extended
     Edge loopback0>, vnis: [...], vrf: <target vrf or default>}]})` —
     `vnis` MUST be limited to the VLANs the Extended Edge actually carries
     (Phase 0 membership), e.g. only 105-107 if that's all it has, even if
     the Stub VTEP itself knows a wider range (e.g. 100-110). On the
     Extended Edge, create its OWN `vxlan1` sourced from its `loopback0`
     (`configure_interface(scope='vxlan', params={interface: 'vxlan1',
     source_ip: <its loopback0>})`) with a static peer pointing back at the
     Stub VTEP's `loopback1`.
   - L2VNI on the Extended Edge: it needs the VLAN + VNI mapping but must NOT
     get an EVPN route-target step (it doesn't run BGP-EVPN). Use
     `configure_service(scope='vlan', action='plan', device=<Extended Edge>,
     params={vlan_id, vni, evpn: false})` — `evpn=false` maps the VLAN to the
     VNI WITHOUT the EVPN route-target step, exactly what a non-EVPN Extended
     Edge needs. Review the plan, then `action='apply'` with the token.
   - **On the Stub VTEP itself, the L2VNI stays fully EVPN-configured** — it
     is still a regular fabric VTEP. Its VNI-to-VLAN mapping and EVPN
     route-targets are the ones created in Phase 3 step 6
     (`configure_service(scope='vlan')`) exactly like any other Access-VTEP;
     do NOT remove or bypass that EVPN configuration for a VLAN just because
     it is also extended to an Extended Edge. The static peer added here is
     an ADDITIONAL tunnel endpoint for the same VNI, not a replacement — that
     coexistence (EVPN-learned tunnels to the rest of the fabric + one static
     tunnel to the Extended Edge, for the same VNI) is exactly what
     `inter_vxlan_bridging_mode: static-evpn` enables.
   - Verify: `get_overlay(scope='vxlan_config', device=<Stub VTEP>)` shows
     `inter_vxlan_bridging_mode: static-evpn`; `get_routing(scope=
     'ospf_neighbors')` Full between Stub and Extended Edge;
     `get_overlay(scope='vxlan_static_peers'|'vxlan_tunnels')` shows the
     tunnel up on both ends.

## Phase 4 — Legacy core cleanup (conditional)

Two independent conditional cleanups on a device whose role changes to Spine
— apply each based on its OWN condition, not on the other:

### 4a. Legacy VLAN removal on Core→Spine devices

A Spine carries NO VLANs in the target design (pure L3 underlay + Route
Reflector — it's excluded from `vxlan`/VTEP scopes per the hard rule above).
Applies to EVERY core that becomes a Spine, regardless of whether it was
VSX-paired.

- Re-confirm with the user before touching a device that's carrying live
  legacy VLANs.
- From Phase 0's per-device VLAN membership, list every VLAN still present
  on the core (excluding the un-deletable default VLAN, typically ID 1).
- Do NOT delete a VLAN still referenced by a live LAG/trunk/SVI on that core
  — confirm first (via `get_switching(scope='vlans')`/`get_interfaces(
  scope='lag'|'svi')`) that every dependency was migrated off in Phase 3
  (VLAN cutover to Access-VTEPs, routing rehomed to Border) or is explicitly
  being decommissioned, not silently orphaned.
- `configure_interface(scope='vlan', action='plan', device=<core>,
  params={vlan_id, delete: true})` per VLAN, right after a fresh checkpoint.
  Review the plan, then `action='apply'` with the token.
- Verify: `get_switching(scope='vlans')` on the Spine shows only the default
  VLAN remaining.

### 4b. Legacy VSX decommission

Distinct from the Phase 3 step 1 Border VSX *pairing* (new) — this step *removes*
an existing VSX pair. Only if the approved proposal said the core(s) become
Spines AND are currently VSX-paired:

- Re-confirm with the user immediately before this step — it is the most
  disruptive, hardest-to-reverse action in the whole migration. Run the
  `plan` yourself right before the apply and use ITS `dry_run_token` only.
- `configure_redundancy(scope='vsx', action='plan', device=<core-A>,
  params={peer_device: <core-B>, delete: true})` — tears down the pairing on
  BOTH peers in one call, right after a fresh checkpoint on each. Review the
  plan, then `action='apply'` with the token.
- Do not attempt this until every VLAN/VRF/route that depended on that VSX
  pair's SVIs/routing is confirmed migrated (Phase 3 steps 5–6) and traffic is
  observed flowing through the new Access-VTEPs/Border instead.
- Re-check with `get_redundancy(scope='vsx_status')` → `configured: false` on
  both former peers confirms the teardown.

## Phase 5 — Final verification (before the summary — do not skip)

- Interface health: `get_interfaces(scope='physical')` on every underlay link
  — `link_state: up`, no lingering `group_speed_mismatch`/other L1 down
  reason (step 2's fix held); `get_interfaces(scope='interface_group')`
  confirms the corrected speed is still the `applied_speed`, not just
  `configured_speed` (a group can accept a config it can't actually apply).
- Underlay: `get_routing(scope='ospf_neighbors')` — Full on every fabric-internal link.
- Overlay control-plane: `get_routing(scope='bgp_neighbors', vrf=...)` —
  Established with EVPN AF active; `get_overlay(scope='evpn_routes')` — type-2/3
  routes present for every migrated VNI on every VTEP that should have them.
- Overlay data-plane: `get_overlay(scope='vxlan_tunnels'|'vtep_neighbors')` — up.
- Services: `configure_service(scope='vlan', action='verify')` per migrated
  VLAN; `configure_routing(scope='vrf', action='verify')` for the target VRF/L3VNI.
- Spine cleanliness: `get_switching(scope='vlans')` on every Core→Spine device
  shows only the default VLAN — no leftover legacy VLANs.
- VSX absence, if decommissioned: `get_redundancy(scope='vsx_status')` →
  `configured: false` on former cores.
- Rehomed routing: confirm EVERY static route/OSPF area+interface/BGP
  neighbor/redistribution rule found on the legacy core in Phase 0 is now
  present on Border **inside the target VRF specifically** (`get_routing(
  scope='route_table'|'ospf_interfaces'|'bgp_config', vrf=<target>)`) — not
  in `default` — and confirm the same items are actually gone from the old
  core once it's decommissioned (Phase 4).
- Stub/Extended Edge (if any): `get_overlay(scope='vxlan_config')` on the
  Stub VTEP shows `static-evpn`; OSPF Full between Stub and Extended Edge;
  static tunnel up (`get_overlay(scope='vxlan_static_peers'|'vxlan_tunnels')`);
  VLAN/VNI present on the Extended Edge (`get_switching(scope='vlans')`).
- For every migrated SVI: confirm it's attached to the target VRF, NOT
  `default` (`get_interfaces(scope='svi')` or `configure_routing(scope='vrf',
  action='verify')` cross-check). If it had a DHCP relay, confirm it's present
  on the new SVI and points at the target VRF (`get_interfaces(scope=
  'dhcp_relay', interface='vlan<id>')` or `configure_interface(scope=
  'dhcp_relay', action='verify', ...)`) and, if possible, that a real client
  can actually obtain a lease through it.

## Phase 6 — Final summary table

One row per action actually taken (include failures/partials, not just
successes):

| Phase | Device | Object | Action | Result | Rollback ref |
|---|---|---|---|---|---|
| 1 | Spine-01 | loopback0/loopback1 | configure_interface(loopback) | applied | checkpoint `PRE_MIG_Spine-01` |
| 4 | Access-01 | VLAN 100 → VNI 10100 | configure_service(vlan) | applied | dry_run_token / rollback_id |
| ... | | | | | |

## Common pitfalls

- A `dry_run_token` must come from a `plan` YOU ran in this session. The server
  binds a token to (operation, plan hash, TTL), not to a caller: a token
  issued by another session for an identical plan is accepted (the result then
  carries `dry_run_token_origin.same_session: false` and a warning; the
  operator can refuse those with `CX_TOKEN_SESSION_BOUND=true`). Never apply a
  token whose origin you cannot account for, and never run a VSX teardown
  (`scope='vsx_pair'`/`vsx`, `delete: true`) from a token you did not plan
  yourself in this session.
- Don't assume the legacy core automatically becomes Border — it's an
  explicit user decision (Phase 1, Q1), independent from the Spine deduction.
- Never widen VLAN scope to "clean up" an asymmetric legacy estate — each
  device keeps exactly the VLANs it had (Stub 100-110 stays 100-110 even if a
  sibling Access-VTEP has 105-116; an Extended Edge with only 105-107 gets a
  static tunnel carrying only 105-107). Homogenizing VLANs across devices is
  a scope change the user did not ask for, not a harmless simplification.
- Don't blind-PUT a shared/existing BGP peer-group — a partial body wipes
  unspecified fields (see `aoscx-change-management`). Prefer creating the new
  Fabric's BGP config as new peer-groups, not by editing a legacy one in place.
- Border can end up running TWO separate BGP instances: the Fabric's own
  overlay BGP (default VRF, AF `l2vpn-evpn`, step 4) and the migrated legacy
  BGP (target VRF, whatever AFs the core used, step 7) — don't merge them
  into a single `configure_routing(scope='bgp')` call or configure the
  legacy one in the default VRF by mistake.
- Spines are excluded from VXLAN/VTEP scopes — don't configure `vxlan` on them.
- Don't skip the interface health check (Phase 3 step 2) or do it AFTER the
  underlay — an OSPF adjacency simply won't come up over a speed-mismatched
  port, and troubleshooting OSPF first (instead of L1) wastes a debugging
  cycle on a symptom, not the cause.
- Changing an interface group's speed can bounce EVERY port sharing that
  group, not just the mismatched one — always say so in the plan review
  before `action='apply'` on `configure_interface(scope='interface_group')`.
- A core becoming a Spine must end up with NO VLANs (Phase 4a) — this is
  independent of whether it was VSX-paired; don't only clean up VLANs on a
  device you're also VSX-decommissioning and forget a non-VSX core that's
  also becoming a Spine.
- EVPN DF election is per-VLAN, not per-ESI — don't conflate the two when
  verifying multihomed Access-VTEPs.
- Every VTEP except the Extended Edge needs a virtual system-MAC
  (`configure_interface(scope='virtual_mac')`) — don't skip it thinking it's
  optional. For any VSX-paired VTEP (Border or otherwise), that MAC AND
  `loopback1` (the VTEP source) must be pushed with the identical value to
  both peers in the same call (`device=[peerA, peerB]`); configuring them
  peer-by-peer with different values is a common source of asymmetric/broken
  active-active VXLAN forwarding.
- VNI numbering collisions: always check existing usage before assigning
  `base + vlan_id` (e.g. `10000` + VLAN `101` = `10101`); numbering is often
  inconsistent across a pre-existing estate.
- Under the flat toolset, only `run_ssh_commands` (plural) stays advertised as
  a CLI fallback — don't assume `run_ssh_command`/`run_cli_command` are
  reachable; it should rarely if ever be needed now that VSX/static-route/
  redistribute/DHCP-relay/admin-state/Extended-Edge all have atomic tools.
- Never do the legacy-core VSX teardown before every dependent VLAN/VRF has
  fully cut over and been verified on the new Access-VTEPs/Border.
- Don't confuse Border VSX *pairing* (new pair, Phase 3 step 1, done early,
  `configure_redundancy(scope='vsx')` with no `delete`) with legacy-core VSX
  *decommission* (existing pair, Phase 4, done last, same scope with
  `delete: true`) — same tool, opposite ends of the migration timeline, don't
  mix up the `delete` flag.
- A VXLAN interface has a single source IP (`options.local_ip`) — the Stub
  VTEP keeps its existing `loopback1` as source for BOTH its dynamic EVPN
  peers and the static peer towards the Extended Edge; only the Extended
  Edge itself sources its own tunnel from `loopback0` (it has no `loopback1`).
  Don't assume both sides use the same loopback number.
- Don't run `configure_service(scope='vlan')` for an Extended Edge's VLAN/VNI
  WITHOUT `params={..., evpn: false}` — the default (`evpn: true`) always
  attaches EVPN route-targets, which don't apply to a device outside the
  EVPN control-plane.
- Never leave a migrated SVI in the `default` VRF, even if the legacy SVI was
  itself in the default VRF — every migrated SVI belongs in the target VRF
  (Phase 1 Q6). Forgetting the `vrf` param on `configure_service(scope=
  'vlan')` silently defaults it to `default`, not an error.
- A DHCP relay follows the VRF it's reachable through, not the VLAN — if you
  carry the relay forward but leave it pointing at the legacy VRF/`default`
  instead of the target VRF, DHCP will silently stop working even though the
  SVI itself looks correctly migrated.

## Tool coverage (full — no `run_ssh_commands` fallback needed)

Every step in this skill has a dedicated, plan/apply/verify atomic tool,
including the L1 down-reason read (`get_interfaces(scope='physical')` now
surfaces `l1_state`/`l1_state_down_reason` directly). `run_ssh_commands`
should not be needed anywhere in the workflow:

- VSX pairing/teardown: `configure_redundancy(scope='vsx', ...)` /
  `verify_vsx` — symmetric pairing via `peer_device` in one call, `delete:
  true` for teardown.
- Static routes: `configure_routing(scope='static_route', ...)` /
  `verify_static_route`.
- Route redistribution into BGP/OSPF: `configure_routing(scope=
  'redistribute', ...)` / `verify_redistribute`.
- Extended Edge plain VLAN-to-VNI mapping (no EVPN RT):
  `configure_service(scope='vlan', params={evpn: false})`.
- DHCP relay (read AND write): `get_interfaces(scope='dhcp_relay', ...)` /
  `configure_interface(scope='dhcp_relay', ...)` / `verify_dhcp_relay`.
- Interface group speed (read AND write) + L1 down-reason:
  `get_interfaces(scope='interface_group'|'physical', ...)` /
  `configure_interface(scope='interface_group', ...)` / `verify_interface_group`.
- Atomic VLAN/SVI/trunk/admin-state primitives (decoupled from
  `configure_service`): `configure_interface(scope='vlan'|'svi'|'trunk'|
  'admin', ...)` + matching `verify_*`.
- `configure_routing(scope='vrf', params={delete: true})` — VRF removal.

If a future gap analysis finds something still missing, add it to
`NOTES_MISSING_TOOLS.md` (git-ignored working notes) rather than silently
reaching for `run_ssh_commands` mid-migration.
