# Changelog

All notable changes to **hpe-cx-mcp** are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/). The current version lives in
[VERSION](VERSION) and is baked into the image (`CX_VERSION`, OCI label,
`/healthz`).

## [Unreleased]

### Added
- IP-unnumbered interfaces: `configure_routed_port(unnumbered_interface=..., remove_unnumbered=...)`
  (also per entry of `interfaces`), new read tool `get_unnumbered_interfaces`,
  and `unnumbered_interface` exposed by `verify_routed_port` / `get_interfaces`.

## [1.7.0] — 2026-10-05

Field feedback from a Campus -> EVPN/VXLAN fabric migration (AOS-CX 10.16-10.18).

### Fixed
- L2VNI creation (`create_l2vni`, used by `overlay_service`/`static_vxlan`/
  `evpn_vlan`/vlan-service) failed on 10.16 (6200) with HTTP 400 "values in post
  body not configurable": the body no longer sends `routing` (default false,
  not writable in the 10.16 VNI schema). `create_l3vni` returns an explicit
  "no L3VNI over REST on this API" error there.
- `get_interfaces(scope='svi')`: exposes `vsx_virtual_ip4/ip6`,
  `vsx_virtual_gw_mac_v4/v6`, `active_gateway`, `ip_mtu`; `routing` is true on
  an SVI/loopback carrying an address (10.16 reports `false`; raw value kept in
  `routing_configured`); `statistics` is `null` + `statistics_note` instead of
  fake zeros when the device reports no counters (L3 counters disabled).
- `get_config(scope='running')` really returns CLI text (`Accept: text/plain`);
  `format` reflects the actual payload.
- Compacted results: orchestrator steps whose result is `partial` now count as
  failed and are always listed (`failed_items`, `summary.failed_items`).
- `remove_from_lag` rewrote the LAG with `configure_lag` defaults (LACP LAG
  silently turned static, `admin: up`): only the member map is changed now. The
  released port gets a real shutdown/no shutdown and its `l1_state_down_reason`
  is checked (8360 `pspo_enablement_layer_down`).
- `vxlan1` created over REST stayed down: created like the CLI does (top-level
  `admin: up` + UDP port 4789); `admin` re-asserted on update.
- BGP peer-group members: update-source/send-community/RR-client are no longer
  copied from the group (CLI conflict "Update source is already configured
  with different transport address"); `update_source: 'loopback0'` /
  `'loopback 0'` is written as `local_interface`.
- SSH: `(y/n)` prompts never hang the session (answered `n` by default,
  `auto_confirm=true` answers `y`); CLI error output (Invalid input, Command
  incomplete, "... is not configured") returns `ok: false`.
- REST re-login now logs the stale session out first (leaked sessions caused
  HTTP 401 "session limit reached" on 6300).

### Added
- `orchestrate_fabric_overlay(spines, leafs, asn)`: iBGP-EVPN for the whole
  fabric (RR peer-group on spines, spine peer-group on leafs, router-id =
  loopback0, send-community extended, ipv4-unicast off) + wait for Established.
- `delete_empty_lags` (underlay / l3_link / routed_port) and a batched
  `release_lag_members` first step in `orchestrate_fabric_underlay`.
- `orchestrate_fabric_underlay(extended_edges=[...])`: Edge loopback0 + /31
  links + OSPF towards its Stub VTEP; MTU mismatch check on every link
  (`mtu_mismatches`), also after `orchestrate_l3_link` (LLDP peer).
- Post-apply operational check of vxlan1 / VNIs / EVIs in `orchestrate_overlay`
  and `orchestrate_overlay_service` (`verify_operational`, `vxlan_check`).
- `configure_bgp(wait_established=N)`: waits for Established, reports the last
  BGP error per session.
- Per-device values: `router_id` (bgp, ospf, `bgp_evpn`) as `{device: ip}` or
  `'loopback0'`; VRF `rd` as `{device: rd}` or `'auto'` (= loopback0:L3VNI);
  `svi_ip` mapping in `overlay_service`.
- `configure_vrf(l3vni=...)` also creates `router bgp / vrf / address-family
  ipv4 unicast` (`bgp_vrf`, `bgp_asn`, `redistribute`).
- Batch cleanup: `configure_vlan(delete, cascade)` (SVI + EVPN RT + L2VNI +
  VLAN), `configure_svi(vlans=[...], delete)`, `configure_static_route(
  prefixes=[...], delete)`.
- `run_ssh_commands(auto_confirm, stop_on_error=true)`: commands after a
  failure are not sent and are listed in `summary.not_executed`.
- `CX_MAX_CONCURRENT_PER_DEVICE` (default 4) caps parallel HTTP connections per
  switch; background reaper (`CX_SESSION_REAPER_INTERVAL`, 60 s) closes idle
  REST/SSH sessions.
- Inventory: secondary VSF members (NetBox virtual-chassis non-master, or no
  IP + `<conductor><N>` name) are listed with `vsf_member_of` and refused as
  targets (excluded from site fan-out).

## [1.6.1] — 2026-10-01

Fixes from the legacy->fabric migration agent feedback.

### Fixed
- `vxlan1` creation (`configure_interface` scopes `vxlan`/`overlay`) sent no
  `type` -> HTTP 400 "missing mandatory value type"; the body now carries
  `type: vxlan`.
- OSPF interfaces created over REST stayed `State Down / Cost 0` (the port
  binding was a late PUT after a bare POST): the row is now created WITH its
  `port` (map form, then URI form, then the old split write as last resort),
  read back (retry on a transient 404), and a row found without a port is
  re-created ("rebound").
- `orchestrate_fabric_underlay` reported `applied` with 0 OSPF neighbors: it now
  polls up to ~30 s and returns `status: partial` + `warning` when the Full
  adjacency count is lower than the number of underlay links
  (`ospf_neighbor_check` carries `expected`). Steps returning `partial`
  (e.g. routed port without connected route) now count as failed.
- BGP over REST: `bgp_peer_group` is written in map form, new sessions get an
  explicit `shutdown: false`, `send_community` accepts a string/list and maps
  `both` -> `extended` on `l2vpn-evpn` (the firmware rejects `both`), every
  neighbor is read back (`status: partial` + `not_applied` when the device
  dropped a field), and `configure_bgp` copies the peer-group's
  `activate`/`remote_as`/`update_source`/`send_community` onto members listed
  in the same call (a group-level `activate` does not activate members).
- Ports left "Administratively down" after `remove_from_lag`: the routed-port
  and `admin` tools now compare the OPERATIONAL `admin_state` with the config
  and do a real down/up flap when they disagree (a same-value PUT is a no-op).
- `ensure_internal_vlan_range` / `internal_vlan_range_size` /
  `verify_connected_route` are now accepted by `l3_link` and
  `orchestrate_fabric_underlay` (they were silently dropped); the REST write is
  verified and the error shows the right CLI (`system internal-vlan-range start
  1024 end 1151 confirm`).
- `configure_routing(scope=vrf)`: `l3vni` (alias `vni`, + `vxlan_interface`) now
  binds the L3 VNI to the VRF (no tool exposed `create_l3vni` before) and is
  shown by `verify`; `rd: auto` is refused with an explicit message (VRF RDs
  are `ASN:nn`/`IP:nn`), VRF-level RTs accept `auto`; RD/RT are read back; an
  `address_families` 500 no longer aborts the VRF/L3VNI and is reported with a
  hint.
- Concurrent applies on one device (`Connector is closed`): a pooled REST
  session is no longer logged out while another operation is mid-request
  (use-count + deferred close).
- A `dry_run_token` is given back (`token_restored: true`) when an apply failed
  on every target before writing anything.
- Flat dispatchers report params the scope does not accept in `ignored_params`
  + `warning` instead of dropping them silently (e.g. `vni`, `passive_interfaces`).
- `configure_routing(scope=ospf)`: `router_id` accepts a `{device: ip}` mapping
  and `passive_interfaces` is implemented; `l3_link` creates the OSPF
  router/area when missing (was HTTP 500) and sets `point_to_point`
  (`ospf_network_type`, default); `orchestrate_fabric_underlay` gained
  `remove_from_lag`, `ensure_internal_vlan_range`, `auto_checkpoint`.
- `get_interfaces(scope=routed)` no longer lists every default-routing port of
  an 8360: only ports with an IP or a non-default VRF (`include_unconfigured`
  for the raw view).

### Added
- EVPN `redistribute local-mac` / `redistribute local-svi`: explicit
  `redistribute_local_mac` / `redistribute_local_svi` on `configure_evpn`
  (scope `evpn`) and in `orchestrate_overlay`'s `evpn_options`; only the keys
  given are changed, the write is read back (`partial` + `not_applied`), and
  `verify_evpn` now reports both flags.

### Security
- A `dry_run_token` is bound to (operation, plan hash, TTL), not to a caller, so
  a token issued by another MCP session for an identical plan is accepted.
  Tokens now record the issuing session; applies report
  `dry_run_token_origin` (+ warning when it differs) and
  `CX_TOKEN_SESSION_BOUND=true` refuses them.

## [1.6.0] — 2026-09-28

Overlay orchestrators + generic `orchestrator` dispatcher.

### Added
- `orchestrate_overlay` (`configure_interface(scope='overlay')`): DEVICE-level
  VTEP overlay bring-up in one call — VXLAN interface (`source_ip` activates
  the tunnel) then branches on `mode`: `evpn` (default, Access-VTEP/Border) adds
  global EVPN options + virtual system-MAC + OPTIONAL BGP-EVPN control-plane
  (`bgp_evpn`, omitted by default so re-running on an already-peered device
  never risks a partial write on a shared peer-group); `static` (Extended Edge)
  stops after the interface — no EVPN/virtual-MAC/BGP; `stub` (Stub VTEP) is
  like `evpn` and defaults `inter_vxlan_bridging_mode` to `static-evpn`.
  `source_ip`/`virtual_mac` accept a per-device mapping (shared value only on
  a VSX pair). `delete: true` tears down the given `bgp_evpn` neighbors and
  optionally the VXLAN interface.
- `orchestrate_overlay_service` (`configure_interface(scope='overlay_service')`):
  BATCH VLAN -> L2VNI -> EVPN route-target and/or static peer, several
  services in ONE call (`services: [...]`), each with its own `attach`:
  `evpn` (route-target + optional SVI), `static` (Extended Edge, no RT, needs
  `static_peers`), or `stub` (fully EVPN-configured PLUS a static peer for the
  same VNI — the Stub VTEP case, requires `orchestrate_overlay(mode='stub')`
  to have run first). Refuses with a clear error if the VXLAN interface is
  absent (`require_vxlan_interface=true`, default) instead of silently
  creating it with unintended defaults. `delete: true` reverses every entry.
  New paired verify tools `verify_overlay` / `verify_overlay_service`.
- Generic `orchestrator(name, action, device, site, params, ...)` dispatcher
  (flat toolset): single discoverable entry point routing to any multi-step
  orchestrator (`vsx_pair`, `l3_link`, `access_port`, `static_vxlan`,
  `evpn_vlan`, `radius_dot1x`, `overlay`, `overlay_service`) by name, mirroring
  what calling `configure_interface`/`routing`/`security`/`redundancy` with
  that scope already does — a thin router, no new write logic.
  `orchestrate_fabric_underlay` stays out of scope (its `spines`/`leafs` lists
  don't fit a single device/site target — call it directly, unchanged).
- 14 new tests (`tests/test_overlay_orchestrators.py`). Flat toolset now
  advertises 28 tools (was 27) — `test_server_split_regression.py` updated.

## [1.5.0] — 2026-09-27

Wave 3: orchestrators. Multi-step workflows composed from the atomic
`configure_*` primitives, each supporting create/update (idempotent) AND
teardown (`delete: true`), running through the usual plan -> dry_run_token ->
apply cycle (auto-checkpoint, compacted results, per-device step list in the
plan). New module `tools/tools_orchestrate.py`.

### Added
- `configure_interface_group` (`configure_interface(scope='interface_group')`)
  + `verify_interface_group` + `get_interface_groups`
  (`get_interfaces(scope='interface_group')`): manage AOS-CX **interface
  (port-group) speeds** — the CLI `system interface-group <id> speed <speed>`.
  Modelled on the Subsystem resource (`interface_group_speed` writable map, with
  read-only applied/default speed and per-group supported speeds); optional
  `subsystem` targeting (auto-resolved when a single capable subsystem exists),
  `delete: true` resets a group to its default. Speed validated
  (5g|10g|25g|40g|50g|100g|200g) in plan AND apply, plus the per-group hardware
  capability check on apply.
- `orchestrate_vsx_pair` (`configure_redundancy(scope='vsx_pair')`): builds a
  COMPLETE VSX pair on BOTH members in one call — keepalive VRF, routed
  keepalive port, ISL LAG (LACP, all VLANs), `/system/vsx` pairing with role
  mirrored / keepalive IPs swapped / identical system_mac, `vsx-sync`
  features (`config_sync_features`), `linkup_delay_timer`, `split_recovery`,
  `keepalive_udp_port`; reads the operational ISL/keepalive state after apply.
  `delete: true` removes VSX + ISL LAG + keepalive IP/VRF on both members.
- `orchestrate_l3_link` (`configure_interface(scope='l3_link')`): VRF (with
  OPTIONAL RD + EVPN import/export route-targets) -> routed port (IP, MTU,
  description) -> optional OSPF area attachment; `delete` detaches OSPF, clears
  IP/VRF binding, optionally deletes the VRF.
- `orchestrate_access_port` (`configure_interface(scope='access_port')`): `no
  routing` + access VLAN (+ tagged voice VLAN) + description + `no shutdown` +
  spanning-tree admin-edge / bpdu-guard / root-guard / loop-guard + optional
  802.1X/MAC-auth (`port_auth` block = configure_port_auth keys), per port
  tolerant, ranges accepted; `delete` clears port-access and resets the ports.
- `orchestrate_radius_dot1x` (`configure_security(scope='radius_dot1x')`):
  RADIUS server group -> servers -> GLOBAL `aaa authentication port-access
  dot1x|mac-auth authenticator enable` bound to the group (+ accounting) ->
  `radius dyn-authorization` (CoA) -> roles -> per-port 802.1X; `delete`
  unwinds in reverse order. Passkeys are masked in the plan.
- `orchestrate_static_vxlan` (`configure_interface(scope='static_vxlan')`):
  static VXLAN without EVPN — VTEP interface (source IP, UDP port,
  inter-VXLAN bridging mode) -> VLAN + L2VNI mappings -> static tunnel
  endpoints to every remote VTEP (VNIs per peer, default all); `delete`
  removes peers -> L2VNIs -> VLANs (-> VTEP interface on request). Verify
  twin `verify_static_vxlan` (peers + every VLAN<->VNI map on the VTEP).
- `orchestrate_evpn_vlan` (`configure_routing(scope='evpn_vlan')`): VLAN ->
  (VXLAN interface source IP) -> L2VNI mapping under `vxlan_interface` ->
  `evpn vlan <id>` with EXPLICIT `rd` + `import_rts` / `export_rts`
  (default 'auto', `route_target_auto_mode` default|legacy) -> optional anycast
  SVI (VRF, IP, active-gateway). `evpn=false` for Stub-VTEP. `delete` removes
  SVI -> RT -> L2VNI -> VLAN. Complements `configure_service(scope='vlan')`
  (fabric discovery + RT deduction) when the RD/RT must be given explicitly.
  `set_evpn_vlan_rt` now accepts 'auto' route-target / RD values. Verify twin
  `verify_evpn_vlan` (VLAN / L2VNI / RD-RT / SVI read-back).
- Verify twins: `verify_vsx_cluster` (both members, role/system-mac consistency),
  `verify_access_port`, `verify_radius_dot1x`.
- `configure_hostname(hostnames={device: hostname, ...})` (or a list of
  `{device, hostname}`): rename 50 switches in ONE call, one status per device.
- Client primitives: `configure_l2_access_port` / `reset_l2_access_port` /
  `read_access_port` (Interface.stp_config), `reset_routed_interface`,
  `set_port_access_global` / `read_port_access_global` (System.aaa dot1x /
  mac-auth / accounting groups + radius_dynamic_authorization),
  `list_radius_servers`, `remove_ospf_interface`.

### Changed
- **Per-device addresses**: `ip_address` (configure_loopback, configure_routed_port,
  orchestrate_l3_link) and `source_ip` / `vxlan_source_ip` (configure_vxlan_interface,
  orchestrate_static_vxlan, orchestrate_evpn_vlan) now accept a `{device: value}`
  mapping. A single value for several devices — or duplicates inside the mapping — is
  REFUSED before any write, EXCEPT when the two devices sharing it are the two members
  of one VSX cluster (checked live: same configured system_mac / operational system
  id — anycast VTEP). `orchestrate_static_vxlan(full_mesh=true)` derives the static
  peers from the mapping (each VTEP peers with the others, never with itself);
  `configure_vxlan_interface` also skips a static peer equal to the device's own
  source IP.

### Notes
- VRF RD / EVPN RT handling is unchanged and optional everywhere: VRF-level
  `rd` + `evpn_import_route_targets` / `evpn_export_route_targets`
  (`configure_vrf`, `orchestrate_l3_link`) and per-address-family RTs
  (`configure_vrf(address_families=[...])`).

## [1.4.0] — 2026-09-27

Agent-feedback release after a from-scratch campus deployment (VLAN / VSX /
MC-LAG / SVI / 802.1X on 6 switches, ~30 of 45 tool calls had to fall back
to `run_ssh_commands`). Fixes the blocking frictions and the ergonomics gaps.

### Fixed
- **SSH prompt detection**: `interface 1/1/1-1/1/24` (prompt
  `(config-if-<1/1/1-1/1/24>)#`) — and in fact ANY config sub-mode whose name
  contains `/`, `<`, `>` or `,` — timed out because the prompt regex only
  allowed `[A-Za-z0-9._-]` inside the parentheses. The pattern now accepts any
  mode string; interface ranges work in `run_ssh_commands`.
- **SSH session no longer killed on a single prompt timeout**: the client
  first tries to re-synchronise the channel (bare newline, 3 s); only if that
  fails is the pooled session invalidated. The error carries the partial
  output and the remaining batch commands keep running. `_ssh_exec` retries
  only when the pooled session really died (no silent replay of a config
  command that merely timed out).
- **Write tools were single-device only**: `_resolve_devices` ignored lists and
  comma-separated strings (`device='A,B,C'` became one bogus name). It now
  accepts one name/IP, a list, a JSON-array string or a CSV string, so EVERY
  `configure_*`, `verify_*`, `backup_config` and `manage_config` call fans out
  over several devices in one call (per-device results + summary), exactly
  like the `get_*` reads already did.
- `configure_security(scope='port_auth')` crashed with `'bool' object has no
  attribute 'get'` on `methods: {dot1x: true}` and pushed a raw string
  `auth_precedence` to the switch (HTTP 400). Parameters are now normalised and
  validated BEFORE the plan: shortcuts `dot1x: true` / `"mac-auth": true` /
  top-level `dot1x=` / `mac_auth=`, `auth_precedence: "dot1x mac-auth"`,
  method aliases (`802.1x`, `mac_auth`, `mac`), CSV `interfaces`. A malformed
  shape returns `invalid_input` + `expected_schema` instead of a 500.

### Added
- `configure_vlan` **batch**: `vlans=[{vlan_id, name, description}, ...]` (or
  a list of ints) combined with several devices = device x VLAN matrix applied
  in ONE plan/apply cycle, one status per cell; a failing VLAN does not stop
  the others (`result.summary.failed_vlans`). Single `vlan_id` unchanged.
- `configure_port_auth` processes each interface independently: a failure on
  one port no longer aborts the 43 others (`result.summary.failed_interfaces`).
  A device with partial failures is reported `ok: false` in the envelope.
- `verbose` flag on the 5 `configure_*` dispatchers. By default long per-object
  result lists (>= 6 items) are compacted to `{count, ok, failed, statuses,
  failed_items, sample}`; `verbose=true` returns the full detail (the 44-port
  port_auth apply went from ~40 KB to a few hundred bytes).
- `configure_hostname` / `verify_hostname` (`configure_interface(scope=
  'hostname')`, one device at a time by design).
- `configure_routed_port(create_vrf=True)` creates a missing non-default VRF
  first (VSX keepalive links, underlay in a dedicated VRF).
- `configure_lag(mtu=...)` — LAG trunk/native/description/MTU/lacp_fallback
  are all settable in the same call.
- `manage_config` accepts `device` list/CSV and `site` (one `write_memory` for
  the whole campus); multi-target result `{status, targets, results, summary}`,
  single-target shape unchanged.

### Changed
- Dispatcher docstrings (`configure_interface` / `configure_security` /
  `configure_routing`) now spell out the multi-device targeting and the exact
  `params` shapes for `routed_port` ("THIS is the tool to put an IP on a
  physical port"), `lag`, `vlan` batch, `aaa`, `user_roles`, `port_auth`
  (incl. `create_roles`) — these tools existed but were invisible to the agent.
- `_coerce_device_list` moved to `core/server_core.py` (single source of truth
  for reads and writes); `dispatch/flat_tools.py` delegates to it.

## [1.3.0] — 2026-09-23

Closes the last gap from `NOTES_MISSING_TOOLS.md` (item #10, added after the
1.2.0 gap-closure pass): DHCP relay had NO read or write tool at all.

### Added
- `get_dhcp_relay(device, interface=None)` — read tool; omit `interface` to
  discover ALL configured DHCP relays on a device in one call, or check a
  single L3 port/SVI. Also reachable as `get_interfaces(scope='dhcp_relay')`
  on the flat toolset.
- `configure_dhcp_relay`/`verify_dhcp_relay` — create/update/delete the DHCP
  relay (helper-address, `ipv4_servers`/`ipv6_servers`, optional
  `bootp_gateway`) on an L3 port/SVI, idempotent, plan/apply. Reachable as
  `configure_interface(scope='dhcp_relay')` on the flat toolset.
- Registered in the legacy `WRITE_TOOLS`/`TOOL_TAGS`/`interface` domain tables
  for `CX_FLAT_TOOLSET=false`.
- Updated the `aoscx-legacy-to-fabric-migration` skill to reference the new
  VSX/static-route/redistribute/DHCP-relay/Extended-Edge tools added in 1.2.0
  and 1.3.0 instead of the `run_ssh_commands` workarounds it previously
  documented — no known tool gaps remain for that workflow.

## [1.2.0] — 2026-09-22

Closes the atomic-tool gaps identified for the `aoscx-legacy-to-fabric-migration`
skill (see former `NOTES_MISSING_TOOLS.md`, git-ignored working notes).

### Added
- `configure_vlan`/`verify_vlan` — bare VLAN definition (no VNI/SVI/RT), decoupled
  from `configure_service(scope='vlan')`.
- `configure_svi`/`verify_svi` — atomic SVI (routed VLAN interface) create/update/
  delete, with optional anycast active-gateway.
- `configure_trunk`/`verify_trunk` — atomic tagged-VLAN add/remove on a trunk
  interface.
- `configure_interface_admin`/`verify_interface_admin` — admin up/down a plain L2
  port (not a LAG member or routed port).
- `configure_vrf` gained a `delete` flag (was create/update only).
- `configure_static_route`/`verify_static_route` — static route + nexthops
  (forward/nullroute/reject, distance, tag, BFD, egress port).
- `configure_redistribute`/`verify_redistribute` — route redistribution into BGP
  (per address-family) or OSPF.
- `configure_vsx`/`verify_vsx` — VSX pairing (role, ISL/keepalive ports+VRF,
  system-mac). Symmetric pairing in one call via `peer_device` (role/keepalive
  IPs mirrored automatically); `delete=True` tears down the pairing. New
  `configure_redundancy` flat dispatcher (mirrors the existing `get_redundancy`
  read dispatcher) added to the flat toolset (26 tools advertised).
- `create_vlan_service`/`configure_service(scope='vlan')` gained an `evpn: bool`
  flag (default `True`): `evpn=False` maps the VLAN to a VNI WITHOUT an EVPN
  route-target, for Extended Edge / Stub-VTEP devices that don't run BGP-EVPN.
- All new `configure_*`/`verify_*` tools registered in the flat dispatchers
  (`configure_interface`/`configure_routing`/`configure_redundancy` scopes) and,
  for `CX_FLAT_TOOLSET=false`, in the legacy `WRITE_TOOLS`/`TOOL_TAGS`/`DOMAINS`
  tables.

### Fixed
- `configure_service(scope='vlan')` (flat dispatcher) always raised
  `TypeError: create_vlan_service() got an unexpected keyword argument 'device'`
  — `create_vlan_service`/`delete_vlan_service` take `devices` (a list), not
  `device`. The dispatcher now adapts the single/list `device` argument before
  calling through.
- `create_vlan_service`'s Route-Target auto-deduction path raised
  `ModuleNotFoundError: No module named 'aruba_client'` (stale pre-package-split
  import) on every EVPN-fabric plan/apply that needed RT deduction (i.e. most
  of them) — fixed to `from clients.aruba_client import ArubaOSCXClient`.

## [1.1.0] — 2026-09-18


Production hardening release.

### Added
- `GET /healthz` — unauthenticated, secret-free health snapshot (version,
  uptime, inventory devices/sites/sources/last error, auth tokens & LOCKED
  state, audit config, write-safety config, pooled sessions, tools
  advertised). Returns **503** when LOCKED or the inventory is empty; the
  Docker `HEALTHCHECK` now relies on it.
- Firmware **auto-checkpoint** (confirmed commit) around every `configure_*`
  apply: armed before the write, confirmed on success; a failed or interrupted
  apply is reverted by the switch itself after `CX_AUTO_CHECKPOINT_MINUTES`.
  Env: `CX_AUTO_CHECKPOINT` (default `true`), `CX_AUTO_CHECKPOINT_MINUTES`
  (default `10`). Opt out globally (`CX_AUTO_CHECKPOINT=false`) or per call
  (`auto_checkpoint=false` on the flat `configure_*` dispatchers).
- `CX_PROTECTED_OBJECTS` — comma-separated fnmatch globs (URL-decoded REST
  path) that refuse PUT/DELETE unless the call passes `force=true`
  (e.g. `/system/vrfs/mgmt`, `*/bgp_neighbors/spine-RR`,
  `/system/interfaces/lag*`). `force` parameter on the flat
  `configure_*` dispatchers.
- **Rollback for created objects**: a `rollback_id` is now returned by every
  successful apply; loopbacks, VRFs and L3 VNIs *created* by a `configure_*`
  apply can be undone with `rollback(rollback_id)` (in addition to the
  VLAN-service steps).
- `dry_run_token` enforcement on the **flat toolset** (`configure_interface`,
  `configure_routing`, `configure_security`, `configure_service`): `plan`
  returns a token, `apply`/`delete` requires it, the plan hash is re-checked
  before writing (TOCTOU guard), tokens are single-use.
- `ARUBA_VERIFY_SSL` (default `true`) and `ARUBA_CA_BUNDLE` (internal CA PEM,
  `./certs` volume) — TLS verification towards switches and sources of truth.
- `get_lldp_neighbors(interface=…)` filter; one wildcard GET
  (`/system/interfaces/*/lldp_neighbors`) instead of one GET per interface.
- Versioned image: `VERSION` file, `CX_VERSION` build arg / env, OCI
  `org.opencontainers.image.version` label, compose tag
  `hpe-cx-mcp:${CX_VERSION}`.
- README §9 operations runbook.

### Changed
- **All update-branch PUTs go through `_put_merge`** (GET `selector=writable`
  → deep-merge → PUT full object). A sparse PUT on AOS-CX resets every omitted
  attribute; this removes the class of incident where updating a peer-group /
  interface / VRF wiped its sibling attributes. A guard test fails the build if
  a raw sparse PUT is reintroduced.
- Shipped compose defaults are now production-grade: `CX_AUDIT_ENABLED=true`
  (`writes`, mirrored to stdout), `CX_REQUIRE_DRY_RUN_TOKEN=true`,
  `CX_AUTH_ENABLED=true`, TLS verification on.

### Security
- Bearer auth guidance: one token per client, revoke + hot-reload
  (`security/cx_reload.py`), LOCKED mode documented.

## [1.0.0] — 2026-09-03

- Baseline: flat toolset (25 dispatchers), Bearer auth + audit (opt-in),
  write-safety tokens (legacy `invoke_tool` path), directory split
  (`core/`, `clients/`, `tools/`, `dispatch/`, `security/`).
