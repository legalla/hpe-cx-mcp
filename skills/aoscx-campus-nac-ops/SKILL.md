---
name: aoscx-campus-nac-ops
description: Deploy and troubleshoot 802.1X/MAC-Auth Network Access Control (NAC) on ArubaOS-CX campus switches via the cx-mcp tools. Use for NAC rollout planning, RADIUS/TACACS+ reachability issues, role/VLAN assignment mismatches, and client authentication failures.
---

# AOS-CX Campus NAC Operations

Domain knowledge for 802.1X/MAC-Auth port access on ArubaOS-CX campus
switches, mapped to `cx-mcp` tool calls. Pair with the
`rollout_8021x_guide` and `troubleshoot_client_8021x` prompts.

## Building blocks

- **Authentication methods**: 802.1X (EAP, needs a supplicant) and
  MAC-Auth (MAB — the switch authenticates by MAC address, for devices
  without a supplicant like printers/cameras). A port can run both,
  usually 802.1X first with MAC-Auth as fallback.
- **AAA backend**: RADIUS (most common for NAC — e.g. ClearPass/Central
  NAC) with a local/TACACS+ fallback for management access separate from
  NAC. Check with `get_access(scope='radius'/'tacacs'/'authentication')`.
- **Role assignment**: on successful auth, the RADIUS server returns
  attributes (VSA) mapping the client to a local user-role, VLAN, and/or
  ACL. `get_access(scope='roles')` lists what's locally defined; the
  server must reference a role that actually exists on the switch.
- **GBP/ABP**: Group-Based Policy and Application-Based Policy provide an
  additional segmentation layer beyond simple VLAN assignment —
  `get_access(scope='gbp'/'gbp_maps'/'abp')`.

## Rollout checklist (before enabling on production ports)

1. Confirm the RADIUS/TACACS+ server is reachable FIRST —
   `get_access(scope='radius')`/`scope='tacacs'`. Never enable port-auth
   against an unreachable server; that locks out legitimate clients with
   no fallback unless a fail-open policy is explicitly configured.
2. Confirm the roles the server will return actually exist locally —
   `get_access(scope='roles')`. A RADIUS response naming a non-existent
   role typically falls back to a restrictive/deny state.
3. Roll out with `configure_security(scope='port_auth', action='plan')`
   first — review the plan, then `action='apply'`, then `action='verify'`.
4. Never apply to a port with an active, already-authenticated client
   without warning the user — it forces re-authentication and can drop
   the session.

## Troubleshooting playbook: "a client can't authenticate"

1. `get_access(scope='clients')` filtered to the interface — is the
   client stuck in an auth state (e.g. `authenticating`) or outright
   `unauthorized`?
2. `get_access(scope='client_detail', interface=..., mac=...)` — check
   the assigned role/VLAN and the EAP method/failure reason if present.
3. `get_access(scope='radius')`/`scope='tacacs'` — is the server actually
   reachable right now (not just configured)?
4. `get_access(scope='authentication')` — check the configured group
   order/fallback for the session type (802.1X vs MAC-Auth vs
   management).
5. `get_access(scope='roles')`/`scope='policies')` — does the
   role/policy the server is trying to assign actually exist and make
   sense?
6. Common root causes ranked by frequency: RADIUS unreachable > wrong
   shared secret > role/VLAN referenced by the server doesn't exist
   locally > EAP method mismatch (e.g. server insists on EAP-TLS but the
   supplicant offers PEAP) > port still has a stale MAC-Auth/802.1X
   session cached from a previous device.

## Common pitfalls

- MAC-Auth alone provides weak assurance (any device can spoof a MAC) —
  it should always be paired with a restrictive role, not full access.
- A guest/BYOD role should never be able to reach management VLANs or
  other clients' subnets — cross-check with the `guest_network_audit`
  prompt.
- Changing port-auth config on a port with a live client always
  interrupts that client's session — plan changes for a maintenance
  window when possible.
