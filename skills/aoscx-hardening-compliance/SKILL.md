---
name: aoscx-hardening-compliance
description: Audit ArubaOS-CX switches (Data Center or Campus) for compliance with the official "AOS-CX 10.17 Hardening Guide" (published Nov 2025) via the cx-mcp tools, and report exactly what is missing/misconfigured. Use when the user asks about hardening compliance, security baseline audit, STIG/CIS-like checks, or "is this switch/site hardened".
---

# AOS-CX Hardening Compliance Audit

Grounded in the official **AOS-CX 10.17 Hardening Guide** (All Switch Series,
published November 2025, version 1). Audit one or more ArubaOS-CX devices
against the control domains below using `cx-mcp` tools, then report a
per-domain compliant/gap verdict plus concrete remediation (the exact CLI
commands from the guide).

## Primary evidence source: the running-config text

Most controls in the guide are CLI configuration lines, so the fastest,
most reliable check is to pull the CLI running-config once per device and
search it for the keywords listed per domain below:

```
get_config(device=<device>, scope='running')
```

Then cross-check the handful of domains that have a dedicated structured
`cx-mcp` scope (listed per domain). Only fall back to
`get_config(scope='raw', path=...)` when neither the running-config text
nor a dedicated scope covers a control — and if a raw path 404s, mark that
domain `unknown`, never `compliant`.

## Control domains

### 1. Factory defaults & physical security
- Admin password set (implicit — a switch with no password can't be reached
  over the API at all; if reachable, this is already satisfied).
- Management VRF segregation: management services should be restricted to
  the `mgmt` VRF where the platform supports it. Grep for `ssh server vrf`
  / `https-server vrf` lines; on platforms without a dedicated mgmt port
  (6100/6000/4100i), check for a Control-Plane ACL or SSH allow-list instead
  (see domain 8).
- Front-panel factory-reset should be **disabled** (default) — gap if grep
  finds `front-panel-security factory-reset` enabled.
- USB Auxiliary port / Bluetooth should be disabled when not in use — gap if
  neither `no usb` nor `bluetooth disable` is present (both default to
  *enabled*).

### 2. Firmware & ServiceOS
- Firmware is always signature-verified at boot (no config to check).
- ServiceOS password prompt should be enabled — grep for
  `system serviceos password-prompt`; absence is a gap (default: no password
  required to reach ServiceOS admin).
- Enhanced secure mode (disables `start-shell` + risky ServiceOS commands)
  is a boot-time system state, not a running-config line — not verifiable
  from `get_config(scope='running')`; mark `unknown` unless a dedicated
  read exists, and recommend the user confirm via CLI `show system` /
  `secure-mode`.

### 3. User management & password control
- Password complexity should be enabled with sane minimums — grep for a
  `password complexity` block containing `enable` (default: disabled).
- Non-default export password — grep for `service export-password`
  (presence indicates it was changed from the identical factory default).
- Per-user management-interface restriction — grep `management-interface`
  under `user` lines; flag admin-level users left with all four
  (ssh/telnet/https-server/console) if that's broader than needed.
- Cross-check roles/least-privilege: `get_access(device, scope='roles')`.

### 4. AAA (authentication, authorization, accounting)
- `get_access(device, scope='authentication')`, `scope='radius'`,
  `scope='tacacs'`, `scope='accounting'` for the structured view.
- Also grep running-config for: `aaa authentication login`,
  `aaa authentication login-attempts` / `console-login-attempts` (brute-force
  lockout), `aaa authorization commands`, `aaa accounting`,
  `radius-server auth-type chap` / `tacacs-server auth-type chap` (CHAP is
  stronger than the PAP default), `radius-server host ... tls` (RadSec —
  recommended over plain RADIUS/UDP).
- Gap: no external RADIUS/TACACS+/RadSec server configured (local-only), no
  login-attempt lockout configured, PAP still in use, plain RADIUS instead
  of RadSec, no accounting.

### 5. SSH hardening
- `get_system(device, scope='ssh')` for the structured VRF-level view.
- Grep running-config for: `ssh server allow-list` (+ `enable`), `ssh
  ciphers`, `ssh macs`, `ssh key-exchange-algorithms`, `ssh
  host-key-algorithms`, `ssh public-key-algorithms` (only needed for
  NDcPP/Common-Criteria environments — defaults are already OpenSSH-safe),
  `ssh server port` (non-default port hardening, optional), `user ...
  authorized-key` (public-key auth in use — preferred over passwords).
- Telnet must be disabled — flag any `telnet-server`/`telnet` enable line
  found (Telnet is not enabled by default and is never recommended).
- Gap: Telnet enabled anywhere; SSH allow-list/control-plane ACL absent on
  an Internet-facing or otherwise exposed management network.

### 6. Session management & shell access
- Grep for a `cli-session` block with `max-per-user`, `timeout` (guide
  recommends 5–10 min for sensitive networks, 15 min otherwise), and
  `tracking-range`.
- Shell access should be restricted — either enhanced secure mode (domain 2)
  or an RBAC/TACACS+ rule denying `start-shell` to non-privileged users
  (grep user-group rules for `deny cli command "start-shell"` or similar).

### 7. SNMP
- Grep for `snmp-server community` (flag default-looking strings like
  `public`/`private`), `snmp-server snmpv3-only` (should be present —
  disables v1/v2c entirely), `snmpv3 user ... auth ... priv ...` (SNMPv3
  users should exist with SHA/AES, not weaker algorithms).
- Gap: SNMP enabled without `snmpv3-only`, or a guessable community string,
  or no source ACL bound to a community.

### 8. Control-plane ACLs
- Grep for `apply access-list ip <name> control-plane vrf <vrf>` — presence
  means management/routing-protocol access is restricted by source subnet.
  Especially important on 6100/6000/4100i platforms which have no mgmt VRF.
- Cross-reference the SSH allow-list (domain 5) and BGP-peer ACL entries
  (domain 14) — a control-plane ACL takes precedence over the SSH allow-list
  if both are configured.

### 9. Time synchronization (NTP)
- Grep for `ntp authentication`, `ntp authentication-key ... md5`, `ntp
  server ... prefer`, `ntp vrf`.
- Gap: NTP not configured at all, or configured without authentication.
  Accurate, authenticated time matters for log correlation, certificate
  validation and OSPF/BGP keyed authentication timers.

### 10. Secure copy & PKI/TLS
- File transfers should use SFTP/SCP, never plaintext TFTP (practice, not a
  persistent config flag to grep).
- PKI: grep for `crypto pki ta-profile` / `crypto pki certificate` and
  whether `local-cert` (self-signed) is still the certificate bound to
  `https-server`/`radsec-client`/`syslog-client` — a CA-signed leaf cert is
  recommended over the self-signed default.
- TLS: grep for `tls check-key-usage` (should be present/on — required for
  NDcPP profiles, disabled by default). Minimum TLS version is always 1.2.

### 11. Secure logging
- Grep for `logging <host> ... vrf <vrf>` and whether
  `include-auditable-events` is set (adds accounting/security logs to the
  forwarded stream). Prefer a TLS-transported syslog client over UDP/TCP.
- Cross-check actual log flow with `get_logs(device, limit=20)`.

### 12. Control Plane Policing (CoPP)
- CoPP is always active (cannot be disabled) with a factory default policy
  rate-limiting classes like `bgp`, `ospf-unicast`, `arp-broadcast`,
  `arp-protect`, `stp`, `ntp`, `lldp`, etc. Grep for a custom `copp-policy
  <name>` + `apply copp-policy <name>` to see if defaults were reviewed and
  tuned for the deployment; absence isn't automatically a gap (defaults are
  reasonable) but worth flagging as `unknown`/`unreviewed` rather than
  asserting compliance either way.

### 13. Layer-2 hardening (spanning tree, DHCP, ARP/ND)
- **Spanning tree**: `get_switching(device, scope='spanning_tree')` for live
  per-port state; grep running-config for `spanning-tree bpdu-guard` (edge
  ports) and `spanning-tree root-guard` (uplinks toward access/server
  ports that must never become root).
- **DHCP snooping**: grep for `dhcpv4-snooping` / `dhcpv6-snooping`
  (global + per-VLAN), `dhcpv4-snooping trust` / `dhcpv6-snooping trust`
  (uplink ports), `dhcpv4-snooping authorized-server` /
  `dhcpv6-snooping authorized-server`, `dhcpv6-snooping guard-policy`.
- **Dynamic ARP Inspection**: grep for `arp inspection` (VLAN context) and
  `arp inspection trust` (interface context — all interfaces are untrusted
  by default). Requires DHCP snooping or static IP bindings to be useful.
- **ND snooping / RA guard / IPv6 destination guard / IP source lockdown**:
  grep for `nd-snooping`, `nd-snooping ra-guard`,
  `ipv6 nd-snooping ra-guard policy`, `ipv6 destination-guard`,
  `ipv4 source-lockdown` / `ipv6 source-lockdown`.
- Gap: any access/edge VLAN with DHCP clients but no DHCP snooping/ARP
  inspection/ND snooping enabled — the classic campus-access gap.

### 14. Routing protocol security (DC + L3 campus)
- **OSPF**: grep for `passive-interface default` on the router process (all
  OSPF-enabled interfaces should default to passive, then be selectively
  un-passived only where a real neighbor is expected) and
  `ip ospf authentication hmac-sha-512` (or another non-null method — null
  auth is the vendor default and a gap) plus `ip ospf sha-key` / `keychain`.
  OSPFv3: `area <n> authentication ipsec` / `area <n> encryption ipsec`.
- **BGP**: grep for `neighbor <ip> password` (MD5 session auth) and
  `neighbor <ip> ttl-security-hops` (GTSM), plus the control-plane ACL
  entries for TCP/179 (domain 8). Gap: any eBGP/iBGP neighbor without MD5
  and/or TTL security, or without a corresponding control-plane ACL.
- Cross-check with `get_routing(device, scope='bgp_config')` /
  `scope='ospf_overview')` for the live neighbor list to match against.

### 15. Multicast security (mainly DC / AV campus)
- Grep for `router pim` + `accept-register access-list` (RP source/group
  filtering), `accept-rp ... access-list` (rogue-RP prevention),
  `pim-ssm range-access-list`, `router msdp` + `password` (MD5 between
  MSDP peers) + `sa-filter in/out access-list`.
- SSDP/UPnP: if not needed, grep for a static multicast route or ACL/policy
  dropping group `239.255.255.250` (IPv4) / `FF0x::C` (IPv6); flag if SSDP
  traffic is unfiltered and unused in the environment.
- IGMP/MLD snooping group policy: grep `ip igmp snooping apply access-list`
  / `ipv6 mld snooping apply access-list`.

### 16. NAE scripts (built-in anomaly detection)
- `get_automation(device, scope='nae_scripts')` — check whether HPE's
  certified hardening-support scripts are installed/running:
  `copp.5.1` (CoPP drop anomalies), `stp_bpdu_tcn_rate_monitor.2.0` (STP
  BPDU/TCN flood detection), `arp_request_monitor.2.0` (ARP flood
  detection). Gap: none of these present on a device that would benefit
  from them (any access/edge switch, any DC leaf).

## Output format

Report, per device, a table: `domain | status (compliant/gap/unknown) |
evidence (the matched/missing config line) | remediation (the exact CLI
command from the guide)`. Finish with a prioritized remediation list —
fix Telnet/AAA/SNMP-community gaps first (highest exposure), then
SSH/logging/NTP, then L2 (DHCP snooping/ARP inspection/BPDU-guard), then
routing-protocol and multicast hardening.

## Notes on tool-coverage gaps

Enhanced secure mode, ServiceOS-only settings, and live CoPP drop counters
have no dedicated `cx-mcp` scope and aren't always visible in
running-config — mark these domains `unknown` rather than guessing, and
suggest the user confirm directly via CLI (`show secure-mode`, `show
copp-policy default`) if a definitive answer is required.

## Appendix: device decommissioning / RMA checklist

Not part of a day-2 compliance audit (these steps intentionally take the
device offline) — only relevant when the user is retiring or shipping a
device back to HPE. From the guide's "Trusted Supply Chain" chapter: boot
in enhanced secure mode, disable the USB port, shut down all physical
interfaces and the mgmt port, disable ssh/https-server/snmp-server on all
VRFs, enable strict password complexity, enable the ServiceOS password
prompt, disable the HPE Aruba Networking Central client
(`hpe-anw-central` / `disable`), and restrict SSH to NDcPP-approved
algorithms only.
