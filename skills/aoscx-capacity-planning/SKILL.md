---
name: aoscx-capacity-planning
description: Monitor ArubaOS-CX switch capacity (hardware scale limits), licensing (feature packs) and PoE power budget via the cx-mcp tools. Use when the user asks about resource exhaustion, license compliance, or PoE headroom for adding new devices.
---

# AOS-CX Capacity Planning

Domain knowledge for tracking resource, licensing and PoE headroom on
ArubaOS-CX switches via `cx-mcp`. Pair with the
`capacity_and_license_review` and `poe_budget_check` prompts.

## Capacity (hardware scale limits)

- `get_system(device, scope='capacity')` exposes both the platform's
  scale limits (`capacities`, e.g. max VXLAN interfaces, max routes, max
  ACL entries) and the current consumption (`capacities_status`), merged
  into a `utilization` list sorted most-used first.
- A resource above ~80% utilization deserves a proactive flag even if
  it's not yet at the hard limit — provisioning workflows
  (`configure_service`, `create_generic_system`-style writes) can push it
  over during a busy change window.
- Utilization is platform/model-specific — the same feature (e.g. VXLAN
  interfaces, ACL entries) has a different ceiling on a fixed 1U switch
  vs. a modular chassis. Never assume a threshold from one platform
  applies to another; always read the actual `capacity`/`capacities`
  pair for that device.

## Licensing (feature packs)

- `get_system(device, scope='feature_pack')` returns the licensing
  `state` (`valid`/`expired`/`central_connected`/`central_disconnected`/
  `honor_config`/…) and the per-feature `mode` (`active`/`strict`/
  `honor`) and `enforcement_method`.
- `honor` mode means a feature is running without being properly
  licensed yet (grace/trial behavior) — flag every feature in `honor`
  mode as a compliance item, not just an informational note.
- `central_disconnected` doesn't necessarily mean a license problem by
  itself (it can just mean the switch isn't cloud-managed) — check
  `management_mode` (`cloud_managed`/`file_based`/`honor`) alongside
  `state` before concluding there's a licensing gap.

## PoE power budget

- `get_interfaces(device, scope='poe')` returns per-port draw (watts)
  plus the chassis-wide PoE power budget (total available vs. used).
- A chassis with little headroom left is a real deployment blocker for
  adding new APs/phones/cameras — flag any switch above ~80% of its PoE
  budget before a rollout that adds more powered devices.
- Cross-check port-level anomalies: a port expected to power a device
  (per naming/description) drawing 0W may indicate a failed PD, a bad
  cable, or PoE disabled on that port — not necessarily a budget issue.

## Site-wide review pattern

For a whole site, pass `site=<site>` (not a single `device`) to
`get_system`/`get_interfaces` so all switches are checked in one batched
call rather than one request per device — this matters for larger
campus/DC sites where per-device round-trips add up.

## Common pitfalls

- Don't compare raw utilization numbers across different switch models —
  always look at `utilization_pct`, not the raw `used`/`capacity`
  counts, since the denominators differ per platform.
- A feature-pack `state` of `valid` doesn't guarantee every individual
  feature is in `active` mode — some features can still be `honor` even
  on a licensed switch if they were enabled before the license was
  applied; always check the per-feature `mode`, not just the top-level
  `state`.
