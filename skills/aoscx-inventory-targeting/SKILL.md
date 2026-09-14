---
name: aoscx-inventory-targeting
description: Efficiently target ArubaOS-CX devices via the cx-mcp flat-dispatcher tools using device/site/source batching instead of one call per device. Use when planning a multi-device query or write, or when a client seems to only support a single device per call.
---

# AOS-CX Inventory Targeting

Domain knowledge for efficiently addressing devices through `cx-mcp`'s
flat dispatchers (`get_system`, `get_interfaces`, `get_switching`,
`get_routing`, `get_overlay`, `get_redundancy`, `get_access`,
`get_automation`, `get_apps`, `get_config`, `diagnose`, `troubleshoot`,
and the `configure_*` writes).

## Batching parameters

Every read dispatcher accepts three ways to target devices, all fanned
out in a **single batched call** server-side (parallel, not sequential):

- `device`: one device name, a comma-separated string
  (`device='Access-01,Access-02'`), or a real list.
- `site`: targets every device in that site (from the inventory).
- `source`: targets devices from an external source of truth
  (NetBox/Nautobot/Infrahub), intersected with the connectable inventory.

Never loop over devices issuing one tool call per device when a
`site=`/comma-separated `device=` call would do it in one round-trip —
this matters both for latency and for keeping the fan-out's shared
per-device error handling (`results`/`errors`/`summary` envelope).

## Discovering devices before targeting

- `manage_inventory(scope='find', site=..., source=..., role=..., model=...,
  tag=...)` — search by filters before committing to a target list.
- `manage_inventory(scope='resolve', device=<name/alias/IP>)` — resolve a
  device name/alias/IP to its canonical inventory record when unsure of
  the exact name to pass.
- `manage_inventory(scope='sources', probe=True)` — list configured
  inventory sources and optionally test reachability, useful when a
  `source=` filter returns nothing unexpectedly.

## The "device as a string" gotcha

Some MCP clients serialize an array parameter as a literal string
(`'["A","B"]'`, `"['A','B']"`, or `"A,B"`) instead of a real JSON array.
The server-side `_coerce_device_list` handles all of these forms
(real list, JSON-array string, single-quoted, comma-separated, single
name) — so when in doubt, or if a client seems to reject an array,
**pass a plain comma-separated string**: it works on every client,
whereas a real array only works if the client's cached tool schema is
fresh. If batched targeting still silently returns only one device's
results, suspect a stale client-side tool-schema cache (fixed by a full
client reload/reconnect) before assuming the server doesn't support it.

## Envelope shape to expect back

Every fan-out returns `{scope, targets, results: {device: data}, errors:
{device: error}, summary: {ok, failed, total, devices}}` — always check
`errors` even when `results` has data, since a partial batch (some
devices succeeded, others failed) is a normal, non-exceptional outcome,
not a tool failure.

## Common pitfalls

- Passing a `site` that doesn't exist yields `{"error": "no target
  device — provide device, site or source"}`, not an exception — check
  for that error key rather than assuming an empty result means "no
  devices matched".
- `limit` (when set) truncates list fields per device and annotates
  `<field>_truncated: {shown, total}` — don't mistake a truncated result
  for the complete dataset when summarizing counts back to the user.
