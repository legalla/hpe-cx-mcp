---
name: aoscx-change-management
description: Safely make configuration changes on ArubaOS-CX switches using checkpoint/backup/compare/restore via the cx-mcp tools. Use before any write operation (configure_*, port-auth rollout, VLAN provisioning) to ensure changes are reversible.
---

# AOS-CX Change Management

Domain knowledge for making reversible configuration changes on
ArubaOS-CX switches via `cx-mcp`'s `manage_config`/`backup_config` tools.
Pair with the `pre_change_safety_guide` prompt.

## Core principle: checkpoint before, diff after, restore if needed

Every non-trivial change should follow this sequence:

1. **Checkpoint**: `manage_config(device, action='create_checkpoint',
   name=<descriptive>)`. Checkpoint names are rejected if they collide
   with `running-config`/`startup-config` (reserved) or an existing
   checkpoint name (409) — use a name with a timestamp or change-ticket
   reference to avoid collisions across repeated runs.
2. **Plan before apply**: every `configure_*` dispatcher defaults to
   `action='plan'` — always show the plan and get explicit confirmation
   before `action='apply'`. Never skip straight to apply on a
   user's behalf.
3. **Diff after**: `manage_config(device, action='diff', config_a=<
   checkpoint name>, config_b='running-config')` — show exactly what
   changed, not just "success".
4. **Restore if needed**: `manage_config(device, action='restore_checkpoint',
   name=<checkpoint name>, target='running-config')` — always confirm
   with the user before restoring, this discards whatever was applied
   after the checkpoint.
5. **Persist only when satisfied**: `manage_config(device,
   action='write_memory')` copies running-config to startup-config. Do
   this only after the user is happy with the result — an unwanted
   change that was never persisted is undone by a simple reboot; one
   that was written to startup-config is not.

## Known constraints (don't promise what the platform can't do)

- There is **no delete API for checkpoints** — cleanup is CLI-only
  (`no checkpoint <name>`), out of `cx-mcp` scope. Don't create
  throwaway checkpoints expecting to remove them via the MCP tools;
  they'll accumulate.
- `auto_checkpoint`/`confirm` (a timed auto-rollback) is available for
  changes made outside this MCP (e.g. directly via CLI) as a safety net:
  arm a timer before the change, `confirm` it after — if not confirmed in
  time, the firmware reverts automatically. This is a good suggestion for
  a user about to make a risky manual change.
- A REST **PUT on an existing resource replaces the writable attributes
  wholesale** — any field not included in the write is reset to firmware
  default. This means an idempotent "update" write can silently wipe
  unrelated settings on a shared object (e.g. a BGP peer-group) if the
  write path only sends a partial body. Prefer targeting NEW/isolated
  objects when testing a `configure_*` tool for the first time, not a
  live shared object (real peer-groups, production SVIs).

## When NOT to use a checkpoint

- Pure read operations (`get_*`, `diagnose`) never need one.
- `action='plan'` calls never touch the device — no checkpoint needed
  until `action='apply'` is about to run.

## Common pitfalls

- Forgetting `write_memory` after a change the user wants to keep — it
  will be lost on the next reboot.
- Restoring a checkpoint without diffing first — always show what will
  be reverted, not just that a restore is available.
- Re-running `create_checkpoint` with the same name across retries —
  409 conflict; use a fresh, unique name per attempt.
