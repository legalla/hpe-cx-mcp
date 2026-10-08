"""Configuration-management tools: running/startup config, checkpoints,
compare, save/rollback and export to an SFTP/TFTP backup server."""

import asyncio

from clients.aruba_client import ArubaAPIError
from core.config_backup import ConfigBackupError, export_config
from core.server_core import mcp, _get_client, _resolve_devices, _device_can_write, _deny_read_only

# ══════════════════════════════════════════════════════════════════════
# TOOLS — Configuration
# ══════════════════════════════════════════════════════════════════════

@mcp.tool()
async def list_configs(device: str) -> dict:
    """List the available configs: running-config, startup-config, checkpoints."""
    async with _get_client(device) as client:
        return await client.list_configs()


@mcp.tool()
async def compare_configs(
    device: str,
    config_a: str = "running-config",
    config_b: str = "startup-config",
    color: bool = True,
    context_lines: int = 3,
) -> dict:
    """Compare two configs (unified diff). config_a/config_b: 'running-config',
    'startup-config' or checkpoint. `color` (ANSI), `context_lines`.
    """
    async with _get_client(device) as client:
        return await client.compare_configs(
            config_a=config_a,
            config_b=config_b,
            color=color,
            context_lines=context_lines,
        )


@mcp.tool()
async def get_config(
    device: str,
    name: str = "running-config",
    diff: str = None,
    mode: str = None,
) -> dict:
    """CLI config (text). `name`: running-config/startup-config/checkpoint. `diff`
    to compare name against this config. `mode`: additions/deletions/shell.
    """
    async with _get_client(device) as client:
        return await client.get_config(name=name, diff=diff, mode=mode)


@mcp.tool()
async def get_full_config(device: str, name: str = "running-config") -> dict:
    """Full config in JSON (REST format), for structural analysis. `name`:
    running-config/startup-config/checkpoint.
    """
    async with _get_client(device) as client:
        return await client.get_full_config(name=name)


@mcp.tool()
async def manage_config(
    device: str = None,
    action: str = None,
    name: str = None,
    source: str = "running-config",
    target: str = "running-config",
    from_config: str = None,
    to_config: str = None,
    config_a: str = None,
    config_b: str = None,
    minutes: int = 10,
    mode: str = None,
    site: str = None,
) -> dict:
    """Config management (checkpoints, backup, copy, restore, diff).
    `device` accepts ONE name, a COMMA-SEPARATED string ('A,B,C') or a list;
    `site` targets a whole site — the action runs on every target in ONE call
    (e.g. a single `write_memory` for 6 switches). With several targets the
    result is {status, targets, results{dev: ...}, summary}.
    `action`:
      - list_checkpoints: list the checkpoints (date, age, author, version).
      - write_memory: running-config → startup-config ("write memory").
      - create_checkpoint: snapshot named `name` from `source` (name must not exist).
      - copy_config: `from_config` → `to_config` (running/startup/checkpoint, src≠dst).
      - restore_checkpoint: restore `name` to `target` (running [default]/startup).
      - auto_checkpoint: arm a confirmed commit (`minutes` 1–60, default 10);
        without `confirm` before the deadline, automatic return to the previous config.
      - confirm: validate the auto checkpoint in progress.
      - diff: compare `config_a`/`config_b` (`mode='deep'` for firmware diff).
    """
    action = (action or "").strip().lower()
    write_actions = {
        "write_memory",
        "create_checkpoint",
        "copy_config",
        "restore_checkpoint",
        "auto_checkpoint",
        "confirm",
    }
    available = [
        "list_checkpoints", "write_memory", "create_checkpoint", "copy_config",
        "restore_checkpoint", "auto_checkpoint", "confirm", "diff",
    ]
    if action not in available:
        return {"status": "error", "error": f"Unknown action: '{action}'.",
                "available_actions": available}
    if action == "create_checkpoint" and not name:
        return {"status": "error", "error": "The 'name' parameter (checkpoint name) is required."}
    if action == "copy_config" and (not from_config or not to_config):
        return {"status": "error",
                "error": "The 'from_config' and 'to_config' parameters are required."}
    if action == "restore_checkpoint" and not name:
        return {"status": "error", "error": "The 'name' parameter (checkpoint to restore) is required."}
    try:
        device_names = _resolve_devices(device=device, site=site)
    except ValueError as exc:
        return {"status": "invalid_input", "error": str(exc)}

    async def _one(dev: str) -> dict:
        if action in write_actions and not _device_can_write(dev):
            return _deny_read_only(dev, f"manage_config:{action}")
        async with _get_client(dev) as client:
            if action == "list_checkpoints":
                return await client.list_checkpoints()
            if action == "write_memory":
                return await client.save_config()
            if action == "create_checkpoint":
                return await client.create_checkpoint(name=name, source=source)
            if action == "copy_config":
                return await client.copy_config(from_config=from_config, to_config=to_config)
            if action == "restore_checkpoint":
                return await client.restore_checkpoint(name=name, target=target)
            if action == "auto_checkpoint":
                return await client.set_auto_checkpoint(minutes=minutes)
            if action == "confirm":
                return await client.confirm_auto_checkpoint()
            a = config_a or "running-config"
            b = config_b or "startup-config"
            if mode == "deep":
                # Native structural diff of the firmware (CLI text), via /configs/{a}?diff=...
                return await client.get_config(name=a, diff=client._uri(f"/configs/{b}"), mode="deep")
            return await client.compare_configs(config_a=a, config_b=b)

    if len(device_names) == 1:
        return await _one(device_names[0])

    async def _safe(dev: str) -> tuple[str, dict]:
        try:
            res = await _one(dev)
            ok = not (isinstance(res, dict) and res.get("status") in ("error", "forbidden"))
            return dev, {"ok": ok, "result": res}
        except Exception as exc:  # noqa: BLE001 - one target must not stop the batch
            return dev, {"ok": False, "error": str(exc)}

    results = dict(await asyncio.gather(*[_safe(d) for d in device_names]))
    failed = [d for d, r in results.items() if not r["ok"]]
    return {
        "status": "ok" if not failed else "partial",
        "action": action,
        "targets": device_names,
        "results": results,
        "summary": {"total": len(device_names),
                    "succeeded": len(device_names) - len(failed),
                    "failed": len(failed), "failed_devices": failed},
    }


@mcp.tool()
async def backup_config(
    device: str = None,
    site: str = None,
    protocol: str = "sftp",
    server: str = None,
    remote_directory: str = None,
    filename_format: str = None,
    source: str = "running-config",
) -> dict:
    """Export a configuration backup campaign to a configured SFTP or TFTP server.

    Target one `device` or every device in `site`. `server` must match the
    configured `CX_BACKUP_<PROTOCOL>_HOST` when that variable is set. `protocol`
    is sftp (default) or tftp. `source` is
    running-config (default) or startup-config. `filename_format` supports only
    `{hostname}` and `{timestamp}`; default: `{hostname}_{timestamp}_config.cfg`.
    SFTP credentials are read only from CX_BACKUP_SFTP_* environment variables;
    TFTP does not use credentials.
    """
    protocol = (protocol or "sftp").strip().lower()
    if protocol not in ("sftp", "tftp"):
        return {"status": "invalid_input", "field": "protocol",
                "error": "protocol must be 'sftp' or 'tftp'."}
    if source not in ("running-config", "startup-config"):
        return {
            "status": "invalid_input",
            "field": "source",
            "error": "source must be 'running-config' or 'startup-config'.",
        }
    try:
        device_names = _resolve_devices(device=device, site=site)
    except ValueError as exc:
        return {"status": "invalid_input", "error": str(exc)}

    async def _backup_one(name: str) -> tuple[str, dict]:
        try:
            async with _get_client(name) as client:
                config = await client.get_config(name=source)
                hostname = name
                try:
                    system = await client.get_system_info()
                    hostname = system.get("hostname") or name
                except Exception:  # noqa: BLE001 - inventory name is a safe fallback
                    pass
                exported = await export_config(
                    protocol=protocol,
                    server=server,
                    remote_directory=remote_directory,
                    filename_format=filename_format,
                    hostname=str(hostname),
                    content=config["content"],
                )
            return name, {"ok": True, "source": source, **exported}
        except (ConfigBackupError, ArubaAPIError, KeyError) as exc:
            return name, {"ok": False, "error": str(exc)}
        except Exception as exc:  # noqa: BLE001 - one target must not stop a campaign
            return name, {"ok": False, "error": str(exc)}

    results = dict(await asyncio.gather(*[_backup_one(name) for name in device_names]))
    failed = [name for name, result in results.items() if not result["ok"]]
    return {
        "status": "exported" if not failed else "partial",
        "protocol": protocol,
        "source": source,
        "targets": device_names,
        "results": results,
        "summary": {
            "total": len(device_names),
            "succeeded": len(device_names) - len(failed),
            "failed": len(failed),
            "failed_devices": failed,
        },
    }


# ══════════════════════════════════════════════════════════════════════
# TOOLS — Debug / raw API
# ══════════════════════════════════════════════════════════════════════

@mcp.tool()
async def get_raw_api(device: str, path: str, depth: int = 2) -> dict:
    """Raw API call."""
    async with _get_client(device) as client:
        return await client.get_raw_api(path, depth)


