"""SSH / CLI escape-hatch tools for the CX MCP server.

These are the raw-access fallbacks (run_ssh_command(s), run_cli_command,
get_cli_supported_commands, get_raw_api) used only when no dedicated tool
covers the need.
"""

import os

from clients.aruba_client import ArubaOSCXClient
from clients.ssh_client import ArubaSSHError, cli_error
from core.server_core import (
    mcp, _get_client, _ssh_exec, _device_can_write, _deny_read_only,
    _is_ssh_write_command,
)

# ══════════════════════════════════════════════════════════════════════
# TOOLS — SSH / CLI
# ══════════════════════════════════════════════════════════════════════

# When enabled (default), a read-only `show …` command that is already covered
# by a dedicated REST/MCP tool is REFUSED on the SSH/CLI escape hatches and the
# agent is redirected to the proper tool. This turns the "fallback only" docstring
# guidance into a hard, prompt-independent guarantee. Set CX_SSH_TOOL_REDIRECT
# to "false" to disable (pure docstring guidance only). Per-call override: force=True.
_SSH_TOOL_REDIRECT = os.getenv("CX_SSH_TOOL_REDIRECT", "true").strip().lower() in (
    "1", "true", "yes", "on",
)


def _dedicated_tool_for(command: str) -> str | None:
    """If a read-only 'show …' command is already covered by a dedicated tool,
    return that tool's name; otherwise None. Reuses the CLI→tool mapping so SSH,
    /cli and search stay consistent."""
    if not isinstance(command, str):
        return None
    normalized = " ".join(command.strip().lower().split())
    best, best_len = None, -1
    for prefix, tool in ArubaOSCXClient._CLI_REST_FALLBACKS:
        if (normalized == prefix or normalized.startswith(prefix + " ")) and len(prefix) > best_len:
            best, best_len = tool, len(prefix)
    return best


def _ssh_redirect_payload(tool: str, command: str) -> dict:
    """Build the 'use the dedicated tool instead of SSH' redirect."""
    return {
        "use_tool": tool,
        "command": command,
        "how": (
            f"A dedicated tool '{tool}' already covers this command — use it instead "
            f"of raw SSH. If '{tool}' is not in your visible tool list, it is a Tier-2 "
            f"tool: discover it with search_tools(query='{tool}'), then run it via "
            f"invoke_tool(name='{tool}', ...). To override and force raw SSH anyway, "
            f"call again with force=true."
        ),
    }


@mcp.tool()
async def run_ssh_command(device: str, command: str, force: bool = False,
                          auto_confirm: bool = False) -> dict:
    """FALLBACK ONLY — use a dedicated tool if one exists, INCLUDING Tier-2 tools
    (discover them first with `search_tools`, then run them via `invoke_tool`).
    Only when no specific tool covers the need, run an arbitrary CLI command
    (e.g. 'show ...' not covered by REST) over SSH. Among the generic escape
    hatches, PREFER this over `run_cli_command` (the /cli REST path is limited).
    If the command is covered by a dedicated tool, this is REFUSED and you are
    redirected to that tool (pass force=true to override). Pagination disabled
    automatically. An interactive '(y/n)' prompt is answered 'n' (command not
    applied, ok=false) unless `auto_confirm=true`. CLI error messages
    (Invalid input, Command incomplete...) return ok=false. Call `logout` at the end."""
    if _SSH_TOOL_REDIRECT and not force:
        tool = _dedicated_tool_for(command)
        if tool:
            return {
                "device": device,
                "command": command,
                "ok": False,
                "redirect": True,
                "error": f"Use the dedicated tool '{tool}' instead of SSH for this command.",
                **_ssh_redirect_payload(tool, command),
            }
    try:
        if _is_ssh_write_command(command) and not _device_can_write(device):
            denied = _deny_read_only(device, "run_ssh_command")
            return {
                "device": denied["device"],
                "command": command,
                "ok": False,
                "error": denied["error"],
                "access_mode": denied["access_mode"],
            }
    except ValueError as exc:
        return {"device": device, "command": command, "ok": False, "error": str(exc)}
    confirmations: list = []

    async def _run(c):
        out = await c.run_command(command, auto_confirm=auto_confirm)
        confirmations.extend(c.last_confirmations)
        return out
    try:
        output = await _ssh_exec(device, _run)
    except (ArubaSSHError, ValueError) as exc:
        return {"device": device, "command": command, "ok": False, "error": str(exc)}
    res = {"device": device, "command": command, "ok": True, "output": output}
    if confirmations:
        res["confirmations"] = confirmations
    declined = [c for c in confirmations if c["answer"] != "y"]
    err = cli_error(output)
    if declined:
        res.update(ok=False, error=f"interactive confirmation declined ('{declined[0]['prompt']}') "
                                   "— command NOT applied; re-run with auto_confirm=true")
    elif err:
        res.update(ok=False, error=f"CLI error: {err}")
    return res


@mcp.tool()
async def run_ssh_commands(device: str, commands: list[str], force: bool = False,
                           auto_confirm: bool = False, stop_on_error: bool = True) -> dict:
    """FALLBACK ONLY — use a dedicated tool if one exists, INCLUDING Tier-2 tools
    (discover them with `search_tools`, then run them via `invoke_tool`). Batch
    variant of `run_ssh_command`: only when no specific tool covers the need, run
    several CLI commands via SSH within a single session. Commands covered by a
    dedicated tool are REFUSED and redirected to that tool (pass force=true to
    override). Each command returns {command, output, ok, executed, error}.
    - interactive '(y/n)' prompts (e.g. `shutdown` on vxlan1,
      `inter-vxlan-bridging-mode`) are answered 'y' with `auto_confirm=true`,
      otherwise 'n' (that command is NOT applied and is ok=false) — the
      session never hangs on them.
    - a CLI error in the output (Invalid input, Command incomplete, '... is
      not configured') makes that command ok=false.
    - `stop_on_error` (default true): after the first failed command the
      remaining ones are NOT sent (`executed: false`, listed in
      summary.not_executed) — avoids applying the rest of a config sequence
      on a half-configured object. Call `logout` at the end."""
    if not commands:
        return {"device": device, "ok": False, "error": "No command provided.", "results": []}
    if _SSH_TOOL_REDIRECT and not force:
        redirects = [
            _ssh_redirect_payload(tool, c)
            for c in commands
            if (tool := _dedicated_tool_for(c))
        ]
        if redirects:
            return {
                "device": device,
                "ok": False,
                "redirect": True,
                "error": ("One or more commands are covered by dedicated tools — use those "
                          "instead of SSH (pass force=true to override). See 'redirects'."),
                "redirects": redirects,
                "results": [],
            }
    try:
        blocked = [c for c in commands if _is_ssh_write_command(c)]
        if blocked and not _device_can_write(device):
            denied = _deny_read_only(device, "run_ssh_commands")
            return {
                "device": denied["device"],
                "ok": False,
                "error": denied["error"],
                "access_mode": denied["access_mode"],
                "blocked_commands": blocked,
                "results": [],
            }
    except ValueError as exc:
        return {"device": device, "ok": False, "error": str(exc), "results": []}
    try:
        results = await _ssh_exec(device, lambda c: c.run_commands(
            commands, auto_confirm=auto_confirm, stop_on_error=stop_on_error))
    except (ArubaSSHError, ValueError) as exc:
        return {"device": device, "ok": False, "error": str(exc), "results": [],
                "summary": {"total": len(commands), "not_executed": list(commands)}}
    failed = [r["command"] for r in results if not r["ok"] and r.get("executed", True)]
    skipped = [r["command"] for r in results if not r.get("executed", True)]
    return {
        "device": device,
        "ok": not failed and not skipped,
        "results": results,
        "summary": {
            "total": len(results),
            "succeeded": len(results) - len(failed) - len(skipped),
            "failed": len(failed),
            "failed_commands": failed,
            "not_executed": skipped,
        },
    }


# TOOLS — CLI
# ══════════════════════════════════════════════════════════════════════

@mcp.tool()
async def get_cli_supported_commands(device: str) -> dict:
    """Try to list the CLI commands (GET /cli rarely supported; prefer run_cli_command)."""
    async with _get_client(device) as client:
        commands = await client.get_cli_supported_commands()
    return {
        "device": device,
        "supported_commands": commands,
        "count": len(commands),
        "note": "GET /cli is not supported by most ArubaOS-CX firmwares. Use run_cli_command with a 'show' command." if not commands else None,
    }


@mcp.tool()
async def run_cli_command(device: str, command: str, force: bool = False) -> dict:
    """LAST-RESORT FALLBACK — use a dedicated tool if one exists, INCLUDING Tier-2
    tools (discover them with `search_tools`, then run them via `invoke_tool`),
    and PREFER `run_ssh_command` over this. Use the /cli REST endpoint for 'show'
    commands ONLY when SSH is unavailable (e.g. only REST/443 reachable, port 22
    blocked). /cli is limited and refuses many commands. If the command is covered
    by a dedicated tool, this is REFUSED and you are redirected to it (pass
    force=true to override). If not executable, returns supported=False with
    'fallback_tool' (equivalent REST tool)."""
    if not command.strip().lower().startswith("show"):
        raise ValueError("Only 'show' commands are allowed.")
    if _SSH_TOOL_REDIRECT and not force:
        tool = _dedicated_tool_for(command)
        if tool:
            return {
                "device": device,
                "command": command,
                "supported": False,
                "ok": False,
                "redirect": True,
                "error": f"Use the dedicated tool '{tool}' instead of /cli for this command.",
                **_ssh_redirect_payload(tool, command),
            }
    async with _get_client(device) as client:
        return await client.run_cli_command(command)


