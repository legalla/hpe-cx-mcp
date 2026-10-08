"""Regression test for the server.py -> server_core.py + tools_*.py split.

Each scenario needs its own interpreter (the toolset mode is decided from env
vars read once at import time, and `mcp`'s tool registry is a process-wide
singleton), so every check below runs `server.py` in a fresh subprocess rather
than importing/reloading it in-process.
"""

import json
import os
import subprocess
import sys

import pytest

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _run_server_snippet(snippet: str, tmp_path, **extra_env) -> dict:
    """Run `snippet` (which must `print(json.dumps(...))` exactly once) inside
    a subprocess that first imports `server`, with a throwaway inventory path
    so startup never touches a real device or a real inventory file."""
    env = {
        **os.environ,
        "ARUBA_DEFAULT_USERNAME": "admin",
        "ARUBA_DEFAULT_PASSWORD": "test",
        "INVENTORY_FILE": str(tmp_path / "missing.yaml"),
        **extra_env,
    }
    code = "import json, server\n" + snippet
    proc = subprocess.run(
        [sys.executable, "-c", code],
        cwd=_REPO_ROOT, env=env, capture_output=True, text=True, timeout=60,
    )
    assert proc.returncode == 0, f"stderr:\n{proc.stderr}\nstdout:\n{proc.stdout}"
    last_line = proc.stdout.strip().splitlines()[-1]
    return json.loads(last_line)


def _tool_names_snippet() -> str:
    return (
        "mgr = getattr(server.mcp, '_tool_manager', None) or getattr(server.mcp, 'tool_manager', None)\n"
        "tools = getattr(mgr, '_tools', None) or getattr(mgr, 'tools', None)\n"
        "print(json.dumps(sorted(tools.keys())))\n"
    )


def test_flat_toolset_advertises_same_25_tools_as_before_the_split(tmp_path):
    names = _run_server_snippet(_tool_names_snippet(), tmp_path, CX_FLAT_TOOLSET="true")
    # 25 dispatchers/kept-atomic tools from the original split + configure_redundancy
    # (added for VSX pairing, mirroring the get_redundancy read dispatcher 1:1)
    # + orchestrate_fabric_underlay (kept-atomic: takes spines/leafs device
    # lists, doesn't fit the single-device configure_*(scope=...) dispatch model)
    # + orchestrator (new generic name/params dispatcher over every multi-step
    # orchestrator, collapsing them into one discoverable entry point)
    # + orchestrate_fabric_overlay (kept-atomic, same spines/leafs shape).
    assert len(names) == 29
    assert "get_system" in names
    assert "configure_service" in names
    assert "configure_redundancy" in names
    assert "orchestrator" in names
    assert "rollback" in names
    assert "manage_inventory" in names
    assert "orchestrate_fabric_underlay" in names
    assert "orchestrate_fabric_overlay" in names


def test_legacy_deferred_tools_and_prefixes_still_resolve(tmp_path):
    names = _run_server_snippet(
        _tool_names_snippet(), tmp_path,
        CX_FLAT_TOOLSET="false", CX_DEFERRED_TOOLS="true", CX_TOOL_PREFIXES="true",
    )
    # Renamed <domain>__<name> by tool_prefixes.py (e.g. "meta__invoke_tool").
    assert any(n.endswith("invoke_tool") for n in names)
    assert any(n.endswith("search_tools") for n in names)
    assert len(names) > 0


@pytest.mark.parametrize("name", [
    "get_system_info", "get_bgp_neighbors", "get_evpn_config", "get_vsx_status",
    "get_nae_scripts", "get_port_access_clients", "list_configs",
    "create_vlan_service", "delete_vlan_service", "configure_bgp",
    "verify_bgp", "run_ssh_command", "run_cli_command", "get_raw_api",
    "diagnostic_equipement", "_is_ssh_write_command", "_canonical_device",
])
def test_every_split_module_tool_is_reachable_on_server_module(tmp_path, name):
    """Each tools_*.py / prompts.py function must still be an attribute of the
    `server` module, since flat_tools/deferred_tools resolve legacy tools via
    getattr(sys.modules[__name__], name) against the entry-point module."""
    snippet = f"print(json.dumps(hasattr(server, {name!r})))\n"
    ok = _run_server_snippet(snippet, tmp_path, CX_FLAT_TOOLSET="true")
    assert ok is True, f"{name} missing from server module namespace"
