import os

import pytest


@pytest.fixture(scope="module")
def server_module(tmp_path_factory):
    """Import server.py once, with harmless env vars so it doesn't warn about
    missing credentials/inventory (those aren't needed for the pure helper
    under test)."""
    os.environ.setdefault("ARUBA_DEFAULT_USERNAME", "admin")
    os.environ.setdefault("ARUBA_DEFAULT_PASSWORD", "test")
    os.environ.setdefault("INVENTORY_FILE", str(tmp_path_factory.mktemp("inv") / "missing.yaml"))
    import server  # noqa: PLC0415
    return server


@pytest.mark.parametrize("command", [
    "show interface 1/1/1",
    "  show run",  # leading whitespace
    "SHOW VLAN",  # case-insensitive
    "ping 192.0.2.1",
    "traceroute 192.0.2.1",
    "nslookup switch01",
    "whoami",
    "",
])
def test_read_only_commands_are_allowed(server_module, command):
    assert server_module._is_ssh_write_command(command) is False


@pytest.mark.parametrize("command", [
    "configure terminal",
    "no shutdown",
    "write memory",
    "copy running-config startup-config",
    "vlan 10",
    "interface 1/1/1",
])
def test_mutating_commands_are_flagged_as_write(server_module, command):
    assert server_module._is_ssh_write_command(command) is True
