"""B2: multi-interface-per-device transactional applies —
configure_routed_port(interfaces=[...]) and orchestrate_l3_link(links=[...])."""
import asyncio

import pytest

from core import server_core
from core.config import DeviceConfig
from tools import tools_configure, tools_orchestrate as orch


def _run(coro):
    return asyncio.run(coro)


@pytest.fixture
def inv(monkeypatch):
    def mk(name, host, site="lab"):
        return DeviceConfig(name=name, host=host, username="u", password="p", site=site)
    monkeypatch.setattr(server_core, "_devices", {
        "A": mk("A", "10.0.0.1"), "B": mk("B", "10.0.0.2")})


def _actions(res, dev):
    return [s["action"] for s in res["plan"][dev]]


# ── configure_routed_port(interfaces=[...]) ─────────────────────────

def test_routed_port_interfaces_batch_plan(inv):
    res = _run(tools_configure.configure_routed_port(interfaces=[
        {"interface": "1/1/1", "ip_address": "10.0.0.0/31"},
        {"interface": "1/1/2", "ip_address": "10.0.0.2/31", "vrf": "TENANT", "create_vrf": True},
    ], device="A"))
    assert res["status"] == "planned"
    actions = _actions(res, "A")
    assert actions == ["configure_routed_interface", "ensure_vrf", "configure_routed_interface"]
    assert res["plan"]["A"][0]["interface"] == "1/1/1"
    assert res["plan"]["A"][2]["interface"] == "1/1/2"
    assert res["plan"]["A"][1]["vrf"] == "TENANT"


def test_routed_port_interfaces_rejects_both_forms(inv):
    res = _run(tools_configure.configure_routed_port(
        "1/1/1", interfaces=[{"interface": "1/1/2"}], device="A"))
    assert res["status"] == "invalid_input" and res["field"] == "interface"


def test_routed_port_interfaces_rejects_malformed_entry(inv):
    res = _run(tools_configure.configure_routed_port(interfaces=[{"ip_address": "10.0.0.0/31"}],
                                                      device="A"))
    assert res["status"] == "invalid_input"


def test_routed_port_single_interface_shape_unchanged(inv):
    # Backward-compat: the single-`interface` path keeps its EXACT plan shape.
    res = _run(tools_configure.configure_routed_port(
        "1/1/48", device="A", ip_address="10.0.0.0/31", vrf="KEEPALIVE", create_vrf=True))
    assert _actions(res, "A") == ["ensure_vrf", "configure_routed_interface"]


# ── orchestrate_l3_link(links=[...]) ────────────────────────────────

def test_l3_link_links_batch_plan(inv):
    res = _run(orch.orchestrate_l3_link(links=[
        {"interface": "1/1/1", "ip_address": "10.1.1.0/31", "ospf_area": "0.0.0.0"},
        {"interface": "1/1/2", "ip_address": "10.1.1.2/31", "ospf_area": "0.0.0.0"},
    ], device="A", vrf="default"))
    assert res["status"] == "planned"
    assert _actions(res, "A") == [
        "configure_routed_interface", "ensure_ospf_router", "ensure_ospf_area",
        "add_ospf_interface", "configure_ospf_interface_options",
        "configure_routed_interface", "add_ospf_interface",
        "configure_ospf_interface_options"]


def test_l3_link_links_rejects_both_forms(inv):
    res = _run(orch.orchestrate_l3_link("1/1/1", links=[{"interface": "1/1/2"}], device="A"))
    assert res["status"] == "invalid_input" and res["field"] == "interface"


def test_l3_link_links_shares_one_vrf(inv):
    res = _run(orch.orchestrate_l3_link(links=[
        {"interface": "1/1/1", "ip_address": "10.1.1.0/31"},
        {"interface": "1/1/2", "ip_address": "10.1.1.2/31"},
    ], device="A", vrf="TENANT", vrf_rd="65000:10"))
    actions = _actions(res, "A")
    assert actions.count("ensure_vrf") == 1  # shared VRF context, not one per link
    assert actions == ["ensure_vrf", "configure_routed_interface", "configure_routed_interface"]


def test_l3_link_single_interface_shape_unchanged(inv):
    res = _run(orch.orchestrate_l3_link("1/1/1", device="A", ip_address="10.1.1.0/31"))
    assert _actions(res, "A") == ["configure_routed_interface"]
