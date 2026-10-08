"""orchestrate_fabric_underlay (B1): loopback0/1 + P2P /31 links + OSPF in one
call, driven by explicit `cabling` (no device I/O needed in plan mode)."""
import asyncio

import pytest

from tools import tools_orchestrate as orch


def _run(coro):
    return asyncio.run(coro)


_CABLING = [
    {"a_device": "Spine1", "a_interface": "1/1/1", "b_device": "Leaf1", "b_interface": "1/1/49"},
    {"a_device": "Spine1", "a_interface": "1/1/2", "b_device": "Leaf2", "b_interface": "1/1/49"},
    {"a_device": "Spine2", "a_interface": "1/1/1", "b_device": "Leaf1", "b_interface": "1/1/50"},
    {"a_device": "Spine2", "a_interface": "1/1/2", "b_device": "Leaf2", "b_interface": "1/1/50"},
]


def _call(**overrides):
    kwargs = dict(
        spines=["Spine1", "Spine2"], leafs=["Leaf1", "Leaf2"],
        underlay_subnet="10.140.253.0/29", loopback0_subnet="10.140.254.0/28",
        loopback1_subnet="10.140.255.0/28", cabling=_CABLING, apply=False,
    )
    kwargs.update(overrides)
    return _run(orch.orchestrate_fabric_underlay(**kwargs))


def test_plan_allocates_unique_loopback0_per_device():
    res = _call()
    assert res["status"] == "planned"
    lo0 = res["ip_allocation"]["loopback0"]
    assert set(lo0) == {"Spine1", "Spine2", "Leaf1", "Leaf2"}
    assert len(set(lo0.values())) == 4  # all unique


def test_plan_allocates_p2p_31s_no_overlap():
    res = _call()
    p2p = res["ip_allocation"]["p2p_links"]
    assert len(p2p) == 4
    assert len(set(l["subnet"] for l in p2p)) == 4


def test_vsx_pair_shares_loopback1():
    res = _call(vsx_pairs=[["Leaf1", "Leaf2"]])
    lo1 = res["ip_allocation"]["loopback1"]
    assert lo1["Leaf1"] == lo1["Leaf2"]


def test_spines_excluded_from_loopback1():
    res = _call()
    lo1 = res["ip_allocation"]["loopback1"]
    assert "Spine1" not in lo1 and "Spine2" not in lo1
    assert set(lo1) == {"Leaf1", "Leaf2"}


def test_ospf_steps_present_per_device():
    res = _call()
    for dev in ("Spine1", "Spine2", "Leaf1", "Leaf2"):
        actions = [s["action"] for s in res["plan"][dev]]
        assert "ensure_ospf_router" in actions
        assert "ensure_ospf_area" in actions
        assert actions.count("add_ospf_interface") >= 1  # loopback0 passive at least


def test_cabling_must_go_spine_to_leaf():
    bad = [{"a_device": "Leaf1", "a_interface": "1/1/1",
           "b_device": "Spine1", "b_interface": "1/1/1"}]
    res = _call(cabling=bad)
    assert res["status"] == "invalid_input"


def test_overlapping_spine_leaf_rejected():
    res = _call(spines=["Spine1", "Leaf1"])
    assert res["status"] == "invalid_input"


def test_underlay_pool_too_small():
    res = _call(underlay_subnet="10.140.253.0/31")  # only 1 usable /31
    assert res["status"] == "invalid_input"
    assert "underlay_subnet" in res["field"]


def test_no_cabling_and_no_discovery_possible_without_devices():
    # spines not in inventory -> LLDP discovery would fail; verify the
    # explicit-cabling path is what's actually exercised (no device I/O).
    res = _call()
    assert res["cabling_used"] == _CABLING
