"""B4: get_interfaces(scope='physical') now surfaces Port.l1_state /
l1_state_down_reason (and the LAG/split-aware l1_state_aggregate) directly —
no more get_config(raw)/SSH fallback needed for L1 diagnosis."""
from clients.aruba_client import _format_interface


def test_l1_state_ready_true_hides_down_reason():
    out = _format_interface("1/1/1", {"l1_state": {"ready": True,
                                                    "l1_state_down_reason": "uninitialized"}})
    assert out["l1_state"] is True
    assert out["l1_state_down_reason"] is None


def test_l1_state_down_reason_surfaced_when_not_ready():
    out = _format_interface("1/1/1", {"l1_state": {"ready": False,
                                                    "l1_state_down_reason": "group_speed_mismatch"}})
    assert out["l1_state"] is False
    assert out["l1_state_down_reason"] == "group_speed_mismatch"


def test_l1_state_missing_defaults_to_na():
    out = _format_interface("1/1/1", {})
    assert out["l1_state"] == "N/A"
    assert out["l1_state_down_reason"] is None


def test_l1_state_aggregate_surfaced():
    out = _format_interface("1/1/1", {"l1_state_aggregate": {
        "ready": False, "l1_state_aggregate_down_reason": "waiting"}})
    assert out["l1_state_aggregate"] is False
    assert out["l1_state_aggregate_down_reason"] == "waiting"
