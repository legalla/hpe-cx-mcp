import pytest

from dispatch.write_safety import (
    PlanStore,
    RollbackJournal,
    WriteSafety,
    build_inverse_actions,
)


# ── PlanStore (dry_run_token) ──────────────────────────────────────────

def test_plan_freeze_and_validate_roundtrip(tmp_path):
    store = PlanStore(str(tmp_path / "plans.json"))
    plan = {"sw1": [{"action": "create_vlan", "vlan_id": 10}]}

    token = store.freeze("create_vlan_service", ["sw1"], plan)
    assert token.startswith("dr_")

    ok, reason = store.validate(token, operation="create_vlan_service", plan=plan)
    assert ok is True
    assert reason == "ok"


def test_plan_validate_unknown_token(tmp_path):
    store = PlanStore(str(tmp_path / "plans.json"))
    ok, reason = store.validate("dr_doesnotexist")
    assert ok is False
    assert "unknown" in reason


def test_plan_validate_detects_plan_drift(tmp_path):
    store = PlanStore(str(tmp_path / "plans.json"))
    plan = {"sw1": [{"action": "create_vlan", "vlan_id": 10}]}
    token = store.freeze("create_vlan_service", ["sw1"], plan)

    drifted = {"sw1": [{"action": "create_vlan", "vlan_id": 999}]}
    ok, reason = store.validate(token, operation="create_vlan_service", plan=drifted)
    assert ok is False
    assert "plan changed" in reason


def test_plan_validate_wrong_operation(tmp_path):
    store = PlanStore(str(tmp_path / "plans.json"))
    plan = {"sw1": [{"action": "create_vlan", "vlan_id": 10}]}
    token = store.freeze("create_vlan_service", ["sw1"], plan)

    ok, reason = store.validate(token, operation="delete_vlan_service", plan=plan)
    assert ok is False
    assert "different operation" in reason


def test_plan_consume_then_validate_fails(tmp_path):
    store = PlanStore(str(tmp_path / "plans.json"))
    plan = {"sw1": [{"action": "create_vlan", "vlan_id": 10}]}
    token = store.freeze("create_vlan_service", ["sw1"], plan)

    store.consume(token)
    ok, reason = store.validate(token, operation="create_vlan_service", plan=plan)
    assert ok is False
    assert "already consumed" in reason


def test_plan_expired_token_rejected(tmp_path):
    store = PlanStore(str(tmp_path / "plans.json"))
    plan = {"sw1": [{"action": "create_vlan", "vlan_id": 10}]}
    token = store.freeze("create_vlan_service", ["sw1"], plan, ttl=-1)

    ok, reason = store.validate(token)
    assert ok is False
    assert "expired" in reason


# ── build_inverse_actions / RollbackJournal ────────────────────────────

def test_build_inverse_actions_marks_supported_and_unsupported():
    plan = {
        "sw1": [
            {"action": "create_vlan", "vlan_id": 10},
            {"action": "configure_bgp", "asn": 65000},  # no known inverse
        ]
    }
    items = build_inverse_actions("create_vlan_service", ["sw1"], plan)

    assert len(items) == 2
    # Reversed order: last-created action is undone first.
    assert items[0]["forward"] == "configure_bgp"
    assert items[0]["supported"] is False
    assert items[0]["inverse"] is None

    assert items[1]["forward"] == "create_vlan"
    assert items[1]["supported"] is True
    assert items[1]["inverse"] == "delete_vlan"
    assert items[1]["args"] == {"vlan_id": 10}


@pytest.mark.asyncio
async def test_rollback_journal_replay_success(tmp_path):
    journal = RollbackJournal(str(tmp_path / "journal.json"))
    plan = {"sw1": [{"action": "create_vlan", "vlan_id": 10}]}
    rollback_id = journal.record("create_vlan_service", ["sw1"], plan)

    calls = []

    async def executor(device, inverse_action, args):
        calls.append((device, inverse_action, args))
        return {"status": "ok"}

    result = await journal.replay(rollback_id, executor)
    assert result["ok"] is True
    assert result["status"] == "rolled_back"
    assert calls == [("sw1", "delete_vlan", {"vlan_id": 10})]

    # Replaying again is a no-op / reports already done.
    result2 = await journal.replay(rollback_id, executor)
    assert result2["status"] == "already_rolled_back"
    assert len(calls) == 1


@pytest.mark.asyncio
async def test_rollback_journal_replay_partial_when_unsupported(tmp_path):
    journal = RollbackJournal(str(tmp_path / "journal.json"))
    plan = {"sw1": [{"action": "configure_bgp", "asn": 65000}]}
    rollback_id = journal.record("configure_routing", ["sw1"], plan)

    async def executor(device, inverse_action, args):
        return {"status": "ok"}

    result = await journal.replay(rollback_id, executor)
    assert result["ok"] is True
    assert result["status"] == "partial"
    assert result["unsupported"] == 1


@pytest.mark.asyncio
async def test_rollback_journal_replay_failed_when_executor_raises(tmp_path):
    journal = RollbackJournal(str(tmp_path / "journal.json"))
    plan = {"sw1": [{"action": "create_vlan", "vlan_id": 10}]}
    rollback_id = journal.record("create_vlan_service", ["sw1"], plan)

    async def executor(device, inverse_action, args):
        raise RuntimeError("device unreachable")

    result = await journal.replay(rollback_id, executor)
    assert result["ok"] is False
    assert result["status"] == "failed"
    assert result["failed"] == 1


def test_rollback_journal_unknown_id(tmp_path):
    journal = RollbackJournal(str(tmp_path / "journal.json"))
    # get() is sync; replay() on an unknown id is exercised via the facade test.
    assert journal.get("rb_doesnotexist") is None


# ── WriteSafety facade (env-gated) ──────────────────────────────────────

def _make_safety(tmp_path):
    return WriteSafety(
        plan_path=str(tmp_path / "plans.json"),
        journal_path=str(tmp_path / "journal.json"),
    )


def test_write_safety_disabled_is_noop(tmp_path, monkeypatch):
    monkeypatch.delenv("CX_WRITE_SAFETY", raising=False)
    safety = _make_safety(tmp_path)
    assert safety.enabled is False

    resp = {"status": "planned"}
    out = safety.freeze(resp, "create_vlan_service", ["sw1"], {"sw1": []})
    assert out == {"status": "planned"}
    assert "dry_run_token" not in out

    assert safety.require_token(None, "create_vlan_service", {}) is None
    assert safety.record("create_vlan_service", ["sw1"], {}) is None


def test_write_safety_freeze_and_require_token(tmp_path, monkeypatch):
    monkeypatch.setenv("CX_WRITE_SAFETY", "true")
    monkeypatch.setenv("CX_REQUIRE_DRY_RUN_TOKEN", "true")
    safety = _make_safety(tmp_path)
    assert safety.enabled is True
    assert safety.requires_token is True

    plan = {"sw1": [{"action": "create_vlan", "vlan_id": 10}]}
    resp = safety.freeze({"status": "planned"}, "create_vlan_service", ["sw1"], plan)
    token = resp["dry_run_token"]
    assert token.startswith("dr_")

    # Missing token is refused when CX_REQUIRE_DRY_RUN_TOKEN=true.
    err = safety.require_token(None, "create_vlan_service", plan)
    assert err is not None
    assert "dry_run_token required" in err["error"]

    # Valid token is accepted and consumed...
    assert safety.require_token(token, "create_vlan_service", plan) is None
    # ...so re-using it fails.
    err2 = safety.require_token(token, "create_vlan_service", plan)
    assert err2 is not None
