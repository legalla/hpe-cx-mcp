"""Flat-toolset write dispatch: dry_run_token lifecycle (plan -> apply)."""
import asyncio

import pytest

from dispatch import flat_tools
from dispatch.write_safety import WriteSafety


class _FakeServer:
    """Stand-in for the server module: one plan/apply write + its verify."""

    def __init__(self):
        self.applied = []
        self.plan_value = {"sw1": {"name": "loopback9", "ip_address": "10.0.0.1/32"}}

    async def configure_loopback(self, device=None, site=None, apply=False, **kw):
        if not apply:
            return {"status": "planned", "targets": ["sw1"], "plan": self.plan_value}
        self.applied.append(kw)
        return {"status": "applied", "targets": ["sw1"], "plan": self.plan_value}

    async def verify_loopback(self, device=None, site=None, **kw):
        return {"status": "ok"}


@pytest.fixture
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("CX_WRITE_SAFETY", "true")
    monkeypatch.setenv("CX_REQUIRE_DRY_RUN_TOKEN", "true")
    ws = WriteSafety(plan_path=str(tmp_path / "plans.json"),
                     journal_path=str(tmp_path / "journal.json"))
    srv = _FakeServer()
    monkeypatch.setattr(flat_tools, "_ws", ws)
    monkeypatch.setattr(flat_tools, "_SRV", srv)
    return srv, ws


def _run(coro):
    return asyncio.run(coro)


def test_plan_returns_dry_run_token(env):
    res = _run(flat_tools.configure_interface("loopback", "plan", device="sw1",
                                              params={"name": "loopback9"}))
    assert res["status"] == "planned"
    assert res["dry_run_token"].startswith("dr_")


def test_apply_without_token_is_refused(env):
    srv, _ = env
    res = _run(flat_tools.configure_interface("loopback", "apply", device="sw1",
                                              params={"name": "loopback9"}))
    assert res["status"] == "error"
    assert "dry_run_token required" in res["error"]
    assert srv.applied == []


def test_apply_with_valid_token_applies_once(env):
    srv, _ = env
    plan = _run(flat_tools.configure_interface("loopback", "plan", device="sw1",
                                               params={"name": "loopback9"}))
    tok = plan["dry_run_token"]
    res = _run(flat_tools.configure_interface("loopback", "apply", device="sw1",
                                              params={"name": "loopback9"},
                                              dry_run_token=tok))
    assert res["status"] == "applied"
    assert res["rollback_id"].startswith("rb_")
    assert len(srv.applied) == 1
    # single-use token
    again = _run(flat_tools.configure_interface("loopback", "apply", device="sw1",
                                                params={"name": "loopback9"},
                                                dry_run_token=tok))
    assert again["status"] == "error"
    assert len(srv.applied) == 1


def test_apply_refused_when_plan_drifted(env):
    srv, _ = env
    plan = _run(flat_tools.configure_interface("loopback", "plan", device="sw1",
                                               params={"name": "loopback9"}))
    srv.plan_value = {"sw1": {"name": "loopback9", "ip_address": "10.9.9.9/32"}}
    res = _run(flat_tools.configure_interface("loopback", "apply", device="sw1",
                                              params={"name": "loopback9"},
                                              dry_run_token=plan["dry_run_token"]))
    assert res["status"] == "error"
    assert "plan changed" in res["error"]
    assert srv.applied == []


def test_apply_without_token_allowed_when_not_required(env, monkeypatch):
    srv, _ = env
    monkeypatch.setenv("CX_REQUIRE_DRY_RUN_TOKEN", "false")
    res = _run(flat_tools.configure_interface("loopback", "apply", device="sw1",
                                              params={"name": "loopback9"}))
    assert res["status"] == "applied"
    assert len(srv.applied) == 1
