"""Apply-time safety rails: CX_PROTECTED_OBJECTS guard, auto-checkpoint wrap,
created-object rollback journaling."""
import asyncio

import pytest

from clients.aruba_client import ArubaAPIError, ArubaOSCXClient, protected_object_match
from dispatch.write_safety import build_inverse_actions
from tools import tools_configure as tc


# ── CX_PROTECTED_OBJECTS (client-level guard) ────────────────────────────

def test_protected_match_globs(monkeypatch):
    monkeypatch.setenv("CX_PROTECTED_OBJECTS",
                       "/system/vrfs/mgmt, */bgp_neighbors/spine-RR,/system/interfaces/1/1/2[78]")
    assert protected_object_match("/system/vrfs/mgmt") == "/system/vrfs/mgmt"
    assert protected_object_match(
        "/system/vrfs/default/bgp_routers/65001/bgp_neighbors/spine-RR") == "*/bgp_neighbors/spine-RR"
    # URL-encoded interface names are decoded before matching
    assert protected_object_match("/system/interfaces/1%2F1%2F27") is not None
    assert protected_object_match("/system/interfaces/1%2F1%2F1") is None
    assert protected_object_match("/system/vrfs/mgmt2") is None


def test_protected_blocks_put_and_delete_not_post(monkeypatch):
    monkeypatch.setenv("CX_PROTECTED_OBJECTS", "/system/vrfs/mgmt")
    c = ArubaOSCXClient("192.0.2.1", "u", "p", api_version="v10.17")
    with pytest.raises(ArubaAPIError) as exc:
        c._assert_write_allowed("PUT", "/system/vrfs/mgmt")
    assert exc.value.status_code == 403 and "force=true" in str(exc.value)
    with pytest.raises(ArubaAPIError):
        c._assert_write_allowed("DELETE", "/system/vrfs/mgmt")
    c._assert_write_allowed("POST", "/system/vrfs")            # creation is fine
    c._assert_write_allowed("PUT", "/system/vrfs/TENANT")      # unprotected
    c.allow_protected = True
    c._assert_write_allowed("PUT", "/system/vrfs/mgmt")        # force


def test_protected_guard_ignored_when_unset(monkeypatch):
    monkeypatch.delenv("CX_PROTECTED_OBJECTS", raising=False)
    c = ArubaOSCXClient("192.0.2.1", "u", "p", api_version="v10.17")
    c._assert_write_allowed("DELETE", "/system/vrfs/mgmt")


# ── Auto-checkpoint wrapper ──────────────────────────────────────────────

class _CkptClient:
    def __init__(self, fail_arm=False):
        self.calls = []
        self.fail_arm = fail_arm
        self.allow_protected = False
        self.writes = 0

    async def set_auto_checkpoint(self, minutes):
        self.calls.append(("arm", minutes))
        if self.fail_arm:
            raise ArubaAPIError("autocheckpoint already pending", 400)
        return {"status": "armed"}

    async def confirm_auto_checkpoint(self):
        self.calls.append(("confirm",))
        return {"status": "confirmed"}


def _run(coro):
    return asyncio.run(coro)


def test_auto_checkpoint_armed_then_confirmed(monkeypatch):
    monkeypatch.setattr(tc._core, "_AUTO_CHECKPOINT", True)
    monkeypatch.setattr(tc._core, "_AUTO_CHECKPOINT_MINUTES", 7)
    client = _CkptClient()

    async def _exec(dev, c):
        c.calls.append(("write",))
        return {"vrf": "T", "status": "created"}

    out = _run(tc._guarded_executor(_exec)("sw1", client))
    assert client.calls == [("arm", 7), ("write",), ("confirm",)]
    assert out["checkpoint"] == "confirmed"
    assert out["result"]["status"] == "created"


def test_auto_checkpoint_failed_write_is_not_confirmed(monkeypatch):
    monkeypatch.setattr(tc._core, "_AUTO_CHECKPOINT", True)
    client = _CkptClient()

    async def _exec(dev, c):
        c.writes += 1            # one object written…
        raise ArubaAPIError("boom", 500)   # …then the second step fails

    with pytest.raises(ArubaAPIError) as exc:
        _run(tc._guarded_executor(_exec)("sw1", client))
    assert ("confirm",) not in client.calls
    assert "left ARMED" in str(exc.value)


def test_auto_checkpoint_disarmed_when_nothing_written(monkeypatch):
    """A pre-flight refusal (guard/validation) must not leave a 10-min timer."""
    monkeypatch.setattr(tc._core, "_AUTO_CHECKPOINT", True)
    client = _CkptClient()

    async def _exec(dev, c):
        raise ArubaAPIError("Write blocked: protected", 403)

    with pytest.raises(ArubaAPIError) as exc:
        _run(tc._guarded_executor(_exec)("sw1", client))
    assert ("confirm",) in client.calls
    assert "disarmed" in str(exc.value)
    assert str(exc.value).count("[HTTP 403]") == 1


def test_auto_checkpoint_arm_failure_refuses_apply(monkeypatch):
    monkeypatch.setattr(tc._core, "_AUTO_CHECKPOINT", True)
    client = _CkptClient(fail_arm=True)
    wrote = []

    async def _exec(dev, c):
        wrote.append(1)

    with pytest.raises(ArubaAPIError) as exc:
        _run(tc._guarded_executor(_exec)("sw1", client))
    assert wrote == []
    assert "nothing written" in str(exc.value)


def test_auto_checkpoint_disabled_bypasses(monkeypatch):
    monkeypatch.setattr(tc._core, "_AUTO_CHECKPOINT", False)
    client = _CkptClient()

    async def _exec(dev, c):
        return {"ok": 1}

    out = _run(tc._guarded_executor(_exec)("sw1", client))
    assert client.calls == [] and out["checkpoint"] == "disabled"


def test_auto_checkpoint_per_call_override(monkeypatch):
    """auto_checkpoint=false on one call wins over the global default (and
    vice-versa); None falls back to CX_AUTO_CHECKPOINT."""
    monkeypatch.setattr(tc._core, "_AUTO_CHECKPOINT", True)

    async def _exec(dev, c):
        return {"ok": 1}

    client = _CkptClient()
    tok = tc._core.AUTO_CHECKPOINT_OVERRIDE.set(False)
    try:
        out = _run(tc._guarded_executor(_exec)("sw1", client))
    finally:
        tc._core.AUTO_CHECKPOINT_OVERRIDE.reset(tok)
    assert client.calls == [] and out["checkpoint"] == "disabled"

    monkeypatch.setattr(tc._core, "_AUTO_CHECKPOINT", False)
    client = _CkptClient()
    tok = tc._core.AUTO_CHECKPOINT_OVERRIDE.set(True)
    try:
        out = _run(tc._guarded_executor(_exec)("sw1", client))
    finally:
        tc._core.AUTO_CHECKPOINT_OVERRIDE.reset(tok)
    assert client.calls == [("arm", tc._core._AUTO_CHECKPOINT_MINUTES), ("confirm",)]
    assert out["checkpoint"] == "confirmed"
    assert tc._core.auto_checkpoint_enabled() is False  # override reset


def test_force_contextvar_sets_allow_protected(monkeypatch):
    monkeypatch.setattr(tc._core, "_AUTO_CHECKPOINT", False)
    client = _CkptClient()
    seen = {}

    async def _exec(dev, c):
        seen["allow"] = c.allow_protected

    tok = tc._core.FORCE_PROTECTED.set(True)
    try:
        _run(tc._guarded_executor(_exec)("sw1", client))
    finally:
        tc._core.FORCE_PROTECTED.reset(tok)
    assert seen["allow"] is True
    assert client.allow_protected is False  # reset after the call


# ── Created-object rollback ──────────────────────────────────────────────

def test_created_actions_extracts_only_created_objects():
    result = {
        "vrf": {"vrf": "TENANT", "status": "created", "config": {}},
        "address_families": [{"vrf": "TENANT", "address_family": "ipv4-unicast",
                              "status": "created"}],
        "interface": {"interface": "loopback9", "status": "updated"},
        "l3": {"vni": 14000, "vrf": "TENANT", "routing": True, "status": "created"},
    }
    actions = tc._created_actions(result)
    assert {"action": "ensure_vrf", "vrf": "TENANT"} in actions
    assert {"action": "create_l3vni", "vni": 14000} in actions
    assert not any(a["action"] == "create_loopback" for a in actions)  # updated, not created
    assert len(actions) == 2  # the AF entry has no inverse → not listed


def test_inverse_actions_for_created_objects():
    plan = {"sw1": [{"action": "ensure_vrf", "vrf": "TENANT"},
                    {"action": "create_loopback", "interface": "loopback9"}]}
    inv = build_inverse_actions("configure_vrf", ["sw1"], plan)
    # reversed order: loopback first, then vrf
    assert [i["inverse"] for i in inv] == ["delete_interface", "delete_vrf"]
    assert inv[0]["args"] == {"interface": "loopback9"}
    assert all(i["supported"] for i in inv)
