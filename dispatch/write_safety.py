"""Write-safety layer for the cx-mcp server: dry_run_token + rollback_id.

Standalone and INERT: importing this module changes nothing and touches no
device. It only becomes active once you wire it into the write helpers of
``server.py`` (see "Integration" below) and set ``CX_WRITE_SAFETY=true``.

What it adds on top of the existing ``apply=False`` dry-run
--------------------------------------------------------
1. ``dry_run_token`` — when a write tool runs in preview mode (apply=False) the
   computed plan is *frozen*: we hash it and hand back an opaque, single-use,
   TTL-bound token. To actually apply, the caller passes that token back; the
   layer refuses the apply if the plan presented at apply-time does not match
   the frozen one (guards against "previewed X, applied Y").

2. ``rollback_id`` — every successful apply is journaled with a replayable set
   of inverse actions and given an id. A later call can replay that id to undo
   the change (best-effort, depends on a per-action inverse being known).

Both stores are file-backed (atomic writes, 0600) so tokens and rollback
journals survive a server restart.

Design notes / honesty about guarantees
----------------------------------------
* The token binds the *plan* (i.e. the resolved arguments), NOT live device
  state. It prevents arg drift between preview and apply. To also guard against
  the device changing underneath you, pass an optional ``state_fingerprint``
  when freezing and re-pass it at apply (the caller computes it by reading the
  device). Level-1 (plan binding) is implemented here; Level-2 (state binding)
  is supported but the fingerprint must be supplied by the caller.
* Rollback is best-effort: only actions present in ``INVERSE_ACTION_MAP`` have a
  known inverse. Unknown actions are journaled as ``inverse: unsupported`` and
  reported (never silently dropped).

Integration (LATER — do NOT modify server now)
----------------------------------------------
Add at the top of server.py::

    from write_safety import write_safety

In ``_domain_write`` (and analogously in create_vlan_service /
delete_vlan_service), thread an optional ``dry_run_token`` arg through and::

    if not apply:
        resp = {"status": "planned", "operation": operation,
                "targets": candidates, "plan": plan, "apply": False, ...}
        return write_safety.freeze(resp, operation, candidates, plan)

    if write_safety.enabled:
        err = write_safety.require_token(dry_run_token, operation, plan)
        if err:
            return err
    ...                       # existing guard + _exec_on_devices
    resp = {...existing applied response...}
    if not failed and write_safety.enabled:
        resp["rollback_id"] = write_safety.record(operation, candidates, plan)
    return resp

Then add a thin meta-tool ``rollback(rollback_id)`` whose executor calls the
right client method per inverse action (a ``replay`` executor you provide), and
set ``CX_WRITE_SAFETY=true`` in docker-compose.yml.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import threading
import time
import uuid
from dataclasses import asdict, dataclass, field
from typing import Any, Awaitable, Callable, Optional

log = logging.getLogger("cx-mcp.write_safety")

_DEFAULT_TTL = int(os.getenv("CX_DRY_RUN_TTL", "900"))  # seconds a token stays valid
_SECRETS_DIR = os.getenv("CX_SECRETS_DIR", os.path.join(os.path.dirname(__file__), "secrets"))


def _env_true(name: str, default: str = "false") -> bool:
    return os.getenv(name, default).strip().lower() in ("1", "true", "yes", "on")


# ──────────────────────────────────────────────────────────────────────
# Canonicalisation / hashing
# ──────────────────────────────────────────────────────────────────────


def canonical(obj: Any) -> str:
    """Stable JSON string for hashing (sorted keys, compact, str fallback)."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str)


def plan_hash(plan: Any, operation: str = "") -> str:
    payload = f"{operation}\x1f{canonical(plan)}".encode()
    return hashlib.sha256(payload).hexdigest()[:16]


# ──────────────────────────────────────────────────────────────────────
# Atomic JSON persistence
# ──────────────────────────────────────────────────────────────────────


def _atomic_write_json(path: str, data: Any) -> None:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    tmp = f"{path}.{os.getpid()}.tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(data, fh, default=str)
    try:
        os.chmod(tmp, 0o600)
    except OSError:
        pass
    os.replace(tmp, path)


def _read_json(path: str) -> dict:
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


# ──────────────────────────────────────────────────────────────────────
# Frozen-plan store (dry_run_token)
# ──────────────────────────────────────────────────────────────────────


@dataclass
class FrozenPlan:
    token: str
    operation: str
    targets: list
    plan_hash: str
    state_fingerprint: Optional[str]
    created_at: float
    ttl: float
    consumed: bool = False
    recipe: Optional[dict] = None  # {"tool": <name>, "arguments": {...}} for replay

    def expired(self, now: Optional[float] = None) -> bool:
        return (now or time.time()) > self.created_at + self.ttl


class PlanStore:
    """File-backed store of frozen dry-run plans keyed by opaque token."""

    def __init__(self, path: str):
        self.path = path
        self._lock = threading.Lock()
        self._plans: dict[str, FrozenPlan] = {}
        self._load()

    def _load(self) -> None:
        raw = _read_json(self.path)
        for tok, d in raw.items():
            try:
                self._plans[tok] = FrozenPlan(**d)
            except TypeError:
                continue

    def _flush(self) -> None:
        _atomic_write_json(self.path, {t: asdict(p) for t, p in self._plans.items()})

    def freeze(self, operation: str, targets: list, plan: Any,
               *, ttl: float = _DEFAULT_TTL,
               state_fingerprint: Optional[str] = None,
               recipe: Optional[dict] = None) -> str:
        token = "dr_" + uuid.uuid4().hex[:24]
        fp = FrozenPlan(
            token=token, operation=operation, targets=list(targets),
            plan_hash=plan_hash(plan, operation),
            state_fingerprint=state_fingerprint,
            created_at=time.time(), ttl=float(ttl), recipe=recipe,
        )
        with self._lock:
            self._purge_locked()
            self._plans[token] = fp
            self._flush()
        return token

    def validate(self, token: str, *, operation: Optional[str] = None,
                 plan: Any = None,
                 state_fingerprint: Optional[str] = None) -> tuple[bool, str]:
        with self._lock:
            fp = self._plans.get(token)
            if fp is None:
                return False, "unknown or already-used dry_run_token"
            if fp.consumed:
                return False, "dry_run_token already consumed"
            if fp.expired():
                return False, "dry_run_token expired"
            if operation is not None and fp.operation != operation:
                return False, "dry_run_token belongs to a different operation"
            if plan is not None and plan_hash(plan, fp.operation) != fp.plan_hash:
                return False, ("plan changed since preview; re-run the dry-run "
                               "and apply the new token")
            if fp.state_fingerprint is not None and \
                    state_fingerprint != fp.state_fingerprint:
                return False, "device state changed since preview (fingerprint mismatch)"
        return True, "ok"

    def consume(self, token: str) -> None:
        with self._lock:
            fp = self._plans.get(token)
            if fp is not None:
                fp.consumed = True
                self._flush()

    def get(self, token: str) -> Optional[FrozenPlan]:
        return self._plans.get(token)

    def _purge_locked(self) -> None:
        now = time.time()
        stale = [t for t, p in self._plans.items()
                 if p.consumed or p.expired(now)]
        for t in stale:
            del self._plans[t]


# ──────────────────────────────────────────────────────────────────────
# Rollback journal (rollback_id)
# ──────────────────────────────────────────────────────────────────────

# Forward plan action -> inverse action name. Only actions with a VERIFIED,
# safe inverse client primitive (and unambiguous argument mapping) are listed.
# These match the step-based plans emitted by create_vlan_service. Anything not
# listed (e.g. idempotent configure_* merges, whose true undo is a prior-state
# restore) is journaled as "unsupported" and reported, never silently skipped.
INVERSE_ACTION_MAP: dict[str, str] = {
    "create_vlan": "delete_vlan",
    "create_l2vni": "delete_l2vni",
    "set_evpn_vlan_rt": "delete_evpn_vlan_rt",
    "create_svi": "delete_svi",
    "add_vlan_to_trunk": "remove_vlan_from_trunk",
}


def build_inverse_actions(operation: str, targets: list, plan: dict) -> list[dict]:
    """Translate a forward plan into per-device inverse actions (reverse order).

    ``plan`` is the {device: [action_dict, ...]} structure the write tools emit.
    Returns a flat list of ``{device, forward, inverse, args, supported}`` items
    ordered so they can be replayed safely (last-created undone first)."""
    items: list[dict] = []
    if isinstance(plan, dict):
        for device, actions in plan.items():
            if not isinstance(actions, list):
                continue
            for action in reversed(actions):
                fwd = action.get("action") if isinstance(action, dict) else None
                inv = INVERSE_ACTION_MAP.get(fwd) if fwd else None
                items.append({
                    "device": device,
                    "forward": fwd,
                    "inverse": inv,
                    "args": {k: v for k, v in (action or {}).items() if k != "action"}
                    if isinstance(action, dict) else {},
                    "supported": inv is not None,
                })
    return items


@dataclass
class RollbackRecord:
    rollback_id: str
    operation: str
    targets: list
    actions: list  # output of build_inverse_actions
    created_at: float
    status: str = "recorded"  # recorded | rolled_back | partial | failed
    note: str = ""


class RollbackJournal:
    """File-backed journal of applied writes with replayable inverse actions."""

    def __init__(self, path: str):
        self.path = path
        self._lock = threading.Lock()
        self._records: dict[str, RollbackRecord] = {}
        self._load()

    def _load(self) -> None:
        raw = _read_json(self.path)
        for rid, d in raw.items():
            try:
                self._records[rid] = RollbackRecord(**d)
            except TypeError:
                continue

    def _flush(self) -> None:
        _atomic_write_json(self.path,
                           {r: asdict(rec) for r, rec in self._records.items()})

    def record(self, operation: str, targets: list, plan: dict,
               *, note: str = "") -> str:
        rid = "rb_" + uuid.uuid4().hex[:24]
        rec = RollbackRecord(
            rollback_id=rid, operation=operation, targets=list(targets),
            actions=build_inverse_actions(operation, targets, plan),
            created_at=time.time(), note=note,
        )
        with self._lock:
            self._records[rid] = rec
            self._flush()
        return rid

    def get(self, rollback_id: str) -> Optional[RollbackRecord]:
        return self._records.get(rollback_id)

    def list(self, limit: int = 20) -> list[dict]:
        recs = sorted(self._records.values(), key=lambda r: r.created_at, reverse=True)
        return [asdict(r) for r in recs[:max(1, limit)]]

    def mark(self, rollback_id: str, status: str, note: str = "") -> None:
        with self._lock:
            rec = self._records.get(rollback_id)
            if rec is not None:
                rec.status = status
                if note:
                    rec.note = note
                self._flush()

    async def replay(self, rollback_id: str,
                     executor: Callable[[str, str, dict], Awaitable[Any]]) -> dict:
        """Replay the inverse actions of ``rollback_id``.

        ``executor(device, inverse_action_name, args) -> result`` is supplied at
        wire time and is responsible for calling the matching client method.
        Returns a per-action report and updates the record status.
        """
        rec = self._records.get(rollback_id)
        if rec is None:
            return {"ok": False, "error": "unknown rollback_id"}
        if rec.status == "rolled_back":
            return {"ok": True, "rollback_id": rollback_id, "status": "already_rolled_back"}

        results: list[dict] = []
        failures = 0
        unsupported = 0
        for item in rec.actions:
            if not item.get("supported"):
                unsupported += 1
                results.append({**item, "ok": False, "skipped": "no known inverse"})
                continue
            try:
                res = await executor(item["device"], item["inverse"], item["args"])
                results.append({**item, "ok": True, "result": res})
            except Exception as exc:  # noqa: BLE001
                failures += 1
                results.append({**item, "ok": False, "error": str(exc)})

        status = ("rolled_back" if failures == 0 and unsupported == 0
                  else "partial" if failures == 0 else "failed")
        self.mark(rollback_id, status)
        return {"ok": failures == 0, "rollback_id": rollback_id, "status": status,
                "unsupported": unsupported, "failed": failures, "results": results}


# ──────────────────────────────────────────────────────────────────────
# Facade — single entry point used by the server hooks
# ──────────────────────────────────────────────────────────────────────


class WriteSafety:
    """Bundles the plan store + rollback journal behind a small helper API."""

    def __init__(self,
                 plan_path: Optional[str] = None,
                 journal_path: Optional[str] = None,
                 enabled_env: str = "CX_WRITE_SAFETY"):
        self.enabled_env = enabled_env
        self.plans = PlanStore(plan_path or os.path.join(_SECRETS_DIR, ".dry_run_plans.json"))
        self.journal = RollbackJournal(journal_path or os.path.join(_SECRETS_DIR, ".rollback_journal.json"))

    @property
    def enabled(self) -> bool:
        return _env_true(self.enabled_env)

    @property
    def requires_token(self) -> bool:
        """Whether an apply must present a valid dry_run_token (enforcement)."""
        return self.enabled and _env_true("CX_REQUIRE_DRY_RUN_TOKEN", "false")

    # -- recipe tokens (preview -> apply_plan replay) -------------------
    def freeze_recipe(self, planned_response: dict, operation: str, targets: list,
                      plan: Any, *, tool: str, arguments: dict,
                      ttl: float = _DEFAULT_TTL) -> dict:
        """Augment a ``status=planned`` response with a replayable dry_run_token.

        The token freezes both the plan hash AND a re-invocation recipe
        ``{tool, arguments}`` so ``apply_plan(token)`` can re-run the exact same
        call with ``apply=True`` after re-checking the plan is unchanged.
        No-op (returns response unchanged) when disabled."""
        if not self.enabled:
            return planned_response
        recipe = {"tool": tool, "arguments": dict(arguments or {})}
        token = self.plans.freeze(operation, targets, plan, ttl=ttl, recipe=recipe)
        planned_response["dry_run_token"] = token
        planned_response["token_expires_in"] = int(ttl)
        planned_response["note"] = (
            (planned_response.get("note", "") +
             f" Call apply_plan(dry_run_token='{token}') to apply this exact plan.")
            .strip())
        return planned_response

    def get_token(self, token: str) -> Optional[FrozenPlan]:
        return self.plans.get(token) if hasattr(self.plans, "get") else None

    def redeem(self, token: str, *, operation: Optional[str] = None,
               plan: Any = None) -> tuple[bool, str, Optional[dict]]:
        """Validate a token (existence/expiry/consumed/plan-hash) WITHOUT
        consuming it and return its recipe. Caller consumes after a successful
        apply via ``consume(token)``."""
        if not self.enabled:
            return False, "write safety disabled", None
        fp = self.plans._plans.get(token)  # noqa: SLF001
        ok, reason = self.plans.validate(token, operation=operation, plan=plan)
        if not ok:
            return False, reason, None
        return True, "ok", (fp.recipe if fp else None)

    def consume(self, token: str) -> None:
        self.plans.consume(token)

    # -- dry_run_token --------------------------------------------------
    def freeze(self, planned_response: dict, operation: str, targets: list,
               plan: Any, *, ttl: float = _DEFAULT_TTL,
               state_fingerprint: Optional[str] = None) -> dict:
        """Augment a ``status=planned`` response with a dry_run_token.

        No-op when disabled (returns the response unchanged)."""
        if not self.enabled:
            return planned_response
        token = self.plans.freeze(operation, targets, plan, ttl=ttl,
                                  state_fingerprint=state_fingerprint)
        planned_response["dry_run_token"] = token
        planned_response["token_expires_in"] = int(ttl)
        planned_response["note"] = (planned_response.get("note", "") +
                                    " Pass dry_run_token to apply this exact plan.").strip()
        return planned_response

    def require_token(self, token: Optional[str], operation: str, plan: Any,
                      *, state_fingerprint: Optional[str] = None) -> Optional[dict]:
        """Return an error dict if the apply must be refused, else None.

        Enforced only when enabled AND a token policy is required. If
        ``CX_REQUIRE_DRY_RUN_TOKEN`` is false, a missing token is allowed
        (back-compat) but a *provided* token is still validated and consumed."""
        if not self.enabled:
            return None
        require = _env_true("CX_REQUIRE_DRY_RUN_TOKEN", "true")
        if not token:
            if require:
                return {"status": "error",
                        "error": "dry_run_token required: run with apply=false "
                                 "first, then apply the returned token."}
            return None
        ok, reason = self.plans.validate(token, operation=operation, plan=plan,
                                         state_fingerprint=state_fingerprint)
        if not ok:
            return {"status": "error", "error": reason}
        self.plans.consume(token)
        return None

    # -- rollback_id ----------------------------------------------------
    def record(self, operation: str, targets: list, plan: dict,
               *, note: str = "") -> Optional[str]:
        """Journal a successful apply and return its rollback_id (or None)."""
        if not self.enabled:
            return None
        return self.journal.record(operation, targets, plan, note=note)

    async def rollback(self, rollback_id: str,
                       executor: Callable[[str, str, dict], Awaitable[Any]]) -> dict:
        return await self.journal.replay(rollback_id, executor)


# Module-level singleton the server hooks import.
write_safety = WriteSafety()
