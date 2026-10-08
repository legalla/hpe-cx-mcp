"""VLAN service provisioning tools (create_vlan_service / delete_vlan_service).

Reads the live device inventory via ``server_core._devices`` (module-qualified,
not imported by value) because the inventory can be replaced wholesale by
``refresh_inventory`` / the SIGHUP hot-reload — a plain
``from server_core import _devices`` would silently keep pointing at the
pre-reload dict.
"""

import asyncio

from core import server_core
from core.server_core import (
    mcp, logger, _get_client, _resolve_devices, _deny_read_only_many,
    _close_sessions, write_safety,
)

# ══════════════════════════════════════════════════════════════════════
# TOOLS — Service provisioning (VLAN creation)
# ══════════════════════════════════════════════════════════════════════

def _match_inventory_device(system_name: str, mgmt_addr: str) -> str | None:
    """Match an LLDP neighbor (system-name / management address) to an inventory
    device. Returns its name, or None."""
    for name, dev in server_core._devices.items():
        if system_name and (system_name.lower() == name.lower()
                            or name.lower() in system_name.lower()
                            or system_name.lower() in name.lower()):
            return name
        if mgmt_addr and dev.host and dev.host in str(mgmt_addr):
            return name
    return None


async def _gather_fabric_contexts(device_names: list[str]) -> dict:
    """Retrieve the fabric context of each target device in parallel."""
    async def _one(name: str):
        try:
            async with _get_client(name) as client:
                return name, {"ok": True, "ctx": await client.get_fabric_context()}
        except Exception as exc:  # noqa: BLE001
            return name, {"ok": False, "error": str(exc)}
    results = await asyncio.gather(*[_one(n) for n in device_names])
    return dict(results)


def _aggregate_fabric_context(ctxs: list[dict]) -> dict:
    """
    Aggregate the context of several VTEPs to make the deductions more reliable
    (a single reference VTEP is misleading: VNI/RT/MAC conventions vary).

    - vni_offset: kept only if ALL VTEPs agree on a single value.
    - vni_by_vlan: union (allows reusing a VNI already assigned to this VLAN).
    - rt_template: union of the distinct (admin, source) pairs (de-duplicated).
    - active_gateway_mac: the most frequent MAC.
    """
    from collections import Counter
    offsets: set = set()
    vni_by_vlan: dict = {}
    rt_pairs: list = []
    gw_macs: Counter = Counter()
    bgp_asn = None
    vxlan_iface = "vxlan1"
    for c in ctxs:
        if c.get("vni_offset") is not None:
            offsets.add(c["vni_offset"])
        vni_by_vlan.update(c.get("vni_by_vlan") or {})
        for entry in (c.get("rt_template") or []):
            pair = (entry["admin"], entry["source"])
            if pair not in rt_pairs:
                rt_pairs.append(pair)
        if c.get("active_gateway_mac"):
            gw_macs[c["active_gateway_mac"]] += 1
        if c.get("bgp_asn") and bgp_asn is None:
            bgp_asn = c["bgp_asn"]
        if c.get("vxlan_interface"):
            vxlan_iface = c["vxlan_interface"]
    return {
        "vni_offset": offsets.pop() if len(offsets) == 1 else None,
        "vni_by_vlan": {int(k): int(v) for k, v in vni_by_vlan.items()},
        "rt_template": [{"admin": a, "source": s} for a, s in rt_pairs] or None,
        "active_gateway_mac": gw_macs.most_common(1)[0][0] if gw_macs else None,
        "bgp_asn": bgp_asn,
        "vxlan_interface": vxlan_iface,
    }



@mcp.tool()
async def create_vlan_service(
    vlan_id: int,
    name: str = None,
    devices: list[str] = None,
    site: str = None,
    network_type: str = None,
    vni: int = None,
    gateway: str = None,
    gateway_mac: str = None,
    vrf: str = None,
    import_route_targets: list = None,
    export_route_targets: list = None,
    evpn: bool = True,
    tag_uplinks: bool = True,
    apply: bool = False,
) -> dict:
    """Create a VLAN service, adapting to the network type (auto-detection unless
    `network_type` is forced):
      - VXLAN/EVPN fabric (VTEP): VLAN + L2VNI + deduced Route-Targets, and if
        `gateway` is provided, the SVI with anycast active-gateway. Without
        `devices`, all the VTEPs (filterable by `site`).
      - Traditional (non-VTEP): VLAN + tagged addition on the LLDP uplinks (also
        created on the upstream inventory switch).

    Params: `vlan_id` (required), `name` (default VLAN<id>), `devices`/`site` (targets),
    `vni` (deduced if omitted), `gateway` (anycast IP/CIDR; otherwise pure L2), `vrf`
    (required if `gateway`), `gateway_mac`/`import_route_targets`/`export_route_targets`
    (deduced if omitted), `evpn` (default True; set to False for an Extended Edge /
    Stub-VTEP device that maps the VLAN to a VNI WITHOUT participating in
    BGP-EVPN — skips the EVPN route-target step entirely, no RT questions/
    deduction), `apply` (False=plan only, True=applies).

    If information is missing, returns status='need_info' with `questions`.
    """
    # 1. Resolve the candidate targets
    try:
        if devices:
            candidates = []
            for d in devices:
                candidates.extend(_resolve_devices(device=d, site=site))
        elif site:
            candidates = _resolve_devices(site=site)
        else:
            candidates = list(server_core._devices.keys())
    except ValueError as exc:
        return {"status": "error", "error": str(exc)}

    if not candidates:
        return {"status": "error", "error": "No resolved target device."}

    if apply:
        denied = _deny_read_only_many(candidates, "create_vlan_service")
        if denied:
            return denied

    # 2. Detect the network type (unless forced)
    contexts = await _gather_fabric_contexts(candidates)
    reachable = {n: r["ctx"] for n, r in contexts.items() if r.get("ok")}
    unreachable = {n: r["error"] for n, r in contexts.items() if not r.get("ok")}
    vtep_devices = [n for n, c in reachable.items() if c.get("fabric")]

    if network_type not in (None, "fabric", "traditional"):
        return {"status": "error",
                "error": "network_type must be 'fabric', 'traditional' or omitted."}

    if network_type is None:
        detected = "fabric" if vtep_devices else "traditional"
    else:
        detected = network_type

    if detected == "fabric":
        result = await _provision_fabric_service(
            vlan_id=vlan_id, name=name, explicit_devices=devices, site=site,
            candidates=candidates, reachable=reachable, vtep_devices=vtep_devices,
            unreachable=unreachable, vni=vni, gateway=gateway, gateway_mac=gateway_mac,
            vrf=vrf, import_rts=import_route_targets, export_rts=export_route_targets,
            evpn=evpn, apply=apply,
        )
    else:
        result = await _provision_traditional_service(
            vlan_id=vlan_id, name=name, targets=candidates, unreachable=unreachable,
            tag_uplinks=tag_uplinks, apply=apply,
        )

    # End of workflow: close the sessions opened on the targeted devices.
    await _close_sessions(candidates)
    # Preview of a write -> freeze a replayable dry_run_token (no-op if disabled).
    if (not apply and write_safety is not None and isinstance(result, dict)
            and result.get("status") == "planned"):
        try:
            write_safety.freeze_recipe(
                result, "create_vlan_service",
                result.get("targets") or [], result.get("plan") or {},
                tool="create_vlan_service",
                arguments=dict(
                    vlan_id=vlan_id, name=name, devices=devices, site=site,
                    network_type=network_type, vni=vni, gateway=gateway,
                    gateway_mac=gateway_mac, vrf=vrf,
                    import_route_targets=import_route_targets,
                    export_route_targets=export_route_targets,
                    evpn=evpn, tag_uplinks=tag_uplinks,
                ),
            )
        except Exception:
            logger.exception("freeze_recipe failed for create_vlan_service")
    return result


async def _provision_fabric_service(*, vlan_id, name, explicit_devices, site, candidates,
                                    reachable, vtep_devices, unreachable, vni, gateway,
                                    gateway_mac, vrf, import_rts, export_rts, evpn=True,
                                    apply) -> dict:
    # Target = explicitly requested VTEPs, otherwise all reachable VTEPs
    if explicit_devices:
        targets = [d for d in candidates if d in vtep_devices]
        non_vtep = [d for d in candidates if d in reachable and d not in vtep_devices]
    else:
        targets = vtep_devices
        non_vtep = []
    if not targets:
        return {"status": "error",
                "error": "No reachable VTEP among the targets.",
                "unreachable": unreachable}

    # Aggregated context of ALL target VTEPs (a single reference VTEP is misleading)
    ref_ctx = _aggregate_fabric_context([reachable[t] for t in targets])

    # VNI deduction
    questions: list[dict] = []
    eff_vni = vni
    if eff_vni is None:
        existing_vni = ref_ctx["vni_by_vlan"].get(vlan_id)
        offset = ref_ctx.get("vni_offset")
        if existing_vni is not None:
            eff_vni = existing_vni  # VLAN already mapped on the fabric: reuse its VNI
        elif offset is not None:
            eff_vni = vlan_id + offset
        else:
            questions.append({
                "key": "vni",
                "question": f"Which L2 VNI to use for VLAN {vlan_id}? "
                            "(the VTEPs do not use a homogeneous VLAN→VNI offset, "
                            "automatic deduction is impossible)",
            })


    # Route-Target deduction (skipped entirely for a non-EVPN / Extended Edge
    # target: plain VLAN-to-VNI mapping via a static VXLAN tunnel, no EVPN RT).
    eff_import = import_rts
    eff_export = export_rts
    if evpn and (eff_import is None or eff_export is None) and eff_vni is not None:
        from clients.aruba_client import ArubaOSCXClient as _Cli
        deduced = _Cli.deduce_route_targets(ref_ctx.get("rt_template"), vlan_id,
                                            eff_vni, ref_ctx.get("bgp_asn"))
        eff_import = eff_import or deduced
        eff_export = eff_export or deduced
    elif not evpn:
        eff_import = None
        eff_export = None

    # Active-gateway (optional)
    eff_gw_mac = gateway_mac
    if gateway:
        if not vrf:
            questions.append({
                "key": "vrf",
                "question": f"In which VRF to place the SVI interface vlan{vlan_id} "
                            f"(active-gateway {gateway})?",
            })
        if not eff_gw_mac:
            eff_gw_mac = ref_ctx.get("active_gateway_mac")
            if not eff_gw_mac:
                questions.append({
                    "key": "gateway_mac",
                    "question": "Which active-gateway MAC to use? "
                                "(no common MAC found on the existing SVIs)",
                })

    if questions:
        return {
            "status": "need_info",
            "network_type": "fabric",
            "service": {"vlan": vlan_id, "vni": eff_vni},
            "targets": targets,
            "questions": questions,
        }

    # Build the plan
    svc_name = name or f"VLAN{vlan_id}"
    steps_template = [
        {"action": "create_vlan", "vlan": vlan_id, "name": svc_name},
        {"action": "create_l2vni", "vni": eff_vni, "vlan": vlan_id,
         "vxlan_interface": ref_ctx.get("vxlan_interface", "vxlan1")},
    ]
    if evpn:
        steps_template.append({"action": "set_evpn_vlan_rt", "vlan": vlan_id,
                               "import_route_targets": eff_import,
                               "export_route_targets": eff_export})
    if gateway:
        steps_template.append({
            "action": "create_svi", "vlan": vlan_id, "vrf": vrf,
            "ip4_address": gateway, "active_gateway_ip": gateway,
            "active_gateway_mac": eff_gw_mac,
        })

    plan = {dev: steps_template for dev in targets}
    service = {
        "vlan": vlan_id, "name": svc_name, "network_type": "fabric", "vni": eff_vni,
        "evpn": evpn,
        "import_route_targets": eff_import, "export_route_targets": eff_export,
        "gateway": gateway, "vrf": vrf, "active_gateway_mac": eff_gw_mac,
    }
    if not apply:
        return {"status": "planned", "service": service, "targets": targets,
                "plan": plan, "apply": False, "unreachable": unreachable,
                "ignored_non_vtep": non_vtep,
                "note": "Preview only. Re-run with apply=true to apply."}

    # Application — with automatic per-device rollback on a mid-course failure
    # (only what THIS pass actually created is undone).
    async def _apply_one(dev: str):
        steps_done = []
        try:
            async with _get_client(dev) as client:
                steps_done.append(await client.create_vlan(vlan_id, svc_name))
                steps_done.append(await client.create_l2vni(
                    eff_vni, vlan_id, ref_ctx.get("vxlan_interface", "vxlan1")))
                if evpn:
                    steps_done.append(await client.set_evpn_vlan_rt(
                        vlan_id, eff_import, eff_export))
                if gateway:
                    steps_done.append(await client.create_svi(
                        vlan_id, vrf, gateway, active_gateway_ip=gateway,
                        active_gateway_mac=eff_gw_mac))
            return dev, {"ok": True, "steps": steps_done}
        except Exception as exc:  # noqa: BLE001
            # Best-effort rollback of what this pass created on this device.
            rb_report = await _rollback_fabric(dev, vlan_id, eff_vni, steps_done, gateway)
            return dev, {"ok": False, "error": str(exc), "steps": steps_done,
                         "rolled_back": rb_report}

    results = dict(await asyncio.gather(*[_apply_one(d) for d in targets]))
    failed = [d for d, r in results.items() if not r["ok"]]
    return {
        "status": "applied" if not failed else "partial",
        "service": service, "targets": targets, "apply": True,
        "results": results, "unreachable": unreachable, "ignored_non_vtep": non_vtep,
        "summary": {"total": len(targets), "succeeded": len(targets) - len(failed),
                    "failed": len(failed), "failed_devices": failed},
    }


async def _rollback_fabric(dev: str, vlan_id: int, vni: int, steps_done: list,
                           gateway: str | None) -> list:
    """
    Undo (best-effort) a partially applied fabric service on a device.
    Only the objects that this pass actually created (status='created' in
    steps_done) are deleted, in reverse order of creation.
    """
    created = {s.get("status"): s for s in steps_done}
    report: list = []
    try:
        async with _get_client(dev) as client:
            # Reverse order: SVI → EVPN RT → L2VNI → VLAN
            if gateway and any(s.get("interface") == f"vlan{vlan_id}"
                               and s.get("status") == "created" for s in steps_done):
                report.append(await client.delete_svi(vlan_id))
            if any("import_route_targets" in s and s.get("status") == "created"
                   for s in steps_done):
                report.append(await client.delete_evpn_vlan_rt(vlan_id))
            if any(s.get("vni") == vni and s.get("status") == "created"
                   for s in steps_done):
                report.append(await client.delete_l2vni(vni))
            if any(s.get("vlan") == vlan_id and s.get("status") == "created"
                   and "vni" not in s and "import_route_targets" not in s
                   for s in steps_done):
                report.append(await client.delete_vlan(vlan_id))
    except Exception as exc:  # noqa: BLE001
        report.append({"rollback_error": str(exc)})
    return report



async def _provision_traditional_service(*, vlan_id, name, targets, unreachable,
                                         tag_uplinks, apply) -> dict:
    if not targets:
        return {"status": "error", "error": "No reachable target device.",
                "unreachable": unreachable}

    svc_name = name or f"VLAN{vlan_id}"
    inv_names = set(server_core._devices.keys())
    inv_hosts = {d.host for d in server_core._devices.values() if d.host}

    # Discovery of uplinks and upstream switches (plan)
    plan: dict[str, list] = {}
    upstream_to_create: dict[str, dict] = {}  # inventory name → {via}

    async def _plan_one(dev: str):
        steps = [{"action": "create_vlan", "vlan": vlan_id, "name": svc_name}]
        uplinks = []
        if tag_uplinks:
            try:
                async with _get_client(dev) as client:
                    uplinks = await client.get_uplink_interfaces(
                        neighbor_system_names=inv_names, neighbor_hosts=inv_hosts)
            except Exception as exc:  # noqa: BLE001
                return dev, steps, [], {"uplink_error": str(exc)}
            for u in uplinks:
                steps.append({"action": "add_vlan_to_trunk",
                              "interface": u["interface"], "vlan": vlan_id,
                              "neighbor": u.get("neighbor_system_name")})
        return dev, steps, uplinks, None

    plan_results = await asyncio.gather(*[_plan_one(d) for d in targets])
    for dev, steps, uplinks, _err in plan_results:
        plan[dev] = steps
        for u in uplinks:
            upstream = _match_inventory_device(
                u.get("neighbor_system_name", ""), u.get("neighbor_mgmt_address", ""))
            if upstream and upstream not in targets:
                upstream_to_create[upstream] = {"via": dev}

    # The VLAN must also exist on the upstream inventory switches
    for up in upstream_to_create:
        plan.setdefault(up, []).insert(
            0, {"action": "create_vlan", "vlan": vlan_id, "name": svc_name,
                "reason": f"upstream switch (via {upstream_to_create[up]['via']})"})

    service = {"vlan": vlan_id, "name": svc_name, "network_type": "traditional",
               "tag_uplinks": tag_uplinks,
               "upstream_devices": list(upstream_to_create.keys())}

    if not apply:
        return {"status": "planned", "service": service,
                "targets": list(plan.keys()), "plan": plan, "apply": False,
                "unreachable": unreachable,
                "note": "Preview only. Re-run with apply=true to apply."}

    # Application
    async def _apply_one(dev: str, steps: list):
        done = []
        try:
            async with _get_client(dev) as client:
                for st in steps:
                    if st["action"] == "create_vlan":
                        done.append(await client.create_vlan(vlan_id, svc_name))
                    elif st["action"] == "add_vlan_to_trunk":
                        done.append(await client.add_vlan_to_trunk(st["interface"], vlan_id))
            return dev, {"ok": True, "steps": done}
        except Exception as exc:  # noqa: BLE001
            return dev, {"ok": False, "error": str(exc), "steps": done}

    results = dict(await asyncio.gather(*[_apply_one(d, s) for d, s in plan.items()]))
    failed = [d for d, r in results.items() if not r["ok"]]
    return {
        "status": "applied" if not failed else "partial",
        "service": service, "targets": list(plan.keys()), "apply": True,
        "results": results, "unreachable": unreachable,
        "summary": {"total": len(plan), "succeeded": len(plan) - len(failed),
                    "failed": len(failed), "failed_devices": failed},
    }


@mcp.tool()
async def delete_vlan_service(
    vlan_id: int,
    devices: list[str] = None,
    site: str = None,
    network_type: str = None,
    remove_from_trunks: bool = True,
    apply: bool = False,
) -> dict:
    """Delete (rollback) a VLAN service, in reverse order of creation
    (auto-detection unless `network_type` is forced):
      - VXLAN/EVPN fabric: SVI → EVPN config (RT/RD) → L2VNI → VLAN.
      - Traditional: remove the VLAN from the tagged uplinks then delete the VLAN.

    Target `devices`/`site` (otherwise everywhere the VLAN/L2VNI is present). `apply`
    (False=plan only, True=applies). Idempotent (object absent → status='absent').
    """
    # 1. Candidate targets
    try:
        if devices:
            candidates = []
            for d in devices:
                candidates.extend(_resolve_devices(device=d, site=site))
        elif site:
            candidates = _resolve_devices(site=site)
        else:
            candidates = list(server_core._devices.keys())
    except ValueError as exc:
        return {"status": "error", "error": str(exc)}

    if apply:
        denied = _deny_read_only_many(candidates, "delete_vlan_service")
        if denied:
            return denied

    # 2. Inventory of service presence per device (read-only)
    async def _inspect(dev: str):
        try:
            async with _get_client(dev) as client:
                has_vlan = await client.vlan_exists(vlan_id)
                ctx = await client.get_fabric_context()
                vni = (ctx.get("vni_by_vlan") or {}).get(vlan_id)
                is_fabric = bool(ctx.get("fabric"))
                has_svi = await client.svi_exists(vlan_id)
                has_evpn = await client.evpn_vlan_exists(vlan_id)
                trunks = []
                if not is_fabric and remove_from_trunks:
                    trunks = await client.list_trunks_with_vlan(vlan_id)
                return dev, {"ok": True, "has_vlan": has_vlan, "vni": vni,
                             "is_fabric": is_fabric, "has_svi": has_svi,
                             "has_evpn": has_evpn, "trunks": trunks}
        except Exception as exc:  # noqa: BLE001
            return dev, {"ok": False, "error": str(exc)}

    inspected = dict(await asyncio.gather(*[_inspect(d) for d in candidates]))
    reachable = {d: i for d, i in inspected.items() if i.get("ok")}
    unreachable = {d: i["error"] for d, i in inspected.items() if not i.get("ok")}

    # Detect the type if not forced: fabric if at least one VTEP is involved
    if network_type not in (None, "fabric", "traditional"):
        return {"status": "error",
                "error": "network_type must be 'fabric', 'traditional' or omitted."}
    fabric_present = any(i.get("is_fabric") for i in reachable.values())
    detected = network_type or ("fabric" if fabric_present else "traditional")

    # 3. Build the plan: only the devices where something remains to clean up
    plan: dict[str, list] = {}
    for dev, info in reachable.items():
        steps = []
        if detected == "fabric" and info.get("is_fabric"):
            if info.get("has_svi"):
                steps.append({"action": "delete_svi", "interface": f"vlan{vlan_id}"})
            if info.get("has_evpn"):
                steps.append({"action": "delete_evpn_vlan_rt", "vlan": vlan_id})
            if info.get("vni") is not None:
                steps.append({"action": "delete_l2vni", "vni": info["vni"]})
            if info.get("has_vlan"):
                steps.append({"action": "delete_vlan", "vlan": vlan_id})
        else:
            for t in info.get("trunks", []):
                steps.append({"action": "remove_vlan_from_trunk", "interface": t, "vlan": vlan_id})
            if info.get("has_vlan"):
                steps.append({"action": "delete_vlan", "vlan": vlan_id})
        if steps:
            plan[dev] = steps

    summary_target = list(plan.keys())
    service = {"vlan": vlan_id, "network_type": detected}
    if not apply:
        # End of workflow (inspection only): close the opened sessions.
        await _close_sessions(candidates)
        planned = {"status": "planned", "service": service, "targets": summary_target,
                   "plan": plan, "apply": False, "unreachable": unreachable,
                   "note": "Preview only. Re-run with apply=true to delete."}
        if write_safety is not None:
            try:
                write_safety.freeze_recipe(
                    planned, "delete_vlan_service", summary_target, plan,
                    tool="delete_vlan_service",
                    arguments=dict(vlan_id=vlan_id, devices=devices, site=site,
                                   network_type=network_type,
                                   remove_from_trunks=remove_from_trunks),
                )
            except Exception:
                logger.exception("freeze_recipe failed for delete_vlan_service")
        return planned

    if not plan:
        await _close_sessions(candidates)
        return {"status": "noop", "service": service, "targets": [],
                "unreachable": unreachable,
                "note": "Nothing to delete: the service is already absent everywhere."}

    # 4. Apply the deletion
    async def _delete_one(dev: str, steps: list):
        done = []
        try:
            async with _get_client(dev) as client:
                for st in steps:
                    act = st["action"]
                    if act == "delete_svi":
                        done.append(await client.delete_svi(vlan_id))
                    elif act == "delete_evpn_vlan_rt":
                        done.append(await client.delete_evpn_vlan_rt(vlan_id))
                    elif act == "delete_l2vni":
                        done.append(await client.delete_l2vni(st["vni"]))
                    elif act == "delete_vlan":
                        done.append(await client.delete_vlan(vlan_id))
                    elif act == "remove_vlan_from_trunk":
                        done.append(await client.remove_vlan_from_trunk(st["interface"], vlan_id))
            return dev, {"ok": True, "steps": done}
        except Exception as exc:  # noqa: BLE001
            return dev, {"ok": False, "error": str(exc), "steps": done}

    results = dict(await asyncio.gather(*[_delete_one(d, s) for d, s in plan.items()]))
    failed = [d for d, r in results.items() if not r["ok"]]
    # End of workflow: close the sessions opened on the targeted devices.
    await _close_sessions(candidates)
    return {
        "status": "applied" if not failed else "partial",
        "service": service, "targets": summary_target, "apply": True,
        "results": results, "unreachable": unreachable,
        "summary": {"total": len(plan), "succeeded": len(plan) - len(failed),
                    "failed": len(failed), "failed_devices": failed},
    }


