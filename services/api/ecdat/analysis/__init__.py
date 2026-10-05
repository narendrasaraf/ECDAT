"""Pure deterministic assessment, feasibility, prerequisite and coverage rules."""
from decimal import Decimal, InvalidOperation
import math


def _interval(value):
    if value is None:
        return None
    if isinstance(value, dict):
        low, high = value.get("low"), value.get("high")
        unit = value.get("unit", "years")
    elif isinstance(value, (list, tuple)) and len(value) == 2:
        low, high = value
        unit = "years"
    else:
        low, high, unit = value, value, "years"
    if low is None or high is None:
        return None
    if isinstance(low, bool) or isinstance(high, bool):
        raise ValueError("Interval values must be numbers, not booleans")
    factors = {"years": Decimal(1), "months": Decimal(1) / 12, "days": Decimal(1) / Decimal("365.25")}
    if unit not in factors:
        raise ValueError("Unsupported interval unit")
    try:
        lo, hi = Decimal(str(low)) * factors[unit], Decimal(str(high)) * factors[unit]
    except InvalidOperation as exc:
        raise ValueError("Invalid interval number") from exc
    if not lo.is_finite() or not hi.is_finite() or lo < 0 or hi < lo:
        raise ValueError("Intervals must be finite, nonnegative and ordered")
    return lo, hi


def assess_context(data_lifetime, migration_time, quantum_horizon):
    inputs = {"data_lifetime": _interval(data_lifetime), "migration_time": _interval(migration_time), "quantum_horizon": _interval(quantum_horizon)}
    missing = [name for name, value in inputs.items() if value is None]
    if missing:
        return {"status": "insufficient_context", "criterion": "X + Y > Z", "missing": missing,
                "investigation_tasks": [{"id": f"context:{name}", "reason": f"Establish attributed {name} interval", "status": "blocked"} for name in missing], "confidence": "not_inferred"}
    x, y, z = inputs.values()
    lo, hi = x[0] + y[0] - z[1], x[1] + y[1] - z[0]
    status = "triggered" if lo > 0 else "not_triggered" if hi <= 0 else "scenario_dependent"
    return {"status": status, "criterion": "X + Y > Z", "delta": {"low": float(lo), "high": float(hi), "unit": "years"},
            "missing": [], "investigation_tasks": [], "confidence": "not_inferred", "explanation": "Timing scenario only; evidence confidence, exposure and business criticality are separate."}


REGISTRY = [
    {"id": "tls-hybrid-mlkem768", "algorithm": "X25519MLKEM768", "roles": ["key_exchange", "kem"], "protocol": "TLSv1.3", "runtime": "OpenSSL>=3.5", "prerequisites": ["hybrid-runtime", "hybrid-peer"], "support": "runtime_probe_required"},
    {"id": "ml-dsa-65", "algorithm": "ML-DSA-65", "roles": ["signature", "authentication"], "protocol": "detached_signature", "runtime": "ML-DSA-capable provider", "prerequisites": ["signature-provider", "verifier-support"], "support": "runtime_probe_required"},
    {"id": "aes-256-gcm", "algorithm": "AES-256-GCM", "roles": ["encryption"], "protocol": "symmetric", "runtime": "AES-GCM provider", "prerequisites": ["key-management"], "support": "runtime_probe_required"},
    {"id": "sha-384", "algorithm": "SHA384", "roles": ["hash"], "protocol": "digest", "runtime": "hash provider", "prerequisites": ["format-compatibility"], "support": "runtime_probe_required"},
]


def candidate_options(role, peer_capabilities=None, **constraints):
    """Unknown support is blocked; absence of evidence must not become compatibility."""
    accepted, excluded = [], []
    if isinstance(peer_capabilities, dict):
        peer_capabilities = peer_capabilities.get("algorithms")
    runtime_capabilities = constraints.get("runtime_capabilities")
    protocol, hsm = constraints.get("protocol"), constraints.get("hsm_capabilities")
    candidates = constraints.get("candidates", REGISTRY)
    for entry in candidates:
        candidate = dict(entry)
        reasons, unknowns = [], []
        if role not in entry.get("roles", []):
            reasons.append("wrong_crypto_role")
        if protocol and protocol != entry.get("protocol"):
            reasons.append("incompatible_protocol")
        if peer_capabilities is None and role in {"key_exchange", "kem", "signature", "authentication"}:
            unknowns.append("peer_capability_unknown")
        elif peer_capabilities is not None and entry["algorithm"] not in peer_capabilities:
            reasons.append("unsupported_peer")
        if runtime_capabilities is None:
            unknowns.append("runtime_support_unverified")
        elif entry["algorithm"] not in runtime_capabilities:
            reasons.append("unsupported_runtime")
        if constraints.get("requires_hsm"):
            if hsm is None:
                unknowns.append("hsm_support_unknown")
            elif entry["algorithm"] not in hsm:
                reasons.append("unsupported_hsm")
        for limit, measurement in (("max_memory_mb", "measured_memory_mb"), ("max_latency_ms", "measured_latency_ms")):
            if constraints.get(limit) is not None:
                if entry.get(measurement) is None:
                    unknowns.append(f"{measurement}_unknown")
                elif entry[measurement] > constraints[limit]:
                    reasons.append(f"{limit}_exceeded")
        candidate.update({"reasons": reasons, "unknowns": unknowns, "status": "rejected" if reasons else "blocked" if unknowns else "feasible"})
        (excluded if reasons else accepted).append(candidate)
    return {"role": role, "candidates": accepted, "excluded": excluded, "registry_version": "ecdat-candidates-0.1"}


def plan_tasks(tasks):
    by_id, references = {}, {}
    for original in tasks:
        task = dict(original)
        task_id = task.get("id")
        if not isinstance(task_id, str) or not task_id:
            raise ValueError("Each task requires a nonempty string ID")
        if task_id in by_id:
            raise ValueError("Duplicate task ID; shared prerequisites must reference one task")
        deps = task.get("depends_on", task.get("dependencies", []))
        if not isinstance(deps, list) or not all(isinstance(dep, str) for dep in deps):
            raise ValueError("Task dependencies must be string IDs")
        task["depends_on"] = list(dict.fromkeys(deps))
        by_id[task_id] = task
        for dep in task["depends_on"]:
            references.setdefault(dep, []).append(task_id)
    missing = [{"task_id": task_id, "dependency": dep} for task_id, task in by_id.items() for dep in task["depends_on"] if dep not in by_id]
    indegrees = {key: sum(dep in by_id for dep in task["depends_on"]) for key, task in by_id.items()}
    ready = sorted(key for key, count in indegrees.items() if count == 0)
    order = []
    while ready:
        key = ready.pop(0)
        order.append(key)
        for child in references.get(key, []):
            if child not in indegrees:
                continue
            indegrees[child] -= 1
            if indegrees[child] == 0:
                ready.append(child)
                ready.sort()
    # Strongly connected components distinguish actual cycles from their dependents.
    sequence, stack, active, indices, lows, cycles = [0], [], set(), {}, {}, []
    def visit(key):
        indices[key] = lows[key] = sequence[0]
        sequence[0] += 1
        stack.append(key)
        active.add(key)
        for dep in by_id[key]["depends_on"]:
            if dep not in by_id:
                continue
            if dep not in indices:
                visit(dep)
                lows[key] = min(lows[key], lows[dep])
            elif dep in active:
                lows[key] = min(lows[key], indices[dep])
        if lows[key] == indices[key]:
            component = []
            while True:
                member = stack.pop()
                active.remove(member)
                component.append(member)
                if member == key:
                    break
            if len(component) > 1 or key in by_id[key]["depends_on"]:
                cycles.append(sorted(component))
    for key in by_id:
        if key not in indices:
            visit(key)
    blockers = []
    for key, task in by_id.items():
        if task.get("status") in {"blocked", "unknown", "revoked", "expired"} or task.get("blocked"):
            blockers.append({"task_id": key, "owner": task.get("owner"), "reason": task.get("reason", "Prerequisite not established"), "evidence_ids": task.get("evidence_ids", [])})
    blocked_ids = {item["task_id"] for item in blockers} | {item["task_id"] for item in missing} | {item for group in cycles for item in group}
    changed = True
    while changed:
        before = len(blocked_ids)
        blocked_ids.update(key for key, task in by_id.items() if any(dep in blocked_ids for dep in task["depends_on"]))
        changed = before != len(blocked_ids)
    return {"tasks": list(by_id.values()), "order": order, "ready_order": [key for key in order if key not in blocked_ids],
            "cycles": cycles, "missing_dependencies": missing, "blockers": blockers, "blocked_task_ids": sorted(blocked_ids),
            "shared_dependencies": [{"task_id": key, "required_by": values} for key, values in references.items() if len(values) > 1],
            "status": "blocked" if blocked_ids else "ready"}


def compare_coverage(before, after):
    def scope(data):
        return {entry["path"] for entry in data.get("manifest", [])}
    missing = sorted(scope(before) - scope(after))
    baseline = {(entry["path"], entry["adapter"]): entry for entry in before.get("coverage", [])}
    candidate = {(entry["path"], entry["adapter"]): entry for entry in after.get("coverage", [])}
    regressions, unresolved = [], []
    strength = {"complete": 3, "partial": 2, "unsupported": 1, "unavailable": 0, "not_run": 0, "failed": 0, "cancelled": 0, "protected": 1}
    for key, entry in baseline.items():
        current = candidate.get(key)
        if current is None:
            regressions.append({"path": key[0], "adapter": key[1], "reason": "coverage_record_missing"})
        elif strength.get(current["status"], -1) < strength.get(entry["status"], -1):
            regressions.append({"path": key[0], "adapter": key[1], "reason": "coverage_regression", "before": entry["status"], "after": current["status"]})
        elif entry.get("version") != current.get("version"):
            regressions.append({"path": key[0], "adapter": key[1], "reason": "adapter_version_changed_requires_new_baseline"})
        if current and current["status"] != "complete":
            unresolved.append({"path": key[0], "adapter": key[1], "status": current["status"]})
    return {"passed": not missing and not regressions, "status": "failed" if missing or regressions else "passed", "missing_files": missing,
            "regressions": regressions, "residual_coverage": unresolved, "before_files": len(scope(before)), "after_files": len(scope(after)),
            "claim": "Coverage preserved only; does not establish successful migration or complete discovery"}
