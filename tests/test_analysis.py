import pytest
from ecdat.analysis import assess_context, candidate_options, plan_tasks, compare_coverage


def test_strict_boundary_and_interval_uncertainty():
    assert assess_context(2, 3, 5)["status"] == "not_triggered"
    assert assess_context([2, 4], [1, 3], [4, 6])["status"] == "scenario_dependent"
    assert assess_context([4, 5], [2, 3], [1, 5])["status"] == "triggered"
    assert assess_context({"low": 12, "high": 12, "unit": "months"}, 1, 2)["status"] == "not_triggered"
    missing = assess_context(None, 2, 5)
    assert missing["status"] == "insufficient_context" and missing["investigation_tasks"]


@pytest.mark.parametrize("value", [[-1, 2], [4, 2], [0, float("inf")], True])
def test_invalid_context_rejected(value):
    with pytest.raises(ValueError):
        assess_context(value, 1, 4)


def test_candidates_reject_kem_for_signature_and_unsupported_peer():
    result = candidate_options("signature", ["ML-DSA-65"], runtime_capabilities=["ML-DSA-65"])
    assert result["candidates"][0]["status"] == "feasible"
    kem = next(item for item in result["excluded"] if item["algorithm"] == "X25519MLKEM768")
    assert "wrong_crypto_role" in kem["reasons"]
    result = candidate_options("key_exchange", ["X25519"], runtime_capabilities=["X25519MLKEM768"])
    assert any("unsupported_peer" in c["reasons"] for c in result["excluded"])
    assert candidate_options("key_exchange")["candidates"][0]["status"] == "blocked"


def test_shared_prerequisite_missing_owner_blocker_and_actual_cycle():
    result = plan_tasks([
        {"id": "runtime", "depends_on": []},
        {"id": "service-a", "depends_on": ["runtime"]},
        {"id": "service-b", "depends_on": ["runtime", "supplier"]},
        {"id": "supplier", "status": "blocked", "owner": "HSM vendor", "reason": "Signature support unconfirmed"},
        {"id": "a", "depends_on": ["b"]}, {"id": "b", "depends_on": ["a"]},
        {"id": "dependent", "depends_on": ["a"]},
        {"id": "missing", "depends_on": ["unprovided"]},
    ])
    assert result["order"].index("runtime") < result["order"].index("service-a")
    assert result["cycles"] == [["a", "b"]]
    assert "dependent" in result["blocked_task_ids"]
    assert "service-b" not in result["ready_order"]
    assert result["shared_dependencies"][0]["task_id"] == "runtime"
    assert result["blockers"][0]["owner"] == "HSM vendor"
    assert result["missing_dependencies"] == [{"task_id": "missing", "dependency": "unprovided"}]


def test_coverage_blocks_missing_and_parser_regression():
    before = {"manifest": [{"path": "a.py"}, {"path": "b.py"}], "coverage": [
        {"path": "a.py", "adapter": "python", "status": "complete", "version": "1"},
        {"path": "b.py", "adapter": "python", "status": "complete", "version": "1"}]}
    after = {"manifest": [{"path": "a.py"}], "coverage": [{"path": "a.py", "adapter": "python", "status": "failed", "version": "1"}]}
    result = compare_coverage(before, after)
    assert result["passed"] is False and result["missing_files"] == ["b.py"]
    assert len(result["regressions"]) == 2
    assert compare_coverage(before, before)["passed"] is True


def test_coverage_does_not_hide_unchanged_partial_status():
    value = {"manifest": [{"path": "binary"}], "coverage": [{"path": "binary", "adapter": "elf", "status": "partial"}]}
    result = compare_coverage(value, value)
    assert result["passed"] and result["residual_coverage"][0]["status"] == "partial"
