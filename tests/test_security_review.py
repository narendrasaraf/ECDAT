"""Independent regression checks from discovery agent's governance review."""
import copy
import json
import time

import pytest


def _proposal(tmp_path, monkeypatch):
    from ecdat import governance
    from ecdat.artifacts import manifest
    from ecdat.store import digest
    (tmp_path / "tls.json").write_text(json.dumps({"tls": {"groups": ["X25519"], "minVersion": "TLSv1.3"}}))
    monkeypatch.setattr(governance, "artifact_path", lambda artifact: tmp_path)
    artifact = {"authored_fixture": True, "manifest_digest": digest(manifest(tmp_path))}
    proposal = copy.deepcopy(governance.propose(artifact, "input-one", "analyst-one", False))
    decision = {"action": "approve", "reviewer_id": "reviewer-two", "proposal_digest": proposal["proposal_digest"]}
    governance.assert_fresh(proposal, artifact, decision)
    return governance, artifact, proposal, decision


@pytest.mark.parametrize("field,value", [("fallback", True), ("author_id", "somebody-else"), ("recipe_version", "new"), ("policy", "weaker")])
def test_approved_duplicate_fields_cannot_drift(tmp_path, monkeypatch, field, value):
    governance, artifact, proposal, decision = _proposal(tmp_path, monkeypatch)
    proposal[field] = value
    with pytest.raises(ValueError):
        governance.assert_fresh(proposal, artifact, decision)


def test_runtime_acceptance_change_invalidates_approval(tmp_path, monkeypatch):
    governance, artifact, proposal, decision = _proposal(tmp_path, monkeypatch)
    revised = copy.deepcopy(governance.ACCEPTANCE)
    revised["required"].append("new_required_verification")
    monkeypatch.setattr(governance, "ACCEPTANCE", revised)
    with pytest.raises(ValueError):
        governance.assert_fresh(proposal, artifact, decision)


@pytest.mark.parametrize("encrypted", [False, True])
def test_binary_private_key_never_enters_portable_snapshot(tmp_path, monkeypatch, encrypted):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from ecdat import artifacts
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    protection = serialization.BestAvailableEncryption(b"fixture-secret") if encrypted else serialization.NoEncryption()
    private = key.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.PKCS8, protection)
    # Unknown extension prevents a suffix-only test from accidentally passing.
    (tmp_path / "secret.blob").write_bytes(private)
    public = key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    (tmp_path / "public.der").write_bytes(public)
    monkeypatch.setattr(artifacts, "artifact_path", lambda artifact: tmp_path)
    snapshot = {item["path"]: item for item in artifacts.snapshot_files({})}
    assert snapshot["secret.blob"]["availability"] == "withheld_private_material"
    assert "content" not in snapshot["secret.blob"]
    assert snapshot["public.der"]["availability"] == "included"


@pytest.fixture
def security_project():
    from ecdat.store import DB, Project, initialize
    initialize()
    with DB() as db:
        project = Project(name="Independent security regression", description="Authored test data")
        db.add(project)
        db.commit()
        return project.id


@pytest.mark.parametrize("status,fence,lease", [("cancelled", 2, 0), ("running", 2, 180), ("running", 1, -1)])
def test_obsolete_anchor_cannot_produce_external_side_effect(security_project, monkeypatch, status, fence, lease):
    from ecdat import exporting
    from ecdat.jobs import perform
    from ecdat.store import DB, Job, uid
    with DB() as db:
        job = Job(project_id=security_project, kind="anchor", payload={"export_id": "unused"},
                  idempotency_key=uid(), status=status, fence=fence, lease_until=time.time()+lease)
        db.add(job)
        db.commit()
        job_id = job.id
    calls = []
    monkeypatch.setattr(exporting, "seal_bundle", lambda export_id: calls.append(export_id))
    perform(job_id, 1)
    assert calls == [], "A revoked, replaced, or expired lease must never invoke chain submission"


def test_superseded_scan_cannot_publish_evidence(security_project, monkeypatch):
    from ecdat import jobs
    from ecdat.store import DB, Job, put, rows, uid
    with DB() as db:
        artifact = put(db, security_project, "artifacts", {"authored_fixture": True})
        job = Job(project_id=security_project, kind="scan", payload={"artifact_id": artifact["id"]},
                  idempotency_key=uid(), status="running", fence=1, lease_until=time.time()+180)
        db.add(job)
        db.commit()
        job_id = job.id
    def stale_scan(*args):
        with DB() as db:
            job = db.get(Job, job_id)
            job.fence = 2
            job.status = "cancelled"
            db.commit()
        return {name: [] for name in ("findings", "coverage", "evidence", "manifest", "conflicts")}
    monkeypatch.setattr(jobs, "run_scan", stale_scan)
    jobs.perform(job_id, 1)
    with DB() as db:
        assert rows(db, security_project, "scans") == []
        assert db.get(Job, job_id).status == "cancelled"


@pytest.mark.parametrize("drift", ["persisted_baseline", "rescanned_output"])
def test_reviewed_baseline_drift_blocks_candidate_creation(security_project, monkeypatch, drift):
    from ecdat import jobs
    from ecdat.store import DB, Job, Record, digest, put, uid
    original = {name: [] for name in ("findings", "coverage", "evidence", "manifest", "conflicts")}
    changed = copy.deepcopy(original)
    changed["coverage"] = [{"path": "payments.py", "adapter": "python", "status": "error"}]
    with DB() as db:
        artifact = put(db, security_project, "artifacts", {"authored_fixture": True})
        baseline = put(db, security_project, "scans", original)
        proposal = put(db, security_project, "proposals", {"binding": {
            "baseline_scan_id": baseline["id"], "baseline_digest": digest(original)}})
        decision = put(db, security_project, "decisions", {"action": "approve"})
        if drift == "persisted_baseline":
            db.get(Record, baseline["id"]).data = changed
        job = Job(project_id=security_project, kind="execute", payload={"artifact_id": artifact["id"],
                  "proposal_id": proposal["id"], "decision_id": decision["id"]}, idempotency_key=uid(),
                  status="running", fence=1, lease_until=time.time()+180)
        db.add(job)
        db.commit()
        job_id = job.id
    monkeypatch.setattr(jobs, "run_scan", lambda *args: changed)
    calls = []
    monkeypatch.setattr(jobs, "create_candidate", lambda *args: calls.append(True))
    with pytest.raises(ValueError, match="baseline"):
        jobs.perform(job_id, 1)
    assert calls == []


def test_approved_fallback_is_measured_and_must_authenticate():
    from ecdat.artifacts import artifact_path, create_demo_artifact, manifest
    from ecdat.discovery import scan_directory
    from ecdat.governance import propose, create_candidate, tls_observation, verify_migration
    artifact = create_demo_artifact()
    original_manifest = manifest(artifact_path(artifact))
    proposal = propose(artifact, "approved-fallback-fixture", "analyst", True)
    decision = {"action": "approve", "reviewer_id": "separate-reviewer", "proposal_digest": proposal["proposal_digest"]}
    candidate = create_candidate(proposal, artifact, decision)
    before, after = scan_directory(artifact_path(artifact)), scan_directory(artifact_path(candidate))
    observation = tls_observation(candidate)
    assert observation["classical"]["connected"] and observation["classical"]["group"] == "X25519"
    verified = verify_migration(proposal, artifact, candidate, decision, before, after, observation)
    assert verified["status"] == "passed", verified
    assert manifest(artifact_path(artifact)) == original_manifest
    assert any("RSA" in residual for residual in verified["residuals"])
    for field in ("authorized", "payload_ok"):
        bad = copy.deepcopy(observation)
        bad["classical"][field] = False
        result = verify_migration(proposal, artifact, candidate, decision, before, after, bad)
        assert next(check for check in result["checks"] if check["id"] == "peer_policy")["status"] == "failed"


@pytest.mark.parametrize("error", ["timeout", "ECONNREFUSED", "ENETUNREACH", None])
def test_transport_failure_is_not_proof_of_strict_hybrid_policy(tmp_path, monkeypatch, error):
    from ecdat import governance
    from ecdat.artifacts import manifest
    from ecdat.store import canonical, digest
    original_path = tmp_path / "original"
    candidate_path = tmp_path / "candidate"
    original_path.mkdir()
    candidate_path.mkdir()
    (original_path / "tls.json").write_bytes(canonical({"tls": {"groups": ["X25519"]}}))
    monkeypatch.setattr(governance, "artifact_path", lambda artifact: original_path if artifact.get("original") else candidate_path)
    artifact = {"original": True, "authored_fixture": True, "manifest": manifest(original_path), "manifest_digest": digest(manifest(original_path))}
    proposal = governance.propose(artifact, "strict-fixture", "analyst", False)
    (candidate_path / "tls.json").write_bytes(canonical(proposal["after"]))
    decision = {"action": "approve", "reviewer_id": "reviewer", "proposal_digest": proposal["proposal_digest"]}
    scan = {"coverage": [], "manifest": []}
    observed = {"hybrid": [{"group": "X25519MLKEM768", "connected": True, "authorized": True, "payload_ok": True}],
                "classical": {"connected": False, "error": error}}
    result = governance.verify_migration(proposal, artifact, {}, decision, scan, scan, observed)
    assert next(check for check in result["checks"] if check["id"] == "peer_policy")["status"] == "failed"
