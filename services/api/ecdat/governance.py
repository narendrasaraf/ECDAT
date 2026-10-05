import difflib
import json
import shutil
import subprocess
from pathlib import Path

from .config import ROOT, STATE, NODE
from .artifacts import artifact_path, manifest, finalize, fixture_certificate
from .store import digest, canonical, uid, now

ACCEPTANCE = {"schema": "ecdat.acceptance.v1", "required": ["original_preserved", "approval_fresh", "expected_patch_only", "scope_preserved", "parser_preserved", "hybrid_observed", "authenticated_payload", "peer_policy"], "residual_required": ["RSA certificate authentication"], "scope": "Registered authored loopback TLS laboratory"}

def propose(artifact, artifact_id, author_id, fallback):
    if not artifact.get("authored_fixture"):
        raise ValueError("This registered recipe supports the authored TLS laboratory only")
    path = artifact_path(artifact) / "tls.json"
    old = path.read_text(encoding="utf-8")
    config = json.loads(old)
    config["tls"]["groups"] = ["X25519MLKEM768", "X25519"] if fallback else ["X25519MLKEM768"]
    new = canonical(config).decode()
    binding = {"schema": "ecdat.proposal.v1", "artifact_id": artifact_id, "manifest_digest": artifact["manifest_digest"], "recipe": "tls-hybrid", "recipe_version": "1", "file": "tls.json", "before_digest": digest(json.loads(old)), "after_digest": digest(config), "fallback": fallback, "acceptance": ACCEPTANCE, "policy": "local-evaluation", "author_id": author_id}
    return {**binding, "binding": binding, "proposal_digest": digest(binding), "status": "proposed", "after": config, "diff": "\n".join(difflib.unified_diff(json.dumps(json.loads(old), indent=2).splitlines(), json.dumps(config, indent=2).splitlines(), fromfile="original/tls.json", tofile="candidate/tls.json", lineterm=""))}

def assert_fresh(proposal, artifact, decision):
    binding=proposal['binding']
    for field in ('artifact_id','manifest_digest','recipe','recipe_version','file','before_digest','after_digest','fallback','acceptance','policy','author_id'):
        if proposal.get(field)!=binding.get(field):
            raise ValueError('Proposal field differs from its reviewed binding: '+field)
    if binding['acceptance']!=ACCEPTANCE or binding['recipe']!='tls-hybrid' or binding['recipe_version']!='1':
        raise ValueError('Recipe or acceptance policy changed; a fresh review is required')
    if decision.get("action") != "approve" or decision.get("proposal_digest") != proposal["proposal_digest"] or digest(proposal["binding"]) != proposal["proposal_digest"]:
        raise ValueError("Approval does not bind the current proposal")
    if decision.get("reviewer_id") == proposal["author_id"]:
        raise ValueError("A proposer cannot approve their own proposal")
    if digest(manifest(artifact_path(artifact))) != proposal["manifest_digest"]:
        raise ValueError("Input bytes changed after proposal review")
    if digest(proposal["after"]) != proposal["binding"]["after_digest"] or proposal["artifact_id"] != proposal["binding"]["artifact_id"]:
        raise ValueError("Proposal contents changed after approval")

def create_candidate(proposal, artifact, decision):
    assert_fresh(proposal, artifact, decision)
    staging = STATE / "staging" / uid()
    staging.parent.mkdir(exist_ok=True)
    shutil.copytree(artifact_path(artifact), staging)
    (staging / "tls.json").write_bytes(canonical(proposal["after"]))
    return finalize(staging, name="Hybrid TLS candidate", authored=True, source_id=proposal["artifact_id"])

def tls_observation(artifact):
    if not artifact.get("authored_fixture"):
        raise ValueError("Only the registered authored TLS lab may execute this check")
    key, cert = fixture_certificate()
    if (artifact_path(artifact)/'server.pem').read_bytes()!=cert.read_bytes():
        raise ValueError('Registered TLS certificate differs from the approved artifact identity')
    result = subprocess.run([NODE, str(ROOT / "packages/verification/tls-lab.mjs"), str(artifact_path(artifact) / "tls.json"), str(key), str(cert)], capture_output=True, text=True, timeout=30, check=False)
    if result.returncode:
        raise RuntimeError("TLS capability check failed: " + result.stderr[-800:])
    return json.loads(result.stdout)

def verify_migration(proposal, artifact, candidate, decision, before, after, observation):
    from .analysis import compare_coverage
    checks=[]
    def check(name, passed, detail):
        checks.append({"id": name, "status": "passed" if passed else "failed", "detail": detail})
    fresh=True
    try:
        assert_fresh(proposal, artifact, decision)
    except ValueError:
        fresh=False
    check("approval_fresh", fresh, "Exact proposal, input and different reviewer are required")
    check("original_preserved", manifest(artifact_path(artifact)) == artifact["manifest"], "Compare every original byte digest")
    original={m['path']:m['sha256'] for m in artifact['manifest']}
    actual={m['path']:m['sha256'] for m in manifest(artifact_path(candidate))}
    check("scope_preserved", set(original)==set(actual), "Every input file must remain")
    changes={p for p in original.keys() | actual.keys() if original.get(p)!=actual.get(p)}
    check("expected_patch_only", changes == {"tls.json"} and digest(json.loads((artifact_path(candidate)/'tls.json').read_text(encoding='utf-8')))==proposal['binding']['after_digest'], "Only the reviewed TLS group change is permitted")
    comparison=compare_coverage(before,after)
    before_ok={ (c['path'],c.get('adapter')) for c in before['coverage'] if c['status'] in ('parsed','complete','completed','success','supported') }
    after_ok={ (c['path'],c.get('adapter')) for c in after['coverage'] if c['status'] in ('parsed','complete','completed','success','supported') }
    check("parser_preserved", bool(comparison['passed']) and before_ok <= after_ok, comparison)
    hybrid=observation.get('hybrid',[])
    check("hybrid_observed", bool(hybrid) and all(x.get('group')=='X25519MLKEM768' and x.get('connected') for x in hybrid), "Actual negotiated group from authenticated client sockets")
    check("authenticated_payload", bool(hybrid) and all(x.get('authorized') and x.get('payload_ok') for x in hybrid), "Certificate chain and loopback payload must validate")
    classical=observation.get('classical',{})
    # Transport failures are inconclusive evidence of a strict TLS policy.
    handshake_rejections={'ERR_SSL_SSLV3_ALERT_HANDSHAKE_FAILURE','ERR_SSL_SSL/TLS_ALERT_HANDSHAKE_FAILURE','ERR_SSL_NO_SUITABLE_KEY_SHARE','ERR_SSL_NO_SHARED_CIPHER'}
    expected=(classical.get('connected') and classical.get('group')=='X25519' and classical.get('authorized') and classical.get('payload_ok')) if proposal['fallback'] else (not classical.get('connected') and classical.get('error') in handshake_rejections)
    check("peer_policy", bool(expected), "Classical fallback is accepted only when explicitly approved" if proposal['fallback'] else "Strict hybrid rejects the classical-only peer")
    return {"schema":"ecdat.verification.v1","status":"passed" if all(c['status']=='passed' for c in checks) else "failed","checks":checks,"coverage_comparison":comparison,"observation":observation,"residuals":["RSA certificate authentication remains", "Static inventory outside tested TLS boundary remains unchanged"],"scope":ACCEPTANCE['scope'],"verified_at":now()}
