import copy
import hashlib
import json
from pathlib import Path

from fastapi.testclient import TestClient
from sqlalchemy import select

from ecdat.main import app
from ecdat import config
from ecdat.store import DB, User, Member, Project, Record, Job, digest, verify_audit, audit_rows, job_dict
from ecdat.jobs import work_once, claim, perform
from ecdat.artifacts import artifact_path, manifest
from ecdat.governance import assert_fresh, create_candidate, verify_migration, tls_observation
from ecdat.exporting import validate_cbom
from ecdat.ai import validate_response, redact, generate

def auth(client,name):
    response=client.post('/api/auth/login',json={'username':name,'password':'demo-'+name+'-change-me'})
    assert response.status_code==200,response.text
    client.headers['X-CSRF-Token']=response.json()['csrf_token']

def test_full_governed_flow_and_negative_controls():
    with TestClient(app) as analyst,TestClient(app) as reviewer:
        auth(analyst,'analyst');auth(reviewer,'reviewer')
        project=analyst.post('/api/projects/demo',json={}).json();pid=project['id']
        assert work_once()
        w=analyst.get(f'/api/projects/{pid}/workspace').json()
        assert w['jobs'][0]['status']=='completed',w['jobs']
        assert len(w['findings'])>=4
        assert w['conflicts'],'Historical expectation mismatch must remain visible'
        artifact=w['artifacts'][0]
        proposal=analyst.post(f'/api/projects/{pid}/proposals',json={'artifact_id':artifact['id'],'recipe':'tls-hybrid','fallback':False})
        assert proposal.status_code==200,proposal.text
        proposal=proposal.json();propid=proposal['id']
        assert analyst.post(f'/api/proposals/{propid}/execute',json={}).status_code==409
        assert analyst.post(f'/api/proposals/{propid}/decisions',json={'action':'approve','reason':'my change'}).status_code==403
        decision=reviewer.post(f'/api/proposals/{propid}/decisions',json={'action':'approve','reason':'Reviewed exact scope and acceptance contract'})
        assert decision.status_code==200,decision.text
        assert reviewer.post(f'/api/proposals/{propid}/decisions',json={'action':'approve','reason':'duplicate'}).status_code==409
        execution=analyst.post(f'/api/proposals/{propid}/execute',json={})
        assert execution.status_code==202,execution.text
        duplicate=analyst.post(f'/api/proposals/{propid}/execute',json={})
        assert duplicate.json()['id']==execution.json()['id']
        assert work_once()
        job=analyst.get('/api/jobs/'+execution.json()['id']).json()
        assert job['status']=='completed',job
        assert job['result']['verification_status']=='passed',job
        w=analyst.get(f'/api/projects/{pid}/workspace').json()
        verification=w['verifications'][-1]
        assert verification['status']=='passed',verification
        assert verification['residuals'] and 'RSA' in verification['residuals'][0]
        assert all(c['status']=='passed' for c in verification['checks'])
        assert not verification['observation']['classical']['connected']
        with DB() as db:
            artifact_data=db.get(Record,artifact['id']).data
            original=manifest(artifact_path(artifact_data))
            stale=copy.deepcopy(proposal);stale['after']['tls']['groups']=['X25519']
            import pytest
            with pytest.raises(ValueError):assert_fresh(stale,artifact_data,decision.json())
            from ecdat.discovery import scan_directory
            before=scan_directory(artifact_path(artifact_data))
            candidate=create_candidate(proposal,artifact_data,decision.json())
            (artifact_path(candidate)/'gateway.ts').unlink()
            after=scan_directory(artifact_path(candidate))
            failed=verify_migration(proposal,artifact_data,candidate,decision.json(),before,after,verification['observation'])
            assert failed['status']=='failed'
            assert any(c['id']=='scope_preserved' and c['status']=='failed' for c in failed['checks'])
            assert manifest(artifact_path(artifact_data))==original
        exported=analyst.post(f'/api/projects/{pid}/exports',json={})
        assert exported.status_code==200,exported.text
        response=analyst.get(exported.json()['download_url'])
        assert hashlib.sha256(response.content).hexdigest()==exported.json()['raw_sha256']
        bundle=response.json();expected=bundle.pop('content_digest')
        assert digest(bundle)==expected
        assert verify_audit(bundle['audit'],bundle['audit_checkpoint'])
        assert not verify_audit(bundle['audit'][:-1],bundle['audit_checkpoint'])
        assert validate_cbom(bundle['cbom'])['status']=='passed'
        bad=copy.deepcopy(bundle['cbom']);bad['components'][0]['type']='invented'
        import pytest
        with pytest.raises(Exception):validate_cbom(bad)
        # CSRF and tenant checks are server-side.
        csrf=analyst.headers.pop('X-CSRF-Token')
        assert analyst.post(f'/api/projects/{pid}/assess',json={}).status_code==403
        analyst.headers['X-CSRF-Token']=csrf
        with DB() as db:
            foreign=Project(name='Unrelated project',description='No membership');db.add(foreign);db.commit();foreign_id=foreign.id
        assert analyst.get(f'/api/projects/{foreign_id}/workspace').status_code==404
        assert analyst.get('/api/projects/'+pid+'/graph').json()['limit']==60

def test_cancel_fence_and_recovery_are_persisted():
    with TestClient(app) as client:
        auth(client,'analyst')
        project=client.post('/api/projects/demo',json={}).json()
        pid=project['id']
        if project.get('job_id'):
            assert work_once()
        artifact=client.get(f'/api/projects/{pid}/workspace').json()['artifacts'][0]
        response=client.post(f'/api/projects/{pid}/scan',json={'artifact_id':artifact['id']},headers={'Idempotency-Key':'cancel-case'})
        jid=response.json()['id']
        with DB() as db:
            picked=claim(db)
        assert picked[0]==jid
        assert client.post(f'/api/jobs/{jid}/cancel',json={}).json()['status']=='cancelled'
        # A stale worker cannot commit results after cancellation.
        from ecdat.jobs import still_active
        assert not still_active(*picked)
        retry=client.post(f'/api/jobs/{jid}/retry',json={});assert retry.status_code==202
        with DB() as db:
            claimed=claim(db);job=db.get(Job,jid);job.lease_until=0;db.commit()
        with DB() as db:
            recovered=claim(db)
        assert recovered[0]==jid and recovered[1]>claimed[1]
        perform(*recovered)
        assert client.get('/api/jobs/'+jid).json()['status']=='completed'

def test_ai_validation_rejects_injection_and_unknown_evidence():
    valid={'summary':'Evidence requires a fresh observation.','citations':[{'evidence_id':'allowed','explanation':'Configuration claim'}],'hypotheses':[],'suggested_check':{'check_id':'compare-artifact-identity','purpose':'Check identities','if_supported':'Keep observation as attributed','if_rejected':'Preserve mismatch'},'limitations':['No execution claim']}
    assert validate_response(valid,{'allowed'})['summary']
    import pytest
    bad=copy.deepcopy(valid);bad['citations'][0]['evidence_id']='another-project'
    with pytest.raises(ValueError):validate_response(bad,{'allowed'})
    bad=copy.deepcopy(valid);bad['suggested_check']['check_id']='shell:rm'
    with pytest.raises(ValueError):validate_response(bad,{'allowed'})
    bad=copy.deepcopy(valid);bad['approved']=True
    with pytest.raises(ValueError):validate_response(bad,{'allowed'})
    text='-----BEGIN PRIVATE KEY-----\nsecret value\n-----END PRIVATE KEY----- token=abc123'
    assert 'secret value' not in redact(text) and 'abc123' not in redact(text)
    result=generate('Question',[], 'public-demo')
    assert result['status']=='abstained'

def test_duplicate_and_nonfinite_json_rejected():
    with TestClient(app) as client:
        response=client.post('/api/auth/login',content='{"username":"a","username":"b","password":"c"}',headers={'Content-Type':'application/json'})
        assert response.status_code==422
